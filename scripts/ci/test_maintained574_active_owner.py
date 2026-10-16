"""Inert daemon/process models only. No Docker, native build, or subprocess actors."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import signal
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('active574_subject',HERE/'maintained574_active_owner.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
TOKEN = 'a'*16
OLD, ROOT, FINAL = ['sha256:'+c*64 for c in '012']
BUILD, PROBE = 'b'*64, 'c'*64


class Daemon:
    def __init__(self):
        self.calls=[]; self.image_rows={OLD:None}; self.container_rows={}; self.uncertain=False
        self.fault=None; self.foreign=False; self.bad_identity=False; self.lose_baseline=False
        self.names={kind:'cachy-asahi-574-active-'+TOKEN+'-'+kind for kind in ('build','probe')}
        self.tags={kind:'cachy-asahi-574-active:'+TOKEN+'-'+kind for kind in ('root','result')}

    def image(self, image, tag):
        return {'Id':image,'Os':'linux','Architecture':'arm64','Config':{'Labels':{m.LABEL:TOKEN}},'RepoTags':[tag],'RepoDigests':[]}

    def run(self,*args,seconds=20,raw=False,stdin_path=None):
        args=tuple(map(str,args)); self.calls.append((args,seconds))
        phase = ('import' if args[:2]==('image','import') else 'commit' if args[:2]==('container','commit')
                 else 'create' if args[:2]==('container','create') else 'copy' if args[:2]==('container','cp') else
                 ('build' if args[-1]==BUILD else 'probe') if args[:3]==('container','start','-a') else None)
        if self.fault and phase==self.fault[0]: raise self.fault[1]
        if args[:2]==('image','import'):
            self.image_rows[ROOT]=self.image(ROOT,self.tags['root']); return ROOT
        if args[:2]==('image','ls'):
            selected=list(self.image_rows)
            if '--filter' in args:
                filt=args[args.index('--filter')+1]
                if filt.startswith('reference='):
                    selected=[i for i,v in self.image_rows.items() if v and filt[10:] in v['RepoTags']]
                else: selected=[i for i,v in self.image_rows.items() if v and v['Config']['Labels'].get(m.LABEL)==filt.split('=',2)[2]]
            return '\n'.join(selected)
        if args[:2]==('image','inspect'): return json.dumps([self.image_rows[args[-1]]])
        if args[:2]==('image','rm'):
            del self.image_rows[args[-1]]
            if self.lose_baseline: self.image_rows.pop(OLD,None)
            return args[-1]
        if args[:2]==('container','create'):
            kind='build' if self.names['build'] in args else 'probe'; cid=BUILD if kind=='build' else PROBE
            image=ROOT if kind=='build' else FINAL
            self.container_rows[cid]={'Id':cid,'Name':'/'+self.names[kind],'Image':image,
                'Config':{'Labels':{m.LABEL:TOKEN}},'State':{'Running':False,'ExitCode':0}}
            return cid
        if args[:2]==('container','ls'):
            filt=args[args.index('--filter')+1]
            if filt.startswith('name='):
                return '\n'.join(cid for cid,v in self.container_rows.items() if filt=='name=^'+v['Name']+'$')
            if filt.startswith('id='): return args[args.index('--filter')+1][3:] if filt[3:] in self.container_rows else ''
            return 'f'*64 if self.foreign else ''
        if args[:2]==('container','inspect'):
            row=copy.deepcopy(self.container_rows[args[-1]])
            if self.bad_identity: row['Config']['Labels'][m.LABEL]='f'*16
            return json.dumps([row])
        if args[:2]==('container','cp'):
            self.copy_input=stdin_path
            return ''
        if args[:3]==('container','start','-a'): return ('one 1\n' if raw else 'one 1') if args[-1]==PROBE else ''
        if args[:2]==('container','commit'):
            self.image_rows[FINAL]=self.image(FINAL,self.tags['result']); return FINAL
        if args[:2]==('container','rm'):
            self.container_rows.pop(args[-1]); return args[-1]
        raise AssertionError(args)


class Controls(unittest.TestCase):
    def setUp(self):
        for name in ('Popen','run','check_output'):
            guard=patch.object(subprocess,name,side_effect=AssertionError('external actor forbidden'))
            guard.start(); self.addCleanup(guard.stop)
        self.temp=tempfile.TemporaryDirectory(dir=HERE); self.addCleanup(self.temp.cleanup)
        self.out=Path(self.temp.name)/'out'; self.out.mkdir(mode=0o700)
        self.prepared=Path(self.temp.name)/'context'; self.prepared.mkdir(mode=0o700)
        for name in ('pacman.conf','finish-keyring.py','disabled-hooks.txt','expected-packages.lock'):
            (self.prepared/name).write_text('inert\n');(self.prepared/name).chmod(0o600)
        for name in ('keys','deps'):
            (self.prepared/name).mkdir(mode=0o700);(self.prepared/name/'fixed').write_bytes(b'fixed data')
        self.d=Daemon(); self.owner=m.Owner(self.d,TOKEN)
        verifier=patch.object(m,'verify_copy',side_effect=self.copy_observation)
        self.verifier=verifier.start();self.addCleanup(verifier.stop)

    def copy_observation(self,owner,expected,archive):
        return {'status':'PASS_ROOT_OWNED_COPY','container':dict(owner.containers[0]),'archive':archive,
                'files_verified':len(expected)-1,'directories_verified':1,'uid':0,'gid':0,
                'members_sha256':'a'*64,'controls':[dict(path=path,uid=0,gid=0,**expected[path]) for path in m.COPY_CONTROLS]}

    def execute(self):
        return m.execute(self.owner,self.prepared,'exact held transaction','one 1\n',self.out)

    def test_failed_build_retains_bounded_public_transaction_tail_and_cleanup(self):
        import base64
        log=self.out/'transaction.log';log.write_bytes(b'x'*5000+b'\xfffailure\n')
        error=m.ClientCommandError(7,log);self.d.fault=('build',error)
        row=self.execute();diagnostic=row['build_failure']
        self.assertEqual(diagnostic['returncode'],7)
        self.assertEqual(diagnostic['log_bytes'],log.stat().st_size)
        self.assertEqual(diagnostic['tail_bytes'],4096)
        self.assertEqual(base64.b64decode(diagnostic['tail_base64']),log.read_bytes()[-4096:])
        self.assertEqual(row['status'],'FAIL');self.assertEqual(row['cleanup']['status'],'PASS')

    def test_other_command_failure_does_not_export_its_log(self):
        log=self.out/'private.log';log.write_text('must stay private')
        self.d.fault=('import',m.ClientCommandError(1,log))
        row=self.execute();self.assertNotIn('build_failure',row)

    def test_trust_probe_failure_never_skips_original_cleanup_or_changes_failure(self):
        log=self.out/'guard.log';log.write_bytes(m.TRUST_FAILURE+b'\n')
        self.d.fault=('build',m.ClientCommandError(1,log))
        with patch.object(m,'trust_metadata',side_effect=OSError('PRIVATE probe details')) as probe:
            row=self.execute()
        probe.assert_called_once_with(self.owner)
        self.assertEqual(row['status'],'FAIL');self.assertEqual(row['error_kind'],'ClientCommandError')
        self.assertEqual(row['cleanup']['status'],'PASS');self.assertEqual(row['trust_metadata']['status'],'UNAVAILABLE')
        self.assertNotIn('PRIVATE',json.dumps(row['trust_metadata']))

    def mutations(self):
        return [a for a,_ in self.d.calls if a[:2] in (('container','rm'),('image','rm'))]

    def test_normal_optional_flow_cleans_only_known_resources(self):
        row=self.execute(); self.assertEqual(row['status'],'PASS')
        self.assertEqual(row['cleanup']['status'],'PASS'); self.assertEqual(set(self.d.image_rows),{OLD})
        self.assertEqual(self.d.container_rows,{})
        self.assertEqual([v['id'] for v in row['cleanup']['images']],[FINAL,ROOT])
        self.assertTrue(row['cleanup']['initial_image_ids_preserved'])
        text=str(self.d.calls)
        self.assertNotIn('privileged',text); self.assertNotIn('SYS_ADMIN',text); self.assertNotIn('prune',text.replace('--no-prune',''))
        for argv,_ in self.d.calls:
            if argv[:2]==('container','create'):
                self.assertIn('--network=none',argv); self.assertIn(m.LABEL+'='+TOKEN,argv)
        copies=[a for a,_ in self.d.calls if a[:2]==('container','cp')]
        self.assertEqual(copies,[('container','cp','--archive','-',BUILD+':/')])
        self.assertEqual(self.d.copy_input,self.out/'copy-inputs.tar')
        with tarfile.open(self.d.copy_input) as archive:
            rows={entry.name:entry for entry in archive}
        self.assertTrue(all(entry.uid==entry.gid==0 for entry in rows.values()))
        self.assertEqual(rows['etc/pacman.conf'].mode,0o644)
        self.assertEqual(rows['tmp/finish-keyring.py'].mode,0o644)
        self.assertEqual((self.prepared/'pacman.conf').stat().st_mode&0o777,0o600)

    def test_bad_copy_verification_cannot_start_transaction_or_waive_unknown(self):
        self.verifier.side_effect=ValueError('metadata mismatch')
        row=self.execute()
        self.assertEqual(row['status'],'FAIL');self.assertEqual(row['phase'],'build-copy')
        self.assertFalse(row['cleanup']['client_fenced']);self.assertEqual(self.mutations(),[])
        self.assertFalse(any(a[:2]==('container','start') for a,_ in self.d.calls))

    def test_interrupted_archive_transfer_preserves_copy_phase_uncertainty(self):
        self.d.fault=('copy',subprocess.TimeoutExpired('inert',240))
        row=self.execute();self.assertEqual(row['phase'],'build-copy');self.assertEqual(row['status'],'FAIL')
        self.assertFalse(row['cleanup']['client_fenced']);self.verifier.assert_not_called()
        self.assertEqual(self.mutations(),[])

    def test_active_build_keyboard_cancel_reaps_exact_daemon_executor(self):
        self.d.fault=('build',KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt): self.execute()
        row=json.loads((self.out/'result.json').read_bytes())
        self.assertTrue(row['cancelled']); self.assertEqual(row['status'],'FAIL')
        self.assertEqual(row['cleanup']['status'],'PASS'); self.assertEqual(set(self.d.image_rows),{OLD})
        self.assertEqual(self.mutations()[0],('container','rm','-f',BUILD))

    def test_active_probe_keyboard_cancel_removes_both_owned_containers(self):
        self.d.fault=('probe',KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt): self.execute()
        row=json.loads((self.out/'result.json').read_bytes())
        self.assertEqual(row['phase'],'active-probe'); self.assertEqual(row['cleanup']['status'],'PASS')
        self.assertEqual([v['cid'] for v in row['cleanup']['containers']],[PROBE,BUILD])

    def test_active_build_timeout_fails_trial_but_can_pass_cleanup(self):
        self.d.fault=('build',subprocess.TimeoutExpired('inert',2400))
        row=self.execute(); self.assertEqual(row['status'],'FAIL'); self.assertEqual(row['cleanup']['status'],'PASS')

    def test_unreaped_client_never_authorizes_daemon_cleanup(self):
        self.d.fault=('build',m.ClientFenceError('inert'))
        row=self.execute(); self.assertEqual(row['cleanup']['status'],'FAIL'); self.assertEqual(self.mutations(),[])
        self.assertIn(BUILD,self.d.container_rows); self.assertIn(ROOT,self.d.image_rows)

    def test_import_commit_and_create_ambiguity_preserve_resources(self):
        for phase in ('import','commit','create'):
            with self.subTest(phase=phase):
                d=Daemon(); owner=m.Owner(d,TOKEN); d.fault=(phase,subprocess.TimeoutExpired('inert',20))
                out=Path(self.temp.name)/phase; out.mkdir()
                row=m.execute(owner,self.prepared,'held','one 1\n',out)
                self.assertEqual(row['status'],'FAIL'); self.assertFalse(row['cleanup']['client_fenced'])
                self.assertFalse(any(a[:2] in (('container','rm'),('image','rm')) for a,_ in d.calls))
                self.assertIn(OLD,d.image_rows)

    def test_wrong_container_label_refuses_before_any_removal(self):
        self.d.image_rows[ROOT]=self.d.image(ROOT,self.d.tags['root']); self.owner.admit_image('root')
        self.owner.create('build',ROOT,['/bin/false']); self.d.bad_identity=True
        row=self.owner.cleanup(True); self.assertEqual(row['status'],'FAIL'); self.assertEqual(self.mutations(),[])

    def test_foreign_image_reference_is_preserved(self):
        self.d.image_rows[ROOT]=self.d.image(ROOT,self.d.tags['root']); self.owner.admit_image('root'); self.d.foreign=True
        row=self.owner.cleanup(True); self.assertEqual(row['status'],'FAIL'); self.assertEqual(self.mutations(),[])

    def test_foreign_tag_or_digest_blocks_image_removal(self):
        for field,value in (('RepoTags',[self.d.tags['root'],'foreign:kept']),('RepoDigests',['foreign@sha256:'+'f'*64])):
            self.d.image_rows[ROOT]=self.d.image(ROOT,self.d.tags['root'])
            if not self.owner.images_owned: self.owner.admit_image('root')
            self.d.image_rows[ROOT][field]=value
            self.assertEqual(self.owner.cleanup(True)['status'],'FAIL'); self.assertEqual(self.mutations(),[])

    def test_baseline_image_cannot_be_admitted(self):
        with self.assertRaises(ValueError): self.owner.image(OLD,self.d.tags['root'])
        self.assertEqual(self.mutations(),[])

    def test_baseline_loss_fails_even_if_exact_cleanup_succeeded(self):
        self.d.lose_baseline=True; row=self.execute()
        self.assertEqual(row['status'],'FAIL'); self.assertFalse(row['cleanup']['initial_image_ids_preserved'])

    def test_token_collision_cannot_start_new_owner(self):
        self.d.image_rows[ROOT]=self.d.image(ROOT,self.d.tags['root'])
        with self.assertRaises(ValueError): m.Owner(self.d,TOKEN)
        self.assertEqual(self.mutations(),[])

    def test_real_client_wrapper_reaps_on_cancel_without_external_actor(self):
        child=Mock(pid=12345); primary=KeyboardInterrupt(); child.wait.side_effect=[primary,0]
        with patch.object(m.subprocess,'Popen',return_value=child) as popen, patch.object(m.os,'killpg',side_effect=ProcessLookupError):
            with self.assertRaises(KeyboardInterrupt) as caught: m.command(['inert'],self.out/'child.log',{},1)
        self.assertIs(caught.exception,primary); self.assertEqual(child.wait.call_count,2)
        self.assertTrue(popen.call_args.kwargs['start_new_session'])

    def test_client_fence_failure_is_distinct_from_cancel(self):
        child=Mock(pid=12345); child.wait.side_effect=KeyboardInterrupt()
        with patch.object(m.subprocess,'Popen',return_value=child), patch.object(m,'reap',side_effect=OSError('inert')):
            with self.assertRaises(m.ClientFenceError) as caught: m.command(['inert'],self.out/'fence.log',{},1)
        self.assertTrue(caught.exception.cancelled)

    def test_live_descendants_are_not_ignored_when_client_already_exited(self):
        child=Mock(pid=12345)
        with patch.object(m.os,'killpg') as kill, patch.object(m.time,'monotonic',side_effect=range(0,100,5)):
            with self.assertRaises(m.ClientFenceError): m.reap(child)
        self.assertIn(((12345,signal.SIGKILL),),[(v.args,) for v in kill.call_args_list])

    def test_held_source_and_default_guard_remain_exact(self):
        root=next(p for p in HERE.parents if (p/'scripts/ci/maintained_desktop574.py').is_file())
        self.assertEqual(m.digest(root/'scripts/ci/maintained_desktop574.py'),m.HELPER)
        self.assertEqual(m.digest(root/'scripts/ci/maintained-desktop574-inputs.json'),m.INPUTS)
        self.assertIn("owner['build_complete']and report['build_returncode']==0",(root/'scripts/ci/maintained_desktop574.py').read_text())

    def test_prepared_context_extra_members_cannot_enter_package_transaction(self):
        wanted={p for p in self.prepared.rglob('*') if p.is_file()}; m.membership(self.prepared,wanted)
        extra=self.prepared/'unplanned.pkg.tar.xz'; extra.write_bytes(b'inert')
        with self.assertRaises(ValueError): m.membership(self.prepared,wanted)
        extra.unlink(); extra.symlink_to(self.prepared/'pacman.conf')
        with self.assertRaises(ValueError): m.membership(self.prepared,wanted)

    def test_context_extra_directories_and_writable_inputs_refused(self):
        wanted={p for p in self.prepared.rglob('*') if p.is_file()}; extra=self.prepared/'unplanned'; extra.mkdir()
        with self.assertRaises(ValueError): m.membership(self.prepared,wanted)
        extra.rmdir(); (self.prepared/'pacman.conf').chmod(0o666)
        with self.assertRaises(ValueError): m.membership(self.prepared,wanted)


class CopyControls(unittest.TestCase):
    def setUp(self):
        for name in ('Popen','run','check_output'):
            guard=patch.object(subprocess,name,side_effect=AssertionError('external actor forbidden'))
            guard.start();self.addCleanup(guard.stop)
        guard=patch.object(m.socket,'socket',side_effect=AssertionError('network actor forbidden'))
        guard.start();self.addCleanup(guard.stop)
        self.temp=tempfile.TemporaryDirectory(dir=HERE);self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.prepared=self.root/'context';self.prepared.mkdir(mode=0o700)
        for name in ('keys','deps'):(self.prepared/name).mkdir(mode=0o700)
        for name in ('archlinuxarm.gpg','archlinuxarm-trusted','archlinuxarm-revoked'):
            (self.prepared/'keys'/name).write_bytes(b'public key fixture')
        for name in ('package.pkg.tar.xz','package.pkg.tar.xz.sig'):(self.prepared/'deps'/name).write_bytes(b'package fixture')
        for path in m.COPY_CONTROLS:
            file=self.prepared/Path(path).name;file.write_bytes(b'control fixture');file.chmod(0o600)
        self.archive=self.root/'input.tar';self.expected,self.archive_row=m.copy_archive(self.prepared,self.archive)

    def response(self,data):
        body=io.BytesIO(data);response=SimpleNamespace(status=200,read=Mock(side_effect=body.read),close=Mock())
        client=Mock();client.getresponse.return_value=response
        return client

    def scope(self,path,change=None,extra=False):
        result=io.BytesIO()
        with tarfile.open(fileobj=result,mode='w') as output,tarfile.open(self.archive) as original:
            for target,row in self.expected.items():
                if target!=path and not target.startswith(path+'/'):continue
                member=copy.copy(original.getmember(target.lstrip('/')))
                member.name=Path(path).name+target[len(path):]
                data=None
                if member.isreg():
                    with original.extractfile(original.getmember(target.lstrip('/'))) as stream:data=stream.read()
                if change and target==change[0]:
                    if change[1]=='data':data=b'x'*len(data)
                    else:setattr(member,change[1],change[2])
                output.addfile(member,io.BytesIO(data) if data is not None else None)
            if extra:
                member=tarfile.TarInfo(Path(path).name+'/existing-key');member.size=4
                output.addfile(member,io.BytesIO(b'base'))
        return result.getvalue()

    def test_archive_root_ownership_modes_and_bytes_without_host_chown(self):
        with tarfile.open(self.archive) as archive:
            for member in archive:
                self.assertEqual((member.uid,member.gid),(0,0))
                row=self.expected['/'+member.name]
                self.assertEqual(member.mode,row['mode'])
                if member.isreg():
                    with archive.extractfile(member) as stream:
                        self.assertEqual(m.hashlib.sha256(stream.read()).hexdigest(),row['sha256'])
        self.assertEqual(self.expected['/etc/pacman.conf']['mode'],0o644)
        self.assertEqual(self.expected['/tmp/finish-keyring.py']['mode'],0o644)
        self.assertEqual((self.prepared/'pacman.conf').stat().st_mode&0o777,0o600)
        self.assertEqual(self.archive.stat().st_mode&0o777,0o600)
        self.assertEqual(m.digest(self.archive),self.archive_row['sha256'])

    def test_byte_bounds_and_symlink_source_refuse(self):
        with patch.object(m,'COPY_LIMIT',5),self.assertRaises(ValueError):m.copy_archive(self.prepared,self.root/'too-large.tar')
        file=self.prepared/'keys/escape';file.symlink_to(self.prepared/'pacman.conf')
        with self.assertRaises(ValueError):m.copy_archive(self.prepared,self.root/'symlink.tar')

    def test_each_scope_verifies_owned_metadata_and_content_and_preserves_base_keys(self):
        seen=set()
        for path in ('/usr/share/pacman/keyrings','/tmp/deps',*m.COPY_CONTROLS):
            client=self.response(self.scope(path,extra=path=='/usr/share/pacman/keyrings'))
            with patch.object(m,'MetadataConnection',return_value=client):seen.update(m.verify_copy_scope(BUILD,path,self.expected))
        self.assertEqual(seen,set(self.expected))

    def test_nonroot_mode_or_content_drift_refuses_before_start(self):
        path='/etc/pacman.conf'
        for change in ((path,'uid',1001),(path,'gid',1001),(path,'mode',0o600),(path,'data',None)):
            client=self.response(self.scope(path,change))
            with self.subTest(change=change),patch.object(m,'MetadataConnection',return_value=client),self.assertRaises(ValueError):
                m.verify_copy_scope(BUILD,path,self.expected)
        client=self.response(self.scope('/tmp/deps',extra=True))
        with patch.object(m,'MetadataConnection',return_value=client),self.assertRaises(ValueError):
            m.verify_copy_scope(BUILD,'/tmp/deps',self.expected)

    def test_complete_copy_proof_is_bound_to_unstarted_executor(self):
        row={'cid':BUILD,'name':'cachy-asahi-574-active-'+TOKEN+'-build','image':ROOT}
        owner=SimpleNamespace(containers=[row],names={'build':row['name']})
        def seen(cid,path,expected):return {target for target in expected if target==path or target.startswith(path+'/')}
        with patch.object(m,'trust_identity') as identity,patch.object(m,'verify_copy_scope',side_effect=seen):
            proof=m.verify_copy(owner,self.expected,self.archive_row)
        self.assertEqual(identity.call_count,2)
        self.assertEqual(identity.call_args.kwargs,{'created':True})
        self.assertEqual(proof['status'],'PASS_ROOT_OWNED_COPY');self.assertEqual(proof['files_verified'],9)
        self.assertEqual(proof['container'],row);self.assertEqual(len(proof['controls']),4)
        self.assertNotIn('control fixture',json.dumps(proof))
        with patch.object(m,'trust_identity'),patch.object(m,'verify_copy_scope',return_value=set()),self.assertRaises(ValueError):
            m.verify_copy(owner,self.expected,self.archive_row)

    def test_streamed_archive_stdin_is_closed_after_client_reaping(self):
        child=Mock(pid=12345);child.wait.return_value=0;incoming=[]
        def spawn(*_,**kwargs):incoming.append(kwargs['stdin']);self.assertEqual(kwargs['stdin'].read(512),self.archive.read_bytes()[:512]);return child
        with patch.object(m.subprocess,'Popen',side_effect=spawn),patch.object(m.os,'killpg',side_effect=ProcessLookupError):
            m.command(['inert'],self.root/'stdin.log',{},1,stdin_path=self.archive)
        self.assertTrue(incoming[0].closed);self.assertEqual(child.wait.call_count,2)


class MetadataControls(unittest.TestCase):
    def setUp(self):
        for name in ('Popen','run','check_output'):
            guard=patch.object(subprocess,name,side_effect=AssertionError('external actor forbidden'))
            guard.start();self.addCleanup(guard.stop)
        guard=patch.object(m.socket,'socket',side_effect=AssertionError('network actor forbidden'))
        guard.start();self.addCleanup(guard.stop)

    def header(self,uid=0,kind=tarfile.REGTYPE,size=10,name='pacman.conf'):
        entry=tarfile.TarInfo(name);entry.uid=uid;entry.gid=1001;entry.mode=0o644;entry.type=kind;entry.size=size
        if kind==tarfile.SYMTYPE:entry.linkname='/PRIVATE_TARGET';entry.size=0
        return entry.tobuf(format=tarfile.PAX_FORMAT)+b'PRIVATE_DATA'+b'\0'*10240

    def connection(self,data,status=200):
        body=io.BytesIO(data);response=SimpleNamespace(status=status,read=Mock(side_effect=body.read),close=Mock())
        client=Mock();client.getresponse.return_value=response
        return client,response

    def test_fixed_archive_header_exposes_only_numeric_metadata_not_contents(self):
        client,response=self.connection(self.header(uid=1001))
        with patch.object(m,'MetadataConnection',return_value=client):row=m.trust_header(BUILD,'/etc/pacman.conf')
        self.assertEqual((row['uid'],row['gid'],row['mode'],row['bytes']),(1001,1001,0o644,10))
        self.assertTrue(row['fails_regular_uid_size_predicate']);self.assertNotIn('PRIVATE',json.dumps(row))
        client.request.assert_called_once_with('GET','/containers/'+BUILD+'/archive?path=%2Fetc%2Fpacman.conf')
        response.close.assert_called_once();client.close.assert_called_once()

    def test_predicate_distinguishes_UID_type_size_but_not_GID_or_mode(self):
        for uid,kind,size,expected in ((0,tarfile.REGTYPE,10,False),(1,tarfile.REGTYPE,10,True),
                                      (0,tarfile.SYMTYPE,0,True),(0,tarfile.REGTYPE,32*1024**2+1,True)):
            with self.subTest(uid=uid,kind=kind,size=size):
                client,_=self.connection(self.header(uid,kind,size))
                with patch.object(m,'MetadataConnection',return_value=client):row=m.trust_header(BUILD,'/etc/pacman.conf')
                self.assertIs(row['fails_regular_uid_size_predicate'],expected)
                self.assertNotIn('PRIVATE',json.dumps(row))

    def test_path_and_archive_root_cannot_escape_fixed_set(self):
        with self.assertRaises(ValueError):m.trust_header(BUILD,'/root/.ssh/id_ed25519')
        client,_=self.connection(self.header(name='../PRIVATE'))
        with patch.object(m,'MetadataConnection',return_value=client),self.assertRaises(ValueError):
            m.trust_header(BUILD,'/etc/pacman.conf')

    def test_HTTP_error_body_is_never_read_or_exported(self):
        client,response=self.connection(b'PRIVATE daemon error',404)
        with patch.object(m,'MetadataConnection',return_value=client):row=m.trust_header(BUILD,'/etc/pacman.conf')
        self.assertEqual(row,{'path':'/etc/pacman.conf','status':'HTTP_ERROR','http_status':404})
        response.read.assert_not_called()

    def test_extended_header_budget_is_finite(self):
        entry=tarfile.TarInfo('x'*100000);raw=entry.tobuf(format=tarfile.PAX_FORMAT)
        client,response=self.connection(raw)
        with patch.object(m,'MetadataConnection',return_value=client),self.assertRaises(ValueError):
            m.trust_header(BUILD,'/etc/pacman.conf')
        self.assertLessEqual(sum(call.args[0] for call in response.read.call_args_list),65536)

    def owner(self,running=False):
        row={'cid':BUILD,'name':'cachy-asahi-574-active-'+TOKEN+'-build','image':ROOT}
        return SimpleNamespace(containers=[row],names={'build':row['name']},token=TOKEN)

    def test_only_stopped_owned_failed_container_is_observed(self):
        owner=self.owner();identity=owner.containers[0]
        def value(running=False):
            return {'Id':BUILD,'Name':'/'+identity['name'],'Image':ROOT,'Config':{'Labels':{m.LABEL:TOKEN}},
                    'State':{'Running':running,'ExitCode':1}}
        for changed in (dict(value(),Id='f'*64),dict(value(),Image=OLD),value(running=True)):
            client,_=self.connection(json.dumps(changed).encode())
            with patch.object(m,'MetadataConnection',return_value=client),patch.object(m,'trust_header') as header:
                row=m.trust_metadata(owner)
            self.assertEqual(row['status'],'UNAVAILABLE');header.assert_not_called()
        client,response=self.connection(json.dumps(value()).encode())
        with patch.object(m,'MetadataConnection',return_value=client):m.trust_identity(owner,identity)
        client.request.assert_called_once_with('GET','/containers/'+BUILD+'/json')
        response.close.assert_called_once()

    def test_copy_boundary_requires_created_not_failed_or_already_running(self):
        owner=self.owner();identity=owner.containers[0]
        value={'Id':BUILD,'Name':'/'+identity['name'],'Image':ROOT,'Config':{'Labels':{m.LABEL:TOKEN}},
               'State':{'Running':False,'ExitCode':0,'Status':'created'}}
        client,_=self.connection(json.dumps(value).encode())
        with patch.object(m,'MetadataConnection',return_value=client):m.trust_identity(owner,identity,created=True)
        value['State']['Status']='exited';value['State']['ExitCode']=1
        client,_=self.connection(json.dumps(value).encode())
        with patch.object(m,'MetadataConnection',return_value=client),self.assertRaises(ValueError):
            m.trust_identity(owner,identity,created=True)

    def test_fixed_nine_paths_and_timeout_preserve_partial_unknown(self):
        owner=self.owner();responses=[{'path':path,'status':'HTTP_ERROR','http_status':404} for path in m.TRUST_PATHS]
        with patch.object(m,'trust_identity'),patch.object(m,'trust_header',side_effect=responses) as header:row=m.trust_metadata(owner)
        self.assertEqual(row['status'],'OBSERVED');self.assertEqual(len(row['rows']),9)
        self.assertEqual([call.args[1] for call in header.call_args_list],list(m.TRUST_PATHS))
        with patch.object(m,'trust_identity'),patch.object(m,'trust_header',side_effect=TimeoutError('PRIVATE')):row=m.trust_metadata(owner)
        self.assertEqual(row['status'],'UNAVAILABLE');self.assertEqual(row['error_kind'],'TimeoutError')
        self.assertEqual(len(row['rows']),1);self.assertNotIn('PRIVATE',json.dumps(row))

    def test_metadata_transport_has_no_TCP_or_remote_socket_fallback(self):
        endpoint=Mock()
        with patch.object(m.socket,'socket',return_value=endpoint) as factory:
            connection=m.MetadataConnection('ignored-host',timeout=3);connection.connect()
        factory.assert_called_once_with(m.socket.AF_UNIX,m.socket.SOCK_STREAM)
        endpoint.connect.assert_called_once_with('/var/run/docker.sock')


if __name__=='__main__': unittest.main()
