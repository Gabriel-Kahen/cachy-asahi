"""Inert daemon/process models only. No Docker, native build, or subprocess actors."""
import copy
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
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

    def run(self,*args,seconds=20,raw=False):
        args=tuple(map(str,args)); self.calls.append((args,seconds))
        phase = ('import' if args[:2]==('image','import') else 'commit' if args[:2]==('container','commit')
                 else 'create' if args[:2]==('container','create') else
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
        if args[:2]==('container','cp'): return ''
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
        for name in ('pacman.conf','finish-keyring.py'): (self.prepared/name).write_text('inert\n')
        self.d=Daemon(); self.owner=m.Owner(self.d,TOKEN)

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
        self.assertTrue(any(a[2].endswith('/keys/.') for a in copies))
        self.assertEqual((self.out/'transfer/pacman.conf').stat().st_mode&0o777,0o644)

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
        wanted=set(self.prepared.iterdir()); m.membership(self.prepared,wanted)
        extra=self.prepared/'unplanned.pkg.tar.xz'; extra.write_bytes(b'inert')
        with self.assertRaises(ValueError): m.membership(self.prepared,wanted)
        extra.unlink(); extra.symlink_to(self.prepared/'pacman.conf')
        with self.assertRaises(ValueError): m.membership(self.prepared,wanted)

    def test_context_extra_directories_and_writable_inputs_refused(self):
        wanted=set(self.prepared.iterdir()); extra=self.prepared/'unplanned'; extra.mkdir()
        with self.assertRaises(ValueError): m.membership(self.prepared,wanted)
        extra.rmdir(); (self.prepared/'pacman.conf').chmod(0o666)
        with self.assertRaises(ValueError): m.membership(self.prepared,wanted)


if __name__=='__main__': unittest.main()
