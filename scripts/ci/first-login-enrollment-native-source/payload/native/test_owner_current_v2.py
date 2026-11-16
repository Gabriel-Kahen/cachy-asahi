# SPDX-License-Identifier: MIT
"""Fenced owner controls: fictional metadata only, never Docker/GPG/actors."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
            'fcntl.flock', 'os.exec', 'os.fork', 'os.system', 'os.posix_spawn'):
        raise RuntimeError('owner DATA controls forbid ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fenced_current_owner', HERE / 'owner_current_v2.py')
O = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = O
spec.loader.exec_module(O)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fiction-owner-data-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'; self.source.mkdir()
        self.output = self.root / 'public'; self.output.mkdir()
        self.image = 'sha256:' + 'a' * 64
        self.uid, self.gid = 12345, 12346
        self.grant = dict(schema=1, selector='FICTION-current-Root-selector', source_date_epoch=100,
            operation='first-login-enrollment-ui-current-v2', stage='backend',
            issuer='Root', approved=True, source_root=str(self.source), output=str(self.output),
            binding=dict(source='b' * 40, ref='refs/heads/codex/FICTION', run='1', job='2',
                         attempt=1, source_lock=dict(bytes=1, sha256='c' * 64)),
            resources=dict(build_seconds=180, builder_cpus=4, builder_memory_bytes=4 * 1024**3,
                           builder_pids=512, total_seconds=600, command_rows=512),
            images={'backend':dict(id=self.image), 'ui':dict(id=self.image),
                    'lifecycle':dict(id=self.image)})

    def generic(self):
        build = self.output / 'builds' / 'enrollment-a'
        name = 'cachy-asahi-' + '1' * 16
        mounts = [f'type=bind,src={build / "inputs"},dst=/inputs,readonly',
                  f'type=bind,src={build / "artifacts"},dst=/out',
                  f'type=bind,src={self.source / "scripts/build/container-entry.sh"},dst=/builder-entry.sh,readonly',
                  f'type=bind,src={build / "expected-packages.lock"},dst=/expected-packages.lock,readonly']
        argv = ['docker', 'run', '--rm', '--name', name, '--pull=never', '--platform', 'linux/arm64',
                '--user', f'{self.uid}:{self.gid}', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--read-only', '--pids-limit', '512', '--memory', '4g', '--cpus', '4',
                '--network', 'none', '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g',
                '--env', 'CACHY_ASAHI_CONTAINER=1', '--env', 'SOURCE_DATE_EPOCH=100']
        for mount in mounts: argv += ['--mount', mount]
        return argv + ['--entrypoint', '/bin/bash', self.image, '/builder-entry.sh']

    def intent(self, argv=None):
        return O.generic_intent(self.generic() if argv is None else argv, self.grant,
                                self.source, self.output, self.uid, self.gid)

    def inspection(self, intent):
        return dict(Id='d' * 64, Name='/' + intent['name'], Image=intent['image'],
            Config=dict(User=intent['user'], Entrypoint=intent['entrypoint'], Cmd=intent['cmd'],
                        Labels=copy.deepcopy(intent['labels'])),
            HostConfig=dict(NetworkMode='none', ReadonlyRootfs=True, Privileged=False,
                PidsLimit=512, Memory=4 * 1024**3, MemorySwap=4 * 1024**3, NanoCpus=4_000_000_000,
                CapDrop=['ALL'], CapAdd=None, SecurityOpt=['no-new-privileges'], Devices=[],
                DeviceRequests=None, VolumesFrom=None, Init=False,
                Tmpfs={'/tmp':'rw,nosuid,nodev,exec,size=4g'}),
            Mounts=[dict(Type='bind', Destination=dst, Source=src, RW=rw)
                    for dst, src, rw in intent['mounts']])

    def test_null_root_grant_refuses_before_any_operational_boundary(self):
        with patch.object(O, 'dependencies', side_effect=AssertionError('unissued owner imported dependencies')):
            for grant in (None, {}, dict(self.grant, issuer=None), dict(self.grant, approved=False)):
                with self.subTest(grant=grant), self.assertRaises((ValueError, KeyError, TypeError, AttributeError)):
                    with O.open_current_session(grant, self.source, self.output):
                        self.fail('unissued session opened')

    def test_exact_generic_provenance_becomes_owned_create(self):
        original = self.generic(); intent = self.intent(original)
        self.assertEqual(intent['image'], self.image)
        self.assertEqual(intent['user'], f'{self.uid}:{self.gid}')
        self.assertEqual(intent['cmd'], ['/builder-entry.sh'])
        self.assertEqual(original, self.generic(), 'declared provenance must not be rewritten')
        create = intent['create_argv']
        self.assertIn('create', create); self.assertNotIn('--rm', create)
        self.assertIn('--memory-swap=4g', create)

    def test_generic_mutated_policy_and_extra_operands_refuse(self):
        original = self.generic()
        for old, new in [('none', 'bridge'), ('4g', '8g'), ('512', '513'), ('4', '8'),
                         ('linux/arm64', 'linux/amd64'), (self.image, 'sha256:'+'e'*64),
                         (f'{self.uid}:{self.gid}', '0:0'), ('/bin/bash', '/bin/sh')]:
            argv = list(original); argv[argv.index(old)] = new
            with self.subTest(old=old, new=new), self.assertRaises((ValueError, KeyError)):
                self.intent(argv)
        for extra in (['--privileged'], ['--env', 'LD_PRELOAD=/FICTION'], ['--label', 'unowned=1']):
            argv = list(original); argv[2:2] = extra
            with self.subTest(extra=extra), self.assertRaises((ValueError, KeyError)):
                self.intent(argv)

    def test_generic_mount_escape_and_unknown_name_refuse(self):
        original = self.generic()
        for index in [i+1 for i, arg in enumerate(original) if arg == '--mount']:
            argv = list(original); argv[index] = argv[index].replace(str(self.output), '/FICTION/foreign').replace(str(self.source), '/FICTION/foreign')
            with self.subTest(mount=index), self.assertRaises((ValueError, KeyError)):
                self.intent(argv)
        argv = list(original); argv[argv.index('--name')+1] = 'cachy-asahi-foreign'
        with self.assertRaises((ValueError, KeyError)): self.intent(argv)

    def test_actual_container_policy_mutations_refuse(self):
        intent = self.intent(); row = self.inspection(intent); token = O.stage_token(self.grant)
        O.inspect_container(row, intent, token)
        changes = [('Name', '/foreign'), ('Image', 'sha256:'+'e'*64)]
        for key, value in changes:
            bad=copy.deepcopy(row); bad[key]=value
            with self.subTest(key=key), self.assertRaises((ValueError, KeyError)):
                O.inspect_container(bad, intent, token)
        for key, value in dict(NetworkMode='bridge', ReadonlyRootfs=False, Privileged=True,
                PidsLimit=513, Memory=5*1024**3, MemorySwap=-1, NanoCpus=2_000_000_000,
                CapDrop=[], CapAdd=['SYS_ADMIN'], Devices=[{'PathOnHost':'/dev/FICTION'}],
                DeviceRequests=[{}], VolumesFrom=['foreign'], Init=True, AutoRemove=True,
                SecurityOpt=['no-new-privileges','seccomp=unconfined'], Tmpfs={}).items():
            bad=copy.deepcopy(row); bad['HostConfig'][key]=value
            with self.subTest(key=key), self.assertRaises((ValueError, KeyError)):
                O.inspect_container(bad, intent, token)
        for key, value in dict(User='0:0', Entrypoint=['/bin/sh'], Cmd=['foreign'], Labels={}).items():
            bad=copy.deepcopy(row); bad['Config'][key]=value
            with self.subTest(key=key), self.assertRaises((ValueError, KeyError)):
                O.inspect_container(bad, intent, token)
        bad=copy.deepcopy(row); bad['Mounts'][0]['RW']=not bad['Mounts'][0]['RW']
        with self.assertRaises((ValueError, KeyError)): O.inspect_container(bad, intent, token)

    def test_host_and_wrong_pid_namespace_refuse_signed_domain(self):
        def proc(path):
            self.assertEqual(path,Path('/proc/1/comm'));return b'bash\n'
        with patch.object(O, '_INSIDE', None), patch.object(O, 'raw', side_effect=AssertionError('host read proc')):
            with self.assertRaises(ValueError): O.signed_local_guard()
        with patch.object(O, '_INSIDE', {'FICTION':True}), \
             patch.object(O.os, 'getuid', return_value=0), patch.object(O.os, 'geteuid', return_value=0), \
             patch.object(O.os, 'uname', return_value=SimpleNamespace(machine='aarch64')), \
             patch.object(O.os, 'getpid', return_value=2), patch.object(O.os, 'getppid', return_value=1), \
             patch.object(O, 'raw', return_value=b'bash\n'), \
             patch.object(O.Path, 'read_bytes', new=proc):
            O.signed_local_guard()
            with patch.object(O.os, 'getppid', return_value=5):
                with self.assertRaises(ValueError): O.signed_local_guard()
            with patch.object(O, 'raw', return_value=b'python3\n'), \
                 patch.object(O.Path, 'read_bytes', return_value=b'python3\n'):
                with self.assertRaises(ValueError): O.signed_local_guard()

    def signed_session(self, failed=False, corrupt_restore=False, retire_failure=False):
        grant=copy.deepcopy(self.grant);grant['stage']='lifecycle'
        public=self.root/'FICTION-public.asc';public.write_bytes(b'FICTION NOT A KEY')
        grant['owner']=dict(test_public_key=dict(path=str(public),**O.pin(public.read_bytes())),test_fingerprint='F'*40,
            lifecycle_capabilities=['CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID'])
        grant['images']['lifecycle']['inventory_pin']={'FICTION':True}
        calls=[];created=[];base=b'fiction-base 1-1\n';retire_calls=[]
        class FakeCommands:
            def __init__(self,output,home,path,**bounds):
                self.output=output;self.records=[];self.env={};self.bounds=bounds;created.append(self)
            def run(self,step,argv,cwd,expected):
                calls.append((step,argv));self.records.append(dict(step=step,argv=argv))
                if step=='current-primary':return ('fpr::::::::: '+'F'*40+':\n').replace(': ',':').encode()
                if step=='failure-inventory':return base+b'cachy-asahi-first-login 0.1.0-3\n'
                if step=='restored-inventory' and corrupt_restore:return base+b'foreign 1-1\n'
                if step in ('baseline-inventory','restored-inventory'):return base
                if step.startswith(('before-','after-')):return b'FICTION install reasons\n'
                return b'FICTION bounded command DATA'
        def retire(run,work,homes):
            retire_calls.append((work,homes));shutil.rmtree(work)
            return dict(failures=['FICTION cleanup refusal'] if retire_failure else [],
                        homes_retired=not retire_failure,no_sockets=True,private_directory_absent=True)
        W=SimpleNamespace(Commands=FakeCommands);T=SimpleNamespace(retire_private=retire)
        A=SimpleNamespace(protected_state=lambda:{'FICTION':'unchanged'})
        R=SimpleNamespace(reference=lambda _:base,PROJECT={'cachy-asahi-first-login':'0.1.0-3'})
        session=O.SignedSession(grant,self.source,self.output,(W,T,A,R))
        private=self.root/'build-tools-test-FICTION'
        def temporary(**kwargs):
            self.assertEqual(kwargs,dict(prefix='build-tools-test-',dir='/tmp'));private.mkdir();return str(private)
        with patch.object(O, 'signed_local_guard'), patch.object(O, '_INSIDE',dict(grant_sha256=O.pin(O.encoded(grant))['sha256'])), \
             patch.object(O.tempfile,'mkdtemp',side_effect=temporary), \
             patch.object(O.os,'uname',return_value=SimpleNamespace(machine='aarch64')):
            session.__enter__()
            lines=Path(session.pacman[1]).read_text().splitlines()
            self.assertEqual(lines,['[options]','Architecture = aarch64','SigLevel = Required','LocalFileSigLevel = Required',
                'GPGDir = '+str(private/'trust'),'HookDir = /builder-disabled-hooks','LogFile = '+str(private/'pacman.log')])
            self.assertEqual(session.verifier,['/usr/bin/gpg','--homedir',str(private/'trust'),'--batch',
                '--no-auto-key-retrieve','--auto-key-locate','clear'])
            self.assertIn(('trust-current-test-primary',session.verifier+['--import-ownertrust',str(private/'ownertrust')]),calls)
            self.assertEqual((private/'ownertrust').read_bytes(),b'F'*40+b':6:\n')
            error=ValueError('FICTION body failure') if failed else None
            if (corrupt_restore or retire_failure) and not failed:
                with self.assertRaises(ValueError):session.__exit__(None,None,None)
            else:session.__exit__(type(error) if error else None,error,None)
        return session,calls,retire_calls,created

    def test_signed_private_trust_forms_and_normal_cleanup_remain_pending_outer(self):
        session,calls,retired,created=self.signed_session()
        self.assertEqual(len(retired),1)
        self.assertEqual(session.cleanup['status'],'PENDING_OUTER_CONTAINER_RETIREMENT')
        self.assertFalse(session.cleanup['owned_container_absence_verified'])
        local=json.loads((self.output/'owner-local.json').read_bytes())
        self.assertEqual(local['status'],'PASS_LOCAL_STAGE_PENDING_OUTER_RETIREMENT')
        self.assertTrue(local['protected_state_unchanged'])
        self.assertTrue(all(c.bounds['max_output']==1024**2 and c.bounds['total']<=600 for c in created))

    def test_signed_body_failure_restores_installed_projects_without_claiming_pass(self):
        session,calls,retired,_=self.signed_session(failed=True)
        remove=next(argv for step,argv in calls if step=='failure-remove-projects')
        self.assertEqual(remove[-1],'cachy-asahi-first-login');self.assertEqual(len(retired),1)
        local=json.loads((self.output/'owner-local.json').read_bytes())
        self.assertEqual(local['status'],'HOLD_LOCAL_STAGE');self.assertFalse(local['body_success'])
        self.assertFalse(session.cleanup['natural_retirement'])

    def test_signed_bad_restoration_or_private_retirement_never_passes(self):
        session,_,retired,_=self.signed_session(corrupt_restore=True)
        self.assertEqual(len(retired),1,'bad restoration must still attempt private TEST retirement')
        self.assertFalse(session.cleanup['protected_state_unchanged'])

    def test_signed_private_retirement_failure_is_hold(self):
        session,_,retired,_=self.signed_session(retire_failure=True)
        self.assertEqual(len(retired),1);self.assertFalse(session.cleanup['protected_state_unchanged'])

    def test_nonempty_owner_label_collision_never_retires_existing_resources(self):
        calls=[]
        class FakeCommands:
            def __init__(self,output,home,path,**bounds):self.output=output;self.records=[]
            def run(self,step,argv,cwd,expected):calls.append((step,argv));return b'FICTION-existing-owned-CID\n'
        session=O.HostSession(self.grant,self.source,self.output,(SimpleNamespace(Commands=FakeCommands),None,None,None))
        with patch.object(O,'require_native_host'):
            with self.assertRaises(ValueError):session.__enter__()
        self.assertEqual([step for step,_ in calls],['fresh-owner-label'])
        self.assertTrue(all('rm' not in argv for _,argv in calls))
        self.assertIsNone(session.cleanup)

    def test_finite_command_budget_refuses_before_fake_runner_construction(self):
        calls=[]
        class FakeCommands:
            def __init__(self,*args,**kwargs):calls.append((args,kwargs))
        W=SimpleNamespace(Commands=FakeCommands)
        with patch.object(O.time,'monotonic',return_value=100):
            with self.assertRaises(ValueError):O.new_commands(W,self.root/'expired',self.root,15,101)
            self.assertFalse(calls)
            O.new_commands(W,self.root/'bounded',self.root,180,2000)
        self.assertEqual(calls[0][1],dict(timeout=180,total=600,max_output=1024**2))

    def test_exact_container_retirement_and_query_errors(self):
        intent=self.intent();row=self.inspection(intent);token=O.stage_token(self.grant)
        for present in (False,True):
            calls=[]
            class FakeCommands:
                output=self.output
                def run(inner,step,argv,cwd,expected):
                    calls.append((step,argv))
                    if step.endswith('-inspect'):return json.dumps([row]).encode()
                    if step.endswith('-query'):return (row['Id']+' '+intent['name']+'\n').encode() if present else b''
                    return b''
            result=O.retire_container(FakeCommands(),intent,token,'FICTION')
            self.assertEqual(result['status'],'REMOVED_AND_ABSENT' if present else 'ABSENT')
            removals=[argv for _,argv in calls if 'rm' in argv]
            self.assertEqual(removals,[O.DOCKER+['container','rm','--force',row['Id']]] if present else [])
        calls=[]
        class QueryError:
            output=self.output
            def run(inner,step,argv,cwd,expected):calls.append(argv);raise ValueError('FICTION query failure')
        with self.assertRaises(ValueError):O.retire_container(QueryError(),intent,token,'FICTION')
        self.assertEqual(len(calls),1);self.assertNotIn('rm',calls[0])

    def test_present_container_identity_mismatch_never_grants_removal(self):
        intent=self.intent();row=self.inspection(intent);row['Image']='sha256:'+'e'*64;calls=[]
        class FakeCommands:
            output=self.output
            def run(inner,step,argv,cwd,expected):
                calls.append(argv)
                return json.dumps([row]).encode() if step.endswith('-inspect') else b'FICTION present\n'
        with self.assertRaises(ValueError):O.retire_container(FakeCommands(),intent,O.stage_token(self.grant),'FICTION')
        self.assertFalse(any('rm' in argv for argv in calls))

    def proxy(self, failed=False):
        intent=self.intent();row=self.inspection(intent)
        row['State']=dict(Running=False,ExitCode=0,OOMKilled=False)
        state=self.root/'proxy-state';state.mkdir();(state/'home').mkdir();(state/'intents').mkdir()
        manifest=state/'proxy.json'
        O.save(manifest,dict(grant=self.grant,source=str(self.source),output=str(self.output),
            deadline=500,uid=self.uid,gid=self.gid))
        calls=[]
        class FakeCommands:
            output=state
            def run(inner,step,argv,cwd,expected):
                calls.append((step,argv))
                if step=='create':return (row['Id']+'\n').encode()
                if step in ('inspect-created','inspect-terminal','proxy-final-inspect'):return json.dumps([row]).encode()
                if step=='start-attached':
                    if failed:raise ValueError('FICTION attached process failure')
                    return b'FICTION complete build output\n'
                if step=='proxy-final-query':return (row['Id']+' '+intent['name']+'\n').encode()
                return b''
        captured=io.BytesIO()
        with patch.object(O,'dependencies',return_value=(None,None,None,None)), \
             patch.object(O,'validate_owner'),patch.object(O.time,'monotonic',return_value=100), \
             patch.object(O.os,'getuid',return_value=self.uid),patch.object(O.os,'getgid',return_value=self.gid), \
             patch.object(O,'new_commands',return_value=FakeCommands()), \
             patch.object(O.sys,'stdout',SimpleNamespace(buffer=captured)):
            if failed:
                with self.assertRaisesRegex(ValueError,'FICTION attached'):O.docker_proxy(manifest,self.generic()[1:])
            else:O.docker_proxy(manifest,self.generic()[1:])
        result=json.loads((state/'intents'/(intent['name']+'.result')).read_bytes())
        self.assertEqual(result['retirement']['status'],'REMOVED_AND_ABSENT')
        self.assertEqual([argv for step,argv in calls if step=='proxy-final-remove'],
                         [O.DOCKER+['container','rm','--force',row['Id']]])
        self.assertEqual(json.loads((state/'intents'/(intent['name']+'.json')).read_bytes())['declared_argv'],self.generic())
        return result,captured.getvalue()

    def test_proxy_normal_completion_retires_only_exact_inspected_container(self):
        result,output=self.proxy()
        self.assertEqual(result['status'],'PASS_OWNED_GENERIC_BUILD_PROXY')
        self.assertEqual(output,b'FICTION complete build output\n')

    def test_proxy_body_failure_still_retires_and_never_passes(self):
        result,output=self.proxy(failed=True)
        self.assertEqual(result['status'],'HOLD');self.assertIn('failure',result);self.assertEqual(output,b'')

    def test_proxy_null_admission_refuses_before_dependency_or_runner(self):
        path=self.root/'FICTION-unissued-proxy.json';O.save(path,dict(grant=None))
        with patch.object(O,'dependencies',side_effect=AssertionError('NULL imported dependencies')), \
             patch.object(O,'new_commands',side_effect=AssertionError('NULL constructed runner')):
            with self.assertRaises((ValueError,TypeError,AttributeError)):O.docker_proxy(path,['info'])

    def signed_intent(self):
        grant=copy.deepcopy(self.grant);grant['stage']='lifecycle'
        output=self.root/'fresh-lifecycle-output'/'public';output.parent.mkdir()
        grant['output']=str(output)
        owner=str(HERE/'owner_current_v2.py');manifest=str(self.root/'private-carrier'/'inside.json')
        desc=lambda path,sha='f'*64:dict(path=str(path),bytes=1,sha256=sha)
        admission=self.root/'Root-admission.json';inputs=self.root/'inputs.json'
        grant['owner']=dict(code=desc(owner),launch_manifest=manifest,input_references=[],
            admission_path=str(admission),inputs=desc(inputs),lifecycle_capabilities=list(O.CAPABILITIES))
        grant['signed']={'FICTION':dict(archive=str(self.root/'input.archive'),signature=str(self.root/'input.signature'))}
        refs={str(O.ROOT/n):desc(Path(manifest).parent/('code-'+str(i)),sha) for i,(n,sha) in enumerate(O.DEPS.items())}
        refs[owner]=desc(Path(manifest).parent/('code-'+str(len(O.DEPS))));refs[manifest]=desc(manifest)
        intent=O.signed_intent(grant,self.source,output,admission,inputs,refs)
        return grant,intent,(self.source,output,admission,inputs,refs)

    def test_signed_outer_vector_has_only_admitted_capabilities_and_mounts(self):
        grant,intent,args=self.signed_intent()
        self.assertEqual(intent['user'],'0:0');self.assertFalse(intent['readonly'])
        self.assertEqual(intent['capadd'],['CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID'])
        vector=intent['create_argv'];self.assertIn('--init=false',vector);self.assertNotIn('--privileged',vector)
        self.assertEqual(intent['entrypoint'],['/bin/bash'])
        self.assertIn('; status=$?; exit "$status"',intent['cmd'][1]);self.assertNotIn('exec ',intent['cmd'][1])
        mounts={d:(s,rw) for d,s,rw in intent['mounts']}
        self.assertEqual([d for d,(s,rw) in mounts.items() if rw],[str(args[1].parent)])
        for path in (args[0],args[2],args[3]):self.assertEqual(mounts[str(path)],(str(path),False))
        self.assertFalse(any(d in ('/var/run/docker.sock','/run/docker.sock','/etc','/root','/home/alarm') for d in mounts))
        row=self.inspection(intent);row['HostConfig']['ReadonlyRootfs']=False
        row['HostConfig']['CapAdd']=list(O.CAPABILITIES);row['HostConfig']['Tmpfs']={}
        O.inspect_container(row,intent,O.stage_token(grant))
        row['HostConfig']['CapAdd'].append('SYS_ADMIN')
        with self.assertRaises(ValueError):O.inspect_container(row,intent,O.stage_token(grant))

    def test_signed_intent_refuses_unpinned_extra_code_and_broad_capabilities(self):
        grant,_,args=self.signed_intent()
        for capabilities in ([],list(O.CAPABILITIES)+['SYS_ADMIN']):
            bad=copy.deepcopy(grant);bad['owner']['lifecycle_capabilities']=capabilities
            with self.assertRaises(ValueError):O.signed_intent(bad,*args)
        bad=copy.deepcopy(args[-1]);bad['/FICTION/ambient.py']=dict(path='/FICTION/carrier',bytes=1,sha256='f'*64)
        with self.assertRaises(ValueError):O.signed_intent(grant,*args[:-1],bad)
        bad=copy.deepcopy(args[-1]);bad.pop(next(iter(bad)))
        with self.assertRaises(ValueError):O.signed_intent(grant,*args[:-1],bad)

    def test_signed_intent_refuses_protected_socket_and_output_input_overlap(self):
        grant,_,args=self.signed_intent()
        for path in ('/etc/FICTION-host-state','/var/run/docker.sock','/run/docker.sock',
                     str(args[1].parent/'FICTION-input.archive')):
            bad=copy.deepcopy(grant);bad['signed']['FICTION']['archive']=path
            with self.subTest(path=path),self.assertRaises(ValueError):O.signed_intent(bad,*args)
        bad=copy.deepcopy(args[-1]);destination=next(d for d in bad if d in {str(O.ROOT/n) for n in O.DEPS})
        bad[destination]['path']=str(args[1].parent/'FICTION-executable-carrier')
        with self.assertRaises(ValueError):O.signed_intent(grant,*args[:-1],bad)

    def finalization(self):
        grant,intent,args=self.signed_intent();row=self.inspection(intent)
        row['HostConfig'].update(ReadonlyRootfs=False,CapAdd=list(O.CAPABILITIES),Tmpfs={})
        row['State']=dict(Running=False,ExitCode=0,OOMKilled=False)
        bound=dict(operation=O.OP,stage='lifecycle',binding=grant['binding'])
        report=dict(bound,status='PENDING_OUTER_CURRENT_STAGE_RETIREMENT',Root_acceptance=None)
        local=dict(bound,status='PASS_LOCAL_STAGE_PENDING_OUTER_RETIREMENT',body_success=True,
                   protected_state_unchanged=True,failures=[])
        receipt=dict(bound,status='PASS_OWNED_CURRENT_LIFECYCLE_RETIREMENT',intent=intent,code_refs=args[-1],created=row,
            terminal=copy.deepcopy(row),retirement=dict(status='REMOVED_AND_ABSENT',cid=row['Id'],inspection=copy.deepcopy(row)))
        expected={'create':intent['create_argv'],'inspect-created':O.DOCKER+['container','inspect',row['Id']],
            'start-attached':O.DOCKER+['container','start','--attach',row['Id']],
            'inspect-terminal':O.DOCKER+['container','inspect',row['Id']],
            'retire-inspect':O.DOCKER+['container','inspect',intent['name']],
            'retire-remove':O.DOCKER+['container','rm','--force',row['Id']],
            'retire-after':O.DOCKER+['container','ls','--all','--no-trunc','--filter','name=^/'+intent['name']+'$','--format','{{.ID}} {{.Names}}']}
        receipt['commands']=[dict(step=step,argv=argv,expected=0,success=True,log_pin=O.pin(b''),
            supervision=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,
                             timeout=False,signals=[],error=None,exit=0)) for step,argv in expected.items()]
        return report,local,receipt,grant

    def test_only_outer_finalization_joins_natural_retirement_and_absence(self):
        report,local,receipt,grant=self.finalization();original=copy.deepcopy(report)
        result=O.finalize_current(report,local,receipt,grant)
        self.assertEqual(result['status'],'PASS_CURRENT_ONBOARDING_OWNED_STAGE_DATA_ONLY')
        self.assertTrue(result['owner_cleanup']['owned_container_absence_verified'])
        self.assertIsNone(result['Root_acceptance']);self.assertEqual(report,original)

    def test_finalizer_refuses_incomplete_local_state_or_unsafe_outer_receipts(self):
        report,local,receipt,grant=self.finalization()
        mutations=[('local-status',lambda l,r:l.update(status='HOLD_LOCAL_STAGE')),
            ('protected',lambda l,r:l.update(protected_state_unchanged=False)),
            ('terminal-cid',lambda l,r:r['terminal'].update(Id='e'*64)),
            ('oom',lambda l,r:r['terminal']['State'].update(OOMKilled=True)),
            ('absence',lambda l,r:r['retirement'].update(status='ABSENT')),
            ('query-output',lambda l,r:r['commands'][-1].update(log_pin=O.pin(b'foreign\n'))),
            ('signals',lambda l,r:r['commands'][2]['supervision'].update(signals=[15])),
            ('wrong-argv',lambda l,r:r['commands'][0].update(argv=['/FICTION/foreign'])),
            ('duplicate',lambda l,r:r['commands'].append(copy.deepcopy(r['commands'][0])))]
        for name,mutate in mutations:
            l,r=copy.deepcopy(local),copy.deepcopy(receipt);mutate(l,r)
            with self.subTest(name=name),self.assertRaises((ValueError,KeyError)):
                O.finalize_current(report,l,r,grant)

    def test_finalizer_does_not_use_mutated_intent_as_its_own_launch_policy(self):
        report,local,receipt,grant=self.finalization()
        receipt['intent']['entrypoint']=['/bin/sh']
        argv=receipt['intent']['create_argv'];argv[argv.index('--entrypoint')+1]='/bin/sh'
        for row in (receipt['created'],receipt['terminal'],receipt['retirement']['inspection']):
            row['Config']['Entrypoint']=['/bin/sh']
        with self.assertRaises(ValueError):O.finalize_current(report,local,receipt,grant)


if __name__ == '__main__': unittest.main()
