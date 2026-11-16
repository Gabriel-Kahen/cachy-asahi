# SPDX-License-Identifier: MIT
"""Fenced delegated-owner metadata controls; never dispatch or invoke a role."""
import copy
import importlib.util
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.')) or event in (
            'os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
        raise RuntimeError('delegated owner DATA controls forbid '+event)


sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fenced_delegated_owner',HERE/'owner_delegated_v3.py')
O=importlib.util.module_from_spec(spec);sys.modules[spec.name]=O;spec.loader.exec_module(O)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='fiction-delegated-owner-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)

    def delegation(self):
        return dict(schema=3,kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3',issuer='Root',approved=True,
            scope='CURRENT_PRIVATE_STAGE_ONLY',stage='backend',nonce='a'*64,expires_epoch=4102444800,
            image_ids=dict(backend=None,ui=None,lifecycle=None),binding=dict(source='b'*40,run=None,job=None),
            Root_final_acceptance=None,independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False)

    def test_new_private_scope_preserves_future_ids_and_cannot_be_promoted(self):
        d=self.delegation();body=O.encoded(d)
        self.assertEqual(O.scope(body,O.pin(body)['sha256']),d)
        for field,value in [('kind','ROOT_CURRENT_STAGE_ADMISSION_V2'),('scope','ROOT_IMAGE_QUALIFICATION'),
                ('Root_final_acceptance',True),('independent_component_acceptance',True),('hardware_acceptance',True),
                ('release_acceptance',True),('image_ids',dict(backend='sha256:'+'c'*64,ui=None,lifecycle=None)),
                ('binding',dict(source='b'*40,run='1',job=None))]:
            bad=copy.deepcopy(d);bad[field]=value;body=O.encoded(bad)
            with self.subTest(field=field),self.assertRaises((ValueError,TypeError,KeyError)):
                O.scope(body,O.pin(body)['sha256'])

    def test_null_and_old_root_scope_refuse_without_dispatch(self):
        for value in (None,{},dict(schema=1,issuer='Root',approved=True,
                operation='first-login-enrollment-ui-current-v2',stage='backend')):
            body=O.encoded(value)
            with self.subTest(value=value),self.assertRaises((ValueError,KeyError,TypeError,AttributeError)):
                O.scope(body,O.pin(body)['sha256'])
            with patch.object(O,'load',side_effect=AssertionError('NULL loaded Source code')), \
                 patch.object(O,'modules',side_effect=AssertionError('NULL imported held helpers')), \
                 self.assertRaises((ValueError,KeyError,TypeError,AttributeError)):
                O.open_delegated_session(delegation_raw=body,delegation_sha256=O.pin(body)['sha256'],
                    context=None,image_report=None,executor=None,source_root=self.root,output=self.root/'out',inputs=None)
        body=O.encoded(None)
        with self.assertRaises(ValueError):O.scope(body,'0'*64)

    def test_only_exact_current_test_primary_and_ultimate_trust_accept(self):
        signer='A'*40
        status=('[GNUPG:] VALIDSIG '+signer+' 2026-11-16 1 0 4 0 1 10 00 '+signer+
                '\n[GNUPG:] TRUST_ULTIMATE\n').encode()
        O.strict_signature(status,signer)
        for bad in (status+status,status+b'[GNUPG:] KEYEXPIRED 1\n',status+b'[GNUPG:] REVKEYSIG A\n',
                status.replace(b'TRUST_ULTIMATE',b'TRUST_UNDEFINED'),status.replace(signer.encode(),b'B'*40),
                status.replace(signer.encode(),b'B'*40,1)):
            with self.subTest(bad=bad),self.assertRaises(ValueError):O.strict_signature(bad,signer)

    def test_material_is_closed_source_relative_whole_data_and_never_calls_helper(self):
        path=self.root/'inputs/FICTION';path.parent.mkdir();path.write_bytes(b'FICTION DATA')
        d=dict(materials={'public':dict(member='inputs/FICTION',**O.pin(b'FICTION DATA'))})
        H=SimpleNamespace(resolve_material=lambda *a:(_ for _ in ()).throw(AssertionError('unexpected external helper')))
        self.assertEqual(O.material(H,d,self.root,'public'),dict(path=str(path),**O.pin(b'FICTION DATA')))
        for member in ('../outside','/absolute','inputs/../FICTION','inputs//FICTION','./inputs/FICTION','inputs\\FICTION'):
            bad=copy.deepcopy(d);bad['materials']['public']['member']=member
            with self.subTest(member=member),self.assertRaises(ValueError):O.material(H,bad,self.root,'public')
            with patch.object(O,'raw',side_effect=AssertionError('traversal reached DATA read')),self.assertRaises(ValueError):
                O.load(self.root,dict(member=member,bytes=1,sha256='f'*64),'never_imported')
        with self.assertRaises(ValueError):O.material(H,d,self.root,'unknown')
        path.write_bytes(b'CHANGED')
        with self.assertRaises(ValueError):O.material(H,d,self.root,'public')

    def runner(self,change=None,stdout=b'FICTION STDOUT',stderr=b'FICTION STDERR'):
        calls=[]
        class FakeExecutor:
            def run(inner,step,argv,seconds,*,expected=0):
                calls.append((step,argv,seconds,expected))
                row=dict(step=step,argv=argv,expected=expected,exit=expected,output_pin=O.pin(stdout),stderr_pin=O.pin(stderr),
                    supervision=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,
                        timeout=False,signals=[],error=None,exit=expected))
                result=dict(stdout=stdout,receipt=row)
                if change:change(result)
                return result
        run=O.Runner(FakeExecutor(),self.root/('runner-'+str(len(list(self.root.glob('runner-*'))))),
                     dict(command_rows=2,max_command_seconds=180),deadline=500)
        return run,calls

    def test_runner_uses_exact_executor_api_and_retains_original_bytes_receipt(self):
        run,calls=self.runner();argv=['/usr/bin/NEVER_EXECUTED','FICTION']
        with patch.object(O.time,'monotonic',return_value=100):
            self.assertEqual(run.run('fixture',argv,timeout_seconds=30),b'FICTION STDOUT')
        self.assertEqual(calls,[('fixture',argv,30,0)])
        self.assertEqual((run.directory/'fixture.stdout').read_bytes(),b'FICTION STDOUT')
        self.assertEqual(O.decode((run.directory/'fixture.json').read_bytes()),run.records[0])
        self.assertEqual(run.records[0]['executor_receipt']['stderr_pin'],O.pin(b'FICTION STDERR'))
        with patch.object(O.time,'monotonic',return_value=100),self.assertRaises(ValueError):run.run('fixture',argv)
        self.assertEqual(len(calls),1)

    def test_runner_rejects_changed_or_nonnatural_executor_receipts(self):
        changes=[lambda r:r['receipt'].update(argv=['/FICTION/foreign']),
            lambda r:r['receipt'].update(output_pin=O.pin(b'FOREIGN')),
            lambda r:r['receipt'].update(expected=1),lambda r:r['receipt'].update(exit=1),
            lambda r:r['receipt']['supervision'].update(signals=[15]),
            lambda r:r['receipt']['supervision'].update(timeout=True),
            lambda r:r['receipt']['supervision'].update(ownership='UNKNOWN'),
            lambda r:r['receipt']['supervision'].update(emergency_retirement=True),
            lambda r:r['receipt']['supervision'].update(forced_cleanup=True),
            lambda r:r['receipt']['supervision'].update(ownership_lost=True)]
        for i,change in enumerate(changes):
            run,_=self.runner(change)
            with self.subTest(change=i),patch.object(O.time,'monotonic',return_value=100),self.assertRaises(ValueError):
                run.run('fixture',['/usr/bin/NEVER_EXECUTED'])
            self.assertFalse(run.records);self.assertEqual(O.decode((run.directory/'commands.json').read_bytes()),[])
            self.assertEqual({p.name for p in run.directory.iterdir()},{'commands.json'})

    def test_runner_expired_or_invalid_argv_refuses_before_executor(self):
        run,calls=self.runner()
        with patch.object(O.time,'monotonic',return_value=500),self.assertRaises(ValueError):run.run('late',['/usr/bin/NEVER_EXECUTED'])
        for argv in ([],['relative'],['/usr/bin/NEVER_EXECUTED','bad\0argument']):
            with self.subTest(argv=argv),self.assertRaises(ValueError):run.run('invalid',argv)
        self.assertFalse(calls)

    def test_trust_retirement_requires_actual_exit_two_empty_stdout_and_exact_separate_stderr(self):
        diagnostic=b'gpg-connect-agent: no gpg-agent running in this session\n'
        for mode in ('complete','zero-exit','stdout-substitution','wrong-stderr','missing-stderr','forced'):
            directory=self.root/mode;directory.mkdir();private=directory/'private';home=private/'trust';home.mkdir(parents=True)
            calls=[]
            class Executor:
                def run(inner,step,argv,seconds,*,expected=0):
                    calls.append((step,argv,expected));is_probe=step=='no-agent-private-0'
                    out=diagnostic if is_probe and mode=='stdout-substitution' else b''
                    err=(b'foreign' if mode=='wrong-stderr' else diagnostic)if is_probe else b''
                    code=0 if is_probe and mode=='zero-exit' else expected
                    supervision=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,
                        timeout=False,signals=[],error=None,exit=code)
                    if is_probe and mode=='forced':supervision['forced_cleanup']=True
                    row=dict(step=step,argv=argv,expected=expected,exit=code,output_pin=O.pin(out),stderr_pin=O.pin(err),supervision=supervision)
                    result=dict(stdout=out,receipt=row)
                    if not(is_probe and mode=='missing-stderr'):result['stderr']=err
                    return result
            runner=O.Runner(Executor(),directory/'commands',dict(command_rows=4,max_command_seconds=180),deadline=500)
            session=SimpleNamespace(private=private,homes=[home],runner=runner,records=runner.records)
            with self.subTest(mode=mode),patch.object(O.time,'monotonic',return_value=100):
                if mode=='complete':O.Session.retire_trust(session)
                else:
                    with self.assertRaises(ValueError):O.Session.retire_trust(session)
            self.assertEqual(calls[-1][0],'no-agent-private-0');self.assertEqual(calls[-1][2],2)
            self.assertEqual(private.exists(),mode!='complete')
            if mode=='complete':
                rows=O.decode((runner.directory/'commands.json').read_bytes())
                self.assertEqual(rows[-1]['exit'],2);self.assertEqual(rows[-1]['expected'],2)
                self.assertEqual((runner.directory/'no-agent-private-0.stdout').read_bytes(),b'')
                self.assertEqual((runner.directory/'no-agent-private-0.stderr').read_bytes(),diagnostic)

    def test_local_retirement_adapts_only_the_registered_no_agent_command_with_real_held_helpers(self):
        tools_member=O.FAMILY+'/payload/native/build_tools_tools_v2.py';callback_member=O.FAMILY+'/payload/native/owner_current_v2.py'
        tools=O.load(O.ROOT,dict(member=tools_member,**O.pin(O.raw(O.ROOT/tools_member))),'fenced_local_retirement_tools')
        callbacks=O.load(O.ROOT,dict(member=callback_member,**O.pin(O.raw(O.ROOT/callback_member))),'fenced_local_retirement_callbacks')
        self.assertEqual(O.pin(O.raw(O.ROOT/tools_member))['sha256'],O.HELD[tools_member])
        self.assertEqual(O.pin(O.raw(O.ROOT/callback_member))['sha256'],'f1a91dee080f76eff88409dd1fe893dc45a2084338017f367ec9874a462a612d')
        diagnostic=b'gpg-connect-agent: no gpg-agent running in this session\n'
        for mode in ('complete','wrong-exit','forced','wrong-diagnostic','foreign-home'):
            work=Path(tempfile.mkdtemp(prefix='build-tools-test-'));self.addCleanup(shutil.rmtree,work,ignore_errors=True)
            homes=[work/'one',work/'two']
            for home in homes:home.mkdir(mode=0o700)
            class Commands:
                def __init__(inner):inner.records=[];inner.output=self.root/mode
                def run(inner,step,argv,cwd,expected):
                    probe=argv[0]=='/usr/bin/gpg-connect-agent';out=diagnostic if probe else b''
                    if probe and mode=='wrong-diagnostic':out=b'foreign diagnostic'
                    actual=0 if probe and mode=='wrong-exit' else expected
                    supervision=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,
                        timeout=False,signals=[],error=None,exit=actual)
                    if probe and mode=='forced':supervision['forced_cleanup']=True
                    row=dict(step=step,argv=argv,expected=expected,success=True,log_pin=O.pin(out),supervision=supervision,
                        channels='stdout+stderr combined in pipe order')
                    inner.records.append(row);return out
            admin=Commands();local=SimpleNamespace(work=work,homes=homes,admin=admin,deps=(None,tools))
            if mode=='foreign-home':
                def foreign(run,where,registered):
                    run('no-agent-private-0',['/usr/bin/gpg-connect-agent','--homedir','/FICTION/foreign','--no-autostart','/bye'])
                local.deps=(None,SimpleNamespace(retire_private=foreign))
            with self.subTest(mode=mode):
                if mode=='complete':
                    result=O.local_retire_trust(local,callbacks);self.assertTrue(result['homes_retired']);self.assertFalse(work.exists())
                    self.assertEqual([r['expected']for r in admin.records],[0,2,0,2])
                    self.assertEqual([r['supervision']['exit']for r in admin.records],[0,2,0,2])
                else:
                    with self.assertRaises(ValueError):O.local_retire_trust(local,callbacks)
            if mode=='foreign-home':self.assertEqual(admin.records,[])

    def image(self):
        d=self.delegation();c=dict(stage='backend',binding=d['binding'],delegation_pin=O.pin(O.encoded(d)),nonce=d['nonce'])
        packages={'base%03d'%i:'1-1' for i in range(349)}|{'cachy-asahi-setup':'0.3.0-1'}
        inventory=''.join(n+' '+v+'\n' for n,v in sorted(packages.items())).encode()
        report=dict(status='PROVISIONAL_CURRENT_IMAGE_CONSTRUCTED_DATA_ONLY',operation=O.OP,stage='backend',binding=c['binding'],
            delegation_pin=c['delegation_pin'],owner_executor_facts=dict(nonce=c['nonce']),Root_final_acceptance=None,
            independent_image_qualification=None,packages=packages,inventory_pin=dict(path='/FICTION/inventory',**O.pin(inventory)),
            image_id='sha256:'+'c'*64)
        return d,c,report,inventory

    def test_image_observation_is_provisional_and_joins_actual_inventory_nonce(self):
        d,c,report,inventory=self.image();result=O.image_data(report,d,c,inventory)
        self.assertEqual(result,dict(id=report['image_id'],packages=report['packages'],inventory_pin=report['inventory_pin']))
        for key,value in [('status','ROOT_REVIEWED_CURRENT_ONBOARDING_IMAGE_V2'),('Root_final_acceptance',True),
                ('independent_image_qualification',{'issuer':'Root'}),('issuer','Root'),('image_id','mutable:tag'),
                ('owner_executor_facts',{'nonce':'f'*64})]:
            bad=copy.deepcopy(report);bad[key]=value
            with self.subTest(key=key),self.assertRaises((ValueError,KeyError)):O.image_data(bad,d,c,inventory)
        with self.assertRaises(ValueError):O.image_data(report,d,c,inventory+b'foreign 1-1\n')

    def actor(self):
        d=self.delegation();c=dict(stage='backend',binding=d['binding'],nonce=d['nonce'])
        mounts=[['/inputs',str(self.root/'inputs'),False],['/out',str(self.root/'artifacts'),True],
                ['/builder-entry.sh',str(self.root/'source/scripts/build/container-entry.sh'),False],
                ['/expected-packages.lock',str(self.root/'packages.lock'),False]]
        intent=O.intent(c,'sha256:'+'c'*64,'cachy-private-fiction','12345:12346',['/builder-entry.sh'],mounts,
            readonly=True,tmpfs={'/tmp':'rw,nosuid,nodev,exec,size=4g'})
        row=dict(Id='d'*64,Name='/'+intent['name'],Image=intent['image'],
            Config=dict(User=intent['user'],Entrypoint=['/bin/bash'],Cmd=intent['cmd'],Labels=intent['labels']),
            HostConfig=dict(NetworkMode='none',Privileged=False,ReadonlyRootfs=True,CapDrop=['ALL'],CapAdd=[],
                SecurityOpt=['no-new-privileges'],Devices=[],DeviceRequests=None,VolumesFrom=None,Tmpfs=intent['tmpfs'],
                Memory=4*1024**3,MemorySwap=4*1024**3,NanoCpus=4*10**9,PidsLimit=512,Init=False,AutoRemove=False,
                PidMode='',UTSMode='',IpcMode='private'),
            Mounts=[dict(Type='bind',Destination=d,Source=s,RW=rw) for d,s,rw in mounts])
        return c,intent,row

    def test_private_build_vector_has_exact_endpoint_resources_and_delegated_labels(self):
        c,intent,row=self.actor();endpoint='unix:///tmp/FICTION-private-docker.sock'
        vector=O.create_argv(endpoint,intent,env=['SOURCE_DATE_EPOCH=17'])
        self.assertEqual(vector[:4],['/usr/bin/docker','--host='+endpoint,'container','create'])
        for flag in ('--memory=4g','--memory-swap=4g','--cpus=4','--pids-limit=512','--init=false','--network=none','--read-only'):
            self.assertIn(flag,vector)
        self.assertIn('SOURCE_DATE_EPOCH=17',vector)
        self.assertEqual(intent['labels']['org.cachy-asahi.current-private.scope'],'DELEGATED_PRIVATE_TEST_ONLY')
        self.assertEqual(O.container(row,intent,c),'d'*64)
        for endpoint in ('unix:///var/run/docker.sock','unix:///run/docker.sock','tcp://FICTION:2375'):
            with self.subTest(endpoint=endpoint),self.assertRaises(ValueError):O.create_argv(endpoint,intent)

    def test_live_metadata_cannot_substitute_root_scope_mounts_or_weaken_limits(self):
        c,intent,row=self.actor()
        for key,value in dict(NetworkMode='bridge',Privileged=True,ReadonlyRootfs=False,MemorySwap=-1,
                Memory=5*1024**3,NanoCpus=2*10**9,PidsLimit=513,CapAdd=['SYS_ADMIN'],Init=True,
                VolumesFrom=['foreign'],Devices=[{}],PidMode='host').items():
            bad=copy.deepcopy(row);bad['HostConfig'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):O.container(bad,intent,c)
        bad=copy.deepcopy(row);bad['Config']['Labels']['org.cachy-asahi.current-private.scope']='ROOT_ACCEPTED'
        with self.assertRaises(ValueError):O.container(bad,intent,c)
        bad=copy.deepcopy(row);bad['Mounts'][0]['RW']=True
        with self.assertRaises(ValueError):O.container(bad,intent,c)

    def test_request_joins_independently_admitted_actual_executor_kernel_facts(self):
        d,c,report,inventory=self.image();source=self.root/'FICTION-source';path=source/'inputs/stages/backend.expected.lock'
        path.parent.mkdir(parents=True);path.write_bytes(inventory)
        d['programs']={'image':{'member':'FICTION-image.py'}};c['delegation_pin']=O.pin(O.encoded(d));report['delegation_pin']=c['delegation_pin']
        facts=dict(nonce=d['nonce'],docker_endpoint='unix:///tmp/FICTION-private.sock',architecture='aarch64',
            kernel=dict(cgroup_version=2,memory_max=4*1024**3,memory_swap_max=0,cpu_max='400000 100000',pids_max=512))
        report.update(owner_executor_facts=copy.deepcopy(facts),protected_before={'FICTION':True},protected_after={'FICTION':True},
                      cleanup=dict(errors=[],retained_target_image_unqualified=report['image_id']))
        executor=SimpleNamespace(facts=facts);policy={'FICTION':'reviewed'};H=object();calls=[]
        class Image:
            def admit(inner,*args):calls.append(args);return d,c,policy,None
        inputs=dict(schema=3,kind='DELEGATED_CURRENT_PRIVATE_INPUTS_V3',source_date_epoch=17)
        with patch.object(O,'source_request',return_value=(d,c,policy,H)),patch.object(O,'load',return_value=Image()), \
             patch.object(O,'modules',return_value=(object(),object(),object(),{})):
            result=O.request(b'FICTION','f'*64,None,source,inputs,report,executor)
            self.assertEqual(calls[0],(b'FICTION','f'*64,None,source,executor,H))
            self.assertEqual(result['image']['id'],report['image_id'])
            executor.facts=copy.deepcopy(facts);executor.facts['kernel']['memory_max']=8*1024**3
            with self.assertRaises(ValueError):O.request(b'FICTION','f'*64,None,source,inputs,report,executor)
        with patch.object(O,'source_request',return_value=(d,c,policy,H)), \
             patch.object(O,'load',return_value=SimpleNamespace(admit=lambda *a:(_ for _ in ()).throw(ValueError('FICTION independent admission HOLD')))), \
             patch.object(O,'modules',side_effect=AssertionError('admission HOLD imported helper')):
            with self.assertRaisesRegex(ValueError,'independent admission HOLD'):O.request(b'FICTION','f'*64,None,source,inputs,report,executor)

    def test_root_signature_decision_is_exact_package_body_authority_and_never_opened_history(self):
        archive=b'FICTION ARCHIVE';signature=b'FICTION SIGNATURE';public=dict(path='/FICTION/public.asc',**O.pin(b'FICTION PUBLIC'))
        fingerprint='A'*40;key=dict(O.pin(b'FICTION PUBLIC'),fingerprint=fingerprint,trust_scope='TEST_ONLY')
        proof=dict(schema=1,Root_issuer='Root',status='ROOT_VERIFIED_PUBLIC_TEST_SIGNATURE',verified=True,trust_scope='TEST_ONLY',
                   archive=O.pin(archive),signature=O.pin(signature),public_test_key=key)
        decision=dict(schema=1,issuer='Root',accepted=True,holds_preserved=True,status='ACCEPTED_PRIVATE_SETUP8_PACKAGE_TEST_ONLY',
            trust_scope='TEST_ONLY',archive=dict(O.pin(archive),package='cachy-asahi-setup',version='0.3.0-1',arch='any'),
            signature=O.pin(signature),public_test_key=key,verification_proof_sha256=O.pin(O.encoded(proof))['sha256'],
            public_test_key_file='/HISTORICAL/NEVER_OPENED',signature_file='/HISTORICAL/NEVER_OPENED.sig')
        with patch.object(O,'raw',side_effect=AssertionError('historical role operand opened')):
            result=O.decision(O.encoded(decision),O.encoded(proof),archive,signature,public,fingerprint,'cachy-asahi-setup','0.3.0-1')
        self.assertEqual(result['Root_decision_pin'],O.pin(O.encoded(decision)))
        for field,value in [('issuer','DELEGATED_CURRENT_OWNER_V3'),('accepted',False),('holds_preserved',False),('trust_scope','SYSTEM')]:
            changed=copy.deepcopy(decision);changed[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                O.decision(O.encoded(changed),O.encoded(proof),archive,signature,public,fingerprint,'cachy-asahi-setup','0.3.0-1')
        changed=copy.deepcopy(proof);changed['verified']=False;decision['verification_proof_sha256']=O.pin(O.encoded(changed))['sha256']
        with self.assertRaises(ValueError):O.decision(O.encoded(decision),O.encoded(changed),archive,signature,public,fingerprint,'cachy-asahi-setup','0.3.0-1')

    def actor_session(self,mode=None):
        c,intent,metadata=self.actor();d=self.delegation();d['capability']=dict(total_seconds=600,max_command_seconds=180,command_rows=512)
        c['delegation_pin']=O.pin(O.encoded(d));output=self.root/'session-output';output.mkdir();calls=[]
        present=False
        class Executor:
            facts=dict(docker_endpoint='unix:///tmp/FICTION-private.sock',nonce=c['nonce'],uid=12345,gid=12346)
            deadline=700
            def run(inner,step,argv,seconds,*,expected=0):
                nonlocal present
                calls.append((step,argv));self.assertEqual(argv[:2],['/usr/bin/docker','--host=unix:///tmp/FICTION-private.sock'])
                if step.endswith('-fresh'):body=b'FICTION collision\n' if mode=='collision' else b''
                elif step.endswith('-create'):present=True;body=(metadata['Id']+'\n').encode()
                elif step.endswith('-attach'):
                    if mode=='attach-failure':raise ValueError('FICTION attached actor failure')
                    body=b'FICTION BUILD OUTPUT'
                elif step.endswith(('-created','-terminal','-inspect')):
                    observed=copy.deepcopy(metadata)
                    if mode=='running':observed['State']=dict(Running=True,ExitCode=0,OOMKilled=False)
                    else:observed['State']=dict(Running=False,ExitCode=0,OOMKilled=False)
                    body=O.encoded([observed])
                elif step.endswith('-query'):
                    if mode=='query-failure':raise ValueError('FICTION discovery query failure')
                    body=(metadata['Id']+' '+intent['name']+'\n').encode() if present else b''
                elif step.endswith('-remove'):present=False;body=(metadata['Id']+'\n').encode()
                elif '-after-'in step:body=b''
                else:raise AssertionError('unexpected fake executor step '+step)
                receipt=dict(step=step,argv=argv,expected=expected,exit=expected,output_pin=O.pin(body),stderr_pin=O.pin(b''),
                    supervision=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,
                        timeout=False,signals=[],error=None,exit=expected))
                return dict(stdout=body,receipt=receipt)
        tools=SimpleNamespace(snapshot_receipt=lambda path:{'FICTION':'unchanged'})
        plan=dict(d=d,c=c,policy={},image=dict(id=intent['image']),profile={},native=object(),tools=tools,alpm=object(),protected_fn=lambda _:{str(self.root/'FICTION-protected'):{'FICTION':'unchanged'}})
        with patch.object(O.time,'monotonic',return_value=100):session=O.Session(plan,self.root/'Source',output,{},None,Executor())
        session.before={str(self.root/'FICTION-protected'):{'FICTION':'unchanged'}}
        return session,intent,calls

    def test_controlled_actor_records_full_identity_and_natural_exact_retirement(self):
        session,intent,calls=self.actor_session()
        with patch.object(O.time,'monotonic',return_value=100):
            output,state=session.actor(intent,'fixture')
            session.__exit__(None,None,None)
        self.assertEqual(output,b'FICTION BUILD OUTPUT');self.assertTrue(state['retired'])
        self.assertEqual(state['retirement']['status'],'REMOVED_AND_ABSENT')
        self.assertEqual([argv[-1]for step,argv in calls if step.endswith('-remove')],['d'*64])
        self.assertEqual(sum('-after-'in step for step,_ in calls),2)
        self.assertTrue(session.cleanup['natural_retirement']);self.assertIsNone(session.cleanup['Root_final_acceptance'])

    def test_controlled_actor_failure_collision_and_discovery_errors_never_promote(self):
        for mode in ('collision','attach-failure','query-failure'):
            case=self.root/mode;case.mkdir();prior=self.root;self.root=case
            try:
                session,intent,calls=self.actor_session(mode)
                with patch.object(O.time,'monotonic',return_value=100):
                    with self.assertRaises(ValueError):session.actor(intent,'fixture')
                    session.__exit__(ValueError,ValueError('FICTION body held'),None)
                self.assertEqual(session.cleanup['status'],'HOLD_DELEGATED_CURRENT_STAGE_RETIREMENT')
                if mode=='collision':self.assertFalse(any(step.endswith(('-create','-remove'))for step,_ in calls))
                if mode=='query-failure':self.assertFalse(any(step.endswith('-remove')for step,_ in calls))
            finally:self.root=prior


    def test_lifecycle_cannot_open_from_host_despite_new_private_scope(self):
        d=self.delegation();d['stage']='lifecycle';c=dict(stage='lifecycle')
        with patch.object(O,'source_request',return_value=(d,c,{},object())),patch.object(O,'_INSIDE',None), \
             patch.object(O,'request',side_effect=AssertionError('host opened runtime admission')):
            with self.assertRaisesRegex(ValueError,'outer-owned namespace'):
                O.open_delegated_session(delegation_raw=O.encoded(d),delegation_sha256=O.pin(O.encoded(d))['sha256'],
                    context=None,image_report=None,executor=None,source_root=self.root,output=self.root/'life',inputs=None)

    def test_generated_public_byte_carriers_are_closed_and_whole_pinned(self):
        directory=self.root/'generated';directory.mkdir();rows={}
        product=dict(archives=[b'FICTION ARCHIVE A',b'FICTION ARCHIVE A'],signature=b'FICTION SIGNATURE',kind='FICTION')
        encoded=O.products_to_data(product,directory,rows)
        self.assertEqual(O.products_from_data(encoded,directory,rows),product)
        self.assertEqual(len(rows),3)
        descriptor=encoded['signature']
        for name in ('../outside','/absolute','body/escape'):
            bad=dict(descriptor,generated_body=name)
            with self.subTest(name=name),self.assertRaises(ValueError):O.products_from_data(bad,directory,rows)
        (directory/descriptor['generated_body']).write_bytes(b'CHANGED')
        with self.assertRaises(ValueError):O.products_from_data(descriptor,directory,rows)
        with self.assertRaises(ValueError):O.products_to_data(b'',directory,rows)

    def test_local_domain_requires_actual_root_namespace_and_exact_kernel_limits(self):
        manifest=dict(hostname='current-private-FICTION')
        good={'memory.max':str(4*1024**3),'memory.swap.max':'0','pids.max':'512','cpu.max':'400000 100000'}
        def comm(path):self.assertEqual(path,Path('/proc/1/comm'));return b'bash\n'
        def text(path):
            self.assertEqual(path.parent,Path('/sys/fs/cgroup'));return good[path.name]+'\n'
        with patch.object(O,'_INSIDE',manifest),patch.object(O.os,'getuid',return_value=0),patch.object(O.os,'geteuid',return_value=0), \
             patch.object(O.os,'getpid',return_value=2),patch.object(O.os,'getppid',return_value=1), \
             patch.object(O.os,'uname',return_value=SimpleNamespace(machine='aarch64',nodename=manifest['hostname'])), \
             patch.object(O.Path,'read_bytes',new=comm),patch.object(O.Path,'read_text',new=text):
            self.assertEqual(O.local_domain(manifest),good)
            with self.assertRaises(ValueError):O.local_domain(dict(manifest))
            for field,value in [('memory.max',str(8*1024**3)),('memory.swap.max','1'),('pids.max','513'),('cpu.max','500000 100000')]:
                before=good[field];good[field]=value
                with self.subTest(field=field),self.assertRaises(ValueError):O.local_domain(manifest)
                good[field]=before
            with patch.object(O.os,'getppid',return_value=3),self.assertRaises(ValueError):O.local_domain(manifest)
            with patch.object(O.os,'getuid',return_value=1000),self.assertRaises(ValueError):O.local_domain(manifest)

    def finalizer(self):
        d=self.delegation();d['stage']='lifecycle'
        c=dict(stage='lifecycle',binding=d['binding'],nonce=d['nonce'],delegation_pin=O.pin(O.encoded(d)))
        cmd=['-c','/usr/bin/python3 -I -B "$@"; status=$?; exit "$status"','current-private','/FICTION/owner.py','--inside','/FICTION/manifest']
        intent=O.intent(c,'sha256:'+'c'*64,'cachy-private-fiction-lifecycle','0:0',cmd,
            [['/FICTION/source','/FICTION/source',False],['/FICTION/output','/FICTION/output',True]],
            readonly=False,capadd=['CHOWN','DAC_OVERRIDE','FOWNER','SETUID','SETGID'])
        intent['hostname']='current-private-FICTION'
        _,_,observed=self.actor();observed['Name']='/'+intent['name'];observed['Config'].update(
            User='0:0',Entrypoint=intent['entrypoint'],Cmd=cmd,Labels=intent['labels'],Hostname=intent['hostname'])
        observed['HostConfig'].update(ReadonlyRootfs=False,CapAdd=intent['capadd'],Tmpfs={})
        observed['Mounts']=[dict(Type='bind',Destination=dst,Source=src,RW=rw)for dst,src,rw in intent['mounts']]
        observed['State']=dict(Running=False,ExitCode=0,OOMKilled=False)
        rows=[]
        for i in range(10):
            argv=['/usr/bin/docker','--host=unix:///tmp/FICTION-private.sock','FICTION-step-'+str(i)]
            natural=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,
                         timeout=False,signals=[],error=None,exit=0)
            original=dict(step='fixture-'+str(i),argv=argv,expected=0,exit=0,output_pin=O.pin(b''),stderr_pin=O.pin(b''),supervision=natural)
            rows.append(dict(original,supervision=copy.deepcopy(natural),success=True,log_pin=O.pin(b''),
                channels='stdout with separately pinned stderr',executor_receipt=copy.deepcopy(original)))
        receipt=dict(intent=intent,created=copy.deepcopy(observed),terminal=copy.deepcopy(observed),retired=True,
                     retirement=dict(status='REMOVED_AND_ABSENT',cid=observed['Id']),command_receipts=rows)
        report=dict(kind='DELEGATED_CURRENT_PRIVATE_STAGE_REPORT_V4',stage='lifecycle',status='PENDING_OUTER_CURRENT_STAGE_RETIREMENT',
            binding=c['binding'],nonce=d['nonce'],delegation_pin=c['delegation_pin'],owner_cleanup=dict(status='PENDING_OUTER_CONTAINER_RETIREMENT',
                natural_retirement=True,owned_container_absence_verified=False,protected_state_unchanged=True),
            Root_final_acceptance=None,independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False)
        return report,receipt,d,c,copy.deepcopy(intent)

    def test_outer_finalization_is_provisional_and_rejects_forced_foreign_or_root_claims(self):
        report,receipt,d,c,intent=self.finalizer()
        result=O.finalize_delegated(report,receipt,d,c,expected_intent=intent)
        self.assertEqual(result['status'],'PROVISIONAL_CURRENT_LIFECYCLE_DATA_ONLY')
        self.assertIsNone(result['Root_final_acceptance']);self.assertFalse(result['independent_component_acceptance'])
        mutations=[('CID',lambda r:r['terminal'].update(Id='e'*64)),
            ('forced',lambda r:r['retirement'].update(status='FORCED_REMOVAL_HOLD')),
            ('signal',lambda r:r['command_receipts'][0]['supervision'].update(signals=[15])),
            ('actual-forced',lambda r:r['command_receipts'][0]['executor_receipt']['supervision'].update(forced_cleanup=True)),
            ('launch',lambda r:r['intent'].update(entrypoint=['/bin/sh']))]
        for label,change in mutations:
            bad=copy.deepcopy(receipt);change(bad)
            with self.subTest(label=label),self.assertRaises(ValueError):O.finalize_delegated(report,bad,d,c,expected_intent=intent)
        bad=copy.deepcopy(report);bad['Root_final_acceptance']=True
        with self.assertRaises(ValueError):O.finalize_delegated(bad,receipt,d,c,expected_intent=intent)

    def test_local_callbacks_receive_private_config_without_old_root_admission(self):
        d=self.delegation();d.update(stage='lifecycle',capability=dict(total_seconds=600,max_command_seconds=180),programs=dict(local_callbacks=dict(
            member='FICTION/callbacks.py',bytes=1,sha256='f1a91dee080f76eff88409dd1fe893dc45a2084338017f367ec9874a462a612d')))
        c=dict(stage='lifecycle',binding=d['binding']);seen=[]
        class FakeSignedSession:
            def __init__(self,config,*args):seen.append(config)
            def __enter__(self):raise ValueError('FICTION stop before callback role')
        BC=SimpleNamespace(dependencies=lambda:(SimpleNamespace(Commands=object),None,None,None),SignedSession=FakeSignedSession,
            admission=lambda *a:(_ for _ in ()).throw(AssertionError('old Root gate called')))
        key=dict(path='/FICTION/public.asc',**O.pin(b'FICTION PUBLIC'))
        with patch.object(O,'modules',return_value=(object(),object(),object(),{})),patch.object(O,'raw',return_value=b'FICTION inventory'), \
             patch.object(O,'image_data',return_value=dict(id='sha256:'+'c'*64)),patch.object(O,'local_domain',return_value={'FICTION':'kernel'}), \
             patch.object(O,'test_policy',return_value=(key,'A'*40)),patch.object(O,'load',return_value=BC):
            local=O.LocalSession(d,c,{},object(),self.root,self.root/'local',{},{} )
            with self.assertRaisesRegex(ValueError,'stop before callback role'):local.__enter__()
        self.assertEqual(len(seen),1)
        self.assertEqual(seen[0]['stage'],'lifecycle');self.assertEqual(seen[0]['owner']['test_public_key'],key)
        for field in ('issuer','approved','selector','Root_admission','Root_qualification'):
            self.assertNotIn(field,seen[0])

    def wrapper(self,mode=None):
        directory=self.root/('wrapper-'+str(len(list(self.root.glob('wrapper-*')))));directory.mkdir()
        source=directory/'Source';source.mkdir();output=directory/'out';output.mkdir(mode=0o700)
        public=directory/'public';events=[]
        d=self.delegation();d['programs']={role:dict(member=role+'.py')for role in ('inputs_assembler','image','route','retention')}
        if mode=='old-key-only':
            d['programs'].pop('inputs_assembler');d['programs']['inputs_validator']=dict(member='inputs_validator.py')
        c=dict(stage='backend',binding=d['binding'],nonce=d['nonce']);H=object();executor=object()
        inner_inputs=dict(stage_inputs={'FICTION':'stage-public-inputs'},image_inputs={'FICTION':'image-public-inputs'})
        inputs={'owner_inputs':inner_inputs}if mode=='outer-schema'else inner_inputs
        allowed=[dict(path='/FICTION/selected-public-data',bytes=1,sha256='f'*64)]
        stage_inputs={'FICTION':'validated-observed-products'}
        image={'FICTION':'actual-image-observation'}
        report=dict(status='PROVISIONAL_CURRENT_BACKEND_DATA_ONLY',Root_final_acceptance=None,
            independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False)
        profile={'FICTION':'profile DATA'}
        class Validator:
            def validate_owner_inputs_v3(inner,*,inputs,delegation,source_root):
                events.append('validate');self.assertEqual(delegation,d);self.assertEqual(source_root,source)
                if set(inputs)!={'stage_inputs','image_inputs'}:raise ValueError('only inner owner input schema')
                self.assertIs(inputs,inner_inputs,'the exact inner object must reach its semantic validator')
                return dict(valid=True,required_refs=allowed)
            def stage_inputs(inner,value):
                events.append('hydrate');self.assertIs(value,inner_inputs)
                return stage_inputs
            def validate_hosted_inputs_v3(inner,**kw):raise AssertionError('hosted outer validator belongs to launcher')
        class OldValidator:
            def validate_owner_inputs_v3(inner,**kw):raise AssertionError('silent legacy program-key fallback')
            def validate_hosted_inputs_v3(inner,**kw):raise AssertionError('silent hosted/schema fallback')
        class Image:
            def build_stage(inner,**kw):
                events.append('image');self.assertIs(kw['inputs'],inner_inputs['image_inputs']);self.assertIs(kw['executor'],executor)
                self.assertIs(kw['context_program'],H);self.assertEqual(kw['output'],output/'image')
                self.assertFalse((output/'completion.json').exists());return image
        class Route:
            def run_registered(inner,**kw):
                events.append('route');self.assertEqual(kw['image'],image);self.assertEqual(kw['inputs'],stage_inputs)
                self.assertIs(kw['open_session'],O.open_delegated_session)
                self.assertEqual(kw['profile'],profile);self.assertFalse((output/'completion.json').exists());return report
        class Retention:
            def retain_delegated_stage(inner,**kw):
                events.append('retention');self.assertEqual(kw['stage_report'],report);self.assertEqual(kw['image_report'],image)
                self.assertEqual(kw['destination'],public);self.assertEqual(kw['inputs'],inputs)
                self.assertFalse((output/'completion.json').exists())
                return dict(evidence_state='HOLD'if mode=='hold'else'COMPLETE',Root_final_acceptance=None,
                    independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False,
                    capsule_pin=O.pin(b'FICTION capsule DATA never interpreted'),manifest={'FICTION':'public retention manifest'})
        modules={'inputs_assembler':Validator(),'image':Image(),'route':Route(),
                 'retention':SimpleNamespace()if mode=='missing-api'else Retention()}
        by_member={role+'.py':module for role,module in modules.items()};by_member['inputs_validator.py']=OldValidator()
        def load(source_root,row,name):
            self.assertEqual(source_root,source)
            self.assertIn(row['member'],by_member);return by_member[row['member']]
        def read(path,cap=16*1024**2):
            self.assertEqual(path,source/(O.FAMILY+'/successor_v2/profile.json'));return O.encoded(profile)
        with patch.object(O,'source_request',return_value=(d,c,{},H)),patch.object(O,'load',side_effect=load),patch.object(O,'raw',side_effect=read):
            args=dict(delegation_raw=b'FICTION delegation',delegation_sha256='f'*64,context={'FICTION':'context'},source_root=source,
                      inputs=inputs,executor=executor,output=output,public_output=public)
            if mode:
                with self.assertRaises((ValueError,KeyError)):O.run_owned_current_v3(**args)
                result=None
            else:result=O.run_owned_current_v3(**args)
        return events,output,result

    def test_wrapper_completes_only_after_validated_image_stage_and_public_retention(self):
        events,output,result=self.wrapper()
        self.assertEqual(events,['validate','hydrate','image','route','retention'])
        self.assertTrue(result['completed']);self.assertIsNone(result['Root_final_acceptance'])
        self.assertFalse(result['independent_component_acceptance']);self.assertFalse(result['hardware_acceptance'])
        self.assertFalse(result['release_acceptance']);self.assertEqual(O.decode((output/'completion.json').read_bytes()),result)
        self.assertFalse((output/'failure.json').exists())

    def test_wrapper_missing_retention_api_or_hold_never_claims_completion(self):
        events,output,_=self.wrapper('missing-api')
        self.assertEqual(events,['validate','hydrate']);self.assertFalse((output/'completion.json').exists())
        events,output,_=self.wrapper('hold')
        self.assertEqual(events,['validate','hydrate','image','route','retention']);self.assertFalse((output/'completion.json').exists())
        failure=O.decode((output/'failure.json').read_bytes())
        self.assertFalse(failure['completed']);self.assertEqual(failure['status'],'HOLD')
        self.assertIsNone(failure['Root_final_acceptance']);self.assertFalse(failure['independent_component_acceptance'])
        for mode,expected_events in (('old-key-only',[]),('outer-schema',['validate'])):
            with self.subTest(mode=mode):
                events,output,_=self.wrapper(mode)
                self.assertEqual(events,expected_events);self.assertFalse((output/'completion.json').exists())

    def test_runner_aggregate_index_tracks_all_actual_receipts_and_preserves_stderr(self):
        run,calls=self.runner();index=run.directory/'commands.json'
        self.assertEqual(O.decode(index.read_bytes()),[])
        with patch.object(O.time,'monotonic',return_value=100):
            run.run('first',['/usr/bin/NEVER_EXECUTED','first'])
            first=copy.deepcopy(run.records[0]);self.assertEqual(O.decode(index.read_bytes()),[first])
            run.run('second',['/usr/bin/NEVER_EXECUTED','second'])
        rows=O.decode(index.read_bytes());self.assertEqual(rows,run.records)
        self.assertEqual([row['step']for row in rows],['first','second']);self.assertEqual(len(calls),2)
        self.assertEqual(rows[0],first)
        for row in rows:
            self.assertEqual(row['executor_receipt']['stderr_pin'],O.pin(b'FICTION STDERR'))
            self.assertEqual(row['executor_receipt']['output_pin'],O.pin((run.directory/(row['step']+'.stdout')).read_bytes()))
            self.assertEqual(O.decode((run.directory/(row['step']+'.json')).read_bytes()),row)


    def test_v4_scope_requires_coherent_schema_and_rejects_old_gate_kind(self):
        d=self.delegation();d.update(schema=4,kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4')
        body=O.encoded(d);self.assertEqual(O.scope(body,O.pin(body)['sha256']),d)
        for schema,kind in ((3,d['kind']),(4,'ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3'),
                            (4,'ROOT_CURRENT_ONBOARDING_STAGE_ADMISSION_V2')):
            bad=dict(d,schema=schema,kind=kind);body=O.encoded(bad)
            with self.subTest(schema=schema,kind=kind),self.assertRaises(ValueError):O.scope(body,O.pin(body)['sha256'])

    def test_v4_selected_pair_verifies_both_signed_bodies_and_preserves_producer_run(self):
        def run(mode,index):
            output=self.root/('selected-'+str(index));output.mkdir()
            keypath=output/'public.asc';keypath.write_bytes(b'FICTION PUBLIC TEST CERTIFICATE')
            public=dict(path=str(keypath),**O.pin(keypath.read_bytes()));fingerprint='A'*40
            recipe=dict(name='cachy-asahi-first-login',version='0.1.0-3')
            selection=dict(component=dict(name=recipe['name'],version=recipe['version'],architecture='any'),
                test_fingerprint=fingerprint,public_test_key_pin={k:public[k]for k in ('bytes','sha256')})
            d=self.delegation();d.update(schema=4,kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V4',
                stage='ui',pair_selection=selection,capability=dict(allow_selected_pair_adoption=True))
            c=dict(stage='ui',binding=dict(source='b'*40,run='202',job='203'))
            product=dict(producer_delegation_raw=b'FICTION PRODUCER DELEGATION',producer_context=dict(binding=dict(source='b'*40,run='101',job='102')),
                completion_raw=b'FICTION PRODUCER COMPLETION',pair_raw=b'FICTION PRODUCER PAIR',
                root_component_raw=b'FICTION ROOT COMPONENT DECISION',root_test_raw=b'FICTION ROOT PUBLIC TEST PROOF',
                archives=[b'FICTION MATCHING ARCHIVE',b'FICTION MATCHING ARCHIVE'],signatures=[b'FICTION SIGNATURE A',b'FICTION SIGNATURE B'])
            if mode=='multiple':
                d['pair_selections']={'first-login-role':d.pop('pair_selection')};product['selection_role']='first-login-role'
            if mode=='foreign-component':selection['component']['name']='cachy-asahi-unrelated'
            if mode=='short-signatures':product['signatures']=product['signatures'][:1]
            adopted=[];verified=[]
            def adopt(delegation,current,**kwargs):
                adopted.append(kwargs);self.assertIs(delegation,d);self.assertIs(current,c)
                self.assertEqual(kwargs['producer_context']['binding']['run'],'101');self.assertEqual(current['binding']['run'],'202')
                self.assertEqual(kwargs['selection_role'],'first-login-role'if mode=='multiple'else None)
                self.assertEqual(kwargs['archive_bodies'],product['archives']);self.assertEqual(kwargs['signature_bodies'],product['signatures'])
                self.assertEqual(kwargs['public_test_key_raw'],keypath.read_bytes())
                for field in ('completion_raw','pair_raw','root_component_raw','root_test_raw'):self.assertEqual(kwargs[field],product[field])
                return dict(kind='DELEGATED_CURRENT_ONBOARDING_SELECTED_PAIR_ADOPTION_V4',current_stage_gpg_required=True,
                    producer_binding=copy.deepcopy(product['producer_context']['binding']),current_binding=copy.deepcopy(c['binding']),
                    Root_final_acceptance=True if mode=='root-final'else None,independent_component_acceptance=False,
                    hardware_acceptance=False,release_acceptance=False)
            forbidden=lambda *a:(_ for _ in ()).throw(AssertionError('old context/Root gate called'))
            H=SimpleNamespace(ISSUER='DELEGATED_CONTEXT_PROGRAM_V4',adopt_selected_pair=adopt,
                validate_delegation=forbidden,validate_context=forbidden)
            def verify(label,archive,signature):
                self.assertTrue(str(signature).endswith('.archive.sig'))
                verified.append((label,archive.read_bytes(),signature.read_bytes()))
            def metadata(step,argv,seconds):
                self.assertEqual(step,'adopted-pkginfo-first-login');self.assertEqual(argv[:2],['/usr/bin/bsdtar','-xOf']);self.assertEqual(seconds,60)
                return b'FICTION PKGINFO DATA'
            session=SimpleNamespace(plan={'H':H},d=d,c=c,profile={'packages':{'first-login':recipe}},fingerprint=fingerprint,
                public_key=public,output=output,verify=verify,runner=SimpleNamespace(run=metadata),
                tools=SimpleNamespace(_metadata=lambda raw:dict(pkgname=[recipe['name']],pkgver=[recipe['version']],arch=['any'])))
            if mode in ('foreign-component','root-final','short-signatures'):
                with self.assertRaises(ValueError):O.Session.selected_product(session,'first-login',product)
                if mode=='foreign-component':self.assertFalse(adopted)
                if mode in ('foreign-component','root-final'):self.assertFalse(verified)
                return
            result=O.Session.selected_product(session,'first-login',product)
            self.assertEqual([row[0]for row in verified],['first-login-selected-0','first-login-selected-1'])
            self.assertEqual([row[1]for row in verified],product['archives']);self.assertEqual([row[2]for row in verified],product['signatures'])
            self.assertEqual(result['archive_pin'],O.pin(product['archives'][0]));self.assertEqual(result['signature_pin'],O.pin(product['signatures'][0]))
            adoption=O.decode((output/'adopted/first-login-selected-adoption.json').read_bytes())
            self.assertEqual(adoption['producer_binding']['run'],'101');self.assertEqual(adoption['current_binding']['run'],'202')
            self.assertIsNone(adoption['Root_final_acceptance'])
            self.assertEqual((output/'adopted/first-login-Root-component.json').read_bytes(),product['root_component_raw'])
            self.assertEqual((output/'adopted/first-login-Root-TEST.json').read_bytes(),product['root_test_raw'])
        for index,mode in enumerate((None,'multiple','foreign-component','root-final','short-signatures')):
            with self.subTest(mode=mode):run(mode,index)


if __name__=='__main__':unittest.main()
