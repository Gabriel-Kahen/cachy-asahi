# SPDX-License-Identifier: MIT
"""Mocked one-fetch transport and pre-native DATA diagnosis; no actors."""
import importlib.util,inspect,json,os,socket,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];PACKET=ROOT.parent
spec=importlib.util.spec_from_file_location('_pgo_transport_fixture',HERE/'owner.py');O=importlib.util.module_from_spec(spec);spec.loader.exec_module(O)
CARRIER='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
PROFILE='4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'

class OwnedTransportControls(unittest.TestCase):
    def setUp(self):
        temporary=PACKET/'evidence/tmp';temporary.mkdir(parents=True,exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(prefix='transport-model-',dir=temporary);self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.runtime=self.root/'runner-temp';self.runtime.mkdir(mode=0o700)
        self.work=self.runtime/'pgo-hosted-work';self.work.mkdir(mode=0o700)
        self.own=dict(source_sha='a'*40,run_id='123',attempt=1)
        self.args=SimpleNamespace(source_root=ROOT,work=self.work,cache=self.runtime/'alarm-cache',public=self.runtime/'pgo-hosted-public',proof=self.runtime/'pgo-hosted-proof.json',carrier=self.runtime/'pgo-hosted-retained',source_sha='a'*40,manifest_sha256='b'*64,execute=True)
        self.enterContext(patch.dict(O.os.environ,{'RUNNER_TEMP':str(self.runtime)}))
        self.enterContext(patch.object(subprocess,'Popen',side_effect=AssertionError('real process forbidden')))
        for name in('killpg','kill','waitpid','waitid'):self.enterContext(patch.object(os,name,side_effect=AssertionError('numeric process operation forbidden')))
        self.enterContext(patch.object(socket,'socket',side_effect=AssertionError('network forbidden')))

    def report(self):return json.loads((self.work/'input-transport-owner.json').read_bytes())

    def actor(self,fail_fetch=False,wrong_fetch=False):
        calls=[];construct=[];carrier=self.args.carrier
        class Fake:
            def __init__(self,directory,seconds):construct.append((directory,seconds))
            def run(self,argv,log=None,timeout=60,*,allowed=(0,)):
                calls.append((argv,timeout))
                if 'fetch'in argv and fail_fetch:
                    (carrier/'partial-DATA').write_bytes(b'partial model')
                    raise subprocess.TimeoutExpired(argv,400)
                if 'rev-parse'in argv:return 'f'*40 if wrong_fetch and 'FETCH_HEAD'in argv else CARRIER
                return ''
        return Fake,calls,construct

    def failed_receipt(self,**changes):
        row=dict(status='FAIL_RETAINED_INPUT_TRANSPORT_DATA',identity=self.own,manifest_sha256=self.args.manifest_sha256,role='RETAINED_INPUT_TRANSPORT_DATA',runtime_temp=str(self.runtime),source_root=str(ROOT),carrier_path=str(self.args.carrier),carrier_source=CARRIER,profile_sha256=PROFILE,expected_carrier_files=1154,expected_carrier_bytes=1046432165,budget_seconds=480,retry=False,partial_data_retained=True,native='NOT_RUN',acceptance=False)
        row.update(changes);O.save(self.work/'input-transport-owner.json',row);return row

    def test_single_fetch_fixed_external_data_and_actual_actor_api(self):
        inspect.signature(O.Actors.run).bind(None,['git','control'],timeout=400)
        actor,calls,construct=self.actor()
        with patch.object(O,'admitted',return_value=({},self.own)),patch.object(O,'Actors',actor):O.transport(self.args)
        self.assertEqual(construct,[(self.work/'input-transport-actors',480)])
        self.assertEqual([limit for _,limit in calls],[10,400,10,45,10]);self.assertEqual(len(calls),5)
        self.assertEqual(sum('fetch'in argv for argv,_ in calls),1)
        fetch=calls[1][0];self.assertEqual(fetch[-2:],['https://github.com/Gabriel-Kahen/cachy-asahi.git',CARRIER])
        for flag in('--depth=1','--no-tags','--no-recurse-submodules','credential.helper=','http.extraHeader=','core.hooksPath=/dev/null','protocol.allow=never','protocol.https.allow=always'):self.assertIn(flag,fetch)
        self.assertEqual(calls[2][0][-3:],['rev-parse','--verify','FETCH_HEAD']);self.assertEqual(calls[3][0][-3:],['checkout','--detach',CARRIER])
        row=self.report();self.assertEqual(row['status'],'PASS_EXACT_RETAINED_INPUT_TRANSPORT_DATA_ONLY')
        self.assertEqual((row['carrier_source'],row['carrier_head'],row['profile_sha256']),(CARRIER,CARRIER,PROFILE))
        self.assertEqual((row['expected_carrier_files'],row['expected_carrier_bytes']),(1154,1046432165))
        self.assertEqual((row['runtime_temp'],row['source_root'],row['carrier_path']),(str(self.runtime),str(ROOT),str(self.args.carrier)))
        self.assertIs(row['retry'],False);self.assertIs(row['acceptance'],False);self.assertEqual(row['native'],'NOT_RUN')
        self.assertFalse(self.args.carrier.is_relative_to(ROOT));self.assertEqual(self.args.carrier.stat().st_mode&0o777,0o700)

    def test_fetch_failure_keeps_partial_external_data_without_retry_or_promotion(self):
        actor,calls,_=self.actor(fail_fetch=True)
        with patch.object(O,'admitted',return_value=({},self.own)),patch.object(O,'Actors',actor),self.assertRaises(subprocess.TimeoutExpired):O.transport(self.args)
        self.assertEqual(len(calls),2);self.assertEqual(sum('fetch'in argv for argv,_ in calls),1)
        self.assertEqual((self.args.carrier/'partial-DATA').read_bytes(),b'partial model')
        row=self.report();self.assertEqual(row['status'],'FAIL_RETAINED_INPUT_TRANSPORT_DATA');self.assertNotIn('carrier_head',row)
        self.assertTrue(row['partial_data_retained']);self.assertFalse(row['acceptance'])

    def test_wrong_fetch_head_prevents_checkout_and_data_success(self):
        actor,calls,_=self.actor(wrong_fetch=True)
        with patch.object(O,'admitted',return_value=({},self.own)),patch.object(O,'Actors',actor),self.assertRaises(ValueError):O.transport(self.args)
        self.assertEqual(len(calls),3);self.assertFalse(any('checkout'in argv for argv,_ in calls));self.assertEqual(self.report()['status'],'FAIL_RETAINED_INPUT_TRANSPORT_DATA')

    def test_existing_or_in_source_destination_refuses_before_actor(self):
        self.args.carrier.mkdir(mode=0o700)
        for path in(self.args.carrier,ROOT/'source-retained'):
            self.args.carrier=path
            with self.subTest(path=path),patch.object(O,'admitted',return_value=({},self.own)),patch.object(O,'Actors')as actor,self.assertRaises(ValueError):O.transport(self.args)
            actor.assert_not_called()

    def test_transport_failure_diagnostic_needs_no_cache_or_native_calls(self):
        self.failed_receipt();self.assertFalse(self.args.cache.exists())
        for name,raw in(('input-transport.stdout',b''),('input-transport.stderr',b'model failure'),('input-transport.exit-code',b'1\n')):(self.work/name).write_bytes(raw)
        with patch.object(O,'binding',return_value=({},self.own)),patch.object(O,'admitted',side_effect=AssertionError('native admission forbidden')),patch.object(O,'Actors',side_effect=AssertionError('actor forbidden')),patch.object(O,'pair_cleanup',side_effect=AssertionError('native cleanup forbidden')):O.cleanup(self.args)
        row=O.load(self.work/'cleanup-owner.json');self.assertEqual(row['status'],'INPUT_TRANSPORT_FAILED_BEFORE_NATIVE_ACTORS_DIAGNOSTIC_ONLY')
        self.assertEqual(row['native'],'NOT_RUN');self.assertEqual(row['native_cleanup'],'NOT_ESTABLISHED');self.assertFalse(row['acceptance'])
        self.assertNotIn('consumer_absence_verified',row);self.assertNotIn('image_absence_verified',row)
        self.assertEqual(row['transport_receipt_sha256'],O.sha(O.read(self.work/'input-transport-owner.json')))

    def test_native_and_unknown_work_markers_cannot_take_diagnostic_bypass(self):
        self.failed_receipt()
        for name in('bootstrap','bootstrap-actors','bootstrap-owner.json','pairs-actors','pairs-owner.json','pair-cleanup-actors','build-observations','build-intent-1.json','producer-binding.json','attempt-1','unexpected-future-native-marker'):
            path=self.work/name;path.write_bytes(b'intent model')
            with self.subTest(name=name),patch.object(O,'binding')as binding,patch.object(O,'admitted',side_effect=ValueError('native admission remains required')),self.assertRaises(ValueError):O.cleanup(self.args)
            binding.assert_not_called();self.assertFalse((self.work/'cleanup-owner.json').exists());path.unlink()
        dangling=self.work/'bootstrap';dangling.symlink_to(self.root/'absent')
        with patch.object(O,'binding')as binding,patch.object(O,'admitted',side_effect=ValueError('native gate')),self.assertRaises(ValueError):O.cleanup(self.args)
        binding.assert_not_called()

    def test_wrong_binding_or_profile_cannot_receive_diagnostic_credit(self):
        for field,value in(('identity',dict(source_sha='f'*40)),('manifest_sha256','f'*64),('runtime_temp',str(self.root)),('source_root',str(self.root)),('carrier_path',str(self.root/'wrong')),('expected_carrier_bytes',1),('retry',True),('acceptance',True)):
            self.failed_receipt(**{field:value})
            with self.subTest(field=field),patch.object(O,'binding',return_value=({},self.own)),patch.object(O,'admitted',side_effect=AssertionError('native gate must not run')),self.assertRaises(ValueError):O.cleanup(self.args)
            self.assertFalse((self.work/'cleanup-owner.json').exists())

    def test_blob_proof_exact_profile_byte_cap_forwards_to_actual_owned_api(self):
        profile=O.load(ROOT/'scripts/ci/setup6-retained-helpers/carrier-profile.json')
        name,row=max(profile['files'].items(),key=lambda item:item[1]['bytes'])
        self.assertEqual(row['bytes'],104330276);self.assertGreater(row['bytes'],8*1024**2)
        argv=['/usr/bin/git','--git-dir='+str(self.args.carrier/'.git'),'-c','protocol.allow=never','cat-file','blob',CARRIER+':'+name]
        environment={'PATH':os.defpath,'LANG':'C','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_REPLACE_OBJECTS':'1','GIT_OPTIONAL_LOCKS':'0','GIT_NO_LAZY_FETCH':'1','GIT_TERMINAL_PROMPT':'0'}
        options=dict(capture_output=True,timeout=30,env=environment,check=False);calls=[]
        result=subprocess.CompletedProcess(argv,0,stdout=b'small mocked blob',stderr=b'')
        def owned(command,**kwargs):calls.append((command,kwargs));return result
        with patch.object(O,'_OWNED',SimpleNamespace(run=owned)):
            self.assertIs(O.owned_subprocess_run(argv,**options),result)
            O.owned_subprocess_run(['git','ordinary-metadata'],capture_output=True,timeout=5,check=False)
        self.assertEqual(calls[0][0],argv)
        self.assertEqual(calls[0][1],dict(options,stdout_limit=row['bytes']))
        self.assertNotIn('stdout_limit',calls[1][1]);self.assertNotIn('stdout_limit',options)
        self.assertEqual(result.stdout,b'small mocked blob')

    def test_nonmatching_or_malformed_blob_proofs_never_receive_large_cap(self):
        profile=O.load(ROOT/'scripts/ci/setup6-retained-helpers/carrier-profile.json')
        name,row=max(profile['files'].items(),key=lambda item:item[1]['bytes'])
        argv=['/usr/bin/git','--git-dir='+str(self.args.carrier/'.git'),'-c','protocol.allow=never','cat-file','blob',CARRIER+':'+name]
        environment={'PATH':os.defpath,'LANG':'C','LC_ALL':'C','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_REPLACE_OBJECTS':'1','GIT_OPTIONAL_LOCKS':'0','GIT_NO_LAZY_FETCH':'1','GIT_TERMINAL_PROMPT':'0'}
        options=dict(capture_output=True,timeout=30,env=environment,check=False);calls=[]
        def owned(command,**kwargs):calls.append(kwargs);return subprocess.CompletedProcess(command,0,stdout=b'small model',stderr=b'')
        selectors=[]
        for index,value in((0,'git'),(1,'--git-dir='+str(self.root/'other/.git')),(5,'commit'),(6,'f'*40+':'+name),(6,CARRIER+':packages/NOT_IN_PROFILE')):
            changed=argv.copy();changed[index]=value;selectors.append(changed)
        selectors.append([*argv,'--extra'])
        with patch.object(O,'_OWNED',SimpleNamespace(run=owned)):
            for command in selectors:
                with self.subTest(command=command):O.owned_subprocess_run(command,**options)
                self.assertNotIn('stdout_limit',calls[-1])
            for change in(dict(capture_output=False),dict(check=True),dict(env=dict(environment,GIT_NO_LAZY_FETCH='0')),dict(env=dict(environment,EXTRA='not-allowed')),dict(text=True),dict(stdout_limit=row['bytes'])):
                before=len(calls)
                with self.subTest(change=change),self.assertRaises(ValueError):O.owned_subprocess_run(argv,**dict(options,**change))
                self.assertEqual(len(calls),before)
            before=len(calls)
            with self.assertRaises(ValueError):O.owned_subprocess_run(['git','ordinary'],stdout_limit=row['bytes'])
            self.assertEqual(len(calls),before)

    def test_main_transport_dispatch_keeps_source_validation_before_utility(self):
        events=[];before=subprocess.run
        def source(*args,**kw):events.append('source');return {}
        def transport(args):events.append('transport');self.assertEqual(args.carrier,self.args.carrier)
        argv=['owner.py','transport','--source-root',str(ROOT),'--source-sha','a'*40,'--manifest-sha256','b'*64,'--proof',str(self.args.proof),'--work',str(self.work),'--cache',str(self.args.cache),'--public',str(self.args.public),'--carrier',str(self.args.carrier),'--execute']
        with patch.object(O.sys,'argv',argv),patch.object(O,'source',side_effect=source),patch.object(O,'transport',side_effect=transport),patch.object(O,'_OWNED',SimpleNamespace(run=lambda *a,**kw:None)),patch.object(O.signal,'signal'):self.assertEqual(O.main(),0)
        self.assertEqual(events,['source','transport']);self.assertIs(subprocess.run,before)

if __name__=='__main__':unittest.main()
