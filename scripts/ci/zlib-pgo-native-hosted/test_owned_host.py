# SPDX-License-Identifier: MIT
"""Focused owned-child composition fixtures; no Docker/native/real child actions."""
import importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;PACKET=HERE.parents[3]

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
O=module('_owned_host_fixture',HERE/'owner.py');D=module('_owned_driver_fixture',HERE/'execute_builder.py')

def lifecycle(code=0):
    return dict(exit=code,natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,
        exit_observed_via_waitpid=True,ownership_lost=False,retirement='REAPED',forced_cleanup=False)

def lost():
    return dict(exit=None,natural_exit=False,group_absent=False,leader_held_until_group_inspection=False,
        exit_observed_via_waitpid=False,ownership_lost=True,retirement='UNKNOWN',forced_cleanup=False)

class OwnedHostControls(unittest.TestCase):
    def setUp(self):
        temporary=PACKET/'evidence/tmp';temporary.mkdir(parents=True,exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=temporary);self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name)
        self.enterContext(patch.object(subprocess,'Popen',side_effect=AssertionError('real child forbidden')))
        self.enterContext(patch.object(os,'killpg',side_effect=AssertionError('numeric signal forbidden')))
        self.enterContext(patch.object(os,'waitid',side_effect=AssertionError('real wait forbidden')))
        self.enterContext(patch.object(os,'waitpid',side_effect=AssertionError('real wait forbidden')))

    def test_owner_actor_loss_cannot_become_zero_or_touch_numeric_group(self):
        def fake(argv,**kw):
            kw['lifecycle'].update(lost());raise ChildProcessError('synthetic ECHILD')
        with patch.object(O,'_OWNED',SimpleNamespace(run=fake)):
            actor=O.Actors(self.work/'actors',5)
            with self.assertRaises(ChildProcessError):actor.run(['control'])
        row=json.loads((self.work/'actors/actors.json').read_text())[0]
        self.assertEqual(row['status'],'FAIL');self.assertIsNone(row['exit']);self.assertEqual(row['retirement'],'UNKNOWN');self.assertTrue(row['ownership_lost'])

    def test_owner_actor_requires_consistent_direct_exit_and_unforced_retirement(self):
        def valid(argv,**kw):
            kw['stdout'].write(b'owned control\n');kw['lifecycle'].update(lifecycle());return subprocess.CompletedProcess(argv,0)
        with patch.object(O,'_OWNED',SimpleNamespace(run=valid)):
            actor=O.Actors(self.work/'good',5);self.assertEqual(actor.run(['control']),'owned control');self.assertEqual(actor.rows[0]['status'],'PASS')
        for key,value in(('exit_observed_via_waitpid',False),('ownership_lost',True),('forced_cleanup',True),('retirement','UNKNOWN'),('exit',7)):
            def bad(argv,**kw):
                kw['lifecycle'].update(lifecycle()|{key:value});return subprocess.CompletedProcess(argv,0)
            with self.subTest(key=key),patch.object(O,'_OWNED',SimpleNamespace(run=bad)):
                with self.assertRaises(ValueError):O.Actors(self.work/key,5).run(['control'])

    def test_owner_pure_source_before_utility_and_git_capture_routes_owned_run(self):
        events=[];before=subprocess.run
        def run(argv,**kw):events.append(('owned',argv));return subprocess.CompletedProcess(argv,0,stdout='joined\n')
        def source(*a,**k):events.append(('source',));return {}
        def proof(args):self.assertEqual(subprocess.check_output(['git','control'],text=True),'joined\n');return 0
        argv=['owner.py','proof','--source-root',str(O.ROOT),'--source-sha','a'*40,'--manifest-sha256','b'*64,'--proof',str(self.work/'proof'),'--work',str(self.work/'work'),'--cache',str(self.work/'cache'),'--public',str(self.work/'public')]
        with patch.object(O.sys,'argv',argv),patch.object(O,'source',side_effect=source),patch.object(O,'proof',side_effect=proof),patch.object(O,'_OWNED',SimpleNamespace(run=run)),patch.object(O.signal,'signal'):
            self.assertEqual(O.main(),0)
        self.assertEqual(events[0],('source',));self.assertEqual(events[1][0],'owned');self.assertIs(subprocess.run,before)

    def driver_fixture(self,ownership_loss=False):
        feature=self.work/'feature';prep=self.work/'attempt-1';observed=self.work/'observed.json';lock=self.work/'packages.lock';lock.write_bytes((HERE/'expected-packages.lock').read_bytes())
        image='sha256:'+'b'*64;binding=self.work/'producer.json';binding.write_text(json.dumps(dict(schema=1,status='PASS_FRESH_OWNED_RUNTIME_IMAGE_AND_FULL341_LOCK',identity=dict(source_sha='a'*40),image=image,package_count=341,packages=O.pin(lock.read_bytes()))))
        args=SimpleNamespace(feature_root=feature,preparation=prep,observation=observed,lock=lock,producer_binding=binding,image=image,source_sha='a'*40)
        events=[];main_held=[False];builder_holder={}
        def owned(argv,**kw):
            if 'inspect'in argv:
                self.assertTrue(main_held[0]);events.append('inspect-owned')
                if ownership_loss:kw['lifecycle'].update(lost());raise ChildProcessError('synthetic lost inspector')
                kw['lifecycle'].update(lifecycle());return subprocess.CompletedProcess(argv,0,stdout=json.dumps([dict(State=dict(Running=True))]))
            self.assertIn('run',argv);events.append('main-held');main_held[0]=True
            try:kw['on_tick']()
            except BaseException:
                kw['lifecycle'].update(lifecycle(-9)|dict(natural_exit=False,forced_cleanup=True));raise
            finally:main_held[0]=False
            events.append('main-direct-reaped');kw['lifecycle'].update(lifecycle());return subprocess.CompletedProcess(argv,0)
        def prepare(*a,**kw):
            prep.mkdir();(prep/'seed-cache').mkdir();(prep/'seed-cache/object').write_bytes(b'control')
            return dict(command=['python','-B','build_v2.py','recipe','--image',image])
        def builder_main():
            result=subprocess.run(['docker','run','--rm','--name','cachy-asahi-'+'a'*16,image],timeout=1)
            artifact=prep/'native-build/artifacts/fixture.pkg.tar.xz';artifact.parent.mkdir(parents=True);artifact.write_bytes(b'pure parser fixture')
            builder_holder['module'].package(artifact)
            return result.returncode
        def spec(name,path):
            def parser(path):return dict(artifact=path.name,sha256=O.sha(path.read_bytes()),status='artifact-static-pass')
            values=dict(main=builder_main,package=parser)if name=='selected_actual_build_v2'else dict(prepare=prepare)
            def load(obj):
                obj.__dict__.update(values)
                if name=='selected_actual_build_v2':builder_holder['module']=obj
            return SimpleNamespace(loader=SimpleNamespace(exec_module=load))
        return args,owned,spec,events

    def test_driver_inspects_synchronously_while_main_child_owned(self):
        args,owned,spec,events=self.driver_fixture();before=subprocess.run
        with patch.object(D,'_OWNED',SimpleNamespace(run=owned)),patch.object(D.importlib.util,'spec_from_file_location',side_effect=spec),patch.object(D.importlib.util,'module_from_spec',side_effect=lambda s:SimpleNamespace()),patch.object(D,'check_inspection'):
            self.assertEqual(D.run_builder(args),0)
        row=json.loads(args.observation.read_text());self.assertEqual(events,['main-held','inspect-owned','main-direct-reaped']);self.assertIs(subprocess.run,before)
        self.assertEqual(row['observer_kind'],'SYNCHRONOUS_OWNED_CHILD_PULSE');self.assertTrue(row['observer_joined']);self.assertTrue(row['consumer_child']['exit_observed_via_waitpid']);self.assertEqual(row['consumer_child']['exit'],0)
        self.assertEqual(len(row['inspection_children']),1);self.assertEqual(row['status'],'PASS_ACTUAL_DAEMON_BUILD_MOUNTS_OBSERVED')
        row['python_socket_events']=[] # main() normally appends its audited socket list.
        collection=self.work/'collection';(collection/'build-observations').mkdir(parents=True)
        target=collection/'build-observations/1.json';target.write_text(json.dumps(row))
        record=dict(clean_environment_id=row['name'],image_id=row['image'],command=row['command'],artifacts={p['artifact']:p['reported_sha256']for p in row['package_inspections']})
        checker=SimpleNamespace(DOCKER=D.DOCKER,check_inspection=lambda *a:None)
        with patch.object(O,'module',return_value=checker):
            O.validate_observations(collection,[record],dict(source_sha='a'*40))
            for key,value in(('exit_observed_via_waitpid',False),('ownership_lost',True),('retirement','UNKNOWN')):
                changed=json.loads(json.dumps(row));changed['consumer_child'][key]=value;target.write_text(json.dumps(changed))
                with self.subTest(key=key),self.assertRaises(ValueError):O.validate_observations(collection,[record],dict(source_sha='a'*40))

    def test_driver_lost_inspector_is_partial_and_never_false_joined_success(self):
        args,owned,spec,events=self.driver_fixture(True)
        with patch.object(D,'_OWNED',SimpleNamespace(run=owned)),patch.object(D.importlib.util,'spec_from_file_location',side_effect=spec),patch.object(D.importlib.util,'module_from_spec',side_effect=lambda s:SimpleNamespace()),patch.object(D,'check_inspection'):
            with self.assertRaises(ChildProcessError):D.run_builder(args)
        row=json.loads(args.observation.read_text());self.assertNotEqual(row['status'],'PASS_ACTUAL_DAEMON_BUILD_MOUNTS_OBSERVED');self.assertTrue(row['inspection_children'][0]['ownership_lost']);self.assertIsNone(row['inspection_children'][0]['exit'])
        source=(HERE/'execute_builder.py').read_text();self.assertNotIn('import threading',source);self.assertNotIn('Thread(',source);self.assertNotIn('.join(',source)

    def test_owned_zstd_wrapper_uses_pure_tar_and_restores_original_identity(self):
        artifact=self.work/'candidate.pkg.tar.zst';artifact.write_bytes(b'compressed control bytes');original=O.pin(artifact.read_bytes());rows=[];temporary=[]
        def run(argv,**kw):
            self.assertEqual(argv,['zstd','-dc','--',str(artifact)])
            self.assertEqual(kw['stdout_limit'],512*1024**2);self.assertEqual(kw['timeout'],120)
            kw['stdout'].write(b'decoded tar control');kw['lifecycle'].update(lifecycle());return subprocess.CompletedProcess(argv,0)
        def pure(path):
            temporary.append(path);self.assertEqual(path.suffix,'.tar');self.assertEqual(path.parent,self.work)
            self.assertEqual(path.read_bytes(),b'decoded tar control')
            return dict(artifact=path.name,sha256=O.sha(path.read_bytes()),status='artifact-static-pass')
        with patch.dict(D.os.environ,{'RUNNER_TEMP':str(self.work)}):report=D.inspect_package(artifact,pure,rows,run)
        self.assertEqual(report['artifact'],artifact.name);self.assertEqual(report['sha256'],original['sha256'])
        self.assertFalse(temporary[0].exists());self.assertTrue(rows[0]['original_unchanged']);self.assertEqual(rows[0]['status'],'PASS')
        self.assertEqual(rows[0]['owned_child']['exit'],0);self.assertEqual(rows[0]['decoded_tar'],O.pin(b'decoded tar control'))

    def test_owned_zstd_loss_or_changed_original_refuses_before_admission(self):
        artifact=self.work/'candidate.pkg.tar.zst';artifact.write_bytes(b'compressed fixture');rows=[];parses=[]
        def pure(path):parses.append(path);return dict(artifact=path.name,sha256='placeholder')
        def failed(argv,**kw):kw['lifecycle'].update(lost());raise ChildProcessError('synthetic ECHILD zstd')
        with patch.dict(D.os.environ,{'RUNNER_TEMP':str(self.work)}):
            with self.assertRaises(ChildProcessError):D.inspect_package(artifact,pure,rows,failed)
        self.assertFalse(parses);self.assertIsNone(rows[0]['owned_child']['exit']);self.assertEqual(rows[0]['status'],'FAIL')
        self.assertFalse(list(self.work.glob('pgo-owned-package-*.tar')))
        def changed(argv,**kw):
            kw['stdout'].write(b'tar fixture');kw['lifecycle'].update(lifecycle());artifact.write_bytes(b'changed')
            return subprocess.CompletedProcess(argv,0)
        with patch.dict(D.os.environ,{'RUNNER_TEMP':str(self.work)}):
            with self.assertRaises(ValueError):D.inspect_package(artifact,pure,rows,changed)
        self.assertEqual(rows[-1]['status'],'FAIL');self.assertFalse(rows[-1]['original_unchanged'])
        self.assertFalse(list(self.work.glob('pgo-owned-package-*.tar')))

if __name__=='__main__':unittest.main()
