# SPDX-License-Identifier: MIT
"""Finite real-source/data controls; never a positive copied606 fixture."""
import base64,copy,hashlib,json,os,subprocess,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];sys.path.insert(0,str(HERE))
import contract as O,selection as S,runtime as R,owner as Y,prepare as E,builds
PACKET=Path(os.environ['APPS7_PAIR_PACKET']).absolute()
DECISION=Path(os.environ['CURRENT606_DECISION']).absolute()
DOCTOR=Path(os.environ['DOCTOR2_PAIR_PACKET']).absolute()

class Controls(unittest.TestCase):
 def test_source_closure_and_original263_held(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(subprocess,'run',side_effect=AssertionError('actor')):
   value=O.verify();self.assertEqual(value['roles']['held606'],263);self.assertIsNone(value['actual_source'])
   P,A,X,C=Y.source_context(ROOT);P.verify(bound=False);Y.capture_program((P.HERE/'tools606.py').read_text());Y.owner_program(A.owner(P.ROOT))
 def test_real_whole_runtime_and_doctor_native_data(self):
  C,P,I=builds.apis()
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(subprocess,'run',side_effect=AssertionError('actor')):
   runtime=builds.inspect(PACKET);self.assertEqual(set(runtime),{'cachy-asahi-apps','cachy-asahi-repository-runtime'})
   with builds.aliases({'contract':C}):doctor=I.inspect(DOCTOR/'payload')
  self.assertEqual(doctor['version'],'0.2.0-1');self.assertEqual(len(doctor['payload']),4);self.assertEqual(doctor['provenance']['signature'],'UNSIGNED_REQUIRES_FRESH_ORIGINAL_PRODUCER_TEST_SIGNING')
 def test_current606_and_new_doctor_authority_refuse_drift(self):
  policy=O.read(HERE/'input-policy.json')
  if policy['status']=='UNBOUND_SOURCE_TEMPLATE':
   with self.assertRaises(ValueError):O.authorize(policy)
  else:
   O.authorize(policy)
   for name,value in [('doctor_source','0'*40),('doctor_packet_source','0'*40),('doctor_packet_index',dict(S.DOCTOR_INDEX,bytes=1))]:
    with self.subTest(name=name),self.assertRaises(ValueError):O.authorize(dict(policy,**{name:value}))
 def test_default_gates_before_any_actor_or_output(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(subprocess,'run',side_effect=AssertionError('actor')):
   with self.assertRaisesRegex(ValueError,'NULL'):O.authorize(O.read(HERE/'null-policy.json'))
   with self.assertRaises(ValueError):S.verify_actor(O.read(HERE/'null-policy.json'),'capture','0'*32)
 def test_inventory_original_doctor1_and_other605(self):
  raw=(ROOT/'held606/scripts/ci/current606-native/expected606.lock').read_bytes();base=dict(line.split()for line in raw.decode().splitlines());self.assertEqual(len(base),606);self.assertEqual(hashlib.sha256(raw).hexdigest(),S.LOCK);self.assertEqual(base['cachy-asahi-doctor'],'0.1.0-1');self.assertEqual(base['cachy-asahi-apps'],'0.1.0-6')
  after=dict(base);after['cachy-asahi-doctor']='0.2.0-1';self.assertEqual({n:v for n,v in base.items()if n!='cachy-asahi-doctor'},{n:v for n,v in after.items()if n!='cachy-asahi-doctor'})
 def test_exact_runtime_argv_and_held_clocks(self):
  C,P,I=builds.apis();paths={n:Path('/owned/'+n)for n in('runner','seed','proof','work','out')};argv=R.argv('worker','sha256:'+'0'*64,'a'*32,paths);C.bindings(Y.parse_mounts(argv))
  self.assertIn('/runner/scripts/ci/current606-doctor2-copy/worker.py',argv);self.assertEqual({v for v in argv if v.startswith('--cap-add=')},{'--cap-add='+c for c in C.WORKER_CAPS});self.assertNotIn('--privileged',argv);self.assertIn('--network=none',argv)
  self.assertEqual(R.SECONDS,dict(finalize=600,worker=1800,dispose=120));self.assertEqual((C.COPY_SECONDS,C.CLEANUP_SECONDS),(600,60))
 def test_fixed_doctor_fixture_and_no_device_or_host_audio(self):
  raw=(ROOT/'copyworker/scripts/ci/current606-doctor2-copy/fixture_entry.py').read_text();self.assertIn("PROGRAM=Path('/usr/bin/cachy-asahi-doctor')",raw);self.assertIn('SOURCE_OWNED_FIXED_PACMAN_Q_NOT_DOCTOR_QUERY',raw);self.assertIn('COPIED_ROOT_UNAVAILABLE_NOT_HEALTH_PROOF',raw);self.assertNotIn('os.mknod',raw);self.assertNotIn('mount(',raw)
  driver=(ROOT/'copyworker/scripts/ci/current606-doctor2-copy/driver.py').read_text();self.assertIn("for kind in('fresh','existing')",driver);self.assertIn('runtime_signature=verification.verify_product',driver)
 def test_source_owned_current_test_signer_and_original_cleanup(self):
  raw=(ROOT/'copyworker/scripts/ci/current606-doctor2-copy/inputs.py').read_text();self.assertIn("signer.sign(producer/'private/test-signing',[candidate_path],signer_fingerprint)",raw);self.assertIn("if getattr(public_verifier,'home',None)==verification_home:public_verifier.close()",raw);self.assertIn("C.pin(C.ordinary(candidate_path))==ARCHIVE",raw)
  lifecycle=(ROOT/'copyworker/scripts/ci/current606-doctor2-copy/lifecycle.py').read_text();self.assertIn("new2['signer']==original1['signer']",lifecycle)
 def test_only_counted_capture_and_owner_control_seams(self):
  P,A,X,C=Y.source_context(ROOT);raw=(P.HERE/'tools606.py').read_text();derived=Y.capture_program(raw);self.assertEqual(derived.replace(Y.CAPTURE_HOOK,Y.CAPTURE_LINE),raw)
  owner=Y.owner_program(A.owner(P.ROOT));self.assertIn('len(owned.rows)==8',owner);self.assertIn('active.process.wait(timeout=1800)',owner);self.assertIn('signal.setitimer(signal.ITIMER_REAL,6600)',owner)
 def test_all_source_programs_compile_without_actor(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   for p in ROOT.rglob('*.py'):compile(p.read_bytes(),str(p),'exec')

 def test_composed_prepare_constructor_path_capture_and_five_row_retirement(self):
  # Execute the genuine composition/return/copy/capture/retire route. Only the
  # pre-existing producer and native input-generation boundaries are inert;
  # this fixture has no accepted606 filesystem or passing native outcome.
  pins=O.read(ROOT/'copyworker/scripts/ci/current606-doctor2-copy/prerequisite-pins.json');raw=DECISION.read_bytes()
  policy=O.read(HERE/'null-policy.json');policy.update(status='ROOT_BOUND_CURRENT606_DOCTOR2_INPUTS',native_pair_source=S.PAIR_SOURCE,native_pair_index=S.PAIR_INDEX,source_manifest606=S.MANIFEST,doctor_source=S.DOCTOR,doctor_packet_source=S.DOCTOR_PACKET,doctor_packet_index=S.DOCTOR_INDEX,current606=dict(source=S.NATIVE,run=39106953257,decision_source=pins['current606_decision_source'],decision_path=pins['current606_decision_path'],decision_pin=pins['current606_decision'],decision_base64=base64.b64encode(raw).decode()))
  O.authorize(policy);calls=[]
  with tempfile.TemporaryDirectory()as tmp:
   out=Path(tmp);(out/'plan').mkdir();tools=out/'tools606';tools.mkdir();runner=out/'runner';runner.mkdir()
   P,A,X,C=Y.source_context(ROOT);(runner/'tools606.py').write_bytes((P.HERE/'tools606.py').read_bytes())
   def construct(**kw):
    self.assertEqual(kw['packet'],PACKET/'payload');self.assertEqual(kw['doctor_packet'],DOCTOR/'payload');self.assertEqual(kw['source'],ROOT/'held606');self.assertEqual(kw['ready604'],out/'ready604');d=kw['output'];d.mkdir();(d/'lifecycle-plan.json').write_text('{"kind":"INERT_CONSTRUCTOR_COMPONENT_NOT_NATIVE"}');calls.append('construct');return {'kind':'plan-object-not-path'}
   api=types.SimpleNamespace(make=construct)
   owned=types.SimpleNamespace(rows=[dict(name='cachy-asahi-builder-'+str(i),id=format(i+1,'064x'),status='LIVE_COMPONENT_ONLY')for i in range(4)],image='sha256:'+'1'*64)
   integration=Y.Integration(ROOT,types.SimpleNamespace(prepare=lambda *args:(tools,runner)),C,policy,PACKET,DOCTOR);integration.deadline=time.monotonic()+30
   with patch.object(builds,'apis',return_value=(object(),object(),api)),patch.object(subprocess,'Popen',side_effect=AssertionError('prepare must not spawn')):
    self.assertEqual(integration.prepare(ROOT/'held606',None,out,owned,None,C),(tools,runner))
   self.assertEqual(calls,['construct']);self.assertEqual((integration.runner/'inputs/lifecycle-plan.json').read_bytes(),(out/'doctor-inputs/lifecycle-plan.json').read_bytes())
   captured=(runner/'tools606.py').read_text();self.assertEqual(captured.replace(Y.CAPTURE_HOOK,Y.CAPTURE_LINE),(P.HERE/'tools606.py').read_text())
   selected=O.read(out/'plan/bridge-selection.json');context=S.verify_actor(selected,'capture',integration.nonce);self.assertEqual(context['source_run'],39106953257)
   cleanup=[]
   def absent():
    cleanup.append('checked-component-absence')
    for row in owned.rows:row['status']='PASS_ABSENCE_VERIFIED'
   owned.cleanup=absent;owned.rows.append(dict(name='cachy-asahi-consumer',id='f'*64,status='LIVE_COMPONENT_ONLY'))
   child=subprocess.Popen([sys.executable,'-I','-B','-c','pass'],start_new_session=True);child.wait(timeout=5)
   finish=[];active=types.SimpleNamespace(process=child,finish=lambda:finish.append('direct-child-reaped'))
   integration.after.retire_original(active);self.assertEqual(finish,['direct-child-reaped']);self.assertEqual(len(cleanup),1)
   retirement=integration.after.retirement_context();S.retired(retirement,'finalizer',integration.nonce);self.assertEqual(len(retirement['containers']),5)
   wrong=copy.deepcopy(retirement);wrong['containers']*=2
   with self.assertRaises(ValueError):S.retired(wrong,'finalizer',integration.nonce)
   self.assertEqual(integration.after.phase,'retired');integration.after.phase='captured';owned.rows*=2
   with self.assertRaises(ValueError):integration.after.retire_original(active)

class FailureRetention(unittest.TestCase):
    """Private inert children and real file guards, never a passing native606 fixture."""
    def record(self, root, *, role='worker', nonce='a'*32, terminal=None, error=None, code=7):
        from types import SimpleNamespace
        return R.failed_role_record(root, role, nonce, [sys.executable, '-I', '-B', '-c', 'INERT_CONTROL'],
                                    SimpleNamespace(process=SimpleNamespace(returncode=code,pid=12345)), terminal, error, 10)

    def tree(self, root, raw=b'original failure\n'):
        (root/'bridge-output').mkdir(mode=0o700)
        (root/'worker.log').write_bytes(raw)

    def test_failure_data_full_capture_hash_tail_and_no_authority(self):
        import base64, hashlib, json
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);raw=b'FIRST\n'+bytes(range(256))*400;self.tree(root,raw)
            value=self.record(root);capture=value['capture']
            self.assertEqual(capture['sha256'],hashlib.sha256(raw).hexdigest())
            self.assertEqual(base64.b64decode(capture['tail_base64'],validate=True),raw[-8192:])
            self.assertEqual((capture['bytes'],capture['tail_bytes'],capture['omitted_bytes'],capture['truncated']),
                             (len(raw),8192,len(raw)-8192,True))
            path=root/'bridge-output/failed-worker.json';encoded=path.read_bytes()
            self.assertLessEqual(len(encoded),32768);self.assertEqual(json.loads(encoded),value)
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertEqual(value['acceptance'],'NOT_GRANTED')
            with self.assertRaises(FileExistsError):self.record(root)
            self.assertEqual(path.read_bytes(),encoded)

    def test_failure_data_alias_hardlink_and_wrong_nonce_refused(self):
        for kind in ('symlink','hardlink','fifo','oversize','bad-nonce','unknown-role','receipt-alias'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.tree(root)
                kw={}
                if kind=='symlink':(root/'worker.log').rename(root/'private');(root/'worker.log').symlink_to('private')
                elif kind=='hardlink':os.link(root/'worker.log',root/'alias')
                elif kind=='fifo':(root/'worker.log').unlink();os.mkfifo(root/'worker.log')
                elif kind=='oversize':
                    with (root/'worker.log').open('r+b') as f:f.truncate(16*1024**2+1)
                elif kind=='bad-nonce':kw['nonce']='x'*32
                elif kind=='unknown-role':kw['role']='private/path'
                else:(root/'bridge-output').rename(root/'private-output');(root/'bridge-output').symlink_to('private-output')
                with self.assertRaises((ValueError,OSError)):self.record(root,**kw)
                self.assertFalse((root/'bridge-output/failed-worker.json').exists())

    def test_failure_data_detects_actual_log_mutation(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.tree(root,b'x'*90000);original=os.read;changed=[]
            def read(fd,count):
                raw=original(fd,count)
                if raw and not changed:
                    changed.append(True)
                    with (root/'worker.log').open('ab') as stream:stream.write(b'changed')
                return raw
            with patch.object(os,'read',side_effect=read),self.assertRaisesRegex(ValueError,'drift'):
                self.record(root)
            self.assertFalse((root/'bridge-output/failed-worker.json').exists())

    def common(self):
        import importlib.util
        name='_failed_role_held_common'
        spec=importlib.util.spec_from_file_location(name,HERE.parents[2]/'held606/held604/scripts/virtual/common.py')
        value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value

    def execute(self,root,script,*,timeout=False):
        from unittest.mock import patch
        common=self.common();seen=[]
        class Owned:
            image='sha256:'+'1'*64
            rows=[dict(status='PASS_ABSENCE_VERIFIED')]
            def launch(self,command):
                seen.append(command)
                return [sys.executable,'-I','-B','-c',script]
            def cleanup(self):pass
        self.tree(root,b'')
        (root/'worker.log').unlink()  # Original logger must itself create the capture.
        owner=R.AfterCapture(owned=Owned(),common=common,env=dict(os.environ),image=Owned.image,
                             nonce='a'*32,output=root,owner_deadline=time.monotonic()+20)
        owner.phase='finalized';paths={n:root/n for n in('runner','seed','proof','work','out')}
        error=None
        with patch.dict(R.SECONDS,worker=.08 if timeout else 10):
            try:owner.run('worker',paths)
            except BaseException as caught:error=caught
        self.assertEqual(len(seen),1);self.assertIn('--network=none',seen[0]);return owner,error

    def test_real_inert_failed_child_result_and_existing_refusal_retained(self):
        import base64,json
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);owner,error=self.execute(root,'import sys;print("OUT",flush=True);print("ERR",file=sys.stderr,flush=True);sys.exit(7)')
            self.assertIsInstance(error,ValueError);self.assertEqual(str(error),'phase failed; receipt cannot authorize continuation')
            self.assertEqual(owner.phase,'retired');self.assertEqual(owner.events[-1]['exit'],'FAILED')
            value=json.loads((root/'bridge-output/failed-worker.json').read_bytes())
            self.assertEqual(value['outcome']['returncode'],7);self.assertEqual(value['outcome']['waitid'],dict(code=os.CLD_EXITED,status=7))
            self.assertEqual(base64.b64decode(value['capture']['tail_base64']),b'OUT\nERR\n')
            self.assertTrue(R.group_absent(owner.events[-1]['pid']))

    def test_real_inert_timeout_original_error_and_retirement_retained(self):
        import json
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);owner,error=self.execute(root,'import time;print("before-timeout",flush=True);time.sleep(10)',timeout=True)
            self.assertIsNotNone(error);self.assertIn('child terminal deadline',str(error))
            value=json.loads((root/'bridge-output/failed-worker.json').read_bytes())
            self.assertIsNone(value['outcome']['waitid']);self.assertEqual(value['outcome']['returncode'],-9)
            self.assertEqual(value['outcome']['error_type'],type(error).__name__);self.assertEqual(owner.phase,'retired')
            self.assertTrue(R.group_absent(owner.events[-1]['pid']))

    def test_success_does_not_export_failure_or_change_event_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);owner,error=self.execute(root,'print("inert success only")')
            self.assertIsNone(error);self.assertEqual(owner.phase,'worker-retired')
            self.assertEqual(set(owner.events[-1]),{'phase','argv','pid','exit','direct_child_reaped','group_absent','containers_absent'})
            self.assertEqual(owner.events[-1]['exit'],0);self.assertEqual(list((root/'bridge-output').iterdir()),[])

    def test_unavailable_diagnostic_never_replaces_original_failure(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with patch.object(R,'failed_role_record',side_effect=OSError('inert diagnostic unavailable')):
                owner,error=self.execute(root,'raise SystemExit(7)')
            self.assertEqual(str(error),'phase failed; receipt cannot authorize continuation')
            self.assertEqual(owner.events[-1]['exit'],'FAILED');self.assertEqual(list((root/'bridge-output').iterdir()),[])

    def test_small_empty_and_bridge_role_failures_have_exact_counts(self):
        import hashlib,json
        for role,raw in (('finalize',b''),('dispose',b'original disposer failure')):
            with self.subTest(role=role),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);self.tree(root);(root/'worker.log').rename(root/(role+'.log'));(root/(role+'.log')).write_bytes(raw)
                value=self.record(root,role=role);capture=value['capture']
                self.assertEqual(capture['bytes'],len(raw));self.assertEqual(capture['tail_bytes'],len(raw))
                self.assertEqual(capture['omitted_bytes'],0);self.assertIs(capture['truncated'],False)
                self.assertEqual(capture['sha256'],hashlib.sha256(raw).hexdigest())
                self.assertEqual(value['outcome']['pid'],12345)
                self.assertEqual(json.loads((root/('bridge-output/failed-'+role+'.json')).read_bytes()),value)


class Archive20SourceControls(unittest.TestCase):
 def test_exact20_helpers_and_four_file_native_subset_are_source_bound(self):
  self.assertEqual(O.pin((HERE/'archive20.py').read_bytes()),dict(bytes=11096,sha256='e8ef66fc0431a04deb331f75258457bf4bdeb13a18bcd863fd5bece3b9a54968'))
  self.assertEqual(O.pin((HERE/'archive20-policy.json').read_bytes()),dict(bytes=6155,sha256='1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae'))
  self.assertEqual(E.ARCHIVE20_NATIVE4,{'libei-1.6.0-1-aarch64.pkg.tar.xz','libei-1.6.0-1-aarch64.pkg.tar.xz.sig','libgudev-238-3-aarch64.pkg.tar.xz','libgudev-238-3-aarch64.pkg.tar.xz.sig'})
  import inspect
  text=inspect.getsource(E.seed_archive20_native);self.assertIn('EXACT_NATIVE_BASE4_FROM_ARCHIVE20_SEEDED_NOT_FULL20',text);self.assertIn('module.checked_index(cache,v)',text);self.assertIn('module.digest_file(Path(cache)/n,row)',text);self.assertIn('whole seed function inverse',text)
 def test_native_four_and_full20_order_and_absolute_operands(self):
  w=(ROOT/'.github/workflows/native-arm-current606-doctor2-owned-copy.yml').read_text();self.assertLess(w.index('seed only exact4 native-base'),w.index('Build the fresh native base'));self.assertLess(w.index('seed full20 original frozen574'),w.index('Required signed604 plus606'))
  self.assertIn("&& steps.frozen574_archive20.outcome == 'success'",w);self.assertIn('"$RUNNER_TEMP/frozen574-archive20"',w);self.assertIn('"$RUNNER_TEMP/alarm-cache"',w)
  self.assertIn('"$GITHUB_WORKSPACE/archive32-original-lock/scripts/ci/maintained-desktop574-inputs.json"',w);self.assertIn('"$GITHUB_WORKSPACE/composition-desktop/scripts/ci/maintained-desktop574-inputs.json"',w);self.assertIn('seed_archive20_native(helper,policy,inputs,native,cache,destination)',w)
  self.assertIn('module.seed_exact(cache,destination,module.policy(policy,inputs))',w)


class Archive8SourceControls(unittest.TestCase):
 def test_exact8_helpers_and_native_join_are_source_bound(self):
  self.assertEqual(O.pin((HERE/'archive8.py').read_bytes()),dict(bytes=11040,sha256='5e24808152c727f5dcd19252c66e1ab121bdb9dbd6b90becb943820634898565'));self.assertEqual(O.pin((HERE/'archive8-policy.json').read_bytes()),dict(bytes=2589,sha256='2b21c05d30a9c5efd2f717cfa8475c9de3150d7729f710b348b70a84f5b16e20'))
  self.assertEqual(len(E.ARCHIVE8_NATIVE8),8)
  import inspect
  text=inspect.getsource(E.seed_archive8_native);self.assertIn('whole original native-base lock required',text);self.assertIn('set(files)&set(native)==set(files)',text);self.assertIn('module.seed_exact(Path(cache),Path(destination),v)',text)
 def test_full8_native_and_full8_producer_separate_order_and_absolute_operands(self):
  w=(ROOT/'.github/workflows/native-arm-current606-doctor2-owned-copy.yml').read_text();self.assertLess(w.index('seed only exact4 native-base'),w.index('seed full8 native-base'));self.assertLess(w.index('seed full8 native-base'),w.index('Build the fresh native base'));self.assertLess(w.index('seed full20 original frozen574'),w.index('seed full8 original frozen574'));self.assertLess(w.index('seed full8 original frozen574'),w.index('Required signed604 plus606'))
  self.assertIn("&& steps.frozen574_archive8.outcome == 'success'",w);self.assertIn('"$RUNNER_TEMP/frozen574-archive8"',w);self.assertIn('"$RUNNER_TEMP/alarm-cache"',w)
  self.assertIn('"$GITHUB_WORKSPACE/archive32-original-lock/scripts/ci/maintained-desktop574-inputs.json"',w);self.assertIn('"$GITHUB_WORKSPACE/composition-desktop/scripts/ci/maintained-desktop574-inputs.json"',w);self.assertIn('seed_archive8_native(helper,policy,inputs,native,cache,destination)',w)


if __name__=='__main__':unittest.main(verbosity=2)
