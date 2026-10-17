# SPDX-License-Identifier: MIT
"""Actor-blocked finite source and real-temporary-file controls; no native credit."""
import ast,copy,importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import contract as C
import adapter,prepare,vm,job

def dump(node):return ast.dump(node,include_attributes=False)
def function(raw,name):return next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name==name)

class Lane(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.original=Path(os.environ['FULL574_REPAIR16K_SOURCE']).absolute();cls.tmp=tempfile.TemporaryDirectory();cls.root=Path(cls.tmp.name)/'source'
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')):cls.emitted=prepare.emit(cls.original,cls.root)
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def setUp(self):self.block=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden'));self.block.start()
 def tearDown(self):self.block.stop()
 def native(self,name):return C.read(self.root/C.NATIVE/name)
 def test_closed_exact_emission_and_unbound_before_output(self):
  with patch.object(C,'HERE',self.root/C.LANE):rows=C.check_source(self.root)
  self.assertEqual(len(rows),134);self.assertEqual(len(prepare.OWN),11);self.assertEqual(C.row(self.root/C.NATIVE/'source-manifest.json')['sha256'],C.NATIVE_MANIFEST)
  self.assertEqual(C.row(self.root/C.LANE/'vm.py'),C.row(HERE/'vm.py'))
  with self.assertRaisesRegex(ValueError,'UNBOUND16K'):C.gate(self.root,'repair-bytes')
  self.assertEqual(set(C.decode(self.native('source-manifest.json'))['files']),set(C.decode(C.read(self.original/C.NATIVE/'source-manifest.json'))['files']))
 def test_guard_derivative_preserves_all_other_backend_functions(self):
  raw=C.read(self.root/'scripts/apps/transaction.py');changed=adapter.backend(raw);before=adapter.functions(raw);after=adapter.functions(changed)
  self.assertEqual([n for n in before if before[n]!=after[n]],['environment_guard']);self.assertIn(adapter.ENV_AFTER.encode(),changed)
  with self.assertRaises(ValueError):adapter.backend(changed)
 def test_lifecycle_genuine_case_loop_and_helpers_byte_AST_preserved(self):
  raw=self.native('lifecycle.py');out=adapter.lifecycle(raw);before=adapter.functions(raw);after=adapter.functions(out)
  self.assertEqual([n for n in before if before[n]!=after[n]],['inspected','main']);self.assertEqual(set(after)-set(before),{'_vm_backend'})
  # Compare each main loop; only entry predicate changes before those loops.
  self.assertEqual([dump(n) for n in ast.walk(function(raw,'main')) if isinstance(n,ast.For)],[dump(n) for n in ast.walk(function(out,'main')) if isinstance(n,ast.For)])
  for n in ('owned','observed','argv','leaf','damage','restore','repaired'):self.assertEqual(before[n],after[n])
  self.assertIn(b"sys.path.insert(0,'/source/scripts/ci/apps-full574-repair-native');import contract as C",out);self.assertIn(b"SOURCE/'scripts/ci/apps-full574-repair-native/checks.py'",out);self.assertIn(b'/execution/scripts/apps/repair_inspection.py',out);self.assertNotIn(b"Path('/.dockerenv')",out)
 def test_real_execution_tree_closed_preserved_and_drift_refused(self):
  manifest=C.decode(self.native('source-manifest.json'))
  with tempfile.TemporaryDirectory() as d:
   out=Path(d)/'execution';r=adapter.execution(self.root,out,manifest);self.assertEqual(r['changed'],['scripts/apps/transaction.py']);self.assertTrue(r['original_source_preserved']);self.assertEqual(len(r['execution_files']),113)
   for n,pin in r['execution_files'].items():self.assertEqual(C.row(out/n),pin)
   bad=copy.deepcopy(manifest);bad['files']['scripts/apps/transaction.py']['sha256']='0'*64
   with self.assertRaises(ValueError):adapter.execution(self.root,Path(d)/'drift',bad)
   self.assertFalse((Path(d)/'drift').exists())
 def test_source_alias_and_input_tree_alias_refusal(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'a').write_bytes(b'actual');(root/'alias').symlink_to('a')
   with self.assertRaises(ValueError):C.row(root/'alias')
   with self.assertRaises(ValueError):C.tree(root)
   (root/'alias').unlink();os.link(root/'a',root/'hard')
   with self.assertRaises(ValueError):C.tree(root)
  for n in ('../x','a/../x','/x','a//x','a\\x','a/.'):
   with self.assertRaises(ValueError):C.relative(n)
 def test_native_module_identity_and_original_actor_security(self):
  native=C.load('control_native',self.root/C.NATIVE/'contract.py');original=sys.modules['contract'];J=job.native_job(self.root,native)
  self.assertIs(J.C,native);self.assertIs(J.H.C,native);self.assertIs(sys.modules['contract'],original);self.assertIs(vm.C,C)
  parts=J.derived(C.read(J.H.__file__).decode());changed=job.actor_body(parts['actor'])
  call=function(changed,'actor');calls=[n for n in ast.walk(call) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='_repair16k_dispatch'];self.assertEqual(len(calls),1)
  reverse=changed.replace(' result=_repair16k_dispatch(command,role,root,output,report,api,argv,False,',' result=command(argv,False,');self.assertEqual(reverse,parts['actor'])
  for flag in ('--network=none','--read-only','--security-opt=no-new-privileges','--pids-limit=128','--memory=4g','--cpus=2','--ulimit=nofile=8192:8192'):self.assertIn(flag,changed)
 def test_actual_isolation_source_uses_only_original_five_caps(self):
  guest=C.read(HERE/'guest.py');self.assertEqual(C.CAPS,(0,1,3,4,31));self.assertEqual(C.MASK,2147483675)
  borrowed=C.read(self.root/'scripts/ci/current604-apps6-updater16k/guest.py');old=ast.get_source_segment(borrowed.decode(),function(borrowed,'isolate'))
  self.assertIn("'EXACT_ORIGINAL_CALLER_NINE_CAPABILITIES_NO_SYS_ADMIN'",old);self.assertIn(b"'EXACT_ORIGINAL_REPAIR_FIVE_CAPABILITIES_NO_SYS_ADMIN'",guest)
  self.assertIn(b"os.statvfs('/seed').f_flag&os.ST_RDONLY",guest);self.assertIn(b"changed_fields=['source_identity']",guest)
 def test_qemu_no_network_and_shared_deadline_no_reset(self):
  argv=vm.qemu(Path('/Image'),Path('/boot.raw'),Path('/data.raw'),1792191793115000000)
  self.assertEqual(argv[argv.index('-nic')+1],'none');self.assertEqual(argv[argv.index('-m')+1],'4096');self.assertEqual(argv[argv.index('-smp')+1],'2');self.assertEqual(argv.count('-drive'),2);self.assertIn('caa_apps574_repair16k=1',argv[argv.index('-append')+1])
  with patch.object(vm.time,'monotonic',return_value=150):self.assertEqual(vm.remaining(200,3000),50)
  with patch.object(vm.time,'monotonic',return_value=201):
   with self.assertRaises(ValueError):vm.remaining(200,3000)
  raw=C.read(HERE/'vm.py').decode();self.assertEqual(raw.count('deadline=time.monotonic()+3000'),1);self.assertIn('remaining(deadline,3000);return result',raw)
 def model(self):
  old=dict(source='/seed',token='control',source_identity=[1,2]);after=dict(old,source_identity=[3,4]);fresh=dict(status='FRESH_ACTUAL_GUEST_SOURCE_LEASE',before=old,before_sha256=C.sha(C.encoded(old)),after=after,after_sha256=C.sha(C.encoded(after)),source_identity=[3,4],changed_fields=['source_identity'])
  s=dict(nonce='model-only-not-runtime',case='repair-bytes',kernel=dict(release='model'),clock_seed_ns=123,host_lease=old,host_lease_sha256=C.sha(C.encoded(old)),source_tree_sha256='a'*64,source_capabilities_sha256='b'*64)
  boot=dict(event='boot',page_size=16384,architecture='aarch64',kernel='model',kernel_profile_sha256=C.sha(C.encoded(s['kernel'])),clock=dict(nofile=dict(after=[8192,8192]),seed_realtime_ns=123),lease=fresh)
  worker=dict(case=s['case'],status='PRIVATE_COMPLETE_CASE',isolation=dict(after=dict(mask=C.MASK,nnp=1,inh=0,amb=0),uid=0,gid=0,groups=[],seccomp=2),child=dict(exit_code=0,group_absence_verified=True),source_tree_sha256='a'*64,source_capabilities_sha256='b'*64,ELF=dict(status='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT',count=1))
  result=dict(event='result',status=C.PASS,case=s['case'],worker=worker,page_size=16384,lease_sha256=fresh['after_sha256']);end=dict(event='exit',status=C.PASS,cleanup='PASS_OWNED_MOUNTS_RETIRED');return s,[boot,result,end]
 def protocol(self,s,frames):return b'\n'.join(('APPS574_REPAIR16K '+s['nonce']+' '+json.dumps(v)).encode() for v in frames)
 def test_protocol_inert_positive_and_original_runtime_refusals(self):
  s,frames=self.model();vm.protocol(self.protocol(s,frames),s,None)
  for path,value in [(('0','page_size'),4096),(('1','worker','child','exit_code'),1),(('1','worker','isolation','after','mask'),0),(('2','cleanup'),'UNKNOWN'),(('0','clock','seed_realtime_ns'),456),(('1','case'),'repair-missing')]:
   bad=copy.deepcopy(frames);v=bad[int(path[0])]
   for n in path[1:-1]:v=v[n]
   v[path[-1]]=value
   with self.assertRaises(ValueError):vm.protocol(self.protocol(s,bad),s,None)
  with self.assertRaises(ValueError):vm.protocol(self.protocol(s,frames).replace(b'APPS574_REPAIR16K',b'APPS6_UPDATE16K'),s,None)
 def test_prior_kernel_narrow_scope_and_pins_data_only(self):
  # Fake revision identity ONLY; no Git/native/boot authorization is claimed.
  K=C.load('control_kernel',self.root/'scripts/ci/managed-gui-generic16k/kernel_contract.py')
  profile=dict(schema_version=1,profile=K.PROFILE,release=K.RELEASE,architecture='aarch64',page_size=16384,source_revision=K.REVISION,archive_sha256=K.ARCHIVE,helper_sha256=K.HELPER_SHA,fragment_sha256=K.FRAGMENT_SHA,diagnostic_fragment_sha256=K.DIAGNOSTIC_SHA,Image=dict(bytes=64,sha256='1'*64),config=dict(bytes=1,sha256='2'*64),modules='DISABLED')
  authority=dict(status='ROOT_ACCEPTED_GENERIC16K_KERNEL_PROFILE',scope='MANAGED_GUI_KERNEL_BUILD_AND_BOOT_COMPONENT_ONLY',GNU_installed_lifecycle='NOT_ACCEPTED',hardware='NOT_RUN',release='NOT_ADMITTED',source_sha='3'*40,run_id='123',profile=profile,retained_receipt=dict(bytes=1,sha256='4'*64),root_decision=dict(bytes=1,sha256='5'*64))
  with tempfile.TemporaryDirectory() as d:
   path=Path(d)/'authority.json'
   def invoke(value):
    C.save(path,value);binding=dict(kernel_authority=dict(path='authority.json',**C.row(path)),kernel_authority_source='6'*40)
    with patch.object(C,'gate',return_value=(None,binding)),patch.object(C.subprocess,'check_output',return_value='6'*40+'\n'):return C.prior_kernel(self.root,'repair-bytes',path)
   self.assertEqual(invoke(authority)[0],profile)
   for k,v in (('scope','WHOLE_GNU_LIFECYCLE'),('GNU_installed_lifecycle','ACCEPTED'),('status','ROOT_ACCEPTED_PRIVATE_GNU16K_RUNTIME')):
    with self.assertRaises(ValueError):invoke(dict(authority,**{k:v}))
 def test_cleanup_absence_fail_closed_and_source_bounds(self):
  with tempfile.TemporaryDirectory() as d:
   out=Path(d);job.cleanup_gate(out);(out/'repair16k-media').mkdir()
   with self.assertRaises(ValueError):job.cleanup_gate(out)
   (out/'repair16k-media').rmdir();C.save(out/'repair16k-state.json',dict(status='RETAINED_VM_OR_MEDIA_ABSENCE_UNKNOWN'))
   with self.assertRaises(ValueError):job.cleanup_gate(out)
   C.save(out/'repair16k-state.json',dict(status='PASS_VM_GROUP_AND_PRIVATE_MEDIA_RETIRED'));job.cleanup_gate(out)
  disk=C.read(HERE/'disk.py');self.assertIn(b'48*1024**3',disk);self.assertIn(b"('boot',16*1024**3),('data',24*1024**3)",disk);self.assertIn(b"backend(s,'dispose-copy'",disk)

if __name__=='__main__':unittest.main()
