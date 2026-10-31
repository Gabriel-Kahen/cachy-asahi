"""Source controls only: whole guards, actual private Python recovery, inert signer."""
import ast,hashlib,importlib.util,json,os,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
ROOT=C.ROOT;L='copyworker/scripts/ci/current606-doctor2-copy'

def load(name,path,aliases=None):return C.module(name,path,aliases)
class Controls(unittest.TestCase):
 def test_whole_source_complete_parent_roles_and_null_actuals(self):
  v=C.verify();self.assertEqual(v['roles']['held606'],263);self.assertEqual(v['roles']['setup240'],240);self.assertIsNone(v['actual_run']);C.authorize(C.read(C.HERE/'input-policy.json'))
 def test_exact_606_and_all_other605_inventory_refusals(self):
  contract=load('_setup_worker_contract',ROOT/L/'contract.py');G=load('_setup_guard',ROOT/L/'guard.py',{'contract':contract});expected=dict(r.split()for r in(ROOT/L/'expected606.lock').read_text().splitlines());self.assertEqual(expected['cachy-asahi-apps'],'0.1.0-6');self.assertEqual(expected['cachy-asahi-setup'],'0.1.0-5');self.assertEqual(len(expected),606)
  for version in('0.1.0-5','0.1.0-6',None):
   actual=dict(expected)
   if version is None:actual.pop('cachy-asahi-setup')
   else:actual['cachy-asahi-setup']=version
   self.assertEqual(G.inventory(actual,expected,version),actual)
   actual['cachy-asahi-apps']='0.1.0-7'
   with self.assertRaisesRegex(ValueError,'other605'):G.inventory(actual,expected,version)
 def test_selected_setup_change_cannot_authorize_apps_or_raw_database_mutation(self):
  import copy
  contract=load('_setup_worker_target_contract',ROOT/L/'contract.py');G=load('_setup_target_guard',ROOT/L/'guard.py',{'contract':contract})
  selected='usr/bin/cachy-asahi-setup';protected=('usr/bin/cachy-asahi-apps','etc/pacman.conf','var/lib/pacman/local/cachy-asahi-apps-0.1.0-6/desc')
  before=dict(complete=True,unsupported_counts={},nodes={n:dict(type='file',sha256='a'*64)for n in(selected,*protected)},hardlink_groups={});after=copy.deepcopy(before);after['nodes'][selected]['sha256']='b'*64
  kwargs=dict(old_paths=[selected],new_paths=[selected],old_database='var/lib/pacman/local/cachy-asahi-setup-0.1.0-5',new_database='var/lib/pacman/local/cachy-asahi-setup-0.1.0-6')
  self.assertTrue(G.target(before,after,**kwargs))
  for name in protected:
   changed=copy.deepcopy(after);changed['nodes'][name]['sha256']='c'*64
   with patch.object(G,'target_failure'):
    with self.assertRaisesRegex(ValueError,'protected605'):G.target(before,changed,**kwargs)
  changed=copy.deepcopy(after);changed['hardlink_groups']={'cross':dict(members=[selected,protected[0]])}
  with self.assertRaisesRegex(ValueError,'cross hardlink'):G.target(before,changed,**kwargs)
 def test_eight_fixed_phases_and_all_original_clocks(self):
  contract=load('_setup_worker_clock_contract',ROOT/L/'contract.py');tree=ast.parse((ROOT/L/'lifecycle.py').read_bytes());phases=ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)and n.targets[0].id=='PHASES'));self.assertEqual(phases,(('baseline5','0.1.0-5'),('install6','0.1.0-6'),('same-version6','0.1.0-6'),('rollback5','0.1.0-5'),('forward6','0.1.0-6'),('remove6',None),('reinstall6','0.1.0-6'),('restore-original5','0.1.0-5')));self.assertEqual((contract.COPY_SECONDS,contract.WORKER_SECONDS,contract.CLEANUP_SECONDS),(600,1800,60));self.assertEqual(contract.WORKER_MASK,0x800400db);self.assertEqual(contract.BOUNDS['max_nodes'],200000)
  raw=(C.HERE/'owner.py').read_text();self.assertIn('active.process.wait(timeout=1800)',raw);self.assertIn('signal.setitimer(signal.ITIMER_REAL,6600)',raw)
 def test_actual_isolated_owner_help_and_preflight_have_no_actors(self):
  entry=C.HERE/'owner.py'
  for option in('--help','--source-preflight','--require-selection'):
   row=subprocess.run([sys.executable,'-I','-B',str(entry),option],capture_output=True,timeout=20)
   self.assertEqual(row.returncode,0,row.stderr)
   if option=='--help':self.assertIn(b'--source-preflight',row.stdout)
 def test_null_authority_refuses_before_actor_io(self):
  value=C.read(C.HERE/'input-policy.json');value['current606']['source']=None
  with self.assertRaises(ValueError):C.authorize(value)
  value=C.read(C.HERE/'null-policy.json')
  with self.assertRaises(ValueError):C.authorize(value)
 def test_source_shaped_legacy_seed_closures_and_paths(self):
  source=(C.HERE/'prepare.py').read_text();tree=ast.parse(source)
  functions={n.name for n in tree.body if isinstance(n,ast.FunctionDef)}
  self.assertTrue({'seed_archive20_native','seed_archive8_native'}<=functions)
  module=load('_source_real_seed_helpers',C.HERE/'prepare.py')
  self.assertEqual(len(module.ARCHIVE20_NATIVE4),4);self.assertEqual(len(module.ARCHIVE8_NATIVE8),8)
  self.assertIn('one original exact seed loop',source);self.assertIn('whole original native-base lock',source)
  workflow=(ROOT/'.github/workflows/native-arm-build.yml').read_text()
  self.assertIn('module.seed_archive20_native(',workflow);self.assertIn('module.seed_archive8_native(',workflow)
  self.assertIn('ref: 24f8d8ed9de7f4ea1aedcc9624110e553204b36c',workflow)
  self.assertLess(workflow.index('Prefill exact Doctor32/20/8/6'),workflow.index('Prefetch exact original26'))
  self.assertLess(workflow.index('Seed complete exact574 inputs'),workflow.index('Prefetch and seed exact32'))
  for token in('ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad','8ee14069b7a74455a7bea1171ba319932c9df304'):self.assertIn(token,workflow)
 def test_actual_helper_readonly_previews_preserve_complete_private_home(self):
  fixture=load('_setup_original_private_fixture',ROOT/'copyworker/held-setup/test_setup.py')
  case=fixture.SetupTests();case.setUp()
  try:
   home=case.home;before=case.snapshot();helper=ROOT/'copyworker/held-setup/setup.py'
   for operation in('activate','remove','recover'):
    argv=[sys.executable,'-I','-B',str(helper),operation,'--home',str(home),'--template-root',str(case.templates)]
    if operation=='activate':argv+=['--components','fish']
    row=subprocess.run(argv,stdin=subprocess.PIPE,capture_output=True,timeout=10)
    self.assertEqual(row.returncode,0,row.stderr);self.assertIsInstance(json.loads(row.stdout),dict);self.assertEqual(case.snapshot(),before)
  finally:case.doCleanups()
 def test_whole_original_sign_body_with_full_real_module_bindings(self):
  import owner
  _,_,_,original_api=owner.source_context(ROOT);module=original_api.scoped_load('_setup_original_full_materializer',ROOT/'held606/held604/scripts/ci/expanded600-installer-vm/materializer.py',{'contract':original_api})
  source=(ROOT/'held606/held604/scripts/ci/expanded600-installer-vm/materializer.py').read_text();node=next(n for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)and n.name=='sign');self.assertEqual(ast.get_source_segment(source,node).splitlines()[0],'def sign(home,paths,signer):')
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);home=root/'authority';home.mkdir(mode=0o700);archive=root/'candidate';archive.write_bytes(b'INERT_SOURCE_CONTROL_NO_PACKAGE');calls=[];fingerprint='A'*40
   def run(argv,**kwargs):calls.append((argv,kwargs));return types.SimpleNamespace(returncode=0)
   with patch.object(module.subprocess,'check_output',return_value='fpr:::::::::'+fingerprint+':\n')as listing,patch.object(module.subprocess,'run',side_effect=run):module.sign(home,[archive],fingerprint)
   self.assertEqual(listing.call_count,1);self.assertEqual(len(calls),2);self.assertIn('--detach-sign',calls[0][0]);self.assertEqual(calls[0][1]['timeout'],30);self.assertEqual(calls[1][0],['gpgconf','--homedir',str(home),'--kill','all']);self.assertEqual(calls[1][1]['timeout'],15)
 def test_actual_installed_helper_six_pure_recovery_bodies_on_host(self):
  # Actual private Python interruption children; no shell, GPG, chroot or native claim.
  fixture=load('_setup_pure_fixture',ROOT/L/'fixture_entry.py')
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);context=root/'context';context.mkdir();tests=context/'setup';tests.mkdir();held=ROOT/'copyworker/held-setup'
   import shutil
   for p in held.iterdir():shutil.copyfile(p,tests/p.name)
   work=root/'work';work.mkdir(mode=0o700)
   with patch.object(fixture,'CONTEXT',context),patch.object(fixture,'PROGRAM',tests/'setup.py'):report=fixture.recovery_controls(work)
   self.assertEqual(report['tests'],6);self.assertTrue(report['private_fixtures_retired']);self.assertEqual(list(work.iterdir()),[])
if __name__=='__main__':unittest.main(verbosity=2)
