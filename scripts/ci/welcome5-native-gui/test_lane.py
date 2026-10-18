# SPDX-License-Identifier: MIT
"""Inert source/data/refusal controls; never a native GUI success fixture."""
import ast,base64,copy,fcntl,importlib.util,json,os,shutil,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import candidates as A
import derive as X
import dns_contract as D
import dns_fixture as F
SOURCE=Path(os.environ.get('WELCOME5_GUI_SOURCE',HERE.parents[2])).absolute()
BASE=Path(os.environ['WELCOME5_GUI_DEVELOPMENT']).absolute()if 'WELCOME5_GUI_DEVELOPMENT'in os.environ else None

def node(text='',name='',enabled=True):
 raw=text.encode();return dict(name_base64=base64.b64encode(name.encode()).decode(),role=43,showing=True,selected=False,checked=False,enabled=enabled,sensitive=enabled,body_base64=base64.b64encode(raw).decode(),text_sha256=D.sha(raw),text_bytes=len(raw))
def report():return D.encoded(dict(status='STORED_CONNECTION_PROFILES',profiles=[D.PROFILE],live_dns='NOT_REAPPLIED_STORED_PROFILE_ONLY'))
def functions(text):return {n.name:ast.dump(n,include_attributes=False)for n in ast.parse(text).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
def child():return dict(argv=D.ARGV,raw_argv=['/usr/bin/python3',*D.ARGV],uid=[23001]*4,welcome_pid=80,original_executable=D.ARGV[0],stopped=False,pid=100,pgid=100,starttime=123,supervisor_pid=90,supervisor_starttime=122,exe='/usr/bin/python3.14')

class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  global BASE
  if BASE is not None:return
  import prepare
  cls.workspace=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.workspace.cleanup);BASE=Path(cls.workspace.name)
  assets=Path(os.environ['WELCOME5_GUI_ASSETS']).absolute()
  with patch('subprocess.Popen',side_effect=AssertionError('actor prohibited')),patch('subprocess.run',side_effect=AssertionError('actor prohibited')):
   for selected in ('minimal','overlay'):
    prepare.prepare(SOURCE,assets,BASE/('generated-'+selected),selected)
    (BASE/('source-control-'+selected+'.json')).write_text(json.dumps(dict(status='PASS_SOURCE_ONLY_NO_ACTORS',actuals=None)))
  (BASE/'held-original-data-joins.json').write_text(json.dumps(dict(code_imported=False,input_route='EXACT_PUBLIC_NATIVE_ARCHIVES_NOT_GUI_ACCEPTANCE')))

 def test_exact_dns_record_and_duplicate_malformed_foreign_refusal(self):
  value,summary=D.report(report());self.assertIn(D.UUID,summary)
  bad=[b'{}',report()+b'\0',report().replace(b'"profiles":',b'"profiles": [], "profiles":')]
  for key,val in [('status','OTHER'),('profiles',[]),('profiles',[dict(D.PROFILE,name='foreign')]),('live_dns','REAPPLIED')]:
   row=copy.deepcopy(value);row[key]=val;bad.append(D.encoded(row))
  for raw in bad:
   with self.subTest(raw=raw[:50]),self.assertRaises((ValueError,UnicodeError)):D.report(raw)
 def test_complete_real_report_preview_and_button_required(self):
  C=A.load('dns_control_management',SOURCE/'scripts/ci/welcome-management-native/management_contract.py')
  raw=report();_,summary=D.report(raw);expected=dict(text=['Elapsed:',summary,raw.decode()],buttons={D.LABEL:True})
  snap=dict(status='PASS',pid=80,nodes=[node(t)for t in expected['text']]+[node(name=D.LABEL)])
  self.assertTrue(D.snapshot(C,snap,80,expected))
  for mutate in ('truncated','disabled','pid'):
   row=copy.deepcopy(snap)
   if mutate=='truncated':row['nodes'][2]=node(raw.decode()[:-5])
   elif mutate=='disabled':row['nodes'][-1]['enabled']=False
   else:row['pid']=81
   with self.subTest(mutate=mutate),self.assertRaises(ValueError):D.snapshot(C,row,80,expected)
 def test_exact_three_argument_owned_default_process(self):
  row=child();D.process(row,80)
  for k,v in [('argv',['/usr/bin/cachy-asahi-dns','profiles']),('uid',[0]*4),('welcome_pid',81),('pgid',99),('stopped',True),('supervisor_pid',80)]:
   with self.subTest(field=k),self.assertRaises(ValueError):D.process(dict(row,**{k:v}),80)
 def test_no_connection_activation_bus_replacement_or_daemon_capability(self):
  cfg=F.configuration(F.WORK)
  for exact in ('dns=none','rc-manager=unmanaged','unmanaged-devices=*','managed=0','enabled=false'):self.assertIn(exact,cfg)
  self.assertIn(b'autoconnect=false',F.keyfile());self.assertNotIn(b'address',F.keyfile())
  argv=F.daemon_argv();self.assertEqual(argv[:6],['/usr/bin/setpriv','--bounding-set=-all','--inh-caps=-all','--ambient-caps=-all','--no-new-privs','--'])
  tree=ast.parse((HERE/'dns_fixture.py').read_text());calls=[n for n in ast.walk(tree)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='nm']
  self.assertEqual(len(calls),2);self.assertTrue(all(n.args[0].value=='--get-values'for n in calls))
  self.assertNotIn('dbus-daemon',(HERE/'dns_fixture.py').read_text())
 def test_private_created_tree_removed_preexisting_identity_preserved(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp)/'state';root.mkdir();p=root/'held';p.write_bytes(b'held');before=F.tree(root)
   (root/'owned').mkdir();(root/'owned/new').write_bytes(b'new');F.remove_new(root,before)
   self.assertEqual(F.tree(root),before);self.assertEqual(p.read_bytes(),b'held')
 def test_changed_preexisting_state_refuses_without_removal(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp)/'state';root.mkdir();p=root/'held';p.write_bytes(b'held');before=F.tree(root);p.write_bytes(b'foreign');new=root/'owned';new.write_bytes(b'new')
   with self.assertRaises(ValueError):F.remove_new(root,before)
   self.assertTrue(new.exists());self.assertEqual(p.read_bytes(),b'foreign')
 def test_null_policy_refuses_before_output_or_actors(self):
  A.verify_source(SOURCE)
  original=A.read
  def fixture(path,*args):return original(HERE/'null-policy.json')if Path(path)==A.HERE/'input-policy.json'else original(path,*args)
  with patch.object(A,'read',side_effect=fixture),patch('subprocess.Popen',side_effect=AssertionError('actor')),patch('subprocess.run',side_effect=AssertionError('actor')):
   with self.assertRaisesRegex(ValueError,'NULL'):A.stage(SOURCE,BASE/'absent-assets',BASE/'must-not-exist')
  self.assertFalse((BASE/'must-not-exist').exists())
 def test_whole_source_guard_rejects_unrecognized_predecessor(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);file=root/'scripts/ci/welcome-management-native/management_phase.py';file.parent.mkdir(parents=True);file.write_text((SOURCE/'scripts/ci/welcome-management-native/management_phase.py').read_text()+'\n# foreign\n')
   with self.assertRaisesRegex(ValueError,'whole held'):X.phase(root)
 def test_unaffected_management_functions_ast_held(self):
  for name,derive,changed in [('management_phase.py',X.phase,{'exercise','report_command'}),('management_root.py',X.root_fixture,{'serve','find'}),('management_contract.py',X.management,{'verify_result'})]:
   old=functions((SOURCE/'scripts/ci/welcome-management-native'/name).read_text());new=functions(derive(SOURCE))
   self.assertEqual(set(old),set(new));self.assertEqual({k:v for k,v in old.items()if k not in changed},{k:v for k,v in new.items()if k not in changed})
 def test_both_real_generated_profile_routes_keep_all_original_frames_limits(self):
  for selected in ('minimal','overlay'):
   root=BASE/('generated-'+selected);runtime=(root/'desktop574_runtime.py').read_text()
   contract=(root/'contract.py').read_text();phase=(root/'management_phase.py').read_text();fixture=(root/'desktop574_fixture.sh').read_text()
   self.assertIn('dns_phase.exercise(base,stage,env,workspace,current,hooks,request,stable,C)',phase)
   self.assertLess(phase.index('dns_phase.exercise('),phase.index('closing_before=stable()'))
   for view in ('home','terminal-action','files-action','system','first-steps','updates','recovery','management-absent','management-doctor','management-orphans','management-failure','management-dns','management-closing'):self.assertIn(selected+'-'+view,runtime)
   self.assertNotIn(('overlay'if selected=='minimal'else'minimal')+'-management-dns',runtime)
   self.assertIn('TimeoutStartSec=1200',fixture);self.assertIn('1300',runtime);self.assertIn('1080',(root/'doctor_lifetime.py').read_text())
   self.assertEqual(contract.count('foreign or missing profile event'),2)
 def test_owner_runtime_and_input_null_guards_precede_every_actor(self):
  import assets,job,run
  original=A.read
  def fixture(path,*args):return original(HERE/'null-policy.json')if Path(path)==A.HERE/'input-policy.json'else original(path,*args)
  with patch.object(A,'read',side_effect=fixture),patch('subprocess.Popen',side_effect=AssertionError('actor')),patch('subprocess.run',side_effect=AssertionError('actor')):
   for function,args in [(job.prove,(SOURCE,'minimal',{})),(assets.prepare,(SOURCE,BASE/'none',BASE/'none',BASE/'must-not-exist')),(run.execute,(SOURCE,BASE/'none',BASE/'none',BASE/'must-not-exist','minimal'))]:
    with self.subTest(function=function.__name__),self.assertRaisesRegex(ValueError,'NULL'):function(*args)
  self.assertFalse((BASE/'must-not-exist').exists())
 def test_active_or_unknown_runtime_preserves_producer(self):
  import job
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);runtime=root/'runtime';runtime.mkdir();lease=os.open(runtime/'runtime.lock',os.O_CREAT|os.O_RDWR,0o600)
   try:
    fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
    with patch.object(job,'binding'),patch('subprocess.run',side_effect=AssertionError('producer must remain')):
     result=job.cleanup(SOURCE,'minimal',dict(runtime_path=str(runtime)),root/'base',runtime,root/'locked.json')
    self.assertEqual(result['status'],'FAIL');self.assertEqual(result['producer'],'NOT_RETIRED')
    fcntl.flock(lease,fcntl.LOCK_UN)
    for n,row in enumerate([dict(child_started=True,reaped=False,group_absent=False),dict(child_started=True,reaped=True,group_absent=False)]):
     (runtime/'runtime-terminal.json').write_text(json.dumps(row))
     with patch.object(job,'binding'),patch('subprocess.run',side_effect=AssertionError('producer must remain')):
      result=job.cleanup(SOURCE,'minimal',dict(runtime_path=str(runtime)),root/'base',runtime,root/('unknown'+str(n)+'.json'))
     self.assertEqual(result['status'],'FAIL');self.assertEqual(result['producer'],'NOT_RETIRED')
   finally:os.close(lease)
 def test_clean_no_actor_prefix_is_not_native_gui_acceptance(self):
  import job
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp)
   with patch.object(job,'binding'),patch('subprocess.run',side_effect=AssertionError('actor')):
    result=job.cleanup(SOURCE,'minimal',dict(runtime_path=str(root/'runtime')),root/'base',root/'runtime',root/'cleanup.json')
   self.assertEqual(result['runtime'],'NOT_STARTED');self.assertEqual(result['producer'],'NOT_STARTED')
   self.assertNotEqual(result['status'],job.SUCCESS)
 def test_wrapper_receipt_exact_argv_pin_joins_and_create_once(self):
  import invocation as I
  # Data-shape control only: no actual source or run ID and no GUI admission.
  proof=dict(profile='minimal',source_path='/source-control-only',runtime_path='/control/welcome5-runtime',manifest_sha256=D.sha(b'manifest-source-control'))
  pins=[dict(bytes=len(raw),sha256=D.sha(raw))for raw in (b'proof-source-control',b'manifest-source-control',b'runner-source-control')]
  with tempfile.TemporaryDirectory()as tmp:
   path=Path(tmp)/'profile-invocation.json';value=I.write(path,I.expected(proof),proof,*pins)
   self.assertEqual(I.validate(value,proof,*pins),value)
   with self.assertRaises(FileExistsError):I.write(path,I.expected(proof),proof,*pins)
   for key in ('source_proof','source_manifest','runner_proof'):
    altered=copy.deepcopy(value);altered[key]['sha256']=D.sha(b'foreign')
    with self.subTest(key=key),self.assertRaises(ValueError):I.validate(altered,proof,*pins)
   for argv in (value['argv']+['--profile','overlay'],value['argv'][1:],['run','--profile','minimal']):
    with self.subTest(argv=argv),self.assertRaises(ValueError):I.validate(dict(value,argv=argv),proof,*pins)
 def test_actual_receipt_is_before_child_and_retention_is_required(self):
  import job
  text=(HERE/'run.py').read_text();self.assertLess(text.index('I.write('),text.index('active=common.LoggedProcess('))
  self.assertIn("'profile-invocation.json'",(HERE/'job.py').read_text())
  self.assertIn('invocation.validate(C.read(runtime/',(HERE/'job.py').read_text())
  self.assertIn("proof['runtime_path']==str(a.runtime.absolute())",(HERE/'job.py').read_text())
 def test_emitted_workflow_exact_alias_hashes_and_source_clocks(self):
  import hashlib,re
  a=(SOURCE/'.github/workflows/native-arm-build.yml').read_bytes();b=(SOURCE/'.github/workflows/native-arm-welcome5-dns-gui.yml').read_bytes();self.assertEqual(a,b)
  text=a.decode();self.assertIn(hashlib.sha256((HERE/'job.py').read_bytes()).hexdigest(),text);self.assertIn(hashlib.sha256((HERE/'source-manifest.json').read_bytes()).hexdigest(),text)
  self.assertLess(text.index('job.py" inputs'),text.index('Seed the six exact retained inputs'))
  self.assertIn('cancel-in-progress: false',text);self.assertIn('2200s',text)
  self.assertIn('2300s',text);self.assertIn('330s',text)
 def test_real_held_source_baseline_controls_are_not_new_gui_credit(self):
  row=json.loads((BASE/'held-original-data-joins.json').read_text());self.assertIs(row['code_imported'],False)
  for selected in ('minimal','overlay'):
   row=json.loads((BASE/('source-control-'+selected+'.json')).read_text());self.assertEqual(row['status'],'PASS_SOURCE_ONLY_NO_ACTORS');self.assertIsNone(row['actuals'])

if __name__=='__main__':unittest.main(verbosity=2)
