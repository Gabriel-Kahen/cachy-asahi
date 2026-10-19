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
  for name,derive,changed in [('management_phase.py',X.phase,{'exercise','report_command'}),('management_root.py',X.root_fixture,{'serve','find'}),('management_contract.py',X.management,{'verify_result','visible_control','action'})]:
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

class GuestTrustProjectionControls(unittest.TestCase):
 def test_closed_legacy_signer_is_replaced_with_same_current_certificate_for_guest(self):
  import importlib.util
  from unittest.mock import patch
  spec=importlib.util.spec_from_file_location('guest_trust_projection_unit',HERE/'renewal.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
  with tempfile.TemporaryDirectory()as td:
   base=Path(td);overlay=base/'assets'/'renewal';overlay.mkdir(parents=True);out=base/'output';out.mkdir();(overlay/'TEST-public.asc').write_bytes(b'UNIT_PUBLIC_CERTIFICATE_NOT_CRYPTO_AUTHORITY');(out/'TEST-public.asc').write_bytes(b'UNIT_LEGACY_CERTIFICATE');(out/'control.json').write_bytes(R.encoded(dict(signer='A'*40)))
   with patch.object(R,'selection'),patch.object(R,'overlay',return_value=dict(roles={},created=1,expires=2)):
    token=object();self.assertIs(R.apply(base,base/'assets',out,token),token)
   self.assertEqual((out/'TEST-public.asc').read_bytes(),(overlay/'TEST-public.asc').read_bytes());self.assertEqual((out/'welcome5-TEST.asc').read_bytes(),(overlay/'TEST-public.asc').read_bytes());self.assertEqual(R.read(out/'control.json'),dict(signer=R.SIGNER));self.assertEqual(R.read(out/'trust.json'),[dict(key='welcome5-TEST.asc',signer=R.SIGNER)])
 def test_extra_or_invalid_guest_control_refuses_before_signature_or_certificate_writes(self):
  import importlib.util
  from unittest.mock import patch
  spec=importlib.util.spec_from_file_location('guest_trust_projection_refusal',HERE/'renewal.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
  for value in(dict(signer='A'*40,extra=True),dict(signer=None),dict(signer=True),dict(signer='A'*39),dict(other='A'*40)):
   with self.subTest(value=value),tempfile.TemporaryDirectory()as td:
    base=Path(td);out=base/'output';out.mkdir();(out/'control.json').write_bytes(R.encoded(value));before={p.name:p.read_bytes()for p in out.iterdir()}
    with patch.object(R,'selection'),patch.object(R,'overlay',return_value=dict(roles={},created=1,expires=2)),self.assertRaises(ValueError):R.apply(base,base/'assets',out,{})
    self.assertEqual({p.name:p.read_bytes()for p in out.iterdir()},before)

class DNSReportFocusControls(unittest.TestCase):
 def test_report_scroll_contract_rejects_foreign_scope_and_role_or_clipping(self):
  from types import SimpleNamespace
  namespace={'__name__':'inert_dns_focus_contract'};exec(compile(X.management(SOURCE),'<source-owned-management-contract>','exec'),namespace);C=SimpleNamespace(**namespace)
  pid=91;chain=[dict(pid=pid,role=r,visible=True,showing=True,rect=[0,0,1000,550])for r in(62,20,39,68,49,23)]
  proof=dict(status='PASS',pid=pid,interface='Component',action_name='ensure-visible',actions=0,scroll_called=True,coordinate_space='ATSPI_SCREEN',scroll_returned=False,focus_called=True,focused=True,unclipped_after_scroll=False,method='FOCUS_SCROLL',name_base64=base64.b64encode(b'View report').decode(),chain=chain)
  window=dict(pid=pid,mapped=True,visible=True,floating=True,hidden=False,xwayland=False,at=[12,12],size=[1000,550],title='cachy-asahi Welcome',**{'class':'cachy-asahi-welcome'},address='0x123')
  C.visible_control(proof,pid,'View report',window,report_scope='Stored DNS profiles')
  for change in('scope','role','clip','foreign_pid','hidden','focus'):
   row=copy.deepcopy(proof);scope='Stored DNS profiles'
   if change=='scope':scope='Doctor'
   elif change=='role':row['chain'][0]['role']=43
   elif change=='clip':row['chain'][0]['rect']=[0,540,100,20]
   elif change=='foreign_pid':row['chain'][1]['pid']=92
   elif change=='hidden':row['chain'][1]['showing']=False
   else:row['focused']=False
   with self.subTest(change=change),self.assertRaises(ValueError):C.visible_control(row,pid,'View report',window,report_scope=scope)
  with self.assertRaises(ValueError):C.visible_control(proof,pid,'View report',window)
 def test_exact_report_scroll_precedes_original_activation_and_preserves_gates(self):
  phase=(HERE/'dns_phase.py').read_text();self.assertEqual(phase.count("action('View report',D.TITLE,scroll=True)"),2)
  self.assertIn("action('View report',D.TITLE,scroll=True)\n        action('View report',D.TITLE)",phase)
  for held in("until=time.monotonic()+45","remaining(until)","D.process(child,current.process.pid)","C.retirement_proof(fast,proof,child,proof['inventory'])","stable()==baseline","hooks['capture'](D.VIEW,semantic)"):self.assertIn(held,phase)
  for driver in (X.driver(X.source_text(SOURCE,'a11y_driver.c')),):
   for held in('getuid() == 23001 && geteuid() == 23001','matches == 1 && target','depth <= 12 && nodes < 192','focused control remains clipped','alarm(20)','atspi_set_timeout(1000, 1000)'):self.assertIn(held,driver)
   self.assertIn('candidate_rows[2][13]',driver);self.assertIn('FAILURE_DATA_ONLY',driver);self.assertIn('NONATOMIC_SAME_CALL_AFTER_REFUSED_MATCH',driver);self.assertIn('valid_mask',driver)
   self.assertIn('if (matches != 1 || !target) failed_candidates((guint)pid);',driver)
   self.assertIn('clear_candidates();\n        check(matches == 1 && target',driver)

class DNSReportPreviewControls(unittest.TestCase):
 def test_exact_quoted_fixed_caption_and_unquoted_snapshot_refusal(self):
  raw=report();_,summary=D.report(raw)
  self.assertEqual(summary,'1 stored connection profile. Read only; live DNS was not reapplied.\nbdb74c1f-1e9e-44b1-820a-705dca6cb760 | 802-3-ethernet | "Owned GUI DNS profile"')
  C=A.load('dns_preview_management',SOURCE/'scripts/ci/welcome-management-native/management_contract.py')
  expected=dict(text=['Elapsed:',summary,raw.decode()],buttons={D.LABEL:True});snap=dict(status='PASS',pid=80,nodes=[node(t)for t in expected['text']]+[node(name=D.LABEL)])
  self.assertTrue(D.snapshot(C,snap,80,expected))
  bad=copy.deepcopy(snap);bad['nodes'][1]=node(summary.replace('"Owned GUI DNS profile"','Owned GUI DNS profile'))
  with self.assertRaises(ValueError):D.snapshot(C,bad,80,expected)
 def test_production_route_scrolls_expanded_report_before_preview_without_capture_authority(self):
  import dns_phase
  from types import SimpleNamespace
  class PreviewStop(Exception):pass
  events=[];calls=[];requests=[];raw=report()
  C=SimpleNamespace(need=D.need,visible_control=lambda *a,**k:None)
  def request(kind,**kwargs):
   requests.append(kind)
   if kind=='observed':return dict(process=child())
   return {}
  def a11y(kind,label=None,**kwargs):
   calls.append((kind,label,kwargs.get('scope')))
   return dict(actions=1,action_name='click')
  def wait(check,healthy,seconds,label):
   self.assertGreater(seconds,0)
   if label=='actual DNS report preview':raise PreviewStop()
   return check()
  helpers=SimpleNamespace(report_command=lambda *a:raw,completed_report_state=lambda:True,remaining=lambda until:until-__import__('time').monotonic())
  hooks=dict(a11y=a11y,window=lambda pid:{},wait=wait,healthy=lambda:True,capture=lambda *a:self.fail('no accepting frame in this control'))
  with patch.dict(sys.modules,{'management_phase':helpers}),self.assertRaises(PreviewStop):
   dns_phase.exercise(SimpleNamespace(emit=lambda event,**kw:events.append(dict(event=event,**kw))),'minimal',{},Path('/source-control-only'),SimpleNamespace(process=SimpleNamespace(pid=80)),hooks,request,lambda:'unchanged',C)
  self.assertEqual(calls,[('scroll',D.LABEL,None),('activate',D.LABEL,None),('scroll','View report',D.TITLE),('activate','View report',D.TITLE),('scroll','View report',D.TITLE)])
  self.assertEqual([e['sequence']for e in events],[1,2,3,4,5]);self.assertEqual(requests[-1],'dns-close')
  self.assertNotIn('dns_result',[e['event']for e in events])
 def test_verifier_requires_exact_six_actions_and_post_open_scroll_before_frame(self):
  tree=ast.parse((HERE/'dns_contract.py').read_text());verify=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='verify')
  plans=[n.comparators[0]for n in ast.walk(verify)if isinstance(n,ast.Compare)and isinstance(n.left,ast.ListComp)and isinstance(n.comparators[0],ast.List)]
  self.assertEqual(len(plans),1)
  expression=ast.Expression(plans[0]);plan=eval(compile(ast.fix_missing_locations(expression),'<exact-six-action-source-plan>','eval'),{'LABEL':D.LABEL,'TITLE':D.TITLE})
  self.assertEqual(plan,[(D.LABEL,None,True),(D.LABEL,None,False),('View report',D.TITLE,True),('View report',D.TITLE,False),('View report',D.TITLE,True),('View report',D.TITLE,False)])
  code=(HERE/'dns_contract.py').read_text()
  self.assertIn('events.index(actions[2])<events.index(actions[3])<events.index(actions[4])<events.index(frame)<events.index(actions[5])<events.index(result)',code)
  phase=(HERE/'dns_phase.py').read_text();self.assertEqual(phase.count('until=time.monotonic()+45'),1)
  self.assertIn("semantic=hooks['wait'](page,hooks['healthy'],remaining(until),'actual DNS report preview')",phase)

class ExpandedDNSReportControls(unittest.TestCase):
 def contract(self):
  from types import SimpleNamespace
  namespace={'__name__':'inert_expanded_dns_contract'};exec(compile(X.management(SOURCE),'<source-owned-management-contract>','exec'),namespace);return SimpleNamespace(**namespace)
 def values(self):
  pid=91;chain=[dict(pid=pid,role=r,visible=True,showing=True,rect=[0,0,1000,550])for r in(62,20,39,68,49,23)]
  inner=[dict(pid=pid,role=r,visible=True,showing=True,rect=[0,0,1000,550])for r in(61,49,68,62)]
  report=dict(scope='Stored DNS profiles',pid=pid,role=61,matches=1,reply='REPLIED',target_checked=True,enabled=True,sensitive=True,visible=True,showing=True,focusable=True,focused=True,chain=inner)
  proof=dict(status='PASS',pid=pid,interface='Component',action_name='ensure-visible',actions=0,scroll_called=True,coordinate_space='ATSPI_SCREEN',scroll_returned=False,focus_called=True,focused=False,unclipped_after_scroll=False,method='EXPANDED_DNS_REPORT_TEXT_FOCUS_SCROLL',name_base64=base64.b64encode(b'View report').decode(),chain=chain,report_focus=report)
  window=dict(pid=pid,mapped=True,visible=True,floating=True,hidden=False,xwayland=False,at=[12,12],size=[1000,550],title='cachy-asahi Welcome',**{'class':'cachy-asahi-welcome'},address='0x123')
  return proof,window
 def test_exact_typed_descendant_focus_and_complete_final_geometry(self):
  C=self.contract();proof,window=self.values();C.visible_control(proof,91,'View report',window,report_scope='Stored DNS profiles')
  for key,value in [('pid',True),('pid',92),('role',43),('matches',True),('matches',2),('reply','TIMEOUT_STATE_CONFIRMED'),('target_checked',False),('enabled',False),('sensitive',False),('visible',False),('showing',False),('focusable',False),('focused',False),('scope','Doctor')]:
   row=copy.deepcopy(proof);row['report_focus'][key]=value
   with self.subTest(key=key,value=value),self.assertRaises(ValueError):C.visible_control(row,91,'View report',window,report_scope='Stored DNS profiles')
 def test_wrong_scope_unexpanded_foreign_ancestry_and_clipping_refuse(self):
  C=self.contract();proof,window=self.values()
  for kind in('scope','unscoped','foreign','child_hidden','child_clipped','bad_join','outer_clipped','window','extra','nonfallback'):
   row=copy.deepcopy(proof);win=copy.deepcopy(window);scope='Stored DNS profiles'
   if kind=='scope':scope='Doctor'
   elif kind=='unscoped':scope=None
   elif kind=='foreign':row['report_focus']['chain'][1]['pid']=92
   elif kind=='child_hidden':row['report_focus']['chain'][1]['showing']=False
   elif kind=='child_clipped':row['report_focus']['chain'][0]['rect']=[0,540,100,20]
   elif kind=='bad_join':row['report_focus']['chain'][-1]['rect']=[0,0,1000,549]
   elif kind=='outer_clipped':row['chain'][0]['rect']=[0,540,100,20]
   elif kind=='window':win['size']=[1000,551]
   elif kind=='extra':row['report_focus']['arbitrary']=True
   else:row.update(method='FOCUS_SCROLL',focused=True)
   with self.subTest(kind=kind),self.assertRaises(ValueError):C.visible_control(row,91,'View report',win,report_scope=scope)
 def test_production_actor_scope_reply_and_fresh_chain_guards(self):
  driver=X.driver(X.source_text(SOURCE,'a11y_driver.c'))
  for required in('strcmp(wanted_scope, "Stored DNS profiles")','strcmp(wanted, "View report")','ATSPI_STATE_CHECKED','ATSPI_ROLE_TEXT','report_matches == 1 && report_text','report_ancestry(pid, FALSE)','actual DNS report text focus reply','report_ancestry(pid, TRUE)','DNS report geometry join','focused control remains clipped','getuid() == 23001 && geteuid() == 23001','alarm(20)','peer_focus_timeout(atspi_component_grab_focus(peer_component, &error))'):
   self.assertIn(required,driver)
  self.assertEqual(driver.count('focus_report_text(pid);'),1)

if __name__=='__main__':unittest.main(verbosity=2)
