#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-free source gates, real owned-leaf mutations and exact decision refusals."""
import ast,copy,importlib.util,json,os,shutil,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
P=load('repair_prepare',HERE/'prepare.py');PACK=load('repair_packet',HERE/'packet.py')
SOURCE=None;ACTUAL=None
if '--actual-packet' in sys.argv:
 index=sys.argv.index('--actual-packet');ACTUAL=Path(sys.argv[index+1]).absolute();del sys.argv[index:index+2]
if '--source' in sys.argv:
 index=sys.argv.index('--source');SOURCE=Path(sys.argv[index+1]).absolute();del sys.argv[index:index+2]

def definition(path,name,namespace):
 text=path.read_text();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name);exec(compile(ast.get_source_segment(text,node),str(path)+':inert-control','exec'),namespace);return namespace[name]

class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='repair-native-control-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
  rows=json.loads((HERE/'source-pins.json').read_bytes())['files'];candidates=([SOURCE] if SOURCE else [])+[q for p in HERE.parents for q in (p,p/'source')];self.source=next((p for p in candidates if p is not None and all((p/n).is_file() and P.pin((p/n).read_bytes())==r for n,r in rows.items())),None);self.assertIsNotNone(self.source,'supply exact finite source closure using --source; no private artifact path required')
 def test_exact_current_versions_and_default_unbound(self):
  policy=json.loads((HERE/'policy.json').read_bytes());self.assertEqual(policy['versions'],PACK.VERSIONS);self.assertEqual(policy['status'],'UNBOUND');self.assertIsNone(policy['packet_source']);self.assertIsNone(policy['packet_index']);self.assertEqual(PACK.VERSIONS['cachy-asahi-apps'],'0.1.0-6');self.assertEqual(PACK.VERSIONS['cachy-asahi-orphans'],'0.1.0-2')
 def test_real_selected_file_damage_missing_and_restoration(self):
  def need(v,w):
   if not v:raise ValueError(w)
  work=self.root/'work';workspace=work/'main';target='usr/share/doc/cachy-asahi-apps/README.md';path=workspace/'root'/target;path.parent.mkdir(parents=True);path.write_bytes(b'actual original\n');path.chmod(0o644)
  C=types.SimpleNamespace(need=need,safe=lambda p:p,read=lambda p,cap=0:p.read_bytes());space=dict(Path=Path,stat=__import__('stat'),os=os,C=C,WORK=work,TARGET=target,UNSELECTED='usr/share/doc/cachy-asahi-cache/README.md')
  # Host fixtures use actual caller ownership; production still requires0:0.
  text=(HERE/'lifecycle.py').read_text();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='leaf');body=ast.get_source_segment(text,node);self.assertEqual(body.count('info.st_uid==info.st_gid==0'),1);body=body.replace('info.st_uid==info.st_gid==0','info.st_uid==os.getuid() and info.st_gid==os.getgid()');exec(compile(body,'actual-host-owned-leaf','exec'),space)
  change=definition(HERE/'lifecycle.py','damage',space);restore=definition(HERE/'lifecycle.py','restore',space);row=change(workspace,target);self.assertNotEqual(path.read_bytes(),row[1]);restore(row);self.assertEqual(path.read_bytes(),b'actual original\n');change(workspace,target,True);self.assertFalse(path.exists())
  for name in ('etc/passwd','../root',target+'-other'):
   with self.assertRaises(ValueError):change(workspace,name)
 def test_selected_type_alias_parent_refusals(self):
  def need(v,w):
   if not v:raise ValueError(w)
  work=self.root/'work';workspace=work/'main';target='usr/share/doc/cachy-asahi-apps/README.md';path=workspace/'root'/target;path.parent.mkdir(parents=True);path.write_bytes(b'x');path.chmod(0o644)
  C=types.SimpleNamespace(need=need,safe=lambda p:need(not any(q.is_symlink() for q in (p,*p.parents)),'parent alias'),read=lambda p,cap:p.read_bytes());space=dict(Path=Path,stat=__import__('stat'),os=os,C=C,WORK=work,TARGET=target,UNSELECTED='unused');text=(HERE/'lifecycle.py').read_text();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='leaf');body=ast.get_source_segment(text,node).replace('info.st_uid==info.st_gid==0','info.st_uid==os.getuid() and info.st_gid==os.getgid()');exec(compile(body,'actual-host-owned-leaf','exec'),space);leaf=space['leaf'];leaf(workspace,target);other=self.root/'alias';os.link(path,other)
  with self.assertRaises(ValueError):leaf(workspace,target)
  other.unlink();path.chmod(0o600)
  with self.assertRaises(ValueError):leaf(workspace,target)
  path.unlink();path.symlink_to('foreign')
  with self.assertRaises(ValueError):leaf(workspace,target)
 def test_actual_copy_marker_and_readonly_preparation_refuse_substitution(self):
  def need(v,w):
   if not v:raise ValueError(w)
  work=self.root/'work';workspace=work/'main';root=workspace/'root';root.mkdir(parents=True);workspace.chmod(0o700);inode=lambda p:[p.stat().st_dev,p.stat().st_ino];marker=workspace/'apps-copy.json';marker.write_bytes(P.encoded(dict(token='a'*32,workspace=inode(workspace),root=inode(root),source='/seed')));sha=__import__('hashlib').sha256
  C=types.SimpleNamespace(need=need,safe=lambda p:p,sha=lambda raw:sha(raw).hexdigest(),read=lambda p,cap:p.read_bytes(),decode=json.loads);T=types.SimpleNamespace(inode=inode);space=dict(Path=Path,stat=__import__('stat'),os=os,C=C,WORK=work)
  text=(HERE/'lifecycle.py').read_text();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='owned');body=ast.get_source_segment(text,node);self.assertEqual(body.count('info.st_uid==0'),1);body=body.replace('info.st_uid==0','info.st_uid==os.getuid()');exec(compile(body,'actual-host-owned-copy-marker','exec'),space);owned=space['owned'];pin=C.sha(marker.read_bytes())
  with patch.dict(os.environ,OWNER_TOKEN='a'*32):
   owned(T,workspace,pin)
   with self.assertRaises(ValueError):owned(T,workspace,'0'*64)
   root.rename(workspace/'old-root');root.mkdir()
   with self.assertRaises(ValueError):owned(T,workspace,pin)
 def test_repair_receipt_cannot_claim_other_target_or_outcome(self):
  def need(v,w):
   if not v:raise ValueError(w)
  C=types.SimpleNamespace(need=need);f=definition(HERE/'lifecycle.py','repaired',dict(C=C));damage={'usr/share/doc/cachy-asahi-apps/README.md':None};row=dict(status='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION',operation='reinstall',prepared_add={'cachy-asahi-apps':'0.1.0-6'},prepared_remove={},commit_started=True,packages_committed=True,dependency_checks='ORDINARY_LIBALPM',full574_closure=dict(repair=dict(status='SELECTED_SIGNED_ORDINARY_LEAVES_RESTORED',selected=['cachy-asahi-apps'],before_damage=damage)));self.assertEqual(f(row,damage),row)
  for change in (dict(packages_committed=False),dict(prepared_add={'cachy-asahi-apps':'0.1.0-5'}),dict(prepared_remove={'base':'1'})):
   with self.assertRaises(ValueError):f(dict(row,**change),damage)
  with self.assertRaises(ValueError):f(row,{'foreign':None})
 def test_generator_and_original_owner_three_explicit_derivations(self):
  source=self.source;out=self.root/'emitted';result=P.emit(source,out);self.assertEqual(result['status'],'SOURCE_ONLY_UNBOUND');lane=out/P.NEW;manifest=json.loads((lane/'source-manifest.json').read_bytes());self.assertEqual(len(manifest['files']),113);self.assertEqual((out/P.WF).read_text(),P.workflow((source/'.github/workflows/native-arm-apps-full574-transaction.yml').read_text()));self.assertEqual((out/'scripts/ci/apps-full574-native/job.py').read_bytes(),(source/'scripts/ci/apps-full574-native/job.py').read_bytes());self.assertNotIn(P.NEW+'/source-manifest.json',manifest['files'])
  with patch.dict(sys.modules,{},clear=False):
   C=load('contract',lane/'contract.py');self.assertEqual(C.VERSIONS,PACK.VERSIONS)
   with self.assertRaisesRegex(ValueError,'UNBOUND'):C.source(out)
   J=load('repair_job_emitted',lane/'job.py');parts=J.derived((source/'scripts/ci/apps-full574-native/job.py').read_text());self.assertEqual(set(parts),{'run','retain','actor'});self.assertNotIn("api,'interruption'",parts['run']);self.assertIn("api,'lifecycle'",parts['run'])
   parsed=ast.parse(parts['run']+parts['retain']);self.assertFalse(any(isinstance(n,ast.Name) and n.id=='interruption' for n in ast.walk(parsed)))
 def test_actual_nested_payload_layout_original_check_and_strict_data(self):
  import subprocess
  carrier=self.root/'carrier';carrier.mkdir();payload=carrier/'payload';environment=dict(os.environ,GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_AUTHOR_NAME='Inert control',GIT_AUTHOR_EMAIL='control@test.invalid',GIT_COMMITTER_NAME='Inert control',GIT_COMMITTER_EMAIL='control@test.invalid')
  if ACTUAL is not None:shutil.copytree(ACTUAL,payload)
  else:payload.mkdir();(payload/'inert-data').write_bytes(b'ordinary data only')
  for argv in (['init','--quiet'],['add','payload'],['commit','--quiet','-m','isolated payload carrier']):subprocess.run(['git','-C',str(carrier),*argv],check=True,env=environment,capture_output=True,timeout=10)
  actual=subprocess.check_output(['git','-C',str(carrier),'rev-parse','HEAD'],text=True,env=environment,timeout=10).strip();self.assertTrue((carrier/'.git').is_dir());self.assertFalse((payload/'.git').exists())
  def need(v,w):
   if not v:raise ValueError(w)
  calls=[]
  def inputs(root,path):
   self.assertEqual(path,payload);calls.append(path)
   if ACTUAL is not None:
    M=load('original_packet_payload_layout',self.source/'scripts/ci/management-tools-generic16k/contract.py');dataC=types.SimpleNamespace(**vars(M));dataC.policy=lambda:dict(packet_index=dict(path='index.json',**P.pin((payload/'index.json').read_bytes())));value=PACK.module(dataC,self.source).packet(payload);self.assertEqual(set(value['packages']),set(PACK.VERSIONS));return value,{},{}
   return {'packages':{}},{},{}
  C=types.SimpleNamespace(need=need,source=lambda p:dict(packet_source=actual),inputs=inputs);namespace=dict(C=C);original=definition(self.source/'scripts/ci/apps-full574-native/job.py','check',namespace);self.assertEqual(original(types.SimpleNamespace(source=self.source,packet=payload))['status'],'EXACT_NATIVE_INPUTS_CHECKED_NOT_EXECUTED');self.assertEqual(calls,[payload])
  if ACTUAL is not None:self.assertEqual({p.relative_to(payload).as_posix():P.pin(p.read_bytes()) for p in payload.rglob('*') if p.is_file()},{p.relative_to(ACTUAL).as_posix():P.pin(p.read_bytes()) for p in ACTUAL.rglob('*') if p.is_file()})
 def test_source_drift_refuses_before_output(self):
  source=self.root/'source';shutil.copytree(self.source,source);path=source/'scripts/apps/transaction.py';path.write_bytes(path.read_bytes()+b'\n');out=self.root/'bad'
  with self.assertRaisesRegex(ValueError,'source differs'):P.emit(source,out)
  self.assertFalse(out.exists())
 def test_workflow_budgets_and_original_retirement(self):
  text=P.workflow((self.source/'.github/workflows/native-arm-apps-full574-transaction.yml').read_text());self.assertIn('3550s',text);self.assertIn('650s',text);self.assertIn('2300s',text);self.assertIn('supervise.py" run',text);self.assertIn('supervise.py" cleanup',text);self.assertIn('steps.repair_trial.outcome',text);self.assertEqual(text.count('actions/upload-artifact@'),1)
 def test_carrier_root_checkout_and_three_packet_arguments_align(self):
  text=P.workflow((self.source/'.github/workflows/native-arm-apps-full574-transaction.yml').read_text());self.assertEqual(text.count('          path: retained-apps574-inputs\n'),1);self.assertNotIn('          path: retained-apps574-inputs/payload\n',text);self.assertEqual(text.count('--packet "$GITHUB_WORKSPACE/retained-apps574-inputs/payload"'),3)
  if ACTUAL is not None:self.assertTrue((ACTUAL/'index.json').is_file());self.assertFalse((ACTUAL/'payload').exists());self.assertEqual(json.loads((ACTUAL/'index.json').read_bytes())['kind'],'ROOT_ACCEPTED_NATIVE_CURRENT4_REPAIR_INPUTS')
 def test_current_repair_bound_source_positive_and_default_actor_refusal(self):
  out=self.root/'current-source';P.emit(self.source,out);lane=out/P.NEW;C=load('contract',lane/'contract.py')
  with self.assertRaisesRegex(ValueError,'UNBOUND'):C.source(out)
  bound=json.loads((lane/'input-policy.json').read_bytes());bound.update(status='ROOT_BOUND_NATIVE574_SIGNED_REPAIR_INPUTS',packet_source='65950a7e3ca82d97e21a65556844dab1cfd1a7f7',packet_index=dict(path='index.json',bytes=55737,sha256='782fd76c06831786cb74df396f195e8f5f8832e04b668c44bdadd802d1cb268b'));(lane/'input-policy.json').write_bytes(P.encoded(bound));manifest=json.loads((lane/'source-manifest.json').read_bytes());manifest['files'][P.NEW+'/input-policy.json']=P.pin((lane/'input-policy.json').read_bytes());(lane/'source-manifest.json').write_bytes(P.encoded(manifest));self.assertEqual(C.source(out),bound);self.assertEqual(C.VERSIONS,PACK.VERSIONS)
  # Also join a real bound input policy when this test runs in Root's frozen view.
  if (HERE/'input-policy.json').is_file():
   actual=json.loads((HERE/'input-policy.json').read_bytes());own=load('contract',HERE/'contract.py')
   if actual['status']=='ROOT_BOUND_NATIVE574_SIGNED_REPAIR_INPUTS':self.assertEqual(own.source(self.source),actual)
   else:
    with self.assertRaisesRegex(ValueError,'UNBOUND'):own.source(self.source)
 def test_actual_root_decision_hashes_are_exact_and_no_future_fallback(self):
  self.assertEqual(PACK.DECISIONS,{'triple':'f904a28e6e02ce2685eaa438c4c3d6d43a119b0d5d85a6706db5864c2bbd1676','orphans':'4495e3104903c755c230606cd4739e95cd78e9cbb909d64ff42ad53fa470ba05'})
  class C:
   @staticmethod
   def checked(root,row):return b'{}'
   sha=staticmethod(lambda raw:'0'*64);decode=staticmethod(json.loads)
   @staticmethod
   def need(v,w):
    if not v:raise ValueError(w)
  with self.assertRaisesRegex(ValueError,'exact original Root'):PACK.decision(C,self.root,{'decision':{}},'cachy-asahi-apps','0.1.0-6',{})
 def test_readonly_before_preparation_has_no_default_inspect_waiver(self):
  text=(HERE/'lifecycle.py').read_text();self.assertIn("value=adapter.measure(workspace/'root',T.limits())",text);self.assertIn("T.pins(value,inventory)",text);self.assertNotIn('authorize_reinstall',text);self.assertIn("H.backend('inspect',workspace,owner),expected=1",text);self.assertIn("checkpoint",(HERE/'../../apps/transaction.py').read_text() if (HERE/'../../apps/transaction.py').exists() else (self.source/'scripts/apps/transaction.py').read_text())
if ACTUAL is not None:
 class ActualInputs(Controls):
  # Exact original data only; no actor, package program, recipe execution or keys.
  def parser(self,root):
   original=load('original_packet_actual',self.source/'scripts/ci/management-tools-generic16k/contract.py');C=types.SimpleNamespace(**vars(original));C.policy=lambda:dict(packet_index=dict(path='index.json',**P.pin((root/'index.json').read_bytes())));return PACK.module(C,self.source),C
  def copy(self):
   target=self.root/'packet';shutil.copytree(ACTUAL,target);return target
  def test_actual_closed_current4_pair_only_input_and_payload(self):
   N,C=self.parser(ACTUAL);value=N.packet(ACTUAL);checks=load('actual_package_parser',self.source/'scripts/checks/package_checks.py');payload,origins=N.package_payload(ACTUAL,value,checks);self.assertEqual(len(value['packages']),4);self.assertEqual(len(payload),25);self.assertEqual(set(origins.values()),set(PACK.VERSIONS));self.assertEqual(value['packages']['cachy-asahi-apps']['qualification'],'NATIVE_PAIR_ONLY')
  def test_actual_original_root_decision_cannot_be_replaced(self):
   root=self.copy();index=json.loads((root/'index.json').read_bytes());row=index['packages']['cachy-asahi-apps'];path=root/row['decision']['path'];value=json.loads(path.read_bytes());value['signed_repair']='PASS_INVENTED';path.write_bytes(P.encoded(value));pin=dict(path=row['decision']['path'],**P.pin(path.read_bytes()))
   def update(v):
    if type(v) is dict:
     if set(v)=={'path','bytes','sha256'} and v['path']==pin['path']:v.update(pin)
     else:
      for child in v.values():update(child)
    elif type(v) is list:
     for child in v:update(child)
   update(index);(root/'index.json').write_bytes(P.encoded(index));N,C=self.parser(root)
   with self.assertRaisesRegex(ValueError,'exact original Root'):N.packet(root)
  def test_actual_old_apps_or_orphans_versions_refused(self):
   for name,old in (('cachy-asahi-apps','0.1.0-5'),('cachy-asahi-orphans','0.1.0-1')):
    root=self.root/name;shutil.copytree(ACTUAL,root);index=json.loads((root/'index.json').read_bytes());index['packages'][name]['version']=old;(root/'index.json').write_bytes(P.encoded(index));N,C=self.parser(root)
    with self.assertRaisesRegex(ValueError,'exact native pair'):N.packet(root)
  def test_actual_unreferenced_file_refused(self):
   root=self.copy();(root/'foreign').write_bytes(b'not authorized');N,C=self.parser(root)
   with self.assertRaisesRegex(ValueError,'reference closure'):N.packet(root)
 # Inherit only fixture setup, not the eight already registered controls.
 for name in list(vars(Controls)):
  if name.startswith('test_') and name not in ActualInputs.__dict__:setattr(ActualInputs,name,None)
if __name__=='__main__':unittest.main()
