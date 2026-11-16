# SPDX-License-Identifier: MIT
"""Portable fenced transfer/constructor DATA. No live provider, actor or Root grant."""
import ast,copy,hashlib,importlib.util,json,os,shutil,socket,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=module('rust_v8_constructor_DATA',HERE/'prepare.py')
T=module('rust_v8_transfer_DATA',HERE/'payload/hosted/phase_transfer.py')
support=module('rust_v7_code_support_DATA',HERE.parent/'successor_v7/test_support.py')
ROOT=support.assembled();BEFORE_TRANSFER=(ROOT/'hosted/phase_transfer.py').read_text();shutil.copytree(HERE/'payload',ROOT,dirs_exist_ok=True)
G=module('rust_v8_admission_DATA',ROOT/'admission.py')

def fence(event,args):
 if event.startswith(('socket.','subprocess.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
  raise AssertionError('fenced DATA no operational role '+event)
sys.addaudithook(fence)


def dispatch():
 v=json.loads((HERE/'Root-admission.TEMPLATE.json').read_bytes())
 v.update(status='ROOT_ADMITTED_RUST199_PHASE_TRANSFER_ONCE',resources=json.loads((ROOT/'resource-policy.json').read_bytes()),reviews=dict.fromkeys(v['reviews'],True))
 v['source'].update(sha='f'*40,ref='refs/heads/codex/FENCED-rust-transfer-v8',map_sha256='b'*64,approval='c'*64)
 v['bootstrap'].update(provider_policy_reviewed=True,qualification_allowed=True,network_during_qualification=False)
 v['delivery']['status']='ROOT_ADMITTED_FINITE_RUST_MATERIAL_DELIVERY'
 for carrier,account in [('llvm_original','8'),('stage0_carrier','2'),('root_proof_carrier','6')]:v['delivery'][carrier].update(accepted_by_root=True,redirect_hosts=['productionresultssa'+account+'.blob.core.windows.net'])
 return v


def facts():
 d=dispatch();current=dict(d['source'],run='101',job='202');args=SimpleNamespace(bootstrap_artifact_id='303',bootstrap_job_id='201',bootstrap_artifact_sha256='d'*64,bootstrap_manifest_sha256='e'*64,bootstrap_image_id='sha256:'+'a'*64,bootstrap_image_sha256='1'*64,bootstrap_image_bytes='5')
 repository=dict(id=1414857795,full_name='Gabriel-Kahen/cachy-asahi')
 run=dict(id=101,run_attempt=1,head_sha='f'*40,head_branch='codex/FENCED-rust-transfer-v8',event='workflow_dispatch',workflow_id=381664314,path='.github/workflows/native-arm-build.yml',status='in_progress',conclusion=None,repository=repository,head_repository=repository)
 artifact=dict(id=303,expired=False,size_in_bytes=5,name='rust199-qualified-transfer-v4-101-1',digest='sha256:'+'d'*64,workflow_run=dict(id=101,head_sha='f'*40,head_branch='codex/FENCED-rust-transfer-v8',repository_id=1414857795,head_repository_id=1414857795))
 job=dict(id=201,run_id=101,run_attempt=1,head_sha='f'*40,head_branch='codex/FENCED-rust-transfer-v8',status='completed',conclusion='success',name='rust199-bootstrap-v4')
 return d,current,args,artifact,job,run


def authorization():return T.authorize_transfer(*facts(),HERE/'payload')


class TransferControls(unittest.TestCase):
 def test_full_current_grant_has_no_future_host_and_keeps_exact_carriers(self):
  d=dispatch();G.validate_dispatch(d);self.assertIsNone(d['bootstrap']['transfer_redirect_hosts'])
  for key,account in [('llvm_original','8'),('stage0_carrier','2'),('root_proof_carrier','6')]:self.assertEqual(d['delivery'][key]['redirect_hosts'],['productionresultssa'+account+'.blob.core.windows.net'])
  a=authorization();self.assertIsNone(a['selected_host']);self.assertEqual(a['binding']['image_pin'],dict(bytes=5,sha256='1'*64))
 def test_old_schema_unreviewed_changed_provider_and_guessed_host_refuse(self):
  for mode in ('old','unreviewed','guess','policy','extra'):
   d=dispatch()
   if mode=='old':d['schema']=4;d['status']='ROOT_ADMITTED_RUST199_SOURCE_RESOURCE_ONCE'
   elif mode=='unreviewed':d['bootstrap']['provider_policy_reviewed']=None
   elif mode=='guess':d['bootstrap']['transfer_redirect_hosts']=['productionresultssa8.blob.core.windows.net']
   elif mode=='extra':d['bootstrap']['waiver']=True
   else:d['bootstrap']['transfer_provider_policy']['sha256']='0'*64
   with self.subTest(mode=mode),self.assertRaises(ValueError):G.validate_dispatch(d)
 def test_current_run_job_artifact_attempt_ref_and_needs_pins_all_required(self):
  mutations=[(3,'id',304),(3,'digest',None),(3,'expired',True),(3,'name','foreign'),(4,'run_attempt',2),(4,'conclusion','failure'),(4,'head_branch','foreign'),(4,'id',999),(5,'run_attempt',2),(5,'head_sha','0'*40),(5,'head_branch','foreign'),(5,'workflow_id',1),(5,'event','push'),(5,'status','completed')]
  for index,key,value in mutations:
   rows=list(copy.deepcopy(facts()));rows[index][key]=value
   with self.subTest(index=index,key=key),self.assertRaises(ValueError):T.authorize_transfer(*rows,HERE/'payload')
  for key,value in [('bootstrap_image_id',None),('bootstrap_image_sha256','0'),('bootstrap_image_bytes','0'),('bootstrap_manifest_sha256',None)]:
   rows=list(facts());setattr(rows[2],key,value)
   with self.subTest(needs=key),self.assertRaises(ValueError):T.authorize_transfer(*rows,HERE/'payload')
 def test_repository_and_artifact_run_binding_cannot_be_replaced(self):
  for mode in ('repo','artifact-run','artifact-ref','current'):
   rows=list(copy.deepcopy(facts()))
   if mode=='repo':rows[5]['head_repository']['id']=1
   elif mode=='artifact-run':rows[3]['workflow_run']['id']=999
   elif mode=='artifact-ref':rows[3]['workflow_run']['head_branch']='foreign'
   else:rows[1]['map_sha256']='0'*64
   with self.subTest(mode=mode),self.assertRaises(ValueError):T.authorize_transfer(*rows,HERE/'payload')
 def test_one_exact_family_host_from_authenticated_exact_zip_only(self):
  a=authorization();host='productionresultssa29.blob.core.windows.net'
  self.assertEqual(T.select_redirect(a,a['endpoint'],'https://'+host+'/artifact?sig=FENCED',True),host)
  with self.assertRaises(ValueError):T.select_redirect(a,a['endpoint'],'https://productionresultssa2.blob.core.windows.net/artifact',True)
  for url in ('http://productionresultssa2.blob.core.windows.net/a','https://evil.blob.core.windows.net/a','https://productionresultssa9999.blob.core.windows.net/a','https://productionresultssa2.blob.core.windows.net.evil.invalid/a','https://user@productionresultssa2.blob.core.windows.net/a','https://productionresultssa2.blob.core.windows.net:444/a','https://productionresultssa2.blob.core.windows.net/a#fragment','https://productionresultssa02.blob.core.windows.net/a'):
   a=authorization()
   with self.subTest(url=url),self.assertRaises(ValueError):T.select_redirect(a,a['endpoint'],url,True)
  for origin,auth in [('https://api.github.com/other',True),(authorization()['endpoint'],False)]:
   a=authorization()
   with self.assertRaises(ValueError):T.select_redirect(a,origin,'https://productionresultssa2.blob.core.windows.net/a',auth)
 def fetch(self,responses,*,existing_requests=0,cap=16*T.GIB,body=b'FENCE',alter=None):
  a=authorization();a['binding']['artifact_sha256']=hashlib.sha256(body).hexdigest();calls=[]
  class Response:
   def __init__(self,row):self.status=row[0];self.headers=row[1];self.body=row[2]
   def getheader(self,name):return self.headers.get(name)
   def read1(self,n):out,self.body=self.body[:n],self.body[n:];return out
  class Connection:
   def __init__(self,host):self.host=host
   def request(self,method,path,headers):calls.append(dict(host=self.host,method=method,path=path,headers=headers))
   def getresponse(self):return Response(responses.pop(0))
   def close(self):pass
  command=SimpleNamespace(deadline=time.monotonic()+100,cancelled=[False],on_tick=None);budget=T.Budget(command,100);budget.requests=[{}for _ in range(existing_requests)]
  with tempfile.TemporaryDirectory(prefix='FENCED-transfer-body-')as name:
   target=Path(name)/'artifact.zip'
   if alter:alter(a)
   with patch.object(T,'_connection',side_effect=lambda host,timeout:Connection(host)):
    result=T.fetch(a['endpoint'],target,budget,{'api.github.com'},'FENCED_NOT_A_CREDENTIAL',dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest()),cap=cap,redirects=3,authorization=a)
   self.assertEqual(target.read_bytes(),body);self.assertEqual(target.stat().st_mode&0o777,0o444)
  return result,calls,budget,a
 def test_storage_get_never_receives_bearer_and_logs_never_keep_signed_query(self):
  host='productionresultssa29.blob.core.windows.net'
  result,calls,budget,a=self.fetch([(303,{'Location':'https://'+host+'/artifact?sig=FENCED_SECRET'},b''),(200,{'Content-Length':'5'},b'FENCE')])
  self.assertIn('Authorization',calls[0]['headers']);self.assertNotIn('Authorization',calls[1]['headers']);self.assertEqual(a['selected_host'],host)
  self.assertNotIn('FENCED_SECRET',T.encode(budget.requests).decode());self.assertEqual(result['bytes'],5)
 def test_changed_host_api_return_direct_api_body_loop_and_request_exhaustion_refuse(self):
  h='https://productionresultssa2.blob.core.windows.net/artifact'
  cases=[[(303,{'Location':h},b''),(303,{'Location':'https://productionresultssa6.blob.core.windows.net/a'},b'')],[(303,{'Location':h},b''),(303,{'Location':'https://api.github.com/other'},b'')],[(200,{},b'FENCE')],[(303,{'Location':h},b''),(303,{'Location':h},b'')]]
  for rows in cases:
   with self.subTest(rows=rows),self.assertRaises(ValueError):self.fetch(rows)
  with self.assertRaises(ValueError):self.fetch([(303,{'Location':h},b'')],existing_requests=7)
 def test_full_seven_requests_and_three_same_host_redirects_remain_bounded(self):
  h='https://productionresultssa2.blob.core.windows.net/'
  _,calls,budget,_=self.fetch([(303,{'Location':h+'a'},b''),(303,{'Location':h+'b'},b''),(303,{'Location':h+'c'},b''),(200,{},b'FENCE')],existing_requests=3)
  self.assertEqual(len(calls),4);self.assertEqual(len(budget.requests),7)
  with self.assertRaises(ValueError):self.fetch([(303,{'Location':h+'a'},b''),(303,{'Location':h+'b'},b''),(303,{'Location':h+'c'},b''),(303,{'Location':h+'d'},b'')])
 def test_whole_digest_content_length_encoding_and_body_caps_still_refuse(self):
  h='https://productionresultssa2.blob.core.windows.net/a'
  for headers,body,cap in [({'Content-Length':'6'},b'FENCE',16*T.GIB),({'Content-Encoding':'gzip'},b'FENCE',16*T.GIB),({},b'FENCE',4),({},b'OTHER',16*T.GIB)]:
   with self.subTest(headers=headers,cap=cap),self.assertRaises(ValueError):self.fetch([(303,{'Location':h},b''),(200,headers,body)],cap=cap)
 def test_manifest_image_id_length_and_sha_are_joined_before_load(self):
  a=authorization();m=dict(image_id=a['binding']['image_id'],files={'image.tar':dict(a['binding']['image_pin'],mode=292)})
  T.image_binding(m,a)
  for key in ('image_id','bytes','sha256'):
   v=copy.deepcopy(m)
   if key=='image_id':v[key]='sha256:'+'0'*64
   else:v['files']['image.tar'][key]=1 if key=='bytes'else'0'*64
   with self.subTest(key=key),self.assertRaises(ValueError):T.image_binding(v,a)
 def test_existing_extract_material_qualification_retirement_functions_byte_exact(self):
  def functions(text):return {n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
  before,after=functions(BEFORE_TRANSFER),functions((HERE/'payload/hosted/phase_transfer.py').read_text())
  for name in ('extract','provider_check','context','image_owner','inspect_image','copy_file','collect','rewrite','Budget','absent','size_limit','natural','call'):
   self.assertEqual(before[name],after[name],name)
 def test_export_import_workflow_pins_precede_docker_load_and_old_recovery_unchanged(self):
  source=(HERE/'payload/hosted/phase_transfer.py').read_text();workflow=(HERE/'payload/.github/workflows/native-arm-build.yml').read_text()
  self.assertLess(source.index("authorization=authorize_transfer("),source.index("cap=ARTIFACT_CAP,redirects=3,authorization=authorization"))
  self.assertLess(source.index("'actual whole manifest/image matches"),source.index("report['load_intent']=True"))
  self.assertIn("image_sha256='+rows['image.tar']['sha256']",source)
  for key in ('image_id','image_sha256','image_bytes'):self.assertIn('needs.bootstrap.outputs.'+key,workflow)
  self.assertIn('timeout-minutes: 246',workflow);self.assertIn('timeout-minutes: 360',workflow)
  self.assertEqual((T.REQUEST_CAP,T.ARTIFACT_CAP,T.IMAGE_CAP),(7,16*T.GIB,12*T.GIB))


class ConstructorControls(unittest.TestCase):
 def before(self):
  support_root=support.assembled();before=P.fs.snapshot(support_root)
  before['source-map.json']=(P.encode(dict(schema=1,operation='rust199-source-reference-native-v1',actual=P.ACTUAL,files=P.fs.descriptors(before))),0o644)
  return before,P.identity(before)
 def test_exact_inverse_preserves_every_nontransfer_leaf(self):
  before,parent=self.before()
  with patch.object(P,'PARENT',parent):
   after=P.render(before);self.assertEqual(P.undo(after),before)
   for name,row in before.items():
    if name not in P.REPLACED|{'source-map.json'}:self.assertEqual(after[name],row,name)
   for name in ('resource-policy.json','recipe/PKGBUILD','candidate-map.json','contract.json','notice_binding.py','hosted/materials.py','hosted/bootstrap.py','hosted/qualification.py','hosted/producer.py'):
    self.assertEqual(after[name],before[name],name)
   self.assertEqual({n for n in after if n not in before},{P.POLICY,P.MARKER}|{P.ARCHIVE+n for n in P.REPLACED|{'source-map.json'}})
 def test_parent_tamper_extra_git_and_inverse_tamper_refuse(self):
  before,parent=self.before()
  with tempfile.TemporaryDirectory(prefix='FENCED-v8-parent-')as name:
   root=Path(name)
   for n,(raw,mode)in before.items():p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(mode)
   with patch.object(P,'PARENT',parent):
    self.assertEqual(P.capture(root),before);(root/'.git').write_text('MODEL extra')
    with self.assertRaises(ValueError):P.capture(root)
    (root/'.git').unlink();after=P.render(before);n='resource-policy.json';after[n]=(after[n][0]+b'\n',0o644)
    with self.assertRaises(ValueError):P.undo(after)
 def test_complete_profile_constructor_external_pin_and_existing_output_refuse(self):
  before,parent=self.before()
  with tempfile.TemporaryDirectory(prefix='FENCED-v8-construct-')as name:
   root=Path(name);base=root/'parent';base.mkdir();constructor=root/'constructor';constructor.mkdir()
   for n,(raw,mode)in before.items():q=base/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(raw);q.chmod(mode)
   shutil.copytree(HERE/'payload',constructor/'payload')
   with patch.object(P,'PARENT',parent),patch.object(P,'HERE',constructor):
    files=P.render(before);profile=dict(schema=8,scope=P.SCOPE,parent=parent,actual=P.ACTUAL,unadmitted=True,constructor_files=P.inputs(),**P.identity(files))
    raw=P.encode(profile);(constructor/'constructor-profile.json').write_bytes(raw);sha=P.fs.pin(raw)['sha256']
    with self.assertRaises(ValueError):P.construct(base,root/'bad','0'*64)
    out=P.construct(base,root/'output',sha);self.assertTrue(out['unadmitted']);self.assertEqual(P.fs.snapshot(root/'output'),files)
    with self.assertRaises((ValueError,OSError)):P.construct(base,root/'output',sha)
 def test_new_templates_and_policy_keep_every_future_selector_null(self):
  v=json.loads((HERE/'Root-admission.TEMPLATE.json').read_bytes());self.assertEqual(v['schema'],5);self.assertIsNone(v['resources']);self.assertTrue(all(x is None for x in v['reviews'].values()))
  self.assertTrue(all(x is None for x in v['source'].values()));self.assertIsNone(v['bootstrap']['transfer_redirect_hosts']);self.assertIsNone(v['bootstrap']['provider_policy_reviewed'])
  policy=T.validate_policy(T.POLICY_PIN,HERE/'payload');self.assertTrue(all(x is None for x in policy['actual'].values()));self.assertIsNone(policy['Root_review'])


if __name__=='__main__':unittest.main(verbosity=2)
