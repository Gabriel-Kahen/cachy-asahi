#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Portable fenced fake-HTTP and Source DATA controls; no live GET or actor."""
import ast,copy,hashlib,importlib.util,io,json,shutil,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=module('rust_v9_constructor_DATA',HERE/'prepare.py')
M=module('rust_v9_materials_FENCED',HERE/'payload/hosted/materials.py')
T=module('rust_v9_transfer_FENCED',HERE/'payload/hosted/phase_transfer.py')
OLD_M=module('rust_v5_materials_FENCED',HERE.parent/'successor_v5/payload/hosted/materials.py')
OLD_T=module('rust_v8_transfer_FENCED',HERE.parent/'successor_v8/payload/hosted/phase_transfer.py')
V8=module('rust_v8_test_support_FENCED',HERE.parent/'successor_v8/test_data.py')

def fence(event,args):
 if event.startswith(('socket.','subprocess.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
  raise AssertionError('FENCED: no network, actor or Root role '+event)
sys.addaudithook(fence)
TOKEN='FENCED_NOT_A_CREDENTIAL';BODY=b'FENCED public body\n';API='https://api.github.com/repos/Gabriel-Kahen/cachy-asahi/actions/artifacts/303';HOST='productionresultssa29.blob.core.windows.net'

def command():return SimpleNamespace(cancelled=[False],on_tick=None,deadline=time.monotonic()+30)
def budget(which):return M.Budget(command())if which is M or which is OLD_M else T.Budget(command(),30)

class FakeHTTPServer:
 """HTTP client factory seam, not a listening socket or external GET."""
 def __init__(self,handler=None):self.rows=[];self.closed=0;self.handler=handler or self.required_agent
 def required_agent(self,host,method,path,headers):
  if headers.get('User-Agent')!=P.USER_AGENT:return 403,b'FENCED User-Agent required',{}
  return 200,BODY,{'Content-Length':str(len(BODY))}
 def connection(self,host,timeout):
  server=self
  class Connection:
   def request(self,method,path,headers):
    server.rows.append(dict(host=host,method=method,path=path,headers=dict(headers)));status,body,response_headers=server.handler(host,method,path,headers)
    self.response=SimpleNamespace(status=status,getheader=lambda name:response_headers.get(name),read1=io.BytesIO(body).read)
   def getresponse(self):return self.response
   def close(self):server.closed+=1
  return Connection()

def get(which,server,target,b,**kwargs):
 with patch.object(which,'_connection',server.connection):
  if which in(M,OLD_M):return which.fetch(API,target,kwargs.pop('expected',P.fs.pin(BODY)),b,kwargs.pop('hosts',{'api.github.com'}),TOKEN,**kwargs)
  return which.fetch(API,target,b,kwargs.pop('hosts',{'api.github.com'}),TOKEN,**kwargs)


def parent_model():
 root=V8.support.assembled();before=V8.P.fs.snapshot(root)
 # Explicit MODEL-only static checkpoint shapes; no operational qualification.
 before['llvm260-reader7-rejoin.json']=(P.encode(dict(schema=6,scope='LLVM260_READER7_PROSPECTIVE_REJOIN_ONLY_NO_ROLES',pending=None,actual=P.ACTUAL,Root_grants=None,FENCED_MODEL=True)),0o644)
 candidate=json.loads(before['candidate-map.json'][0]);before['notice-preservation.json']=(P.encode(dict(schema=7,scope='RUST199_NOTICE_PRESERVATION_UNADMITTED_SOURCE_V7',pending=None,actual=P.ACTUAL,unadmitted=True,holds_preserved=True,candidate_binding=candidate['notice_binding'],candidate_map_pin=P.fs.pin(before['candidate-map.json'][0]),contract_pin=P.fs.pin(before['contract.json'][0]),Root_grants=None,FENCED_MODEL=True)),0o644)
 before['source-map.json']=(P.encode(dict(schema=1,operation='rust199-source-reference-native-v1',actual=P.ACTUAL,files=P.fs.descriptors(before))),0o644)
 with patch.object(V8.P,'PARENT',V8.P.identity(before)):return V8.P.render(before)


def write(files,root):
 root.mkdir()
 for name,(raw,mode)in files.items():p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(mode)

class HeaderControls(unittest.TestCase):
 def test_old_clients_reproduce_user_agent_403_without_retry(self):
  for which in(OLD_M,OLD_T):
   with self.subTest(which=which.__name__),tempfile.TemporaryDirectory(prefix='FENCED-v9-old-')as name:
    server=FakeHTTPServer();b=budget(which);out=Path(name)/'body'
    with self.assertRaises(ValueError):get(which,server,out,b)
    self.assertEqual(len(server.rows),1);self.assertEqual(server.closed,1);self.assertFalse(out.exists());self.assertEqual(b.requests[0]['status'],403);self.assertEqual(b.requests[0]['bytes'],0)
 def test_both_clients_send_fixed_public_agent_and_preserve_bytes(self):
  for which in(M,T):
   with self.subTest(which=which.__name__),tempfile.TemporaryDirectory(prefix='FENCED-v9-agent-')as name:
    server=FakeHTTPServer();b=budget(which);out=Path(name)/'body';self.assertEqual(get(which,server,out,b,expected=P.fs.pin(BODY)),P.fs.pin(BODY));self.assertEqual(out.read_bytes(),BODY);self.assertEqual(out.stat().st_mode&0o777,0o444)
    row=server.rows[0];self.assertEqual(row['method'],'GET');self.assertEqual(row['headers']['User-Agent'],P.USER_AGENT);self.assertEqual(row['headers']['Authorization'],'Bearer '+TOKEN);self.assertEqual(row['headers']['Accept-Encoding'],'identity');self.assertNotIn('X-GitHub-Api-Version',row['headers']);self.assertEqual(len(server.rows),server.closed)
    if which is M:self.assertEqual(row['headers']['Accept'],'application/vnd.github+json')
    self.assertNotIn(TOKEN,json.dumps(b.requests));self.assertNotIn(P.USER_AGENT,json.dumps(b.requests))
 def test_api_to_storage_redirect_has_no_authorization_or_query_retention(self):
  def handler(host,method,path,headers):
   self.assertEqual(headers['User-Agent'],P.USER_AGENT)
   if host=='api.github.com':return 302,b'',{'Location':'https://'+HOST+'/payload?sig=FENCED_SIGNED_QUERY'}
   self.assertNotIn('Authorization',headers);return 200,BODY,{'Content-Length':str(len(BODY))}
  for which in(M,T):
   with self.subTest(which=which.__name__),tempfile.TemporaryDirectory(prefix='FENCED-v9-redirect-')as name:
    server=FakeHTTPServer(handler);b=budget(which);get(which,server,Path(name)/'body',b,expected=P.fs.pin(BODY),hosts={'api.github.com',HOST},redirects=3)
    self.assertEqual(len(server.rows),2);self.assertIn('Authorization',server.rows[0]['headers']);self.assertNotIn('Authorization',server.rows[1]['headers']);self.assertNotIn('FENCED_SIGNED_QUERY',json.dumps(b.requests));self.assertNotIn(TOKEN,json.dumps(b.requests))
 def test_metadata_redirect_still_refuses_and_forwards_no_token(self):
  for which in(M,T):
   with self.subTest(which=which.__name__),tempfile.TemporaryDirectory(prefix='FENCED-v9-no-redirect-')as name:
    server=FakeHTTPServer(lambda *args:(302,b'',{'Location':'https://'+HOST+'/payload?sig=FENCED'}));b=budget(which)
    with self.assertRaises(ValueError):get(which,server,Path(name)/'body',b,hosts={'api.github.com',HOST})
    self.assertEqual(len(server.rows),1)
 def test_unknown_origin_http_userinfo_fragment_and_loops_still_refuse(self):
  for location in('https://foreign.invalid/body','http://'+HOST+'/body','https://u:p@'+HOST+'/body','https://'+HOST+'/body#fragment',API):
   for which in(M,T):
    with self.subTest(location=location,which=which.__name__),tempfile.TemporaryDirectory(prefix='FENCED-v9-origin-')as name:
     server=FakeHTTPServer(lambda *args:(302,b'',{'Location':location}));b=budget(which)
     with self.assertRaises(ValueError):get(which,server,Path(name)/'body',b,hosts={'api.github.com',HOST},redirects=3)
     self.assertEqual(len(server.rows),1)
 def test_changed_body_declared_length_and_encoding_refuse_without_retry(self):
  for response in((200,b'changed',{}),(200,BODY,{'Content-Length':'999'}),(200,BODY,{'Content-Encoding':'gzip'}),(403,b'FENCED failure',{})):
   for which in(M,T):
    with self.subTest(response=response[0:1],which=which.__name__),tempfile.TemporaryDirectory(prefix='FENCED-v9-bound-')as name:
     server=FakeHTTPServer(lambda *args:response);b=budget(which)
     with self.assertRaises(ValueError):get(which,server,Path(name)/'body',b,expected=P.fs.pin(BODY))
     self.assertEqual(len(server.rows),1)
 def test_request_caps_cancellation_deadline_and_fixed_agent_not_environment(self):
  for which,cap in((M,M.REQUESTS),(T,T.REQUEST_CAP)):
   with self.subTest(which=which.__name__),tempfile.TemporaryDirectory(prefix='FENCED-v9-caps-')as name:
    for what in('count','cancel','time'):
     server=FakeHTTPServer();b=budget(which)
     if what=='count':b.requests=[{}]*cap
     elif what=='cancel':b.command.cancelled[0]=True
     else:b.deadline=time.monotonic()-1
     with self.assertRaises(ValueError):get(which,server,Path(name)/what,b)
     self.assertEqual(server.rows,[])
  self.assertEqual((M.SECONDS,M.REQUESTS,M.RETAINED_SECONDS,T.IMPORT_SECONDS,T.REQUEST_CAP,T.ARTIFACT_CAP,T.IMAGE_CAP),(1800,24,500,1800,7,16*T.GIB,12*T.GIB))
 def test_conditional_v8_authorization_still_uses_one_observed_storage_host(self):
  facts=V8.facts();a=T.authorize_transfer(*facts,HERE.parent/'successor_v8/payload');self.assertIsNone(a['selected_host']);endpoint=a['endpoint'];payload=b'FENCED'
  def handler(host,method,path,headers):
   if host=='api.github.com':return 302,b'',{'Location':'https://'+HOST+'/phase.zip?sig=FENCED_SIGNED_QUERY'}
   self.assertNotIn('Authorization',headers);return 200,payload,{'Content-Length':str(len(payload))}
  a['binding']['artifact_sha256']=P.fs.pin(payload)['sha256'];expected=P.fs.pin(payload)
  with tempfile.TemporaryDirectory(prefix='FENCED-v9-conditional-')as name:
   server=FakeHTTPServer(handler);b=budget(T)
   with patch.object(T,'_connection',server.connection):self.assertEqual(T.fetch(endpoint,Path(name)/'phase.zip',b,{'api.github.com'},TOKEN,expected,cap=T.ARTIFACT_CAP,redirects=3,authorization=a),expected)
   self.assertEqual(a['selected_host'],HOST);self.assertEqual(len(server.rows),2);self.assertNotIn('FENCED_SIGNED_QUERY',json.dumps(b.requests));self.assertNotIn(TOKEN,json.dumps(b.requests))
 def test_current_pregrant_and_needs_provider_controls_unchanged(self):
  d=V8.dispatch();V8.G.validate_dispatch(d);T.authorize_transfer(*V8.facts(),HERE.parent/'successor_v8/payload')
  for mutate in('unreviewed','attempt','host','image'):
   facts=list(copy.deepcopy(V8.facts()))
   if mutate=='unreviewed':facts[0]['bootstrap']['provider_policy_reviewed']=None
   elif mutate=='attempt':facts[5]['run_attempt']=2
   elif mutate=='host':facts[0]['bootstrap']['transfer_redirect_hosts']=['foreign.invalid']
   else:facts[2].bootstrap_image_sha256=None
   with self.assertRaises(ValueError):T.authorize_transfer(*facts,HERE.parent/'successor_v8/payload')

class SourceControls(unittest.TestCase):
 def test_exact_finite_transport_entry_and_workflow_inverses(self):
  before=parent_model();parent=P.identity(before)
  with patch.object(P,'PARENT',parent):
   after=P.render(before);self.assertEqual(P.undo(after),before)
   for name,row in before.items():
    if name not in P.REPLACED|{'source-map.json'}:self.assertEqual(after[name],row,name)
   self.assertEqual(set(after)-set(before),{P.MARKER}|{P.ARCHIVE+n for n in P.REPLACED|{'source-map.json'}})
   for leaf in('resource-policy.json','admission.py','recipe/PKGBUILD','candidate-map.json','contract.json','notice_binding.py','hosted/producer.py','hosted/phase-transfer-provider-policy.json','phase-transfer-v8.json'):
    self.assertEqual(after[leaf],before[leaf],leaf)
 def test_complete_old_new_functions_differ_only_in_one_header(self):
  for old,new in((OLD_M,M),(OLD_T,T)):
   old_text=Path(old.__file__).read_text();new_text=Path(new.__file__).read_text();needle="'User-Agent':'"+P.USER_AGENT+"',";self.assertEqual(new_text.count(needle),1);self.assertEqual(new_text.replace(needle,''),old_text)
 def test_source_aliases_entry_hashes_and_all_six_workflow_inputs(self):
  workflow=(HERE/'payload/.github/workflows/native-arm-build.yml').read_bytes();self.assertEqual(workflow,(HERE/'payload/.github/workflows/native-arm-rust199-source-reference-v1.yml').read_bytes());sha=P.fs.pin((HERE/'payload/hosted/entry.py').read_bytes())['sha256'];self.assertEqual(workflow.count(sha.encode()),2)
  for name in('source_sha','source_map_sha256','approval_sha256','root_admission_sha256','root_admission_json','operation'):self.assertIn(('  '+name+':').encode(),workflow)
  self.assertIn(b'timeout-minutes: 246',workflow);self.assertIn(b'timeout-minutes: 360',workflow)
 def test_invalid_parent_extra_git_payload_or_changed_metadata_format_refuse(self):
  before=parent_model();parent=P.identity(before)
  with patch.object(P,'PARENT',parent):
   bad=dict(before);bad['extra']=(b'FENCED',0o644)
   with self.assertRaises(ValueError):P.render(bad)
   payload=P.fs.snapshot(HERE/'payload');payload['hosted/materials.py']=(payload['hosted/materials.py'][0]+b'\n',0o644)
   with self.assertRaises(ValueError):P.check_delta(before,payload)
   after=P.render(before);after['resource-policy.json']=(after['resource-policy.json'][0]+b'\n',0o644)
   with self.assertRaises(ValueError):P.undo(after)
 def test_current_source_gate_and_unissued_marker_refusal(self):
  before=parent_model();parent=P.identity(before)
  with tempfile.TemporaryDirectory(prefix='FENCED-v9-source-gate-')as name,patch.object(P,'PARENT',parent):
   files=P.render(before);root=Path(name)/'source';write(files,root);entry=module('rust_v9_entry_gate_FENCED',root/'hosted/entry.py');entry.source_gate(root,P.identity(files)['map_sha256'])
   marker=json.loads((root/P.MARKER).read_bytes());marker['Root_grants']={'FENCED':'not authority'};files[P.MARKER]=(P.encode(marker),0o644);mapping=json.loads(files['source-map.json'][0]);mapping['files']=P.fs.descriptors({n:r for n,r in files.items()if n!='source-map.json'});files['source-map.json']=(P.encode(mapping),0o644)
   (root/P.MARKER).write_bytes(files[P.MARKER][0]);(root/'source-map.json').write_bytes(files['source-map.json'][0])
   with self.assertRaises(ValueError):entry.source_gate(root,P.identity(files)['map_sha256'])
 def test_profile_construction_and_full_closed_inverse(self):
  before=parent_model();parent=P.identity(before)
  with tempfile.TemporaryDirectory(prefix='FENCED-v9-constructor-')as name:
   root=Path(name);base=root/'parent';write(before,base);constructor=root/'constructor';constructor.mkdir();shutil.copytree(HERE/'payload',constructor/'payload')
   with patch.object(P,'PARENT',parent),patch.object(P,'HERE',constructor):
    files=P.render(before);profile=dict(schema=9,scope=P.SCOPE,parent=parent,actual=P.ACTUAL,Root_review=None,accepted=None,unadmitted=True,constructor_files=P.inputs(),**P.identity(files));raw=P.encode(profile);(constructor/'constructor-profile.json').write_bytes(raw);sha=P.fs.pin(raw)['sha256']
    with self.assertRaises(ValueError):P.construct(base,root/'bad','0'*64)
    result=P.construct(base,root/'output',sha);self.assertTrue(result['unadmitted']);self.assertEqual(P.fs.snapshot(root/'output'),files)
    with self.assertRaises((ValueError,OSError)):P.construct(base,root/'output',sha)
    (base/'.git').write_text('FENCED extra')
    with self.assertRaises(ValueError):P.capture(base)
 def test_root_pregrant_template_identical_and_new_authority_unissued(self):
  self.assertEqual((HERE/'Root-admission.TEMPLATE.json').read_bytes(),(HERE.parent/'successor_v8/Root-admission.TEMPLATE.json').read_bytes());v=json.loads((HERE/'Root-admission.TEMPLATE.json').read_bytes());self.assertIsNone(v['resources']);self.assertTrue(all(x is None for x in v['source'].values()));self.assertTrue(all(x is None for x in v['reviews'].values()));self.assertIsNone(v['bootstrap']['provider_policy_reviewed'])

 def test_checked_in_profile_matches_complete_constructor_and_null_authority(self):
  v=json.loads((HERE/'constructor-profile.json').read_bytes());self.assertEqual(v['schema'],9);self.assertEqual(v['parent'],P.PARENT);self.assertEqual(v['constructor_files'],P.inputs());self.assertEqual(v['actual'],P.ACTUAL);self.assertIsNone(v['Root_review']);self.assertIsNone(v['accepted']);self.assertTrue(v['unadmitted']);self.assertEqual(v['files'],333)

if __name__=='__main__':unittest.main(verbosity=2)
