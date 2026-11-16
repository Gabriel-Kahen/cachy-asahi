#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fenced HTTP protocol and complete333 inverse DATA; no real HTTP or role."""
import copy,hashlib,importlib.util,json,shutil,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=module('v10_constructor_DATA',HERE/'prepare.py');M=module('v10_material_client_FENCED',HERE/'payload/hosted/materials.py');T=module('v10_phase_client_FENCED',HERE/'payload/hosted/phase_transfer.py');V9=module('v9_support_FENCED',HERE.parent/'successor_v9/test_data.py');OLD_M=V9.M;OLD_T=V9.T
TOKEN=V9.TOKEN;BODY=V9.BODY;API=V9.API;HOST=V9.HOST;META=b'{"FENCED":"metadata bytes unchanged"}\n'

def fence(event,args):
 if event.startswith(('socket.','subprocess.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
  raise AssertionError('FENCED no HTTP/process/lease '+event)
sys.addaudithook(fence)

def budget(which):return M.Budget(V9.command())if which in(M,OLD_M)else T.Budget(V9.command(),30)
def fetch(which,url,target,b,**kwargs):
 if which in(M,OLD_M):return which.fetch(url,target,kwargs.pop('expected',None),b,kwargs.pop('hosts',{'api.github.com'}),TOKEN,cap=kwargs.pop('cap',1024),**kwargs)
 return which.fetch(url,target,b,kwargs.pop('hosts',{'api.github.com'}),TOKEN,cap=kwargs.pop('cap',1024),**kwargs)

class ProtocolServer(V9.FakeHTTPServer):
 """Enforces endpoint methods/media types at the in-memory connection seam."""
 def __init__(self,metadata_accept,alter=None):
  self.metadata_accept=metadata_accept;self.alter=alter;super().__init__(self.respond)
 def respond(self,host,method,path,headers):
  if self.alter:host,method,path,headers=self.alter(host,method,path,dict(headers))
  if method!='GET':return 405,b'FENCED GET only',{}
  if headers.get('User-Agent')!=P.USER_AGENT:return 403,b'FENCED User-Agent required',{}
  if host=='api.github.com':
   if headers.get('Authorization')!='Bearer '+TOKEN:return 401,b'FENCED scoped API auth required',{}
   if path.endswith('/zip'):
    if headers.get('Accept')!='application/vnd.github+json':return 415,b'FENCED API vendor Accept required',{}
    return 303,b'',{'Location':'https://'+HOST+'/opaque.bin?sig=FENCED_SIGNED_QUERY'}
   if headers.get('Accept')!=self.metadata_accept:return 415,b'FENCED metadata headers changed',{}
   return 200,META,{'Content-Length':str(len(META))}
  if host!=HOST:return 400,b'FENCED wrong origin',{}
  if 'Authorization'in headers:return 401,b'FENCED forwarded credentials',{}
  if headers.get('Accept')!='application/octet-stream':return 406,b'FENCED storage octet-stream required',{}
  return 200,BODY,{'Content-Length':str(len(BODY))}


def parent_model():
 before=V9.parent_model()
 with patch.object(V9.P,'PARENT',V9.P.identity(before)):return V9.P.render(before)

class HTTPControls(unittest.TestCase):
 def test_old_v9_api_metadata200_then_zip415_and_no_body_or_retry(self):
  for which in(OLD_M,OLD_T):
   with self.subTest(client=which.__name__),tempfile.TemporaryDirectory(prefix='FENCED-v10-old-')as temp:
    server=ProtocolServer('application/vnd.github+json'if which is OLD_M else None);b=budget(which)
    with patch.object(which,'_connection',server.connection):
     self.assertEqual(fetch(which,API,Path(temp)/'meta',b),P.fs.pin(META))
     with self.assertRaises(ValueError):fetch(which,API+'/zip',Path(temp)/'zip',b,expected=P.fs.pin(BODY),hosts={'api.github.com',HOST},redirects=3)
    self.assertEqual([r['status']for r in b.requests],[200,415]);self.assertEqual(len(server.rows),2);self.assertFalse((Path(temp)/'zip').exists());self.assertEqual(b.requests[-1]['bytes'],0)
 def test_new_metadata200_vendor_api_redirect303_storage_octet200(self):
  for which in(M,T):
   with self.subTest(client=which.__name__),tempfile.TemporaryDirectory(prefix='FENCED-v10-wire-')as temp:
    server=ProtocolServer('application/vnd.github+json'if which is M else None);b=budget(which)
    with patch.object(which,'_connection',server.connection):
     self.assertEqual(fetch(which,API,Path(temp)/'meta',b),P.fs.pin(META));self.assertEqual(fetch(which,API+'/zip',Path(temp)/'body',b,expected=P.fs.pin(BODY),hosts={'api.github.com',HOST},redirects=3),P.fs.pin(BODY))
    self.assertEqual([r['status']for r in b.requests],[200,303,200]);self.assertEqual((Path(temp)/'meta').read_bytes(),META);self.assertEqual((Path(temp)/'body').read_bytes(),BODY)
    metadata,api,storage=server.rows;self.assertEqual(api['headers']['Accept'],'application/vnd.github+json');self.assertEqual(storage['headers']['Accept'],'application/octet-stream');self.assertIn('Authorization',metadata['headers']);self.assertIn('Authorization',api['headers']);self.assertNotIn('Authorization',storage['headers']);self.assertTrue(all(r['method']=='GET'for r in server.rows));self.assertTrue(all('X-GitHub-Api-Version'not in r['headers']for r in server.rows));self.assertTrue(all(r['headers']['User-Agent']==P.USER_AGENT for r in server.rows));self.assertNotIn(TOKEN,json.dumps(b.requests));self.assertNotIn('FENCED_SIGNED_QUERY',json.dumps(b.requests));self.assertEqual(server.closed,3)
 def test_conditional_phase_same_needs_authorization_protocol(self):
  facts=V9.V8.facts();a=T.authorize_transfer(*facts,HERE.parent/'successor_v8/payload');a['binding']['artifact_sha256']=P.fs.pin(BODY)['sha256'];server=ProtocolServer(None);b=budget(T)
  with tempfile.TemporaryDirectory(prefix='FENCED-v10-needs-')as temp,patch.object(T,'_connection',server.connection):
   fetch(T,API,Path(temp)/'meta',b);self.assertEqual(fetch(T,a['endpoint'],Path(temp)/'body',b,expected=P.fs.pin(BODY),cap=T.ARTIFACT_CAP,redirects=3,authorization=a),P.fs.pin(BODY))
  self.assertEqual(a['selected_host'],HOST);self.assertEqual([r['status']for r in b.requests],[200,303,200]);self.assertNotIn('Authorization',server.rows[-1]['headers'])
 def test_incorrect_api_accept_method_ua_auth_and_storage_accept_refuse(self):
  def alter(kind):
   def changed(host,method,path,headers):
    if kind=='accept'and host=='api.github.com':headers['Accept']='application/octet-stream'
    elif kind=='method':method='HEAD'
    elif kind=='UA':headers.pop('User-Agent',None)
    elif kind=='auth'and host=='api.github.com':headers.pop('Authorization',None)
    elif kind=='storage'and host==HOST:headers['Accept']='application/vnd.github+json'
    return host,method,path,headers
   return changed
  for which in(M,T):
   for kind,status in(('accept',415),('method',405),('UA',403),('auth',401),('storage',406)):
    with self.subTest(client=which.__name__,kind=kind),tempfile.TemporaryDirectory(prefix='FENCED-v10-refuse-')as temp:
     server=ProtocolServer('application/vnd.github+json'if which is M else None,alter(kind));b=budget(which)
     with patch.object(which,'_connection',server.connection),self.assertRaises(ValueError):fetch(which,API+'/zip',Path(temp)/'body',b,expected=P.fs.pin(BODY),hosts={'api.github.com',HOST},redirects=3)
     self.assertEqual(b.requests[-1]['status'],status);self.assertLessEqual(len(server.rows),2);self.assertFalse((Path(temp)/'body').exists())
 def test_metadata_headers_are_exact_old_dicts_and_no_api_version_change(self):
  for old,new,accept in((OLD_M,M,'application/vnd.github+json'),(OLD_T,T,None)):
   headers=[]
   for which in(old,new):
    with tempfile.TemporaryDirectory(prefix='FENCED-v10-meta-')as temp:
     server=ProtocolServer(accept);b=budget(which)
     with patch.object(which,'_connection',server.connection):fetch(which,API,Path(temp)/'meta',b)
     headers.append(server.rows[0]['headers'])
   self.assertEqual(headers[0],headers[1])
 def test_conditional_second_host_loop_and_metadata_redirect_still_refuse(self):
  for location in('https://foreign.invalid/zip?sig=FENCED',API+'/zip'):
   for which in(M,T):
    with self.subTest(location=location,client=which.__name__),tempfile.TemporaryDirectory(prefix='FENCED-v10-host-')as temp:
     server=V9.FakeHTTPServer(lambda *args:(303,b'',{'Location':location}));b=budget(which)
     with patch.object(which,'_connection',server.connection),self.assertRaises(ValueError):fetch(which,API+'/zip',Path(temp)/'body',b,expected=P.fs.pin(BODY),hosts={'api.github.com',HOST},redirects=3)
     self.assertEqual(len(server.rows),1)
  for which in(M,T):
   with tempfile.TemporaryDirectory(prefix='FENCED-v10-meta-redirect-')as temp:
    server=V9.FakeHTTPServer(lambda *args:(303,b'',{'Location':'https://'+HOST+'/opaque.bin'}));b=budget(which)
    with patch.object(which,'_connection',server.connection),self.assertRaises(ValueError):fetch(which,API,Path(temp)/'meta',b,hosts={'api.github.com',HOST})
    self.assertEqual(len(server.rows),1)
 def test_body_sha_length_encoding_and_request_caps_unchanged(self):
  for which,cap in((M,M.REQUESTS),(T,T.REQUEST_CAP)):
   for response in((200,BODY,{'Content-Length':'999'}),(200,b'changed',{}),(200,BODY,{'Content-Encoding':'gzip'})):
    with tempfile.TemporaryDirectory(prefix='FENCED-v10-byte-')as temp:
     server=V9.FakeHTTPServer(lambda *args:response);b=budget(which)
     with patch.object(which,'_connection',server.connection),self.assertRaises(ValueError):fetch(which,API+'/zip',Path(temp)/'body',b,expected=P.fs.pin(BODY))
     self.assertEqual(len(server.rows),1)
   with tempfile.TemporaryDirectory(prefix='FENCED-v10-cap-')as temp:
    server=ProtocolServer(None);b=budget(which);b.requests=[{}]*cap
    with patch.object(which,'_connection',server.connection),self.assertRaises(ValueError):fetch(which,API,Path(temp)/'meta',b)
    self.assertEqual(server.rows,[])

class SourceControls(unittest.TestCase):
 def test_full333_inverse_preserves_workflows_entry_ua_resources_and_all_other_bodies(self):
  before=parent_model();parent=P.identity(before)
  with patch.object(P,'PARENT',parent):
   after=P.render(before);self.assertEqual(P.undo(after),before)
   for name,row in before.items():
    if name not in P.REPLACED|{'source-map.json'}:self.assertEqual(after[name],row,name)
   self.assertEqual(set(after)-set(before),{P.MARKER}|{P.ARCHIVE+n for n in P.REPLACED|{'source-map.json'}})
   for leaf in('hosted/entry.py','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-rust199-source-reference-v1.yml','resource-policy.json','admission.py','candidate-map.json','contract.json','recipe/PKGBUILD','http-user-agent-v9.json','phase-transfer-v8.json'):self.assertEqual(after[leaf],before[leaf],leaf)
 def test_program_whole_inverse_is_only_header_selection(self):
  before=parent_model();P.check_delta(before,P.fs.snapshot(HERE/'payload'))
  self.assertEqual(M.SECONDS,OLD_M.SECONDS);self.assertEqual(M.REQUESTS,OLD_M.REQUESTS);self.assertEqual((T.REQUEST_CAP,T.IMPORT_SECONDS,T.ARTIFACT_CAP,T.IMAGE_CAP),(OLD_T.REQUEST_CAP,OLD_T.IMPORT_SECONDS,OLD_T.ARTIFACT_CAP,OLD_T.IMAGE_CAP));self.assertEqual(P.USER_AGENT,V9.P.USER_AGENT)
 def test_parent_payload_or_inverse_tamper_refuses(self):
  before=parent_model();parent=P.identity(before)
  with patch.object(P,'PARENT',parent):
   bad=dict(before);bad['extra']=(b'FENCED',0o644)
   with self.assertRaises(ValueError):P.render(bad)
   bad=P.fs.snapshot(HERE/'payload');bad['hosted/materials.py']=(bad['hosted/materials.py'][0]+b'\n',0o644)
   with self.assertRaises(ValueError):P.check_delta(before,bad)
   after=P.render(before);after['hosted/entry.py']=(after['hosted/entry.py'][0]+b'\n',0o644)
   with self.assertRaises(ValueError):P.undo(after)
 def test_profile_publication_existing_output_and_extra_git_refuse(self):
  before=parent_model();parent=P.identity(before)
  with tempfile.TemporaryDirectory(prefix='FENCED-v10-constructor-')as temp:
   root=Path(temp);base=root/'parent';V9.write(before,base);constructor=root/'constructor';constructor.mkdir();shutil.copytree(HERE/'payload',constructor/'payload')
   with patch.object(P,'PARENT',parent),patch.object(P,'HERE',constructor):
    files=P.render(before);profile=dict(schema=10,scope=P.SCOPE,parent=parent,actual=P.ACTUAL,Root_review=None,accepted=None,unadmitted=True,constructor_files=P.inputs(),**P.identity(files));raw=P.encode(profile);(constructor/'constructor-profile.json').write_bytes(raw);sha=P.fs.pin(raw)['sha256']
    with self.assertRaises(ValueError):P.construct(base,root/'bad','0'*64)
    self.assertTrue(P.construct(base,root/'output',sha)['unadmitted']);self.assertEqual(P.fs.snapshot(root/'output'),files)
    with self.assertRaises((ValueError,OSError)):P.construct(base,root/'output',sha)
    (base/'.git').write_text('FENCED extra')
    with self.assertRaises(ValueError):P.capture(base)
 def test_source_gate_still_checks_complete_current_map_and_pregrant_unissued(self):
  before=parent_model();parent=P.identity(before)
  with tempfile.TemporaryDirectory(prefix='FENCED-v10-gate-')as temp,patch.object(P,'PARENT',parent):
   files=P.render(before);root=Path(temp)/'source';V9.write(files,root);entry=module('v10_whole_current_source_gate_FENCED',root/'hosted/entry.py');entry.source_gate(root,P.identity(files)['map_sha256']);(root/'hosted/materials.py').write_bytes(files['hosted/materials.py'][0]+b'\n')
   with self.assertRaises(ValueError):entry.source_gate(root,P.identity(files)['map_sha256'])
  self.assertEqual((HERE/'Root-admission.TEMPLATE.json').read_bytes(),(HERE.parent/'successor_v9/Root-admission.TEMPLATE.json').read_bytes());v=json.loads((HERE/'Root-admission.TEMPLATE.json').read_bytes());self.assertIsNone(v['resources']);self.assertTrue(all(x is None for x in v['source'].values()));self.assertTrue(all(x is None for x in v['reviews'].values()))

 def test_checked_in_profile_unissued_and_complete_constructor(self):
  v=json.loads((HERE/'constructor-profile.json').read_bytes());self.assertEqual(v['schema'],10);self.assertEqual(v['parent'],P.PARENT);self.assertEqual(v['constructor_files'],P.inputs());self.assertEqual(v['files'],337);self.assertEqual(v['actual'],P.ACTUAL);self.assertIsNone(v['Root_review']);self.assertIsNone(v['accepted']);self.assertTrue(v['unadmitted'])

if __name__=='__main__':unittest.main(verbosity=2)
