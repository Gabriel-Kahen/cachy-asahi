# SPDX-License-Identifier: MIT
"""Modeled Docker DATA callback only; never enters Docker, a lease or a process."""
import contextlib,copy,importlib.util,json,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('xs_v4_modeled_image',HERE/'payload/xs/compiler_image.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
COMMON=types.SimpleNamespace(decode=json.loads,encode=lambda v:(json.dumps(v,sort_keys=True)+'\n').encode())
class Model:
 def __init__(self,source,fail=None):
  self.deadline=9000;self.cleaning=False;self.source=source;self.fail=fail;self.container=None;self.derived=None;self.calls=[];self.labels=None;self.tag=None
  self.parent=dict(Id='sha256:'+'1'*64,Architecture='arm64',Os='linux',Size=1000000,Config=dict(User='alarm',WorkingDir='/tmp',Entrypoint=None,Cmd=None,Env=['PATH=/usr/bin'],Labels={'cachy-asahi.hosted-perl':'parent'},AttachStdout=False,AttachStderr=False,Hostname='',Image=''),RootFS={'Layers':['sha256:'+'a'*64]})
 def __call__(self,argv,timeout):
  self.calls.append(list(argv));cmd=argv[len(C.DOCKER):];out=b'';err=b'';exit=0
  if cmd[:2]==['container','ls']:out=((self.container['Name'][1:]+'\n').encode()if self.container else b'')
  elif cmd[:2]==['image','ls']:out=((self.derived['Id']+'\n').encode()if self.derived else b'')
  elif cmd[:2]==['image','inspect']:
   value=self.parent if cmd[-1]==self.parent['Id']else self.derived
   if value is None:exit=1;err=('Error response from daemon: No such image: '+cmd[-1]+'\n').encode()
   else:out=json.dumps([value]).encode()
  elif cmd[0]=='create':
   labels=dict(v.split('=',1)for i,v in enumerate(cmd)if i and cmd[i-1]=='--label');self.labels=labels;name=cmd[cmd.index('--name')+1]
   h=dict(NetworkMode='none',CapDrop=['ALL'],CapAdd=None,Privileged=False,ReadonlyRootfs=False,Devices=[],Init=False,SecurityOpt=['no-new-privileges'],Memory=512*1024**2,MemorySwap=512*1024**2,NanoCpus=2000000000,PidsLimit=64,Tmpfs={'/tmp':'rw,noexec,nosuid,nodev,size=8m'})
   self.container=dict(Id='c'*64,Name='/'+name,Image=self.parent['Id'],Config={'Labels':labels,'User':'0:0','AttachStdout':True,'AttachStderr':True,'Hostname':'c'*12,'Image':self.parent['Id'],'Entrypoint':['/usr/bin/python3'],'Cmd':['-I','-B','/tmp/source/xs/compiler_image.py','--copy-driver',self.source]},Mounts=[{'Type':'bind','Source':'/retained/source','Destination':'/tmp/source','RW':False}],HostConfig=h,State={'Running':False,'Pid':0,'ExitCode':0,'OOMKilled':False})
   if self.fail=='ambiguous-create':raise TimeoutError('modeled create returned ambiguously')
   out=b'modeled-container-id\n'
  elif cmd[0]=='inspect':out=json.dumps([self.container]).encode()
  elif cmd[:2]==['start','--attach']:
   if self.fail=='running-timeout':self.container['State'].update(Running=True,Pid=123);raise TimeoutError('modeled original start timeout')
   out=json.dumps(dict(kind='XS_V4_SINGLE_LINK_COMPILER_COPY_V1',status='COPIED_DATA_ONLY',source=self.source,operation=C.OP,manifest=C.MANIFEST,count=349,driver={'nlink':1},compiler_invocations=0)).encode()
  elif cmd[0]=='diff':out=b'C /usr\nC /usr/bin\nA /usr/bin/cachy-asahi-xs-gcc\n'
  elif cmd[0]=='commit':
   self.tag=cmd[-1];self.derived=copy.deepcopy(self.parent);self.derived.update(Id='sha256:'+'2'*64,RepoTags=[self.tag],Size=3365000);self.derived['Config']=C.expected_config(self.parent,self.labels,self.container['Config']);self.derived['RootFS']['Layers'].append('sha256:'+'b'*64)
   if self.fail=='ambiguous-commit':raise TimeoutError('modeled commit returned ambiguously')
   out=(self.derived['Id']+'\n').encode()
  elif cmd[0]=='stop':self.container['State'].update(Running=False,Pid=0,ExitCode=143)
  elif cmd[0]=='rm':self.container=None
  elif cmd[:2]==['image','rm']:self.derived=None
  else:raise AssertionError('unexpected modeled callback '+str(cmd))
  return types.SimpleNamespace(returncode=exit,stdout=out,stderr=err)

class Controls(unittest.TestCase):
 def setUp(self):
  stack=contextlib.ExitStack();self.addCleanup(stack.close)
  for n in ['subprocess.run','subprocess.Popen','socket.socket','fcntl.flock']:stack.enter_context(patch(n,side_effect=AssertionError('modeled DATA only; no actor')))
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.path=Path(self.tmp.name);self.binding={'source':'b'*40,'run':'12345'}
 def invoke(self,model):return C.run(COMMON,model,self.path,self.binding,model.parent['Id'],Path('/retained/source'))
 def test_modeled_natural_copy_qualifies_distinct_image_and_retires_actor(self):
  model=Model(self.binding['source']);result=self.invoke(model);self.assertEqual(result['status'],'QUALIFIED_COPY_ONLY_XS_NOT_RUN');self.assertIsNone(model.container);self.assertIsNotNone(model.derived);self.assertEqual(model.parent['Config']['Labels'],{'cachy-asahi.hosted-perl':'parent'});self.assertEqual(model.deadline,9000);self.assertFalse(model.cleaning)
  commit=next(argv for argv in model.calls if argv[len(C.DOCKER)]=='commit');self.assertIn('ENTRYPOINT [\"/usr/bin/false\"]',commit);self.assertIn('CMD [\"/usr/bin/false\"]',commit)
  C.retire(COMMON,model,result);self.assertIsNone(model.derived)
 def test_ambiguous_create_recovers_exact_owned_container_without_retry(self):
  model=Model(self.binding['source'],'ambiguous-create')
  with self.assertRaisesRegex(TimeoutError,'create returned ambiguously'):self.invoke(model)
  self.assertIsNone(model.container);self.assertIsNone(model.derived);self.assertEqual(sum(v[len(C.DOCKER)]=='create'for v in model.calls),1)
 def test_ambiguous_commit_recovers_and_removes_only_owned_derived_image(self):
  model=Model(self.binding['source'],'ambiguous-commit')
  with self.assertRaisesRegex(TimeoutError,'commit returned ambiguously'):self.invoke(model)
  self.assertIsNone(model.container);self.assertIsNone(model.derived);self.assertEqual(model.parent['Id'],'sha256:'+'1'*64)
 def test_start_timeout_keeps_original_error_and_retires_exact_actor(self):
  model=Model(self.binding['source'],'running-timeout')
  with self.assertRaisesRegex(TimeoutError,'original start timeout'):self.invoke(model)
  self.assertIsNone(model.container);self.assertIsNone(model.derived);receipt=json.loads((self.path/'compiler-image-cleanup.json').read_bytes());self.assertFalse(receipt['qualified']);self.assertEqual(receipt['original_error']['category'],'TimeoutError')

if __name__=='__main__':unittest.main()
