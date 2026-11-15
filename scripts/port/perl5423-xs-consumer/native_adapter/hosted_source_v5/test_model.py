# SPDX-License-Identifier: MIT
"""Actual adapter definitions against an owned DATA-only Docker/filesystem model."""
import ast,contextlib,copy,hashlib,json,os,re,signal,stat,subprocess,tempfile,time,types,unittest,uuid,io,tarfile,importlib.util
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;NATIVE=HERE/'payload/consumer/native_adapter/native.py'
TMPFS={'/run':'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001','/tmp':'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001','/xs-work':'rw,exec,nosuid,nodev,size=256m,uid=1001,gid=1001,mode=0700'}
def encode(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(v):return dict(bytes=len(v),sha256=hashlib.sha256(v).hexdigest())
def need(v,s):
 if not v:raise ValueError(s)
def statdata(s,uid=1001,gid=1001):
 return types.SimpleNamespace(**{**{n:getattr(s,n)for n in ['st_mode','st_dev','st_ino','st_nlink','st_size','st_mtime_ns','st_ctime_ns']},'st_uid':uid,'st_gid':gid})
class Model:
 def __init__(self,root,caps=None,mode=0o755,nonempty=False,drop_nocopy=False,foreign_cleanup=False,owner_after_init=1001):
  self.root=root;self.work=root/'work';self.work.mkdir(mode=mode);self.work.chmod(mode);self.bundle=root/'bundle';self.bundle.mkdir();self.output=root/'result';self.owner=0;self.events=[];self.calls=[];self.containers={};self.volumes={};self.caps=['CAP_CHOWN']if caps is None else caps;self.drop_nocopy=drop_nocopy;self.foreign_cleanup=foreign_cleanup;self.actor_calls=0;self.owner_after_init=owner_after_init
  if nonempty:(self.work/'preexisting').write_bytes(b'MODELED_EXISTING')
  self.operation=dict(schema=1,operation='perl5423-native-xs-v1',authorization='ROOT_ACCEPTED_PAIR_AND_ADMITTED_NATIVE_XS',source=dict(sha='7'*40,ref='codex/MODELED_NOT_ACTUAL'),run='1',job='2',pair=dict(source='8'*40,run='3',job='4'),image='sha256:'+'a'*64,authorize_runtime_observation_only=True,runner_sha256='bf2903fd1f72fe5c33a71bd00a15f71e7a4ae153d13522682af4f71d660e580e',expected349_sha256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453',nested_invocation='NOT_INVOKED',nested_qualification='NOT_QUALIFIED',accepted_reader_receipt=dict(path='/inputs/accepted-reader.json',bytes=1,sha256='b'*64))
  for n in ['approval','source_readback_sha256','native_daemon_identity_sha256','input_signature_audit_sha256','bundle_map_sha256','xs_admission_sha256','inputs_sha256','plan_sha256']:self.operation[n]='c'*64
  self.operation['runtime_identity_generator_sha256']=pin(NATIVE.read_bytes())['sha256'];self.ar=encode(self.operation);self.admission=pin(self.ar)['sha256'];(self.bundle/'operation.json').write_bytes(self.ar);(self.bundle/'daemon.json').write_bytes(b'{}')
  self.ns=self.namespace()
 def namespace(self):
  model=self
  class OwnedPath:
   def __init__(self,p):
    text=os.fspath(p);self.real=model.work/str(text)[6:]if text=='/work'or text.startswith('/work/')else model.bundle/str(text)[8:]if text.startswith('/inputs/')else Path(text)
   def __fspath__(self):return str(self.real)
   def __str__(self):return str(self.real)
   def __truediv__(self,p):return OwnedPath(self.real/p)
   def __eq__(self,p):return self.real==Path(os.fspath(p))
   @property
   def parent(self):return OwnedPath(self.real.parent)
   @classmethod
   def cwd(cls):return cls(model.work)
   def stat(self):
    if self.real==Path('/var/run/docker.sock'):return types.SimpleNamespace(st_dev=1,st_ino=2,st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_gid=0)
    return statdata(self.real.stat(),model.owner if self.real==model.work else 1001,model.owner if self.real==model.work else 1001)
   lstat=stat
   def read_text(self):return 'MemAvailable: 16777216 kB\n'if self.real==Path('/proc/meminfo')else self.real.read_text()
   def __getattr__(self,n):return getattr(self.real,n)
  class OS:
   def __getattr__(self,n):return getattr(os,n)
   getuid=geteuid=getgid=getegid=staticmethod(lambda:1001)
   uname=staticmethod(lambda:types.SimpleNamespace(sysname='Linux',machine='aarch64'))
   @staticmethod
   def fstat(fd):
    s=os.fstat(fd);p=Path(os.readlink('/proc/self/fd/'+str(fd)));return statdata(s,model.owner if p==model.work else 1001,model.owner if p==model.work else 1001)
  def read(p,cap=16*1024**2):
   p=OwnedPath(p);raw=p.real.read_bytes();need(len(raw)<=cap,'modeled DATA cap');return raw
  common=types.SimpleNamespace(need=need,pin=pin,encode=encode,decode=json.loads,sha=lambda s,n=64:type(s)is str and re.fullmatch('[0-9a-f]{'+str(n)+'}',s)is not None,read=read,path=OwnedPath,natural=lambda row,zero=True:row.get('natural_exit')and row.get('group_absent')and row.get('retirement')=='REAPED'and not row.get('forced_cleanup')and (not zero or row.get('exit')==0))
  parser_path=HERE.parent/'support/data_export.py';need(pin(parser_path.read_bytes())['sha256']=='ac59342608cc8279ccb0aa218da792e72d903960769ab2f4553ee8ea9b5d334e','whole frozen passive export parser')
  spec=importlib.util.spec_from_file_location('model_pinned_export_parser',parser_path);parser=importlib.util.module_from_spec(spec);spec.loader.exec_module(parser)
  runner=types.SimpleNamespace(HELPER_SHA='0'*64,load_module=lambda name,*a:model if name=='native_xs_owned'else parser,Cancellation=lambda:types.SimpleNamespace(signum=None,check=lambda:None,signal=lambda *a:None),signal=types.SimpleNamespace(SIGINT=signal.SIGINT,SIGTERM=signal.SIGTERM,getsignal=lambda s:None,signal=lambda *a:None))
  ns=dict(c=common,runner=runner,p=types.SimpleNamespace(),os=OS(),Path=OwnedPath,re=re,stat=stat,time=time,uuid=uuid,subprocess=types.SimpleNamespace(STDOUT=-2),resource=types.SimpleNamespace(RLIMIT_FSIZE=1,RLIM_INFINITY=-1,getrlimit=lambda *a:(-1,-1),setrlimit=lambda *a:None),shutil=types.SimpleNamespace(disk_usage=lambda p:types.SimpleNamespace(free=32*1024**3)),HERE=NATIVE.parent,CONSUMER=NATIVE.parent.parent,DOCKER=['/usr/bin/docker','--host=unix:///var/run/docker.sock'],TMPFS=TMPFS,RUNNER_SHA=self.operation['runner_sha256'],OPERATION='perl5423-native-xs-v1',INVENTORY=self.operation['expected349_sha256'])
  tree=ast.parse(NATIVE.read_bytes());functions=[n for n in tree.body if isinstance(n,ast.FunctionDef)];exec(compile(ast.Module(body=functions,type_ignores=[]),'<actual-adapter-definitions-DATA-model>','exec'),ns)
  ns.update(bundle_check=lambda *a:None,inputs=lambda *a:None,daemon_join=lambda *a:None)
  before=ns['work_preentry']
  def preentry(sha):
   result=before(sha);self.events.append(('preentry',result[0]));return result
  def actor(sha):
   self.actor_calls+=1;self.events.append(('actor_first_write',None));out=self.work/'output';out.mkdir(mode=0o700)
   data=b'FENCED_DATA_NOT_XS';rows={'fixture.data':dict(file='evidence-000.data',**pin(data))};files={'runtime-observation.json':encode(dict(schema=1,generator_sha256=self.operation['runtime_identity_generator_sha256'])),'actor-result.json':encode(dict(status='RUNNER_COMPLETED',operation_sha256=sha,native_acceptance=False,XS_acceptance=False)),'evidence-map.json':encode(rows),'evidence-000.data':data,'actual-packages.txt':b'FENCED_DATA_NOT_349\n','operation.json':self.ar,'accepted-reader.json':b'{}'}
   self.original_json={k:v for k,v in files.items()if k in('runtime-observation.json','actor-result.json')}
   for n,raw in files.items():(out/n).write_bytes(raw)
   return 0
  ns.update(work_preentry=preentry,actor=actor);return ns
 def run(self,argv,**kw):
  self.calls.append(list(argv));cmd=argv[2:];out=b'';code=0
  if cmd[:2]==['image','inspect']:out=encode([dict(Id=self.operation['image'],Architecture='arm64',Os='linux',Config={'Volumes':None})])
  elif cmd[:1]==['info']:out=encode({'DockerRootDir':str(self.root)})
  elif cmd[:1]==['version']:out=b'{}'
  elif cmd[:2]==['container','ls']:out='\n'.join(self.containers).encode()
  elif cmd[:2]==['volume','ls']:out='\n'.join(self.volumes).encode()
  elif cmd[:2]==['volume','create']:self.volumes[cmd[-1]]=dict(Name=cmd[-1],Labels={'cachy-asahi.admission':self.admission});out=(cmd[-1]+'\n').encode()
  elif cmd[0]=='create':
   name=cmd[cmd.index('--name')+1];is_init=name.endswith('-init');cid=('1'if is_init else'2')*64;volume=next(x.split('src=',1)[1].split(',',1)[0]for x in cmd if x.startswith('type=volume,'));mounts=[dict(Type='volume',Name=volume,Destination='/work',RW=True)]
   if not is_init:mounts.insert(0,dict(Type='bind',Source=str(self.bundle),Destination='/inputs',RW=False))
   declaration=dict(Type='volume',Source=volume,Target='/work',VolumeOptions={'NoCopy':not self.drop_nocopy and any('volume-nocopy'in x for x in cmd)})
   row=dict(Id=cid,Name='/'+name,Image=self.operation['image'],State=dict(Status='created',Running=False,Pid=0,ExitCode=0,OOMKilled=False),Config=dict(User='0:0'if is_init else'1001:1001',Hostname='perl5423-native',Labels={'cachy-asahi.admission':self.admission},Entrypoint=['/usr/bin/chown']if is_init else['/usr/bin/python3'],WorkingDir='/work',Cmd=['1001:1001','/work']if is_init else['-I','-B','/inputs/consumer/native_adapter/native.py','actor','--admission-sha256',self.admission]),HostConfig=dict(NanoCpus=2000000000,Memory=4294967296,MemorySwap=4294967296,PidsLimit=256,ReadonlyRootfs=True,Init=not is_init,NetworkMode='none',CgroupnsMode='private',CapDrop=['ALL'],CapAdd=self.caps if is_init else[],SecurityOpt=['no-new-privileges'],Privileged=False,Devices=[],DeviceRequests=[],Tmpfs=TMPFS,Mounts=[declaration]),Mounts=mounts)
   self.containers[name]=row;self.events.append(('create_init'if is_init else'create_consumer',None));out=(cid+'\n').encode()
  elif cmd[0]=='inspect'or cmd[:2]in(['container','inspect'],['volume','inspect']):
   name=cmd[-1];row=self.volumes.get(name)if cmd[0]=='volume'else self.containers.get(name)
   if row is None:out=('Error: No such container: '+name).encode();code=1
   else:out=encode([row])
  elif cmd[:2]==['start','--attach']:
   row=self.containers[cmd[-1]]
   if cmd[-1].endswith('-init'):self.owner=self.owner_after_init;self.events.append(('start_init',None))
   else:
    self.events.append(('start_consumer',None))
    try:code=self.ns['actor_dispatch'](self.admission)
    except BaseException as error:code=1;out=(type(error).__name__+': '+str(error)).encode()
   row['State'].update(Status='exited',ExitCode=code)
  elif cmd[0]=='stop':self.containers[cmd[-1]]['State'].update(Status='exited',Running=False,Pid=0)
  elif cmd[0]=='cp':
   if (self.work/'output').exists():
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=tarfile.USTAR_FORMAT)as archive:
     directory=tarfile.TarInfo('output');directory.type=tarfile.DIRTYPE;directory.mode=0o700;archive.addfile(directory)
     for path in sorted((self.work/'output').iterdir()):
      body=path.read_bytes();item=tarfile.TarInfo('output/'+path.name);item.size=len(body);item.mode=stat.S_IMODE(path.stat().st_mode);archive.addfile(item,io.BytesIO(body))
    out=stream.getvalue()
   else:code=1
  elif cmd[:2]==['container','rm']:
   selected=next(n for n,row in self.containers.items()if row['Id']==cmd[-1]);self.containers.pop(selected);out=(cmd[-1]+'\n').encode()
  elif cmd[:2]==['volume','rm']:self.volumes.pop(cmd[-1]);out=(cmd[-1]+'\n').encode()
  else:raise AssertionError('unreviewed modeled Docker operation '+str(cmd))
  if self.foreign_cleanup and cmd[:2]==['container','inspect']and cmd[-1]in self.containers:self.containers[cmd[-1]]['Config']['Labels']={};out=encode([self.containers[cmd[-1]]])
  kw['stdout'].write(out);kw['lifecycle'].update(pid=123,exit=code,natural_exit=True,group_absent=True,retirement='REAPED',forced_cleanup=False,ownership_lost=False,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,elapsed_seconds=.01);return types.SimpleNamespace(returncode=code)
 def invoke(self):
  result=self.ns['producer'](str(self.bundle),self.admission,str(self.output));return result,json.loads((self.output/'producer-receipt.json').read_bytes())

class Controls(unittest.TestCase):
 def setUp(self):
  stack=contextlib.ExitStack();self.addCleanup(stack.close)
  for n in ['subprocess.Popen','subprocess.run','socket.socket','socket.create_connection','fcntl.flock','os.fork','os.pidfd_open']:stack.enter_context(patch(n,side_effect=AssertionError('DATA model forbids actual actor/network/lease'),create=True))
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def test_actual_producer_dispatch_receipt_parse_and_empty_order(self):
  m=Model(self.root);code,report=m.invoke();self.assertEqual(code,0);self.assertEqual(report['status'],'SMOKE_EVIDENCE_EXPORTED_PENDING_INDEPENDENT_READER');self.assertTrue(report['owned_resources_absent']);self.assertFalse(m.containers);self.assertFalse(m.volumes)
  labels=[x[0]for x in m.events];self.assertLess(labels.index('create_consumer'),labels.index('start_init'));self.assertLess(labels.index('create_init'),labels.index('start_init'));self.assertLess(labels.index('preentry'),labels.index('actor_first_write'))
  self.assertTrue(m.events[labels.index('preentry')][1]['work_root']['empty']);self.assertEqual(m.actor_calls,1)
  for name,raw in m.original_json.items():self.assertEqual((m.work/'output'/name).read_bytes(),raw)
  receipt=json.loads((m.output/'exported/work-preentry-v5.json').read_bytes());self.assertEqual(receipt['phase'],'OBSERVED_BEFORE_ANY_WORK_WRITE');self.assertEqual(receipt['runtime_observation'],pin(m.original_json['runtime-observation.json']));self.assertEqual(receipt['actor_result'],pin(m.original_json['actor-result.json']))
  start=next(row for row in report['operations']if row['argv'][-1]==report['planned']['actor']and 'start'in row['argv']);self.assertEqual((m.output/start['log']).read_bytes(),b'')
 def test_two_raw_cap_spellings_same_semantics(self):
  for i,caps in enumerate([['CHOWN'],['CAP_CHOWN']]):
   root=self.root/str(i);root.mkdir();m=Model(root,caps=caps);self.assertEqual(m.invoke()[0],0)
 def test_duplicate_extra_other_capability_never_starts_actor(self):
  for i,caps in enumerate([[],['CAP_SYS_ADMIN'],['CHOWN','CAP_CHOWN'],['CAP_CHOWN','CAP_CHOWN'],['CAP_CHOWN','CAP_FOWNER']]):
   root=self.root/str(i);root.mkdir();m=Model(root,caps=caps);self.assertEqual(m.invoke()[0],2);self.assertEqual(m.actor_calls,0)
 def test_missing_nocopy_is_refused(self):
  m=Model(self.root,drop_nocopy=True);self.assertEqual(m.invoke()[0],2);self.assertEqual(m.actor_calls,0)
 def test_preentry_unsafe_mode_or_nonempty_refuses_before_writes(self):
  for i,opts in enumerate([dict(mode=0o777),dict(nonempty=True)]):
   root=self.root/str(i);root.mkdir();m=Model(root,**opts);self.assertEqual(m.invoke()[0],2);self.assertEqual(m.actor_calls,0);self.assertFalse((m.work/'output').exists())
 def test_private0700_work_mode_also_passes(self):
  m=Model(self.root,mode=0o700);self.assertEqual(m.invoke()[0],0)
 def test_foreign_cleanup_label_cannot_authorize_removal(self):
  m=Model(self.root,foreign_cleanup=True);code,report=m.invoke();self.assertEqual(code,2);self.assertTrue(m.containers);self.assertTrue(any('error'in row for row in report['cleanup']))
 def test_wrong_post_chown_owner_refuses_before_any_actor_write(self):
  m=Model(self.root,owner_after_init=0);self.assertEqual(m.invoke()[0],2);self.assertEqual(m.actor_calls,0);self.assertFalse((m.work/'output').exists())
 def test_existing_versioned_receipt_is_never_overwritten(self):
  m=Model(self.root);original=m.ns['actor']
  def actor(sha):
   code=original(sha);(m.work/'output/work-preentry-v5.json').write_bytes(b'EXISTING_FENCED_DATA');return code
  m.ns['actor']=actor;self.assertEqual(m.invoke()[0],2);self.assertEqual((m.work/'output/work-preentry-v5.json').read_bytes(),b'EXISTING_FENCED_DATA')
 def test_versioned_receipt_tamper_refuses_export_join(self):
  m=Model(self.root);self.assertEqual(m.invoke()[0],0);exported={p.name:(p.read_bytes(),stat.S_IMODE(p.stat().st_mode))for p in(m.work/'output').iterdir()}
  for key in('operation_sha256','runtime_observation','actor_result'):
   bad=copy.deepcopy(exported);receipt=json.loads(bad['work-preentry-v5.json'][0]);receipt[key]='WRONG';bad['work-preentry-v5.json']=(encode(receipt),0o600)
   with self.subTest(key=key),self.assertRaises(ValueError):m.ns['export_join'](bad)
if __name__=='__main__':unittest.main(verbosity=2)
