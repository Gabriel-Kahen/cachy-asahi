"""Fenced actual generator/driver MODEL controls; no Docker/process/kernel actor."""
import copy,hashlib,importlib.util,json,os,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
T=module('v14_runtime_support',HERE.parent/'successor_v12/test_runtime.py')
P=T.load('v14_producer',HERE/'payload/hosted/producer.py');Q=module('v14_qualifier',HERE/'payload/hosted/qualification.py');M=module('v14_UNCHANGED_kernel',HERE.parent/'successor_v13/payload/actor/mount_proof.py')
def fence(event,args):
 if event.startswith(('subprocess.','socket.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','resource.setrlimit','fcntl.flock'):raise AssertionError('FENCED no actors '+event)
sys.addaudithook(fence)
INFO=dict(ID='MODEL-daemon',DockerRootDir='/MODEL/docker',OSType='linux',Architecture='aarch64',CgroupVersion='2',SecurityOptions=['name=seccomp,profile=builtin'],OperatingSystem='Ubuntu 24.04.5 LTS')
SOURCE=dict(sha='a'*40,ref='refs/heads/codex/MODEL',map_sha256='b'*64,approval='c'*64,run='123',job='456');IMAGE='sha256:'+'d'*64
VOLUME='rust199-'+'e'*24+'-work';LABELS=P.labels(SOURCE,'e'*24,'volume')
def volume(name=VOLUME,labels=LABELS):return dict(Name=name,Driver='local',Scope='local',Options=None,Labels=labels,Mountpoint='/MODEL/docker/volumes/'+name+'/_data')
def proof(info=None,row=None):return P.owned_work_bind(P.encode(INFO if info is None else info),P.encode([volume()if row is None else row]),VOLUME,LABELS)
def materials(root=Path('/MODEL/materials')):return{str(i)+'.xz':root/(str(i)+'.xz')for i in range(5)}

def inspect_from_argv(argv):
 mounts=[]
 for i,x in enumerate(argv):
  if x!='--mount':continue
  fields=dict((v.split('=',1)if'='in v else(v,True))for v in argv[i+1].split(','));mounts.append(dict(Type=fields['type'],Source=fields['src'],Target=fields['dst'],ReadOnly=bool(fields.get('readonly',False)),BindOptions=dict(Propagation=fields['bind-propagation'])))
 env=[argv[i+1]for i,x in enumerate(argv)if x=='--env'];image=argv.index(IMAGE);labels=dict(argv[i+1].split('=',1)for i,x in enumerate(argv)if x=='--label');name=argv[argv.index('--name')+1];init='--user=0:0'in argv
 return dict(Id=hashlib.sha256(name.encode()).hexdigest(),Name='/'+name,Image=IMAGE,Config=dict(User='0:0'if init else'1001:1001',Labels=labels,Hostname='rust199-qualification'if'--hostname=rust199-qualification'in argv else'rust199-native',WorkingDir='/'if init else'/work',Entrypoint=['/usr/bin/python'],Cmd=argv[image+1:],Env=env),HostConfig=dict(ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=['CHOWN']if init else None,SecurityOpt=['no-new-privileges'],Privileged=False,Devices=[],DeviceRequests=None,Binds=None,VolumesFrom=None,Links=None,ExtraHosts=None,UsernsMode='',PidMode='',IpcMode='private',CgroupnsMode='private',Memory=128*1024**2 if init else 8*1024**3,MemorySwap=128*1024**2 if init else 8*1024**3,NanoCpus=2000000000,PidsLimit=32 if init else 512,Init=True,Ulimits=[dict(Name='nofile',Soft=1024,Hard=1024),dict(Name='core',Soft=0,Hard=0)],RestartPolicy=dict(Name='no'),LogConfig=dict(Type='none',Config={}),Tmpfs={}if init else{'/tmp':'rw,noexec,nosuid,nodev,size=64m,uid=1001,gid=1001','/run':'rw,noexec,nosuid,nodev,size=8m,uid=1001,gid=1001'},Mounts=mounts),Mounts=[dict(Type='bind',Source=m['Source'],Destination=m['Target'],RW=not m['ReadOnly'],Propagation='rprivate')for m in mounts],State=dict(Status='created',Running=False,Restarting=False,ExitCode=0,OOMKilled=False,Error=''))

class Daemon:
 def __init__(self):self.events=[];self.vol=None;self.actors={};self.deadline=time.monotonic()+2000;self.cleaning=False;self.cancelled=[False];self.on_tick=None
 def __call__(self,argv,timeout=60,check=True):
  assert argv[:2]==P.DOCKER;args=argv[2:];self.events.append(args);answer=lambda raw=b'':SimpleNamespace(stdout=raw,stderr=b'',returncode=0)
  if args[0]=='info':assert args==['info','--format',P.DAEMON_BIND_INFO_FORMAT];return answer(P.encode(INFO))
  if args[:2]==['container','ls']:return answer(('\n'.join(self.actors)+'\n'if self.actors else'').encode())
  if args[:2]==['volume','ls']:return answer((self.vol['Name']+'\n').encode()if self.vol else b'')
  if args[:2]==['image','inspect']:return answer(P.encode([dict(Id=IMAGE,Os='linux',Architecture='arm64',Config={})]))
  if args[:2]==['volume','create']:
   labels=dict(args[i+1].split('=',1)for i,x in enumerate(args)if x=='--label');self.vol=volume(args[-1],labels);return answer((args[-1]+'\n').encode())
  if args[:2]==['volume','inspect']:return answer(P.encode([self.vol]))
  if args[0]=='create':
   row=inspect_from_argv(argv);name=row['Name'][1:];assert name not in self.actors;self.actors[name]=row;return answer((row['Id']+'\n').encode())
  if args[:2]==['container','inspect']:return answer(P.encode([self.actors[args[-1]]]))
  if args[0]=='start':
   row=self.actors[args[-1]]
   if row['Config']['User']!='0:0':raise ValueError('MODEL_CAP0_KERNEL_BOUNDARY')
   owner=json.loads(row['Config']['Cmd'][-1]);row['State']['Status']='exited';before=dict(device=1,inode=2,uid=0,gid=0,mode=0o755);after=dict(device=1,inode=2,uid=1001,gid=1001,mode=0o700)
   return answer(P.encode(dict(schema=1,status='INITIALIZED_EMPTY_WORK_VOLUME',binding=owner,before=before,after=after,limits=P.V.LIMITS,capabilities='CHOWN_ONLY_CHMOD_BEFORE_CHOWN',recursive=False)))
  if args[:2]==['container','rm']:
   name=next(n for n,row in self.actors.items()if row['Id']==args[-1]);assert len(args)==3;del self.actors[name];return answer()
  if args[:2]==['volume','rm']:assert not self.actors;self.vol=None;return answer()
  raise AssertionError('Unknown MODEL command '+repr(args))

class Runtime(unittest.TestCase):
 def test_owned_chain_projection_and_raw_whole_pins_replay(self):
  p=proof();self.assertEqual(p['stage0_source'],p['work_source']+'/build/stage0');self.assertEqual(P.replay_work_bind(p,VOLUME,LABELS),p);self.assertFalse(p['native_acceptance']);self.assertNotIn('HTTPProxy',p['daemon_inspect']['json']);self.assertNotIn('RegistryConfig',P.DAEMON_BIND_INFO_FORMAT)
  for key in('work_source','daemon_root','labels','daemon_inspect','volume_inspect'):
   bad=copy.deepcopy(p);bad[key]={}if type(bad[key])is dict else'/foreign'
   with self.subTest(key=key),self.assertRaises((ValueError,KeyError)):P.replay_work_bind(bad,VOLUME,LABELS)
 def test_remote_rootless_desktop_and_wrong_platform_refuse(self):
  with self.assertRaises(ValueError):P.owned_work_bind(P.encode(INFO),P.encode([volume()]),VOLUME,LABELS,'tcp://MODEL:2375')
  for k,v in(('SecurityOptions',['name=rootless']),('OperatingSystem','Docker Desktop'),('OSType','windows'),('Architecture','amd64'),('CgroupVersion','1'),('HTTPProxy','never-retain')):
   info=dict(INFO);info[k]=v
   with self.subTest(k=k),self.assertRaises(ValueError):proof(info=info)
 def test_unowned_remote_driver_options_malformed_and_foreign_mountpoints_refuse(self):
  for k,v in(('Name','foreign'),('Driver','nfs'),('Scope','global'),('Options',{'device':'/foreign'}),('Labels',{}),('Mountpoint','/MODEL/foreign'),('Mountpoint','/MODEL/docker/volumes/'+VOLUME+'/../_data'),('Mountpoint','/MODEL//docker/volumes/'+VOLUME+'/_data'),('Mountpoint','/OTHER/docker/volumes/'+VOLUME+'/_data')):
   row=volume();row[k]=v
   with self.subTest(k=k,v=v),self.assertRaises(ValueError):proof(row=row)
 def test_actual_generators_make_only_explicit_private_binds_with_exact_ro_aliases(self):
  path=Path(proof()['work_source']);env={k:'1'*64 for k in('ROOT_ADMISSION_SHA256','SOURCE_MAP_SHA256','CONTRACT_SHA256','WORK_VOLUME_ADMISSION_SHA256')}
  for phase in('prepare','makepkg'):
   rows=P.mount_specs(VOLUME,Path('/MODEL/inputs'),Path('/MODEL/source'),materials(),phase,path);self.assertTrue(all(r['Type']=='bind'and r['BindOptions']==dict(Propagation='rprivate')for r in rows));argv=P.actor_options('MODEL',VOLUME,IMAGE,Path('/MODEL/inputs'),Path('/MODEL/source'),materials(),phase,env,{},path);actual=inspect_from_argv(argv);P.inspect_mounts(actual,rows,VOLUME,path);self.assertIn('--cap-drop=ALL',argv);self.assertNotIn('--privileged',argv)
   if phase=='makepkg':self.assertTrue(all(r['ReadOnly']and r['Source']==str(path/'build/stage0')for r in rows if r['Target']in('/stage0','/work/build/stage0')))
   for role in('data','probe'):
    qargv=Q.options(P,'MODEL',VOLUME,IMAGE,Path('/MODEL/inputs'),Path('/MODEL/source'),materials(),role,'2'*64,{},path);self.assertTrue(all('bind-propagation=rprivate'in qargv[i+1]for i,x in enumerate(qargv)if x=='--mount'))
 def test_actual_inspector_refuses_slave_missing_private_shadow_and_writable_alias(self):
  path=Path(proof()['work_source']);rows=P.mount_specs(VOLUME,Path('/MODEL/inputs'),Path('/MODEL/source'),materials(),'makepkg',path);base=dict(HostConfig=dict(Mounts=copy.deepcopy(rows)),Mounts=[dict(Type='bind',Source=r['Source'],Destination=r['Target'],RW=not r['ReadOnly'],Propagation='rprivate')for r in rows]);P.inspect_mounts(base,rows,VOLUME,path)
  for edit in('slave','missing','rw','source','options','volume','extra'):
   bad=copy.deepcopy(base)
   if edit=='slave':bad['Mounts'][0]['Propagation']='rslave'
   if edit=='missing':bad['Mounts'][0].pop('Propagation')
   if edit=='rw':bad['Mounts'][-1]['RW']=True
   if edit=='source':bad['Mounts'][-1]['Source']=str(path)
   if edit=='options':bad['HostConfig']['Mounts'][0]['BindOptions']['Propagation']='rslave'
   if edit=='volume':bad['HostConfig']['Mounts'][0]['Type']='volume'
   if edit=='extra':bad['Mounts'].append(dict(bad['Mounts'][0],Destination='/work/foreign'))
   with self.subTest(edit=edit),self.assertRaises(ValueError):P.inspect_mounts(bad,rows,VOLUME,path)
 def test_curated_actual_master_still_refuses_unchanged_kernel_helper(self):
  raw=(HERE/'fixtures/mountinfo-data.ACTUAL.raw').read_bytes();self.assertEqual(len(raw),5794);self.assertEqual(hashlib.sha256(raw).hexdigest(),'c52d3185956b93870365913050bac4ebd012c3db08b5b803095822888db13460');f=json.loads((HERE/'fixtures/public-failure.ACTUAL-r2.json').read_bytes());ctx=dict(source=f['provider']['source'],dispatch_sha256=f['provider']['dispatch_sha256'],input_admission_sha256='1'*64,image_id=f['image'],volume_token=f['initialization']['binding']['token'],phase='qualification-data')
  with self.assertRaisesRegex(ValueError,'private selected mount propagation'):M.verify(raw,ctx,'kernel-mountinfo-qualification-data.raw','2'*64)
 def test_private_MODEL_kernel_work_and_same_subroot_aliases_pass_without_waiver(self):
  ctx=dict(source=SOURCE,dispatch_sha256='1'*64,input_admission_sha256='2'*64,image_id=IMAGE,volume_token='e'*24,phase='qualification-probe');path=proof()['work_source'];data=('1 9 0:1 / / ro - overlay overlay rw\n2 1 8:1 '+path+' /work rw - ext4 /dev/MODEL rw\n3 1 8:1 '+path+'/build/stage0 /stage0 ro - ext4 /dev/MODEL rw\n4 2 8:1 '+path+'/build/stage0 /work/build/stage0 ro - ext4 /dev/MODEL rw\n').encode();row=M.verify(data,ctx,'kernel-mountinfo-qualification-probe.raw','3'*64);self.assertFalse(row['native_acceptance']);self.assertEqual(row['alias_root'],path+'/build/stage0')
  with self.assertRaisesRegex(ValueError,'private selected mount propagation'):M.verify(data.replace(b'/work rw -',b'/work rw master:1 -'),ctx,'kernel-mountinfo-qualification-probe.raw','3'*64)
 def test_maintained_qualification_and_producer_drivers_use_inspected_chain_before_cap0(self):
  for role in('qualification','producer'):
   with self.subTest(role=role),tempfile.TemporaryDirectory()as tmp:
    root=Path(tmp)/'source';work=Path(tmp)/'work';root.mkdir();work.mkdir();(root/'source-map.json').write_bytes(b'MODEL Source map');(work/'daemon.json').write_bytes(P.encode(dict(info=INFO)));source=dict(SOURCE,map_sha256=P.pin(root/'source-map.json',1024)['sha256']);provider=dict(source=source,dispatch_sha256='3'*64);daemon=Daemon();ma=[]
    for i in range(5):
     p=work/(str(i)+'.xz');p.write_bytes(b'MODEL material');ma.append(dict(name=p.name,local_path=str(p),transport='LOCAL_READONLY',**P.pin(p,1024)))
    if role=='qualification':
     audit=work/'audit.json';audit.write_bytes(P.encode(dict(MODEL_ONLY=True)));plan=dict(reviews={k:True for k in('stage0','source','llvm_material')},source_audit=json.loads(audit.read_bytes()),holds_preserved=True);delivered=dict(materials=ma,files=dict(source_audit=dict(local_path=str(audit))))
     with patch.object(Q,'load',return_value=P):
      with self.assertRaisesRegex(ValueError,'MODEL_CAP0_KERNEL_BOUNDARY'):Q.run(root,work,provider,plan,delivered,dict(image=IMAGE,rootfs_tree_sha256='4'*64),daemon)
     report=json.loads((work/'qualification/controller.json').read_bytes())
    else:
     env={k:'5'*64 for k in('ROOT_ADMISSION_SHA256','SOURCE_MAP_SHA256','CONTRACT_SHA256')};real=Path.read_text
     with patch.object(P,'snapshot',return_value=env),patch.object(P.os,'statvfs',return_value=SimpleNamespace(f_bavail=16*1024**3,f_frsize=1,f_favail=200000)),patch.object(Path,'read_text',lambda p,*a,**k:'MemAvailable: 16777216 kB\n'if str(p)=='/proc/meminfo'else real(p,*a,**k)):
      report=P.run(root,work,dict(source=source,image=dict(id=IMAGE),materials=ma),daemon)
     self.assertNotEqual(report['status'],'COMPLETED_EXPORTED_RETIRED')
    P.replay_work_bind(report['owned_work_bind'],report['volume'],report['owned_work_bind']['labels']);self.assertTrue(report['owned_resources_absent']);self.assertFalse(daemon.actors);self.assertIsNone(daemon.vol);self.assertTrue(any(x[0]=='start'for x in daemon.events));self.assertTrue(any(x[0]=='info'and x[-1]==P.DAEMON_BIND_INFO_FORMAT for x in daemon.events))

if __name__=='__main__':unittest.main(verbosity=2)
