# SPDX-License-Identifier: MIT
"""Independent synthetic DATA joins; never invokes operational main or replay."""
import argparse,ast,contextlib,copy,ctypes,fcntl,hashlib,importlib.util,json,os,socket,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('independent_v2',HERE/'reader.py');r=importlib.util.module_from_spec(s);s.loader.exec_module(r)
SOURCE=PARENT=None

def life():return dict(natural_exit=True,group_absent=True,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,retirement='REAPED',ownership_lost=False,forced_cleanup=False,exit=0,elapsed_seconds=0.1)
def store(root,name,value):
 p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(r.canonical(value))
def statrow(uid,gid,mode):return dict(device=9,inode=100,uid=uid,gid=gid,mode=mode)

def fixture(root):
 pins=r.load(HERE/'pins.json');a=dict(source=pins['source'],run='111',job='222',image='sha256:'+'3'*64);owner=r.volume_owner(a);vol=owner['volume'];image=a['image']
 # Parse a pinned literal as DATA. No Source module is imported or executed.
 code=next(n.value.value for n in ast.parse(r.read(SOURCE/'hosted/volume.py')).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name)and t.id=='INIT_CODE'for t in n.targets))
 initialized=dict(schema=1,status='INITIALIZED_EMPTY_WORK_VOLUME',binding=owner,before=statrow(0,0,493),after=statrow(1001,1001,448),limits={'cpu.max':'100000 100000','memory.max':'536870912','memory.swap.max':'0','pids.max':'64'},recursive=False,capabilities='CHOWN_ONLY_CHMOD_BEFORE_CHOWN')
 admission=dict(schema=1,outer_operation=pins['operation'],inner_operation=pins['inner_operation'],binding=owner,expected_owner=dict(uid=1001,gid=1001,mode=448),native_acceptance=False);volume_sha=hashlib.sha256(r.canonical(admission)).hexdigest()
 producer=dict(actor=owner['actor'],init=owner['init'],volume=vol,volume_owner=owner,inner_operation=pins['inner_operation'],volume_initialization=initialized,volume_admission_sha256=volume_sha,admission_sha256='4'*64,inputs_path='/fenced/inputs',source_intake={'root':'/fenced/source'},export={'lifecycle':life()},export_lifecycle=life())
 host=dict(ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=[],SecurityOpt=['no-new-privileges'],Privileged=False,UsernsMode='',Devices=[],DeviceRequests=[],Memory=8*r.GIB,MemorySwap=8*r.GIB,NanoCpus=2*10**9,PidsLimit=512,Init=True,Mounts=[dict(Type='volume',Source=vol,Target='/work',VolumeOptions={'NoCopy':True})])
 actor=dict(Name='/'+owner['actor'],Id='5'*64,Image=image,Config=dict(User='1001:1001',Hostname='llvm23-native',WorkingDir='/work',Entrypoint=['/usr/bin/bash'],Cmd=['--noprofile','--norc','/inputs/actor/entry.sh'],Labels=r.volume_labels(owner,'builder'),Env=['ADMISSION_SHA256='+producer['admission_sha256'],'WORK_VOLUME_ADMISSION_SHA256='+volume_sha]),HostConfig=host,Mounts=[dict(Type='volume',Name=vol,Destination='/work',RW=True),dict(Type='bind',Source='/fenced/inputs',Destination='/inputs',RW=False),dict(Type='bind',Source='/fenced/source',Destination='/source',RW=False)],State=dict(Status='created',Running=False,Pid=0,ExitCode=0,OOMKilled=False))
 done=copy.deepcopy(actor);done['State']['Status']='exited'
 init=dict(Name='/'+owner['init'],Id='6'*64,Image=image,Config=dict(User='0:0',WorkingDir='/',Entrypoint=['/usr/bin/python3'],Cmd=['-I','-B','-c',code,r.canonical(owner).decode()],Labels=r.volume_labels(owner,'initializer')),HostConfig=dict(host,CapAdd=['CHOWN'],Memory=512*r.MIB,MemorySwap=512*r.MIB,NanoCpus=10**9,PidsLimit=64,Init=False),Mounts=[actor['Mounts'][0]],State=dict(Status='created',Running=False,Pid=0,ExitCode=0,OOMKilled=False))
 initdone=copy.deepcopy(init);initdone['State']['Status']='exited'
 values={'volume-before.json':dict(Name=vol,Driver='local',Scope='local',Options=None,Labels=r.volume_labels(owner,'work')),'initializer-before.json':init,'initializer-after.json':initdone,'volume-initialization.json':initialized,'inputs/volume-initialization.json':initialized,'inputs/volume-admission.json':admission,'actor-inspect.json':actor,'actor-finished.json':done}
 for n,v in values.items():store(root,'llvm-build/'+n,v)
 docker=['/usr/bin/docker','--host=unix:///var/run/docker.sock'];rows=[]
 def operation(argv,stdout=b'',stderr=b'',code=0):
  prefix='bootstrap/operations/'+str(len(rows));row=dict(argv=docker+argv,stdout=prefix+'.stdout',stderr=prefix+'.stderr',lifecycle=dict(life(),exit=code),returncode=code)
  for channel,body in [('stdout',stdout),('stderr',stderr)]:
   p=root/row[channel];p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(body);row[channel+'_pin']=r.hashed(p)
  rows.append(row)
 operation(r.builder_command(owner,producer,image,volume_sha)[2:],(actor['Id']+'\n').encode());operation(['inspect',owner['actor']],r.canonical([actor]))
 initargv=['create','--name',owner['init'],*[x for k,v in r.volume_labels(owner,'initializer').items()for x in('--label',k+'='+v)],'--user=0:0','--init=false','--workdir=/','--cpus=1','--memory=512m','--memory-swap=512m','--pids-limit=64','--network=none','--read-only','--cap-drop=ALL','--cap-add=CHOWN','--security-opt=no-new-privileges','--mount','type=volume,src='+vol+',dst=/work,volume-nocopy','--entrypoint=/usr/bin/python3',image,*init['Config']['Cmd']]
 operation(initargv,(init['Id']+'\n').encode());operation(['inspect',owner['init']],r.canonical([init]));operation(['start','--attach',owner['init']],r.canonical(initialized));operation(['inspect',owner['init']],r.canonical([initdone]))
 preentry=dict(status='NONROOT_WORK_VOLUME_VERIFIED',binding=owner,actual=initialized['after'],write_probe=False)
 operation(['start','--attach',owner['actor']],json.dumps(preentry).encode()+b'\nFENCED_ACTOR_OUTPUT_NOT_EXECUTION\n');operation(['inspect',owner['actor']],r.canonical([done]))
 for name in(owner['actor'],owner['init']):operation(['rm','-f',name])
 operation(['volume','rm',vol]);operation(['container','ls','--all','--format','{{.Names}}']);operation(['volume','ls','--quiet']);operation(['image','rm',image]);operation(['image','inspect',image],stderr=('Error response from daemon: No such image: '+image+'\n').encode(),code=1)
 store(root,'bootstrap/operations.json',rows);return producer,a,pins,rows

class VolumeControls(unittest.TestCase):
 def run_fixture(self,mutate=None,retirement=False):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);producer,a,pins,rows=fixture(root)
   if mutate:mutate(root,producer,a,pins,rows)
   r.volume_initialization(root,producer,a,pins)
   if retirement:r.retirement(root,producer,a['image'])
 def test_complete_init_builder_and_retirement_fixture(self):self.run_fixture(retirement=True)
 def test_root_builder_refused(self):
  def mutate(root,*args):
   p=root/'llvm-build/actor-inspect.json';v=r.load(p);v['Config']['User']='0:0';p.write_bytes(r.canonical(v))
  with self.assertRaisesRegex(ValueError,'actor identity'):self.run_fixture(mutate)
 def test_initializer_capability_or_extra_mount_refused(self):
  for mode in('cap','mount','network','limit','user'):
   def mutate(root,*args):
    p=root/'llvm-build/initializer-before.json';v=r.load(p)
    if mode=='cap':v['HostConfig']['CapAdd'].append('FOWNER')
    elif mode=='mount':v['Mounts'].append({'Destination':'/host'})
    elif mode=='network':v['HostConfig']['NetworkMode']='host'
    elif mode=='limit':v['HostConfig']['PidsLimit']=512
    else:v['Config']['User']='1001:1001'
    p.write_bytes(r.canonical(v))
   with self.subTest(mode=mode),self.assertRaises(ValueError):self.run_fixture(mutate)
 def test_wrong_volume_label_token_or_driver_refused(self):
  for mode in('source','token','driver','name'):
   def mutate(root,*args):
    p=root/'llvm-build/volume-before.json';v=r.load(p)
    if mode=='source':v['Labels']['cachy-asahi.llvm-work.source']='0'*40
    elif mode=='token':v['Labels']['cachy-asahi.llvm-work.token']='0'*24
    elif mode=='driver':v['Driver']='nfs'
    else:v['Name']='foreign'
    p.write_bytes(r.canonical(v))
   with self.subTest(mode=mode),self.assertRaises(ValueError):self.run_fixture(mutate)
 def test_builder_or_initializer_copyup_refused(self):
  for name in('actor-inspect.json','initializer-before.json'):
   def mutate(root,*args):
    p=root/'llvm-build'/name;v=r.load(p);v['HostConfig']['Mounts'][0]['VolumeOptions']['NoCopy']=False;p.write_bytes(r.canonical(v))
   with self.subTest(name=name),self.assertRaisesRegex(ValueError,'nocopy'):self.run_fixture(mutate)
 def test_stat_owner_mode_inode_and_receipt_binding_refused(self):
  for key,value in [('uid',0),('gid',0),('mode',493),('inode',999)]:
   def mutate(root,producer,*args):
    producer['volume_initialization']['after'][key]=value
    for name in('volume-initialization.json','inputs/volume-initialization.json'):store(root,'llvm-build/'+name,producer['volume_initialization'])
   with self.subTest(key=key),self.assertRaisesRegex(ValueError,'same initialized'):self.run_fixture(mutate)
 def test_both_created_before_initialization_and_no_repeated_start(self):
  for mode in('order','duplicate'):
   def mutate(root,producer,a,pins,rows):
    if mode=='order':rows[2],rows[4]=rows[4],rows[2]
    else:rows.append(rows[4])
    store(root,'bootstrap/operations.json',rows)
   with self.subTest(mode=mode),self.assertRaises(ValueError):self.run_fixture(mutate)
 def test_missing_or_different_preentry_refused(self):
  def mutate(root,producer,a,pins,rows):
   row=rows[6];(root/row['stdout']).write_bytes(b'FENCED_NO_PREENTRY\n');row['stdout_pin']=r.hashed(root/row['stdout']);store(root,'bootstrap/operations.json',rows)
  with self.assertRaises(ValueError):self.run_fixture(mutate)
 def test_changed_created_ID_refused(self):
  def mutate(root,producer,a,pins,rows):
   row=rows[0];(root/row['stdout']).write_bytes(b'0'*64+b'\n');row['stdout_pin']=r.hashed(root/row['stdout']);store(root,'bootstrap/operations.json',rows)
  with self.assertRaisesRegex(ValueError,'created IDs'):self.run_fixture(mutate)
 def test_forced_init_or_retirement_not_accepted(self):
  def mutate(root,producer,a,pins,rows):rows[4]['lifecycle']['forced_cleanup']=True;store(root,'bootstrap/operations.json',rows)
  with self.assertRaisesRegex(ValueError,'retirement'):self.run_fixture(mutate)
 def test_builder_prestarted_or_still_running_refused(self):
  for name in('actor-inspect.json','actor-finished.json'):
   def mutate(root,*args):
    p=root/'llvm-build'/name;v=r.load(p);v['State']['Running']=True;v['State']['Pid']=123;p.write_bytes(r.canonical(v))
   with self.subTest(name=name),self.assertRaisesRegex(ValueError,'builder remains unstarted'):self.run_fixture(mutate)
 def test_initializer_observed_timeout_refused(self):
  def mutate(root,producer,a,pins,rows):rows[4]['lifecycle']['elapsed_seconds']=121;store(root,'bootstrap/operations.json',rows)
  with self.assertRaisesRegex(ValueError,'120-second'):self.run_fixture(mutate)
 def test_actual_published_source_DATA_full_inverse(self):
  pins=r.load(HERE/'pins.json');found=r.source_namespace(SOURCE,pins);before=r.source_successor(SOURCE,PARENT,pins,found);self.assertEqual(len(found),251);self.assertEqual(len(before),248)
 def test_full_inverse_and_frozen_actor_negative_controls(self):
  pins=r.load(HERE/'pins.json');found=r.source_namespace(SOURCE,pins);meta=r.load(SOURCE/'successor-v2.json');actual=r.load
  for mode in('parent','member','before','frozen','candidate'):
   bad=copy.deepcopy(meta)
   if mode=='parent':bad['parent']['source']='0'*40
   elif mode=='member':bad['changed'].pop('actor/entry.sh')
   elif mode=='before':bad['changed']['actor/entry.sh']['before']['sha256']='0'*64
   elif mode=='frozen':bad['frozen_python'].pop('actor/entry.py')
   else:bad['candidate_unchanged']=False
   with self.subTest(mode=mode),patch.object(r,'load',side_effect=lambda p,*a:bad if p==SOURCE/'successor-v2.json'else actual(p,*a)),self.assertRaises(ValueError):r.source_successor(SOURCE,PARENT,pins,found)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source-root',type=Path,required=True);p.add_argument('--parent-source',type=Path,required=True);a=p.parse_args();SOURCE=a.source_root.resolve();PARENT=a.parent_source.resolve()
 with contextlib.ExitStack()as stack:
  def denied(*a,**k):raise AssertionError('operational Reader forbidden in DATA controls')
  stack.enter_context(patch.object(r,'main',denied));stack.enter_context(patch.object(r,'replay',denied))
  for module,names in((fcntl,('flock',)),(subprocess,('Popen','run','check_output')),(socket,('socket','create_connection')),(ctypes,('CDLL',)),(os,('system','fork','forkpty','posix_spawn','posix_spawnp','execv','execve','execvp','execvpe','pidfd_open'))):
   for name in names:
    if hasattr(module,name):stack.enter_context(patch.object(module,name,side_effect=AssertionError('actor fenced: '+name)))
  result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(VolumeControls));raise SystemExit(not result.wasSuccessful())
