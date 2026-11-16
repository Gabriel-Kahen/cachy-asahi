"""Fenced local-FD and maintained-driver MODEL controls; no actor/network."""
import copy, hashlib, importlib.util, json, os, sys, tempfile, time, unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=module('v15_producer',HERE/'payload/hosted/producer.py');Q=module('v15_qualifier',HERE/'payload/hosted/qualification.py');D=P.workspace_module()
OLD=module('v15_previous_runtime',HERE.parent/'successor_v14/test_runtime.py')
M=OLD.M;SOURCE=OLD.SOURCE;IMAGE=OLD.IMAGE;INFO=OLD.INFO

def fence(event,args):
 if event.startswith(('subprocess.','socket.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','resource.setrlimit','fcntl.flock','os.chown'):raise AssertionError('FENCED no actors/ownership mutation '+event)
sys.addaudithook(fence)

# Actual local FD operations run as gabe1000. Only the MODEL identity projection
# changes1000 -> admitted runner1001; no process/user/permission actor is launched.
REAL_NODE=D.node

def domain():
 from contextlib import ExitStack
 stack=ExitStack();stack.enter_context(patch.object(D,'node',side_effect=model_node))
 for k in('getuid','geteuid','getgid','getegid'):stack.enter_context(patch.object(D.os,k,return_value=1001))
 # model_node must compare actual process owner, not the patched accessors.
 return stack
ACTUAL_UID=os.getuid();ACTUAL_GID=os.getgid()
def model_node(s):
 v=REAL_NODE(s)
 if v['uid']==ACTUAL_UID:v['uid']=1001
 if v['gid']==ACTUAL_GID:v['gid']=1001
 return v

def source_token():return P.V.binding(SOURCE,IMAGE,'1'*64)['token']
def name():return 'rust199-'+source_token()+'-work'
def lease(work,root):return D.Lease(work,name(),P.encode(INFO),P.labels(SOURCE,source_token(),'volume'),root)

class Daemon:
 def __init__(self):self.events=[];self.rows=[];self.actors={};self.deadline=time.monotonic()+2000;self.cleaning=False;self.cancelled=[False];self.on_tick=None
 def __call__(self,argv,timeout=60,check=True):
  assert argv[:2]==P.DOCKER;args=argv[2:];self.events.append(args);self.rows.append(dict(argv=argv));answer=lambda raw=b'':SimpleNamespace(stdout=raw,stderr=b'',returncode=0)
  if args[0]=='info':assert args==['info','--format',P.DAEMON_BIND_INFO_FORMAT];return answer(P.encode(INFO))
  if args[:2]==['container','ls']:return answer(('\n'.join(self.actors)+'\n'if self.actors else'').encode())
  if args[:2]==['volume','ls']:return answer()
  if args[:2]==['image','inspect']:return answer(P.encode([dict(Id=IMAGE,Os='linux',Architecture='arm64',Config={})]))
  if args[0]=='create':
   row=OLD.inspect_from_argv(argv);isinit='-c'in row['Config']['Cmd']
   if isinit:
    row['Config'].update(WorkingDir='/',Hostname='rust199-native');row['HostConfig'].update(Memory=128*1024**2,MemorySwap=128*1024**2,PidsLimit=32,Tmpfs={})
   row['Config']['Labels']=dict(row['Config']['Labels']);self.actors[row['Name'][1:]]=row;return answer((row['Id']+'\n').encode())
  if args[:2]==['container','inspect']:return answer(P.encode([self.actors[args[-1]]]))
  if args[0]=='start':
   row=self.actors[args[-1]]
   if '-c'not in row['Config']['Cmd']:raise ValueError('MODEL_CAP0_KERNEL_BOUNDARY')
   owner=json.loads(row['Config']['Cmd'][-1]);row['State']['Status']='exited';src=next(x['Source']for x in row['Mounts']if x['Destination']=='/work');node=model_node(Path(src).stat());assert not list(Path(src).iterdir())
   return answer(P.encode(dict(schema=1,status='INITIALIZED_EMPTY_WORK_VOLUME',binding=owner,before=node,after=node,limits=P.V.LIMITS,capabilities='NO_CAPS_NO_MUTATION_OWNED_DIRECTORY',recursive=False)))
  if args[:2]==['container','rm']:
   key=next(n for n,row in self.actors.items()if row['Id']==args[-1]);del self.actors[key];return answer()
  raise AssertionError('Unknown MODEL command '+repr(args))

class Runtime(unittest.TestCase):
 def roots(self,tmp):
  root=Path(tmp)/'source';work=Path(tmp)/'rust199-hosted';root.mkdir();work.mkdir(mode=0o700);return root,work
 def test_real_fd_create_empty_and_retire_owned_files_and_leaf_symlink_without_target(self):
  with tempfile.TemporaryDirectory()as tmp,domain():
   root,work=self.roots(tmp);outside=root/'foreign';outside.write_text('unchanged');l=lease(work,root)
   try:
    proof=l.bind_source(SOURCE);self.assertEqual(D.validate(proof,name(),proof['labels']),proof);child=l.path/'build';child.mkdir();(child/'one').write_text('data');(child/'alias').symlink_to(outside);l.check();r=l.retire(lambda:None);self.assertEqual(r['status'],'RETIRED_ABSENT');self.assertEqual(r['nodes'],3);self.assertFalse(l.path.exists());self.assertEqual(outside.read_text(),'unchanged')
   finally:l.close()
 def test_replaced_inode_and_ancestor_symlink_refuse_without_foreign_cleanup(self):
  with tempfile.TemporaryDirectory()as tmp,domain():
   root,work=self.roots(tmp);l=lease(work,root)
   try:
    moved=work/(name()+'-moved');l.path.rename(moved);l.path.mkdir(mode=0o700)
    with self.assertRaises(ValueError):l.check()
    self.assertTrue(moved.is_dir());l.path.rmdir();moved.rename(l.path)
    saved=work.with_name('saved');work.rename(saved);work.symlink_to(saved,target_is_directory=True)
    with self.assertRaises(OSError):l.check()
    work.unlink();saved.rename(work);l.retire(lambda:None)
   finally:l.close()
 def test_foreign_mount_special_and_cleanup_deadline_refuse_before_any_deletion(self):
  with tempfile.TemporaryDirectory()as tmp,domain():
   root,work=self.roots(tmp);l=lease(work,root)
   try:
    (l.path/'keep').write_text('keep');os.mkfifo(l.path/'special')
    with self.assertRaises(ValueError):l.retire(lambda:None)
    self.assertTrue((l.path/'keep').exists());(l.path/'special').unlink()
    real=D.mount_id
    with patch.object(D,'mount_id',side_effect=lambda fd:real(fd)+1 if os.fstat(fd).st_ino==(l.path/'keep').stat().st_ino else real(fd)):
     with self.assertRaises(ValueError):l.retire(lambda:None)
    with self.assertRaisesRegex(ValueError,'MODEL deadline'):l.retire(lambda:(_ for _ in()).throw(ValueError('MODEL deadline')))
    self.assertTrue((l.path/'keep').exists());l.retire(lambda:None)
   finally:l.close()
 def test_source_token_proof_tamper_and_daemon_root_negative(self):
  with tempfile.TemporaryDirectory()as tmp,domain():
   root,work=self.roots(tmp);l=lease(work,root)
   try:
    proof=l.bind_source(SOURCE)
    for k,v in(('work_source','/foreign'),('stage0_source','/foreign'),('workspace_mount_id',True),('nonce','x'),('job_root_node',{}),('labels',{}),('schema',True)):
     bad=copy.deepcopy(proof);bad[k]=v
     with self.subTest(k=k),self.assertRaises((ValueError,KeyError)):D.validate(bad,name(),proof['labels'])
    l.retire(lambda:None)
   finally:l.close()
   info=dict(INFO,DockerRootDir=str(work.parent))
   with self.assertRaises(ValueError):D.Lease(work,name(),P.encode(info),P.labels(SOURCE,source_token(),'volume'),root)
   self.assertFalse((work/name()).exists())
 def test_actual355_daemon_root_failure_is_retained_and_never_relaxes_private(self):
  v=json.loads((HERE/'fixtures/public-failure.ACTUAL355.json').read_bytes());self.assertEqual(v['run'],43959643188);self.assertEqual(v['kernel_mount_proof'],'NOT_STARTED');self.assertIn('must use either propagation mode',v['stderr']);self.assertEqual(v['stderr_pin'],dict(bytes=len(v['stderr'].encode()),sha256=hashlib.sha256(v['stderr'].encode()).hexdigest()))
  outcome=unittest.TestResult();OLD.Runtime('test_curated_actual_master_still_refuses_unchanged_kernel_helper').run(outcome);self.assertTrue(outcome.wasSuccessful(),outcome.errors+outcome.failures)
  ctx=dict(source=SOURCE,dispatch_sha256='1'*64,input_admission_sha256='2'*64,image_id=IMAGE,volume_token=source_token(),phase='qualification-data');raw=b'1 9 0:1 / / ro - overlay overlay rw\n2 1 8:1 /MODEL/work /work rw master:1 - ext4 /dev/MODEL rw\n'
  with self.assertRaisesRegex(ValueError,'private selected mount propagation'):M.verify(raw,ctx,'kernel-mountinfo-qualification-data.raw','3'*64)
 def test_generators_inspect_both_phase_aliases_and_initializer_caps0(self):
  volume=name();path=Path('/MODEL/rust199-hosted')/volume;materials={str(i)+'.xz':Path('/MODEL/materials')/(str(i)+'.xz')for i in range(5)};env={k:'1'*64 for k in('ROOT_ADMISSION_SHA256','SOURCE_MAP_SHA256','CONTRACT_SHA256','WORK_VOLUME_ADMISSION_SHA256')}
  for phase in('prepare','makepkg'):
   rows=P.mount_specs(volume,Path('/MODEL/inputs'),Path('/MODEL/source'),materials,phase,path);argv=P.actor_options('MODEL',volume,IMAGE,Path('/MODEL/inputs'),Path('/MODEL/source'),materials,phase,env,{},path);actual=OLD.inspect_from_argv(argv);P.inspect_mounts(actual,rows,volume,path)
   self.assertTrue(all(r['Type']=='bind'and r['BindOptions']==dict(Propagation='rprivate')for r in rows))
   if phase=='makepkg':self.assertEqual([(r['Target'],r['Source'],r['ReadOnly'])for r in rows if r['Target']in('/stage0','/work/build/stage0')],[('/stage0',str(path/'build/stage0'),True),('/work/build/stage0',str(path/'build/stage0'),True)])
   for badkind in('slave','writable','shadow','source'):
    bad=copy.deepcopy(actual)
    if badkind=='slave':bad['Mounts'][0]['Propagation']='rslave'
    if badkind=='writable':bad['Mounts'][-1]['RW']=True
    if badkind=='shadow':bad['Mounts'].append(dict(bad['Mounts'][0],Destination='/work/foreign'))
    if badkind=='source':bad['Mounts'][0]['Source']='/foreign'
    with self.subTest(phase=phase,bad=badkind),self.assertRaises(ValueError):P.inspect_mounts(bad,rows,volume,path)
  owner=P.V.binding(SOURCE,IMAGE,'2'*64);argv=P.init_options(owner['init'],volume,IMAGE,{},owner,path)
  self.assertIn('--user=1001:1001',argv);self.assertIn('--cap-drop=ALL',argv);self.assertFalse(any(x.startswith('--cap-add')for x in argv));self.assertIn('--workdir=/',argv);self.assertNotIn('os.fchown',P.V.INIT_CODE);self.assertNotIn('os.fchmod',P.V.INIT_CODE)
  node=dict(device=1,inode=2,uid=1001,gid=1001,mode=0o700);receipt=dict(schema=1,status='INITIALIZED_EMPTY_WORK_VOLUME',binding=owner,before=node,after=node,limits=P.V.LIMITS,capabilities='NO_CAPS_NO_MUTATION_OWNED_DIRECTORY',recursive=False);P.V.verify_receipt(receipt,owner)
  bad=copy.deepcopy(receipt);bad['before']['uid']=0
  with self.assertRaises(ValueError):P.V.verify_receipt(bad,owner)
 def test_both_maintained_drivers_allocate_external_then_retire_after_actor_cids(self):
  for role in('qualification','producer'):
   with self.subTest(role=role),tempfile.TemporaryDirectory()as tmp,domain():
    root,work=self.roots(tmp);(root/'source-map.json').write_bytes(b'MODEL Source map');(work/'daemon.json').write_bytes(P.encode(dict(info=INFO)));source=dict(SOURCE,map_sha256=P.pin(root/'source-map.json',1024)['sha256']);provider=dict(source=source,dispatch_sha256='3'*64);daemon=Daemon();ma=[]
    for i in range(5):
     p=work/(str(i)+'.xz');p.write_bytes(b'MODEL material');ma.append(dict(name=p.name,local_path=str(p),transport='LOCAL_READONLY',**P.pin(p,1024)))
    with patch.object(P,'workspace_module',return_value=D):
     if role=='qualification':
      audit=work/'audit.json';audit.write_bytes(P.encode(dict(MODEL_ONLY=True)));plan=dict(reviews={k:True for k in('stage0','source','llvm_material')},source_audit=json.loads(audit.read_bytes()),holds_preserved=True);delivered=dict(materials=ma,files=dict(source_audit=dict(local_path=str(audit))))
      with patch.object(Q,'load',return_value=P):
       with self.assertRaisesRegex(ValueError,'MODEL_CAP0_KERNEL_BOUNDARY'):Q.run(root,work,provider,plan,delivered,dict(image=IMAGE,rootfs_tree_sha256='4'*64),daemon)
      report=json.loads((work/'qualification/controller.json').read_bytes())
     else:
      env={k:'5'*64 for k in('ROOT_ADMISSION_SHA256','SOURCE_MAP_SHA256','CONTRACT_SHA256')};real=Path.read_text
      with patch.object(P,'snapshot',return_value=env),patch.object(P.os,'statvfs',return_value=SimpleNamespace(f_bavail=16*1024**3,f_frsize=1,f_favail=200000)),patch.object(Path,'read_text',lambda p,*a,**k:'MemAvailable: 16777216 kB\n'if str(p)=='/proc/meminfo'else real(p,*a,**k)):
       report=P.run(root,work,dict(source=source,image=dict(id=IMAGE),materials=ma),daemon)
    self.assertTrue(report['owned_resources_absent'],report);self.assertFalse(daemon.actors);self.assertEqual([x['status']for x in report['workspace_lifecycle']],['CREATED_HELD','RETIRED_ABSENT']);self.assertLess(report['workspace_lifecycle'][0]['after_operation_count'],report['workspace_lifecycle'][1]['after_operation_count']);self.assertFalse(any(x[:2]in(['volume','create'],['volume','inspect'],['volume','rm'])for x in daemon.events));proof=report['owned_work_bind'];D.validate(proof,report['volume'],proof['labels']);self.assertFalse(Path(proof['work_source']).exists());self.assertEqual(report['initialization'if role=='qualification'else'volume_initialization']['before'],proof['workspace_node'])

if __name__=='__main__':unittest.main(verbosity=2)
