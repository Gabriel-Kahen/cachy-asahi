#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual emitted guards and actor derivation; mocked process/Docker DATA only.

Process tests mock C.selection to isolate process/capability guards. Actor tests
load the held owner module but never call it; every Docker command is synthetic.
No source preflight, helper execution, namespace change or native actor runs.
"""
import ast,contextlib,importlib.util,json,os,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
SOURCE=Path(os.environ['CORE622_EMITTED_SOURCE']).resolve()
PARENT=Path(os.environ['CORE622_B7_SOURCE']).resolve()
CORE=Path(os.environ['CORE622_CORE_SOURCE']).resolve()
sys.path[:0]=[str(SOURCE),str(CORE/'scripts/ci/core-native-lifecycle')]
spec=importlib.util.spec_from_file_location('_emitted_owned_aux',SOURCE/'provision622.py')
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
import controller as CONTROLLER,lane622 as L
FIVE=0x8000001b
SIX=0x8004001b
CAPS={'CHOWN','DAC_OVERRIDE','FOWNER','FSETID','SETFCAP'}
NONCE='c'*32
SELECTED=dict(nonce=NONCE)

@contextlib.contextmanager
def process(mask=FIVE,pid=1,ppid=0,uid=0,euid=0,machine='aarch64',docker=True,net=('lo',),nonce=NONCE,fields=None):
 values=dict(CapEff=hex(mask)[2:],CapPrm=hex(mask)[2:],CapBnd=hex(mask)[2:],CapInh='0',CapAmb='0',NoNewPrivs='1')
 if fields:values.update(fields)
 class Observation:
  def __init__(self,name):self.name=name
  def is_file(self):
   if self.name!='/.dockerenv':raise AssertionError('unexpected process path')
   return docker
  def iterdir(self):
   if self.name!='/sys/class/net':raise AssertionError('unexpected process path')
   return [types.SimpleNamespace(name=n)for n in net]
  def read_text(self):
   if self.name!='/proc/self/status':raise AssertionError('unexpected process path')
   return ''.join(k+':\t'+str(v)+'\n'for k,v in values.items())
 with contextlib.ExitStack()as stack:
  selection=stack.enter_context(patch.object(P.C,'selection',return_value=SELECTED))
  stack.enter_context(patch.object(P,'Path',Observation))
  for name,value in(('getpid',pid),('getppid',ppid),('getuid',uid),('geteuid',euid)):
   stack.enter_context(patch.object(P.os,name,return_value=value))
  stack.enter_context(patch.object(P.os,'uname',return_value=types.SimpleNamespace(machine=machine)))
  stack.enter_context(patch.object(P.os,'environ',dict(CAA_CORE7_PREPARE=nonce)))
  yield selection

class DockerData:
 """Only synthetic command DATA; no Docker executable is ever called."""
 def __init__(self,args,role,readback_caps=None,host_changes=None):
  self.args=args;self.role=role;self.name='caa-core7-vm-'+NONCE+'-'+role;self.exists=False;self.commands=[];self.run=None;self.seconds=None
  expected=CAPS|({'SYS_CHROOT'}if role=='provision607'else set());self.caps=expected if readback_caps is None else readback_caps;self.host_changes=host_changes or {}
 def __call__(self,argv,*options):
  self.commands.append(list(argv));row=dict(argv=list(argv));self.args._owner_report['commands'].append(row)
  if argv[:3]==['/usr/bin/docker','image','inspect']:
   return dict(code=0,err=b'',out=json.dumps([dict(Id=self.args.image,Architecture='arm64',Os='linux',Config=dict(Labels={'org.cachy-asahi.bootstrap574.job':'fixture-token'}))]).encode())
  if argv[:3]==['/usr/bin/docker','container','inspect']:
   if not self.exists:return dict(code=1,out=b'',err=('No such container: '+self.name).encode())
   host=dict(NetworkMode='none',ReadonlyRootfs=True,CapDrop=['ALL'],CapAdd=['CAP_'+n for n in sorted(self.caps)],SecurityOpt=['no-new-privileges']);host.update(self.host_changes)
   value=dict(Name='/'+self.name,Image=self.args.image,Id='d'*64,Config=dict(Labels={'org.cachy-asahi.core7-systemd-vm':NONCE}),HostConfig=host,State=dict(Running=False,Pid=0,ExitCode=0))
   mounts=[];host_mounts=[]
   for index,part in enumerate(self.run):
    if part!='--mount':continue
    bits=self.run[index+1].split(',');fields=dict(bit.split('=',1)for bit in bits if '='in bit);flags=[bit for bit in bits if '='not in bit];assert set(fields)=={'type','src','dst'} and flags in([],['readonly'])
    readonly='readonly'in flags;mounts.append(dict(Type=fields['type'],Source=fields['src'],Destination=fields['dst'],RW=not readonly,Propagation='rprivate'));host_mounts.append(dict(Type=fields['type'],Source=fields['src'],Target=fields['dst'],ReadOnly=readonly))
   host['Mounts']=host_mounts;value['Mounts']=mounts
   return dict(code=0,err=b'',out=json.dumps([value]).encode())
  if argv[:2]==['/usr/bin/docker','run']:
   self.exists=True;self.run=list(argv);self.seconds=options[1];return dict(code=0,out=b'',err=b'')
  if argv[:3]==['/usr/bin/docker','rm','-f']:
   self.exists=False;return dict(code=0,out=b'',err=b'')
  raise AssertionError('unexpected synthetic Docker command')

class ScopedCaps(unittest.TestCase):
 def test_original_pid1_five_cap_role_stays_exact(self):
  with process()as selected:self.assertIs(P.owned(SELECTED),SELECTED);selected.assert_called_once_with(SELECTED)
  with process(mask=SIX),self.assertRaises(ValueError):P.owned(SELECTED)
  with process(pid=2,ppid=1),self.assertRaises(ValueError):P.owned(SELECTED)
 def test_only_explicit_initialization_accepts_exact_six_caps(self):
  with process(mask=SIX):self.assertIs(P.owned(SELECTED,initialization=True),SELECTED)
  for mask in(FIVE,SIX|(1<<21),SIX&~(1<<3)):
   with self.subTest(mask=mask),process(mask=mask),self.assertRaises(ValueError):P.owned(SELECTED,initialization=True)
 def test_worker_must_be_direct_pid1_child_and_initialization_role(self):
  with process(mask=SIX,pid=42,ppid=1):self.assertIs(P.owned(SELECTED,initialization=True,worker=True),SELECTED)
  for kw in(dict(pid=1,ppid=1),dict(pid=42,ppid=2),dict(pid=42,ppid=0)):
   with self.subTest(kw=kw),process(mask=SIX,**kw),self.assertRaises(ValueError):P.owned(SELECTED,initialization=True,worker=True)
  with process(mask=SIX,pid=42,ppid=1),self.assertRaises(ValueError):P.owned(SELECTED,worker=True)
 def test_flags_are_exact_booleans(self):
  for kw in(dict(initialization=1),dict(worker=1),dict(initialization=True,worker=1),dict(initialization=None)):
   with self.subTest(kw=kw),process(mask=SIX),self.assertRaises(ValueError):P.owned(SELECTED,**kw)
 def test_offline_root_arm_container_nonce_and_nnp_guards_remain(self):
  for kw in(dict(uid=1000),dict(euid=1000),dict(machine='x86_64'),dict(docker=False),dict(net=('lo','eth0')),dict(net=()),dict(nonce='d'*32),dict(fields={'NoNewPrivs':'0'})):
   with self.subTest(kw=kw),process(mask=SIX,**kw),self.assertRaises(ValueError):P.owned(SELECTED,initialization=True)
 def test_every_capability_set_is_checked_without_inheritable_or_ambient_caps(self):
  for fields in({'CapEff':hex(FIVE)[2:]},{'CapPrm':hex(FIVE)[2:]},{'CapBnd':hex(FIVE)[2:]},{'CapInh':'1'},{'CapAmb':'1'}):
   with self.subTest(fields=fields),process(mask=SIX,fields=fields),self.assertRaises(ValueError):P.owned(SELECTED,initialization=True)
 def test_source_selection_refusal_precedes_process_guards(self):
  original=ValueError('selection rejected')
  with patch.object(P.C,'selection',side_effect=original),patch.object(P.os,'getpid',side_effect=AssertionError('process guard must not run')),self.assertRaises(ValueError)as found:P.owned({})
  self.assertIs(found.exception,original)
 def test_actual_prepare_retire_and_worker_calls_have_scoped_flags(self):
  functions={n.name:n for n in ast.parse((SOURCE/'provision622.py').read_bytes()).body if isinstance(n,ast.FunctionDef)}
  for name,want in(('prepare',{'initialization':True}),('retire',{}),('initialize_worker',{'initialization':True,'worker':True})):
   call=next(n for n in ast.walk(functions[name])if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='owned')
   self.assertEqual({k.arg:ast.literal_eval(k.value)for k in call.keywords},want)
 def actor(self,role,caps=None,host_changes=None):
  temp=tempfile.TemporaryDirectory(prefix='scoped-docker-data-',dir=HERE);self.addCleanup(temp.cleanup);root=Path(temp.name);base=root/'base';base.mkdir(mode=0o700);image='sha256:'+'a'*64;(base/'report.json').write_text(json.dumps(dict(image=image,ownership=dict(token='fixture-token'))))
  args=types.SimpleNamespace(selected=SELECTED,base=base,output=root/'output',vm_source=root/'vm-source',kernel_inputs=root/'kernel-inputs',core_source=CORE,current607_inputs=root/'current607-inputs',fresh607_source=root/'fresh607-source',current607_code=root/'current607-code',provision_public=root/'current607-public',provision_deadline=time.monotonic()+100,retirement_deadline=time.monotonic()+60,_owner_report=dict(commands=[]),image=image)
  docker=DockerData(args,role,caps,host_changes);value=CONTROLLER.actor(args,docker,root/'work',root/'media',role);return value,docker
 def test_actual_derived_actor_grants_chroot_only_for_provision607(self):
  for role in('provision607','retire607','prepare','scrub','export'):
   with self.subTest(role=role):
    value,docker=self.actor(role);actual={n.split('=',1)[1]for n in docker.run if n.startswith('--cap-add=')};self.assertEqual(actual,CAPS|({'SYS_CHROOT'}if role=='provision607'else set()));self.assertTrue(value['actor_absent']);self.assertFalse(docker.exists)
    for fixed in('--cap-drop=ALL','--network=none','--read-only','--user=0:0','--security-opt=no-new-privileges','--pull=never','--platform=linux/arm64'):self.assertIn(fixed,docker.run)
    self.assertEqual(docker.run[-2:],['/workspace/provision622.py'if role in('provision607','retire607')else'/workspace/media.py',role])
    self.assertLessEqual(docker.seconds,1900 if role in('provision607','prepare')else 60 if role=='retire607'else 120)
 def test_actual_actor_readback_refuses_chroot_scope_drift(self):
  for role,caps in(('provision607',CAPS),('provision607',CAPS|{'SYS_CHROOT','SYS_ADMIN'}),('retire607',CAPS|{'SYS_CHROOT'}),('prepare',CAPS|{'SYS_CHROOT'}),('export',CAPS|{'SYS_CHROOT'}),('scrub',CAPS|{'SYS_CHROOT'})):
   with self.subTest(role=role,caps=caps),self.assertRaises(ValueError):self.actor(role,caps)
 def test_actual_actor_readback_still_refuses_network_write_or_privilege_drift(self):
  for change in(dict(NetworkMode='host'),dict(ReadonlyRootfs=False),dict(CapDrop=[]),dict(SecurityOpt=[])):
   with self.subTest(change=change),self.assertRaises(ValueError):self.actor('provision607',host_changes=change)
 def test_worker_is_not_an_extra_docker_actor_role(self):
  with self.assertRaises(ValueError):self.actor('initialize607')
 def test_actual_controller_body_is_held_and_selected_modules_are_emitted(self):
  self.assertEqual((SOURCE/'controller.py').read_bytes(),(PARENT/'controller.py').read_bytes());self.assertEqual(Path(CONTROLLER.__file__).resolve(),SOURCE/'controller.py');self.assertEqual(Path(L.__file__).resolve(),SOURCE/'lane622.py');self.assertEqual(Path(P.owned.__code__.co_filename),SOURCE/'provision622.py')

if __name__=='__main__':unittest.main(verbosity=2)
