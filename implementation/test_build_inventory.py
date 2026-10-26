# SPDX-License-Identifier: MIT
"""Genuine private source/FD controls; Docker, VM and native actors never run."""
import copy,fcntl,importlib.util,json,os,shutil,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;FACTORY=HERE/'factory';sys.path.insert(0,str(HERE))
import build_inventory as B

def load(n,path):
 s=importlib.util.spec_from_file_location(n,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class BuildSentinel(RuntimeError):pass
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(prefix='fixed607-build-');self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name);self.S=load('_fixed607_scope',FACTORY/'build_scope.py');self.F=load('_fixed607_failure',FACTORY/'failure_cleanup.py');self.image='sha256:'+'a'*64;self.ref='cachy-asahi-desktop574-base:'+'b'*32
 def context(self,raw=None):
  p=self.work/'context';p.mkdir();(p/'bundle').mkdir();(p/'bundle/expected-installed.lock').write_bytes(raw if raw is not None else(HERE/'expected607.lock').read_bytes())
  for n in('build_scope.py','install606.py'):(p/n).write_bytes((FACTORY/n).read_bytes())
  return p
 def report(self):return dict(status='FAIL',commands=[dict(argv=['docker','image','tag',self.image,self.ref],log='base-reference.log')],frames={},events=[],base_image=self.image,base_reference=self.ref,build_acquisition=copy.deepcopy(B.PHASE))
 def failed(self):
  v=self.report();v['resource_acquisition']=self.F.selected_plan([],[],self.image,self.ref,False,v,None,None);actions=['check-base-alias','remove-base-alias','check-base-alias-absent','check-base-image-after-alias'];outs=[(self.image+'\n').encode(),('Untagged: '+self.ref+'\n').encode(),b'',(self.image+'\n').encode()];v['cleanup']=[dict(action=a,exit=0,**self.F.output(b))for a,b in zip(actions,outs)];v['base_reference_cleanup']=dict(ok=True,base_image_present=True);return v
 def test_actual_prepare607_private_FDs_and_original606_branch(self):
  context=self.context();selected=self.S.selected607();self.assertIs(selected.prepare.__globals__['read'],selected.check.__globals__['read']);self.assertEqual(self.S.ROLES['runtime606'][3],606);self.assertEqual(selected.ROLES['runtime607'][3],607);self.assertNotIn('runtime606',selected.ROLES)
  flags,p=selected.prepare(context,'runtime607',self.image,self.ref,self.work/'proof');self.assertEqual(p['lock'],dict(path='bundle/expected-installed.lock',packages=607,**B.TARGET));self.assertIn('CAA_GUI_BUILD_PROOF_SHA=',flags[-1]);self.assertEqual((self.work/'proof').stat().st_mode&0o777,0o600)
  with self.assertRaises(ValueError):self.S.prepare(context,'runtime607',self.image,self.ref,self.work/'bad')
  other=self.work/'legacy';other.mkdir();(other/'bundle').mkdir();lock=b''.join(('p'+str(i)+' 1-1\n').encode()for i in range(606));(other/'bundle/expected-installed.lock').write_bytes(lock)
  for n in('build_scope.py','install606.py'):(other/n).write_bytes(b'# source fixture\n')
  _,old=self.S.prepare(other,'runtime606',self.image,self.ref,self.work/'old-proof');self.assertEqual(old['lock']['packages'],606);self.assertEqual(selected.ROLES['controller590'],self.S.ROLES['controller590'])
 def test_actual_inside_check_uses_typed_lock_with_whole_private_FDs(self):
  context=self.context();selected=self.S.selected607();secret=self.work/'secret';_,proof=selected.prepare(context,'runtime607',self.image,self.ref,secret);secret.chmod(0o400);self.S.SECRET=secret;selected.check.__globals__['SECRET']=secret;selected.check.__globals__['ROLES']['runtime607']=(str(context),'install606.py','bundle/expected-installed.lock',607)
  original_text=Path.read_text;original_exists=Path.exists;original_iter=Path.iterdir;original_stat=Path.lstat
  def text(path,*a,**kw):return '1 1 0:0 / '+str(secret)+' ro - tmpfs tmpfs ro\n'if str(path)=='/proc/self/mountinfo'else original_text(path,*a,**kw)
  def exists(path):return False if str(path)=='/run/systemd/system'else original_exists(path)
  def iterdir(path):return iter([Path('lo')])if str(path)=='/sys/class/net'else original_iter(path)
  from types import SimpleNamespace
  def lstat(path,*a,**kw):
   st=original_stat(path,*a,**kw)
   return SimpleNamespace(**{name:(0 if name in('st_uid','st_gid')else getattr(st,name))for name in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')})if path==secret else st
  with patch.object(Path,'lstat',lstat),patch.object(Path,'read_text',text),patch.object(Path,'exists',exists),patch.object(Path,'iterdir',iterdir),patch.object(self.S.os,'geteuid',return_value=0),patch.object(self.S.os,'uname',return_value=SimpleNamespace(machine='aarch64')):
   value=selected.check(proof['proof']['sha256'],'runtime607');self.assertEqual(value['lock']['packages'],607)
   lock=context/'bundle/expected-installed.lock';lock.write_bytes(lock.read_bytes().replace(b'cachy-asahi-setup 0.1.0-6',b'cachy-asahi-setup 0.1.0-5'))
   with self.assertRaises(ValueError):selected.check(proof['proof']['sha256'],'runtime607')
 def test_same607count_wrongversion_extra_missing_duplicate_and_alias_refuse(self):
  raw=(HERE/'expected607.lock').read_bytes();variants=[raw.replace(b'cachy-asahi-setup 0.1.0-6',b'cachy-asahi-setup 0.1.0-5'),raw+b'foreign 1-1\n',b'\n'.join(raw.splitlines()[1:])+b'\n',raw.replace(raw.splitlines()[0],raw.splitlines()[1],1)]
  for i,b in enumerate(variants):
   p=self.work/('lock'+str(i));(p/'bundle').mkdir(parents=True);f=p/'bundle/expected-installed.lock';f.write_bytes(b)
   with self.assertRaises(ValueError):self.S.selected607().read(f,65536)
  context=self.context();file=context/'bundle/expected-installed.lock';file.unlink();file.symlink_to(HERE/'expected607.lock')
  with self.assertRaises(ValueError):self.S.selected607().read(file,65536)
 def test_actual_context607_before_after_first_build_intent(self):
  C=load('_fixed607_actual_context',FACTORY/'context606.py');runner=self.work/'runner';runner.mkdir();context=self.context();shutil.move(context,runner/'install-context606');context=runner/'install-context606';target=(HERE/'expected607.lock').read_bytes();(runner/'expected606.lock').write_bytes(target);(runner/'desktop.pkg').write_bytes(b'exact test-only archive');receipt=dict(files={p.relative_to(context).as_posix():B.pin(p.read_bytes())for p in context.rglob('*')if p.is_file()},expected=B.pin(target),desktop='desktop.pkg',desktop_pin=B.pin(b'exact test-only archive'));(runner/'context606.json').write_text(json.dumps(receipt));out=self.work/'out';out.mkdir();report=dict(commands=[],frames={},events=[])
  def bind(image,reference,execute,text):report['commands'].append(dict(argv=['docker','image','tag',image,reference],log='base-reference.log'))
  def execute(argv,label,cap):self.assertEqual((label,cap),('runtime-image',300));self.assertTrue(report['build_acquisition']['build_requested']);raise BuildSentinel('FIRST_BUILD_REQUESTED_NO_ACTOR')
  with self.assertRaises(BuildSentinel):C.build(runner,self.image,out,execute,None,bind,[],report)
  self.assertEqual(report['image_build_proofs']['runtime607']['role'],'runtime607')
  with self.assertRaises(ValueError):self.F.selected_plan([],[],self.image,report['base_reference'],False,report,None,None)
  # Error before prepare succeeds retains the exact alias-only state.
  (context/'bundle/expected-installed.lock').write_bytes(target.replace(b'cachy-asahi-setup 0.1.0-6',b'cachy-asahi-setup 0.1.0-5'));receipt['files']['bundle/expected-installed.lock']=B.pin((context/'bundle/expected-installed.lock').read_bytes());(runner/'context606.json').write_text(json.dumps(receipt));out2=self.work/'out2';out2.mkdir();report.clear();report.update(commands=[],frames={},events=[])
  with self.assertRaises(ValueError):C.build(runner,self.image,out2,execute,None,bind,[],report)
  self.assertFalse(report['build_acquisition']['build_requested']);p=self.F.selected_plan([],[],self.image,report['base_reference'],False,report,None,None);self.assertEqual(p['schema_version'],2)
 def test_alias_only_complete_retirement_and_partial_forged_rows_refuse(self):
  v=self.failed();self.assertEqual(self.F.retired(v)['GUI'],'FAILED_NOT_ACCEPTED')
  variants=[]
  for key,bad in(('status','PASS'),('frames',{'foreign':{}}),('events',[{}]),('runtime_image','sha256:'+'c'*64)):
   q=copy.deepcopy(v);q[key]=bad;variants.append(q)
  q=copy.deepcopy(v);q['cleanup']=q['cleanup'][:-1];variants.append(q)
  for index in range(4):
   q=copy.deepcopy(v);q['cleanup'][index]['stdout']['sha256']='0'*64;variants.append(q)
  q=copy.deepcopy(v);q['cleanup'][2].update(self.F.output(b'alias still present\n'));variants.append(q)
  q=copy.deepcopy(v);q['build_acquisition']['build_requested']=True;variants.append(q)
  q=copy.deepcopy(v);q['commands'].append(dict(argv=['docker','build'],log='x'));variants.append(q)
  for q in variants:
   with self.assertRaises((ValueError,KeyError)):self.F.retired(q)
 def owner(self):
  runtime=self.work/'runtime';runtime.mkdir();lease=runtime/'runtime.lease';lease.touch(mode=0o600);fd=os.open(lease,os.O_RDONLY|os.O_CLOEXEC);self.addCleanup(os.close,fd);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);base=self.work/'base';base.mkdir();job='d'*16;sha='e'*40;proof=dict(runtime_path=str(runtime),profile='minimal',job_token=job,source_sha=sha,workflow_sha=sha,run_id='123',run_attempt='1');current=dict(status='SOURCE_BOUND_LATEST607_GUI_NATIVE_CASE',profile='minimal',mode='generic4k',case='minimal-generic4k',run=123,attempt=1,source=sha,job_token=job,original348=proof);terminal=dict(schema_version=1,profile='minimal',mode='generic4k',child_started=True,natural_exit=True,reaped=True,group_absent=True,returncode=1);report=dict(status='PASS_NATIVE_OFFLINE_574_TRANSACTION',image=self.image,ownership=dict(token=job,image=self.image,build_started=True,build_complete=True,probe_started=True,probe_complete=True));(base/'report.json').write_text(json.dumps(report));(base/'image-id').write_text(self.image+'\n');return runtime,fd,base,proof,current,terminal
 def test_genuine_held_lease_current_job_alias_only_and_default_delegation(self):
  runtime,fd,base,proof,current,terminal=self.owner();v=self.failed();result=B.lease_retirement(self.F.retired,v,terminal,fd,proof,runtime,base,current);self.assertEqual(result['status'],'PASS_FAILED_PRE_BUILD_ALIAS_RETIREMENT_ONLY');self.assertEqual(v['status'],'FAIL')
  self.assertEqual(B.lease_retirement(lambda _: 'HELD_OLD_GATE',dict(resource_acquisition=dict(schema_version=1)),None,None,None,None,None,None),'HELD_OLD_GATE')
 def test_foreign_job_owner_image_terminal_extra_actor_and_lease_refuse(self):
  runtime,fd,base,proof,current,terminal=self.owner();v=self.failed()
  for key,bad in(('job_token','f'*16),('source','f'*40),('run',124),('original348',{}),('case','overlay-generic4k')):
   q=copy.deepcopy(current);q[key]=bad
   with self.assertRaises((ValueError,KeyError)):B.lease_retirement(self.F.retired,v,terminal,fd,proof,runtime,base,q)
  for key,bad in(('reaped',False),('group_absent',False),('returncode',0),('profile','overlay'),('extra_actor',True)):
   q=dict(terminal);q[key]=bad
   with self.assertRaises((ValueError,KeyError)):B.lease_retirement(self.F.retired,v,q,fd,proof,runtime,base,current)
  report=json.loads((base/'report.json').read_text());report['image']='sha256:'+'f'*64;(base/'report.json').write_text(json.dumps(report))
  with self.assertRaises(ValueError):B.lease_retirement(self.F.retired,v,terminal,fd,proof,runtime,base,current)
  (runtime/'runtime.lease').chmod(0o644)
  with self.assertRaises(ValueError):B.lease_retirement(self.F.retired,v,terminal,fd,proof,runtime,base,current)
 def test_full_original_body_and_native_callback_source_seams(self):
  raw=(HERE/'native.py').read_text();self.assertIn('validate_cleanup(gui,terminal,lease,proof,runtime,base)',raw);self.assertIn('lease_retirement(owner.retirement,gui,terminal,lease,proof,runtime,base,p)',raw);factory=(FACTORY/'factory.py').read_text();self.assertIn('selected_plan(containers,images,image,base_reference',factory);self.assertNotIn('return 0', (FACTORY/'failure_cleanup.py').read_text())
if __name__=='__main__':unittest.main(verbosity=2)
