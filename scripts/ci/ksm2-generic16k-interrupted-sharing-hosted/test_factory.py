# SPDX-License-Identifier: MIT
"""Bounded source/real-process controls. Guest/sysfs fakes never grant VM credit."""
import hashlib,importlib.util,json,os,select,shutil,signal,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;spec=importlib.util.spec_from_file_location('_controlled_factory',HERE/'prepare.py');N=importlib.util.module_from_spec(spec);spec.loader.exec_module(N)
RUNTIME=Path(os.environ['KSM_SHARING_SCALAR_RUNTIME']).absolute()
def pins(root):return{p.relative_to(root).as_posix():dict(bytes=len((raw:=p.read_bytes())),sha256=hashlib.sha256(raw).hexdigest())for p in root.rglob('*')if p.is_file()}
PROCESS=r'''import importlib.util,json,os,signal,sys,time
from pathlib import Path
spec=importlib.util.spec_from_file_location('owned_controller_control',sys.argv[1]);S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
S.guard=lambda selection,parent:'a'*32
children=[];descriptors=[];events=[];kind=sys.argv[2]
class ScalarControl:
 def counters(self):
  if kind=='before':print('CONTROL_READY',flush=True);time.sleep(30)
  return dict.fromkeys(S.COUNTERS,0)
 def restore(self):
  if kind=='foreign':events.append('FOREIGN_KEPT_REFUSED');raise ValueError('foreign edit refused')
  events.append('RESTORE_CALLED_NO_SYSFS')
 def close(self):events.append('DESCRIPTORS_CLOSED_NO_SYSFS')
S.Scalars=ScalarControl
if kind!='before':
 def spawn(nonce,deadline,previous):
  incoming,send=os.pipe();receive,outgoing=os.pipe();pid=os.fork()
  if pid==0:
   try:os.close(send);os.close(receive);os.read(incoming,1)
   finally:os._exit(0)
  os.close(incoming);os.close(outgoing);children.append(pid);descriptors.extend((send,receive));return dict(pid=pid,send=send,receive=receive,initial={})
 def observe(*a,**kw):print('CONTROL_READY',flush=True);time.sleep(30);raise AssertionError('NO_MEMORY_REGISTRATION_OR_NATIVE_RECEIPT')
 S.spawn=spawn;S.observe_children=observe
prior=signal.getsignal(signal.SIGTERM)
try:S.experiment({},1)
except BaseException as e:
 reaped=[]
 for pid in children:
  try:os.waitpid(pid,os.WNOHANG);reaped.append(False)
  except ChildProcessError:reaped.append(True)
 closed=[]
 for fd in descriptors:
  try:os.fstat(fd);closed.append(False)
  except OSError:closed.append(True)
 print(json.dumps(dict(error=type(e).__name__,events=events,handler_restored=signal.getsignal(signal.SIGTERM)==prior,children_reaped=reaped,children_absent=[not Path('/proc',str(p)).exists()for p in children],protocol_fds_closed=closed,scope='CONTROL_FAKE_GUEST_SYSFS_NO_MEMORY_REGISTRATION')),flush=True)
'''
class Controls(unittest.TestCase):
 def test_public_CLI_normal628_controlled637_and_full_reproduction(self):
  F=N.base();p=N.profile(F)
  for controlled,view in((False,'default'),(True,'default'),(True,'selected')):
   with self.subTest(controlled=controlled,view=view),tempfile.TemporaryDirectory()as tmp:
    root=Path(tmp);binding=root/'binding';binding.write_bytes(F.encoded(p['base_profile']['policies']['selected']));out=root/'source';argv=[sys.executable,'-I','-B',str(N.BASE/'prepare.py'),'--runtime',str(RUNTIME),'--output',str(out)]
    if controlled:argv.append('--controlled-interruption')
    if view=='selected':argv+=['--binding',str(binding)]
    r=subprocess.run(argv,capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(pins(out),(p['expected_sources']if controlled else p['base_profile']['expected_sources'])[view])
    if controlled:
     again=root/'again';r=subprocess.run([sys.executable,'-I','-B',str(out/F.LANE/'prepare.py'),'--runtime',str(out/'runtime'),'--output',str(again)]+(['--binding',str(binding)]if view=='selected'else[]),capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(pins(again),pins(out))
 def run_signal(self,path,kind):
  p=subprocess.Popen([sys.executable,'-I','-B','-c',PROCESS,str(path),kind],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  try:
   self.assertTrue(select.select([p.stdout],[],[],3)[0]);self.assertEqual(p.stdout.readline(),b'CONTROL_READY\n');p.send_signal(signal.SIGTERM);out,err=p.communicate(timeout=3);self.assertEqual(err,b'');return p.returncode,out
  finally:
   if p.poll()is None:p.kill();p.communicate()
 def test_real_before_after_SIGTERM_enters_existing_finally(self):
  code,out=self.run_signal(N.BASE/'runtime/sharing.py','before');self.assertEqual((code,out),(-signal.SIGTERM,b''));code,out=self.run_signal(HERE/'payload/sharing.py','before');v=json.loads(out);self.assertEqual(code,0);self.assertEqual(v['error'],'SharingInterrupted');self.assertEqual(v['events'],['RESTORE_CALLED_NO_SYSFS','DESCRIPTORS_CLOSED_NO_SYSFS']);self.assertTrue(v['handler_restored'])
 def test_real_owned_children_reaped_FDs_closed_and_foreign_refusal_kept(self):
  for kind in('children','foreign'):
   with self.subTest(kind=kind):
    code,out=self.run_signal(HERE/'payload/sharing.py',kind);v=json.loads(out);self.assertEqual(code,0);self.assertEqual(v['children_reaped'],[True,True]);self.assertEqual(v['children_absent'],[True,True]);self.assertEqual(v['protocol_fds_closed'],[True]*4);self.assertTrue(v['handler_restored']);self.assertEqual(v['error'],'ValueError'if kind=='foreign'else'SharingInterrupted');self.assertEqual(v['events'],['FOREIGN_KEPT_REFUSED'if kind=='foreign'else'RESTORE_CALLED_NO_SYSFS','DESCRIPTORS_CLOSED_NO_SYSFS'])
 def test_payload_source_or_actual_selection_refused_before_output(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);out=root/'absent';bad=root/'binding';bad.write_text('{"actual_run":1}')
   with self.assertRaises(ValueError):N.assemble(RUNTIME,out,bad)
   self.assertFalse(out.exists());copy=root/'factory';shutil.copytree(HERE,copy);path=copy/'payload/interrupted.py';path.write_bytes(path.read_bytes()+b' ')
   with patch.object(N,'HERE',copy),self.assertRaises(ValueError):N.assemble(RUNTIME,out)
   self.assertFalse(out.exists())
 def test_real_atime_refresh_excludes_only_atime(self):
  with tempfile.TemporaryDirectory(dir='/dev/shm',prefix='ksm-maintained-atime-')as tmp:
   p=Path(tmp)/'source';p.write_bytes(b'whole controlled source\n');os.utime(p,ns=(1,p.stat().st_mtime_ns));before=p.stat();self.assertEqual(N.local_read(p),b'whole controlled source\n');after=p.stat();self.assertGreater(after.st_atime_ns,before.st_atime_ns)
   fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');self.assertEqual([getattr(before,n)for n in fields],[getattr(after,n)for n in fields]);real=Path.read_bytes
   def drift(path):raw=real(path);path.chmod(0o640);return raw
   with patch.object(Path,'read_bytes',drift),self.assertRaisesRegex(ValueError,'drift'):N.local_read(p)
if __name__=='__main__':unittest.main(verbosity=2)
