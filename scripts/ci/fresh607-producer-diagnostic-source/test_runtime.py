#!/usr/bin/env python3
"""Owned real host-build/FD/lifecycle controls, never native package/VM actors."""
import ast,base64,copy,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
sys.dont_write_bytecode=True
D=Path(__file__).resolve().parent

def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
V=load('_producer_failure_data',D/'producer_diagnostic.py');CODE=Path(os.environ['FRESH607_DIAGNOSTIC_INPUT'])/'installer604';PRODUCER=CODE/V.PRODUCER
class Controls(unittest.TestCase):
 def fixture(self,root,positive=False):
  output=root/'producer';updater=root/'updater-source';package=updater/'packages/tools/cachy-asahi-update';package.mkdir(parents=True);script=package/'updater-native.py'
  script.write_text("import pathlib,subprocess,sys\nout=pathlib.Path(sys.argv[sys.argv.index('--output')+1]);out.mkdir(parents=True)\nsrc=out/'private-control.c';src.write_text("+repr('int main(void) { return 0; }'if positive else'int main( { SYNTAX_ERROR; }')+")\nresult=subprocess.run(['/usr/bin/cc','-c',str(src),'-o',str(out/'private-control.o')],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)\nsys.stdout.buffer.write(result.stdout);sys.stdout.flush()\n(out/'result.json').write_text('{\"scope\":\"HOST_PRIVATE_FIXTURE_ONLY\",\"status\":\"'+('PASS'if result.returncode==0 else'FAIL')+'\"}')\nsys.exit(result.returncode)\n")
  a=types.SimpleNamespace(output=output,code=CODE,updater=updater,cache=root/'borrowed-cache',preparation_source=root/'pinned-preparation');a.cache.mkdir();a.preparation_source.mkdir();apis=[];failure=[]
  P=types.SimpleNamespace(__file__=str(PRODUCER))
  def original_load(path):
   api=load('_private_exact_caller_'+str(len(apis)),path);apis.append(api);return api
  P.load=original_load
  def prepare(a):
   api=P.load(a.code/V.CALLER);a.output.mkdir();raw=a.output/'private';public=a.output/'public';raw.mkdir();public.mkdir();(a.output/'producer-owner.json').write_bytes(V.encoded(dict(schema_version=1,token='a'*32,preparation_source=str(a.preparation_source),core_image='sha256:'+'b'*64,images_preexisting=[])));work=raw/'updater';(work/'candidate').mkdir(parents=True);candidate=work/'candidate/candidate.json';candidate.write_bytes(b'{}');result=dict(status='FAIL',phase='updater-exact354-pair',installer='NOT RUN',upgrade='NOT RUN')
   try:
    api.command([sys.executable,'-B',package/'updater-native.py','build','--candidate',candidate,'--candidate-sha256',hashlib.sha256(candidate.read_bytes()).hexdigest(),'--cache',a.cache,'--output',work/'native'],work/'build.log',5400)
    result.update(status='READY_SIGNED_INITIAL587',phase='export-completed');return raw/'ready'
   except BaseException as error:failure.append(error);result.update(error_type=type(error).__name__,error=str(error));raise
   finally:(public/'producer.json').write_bytes(V.encoded(result))
  P.prepare=prepare;return P,a,original_load,apis,failure
 def test_real_failing_private_c_build_captured_before_cleanup_and_same_exception(self):
  with tempfile.TemporaryDirectory(prefix='producer-diagnostic-control-')as td:
   p,a,original,apis,failures=self.fixture(Path(td));caught=None
   try:V.prepare(p,a)
   except AssertionError as error:caught=error
   self.assertIs(caught,failures[0]);self.assertIs(p.load,original);value=json.loads((a.output/'public/producer.json').read_bytes());data=value['failure_data'];self.assertEqual(data['command']['returncode'],1);self.assertEqual(data['command']['timeout_seconds'],5400);self.assertFalse(data['acceptance_authority']);self.assertFalse(data['cleanup_authority']);body=base64.b64decode(data['logs']['updater/build.log']['base64']);self.assertIn(b'error:',body);self.assertEqual(V.pin(body),{k:data['logs']['updater/build.log'][k]for k in('bytes','sha256')});self.assertTrue(data['logs']['updater/build.log']['complete']);self.assertEqual(data['logs']['updater/native/bootstrap.log']['status'],'NOT_PRESENT');self.assertNotIn('_producer_failure_callback',apis[0].command.__globals__)
   shutil.rmtree(a.output/'private');self.assertEqual(json.loads((a.output/'public/producer.json').read_bytes())['failure_data'],data);self.assertEqual({x.name for x in(a.output/'public').iterdir()},{'producer.json'})
 def test_real_positive_private_build_return_report_and_original_functions_held(self):
  with tempfile.TemporaryDirectory(prefix='producer-diagnostic-control-')as td:
   p,a,original,apis,failure=self.fixture(Path(td),True);result=V.prepare(p,a);self.assertEqual(result,a.output/'private/ready');self.assertIs(p.load,original);self.assertEqual((a.output/'public/producer.json').read_bytes(),V.encoded(dict(status='READY_SIGNED_INITIAL587',phase='export-completed',installer='NOT RUN',upgrade='NOT RUN')));self.assertEqual(failure,[]);self.assertNotIn('_producer_failure_callback',apis[0].command.__globals__);self.assertFalse((a.output/'private/producer-diagnostic-report.json.tmp').exists())
 def test_tail_is_exact_bounded_bytes_no_full_log_hash_claim(self):
  with tempfile.TemporaryDirectory(prefix='producer-diagnostic-control-')as td:
   root=Path(td);(root/'updater').mkdir();body=bytes(range(256))*1000;(root/'updater/build.log').write_bytes(body);v=V.tail(root,'updater/build.log',65536);self.assertEqual(base64.b64decode(v['base64']),body[-65536:]);self.assertEqual(v['offset'],len(body)-65536);self.assertFalse(v['complete']);self.assertEqual(v['file_bytes'],len(body));self.assertEqual(v['sha256'],hashlib.sha256(body[-65536:]).hexdigest())
   with self.assertRaises(ValueError):V.tail(root,'../foreign',65536)
   with self.assertRaises(ValueError):V.tail(root,'updater/build.log',65537)
 def test_alias_hardlink_parent_and_during_read_drift_refuse_without_leaks(self):
  for kind in('symlink','hardlink','parent','mutation'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory(prefix='producer-diagnostic-control-')as td:
    root=Path(td);(root/'updater').mkdir();target=root/'updater/build.log';target.write_bytes(b'a'*65536)
    if kind=='symlink':target.rename(root/'actual');target.symlink_to(root/'actual')
    elif kind=='hardlink':os.link(target,root/'alias')
    elif kind=='parent':(root/'updater').rename(root/'actual');(root/'updater').symlink_to(root/'actual',target_is_directory=True)
    before=len(list(Path('/proc/self/fd').iterdir()))
    if kind=='mutation':
     original=os.read;once=[]
     def mutate(fd,n):
      b=original(fd,n)
      if not once:once.append(None);target.write_bytes(b'b'*65536)
      return b
     with patch.object(V.os,'read',side_effect=mutate),self.assertRaises(ValueError):V.tail(root,'updater/build.log',65536)
    else:
     with self.assertRaises(ValueError):V.tail(root,'updater/build.log',65536)
    self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)
 def test_capture_failure_never_replaces_original_failure_or_cleanup(self):
  with tempfile.TemporaryDirectory(prefix='producer-diagnostic-control-')as td:
   p,a,original,apis,failures=self.fixture(Path(td));record_error=ValueError('PRIVATE_DIAGNOSTIC_CONTROL_REFUSAL')
   with patch.object(V,'record',side_effect=record_error),self.assertRaises(AssertionError)as raised:V.prepare(p,a)
   self.assertIs(raised.exception,failures[0]);self.assertEqual(json.loads((a.output/'public/producer.json').read_bytes())['failure_data']['status'],'UNAVAILABLE_UNSAFE_OR_CHANGED_SOURCE');self.assertIs(p.load,original);shutil.rmtree(a.output/'private')
 def test_atomic_append_refuses_drift_without_losing_original_report(self):
  with tempfile.TemporaryDirectory(prefix='producer-diagnostic-control-')as td:
   root=Path(td);(root/'private').mkdir();(root/'public').mkdir();p=root/'public/producer.json';original=V.encoded(dict(status='FAIL',phase='updater-exact354-pair',installer='NOT RUN',upgrade='NOT RUN',error_type='AssertionError',error='command failed: build.log'));p.write_bytes(original)
   with patch.object(V.os,'replace',side_effect=OSError('OWNED_ATOMIC_REPLACEMENT_CONTROL')),self.assertRaises(OSError):V.append(types.SimpleNamespace(output=root),dict(status='INERT_DATA'))
   self.assertEqual(p.read_bytes(),original);self.assertFalse((root/'private/producer-diagnostic-report.json.tmp').exists())
 def test_genuine_private_wait_timeout_retirement_and_original_exception(self):
  with tempfile.TemporaryDirectory(prefix='producer-diagnostic-control-')as td:
   root=Path(td);api=load('_private_timeout_command',CODE/V.CALLER);events=[];original=api.command;derived=V.command(original,(CODE/V.CALLER).read_bytes(),lambda *a:events.append(a));log=root/'timeout.log'
   with self.assertRaises(subprocess.TimeoutExpired)as caught:derived([sys.executable,'-I','-B','-c','import time;time.sleep(5)'],log,0.02)
   self.assertEqual(len(events),1);self.assertIs(events[0][4],caught.exception);self.assertEqual(events[0][3],-15);self.assertEqual(events[0][2],0.02);self.assertEqual(log.read_bytes(),b'')
 def test_fixed_role_and_complete_source_command_inverse(self):
  with tempfile.TemporaryDirectory(prefix='producer-diagnostic-control-')as td:
   p,a,_,_,_=self.fixture(Path(td));raw=a.output/'private';candidate=raw/'updater/candidate/candidate.json';argv=[sys.executable,'-B',a.updater/'packages/tools/cachy-asahi-update/updater-native.py','build','--candidate',candidate,'--candidate-sha256','a'*64,'--cache',a.cache,'--output',raw/'updater/native'];self.assertTrue(V.role(a,argv,raw/'updater/build.log',5400))
   for i,value in((3,'freeze'),(4,'--other'),(7,'bad'),(11,raw/'foreign')):
    bad=list(argv);bad[i]=value;self.assertFalse(V.role(a,bad,raw/'updater/build.log',5400))
   for seconds in(5400.0,True,5401):self.assertFalse(V.role(a,argv,raw/'updater/build.log',seconds))
  api=load('_private_command_source',CODE/V.CALLER);source=(CODE/V.CALLER).read_bytes();original=api.command;derived=V.command(original,source,lambda *a:None);self.assertEqual(derived.__defaults__,original.__defaults__)
  with self.assertRaises(ValueError):V.command(original,source.replace(b'code == 0',b'code != 0'),lambda *a:None)
if __name__=='__main__':unittest.main(verbosity=2)
