"""Genuine private child/FD dependency failure DATA controls; no package/VM/native actor."""
import base64,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_fixed_factory',D/'prepare.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)
PARENT=F.ordinary(os.environ['FRESH_DEPENDENCY_INPUT']);SOURCE=F.ordinary(os.environ['FRESH_DEPENDENCY_SOURCE'])
p=json.loads(F.read(D/'profile.json'))
F.need({n:F.pin(b)for n,b in F.tree(PARENT).items()}==p['parent']['files']and{n:F.pin(b)for n,b in F.tree(SOURCE).items()}==p['result']['files'],'complete trusted current/source parent bytes before runtime controls')
s=importlib.util.spec_from_file_location('_dependency_diagnostic',SOURCE/'implementation/producer_diagnostic.py');V=importlib.util.module_from_spec(s);s.loader.exec_module(V)
CODE=PARENT/'installer604'
def load(path):
 s=importlib.util.spec_from_file_location('_private_dependency_caller',path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
class Controls(unittest.TestCase):
 def fixture(self,root,mode='fail'):
  a=types.SimpleNamespace(output=root/'producer',code=CODE,updater=root/'updater',cache=root/'cache',preparation_source=root/'preparation')
  for p in(a.updater,a.cache,a.preparation_source):p.mkdir()
  script=a.preparation_source/'scripts/ci/full-development-composition/dependencies/acquire.py';script.parent.mkdir(parents=True)
  script.write_text("import pathlib,sys,time\nout=pathlib.Path(sys.argv[sys.argv.index('--output')+1]);out.mkdir()\nprint('PRIVATE_DEPENDENCY_STDOUT',flush=True)\nprint('PRIVATE_DEPENDENCY_STDERR',file=sys.stderr,flush=True)\n"+("time.sleep(5)\n"if mode=='wait'else"sys.exit(7)\n"if mode=='fail'else"(out/'acquisition.json').write_text('{\"PRIVATE_CONTROL\":true}')\n"))
  apis=[];errors=[];P=types.SimpleNamespace(__file__=str(CODE/V.PRODUCER))
  def original(path):api=load(path);apis.append(api);return api
  P.load=original
  def prepare(a):
   api=P.load(CODE/V.CALLER);a.output.mkdir();raw=a.output/'private';public=a.output/'public';raw.mkdir();public.mkdir()
   (a.output/'producer-owner.json').write_bytes(V.encoded(dict(schema_version=1,token='a'*32,preparation_source=str(a.preparation_source))))
   result=dict(status='FAIL',phase='authenticate-five-deduplicate-four',installer='NOT RUN',upgrade='NOT RUN')
   try:
    api.command([sys.executable,'-B',script,'--source-root',a.updater,'--cache',a.cache,'--keydir',a.cache,'--output',raw/'dependency-audit'],raw/'dependency.log',180)
    result.update(status='READY_SIGNED_INITIAL587',phase='export-completed');return raw/'ready'
   except BaseException as error:errors.append(error);result.update(error_type=type(error).__name__,error=str(error));raise
   finally:(public/'producer.json').write_bytes(V.encoded(result))
  P.prepare=prepare;return P,a,original,apis,errors
 def test_real_failure_data_before_cleanup_and_original_exception_functions(self):
  with tempfile.TemporaryDirectory(dir=D)as td:
   p,a,original,apis,errors=self.fixture(Path(td))
   with self.assertRaises(AssertionError)as caught:V.prepare(p,a)
   self.assertIs(caught.exception,errors[0]);data=json.loads((a.output/'public/producer.json').read_bytes())['failure_data']
   self.assertEqual(data['command']['role'],'AUTHENTICATE_FIVE_DEDUPLICATE_FOUR');self.assertEqual(data['command']['timeout_seconds'],180);self.assertEqual(data['command']['returncode'],7)
   row=data['logs']['dependency.log'];raw=base64.b64decode(row['base64']);self.assertIn(b'PRIVATE_DEPENDENCY_STDERR',raw);self.assertIn(b'PRIVATE_DEPENDENCY_STDOUT',raw);self.assertEqual(V.pin(raw),{k:row[k]for k in('bytes','sha256')});self.assertTrue(row['complete']);self.assertEqual(data['logs']['dependency-audit/acquisition.json'],{'status':'ABSENT_DATA'})
   self.assertFalse(data['acceptance_authority']);self.assertFalse(data['cleanup_authority']);self.assertIs(p.load,original);self.assertNotIn('_producer_failure_callback',apis[0].command.__globals__)
   shutil.rmtree(a.output/'private');self.assertEqual(json.loads((a.output/'public/producer.json').read_bytes())['failure_data'],data);self.assertEqual({p.name for p in(a.output/'public').iterdir()},{'producer.json'})
 def test_positive_return_and_report_bytes_unchanged(self):
  with tempfile.TemporaryDirectory(dir=D)as td:
   p,a,original,apis,errors=self.fixture(Path(td),'pass');self.assertEqual(V.prepare(p,a),a.output/'private/ready')
   self.assertEqual((a.output/'public/producer.json').read_bytes(),V.encoded(dict(status='READY_SIGNED_INITIAL587',phase='export-completed',installer='NOT RUN',upgrade='NOT RUN')));self.assertFalse(errors);self.assertIs(p.load,original);self.assertNotIn('_producer_failure_callback',apis[0].command.__globals__)
 def test_wait_error_with_real_child_retirement_held180_role(self):
  with tempfile.TemporaryDirectory(dir=D)as td:
   p,a,original,apis,errors=self.fixture(Path(td),'wait');real=subprocess.Popen;events=[]
   def spawn(*args,**kwargs):
    proc=real(*args,**kwargs);wait=proc.wait;first=[True]
    def controlled(timeout=None):
     events.append(timeout)
     if first[0]:first[0]=False;return wait(timeout=.05)
     return wait(timeout=timeout)
    proc.wait=controlled;return proc
   with patch('subprocess.Popen',side_effect=spawn),self.assertRaises(subprocess.TimeoutExpired)as caught:V.prepare(p,a)
   self.assertIs(caught.exception,errors[0]);data=json.loads((a.output/'public/producer.json').read_bytes())['failure_data'];self.assertEqual(data['command']['wait_error_type'],'TimeoutExpired');self.assertEqual(data['command']['returncode'],-15);self.assertEqual(data['command']['timeout_seconds'],180);self.assertEqual(events[:2],[180,10]);self.assertIs(p.load,original)
 def test_foreign_argv_log_timeout_refused_closed_role(self):
  with tempfile.TemporaryDirectory(dir=D)as td:
   p,a,*_=self.fixture(Path(td));raw=a.output/'private';argv=[sys.executable,'-B',a.preparation_source/'scripts/ci/full-development-composition/dependencies/acquire.py','--source-root',a.updater,'--cache',a.cache,'--keydir',a.cache,'--output',raw/'dependency-audit'];self.assertTrue(V.dependency_role(a,argv,raw/'dependency.log',180))
   for index in range(11):
    bad=list(argv);bad[index]='FOREIGN';self.assertFalse(V.dependency_role(a,bad,raw/'dependency.log',180))
   for seconds in(True,180.,179,181):self.assertFalse(V.dependency_role(a,argv,raw/'dependency.log',seconds))
   self.assertFalse(V.dependency_role(a,argv,raw/'other.log',180));self.assertFalse(V.dependency_role(a,argv+[1],raw/'dependency.log',180))
 def test_tail_cap_report_absence_and_no_arbitrary_path(self):
  with tempfile.TemporaryDirectory(dir=D)as td:
   root=Path(td);body=bytes(range(256))*1000;(root/'dependency.log').write_bytes(body)
   row=V.tail(root,'dependency.log',65536);self.assertEqual(base64.b64decode(row['base64']),body[-65536:]);self.assertEqual(row['offset'],len(body)-65536);self.assertFalse(row['complete']);self.assertLess(len(V.encoded(row)),V.MAX_DATA)
   for name,cap in(('../dependency.log',65536),('dependency.log',65537),('foreign.json',16384)):
    with self.assertRaises(ValueError):V.tail(root,name,cap)
 def test_alias_hardlink_parent_and_stablefd_mutation_refuse(self):
  for kind in('symlink','hardlink','parent','mutation'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory(dir=D)as td:
    root=Path(td);sub=root/'private';sub.mkdir();target=sub/'dependency.log';target.write_bytes(b'a'*65536)
    if kind=='symlink':target.rename(root/'real');target.symlink_to(root/'real')
    elif kind=='hardlink':os.link(target,root/'alias')
    elif kind=='parent':sub.rename(root/'real');sub.symlink_to(root/'real',target_is_directory=True)
    before=len(list(Path('/proc/self/fd').iterdir()))
    if kind=='mutation':
     original=os.read;once=[]
     def mutate(fd,n):
      b=original(fd,n)
      if not once:once.append(1);target.write_bytes(b'b'*65536)
      return b
     with patch.object(V.os,'read',side_effect=mutate),self.assertRaises(ValueError):V.tail(sub,'dependency.log',65536)
    else:
     with self.assertRaises(ValueError):V.tail(sub,'dependency.log',65536)
    self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)
 def test_optional_capture_refusal_and_atomic_failure_keep_original_outcome(self):
  for operation in('record','atomic'):
   with self.subTest(operation=operation),tempfile.TemporaryDirectory(dir=D)as td:
    p,a,original,apis,errors=self.fixture(Path(td));context=patch.object(V,'dependency_record',side_effect=ValueError('PRIVATE_REFUSAL'))if operation=='record'else patch.object(V.os,'replace',side_effect=OSError('PRIVATE_ATOMIC_REFUSAL'))
    with context,self.assertRaises(AssertionError)as caught:V.prepare(p,a)
    self.assertIs(caught.exception,errors[0]);self.assertIs(p.load,original);row=json.loads((a.output/'public/producer.json').read_bytes())
    if operation=='record':self.assertEqual(row['failure_data']['status'],'UNAVAILABLE_UNSAFE_OR_CHANGED_SOURCE')
    else:self.assertNotIn('failure_data',row)
    self.assertFalse((a.output/'private/producer-diagnostic-report.json.tmp').exists())
 def test_whole_old_helper_inverse_and_old_functions_held(self):
  old=(PARENT/'implementation/producer_diagnostic.py').read_bytes()
  change=json.loads((D/'helper-edits.json').read_bytes());new=(SOURCE/'implementation/producer_diagnostic.py').read_text();self.assertTrue(new.endswith(change['append']));new=new[:-len(change['append'])]
  for a,b in reversed(change['edits']):self.assertEqual(new.count(b),1);new=new.replace(b,a,1)
  self.assertEqual(new.encode(),old)
if __name__=='__main__':unittest.main(verbosity=2)
