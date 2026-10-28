# SPDX-License-Identifier: MIT
"""Eight portable cleanup controls; exact source-held emission transform and original finally at inert Docker boundary."""
import ast,base64,copy,hashlib,importlib.util,io,json,os,re,shutil,subprocess,sys,tempfile,textwrap,types,unittest
from pathlib import Path
from unittest.mock import patch
D=Path(__file__).resolve().parent;SOURCE=Path(os.environ['GUI_CLEANUP_EXPECTED']);PARENT=Path(os.environ['GUI_CLEANUP_PARENT']);ACTUAL=D/'failure-cleanup-controls'
def load(name,path):
 saved=sys.path[:];sys.path.insert(0,str(path.parent))
 try:
  s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
 finally:sys.path[:]=saved
H=load('_cleanup_helper_control',SOURCE/'factory/failure_cleanup.py')
def obj(p):return json.loads(p.read_bytes())
def nodes(path,name):return ast.dump(next(n for n in ast.parse(path.read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name==name),include_attributes=False)
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
  original=(PARENT/'original/scripts/ci/desktop574_runtime.py').read_text();(cls.root/'old').mkdir();(cls.root/'new').mkdir();(cls.root/'old/desktop574_runtime.py').write_text(original)
  factory=load('_trusted_complete_factory',SOURCE/'factory/factory.py');transform=next(n for n in ast.parse((SOURCE/'factory/factory.py').read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name=='transform');retire=next(n for n in transform.body if isinstance(n,ast.FunctionDef)and n.name=='retirement');env=dict(once=factory.once);exec(compile(ast.fix_missing_locations(ast.Module(body=[retire],type_ignores=[])),'<exact-source-held-emitted-retirement-transform>','exec'),env);(cls.root/'new/desktop574_runtime.py').write_text(env['retirement'](original))
  calls=[n for n in ast.walk(transform)if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='edit'and len(n.args)==2 and isinstance(n.args[1],ast.Name)and n.args[1].id=='retirement'];assert len(calls)==1 and calls[0].args[0].value=='desktop574_runtime.py'
 @classmethod
 def tearDownClass(cls):cls.temp.cleanup()
 def run_finally(self,variant='new',fault=None):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td);fixture=out/'fixture';fixture.mkdir();(fixture/'owned').write_bytes(b'owned disposable fixture')
   value=copy.deepcopy(obj(ACTUAL/'gui/runtime.json'));value['cleanup']=[]
   containers=[r['action'].split(':',1)[1]for r in obj(ACTUAL/'gui/runtime.json')['cleanup']if r.get('action','').startswith('remove-container:')][::-1]
   images=[value['runtime_image'],value['controller_image']];base=value['base_image'];alias=value['base_reference'];present=set(images+[base]);bound={alias:base};remaining=set(containers);commands=[]
   if fault=='substituted_alias':bound[alias]='sha256:'+'f'*64
   def invoke(argv,**kwargs):
    commands.append(argv);raw=b'';code=0
    if argv[:3]==['docker','rm','-f']:remaining.discard(argv[3])
    elif argv[:3]==['docker','container','ls']:raw=b'foreign\n'if fault=='container_present'else(b'container\n'if containers[-1]in remaining else b'')
    elif argv[:3]==['docker','image','rm']:
     if '--no-prune'in argv:bound.pop(argv[-1],None)
     else:present.discard(argv[-1])
    elif argv[:3]==['docker','image','ls']:
     if '--filter'in argv:raw=((bound[alias]+'\n').encode()if alias in bound else b'')
     else:raw=('\n'.join(sorted(present))+ '\n').encode()
    elif argv[:2]==['docker','run']:
     for p in fixture.iterdir():p.unlink()
    else:raise AssertionError(argv)
    if fault=='remove_error'and argv[:3]==['docker','image','rm']:code=1
    return types.SimpleNamespace(returncode=code,stdout=raw)
   text=(self.root/variant/'desktop574_runtime.py').read_text();main=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='main');trial=next(n for n in main.body if isinstance(n,ast.Try)and n.finalbody);fn=ast.FunctionDef(name='finish',args=ast.arguments(posonlyargs=[],args=[],kwonlyargs=[],kw_defaults=[],defaults=[]),body=[ast.Global(names=['base_reference'])]+trial.finalbody,decorator_list=[]);module=ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[]))
   def require(ok,why):
    if not ok:raise ValueError(why)
   runtime=load('_original_release_only',PARENT/'original/scripts/ci/desktop574_runtime.py')
   env=dict(report=value,out=out,containers=containers,images=images,image=base,base_reference=None,active=None,qmp=None,previous={},signal=types.SimpleNamespace(ITIMER_REAL=0,SIG_IGN=0,setitimer=lambda *_:None,signal=lambda *_:None),subprocess=types.SimpleNamespace(run=invoke,PIPE=subprocess.PIPE,STDOUT=subprocess.STDOUT),os=os,json=json,MAX_EVENTS=8*1024**2,require=require,release_local_base=runtime.release_local_base,failure_cleanup=H,original={'image':base})
   exec(compile(module,'<whole-actual-emitted-finally>','exec'),env)
   with patch('sys.stdout',new=io.StringIO()):env['finish']()
   return obj(out/'runtime.json'),commands
 def test_authentic_failed_record_and_old_emitted_bug_are_not_cleanup_credit(self):
  v=obj(ACTUAL/'gui/runtime.json');self.assertEqual((v['status'],len(v['cleanup'])),('FAIL',11));self.assertNotIn('base_reference_cleanup',v)
  with self.assertRaises((KeyError,ValueError)):H.retired(v)
  old=load('_held_positive_cleanup_gate',PARENT/'factory/run.py')
  with self.assertRaises(ValueError):old.cleanup(v)
  reproduced,commands=self.run_finally('old');self.assertEqual(len(reproduced['cleanup']),11);self.assertFalse(any('--no-prune'in c for c in commands));self.assertNotIn('base_reference_cleanup',reproduced)
 def test_whole_new_emitted_finally_retires_alias_and_preserves_failure(self):
  v,commands=self.run_finally();self.assertEqual(v['status'],'FAIL');self.assertEqual(len(v['cleanup']),15);r=H.retired(v);self.assertEqual(r['GUI'],'FAILED_NOT_ACCEPTED');self.assertIn(['docker','image','rm','--no-prune',v['base_reference']],commands)
  owner=load('_new_failure_owner',SOURCE/'factory/run.py');self.assertEqual(owner.retirement(v),r)
  self.assertEqual(nodes(SOURCE/'factory/run.py','cleanup'),nodes(PARENT/'factory/run.py','cleanup'))
  positive=copy.deepcopy(v);positive['status']='PASS_CURRENT606_WELCOME8_GENERIC4K_GUI_METADATA';self.assertTrue(owner.retirement(positive)['status'].startswith('PASS_NEW15'))
 def test_missing_error_substitution_and_fresh_absence_refusals(self):
  v,_=self.run_finally()
  for index in range(15):
   bad=copy.deepcopy(v);bad['cleanup'].pop(index)
   with self.assertRaises(ValueError):H.retired(bad)
  for mutate in(lambda b:b['cleanup'][0].update(exit=1),lambda b:b['cleanup'][5].update(H.output(b'foreign\n')),lambda b:b['cleanup'][14].update(H.output((b['runtime_image']+'\n'+b['base_image']+'\n').encode())),lambda b:b['resource_acquisition']['images'].reverse(),lambda b:b['base_reference_cleanup'].update(base_image_present=False),lambda b:b.update(status='FAIL_CLEANUP')):
   b=copy.deepcopy(v);mutate(b)
   with self.assertRaises(ValueError):H.retired(b)
  for fault in('substituted_alias','container_present','remove_error'):
   bad,_=self.run_finally(fault=fault)
   with self.assertRaises((KeyError,ValueError)):H.retired(bad)
 def test_whole_builder_publishes_lease_before_uncertain_bind(self):
  C=load('_actual_nested_build_lease',SOURCE/'factory/context606.py')
  with tempfile.TemporaryDirectory()as td:
   runner=Path(td);ctx=runner/'install-context606';ctx.mkdir();(ctx/'leaf').write_bytes(b'exact source-shaped input');(runner/'desktop').write_bytes(b'exact archive fixture');shutil.copyfile(SOURCE/'factory/expected606.lock',runner/'expected606.lock');(runner/'context606.json').write_text(json.dumps(dict(files={'leaf':C.pin(b'exact source-shaped input')},expected=C.pin((runner/'expected606.lock').read_bytes()),desktop='desktop',desktop_pin=C.pin(b'exact archive fixture'))));report={};calls=[]
   def bind(*args):calls.append(args);raise RuntimeError('inert uncertain tag command')
   with self.assertRaises(RuntimeError):C.build(runner,'sha256:'+'a'*64,runner/'out',None,None,bind,[],report)
   self.assertEqual(report['base_image'],'sha256:'+'a'*64);self.assertRegex(report['base_reference'],'^cachy-asahi-desktop574-base:[a-f0-9]{32}$');self.assertEqual(calls[0][1],report['base_reference'])
 def test_whole_parent_source_guard_and_inverse_and_drift(self):
  a=load('_complete_cleanup_source',SOURCE/'admission.py');self.assertEqual(a.prove(SOURCE)['files'],561);profile=obj(D/'failure-cleanup-profile.json');self.assertEqual((len(profile['held']),sum(n in profile['after']and w!=profile['after'][n]for n,w in profile['before'].items()),len(set(profile['after'])-set(profile['before']))),(553,6,2));parent=obj(SOURCE/'failure-cleanup-parent.json')
  for n,w in parent['files'].items():
   b=base64.b64decode(parent['before_bodies'][n],validate=True)if n in parent['before_bodies']else(SOURCE/n).read_bytes();self.assertEqual(H.pin(b),w)
  read=a.read
  def changed(p,cap=16*1024**2):return read(p,cap)+(b'X'if Path(p)==SOURCE/'factory/failure_cleanup.py'else b'')
  with patch.object(a,'read',side_effect=changed),self.assertRaises(ValueError):a.prove(SOURCE)
 def test_ordered_producer_cleanup_holds_original_lease_credentials_and_body(self):
  raw=(SOURCE/'native.py').read_text();self.assertIn("env['validate_cleanup']=owner.retirement",raw);self.assertIn("value['runtime_retirement']=validate_cleanup(gui)",raw)
  original=(SOURCE/'original/scripts/ci/welcome5-native-gui/job.py').read_bytes();self.assertEqual(original,(PARENT/'original/scripts/ci/welcome5-native-gui/job.py').read_bytes());self.assertIn(b"terminal.get('reaped')is True and terminal.get('group_absent')is True",original)
 def test_whole_ordered_cleanup_requires_runtime_retirement_before_producer(self):
  import fcntl
  raw=(SOURCE/'original/scripts/ci/welcome5-native-gui/job.py').read_text();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='cleanup');body=ast.get_source_segment(raw,node).replace("runtime/'runtime.lock'","runtime/'runtime.lease'",1).replace("validate_cleanup(gui);value['runtime']=gui['cleanup']","value['runtime_retirement']=validate_cleanup(gui);value['runtime']=gui['cleanup']",1)
  good,_=self.run_finally();owner=load('_ordered_failure_owner',SOURCE/'factory/run.py')
  for role in('good','missing_resource','live_group','lease_busy'):
   with tempfile.TemporaryDirectory()as td:
    root=Path(td);runtime=root/'runtime';runtime.mkdir();(runtime/'runtime').mkdir();base=root/'base';base.mkdir();(base/'report.json').write_text('{}');(runtime/'runtime.lease').touch();terminal=obj(ACTUAL/'runtime-terminal.json');value=copy.deepcopy(good)
    if role=='missing_resource':value['cleanup'].pop()
    if role=='live_group':terminal['group_absent']=False
    (runtime/'runtime-terminal.json').write_text(json.dumps(terminal));(runtime/'runtime/runtime.json').write_text(json.dumps(value));calls=[];bindings=[]
    def run(argv,**kw):
     calls.append(argv);self.assertIn('--job-token',argv);self.assertEqual(argv[-1],'a'*16);self.assertEqual(kw['timeout'],240);self.assertEqual(kw['capture_output'],True);(base/'report.json').write_text(json.dumps(dict(owned_cleanup=dict(status='PASS'))));return types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
    def need(ok,why):
     if not ok:raise ValueError(why)
    def save(path,v):path.write_text(json.dumps(v))
    env=dict(binding=lambda *args:bindings.append(args),C=types.SimpleNamespace(need=need,read=lambda p:obj(p)),os=os,fcntl=fcntl,sys=sys,validate_cleanup=owner.retirement,save=save);exec(compile(body,'<whole-original-ordered-cleanup-two-exact-seams>','exec'),env);lock=None
    if role=='lease_busy':lock=os.open(runtime/'runtime.lease',os.O_RDONLY);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    try:
     with patch.object(subprocess,'run',side_effect=run):result=env['cleanup'](SOURCE/'original','minimal',dict(runtime_path=str(runtime),job_token='a'*16),base,runtime,root/'ordered.json')
    finally:
     if lock is not None:os.close(lock)
    self.assertEqual(len(bindings),1)
    if role=='good':self.assertEqual(len(calls),1);self.assertEqual(result['status'],'PASS_RUNTIME_RETIRED_BEFORE_ORIGINAL_PRODUCER');self.assertEqual(result['runtime_retirement']['GUI'],'FAILED_NOT_ACCEPTED')
    else:self.assertEqual(calls,[]);self.assertEqual(result['status'],'FAIL');self.assertEqual(result['producer'],'NOT_RETIRED')
 def test_isolated_constructor_exact_and_complete_workflow_aliases_held(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'new';p=subprocess.run([sys.executable,'-I','-B','-Werror',str(D/'prepare.py'),'--failure-cleanup','--predecessor-root',str(PARENT),'--output',str(out)],capture_output=True,timeout=10);self.assertEqual(p.returncode,0,p.stderr)
   before=obj(D/'failure-cleanup-profile.json')['after'];self.assertEqual({p.relative_to(out).as_posix():H.pin(p.read_bytes())for p in out.rglob('*')if p.is_file()},before)
  for n in('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current606-welcome8-gui.yml'):self.assertEqual((SOURCE/n).read_bytes(),(PARENT/n).read_bytes())
if __name__=='__main__':unittest.main(verbosity=2)
