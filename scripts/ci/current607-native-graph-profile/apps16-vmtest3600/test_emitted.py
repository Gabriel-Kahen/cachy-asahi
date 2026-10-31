# SPDX-License-Identifier: MIT
"""Controlled clocks and original whole-body inverses; no native actor or shortened graphs."""
import ast,copy,json,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[2]
import sys
sys.path.insert(0,str(ROOT/'latest/implementation'))
import latest_plan as P,latest_graph_timing as T,validation_capacity as C
NAME='latest/implementation/validation-capacity-parent.json';RAW=(ROOT/NAME).read_bytes();WANT=C.pin(RAW)
class Controls(unittest.TestCase):
 def test_closed_profile_finite_inverse_all_other_runtime_bodies_held(self):
  p,actual,mf=C.inspect(ROOT,NAME,WANT);self.assertEqual((len(p['before']),len(actual)),(849,853));self.assertEqual(len(p['added']),4);self.assertEqual(len(p['before_bodies']),7);self.assertFalse(C.PROFILE['consumer_difference_is_guaranteed_margin']);self.assertEqual(C.PROFILE['outer4200_fit'],'NOT_ESTABLISHED')
  with C.parent(ROOT,p)as(old,bodies):
   for n in p['before']:
    if n not in p['before_bodies']:self.assertEqual((ROOT/n).read_bytes(),bodies[n],n)
   for n,edits in p['edits'].items():
    text=(ROOT/n).read_text()
    for a,b in reversed(edits):self.assertEqual(text.count(b),1);text=text.replace(b,a,1)
    self.assertEqual(text.encode(),bodies[n])
   for n in('latest_component.py','held/package_graph.py','latest_setup.py','latest_owner.py','latest_validate.py','latest_fixture.py','step_entry.py','sixcap_api.py'):
    path='latest/implementation/'+n
    if path in p['before']:self.assertEqual(actual[path],p['before'][path])
 def test_other_clock_work_scope_and_profile_drift_refusals(self):
  original=dict(P.BOUNDS)
  for key in original:
   if key=='component':continue
   with patch.dict(P.BOUNDS,{key:original[key]+1}),self.assertRaises(ValueError):C.inspect(ROOT,NAME,WANT)
  with patch.dict(P.BOUNDS,component=3601),self.assertRaises(ValueError):C.inspect(ROOT,NAME,WANT)
  with patch.object(P,'GRAPHS',64),self.assertRaises(ValueError):C.inspect(ROOT,NAME,WANT)
  with patch.object(T,'PROFILE','ACCEPTED'),self.assertRaises(ValueError):C.inspect(ROOT,NAME,WANT)
  with self.assertRaises(ValueError):C.inspect(ROOT,NAME,dict(WANT,sha256='0'*64))
 def test_single_shared_deadline_same_object_near_boundary_original_tick(self):
  text=(ROOT/'latest/implementation/latest_component.py').read_text();exercise=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='exercise');assigns=[n for n in ast.walk(exercise)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='deadline'for t in n.targets)];self.assertEqual(len(assigns),1);capture=next(n for n in exercise.body if isinstance(n,ast.FunctionDef)and n.name=='capture');self.assertEqual(sum(isinstance(n,ast.Name)and isinstance(n.ctx,ast.Store)and n.id=='deadline'for n in ast.walk(capture)),0)
  graph=ast.parse((ROOT/'latest/implementation/held/package_graph.py').read_text());tick=next(n for n in ast.walk(graph)if isinstance(n,ast.FunctionDef)and n.name=='tick');now=[100.0];calls=[]
  with tempfile.TemporaryDirectory(prefix='vmtest-shared-deadline-')as td,patch.object(T.time,'monotonic',side_effect=lambda:now[0]):
   env=dict(time=T.time,P=P);exec(compile(ast.fix_missing_locations(ast.Module(body=assigns,type_ignores=[])),'<exact-source-deadline>','exec'),env);deadline=env['deadline'];self.assertEqual(deadline,3700.0)
   original_tick=dict(time=T.time,deadline=deadline,need=C.need);exec(compile(ast.fix_missing_locations(ast.Module(body=[tick],type_ignores=[])),'<exact-held-graph-tick>','exec'),original_tick)
   def raw(root,rows,*,deadline):calls.append(deadline);original_tick['tick']();return dict(nodes={},bytes_read=0)
   timings=T.GraphTiming(Path(td)/'latest607-graph-timing.json','a'*32,deadline,lambda:'baseline606');scope=types.SimpleNamespace(capture=timings.wrap(raw));want={'fixture':'1'};env.update(g={'inventory':lambda:want},need=C.need,context={'driver':types.SimpleNamespace(database=lambda *a,**k:[dict(name='fixture',version='1')])},users=lambda:None,capture_scope=scope,Path=Path,mark=lambda operation:None);exec(compile(ast.fix_missing_locations(ast.Module(body=[capture],type_ignores=[])),'<exact-source-capture>','exec'),env)
   now[0]=2500.001;env['capture'](want);self.assertTrue(now[0]>100+2400);now[0]=3699.999;env['capture'](want);self.assertTrue(all(v is deadline for v in calls));self.assertEqual(len(calls),2);self.assertEqual({r['component_seconds']for r in[json.loads(timings.path.read_bytes())]},{3600})
   now[0]=3700.0
   with self.assertRaisesRegex(ValueError,'layered4200 deadline'):env['capture'](want)
   self.assertEqual(len(calls),2);self.assertIs(env['deadline'],deadline)
   with self.assertRaisesRegex(ValueError,'native package graph observation deadline'):original_tick['tick']()
 def test_all65_timing_rows_share_one_deadline_and_66_refuses(self):
  now=[100.0];deadline=3700.0;calls=[]
  with tempfile.TemporaryDirectory(prefix='vmtest-65-fixed-')as td,patch.object(T.time,'monotonic',side_effect=lambda:now[0]):
   t=T.GraphTiming(Path(td)/'latest607-graph-timing.json','b'*32,deadline,lambda:'baseline606')
   def capture(root,packages,**kwargs):calls.append(kwargs['deadline']);return dict(nodes={'x':{}},bytes_read=1)
   wrapped=t.wrap(capture)
   for n in range(65):now[0]+=1;wrapped(Path('/'),[],deadline=deadline)
   self.assertEqual(len(t.rows),65);self.assertTrue(all(v is deadline for v in calls));self.assertEqual(t.deadline,3700.0)
   with self.assertRaisesRegex(ValueError,'65 complete captures'):wrapped(Path('/'),[],deadline=deadline)
   with self.assertRaises(ValueError):t.wrap(capture)(Path('/'),[],deadline=3701)
 def test_source_entry_dispatches_whole_original849_then_new_controls(self):
  p=json.loads(RAW);raw=(ROOT/'next/test_source.py').read_text();env=dict(__name__='_source_entry_control',__file__=str(ROOT/'next/test_source.py'));exec(compile(raw,str(ROOT/'next/test_source.py'),'exec'),env);seen=[]
  def run(argv,**kwargs):
   if argv[-1].endswith('/next/test_source.py'):
    seen.append(('whole849',C.pin(Path(argv[-1]).read_bytes()),kwargs['timeout']))
   else:seen.append(('new',argv,kwargs['timeout']))
   return types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
  with patch.object(env['G'],'verify',return_value=dict(files=853)),patch.object(env['subprocess'],'run',side_effect=run):env['main']()
  self.assertEqual(seen[0],('whole849',p['before']['next/test_source.py'],180));self.assertEqual(seen[1][0],'new');self.assertIn('test_validation_capacity.py',seen[1][1]);self.assertEqual(seen[1][2],120)
 def test_whole_original849_guard_is_called_not_bypassed(self):
  reached=[];real=C.importlib.util.spec_from_file_location
  class Loader:
   def create_module(self,spec):return None
   def exec_module(self,module):module.verify=lambda:(reached.append('whole849')or dict(files=849))
  def spec(name,path):return C.importlib.util.spec_from_loader(name,Loader())if name=='_whole_original849_vmtest_guard'else real(name,path)
  with patch.object(C.importlib.util,'spec_from_file_location',side_effect=spec):fact=C.verify(ROOT,NAME,WANT)
  self.assertEqual(reached,['whole849']);self.assertEqual(fact['parent849']['files'],849);self.assertEqual(fact['files'],853)
if __name__=='__main__':unittest.main(verbosity=2)
