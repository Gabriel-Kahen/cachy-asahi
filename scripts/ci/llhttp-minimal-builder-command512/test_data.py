# SPDX-License-Identifier: MIT
"""Actual6651 source inverse plus MODEL guards/time/catalogs; no native actor."""
import argparse,ast,copy,importlib.util,json,math,os,tempfile,types,unittest
from pathlib import Path
H=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('minimal512',H/'prepare.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
a=argparse.ArgumentParser(add_help=False);a.add_argument('--parent',type=Path,default=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-llhttp-minimal-builder-source-readiness-20261117-r4/constructed-source'));ARGS,REST=a.parse_known_args()
class Clock:
 def __init__(self):self.n=0
 def monotonic(self):return self.n
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(c):
  c.old=P.parent_bodies(ARGS.parent);c.b=P.assemble(c.old);c.t=tempfile.TemporaryDirectory(prefix='minimal512-data-');c.root=Path(c.t.name)/'Source';c.report=P.construct(ARGS.parent,c.root);sp=importlib.util.spec_from_file_location('minimal512_data',c.root/P.NO/'data.py');c.D=importlib.util.module_from_spec(sp);sp.loader.exec_module(c.D);c.E={};exec(compile(c.b[P.NO+'public_evidence.py'],'<fixed finite exporter>','exec'),c.E)
 @classmethod
 def tearDownClass(c):c.t.cleanup()
 def test_genuine6651_full96_inverse_and_old95_chain(self):
  self.assertEqual(P.inverse(self.b),self.old);self.assertEqual(len(self.b),96);self.assertLess(sum(map(len,self.b.values())),2*1024**2);self.assertEqual(P.tree(P.predecessor95(P.inverse(self.b))),'b73f92b1ed4e6f6ab8c4210fdaa19617b1a5721f');self.D.source(self.root,P.pin(self.b['source-map.json'])['sha256'])
 def test_default_missing_operand_refuses_without_output(self):
  with tempfile.TemporaryDirectory(prefix='minimal512-refusal-')as t:
   out=Path(t)/'not-created';self.assertRaises((ValueError,FileNotFoundError),P.construct,Path(t)/'absent-parent',out);self.assertFalse(out.exists())
 def test_historical_compression_reused_without_recompression(self):
  original=P.zlib.compress
  def forbidden(*args):raise AssertionError('no recompression of historical ledger')
  try:
   P.zlib.compress=forbidden;self.assertEqual(P.inverse(self.b),self.old)
  finally:P.zlib.compress=original
 def test_no_new_leaf_or_copied_old_map(self):
  self.assertEqual(set(self.b),set(self.old));m=P.decode(self.b[P.MARKER]);old=P.decode(self.old[P.MARKER]);self.assertIn(P.EXT,m);m.pop(P.EXT);self.assertEqual(m,old);self.assertNotIn('body_base64',P.encode(m[P.EXT]if P.EXT in m else{}).decode());self.assertEqual({n for n in self.old if self.old[n]!=self.b[n]},set(P.CHANGED))
 def test_unrelated_resources_inputs_workflow_recipe_and_Root_guards_unchanged(self):
  old=P.decode(self.old[P.NO+'policy.json']);new=P.decode(self.b[P.NO+'policy.json']);new.pop('command_ledger');new['inner_public_retention']=old['inner_public_retention'];self.assertEqual(old,new)
  for n in self.old:
   if n not in P.CHANGED:self.assertEqual(self.b[n],self.old[n],n)
  self.assertEqual(self.b[P.NB+'profile.json'],self.old[P.NB+'profile.json']);self.assertTrue(all(v is None for v in self.report['actual'].values()));self.assertIsNone(self.report['native'])
 def test_mutated_bodies_marker_membership_refuse(self):
  for n in(P.NB+'entry.py',P.NO+'hosted_owner.py',P.NO+'public_evidence.py',P.NO+'policy.json',P.MARKER,'source-map.json'):
   d=dict(self.b);d[n]+=b'x';self.assertRaises((ValueError,KeyError,json.JSONDecodeError),P.inverse,d)
  d=dict(self.b);d['MODEL_extra']=b'never';self.assertRaises(ValueError,P.inverse,d)
 def test_corrupt_original_parent_refuses(self):
  d=dict(self.old);d[P.NB+'runtime/scripts/ci/inputs.lock.json']+=b'x';self.assertRaises(ValueError,P.validate_parent,d)
 def test_inner512_boundary_pre_child_actual_AST_MODEL(self):
  node=next(n for n in ast.walk(ast.parse(self.b[P.NB+'entry.py']))if isinstance(n,ast.FunctionDef)and n.name=='__call__');guard=ast.FunctionDef(name='guard',args=ast.arguments(posonlyargs=[],args=[ast.arg(arg='self')],kwonlyargs=[],kw_defaults=[],defaults=[]),body=node.body[0].body[:3],decorator_list=[]);scope=dict(C=types.SimpleNamespace(need=P.need),time=Clock());exec(compile(ast.fix_missing_locations(ast.Module(body=[guard],type_ignores=[])),'<actual count gate only>','exec'),scope);o=types.SimpleNamespace(rows=[None]*511,state=types.SimpleNamespace(pending=False,cleaning=False),end=100,cleanup_end=100);scope['guard'](o);o.rows.append(None);self.assertRaises(ValueError,scope['guard'],o)
 def test_outer512_boundary_unchanged_pre_child_MODEL(self):
  node=next(n for n in ast.walk(ast.parse(self.b[P.NO+'hosted_owner.py']))if isinstance(n,ast.FunctionDef)and n.name=='run');stmt=next(n for n in node.body if isinstance(n,ast.Expr)and 'len(self.commands)'in ast.unparse(n));scope=dict(D=types.SimpleNamespace(need=P.need),self=types.SimpleNamespace(commands=[None]*511));code=compile(ast.fix_missing_locations(ast.Module(body=[stmt],type_ignores=[])),'<actual outer gate only>','exec');exec(code,scope);scope['self'].commands.append(None);self.assertRaises(ValueError,exec,code,scope)
 def test_full_lifetime_clipped_cadence_MODEL_clock(self):
  tree=ast.parse(self.b[P.NO+'hosted_owner.py']);start=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='start');main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');args=[next(n.args[0]for n in ast.walk(fn)if isinstance(n,ast.Call)and ast.unparse(n.func)=='time.sleep')for fn in(start,main)]
  def count(expr,end):
   clock=Clock();n=0
   while clock.n<end:
    n+=1;wait=eval(compile(ast.Expression(body=expr),'<actual cadence only>','eval'),dict(time=clock,until=end,owner=types.SimpleNamespace(end=end)));self.assertGreater(wait,0);self.assertLessEqual(clock.n+wait,end);clock.n+=wait
   return n
  self.assertLessEqual(count(args[0],30),31);self.assertLessEqual(count(args[1],1650),166);self.assertEqual(count(args[1],.5),1);self.assertEqual(1+5+2*(1+1+31)+1+166+1+2*4+5,253);self.assertLess(253,512)
 def test_all208_GPG_plus_cleanbuilds_and_cleanup_fit(self):
  native=P.decode(self.b[P.NB+'runtime/scripts/ci/inputs.lock.json']);audit=1+(len(native['packages'])+1);self.assertEqual(audit,208);normal=audit+6+6+1+3+4;conservative=normal-3+3*5;self.assertEqual((normal,conservative),(228,240));self.assertLess(conservative,512)
 def test_fixed_catalog_all512_complete_under_same16MiB(self):
  E=self.E;self.assertEqual(len(E['PUBLIC_LEAVES']),1582);self.assertIn('commands/511.stderr',E['PUBLIC_LEAVES']);self.assertNotIn('commands/512.json',E['PUBLIC_LEAVES']);self.assertEqual(E['MAX_BYTES'],16*1024**2);self.assertEqual(E['SUCCESS_REQUIRED'],tuple(P.decode(self.old[P.NO+'policy.json'])['inner_public_retention']['success_required']));self.assertLess(len(E['PUBLIC_LEAVES'])+1,4096)
 def test_MODEL_failure_receipts_still_nonaccepting_before_cleanup(self):
  expected=dict(source='1'*40,ref='refs/heads/codex/MODEL',source_map_sha256='2'*64,run='123456',attempt=1,job='pair',nonce='3'*32)
  with tempfile.TemporaryDirectory(prefix='MODEL-minimal512-failure-')as t:
   root=Path(t);inner=root/'volume/work/llhttp-minimal-builder-native';inner.mkdir(parents=True);(inner/'report.json').write_bytes(P.encode(dict(expected,status='HOLD',Root_acceptance=None,hardware='NOT RUN',release='NOT ADMITTED')));(inner/'cleanup.json').write_bytes(b'{}\n');row=self.E['export'](inner,root/'evidence',expected,os.getuid());self.assertEqual(row['status'],'EXPORTED');self.assertFalse(row['accepting'])
  code=self.b[P.NO+'hosted_owner.py'].decode();self.assertLess(code.index('E.preserve('),code.index("report['cleanup']=owner.cleanup("));self.assertIn('argv=Q.project_service',code)
 def test_no_actual_provider_authority_or_actor_on_export(self):
  for n,b in self.b.items():
   if n.endswith('.py'):ast.parse(b,filename=n)
  self.assertTrue(all(v is None for v in P.decode(self.b['source-map.json'])['actual'].values()));self.assertIsNone(self.report['Root_selection']);self.assertIsNone(self.report['publication']);self.assertIsNone(self.report['signature_authentication'])
if __name__=='__main__':unittest.main(argv=['test_data.py',*REST],verbosity=2)
