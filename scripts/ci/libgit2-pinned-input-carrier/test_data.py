# SPDX-License-Identifier: MIT
"""Real frozen501/static-code checks plus fenced MODEL clocks/counters; no builds."""
import ast,copy,importlib.util,json,math,os,tempfile,threading,types,unittest
from pathlib import Path
from unittest.mock import patch
H=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('libgit2_new_carrier',H/'prepare.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
def actual_static_v4():
 v=P.predecessor();root=P.ROOT/'scripts/ci/libgit2-reference-native-source';b={P.PREFIX+'hosted_owner.py':P.read(root/'owner/hosted_owner.py'),P.PREFIX+'payload.py':P.read(root/'owner/payload.py')};b[P.PREFIX+'hosted_owner.py']=v.P3.P2.project(b[P.PREFIX+'hosted_owner.py']);b.update(v.P3.projections(b)[0]);b.update(v.projections(b)[0]);return v,b
class Clock:
 def __init__(self,n=0):self.n=n
 def monotonic(self):return self.n
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.v,cls.b=actual_static_v4();cls.raw=P.read(P.ROOT/'scripts/ci/libgit2-reference-native-source/base/entry.py');cls.N=P.A.module();cls.projected=cls.N.project_entry(cls.raw);cls.owner,cls.seams=P.controller_projection(cls.b[P.PREFIX+'hosted_owner.py']);cls.payload,cls.ps=P.payload_projection(cls.b[P.PREFIX+'payload.py']);cls.E=types.ModuleType('libgit2_finite_public_export');exec(compile(P.A.public_runtime(),'<public exporter>','exec'),cls.E.__dict__)
 def test_ACTUAL501_and_all182_exact_archives_signatures_match(self):
  d=P.input_check(P.read(H/'fixtures/actual501.lock.json'));self.assertEqual(len(d['packages']),248);self.assertEqual(len(d['keyring_files']),3);self.assertEqual(P.pin(P.read(H/'fixtures/actual501.lock.json')),P.LOCK);self.assertEqual(json.loads(P.read(P.ROOT/'scripts/ci/libgit2-reference-native-source/base/profile.json'))['inputs_sha256'],P.LOCK['sha256'])
 def test_changed_input_lock_refuses_before_carrier(self):
  self.assertRaises(ValueError,P.input_check,P.read(H/'fixtures/actual501.lock.json')+b'x');self.assertRaises(ValueError,P.input_check,b'MODEL minimal206 or substitution')
 def test_exact29c2_namespace_projection_and_complete_original_inverse(self):
  raw=P.A.frozen('carrier.py');text=P.A.project(raw).decode()
  for before,after,count in reversed(P.A.EDITS):text=text.replace(after,before)
  self.assertEqual(text.encode(),raw);self.assertEqual(self.N.TOTAL,544634853);self.assertEqual(self.N.LARGEST,104330276);self.assertTrue('StrictHostKeyChecking=yes'in P.A.runtime().decode());self.assertEqual(len(self.N.FORBIDDEN),4)
 def test_unissued_binding_refuses_before_secret_or_command(self):
  class NoSecret(dict):
   def get(self,*a):raise AssertionError('no environment/credential access')
  with patch('subprocess.Popen',side_effect=AssertionError('no actor')),patch('subprocess.run',side_effect=AssertionError('no command')):self.assertRaisesRegex(ValueError,'unissued',self.N.fetch,Path('/MODEL/source'),Path('/MODEL/output'),environment=NoSecret())
 def test_provider_parent_default_refuses_before_output(self):
  with tempfile.TemporaryDirectory(prefix='MODEL-unissued-libgit2-')as t:
   out=Path(t)/'never-created';self.assertRaisesRegex(ValueError,'provider.*UNISSUED',P.construct,None,None,out);self.assertFalse(out.exists())
  T=P.load(P.ROOT/'scripts/ci/libgit2-reference-native-source/project_test.py','unissued_project_tuple');template=json.loads(P.read(P.ROOT/'scripts/ci/libgit2-reference-native-source/project-test.TEMPLATE.json'));self.assertTrue(all(x is None for x in template['expected']['pins'].values()));self.assertRaises(ValueError,T.validate_compatible_tuple,template['paths'],template['expected'],consumer_root=None)
 def test_held_entry_two_seams_inverse_and_audit_order(self):
  restored=self.projected.replace(b'len(self.rows)<512',b'len(self.rows)<160').replace(b"\n        PINNED_CARRIER.seed(PINNED_INPUTS,output/'cache')",b'');self.assertEqual(restored,self.raw);text=self.projected.decode();self.assertLess(text.index('seed.seed_current_build_cache('),text.index('PINNED_CARRIER.seed('));self.assertLess(text.index('PINNED_CARRIER.seed('),text.index('native.audit(inputs,'));self.assertLess(text.index('native.audit(inputs,'),text.index('image=native.build('));self.assertIn('X.verify_result(plan,',text);self.assertLess(text.index('X.verify_result('),text.index('C.plans('))
 def test_provider_current_GPG_normal_install_loader_and_smoke_preserved(self):
  dep=P.read(P.ROOT/'scripts/ci/libgit2-reference-native-source/dependency.py').decode();recipe=P.read(P.ROOT/'packages/libraries/cachy-asahi-libgit2-reference/PKGBUILD').decode()
  for token in("'--verify'","'EXPKEYSIG'","'NO_PUBKEY'","int(time.time())","SigLevel = Required TrustedOnly","LocalFileSigLevel = Required TrustedOnly","'-U','--noconfirm'","LLHTTP_PROJECT_TEST_RTLD_NOW_PASSED",'official_trust_before','database_after'):self.assertIn(token,dep)
  self.assertIn("-R '^(offline|util)$'",recipe);self.assertIn('smoke',recipe);self.assertNotIn('--nodeps',dep);self.assertNotIn('--nodeps',recipe);self.assertIn('expected350.lock',self.projected.decode())
 def test_controller_payload_full_seam_inverses(self):
  for raw,new,seams in((self.b[P.PREFIX+'hosted_owner.py'],self.owner,self.seams),(self.b[P.PREFIX+'payload.py'],self.payload,self.ps)):
   text=new.decode()
   for r in reversed(seams):text=text.replace(r['after'],r['before'])
   self.assertEqual(text.encode(),raw)
  self.assertIn('argv=Q.project_service',self.owner.decode());self.assertIn('F.retire_failed',self.owner.decode());self.assertIn('original_pidfd_identity',self.owner.decode());self.assertLess(self.owner.decode().index('E.preserve('),self.owner.decode().index("report['cleanup']=owner.cleanup("))
 def test_inner512th_allowed_513th_refused_before_child_MODEL(self):
  call=next(n for n in ast.walk(ast.parse(self.projected))if isinstance(n,ast.FunctionDef)and n.name=='__call__');block=call.body[0];self.assertIsInstance(block,ast.With);guard=ast.FunctionDef(name='guard',args=ast.arguments(posonlyargs=[],args=[ast.arg(arg='self')],kwonlyargs=[],kw_defaults=[],defaults=[]),body=block.body[:3],decorator_list=[]);space=dict(C=types.SimpleNamespace(need=P.need),time=Clock());exec(compile(ast.fix_missing_locations(ast.Module(body=[guard],type_ignores=[])),'<actual pre-child guard only>','exec'),space);obj=types.SimpleNamespace(rows=[None]*511,state=types.SimpleNamespace(pending=False,cleaning=False),cleanup_end=100,end=100);space['guard'](obj);obj.rows.append(None);self.assertRaises(ValueError,space['guard'],obj)
 def test_outer512th_allowed_513th_refused_before_child_MODEL(self):
  node=next(n for n in ast.walk(ast.parse(self.owner))if isinstance(n,ast.FunctionDef)and n.name=='run');guard=next(n for n in node.body if isinstance(n,ast.Expr)and 'len(self.commands)'in ast.unparse(n));space=dict(D=types.SimpleNamespace(need=P.need),self=types.SimpleNamespace(commands=[None]*511));code=compile(ast.fix_missing_locations(ast.Module(body=[guard],type_ignores=[])),'<actual outer count guard>','exec');exec(code,space);space['self'].commands.append(None);self.assertRaises(ValueError,exec,code,space)
 def test_max_authorized_lifetime_poll_count_MODEL_clock(self):
  tree=ast.parse(self.owner);start=next(n for n in ast.walk(tree)if isinstance(n,ast.FunctionDef)and n.name=='start');startup=next(n.args[0]for n in ast.walk(start)if isinstance(n,ast.Call)and ast.unparse(n.func)=='time.sleep');main=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='main');running=next(n.args[0]for n in ast.walk(main)if isinstance(n,ast.Call)and ast.unparse(n.func)=='time.sleep')
  def polls(expr,end,owner=False):
   c=Clock();count=0
   while c.n<end:
    count+=1;scope=dict(time=c,until=end,owner=types.SimpleNamespace(end=end));wait=eval(compile(ast.Expression(body=expr),'<actual clipped cadence>','eval'),scope);self.assertGreater(wait,0);self.assertLessEqual(c.n+wait,end);c.n+=wait
   return count
  self.assertLessEqual(polls(startup,30),31);self.assertLessEqual(polls(running,2850,True),286);outer=1+5+2*(1+1+31)+1+286+1+2*4+5;self.assertEqual(outer,373);self.assertLess(outer,512);self.assertLessEqual(polls(running,.5,True),1)
 def test_complete_held_normal_failure_cleanup_bound(self):
  audit=1+(248+1);normal=audit+6+2+6+6+1+5+6;conservative=normal-5+5*5;self.assertEqual((normal,conservative),(282,302));self.assertLess(conservative,512);self.assertIn('runner(plan[',self.raw.decode());self.assertIn('finisher.finish(',self.raw.decode())
 def test_public_finite_catalog_all512_commands_and_provider_receipts(self):
  self.assertEqual(len(self.E.PUBLIC_LEAVES),1585);self.assertIn('commands/000.json',self.E.PUBLIC_LEAVES);self.assertIn('commands/511.stderr',self.E.PUBLIC_LEAVES);self.assertNotIn('commands/512.json',self.E.PUBLIC_LEAVES);self.assertLess(len(self.E.PUBLIC_LEAVES)+1,4096);self.assertEqual(self.E.MAX_BYTES,16*1024**2)
  for n in('project-test.json','project-test-inventory.lock','project-test-evidence.json'):self.assertIn(n,self.E.SUCCESS_REQUIRED)
 def test_failed_public_receipt_export_MODEL_only(self):
  expected=dict(source='1'*40,ref='refs/heads/codex/MODEL',source_map_sha256='2'*64,run='123456',attempt=1,job='pair',nonce='3'*32)
  with tempfile.TemporaryDirectory(prefix='MODEL-libgit2-failure-')as t:
   root=Path(t);inner=root/'volume/work/libgit2-reference-native';inner.mkdir(parents=True);public=root/'evidence';r=dict(expected,status='HOLD',Root_acceptance=None,hardware='NOT RUN',release='NOT ADMITTED',failure=dict(type='MODEL_ONLY'));(inner/'report.json').write_bytes(P.encode(r));(inner/'cleanup.json').write_bytes(b'{}\n');row=self.E.export(inner,public,expected,os.getuid());self.assertEqual(row['status'],'EXPORTED');self.assertFalse(row['accepting']);self.assertEqual(json.loads((public/'report.json').read_bytes())['status'],'HOLD')
 def test_forbidden_stored_or_unreachable_object_refuses(self):
  oid=next(iter(self.N.FORBIDDEN));self.assertRaises(ValueError,self.N.metadata_guard,(oid+' blob\n').encode(),b'');self.assertRaises(ValueError,self.N.metadata_guard,b'',(oid+' path\n').encode())
 def test_dedicated_workflow_secret_only_in_four_minute_fetch(self):
  w=P.workflow(P.read(H/'frozen/libgit2-workflow.yml.in')).decode();self.assertEqual(w,(H/'workflow.yml.in').read_text());self.assertEqual(w.count('CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY:'),1);fetch=w[w.index('      - name: Root-admitted exact private'):w.index('      - name: Admitted existing-host')];rest=w[w.index('      - name: Admitted existing-host'):];self.assertIn('timeout-minutes: 4',fetch);self.assertIn('CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY',fetch);self.assertNotIn('CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY',rest);self.assertIn('timeout-minutes: 55',w);self.assertIn('timeout-minutes: 50',rest)
if __name__=='__main__':unittest.main(verbosity=2)
