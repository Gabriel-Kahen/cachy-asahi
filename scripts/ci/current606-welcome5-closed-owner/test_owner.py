"""Source/emission/real argv controls; no accepting606 decision or native fixture."""
import ast,copy,importlib.util,json,os,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import contract as C,owner as O,runtime as R,selection as S,prepare as E
class Owner(unittest.TestCase):
 def test_real_four_complete_source_roles(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   fact=C.verify();self.assertEqual(fact['roles']['held606'],263);self.assertEqual(fact['roles']['heldwelcome'],99)
 def test_actual_default_authority_before_actors(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   with self.assertRaisesRegex(ValueError,'NULL/UNBOUND'):O.main(['--require-selection'])
   with self.assertRaisesRegex(ValueError,'NULL/UNBOUND'):O.main([])
 def test_counted_complete_owner_and_capture_derivations(self):
  P,A,X,old=O.source_context(C.ROOT);raw=A.owner(P.ROOT);derived=O.owner_program(raw)
  self.assertIn('active.process.wait(timeout=1800)',derived);self.assertIn('signal.setitimer(signal.ITIMER_REAL,6600)',derived)
  self.assertEqual(derived.count('Y.complete(active,report)'),1);self.assertEqual(derived.count('Y.failure(active,absence,report)'),1)
  original=(P.HERE/'tools606.py').read_text();capture=O.capture_program(original);self.assertEqual(capture.replace(O.CAPTURE_HOOK,O.CAPTURE_LINE),original)
  self.assertLess(capture.index("install('same-version606')"),capture.index("bridge=runpy"));self.assertLess(capture.index("bridge=runpy"),capture.index("remove('remove604')"))
  self.assertIn('return previous_ld,previous_aux',capture)
 def actual_capture(self):
  P,A,X,old=O.source_context(C.ROOT);tree=ast.parse(O.owner_program(A.owner(P.ROOT)));main=next(x for x in tree.body if isinstance(x,ast.FunctionDef)and x.name=='main');body=next(x.body for x in main.body if isinstance(x,ast.Try));start=next(i for i,x in enumerate(body)if isinstance(x,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='name'for t in x.targets));stop=next(i for i,x in enumerate(body[start:],start)if isinstance(x,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='command'for t in x.targets)and isinstance(x.value,ast.Call)and isinstance(x.value.func,ast.Attribute)and x.value.func.attr=='launch')
  code=ast.Module(body=body[start:stop],type_ignores=[]);scope={'os':os,'owned':types.SimpleNamespace(token='1'*32),'Y':types.SimpleNamespace(nonce='2'*32,measurement=Path('/owned/measurement')),'HERE':Path('/owned/held-runner'),'ready':Path('/owned/original'),'target':Path('/owned/target'),'planroot':Path('/owned/plan'),'runner606':Path('/owned/runner'),'tools606':Path('/owned/tools606'),'args':types.SimpleNamespace(code=Path('/owned/code'),legacy_source=Path('/owned/combined')),'resultdir':Path('/owned/out')};exec(compile(code,'<actual-counted-owner-argv>','exec'),scope);return scope['command']
 def test_actual_capture_argv_matches_bridge_mount_runtime_allowlist(self):
  argv=self.actual_capture();rows=O.parse_mounts(argv);B=C.module('_owned_bridge_contract',C.ROOT/'bridge/scripts/ci/current606-welcome5-source-bridge/bridge.py')
  apis=B.load_apis(C.ROOT/'bridge');self.assertEqual({r['target'].lstrip('/')for r in rows},B.INFRA);self.assertEqual(apis.scope.INFRASTRUCTURE,B.INFRA)
  self.assertEqual(apis.scope.MOUNT_FILES,{'etc/hosts','etc/hostname','etc/resolv.conf'});self.assertTrue({'proc','sys','dev','run','tmp'}<=apis.scope.RUNTIME)
  self.assertEqual(tuple(t.split('=',1)[1]for t in argv if t.startswith('--cap-add=')),S.CAPS['capture']);self.assertEqual(sum(not r['readonly']for r in rows),2)
  self.assertIn('--env=CAA_CURRENT606_BRIDGE='+'2'*32,argv);self.assertIn('--network=none',argv);self.assertNotIn('--rm',argv);self.assertNotIn('--privileged',argv)
 def test_actual_worker_argv_matches_worker_typed_guard(self):
  paths={n:Path('/owned')/n for n in('runner','seed','proof','work','out')};argv=R.argv('worker','sha256:'+'1'*64,'2'*32,paths)
  W=C.module('_owned_worker_contract',C.ROOT/'copyworker/scripts/ci/current606-welcome5-copy/contract.py');self.assertTrue(W.bindings(O.parse_mounts(argv)));self.assertEqual(tuple(t.split('=',1)[1]for t in argv if t.startswith('--cap-add=')),W.WORKER_CAPS)
  bad=O.parse_mounts(argv);bad[1]['readonly']=False
  with self.assertRaises(ValueError):W.bindings(bad)
 def test_whole_owner_api_is_exact_in_both_components(self):
  actual=C.pin((HERE/'selection.py').read_bytes());bridge=C.read(C.ROOT/'bridge/scripts/ci/current606-welcome5-source-bridge/owner-api.json');worker=C.read(C.ROOT/'copyworker/scripts/ci/current606-welcome5-copy/owner-api.json')
  self.assertEqual(bridge,dict(path='/runner/owner/selection.py',pin=actual));self.assertEqual(worker,dict(path='/runner/owner/selection.py',**actual))
 def test_fresh_emission_default_and_all_bash_hash_pairs(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   output=Path(d)/'source';inputs={r:C.ROOT/r for r in C.ROLES};auth=E.emit(inputs,output)
   self.assertEqual(len(auth),len(C.read(HERE/'source-manifest.json')['files'])+3)
   wf=(output/'.github/workflows/native-arm-build.yml').read_text();self.assertEqual(wf,(output/'.github/workflows/native-arm-current606-welcome5-owned-copy.yml').read_text())
   self.assertIn('/'+C.LANE+'/owner.py"',wf);self.assertIn('--require-selection',wf)
   workspace=Path(d)/'workspace';workspace.mkdir();(workspace/'expanded604-code').symlink_to(output)
   commands=[line.strip()for line in wf.splitlines()if 'expanded604-code/'in line and ('| sha256sum --check'in line or('test "$(sha256sum 'in line))]
   self.assertGreaterEqual(len(commands),4)
   for command in commands:subprocess.run(['bash','-euo','pipefail','-c',command],cwd=workspace,check=True,capture_output=True)
   self.assertTrue(all(x is None for x in json.loads((output/C.LANE/'input-policy.json').read_bytes())['current606'].values()))
 def test_second_source_role_drift_refuses_before_output(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   output=Path(d)/'forbidden';inputs={r:C.ROOT/r for r in C.ROLES};inputs['heldwelcome']=C.ROOT/'held606'
   with self.assertRaisesRegex(ValueError,'whole role set'):E.emit(inputs,output)
   self.assertFalse(output.exists())
 def test_real_untouched_measurement_cleanup_before_any_actor(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   i=O.Integration(C.ROOT,None,None,{});i.measurement=Path(d)/'measurement';i.measurement.mkdir(mode=0o700);i.lease=R.measurement_lease(i.measurement)
   with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):i.failure(None,True,{})
   self.assertFalse(i.measurement.exists())
 def test_only_two_fixed_capture_selection_data_exports(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   out=Path(d);(out/'plan').mkdir();(out/'plan/private-map.json').write_text('{}')
   owner=O.Integration(C.ROOT,types.SimpleNamespace(export_names=lambda _:[]),None,{})
   self.assertEqual(owner.export_names(out),['container/bridge-capture.json','plan/bridge-selection.json'])
 def test_realistic_primary_git_file_or_directory_metadata_allowed(self):
  from unittest.mock import patch
  for kind in('file','directory'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory(dir=HERE)as d:
    root=Path(d)/'source';E.emit({r:C.ROOT/r for r in C.ROLES},root)
    if kind=='file':(root/'.git').write_text('gitdir: /owned/metadata\n')
    else:
     (root/'.git/objects').mkdir(parents=True);(root/'.git/objects/ordinary').write_text('metadata');(root/'.git/config').write_text('[core]\n')
    with patch.object(C,'HERE',root/C.LANE):self.assertEqual(C.verify(root)['files'],len(C.read(root/C.LANE/'source-manifest.json')['files'])+3)
 def test_only_git_metadata_excluded_unknown_root_private_refuses(self):
  from unittest.mock import patch
  for name in('.git-shadow','private/unexpected'):
   with self.subTest(path=name),tempfile.TemporaryDirectory(dir=HERE)as d:
    root=Path(d)/'source';E.emit({r:C.ROOT/r for r in C.ROLES},root);(root/'.git').mkdir();(root/'.git/metadata').write_text('ignored');p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('unexpected source')
    with patch.object(C,'HERE',root/C.LANE),self.assertRaisesRegex(ValueError,'closed exact owner source closure'):C.verify(root)
 def test_advertised_source_drift_refuses_with_git_metadata(self):
  from unittest.mock import patch
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   root=Path(d)/'source';E.emit({r:C.ROOT/r for r in C.ROLES},root);(root/'.git').write_text('gitdir: /owned/metadata\n');p=root/C.LANE/'selection.py';p.write_bytes(p.read_bytes()+b'\n# drift\n')
   with patch.object(C,'HERE',root/C.LANE),self.assertRaisesRegex(ValueError,'whole source differs'):C.verify(root)
 def test_unknown_measurement_never_removed(self):
  with tempfile.TemporaryDirectory(dir=HERE)as d:
   i=O.Integration(C.ROOT,None,None,{});i.measurement=Path(d)/'measurement';i.measurement.mkdir(mode=0o700);i.lease=R.measurement_lease(i.measurement);p=i.measurement/'unknown';p.write_bytes(b'held')
   with self.assertRaisesRegex(ValueError,'unknown partial capture retained'):i.failure(None,True,{})
   self.assertEqual(p.read_bytes(),b'held')
if __name__=='__main__':unittest.main()
