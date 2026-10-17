# SPDX-License-Identifier: MIT
"""Original public bytes and finite source derivations; no native positive fixture."""
import ast,copy,importlib.util,json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare as P
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('CAA3_PUBLIC_ROUTE_SOURCE',next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())))
PACKET=Path(os.environ.get('CAA3_PUBLIC_ROUTE_PACKET',ROOT/'artifacts/development/maintained-caa3-public-input-route-20261017/public-inputs/payload'))
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.temp=tempfile.TemporaryDirectory();cls.addClassCleanup(cls.temp.cleanup);cls.base=Path(cls.temp.name)
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')):cls.receipt=P.derive(ROOT,cls.base/'derived')
  cls.out=cls.base/'derived'
 def setUp(self):
  p=patch.object(subprocess,'Popen',side_effect=AssertionError('actors/Git/network forbidden'));p.start();self.addCleanup(p.stop)
 def test_actual_public21_and_original_both13_compiler_checks(self):
  v=P.validate_packet(ROOT,PACKET);self.assertEqual(v['files'],21);self.assertEqual(v['compile_pair']['run_id'],38994309021);self.assertEqual(v['normal_compiler_receipts'],'PASS_ORIGINAL_BOTH13_COMMAND_CHECKS');self.assertIn('NOT_ALPM_OR16K',v['status'])
 def test_default_unbound_before_any_output_or_actor(self):
  with tempfile.TemporaryDirectory() as td:
   fixture=Path(td);(fixture/'policy.json').write_bytes(P.encoded(dict(status='UNBOUND_CAA3_PUBLIC_COMPILE_NATIVE_ROUTE',authorization=None,packet=None,future_native_ALPM_authority=None)))
   with patch.object(P,'HERE',fixture),self.assertRaisesRegex(ValueError,'UNBOUND'):P.emit(ROOT,self.base/'never')
  self.assertFalse((self.base/'never').exists());policy=json.loads((self.out/(P.NEW+'-owner')/'policy.json').read_bytes());self.assertIsNone(policy['packet']);self.assertIn('UNBOUND',policy['status'])
 def test_wrong_index_and_missing_extra_or_alias_refuse(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);(root/'packet.json').write_bytes(b'{}')
   with self.assertRaisesRegex(ValueError,'132aec'):P.validate_packet(ROOT,root)
   (root/'packet.json').write_bytes((PACKET/'packet.json').read_bytes())
   with self.assertRaisesRegex(ValueError,'closure'):P.validate_packet(ROOT,root)
   (root/'packet.json').unlink();(root/'packet.json').symlink_to(PACKET/'packet.json')
   with self.assertRaises(ValueError):P.validate_packet(ROOT,root)
   complete=root/'complete';shutil.copytree(PACKET,complete);p=complete/'source-proof.json';p.write_bytes(p.read_bytes()+b'\n')
   with self.assertRaisesRegex(ValueError,'reference differs'):P.validate_packet(ROOT,complete)
 def test_all_transaction_runtime_copy_config_caps_and_cleanup_modules_byteexact(self):
  for n in ('container.py','run.py','scrub.py','dependencies.json','normal-exec-change.json','smoke-normal.c','input-policy.json','candidate_gate.py'):
   self.assertEqual((self.out/P.NEW/n).read_bytes(),(self.out/P.PRIOR/n).read_bytes(),n)
  for n in ('snapshot.py','capability_snapshot.py'):self.assertEqual((self.out/(P.NEW+'-owner')/n).read_bytes(),(self.out/(P.PRIOR+'-owner')/n).read_bytes())
 def test_common_only_two_input_functions_differ(self):
  def funcs(p):return {n.name:ast.get_source_segment(p.read_text(),n) for n in ast.parse(p.read_bytes()).body if isinstance(n,ast.FunctionDef)}
  a,b=funcs(self.out/P.PRIOR/'common.py'),funcs(self.out/P.NEW/'common.py');self.assertEqual({n for n in a if a[n]!=b[n]},{'validate_candidate_inputs'})
  first=lambda p:ast.get_source_segment(p.read_text(),next(n for n in ast.parse(p.read_bytes()).body if isinstance(n,ast.FunctionDef) and n.name=='configuration'))
  before,after=first(self.out/P.PRIOR/'common.py'),first(self.out/P.NEW/'common.py');self.assertNotEqual(before,after);self.assertIn("value['status']=='ROOT_BOUND_CAA3_PUBLIC_COMPILE_NATIVE_LIFECYCLE'",after);self.assertNotIn("value['private16k']",after)
 def test_owner_only_packet_materialize_functions_differ_and_original_operations_held(self):
  def funcs(p):return {n.name:ast.get_source_segment(p.read_text(),n) for n in ast.parse(p.read_bytes()).body if isinstance(n,ast.FunctionDef)}
  a,b=funcs(self.out/(P.PRIOR+'-owner')/'job.py'),funcs(self.out/(P.NEW+'-owner')/'job.py');self.assertEqual({n for n in a if a[n]!=b[n]},{'packet','materialize'})
  self.assertIn("public_input_index=ref(inputs,inputs/'packet.json')",b['materialize']);self.assertIn('3800',b['execute_leased']);self.assertEqual(a['cleanup'],b['cleanup']);self.assertEqual(a['snapshot_source'],b['snapshot_source']);self.assertEqual(a['retain'],b['retain'])
 def test_generated_manifests_close_every_new_gate_and_public_phase(self):
  root=self.out/(P.NEW+'-owner');value=json.loads((root/'integration-manifest.json').read_bytes())
  for n,row in value['files'].items():self.assertEqual(P.pin((self.out/n).read_bytes()),row,n)
  common=P.load('inert_public_native_common',self.out/P.NEW/'common.py');index=json.loads((PACKET/'packet.json').read_bytes());receipt=common.validate_candidate_inputs(PACKET,index);self.assertEqual(receipt['phase'],'NATIVE_COMPILE_INPUTS_ONLY_NO_INSTALLATION_OR16K_ACCEPTANCE')
  gate=common.load('public_phase_gate_control',self.out/P.NEW/'public_gate.py');bad=copy.deepcopy(index);bad['private16k']={}
  with self.assertRaisesRegex(ValueError,'exact public packet'):gate.validate(common,PACKET,bad)
 def test_no_unpublished_metadata_or_fabricated_root_private_receipt(self):
  text=(HERE/'prepare.py').read_text()+(HERE/'public_gate.py').read_text();self.assertNotIn('e6e04dd',text);self.assertNotIn('lifecycle-source-map.json',text);self.assertNotIn('acceptance/private16k.json',text)
  value=json.loads((PACKET/'packet.json').read_bytes());self.assertNotIn('private16k',value);self.assertEqual(set(value['files']),{p.relative_to(PACKET).as_posix() for p in PACKET.rglob('*') if p.is_file()}-{'packet.json'})
 def test_manual_workflow_refuses_default_before_original_actors_and_preserves_order(self):
  text=(HERE.parents[2]/P.WF).read_text();positions=[text.index(t) for t in ('id: adaptation','id: proof','id: packet','secrets.','Reuse unchanged owned574','"$SLICE/job.py" execute','"$SLICE/job.py" cleanup','"$SLICE/job.py" retain','--retain-exit "$retain_status"','uses: actions/upload-artifact')];self.assertEqual(positions,sorted(positions))
  for marker in ('timeout-minutes: 180','timeout-minutes: 80','timeout-minutes: 15','2300s','cancel-in-progress: false',P.ROUTE+'/prepare.py emit','CAA3_PUBLIC_ROUTE_PACKET=',P.NEW+'-owner'):self.assertIn(marker,text)
  self.assertIn(P.pin((HERE/'prepare.py').read_bytes())['sha256'],text);self.assertIn(P.pin((HERE/'source-pins.json').read_bytes())['sha256'],text)
  self.assertNotIn('e6e04dd',text);self.assertNotIn('apparmor=unconfined',text);self.assertNotIn('--privileged',text)


class SummaryClosure(unittest.TestCase):
 def test_exact_helper_is_closed_and_declared_before_secrets(self):
  helper='scripts/ci/glibc-gnu-failure-log/summary.py';expected=dict(bytes=11924,sha256='9bd52ce4453a3a03d8dc8b5edb6b6a4b8ec421e0c3037dfb64dc31da45687555')
  table=json.loads((HERE/'source-pins.json').read_bytes());rows=table['files']
  self.assertEqual(rows[helper],expected);self.assertEqual(P.pin((ROOT/helper).read_bytes()),expected)
  text=(ROOT/'.github/workflows/native-arm-glibc-debian-maintained-public-provider-lifecycle.yml').read_text();self.assertLess(text.index('Verify exact retained diagnostic helper before secrets'),text.index('secrets.'));self.assertIn('summary.py" --help',text);self.assertIn(expected['sha256'],text)
 def test_closed_view_old_missing_hash_refuses_and_corrected_helper_help_runs(self):
  with tempfile.TemporaryDirectory(prefix='caa3-summary-closed-') as td:
   work=Path(td);closed=work/'closed'
   with patch.object(subprocess,'Popen',side_effect=AssertionError('source emission cannot start actors')):
    P.derive(ROOT,closed)
   helper=closed/'scripts/ci/glibc-gnu-failure-log/summary.py';raw=helper.read_bytes();self.assertEqual(P.pin(raw)['sha256'],'9bd52ce4453a3a03d8dc8b5edb6b6a4b8ec421e0c3037dfb64dc31da45687555')
   manifest=(P.pin(raw)['sha256']+'  '+str(helper)+'\n').encode();helper.unlink()
   before=subprocess.run(['/usr/bin/sha256sum','--check'],input=manifest,capture_output=True,cwd=work,timeout=10);self.assertNotEqual(before.returncode,0);self.assertIn(b'No such file or directory',before.stderr)
   helper.write_bytes(raw);after=subprocess.run(['/usr/bin/sha256sum','--check'],input=manifest,capture_output=True,cwd=work,timeout=10);self.assertEqual(after.returncode,0)
   help=subprocess.run([os.sys.executable,'-I','-B',str(helper),'--help'],capture_output=True,cwd=work,timeout=10);self.assertEqual(help.returncode,0,help.stderr);self.assertLess(len(help.stdout+help.stderr),65536);self.assertIn(b'emit',help.stdout);self.assertIn(b'extract',help.stdout)

if __name__=='__main__':unittest.main(verbosity=2)
