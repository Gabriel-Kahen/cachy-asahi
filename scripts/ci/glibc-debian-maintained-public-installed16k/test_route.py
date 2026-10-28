# SPDX-License-Identifier: MIT
"""Source/temporary-data controls only; modeled decisions are never authorities."""
import ast,copy,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
s=importlib.util.spec_from_file_location('public_installed_test',HERE/'prepare.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
COMPONENT=Path(os.environ['CAA3_PUBLIC_NATIVE_SOURCE'])
class Controls(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup);self.work=Path(self.t.name);self.no=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors'));self.no.start();self.addCleanup(self.no.stop)
 def emitted(self):
  out=self.work/'emitted';r=P.derive(ROOT,COMPONENT,out);C=P.load('public_test_contract',out/P.LANE/'contract.py');return out,r,C
 def test_exact_source_roles_and_emission(self):
  v=P.source(ROOT);self.assertEqual(len(v['implementation']),149);self.assertEqual(len(P.native(COMPONENT)),159);out,r,C=self.emitted();C.check_source(out);self.assertEqual(C.NATIVE,P.NATIVE)
  self.assertEqual(r['ALPM_installation'],'NOT_RUN');self.assertEqual(r['original_derivation']['unchanged_native_bodies'],20)
 def test_default_refuses_before_output_or_git(self):
  with tempfile.TemporaryDirectory() as td:
   fixture=Path(td);policy=json.loads((HERE/'policy.json').read_bytes());policy.update(status='UNBOUND_DO_NOT_EXECUTE',binding=dict.fromkeys(P.KINDS));(fixture/'policy.json').write_bytes(P.encoded(policy))
   with patch.object(P,'HERE',fixture),self.assertRaisesRegex(ValueError,'UNBOUND public ALPM16K'):P.preflight(ROOT,dict.fromkeys(P.KINDS),{})
  self.assertEqual(list(self.work.iterdir()),[])
 def test_native_missing_drift_alias_and_extra_refuse_before_output(self):
  target=self.work/'component';shutil.copytree(COMPONENT,target);n=P.NATIVE+'/container.py';p=target/n;p.write_bytes(p.read_bytes()+b'\n')
  with self.assertRaisesRegex(ValueError,'exact source differs'):P.derive(ROOT,target,self.work/'output')
  self.assertFalse((self.work/'output').exists());shutil.copyfile(COMPONENT/n,p);(target/'foreign').write_text('unknown')
  with self.assertRaisesRegex(ValueError,'closed159'):P.native(target)
  (target/'foreign').unlink();p.unlink();p.symlink_to(COMPONENT/n)
  with self.assertRaisesRegex(ValueError,'unaliased'):P.native(target)
 def test_all_nine_vm_bodies_conserved_except_explicit_contract_role(self):
  out,r,C=self.emitted();G=P.load('original_generator_control',ROOT/P.LANE/'generator.py')
  for name in G.MODULES:
   raw=G.adapt(P.read(ROOT/G.OLD/name),name)[0]
   if name=='contract.py':raw=raw.replace(("NATIVE='"+P.PRIOR+"'").encode(),("NATIVE='"+P.NATIVE+"'").encode())
   self.assertEqual((out/P.LANE/name).read_bytes(),raw,name)
  for name in ('container.py','run.py','common.py','public_gate.py'):
   self.assertEqual((out/P.NATIVE/name).read_bytes(),(COMPONENT/P.NATIVE/name).read_bytes())
 def test_original_four_edits_twenty_bodies_from_public_container(self):
  out,r,C=self.emitted()
  with patch.dict(sys.modules,{'contract':C}):A=P.load('public_test_adapter',out/P.LANE/'adapter.py')
  text,v=A.derive(out);self.assertEqual(v['counted_edits'],4);self.assertEqual(len(v['unchanged_bodies']),20);self.assertEqual(v['changed_bodies'],['guard','validate_runtime']);ast.parse(text)
 def values(self,out,C):
  F=P.load('public_test_phase',out/P.LANE/'phase_gate.py');G=C.load('current_candidate',C.HERE/'candidate_gate.py');base=dict(candidate=G.EXPECTED,source_authority_sha256=G.EXPECTED['authority_sha256'],native_pair=F.PAIR,provider_archive_sha256=F.PAIR['archive_sha256'],provider_archive_bytes=F.ARCHIVE_BYTES,hardware='NOT_RUN',release='NOT_ADMITTED')
  rows={k:dict(base,status=status,source_sha=P.COMPONENT if k=='native_lifecycle' else 'b'*40,run_id=1 if k=='native_lifecycle' else 2,ordered_cleanup='PASS',cleanup='PASS',page_size=4096 if k=='native_lifecycle' else 16384,ALPM_installation='PASS' if k=='native_lifecycle' else 'NOT_RUN',scope='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION',input_phase='NATIVE_COMPILE_INPUTS') for k,status in F.STATUSES.items()};return rows
 def gate(self,C,rows):
  p=C.HERE/'prerequisites';p.mkdir(exist_ok=True);policy=json.loads((C.HERE/'input-policy.json').read_bytes());policy.update(status='BOUND_BY_ROOT',binding={k:dict(path=k+'.json',**P.pin(P.encoded(v))) for k,v in rows.items()})
  for k,v in rows.items():(p/(k+'.json')).write_bytes(P.encoded(v))
  (C.HERE/'input-policy.json').write_bytes(P.encoded(policy));return C.gate(p)
 def test_new_phase_gate_rejects_compile_staged_old_native_or_source_substitution(self):
  out,r,C=self.emitted();rows=self.values(out,C);self.assertEqual(set(self.gate(C,rows)),set(P.KINDS))
  for field,bad in [('status','ROOT_ACCEPTED_DEBIAN_MAINTAINED_PROVIDER_NORMAL_LIFECYCLE'),('ALPM_installation','NOT_RUN'),('source_sha','f'*40),('input_phase','PRIVATE16K'),('ordered_cleanup','UNKNOWN')]:
   v=copy.deepcopy(rows);v['native_lifecycle'][field]=bad
   with self.assertRaises(ValueError):self.gate(C,v)
  v=copy.deepcopy(rows);v['system16k']['ALPM_installation']='PASS'
  with self.assertRaises(ValueError):self.gate(C,v)
 def test_uart_bytes_and_strings_existing_protocol_controls_declared(self):
  out,r,C=self.emitted();raw=(out/P.LANE/'run.py').read_bytes();guest=(out/P.LANE/'guest.py').read_bytes();self.assertIn(b"b'DEBIAN_MAINTAINED_INSTALLED16K '",raw);self.assertIn(b"'DEBIAN_MAINTAINED_INSTALLED16K '",guest);self.assertIn(b'8192,8192',raw.replace(b' ',b''));self.assertIn(b'seconds=10800',raw)
 def test_workflow_native_component_and_original_security_stages(self):
  text=(ROOT/'.github/workflows/native-arm-glibc-debian-maintained-public-installed16k.yml').read_text();self.assertIn('public-native-component',text);self.assertIn('steps.decisions.outputs.native_component_ref',text);self.assertNotIn('wiring.py native-source',text);self.assertNotIn('--vm-source',text)
  for term in ('10800','--memory=4g'):
   self.assertIn(term,(ROOT/'scripts/ci/glibc-gnu-provider-installed16k/run.py').read_text())
  for term in ('timeout-minutes: 360','timeout-minutes: 220','timeout-minutes: 80','874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad','"$SLICE/job.py" cleanup','"$SLICE/job.py" retain','wiring.py','--private-key'):
   if term=='wiring.py':self.assertNotIn(term+' native-source',text)
   elif term=='--private-key':continue
   else:self.assertIn(term,text)

class InventoryRoleCollision(unittest.TestCase):
 def test_exact_current_inventory_is_selected_after_full_native159_verification(self):
  with tempfile.TemporaryDirectory()as td,patch.object(subprocess,'Popen',side_effect=AssertionError('no actors')):
   out=Path(td)/'emitted';held=P.source(ROOT);self.assertEqual(len(P.native(COMPONENT)),159);P.derive(ROOT,COMPONENT,out)
   name='manifests/packages.toml';self.assertNotEqual(held['implementation'][name],held['native_component'][name]);self.assertEqual(P.pin(P.read(out/name)),held['implementation'][name])
   deps=json.loads(P.read(out/P.LANE/'dependencies.json'))['files'];self.assertEqual(deps[name],held['implementation'][name]);native_deps=json.loads(P.read(out/P.NATIVE/'dependencies.json'))['files'];self.assertNotIn(name,native_deps)
   common=P.load('native_inventory_scope_control',out/P.NATIVE/'common.py');self.assertNotIn(name,common.read(out/P.NATIVE/'dependencies.json').decode());api=common.helpers(out);self.assertIn('roots',api);self.assertIn('db',api)
 def test_copy_exception_is_one_exact_leaf_and_wrong_inventory_or_second_overlap_refuses(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);component=root/'component';output=root/'output';component.mkdir();output.mkdir();name='manifests/packages.toml';a=b'UNIT_CURRENT_INVENTORY';b=b'UNIT_HISTORICAL_INVENTORY'
   for base,raw in ((component,b),(output,a)):
    p=base/name;p.parent.mkdir();p.write_bytes(raw)
   held=dict(implementation={name:P.pin(a)},native_component={name:P.pin(b)});P.copy_component(held,component,output);self.assertEqual((output/name).read_bytes(),a)
   (output/name).write_bytes(b'wrong')
   with self.assertRaisesRegex(ValueError,'current implementation inventory'):P.copy_component(held,component,output)
   (output/name).write_bytes(a);second='runtime.py';(component/second).write_bytes(b'UNIT_NATIVE');(output/second).write_bytes(b'UNIT_OTHER');held['native_component'][second]=P.pin(b'UNIT_NATIVE')
   with self.assertRaisesRegex(ValueError,'separate component source conflict'):P.copy_component(held,component,output)

class SummaryClosure(unittest.TestCase):
 def test_exact_helper_is_closed_and_declared_before_secrets(self):
  helper='scripts/ci/glibc-gnu-failure-log/summary.py';expected=dict(bytes=11924,sha256='9bd52ce4453a3a03d8dc8b5edb6b6a4b8ec421e0c3037dfb64dc31da45687555')
  table=json.loads((HERE/'source-pins.json').read_bytes());rows=table['implementation']
  self.assertEqual(rows[helper],expected);self.assertEqual(P.pin((ROOT/helper).read_bytes()),expected)
  text=(ROOT/'.github/workflows/native-arm-glibc-debian-maintained-public-installed16k.yml').read_text();self.assertLess(text.index('Verify exact retained diagnostic helper before secrets'),text.index('secrets.'));self.assertIn('summary.py" --help',text);self.assertIn(expected['sha256'],text)
 def test_closed_view_old_missing_hash_refuses_and_corrected_helper_help_runs(self):
  with tempfile.TemporaryDirectory(prefix='caa3-summary-closed-') as td:
   work=Path(td);closed=work/'closed'
   with patch.object(subprocess,'Popen',side_effect=AssertionError('source emission cannot start actors')):
    P.derive(ROOT,COMPONENT,closed)
   helper=closed/'scripts/ci/glibc-gnu-failure-log/summary.py';raw=helper.read_bytes();self.assertEqual(P.pin(raw)['sha256'],'9bd52ce4453a3a03d8dc8b5edb6b6a4b8ec421e0c3037dfb64dc31da45687555')
   manifest=(P.pin(raw)['sha256']+'  '+str(helper)+'\n').encode();helper.unlink()
   before=subprocess.run(['/usr/bin/sha256sum','--check'],input=manifest,capture_output=True,cwd=work,timeout=10);self.assertNotEqual(before.returncode,0);self.assertIn(b'No such file or directory',before.stderr)
   helper.write_bytes(raw);after=subprocess.run(['/usr/bin/sha256sum','--check'],input=manifest,capture_output=True,cwd=work,timeout=10);self.assertEqual(after.returncode,0)
   help=subprocess.run([os.sys.executable,'-I','-B',str(helper),'--help'],capture_output=True,cwd=work,timeout=10);self.assertEqual(help.returncode,0,help.stderr);self.assertLess(len(help.stdout+help.stderr),65536);self.assertIn(b'emit',help.stdout);self.assertIn(b'extract',help.stdout)

if __name__=='__main__':unittest.main()
