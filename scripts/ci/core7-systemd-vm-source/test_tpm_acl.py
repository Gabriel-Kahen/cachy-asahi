# SPDX-License-Identifier: MIT
"""Portable factory and genuine private typed ACL controls; no native actor."""
import argparse,ast,base64,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_Core41_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
def command(args,seconds=90):return subprocess.run([sys.executable,'-I','-B','-Werror',*map(str,args)],capture_output=True,cwd='/',timeout=seconds)
class Factory(unittest.TestCase):
 def test_all_eight_old_function_outputs_and25_function_bodies_held(self):
  calls=[(F.inputs,F.emit),(F.virtio20_inputs,F.emit_virtio20),(F.rollback_inputs,F.emit_rollback),(lambda:F.host_clock_inputs(False),lambda p:F.emit_host_clock(p,False)),(lambda:F.host_clock_inputs(True),lambda p:F.emit_host_clock(p,True)),(F.module_index_inputs,F.emit_module_indexes),(F.gzip1_inputs,F.emit_gzip1),(F.fresh_graph_inputs,F.emit_fresh_graph)]
  with tempfile.TemporaryDirectory()as td:
   for i,(inputs,emit)in enumerate(calls):
    p,bodies=inputs();out=Path(td)/str(i);emit(out);self.assertEqual(F.source(out,p['result']['files']),bodies)
  p,_=F.tpm_acl_inputs();text=(HERE/'prepare.py').read_text();held={n.name:F.pin(ast.get_source_segment(text,n).encode())for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name in p['held_factory_functions']};self.assertEqual(held,p['held_factory_functions']);self.assertEqual(len(held),25)
 def test_exact_published41_and_unbound41_identical_bytes_explicit_authority(self):
  p,bodies=F.tpm_acl_inputs();self.assertEqual(F.source(EXPECTED,p['stages']['41']['after']),bodies);self.assertEqual(F.source(PARENT,p['stages']['40']['after']),{n:base64.b64decode(row['before_base64'],validate=True)if n in p['stages']['41']['changed']and row['before']is not None else bodies[n]for n in p['stages']['40']['after']for row in[p['stages']['41']['changed'].get(n,{})]})
  with tempfile.TemporaryDirectory()as td:
   for unbound in(False,True):
    out=Path(td)/str(unbound);auth=Path(td)/(str(unbound)+'.json')
    with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS_API_GIT')):v=F.emit_tpm_acl(out,unbound,auth)
    self.assertEqual(F.source(out,p['stages']['41']['after']),bodies);self.assertEqual(json.loads(auth.read_bytes()),v);self.assertIsNone(v['actual']);self.assertIsNone(v['run']);self.assertFalse(v['acceptance']);self.assertEqual(v['source'],None if unbound else p['source_after']);self.assertFalse(v['old_closed_schema_held']);self.assertNotEqual(v['authority'],'NATIVE_ACCEPTANCE')
    r=command([out/'entry.py','source']);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertIsNone(json.loads(r.stdout)['actual'])
 def test_actual_isolated_new_CLI_and_source_only_receipts(self):
  p,_=F.tpm_acl_inputs()
  with tempfile.TemporaryDirectory()as td:
   for unbound in(False,True):
    args=[HERE/'prepare.py','--tpm-default-acl']+(['--unbound']if unbound else[]);r=command([*args,'--source-only']);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(json.loads(r.stdout)['source'],None if unbound else p['source_after'])
    out=Path(td)/str(unbound);auth=Path(td)/(str(unbound)+'.json');r=command([*args,'--output',out,'--authorization',auth]);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(json.loads(r.stdout),json.loads(auth.read_bytes()));self.assertEqual(F.source(out,p['stages']['41']['after']),F.source(EXPECTED,p['stages']['41']['after']))
   self.assertEqual(command([HERE/'prepare.py','--help']).returncode,0)
 def test_complete_counted41_40_39_body_inverses_and_publication_custody(self):
  p,bodies=F.tpm_acl_inputs();self.assertEqual([len(p['stages'][n]['held'])for n in('40','41')],[33,32]);self.assertEqual(len(p['stages']['40']['payload']),4);self.assertEqual(len(p['stages']['41']['payload']),6)
  self.assertEqual(p['publication_custody']['40']['publication']['source'],'536f96af5451697da2467e2e45e3129f32eed6d8');self.assertEqual(p['publication_custody']['41']['publication']['source'],p['source_after'])
  self.assertEqual(bodies['case.py'],F.source(PARENT,p['stages']['40']['after'])['case.py']);self.assertEqual(bodies['xattr_diagnostic.py'],F.source(PARENT,p['stages']['40']['after'])['xattr_diagnostic.py'])
 def test_profile_payload_research_license_and_custody_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);out=root/'absent'
   for name in('tpm_acl.py','tpm-acl-profile.json','tpm-default-acl/40/guest.py','tpm-default-acl/41/acl_policy.py','tpm-acl-research/TPM-LICENSE','tpm-acl-research/linux-posix_acl.c','tpm-acl-custody/qualification-status.json'):
    path=factory/name;raw=path.read_bytes();path.write_bytes(raw+b'x');r=command([factory/'prepare.py','--tpm-default-acl','--output',out]);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists());path.write_bytes(raw)
   (factory/'tpm-default-acl/41/foreign-empty-directory').mkdir();r=command([factory/'prepare.py','--tpm-default-acl','--output',out]);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists())
 def test_output_authorization_alias_reuse_traversal_and_modes_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);alias=root/'alias';alias.symlink_to(root,target_is_directory=True)
   for out in[alias/'never',root/'not-created/../never',HERE/'never',HERE,root]:
    with self.assertRaises(ValueError):F.emit_tpm_acl(out)
   for auth in[HERE/'never.json',alias/'never.json',root/'unmade/../never.json',root/'out/receipt.json']:
    out=root/'out'
    with self.assertRaises(ValueError):F.emit_tpm_acl(out,False,auth)
    self.assertFalse(out.exists())
   for mode in(None,0,1,'unbound'):
    with self.assertRaises(ValueError):F.emit_tpm_acl(root/'never',mode)
   out=root/'created';out.mkdir()
   with self.assertRaises(ValueError):F.emit_tpm_acl(out)
 def test_new_profile_conflicts_do_not_change_old_CLI_defaults(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'never'
   for flag in('--fresh-graph','--gzip1','--module-indexes','--host-clock','--virtio20','--automatic-rollback'):
    r=command([HERE/'prepare.py','--tpm-default-acl',flag,'--output',out]);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists())
   for args in([HERE/'prepare.py','--unbound','--output',out],[HERE/'prepare.py','--authorization',Path(td)/'never.json','--output',out]):
    r=command(args);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists())
   r=command([HERE/'prepare.py','--source-only']);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(json.loads(r.stdout)['files'],34)
   r=command([HERE/'prepare.py','--fresh-graph','--source-only']);self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(json.loads(r.stdout)['files'],39)
 def test_new_schema_AND_not_held_old_closed_positive_and_pinned_research(self):
  p,bodies=F.tpm_acl_inputs();schema=p['schema'];self.assertIs(schema['old_closed_schema_held'],False);self.assertIs(schema['typed_value_required'],True);self.assertEqual(set(schema['keys'])-set(schema['parent_keys']),{'posix_acl_defaults'});self.assertEqual(schema['later_required_acl_sha256'],'371f93a94c93284aeefacd8d3b58b96aff4d4d11e1eb750b460afbf756d0f576');self.assertEqual(p['source_controls_reused_unique'],64)
  for name in('guest.py','validate.py'):self.assertIn(b"__import__('acl_policy').check_graph(",bodies[name])
  self.assertIn(b'TPM_NOTICE=',bodies['acl_policy.py']);self.assertIn(b'Redistribution and use',bodies['acl_policy.py']);self.assertEqual(p['schema']['unknown_access_or_user_attrs'],'REFUSE')
 def test_actual_five_emitted_typed_ACL_and_genuine_private_graph_controls(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';F.emit_tpm_acl(out);args=[out/'test_sources.py','--vm-source',VM,'--core-source',CORE,'--kernel-carrier',KERNEL,'TypedACLControls','GraphAPI.test_entire_actual_guest_graph_private_descriptor_and_caps_route','GraphAPI.test_graph_api_source_drift_and_unknown_caps_refuse'];r=command(args);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertRegex(r.stderr,rb'Ran 5 tests in ');self.assertNotRegex(r.stderr,rb'\b(?:FAILED|ERROR|skipped)\b');print('focused emitted typedACL3 +genuine privategraph1 +heldrefusal1 PASS',file=sys.stderr)
if __name__=='__main__':
 p=argparse.ArgumentParser()
 for n in('expected','parent40','core-source','vm-source','kernel-carrier'):p.add_argument('--'+n,type=Path,required=True)
 a,rest=p.parse_known_args();EXPECTED=a.expected.absolute();PARENT=a.parent40.absolute();CORE=a.core_source.absolute();VM=a.vm_source.absolute();KERNEL=a.kernel_carrier.absolute();unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
