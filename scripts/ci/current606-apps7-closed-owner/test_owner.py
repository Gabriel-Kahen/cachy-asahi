# SPDX-License-Identifier: MIT
"""Finite real-source/data controls; never a positive copied606 fixture."""
import base64,copy,hashlib,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];sys.path.insert(0,str(HERE))
import contract as O,selection as S,runtime as R,owner as Y,prepare as E,builds
PACKET=Path(os.environ['APPS7_PAIR_PACKET']).absolute()
DECISION=Path(os.environ['CURRENT606_DECISION']).absolute()

class Controls(unittest.TestCase):
 def test_source_closure_and_original263_held(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(subprocess,'run',side_effect=AssertionError('actor')):
   value=O.verify();self.assertEqual(value['roles']['held606'],263);self.assertIsNone(value['actual_source'])
   P,A,X,C=Y.source_context(ROOT);P.verify(bound=False);Y.capture_program((P.HERE/'tools606.py').read_text());Y.owner_program(A.owner(P.ROOT))
 def test_whole192_real_native_pairs_and_root_authorities(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(subprocess,'run',side_effect=AssertionError('actor')):
   values=builds.inspect(PACKET);self.assertEqual(set(values),{'cachy-asahi-apps','cachy-asahi-repository-runtime'});self.assertEqual(values['cachy-asahi-repository-runtime']['version'],'0.1.0-1')
  row=O.read(ROOT/'copyworker/scripts/ci/current606-apps7-copy/prerequisite-pins.json');raw=DECISION.read_bytes();selected=dict(source=S.NATIVE,run=39106953257,decision_source=row['current606_decision_source'],decision_path=row['current606_decision_path'],decision_pin=row['current606_decision'],decision_base64=base64.b64encode(raw).decode());self.assertEqual(S.decision(selected)['package_count'],606)
  for field,value in [('run',39106953258),('decision_source','0'*40),('decision_pin',dict(row['current606_decision'],sha256='0'*64))]:
   with self.subTest(field=field),self.assertRaises(ValueError):S.decision(dict(selected,**{field:value}))
 def test_inventory_proves606_and_exact_runtime_unchanged(self):
  raw=(ROOT/'held606/scripts/ci/current606-native/expected606.lock').read_bytes();base=dict(line.split()for line in raw.decode().splitlines());self.assertEqual(len(base),606);self.assertEqual(hashlib.sha256(raw).hexdigest(),S.LOCK);self.assertEqual(base['cachy-asahi-apps'],'0.1.0-6');self.assertEqual(base['cachy-asahi-repository-runtime'],'0.1.0-1')
  after=dict(base);after['cachy-asahi-apps']='0.1.0-7';self.assertEqual(len(after),606);self.assertEqual({n:v for n,v in base.items()if n!='cachy-asahi-apps'},{n:v for n,v in after.items()if n!='cachy-asahi-apps'})
 def test_default_gates_refuse_before_actors_io(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(subprocess,'run',side_effect=AssertionError('actor')):
   with self.assertRaisesRegex(ValueError,'NULL'):O.authorize(O.read(HERE/'null-policy.json'))
   with self.assertRaises(ValueError):S.verify_actor(O.read(HERE/'null-policy.json'),'capture','0'*32)
 def test_actual_runtime_argv_typed_five_binds_and_no_new_caps(self):
  C,P,I=builds.apis();paths={n:Path('/owned/'+n)for n in('runner','seed','proof','work','out')};argv=R.argv('worker','sha256:'+'0'*64,'a'*32,paths);C.bindings(Y.parse_mounts(argv))
  self.assertIn('/runner/scripts/ci/current606-apps7-copy/worker.py',argv);self.assertIn('--env=CAA_CURRENT606_APPS7_COPY='+'a'*32,argv);self.assertEqual({v for v in argv if v.startswith('--cap-add=')},{'--cap-add='+c for c in C.WORKER_CAPS});self.assertNotIn('--privileged',argv);self.assertIn('--network=none',argv)
  self.assertEqual(R.SECONDS,dict(finalize=600,worker=1800,dispose=120));self.assertEqual((C.COPY_SECONDS,C.CLEANUP_SECONDS),(600,60))
 def test_manifest_test_key_operand_regression_and_refusals(self):
  C,P,I=builds.apis();native=I.inspect(PACKET/'payload')['cachy-asahi-apps'];raw=native['key'].read_bytes()
  with tempfile.TemporaryDirectory()as tmp:
   ready=Path(tmp);(ready/'keys').mkdir();p=ready/'keys/TEST-public.asc';p.write_bytes(raw);signer=native['signer'];manifest=dict(keyrings=[dict(path='keys/archlinuxarm.gpg',size=1,sha256='0'*64),dict(path='keys/TEST-public.asc',size=len(raw),sha256=hashlib.sha256(raw).hexdigest())],preparation=dict(signer_roles=dict(ephemeral_TEST=signer,upstream_ALARM='A'*40)))
   self.assertEqual(I.original_key(ready,manifest,signer),p);self.assertFalse((ready/'TEST-public.asc').exists())
   for change in('wrong-pin','wrong-role','extra-key'):
    m=copy.deepcopy(manifest)
    if change=='wrong-pin':m['keyrings'][1]['sha256']='0'*64
    elif change=='wrong-role':m['preparation']['signer_roles']['ephemeral_TEST']='B'*40
    else:m['keyrings'].append(dict(path='keys/foreign.asc',size=1,sha256='0'*64))
    with self.subTest(change=change),self.assertRaises(ValueError):I.original_key(ready,m,signer)
 def test_only_counted_capture_and_owner_control_seams(self):
  P,A,X,C=Y.source_context(ROOT);raw=(P.HERE/'tools606.py').read_text();derived=Y.capture_program(raw);self.assertEqual(derived.replace(Y.CAPTURE_HOOK,Y.CAPTURE_LINE),raw)
  self.assertLess(derived.index("checkpoint('baseline604'"),derived.index('import runpy'));self.assertLess(derived.index('import runpy'),derived.index("remove('remove604')"))
  owner=Y.owner_program(A.owner(P.ROOT));self.assertIn('len(owned.rows)==8',owner);self.assertIn('active.process.wait(timeout=1800)',owner);self.assertIn('signal.setitimer(signal.ITIMER_REAL,6600)',owner)
 def test_frozen_original_fixture_source_and_actual_cli_entry(self):
  entry=(ROOT/'copyworker/scripts/ci/current606-apps7-copy/fixture_entry.py').read_text();self.assertIn("'/usr/bin/cachy-asahi-apps','inventory'",entry);self.assertIn("module.run_suite('apps',fixtures=CONTEXT)",entry)
  held=(ROOT/'copyworker/held-apps/fixture_checks.py').read_text();self.assertIn("expected=15",held);self.assertIn("fixture.a=load('actual_installed_apps7'",held)
  driver=(ROOT/'copyworker/scripts/ci/current606-apps7-copy/driver.py').read_text();self.assertIn("for kind in('fresh','existing')",driver);self.assertIn("runtime_signature=verification.verify_product",driver)
 def test_only_top_git_metadata_excluded_from_role_closure(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);(root/'held').write_bytes(b'held');self.assertEqual(O.files(root),{'held'})
   (root/'.git').write_text('gitdir: /source-control-only\n');self.assertEqual(O.files(root),{'held'});(root/'.git').unlink()
   (root/'.git').mkdir();(root/'.git/HEAD').write_text('metadata');self.assertEqual(O.files(root),{'held'})
   (root/'.unexpected').write_text('refused by whole-role comparison');self.assertNotEqual(O.files(root),{'held'})
 def test_all_source_programs_compile_no_actor(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   for p in ROOT.rglob('*.py'):compile(p.read_bytes(),str(p),'exec')

if __name__=='__main__':unittest.main(verbosity=2)
