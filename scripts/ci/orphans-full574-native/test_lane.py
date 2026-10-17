# SPDX-License-Identifier: MIT
"""Finite source/header/fixture adapter controls, no native/signing/ALPM actors."""
import ast,copy,importlib.util,json,os,re,subprocess,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
import contract as C
import install_dependency as D
import lifecycle as L
ROOT=Path(os.environ.get('ORPHAN_NATIVE_SOURCE',Path(__file__).resolve().parents[3]))
class Controls(unittest.TestCase):
 def setUp(self):
  self.block=patch.object(subprocess,'Popen',side_effect=AssertionError('all actors forbidden'));self.block.start();self.addCleanup(self.block.stop)
 def test_policy_unbound_before_any_original_owner_or_source_action(self):
  template=C.read(C.HERE/'policy.json')
  with patch.object(C,'read',return_value=template):
   with self.assertRaisesRegex(ValueError,'UNBOUND'):C.policy()
   with self.assertRaisesRegex(ValueError,'UNBOUND'):C.source(ROOT)
 def test_only_fixture_install_adds_public_alldeps_preserving_original_flags(self):
  seen=[];actor=NS(handle=123,alpm_trans_init=lambda h,f:seen.append((h,f)) or 0)
  wrapped=D.factory(lambda *a,**k:actor,(1<<7)|(1<<10))
  value=wrapped();self.assertEqual(value.alpm_trans_init(123,(1<<7)|(1<<10)),0)
  self.assertEqual(seen,[(123,(1<<7)|(1<<10)|(1<<8))])
  for handle,flags in ((124,(1<<7)|(1<<10)),(123,0),(123,(1<<7)|(1<<10)|(1<<8))):
   with self.assertRaisesRegex(ValueError,'original install flags'):value.alpm_trans_init(handle,flags)
 def test_fixture_accepts_original_sanitized_child_environment_only(self):
  # Original Calls.call passes a disposable owner token, not the outer actor flag.
  env=dict(C.ENV,HOME='/tmp',CACHY_ASAHI_APPS_TRANSACTION='a'*32)
  with patch.object(D.C,'source'),patch.object(D.os,'getuid',return_value=0),patch.object(D.os,'geteuid',return_value=0),patch.object(D.os,'uname',return_value=NS(machine='aarch64')),patch.object(D.sys,'argv',['fixture']):
   with patch.dict(D.os.environ,env,clear=True):
    with self.assertRaisesRegex(ValueError,'install fixture only'):D.main()
   for bad in ('','a'*31,'g'*32):
    with patch.dict(D.os.environ,dict(env,CACHY_ASAHI_APPS_TRANSACTION=bad,CACHY_APPS574_LIFECYCLE='1'),clear=True):
     with self.assertRaisesRegex(ValueError,'native fixture actor'):D.main()
 def test_native_header_requires_one_exact_supported_public_enum(self):
  self.assertEqual(D.dependency_flag('enum flags { ALPM_TRANS_FLAG_ALLDEPS = (1 << 8), OTHER = 1 };'),256)
  for header in ('', 'ALPM_TRANS_FLAG_ALLDEPS = (1 << 9),', 'ALPM_TRANS_FLAG_ALLDEPS = 256,', 'ALPM_TRANS_FLAG_ALLDEPS = (1 << 8),\nALPM_TRANS_FLAG_ALLDEPS = (1 << 8),', 'x'*(1024**2+1)):
   with self.assertRaises(ValueError):D.dependency_flag(header)
 def test_request_keeps_original_exact_signed_remove_operands(self):
  with tempfile.TemporaryDirectory() as name:
   path=Path(name)/'orphan-plan.json';path.write_bytes(b'{}')
   argv=['python','-I','-B','/source/scripts/apps/transaction.py','apply','--workspace','/work/main','--operation','remove','--applications','cache','--plan','/out/p.json','--plan-sha256','a'*64,'--confirm-disposable-transaction']
   value=L.args_request(argv,path);self.assertEqual(value['applications'],['cache']);self.assertEqual(value['selected'],['cachy-asahi-cache']);self.assertTrue(value['confirm_disposable_transaction']);self.assertEqual(value['plan_sha256'],'a'*64)
   with self.assertRaisesRegex(ValueError,'exact signed Cache'):L.args_request([x if x!='cache' else 'runtime' for x in argv],path)
 def test_original_owner_custody_resource_and_cleanup_functions_unchanged(self):
  root=ROOT/'scripts/ci/apps-full574-native/job.py';raw=root.read_bytes();tree=ast.parse(raw)
  self.assertIn('actor',{n.name for n in tree.body if isinstance(n,ast.FunctionDef)})
  # Our wrapper imports these functions from the pinned original; no replacement bodies.
  wrapper=(ROOT/C.LANE/'job.py').read_text();self.assertIn("H=C.load('original_apps_owner'",wrapper)
  self.assertNotIn('def actor(',wrapper);self.assertNotIn('def cleanup(',wrapper);self.assertNotIn('def retain(',wrapper)
  self.assertIn("3000 if role=='lifecycle' else 900",raw.decode())
 def test_emitted_source_and_selected_source_pins_join(self):
  manifest=C.decode(C.read(C.HERE/'source-manifest.json'))
  for name,row in manifest['files'].items():self.assertEqual(C.checked(ROOT,dict(path=name,**row)),(ROOT/name).read_bytes())
  selected=C.decode(C.read(ROOT/'scripts/orphans/selected-source-pins.json'))
  for name,row in selected['files'].items():self.assertEqual(C.checked(ROOT,dict(path=name,**row)),(ROOT/name).read_bytes())
 def test_result_requires_actual_reason_preservation_and_single_commit_truth(self):
  normal=dict(status='PASS_SELECTED_CATALOG_ORPHAN_REMOVAL_IN_OWNED_COPY',prepared_add={},prepared_remove={'cachy-asahi-cache':'0.2.0-1'},commit_started=True,packages_committed=True,dependency_checks='ORDINARY_LIBALPM',selected=['cachy-asahi-cache'],retained_matching_signed_cache={'cachy-asahi-cache':{}})
  closure=dict(status='PASS-recorded-state-preserved',main_cache='RAW_EQUAL',auxiliary_transition={'kind':'RAW_EQUAL'},security_capabilities='EXACT_SOURCE_MAP_PRESERVED',source_capabilities_sha256='a'*64)
  installed=dict(prepared_add={'cachy-asahi-cache':'0.2.0-1','cachy-asahi-repository-runtime':'0.1.0-1'})
  for row in (normal,installed):row.update(full574_closure=copy.deepcopy(closure),cleanup='OWNED_WORKSPACE_TEMP_AND_ALPM_HANDLE_LOCK_RELEASED')
  pins={n:'a'*64 for n in ('tree_sha256','database_sha256','packages_sha256','inventory_sha256')}
  value=dict(status='PASS_NATIVE574_SELECTED_ORPHAN_CLEANUP',base_count=574,counts=[576,575],selected=['cachy-asahi-cache'],source_preserved=True,user_trust_protected_preserved=True,workspaces_disposed=True,hardware='NOT_RUN',rollback='NOT_CLAIMED',interrupted_copy='NOT_RUN_SEPARATE_ACTOR_REQUIRED',cases=dict(noop={'status':'NOT_APPLIED_NO_SELECTION'},cancel={'status':'CANCELLED_NOT_APPLIED'},foreign_lock={'status':'FAIL'},stale={'status':'FAIL'},normal=normal),case_preservation=dict(noop_cancel_foreign=dict(before=pins.copy(),after=pins.copy()),stale=dict(before=pins.copy(),after=pins.copy()),qualification='FULL_ROOT_DIGEST_EQUALITY_NOT_COMMIT_EVENT_PROOF'),actual_reason_graph={'cachy-asahi-cache':dict(candidate=True,reason='dependency',required_by=[],optional_required_by=[]),'cachy-asahi-repository-runtime':dict(reason='dependency',required_by=['cachy-asahi-cache'])},dependency_reason_readback='ACTUAL_PUBLIC_ALPM_ALLDEPS_AND_ORPHANS2_GRAPH',security_capabilities='EXACT_SOURCE_MAP_PRESERVED',source_capabilities_sha256='a'*64,transactions=[installed,normal])
  self.assertEqual(C.result(value),value)
  for change in ('reason','preservation','commit','recursive'):
   bad=copy.deepcopy(value)
   if change=='reason':bad['actual_reason_graph']['cachy-asahi-cache']['reason']='explicit'
   elif change=='preservation':bad['case_preservation']['stale']['after']['tree_sha256']='b'*64
   elif change=='commit':bad['cases']['normal']['packages_committed']='UNKNOWN'
   else:bad['cases']['normal']['prepared_remove']['cachy-asahi-repository-runtime']='0.1.0-1'
   with self.assertRaises(ValueError):C.result(bad)
if __name__=='__main__':unittest.main(verbosity=2)
