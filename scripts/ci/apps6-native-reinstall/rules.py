# SPDX-License-Identifier: MIT
"""Finite Apps6 policy and actual signed repair result guards."""
VERSIONS={'runtime':'0.1.0-1','apps':'0.1.0-6','cache':'0.2.0-1'}
PURPOSE='APPS6_NATIVE_PAIR_AND_SIGNED_COPIED_ROOT_REINSTALL'
LIFECYCLE='PASS_APPS6_INSTALLED_LIFECYCLE_AND_SIGNED_REPAIR'
REPORT='PASS_NATIVE_APPS6_PAIRS_INSTALLED_AND_SIGNED_REPAIR'
EXPORT='PASS_NATIVE_APPS6_PAIR_AND_SIGNED_REPAIR_CANDIDATE'

def validate_repair(C,value):
 C.need(value.get('status')==LIFECYCLE and value.get('plans_applied_scope')=='INSTALLED_CATALOG_CLI_CASES_ONLY','distinct Apps6 lifecycle/catalog-scope required')
 r=value.get('repair',{});C.need(r.get('status')=='PASS_REAL_SIGNED_SYNTHETIC_SAME_VERSION_REPAIR' and r.get('host_architecture')=='aarch64' and r.get('native_aarch64')=='EXECUTED_SIGNED_SYNTHETIC_COPY_ONLY' and r.get('hardware')=='NOT_RUN' and r.get('host_database')=='NOT_ACCESSED' and r.get('trust')=='ISOLATED_TEST_AUTHORITY_NOT_PRODUCTION','actual native signed copied-root repair absent')
 C.need(all(r.get(k) is True for k in ('damaged_selected_payload_restored','missing_selected_leaf_restored','repeat_reinstall_committed','source_preserved','copied_workspace_absent')),'complete repair/preservation/disposal facts required')
 transactions=r.get('transactions',[]);C.need(len(transactions)==5 and [t.get('operation') for t in transactions]==['install','reinstall','reinstall','reinstall','remove'],'five exact repair transitions required')
 for t in transactions:
  C.need(t.get('status')=='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION' and t.get('architecture')=='aarch64' and t.get('commit_started') is True and t.get('packages_committed') is True and t.get('cleanup')=='OWNED_WORKSPACE_TEMP_AND_ALPM_HANDLE_LOCK_RELEASED' and t.get('scope')=='DEVELOPMENT_OWNED_OFFLINE_COPIED_ROOT_ONLY' and t.get('synthetic') is True and t.get('dependency_checks')=='ORDINARY_LIBALPM' and t.get('worker',{}).get('direct_child_reaped') is True and t['worker'].get('termination') is None and t['worker'].get('returncode')==0,'repair actual commit/ordinary guards/child retirement absent')
  if t['operation']=='reinstall':C.need(t.get('prepared_add')=={'fixture':'1-1'} and t.get('prepared_remove')=={} and t['before']['packages_sha256']==t['after']['packages_sha256'],'same-version/no-expansion repair required')
 refusals=r.get('refusals',[]);C.need(len(refusals)==2 and [t.get('error') for t in refusals]==['caller plan SHA256 differs','complete before snapshot differs'] and all(t.get('status')=='FAIL' and t.get('commit_started') is False and t.get('packages_committed') is False for t in refusals),'two exact zero-commit refusals required')
 C.need(r.get('libalpm',{}).get('sha256')=='94c013b9026772ffe4f227f508a2cdf0c61323dc1f7b7836fe629b49bfbc3902','original native ALPM16 identity differs')

def bind(C,here):
 old_policy=C.policy;old_validate=C.validate_lifecycle;C.HERE=here;C.LABEL='org.cachy-asahi.apps6-native-reinstall.job'
 def policy():
  raw=C.read(here/'input-policy.json');C.need(raw.get('purpose')==PURPOSE and raw.get('status')=='ROOT_BOUND_FINAL_PRODUCT_SOURCES','Apps6 candidate remains UNBOUND before secrets or actors')
  value=old_policy();C.need({role:row['version'] for role,row in value['products'].items()}==VERSIONS,'distinct Apps6/held Runtime1/Cache2 versions required');return value
 def lifecycle(value):
  if value.get('status')==LIFECYCLE:
   old_validate(dict(value,status='PASS_APPS_CACHE_INSTALLED_LIFECYCLE'));validate_repair(C,value)
  else:old_validate(value)
 C.policy=policy;C.validate_lifecycle=lifecycle;C.validate_repair=lambda v:validate_repair(C,v)
 return C
