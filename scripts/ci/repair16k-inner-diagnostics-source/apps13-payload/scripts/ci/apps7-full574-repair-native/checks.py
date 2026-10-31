# SPDX-License-Identifier: MIT
"""Finite actual commit, damage, original-root and repair evidence gates."""
import re

def preserved(C,row,caps):
 C.need(row['status']=='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION' and row['dependency_checks']=='ORDINARY_LIBALPM' and row['cleanup']=='OWNED_WORKSPACE_TEMP_AND_ALPM_HANDLE_LOCK_RELEASED' and row['rollback']=='NOT_ATTEMPTED_DISPOSABLE_COPY_ONLY' and row['commit_started'] is True and row['packages_committed'] is True,'actual ordinary commit and cleanup required')
 proof=row['full574_closure'];C.need(proof['status']=='PASS-recorded-state-preserved' and proof['main_cache']=='RAW_EQUAL' and proof['auxiliary_transition']=={'kind':'RAW_EQUAL'} and proof['auxiliary_inode_liveness']=='NOT_ESTABLISHED_SOURCE_SNAPSHOT_KEYS' and proof['security_capabilities']=='EXACT_SOURCE_MAP_PRESERVED' and proof['source_capabilities_sha256']==caps,'unchanged complete capability/hardlink/user/trust/raw-cache preservation required')

def result(C,value):
 case=C.case(value['case']);C.need(value['aggregate']=='BOTH_INDEPENDENT_ROOT_CASE_DECISIONS_REQUIRED','no aggregate native case claim')
 C.need(value['status']=='PASS_NATIVE574_AUTHENTICATED_SELECTED_REPAIR_CASE' and value['base_count']==574 and value['counts']==[578,575,574] and value['hardware']=='NOT_RUN' and value['rollback']=='NOT_CLAIMED' and all(value[k] is True for k in ('source_preserved','workspaces_disposed','user_trust_protected_preserved')) and value['original_user_nodes']>0,'actual full574 repair/source/user/retirement evidence required')
 caps=value['source_capabilities_sha256'];C.need(value['security_capabilities']=='EXACT_SOURCE_MAP_PRESERVED' and re.fullmatch('[0-9a-f]{64}',caps),'full original capability map hash required')
 C.need(len(value['transactions'])==3 and set(value['repairs'])==set(value['preparations'])=={case},'one explicit actual repair case required')
 for row in value['transactions']+list(value['repairs'].values()):preserved(C,row,caps)
 install,selected,runtime=value['transactions'];C.need(install['prepared_add']==C.VERSIONS and not install['prepared_remove'] and not selected['prepared_add'] and selected['prepared_remove']=={n:v for n,v in C.VERSIONS.items() if n!='cachy-asahi-repository-runtime'} and not runtime['prepared_add'] and runtime['prepared_remove']=={'cachy-asahi-repository-runtime':'0.1.0-1'},'exact current install and original explicit removals required')
 for label,row in value['repairs'].items():
  proof=row['full574_closure']['repair'];before=value['preparations'][label];target='usr/share/doc/cachy-asahi-apps/README.md';damage=before['damage']
  C.need(row['operation']=='reinstall' and row['prepared_add']=={'cachy-asahi-apps':'0.1.0-13'} and row['prepared_remove']=={} and proof['status']=='SELECTED_SIGNED_ORDINARY_LEAVES_RESTORED' and proof['scope']=='AUTHENTICATED_SAME_VERSION_ORDINARY_FILE_BYTES_OR_MISSING_LEAF_ONLY' and proof['selected']==['cachy-asahi-apps'] and set(proof['archives'])=={'cachy-asahi-apps'} and proof['plan_sha256']==row['plan_sha256'] and proof['before_damage']==damage and set(damage)=={target} and row['before']==before['before'] and before['archives']==proof['archives'] and before['plan_sha256']==proof['plan_sha256'],'exact actual before map and authenticated selected restoration required')
  inspection(C,before,row['plan_sha256']);C.need(before['source_tree_sha256']==value['source_tree_sha256'] and before['capabilities_sha256']==caps and before['full574_binding']['source_capabilities_sha256']==caps,'actual readonly source/capability joins')
  C.need(damage[target] is None if label=='repair-missing' else type(damage[target]) is dict and damage[target]['type']=='file','distinct actual missing versus damaged original leaves required')
 C.need(set(value['refusals'])=={case+'-default-inspect','wrong-plan-sha','unselected-damage','foreign-alpm-lock'},'exact finite refusal cases required')
 for label,row in value['refusals'].items():
  C.need(row['status']=='FAIL','actual refusal absent')
  if not label.endswith('-default-inspect'):C.need(row['commit_started'] is False and row['packages_committed'] is False,'actual zero-commit refusal required')
 return value


def inspection(C,row,plan_sha256):
 C.need(row['status']=='INSPECTED_AUTHENTICATED_OWNED_FULL574_REINSTALL' and row['scope']=='READONLY_AUTHENTICATED_OWNED_FULL574_REINSTALL_PREPARATION' and row['operation']=='reinstall' and row['selected']==['cachy-asahi-apps'] and row['plan_sha256']==plan_sha256 and set(row['archives'])=={'cachy-asahi-apps'},'actual authenticated readonly inspection required')
 C.need(row['commit_started'] is False and row['packages_committed'] is False and row['transaction']=='NOT_RUN' and row['repair_authority'] is False and row['installer_authority'] is False and row['root_preserved'] is True and row['cleanup']=='OWNED_TEMP_REMOVED_WORKSPACE_FLOCK_RELEASED' and row['source_preservation']=='LEASED_READONLY_SOURCE_REVALIDATED','readonly inspection must not commit or waive source/root/temp guards')
 C.need(set(row['before'])=={'tree_sha256','database_sha256','packages_sha256','inventory_sha256'} and all(re.fullmatch('[0-9a-f]{64}',v) for v in row['before'].values()) and set(row['damage'])=={'usr/share/doc/cachy-asahi-apps/README.md'},'complete genuine damaged-before pins/map')
 worker=row['worker'];C.need(worker['seconds']==600 and worker['output_limit']==512*1024 and worker['returncode']==0 and worker['termination'] is None and worker['direct_child_reaped'] is True and worker['group_kill_sent'] is True and worker['retirement']=='ORIGINAL_SUPERVISOR_SIGNALS_GROUP_BEFORE_LEADER_REAP','original600s readonly worker boundary and retirement')
 aux=row['auxiliary_preservation'];C.need(aux['status']=='PASS-recorded-state-preserved' and aux['main_cache']=='RAW_EQUAL' and aux['auxiliary_transition']=={'kind':'RAW_EQUAL'},'actual readonly raw auxiliary/cache preservation')
 return row

def retained(C,value,directory,files):
 C.need(set(value['inspection_files'])=={C.case(value['case'])},'one retained original readonly receipt for the explicit case')
 for label,pin in value['inspection_files'].items():
  name=label+'-inspection.json';C.need(pin['path']==name and 0<pin['bytes']<=512*1024,'fixed bounded readonly receipt path')
  raw=C.read(directory/name,512*1024);C.need(len(raw)==pin['bytes'] and C.sha(raw)==pin['sha256'] and C.decode(raw)==value['preparations'][label] and files['lifecycle-public/'+name]=={k:pin[k] for k in ('bytes','sha256')},'raw original readonly receipt/hash/export/lifecycle join')
