# SPDX-License-Identifier: MIT
"""Two actual Root pair-decision shapes; no prior repair/installation credit."""
import ast,hashlib,types
VERSIONS={'cachy-asahi-apps':'0.1.0-6','cachy-asahi-orphans':'0.1.0-2','cachy-asahi-repository-runtime':'0.1.0-1','cachy-asahi-cache':'0.2.0-1'}
DECISIONS={'triple': 'f904a28e6e02ce2685eaa438c4c3d6d43a119b0d5d85a6706db5864c2bbd1676', 'orphans': '4495e3104903c755c230606cd4739e95cd78e9cbb909d64ff42ad53fa470ba05'}

def decision(C,root,row,name,version,comparison):
 raw=C.checked(root,row['decision']);value=C.decode(raw)
 C.need(C.sha(raw)==DECISIONS['orphans' if name=='cachy-asahi-orphans' else 'triple'],'exact original Root pair decision bytes required')
 if name=='cachy-asahi-orphans':
  C.need(value['status']=='ROOT_ACCEPTED_ORPHANS2_NATIVE_PAIR_AND_SIGNED_INSTALLED_READONLY_CLI_ONLY' and value['source_sha']==row['native_source'] and str(value['run_id'])==row['native_run'] and value['cleanup']=='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP' and value['hardware']=='NOT_RUN' and value['lifecycle']=='PASS_MANAGEMENT_INSTALLED_READONLY_LIFECYCLE','actual Orphans2 pair/readonly input decision required')
  product=value['packages'][name];C.need(product['check_markers']['status']=='PASS_COMPLETE_ROOT_BOUND_CHECKS_NO_SKIPS' and product['check_markers']['skipped']==0 and product['check_markers']['check_enabled'] is True,'all20 original Orphans2 native checks required')
 else:
  C.need(value['status']=='ROOT_ACCEPTED_APPS6_NATIVE_PAIRS_FAILED_LIFECYCLE_LANE' and value['root_acceptance']=='SCOPED_NATIVE_PACKAGE_PAIRS_ONLY' and value['source']==row['native_source'] and str(value['run'])==row['native_run'] and value['native_builds']==6 and value['pairs']==3 and value['overall']=='FAIL' and value['installed_apps_lifecycle']==value['signed_repair']=='NOT_RUN','actual scoped Apps6 triple pair-only decision required; no lifecycle credit')
  product=value['products'][name]
 C.need(product['version']==version and product['builds' if name=='cachy-asahi-orphans' else 'native_builds']==2 and product['bytes']==row['files']['a']['bytes'] and product['sha256']==row['files']['a']['sha256'],'actual current native archive identity differs')

def finite(text,old,new):
 if text.count(old)!=1:raise ValueError('one frozen packet seam required')
 return text.replace(old,new)

def module(C,root):
 original=C.load('original_management_packet',root/'scripts/ci/management-tools-generic16k/contract.py');text=C.read(root/'scripts/ci/management-tools-generic16k/contract.py').decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='packet');body=ast.get_source_segment(text,node)
 body=finite(body,"'ROOT_ACCEPTED_MANAGEMENT16K_NATIVE_INPUTS'","'ROOT_ACCEPTED_NATIVE_CURRENT4_REPAIR_INPUTS'")
 body=finite(body,"'FOUR_ROOT_ACCEPTED_NATIVE_PAIRS_FOR_PRIVATE16K_DATA_STAGE'","'FOUR_ROOT_ACCEPTED_NATIVE_PAIRS_FOR_NATIVE_FULL574_REPAIR'")
 start=body.index("        if decision.get('status')==");end=body.index("        need(set(row['checks'])",start)
 body=body[:start]+"        repair_decision(C,root,row,name,version,comparison)\n"+body[end:]
 namespace=dict(vars(original),VERSIONS=VERSIONS,policy=C.policy,C=C,repair_decision=decision);exec(compile(body,str(root/'scripts/ci/management-tools-generic16k/contract.py')+':full574-repair-inputs','exec'),namespace)
 return types.SimpleNamespace(packet=namespace['packet'],package_payload=original.package_payload)
