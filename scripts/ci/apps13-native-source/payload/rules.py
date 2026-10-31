# SPDX-License-Identifier: MIT
"""Finite actual receipts: no Cache action, repair,604,16K or hardware admission."""
def validate(C,value):
 C.need(value.get('status')=='PASS_APPS13_CLIENT_V2_INSTALLED_LIFECYCLE' and value.get('base_count')==574 and value.get('installed_count')==577 and value.get('architecture')=='aarch64' and value.get('page_size')==4096 and value.get('hardware')=='NOT_RUN','distinct native4K software lifecycle required')
 C.need(all(value.get(k)is True for k in ('base574_preserved','user_preserved'))and value.get('plans_applied')=='NOT_APPLIED'and value.get('cache_cleanup')=='NOT_RUN'and 'cache_apply'not in value,'original base/user preservation and no Cache apply required')
 C.need(value.get('client_v2')=='PASS_INSTALLED_SIGNED_TILDE_READONLY'and value.get('apps13_inventory')=='PASS_INSTALLED_15_CONTROLS'and value.get('removal_order')==[C.ROLES[k]for k in ('client','apps','runtime')],'exact new installed controls and dependency removal order required')
 events=value.get('events');C.need(type(events)is list and len(events)==5,'five exact original lifecycle transitions')
 for event,(phase,count)in zip(events,(('install',577),('same-version-reinstall',577),('remove',574),('reinstall-after-removal',577),('final-remove',574))):
  C.need(event.get('phase')==phase and event.get('count')==count and event.get('base574_preserved')is True and event.get('user_preserved')is True,'exact inventory and preservation transition')
  if count==574:C.need(event.get('payloads_absent')is True,'all owned non-directory payloads absent');continue
  C.need(event.get('installed_default_helpers')=='PASS'and event.get('signed_catalog')=='PASS_NOT_APPLIED'and event.get('inventory_collector')=='PASS_READONLY_OBSERVED_ALPM9','held installed Apps CLI and full actual577 inventory required')
  records=event.get('observations');C.need(type(records)is list and len(records)==2 and {r.get('home')for r in records}=={'apps-cache-home-fresh','apps-cache-home-existing'},'both original ordinary-user homes')
  for r in records:
   C.need(r.get('apps_commands')==['list','search','show','plan-install','plan-remove']and r.get('default_helpers')=='PASS_INSTALLED_EXACT_THREE'and r.get('signed_catalog')=='PASS_NOT_APPLIED'and r.get('plan_inventory_source')=='OBSERVED_SYNTHETIC_ALPM9_FIXTURE'and r.get('real_database_inventory')=='PASS_EXACT577_OBSERVED_METADATA_RAW_HASHES_PRESERVED'and r.get('inventory_collector')=='PASS_READONLY_OBSERVED_ALPM9','original signed/catalog/raw metadata guards held')
   for key,count in (('apps13_installed_controls',15),('client_v2_installed_controls',2),('apps13_stage_controls',4)):
    control=r.get(key,{});C.need(control.get('status')=='PASS_INSTALLED_CONTROLS'and control.get('mode')==('apps'if count==15 else'client'if count==2 else'apps-stage')and control.get('tests')==count and control.get('failures')==control.get('errors')==control.get('skipped')==0 and control.get('installed_source')is True,'exact actual installed fixture completion required')
    C.need(type(control.get('report_bytes'))is int and 0<control['report_bytes']<=65536 and C.re.fullmatch('[0-9a-f]{64}',control.get('report_sha256')or''),'bounded genuine original test report binding')
