# SPDX-License-Identifier: MIT
"""Strict same-package1→2 upgrade; persisted records are never current-kernel credit."""
import re
PACKAGE='cachy-asahi-sysctl'
def need(ok,why):
 if not ok:raise ValueError(why)
def validate(v):
 need(v.get('status')=='PASS_SYSCTL2_SIGNED_UPGRADE_PRIVATE_LIFECYCLE'and v.get('base_count')==574 and v.get('installed_count')==575 and all(v.get(k)is True for k in('base574_preserved','user_preserved','system_trust_preserved','legacy_records_preserved'))and v.get('signatures')=='REQUIRED_EPHEMERAL_TEST_ONLY'and re.fullmatch('[A-F0-9]{40}',v.get('signer')or'')and v.get('architecture')=='aarch64'and type(v.get('page_size'))is int and v['page_size']>0 and v.get('hardware')=='NOT_RUN'and v.get('host_sysctl_mutation')=='NOT_RUN'and v.get('release')=='NOT_ADMITTED','strict signed native upgrade absent')
 rows=v.get('events');need(type(rows)is list and len(rows)==5,'five real ALPM transitions')
 for row,(phase,version)in zip(rows,[('install-v1','0.1.0-1'),('upgrade-v2','0.1.0-2'),('remove',None),('reinstall-v2','0.1.0-2'),('final-remove',None)]):
  need(row.get('phase')==phase and row.get('version')==version and row.get('count')==(575 if version else 574)and all(row.get(k)is True for k in('base574_preserved','user_preserved','system_trust_preserved','legacy_records_preserved')),'exact version/inventory/preservation transition')
  if version:
   records=row.get('observations');need(type(records)is list and len(records)==2 and {x.get('home')for x in records}=={'sysctl2-home-fresh','sysctl2-home-existing'},'two ordinary-user contexts')
   for r in records:
    need(r.get('status')=='PASS_INSTALLED_SYSCTL_PRIVATE_UPGRADE_FIXTURES'and r.get('version')==version and r.get('controls')==(19 if phase=='install-v1'else 28)and r.get('legacy_preserved')is True and r.get('kernel_mutation')=='NOT_RUN','exact installed private suite')
    if phase!='install-v1':
     d=r.get('discovery',{});need(d.get('status')=='PASS_V1_RECORDS_DISCOVERED_READONLY'and d.get('records')==2 and d.get('phases')=={'planned':'PLANNED','applied':'APPLIED'}and d.get('live_state')=='NOT_READ'and d.get('kernel_mutation')=='NOT_RUN','original v1 records must be discovered read-only')
  else:need(row.get('payloads_absent')is True,'removed payload remains')
