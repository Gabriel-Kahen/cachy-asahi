# SPDX-License-Identifier: MIT
"""Five signed same-package transitions plus exact installed software fixtures."""
import re
PACKAGE='cachy-asahi-ksmctl'
def need(ok,why):
 if not ok:raise ValueError(why)
def validate(v):
 need(v.get('status')=='PASS_KSM2_SIGNED_UPGRADE_PRIVATE_LIFECYCLE'and v.get('base_count')==574 and v.get('installed_count')==575 and all(v.get(k)is True for k in('base574_preserved','user_preserved','system_trust_preserved','fixture_receipts_preserved'))and v.get('signatures')=='REQUIRED_EPHEMERAL_TEST_ONLY'and re.fullmatch('[A-F0-9]{40}',v.get('signer')or'')and v.get('architecture')=='aarch64'and type(v.get('page_size'))is int and v['page_size']>0 and v.get('hardware')=='NOT_RUN'and v.get('live_kernel_write')=='NOT_RUN'and v.get('live_store')=='NOT_CREATED'and v.get('release')=='NOT_ADMITTED','strict signed KSM native upgrade absent')
 rows=v.get('events');need(type(rows)is list and len(rows)==5,'five real signed ALPM transitions required')
 for row,(phase,version)in zip(rows,[('install-v1','0.1.0-1'),('upgrade-v2','0.1.0-2'),('remove',None),('reinstall-v2','0.1.0-2'),('final-remove',None)]):
  need(row.get('phase')==phase and row.get('version')==version and row.get('count')==(575 if version else 574)and all(row.get(k)is True for k in('base574_preserved','user_preserved','system_trust_preserved','fixture_receipts_preserved')),'exact package/version/base preservation required')
  if version:
   observations=row.get('observations');need(type(observations)is list and len(observations)==2 and {r.get('home')for r in observations}=={'ksm2-home-fresh','ksm2-home-existing'},'both ordinary user contexts required')
   for r in observations:
    new=phase!='install-v1';need(r.get('status')=='PASS_INSTALLED_KSM_REPORT_AND_PRIVATE_EXPERIMENT_FIXTURES'and r.get('version')==version and type(r.get('report_controls'))is int and r['report_controls']==18 and type(r.get('experiment_controls'))is int and r['experiment_controls']==(26 if new else 0)and r.get('live_kernel_write')=='NOT_RUN'and r.get('merge_eligibility')=='NOT_CHANGED','complete installed KSM software/private controls required')
    need(re.fullmatch('[0-9a-f]{64}',r.get('reporter_sha256')or'')and (re.fullmatch('[0-9a-f]{64}',r.get('helper_sha256')or'')if new else r.get('helper_sha256')is None),'exact observed installed helper identities required')
    commands=r.get('commands');expected=[(p,a)for p in([PACKAGE,'cachy-asahi-ksm-experiment']if new else[PACKAGE])for a in('--help','--version')]
    need(type(commands)is list and [(x.get('program'),x.get('argument'))for x in commands]==expected,'only exact installed help/version commands required')
    for command in[*commands,r.get('suite',{})]:
     need(command.get('exit_code')==0,'successful actual installed command required')
     for stream in('stdout','stderr'):
      pin=command.get(stream,{});need(set(pin)=={'bytes','sha256'}and type(pin.get('bytes'))is int and 0<=pin['bytes']<=128*1024 and re.fullmatch('[0-9a-f]{64}',pin.get('sha256')or''),'bounded original command stream pins required')
  else:need(row.get('payloads_absent')is True,'all seven candidate payloads must be removed')
