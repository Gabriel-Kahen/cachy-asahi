# SPDX-License-Identifier: MIT
"""Five actual signed Welcome4→5 transitions, never GUI/M2 acceptance."""
import re
def need(ok,why):
 if not ok:raise ValueError(why)
def validate(v):
 need(v.get('status')=='PASS_WELCOME5_UPGRADE_SIGNED_DISPLAYLESS_LIFECYCLE'and v.get('base_count')==574 and v.get('installed_count')==575 and all(v.get(k)is True for k in('base574_preserved','user_preserved','production_trust_preserved'))and v.get('signatures')=='REQUIRED_EPHEMERAL_TEST_ONLY'and re.fullmatch('[A-F0-9]{40}',v.get('signer')or'')and v.get('architecture')=='aarch64'and type(v.get('page_size'))is int and v['page_size']>0 and v.get('GUI')==v.get('live_DNS')==v.get('actual_16k_execution')==v.get('hardware')=='NOT_RUN'and v.get('release')=='NOT_ADMITTED','strict signed native Welcome upgrade absent')
 events=v.get('events');need(type(events)is list and len(events)==5,'five required ALPM transitions')
 for row,(phase,version,role)in zip(events,[('install-v4','0.1.0-4','cachy-asahi-welcome'),('upgrade-v4-to-v5','0.1.0-5','cachy-asahi-welcome5'),('remove-v5',None,None),('reinstall-v5','0.1.0-5','cachy-asahi-welcome5'),('final-remove-v5',None,None)]):
  need(row.get('phase')==phase and row.get('count')==(575 if version else 574)and all(row.get(k)is True for k in('base574_preserved','user_preserved','production_trust_preserved')),'exact inventory/preservation transition')
  if not version:need(row.get('payloads_absent')is True,'removed payload remains');continue
  need(row.get('version')==version and row.get('recipe_role')==role and row.get('package_name')=='cachy-asahi-welcome','same actual package exact role/version')
  root=row.get('root_guard',{});need(root.get('status')=='PASS_ORIGINAL_ROOT_REFUSAL_ASSERTION'and root.get('recipe_role')==role,'original root assertion must be executed, not skipped')
  streams=[root.get('receipt')];records=row.get('observations');need(type(records)is list and len(records)==2 and {r.get('home')for r in records}=={'welcome-upgrade-home-fresh','welcome-upgrade-home-existing'},'both ordinary-user homes')
  for r in records:
   need(r.get('status')=='PASS_INSTALLED_WELCOME_DISPLAYLESS_AND_NATIVE_SCHEMA_FIXTURES'and r.get('version')==version and r.get('recipe_role')==role and r.get('cli_controls')==5 and r.get('report_controls')==(8 if version.endswith('-4')else 12)and re.fullmatch('[a-f0-9]{64}',r.get('program_sha256')or'')and r.get('GUI')==r.get('live_DNS')==r.get('hardware')=='NOT_RUN','installed CLI/source-schema proof')
   streams.extend([r.get('CLI'),r.get('schema')])
  for s in streams:
   need(type(s)is dict and set(s)=={'stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256','exit_code'}and s['exit_code']==0 and all(type(s[k])is int and 0<=s[k]<=128*1024 for k in('stdout_bytes','stderr_bytes'))and s['stdout_bytes']+s['stderr_bytes']<=128*1024 and all(re.fullmatch('[a-f0-9]{64}',s[k]or'')for k in('stdout_sha256','stderr_sha256')),'bounded actual fixture stream receipts')

def validate_products(report):
 validate(report['lifecycle'])
 for event in report['lifecycle']['events']:
  if event['count']==574:continue
  row=report['products'][event['recipe_role']];need(row['version']==event['version']and len(row['builds'])==2,'two exact selected-version native builders')
  for build in row['builds']:
   e=build.get('elf');need(type(e)is dict and e.get('machine')==183 and not e.get('errors')and e.get('load_segments',0)>0 and e.get('actual_16k_execution')=='NOT_RUN'and e.get('interpreter')=='/lib/ld-linux-aarch64.so.1'and {'libgtk-3.so.0','libglib-2.0.so.0','libc.so.6'}<=set(e.get('needed',[])),'original structural AArch64/16K ELF receipt')
  sha=row['builds'][0]['payload']['usr/bin/cachy-asahi-welcome']['sha256']
  need(all(r['program_sha256']==sha for r in event['observations']),'installed CLI ELF/build-A payload identity')
