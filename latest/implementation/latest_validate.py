# SPDX-License-Identifier: MIT
"""Strict finite component receipt validation; never source/native acceptance."""
import hashlib,json,re
import latest_plan as P
import latest_restoration as R

def digest(v):return type(v)is str and re.fullmatch('[a-f0-9]{64}',v)
def doctor(value,version,want):
 P.need(type(value)is dict and value.get('schema_version')==1 and value.get('tool')=='cachy-asahi-doctor'and value.get('scope')=='local observations only'and value.get('version')==('0.2.0'if version=='0.2.0-1'else'0.1.0'),'complete actual Doctor identity/version/report scope')
 rows=value['checks'];P.need(type(rows)is list and len(rows)<128 and len({r['check']for r in rows})==len(rows),'unique bounded Doctor report rows');platform=next(r for r in rows if r['check']=='platform')['value'];P.need(set(platform)=={'architecture','kernel','page_size_bytes'}and platform['architecture']=='aarch64'and type(platform['kernel'])is str and 0<len(platform['kernel'])<=256 and type(platform['page_size_bytes'])is int and platform['page_size_bytes']in(4096,16384,65536),'finite generic native report platform fields, no hardware authority')
 for row in rows:
  if row['check'].startswith('package/'):
   name=row['check'][8:];v=row['value'];P.need(row['state']in('checked','unknown','unavailable'),'actual package query states')
   if row['state']=='checked':P.need(v['presence']==('present'if name in want else'absent')and v['version']==want.get(name),'successful observed Doctor query exact inventory join')
   else:P.need(v['presence']=='unknown'and v['version']is None,'unknown package query never healthy/absent')
  if row['check'].startswith(('system/','user/')):P.need(row['state']in('checked','unknown','unavailable'),'offline service state, no health inference')
 audio=[r for r in rows if r['check']=='audio/default-output'];P.need(not audio if version=='0.1.0-1'else len(audio)==1 and audio[0]['state']=='unavailable'and audio[0]['value']is None,'unavailable audio actual scope')
 return value
def validate(value,before,after,nonce,original=None,boot_validator=None):
 P.need(type(value)is dict and value.get('status')=='PASS_NATIVE607_LATEST_FIVE_TOOL_COMPONENT_REQUIRES_FULL_REPLAY'and(value['base_count'],value['peak_count'],value['restored_count'])==(606,607,606),'complete native latest-five result')
 P.need(value['scope']=='COMPLETE_PACKAGE_PAYLOAD_RAW_DB_KNOWN_ANCESTRY_PLUS_ETC_HOME_ROOT_NOT_WHOLE_ROOT'and value['source_owned_nonce']==nonce and type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce)and value['nonce_authority']=='SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION','full original transport/source-owned nonce scope')
 P.need(value['other602_physical_preservation']==dict(original604_unselected=600,original606_additions=2,total=602,domain='COMPLETE_PAYLOAD_RAW_DB_INODE_HARDLINK_CAPABILITY_WITH_PROVEN_SELECTED_PARENT_TRANSITIONS')and value['selected_four_inode_restoration']=='NOT_CLAIMED','exact original604-4=600 plus2 physical; four logical only')
 P.need(all(value[k]=='NOT_RUN'for k in('hardware','GUI','live_audio','live_KSM'))and value['real_journal']==value['live_pstore']=='NOT_READ'and value['performance']=='NOT_CLAIMED'and value['release']=='NOT_ADMITTED'and value['new_tool_builds']=='NOT_RUN_ACCEPTED_NATIVE_ARCHIVES_REUSED','finite honest fixture/hardware/performance scope')
 if original is None:
  from pathlib import Path
  original=dict(r.split()for r in(Path(__file__).resolve().parent/'expected606.lock').read_text().splitlines())
 plan=P.transitions(original);events=value['events'];P.need(type(events)is list and len(events)==25,'complete25 ordered transactions');clocks={}
 for expected,event in zip(plan,events):
  role=expected['role'];version=expected['version'];t=event['transaction'];P.need((event['phase'],event['role'],event['count'],event['unaffected_count'])==(expected['phase'],role,len(expected['after']),expected['unaffected_count'])and event['other602_physical_preservation']is True and event['selected_four_inode_restoration']=='NOT_CLAIMED','exact finite transition/count/protected602')
  proof=event['all_nonacted'];P.need(proof['status']=='PROTECTED_KNOWN606_GRAPH_HELD'and proof['whole_root']is False and type(proof['directory_counter_modes'])is dict and all(v in('ARITHMETIC_CHILD_DIRECTORY_DELTA','CONSTANT_ONE_WITH_COMPLETE_INDEPENDENT_CHILD_PROOF')for v in proof['directory_counter_modes'].values()),'full fresh per-action nonacted payload/rawDB/identity/hardlink/caps proof')
  P.need(event['signature']=='REQUIRED_ORIGINAL_EPHEMERAL_TEST'and event['fixture_graph_unchanged']is event['user_config_preserved']is event['prior_reports_preserved']is True and digest(event['graph_sha256']),'complete fixture/private user/raw graph predicates')
  P.need(t['status']=='COMMITTED_SELECTED_LATEST_TOOL_REQUIRES_FULL_NATIVE_READBACK'and t['role']==role and t['product']==expected['name']and(t['before_count'],t['after_count'])==(len(expected['before']),len(expected['after']))and t['signature']=='REQUIRED_TEST_ONLY'and t['hooks']==t['scriptlets']=='DISABLED'and t['preservation']=='NOT_YET_CHECKED','original signed ordinary ALPM/noexec receipt, independent preservation follows');R.interval(t['transaction_clock'])
  process=event['transaction_process'];P.need(process['returncode']==0 and process['termination']is None and process['direct_child_reaped']is process['group_retired']is True and type(process['owned_group_id'])is int and process['owned_group_id']>1 and type(process['descendants_reaped'])is int and 0<=process['descendants_reaped']<=512 and all(type(process[k]['bytes'])is int and 0<=process[k]['bytes']<=128*1024 and digest(process[k]['sha256'])for k in('stdout','stderr')),'whole original transaction stdout/stderr/group retirement receipt');P.need(process['stdout']==R.pin((json.dumps(t,sort_keys=True)+'\n').encode()),'complete exact original isolated-step printed receipt/stream join')
  witness=t['lock_parent'];P.need(witness['path']=='var/lib/pacman'and witness['lock_created']is witness['lock_removed']is True and witness['before'][:6]==witness['after'][:6]and'db.lck'not in witness['names'],'exact ALPM lock lifetime witness')
  signature=t['signature_receipt'];P.need(signature is None if version is None else type(signature)is dict and signature['returncode']==0 and signature['group_retired']is True and re.fullmatch('[A-F0-9]{40}',signature['signer'])and all(type(signature[k]['bytes'])is int and 0<=signature[k]['bytes']<=65536 and digest(signature[k]['sha256'])for k in('status_stdout','status_stderr')),'complete original GPG signature/status/group pin receipt')
  observations=event['observations'];P.need(len(observations)==(0 if version is None else 2),'both ordinary homes for every installed acted role')
  if version is not None:
   P.need({r['home']for r in observations}=={'latest607-home-fresh','latest607-home-existing'},'two exact ordinary private homes')
   for row in observations:
    P.need((row['status'],row['role'],row['version'],row['phase'])==('PASS_ACTUAL_LATEST_TOOL_PRIVATE_FIXTURE',role,version,expected['phase'])and row['inventory_sha256']==hashlib.sha256(P.inventory_bytes(expected['after'])).hexdigest()and row['inventory_authority']=='SOURCE_OWNED_FULL_PACMAN_Q_SEPARATE_TOOL_QUERY_AUTHORITY'and row['hardware']=='NOT_RUN'and row['performance']=='NOT_CLAIMED'and row['release']=='NOT_ADMITTED','full actual installed fixture inventory/receipt scope')
    observed=row['observation'];new=version==P.product(role)[3];controls=observed['controls']
    if role=='boot':
     # Boot controls retain their complete actual synthetic decoded-record and
     # child/report/privacy proof through the exact original fixture validator.
     P.need(callable(boot_validator),'original full Boot fixture validator mandatory');boot_validator(controls,'77c326d908442852de51e66c660153d4c6051390b14466e48fa9c037cc1c573e')
     P.need(observed['real_journal']==observed['live_pstore']=='NOT_READ'and controls['status']=='PASS_INSTALLED_SYNTHETIC_FIXTURE_ONLY'and len(controls['checks'])==15 and controls['history_completeness']=='UNKNOWN'and controls['kernel_crash_diagnosis']=='NOT_ESTABLISHED','synthetic Boot scope only')
    elif role=='ksm':P.need(controls==dict(reporting=18,experiment=26,domain='PRIVATE_REGULAR_FILES_ONLY',live_kernel_write='NOT_RUN')if new else controls is None,'original44 KSM private controls; no sysfs claim')
    elif role=='apps':
     P.need(observed['CLI']==2 and observed['inventory_count']==len(expected['after'])and observed['applied']=='NOT_APPLIED','actual readonly Apps inventory')
     P.need(controls is None if not new else controls['status']=='PASS_INSTALLED_CONTROLS'and controls['tests']==15 and controls['failures']==controls['errors']==controls['skipped']==0 and controls['installed_source']is True,'whole original15 Apps controls')
    else:
     P.need(controls is None if not new else controls['tests']==(27 if role=='doctor'else 5)and controls['failures']==controls['errors']==controls['skipped']==0 and controls['scope']=='INSTALLED_SOURCE_PRIVATE_FIXTURE_ONLY','complete fixed Doctor27 or WelcomeCLI5 private controls')
     if role=='doctor':
      doctor(observed['report'],version,expected['after']);P.need(observed['CLI']==4 and observed['private_report']['mode']=='0600'and observed['private_report']['no_overwrite']is observed['private_report']['symlink_refusal']is True and observed['live_audio']=='NOT_RUN','Doctor report/privacy/nooverwrite/symlink scope')
     else:P.need(observed['GUI']=='NOT_RUN'and observed['status']['hardware_compatibility']=='not-assessed','Welcome readonly status, no GUI/hardware credit')
  if expected['action']=='restore-original'and version is not None:clocks[role]=t['transaction_clock']
 P.need(R.records(before,after,clocks)==value['selected_four_logical_restoration'],'whole retained rawselected4 before/after exact INSTALLDATE-only proof')
 aux=value['ldconfig'];P.need(type(aux)is list and len(aux)==26,'26 full fresh observations with explicitly shared retained blobs')
 for row in aux:
  P.need(row['source_owned_nonce']==nonce and row['retention']=='EXACT_EQUAL_BLOB_SHARED_AFTER_FRESH_COMPLETE_OBSERVATION'and row['state_reference']==aux[0]['state_reference']and row['auxiliary_reference']==aux[0]['auxiliary_reference']and row['state_reference']['path']=='container/latest607-ld-baseline606.json'and row['auxiliary_reference']['path']=='container/latest607-aux-baseline606.bin'and row['state_reference']['sha256']==row['state_sha256']and row['auxiliary_reference']['sha256']==row['aux_sha256'],'finite exact lossless auxiliary references; no inferred freshness')
 P.need([r['phase']for r in aux]==['baseline606',*(e['phase']for e in plan)]and len(aux)==26 and all(r['helper_exit']=='NOT_OBSERVED'and r['transition']['kind']=='RAW_EQUAL'and digest(r['state_sha256'])and digest(r['aux_sha256'])for r in aux),'all26 complete fresh source-owned raw auxiliary checkpoints')
 return value
