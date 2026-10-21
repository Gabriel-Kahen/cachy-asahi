"""Exact Root boot availability DATA, never runtime mapping authority."""
import deploy as D
DECISION={'bytes': 9265, 'sha256': '301c4cb3c9edddac92064f6f9845d8255d5940e30175ea8c8ff286a5bbf87492'}
STRICT={'bytes': 16477, 'sha256': '086c4a0b9389b56cf4d16454244e44fc2a2237c4331b63747516ea4cc67277e3'}
SOURCE='bd31022395cc9231dfd966a4c0efc589ac1d49c2'
REF='codex/gnu-verity-kernel-boot-probe-v1'
RUN=39159992802
SCOPE=['GENERIC16K_BOOT','ACTUAL_PID1','AT_PAGESZ_16384','DM_VERSION','VERITY_TARGET_AVAILABLE','NATURAL_POWEROFF']
def projection(raw,result,kernel):
 D.need(D.pin(raw)==DECISION and D.pin(result)==STRICT,'exact source-held Root boot decision and strict-result pin')
 v=D.obj(raw);D.obj(result)
 D.need(v['status']=='ROOT_ACCEPTED_GNU_VERITY_STANDALONE_BOOT_DM_TARGET_AVAILABILITY_ONLY'and v['scope']=='BOOT_AND_DM_TARGET_AVAILABILITY_ONLY'and (v['source'],v['ref'],v['run'],v['attempt'])==(SOURCE,REF,RUN,1)and v['strict_result']==STRICT,'exact finite Root boot availability identity')
 i=v['kernel_input'];D.need(i['source']==kernel['source']and i['ref']==kernel['ref']and i['run_id']==kernel['run']and i['Image']==kernel['Image']and i['config']==kernel['config']and i['artifact']['id']==kernel['artifact']['id']and {n:i['artifact'][n]for n in('bytes','sha256')}==kernel['transport']['artifact'],'same exact accepted kernel build artifact')
 D.need(v['original_files']['Root-build-decision.json']==kernel['kernel_decision'],'whole Root build decision join')
 g=v['guest'];D.need(g['boot']['pid']==1 and g['boot']['machine']=='aarch64'and g['boot']['page_size']==16384 and g['dm_version']['version']==[4,50,0]and g['dm_targets']['targets']['verity']==[1,13,0]and g['poweroff_request']==dict(dm_closed=True,event='poweroff',method='LINUX_REBOOT_CMD_POWER_OFF',pid=1),'genuine finite boot PID1/page/DM/poweroff facts')
 D.need(all(v[n]=='NOT_TESTED'for n in('verity_mapping','integrity','lifecycle'))and v['hardware']=='NOT_RUN'and v['release']=='NOT_ADMITTED'and all(r['exit_code']==0 and r['natural_exit']is True and r['group_absence_verified']is True for r in v['native_commands']),'no mapping/lifecycle or hardware promotion')
 return dict(purpose='GNU_VERITY_KERNEL_BOOT_AVAILABILITY_ONLY_V1',source=SOURCE,run=RUN,kernel_build_decision=kernel['kernel_decision'],scope=SCOPE,page_size=16384,PID1=True,DM_VERSION=True,verity_target=True,poweroff='NATURAL',verity_mapping='NOT_QUALIFIED',integrity='NOT_QUALIFIED',lifecycle='NOT_QUALIFIED')
