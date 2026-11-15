#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-reviewed next VM invocation using the unchanged completed substrate."""
import argparse,hashlib,importlib.util,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;SUB=HERE.parent/'systemd_tcg_guest'
EXPECTED_BOOT='e7c8935f342d4b36bb6f8f24c0b48c3b8aa04be9807f62c3f8141aeaf26819fc'
def parse_journey(data,nonce):
 text=data.decode(errors='replace').replace('\r','');begin='NM_SESSION_BEGIN '+nonce+'\n';end='\nNM_SESSION_END '+nonce
 assert text.count(begin)==1 and text.count(end)==1,'missing/duplicate NM session frame'
 body=text.split(begin,1)[1].split(end,1)[0];assert len(body)<256*1024
 value=json.loads(body);assert value['schema_version']==1
 return value
def accept(value):
 assert value['status']=='PASS_X86_REAL_LOGIN_OWN_PROFILE_AND_DENIALS_ONLY',value.get('failure',value['status'])
 assert value['account']['uid']==value['account']['gid']==1000 and value['account']['tty']=='/dev/ttyS0'
 assert value['bus_identity']['UnixUserID']==1000 and value['bus_identity']['ProcessID']==value['account']['pid']
 assert value['logind']['Active']is True and value['logind']['Name']=='builder'and value['logind']['Type']=='tty'and value['logind']['Class']=='user'and value['logind']['Service']=='login'and value['logind']['Remote']is False
 for service,uid in [('org.freedesktop.NetworkManager',0),('org.freedesktop.PolicyKit1',102),('org.freedesktop.login1',0)]:assert value['service_bus_identities'][service]['credentials']['UnixUserID']==uid
 assert value['stock_service_states']==['active']*4
 assert value['agent']['registered']is True and value['agent']['same_real_login_session']is True and value['agent']['process_subject_pid']==value['account']['pid']
 assert value['own_create']['success']and value['own_edit']['success']and value['own_cleanup']['success']and value['persistence']['passed']
 assert len(value['denials'])==2 and {x['name']for x in value['denials']}=={'system-delete','foreign-delete'}and all(x['success']is False for x in value['denials'])
 assert value['denied_state']['passed']and value['denied_state']['complete_profile_policy_package_snapshot_unchanged']
 root=value['root_observer'];assert root['status']=='PASS_X86_ROOT_OBSERVATION_ONLY'
 for k in ['own_persisted','denied_state_unchanged','own_profile_cleanup','user_and_original_profiles_preserved','inventory_policy_PAM_unchanged']:assert root[k]is True,k
 assert root['initial']==root['final']and value['agent_exit']in {0,-15},'root state/normal agent retirement failed'
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-first-nm-session-vm-boot',action='store_true');p.add_argument('--prepared',type=Path,required=True);p.add_argument('--prepared-sha256',required=True);p.add_argument('--tool-image',required=True);p.add_argument('--tool-image-id',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(a.allow_first_nm_session_vm_boot and __debug__ and os.geteuid()!=0):p.error('explicit reviewed next experiment and ordinary host user required')
 assert hashlib.sha256((SUB/'boot.py').read_bytes()).hexdigest()==EXPECTED_BOOT,'completed controller drift refused'
 # The fixed controller owns all process/container/signal/once/serial cleanup.
 # Its source and original once marker are never edited or reset here.
 spec=importlib.util.spec_from_file_location('nm_session_fixed_controller',SUB/'boot.py');controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(controller)
 original=sys.argv;sys.argv=[str(SUB/'boot.py'),'--allow-first-x86-reference-boot','--prepared',str(a.prepared),'--prepared-sha256',a.prepared_sha256,'--tool-image',a.tool_image,'--tool-image-id',a.tool_image_id,'--output',str(a.output)]
 try:code=controller.main()
 finally:sys.argv=original
 out=a.output.resolve();result={'schema_version':1,'status':'HOLD','scope':'x86 full-system real-login NM own-profile and denial software only','ARM_M2_release':'NOT RUN','substrate_report':str(out/'report.json'),'password_policy':'Own writes allowed for active users by unchanged upstream policy; genuine password verification is serial PAM login; no forced own-write challenge'}
 try:
  substrate=json.loads((out/'report.json').read_text());assert code==0 and substrate['status']=='PASS_X86_REFERENCE_SERIAL_PAM_SESSION_ONLY'
  prepared=json.loads((a.prepared/'prepared.json').read_text());journey=parse_journey((out/'serial.redacted.log').read_bytes(),prepared['nonce']);result['journey']=journey;accept(journey)
  result['status']='PASS_X86_REAL_LOGIN_OWN_PROFILE_AND_DENIALS_ONLY'
 except BaseException as e:result['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 (out/'journey.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');print(json.dumps({'status':result['status'],'report':str(out/'journey.json'),'failure':result.get('failure')}));return 0 if result['status'].startswith('PASS_')else 1
if __name__=='__main__':raise SystemExit(main())
