# SPDX-License-Identifier: MIT
"""Closed diagnostic data; no normal ALPM/lifecycle acceptance status exists."""
import json,re
STATUS='FIRST_NORMAL_SOURCE_OBSERVER_RETURNED_DIAGNOSTIC_ONLY'
DONE='FIRST_NORMAL_SOURCE_OBSERVER_DIAGNOSTIC_COMPLETED_NO_ACCEPTANCE'
FORBIDDEN='FORBIDDEN_DIAGNOSTIC_ONLY_NO_LIFECYCLE_ACCEPTANCE'
ROUTE='FIRST_NORMAL_SOURCE_OBSERVER_ONLY_600S_NO_ACCEPTANCE'
PREFIX='DEBIAN_MAINTAINED_SOURCE_OBSERVER16K'
FILES={'result.json':65536,'isolation.json':65536,'pristine-guest-progress.log':65536}
def need(ok,why):
 if not ok:raise ValueError(why)
def row(v):
 need(type(v) is dict and set(v)=={'bytes','sha256'} and type(v['bytes']) is int and 0<v['bytes']<=64*1024**2 and type(v['sha256']) is str and re.fullmatch('[0-9a-f]{64}',v['sha256']),'closed finite diagnostic pin')
def subject(v,s):
 need(type(v) is dict and set(v)=={'status','acceptance','source_sha','nonce','page_size','source_nodes_sha256','complete','nodes','capabilities','stop','normal_subject','normal_failure','ALPM','normal_lifecycle','hardware','release'},'closed first-normal-observer subject')
 need(s.get('diagnostic_route')==ROUTE and v['status']==STATUS and v['acceptance']==FORBIDDEN and v['source_sha']==s['source_sha'] and v['nonce']==s['nonce'] and v['page_size']==16384 and type(v['page_size']) is int and v['source_nodes_sha256']==s['source_nodes_sha256'] and v['complete'] is True and type(v['nodes']) is int and 0<v['nodes']<=500000,'complete actual16K first original source observation identity')
 need(v['capabilities']=='NOT_RUN_STOPPED_BEFORE_CAPABILITY_OBSERVER' and v['stop']=='AFTER_FIRST_ROOTS_OBSERVE_BEFORE_CAPS_CLONE_ALPM' and v['normal_subject']=='UNCHANGED_NORMAL_G_WORKER_MAIN','exact diagnostic-only stopping seam')
 failure=v['normal_failure'];need(type(failure) is dict and set(failure)=={'exit_code','status','error_type','error'} and type(failure['exit_code']) is int and failure==dict(exit_code=1,status='FAIL',error_type='FirstObserverComplete',error='DIAGNOSTIC_STOP_AFTER_FIRST_OBSERVER_BEFORE_CAPABILITIES'),'unchanged normal program refuses diagnostic interruption')
 need(v['ALPM']==v['normal_lifecycle']==v['hardware']=='NOT_RUN' and v['release']=='NOT_ADMITTED','diagnostic cannot credit lifecycle/hardware/release');return v

def protocol(C,raw,s):
 need(type(raw) is bytes and len(raw)<=16*1024**2,'UART bound')
 need(not any(line.startswith((b'DEBIAN_MAINTAINED_INSTALLED16K ',b'GNU_INSTALLED16K ',b'GNU_SOURCE_OBSERVER_ONLY ')) for line in raw.splitlines()),'foreign normal/child receipt is not a diagnostic UART event')
 prefix=(PREFIX+' '+s['nonce']+' ').encode();lines=[line.rstrip(b'\r') for line in raw.splitlines() if line.startswith((PREFIX+' ').encode())]
 need(len(lines)==3 and all(line.startswith(prefix) for line in lines),'three nonce-bound diagnostic events')
 events=[C.decode(line[len(prefix):]) for line in lines];need([v.get('event') for v in events]==['boot','result','exit'],'ordered diagnostic events')
 boot,result,exit=events
 need(set(boot)=={'event','page_size','kernel','architecture','kernel_profile_sha256','observer_nofile','diagnostic_route'} and boot['page_size']==16384 and type(boot['page_size']) is int and boot['kernel']==s['kernel']['release'] and boot['architecture']=='aarch64' and boot['kernel_profile_sha256']==s['kernel_profile_sha256'] and boot['diagnostic_route']==ROUTE,'actual boot/profile/route binding')
 n=boot['observer_nofile'];need(type(n) is dict and set(n)=={'before','after','scope'} and type(n['before']) is list and len(n['before'])==2 and all(type(x) is int and 0<x<=2**31-1 for x in n['before']) and n['before'][0]<=n['before'][1] and n['after']==[8192,8192] and all(type(x) is int for x in n['after']) and n['scope']=='NATIVE_TRIAL_8192_BOTH_INHERITED_BY_LIFECYCLE_CHILD','exact inherited descriptor limit')
 need(set(result)=={'event','subject','isolation','files','bytes','acceptance','supervisor'},'closed source diagnostic result');subject(result['subject'],s);need(result['acceptance']==FORBIDDEN,'diagnostic only')
 supervisor=result['supervisor'];need(supervisor==dict(exit_code=0,group_absence_verified=True,time_limit=600) and type(supervisor['exit_code']) is int and supervisor['group_absence_verified'] is True and type(supervisor['time_limit']) is int,'actual successful600s supervisor retirement')
 isolation=result['isolation'];need(type(isolation) is dict and set(isolation)=={'status','mask','no_new_privs','seccomp','raw_block_devices','writable_source_alias','mount_flags','filter_sha256','held_capability_helper','held_ipc_helper'} and all(type(isolation[k]) is int for k in ('mask','no_new_privs','seccomp')) and re.fullmatch('[0-9a-f]{64}',isolation['filter_sha256']) and isolation['held_capability_helper']=='UNCHANGED_REDUCE_CAPABILITIES_BODY_WITH_EXPLICIT_GNU_MASK' and isolation['held_ipc_helper']=='UNCHANGED_AARCH64_BLOCK_SERVICE_IPC' and isolation.get('status')=='PASS_OBSERVED_NATIVE_CAPS_AND_MOUNT_FENCE' and isolation.get('mask')==2149843195 and isolation.get('no_new_privs')==1 and isolation.get('seccomp')==2 and isolation.get('raw_block_devices')==[] and isolation.get('writable_source_alias') is False and isolation.get('mount_flags')==[15,4096],'original source subject authority')
 files=result['files'];need(type(files) is dict and set(files)==set(FILES),'fixed diagnostic files only')
 for name,pin in files.items():row(pin);need(pin['bytes']<=FILES[name],'fixed diagnostic file limit')
 need(type(result['bytes']) is int and result['bytes']==sum(p['bytes'] for p in files.values())<=sum(FILES.values()),'finite diagnostic export total')
 need(exit==dict(event='exit',status=DONE,cleanup='PASS_OWNED_CLONES_REMOVED',acceptance=FORBIDDEN),'original mount retirement plus diagnostic qualification');return result
