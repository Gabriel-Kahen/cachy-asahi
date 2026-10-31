#!/usr/bin/env python3
"""NEW synthetic prior-build retirement DATA controls; never executes actors."""
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import types

HERE=Path(__file__).resolve().parent
HELPER=HERE/'source/native/release_build_cause_v1.py'
PRIVACY=HERE/'source/native/release_projection_v1.py'
RESULTS=HERE/'new-prior-build-data-results'
MAP='2'*64
PRIMARY='command failed or retirement unknown: install-v1'

class Failure(RuntimeError):pass

def require(ok,why):
 if not ok:raise AssertionError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def read(path):
 require(path.resolve()==path and not any(p.is_symlink()for p in(path,*path.parents)),'fixed ordinary fixture Source')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);require(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<=1024**2,'bounded single-link Source DATA');raw=bytearray()
  while block:=os.read(fd,min(65536,a.st_size+1-len(raw))):raw.extend(block);require(len(raw)<=a.st_size,'whole Source cap')
  keys=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  require(len(raw)==a.st_size and tuple(getattr(a,k)for k in keys)==tuple(getattr(os.fstat(fd),k)for k in keys)==tuple(getattr(path.lstat(),k)for k in keys),'stable Source FD/path');return bytes(raw)
 finally:os.close(fd)

def load_frozen(helper_pin,privacy_pin):
 raw=read(HELPER);privacy=read(PRIVACY)
 require(pin(raw)['sha256']==helper_pin and pin(privacy)['sha256']==privacy_pin,'coordinator frozen helper/privacy pins')
 nodes=[n.value for n in ast.parse(privacy).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='PRIVATE_MARKER'for t in n.targets)]
 require(len(nodes)==1,'one authenticated privacy assignment');node=nodes[0]
 require(isinstance(node,ast.Call)and ast.unparse(node.func)=='re.compile'and len(node.args)==2 and not node.keywords and ast.unparse(node.args[1])=='re.I','exact authenticated regex AST form')
 pattern=ast.literal_eval(node.args[0]);require(type(pattern)is bytes,'bytes privacy literal')
 adapter=types.ModuleType('release_projection_v1');adapter.PRIVATE_MARKER=re.compile(pattern,re.I)
 denied=[]
 def audit(event,args):
  forbidden=event.startswith(('subprocess.','socket.','pty.','os.exec','os.spawn','os.fork','os.posix_spawn','ctypes.'))or event in('os.system','os.kill','os.killpg','signal.pthread_kill')
  if event=='open'and isinstance(args[0],(str,bytes,os.PathLike)):
   path=Path(os.fsdecode(args[0]));forbidden|=str(path).startswith(('/opt/native-release-tools-alpm-v1','/tmp/release-tools-test-'))
   if args[2]&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):forbidden|=not path.is_relative_to(RESULTS)
  if forbidden:denied.append(event);raise RuntimeError('DATA fixture denies actors and native-path access')
 sys.addaudithook(audit)
 sys.modules['release_projection_v1']=adapter
 spec=importlib.util.spec_from_file_location('release207_new_prior_fixture',HELPER);helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
 return helper,dict(helper=pin(raw),privacy_source=pin(privacy),privacy_pattern=pin(pattern),projection_body_executed=False),denied

def snapshot(adopted=False):
 owner=710;leader=dict(pid=711,start_ticks=1000)
 member=dict(pid=711,state='Z',group=711,session=711,start_ticks=1000,ppid=owner,parent_relation='WAIT_OWNER_PID')
 value=dict(phase='PRE_REAP',reserved_leader=leader,wait_owner_pid=owner,wait_owner_subreaper='NOT_OBSERVED',member_count=1,members=[member],truncated=False)
 if adopted:
  candidate=dict(pid=712,state='Z',group=711,session=711,start_ticks=1001,ppid=owner,parent_relation='WAIT_OWNER_PID')
  value['adopted_child']=dict(schema=1,status='QUALIFIED_ONE_ADOPTED_CHILD_REAPED',candidate=candidate,initial_member_count=2,initial_scan_complete=True,waitid=dict(observed=True,pid=712,code='CLD_EXITED',status=0),identity_reverified=True,leader_reserved_before_reap=True,raw_reap=dict(attempted=True,pid=712,exit=0,status_matches=True),ownership='REAPED',target_queries_closed=True,before_leader_reap=True,final_scan_complete=True,final_census='RESERVED_LEADER_ONLY',refusal='NONE')
 return value

def supervision(group=True,adopted=False):
 value=dict(exit=0,reaped=True,ownership='REAPED',timeout=False,signals=[],output_complete=True,group_census='RESERVED_LEADER_ONLY',error=None,seconds=0.25,passed=True)
 if group:value['group_retirement']=snapshot(adopted)
 return value

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--helper-sha256',required=True);parser.add_argument('--privacy-sha256',required=True);args=parser.parse_args()
 require(all(re.fullmatch('[0-9a-f]{64}',v)for v in vars(args).values()),'explicit frozen pins')
 H,provenance,denied=load_frozen(args.helper_sha256,args.privacy_sha256)
 run_controls(H,provenance,denied)

def run_controls(H,provenance,denied):
 logs={};reads=[];cases=[];observations={}
 def memory_log(scope,name):
  require(scope==H.SCOPE and name=='004-install-v1.log','only in-memory failed-install output permitted');reads.append(name);return logs[name]
 H._read_log=memory_log
 output=b'synthetic install-v1 refusal; not a native observation\n'
 install=dict(step='install-v1',argv=['/usr/bin/pacman','--config','/tmp/release-tools-test-fixture/pacman.conf','--noconfirm','--noscriptlet','-U','/opt/native-release-tools-alpm-v1/build-inputs/v1/cachy-asahi-release-tools-0.1.0-1-any.pkg.tar.zst'],cwd='/tmp/release-tools-test-fixture',expected=0,success=False,log='004-install-v1.log',log_pin=pin(output),supervision=dict(supervision(group=False),exit=1,passed=False),channels='stdout+stderr combined in pipe order')
 def successful(stage='build-v1',group=True,adopted=False):
  return dict(step=stage,argv=H.argv(stage),cwd='/opt/native-release-tools-alpm-v1/build-inputs/'+stage[-2:],expected=0,success=True,log=('001-'if stage=='build-v1'else '002-')+stage+'.log',log_pin=pin(b'fresh synthetic successful-build log not exported'),supervision=supervision(group,adopted),channels='stdout+stderr combined in pipe order')
 def build(records=None,primary=None):
  logs.clear();reads.clear();logs[install['log']]=output
  records=[successful('build-v1'),successful('build-v2')]if records is None else copy.deepcopy(records)
  return H.build(H.SCOPE,records+[copy.deepcopy(install)],{},MAP,Failure(PRIMARY)if primary is None else primary)
 def summary(value):
  value=value['prior_build_retirement'];require(type(value)is dict and set(value)=={'build-v1','build-v2'},'exact two fixed slots');return value
 def unknown(slot,stage):
  require(slot==dict(status='UNKNOWN',role='SOURCE_SUCCESSFUL_BUILD_COMMAND_RETIREMENT_V1',step=stage,original_row_pin=None,log_pin=None,expected='UNKNOWN',success='UNKNOWN',supervision=None,pre_reap_snapshot_observation='UNKNOWN',adoption_observation='UNKNOWN',post_reap_group_absence='UNKNOWN'),'missing/refused facts remain UNKNOWN, never False')
 def refuse(value):
  try:H.validate(value,MAP)
  except (ValueError,TypeError,KeyError):return
  raise AssertionError('forged public summary accepted')
 def case(name,action):
  action();cases.append(dict(name=name,status='PASS_NEW_SYNTHETIC_DATA'))
 def two_roles():
  rows=[successful('build-v1'),successful('build-v2')];value=build(rows);prior=summary(value)
  for stage,row in zip(('build-v1','build-v2'),rows):
   slot=prior[stage];require(set(slot)=={'status','role','step','original_row_pin','log_pin','expected','success','supervision','pre_reap_snapshot_observation','adoption_observation','post_reap_group_absence'},'closed slot fields')
   require(slot['status']=='OBSERVED'and slot['role']=='SOURCE_SUCCESSFUL_BUILD_COMMAND_RETIREMENT_V1'and slot['step']==stage and type(slot['expected'])is int and slot['expected']==0 and slot['success']is True,'fixed successful command role')
   require(slot['original_row_pin']==pin(H.encoded(row))and slot['log_pin']==row['log_pin']and slot['supervision']==row['supervision'],'whole original row hash/log pin/exact supervision')
   require(slot['pre_reap_snapshot_observation']=='OBSERVED'and slot['adoption_observation']=='NOT_OBSERVED'and slot['post_reap_group_absence']=='UNKNOWN','sole-leader snapshot says no observed adoption; no postreap claim')
  require(reads==['004-install-v1.log'],'no prior-build body read');H.validate(value,MAP);observations['two_direct_snapshots']=value
 case('two_fixed_successful_build_roles_whole_original_pins_and_direct_snapshots',two_roles)
 def adopted():
  rows=[successful('build-v1',adopted=True),successful('build-v2',adopted=True)];value=build(rows)
  for stage,row in zip(('build-v1','build-v2'),rows):
   slot=summary(value)[stage];require(slot['status']=='OBSERVED'and slot['adoption_observation']=='OBSERVED'and slot['supervision']==row['supervision'],'qualified actual-shaped adoption DATA copied exactly')
   require(slot['post_reap_group_absence']=='UNKNOWN','adopted child is no postleader-reap census')
  H.validate(value,MAP);observations['synthetic_qualified_adoption_receipts']=value
 case('qualified_actual_shaped_adoption_receipts_copied_exactly_DATA_only',adopted)
 def missing():
  value=build([])
  for stage,slot in summary(value).items():unknown(slot,stage)
  rows=[successful('build-v1',group=False),successful('build-v2')];rows[1]['supervision']['group_retirement']=None;value=build(rows)
  for slot in summary(value).values():require(slot['status']=='OBSERVED'and slot['pre_reap_snapshot_observation']==slot['adoption_observation']==slot['post_reap_group_absence']=='UNKNOWN','missing snapshot is not false or invented observation')
 case('missing_roles_or_snapshot_stay_UNKNOWN_not_False',missing)
 def duplicate():
  first=successful();value=build([first,copy.deepcopy(first),successful('build-v2')]);unknown(summary(value)['build-v1'],'build-v1');require(summary(value)['build-v2']['status']=='OBSERVED','duplicate refusal stays in its fixed role')
 case('duplicate_role_refused_independently_of_other_fixed_role',duplicate)
 def arbitrary_rows():
  mutations=[lambda r:r['argv'].__setitem__(0,'/usr/bin/true'),lambda r:r['argv'].__setitem__(-1,'/opt/foreign/config'),lambda r:r.__setitem__('cwd','/tmp/foreign'),lambda r:r.__setitem__('log','../001-build-v1.log'),lambda r:r.__setitem__('log','001-build-v2.log'),lambda r:r.__setitem__('channels','stderr'),lambda r:r.__setitem__('expected',True),lambda r:r.__setitem__('expected',1)]
  for mutate in mutations:
   first=successful();mutate(first);value=build([first,successful('build-v2')]);unknown(summary(value)['build-v1'],'build-v1');require(summary(value)['build-v2']['status']=='OBSERVED','arbitrary row cannot migrate roles')
 case('arbitrary_argv_cwd_log_channels_and_expectation_refused',arbitrary_rows)
 def unrelated():
  first=successful();first['step']='build-v3';value=build([first]);unknown(summary(value)['build-v1'],'build-v1');unknown(summary(value)['build-v2'],'build-v2')
  for primary in(Failure('unrelated synthetic primary'),RuntimeError(PRIMARY)):
   value=build(primary=primary)
   for stage,slot in summary(value).items():unknown(slot,stage)
 case('unrelated_role_or_primary_cannot_admit_prior_success',unrelated)
 def non_success():
  for change in [lambda r:r.__setitem__('success',False),lambda r:r.__setitem__('success',1),lambda r:r.__setitem__('launch_error','synthetic launch failure')]:
   first=successful();change(first);value=build([first]);unknown(summary(value)['build-v1'],'build-v1')
 case('non_success_bool_forgery_and_any_launch_error_refused',non_success)
 def bad_supervision():
  mutations={'exit':1,'reaped':False,'ownership':'OWNED','passed':False,'timeout':True,'signals':['SIGTERM'],'error':'synthetic error','output_complete':False,'group_census':'UNKNOWN','seconds':300}
  for key,bad in mutations.items():
   first=successful();first['supervision'][key]=bad;unknown(summary(build([first]))['build-v1'],'build-v1')
  for bad in(True,-1,float('nan'),float('inf')):
   first=successful();first['supervision']['seconds']=bad;unknown(summary(build([first]))['build-v1'],'build-v1')
  first=successful();first['supervision']['exit']=True;unknown(summary(build([first]))['build-v1'],'build-v1')
 case('nonzero_unreaped_unknown_timeout_signal_error_output_and_deadline_states_refused',bad_supervision)
 def bad_snapshot():
  mutations=[lambda s:s.__setitem__('phase','POST_REAP'),lambda s:s['members'][0].__setitem__('state','S'),lambda s:s['members'][0].__setitem__('start_ticks',999),lambda s:s.__setitem__('truncated',True),lambda s:s.__setitem__('wait_owner_subreaper',True),lambda s:s['members'][0].__setitem__('parent_relation','OTHER')]
  for mutate in mutations:
   first=successful();mutate(first['supervision']['group_retirement']);unknown(summary(build([first]))['build-v1'],'build-v1')
  first=successful();s=first['supervision']['group_retirement'];s['member_count']=2;s['members'].append(dict(s['members'][0],pid=713,start_ticks=1002));unknown(summary(build([first]))['build-v1'],'build-v1')
 case('pre_reap_group_identity_live_member_truncation_extra_member_and_subreaper_forgery_refused',bad_snapshot)
 def bad_adoption():
  mutations=[lambda a:a['candidate'].__setitem__('state','S'),lambda a:a['raw_reap'].__setitem__('exit',1),lambda a:a['waitid'].__setitem__('status',1),lambda a:a.__setitem__('ownership','WNOWAIT_RESERVED'),lambda a:a.__setitem__('final_scan_complete',False),lambda a:a.__setitem__('target_queries_closed',False)]
  for mutate in mutations:
   first=successful(adopted=True);mutate(first['supervision']['group_retirement']['adopted_child']);unknown(summary(build([first]))['build-v1'],'build-v1')
 case('adoption_live_status_wait_identity_ownership_and_closed_query_forgery_refused',bad_adoption)
 def public_forgery():
  baseline=build()
  mutations=[lambda s:s.__setitem__('role','OTHER'),lambda s:s.__setitem__('step','build-v2'),lambda s:s.__setitem__('expected',True),lambda s:s.__setitem__('success',1),lambda s:s['original_row_pin'].__setitem__('bytes',-1),lambda s:s.__setitem__('post_reap_group_absence',True),lambda s:s.__setitem__('adoption_observation','OBSERVED'),lambda s:s.__setitem__('pre_reap_snapshot_observation','UNKNOWN')]
  for mutate in mutations:
   value=copy.deepcopy(baseline);mutate(summary(value)['build-v1']);refuse(value)
  value=copy.deepcopy(baseline);value['primary']['message']='forged primary';refuse(value)
  value=copy.deepcopy(baseline);value['native']='ADMITTED';refuse(value)
 case('public_role_pin_observation_primary_and_acceptance_forgery_refused',public_forgery)
 def illegal_slots():
  baseline=build();extra=copy.deepcopy(baseline);extra['prior_build_retirement']['build-v3']=copy.deepcopy(summary(extra)['build-v1']);refuse(extra)
  missing=copy.deepcopy(baseline);del missing['prior_build_retirement']['build-v2'];refuse(missing)
 case('extra_or_missing_fixed_map_slot_rejected',illegal_slots)
 def private_and_caps():
  value=build();serialized=H.encoded(summary(value))
  require(all(token not in serialized for token in(b'/opt/',b'/tmp/',b'/home/',b'"argv":',b'"cwd":',b'001-build-v1.log',b'002-build-v2.log',b'fresh synthetic successful-build log',b'"output":',b'"body":')),'no command paths/log names/body/output in summaries')
  require(H.ROW_CAP==16*1024 and H.MAX_LINE==32*1024 and len(H.encoded(successful()))<H.ROW_CAP and len(H.MARKER.encode())+len(H.encoded(value))+1<=H.MAX_LINE,'original row and whole additive marker bounds held')
  first=successful();first['supervision']['error']='PRIVATE_KEY=synthetic_only';unknown(summary(build([first]))['build-v1'],'build-v1')
  first=successful();first['channels']='x'*(H.ROW_CAP+1);require(len(H.encoded(first))>H.ROW_CAP,'oversize row fixture');unknown(summary(build([first]))['build-v1'],'build-v1')
 case('private_fields_bodies_and_oversize_raw_rows_not_exported_marker_caps_held',private_and_caps)
 def anchor():
  value=build();public=value['command']['row'];require(value['stage']=='install-v1'and value['command']['status']=='OBSERVED'and value['observed_exit']==1,'one NEW install anchor')
  require(public['original_row_pin']==pin(H.encoded(install))and public['cwd']=='[REDACTED_INSTALL_WORK]'and public['argv'][2]=='[REDACTED_INSTALL_WORK]/pacman.conf'and public['supervision']==install['supervision'],'install redaction/original hash/supervision unchanged')
  require(value['native']==value['release']=='NOT_ADMITTED'and value['physical_M2']=='NOT_RUN','no migration/native/acceptance authority');H.validate(value,MAP)
 case('one_NEW_install_public_contract_anchor_no_old12_replay',anchor)
 require(not denied and not {'capsule','reader','release_reader_v1'}.intersection(sys.modules),'no actor/capsule/reader execution')
 RESULTS.mkdir(mode=0o700,exist_ok=False)
 result=dict(schema=1,status='PASS_NEW_PRIOR_BUILD_RETIREMENT_SYNTHETIC_DATA_CONTROLS',total=len(cases),cases=cases,provenance=provenance,privacy_adapter='ModuleType from authenticated PRIVATE_MARKER AST literal; projection body not executed',log_adapter='in-memory failed-install only; prior successful build bodies never read',fixture_map_sha256=MAP,synthetic_process_identifiers=True,observations_not_actual=True,actor_denial_before_new_helper_import=True,denied_actor_attempts=denied,old12_controls_rerun=False,old_suite_reader_capsule_replays=0,native_GPG_VM_Git_API_GET_runtime_actors=0,native='NOT_ADMITTED',physical_M2='NOT_RUN',release='NOT_ADMITTED')
 for name,value in [('results.json',result),('fixture-observations.json',observations)]:
  with(RESULTS/name).open('x')as stream:json.dump(value,stream,indent=2,sort_keys=True,allow_nan=False);stream.write('\n')
 print(json.dumps(dict(status=result['status'],controls=len(cases),synthetic_DATA_only=True,native='NOT_ADMITTED'),sort_keys=True))

if __name__=='__main__':main()
