#!/usr/bin/env python3
"""NEW synthetic helper DATA controls; no native actor or historical-suite replay."""
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
OUTPUT=HERE/'data-control-results'
MAP='1'*64  # Deliberately synthetic binding, never native Source acceptance.
WORK='/tmp/release-tools-test-fixture'
ARCHIVE='/opt/native-release-tools-alpm-v1/build-inputs/v1/cachy-asahi-release-tools-0.1.0-1-any.pkg.tar.zst'
PRIMARY='command failed or retirement unknown: install-v1'

class Failure(RuntimeError):pass

def require(ok,message):
 if not ok:raise AssertionError(message)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def ordinary(path):
 require(path.resolve()==path and not any(x.is_symlink()for x in(path,*path.parents)),'ordinary fixed Source DATA')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);require(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<=1024**2,'bounded Source DATA');raw=bytearray()
  while block:=os.read(fd,min(65536,a.st_size+1-len(raw))):raw.extend(block);require(len(raw)<=a.st_size,'stable Source bound')
  keys=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  require(len(raw)==a.st_size and tuple(getattr(a,k)for k in keys)==tuple(getattr(os.fstat(fd),k)for k in keys)==tuple(getattr(path.lstat(),k)for k in keys),'stable whole Source DATA');return bytes(raw)
 finally:os.close(fd)

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--helper-sha256',required=True);parser.add_argument('--privacy-sha256',required=True)
 args=parser.parse_args()
 for value in(vars(args).values()):require(re.fullmatch('[0-9a-f]{64}',value)is not None,'explicit frozen pin')
 helper_raw=ordinary(HELPER);privacy_raw=ordinary(PRIVACY)
 require(pin(helper_raw)['sha256']==args.helper_sha256 and pin(privacy_raw)['sha256']==args.privacy_sha256,'coordinator frozen helper/privacy pins')
 tree=ast.parse(privacy_raw)
 assignments=[node for node in tree.body if isinstance(node,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='PRIVATE_MARKER'for t in node.targets)]
 require(len(assignments)==1,'one exact privacy literal')
 call=assignments[0].value
 require(isinstance(call,ast.Call)and ast.unparse(call.func)=='re.compile'and len(call.args)==2 and not call.keywords and ast.unparse(call.args[1])=='re.I','exact privacy regex AST form')
 pattern=ast.literal_eval(call.args[0]);require(type(pattern)is bytes,'bytes privacy literal')
 adapter=types.ModuleType('release_projection_v1');adapter.PRIVATE_MARKER=re.compile(pattern,re.I)
 actor_events=[]
 def deny(event,values):
  forbidden=event.startswith(('subprocess.','socket.','pty.','os.exec','os.spawn','os.fork','os.posix_spawn','ctypes.'))or event in('os.system','os.kill','os.killpg','signal.pthread_kill')
  if event=='open':
   path=values[0];flags=values[2]
   if isinstance(path,(str,bytes,os.PathLike)):
    path=Path(os.fsdecode(path));forbidden|=str(path).startswith(('/opt/native-release-tools-alpm-v1','/tmp/release-tools-test-'))
    if flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND):forbidden|=not path.is_relative_to(OUTPUT)
  if forbidden:actor_events.append(event);raise RuntimeError('fixture actor or real native-path access denied')
 sys.addaudithook(deny)  # Process-local; installed BEFORE importing changed helper.
 sys.modules['release_projection_v1']=adapter
 spec=importlib.util.spec_from_file_location('release206_new_helper_fixture',HELPER)
 H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)
 require('capsule'not in sys.modules,'no capsule/reader import')
 logs={};reads=[]
 def in_memory_log(scope,name):
  require(scope==H.SCOPE,'fixed role only');reads.append(name);require(name in logs,'fixture log must exist');return logs[name]
 H._read_log=in_memory_log
 def supervision(exit=1):
  return dict(exit=exit,reaped=True,ownership='REAPED',timeout=False,signals=[],output_complete=True,group_census='RESERVED_LEADER_ONLY',error=None,seconds=0.125,passed=False)
 def row(output=b'pacman: synthetic installation refused\n'):
  return dict(step='install-v1',argv=['/usr/bin/pacman','--config',WORK+'/pacman.conf','--noconfirm','--noscriptlet','-U',ARCHIVE],cwd=WORK,expected=0,success=False,log='004-install-v1.log',log_pin=pin(output),supervision=supervision(),channels='stdout+stderr combined in pipe order')
 def build(record=None,output=b'pacman: synthetic installation refused\n',primary=None,records=None):
  logs.clear();reads.clear();logs['004-install-v1.log']=output
  original=row(output)if record is None else copy.deepcopy(record)
  return H.build(H.SCOPE,[original]if records is None else records,{},MAP,Failure(PRIMARY)if primary is None else primary)
 def validate(value):return H.validate(value,MAP)
 def refuses(value):
  try:validate(value)
  except (ValueError,TypeError,KeyError):return
  raise AssertionError('mutated public DATA was accepted')
 observations={};cases=[]
 def case(name,action):
  try:action();cases.append(dict(name=name,status='PASS_SYNTHETIC_DATA'))
  except BaseException as error:cases.append(dict(name=name,status='FAIL_SYNTHETIC_DATA',failure_type=type(error).__name__));raise
 def observed_install():
  output=b'\x1b[31msynthetic refusal\x1b[0m '+WORK.encode()+b'/pacman.conf https://example.invalid/p /home/synthetic/private\n'
  original=row(output);primary=Failure(PRIMARY);value=build(original,output,primary)
  require(value['stage']=='install-v1'and value['command']['status']=='OBSERVED'and value['observed_exit']==1,'exact install observed')
  public=value['command']['row'];require(public['original_row_pin']==pin(H.encoded(original))and value['command']['pin']==pin(H.encoded(public)),'original and public canonical pins')
  require(public['cwd']=='[REDACTED_INSTALL_WORK]'and public['argv'][2]=='[REDACTED_INSTALL_WORK]/pacman.conf'and public['supervision']==original['supervision'],'only work paths redacted; supervision preserved')
  require(set(public)==set(original)|{'original_row_pin','redaction'}and public['redaction']==dict(scheme='install-v1-work-root-v1',role='FAILED_INSTALL_V1_ORIGINAL_COMMAND',fields=['cwd','argv[2]'],replacement='[REDACTED_INSTALL_WORK]'),'exact fixed redaction schema')
  require(value['output']['status']=='OBSERVED_SUFFIX'and all(x not in value['output']['suffix']for x in(WORK,'https://','/home/','\x1b')),'sanitized output suffix')
  require(value['primary']==dict(type='Failure',message=PRIMARY,message_pin=pin(PRIMARY.encode()))and str(primary)==PRIMARY,'primary retained')
  require(value['native']==value['release']=='NOT_ADMITTED'and value['physical_M2']=='NOT_RUN','nonaccepting DATA only');validate(value);observations['observed_install']=value
 case('exact_install_original_public_pins_redaction_primary_nonacceptance',observed_install)
 def launch_unknown():
  original=row();original['supervision']=None;original['launch_error']='synthetic launch failure';value=build(original)
  require(value['command']['status']=='OBSERVED'and value['observed_exit']=='UNKNOWN'and value['command']['row']['supervision']is None,'no invented launch exit');validate(value)
 case('launch_error_without_supervision_exit_stays_UNKNOWN',launch_unknown)
 def arbitrary_commands():
  variants=[]
  for mutate in [lambda r:r['argv'].__setitem__(0,'/usr/bin/true'),lambda r:r['argv'].__setitem__(2,WORK+'/other.conf'),lambda r:r['argv'].__setitem__(5,'--needed'),lambda r:r['argv'].__setitem__(-1,ARCHIVE.replace('0.1.0-1','0.1.1-1')),lambda r:r.__setitem__('cwd','/tmp/foreign'),lambda r:r.__setitem__('log','../004-install-v1.log'),lambda r:r.__setitem__('log','004-build-v1.log'),lambda r:r.__setitem__('step','install-v2'),lambda r:r.__setitem__('expected',True)]:
   original=row();mutate(original);variants.append(original)
  for original in variants:
   value=build(original);require(value['command']['status']!='OBSERVED'and value['observed_exit']=='UNKNOWN'and not reads,'foreign row refused before log read')
 case('arbitrary_argv_cwd_archive_log_step_bool_expectation_refused',arbitrary_commands)
 def duplicate_refusal():
  original=row();value=build(records=[original,copy.deepcopy(original)]);require(value['command']['status']=='UNKNOWN'and value['stage']=='UNKNOWN'and not reads,'duplicate candidate cannot be selected')
 case('duplicate_install_candidates_not_admitted',duplicate_refusal)
 def unrelated_primary():
  for primary in(Failure('unrelated failure'),RuntimeError(PRIMARY)):
   value=build(primary=primary);require(value['stage']=='UNKNOWN'and value['command']['status']=='UNKNOWN'and not reads,'only exact original Failure role selects install')
 case('unrelated_message_or_primary_type_not_admitted',unrelated_primary)
 def privacy_refusal():
  output=b'PRIVATE_KEY=synthetic_fixture_only\n'+b'safe filler\n'*400+b'safe ending\n';value=build(row(output),output)
  require(value['output']==dict(status='REFUSED_PRIVACY',pin=pin(output),suffix=None),'whole original privacy scan precedes safe suffix');validate(value)
 case('private_marker_before_safe_suffix_refuses_entire_output',privacy_refusal)
 def mismatch_refusal():
  original=row(b'different original log\n');value=build(original,b'captured synthetic log\n');require(value['output']['status']=='REFUSED_PIN'and value['output']['suffix']is None,'whole log pin mismatch refuses suffix');validate(value)
 case('output_pin_mismatch_refused',mismatch_refusal)
 def cap_refusal():
  output=b'x'*(1024**2+1);value=build(row(b'bounded original pin\n'),output);require(value['output']['status']=='UNAVAILABLE_OR_REFUSED_READ'and value['output']['pin']is None and value['output']['suffix']is None,'whole output cap refuses')
 case('output_over_one_MiB_refused',cap_refusal)
 def positive_forgery():
  original=row();original['success']=True;value=build(original);require(value['command']['status']=='UNKNOWN'and not reads,'positive original row not selected')
  baseline=build()
  for key,value in [('native','ADMITTED'),('release','ADMITTED'),('operation','forged-operation'),('status','PASS')]:
   forged=copy.deepcopy(baseline);forged[key]=value;refuses(forged)
  forged=copy.deepcopy(baseline);forged['command']['row']['success']=True;forged['command']['pin']=pin(H.encoded(forged['command']['row']));refuses(forged)
 case('positive_row_and_acceptance_marker_forgery_refused',positive_forgery)
 def public_tampering():
  baseline=build()
  for change in [lambda r:r.__setitem__('cwd',WORK),lambda r:r['argv'].__setitem__(2,WORK+'/pacman.conf'),lambda r:r['redaction'].__setitem__('role','OTHER'),lambda r:r['redaction'].__setitem__('fields',['cwd']),lambda r:r['original_row_pin'].__setitem__('bytes',-1)]:
   forged=copy.deepcopy(baseline);change(forged['command']['row']);forged['command']['pin']=pin(H.encoded(forged['command']['row']));refuses(forged)
  forged=copy.deepcopy(baseline);forged['observed_exit']=True;refuses(forged)
  forged=copy.deepcopy(baseline);forged['command']['row']['supervision']['exit']=2;refuses(forged)
 case('tampered_public_row_redaction_pins_and_exit_types_refused',public_tampering)
 def build_fixture():
  output=b'new synthetic makepkg failure\n';logs.clear();reads.clear();logs['001-build-v1.log']=output
  original=dict(step='build-v1',argv=H.argv('build-v1'),cwd='/opt/native-release-tools-alpm-v1/build-inputs/v1',expected=0,success=False,log='001-build-v1.log',log_pin=pin(output),supervision=supervision(),channels='stdout+stderr combined in pipe order')
  value=H.build(H.SCOPE,[original],{},MAP,Failure('command failed or retirement unknown: build-v1'));require(value['stage']=='build-v1'and value['command']['row']==original and value['observed_exit']==1 and value['native']=='NOT_ADMITTED','new exact build fixture remains DATA-only');validate(value)
 case('new_build_v1_fixture_preserves_existing_DATA_contract',build_fixture)
 def primary_identity():
  try:raise Failure(PRIMARY)
  except Failure as primary:
   trace=primary.__traceback__
   for kind in(Exception,ValueError,RuntimeError,KeyboardInterrupt,SystemExit,GeneratorExit,BaseException):
    def fail(kind=kind):raise kind('synthetic later cleanup failure')
    require(H.preserve_primary(primary,fail)is primary and primary.__traceback__ is trace,'later BaseException cannot replace primary')
   build(primary=primary,output=b'PRIVATE_KEY=synthetic_fixture_only\n');require(primary.__traceback__ is trace and str(primary)==PRIMARY,'privacy refusal retains primary identity/trace')
 case('primary_identity_traceback_survives_later_BaseExceptions_and_privacy_refusal',primary_identity)
 require(not actor_events and 'capsule'not in sys.modules and not any(name.endswith('reader')for name in sys.modules),'no denied actors or reader/capsule execution')
 OUTPUT.mkdir(mode=0o700,exist_ok=False)
 result=dict(schema=1,status='PASS_NEW_SYNTHETIC_HELPER_DATA_CONTROLS',cases=cases,total=len(cases),helper=pin(helper_raw),privacy_source=pin(privacy_raw),privacy_adapter=dict(kind='ModuleType exact authenticated AST PRIVATE_MARKER bytes literal plus re.I',pattern_pin=pin(pattern),projection_module_executed=False),log_adapter='EXPLICIT_IN_MEMORY_ONLY_NO_NATIVE_FILESYSTEM',fixture_map_sha256=MAP,synthetic_DATA_only=True,actor_denial_installed_before_helper_import=True,denied_actor_attempts=actor_events,Source_capsule_or_reader_imports=0,native_GPG_VM_Git_API_GET_actors=0,old_suite_replays=0,native='NOT_ADMITTED',physical_M2='NOT_RUN',release='NOT_ADMITTED')
 for name,value in [('results.json',result),('fixture-observations.json',observations)]:
  path=OUTPUT/name
  with path.open('x')as stream:json.dump(value,stream,indent=2,sort_keys=True,allow_nan=False);stream.write('\n')
 print(json.dumps(dict(status=result['status'],controls=len(cases),synthetic_DATA_only=True,native='NOT_ADMITTED'),sort_keys=True))

if __name__=='__main__':main()
