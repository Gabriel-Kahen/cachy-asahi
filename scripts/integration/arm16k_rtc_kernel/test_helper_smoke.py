#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-authorized ordinary-host helper smoke: two benign Python prints only."""
import argparse,hashlib,importlib.util,json,os,sys,tempfile,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent


def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--owned-process',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if os.geteuid()==0 or not sys.flags.isolated:raise ValueError('isolated ordinary host user required')
 C=load('rtc_smoke_contract',HERE/'contract.py');C.checked(a.owned_process,C.lock()['owned_process']);O=load('rtc_smoke_held_process',a.owned_process);B=load('rtc_smoke_build',HERE/'build.py');O.prepare()
 started=time.monotonic();argv=[sys.executable,'-I','-B','-c',"print('RTC_HELPER_SMOKE')"]
 expected=b'RTC_HELPER_SMOKE\n';normal=B.owned_command(O,argv,cap=1.5,retirement=.5,grace=.1,max_output=32768)
 output=normal.pop('output');assert normal['passed'] and normal['reaped'] and normal['group_census']=='EMPTY_TWICE' and output==expected
 with tempfile.TemporaryDirectory(prefix='rtc-helper-log-') as tmp:
  log=Path(tmp)/'regular.log';log.write_bytes(output);assert log.read_bytes()==expected
 count=0
 def refuse_before_transfer(child,**kwargs):
  nonlocal count
  count+=1
  if count==1:raise ValueError('modeled pre-transfer API refusal')
  return O.supervise(child,**kwargs)
 try:B.owned_command(types.SimpleNamespace(supervise=refuse_before_transfer),argv,cap=1.5,retirement=.5,grace=.1,max_output=32768)
 except B.OwnedCommandError as error:recovery=error.retirement
 else:raise AssertionError('refused command must remain failed')
 recovered=recovery.pop('output');assert count==2 and recovery['reaped'] and recovery['ownership']=='REAPED' and recovery['group_census']=='EMPTY_TWICE' and recovered==expected
 elapsed=time.monotonic()-started;assert elapsed<5 and len(output)+len(recovered)<=65536
 report={'schema_version':1,'status':'PASS_BENIGN_HOST_HELPER_API_ONLY','helper':C.pin(a.owned_process),'ordinary_uid':os.getuid(),'benign_children':2,'normal':normal,'pretransfer_refusal_same_child_retirement':recovery,'refused_command_accepted':False,'captured_bytes':len(output)+len(recovered),'elapsed_seconds':elapsed,'whole_limit_seconds':5,'combined_output_limit_bytes':65536,'regular_log_after_supervision':'PASS exact bytes','kernel_source_execution':'NOT RUN','package_execution':'NOT RUN','configure':'NOT RUN','VM':'NOT RUN'}
 with a.output.open('x') as f:json.dump(report,f,indent=2,sort_keys=True);f.write('\n')
 print(json.dumps(report,sort_keys=True));return 0


if __name__=='__main__':raise SystemExit(main())
