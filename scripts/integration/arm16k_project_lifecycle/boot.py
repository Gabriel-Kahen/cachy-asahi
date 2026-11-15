#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Root-admitted fresh project lifecycle; delegate the unchanged ARM16K actor."""
import argparse,importlib.util,json,os,re,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent


def inputs():
 spec=importlib.util.spec_from_file_location('arm16k_project_controller_inputs',HERE/'inputs.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def parse_lifecycle(data,nonce):
 text=data.decode('utf-8',errors='replace').replace('\r','');start='ARM16K_PROJECT_BEGIN '+nonce+'\n';end='ARM16K_PROJECT_END '+nonce
 if text.count(start)!=1 or text.count(end)!=1:raise ValueError('missing/duplicate exact project frame')
 fields={}
 for line in text.split(start,1)[1].split(end,1)[0].splitlines():
  if '='not in line:raise ValueError('malformed project field')
  key,value=line.split('=',1)
  if key in fields or not re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,63}',key)or len(value)>256:raise ValueError('invalid/duplicate project field')
  fields[key]=value
 if fields.get('STATUS')=='HOLD':return fields
 expected={'STATUS':'PASS','BASELINE_PACKAGES':'111','INSTALLED_PACKAGES':'114','FINAL_PACKAGES':'111','ARCH':'aarch64','PAGESIZE':'16384','CLI_UID':'1000','CLI_HELP_EXIT':'0','CLI_VERSION_EXIT':'0','CLI_ENABLE_EXIT':'2','CLI_DISABLE_EXIT':'2','EXCLUSIVE_PAYLOAD_ABSENT':'yes','PRIVATE_TEST_TRUST_REMOVED':'yes','ORDINARY_HOOKS_SCRIPTLETS':'unsuppressed','KSM_POLICY_ACTION':'none_requested','KSM_KERNEL_FUNCTIONALITY':'not_qualified','NATIVE16K':'NOT_RUN','M2':'NOT_RUN'}
 for key,value in expected.items():
  if fields.get(key)!=value:raise ValueError('project invariant differs: '+key)
 for key in ('CLI_STATUS_EXIT','CLI_REPORT_EXIT'):
  if fields.get(key)not in ('0','3'):raise ValueError('unexpected installed diagnostic status')
 for before,after in [('BASE_'+key,'FINAL_'+key)for key in ('meta','hash','db','xattr')]+[('USER_BEFORE','USER_FINAL')]:
  if not re.fullmatch('[0-9a-f]{64}',fields.get(before,''))or fields.get(before)!=fields.get(after):raise ValueError('baseline/user restoration differs: '+before)
 if len(fields)!=30:raise ValueError('unexpected project result field set')
 return fields


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-first-arm16k-project-lifecycle',action='store_true');p.add_argument('--prepared',type=Path,required=True);p.add_argument('--prepared-sha256',required=True);p.add_argument('--output',type=Path,required=True)
 args=p.parse_args()
 if not(args.allow_first_arm16k_project_lifecycle and __debug__ and sys.flags.isolated and os.geteuid()!=0):p.error('isolated ordinary user and explicit fresh Root admission required')
 I=inputs();lock,_,reference=I.reference();source=args.prepared.resolve(strict=True);I.checked(source/'prepared.json',{'bytes':(source/'prepared.json').stat().st_size,'sha256':args.prepared_sha256})
 prepared=json.loads((source/'prepared.json').read_text());assert prepared['operation']=='arm16k-project-lifecycle-ksm1'and prepared['status']=='PREPARED_NOT_BOOTED'
 lineage=prepared['provenance']['project_lifecycle'];assert lineage['operation']=='arm16k-project-lifecycle-ksm1'and lineage['added_packages']==lock['added_packages']
 for name in ('guest-root.sh','guest-proof.sh','guest-runtime.sh','gpg-receipts.sh','check-probes.py'):I.checked(HERE/name,lineage['source_pins'][name])
 for name,ref in prepared['files'].items():I.checked(source/name,ref)
 assert re.fullmatch('[0-9a-f]{32}',prepared['nonce'])and not(source/'arm16k-first-boot-attempt.json').exists(),'fresh child input required'
 marker=source/'arm16k-project-lifecycle-attempt.json'
 with marker.open('x')as stream:json.dump({'operation':'arm16k-project-lifecycle-ksm1','nonce':prepared['nonce'],'prepared_sha256':args.prepared_sha256},stream)
 argv=['boot.py','--allow-first-arm16k-systemd-boot','--prepared',str(source),'--prepared-sha256',args.prepared_sha256,'--tool-image',lock['tool_image_id'],'--tool-image-id',lock['tool_image_id'],'--output',str(args.output)]
 original=sys.argv;report={'schema_version':1,'status':'HOLD','scope':'emulated ARM16K KSM package lifecycle only','native16K':'NOT RUN','M2':'NOT RUN','release':'NOT RUN','KSM_kernel_functionality':'NOT QUALIFIED'}
 try:
  sys.argv=argv;code=reference.main();report['reference_controller_exit']=code
  base_report=args.output/'report.json';base=json.loads(base_report.read_text());report['base_session_report']=I.pin(base_report);report['base_session_status']=base['status']
  fields=parse_lifecycle((args.output/'serial.redacted.log').read_bytes(),prepared['nonce']);report['project']=fields
  if code==0 and fields.get('STATUS')=='PASS':report['status']='PASS_EMULATED_ARM16K_SIGNED_PROJECT_INSTALL_REMOVE_ONLY'
 except BaseException as error:report['failure']={'category':type(error).__name__,'message':str(error)[:2048]}
 finally:
  sys.argv=original
  if args.output.is_dir():(args.output/'project-lifecycle-report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 print(json.dumps(report,sort_keys=True))
 return 0 if report['status']=='PASS_EMULATED_ARM16K_SIGNED_PROJECT_INSTALL_REMOVE_ONLY'else 1


if __name__=='__main__':raise SystemExit(main())
