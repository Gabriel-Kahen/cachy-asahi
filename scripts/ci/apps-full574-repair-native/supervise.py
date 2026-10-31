#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Bind original owned-job cancellation handoff to this single normal trial."""
import argparse,hashlib,os,sys,stat,base64
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def diagnostic(receipt,identity):
 # Retention only: this never substitutes for original.check or permits cleanup.
 C.safe(receipt);before=receipt.lstat();C.need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and before.st_uid==os.getuid() and before.st_size<=16384,'original owned bounded private handoff diagnostic')
 raw=C.read(receipt,16384);after=receipt.lstat();C.need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'original handoff changed during diagnostic read')
 value=C.decode(raw);C.need(type(value) is dict and value.get('identity')==identity and type(value.get('status')) is str and len(value['status'])<=128 and type(value.get('group_absent')) is bool and type(value.get('direct_reaped')) is bool,'typed original handoff identity')
 return dict(status='ORIGINAL_OUTER_HANDOFF_DIAGNOSTIC_NOT_CLEANUP_AUTHORITY',identity=identity,original_status=value['status'],direct_reaped=value['direct_reaped'],group_absent=value['group_absent'],raw_bytes=len(raw),raw_sha256=C.sha(raw),raw_base64=base64.b64encode(raw).decode(),cleanup_authority=False)

def save_diagnostic(path,value):
 C.safe(path);raw=C.encoded(value);C.need(len(raw)<=32768,'bounded handoff diagnostic export')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 info=path.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid() and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600 and C.read(path,32768)==raw,'private diagnostic readback')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('run','cleanup'));p.add_argument('--handoff',type=Path,required=True);p.add_argument('--job-outcome',choices=('success','failure','cancelled','skipped'))
 for name in ('source','proof','base','output','packet','receipt'):p.add_argument('--'+name,type=Path,required=name not in ('packet','receipt'))
 p.add_argument('--case',choices=('repair-bytes','repair-missing'),required=True)
 a=p.parse_args();C.case(a.case);C.need(os.environ.get('REPAIR_CASE')==a.case,'explicit workflow case matches supervisor');C.source(a.source);raw=C.read(a.proof,65536);proof=C.decode(raw);C.need(proof['source_sha']==os.environ['SOURCE_SHA']==os.environ['GITHUB_WORKFLOW_SHA']==os.environ['GITHUB_SHA'],'exact normal repair source/workflow required');C.need(proof['case']==a.case and proof['outer_handoff']==str(a.handoff) and a.handoff==a.proof.parent/'apps574-repair-job.json','exact proof case and fixed outer handoff');identity=dict(case=a.case,source_sha=proof['source_sha'],trial='full574-signed-repair',proof_sha256=C.sha(raw),consumer_token=proof['consumer_token'],producer_token=proof['job_token']);original=C.load('original_owned_job_handoff',a.source/'scripts/ci/orphans-full574-native/supervise.py')
 common=['--case',a.case,'--source',str(a.source),'--proof',str(a.proof),'--base',str(a.base),'--output',str(a.output)];prefix=['/usr/bin/python3','-I','-B',str(C.HERE/'job.py')]
 if a.mode=='cleanup':
  C.need(a.job_outcome is not None and a.receipt is not None,'original cleanup receipt/outcome required')
  if a.handoff.exists():
   retained=diagnostic(a.handoff,identity);save_diagnostic(a.proof.parent/'apps574-repair-handoff-diagnostic.json',retained);print('APPS574_REPAIR_OUTER_HANDOFF_DIAGNOSTIC '+C.encoded(retained).decode(),flush=True)
  original.check(a.handoff,identity,a.job_outcome=='skipped');os.execv(prefix[0],[*prefix,'cleanup',*common,'--receipt',str(a.receipt)])
 C.need(a.packet is not None,'exact packet required');value=original.handoff([*prefix,'run',*common,'--packet',str(a.packet)],a.handoff,identity);print('APPS574_REPAIR_JOB_HANDOFF '+C.encoded(value).decode(),flush=True);return 128+value['cancellation_signal'] if value['cancellation_signal'] is not None else value['exit_code'] if value['exit_code']>=0 else 128-value['exit_code']
if __name__=='__main__':raise SystemExit(main())
