#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Bind original owned-job cancellation handoff to this single normal trial."""
import argparse,hashlib,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('run','cleanup'));p.add_argument('--handoff',type=Path,required=True);p.add_argument('--job-outcome',choices=('success','failure','cancelled','skipped'))
 for name in ('source','proof','base','output','packet','receipt'):p.add_argument('--'+name,type=Path,required=name not in ('packet','receipt'))
 a=p.parse_args();C.source(a.source);raw=C.read(a.proof,65536);proof=C.decode(raw);C.need(proof['source_sha']==os.environ['SOURCE_SHA']==os.environ['GITHUB_WORKFLOW_SHA']==os.environ['GITHUB_SHA'],'exact normal repair source/workflow required');identity=dict(source_sha=proof['source_sha'],trial='full574-signed-repair',proof_sha256=C.sha(raw),consumer_token=proof['consumer_token'],producer_token=proof['job_token']);original=C.load('original_owned_job_handoff',a.source/'scripts/ci/orphans-full574-native/supervise.py')
 common=['--source',str(a.source),'--proof',str(a.proof),'--base',str(a.base),'--output',str(a.output)];prefix=['/usr/bin/python3','-I','-B',str(C.HERE/'job.py')]
 if a.mode=='cleanup':
  C.need(a.job_outcome is not None and a.receipt is not None,'original cleanup receipt/outcome required');original.check(a.handoff,identity,a.job_outcome=='skipped');os.execv(prefix[0],[*prefix,'cleanup',*common,'--receipt',str(a.receipt)])
 C.need(a.packet is not None,'exact packet required');value=original.handoff([*prefix,'run',*common,'--packet',str(a.packet)],a.handoff,identity);print('APPS574_REPAIR_JOB_HANDOFF '+C.encoded(value).decode(),flush=True);return 128+value['cancellation_signal'] if value['cancellation_signal'] is not None else value['exit_code'] if value['exit_code']>=0 else 128-value['exit_code']
if __name__=='__main__':raise SystemExit(main())
