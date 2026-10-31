#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""One original owned repair job; genuine16K bridge, unchanged retirement check."""
import argparse,base64,os,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import support as S

def identity(C,proof,source,case,handoff):
 raw=C.read(proof,65536);p=C.decode(raw);C.need(p['source_sha']==os.environ['SOURCE_SHA'] and p['case']==case and p['outer_handoff']==str(handoff) and handoff==proof.parent/'apps574-repair-job.json','exact original source proof/case/handoff')
 return dict(case=case,source_sha=p['source_sha'],trial='full574-signed-repair',proof_sha256=C.sha(raw),consumer_token=p['consumer_token'],producer_token=p['job_token'])
def run(args,C,native):
 C.authorize(args);who=identity(C,args.proof,args.source,args.case,args.handoff);original=C.load('ci_original_supervisor',args.source/'scripts/ci/orphans-full574-native/supervise.py')
 argv=['/usr/bin/python3','-I','-B',str(args.source/S.BRIDGE/'job.py'),'run',*common(args),'--packet',str(args.packet),'--kernel-work',str(args.kernel_work),'--kernel-receipt',str(args.kernel_receipt),'--native-decisions',str(args.native_decisions),'--kernel-authority',str(args.kernel_authority)]
 value=original.handoff(argv,args.handoff,who)
 print('REPAIR16K_CI_JOB_HANDOFF '+C.encoded(value).decode(),flush=True)
 return 128+value['cancellation_signal'] if value['cancellation_signal'] is not None else value['exit_code'] if value['exit_code']>=0 else 128-value['exit_code']
def common(a):return ['--source',str(a.source),'--case',a.case,'--proof',str(a.proof),'--base',str(a.base),'--output',str(a.output)]
def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('proof','decisions','check','run','cleanup','retain'));p.add_argument('--source',type=Path,required=True);p.add_argument('--case',choices=('repair-bytes','repair-missing'),required=True)
 for name in ('packet','proof','base','output','handoff','receipt','public','native-decisions','kernel-work','kernel-receipt','kernel-authority','kernel-authority-root'):p.add_argument('--'+name,type=Path)
 p.add_argument('--job-outcome',choices=('success','failure','cancelled','skipped'));a=p.parse_args(argv);C,native,binding=S.authorize(a.source,a.case)
 if a.mode=='decisions':C.decisions(a.source,a.case,a.native_decisions);C.prior_kernel(a.source,a.case,a.kernel_authority);return 0
 if a.mode=='proof':
  S.output('native_decision_source',binding['native_decision_source'])
  # Exact authority carrier/ref fields are supplied by the bridge, never guessed.
  S.output('kernel_authority_source',binding['kernel_authority_source'])
  S.output('kernel_authority_path',binding['kernel_authority']['path'])
  forward=['--proof',str(a.proof)]
 elif a.mode=='check':forward=['--packet',str(a.packet)]
 elif a.mode=='run':return run(a,C,native)
 elif a.mode=='cleanup':
  C.need(a.job_outcome is not None and a.receipt is not None,'original cleanup outcome/receipt');who=identity(C,a.proof,a.source,a.case,a.handoff);original=C.load('ci_original_supervisor',a.source/'scripts/ci/orphans-full574-native/supervise.py')
  if a.handoff.exists():
   space=dict(C=native,os=os,stat=stat,base64=base64);diagnostic=C.function(a.source/C.NATIVE/'supervise.py','diagnostic',space);save=C.function(a.source/C.NATIVE/'supervise.py','save_diagnostic',space);value=diagnostic(a.handoff,who);save(a.proof.parent/'apps574-repair-handoff-diagnostic.json',value);print('REPAIR16K_CI_HANDOFF_DIAGNOSTIC '+C.encoded(value).decode(),flush=True)
  original.check(a.handoff,who,a.job_outcome=='skipped');forward=common(a)[4:]+['--receipt',str(a.receipt)]
 else:forward=common(a)[4:]+['--packet',str(a.packet),'--receipt',str(a.receipt),'--public',str(a.public)]
 os.execv('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(a.source/S.BRIDGE/'job.py'),a.mode,'--source',str(a.source),'--case',a.case,*forward])
if __name__=='__main__':raise SystemExit(main())
