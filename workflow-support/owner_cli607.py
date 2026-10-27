#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed workflow-to-owner argv; inherited acquisition/build contexts stay pinned."""
import argparse,hashlib,os,re,sys
from pathlib import Path
MODES=('supervised-run','supervised-cleanup','retain')
PROVIDER='b9976eea34eaed4b6e56af3be21d4d652fa971d6'
def need(ok,why):
 if not ok:raise ValueError(why)
def command(mode,root,env):
 need(mode in MODES,'one fixed workflow owner mode');workspace=Path(env['GITHUB_WORKSPACE']);temporary=Path(env['RUNNER_TEMP']);root=Path(root)
 for p in(workspace,temporary,root):need(p.is_absolute()and p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary workflow paths')
 source=env['SOURCE_SHA'];run=env['GITHUB_RUN_ID'];attempt=env['GITHUB_RUN_ATTEMPT'];need(re.fullmatch('[0-9a-f]{40}',source)and source==env['GITHUB_SHA']==env['GITHUB_WORKFLOW_SHA']and re.fullmatch('[1-9][0-9]*',run)and re.fullmatch('[1-9][0-9]*',attempt),'actual same-source workflow identity')
 profile=env['OPERATION_PROFILE_SHA256'];need(re.fullmatch('[0-9a-f]{64}',profile)and env['OPERATION']=='recover-apps16-reinstall607','independent selected operation profile')
 token=hashlib.sha256(('apps607-consumer:'+run+':'+attempt+':'+source).encode()).hexdigest()[:32]
 paths={
 'source':root/'repair-source','operation-root':root/'operation','recovery-root':root/'recovery-parent259',
 'fresh-source':workspace/'fresh607-code','fresh-authorization':root/'workflow-support/provider1197.json',
 'six-record':workspace/'fresh607-record','six-public':temporary/'fresh607-input-data','tooling-inputs':workspace/'fresh607-tooling-inputs',
 'implementation':workspace/'expanded604-installer','legacy-source':workspace/'expanded604-legacy',
 'preparation-source':workspace/'composition-preparation','updater-v2-source':workspace/'composition-updater-v2','setup4-pair':temporary/'setup4-retained',
 'product':workspace/'composition-product','updater':workspace/'composition-updater','desktop':workspace/'composition-desktop',
 'native':temporary/'native-evidence','fdk':temporary/'fdk-evidence','cache':temporary/'alarm-cache',
 'seven-source':workspace/'expanded604-seven','eight-source':workspace/'expanded604-eight','management-source':workspace/'expanded604-management-source/payload',
 'setup-source':workspace/'expanded604-setup-source','welcome-source':workspace/'expanded604-welcome-source/payload',
 'fresh600-decisions':workspace/'expanded604-fresh600-decisions','native604-decisions':workspace/'expanded604-native604-decisions',
 'apps6-source':workspace/'apps6-inputs/payload','apps6-authority-source':workspace/'apps6-authority','audio-inputs':temporary/'audio-archives',
 'packet':workspace/'apps607-repair-packet/payload','apps16-pair':workspace/'apps16-native-pair',
 'output':Path('/tmp')/('cachy-asahi-expanded604-installer-'+run+'-'+attempt),'owner-output':Path('/tmp')/('caa-apps607-'+token),
 'handoff':temporary/('apps607-handoff-'+token+'.json'),'public':temporary/'apps607-fresh-recovery-public'}
 argv=[sys.executable,'-I','-B',str(root/'operation/native_owner607.py'),mode]
 for name,path in paths.items():argv+=['--'+name,str(path)]
 argv+=['--fresh-source-revision',PROVIDER,'--implementation-revision','bd0cf1891083d011b70edab10501c317d3720b78','--operation-profile-sha256',profile]
 if mode=='supervised-cleanup':
  outcome=env['RECOVERY_JOB_OUTCOME'];need(outcome in('success','failure','cancelled','skipped'),'actual workflow outcome');argv+=['--job-outcome',outcome]
 clean=dict(PATH='/usr/local/bin:/usr/bin:/bin',HOME=str(temporary/'apps607-coordinator-home'),LANG='C.UTF-8',TZ='UTC',PYTHONDONTWRITEBYTECODE='1',SOURCE_SHA=source,GITHUB_SHA=source,GITHUB_WORKFLOW_SHA=source,GITHUB_RUN_ID=run,GITHUB_RUN_ATTEMPT=attempt)
 return argv,clean
def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=MODES);a=p.parse_args(argv);args,env=command(a.mode,Path(__file__).resolve().parents[1],os.environ);return os.execve(sys.executable,args,env)
if __name__=='__main__':raise SystemExit(main())
