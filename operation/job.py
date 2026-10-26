# SPDX-License-Identifier: MIT
"""Separately selected companion; original native owner/cleanup remain authoritative."""
import argparse,importlib.util,os,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as X
import lifecycle as L
HERE=Path(__file__).resolve().parent


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m


def parts(repair,text):
    """Finite companion-only seams; original source and default job stay untouched."""
    out=repair.derived(text)
    def edit(name,before,after):
        X.need(out[name].count(before)==1,'one companion owner seam: '+name)
        old=out[name];out[name]=old.replace(before,after,1)
        X.need(out[name].replace(after,before,1)==old,'whole owner seam inverse')
    edit('actor'," for source,target,readonly in mounts:"," if role=='lifecycle':\n  mounts.append((OPERATION_ROOT,'/operation',True));argv+=['--env=CACHY_APPS574_OPERATION='+OPERATION,'--env=APPS16_INTERRUPTION_PROFILE_SHA256='+OPERATION_PROFILE_SHA]\n for source,target,readonly in mounts:")
    edit('actor',"'/source/'+C.LANE+'/'+script","('/operation/lifecycle.py'if role=='lifecycle'else'/source/'+C.LANE+'/'+script)")
    edit('run',"report=dict(status='FAIL',case=args.case,token=","report=dict(status='FAIL',operation=OPERATION,operation_profile_sha256=OPERATION_PROFILE_SHA,case=args.case,token=")
    edit('retain'," for path in C.HERE.iterdir():"," for path in OPERATION_ROOT.iterdir():\n  if path.is_file():copy(path,'operation-source/'+path.name,2*1024**2)\n for path in C.HERE.iterdir():")
    edit('retain',"  C.need(not result['errors'],'closed evidence incomplete')","  operation_retained(C,life,args.output/'lifecycle-public',result['files'])\n  operation_source_retained(result['files'])\n  C.need(proof_value['operation']==owner['operation']==ordered['operation']==OPERATION and proof_value['operation_profile_sha256']==owner['operation_profile_sha256']==ordered['operation_profile_sha256']==OPERATION_PROFILE_SHA,'exact companion proof/owner/ordered-cleanup binding')\n  C.need(not result['errors'],'closed evidence incomplete')")
    return out


def configure(source,profile_sha):
    X.verify(source,profile_sha)
    sys.path.insert(0,str(source/X.LANE))
    original=load('contract',source/X.LANE/'contract.py')
    repair=original.load('companion_original_repair_owner',source/X.LANE/'job.py')
    H=repair.H
    proxy=types.ModuleType('apps16_reinstall_interruption_contract');proxy.__dict__.update(vars(original))
    def source_guard(root):
        X.verify(root,profile_sha)
        return original.source(root)
    proxy.source=source_guard;proxy.result=lambda value:L.validate(original,value);proxy.STATUS=X.STATUS
    H.C=proxy
    H.OPERATION_ROOT=HERE;H.OPERATION=X.OPERATION;H.OPERATION_PROFILE_SHA=profile_sha
    H.operation_retained=L.retained
    def source_retained(files):
        expected=X.tree(HERE)
        X.need(expected['profile.json']['sha256']==profile_sha and
               {n.removeprefix('operation-source/'):w for n,w in files.items()if n.startswith('operation-source/')}==expected,
               'complete exact companion source export and Root profile pin')
    H.operation_source_retained=source_retained
    bodies=parts(repair,original.read(Path(H.__file__)).decode())
    for body in bodies.values():exec(compile(body,H.__file__+':separate-apps16-interruption','exec'),H.__dict__)
    return original,H,bodies


def binding(C,args):
    raw=C.read(args.proof,65536);proof=C.decode(raw)
    C.need(proof['case']=='repair-bytes'and proof['operation']==X.OPERATION and proof['operation_profile_sha256']==args.operation_profile_sha256,'explicit proof operation/profile/case join')
    C.need(proof['source_sha']==os.environ['SOURCE_SHA']==os.environ['GITHUB_SHA']==os.environ['GITHUB_WORKFLOW_SHA'],'original same-source native workflow proof')
    return dict(operation=X.OPERATION,operation_profile_sha256=args.operation_profile_sha256,source_sha=proof['source_sha'],proof_sha256=C.sha(raw),case='repair-bytes',consumer_token=proof['consumer_token'],producer_token=proof['job_token'])


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode',choices=('proof','check','run','cleanup','retain','supervised-run','supervised-cleanup'))
    p.add_argument('--operation',choices=(X.OPERATION,),required=True)
    p.add_argument('--operation-profile-sha256',required=True)
    for name in('source','packet','proof','base','output','receipt','public','handoff'):p.add_argument('--'+name,type=Path)
    p.add_argument('--job-outcome',choices=('success','failure','cancelled','skipped'))
    args=p.parse_args(argv);X.need(args.source is not None,'explicit original source')
    C,H,_=configure(args.source,args.operation_profile_sha256)
    C.need(os.environ.get('REPAIR_CASE')=='repair-bytes','original explicit workflow case binding')
    H.C.source(args.source);args.case='repair-bytes'
    modes={'proof':('proof',),'check':('packet',),'run':('proof','base','output','packet'),'cleanup':('proof','base','output','receipt'),'retain':('proof','base','output','receipt','public','packet'),'supervised-run':('proof','base','output','packet','handoff'),'supervised-cleanup':('proof','base','output','receipt','handoff')}
    C.need(all(getattr(args,k)is not None for k in modes[args.mode]),'all original mode operands required')
    if args.mode not in('proof','check'):identity=binding(C,args)
    mode=args.mode
    if mode.startswith('supervised-'):
        C.need(args.handoff==args.proof.parent/'apps16-reinstall-interruption-handoff.json','one explicit operation handoff path')
        supervisor=C.load('companion_original_handoff',args.source/'scripts/ci/orphans-full574-native/supervise.py')
        if mode=='supervised-run':
            command=[sys.executable,'-I','-B',str(HERE/'job.py'),'run','--operation',X.OPERATION,'--operation-profile-sha256',args.operation_profile_sha256]
            for key in('source','proof','base','output','packet'):command+=['--'+key,str(getattr(args,key))]
            value=supervisor.handoff(command,args.handoff,identity)
            print(X.encoded(value).decode(),end='')
            return 128+value['cancellation_signal']if value['cancellation_signal']is not None else value['exit_code']if value['exit_code']>=0 else 128-value['exit_code']
        C.need(args.job_outcome is not None,'original workflow outcome required before cleanup')
        supervisor.check(args.handoff,identity,args.job_outcome=='skipped');mode='cleanup'
    value=getattr(H,mode)(args)
    if mode=='proof':
        value.update(case='repair-bytes',operation=X.OPERATION,operation_profile_sha256=args.operation_profile_sha256,outer_handoff=str(args.proof.parent/'apps16-reinstall-interruption-handoff.json'));C.save(args.proof,value)
    elif mode=='cleanup':value.update(case='repair-bytes',operation=X.OPERATION,operation_profile_sha256=args.operation_profile_sha256);C.save(args.receipt,value)
    print(X.encoded(dict(status=value['status'],operation=X.OPERATION)).decode(),end='')
    return int(value['status']not in('SOURCE_PROOF_PASS','EXACT_NATIVE_INPUTS_CHECKED_NOT_EXECUTED','PASS_ACTUAL_TRANSACTIONS_PENDING_ORDERED_CLEANUP','PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER',X.STATUS))

if __name__=='__main__':raise SystemExit(main())
