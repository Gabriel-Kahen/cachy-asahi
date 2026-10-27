# SPDX-License-Identifier: MIT
"""Separately selected companion; original native owner/cleanup remain authoritative."""
import argparse,importlib.util,math,os,re,stat,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as X
import lifecycle as L
HERE=Path(__file__).resolve().parent
OUTER_HANDOFF='apps16-reinstall-interruption-handoff.json'
OUTER_RAW_STAGE='apps16-reinstall-interruption-handoff-raw-export.json'
OUTER_RECEIPT_STAGE='apps16-reinstall-interruption-handoff-export.json'
OUTER_RAW='outer-handoff-raw.json'
OUTER_RECEIPT='outer-handoff-export.json'
INPUT_ROUTES='native-input-routing.json'
INPUT_ROUTES_STAGE='apps16-retained-input-routes.json'
PAIR_SOURCE='950b0699a6e3f7a56758d4d17a5d30dabc7b6e11'
PAIR_PIN={'bytes':29664,'sha256':'319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af'}


def _outer_handoff(raw,identity):
    X.need(type(raw)is bytes and 0<len(raw)<=16384,'complete bounded original outer handoff')
    value=X.decode(raw)
    keys={'schema_version','status','identity','job','group_absent','direct_reaped','inner_actors','exit_code','signals','cancellation_signal','cancellation_seconds','seconds'}
    X.need(type(value)is dict and set(value)==keys and type(value['schema_version'])is int and value['schema_version']==1 and X.encoded(value)==raw,'closed canonical original handoff schema')
    X.need(value['identity']==identity and value['status']=='DIRECT_JOB_REAPED_GROUP_ABSENT_INNER_CLEANUP_STILL_REQUIRED'and value['direct_reaped']is True and value['group_absent']is True,'original exact identity/direct-reap/group-absence predicates')
    job=value['job'];X.need(type(job)is dict and set(job)=={'pid','pgid','sid','start'}and all(type(job[k])is int for k in job)and job['pid']>1 and job['pid']==job['pgid']==job['sid']and job['start']>0,'original owned session PID/PGID/SID/start predicates')
    X.need(value['inner_actors']=='NOT_OBSERVED_OR_RETIRED_BY_OUTER_SUPERVISOR'and type(value['exit_code'])is int and -255<=value['exit_code']<=255,'outer process cannot supply inner cleanup authority')
    X.need(type(value['seconds'])in(int,float)and math.isfinite(value['seconds'])and value['seconds']>=0,'finite original elapsed seconds')
    cancellation=value['cancellation_signal'];X.need(cancellation is None or type(cancellation)is int and cancellation in(2,15),'original two cancellation signal handlers')
    elapsed=value['cancellation_seconds'];X.need(elapsed is None if cancellation is None else type(elapsed)in(int,float)and math.isfinite(elapsed)and 0<=elapsed<=value['seconds'],'original cancellation timing scope')
    signals=value['signals'];X.need(type(signals)is list and len(signals)<=3 and all(type(n)is int for n in signals),'original bounded signal trace')
    requested=([cancellation]if cancellation is not None else[])+[15,9];at=0
    for number in signals:
        while at<len(requested)and requested[at]!=number:at+=1
        X.need(at<len(requested),'signal trace must follow the original ordered sends');at+=1
    return value


def _outer_key(info):
    return {name:getattr(info,'st_'+field)for name,field in(('device','dev'),('inode','ino'),('mode','mode'),('uid','uid'),('gid','gid'),('nlink','nlink'),('bytes','size'),('mtime_ns','mtime_ns'),('ctime_ns','ctime_ns'))}


def _outer_read(path,cap,private=False):
    path=X.canonical(path);parents={str(p):_outer_key(p.lstat())for p in(path.parent,*path.parent.parents)}
    X.need(all(stat.S_ISDIR(v['mode'])for v in parents.values()),'ordinary original ancestry')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        before=os.fstat(fd);identity=_outer_key(before)
        X.need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==os.getuid()and 0<before.st_size<=cap,'owned bounded singlelink original handoff/proof')
        if private:X.need(stat.S_IMODE(before.st_mode)==0o600,'original handoff must remain private0600')
        parts=[];size=0
        while part:=os.read(fd,4096):parts.append(part);size+=len(part);X.need(size<=before.st_size,'original handoff growth')
        X.need(size==before.st_size and identity==_outer_key(os.fstat(fd))==_outer_key(path.lstat()),'full original handoff FD/path identity')
        X.need(all(_outer_key(Path(p).lstat())==v for p,v in parents.items()),'original handoff ancestry changed during read')
        return b''.join(parts),identity
    finally:os.close(fd)


def _outer_write(path,raw):
    path=X.canonical(path);X.need(path.parent.is_dir()and not os.path.lexists(path),'fresh owned outer-export staging leaf')
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb')as stream:
        stream.write(raw);stream.flush();os.fsync(stream.fileno());os.fchmod(stream.fileno(),0o600)


def outer_export_stage(C,args):
    """Diagnostic export only; an export failure must not skip original retention."""
    result=dict(schema_version=1,status='REFUSED_ORIGINAL_OUTER_HANDOFF_EXPORT',cleanup_authority=False,rollback='NOT_CLAIMED')
    proof_path=X.canonical(args.proof);receipt=proof_path.parent/OUTER_RECEIPT_STAGE
    try:
        X.need(proof_path.name=='apps574-source-proof.json','fixed original source-proof leaf')
        proof_raw,proof_identity=_outer_read(proof_path,65536);proof=X.decode(proof_raw)
        run=os.environ['GITHUB_RUN_ID'];attempt=os.environ['GITHUB_RUN_ATTEMPT'];source=os.environ['SOURCE_SHA']
        X.need(re.fullmatch('[1-9][0-9]{0,19}',run)and attempt=='1'and re.fullmatch('[0-9a-f]{40}',source)and source==os.environ['GITHUB_SHA']==os.environ['GITHUB_WORKFLOW_SHA'],'exact current first-attempt source/run/workflow')
        X.need(type(args.operation_profile_sha256)is str and re.fullmatch('[0-9a-f]{64}',args.operation_profile_sha256),'explicit operation profile SHA256')
        identity=binding(C,args);full=run+':'+attempt+':'+source
        X.need(proof['status']=='SOURCE_PROOF_PASS'and proof['consumer_token']==C.sha(('apps574-consumer:'+full).encode())[:32]and proof['job_token']==C.sha(('apps574-producer:'+full).encode())[:16],'original run-derived proof/owner tokens')
        original=proof_path.parent/OUTER_HANDOFF;X.need(proof['outer_handoff']==str(original),'fixed source-proof sibling original handoff path')
        raw,owned=_outer_read(original,16384,private=True);_outer_handoff(raw,identity)
        staged=proof_path.parent/OUTER_RAW_STAGE;_outer_write(staged,raw)
        X.need(_outer_read(original,16384,private=True)==(raw,owned)and _outer_read(proof_path,65536)==(proof_raw,proof_identity),'original proof/handoff custody after staging')
        result=dict(schema_version=1,status='EXPORTED_EXACT_ORIGINAL_OUTER_HANDOFF_DATA_ONLY',operation=X.OPERATION,operation_profile_sha256=args.operation_profile_sha256,
          source=source,run=int(run),attempt=1,case='repair-bytes',identity=identity,proof_path=str(proof_path),proof=dict(path='source-proof.json',**X.pin(proof_raw)),
          input_path=str(original),input_identity=owned,ancestry='ORDINARY_NO_ALIAS_SOURCE_FD_PATH_CHECKED',raw=dict(path=OUTER_RAW,**X.pin(raw)),descriptor_closed=True,
          original_check='ORIGINAL_SUPERVISOR_CHECK_BEFORE_CLEANUP_HELD',cleanup_authority=False,live_group_reobservation='NOT_RUN_DIAGNOSTIC_EXPORT_ONLY',rollback='NOT_CLAIMED')
    except Exception as error:result.update(error_type=type(error).__name__,error=str(error)[:512])
    try:_outer_write(receipt,X.encoded(result))
    except Exception as error:result.update(export_receipt_write_error=type(error).__name__)
    return result


def outer_export_retained(C,args,result,expected):
    X.need(type(expected)is dict and expected.get('status')=='EXPORTED_EXACT_ORIGINAL_OUTER_HANDOFF_DATA_ONLY','original outer handoff export refused; retained failure is not acceptance')
    raw=C.read(args.public/OUTER_RAW,16384);receipt_raw=C.read(args.public/OUTER_RECEIPT,16384);receipt=X.decode(receipt_raw)
    X.need(receipt==expected and receipt['raw']==dict(path=OUTER_RAW,**X.pin(raw))and result['files'][OUTER_RAW]==X.pin(raw)and result['files'][OUTER_RECEIPT]==X.pin(receipt_raw),'exact original raw/ownership receipt closed-retention joins')
    proof_raw=C.read(args.public/'source-proof.json',65536)
    X.need(receipt['proof']==dict(path='source-proof.json',**X.pin(proof_raw)),'same physically retained original source-proof')
    _outer_handoff(raw,receipt['identity'])


def _operation_refs(value):
    rows={};count=0
    def visit(node,depth=0):
        nonlocal count
        count+=1;X.need(count<=100000 and depth<=64,'bounded source-owned input references')
        if type(node)is dict:
            if set(node)=={'path','bytes','sha256'}:
                name=node['path'];X.need(type(name)is str and name and not name.startswith('/')and '\\'not in name and all(p not in('','.','..')for p in name.split('/')),'ordinary source-owned input reference')
                X.need(type(node['bytes'])is int and 0<=node['bytes']<=16*1024**2 and type(node['sha256'])is str and re.fullmatch('[0-9a-f]{64}',node['sha256']),'bounded complete source input pin')
                X.need(name not in rows or rows[name]==node,'conflicting duplicate source input reference');rows[name]=node
            else:
                for item in node.values():visit(item,depth+1)
        elif type(node)is list:
            for item in node:visit(item,depth+1)
    visit(value);return rows


def operation_input_context(C,args,packet,declared):
    """Keep original192, prefixed carrier94 AND all four original bare archive roles."""
    policy_raw=C.read(args.source/'apps16-repair/carrier-profile.json',4*1024**2);policy=C.decode(policy_raw)
    X.need(packet['apps16_authority']['profile']==policy and policy['source']==PAIR_SOURCE and len(policy['files'])==94,'exact independently proved Apps16 carrier policy')
    base=X.canonical(args.source.parent/'apps16-native-pair')
    index_raw,index_identity=_outer_read(base/'index.json',4*1024**2)
    X.need(X.pin(index_raw)==policy['files']['index.json'],'complete current carrier index source pin')
    index=C.decode(index_raw);decision_name=index['acceptance']
    X.need(type(decision_name)is str and decision_name in policy['files']and not decision_name.startswith('/')and '\\'not in decision_name and all(p not in('','.','..')for p in decision_name.split('/')),'declared current carrier acceptance role')
    decision_raw,decision_identity=_outer_read(base/decision_name,4*1024**2)
    X.need(X.pin(decision_raw)==policy['files'][decision_name]and C.decode(decision_raw)==policy['acceptance']and index['archives']==policy['archives'],'current carrier index/Root acceptance/policy joins')
    routes={}
    for side in('a','b'):
        target='native/packages/cachy-asahi-apps-'+side+'/cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz'
        documentary='Root-strict/current-apps16/original-public/packages/cachy-asahi-apps-'+side+'/cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz'
        expected=dict(path=target,**PAIR_PIN);doc=dict(path=documentary,**PAIR_PIN)
        X.need(policy['archives'].count(expected)==index['archives'].count(expected)==1 and policy['acceptance']['accepted_pair']['archives'].count(doc)==1 and policy['files'][target]==PAIR_PIN,'exact native/current Root documentary archive obligation')
        routes[target]=target;routes[documentary]=target
    X.need(len(policy['archives'])==len(policy['acceptance']['accepted_pair']['archives'])==2 and len(routes)==4,'exact four bare source-owned roles')
    old=_operation_refs(packet['apps16_original_packet']);row=C.policy()['packet_index'];old[row['path']]=row
    X.need(len(old)==192 and not any(n.startswith('APPS16_CARRIER/')for n in old),'complete unchanged original192 input closure')
    carrier={'APPS16_CARRIER/'+name:dict(path='APPS16_CARRIER/'+name,**p)for name,p in policy['files'].items()}
    extras={name:dict(path=name,**PAIR_PIN)for name in routes}
    expected=dict(old,**carrier,**extras)
    X.need(len(expected)==290 and declared==expected,'all original recursive obligations retained:192+94+4, no generic extras')
    return dict(base=base,expected=expected,routes=routes,seen={},policy=policy,
                policy_ref=dict(path='repair-source/apps16-repair/carrier-profile.json',**X.pin(policy_raw)),
                index_ref=dict(path='native-inputs/APPS16_CARRIER/index.json',**X.pin(index_raw)),
                decision_ref=dict(path='native-inputs/APPS16_CARRIER/'+decision_name,**X.pin(decision_raw)),
                metadata_before=(index_raw,index_identity,decision_raw,decision_identity),decision_name=decision_name)


def operation_input_copy(C,copy,args,name,row,result,context):
    X.need(context['expected'].get(name)==row,'one exact original recursive input obligation')
    export='native-inputs/'+name
    if name in context['routes']:
        target=context['routes'][name];path=context['base']/target;raw,identity=_outer_read(path,PAIR_PIN['bytes'])
        X.need(X.pin(raw)==PAIR_PIN and row==dict(path=name,**PAIR_PIN),'whole independently selected native Apps16 archive')
        copy(path,export,16*1024**2)
        X.need(result['files'].get(export)==PAIR_PIN and _outer_read(path,PAIR_PIN['bytes'])==(raw,identity),'full bare-role export pin and original carrier FD/path custody')
        exported=C.read(args.public/export,PAIR_PIN['bytes']);X.need(exported==raw,'same complete ordinary archive bytes under original bare public role')
        context['seen'][name]=dict(export=export,requested=row,carrier=dict(path='APPS16_CARRIER/'+target,**PAIR_PIN),input_path=str(path),input_identity=identity,
                                   custody='ORDINARY_NO_ALIAS_SOURCE_FD_PATH_CHECKED',export_pin=X.pin(exported))
    else:
        path=context['base']/name[len('APPS16_CARRIER/'):]if name.startswith('APPS16_CARRIER/')else args.packet/name
        copy(path,export,16*1024**2)
        X.need(result['files'].get(export)=={k:row[k]for k in('bytes','sha256')},'complete original192/carrier94 obligation exported')


def operation_input_finish(C,copy,args,result,context):
    X.need(set(context['seen'])==set(context['routes']),'all four documentary/native bare archives remain required')
    expected={'native-inputs/'+n:{k:r[k]for k in('bytes','sha256')}for n,r in context['expected'].items()}
    X.need({n:p for n,p in result['files'].items()if n.startswith('native-inputs/')}==expected and len(expected)==290,'complete exact290 native output closure')
    a,b=_outer_read(context['base']/'index.json',4*1024**2);c,d=_outer_read(context['base']/context['decision_name'],4*1024**2)
    X.need((a,b,c,d)==context['metadata_before'],'current carrier index/acceptance custody after complete routing')
    proof=dict(schema_version=1,status='PASS_EXACT_FOUR_SOURCE_BOUND_APPS16_BARE_ARCHIVE_ROUTES_DATA_ONLY',
               carrier_source=PAIR_SOURCE,policy=context['policy_ref'],index=context['index_ref'],acceptance=context['decision_ref'],
               counts=dict(original=192,carrier=94,bare_archive_roles=4,exported_native_inputs=290),
               routes=[context['seen'][name]for name in sorted(context['seen'])],input_mutation='NONE_READONLY_SOURCE_ROUTES',
               acceptance_authority=False,cleanup_authority=False)
    raw=X.encoded(proof);X.need(len(raw)<=16384,'bounded exact four-route receipt')
    stage=args.output/INPUT_ROUTES_STAGE;_outer_write(stage,raw);copy(stage,INPUT_ROUTES,16384)
    X.need(result['files'].get(INPUT_ROUTES)==X.pin(raw),'route receipt belongs to original closed retention')


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m


def parts(repair,text):
    """Finite companion-only seams; original source and default job stay untouched."""
    out=repair.derived(text)
    def edit(name,before,after):
        X.need(out[name].count(before)==1,'one companion owner seam: '+name)
        old=out[name];out[name]=old.replace(before,after,1)
        X.need(out[name].replace(after,before,1)==old,'whole owner seam inverse')
    edit('actor'," for source,target,readonly in mounts:"," if role=='lifecycle':\n  mounts.append((OPERATION_ROOT,'/operation',True));argv+=['--env=CACHY_APPS574_OPERATION='+OPERATION,'--env=APPS16_INTERRUPTION_PROFILE_SHA256='+OPERATION_PROFILE_SHA,'--cap-add=SYS_CHROOT']\n for source,target,readonly in mounts:")
    edit('actor',"'/source/'+C.LANE+'/'+script","('/operation/lifecycle.py'if role=='lifecycle'else'/source/'+C.LANE+'/'+script)")
    edit('run',"report=dict(status='FAIL',case=args.case,token=","report=dict(status='FAIL',operation=OPERATION,operation_profile_sha256=OPERATION_PROFILE_SHA,case=args.case,token=")
    edit('retain'," for path in C.HERE.iterdir():"," for path in OPERATION_ROOT.iterdir():\n  if path.is_file():copy(path,'operation-source/'+path.name,2*1024**2)\n for path in C.HERE.iterdir():")
    edit('retain'," copy(args.proof,'source-proof.json',65536);", " copy(args.proof.parent/OUTER_RECEIPT_STAGE,OUTER_RECEIPT,16384)\n copy(args.proof.parent/OUTER_RAW_STAGE,OUTER_RAW,16384,False)\n copy(args.proof,'source-proof.json',65536);")
    edit('retain',"  for name,pin in files.items():copy(args.source.parent/'apps16-native-pair'/name[len('APPS16_CARRIER/'):]if name.startswith('APPS16_CARRIER/')else args.packet/name,'native-inputs/'+name,16*1024**2)",
         "  routes=operation_input_context(C,args,packet,files)\n  for name,pin in files.items():operation_input_copy(C,copy,args,name,pin,result,routes)\n  operation_input_finish(C,copy,args,result,routes)")
    edit('retain',"  C.need(not result['errors'],'closed evidence incomplete')","  operation_retained(C,life,args.output/'lifecycle-public',result['files'])\n  operation_source_retained(result['files'])\n  C.need(proof_value['operation']==owner['operation']==ordered['operation']==OPERATION and proof_value['operation_profile_sha256']==owner['operation_profile_sha256']==ordered['operation_profile_sha256']==OPERATION_PROFILE_SHA,'exact companion proof/owner/ordered-cleanup binding')\n  C.need(not result['errors'],'closed evidence incomplete')")
    edit('retain',"  C.need(not result['errors'],'closed evidence incomplete')", "  outer_export_retained(C,args,result,OUTER_EXPORT_STAGE)\n  C.need(not result['errors'],'closed evidence incomplete')")
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
    H.OUTER_HANDOFF=OUTER_HANDOFF;H.OUTER_RAW_STAGE=OUTER_RAW_STAGE;H.OUTER_RECEIPT_STAGE=OUTER_RECEIPT_STAGE
    H.OUTER_RAW=OUTER_RAW;H.OUTER_RECEIPT=OUTER_RECEIPT;H.OUTER_EXPORT_STAGE=None;H.outer_export_retained=outer_export_retained
    H.operation_input_context=operation_input_context;H.operation_input_copy=operation_input_copy;H.operation_input_finish=operation_input_finish
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
    if mode=='retain':H.OUTER_EXPORT_STAGE=outer_export_stage(C,args)
    value=getattr(H,mode)(args)
    if mode=='proof':
        value.update(case='repair-bytes',operation=X.OPERATION,operation_profile_sha256=args.operation_profile_sha256,outer_handoff=str(args.proof.parent/'apps16-reinstall-interruption-handoff.json'));C.save(args.proof,value)
    elif mode=='cleanup':value.update(case='repair-bytes',operation=X.OPERATION,operation_profile_sha256=args.operation_profile_sha256);C.save(args.receipt,value)
    print(X.encoded(dict(status=value['status'],operation=X.OPERATION)).decode(),end='')
    return int(value['status']not in('SOURCE_PROOF_PASS','EXACT_NATIVE_INPUTS_CHECKED_NOT_EXECUTED','PASS_ACTUAL_TRANSACTIONS_PENDING_ORDERED_CLEANUP','PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER',X.STATUS))

if __name__=='__main__':raise SystemExit(main())
