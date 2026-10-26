# SPDX-License-Identifier: MIT
"""Selected REMOVE interruption; exact normal749 rendering remains callable."""
import ast,hashlib,json
from pathlib import Path
CASES=('pristine','modified')
STAGES=('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after','interrupted-before-unlock','recovered-held574')
PREFIX='runtime-vm/scripts/ci/'
NATIVE=PREFIX+'glibc-gnu-provider-lifecycle/container.py'
INTERRUPTED=PREFIX+'glibc-gnu-provider-interruption/container.py'
CHECKPOINT=PREFIX+'glibc-gnu-provider-interruption/interruption.py'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def functions(raw):
 text=raw.decode();return{n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
def profile(case,normal):
 need(case in CASES,'explicit interruption case only; both is not implicit')
 p=dict(normal);p.update(name='GNU_TCG_SELECTED_REMOVE_INTERRUPTION_RECOVERY_V1',scenario='REAL_REMOVE_CHECKPOINT_KILL_AND_EXTERNAL_RECOVERY',case=case,required_cases=list(CASES),acceptance='BOTH_SEPARATE_SAME_SOURCE_INTERRUPTION_CASES_REQUIRED_NO_NORMAL_TRANSFER',graph_stages=10,runtime_observations=5,interruption_seconds=120,candidate_extraction='NOT_TESTED',power_loss_durability='NOT_TESTED',interruption_native='NOT_RUN')
 return p

def render(before,case,fixed_case,operation='remove-interruption'):
 """Only pinned source DATA is transformed; no live transaction/actor here."""
 need(operation in('normal','remove-interruption'),'closed operation')
 normal,normal_ledger=fixed_case.render(before,case)
 if operation=='normal':return normal,normal_ledger
 need(case in CASES and len(before)==len(normal)==667,'selected complete current667 runtime')
 oldp=fixed_case.profile(case);p=profile(case,oldp);out=dict(normal);ledger={}
 def change(name,old,new,count=1):
  a,b=old.encode(),new.encode();need(a and out[name].count(a)==count,'counted interruption source seam '+name+' '+old[:70]);out[name]=out[name].replace(a,b,count);ledger.setdefault(name,[]).append(dict(before=old,after=new,count=count))
 def append(name,text):out[name]+=text.encode();ledger.setdefault(name,[]).append(dict(before='',after=text,count=1,append=True))
 # Exact original checkpoint module/function operands are already in749.
 original=functions(before[NATIVE]);interrupted=functions(before[INTERRUPTED]);need(set(original)==set(interrupted),'same original lifecycle function namespace')
 need([n for n in original if original[n]!=interrupted[n]]==['transaction','guard','run_case','main'],'original interruption delta is finite')
 worker='immutable/worker.py'
 change(worker,'text=fixed_case_lifecycle(text)','text=remove_interruption_lifecycle(text)')
 change(worker,"module.C.helpers=bound_helpers;worker_api.install_validation(module)","module.C.helpers=bound_helpers;worker_api.install_validation(module)\n module.GNU_SELECTED_INTERRUPTION=remove_checkpoint(module)")
 change(worker,"row['status']=='PASS_NORMAL_DISPOSABLE_PROVIDER_SEQUENCE'","row['status']=='PASS_INTERRUPTED_RECOVERED_NORMAL_PROVIDER_SEQUENCE'")
 change(worker,"('before_runtime','provider_runtime','reinstalled_runtime','held_runtime')","('before_runtime','recovered_runtime','provider_runtime','reinstalled_runtime','held_runtime')")
 change(worker,"stages=('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after')",'stages='+repr(STAGES))
 change(worker,"==8 and all(not n.startswith(('pristine-','modified-'))","==10 and all(not n.startswith(('pristine-','modified-'))")
 # These are real checkpoint/recovery predicates, not status/count annotation.
 anchor="  for name in('before_runtime','recovered_runtime','provider_runtime','reinstalled_runtime','held_runtime'):"
 predicates="""  interrupted=row['interruption'];P.need(interrupted['status']=='PASS_ACTUAL_REMOVE_PHASE_KILL_AND_EXTERNAL_RECOVERY'and interrupted['writer']['exit_code']==-9 and interrupted['writer']['group_absence_verified']is True and interrupted['observed_stop']=='KERNEL_CLD_STOPPED_SIGSTOP_WITH_UNREAPED_OWNED_LEADER','actual REMOVE callback/stop/kill/absence required')
  P.need(interrupted['lock_recovery']['status']=='PASS_EXACT_OWNED_STALE_LOCK_REMOVED_AFTER_GROUP_ABSENCE'and interrupted['external_recovery']['status']=='PASS_COMMITTED_REPLACEMENT'and interrupted['recovered_preservation']['unrelated_preserved']is True and interrupted['outer_runtime_before']==interrupted['outer_runtime_after'],'exact owned lock/external held reinstall/preservation required')
  if case=='modified':P.need(tuple(row['configuration_handoff'])==('provider','rollback_prepare','rollback_finish'),'all three explicit clone configuration handoffs required')
"""
 # Existing report is a list, checked below from the held source—not guessed.
 predicates=predicates.replace("tuple(row['configuration_handoff'])==('provider','rollback_prepare','rollback_finish')","tuple(row[n]['phase']for n in('provider_config_handoff','rollback_config_prepare','rollback_config_handoff'))==('provider','rollback_prepare','rollback_finish')and all(row[n]['status']=='PASS_EXPLICIT_CLONE_CONFIG_HANDOFF'for n in('provider_config_handoff','rollback_config_prepare','rollback_config_handoff'))")
 change(worker,anchor,predicates+anchor)
 change('immutable/leases.py',"ORDER=('probe',)+("+repr(case)+',)*4',"ORDER=('probe',)+("+repr(case)+',)*5')
 for name in('immutable/owner.py','immutable/native_controller.py'):
  if name.endswith('owner.py'):
   change(name,"retired['leases'] == 5","retired['leases'] == 6")
   change(name,"('probe',)+("+repr(case)+",)*4","('probe',)+("+repr(case)+",)*5")
  else:
   change(name,"w['capabilities']['stages']==8","w['capabilities']['stages']==10")
   change(name,"==8 and all(not n.startswith(('pristine-','modified-'))","==10 and all(not n.startswith(('pristine-','modified-'))")
   change(name,"v['leases']['leases']==5","v['leases']['leases']==6")
   change(name,"('probe',)+("+repr(case)+',)*4',"('probe',)+("+repr(case)+',)*5')
 old_statuses={
  'PASS_FIXED_CASE_PROVIDER_LIFECYCLE_PENDING_PAIRED_ROOT_ACCEPTANCE':'PASS_REMOVE_INTERRUPTION_RECOVERY_PENDING_PAIRED_ROOT_ACCEPTANCE',
  'SOURCE_ENFORCED_FIXED_CASE_AWAITING_PID1_RETIREMENT':'SOURCE_ENFORCED_REMOVE_INTERRUPTION_AWAITING_PID1_RETIREMENT',
  'FIXED_CASE_AND_GUEST_RETIREMENT_SOURCE_ENFORCED_NOT_ROOT_ACCEPTED':'REMOVE_INTERRUPTION_AND_GUEST_RETIREMENT_SOURCE_ENFORCED_NOT_ROOT_ACCEPTED',
  'PASS_FIXED_CASE_IMMUTABLE_GNU_RUNTIME_PENDING_PAIRED_ROOT_ACCEPTANCE':'PASS_REMOVE_INTERRUPTION_IMMUTABLE_GNU_RUNTIME_PENDING_PAIRED_ROOT_ACCEPTANCE'}
 for name in('immutable/worker_api.py',worker,'immutable/owner.py','immutable/native_controller.py'):
  for a,b in[(repr(oldp),repr(p)),*old_statuses.items()]:
   count=out[name].count(a.encode())
   if count:change(name,a,b,count)
 operands=dict(normal_transaction=original['transaction'],normal_run_case=original['run_case'],interrupted_transaction=interrupted['transaction'],interrupted_run_case=interrupted['run_case'])
 suffix='\nREMOVE_OPERANDS='+repr(operands)+'\nREMOVE_PROFILE='+repr(p)+'\nREMOVE_CHECKPOINT='+repr(dict(path=CHECKPOINT,pin=pin(before[CHECKPOINT])))+'\n'+WORKER_HELPER
 append(worker,suffix)
 manifest=json.loads(out['runtime-source.json']);manifest['files']={n:pin(b)for n,b in out.items()if n!='runtime-source.json'};out['runtime-source.json']=enc(manifest)
 restored=inverse(out,ledger);restored['runtime-source.json']=normal['runtime-source.json'];need(restored==normal,'whole normal749 selected runtime inverse')
 for n in ledger:compile(out[n],n,'exec')
 need(set(out)==set(before),'held667 runtime namespace; no new member')
 return out,ledger

def inverse(after,ledger):
 out=dict(after)
 for n,rows in ledger.items():
  raw=out[n]
  for row in reversed(rows):
   a,b=row['before'].encode(),row['after'].encode()
   if row.get('append'):need(raw.endswith(b),'whole appended helper inverse');raw=raw[:-len(b)]
   else:need(raw.count(b)==row['count'],'counted complete interruption inverse');raw=raw.replace(b,a,row['count'])
  out[n]=raw
 return out

WORKER_HELPER='''
def remove_checkpoint(module):
    import types,stat
    path=inputs.D.parent/REMOVE_CHECKPOINT['path'];P.need(path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'exact source-owned checkpoint path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);P.need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size==REMOVE_CHECKPOINT['pin']['bytes'],'whole checkpoint extent')
        raw=bytearray()
        while part:=os.read(fd,1024**2):raw.extend(part);P.need(len(raw)<=REMOVE_CHECKPOINT['pin']['bytes'],'bounded exact checkpoint bytes')
        raw=bytes(raw);P.need(P.stable(a)==P.stable(os.fstat(fd))==P.stable(path.lstat())and P.pin(raw)==REMOVE_CHECKPOINT['pin'],'whole checkpoint FD/path/hash identity')
    finally:os.close(fd)
    anchor=b'import common as C\\n';P.need(raw.count(anchor)==1,'one original checkpoint private import');private=types.ModuleType('_current749_owned_remove_checkpoint');private.__file__=str(path);private.C=module.C
    exec(compile(raw.replace(anchor,b'',1),str(path),'exec'),vars(private));return private

def remove_interruption_lifecycle(text):
    tree=ast.parse(text);functions={n.name:ast.get_source_segment(text,n)for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))};before=text;steps=[]
    def replace(old,new,count=1):
        nonlocal text
        P.need(text.count(old)==count,'one original generated16K interruption seam');text=text.replace(old,new,count);steps.append((old,new,count))
    for role in('transaction','run_case'):
        old=REMOVE_OPERANDS['normal_'+role];new=REMOVE_OPERANDS['interrupted_'+role]
        P.need(role in functions and functions[role]==old,'whole original normal generated16K function')
        if role=='run_case':
            anchor='            import interruption';P.need(new.count(anchor)==1,'one existing interruption namespace import');new=new.replace(anchor,'            interruption=GNU_SELECTED_INTERRUPTION',1)
        replace(old,new)
    replace("'PASS_GENERIC_ARM_SYSTEM_PROVIDER_LIFECYCLE'","'PASS_REMOVE_INTERRUPTION_RECOVERY_PENDING_PAIRED_ROOT_ACCEPTANCE'",2)
    replace("interrupted_in_progress_replacement='NOT_RUN'","interrupted_in_progress_replacement='REMOVE_PHASE_ONLY_CANDIDATE_EXTRACTION_NOT_TESTED'")
    replace("report=dict(status='FAIL',scope=",'report=dict(fixed_case_validation='+repr(REMOVE_PROFILE)+",status='FAIL',scope=")
    restored=text
    for a,b,count in reversed(steps):P.need(restored.count(b)==count,'whole normal lifecycle inverse');restored=restored.replace(b,a,count)
    P.need(restored==before,'all original generated16K guard/config/runtime/cleanup/clocks held')
    changed={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
    P.need(set(changed)==set(functions)and {n for n in functions if functions[n]!=changed[n]}=={'transaction','run_case','main'}and changed['config_handoff']==functions['config_handoff'],'only existing interruption functions/main operands; all three config handoffs held')
    return text
'''

def selector(case,operation):
 need(type(operation)is str and operation in('normal','remove-interruption'),'closed validation operation')
 need(type(case)is str and case in(('both',*CASES)if operation=='normal'else CASES),'interruption requires explicit pristine or modified; no hidden second case')
 return case,operation

def _source():
 import fixed_case
 root=Path(__file__).resolve().parents[3];q=json.loads(fixed_case.read(Path(__file__).with_name('interruption-profile.json')))
 base=fixed_case.snapshot(root/'runtime');need({n:pin(b)for n,b in base.items()}=={n[8:]:w for n,w in q['before'].items()if n.startswith('runtime/')},'whole source-owned749 raw runtime substrate')
 return root,fixed_case,base

def prepare(root,case,operation='normal'):
 """Private derivation AFTER the whole source gate, BEFORE any runtime import."""
 selector(case,operation)
 if operation=='normal':
  import fixed_case
  return fixed_case.prepare(root,case)
 import os,stat
 source,F,base=_source();expected,ledger=render(base,case,F,operation);normal,_=F.render(base,case)
 # Keep original path/private-parent/raw747 identity and whole read checks.
 F.prepare(root,case);root=Path(root);need(F.snapshot(root)==normal,'exact original normal selection before interruption writes')
 for name,raw in expected.items():
  if raw==normal[name]:continue
  path=root/name;fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   a=os.fstat(fd);key=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
   need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size==len(normal[name]),'ordinary private interruption output')
   before=bytearray()
   while part:=os.read(fd,1024**2):before.extend(part)
   need(bytes(before)==normal[name]and key(a)==key(os.fstat(fd))==key(path.lstat()),'whole original private bytes/FD/path identity immediately before write')
   os.lseek(fd,0,os.SEEK_SET);os.ftruncate(fd,0);view=memoryview(raw)
   while view:
    size=os.write(fd,view);need(size>0,'complete private interruption write');view=view[size:]
   os.fsync(fd)
  finally:os.close(fd)
 need(F.snapshot(root)==expected,'whole selected interruption runtime after derivation')
 return dict(profile=profile(case,F.profile(case)),operation=operation,changed={n:dict(before=pin(base[n]),after=pin(b))for n,b in expected.items()if b!=base[n]},actual_acceptance=False)

def verify_selected(source,selected,case,operation='normal'):
 selector(case,operation)
 import fixed_case as F
 if operation=='normal':return F.verify_selected(source,selected,case)
 actual_source,F,base=_source();need(Path(source).resolve()==actual_source,'current source origin')
 expected,_=render(base,case,F,operation);actual=F.snapshot(selected);need(set(actual)==set(expected),'complete interrupted runtime namespace')
 selectors={'immutable/policy.json','immutable/qualification-pins.json'}
 need(all(actual[n]==b for n,b in expected.items()if n not in selectors|{'runtime-source.json'}),'every interrupted executable equals exact source-owned derivative')
 manifest=json.loads(expected['runtime-source.json'])
 for n in selectors:manifest['files'][n]=pin(actual[n])
 need(enc(manifest)==actual['runtime-source.json'],'only original two private selector manifest rows differ')
 return dict(case=case,operation=operation,files=len(actual),code='EXACT_SOURCE_OWNED_REMOVE_DERIVATIVE',acceptance=False)
