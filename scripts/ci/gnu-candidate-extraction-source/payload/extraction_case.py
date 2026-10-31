# SPDX-License-Identifier: MIT
"""Separate candidate extraction selection; both existing operations delegate."""
import json,os,stat
from pathlib import Path
import interruption_case as I
OPERATION='candidate-extraction-interruption'

def selector(case,operation):
 if operation!=OPERATION:return I.selector(case,operation)
 I.need(type(case)is str and case in I.CASES,'candidate extraction requires one explicit case');return case,operation

def profile(case,fixed_case):
 return dict(I.profile(case,fixed_case.profile(case)),name='GNU_SELECTED_CANDIDATE_EXTRACTION_INTERRUPTION_V1',scenario='REAL_ADD_PAYLOAD_CHECKPOINT_KILL_AND_EXPLICIT_HELD_REPAIR',operation=OPERATION,acceptance='BOTH_SEPARATE_SAME_SOURCE_EXTRACTION_CASES_REQUIRED',candidate_extraction='SOURCE_IMPLEMENTED_NATIVE_NOT_RUN',automatic_rollback='NOT_CLAIMED',automatic_configuration_preservation='NOT_CLAIMED')

def render(before,case,fixed_case,operation='normal'):
 selector(case,operation)
 if operation!=OPERATION:return I.render(before,case,fixed_case,operation)
 normal,_=I.render(before,case,fixed_case,'remove-interruption');out=dict(normal);ledger={};oldp=I.profile(case,fixed_case.profile(case));p=profile(case,fixed_case)
 def change(name,a,b):
  count=out[name].count(a.encode());I.need(count>0,'exact extraction seam '+name);out[name]=out[name].replace(a.encode(),b.encode());ledger.setdefault(name,[]).append(dict(before=a,after=b,count=count))
 for name in('immutable/worker_api.py','immutable/worker.py','immutable/owner.py','immutable/native_controller.py'):change(name,repr(oldp),repr(p))
 worker='immutable/worker.py';change(worker,'module.GNU_SELECTED_INTERRUPTION=remove_checkpoint(module)','module.GNU_SELECTED_INTERRUPTION=extraction_checkpoint(module)')
 change(worker,"interrupted['status']=='PASS_ACTUAL_REMOVE_PHASE_KILL_AND_EXTERNAL_RECOVERY'","interrupted['status']=='PASS_ACTUAL_CANDIDATE_EXTRACTION_KILL_AND_EXPLICIT_HELD_RECOVERY'and interrupted['operation']=='candidate-extraction-interruption'and interrupted['configuration_recovery']['status']=='PASS_EXPLICIT_EXTRACTION_RECOVERY_CONFIG_RESTORE'and interrupted['held_database']['status']=='PASS_COMPLETE_574_ROWS_AND_UNRELATED_573_RECORDS'")
 change(worker,'actual REMOVE callback/stop/kill/absence required','actual candidate ADD callback/stop/kill/absence and explicit recovery required')
 change(worker,'REMOVE_PHASE_ONLY_CANDIDATE_EXTRACTION_NOT_TESTED','CANDIDATE_EXTRACTION_WITH_EXPLICIT_HELD_REPAIR_NO_AUTOMATIC_ROLLBACK')
 statuses={'PASS_REMOVE_INTERRUPTION_RECOVERY_PENDING_PAIRED_ROOT_ACCEPTANCE':'PASS_CANDIDATE_EXTRACTION_RECOVERY_PENDING_PAIRED_ROOT_ACCEPTANCE','SOURCE_ENFORCED_REMOVE_INTERRUPTION_AWAITING_PID1_RETIREMENT':'SOURCE_ENFORCED_CANDIDATE_EXTRACTION_AWAITING_PID1_RETIREMENT','REMOVE_INTERRUPTION_AND_GUEST_RETIREMENT_SOURCE_ENFORCED_NOT_ROOT_ACCEPTED':'CANDIDATE_EXTRACTION_AND_GUEST_RETIREMENT_SOURCE_ENFORCED_NOT_ROOT_ACCEPTED','PASS_REMOVE_INTERRUPTION_IMMUTABLE_GNU_RUNTIME_PENDING_PAIRED_ROOT_ACCEPTANCE':'PASS_CANDIDATE_EXTRACTION_IMMUTABLE_GNU_RUNTIME_PENDING_PAIRED_ROOT_ACCEPTANCE'}
 for name in('immutable/worker_api.py',worker,'immutable/owner.py','immutable/native_controller.py'):
  for a,b in statuses.items():
   if a.encode()in out[name]:change(name,a,b)
 raw=fixed_case.read(Path(__file__).with_name('candidate_extraction.py'));suffix='\nEXTRACTION_BODY='+repr(raw)+'\nEXTRACTION_PIN='+repr(I.pin(raw))+'\n'+LOADER;out[worker]+=suffix.encode();ledger.setdefault(worker,[]).append(dict(before='',after=suffix,count=1,append=True))
 manifest=json.loads(out['runtime-source.json']);manifest['files']={n:I.pin(b)for n,b in out.items()if n!='runtime-source.json'};out['runtime-source.json']=I.enc(manifest)
 back=I.inverse(out,ledger);back['runtime-source.json']=normal['runtime-source.json'];I.need(back==normal,'whole remove runtime inverse; original operation untouched')
 for n in ledger:compile(out[n],n,'exec')
 I.need(set(out)==set(before)and len(out)==667,'complete original raw runtime namespace');return out,ledger

LOADER='''
def extraction_checkpoint(module):
    import types
    P.need(P.pin(EXTRACTION_BODY)==EXTRACTION_PIN,'whole source-owned extraction helper')
    private=types.ModuleType('_current_owned_candidate_extraction');private.__file__='<SOURCE_OWNED_CANDIDATE_EXTRACTION>';private.C=module.C;private.R=remove_checkpoint(module)
    exec(compile(EXTRACTION_BODY,private.__file__,'exec'),vars(private));return private
'''

def prepare(root,case,operation='normal'):
 selector(case,operation)
 if operation!=OPERATION:return I.prepare(root,case,operation)
 source,F,base=I._source();expected,_=render(base,case,F,operation);previous,_=I.render(base,case,F,'remove-interruption');I.prepare(root,case,'remove-interruption');root=Path(root);I.need(F.snapshot(root)==previous,'whole original remove selection before extraction writes')
 for n,b in expected.items():
  if b==previous[n]:continue
  p=root/n;fd=os.open(p,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   s=os.fstat(fd);I.need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size==len(previous[n]),'ordinary private extraction selection');raw=bytearray()
   while part:=os.read(fd,1024**2):raw.extend(part)
   key=lambda x:tuple(getattr(x,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'));I.need(bytes(raw)==previous[n]and key(s)==key(os.fstat(fd))==key(p.lstat()),'late whole private extraction FD/path identity');os.lseek(fd,0,os.SEEK_SET);os.ftruncate(fd,0);view=memoryview(b)
   while view:size=os.write(fd,view);I.need(size>0,'whole private extraction write');view=view[size:]
   os.fsync(fd)
  finally:os.close(fd)
 I.need(F.snapshot(root)==expected,'whole selected extraction runtime');return dict(profile=profile(case,F),operation=operation,changed={n:dict(before=I.pin(base[n]),after=I.pin(b))for n,b in expected.items()if b!=base[n]},actual_acceptance=False)

def verify_selected(source,selected,case,operation='normal'):
 selector(case,operation)
 if operation!=OPERATION:return I.verify_selected(source,selected,case,operation)
 actual_source,F,base=I._source();I.need(Path(source).resolve()==actual_source,'current extraction source origin');expected,_=render(base,case,F,operation);actual=F.snapshot(selected);I.need(set(actual)==set(expected),'complete extraction runtime namespace');selectors={'immutable/policy.json','immutable/qualification-pins.json'}
 I.need(all(actual[n]==b for n,b in expected.items()if n not in selectors|{'runtime-source.json'}),'every extraction executable is exact source derivative');manifest=json.loads(expected['runtime-source.json'])
 for n in selectors:manifest['files'][n]=I.pin(actual[n])
 I.need(I.enc(manifest)==actual['runtime-source.json'],'only original two private selector rows differ');return dict(case=case,operation=operation,files=len(actual),code='EXACT_SOURCE_OWNED_CANDIDATE_EXTRACTION_DERIVATIVE',acceptance=False)
