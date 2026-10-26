# SPDX-License-Identifier: MIT
"""Explicit private single-case TCG validation; the default two-case route is held."""
import ast,hashlib,json,os,stat
from pathlib import Path
CASES=('both','pristine','modified')
PROFILE_NAME='GNU_TCG_FIXED_CASE_CLEANUP600_OBSERVATION1200_SHARED7200_V1'
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def read(path,cap=16*1024**2):
 p=Path(path);need(p.is_absolute()and p==p.resolve()and not any(x.is_symlink()for x in(p,*p.parents)),'canonical ordinary fixed-case input');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink fixed-case input');data=bytearray()
  while len(data)<a.st_size:
   part=os.read(fd,min(1024**2,a.st_size-len(data)));need(bool(part),'complete fixed-case input');data.extend(part)
  key=lambda q:tuple(getattr(q,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
  need(key(a)==key(os.fstat(fd))==key(p.lstat()),'fixed-case input drift');return bytes(data)
 finally:os.close(fd)
def profile(case):
 need(type(case)is str and case in CASES,'explicit fixed validation case')
 return dict(name=PROFILE_NAME,case=case,required_cases=['pristine','modified'],acceptance='BOTH_SEPARATE_SAME_SOURCE_OUTCOMES_REQUIRED',cleanup_seconds=600,observation_seconds=1200,copy_context_seconds=7200,owner_ceiling=10500,qemu_ceiling=10800,capacity_reserved=False,cleanup600_fit='NOT_ESTABLISHED',old_two_case_fit='NOT_ESTABLISHED',hardware='NOT_RUN')
def edit(raw,old,new):
 need(raw.count(old)==1,'one exact whole747 fixed-case seam');value=raw.replace(old,new,1);need(value.replace(new,old,1)==raw,'whole747 fixed-case body inverse');return value

def render(before,case):
 need(type(case)is str and case in CASES,'explicit fixed validation case');before=dict(before)
 if case=='both':return before,{}
 out=dict(before);ledger={};p=profile(case)
 def change(name,old,new):
  raw=out[name];out[name]=edit(raw,old.encode(),new.encode());ledger.setdefault(name,[]).append(dict(before=old,after=new,count=1))
 w='immutable/worker_api.py'
 change(w,"  module=aux._isolated(aux.disposable_copy.__file__,aux.LIFETIME_SHA256);module.measure_copy=types.SimpleNamespace(copy_data=copy_data)","  P.need(kwargs.get('cleanup_seconds')==120,'exact original120 cleanup caller')\n  kwargs=dict(kwargs,cleanup_seconds=600)\n  module=fixed_case_lifetime(aux);module.measure_copy=types.SimpleNamespace(copy_data=copy_data)")
 change(w,'bridge.records=clone(oldbridge.records,scope=scope)','bridge.records=clone(fixed_case_records,**dict(vars(oldbridge),scope=scope,FIXED_CASE='+repr(case)+'))')
 # Derive the original complete capability records function, changing only its
 # explicit case set/count. No invented row stands in for the unexecuted case.
 caps=before['runtime-vm/scripts/ci/glibc-gnu-provider-lifecycle/capabilities.py'].decode();node=next(n for n in ast.parse(caps).body if isinstance(n,ast.FunctionDef)and n.name=='records');records=ast.get_source_segment(caps,node)
 records=edit(records,'def records(index,cases,stages):','def fixed_case_records(index,cases,stages):')
 records=edit(records,"set(cases)=={'pristine','modified'}","set(cases)=={FIXED_CASE}")
 records=edit(records,'paths=len(mapping),cases=2,stages=len(stages)','paths=len(mapping),cases=1,stages=len(stages)')
 suffix='\nFIXED_CASE='+repr(case)+'\nFIXED_CASE_VALIDATION_PROFILE='+repr(p)+'\n'+records+'\n'+LIFETIME_HELPER
 out[w]+=suffix.encode();ledger[w].append(dict(before='',after=suffix,count=1,append=True))
 w='immutable/worker.py'
 change(w,'text=lifecycle(original);module=G.load','text=lifecycle(original);text=fixed_case_lifecycle(text);module=G.load')
 addition=f"""
def fixed_case_lifecycle(text):
 old={"'PASS_GENERIC_ARM_SYSTEM_PROVIDER_LIFECYCLE'"!r}
 new={"'PASS_FIXED_CASE_PROVIDER_LIFECYCLE_PENDING_PAIRED_ROOT_ACCEPTANCE'"!r}
 anchor={"report=dict(status='FAIL',scope="!r}
 replacement={('report=dict(fixed_case_validation='+repr(p)+",status='FAIL',scope=")!r}
 P.need(text.count(old)==2 and text.count(anchor)==1,'exact selected raw lifecycle result seams')
 changed=text.replace(old,new).replace(anchor,replacement,1)
 P.need(changed.replace(new,old).replace(replacement,anchor,1)==text,'entire raw lifecycle outside honest selected result fields held')
 return changed
"""
 out[w]+=addition.encode();ledger.setdefault(w,[]).append(dict(before='',after=addition,count=1,append=True))
 change(w,"report['status']=='PASS_GENERIC_ARM_SYSTEM_PROVIDER_LIFECYCLE'","report['status']=='PASS_FIXED_CASE_PROVIDER_LIFECYCLE_PENDING_PAIRED_ROOT_ACCEPTANCE'and report.get('fixed_case_validation')==worker_api.FIXED_CASE_VALIDATION_PROFILE " )
 change(w,'module.C.helpers=bound_helpers;worker_api.install_validation(module)','module.C.helpers=bound_helpers;worker_api.install_validation(module)\n module.C=__import__(\'types\').SimpleNamespace(**dict(vars(module.C),CASES=('+repr(case)+',)))')
 change(w,"code=module.main();P.need(code==0,'unchanged complete two-case574 provider lifecycle')","code=module.main();P.need(code==0,'complete selected fixed-case574 provider lifecycle; other case not inferred')")
 change(w,"and not any(Path('/work').iterdir()),'full original lifecycle/clone cleanup'","and set(report['cases'])=={worker_api.FIXED_CASE}and not any(Path('/work').iterdir()),'full selected lifecycle/clone cleanup'")
 change(w,"sum(n.endswith('-root.json.gz')for n in files)==16,'all16 fullmaps and original export limits'","sum(n.endswith('-root.json.gz')for n in files)==8 and all(not n.startswith(('pristine-','modified-'))or n.startswith(worker_api.FIXED_CASE+'-')for n in files),'all8 selected fullmaps and original export limits'")
 change(w,'dict(descriptor_query=dict(worker_api.DESCRIPTOR_QUERY_PROFILE),','dict(fixed_case_validation=dict(worker_api.FIXED_CASE_VALIDATION_PROFILE),descriptor_query=dict(worker_api.DESCRIPTOR_QUERY_PROFILE),')
 change(w,"status='SOURCE_ENFORCED_FULL_LIFECYCLE_AWAITING_PID1_RETIREMENT'","status='SOURCE_ENFORCED_FIXED_CASE_AWAITING_PID1_RETIREMENT'")
 w='immutable/leases.py';change(w,"ORDER=('probe',)+('pristine',)*4+('modified',)*4","ORDER=('probe',)+("+repr(case)+',)*4')
 w='immutable/owner.py'
 change(w,"(result['status'] == 'SOURCE_ENFORCED_FULL_LIFECYCLE_AWAITING_PID1_RETIREMENT')","(result['status'] == 'SOURCE_ENFORCED_FIXED_CASE_AWAITING_PID1_RETIREMENT') and result.get('fixed_case_validation')=="+repr(p))
 change(w,"P.need(retired['leases'] == 9, 'one original preflight plus eight real runtime leases')","P.need(retired['leases'] == 5 and tuple(r['case']for r in retired['records'])==('probe',)+("+repr(case)+",)*4, 'one original preflight plus four selected real runtime leases')")
 change(w,'return dict(cold_validation=dict(COLD_VALIDATION_PROFILE),','return dict(fixed_case_validation='+repr(p)+',cold_validation=dict(COLD_VALIDATION_PROFILE),')
 change(w,"status='FULL_LIFECYCLE_AND_GUEST_RETIREMENT_SOURCE_ENFORCED_NOT_ROOT_ACCEPTED'","status='FIXED_CASE_AND_GUEST_RETIREMENT_SOURCE_ENFORCED_NOT_ROOT_ACCEPTED'")
 w='immutable/native_controller.py'
 change(w,"PASS='PASS_NEW_IMMUTABLE_GNU_RUNTIME_PENDING_ROOT_ACCEPTANCE'","PASS='PASS_FIXED_CASE_IMMUTABLE_GNU_RUNTIME_PENDING_PAIRED_ROOT_ACCEPTANCE'")
 change(w,"v['status']=='FULL_LIFECYCLE_AND_GUEST_RETIREMENT_SOURCE_ENFORCED_NOT_ROOT_ACCEPTED'","v['status']=='FIXED_CASE_AND_GUEST_RETIREMENT_SOURCE_ENFORCED_NOT_ROOT_ACCEPTED'and v.get('fixed_case_validation')=="+repr(p))
 change(w,"w['status']=='SOURCE_ENFORCED_FULL_LIFECYCLE_AWAITING_PID1_RETIREMENT'","w['status']=='SOURCE_ENFORCED_FIXED_CASE_AWAITING_PID1_RETIREMENT'and w.get('fixed_case_validation')=="+repr(p))
 change(w,"w['capabilities']['cases']==2","w['capabilities']['cases']==1 and set(w['capabilities']['copy_scope_sha256'])=={"+repr(case)+'}')
 change(w,"sum(n.endswith('-root.json.gz')for n in files)==16","sum(n.endswith('-root.json.gz')for n in files)==8 and all(not n.startswith(('pristine-','modified-'))or n.startswith("+repr(case)+"+'-')for n in files)")
 change(w,"v['leases']['leases']==9","v['leases']['leases']==5 and tuple(r['case']for r in v['leases']['records'])==('probe',)+("+repr(case)+',)*4')
 change(w,'complete original16 root snapshots and aggregate export','complete selected8 root snapshots and original aggregate export')
 # Honest private runtime seal; all remaining667 namespace entries stay exact.
 manifest=json.loads(out['runtime-source.json']);manifest['files']={n:pin(b)for n,b in out.items()if n!='runtime-source.json'};out['runtime-source.json']=enc(manifest)
 for n,steps in ledger.items():
  restored=out[n]
  for step in reversed(steps):
   a,b=step['before'].encode(),step['after'].encode()
   if step.get('append'):need(restored.endswith(b),'exact fixed-case append');restored=restored[:-len(b)]
   else:restored=edit(restored,b,a)
  need(restored==before[n],'entire original747 runtime body recovered '+n);compile(out[n],n,'exec')
 need(set(out)==set(before)and len(out)==667,'complete held runtime namespace')
 return out,ledger

LIFETIME_HELPER='''
def fixed_case_lifetime(aux):
    # Original stable-FD/hash loader is unchanged. Its private compile seam
    # sees only the exact already-verified lifetime bytes, then changes the
    # explicit allowed cleanup capacity; every live cleanup operation is held.
    def compile_lifetime(raw, filename, mode):
        import hashlib
        P.need(type(raw)is bytes and hashlib.sha256(raw).hexdigest()==aux.LIFETIME_SHA256 and mode=='exec','exact original cleanup source')
        before=b'0 < cleanup_seconds <= 120';after=b'0 < cleanup_seconds <= 600'
        P.need(raw.count(before)==1,'one explicit cleanup120 maximum')
        changed=raw.replace(before,after,1)
        P.need(changed.replace(after,before,1)==raw,'whole original cleanup body inverse')
        return compile(changed,filename,mode)
    return clone(aux._isolated,compile=compile_lifetime)(aux.disposable_copy.__file__,aux.LIFETIME_SHA256)
'''

def snapshot(root):
 root=Path(root);need(root.is_absolute()and root==root.resolve()and not any(p.is_symlink()for p in(root,*root.parents)),'canonical fixed-case runtime root');out={}
 for p in sorted(root.rglob('*')):
  need(not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary complete runtime namespace')
  if p.is_file():out[p.relative_to(root).as_posix()]=read(p)
 return out

def prepare(root,case):
 need(case in CASES,'explicit fixed validation case');root=Path(root);source=Path(__file__).resolve().parents[3];parent=root.parent.lstat();need(root.name=='selected-runtime'and parent.st_uid==os.geteuid()and stat.S_IMODE(parent.st_mode)==0o700 and not root.is_relative_to(source)and not source.is_relative_to(root),'caller-private selected runtime outside source inputs');before=snapshot(root);proof=json.loads(read(Path(__file__).with_name('lifetime-validation-profile.json')));expected={n[len('runtime/'):]:w for n,w in proof['before'].items()if n.startswith('runtime/')}
 need({n:pin(b)for n,b in before.items()}==expected,'whole exact747 runtime before private profile derivation');after,ledger=render(before,case)
 need(snapshot(root)==before,'late whole runtime drift before any profile write')
 for n,b in after.items():
  if b==before[n]:continue
  p=root/n;fd=os.open(p,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   opened=os.fstat(fd);need(stat.S_ISREG(opened.st_mode)and opened.st_nlink==1 and opened.st_size==len(before[n]),'ordinary private runtime output')
   original=bytearray()
   while part:=os.read(fd,1024**2):original.extend(part)
   key=lambda q:tuple(getattr(q,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
   need(bytes(original)==before[n]and key(opened)==key(os.fstat(fd))==key(p.lstat()),'late exact private output identity and bytes before write')
   os.lseek(fd,0,os.SEEK_SET);os.ftruncate(fd,0);view=memoryview(b)
   while view:view=view[os.write(fd,view):]
   os.fsync(fd)
  finally:os.close(fd)
 need(snapshot(root)==after,'whole selected fixed-case runtime after derivation')
 return dict(profile=profile(case)if case!='both'else'HELD_ORIGINAL_TWO_CASE_CLEANUP120',changed={n:dict(before=pin(before[n]),after=pin(after[n]))for n in before if after[n]!=before[n]},actual_acceptance=False)

def verify_selected(source,selected,case):
    # This runs after the complete current source guard and BEFORE importing
    # any private executable. Only the two original private selector documents
    # retain their original downstream closed-policy validation.
    source=Path(source);selected=Path(selected);proof=json.loads(read(Path(__file__).with_name('lifetime-validation-profile.json')));base=snapshot(source/'runtime');need({n:pin(b)for n,b in base.items()}=={n[8:]:w for n,w in proof['before'].items()if n.startswith('runtime/')},'complete source-owned747 runtime substrate')
    expected,_=render(base,case);actual=snapshot(selected);need(set(actual)==set(expected),'complete selected runtime namespace')
    selectors={'immutable/policy.json','immutable/qualification-pins.json'}
    need(all(actual[n]==b for n,b in expected.items()if n not in selectors|{'runtime-source.json'}),'every selected executable equals exact source-owned fixed-case derivative')
    manifest=json.loads(expected['runtime-source.json'])
    for n in selectors:manifest['files'][n]=pin(actual[n])
    need(enc(manifest)==actual['runtime-source.json'],'only original two private selector manifest rows differ')
    return dict(case=case,files=len(actual),code='EXACT_SOURCE_OWNED_DERIVATIVE',acceptance=False)
