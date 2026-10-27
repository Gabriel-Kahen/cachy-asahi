# SPDX-License-Identifier: MIT
"""Explicit raw runtime delta; exact old-substrate derivation bridge."""
import hashlib,importlib.util,json,os,stat,sys,tempfile,types
from pathlib import Path
LANE='scripts/ci/gnu-immutable-source-native';PROFILE=LANE+'/original-signature-profile.json'
RAW=('immutable/worker_api.py','immutable/worker.py','immutable/stage.py','immutable/disk_adapter.py','immutable/owner.py')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def obj(b):return json.loads(b)
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def inline(name,body):
 return ('\n# ORIGINAL_SIGNATURE_'+name.upper()+'\n'+name+'_BODY='+repr(body)+'\n'+name+'_PIN='+repr(pin(body))+"\nimport types as _original_signature_types\n"+name+"=_original_signature_types.ModuleType('<SOURCE_OWNED_"+name+">')\nif {'bytes':len("+name+"_BODY),'sha256':__import__('hashlib').sha256("+name+"_BODY).hexdigest()}!="+name+"_PIN:raise ValueError('whole original signature helper')\nexec(compile("+name+"_BODY,'<SOURCE_OWNED_"+name+">','exec'),vars("+name+"))\n")

def raw_edits(helper,clock,signature):
 need(pin(signature)==dict(bytes=566,sha256='82501115482ffeb93cce58cbc36372d917159f9dd60e3b98fd465e94e16c2103'),'original locked detached signature')
 api=inline('_ORIGINAL_SIG',helper)+inline('_ORIGINAL_CLOCK',clock)+'''
_ORIGINAL_TRUST_CONTEXT=None
def install_original_signature_context(text,nonce):
 global _ORIGINAL_TRUST_CONTEXT
 receipt=_ORIGINAL_CLOCK.unpack_receipt(text)
 selection=dict(nonce=nonce,source_sha=receipt['source_sha'],trusted_clock=receipt)
 _ORIGINAL_SIG.guest_clock(selection);_ORIGINAL_TRUST_CONTEXT=selection
_ORIGINAL_SIGNATURE_PARENT_BIND=bind
def bind(api,channel,guest):
 value=_ORIGINAL_SIGNATURE_PARENT_BIND(api,channel,guest)
 P.need(_ORIGINAL_TRUST_CONTEXT is not None,'PID1 current clock required before lifecycle helpers')
 selection=guest.C.decode(guest.C.read('/debian-maintained-installed16k/selection.json'))
 P.need(selection['nonce']==_ORIGINAL_TRUST_CONTEXT['nonce']and selection['source_sha']==_ORIGINAL_TRUST_CONTEXT['source_sha'],'same actual original signature context')
 raw=guest.C.read('/inputs/lifecycle-input.json',2*1024**2)
 P.need(guest.C.sha(raw)==selection['input_index_sha256'],'same signed-restore input index')
 index=__import__('json').loads(raw);work=Path('/tmp/original-signature-work')
 if not work.exists():work.mkdir(mode=0o700)
 return _ORIGINAL_SIG.wrap_alpm(value,index,_ORIGINAL_TRUST_CONTEXT,work,diagnostic_root=Path('/out'))
'''
 worker='''
# ORIGINAL_SIGNATURE_WORKER_CONTEXT
_ORIGINAL_SIGNATURE_PARENT_RUN=run
def run(fd,nonce,bootstrap):
 worker_api.install_original_signature_context(os.environ.pop('CAA_ORIGINAL_TRUST_CLOCK',None),nonce)
 return _ORIGINAL_SIGNATURE_PARENT_RUN(fd,nonce,bootstrap)
'''
 stage=inline('_ORIGINAL_SIG',helper)+"\n_ORIGINAL_SIGNATURE_BYTES="+repr(signature)+'''
_ORIGINAL_SIGNATURE_PARENT_STAGE=execute
def execute(boot,volume,held,index,bundle,value):
 result=_ORIGINAL_SIGNATURE_PARENT_STAGE(boot,volume,held,index,bundle,value)
 row=index['held'];_ORIGINAL_SIG.need({k:row[k]for k in('bytes','sha256')}==_ORIGINAL_SIG.PACKAGE_PIN,'exact native held original binding')
 path=boot/'inputs'/row['path'];_ORIGINAL_SIG.need(path.name==_ORIGINAL_SIG.PACKAGE,'exact original signature destination')
 with _ORIGINAL_SIG.exact_file(path,_ORIGINAL_SIG.PACKAGE_PIN):
  target=path.with_name(path.name+'.sig')
  if target.exists():
   with _ORIGINAL_SIG.exact_file(target,_ORIGINAL_SIG.SIGNATURE_PIN):pass
  else:_ORIGINAL_SIG.fresh_file(target,_ORIGINAL_SIGNATURE_BYTES)
 return dict(result,original_signature_input=dict(archive=_ORIGINAL_SIG.PACKAGE_PIN,signature=_ORIGINAL_SIG.SIGNATURE_PIN,upstream_key=_ORIGINAL_SIG.FINGERPRINT,authority='SOURCE_DEFINED_INPUT_ONLY_NOT_ACCEPTANCE'))
'''
 disk=inline('_ORIGINAL_CLOCK',clock)+'''
_ORIGINAL_SIGNATURE_PARENT_QEMU=qemu
def qemu(original,kernel,boot,work,source,hashed):
 return _ORIGINAL_CLOCK.host_argv(_ORIGINAL_SIGNATURE_PARENT_QEMU(original,kernel,boot,work,source,hashed),work)
'''
 owner=inline('_ORIGINAL_CLOCK',clock)
 edits={n:[dict(before='',after=b,count=1,append=True,purpose='ORIGINAL_SIGNATURE_TRUST_V1')]for n,b in zip(RAW,(api,worker,stage,disk,owner))}
 edits['immutable/owner.py'].insert(0,dict(before='    nofile = guest.observer_file_limit()',after="    original_clock = _ORIGINAL_CLOCK.guest_handoff(value, selected)\n    nofile = guest.observer_file_limit()",count=1))
 a="PYTHONDONTWRITEBYTECODE='1'), seconds, 512 * 1024, service=transport)";b="PYTHONDONTWRITEBYTECODE='1', CAA_ORIGINAL_TRUST_CLOCK=_ORIGINAL_CLOCK.pack_receipt(original_clock)), seconds, 512 * 1024, service=transport)"
 edits['immutable/owner.py'].insert(1,dict(before=a,after=b,count=1))
 export='runtime-vm/scripts/ci/glibc-debian-maintained-installed16k/export.py'
 prefix="    for name,cap in (('result.json',8*1024**2),"
 expanded=prefix+"('pristine-original-signature.log',65536),('modified-original-signature.log',65536),"
 line="            if name=='result.json':entry['projection']=diagnostic_projection(raw)"
 branch=line+"\n            elif name.endswith('-original-signature.log'):entry['original_signature_data']=original_signature_data(raw,name,request)"
 helper=r"""
def original_signature_data(raw,name,request):
    import base64,hashlib,json,re
    C.need(type(raw)is bytes and 0<len(raw)<=65536,'bounded original signature failure log')
    value=json.loads(raw,parse_constant=lambda _:C.need(False,'finite signature diagnostics'))
    case=name.split('-',1)[0]
    C.need(case in('pristine','modified')and name==case+'-original-signature.log'and type(value)is dict and set(value)=={'schema','status','case','source_sha','nonce','clock','events','acceptance','Root_acceptance'}and type(value['schema'])is int and value['schema']==1 and value['status']=='ORIGINAL_SIGNATURE_DIAGNOSTIC_DATA_ONLY'and value['case']==case and value['source_sha']==request['source_sha']and value['nonce']==request['nonce']and value['acceptance']is False and value['Root_acceptance']is None,'same original nonce/source bounded signature DATA only')
    C.need(type(value['events'])is list and 0<len(value['events'])<=12 and type(value['clock'])is dict,'finite signature/clock diagnostic rows')
    reference=dict(path=name,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    envelope=dict(schema=1,status='GNU_ORIGINAL_SIGNATURE_FAILURE_DATA_ONLY',nonce=request['nonce'],source_sha=request['source_sha'],case=case,reference=reference,raw_base64=base64.b64encode(raw).decode('ascii'),acceptance=False,native_authority=False,cleanup_authority=False,Root_acceptance=None)
    text=json.dumps(envelope,sort_keys=True,separators=(',',':'),allow_nan=False)
    C.need(len(text.encode('ascii'))<=96*1024,'bounded signature DATA stdout envelope')
    print('GNU_ORIGINAL_SIGNATURE_FAILURE_DATA '+text,flush=True)
    return dict(status='RAW_ORIGINAL_SIGNATURE_DIAGNOSTIC_ONLY',reference=reference,acceptance=False)
"""
 edits[export]=[dict(before=prefix,after=expanded,count=1),dict(before=line,after=branch,count=1),dict(before="if __name__=='__main__':main()",after=helper+"\nif __name__=='__main__':main()",count=1)]
 return edits

def manifest(out):
 q=obj(out['runtime-source.json']);q['files']={n:pin(b)for n,b in out.items()if n!='runtime-source.json'};out['runtime-source.json']=enc(q)
def apply(before,edits):
 out=dict(before)
 for n,rows in edits.items():
  for row in rows:
   a,b=row['before'].encode(),row['after'].encode()
   if row.get('append'):need(b not in out[n],'one fresh original signature append');out[n]+=b
   else:need(out[n].count(a)==row['count'],'counted original signature runtime seam');out[n]=out[n].replace(a,b,row['count'])
 manifest(out);return out

def undo(after,edits):
 out=dict(after)
 for n,rows in edits.items():
  for row in reversed(rows):
   a,b=row['before'].encode(),row['after'].encode()
   if row.get('append'):need(out[n].endswith(b),'whole original signature append inverse');out[n]=out[n][:-len(b)]
   else:need(out[n].count(b)==row['count'],'counted original signature runtime inverse');out[n]=out[n].replace(b,a,row['count'])
 manifest(out);return out

def profile():return obj(Path(__file__).with_name('original-signature-profile.json').read_bytes())
def normalize(before):
 q=profile();need({n:pin(b)for n,b in before.items()}==q['raw_after'],'entire current raw runtime667')
 out=undo(before,q['runtime_edits']);need({n:pin(b)for n,b in out.items()}==q['raw_before'],'entire old raw runtime667 recovered');return out

def render(before,case,F,operation,parent):
 q=profile();old=normalize(before);selected,ledger=parent(old,case,F,operation);out=apply(selected,q['selected_edits']);ledger={n:list(rows)for n,rows in ledger.items()}
 for n,rows in q['selected_edits'].items():ledger.setdefault(n,[]).extend(dict(row,trust_operation=operation)for row in rows)
 return out,ledger

def original_source():
 import fixed_case as F
 root=Path(__file__).resolve().parents[3];before=normalize(F.snapshot(root/'runtime'));q=obj(F.read(Path(__file__).with_name('interruption-profile.json')))
 need({n:pin(b)for n,b in before.items()}=={n[8:]:w for n,w in q['before'].items()if n.startswith('runtime/')},'all original substrate guards preserved by complete inverse');return root,F,before

def inverse(after,ledger,parent):
 operations={row['trust_operation']for rows in ledger.values()for row in rows if 'trust_operation'in row};out=parent(after,ledger)
 if not operations:return out
 need(len(operations)==1,'one original signature operation inverse');operation=next(iter(operations));q=profile()
 return apply(out,q['runtime_edits']if operation=='normal'else q['selected_edits'])

def write_delta(root,before,after):
 import fixed_case as F
 root=Path(root);source=Path(__file__).resolve().parents[3];parent=root.parent.lstat()
 need(root.name=='selected-runtime'and parent.st_uid==os.geteuid()and stat.S_IMODE(parent.st_mode)==0o700 and not root.is_relative_to(source)and not source.is_relative_to(root),'original caller-private selection namespace')
 need(F.snapshot(root)==before,'whole exact private runtime before derivative')
 for n,b in after.items():
  if b==before[n]:continue
  path=root/n;fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   a=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_uid==os.geteuid()and a.st_size==len(before[n]),'ordinary private output')
   raw=bytearray()
   while part:=os.read(fd,1024**2):raw.extend(part)
   need(bytes(raw)==before[n]and key(a)==key(os.fstat(fd))==key(path.lstat()),'complete private output bytes/FD/path')
   os.lseek(fd,0,os.SEEK_SET);os.ftruncate(fd,0);view=memoryview(b)
   while view:size=os.write(fd,view);need(size>0,'whole private write');view=view[size:]
   os.fsync(fd)
  finally:os.close(fd)
 need(F.snapshot(root)==after,'whole private derivative after write')

def prepare(root,case,operation,parent_prepare,parent_render):
 import fixed_case as F
 q=profile();before=F.snapshot(root);old=normalize(before);write_delta(root,before,old)
 old_prepare=types.FunctionType(parent_prepare.__code__,dict(parent_prepare.__globals__,render=parent_render),parent_prepare.__name__,parent_prepare.__defaults__,parent_prepare.__closure__)
 result=old_prepare(root,case,operation);original=F.snapshot(root);expected=apply(original,q['selected_edits']);write_delta(root,original,expected)
 return dict(result,original_signature='REQUIRED_UPSTREAM_ALPM_NO_VALIDATION_WAIVER',raw_runtime_changed=6,acceptance=False)

def verify_selected(source,selected,case,operation,parent_render):
 import fixed_case as F
 source=Path(source);root,F,old=original_source();need(source.resolve()==root,'same current source origin');q=profile();expected,_=parent_render(old,case,F,operation);expected=apply(expected,q['selected_edits']);actual=F.snapshot(selected);selectors={'immutable/policy.json','immutable/qualification-pins.json'}
 need(set(actual)==set(expected)and all(actual[n]==b for n,b in expected.items()if n not in selectors|{'runtime-source.json'}),'every current executable equals source-owned derivative')
 seal=obj(expected['runtime-source.json'])
 for n in selectors:seal['files'][n]=pin(actual[n])
 need(enc(seal)==actual['runtime-source.json'],'only original two private selector manifest rows may differ');return dict(case=case,operation=operation,files=len(actual),code='EXACT_SOURCE_OWNED_SIGNED_ORIGINAL_DERIVATIVE',acceptance=False)

def footer(row):return ('\n# ORIGINAL_SIGNATURE_SOURCE_GUARD\n_ORIGINAL_SIGNATURE_PROFILE_PIN='+repr(row)+"\ndef source(root=ROOT):\n return load('_original_signature_source',Path(root)/LANE/'original_signature_source.py').check(root)\n").encode()
def reseal(values):
 manifest_name=LANE+'/source-manifest.json';wfs=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-gnu-immutable-source.yml');m=obj(values[manifest_name]);m['files']={n:pin(b)for n,b in values.items()if n not in(manifest_name,*wfs)};values[manifest_name]=enc(m);workflow=values[LANE+'/workflow.yml.in'].decode().replace('@ENTRY_SHA@',pin(values[LANE+'/entry.py'])['sha256']).replace('@MANIFEST_SHA@',pin(values[manifest_name])['sha256']).encode()
 for name in wfs:values[name]=workflow

def source_inverse(current,q):
 need(len(current)==len(q['before'])+4 and set(current)==set(q['before'])|set(q['payload'])|{PROFILE},'complete signed-original source successor namespace')
 need(all(pin(current[n])==row for n,row in q['payload'].items()),'whole signed-original helper payloads')
 out={n:current[n]for n in q['before']};raw={n[8:]:b for n,b in out.items()if n.startswith('runtime/')};old=undo(raw,q['runtime_edits']);need({n:pin(b)for n,b in old.items()}==q['raw_before'],'every predecessor raw667 byte inverse');out.update({'runtime/'+n:b for n,b in old.items()})
 for name,suffix in q['source_suffixes'].items():
  b=suffix.encode();need(out[name].endswith(b),'whole source derivation bridge inverse');out[name]=out[name][:-len(b)]
 name=LANE+'/deploy.py';tail=footer(pin(current[PROFILE]));need(out[name].endswith(tail),'complete current profile footer inverse');out[name]=out[name][:-len(tail)]
 reseal(out);need({n:pin(b)for n,b in out.items()}==q['before'],'every original source778 byte recovered');return out

def check(root):
 import deploy as D
 root=Path(root);raw=D.read(root/PROFILE,4*1024**2);q=obj(raw);need(pin(raw)==D._ORIGINAL_SIGNATURE_PROFILE_PIN and q['parent_source']=='580daabb50a57b250ddbabb97f1423901a8d5d5d','hard-pinned signed-original profile and exact predecessor')
 need(all(q[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')),'source-only default selectors remain NULL')
 current={}
 for p in root.rglob('*'):
  if p.relative_to(root).parts[0]=='.git':continue
  need(not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary closed signed-original source')
  if p.is_file():current[p.relative_to(root).as_posix()]=D.read(p,16*1024**2)
 sealed=dict(current);reseal(sealed);need(sealed==current,'whole current source manifest and both workflow stamps')
 old=source_inverse(current,q);base={n[8:]:b for n,b in current.items()if n.startswith('runtime/')};need({n:pin(b)for n,b in base.items()}==q['raw_after'],'whole new raw667 runtime source')
 import extraction_case as X,fixed_case as F
 for operation,cases in(('normal',('both','pristine','modified')),('remove-interruption',('pristine','modified')),('candidate-extraction-interruption',('pristine','modified'))):
  for case in cases:
   selected,ledger=X.render(base,case,F,operation);need({n:pin(b)for n,b in selected.items()}==q['runtime_profiles'][operation][case],'complete signed-original runtime profile')
   untrusted=undo(selected,q['selected_edits']);need(apply(untrusted,q['selected_edits'])==selected,'complete original signature runtime delta inverse')
   for n,b in selected.items():
    if n.endswith('.py'):compile(b,n,'exec')
 saved=dict(sys.modules);paths=list(sys.path)
 try:
  with tempfile.TemporaryDirectory(prefix='original-signature-whole778-')as td:
   prior=Path(td)/'source';prior.mkdir()
   for n,b in old.items():p=prior/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
   for p in prior.rglob('*.py'):sys.modules.pop(p.stem,None)
   sys.path.insert(0,str(prior/LANE));entry=load('_original_signature_parent_entry',prior/LANE/'entry.py');parent=entry.source(prior);need(parent['files']==778 and parent['actual_run']is None,'original complete source778 entry remains mandatory')
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(parent,files=len(current),raw_runtime_files=667,raw_runtime_changed=6,raw_runtime_held=661,original_signature='REQUIRED_UPSTREAM_PGP_NO_VALIDATION_WAIVER',clock='SAME_RUN_NATIVE_REALTIME_HANDOFF_GUEST_PID1_ONLY',native='NOT_RUN',Root_acceptance=None)
