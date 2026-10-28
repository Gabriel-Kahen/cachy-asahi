#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact owner entrypoint: selected authority and old packet are distinct roots."""
import ast,hashlib,os,re,stat,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent.parent
OWNER={'bytes':39552,'sha256':'973c96eacc1a321aa497962b449f4c7d46bd41ed5d1361f8b7ec56c36c2edfb7'}
PROFILE={'bytes':44437,'sha256':'359a8cf7ff531160981fae4a9fce486f0904b4798bbee30311919e500f0395d6'}
BOOT={'bytes':5868,'sha256':'8bfac0641230cbf52571b8d000bdf79f80adaa33f6d54f649eacba2d6eb54fca'}
SELECTED={
 'apps16-repair/selection.py':{'bytes':8889,'sha256':'616cfe431e97c1576fca6119ec552d5f16226847d3569c8e248410a6bdee2150'},
 'apps16-repair/carrier.py':{'bytes':4181,'sha256':'a181a6d080dab7a5a1613f23e6a1da70596c8c3d8c84fd44e444a32f3a7950f1'},
 'apps16-repair/carrier-profile.json':{'bytes':46416,'sha256':'805e3ef1b4e2be899476c3d215468af02f824eb8a071e473e22aeb7bae3aed0e'},
 'apps16-repair/contract_common.py':{'bytes':4407,'sha256':'340f6db4592c72507f1028e882fe78b5398ea9b8cab6323260ff6e0c88543380'}}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def bootstrap_snapshot(path):
 need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary bootstrap ancestry')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==BOOT['bytes'],'bounded singlelink ordinary bootstrap')
  raw=bytearray()
  while block:=os.read(fd,BOOT['bytes']+1):raw.extend(block);need(len(raw)<=BOOT['bytes'],'bootstrap growth')
  key=lambda s:tuple(getattr(s,n)for n in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
  need(len(raw)==before.st_size and key(before)==key(os.fstat(fd))==key(path.lstat()),'stable bootstrap FD/path snapshot');return bytes(raw)
 finally:os.close(fd)
def module(raw,path,name):
 m=types.ModuleType(name);m.__file__=str(path);sys.modules[name]=m;exec(compile(raw,str(path),'exec'),vars(m));return m
def selected_checker(owner,args,ordinary):
 """Use the admitted selected source, not the caller's old packet directory."""
 profile=owner.source_gate(args);source=owner.canonical(args.recovery_source)
 need(source==ROOT/'repair-source' and all(profile['source_files'][n]==v for n,v in SELECTED.items()),'exact selected carrier authority closure')
 packet=owner.canonical(args.packet);carrier=owner.canonical(args.apps16_pair)
 need(all(not a.is_relative_to(b) and not b.is_relative_to(a) for a,b in((source,packet),(carrier,packet),(source,carrier))),'distinct selected source, carrier and old packet')
 selected=owner.load('source_bound_selected_checker',source/'apps16-repair/selection.py')
 def checked(root,row):
  if row['path'].startswith('APPS16_CARRIER/'):
   need(owner.canonical(root)==packet,'explicit original packet operand for selected row')
   owner.source_gate(args)
   need(owner.canonical(args.recovery_source)==source and owner.canonical(args.apps16_pair)==carrier,'held selected authority and carrier roots')
   return selected.checked(source,row,carrier_root=carrier)
  return ordinary(root,row)
 return checked
def configure(owner):
 """Keep all original guards; change one checked root and one reexec target."""
 original=owner.modules
 def modules(args,cleanup=False):
  result=original(args,cleanup)
  result.H.C.checked=selected_checker(owner,args,result.H.C.checked)
  return result
 owner.modules=modules
 original_plan=owner.Runtime.actor_plan
 def actor_plan(runtime,role,context_sha=None):
  name,argv,public=original_plan(runtime,role,context_sha)
  if role=='install':
   path=ROOT/'workflow-support/install_diagnostic607.py';raw=owner.read(path,64*1024);sha=pin(raw)['sha256']
   capsule=owner.read(ROOT/'capsule.json');need(pin(capsule)['sha256']==os.environ.get('CAPSULE_SHA256'),'held independent capsule before actor mount')
   need(owner.decode(capsule)['files']['workflow-support/install_diagnostic607.py']==pin(raw),'source-bound diagnostic helper before actor mount')
   alpm_path=ROOT/'workflow-support/alpm_load_diagnostic607.py';alpm_raw=owner.read(alpm_path,64*1024);alpm_sha=pin(alpm_raw)['sha256']
   need(owner.decode(capsule)['files']['workflow-support/alpm_load_diagnostic607.py']==pin(alpm_raw),'source-bound signed-load helper before actor mount')
   need(argv[-4:]==['-I','-B','/fresh-operation/provider607.py','--install']and argv.count('--entrypoint=/usr/bin/python3')==1,'one exact original install actor slot')
   at=argv.index('--entrypoint=/usr/bin/python3');argv=argv[:at]+['--mount','type=bind,src='+str(path)+',dst=/fresh-install-diagnostic.py,readonly','--env=FRESH_INSTALL_DIAGNOSTIC_SHA256='+sha,'--mount','type=bind,src='+str(alpm_path)+',dst=/fresh-alpm-diagnostic.py,readonly','--env=FRESH_ALPM_DIAGNOSTIC_SHA256='+alpm_sha]+argv[at:]
   argv[-2]='/fresh-install-diagnostic.py'
  return name,argv,public
 owner.Runtime.actor_plan=actor_plan
 raw=owner.read(Path(owner.__file__));need(pin(raw)==OWNER,'whole held owner before main derivation')
 text=raw.decode();node=next(n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)and n.name=='main');before=ast.get_source_segment(text,node)+'\n'
 old='str(Path(__file__).resolve())';new='str(SELECTED_OWNER_ENTRY)'
 need(before.count(old)==1 and new not in before,'one exact supervised child entrypoint seam')
 after=before.replace(old,new,1);need(after.replace(new,old,1)==before,'whole original main inverse')
 owner.SELECTED_OWNER_ENTRY=Path(__file__).resolve()
 exec(compile(after,'<source-bound-owner-main-exact-inverse>','exec'),vars(owner))
 return dict(owner=OWNER,main_before=pin(before.encode()),main_after=pin(after.encode()),whole_main_inverse=True,selected_source=SELECTED,supervised_child=str(owner.SELECTED_OWNER_ENTRY))
def load_owner():
 need(ROOT.is_absolute() and ROOT==ROOT.resolve() and not any(p.is_symlink()for p in(ROOT,*ROOT.parents)),'canonical closed owner source')
 expected=os.environ.get('CAPSULE_SHA256');need(type(expected)is str and re.fullmatch('[0-9a-f]{64}',expected),'independent capsule pin inherited by owned child')
 path=ROOT/'workflow-support/bootstrap.py';raw=bootstrap_snapshot(path);need(pin(raw)==BOOT,'held bounded source reader')
 boot=module(raw,path,'_selected_source_bootstrap');capsule=boot.read(ROOT/'capsule.json');need(pin(capsule)['sha256']==expected,'independent whole capsule pin')
 value=boot.decode(capsule);need(value['operation']=='recover-apps16-reinstall607' and value['actual']is value['Root_acceptance']is None,'source-only capsule identity')
 rows=boot.tree(ROOT,capsule=True);need(rows==dict(value['files'],**{'capsule.json':pin(capsule)}),'whole exact capsule namespace before owner import')
 need(rows['workflow-support/selected_source_owner607.py']==pin(boot.read(Path(__file__))) and rows['operation/native_owner607.py']==OWNER and rows['operation/profile.json']==PROFILE,'exact entrypoint, owner and operation profile')
 path=ROOT/'operation/native_owner607.py';raw=boot.read(path);need(pin(raw)==OWNER,'held owner import snapshot')
 owner=module(raw,path,'_selected_source_original_owner607');configure(owner);return owner
if __name__=='__main__':raise SystemExit(load_owner().main())
