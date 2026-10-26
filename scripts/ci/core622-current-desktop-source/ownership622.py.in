# SPDX-License-Identifier: MIT
"""Retain one genuine already-retired generated image-id between whole owners."""
import hashlib,json,math,os,re,stat,time
from pathlib import Path

def need(v,s):
 if not v:raise ValueError(s)
def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
def read(p,cap):
 p=Path(p);need(not any(x.is_symlink()for x in(p,*p.parents)),'ordinary owned retirement path');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_uid==os.getuid()and a.st_size<=cap,'bounded caller-owned retirement metadata');raw=os.read(fd,cap+1);need(len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(p.lstat()),'whole stable generated metadata');return raw,identity(a)
 finally:os.close(fd)
def handoff(producer,core_output,proof,cleanup,command,deadline):
 need(type(deadline)in(int,float)and math.isfinite(deadline)and time.monotonic()<deadline,"remaining original producer cleanup allowance, no reset")
 producer,core_output=Path(producer),Path(core_output);need(producer.parent==Path('/tmp')and core_output.parent==producer.parent and producer.is_absolute()and core_output.is_absolute()and producer!=core_output,'same fresh original owner siblings');base=producer/'private/desktop574';iid=base/'image-id';raw,iid_identity=read(iid,128);need(re.fullmatch(b'sha256:[a-f0-9]{64}\n',raw)is not None,'entire exact generated image-id bytes');image=raw.decode().strip();report=json.loads(read(base/'report.json',2*1024**2)[0]);owner=json.loads(read(producer/'producer-owner.json',2*1024**2)[0]);need(re.fullmatch('[a-f0-9]{32}',owner['token'])and image!=owner['core_image']and image not in owner['images_preexisting'],'never retire/move borrowed image authority')
 need(report['image']==image and report['ownership']['token']==proof['producer_token']and image not in report['ownership']['before_images'],'actual base image/token equality');retired=report['owned_cleanup'];need(retired['status']=='PASS'and retired['image']==dict(id=image,absence_verified=True)and retired['probe']['absence_verified']is True,'entire original base cleanup required')
 need(cleanup['status']=='PASS_ALL_VM_THEN_ORIGINAL800_CONSUMER_PRODUCER_RETIREMENT'and cleanup['original_cleanup']==0,'VM and entire original Core cleanup precede ownership handoff')
 # This is an independent live absence query in the current owned run, not
 # authority inferred from an earlier receipt, a suppressed rm or cached result.
 result=command(['/usr/bin/docker','image','inspect',image],False,min(20,deadline-time.monotonic()));need(time.monotonic()<deadline,'original shared producer cleanup allowance after query');need(result['code']==1 and image.encode()in result['err']and b'No such image'in result['err']and result['out'].strip()in(b'',b'[]'),'unambiguous independently observed exact image absence')
 need(identity(iid.lstat())==iid_identity and read(iid,128)[0]==raw,'same generated image-id before move');target=core_output/'image-retirement';need(not os.path.lexists(target)and core_output.is_dir()and core_output.stat().st_uid==os.getuid(),'fresh caller-owned public retirement role');target.mkdir(mode=0o700);iid.rename(target/'original-desktop574-image-id');need(not os.path.lexists(iid)and read(target/'original-desktop574-image-id',128)[0]==raw,'only exact generated marker moved, raw DATA retained')
 value=dict(schema=1,status='EXACT_ORIGINAL_BASE_IMAGE_RETIRED_BEFORE_FRESH_PRODUCER_PRIVATE_CLEANUP',image=image,producer_token=proof['producer_token'],parent_producer_token=owner['token'],original_core_cleanup=cleanup['status'],independent_absence=True,marker=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),borrowed_core_image='PRESERVED',native_result='NOT_GRANTED_BY_THIS_RECEIPT');(target/'retirement.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n');return value

def prepare_owned(original,args,prepare,caller_pin):
 """Use the existing genuine owned574 build branch before image creation."""
 import ast,inspect
 import desktop622 as X
 caller=Path(args.code)/'scripts/ci/full-root-upgrade-caller/run.py';old_load=original.load;restores=[]
 def token(raw):
  need(Path(raw)==Path(args.output)/'private','same original producer private root');owner=json.loads(read(Path(args.output)/'producer-owner.json',65536)[0]);need(owner['schema_version']==1 and re.fullmatch('[a-f0-9]{32}',owner['token'])and owner['preparation_source']==str(args.preparation_source),'same actual parent producer source/instance');return hashlib.sha256(('core622-owned574:'+owner['token']).encode()).hexdigest()[:16]
 def load(path):
  api=old_load(path)
  if Path(path)==caller:
   raw=read(caller,128*1024)[0];need(hashlib.sha256(raw).hexdigest()==caller_pin,'entire immutable original fresh caller');tree=ast.parse(raw);nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='desktop'];need(len(nodes)==1,'one original574 producer function');body=ast.get_source_segment(raw.decode(),nodes[0]);need(inspect.getsource(api.desktop).strip()==body,'actual original producer function identity')
   edits=(("work = root / 'desktop574'; work.mkdir()","work = root / 'desktop574'; work.mkdir(mode=0o700)"),("'--output', work], work / 'build.log', 2400)","'--output', work, '--job-token', CURRENT_CORE622_BASE_TOKEN(root)], work / 'build.log', 2400)"));changed=body
   for a,b in edits:need(changed.count(a)==1,'one owned base CLI seam');changed=changed.replace(a,b)
   inverse=changed
   for a,b in reversed(edits):need(inverse.count(b)==1,'unique owned base inverse');inverse=inverse.replace(b,a)
   need(inverse==body,'entire original default desktop function inverse');prior=api.desktop;missing=object();previous=vars(api).get('CURRENT_CORE622_BASE_TOKEN',missing);api.CURRENT_CORE622_BASE_TOKEN=token;exec(compile(changed,'original-fresh-desktop-with-existing-job-token-role','exec'),vars(api));restores.append((api,prior,missing,previous))
  return api
 scoped=X.clone(original,load=load)
 try:return prepare(scoped,args)
 finally:
  for api,prior,missing,previous in restores:
   api.desktop=prior
   if previous is missing:vars(api).pop('CURRENT_CORE622_BASE_TOKEN',None)
   else:api.CURRENT_CORE622_BASE_TOKEN=previous
