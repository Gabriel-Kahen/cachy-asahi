"""Finite four-cell native core source and role protocol."""
import hashlib,json,os,re,stat,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
CELLS=('systemd-a','systemd-b','pacman-a','pacman-b')
SCOPE='UNSELECTED_CORE_2X2_NATIVE_BUILDS_NO_OLD261_CREDIT'
BUDGET={'baseline':2300,'candidate':1800,'probes':120,'selection':30,'package':14760,'makepkg':14400,'export':120,'cleanup':540,'owner':19680,'shell':19740,'step_minutes':330,'job_minutes':360,'prefetch':900,'new64':300,'seed':120}
ENC=lambda v:(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def need(ok,why):
 if not ok:raise ValueError(why)
def read(p,cap=256*1024**2):
 p=Path(p);fd=os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size<=cap,'ordinary bounded DATA required')
  blocks=[];size=0
  while size<=cap:
   b=os.read(fd,min(1024**2,cap+1-size))
   if not b:break
   blocks.append(b);size+=len(b)
  raw=b''.join(blocks)
  after=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(len(raw)==before.st_size and key(before)==key(after),'DATA read drift');return raw
 finally:os.close(fd)
def files(root):
 result={}
 for p in sorted(Path(root).rglob('*')):
  relative=p.relative_to(root)
  if relative.parts[0]=='.git':continue
  need(not p.is_symlink(),'symlink source/evidence refused')
  if not p.is_dir():result[str(relative)]=pin(read(p,1024**3))
 return result
def load(p,cap=256*1024**2):return json.loads(read(p,cap))
def save(p,v):
 p=Path(p);tmp=p.with_name('.'+p.name+'.partial')
 with tmp.open('xb')as f:f.write(ENC(v));f.flush();os.fsync(f.fileno())
 tmp.replace(p)
def preflight(root=ROOT):
 root=Path(root);raw=read(root/'source-manifest.json');v=json.loads(raw)
 need(set(v)=={'schema','scope','files','workflow','workflow_alias','workflow_base','core_authority','budget'}and v['schema']==1 and v['scope']==SCOPE and v['budget']==BUDGET,'exact source manifest/profile')
 actual=files(root);expected=dict(v['files']);expected['source-manifest.json']=pin(raw)
 marker='SOURCE_MANIFEST_SHA256='+pin(raw)['sha256'];texts=[]
 for name in(v['workflow'],v['workflow_alias']):
  text=read(root/name).decode();need(text.count(marker)==1,'one source-manifest workflow stamp');base=text.replace(marker,'SOURCE_MANIFEST_SHA256=UNSTAMPED')
  need(pin(base.encode())==v['workflow_base'],'whole workflow inverse differs');expected[name]=pin(text.encode());texts.append(text)
 need(texts[0]==texts[1],'owned standalone workflow alias must byte-equal dedicated workflow')
 need(actual==expected,'whole closed source differs')
 authority=load(root/'authority.json');need(pin(read(root/'authority.json'))==v['core_authority'],'whole original authority differs')
 for rel,want in authority['whole_core'].items():
  if rel in omitted(root):continue
  need(pin(read(root/'core'/rel))==want,'whole original403 core public leaf differs')
 need(pin(read(root/'core/native-source-closure.json'))==authority['frozen_core_manifest'],'whole original403 manifest differs')
 need(len(authority['whole_core'])==403,'whole original403 membership')
 for old,row in authority['baseline_unchanged'].items():need(pin(read(root/row['destination']))==row['pin'],'whole original baseline helper differs')
 return v
def policy(root=ROOT):
 root=Path(root);v=load(root/'lane/root-source-authorization.json')
 authority=load(root/'authority.json');profile=load(root/'core/profile/profile.json')
 expected={'schema':1,'status':'ROOT_SELECTED_UNSELECTED_CORE_NATIVE_BUILDS_ONLY','core_source_manifest':authority['frozen_core_manifest'],'core_profile':pin(read(root/'core/profile/profile.json')),'baseline_inputs':pin(read(root/'baseline/maintained-desktop574-inputs.json')),'matrix':list(CELLS),'versions':{k:r['version']+'-'+r['pkgrel']for k,r in profile['packages'].items()},'source_date_epoch':v.get('source_date_epoch'),'target_selection':False,'hardware_acceptance':False,'old261_credit':False}
 need(v==expected and type(v['source_date_epoch'])is int and 0<=v['source_date_epoch']<2**40,'explicit exact Root source-only selection required')
 return v
def identity(source,run,attempt,cell):
 need(re.fullmatch('[0-9a-f]{40}',source or''),'exact source commit required')
 need(type(run)is int and run>0 and type(attempt)is int and attempt>0 and cell in CELLS,'exact actual identity required')
 return dict(source=source,run=run,attempt=attempt,cell=cell,scope=SCOPE)
def private(p,create=False):
 p=Path(p);need(p.is_absolute()and not any(x.is_symlink()for x in(p,*p.parents)),'ordinary explicit private path')
 if create:p.mkdir(mode=0o700)
 s=p.stat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o700,'owned0700 directory required');return p

def omitted(root=ROOT):
 root=Path(root);lock=load(root/'core/builder-inputs.lock.json');authority=load(root/'authority.json');result={}
 need(len(lock['packages'])==64,'exact signed64 input set')
 for row in lock['packages']:
  for suffix,sz,sha in(('',row['size'],row['sha256']),('.sig',row['signature_size'],row['signature_sha256'])):
   rel='builder-context/deps/'+row['filename']+suffix;want=dict(bytes=sz,sha256=sha)
   need(authority['whole_core'].get(rel)==want,'whole original403 binary omission inverse')
   result[rel]=want
 need(len(result)==128,'only128 public binary leaves omitted');return result

def materialized(root):
 root=Path(root);expected=dict(load(ROOT/'authority.json')['whole_core']);expected['native-source-closure.json']=pin(read(ROOT/'core/native-source-closure.json'))
 need(files(root)==expected,'full original403+manifest private restoration differs');return root
