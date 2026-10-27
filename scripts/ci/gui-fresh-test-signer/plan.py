# SPDX-License-Identifier: MIT
"""Exact existing GUI signing bodies and source-only validation; no key access."""
import hashlib,json,os,re,stat
from pathlib import Path
PURPOSE='GUI_FRESH_TEST_SIGNER_NATIVE_V1'
PLAN_PIN=dict(bytes=81278,sha256='f0160e53afea8d7116f0b7552514f753f6fd95ae2d58d1b30d4d3fe6d5b5ceda')
SLICE='scripts/ci/gui-fresh-test-signer'
BASE_PINS={'runner/sign_fixture.py':dict(bytes=35990,sha256='430a52245fb2adb6a6c9fb68ee256570ca1c5468863f5e0f3b04145e0d9dcf85'),'runner/native_arm.py':dict(bytes=28318,sha256='a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898'),'scripts/checks/package_checks.py':dict(bytes=17706,sha256='e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8')}
BASE_PATHS={'runner/sign_fixture.py':'scripts/ci/sign_fixture.py','runner/native_arm.py':'scripts/ci/native_arm.py','scripts/checks/package_checks.py':'scripts/checks/package_checks.py'}
CODE_PATHS=set(BASE_PINS)|{'route/route.py','route/plan.py','route/inside.py','route/environment.py'}
PACKAGE_CHECK=None
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def obj(raw):
 def pairs(rows):
  out={}
  for key,value in rows:need(key not in out,'duplicate JSON key');out[key]=value
  return out
 value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON required'));need(type(value)is dict,'JSON object required');return value
def relative(name):
 need(type(name)is str and name and not name.startswith('/')and '\\'not in name and all(p not in('','.','..')for p in name.split('/'))and all(ord(c)>=32 for c in name),'closed relative path');return name
def ordinary(path):
 p=Path(path);need(p.is_absolute()and p==p.resolve()and not any(x.is_symlink()for x in(p,*p.parents)),'canonical no-alias path');return p
def read(path,cap=16*1024**2):
 p=ordinary(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);key=lambda s:tuple(getattr(s,n)for n in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'));need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded ordinary singlelink body');raw=bytearray()
  while part:=os.read(fd,min(65536,a.st_size+1-len(raw))):raw.extend(part);need(len(raw)<=a.st_size,'body growth refused')
  need(len(raw)==a.st_size and key(a)==key(os.fstat(fd))==key(p.lstat()),'stable whole body FD/path');return bytes(raw)
 finally:os.close(fd)
def rows(root):
 root=ordinary(root);out={};dirs=set()
 for p in sorted(root.rglob('*')):
  need(not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary closed source/body namespace');name=p.relative_to(root).as_posix()
  if p.is_dir():dirs.add(name)
  else:out[name]=pin(read(p));need(len(out)<=1024,'bounded input member count')
 need(dirs=={p.as_posix()for n in out for p in Path(n).parents if p.as_posix()!='.'},'no foreign empty directory');return out
def manifest(raw):
 need(pin(raw)==PLAN_PIN,'exact reviewed GUI body plan');v=obj(raw);need(v['schema_version']==1 and v['purpose']=='GUI607_FRESH_TEST_SIGNING_INPUTS_SOURCE_ONLY'and v['actual']is v['Root_acceptance']is None,'source-only immutable plan');docs=v['documents'];need(type(docs)is list and len(docs)==6 and{r['role']for r in docs}=={'welcome5','dns2','doctor','orphans','native73-index','held77-index'},'exact six reviewed bodies')
 for row in docs:
  need(re.fullmatch('[a-z0-9-]{1,40}',row['role'])and row['carrier']in v['carriers']and row['signature_path']=='signatures/'+row['role']+'.sig','closed unique body/signature roles');relative(row['path']);need(type(row['bytes'])is int and 0<row['bytes']<=8*1024**2 and re.fullmatch('[a-f0-9]{64}',row['sha256']),'typed body pin');need(v['carriers'][row['carrier']]['files'][row['path']]=={k:row[k]for k in('bytes','sha256')},'body joins complete reviewed carrier')
 v['retired_signers']=[v['historical_renewal']['recorded_signer']];return v,docs
def body_path(root,row):return Path(root)/'bodies'/row['role']
def validate_body(path,row):
 raw=read(path,8*1024**2);need(pin(raw)=={k:row[k]for k in('bytes','sha256')},'exact immutable existing body')
 if row['kind']=='metadata-json':obj(raw);need(row['package']is None,'metadata is not package authority');return dict(status='PASS_EXACT_REVIEWED_JSON_BODY',pin=pin(raw))
 need(row['kind']=='package-archive'and callable(PACKAGE_CHECK),'reviewed archive and pinned static checker required');report=PACKAGE_CHECK(path);q=row['package'];need(not report['errors']and report['metadata'].get('.PKGINFO')==q['PKGINFO'],'complete exact package metadata and checker result');need('.INSTALL'not in report['members']and q['INSTALL_absent']is True,'no install script accepted')
 for name,w in q['packaged_metadata'].items():need(report['members'][name]['size']==w['bytes']and report['members'][name]['sha256']==w['sha256'],'exact packaged metadata bytes')
 need({n:dict({'class':64},machine=r.get('machine'))for n,r in report['elf'].items()}==q['expected_elf'],'exact reviewed ELF64-only checker set and architecture');return dict(status='PASS_EXACT_REVIEWED_ARCHIVE_NO_EXECUTION',pin=pin(raw),name=q['name'],version=q['version'],architecture=q['architecture'])
def tool_identity(contract):
 need(type(contract['tools'])is dict and set(contract['tools'])=={'/usr/bin/python3','/usr/bin/gpg','/usr/bin/gpgconf','/usr/bin/gpg-agent','/usr/bin/pacman'},'complete reviewed tool set');result={}
 for name,w in contract['tools'].items():
  p=Path(name).resolve();s=p.stat();need(stat.S_ISREG(s.st_mode)and s.st_uid==s.st_gid==0 and not s.st_mode&0o022,'root-owned immutable tool');need(pin(read(p,128*1024**2))==w,'reviewed tool binary bytes');result[name]=dict(path=str(p),**w)
 return result
def public_names(docs):return {'public-key.asc','catalog.json','catalog.json.sig','result.json'}|{row['signature_path']for row in docs}
def validate(root,contract,extra_public=False):
 root=ordinary(root);need(set(contract)=={'schema_version','purpose','nonce','source_sha','image_id','image_contract_sha256','manifest_pin','files','baseline'}and type(contract['schema_version'])is int and contract['schema_version']==1 and contract['purpose']==PURPOSE,'exact fresh signer contract');need(re.fullmatch('[a-f0-9]{32}',contract['nonce'])and re.fullmatch('[a-f0-9]{40}',contract['source_sha'])and re.fullmatch('sha256:[a-f0-9]{64}',contract['image_id']),'actual nonce/source/image binding')
 raw=read(root/'manifest.json',1024**2);need(pin(raw)==contract['manifest_pin']==PLAN_PIN,'source-owned exact signing plan');v,docs=manifest(raw);need(set(contract['files'])==CODE_PATHS,'complete signer source closure')
 for name,w in contract['files'].items():need(pin(read(root/relative(name)))==w,'whole signer source pin')
 for name,w in BASE_PINS.items():need(contract['files'][name]==w,'unchanged baseline signer machinery')
 b=contract['baseline'];need(b==dict(schema_version=1,purpose='TEST-ONLY-integration-signatures',nonce=contract['nonce'],image_id=contract['image_id'],manifest_sha256=PLAN_PIN['sha256'],entry_sha256=BASE_PINS['runner/sign_fixture.py']['sha256'],helpers_sha256={n:BASE_PINS[n]['sha256']for n in('runner/native_arm.py','scripts/checks/package_checks.py')}),'unchanged full baseline guard contract')
 image_raw=read(root/'image-contract.json',65536);need(pin(image_raw)['sha256']==contract['image_contract_sha256'],'reviewed immutable image contract bytes');image=obj(image_raw);need(image['source_sha']==contract['source_sha']and image['image_id']==contract['image_id']and os.getuid()==image['alarm_uid']and os.getgid()==image['alarm_gid'],'qualified image/source/account join');tool_identity(image)
 need(type(extra_public)is bool,'literal public verification selection');expected=set(CODE_PATHS)|{'manifest.json','contract.json','image-contract.json'}|{'bodies/'+row['role']for row in docs}
 if extra_public:expected|={'public/'+name for name in public_names(docs)}
 need(set(rows(root))==expected,'exact closed read-only input snapshot');need(obj(read(root/'contract.json'))==contract,'same pinned actual contract')
 for row in docs:validate_body(body_path(root,row),row)
 return v,docs
