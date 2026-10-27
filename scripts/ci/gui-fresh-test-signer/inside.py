# SPDX-License-Identifier: MIT
"""Fresh TEST signatures within the unchanged capability-free native guard."""
import hashlib,json,os,re,stat,time
from pathlib import Path

PURPOSE='GUI_FRESH_TEST_SIGNER_NATIVE_V1'
STATUS='PASS_FRESH_TEST_SIGNATURES_ONLY_NO_GUI_OR_BUILD_ACCEPTANCE'
AUTHORITY='FRESH_TEST_SIGNATURES_ONLY_HISTORICAL_NATIVE_CREDIT_NEW_SOURCE_SELECTION_REQUIRED'
INPUT_ROOT,OUTPUT_ROOT=Path('/inputs'),Path('/out')
TOOLS=('/usr/bin/python3','/usr/bin/gpg','/usr/bin/gpgconf','/usr/bin/gpg-agent','/usr/bin/pacman')
ENV_OVERRIDES=('LD_PRELOAD','LD_LIBRARY_PATH','FAKETIME','FAKETIME_TIMESTAMP_FILE','GPG_AGENT_INFO','GNUPGHOME','PYTHONHOME','PYTHONPATH')
BASE_FILES={'runner/sign_fixture.py':{'bytes':35990,'sha256':'430a52245fb2adb6a6c9fb68ee256570ca1c5468863f5e0f3b04145e0d9dcf85'},'runner/native_arm.py':{'bytes':28318,'sha256':'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898'},'scripts/checks/package_checks.py':{'bytes':17706,'sha256':'e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8'}}
SOURCE_FILES=set(BASE_FILES)|{'route/route.py','route/plan.py','route/inside.py','route/environment.py'}
CONTRACT_FIELDS={'schema_version','purpose','nonce','source_sha','image_id','image_contract_sha256','manifest_pin','files','baseline'}
BASELINE_FIELDS={'schema_version','purpose','nonce','image_id','manifest_sha256','entry_sha256','helpers_sha256'}
LIMIT=4*1024**2
SIGN_REPORT_FIELDS={'schema_version','purpose','status','contract','guard','fingerprint','created','expiry','public_certificate_pin','signatures','public_catalog','private_home_retired','production_credentials_used','native_build','GUI','hardware','Root_acceptance'}

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def identity(info):return tuple(getattr(info,key)for key in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
def relative(value):
 need(type(value)is str and 0<len(value)<=512 and not value.startswith('/')and '\\'not in value and all(32<=ord(c)<127 for c in value)and all(p not in('','.','..')for p in value.split('/')),'ordinary relative signer path');return value
def expected_pin(value,cap):
 need(type(value)is dict and set(value)=={'bytes','sha256'}and type(value['bytes'])is int and 0<value['bytes']<=cap and type(value['sha256'])is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),'bounded exact public input pin');return value
def read(path,cap):
 path=Path(path);need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'canonical ordinary signer input');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  info=os.fstat(fd);need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and 0<=info.st_size<=cap,'bounded single-link signer input');raw=bytearray()
  while part:=os.read(fd,min(65536,info.st_size+1-len(raw))):raw.extend(part);need(len(raw)<=info.st_size,'signer input growth')
  need(len(raw)==info.st_size and identity(info)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable signer input FD/path');return bytes(raw),identity(info)
 finally:os.close(fd)
def decode(raw):
 def unique(items):
  value={}
  for key,item in items:need(key not in value,'duplicate signer JSON field');value[key]=item
  return value
 return json.loads(raw,object_pairs_hook=unique,parse_constant=lambda _:need(False,'finite signer JSON'))

def source_state(root,contract,core,plan):
 need(type(contract)is dict and set(contract)==CONTRACT_FIELDS and type(contract['schema_version'])is int and contract['schema_version']==1 and contract['purpose']==PURPOSE,'exact GUI TEST signer contract')
 for key,pattern in(('nonce','[0-9a-f]{32}'),('source_sha','[0-9a-f]{40}'),('image_id','sha256:[0-9a-f]{64}'),('image_contract_sha256','[0-9a-f]{64}')):need(type(contract[key])is str and re.fullmatch(pattern,contract[key]),'resolved signer contract identity')
 baseline=contract['baseline'];need(type(baseline)is dict and set(baseline)==BASELINE_FIELDS and baseline['purpose']==core.PURPOSE and baseline['nonce']==contract['nonce']and baseline['image_id']==contract['image_id']and baseline['manifest_sha256']==expected_pin(contract['manifest_pin'],LIMIT)['sha256'],'unchanged baseline contract joins outer GUI scope')
 files=contract['files'];need(type(files)is dict and set(files)==SOURCE_FILES and all(files[n]==w for n,w in BASE_FILES.items()),'exact seven source pins and original baseline/helper bytes');state={}
 for name,wanted in files.items():
  raw,file_id=read(root/relative(name),16*1024**2);need(pin(raw)==expected_pin(wanted,16*1024**2),'signer source pin differs');state[name]=(pin(raw),file_id)
 for actual,name in((__file__,'route/inside.py'),(plan.__file__,'route/plan.py'),(core.__file__,'runner/sign_fixture.py'),(core.native.__file__,'runner/native_arm.py')):need(Path(actual)==root/name and Path(actual)==Path(actual).resolve(),'actual loaded inside/plan/baseline/native source belongs to exact input closure')
 need(baseline['entry_sha256']==BASE_FILES['runner/sign_fixture.py']['sha256']and baseline['helpers_sha256']=={n:BASE_FILES[n]['sha256']for n in('runner/native_arm.py','scripts/checks/package_checks.py')},'unchanged baseline entry and helper pins')
 for name in('manifest.json','contract.json'):
  raw,file_id=read(root/name,LIMIT)
  if name=='manifest.json':need(pin(raw)==contract['manifest_pin'],'outer manifest bytes')
  else:need(decode(raw)==contract,'outer contract file equals actual argument')
  state['@'+name]=(pin(raw),file_id)
 need(len(encoded(contract))<=LIMIT and b'PRIVATE KEY'not in encoded(contract),'bounded public contract');return state

def image_state(root,contract,core):
 need(not any(os.environ.get(name)for name in ENV_OVERRIDES),'clock, key-home and loader environment overrides refused')
 raw,image_file_id=read(root/'image-contract.json',65536);need(pin(raw)['sha256']==contract['image_contract_sha256'],'exact reviewed image contract bytes');image=decode(raw)
 need(type(image)is dict and set(image)=={'schema_version','purpose','source_sha','oci_ref','image_id','alarm_uid','alarm_gid','packages_sha256','tools'}and type(image['schema_version'])is int and image['schema_version']==1 and image['purpose']=='GUI-FRESH-TEST-SIGNER-IMAGE'and image['source_sha']==contract['source_sha']and image['image_id']==contract['image_id']and(image['alarm_uid'],image['alarm_gid'])==(os.geteuid(),os.getegid()),'reviewed image/source and actual alarm mapping')
 need(type(image['tools'])is dict and set(image['tools'])==set(TOOLS),'complete pinned image executable set');tools={}
 for name,wanted in image['tools'].items():
  path=Path(name);target=path.resolve(strict=True);info=target.stat();need(target.is_relative_to('/usr')and info.st_uid==info.st_gid==0 and stat.S_ISREG(info.st_mode)and os.access(target,os.X_OK),'ordinary root-owned image executable');body,file_id=read(target,128*1024**2);need(pin(body)==expected_pin(wanted,128*1024**2)and path.resolve(strict=True)==target,'exact image executable bytes');tools[name]=(str(target),identity(path.lstat()),pin(body),file_id)
 text=core.checked(['/usr/bin/pacman','-Q'],'unchanged image package inventory',30);lines=text.splitlines();need(0<len(lines)<=4096 and len({line.split(' ')[0]for line in lines})==len(lines)and all(re.fullmatch(r'[a-z0-9@_+.-]+ [A-Za-z0-9._+:~@-]+',line)for line in lines),'canonical complete image package inventory');packages=('\n'.join(sorted(lines))+'\n').encode();need(pin(packages)['sha256']==image['packages_sha256'],'complete unchanged image package lock');return(pin(raw),image_file_id,tools,pin(packages))

def body_state(root,docs,plan):
 need(type(docs)is list and len(docs)==6,'fixed four archives and two index bodies');state={};roles=set()
 for row in docs:
  extras={'package-archive':{'legacy_role_alias','native_evidence'},'metadata-json':{'body_policy'}};need(type(row)is dict and row.get('kind')in extras and set(row)=={'role','carrier','path','bytes','sha256','kind','package','signature_path'}|extras[row['kind']],'complete exact GUI signing document by kind');role=row['role'];need(type(role)is str and re.fullmatch('[a-z][a-z0-9-]{0,63}',role)and role not in roles and row['signature_path']=='signatures/'+role+'.sig','unique closed role signature path');roles.add(role);path=plan.body_path(root,row);need(path==root/'bodies'/role,'exact source-selected body path');raw,file_id=read(path,32*1024**2);need(pin(raw)==expected_pin({key:row[key]for key in('bytes','sha256')},32*1024**2),'whole document body pin before signing');plan.validate_body(path,row);need(read(path,32*1024**2)==(raw,file_id),'body metadata inspection retains exact input identity');state[role]=(pin(raw),file_id)
 return state

def fresh_key(core,home,gpg,nonce,started,ended,retired):
 fp,expiry=core.fingerprint(home);text=core.checked(gpg+['--with-colons','--list-keys'],'fresh TEST primary creation inspection');rows=[line.split(':')for line in text.splitlines()];pubs=[row for row in rows if row[0]=='pub'];uids=[row for row in rows if row[0]=='uid'];need(len(pubs)==len(uids)==1 and len(pubs[0])>=10 and len(uids[0])>=10,'one fresh TEST primary and identity');primary=pubs[0];need(primary[1]not in('r','e')and primary[2:4]==['2048','1']and re.fullmatch('[0-9]{1,20}',primary[5])and re.fullmatch('[0-9]{1,20}',primary[6]),'fresh RSA2048 primary timestamps');created=int(primary[5]);need(ended>=started and int(started)-1<=created<=int(ended)+1 and expiry==int(primary[6])and expiry-created==86400,'actual new primary creation and one-day expiry at the real clock');need(uids[0][9]=='CACHY-ASAHI TEST ONLY '+nonce+' <test-only@invalid.example>','exact fresh TEST nonce identity');need(type(retired)is list and len(retired)<=128 and len(set(retired))==len(retired)and all(type(item)is str and re.fullmatch('[0-9A-F]{40}',item)for item in retired)and fp not in retired,'fresh primary cannot reuse any retired signer');return fp,created,expiry

def write(path,raw):
 need(len(raw)<=LIMIT and not os.path.lexists(path),'fresh bounded public output');fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
 try:
  os.fchmod(fd,0o644)
  with os.fdopen(os.dup(fd),'wb')as stream:need(stream.write(raw)==len(raw),'whole public output write');stream.flush();os.fsync(stream.fileno())
 finally:os.close(fd)

def sign(core,gpg,fp,source,signature):
 need(not os.path.lexists(signature),'fresh detached signature output');core.checked(gpg+['--local-user',fp,'--digest-algo','SHA256','--output',str(signature),'--detach-sign',str(source)],'fresh TEST detached signature');raw,unused=read(signature,8192);need(raw,'nonempty detached signature');signature.chmod(0o644);status=core.checked(gpg+['--status-fd','1','--verify',str(signature),str(source)],'fresh TEST detached signature verification');core.native.valid_signature(status,fp);need(not any('[GNUPG:] '+marker in status for marker in('KEYEXPIRED','KEYREVOKED','SIGEXPIRED','FAILURE','ERROR','NODATA','BADARMOR')),'current complete signature status');need(read(signature,8192)[0]==raw,'exact detached signature bytes after verification');return dict(signature_pin=pin(raw),status=status,gpg_exit=0)

def public_namespace(output,roles,result=False):
 expected={'public-key.asc','catalog.json','catalog.json.sig'}|{'signatures/'+role+'.sig'for role in roles}
 if result:expected.add('result.json')
 found=set()
 for path in output.rglob('*'):
  need(not path.is_symlink(),'ordinary public output namespace');name=path.relative_to(output).as_posix()
  if path.is_dir():need(name=='signatures','no private or foreign output directory')
  else:need(path.is_file()and path.stat().st_nlink==1 and stat.S_IMODE(path.stat().st_mode)==0o644,'ordinary mode0644 public output');found.add(name)
 need(found==expected,'complete exact public signer outputs')

def run(root,output,contract,core,plan):
 """Return 0/1 and emit only public evidence; no generic eight-archive gate."""
 root,output=Path(root),Path(output);output_ready=False;report=dict(schema_version=1,purpose=PURPOSE,status='FAIL',contract=contract,guard=None,fingerprint=None,created=None,expiry=None,public_certificate_pin=None,signatures={},public_catalog=None,private_home_retired=False,production_credentials_used=False,native_build='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',Root_acceptance=None)
 try:
  need(root==INPUT_ROOT and output==OUTPUT_ROOT and root==root.resolve()and output==output.resolve()and not any(p.is_symlink()for p in(root,output,*root.parents,*output.parents))and root.is_dir()and output.is_dir()and not any(output.iterdir()),'fixed ordinary /inputs and fresh empty /out');output_ready=True;original_contract=encoded(contract);sources=source_state(root,contract,core,plan);observed=core.environment();report['guard']=observed;core.signer_guard(observed,contract['baseline']);image=image_state(root,contract,core);manifest,docs=plan.validate(root,contract);bodies=body_state(root,docs,plan);need(encoded(contract)==original_contract,'plan retains exact outer contract');(output/'signatures').mkdir(mode=0o755);inner_error=None
  with core.gpg_home('cachy-asahi-gui-fresh-test-','/tmp')as home:
   try:
    gpg=['gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve'];uid='CACHY-ASAHI TEST ONLY '+contract['nonce']+' <test-only@invalid.example>';started=time.time();core.checked(gpg+['--pinentry-mode','loopback','--passphrase','','--quick-generate-key',uid,'rsa2048','sign','1d'],'fresh ephemeral TEST key generation',120);ended=time.time();fp,created,expiry=fresh_key(core,home,gpg,contract['nonce'],started,ended,manifest['retired_signers']);report.update(fingerprint=fp,created=created,expiry=expiry);text=core.checked(gpg+['--armor','--export',fp],'fresh public TEST certificate export');raw=text.encode('ascii');core.public_certificate(raw);need(len(raw)<=65536 and b'PRIVATE KEY'not in raw,'bounded public-only TEST certificate');write(output/'public-key.asc',raw);report['public_certificate_pin']=pin(raw)
    for row in docs:
     signed=sign(core,gpg,fp,plan.body_path(root,row),output/row['signature_path']);report['signatures'][row['role']]=dict(signed,input_pin={key:row[key]for key in('bytes','sha256')});need(body_state(root,docs,plan)==bodies,'all document bytes/metadata remain exact after signing')
    catalog=dict(schema_version=1,purpose='NEW_GUI_TEST_SIGNATURE_CATALOG',source_sha=contract['source_sha'],nonce=contract['nonce'],signer=fp,created=created,expires=expiry,inputs={row['role']:dict(carrier=row['carrier'],path=row['path'],pin={key:row[key]for key in('bytes','sha256')})for row in docs},signatures={role:row['signature_pin']for role,row in report['signatures'].items()},authority_scope=AUTHORITY,native_build='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',Root_acceptance=None);raw=encoded(catalog);need(len(raw)<=65536,'bounded fresh signature catalog');write(output/'catalog.json',raw);signed=sign(core,gpg,fp,output/'catalog.json',output/'catalog.json.sig');report['public_catalog']=dict(signed,body_pin=pin(raw));need(read(output/'catalog.json',65536)[0]==raw,'exact signed new catalog body')
   except BaseException as error:inner_error=error
  report['private_home_retired']=True
  if inner_error is not None:raise inner_error
  need(source_state(root,contract,core,plan)==sources and image_state(root,contract,core)==image,'late complete source/tool/image identity join');after_manifest,after_docs=plan.validate(root,contract);need(after_manifest==manifest and after_docs==docs and body_state(root,docs,plan)==bodies and encoded(contract)==original_contract,'late independent manifest/body/metadata join');public_namespace(output,report['signatures']);report['status']=STATUS
 except BaseException as error:report['error_type']=type(error).__name__[:64]
 if not output_ready:return 1
 raw=encoded(report);need(len(raw)<=LIMIT and b'PRIVATE KEY'not in raw,'bounded public signer receipt');write(output/'result.json',raw)
 if report['status']==STATUS:public_namespace(output,report['signatures'],result=True);return 0
 return 1

def verified(core,gpg,fp,source,signature,saved,input_pin=None):
 fields={'body_pin','signature_pin','status','gpg_exit'}if input_pin is None else{'input_pin','signature_pin','status','gpg_exit'}
 need(type(saved)is dict and set(saved)==fields and type(saved['gpg_exit'])is int and saved['gpg_exit']==0 and type(saved['status'])is str and len(saved['status'].encode())<=LIMIT,'exact original public signature receipt')
 if input_pin is not None:need(saved['input_pin']==input_pin,'original detached signature input binding')
 raw,file_id=read(signature,8192);need(pin(raw)==expected_pin(saved['signature_pin'],8192),'original public detached signature bytes');core.native.valid_signature(saved['status'],fp);need(not any('[GNUPG:] '+marker in saved['status']for marker in('KEYEXPIRED','KEYREVOKED','SIGEXPIRED','FAILURE','ERROR','NODATA','BADARMOR')),'original current signature status');status=core.checked(gpg+['--status-fd','1','--verify',str(signature),str(source)],'independent public-only TEST signature verification');core.native.valid_signature(status,fp);need(not any('[GNUPG:] '+marker in status for marker in('KEYEXPIRED','KEYREVOKED','SIGEXPIRED','FAILURE','ERROR','NODATA','BADARMOR')),'independent current signature status');need(read(signature,8192)==(raw,file_id),'unchanged exact public signature observation');return dict(signature_pin=pin(raw),status=status,gpg_exit=0)

def public_state(public,roles):
 public_namespace(public,roles,result=True);return{p.relative_to(public).as_posix():(pin(raw),file_id)for p in sorted(public.rglob('*'))if p.is_file()for raw,file_id in[read(p,LIMIT)]}

def verify(root,output,contract,core,plan):
 """Verify public copies in a second fresh container and tmpfs-only home."""
 root,output=Path(root),Path(output);output_ready=False;report=dict(schema_version=1,status='FAIL',contract=contract,fingerprint=None,expiry=None,guard=None,signatures={},public_catalog=None,public_only_home_retired=False,Root_acceptance=None)
 try:
  need(root==INPUT_ROOT and output==OUTPUT_ROOT and root==root.resolve()and output==output.resolve()and not any(p.is_symlink()for p in(root,output,*root.parents,*output.parents))and root.is_dir()and output.is_dir()and not any(output.iterdir()),'fixed ordinary public verifier inputs and fresh empty output')
  output_ready=True;original_contract=encoded(contract);sources=source_state(root,contract,core,plan);observed=core.environment();report['guard']=observed;core.signer_guard(observed,contract['baseline']);image=image_state(root,contract,core);manifest,docs=plan.validate(root,contract,extra_public=True);bodies=body_state(root,docs,plan);roles={row['role']for row in docs};public=root/'public';public_before=public_state(public,roles);raw,unused=read(public/'result.json',LIMIT);saved=decode(raw)
  need(type(saved)is dict and set(saved)==SIGN_REPORT_FIELDS and type(saved['schema_version'])is int and saved['schema_version']==1 and saved['purpose']==PURPOSE and saved['status']==STATUS and saved['contract']==contract and saved['private_home_retired']is True and saved['production_credentials_used']is False and all(saved[n]=='NOT_RUN'for n in('native_build','GUI','hardware'))and saved['Root_acceptance']is None,'exact successful TEST-only signer receipt with retired private home')
  core.signer_guard(saved['guard'],contract['baseline']);need(type(saved['signatures'])is dict and set(saved['signatures'])==roles and type(saved['created'])is int and type(saved['expiry'])is int,'complete original public signature set and timestamps');raw,unused=read(public/'public-key.asc',65536);need(pin(raw)==expected_pin(saved['public_certificate_pin'],65536)and b'PRIVATE KEY'not in raw,'exact original public certificate');core.public_certificate(raw);inner_error=None
  with core.gpg_home('cachy-asahi-gui-public-only-','/tmp')as home:
   try:
    gpg=['gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve'];certificate=public/'public-key.asc';fp,expiry=core.fingerprint(home,certificate);need(fp==saved['fingerprint']and expiry==saved['expiry']and fp not in manifest['retired_signers'],'independent public certificate identity and expiry');core.checked(gpg+['--import',str(certificate)],'fresh public-only TEST certificate import');fp2,created,expiry2=fresh_key(core,home,gpg,contract['nonce'],saved['created'],saved['created'],manifest['retired_signers']);need((fp2,created,expiry2)==(fp,saved['created'],expiry),'public certificate actual creation and exact nonce identity');report.update(fingerprint=fp,expiry=expiry)
    for row in docs:
     input_pin={key:row[key]for key in('bytes','sha256')};signed=verified(core,gpg,fp,plan.body_path(root,row),public/row['signature_path'],saved['signatures'][row['role']],input_pin);report['signatures'][row['role']]=dict(signed,input_pin=input_pin)
    expected_catalog=dict(schema_version=1,purpose='NEW_GUI_TEST_SIGNATURE_CATALOG',source_sha=contract['source_sha'],nonce=contract['nonce'],signer=fp,created=created,expires=expiry,inputs={row['role']:dict(carrier=row['carrier'],path=row['path'],pin={key:row[key]for key in('bytes','sha256')})for row in docs},signatures={role:row['signature_pin']for role,row in report['signatures'].items()},authority_scope=AUTHORITY,native_build='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',Root_acceptance=None)
    raw,unused=read(public/'catalog.json',65536);need(type(saved['public_catalog'])is dict and decode(raw)==expected_catalog and pin(raw)==expected_pin(saved['public_catalog']['body_pin'],65536),'exact new TEST-only catalog body and original receipt');signed=verified(core,gpg,fp,public/'catalog.json',public/'catalog.json.sig',saved['public_catalog']);report['public_catalog']=dict(signed,body_pin=pin(raw))
   except BaseException as error:inner_error=error
  report['public_only_home_retired']=True
  if inner_error is not None:raise inner_error
  need(source_state(root,contract,core,plan)==sources and image_state(root,contract,core)==image,'late complete public verifier source/tool/image identity join');after_manifest,after_docs=plan.validate(root,contract,extra_public=True)
  need(after_manifest==manifest and after_docs==docs and body_state(root,docs,plan)==bodies and public_state(public,roles)==public_before and encoded(contract)==original_contract,'late complete original bodies/public exports/metadata identity join');report['status']='PASS_INDEPENDENT_PUBLIC_ONLY_TEST_SIGNATURE_VERIFICATION'
 except BaseException as error:report['error_type']=type(error).__name__[:64]
 if not output_ready:return 1
 raw=encoded(report);need(len(raw)<=LIMIT and b'PRIVATE KEY'not in raw,'bounded public-only verification receipt');write(output/'verify-result.json',raw);need({p.name for p in output.iterdir()}=={'verify-result.json'},'only public-only verification receipt exported');return 0 if report['status']=='PASS_INDEPENDENT_PUBLIC_ONLY_TEST_SIGNATURE_VERIFICATION'else 1
