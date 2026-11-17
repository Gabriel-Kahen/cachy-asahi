# SPDX-License-Identifier: MIT
"""Closed signed ALARM additions; no import-time role or authority issuance."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile

MIB=1024**2
MAX_PACKAGES=8;INPUT_CAP=32*MIB;EXPANDED_CAP=128*MIB
POLICY_PIN=None # HOLD until the complete signed compatible closure is pinned.
PARENT350=dict(bytes=6845,sha256='60554bd6189cf253a90c8a58271f74a3c8434d4c23c8e65380ef77d552608061')
KEYRING=dict(bytes=3098,sha256='6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f')
SIGNER='68B3537F39A313B3E574D06777193F152BDBE6A6'
ACTUAL=dict.fromkeys(('source','ref','run','job','image','Root_acceptance','native_acceptance'))


def need(v,s):
 if not v:raise ValueError(s)
def encode(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(v):return dict(bytes=len(v),sha256=hashlib.sha256(v).hexdigest())
def sha(v):return type(v)is str and re.fullmatch('[0-9a-f]{64}',v)is not None
def literal(v):return type(v)is str and re.fullmatch('[A-Za-z0-9@._+:<>=~-]{1,255}',v)is not None

def decode(raw):
 need(type(raw)is bytes and len(raw)<=MIB,'bounded dependency JSON')
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate dependency JSON key');out[k]=v
  return out
 def invalid(_):raise ValueError('noninteger/nonfinite dependency JSON')
 value=json.loads(raw,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)
 need(type(value)is dict,'dependency JSON object');return value

def relative(name):
 need(type(name)is str and 0<len(name)<=255 and '\\'not in name and '\x00'not in name,'bounded dependency member')
 p=PurePosixPath(name);need(not p.is_absolute()and name==p.as_posix()and all(x not in ('','.','..')for x in name.split('/')),'ordinary dependency member');return p

def read(path,cap=INPUT_CAP,tick=lambda:None):
 path=Path(path);need(path.is_absolute()and '..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute dependency file')
 with path.open('rb')as stream:
  before=os.fstat(stream.fileno());need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded single-link dependency file')
  data=bytearray()
  while block:=stream.read(min(MIB,cap+1-len(data))):tick();data.extend(block);need(len(data)<=cap,'dependency byte cap')
  key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(key(before)==key(os.fstat(stream.fileno()))==key(path.lstat())and len(data)==before.st_size,'dependency file changed')
 return bytes(data)

def descriptor(row,cap=INPUT_CAP):
 need(type(row)is dict and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<row['bytes']<=cap and sha(row['sha256']),'exact positive dependency descriptor')

def policy(root):
 need(POLICY_PIN is not None,'complete pinned signed dependency closure required; HOLD on unavailable inputs')
 raw=read(Path(root)/'hosted/build-dependencies.json',MIB)
 descriptor(POLICY_PIN,MIB);need(pin(raw)==POLICY_PIN,'whole pinned signed dependency policy bytes')
 return validate_policy(decode(raw))

def validate_policy(p):
 need(set(p)=={'schema','status','parent350','keyring','signer','packages','actual'}and type(p['schema'])is int and p['schema']==18 and p['status']=='PINNED_SIGNED_ALARM_BUILD_DEPENDENCIES_DATA_ONLY'and p['parent350']==PARENT350 and p['keyring']==KEYRING and p['signer']==SIGNER and p['actual']==ACTUAL,'closed unissued signed dependency policy; existing trust only')
 packages=p['packages'];need(type(packages)is list and 1<=len(packages)<=MAX_PACKAGES,'finite complete dependency closure');names=set();files=set();providers=set();total=0
 for row in packages:
  need(type(row)is dict and set(row)=={'name','version','filename','archive','signature','metadata','providers','license_provenance','url'}and literal(row['name'])and literal(row['version'])and row['name']not in names,'unique exact signed addition');names.add(row['name'])
  filename=row['filename'];need(type(filename)is str and re.fullmatch(r'[A-Za-z0-9._+-]+-aarch64\.pkg\.tar\.xz',filename)and filename not in files,'only exact original aarch64 XZ package');files.add(filename)
  need(type(row['url'])is str and 0<len(row['url'])<=2048 and row['url'].startswith('https://'),'pinned original signed archive HTTPS provenance')
  for k,cap in(('archive',INPUT_CAP),('signature',65536)):descriptor(row[k],cap);total+=row[k]['bytes']
  m=row['metadata'];need(type(m)is dict and set(m)=={'pkgname','pkgver','arch','license','depend','provides','conflict','replaces'}and m['pkgname']==[row['name']]and m['pkgver']==[row['version']]and m['arch']==['aarch64'],'exact package metadata identity')
  need(all(type(m[k])is list and len(m[k])<=64 and all(type(v)is str and 0<len(v)<=255 and '\n'not in v and '\x00'not in v and(k=='license'or literal(v))for v in m[k])and len(set(m[k]))==len(m[k])for k in m),'finite literal signed metadata')
  need(m['license']and not m['conflict']and not m['replaces'],'license required; no conflict/replacement or baseline migration')
  provenance=row['license_provenance'];prefix='dependency-provenance/'+row['name']+'/'
  need(type(provenance)is dict and set(provenance)=={'url','revision','licenses','pkgbuild','buildinfo','license_files'}and type(provenance['revision'])is str and re.fullmatch('[0-9a-f]{40}',provenance['revision'])and type(provenance['url'])is str and len(provenance['url'])<=2048 and provenance['url'].startswith('https://')and provenance['revision']in provenance['url']and provenance['licenses']==m['license'],'immutable exact official recipe/license provenance')
  descriptor(provenance['buildinfo'],MIB)
  need(type(provenance['pkgbuild'])is dict and set(provenance['pkgbuild'])=={'path','bytes','sha256'}and provenance['pkgbuild']['path']==prefix+'PKGBUILD','retained exact package recipe path')
  descriptor({k:provenance['pkgbuild'][k]for k in('bytes','sha256')},MIB)
  need(type(provenance['license_files'])is dict and 1<=len(provenance['license_files'])<=16,'retained finite source license evidence')
  for name,item in provenance['license_files'].items():
   relative(name);need(name.startswith(prefix+'licenses/'),'package-scoped source license evidence');descriptor(item,MIB)
  need(type(row['providers'])is dict and 1<=len(row['providers'])<=32,'finite exact installed library providers')
  for path,item in row['providers'].items():
   relative(path);need(path.startswith('usr/lib/')and '.so'in PurePosixPath(path).name and path not in providers,'only unique public library providers');providers.add(path)
   need(type(item)is dict and item.get('kind')in('file','symlink')and type(item.get('mode'))is int and 0<=item['mode']<=0o777,'ordinary provider type/mode')
   if item['kind']=='file':need(set(item)=={'kind','mode','bytes','sha256'}and type(item['bytes'])is int and 0<item['bytes']<=16*MIB and sha(item['sha256']),'complete bounded regular provider pin')
   else:need(set(item)=={'kind','mode','target'}and item['mode']==0o777 and type(item['target'])is str and '/'not in item['target']and literal(item['target']),'exact internal library alias')
 need('libgit2'in names and total<=INPUT_CAP,'complete missing libgit2 closure within existing Source/data bounds');return p

def provenance_inputs(row):
 p=row['license_provenance'];return {p['pkgbuild']['path']:{k:p['pkgbuild'][k]for k in('bytes','sha256')},**p['license_files']}

def audit_provenance(source_root,row,tick=lambda:None):
 # Retain bytes, never import or execute the official recipe or source licenses.
 result={}
 for name,wanted in provenance_inputs(row).items():
  relative(name);body=read(Path(source_root)/name,MIB,tick);need(pin(body)==wanted,'whole retained exact recipe/source license bytes');result[name]=wanted
 return result

def inventory(raw):
 need(type(raw)is bytes and len(raw)<=MIB,'finite complete inventory');rows={}
 for line in raw.decode().splitlines():
  fields=line.split(' ');need(len(fields)==2 and all(literal(v)for v in fields)and fields[0]not in rows,'unique literal inventory');rows[fields[0]]=fields[1]
 need(raw==''.join(k+' '+v+'\n'for k,v in sorted(rows.items())).encode(),'canonical complete inventory');return rows

def expected_inventory(root,p):
 base=inventory(read(Path(root)/'expected349.lock',MIB));need(len(base)==349,'unchanged original349 baseline')
 base['cachy-asahi-llvm23-source-reference']='23.1.1-1';parent=''.join(k+' '+v+'\n'for k,v in sorted(base.items())).encode();need(pin(parent)==PARENT350,'same exact actual350 parent before additions')
 for row in p['packages']:need(row['name']not in base,'addition may never upgrade or replace baseline');base[row['name']]=row['version']
 return ''.join(k+' '+v+'\n'for k,v in sorted(base.items())).encode()

def pkginfo(raw):
 result={}
 for line in raw.decode().splitlines():
  if line and not line.startswith('#'):
   need(' = 'in line,'literal package metadata line');key,value=line.split(' = ',1);result.setdefault(key,[]).append(value)
 return result

def audit_archive(path,row,tick=lambda:None):
 need(pin(read(path,INPUT_CAP,tick))==row['archive'],'whole original signed package pin');seen=set();expanded=0;found=None;buildinfo=None;observed={};headers=0
 with tarfile.open(path,'r|xz')as archive:
  for member in archive:
   tick();headers+=1;need(headers<=8192,'package header cap');name=member.name.removeprefix('./');relative(name);need(name not in seen,'unique dependency package member');seen.add(name)
   need(not member.sparse and not any(k.startswith('GNU.sparse')for k in member.pax_headers)and(member.isdir()or member.isfile()or member.issym()),'no sparse, hardlink or special package nodes')
   expanded+=member.size;need(0<=member.size<=32*MIB and expanded<=EXPANDED_CAP,'finite package expanded bytes')
   need(name!='.INSTALL'and not name.startswith(('usr/share/libalpm/hooks/','etc/pacman.d/hooks/')),'no dependency scripts or new hooks')
   if name=='.PKGINFO':need(member.isfile()and member.size<=MIB,'bounded regular package metadata');found=pkginfo(archive.extractfile(member).read())
   if name=='.BUILDINFO':
    need(member.isfile()and member.size<=MIB,'bounded regular signed BUILDINFO');body=archive.extractfile(member).read();need(pin(body)==row['license_provenance']['buildinfo'],'whole original signed BUILDINFO pin');buildinfo=pkginfo(body)
   if name in row['providers']:
    if member.isfile():
     body=archive.extractfile(member).read();need(len(body)>=64 and body[:6]==b'\x7fELF\x02\x01'and body[18:20]==b'\xb7\x00','selected shared provider is ELF64 little-endian AArch64 DATA');observed[name]=dict(kind='file',mode=member.mode,**pin(body))
    elif member.issym():observed[name]=dict(kind='symlink',mode=member.mode,target=member.linkname)
    else:raise ValueError('provider must be file or alias')
   archive.members.clear()
 need(found is not None and {k:found.get(k,[])for k in row['metadata']}==row['metadata']and observed==row['providers'],'exact signed metadata and provider bytes/aliases')
 need(buildinfo is not None and buildinfo.get('format')==['2']and buildinfo.get('pkgname')==[row['name']]and buildinfo.get('pkgver')==[row['version']]and buildinfo.get('pkgarch')==['aarch64']and buildinfo.get('pkgbuild_sha256sum')==[row['license_provenance']['pkgbuild']['sha256']],'signed BUILDINFO exact package/architecture/recipe hash correspondence')
 return dict(metadata=row['metadata'],providers=observed,buildinfo=row['license_provenance']['buildinfo'],pkgbuild=row['license_provenance']['pkgbuild'],expanded_bytes=expanded,headers=headers)

def signature_status(raw):
 need(type(raw)is bytes and len(raw)<=65536,'bounded ALARM signature status')
 rows=[line.split()for line in raw.decode().splitlines()if line.startswith('[GNUPG:] VALIDSIG ')]
 need(len(rows)==1 and len(rows[0])==12 and rows[0][2]==rows[0][-1]==SIGNER and not any(x in raw.decode()for x in('BADSIG','ERRSIG','NO_PUBKEY','EXPSIG','EXPKEYSIG','REVKEYSIG')),'existing exact ALARM signer; invalid/expired/revoked/refused trust')

def fields(raw):
 rows={}
 for chunk in raw.decode().split('\n\n'):
  parts=chunk.strip().splitlines()
  if parts:need(parts[0]not in rows,'unique ALPM metadata section');rows[parts[0]]=parts[1:]
 return rows

def observe(image_root,source_root,p,tick=lambda:None,native=False):
 image_root=Path(image_root);expected=expected_inventory(source_root,p);records={};actual={}
 db=image_root/'var/lib/pacman/local';need(db.is_dir()and not any(x.is_symlink()for x in(db,*db.parents)),'ordinary installed ALPM database')
 for path in sorted(db.glob('*/desc')):
  tick();need(len(records)<600,'unchanged600 ALPM inventory bound');row=fields(read(path,MIB,tick));name,version=row.get('%NAME%'),row.get('%VERSION%')
  need(type(name)is list and len(name)==1 and type(version)is list and len(version)==1 and literal(name[0])and literal(version[0])and name[0]not in records,'exact installed ALPM identity');records[name[0]]=(path.parent,row);actual[name[0]]=version[0]
 raw=''.join(k+' '+v+'\n'for k,v in sorted(actual.items())).encode();need(raw==expected,'actual complete dependency inventory without baseline drift or extras');providers={}
 mapping={'pkgname':'%NAME%','pkgver':'%VERSION%','arch':'%ARCH%','license':'%LICENSE%','depend':'%DEPENDS%','provides':'%PROVIDES%','conflict':'%CONFLICTS%','replaces':'%REPLACES%'}
 for package in p['packages']:
  folder,desc=records[package['name']];need(all(sorted(desc.get(mapping[k],[]))==sorted(v)for k,v in package['metadata'].items()),'actual installed signed package metadata')
  owned=fields(read(folder/'files',MIB,tick)).get('%FILES%',[])
  for name,wanted in package['providers'].items():
   tick();need(name in owned,'actual ALPM provider ownership');path=image_root/name;need(not any(x.is_symlink()for x in path.parents),'provider parent cannot alias');info=path.lstat()
   if native:need(info.st_uid==info.st_gid==0,'actual root-owned image provider')
   if wanted['kind']=='file':need(stat.S_ISREG(info.st_mode),'regular image provider');item=dict(kind='file',mode=stat.S_IMODE(info.st_mode),**pin(read(path,16*MIB,tick)))
   else:need(stat.S_ISLNK(info.st_mode),'actual image alias');item=dict(kind='symlink',mode=stat.S_IMODE(info.st_mode),target=os.readlink(path))
   need(item==wanted,'actual provider bytes/mode/alias');providers[name]=dict(owner=package['name'],**item)
 loads=None
 if native:
  need(image_root==Path('/'),'native library loading only inside qualified image root')
  loads=load_runtime(p,tick)
 return dict(schema=18,status='OBSERVED_EXACT_SIGNED_BUILD_DEPENDENCIES_DATA_ONLY',policy=POLICY_PIN,inventory=pin(raw),providers=providers,native_uid_gid_checked=native,runtime_loads=loads,native_acceptance=False,Root_acceptance=None)

def load_runtime(p,tick=lambda:None):
 import ctypes
 handles=[]
 for path in expected_loads(p):tick();handles.append(ctypes.CDLL('/'+path,mode=os.RTLD_NOW|os.RTLD_LOCAL))
 return expected_loads(p)

def expected_loads(p):return {name:'LOADED_RTLD_NOW_RTLD_LOCAL'for row in p['packages']for name,item in sorted(row['providers'].items())if item['kind']=='file'}

def validate_observation(value,source_root,p,expected=None,native=True):
 need(type(value)is dict and set(value)=={'schema','status','policy','inventory','providers','native_uid_gid_checked','runtime_loads','native_acceptance','Root_acceptance'}and type(value['schema'])is int and value['schema']==18 and value['status']=='OBSERVED_EXACT_SIGNED_BUILD_DEPENDENCIES_DATA_ONLY'and value['policy']==POLICY_PIN and value['native_uid_gid_checked']is native and value['runtime_loads']==(expected_loads(p)if native else None)and value['native_acceptance']is False and value['Root_acceptance']is None,'exact observed dependency scope and held acceptance')
 providers={name:dict(owner=row['name'],**item)for row in p['packages']for name,item in row['providers'].items()}
 need(encode(value['inventory'])==encode(pin(expected_inventory(source_root,p)))and encode(value['providers'])==encode(providers),'whole exact inventory and every owned provider join')
 if expected is not None:need(all(encode(value[k])==encode(expected[k])for k in('policy','inventory','providers')),'same host-qualified image dependency state')
 return value


def prepare_context(source_root,context,out,cache,p,call,tick=lambda:None):
 """Future supervised public gpgv only; package installation is image-only."""
 source_root,context,out,cache=map(Path,(source_root,context,out,cache));validate_policy(p)
 keyring=cache/'archlinuxarm.gpg';need(pin(read(keyring,65536,tick))==KEYRING,'same existing signed349 public ALARM keyring')
 home=out/'alarm-dependency-verification';home.mkdir(mode=0o700);target=context/'build-dependencies';target.mkdir(mode=0o700);audits={}
 for row in p['packages']:
  package=source_root/'build-dependencies'/row['filename'];signature=package.with_name(package.name+'.sig')
  need(pin(read(package,INPUT_CAP,tick))==row['archive'],'bounded exact original package before verification')
  need(pin(read(signature,65536,tick))==row['signature'],'exact original detached ALARM signature')
  # Verify signature mathematics against the unchanged public keyring before
  # parsing any package member; gpgv neither imports keys nor starts an agent.
  result=call(['/usr/bin/gpgv','--homedir',str(home),'--keyring',str(keyring),'--status-fd','1',str(signature),str(package)],timeout=30)
  need(result.returncode==0,'successful public ALARM gpgv verification');signature_status(result.stdout);audit=audit_archive(package,row,tick);audit['source_license_files']=audit_provenance(source_root,row,tick)
  for path,expected in((package,row['archive']),(signature,row['signature'])):
   body=read(path,INPUT_CAP,tick);need(pin(body)==expected,'stable audited dependency input before copy');dest=target/path.name
   with dest.open('xb')as stream:stream.write(body)
   dest.chmod(0o444);need(pin(read(dest,INPUT_CAP,tick))==expected,'same signed dependency Docker context bytes')
  audits[row['name']]=dict(archive=row['archive'],signature=row['signature'],signature_status=pin(result.stdout),signer=SIGNER,**audit)
 need(not any(home.iterdir()),'public gpgv verification leaves no agent/keyhome state')
 expected=expected_inventory(source_root,p);(target/'expected-qualified.lock').write_bytes(expected);(target/'expected-qualified.lock').chmod(0o444)
 value=dict(schema=18,status='VERIFIED_SIGNED_ALARM_DEPENDENCY_CONTEXT_DATA_ONLY',policy=POLICY_PIN,keyring=KEYRING,signer=SIGNER,packages=audits,qualified_inventory=pin(expected),network=False,native_acceptance=False,Root_acceptance=None)
 path=out/'build-dependency-audit.json';path.write_bytes(encode(value));return value


def extend_dockerfile(original,p):
 # Required ALARM trust is independent of the preceding private LLVM TEST key.
 # Every dependency check remains active here and again in actual makepkg.
 import shlex
 validate_policy(p);need(type(original)is bytes and original.endswith(b'USER alarm\nWORKDIR /tmp\n'),'exact existing normal LLVM Dockerfile ending')
 names=['/tmp/rust-build-dependencies/'+row['filename']for row in p['packages']]
 required=['bash','curl','gcc','glibc','libgcc','libstdc++','libgit2','libssh2','openssl','sqlite','zlib','cachy-asahi-llvm23-source-reference=23.1.1','python>=3.12','bubblewrap','libarchive']
 required=sorted(set(required+[v for row in p['packages']for v in row['metadata']['depend']]))
 install=' '.join(shlex.quote(n)for n in names);checks=' '.join(shlex.quote(n)for n in required)
 commands=['test "$(cat /etc/pacman.conf)" = "$(printf \'[options]\\nArchitecture = aarch64\\nSigLevel = Required\\nLocalFileSigLevel = Required\\nHookDir = /builder-disabled-hooks\\n\')"',
  '/usr/bin/pacman --gpgdir /etc/pacman.d/gnupg --config /etc/pacman.conf -U --noconfirm --noscriptlet '+install,
  '/usr/bin/pacman --config /etc/pacman.conf -T '+checks,
  'ldconfig','pacman -Q | LC_ALL=C sort > /builder-qualified.lock',
  'cmp -s /builder-qualified.lock /tmp/rust-build-dependencies/expected-qualified.lock',
  'gpgconf --homedir /etc/pacman.d/gnupg --kill gpg-agent']
 for suffix in('','.browser','.extra','.ssh'):
  path='/etc/pacman.d/gnupg/S.gpg-agent'+suffix;commands+=['test ! -e '+path,'test ! -L '+path]
 commands+=['rm -rf /tmp/rust-build-dependencies']
 return original+('USER root\nCOPY build-dependencies/ /tmp/rust-build-dependencies/\nRUN '+' && '.join(commands)+'\nUSER alarm\nWORKDIR /tmp\n').encode()
