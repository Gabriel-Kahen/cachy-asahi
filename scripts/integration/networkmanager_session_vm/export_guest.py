#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite installed-package dependency/payload export; image build only."""
import ctypes as C,ctypes.util,hashlib,json,os,re,subprocess,tarfile
from pathlib import Path
assert os.geteuid()==0 and os.environ.get('NM_SESSION_IMAGE_BUILD')=='1'
mounts=[line.split(' - ')for line in Path('/proc/self/mountinfo').read_text().splitlines()]
assert any(before.split()[4]=='/'and after.split()[0]in {'overlay','fuse-overlayfs'}for before,after in mounts),'private image overlay required'
I=Path('/opt/nm-session-input');base=json.loads((I/'base-inventory.json').read_text());contract=json.loads((I/'contract.json').read_text())
# Actual ALPM installation: exact unsigned candidates, existing dependency checks,
# no scripts/hooks, no network. This does not promote production trust.
mask=Path('/tmp/nm-session-masked-hooks');mask.mkdir()
for folder in ['/usr/share/libalpm/hooks','/etc/pacman.d/hooks']:
 for f in Path(folder).glob('*.hook'):
  p=mask/f.name
  if not p.is_symlink():p.symlink_to('/dev/null')
conf=Path('/tmp/nm-session-pacman.conf');conf.write_text('[options]\nArchitecture=x86_64\nSigLevel=Required TrustedOnly\nLocalFileSigLevel=Optional TrustedOnly\n')
archives=[]
for ref in contract['archives']:
 p=I/ref['name'];assert p.stat().st_size==ref['bytes'] and hashlib.sha256(p.read_bytes()).hexdigest()==ref['sha256'];archives.append(str(p))
subprocess.run(['pacman','--config',str(conf),'--hookdir',str(mask),'--noscriptlet','--noconfirm','-U',*archives],check=True,timeout=90)
subprocess.run(['pacman','--config',str(conf),'-Dk'],check=True,timeout=20)
# Read-only libalpm resolves real installed dependencies/provides. No transaction
# API or automatic ambiguous-provider selection is used for the finite export.
class Link(C.Structure):pass
Link._fields_=[('data',C.c_void_p),('prev',C.POINTER(Link)),('next',C.POINTER(Link))]
L=C.POINTER(Link);a=C.CDLL(C.util.find_library('alpm'))
def api(name,result,args):
 f=getattr(a,name);f.restype=result;f.argtypes=args;return f
version=api('alpm_version',C.c_char_p,[])().decode();assert version=='16.0.1'
init=api('alpm_initialize',C.c_void_p,[C.c_char_p,C.c_char_p,C.POINTER(C.c_int)]);error=C.c_int();handle=init(b'/',b'/var/lib/pacman',C.byref(error));assert handle
release=api('alpm_release',C.c_int,[C.c_void_p]);db=api('alpm_get_localdb',C.c_void_p,[C.c_void_p])(handle)
cache=api('alpm_db_get_pkgcache',L,[C.c_void_p])(db)
name=api('alpm_pkg_get_name',C.c_char_p,[C.c_void_p]);ver=api('alpm_pkg_get_version',C.c_char_p,[C.c_void_p]);deps=api('alpm_pkg_get_depends',L,[C.c_void_p]);satisfier=api('alpm_find_satisfier',C.c_void_p,[L,C.c_char_p]);depstr=api('alpm_dep_compute_string',C.c_void_p,[C.c_void_p]);free=C.CDLL(C.util.find_library('c')).free;free.argtypes=[C.c_void_p]
def entries(p):
 while p:yield p.contents.data;p=p.contents.next
packages={name(p).decode():p for p in entries(cache)}
for n,v in base.items():assert n in packages and ver(packages[n]).decode()==v,('base version drift',n,v)
roots=sorted(set(base)|{'networkmanager','libnm','nm-cloud-setup','networkmanager-docs','polkit','python','python-gobject'})
selected=set();queue=list(roots);edges=[]
while queue:
 n=queue.pop()
 if n in selected:continue
 assert n in packages,n
 selected.add(n)
 for d in entries(deps(packages[n])):
  ptr=depstr(d)
  try:text=C.string_at(ptr).decode()
  finally:free(ptr)
  candidates=[]
  for key,pkg in packages.items():
   one=Link(pkg,None,None)
   if satisfier(C.pointer(one),text.encode()):candidates.append(key)
  direct=re.split(r'[<>=]',text,1)[0]
  if direct in candidates:provider=direct
  else:assert len(candidates)==1,('ambiguous/missing provider',n,text,candidates);provider=candidates[0]
  edges.append({'package':n,'dependency':text,'provider':provider});queue.append(provider)
additions=sorted(selected-set(base));paths=set();records={}
def section(text,key):
 marker='%'+key+'%\n';return text.split(marker,1)[1].split('\n\n',1)[0].splitlines()if marker in text else[]
for n in additions:
 p=packages[n];v=ver(p).decode();directory=Path('/var/lib/pacman/local')/(n+'-'+v);assert directory.is_dir()
 files=section((directory/'files').read_text(),'FILES');desc=(directory/'desc').read_bytes()
 for value in files:
  f=Path(value);assert not f.is_absolute() and '..'not in f.parts
  disk=Path('/')/f;assert disk.is_file()or disk.is_symlink()or disk.is_dir(),str(disk);paths.add(value)
 for f in directory.iterdir():
  assert f.is_file()and not f.is_symlink();paths.add(str(f).lstrip('/'))
 records[n]={'version':v,'local_desc_sha256':hashlib.sha256(desc).hexdigest(),'files':len(files)}
# A package export never imports build-image account or machine identity files.
assert not paths&{'etc/passwd','etc/group','etc/shadow','etc/gshadow','etc/machine-id','etc/hostname','etc/hosts','etc/resolv.conf'}
filepins={}
for relative in sorted(paths):
 f=Path('/')/relative
 if f.is_symlink():filepins[relative]={'symlink':os.readlink(f)}
 elif f.is_dir():filepins[relative]={'directory':True,'mode':f.stat().st_mode&0o7777,'uid':f.stat().st_uid,'gid':f.stat().st_gid}
 else:
  with f.open('rb')as s:d=hashlib.file_digest(s,'sha256').hexdigest()
  filepins[relative]={'bytes':f.stat().st_size,'sha256':d,'mode':f.stat().st_mode&0o7777}
assert sum(p.get('bytes',0)for p in filepins.values())<512*1024**2
listing=I/'export-files';listing.write_text('\n'.join(sorted(paths))+'\n')
subprocess.run(['bsdtar','--no-recursion','--zstd','-cpf','/opt/nm-session-additions.tar.zst','-C','/','-T',str(listing)],check=True,timeout=90)
report={'schema_version':1,'scope':'installed exact retained prerequisite image dependency/payload export; unsigned x86 candidate only','libalpm':version,'base':base,'roots':roots,'selected':{n:ver(packages[n]).decode()for n in sorted(selected)},'additions':records,'dependency_edges':edges,'file_pins':filepins,'archives':contract['archives'],'source_provider':contract['provider'],'package_signature_custody':'official prerequisite image retained pins; candidate unsigned; no new trust/freshness assertion','source_native_hardware_release':'HOLD/NOT RUN'}
Path('/opt/nm-session-export.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');release(handle)
print(json.dumps({'selected':len(selected),'additions':len(additions),'payload_bytes':sum(p.get('bytes',0)for p in filepins.values())}))
