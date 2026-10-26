# SPDX-License-Identifier: MIT
"""Source-relative legacy tooling and retirement of our temporary sealed604 cache."""
import importlib.util,json,os,re,stat,sys
from pathlib import Path
import common as C

LEGACY_PINS = {'common.py': {'bytes': 84361, 'sha256': 'aef2b4f09a91c4cfd66dd4504e69ef18396a94214c82ae0ec0a43c2716894a03'}, 'audit_tooling.py': {'bytes': 7045, 'sha256': '6677f391f2de23540bc147770148729fe4c993850b7bbed0b71fb7e48d296fdc'}}
KEYS=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
def identity(p):return tuple(getattr(p.lstat(),k)for k in KEYS)
def tooling(contract,legacy):
 paths={n:legacy/'scripts/virtual'/n for n in LEGACY_PINS}
 for n,w in LEGACY_PINS.items():C.checked(paths[n],w)
 common=contract.scoped_load('_fresh607_legacy_virtual_common',paths['common.py'])
 result=contract.scoped_load('_fresh607_legacy_audit_tooling',paths['audit_tooling.py'],{'common':common})
 for n,w in LEGACY_PINS.items():C.checked(paths[n],w)
 C.need(result.digest is common.digest,'exact source-relative tooling digest')
 return result

class BaseCache:
 """Retire only a successfully materialized base we own; never repair arbitrary trees."""
 def __init__(self,producer,base):
  self.producer=C.safe(producer);self.base=C.safe(base)
  C.need(producer.parent==Path('/tmp')and base==producer/'private/latest607-base604','fixed owned temporary cache path')
  for p in(producer,producer/'private',base):
   s=p.lstat();C.need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o700,'private owned cache ancestry')
  self.owner_path=producer/'producer-owner.json';self.owner=C.read(self.owner_path);owner=json.loads(self.owner)
  C.need(owner['schema_version']==1 and re.fullmatch('[0-9a-f]{32}',owner['token']),'same original producer ownership token')
  manifest=json.loads(C.read(base/'manifest.json'));C.need(manifest['status']=='READY_SIGNED_EXPANDED604'and len(manifest['packages'])==604,'complete successful original604 cache')
  expected={n:None for n in('manifest.json','expected-installed.lock','builder-packages.lock')}
  for r in manifest['packages']:
   for n,w in((r['archive'],dict(bytes=r['size'],sha256=r['sha256'])),(r['signature'],dict(bytes=r['signature_size'],sha256=r['signature_sha256']))):
    C.need(n not in expected and Path(n).parts[0]=='packages'and len(Path(n).parts)==2,'closed flat package member');expected[n]=w
  for r in manifest['keyrings']:
   n=r['path'];C.need(n not in expected and Path(n).parts[0]=='keys'and len(Path(n).parts)==2,'closed flat key member');expected[n]=dict(bytes=r['size'],sha256=r['sha256'])
  C.need({p.relative_to(base).as_posix()for p in base.rglob('*')}==set(expected)|{'packages','keys'},'closed original604 cache namespace')
  self.entries={}
  for n,w in expected.items():
   p=base/n;s=p.lstat();C.need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o444,'owned sealed cache member')
   if w:C.checked(p,w)
   self.entries[n]=identity(p)
  for n in('packages','keys'):
   s=(base/n).lstat();C.need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o555,'two owned sealed cache directories')
  self.dirs={p:identity(p)for p in(producer,producer/'private',base,base/'packages',base/'keys')}
 def retire(self):
  C.need(C.read(self.owner_path)==self.owner,'producer token/receipt unchanged')
  C.need(all(not os.path.lexists(self.producer/'private'/n)for n in('expanded604-verifier','latest607-verifier')),'original and current verifier homes retired')
  # Parent private directory legitimately changed when the current verifier ran.
  for p,w in self.dirs.items():
   now=identity(p);C.need(now[:6]==w[:6]and(p==self.producer/'private'or now==w),'owned cache directory identity unchanged')
  C.need({p.relative_to(self.base).as_posix()for p in self.base.rglob('*')}==set(self.entries)|{'packages','keys'},'cache namespace unchanged')
  for n,w in self.entries.items():C.need(identity(self.base/n)==w,'sealed cache member unchanged')
  for n in('packages','keys'):(self.base/n).chmod(0o700)
  for n in self.entries:(self.base/n).unlink()
  for n in('packages','keys'):(self.base/n).rmdir()
  self.base.rmdir();C.need(not os.path.lexists(self.base),'temporary base604 retired')
