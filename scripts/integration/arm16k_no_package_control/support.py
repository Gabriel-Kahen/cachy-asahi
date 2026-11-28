# SPDX-License-Identifier: MIT
"""Pinned code loading only; no transport, credentials or images on import."""
import hashlib,importlib.util,json,re,stat
from functools import lru_cache
from pathlib import Path
HERE=Path(__file__).resolve().parent
LEGACY=HERE.parent/'arm16k_perl5423_vm'
if not LEGACY.is_dir():LEGACY=Path('/legacy')
SOURCE65_SHA='d0e5f15ceeb752247961ce0779fa39da630ce24d545007484c4a283e65bb08d7'


@lru_cache(None)
def load(name,root):
 if not re.fullmatch('[a-z_]+',name):raise ValueError('fixed code module name')
 spec=importlib.util.spec_from_file_location('no_package_'+str(root)+'_'+name,root/(name+'.py'))
 value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def local(name):return load(name,HERE)
def legacy(name):
 value=load(name,LEGACY)
 # Share the existing runtime's deadline-bearing contract object in this
 # process. The pinned legacy source bytes remain unchanged.
 if name=='runtime':value.module=legacy
 return value


def source(expected):
 """Require exact source membership and the whole maintained dependency seal."""
 lock=HERE/'source.lock.json';raw=lock.read_bytes();pin=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
 if not (expected==pin or type(expected)is str and expected==pin['sha256']):raise ValueError('exact diagnostic Source lock required')
 value=json.loads(raw);files=value['files'];actual=set()
 for p in HERE.rglob('*'):
  info=p.lstat();relative=p.relative_to(HERE).as_posix()
  if stat.S_ISDIR(info.st_mode):raise ValueError('flat diagnostic Source only')
  if not(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o644):raise ValueError('ordinary Git0644 Source required')
  if relative=='source.lock.json':continue
  actual.add(relative);body=p.read_bytes()
  if files.get(relative)!=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),mode=0o644):raise ValueError('diagnostic Source bytes/mode mismatch')
 if actual!=set(files):raise ValueError('exact diagnostic Source membership required')
 legacy('adapter').source(SOURCE65_SHA)
 return pin
