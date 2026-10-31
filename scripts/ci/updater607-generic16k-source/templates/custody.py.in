# SPDX-License-Identifier: MIT
"""Closed source/DATA identity checks only; no package or VM actors."""
import hashlib,json,os,stat
from pathlib import Path
ROOT=Path(__file__).resolve().parent
def need(ok,why):
 if not ok:raise ValueError(why)
def enc(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def safe(path):
 path=Path(path).absolute();need(path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'canonical ordinary source path');return path
def read(path,cap=16*1024**2):
 path=safe(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  info=os.fstat(fd);need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and 0<=info.st_size<=cap,'bounded regular singlelink source')
  raw=bytearray()
  while chunk:=os.read(fd,1024**2):raw.extend(chunk);need(len(raw)<=info.st_size,'source grew')
  identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(len(raw)==info.st_size and identity(info)==identity(os.fstat(fd))==identity(path.lstat()),'stable descriptor/path identity');return bytes(raw)
 finally:os.close(fd)
def rows(root):
 root=safe(root);result={}
 for path in root.rglob('*'):
  name=path.relative_to(root).as_posix()
  if name.split('/')[0]=='.git':continue
  need(not path.is_symlink()and(path.is_file()or path.is_dir()),'ordinary closed source tree')
  if path.is_file():result[name]=pin(read(path))
  need(len(result)<=4096,'bounded source closure')
 return result
def profile():return json.loads(read(ROOT/'profile.json'))
def verify_dependencies(root,role):
 need(role in('held','fresh16k','updater'),'closed dependency role');expected=profile()['dependencies'][role]
 need(rows(root)==expected['files'],'complete exact '+role+' source, no partial/foreign substitution');return expected
def verify():
 expected=json.loads(read(ROOT/'source-manifest.json'));actual=rows(ROOT)
 need(actual==dict(expected['files'],**{'source-manifest.json':pin(read(ROOT/'source-manifest.json'))}),'whole emitted child source closure')
 p=profile();need(p['default']=='generic4k'and p['optional']=='generic16k'and all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')),'no source actual/Root acceptance')
 verify_dependencies(ROOT/'parent360','updater')
 need(len(p['dependencies']['updater']['files'])==360 and p['dependencies']['updater']['source']=='c6a5de859c3f190d47a5aef30962d2c3b50eaf8d','complete exact360 parent inverse')
 return dict(status='SOURCE_ONLY_COMPLETE_PARENT360_INVERSE',files=len(actual),actual=None,hardware='NOT_RUN',fit='NOT_ESTABLISHED')
