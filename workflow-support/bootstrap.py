#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact source preflight before fresh producer inputs, secrets or native actors."""
import argparse,hashlib,json,os,re,stat
from pathlib import Path
OPERATION='recover-apps16-reinstall607'
PROVIDER='b9976eea34eaed4b6e56af3be21d4d652fa971d6'
AUTH='26902de45f63d4873a3be035adad610f9b2ad76cd2c798676424a2e3edf39a85'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def decode(raw):
 def pairs(rows):
  out={}
  for key,value in rows:need(key not in out,'duplicate source key');out[key]=value
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite source JSON'))
def canonical(value):
 text=os.fspath(value);p=Path(text);need(p.is_absolute()and text==os.path.normpath(text)and not text.startswith('//')and p!=Path('/'),'absolute normalized source root')
 need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary source ancestry');return p
def read(path):
 path=canonical(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=16*1024**2,'bounded singlelink source file');raw=bytearray()
  while block:=os.read(fd,65536):raw.extend(block);need(len(raw)<=a.st_size,'source growth')
  key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(len(raw)==a.st_size and key(a)==key(os.fstat(fd))==key(path.lstat()),'stable complete source FD/path');return bytes(raw)
 finally:os.close(fd)
def tree(root,*,capsule=False):
 root=canonical(root);need(root.is_dir(),'ordinary source directory');out={};directories=set();total=0;nodes=0
 metadata=root/'.git'
 if os.path.lexists(metadata):need(metadata.is_dir()and not metadata.is_symlink()and metadata.stat().st_uid==os.getuid(),'ordinary owned Git metadata only')
 for folder,dirs,names in os.walk(root,topdown=True,followlinks=False):
  if Path(folder)==root:dirs[:]=[n for n in dirs if n!='.git']
  for name in sorted(dirs+names):
   nodes+=1;need(nodes<=10000,'bounded complete source namespace');p=Path(folder)/name;n=p.relative_to(root).as_posix();s=p.lstat();need(not p.is_symlink()and len(Path(n).parts)<=64,'ordinary bounded source path')
   if stat.S_ISDIR(s.st_mode):directories.add(n)
   else:
    need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and stat.S_IMODE(s.st_mode)&0o022==0,'ordinary nonwritable source')
    if capsule:need(stat.S_IMODE(s.st_mode)==0o644,'exact capsule0644')
    raw=read(p);total+=len(raw);need(total<=256*1024**2 and len(out)<4096,'bounded source bytes/files');out[n]=pin(raw)
 need(directories=={q.as_posix()for n in out for q in Path(n).parents if str(q)!='.'},'complete source directory namespace');return out
def verify(root,operation,capsule_sha,profile_sha,provider_source):
 root=canonical(root);need(operation==OPERATION and all(type(v)is str and re.fullmatch('[0-9a-f]{64}',v)for v in(capsule_sha,profile_sha)),'explicit exact operation/capsule/profile')
 raw=read(root/'capsule.json');need(pin(raw)['sha256']==capsule_sha,'independent whole capsule pin');value=decode(raw)
 need(value['schema_version']==1 and value['status']=='SOURCE_ONLY_FRESH_PROVISIONED607_NATIVE_RECOVERY'and value['operation']==operation and value['operation_profile_sha256']==profile_sha and value['actual']is value['Root_acceptance']is None,'source-only fresh607 envelope')
 need(tree(root,capsule=True)==dict(value['files'],**{'capsule.json':pin(raw)}),'entire fresh607 source closure')
 profile_raw=read(root/'operation/profile.json');need(pin(profile_raw)['sha256']==profile_sha,'independent operation profile');profile=decode(profile_raw)
 need(profile['operation']==operation and profile['actual']is profile['Root_acceptance']is None and profile['source']=='c14a8362e2cf9cda84c0b5c1a181658a8c9111a6','normal source/profile identity')
 need(profile['source_files']=={n.removeprefix('repair-source/'):v for n,v in value['files'].items()if n.startswith('repair-source/')}and len(profile['source_files'])==245,'complete unchanged public245')
 need(dict(profile['operation_files'],**{'profile.json':pin(profile_raw)})=={n.removeprefix('operation/'):v for n,v in value['files'].items()if n.startswith('operation/')},'entire operation closure')
 authorization=read(root/'workflow-support/provider1197.json');need(pin(authorization)==dict(bytes=221235,sha256=AUTH),'accepted fresh4K complete1197 authorization')
 rows=decode(authorization);need(len(rows)==1197 and tree(provider_source)==rows,'exact accepted fresh607 provider source; no collected code')
 need(value['provider']['source']==PROVIDER and value['provider']['authorization_sha256']==AUTH and value['provider']['files']==1197,'provider/capsule joins')
 return dict(status='PASS_SOURCE_ONLY_FRESH_PROVISIONED607_NATIVE_RECOVERY',operation=operation,source_files=len(value['files'])+1,operation_files=len(profile['operation_files'])+1,held_public245=True,provider_source=PROVIDER,provider_files=1197,capsule_sha256=capsule_sha,operation_profile_sha256=profile_sha,disposable_outputs='CREATED_BY_FUTURE_OWNED_JOB_NOT_EXPECTED_TO_SURVIVE_ACCEPTED_VM',actual=None,native='NOT_RUN',Root_acceptance=None,hardware='NOT_RUN')
def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('verify',));p.add_argument('--root',type=Path,required=True);p.add_argument('--operation',required=True);p.add_argument('--capsule-sha256',required=True);p.add_argument('--operation-profile-sha256',required=True);p.add_argument('--provider-source',type=Path,required=True);a=p.parse_args(argv)
 print(json.dumps(verify(a.root,a.operation,a.capsule_sha256,a.operation_profile_sha256,a.provider_source),sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
