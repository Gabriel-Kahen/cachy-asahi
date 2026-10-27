# SPDX-License-Identifier: MIT
"""Source-owned exact cache DATA helpers; fetched carrier code is never imported."""
import argparse,hashlib,importlib.util,json,math,os,stat,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3];LANE='scripts/ci/gnu-immutable-source-native'
PINS={'archive_prefill.py':{'bytes':4717,'sha256':'2090bd8098783834ac7b11a19eb3d8cd047b7de5b01f77ddc4bb60cd57bea726'},'complete574_seed.py':{'bytes':6658,'sha256':'76b787fa71b121ec1bf83b86e4d5db849913614bc90e03239b869d7061af1db4'}}
def need(ok,why):
 if not ok:raise ValueError(why)
def load(name,path,pin=None):
 path=Path(path);need(path.is_absolute()and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary Source-owned helper path');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);identity=lambda a:(a.st_dev,a.st_ino,a.st_mode,a.st_uid,a.st_gid,a.st_nlink,a.st_size,a.st_mtime_ns,a.st_ctime_ns);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<before.st_size<=256*1024,'bounded ordinary Source-owned helper');raw=bytearray()
  while len(raw)<=before.st_size:
   chunk=os.read(fd,min(65536,before.st_size-len(raw)+1))
   if not chunk:break
   raw.extend(chunk)
  need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'stable whole Source-owned helper FD/path');raw=bytes(raw)
 finally:os.close(fd)
 if pin is not None:need({'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}==pin,'whole unchanged Source-owned cache helper')
 module=importlib.util.module_from_spec(importlib.util.spec_from_file_location(name,path));exec(compile(raw,str(path),'exec'),vars(module));return module

def prepare(action,carrier,source_root,temp,cache=None,deadline=None):
 source_root=Path(source_root);carrier=Path(carrier);temp=Path(temp);deadline=time.monotonic()+230 if deadline is None else deadline
 need(action in('prefill','seed')and type(deadline)in(int,float)and math.isfinite(deadline)and time.monotonic()<deadline,'original finite cache deadline')
 lane=source_root/LANE;transport=load('_source_owned_retained_transport',lane/'retained_transport.py');proof=transport.verify_existing(carrier,source_root,deadline)
 lock=source_root/'runtime/runtime-vm/scripts/ci/maintained-desktop574-inputs.json'
 if action=='prefill':
  helper=load('_source_owned_unchanged_archive_prefill',lane/'archive_prefill.py',PINS['archive_prefill.py']);results=[]
  for n in (32,20,8):
   original=load('_source_owned_unchanged_archive'+str(n),lane/('archive'+str(n)+'.py'));policy=original.policy(lane/('archive'+str(n)+'-policy.json'),lock);results.append(helper.prefill(carrier,temp/('immutable-archive'+str(n)),policy,deadline))
 else:
  need(cache is not None,'explicit original private cache destination');helper=load('_source_owned_unchanged_complete574_seed',lane/'complete574_seed.py',PINS['complete574_seed.py']);helper.HERE=carrier;result=helper.seed(lock,Path(cache),'desktop574',deadline)
  held=result['cache'];need(held['fresh_cache']is False and held['all_previous_inode_metadata_bytes_unchanged']is True and held['before_identity']==held['after_previous_identity'],'unchanged previous original package/rootfs/keyring inode metadata bytes');results=[result]
 need(time.monotonic()<deadline and all(r['actual_authority']is False for r in results),'cache DATA is not native authority and original deadline held')
 return dict(status='PASS_SOURCE_OWNED_RETAINED_CACHE_DATA_ONLY',action=action,carrier_source_proof=proof,results=results,fetched_execution=False,actual_authority=False,Root_acceptance=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('prefill','seed'));p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--carrier',type=Path,required=True);p.add_argument('--temp',type=Path,required=True);p.add_argument('--cache',type=Path);a=p.parse_args();print(json.dumps(prepare(a.action,a.carrier,a.root,a.temp,a.cache),sort_keys=True))
