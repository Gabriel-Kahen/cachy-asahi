# SPDX-License-Identifier: MIT
"""Fixed KSM archive prefills and original574 cache join; DATA only, no clock reset."""
import argparse,hashlib,json,math,stat,sys,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes':2426,'sha256':'5d923d541f743f3442f4909766cea19db24a1e7c62c7ea7b1ea5a4934c2eb135'}

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def tick(deadline):need(type(deadline)in(int,float)and math.isfinite(deadline)and time.monotonic()<deadline,'original KSM caller deadline exhausted')
def ordinary(path):
 p=Path(path);need(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary explicit KSM path');return p

def maintained(deadline):
 tick(deadline);raw=(ordinary(HERE)/'ksm-retained-profile.json').read_bytes();need(pin(raw)==PROFILE,'whole fixed KSM retained-input profile');p=json.loads(raw)
 bodies={}
 for name,want in p['files'].items():
  path=ordinary(HERE/name);before=path.stat();raw=path.read_bytes();fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns');need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==want['bytes']and pin(raw)==want and all(getattr(before,k)==getattr(path.stat(),k)for k in fields),'exact maintained API body '+name);bodies[name]=raw
 def load(name,relative):
  m=types.ModuleType(name);m.__file__=str(HERE/relative);exec(compile(bodies[relative],m.__file__,'exec'),m.__dict__);return m
 L=load('_ksm_fixed_legacy_prefill','maintained/legacy_prefill.py');saved=sys.modules.get('legacy_prefill')
 try:sys.modules['legacy_prefill']=L;P=load('_ksm_fixed_retained_prepare','maintained/prepare.py')
 finally:
  if saved is None:sys.modules.pop('legacy_prefill',None)
  else:sys.modules['legacy_prefill']=saved
 tick(deadline);return L,P,p

def paths(root,p,L,deadline):
 root=ordinary(root);lock=root/'runtime/borrowed/maintained574-inputs.json';need(L.pin(L.read(lock,deadline,1024**2))==p['original_lock'],'whole original KSM574 input lock');carrier=ordinary(root/p['carrier_relative']);return root,lock,carrier

def early(root,cache_parent,deadline):
 tick(deadline);need(deadline-time.monotonic()<=180,'one bounded KSM prefill step before unchanged CLI timers');L,P,p=maintained(deadline);root,lock,carrier=paths(root,p,L,deadline);cache_parent=ordinary(cache_parent);facts={}
 for n in(32,20,8):
  name='archive'+str(n);helper=root/p['outer_lane']/(name+'.py');policy=root/p['outer_lane']/(name+'-policy.json');need(L.pin(L.read(policy,deadline,65536))==p['archive_source'][policy.name],'whole original archive policy');M=P.module(helper,p['archive_source'][helper.name],deadline);v=M.policy(policy,lock);facts[str(n)]=L.prefill(carrier,cache_parent/('ksm2-archive'+str(n)),v,deadline,git_dir=carrier/'.git',profile_dir=HERE/'maintained')
 tick(deadline);return dict(status='KSM_EXACT32_20_8_PREFILLED_ORIGINAL_CLIS_STILL_REQUIRED',source=p['source'],profile=PROFILE,caches=facts,original_deadline=deadline,original_cli_deadlines='UNCHANGED_EACH180',actual_authority=False)

def seed(root,deps,deadline):
 tick(deadline);L,P,p=maintained(deadline);root,lock,carrier=paths(root,p,L,deadline);deps=ordinary(deps);receipt=P.prepare(carrier,deps,'desktop574',lock,deadline,carrier/'.git');tick(deadline);return dict(status='KSM_COMPLETE1148_JOINED_BEFORE_UNCHANGED_BUILD2300',source=p['source'],profile=PROFILE,preparation=receipt,original_deadline=deadline,owner_seconds=6600,original_build_seconds=2300,actual_authority=False)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('early','seed'));p.add_argument('--source',type=Path,required=True);p.add_argument('--cache',type=Path,required=True);p.add_argument('--deadline',type=float,required=True);a=p.parse_args();print(json.dumps((early if a.phase=='early'else seed)(a.source,a.cache,a.deadline),sort_keys=True))
