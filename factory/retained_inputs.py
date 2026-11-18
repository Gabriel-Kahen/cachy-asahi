#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit existing-clock cache preparation; original policy/GPG/build gates stay held."""
import argparse,hashlib,importlib.util,json,math,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent

def need(ok,why):
    if not ok:raise ValueError(why)
def pin(p):b=p.read_bytes();return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def load(name,path):s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m

def prepare(mode,source,carrier,cache,deadline,git_dir):
    need(mode in('early32-20-8','seed574')and type(deadline)in(int,float)and math.isfinite(deadline)and time.monotonic()<deadline,'explicit fixed mode and still-live original caller deadline')
    source,carrier,cache,git_dir=(Path(p).absolute()for p in(source,carrier,cache,git_dir));profile=json.loads((HERE/'retained-helper-pins.json').read_bytes())
    for n,w in profile.items():need(pin(HERE/'retained-helpers'/n)==w,'whole maintained helper source '+n)
    sys.path.insert(0,str(HERE/'retained-helpers'));P=load('_welcome606_retained_prepare',HERE/'retained-helpers/prepare.py');L=sys.modules['legacy_prefill']
    lock=source/'scripts/ci/maintained-desktop574-inputs.json'
    if mode=='seed574':return P.prepare(carrier,cache,'desktop574',lock,deadline,git_dir)
    receipts={}
    for count in(32,20,8):
        home=source/'scripts/ci/welcome5-native-gui';module=load('_welcome606_original_archive'+str(count),home/('archive'+str(count)+'.py'));v=module.policy(home/('archive'+str(count)+'-policy.json'),lock);target=cache/('welcome5-frozen574-archive'+str(count));receipts[str(count)]=L.prefill(carrier,target,v,deadline,git_dir=git_dir,profile_dir=HERE/'retained-helpers')
    return dict(status='EXACT_ORIGINAL_LEGACY_CACHES_PREFILLED_DATA_ONLY',receipts=receipts,original_CLIs='STILL_REQUIRED_UNCHANGED_EXPECT_REQUESTS_ZERO_REUSE_ALL',actual_authority=False)
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--mode',choices=('early32-20-8','seed574'),required=True)
    for n in('source','carrier','cache','git-dir'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--deadline',type=float,required=True);a=p.parse_args();print(json.dumps(prepare(a.mode,a.source,a.carrier,a.cache,a.deadline,a.git_dir),sort_keys=True))
