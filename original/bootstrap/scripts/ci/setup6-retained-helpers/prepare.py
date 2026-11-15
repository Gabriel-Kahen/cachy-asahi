#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Two immutable retained carriers and three explicit DATA-only preparation modes."""
import argparse,json,math,os,stat,time,types
from pathlib import Path
import legacy_prefill as L
HERE=Path(__file__).resolve().parent
POLICY={'bytes':11090,'sha256':'5e448ef6677fc26485e044b3ac2d35a07105703d4f1a719bb7c030678eff87ae'}

def module(path,want,deadline):
 body=L.read(path,deadline);L.need(L.pin(body)==want,'immediately pinned source helper');m=types.ModuleType('_exact_retained_'+path.stem);m.__file__=str(path);exec(compile(body,str(path),'exec'),m.__dict__);return m

def profile(mode,deadline):
 raw=L.read(HERE/'legacy-prefill-profile.json',deadline,65536);L.need(L.pin(raw)==L.PROFILE,'whole fixed capability profile');name='compiler6-profile.json'if mode=='compiler6'else'carrier-profile.json';row=json.loads(raw)['carriers'][name];raw=L.read(HERE/name,deadline,2*1024**2);L.need(L.pin(raw)==row['profile'],'whole immutable carrier profile');p=json.loads(raw);L.need(p['source']==row['source']and p['ref']==row['ref']and len(p['files'])==row['files']and p['actual']is None,'fixed source-only carrier');return p

def prepare(carrier,cache,mode,lock,deadline,git_dir):
 L.need(mode in('native248','desktop574','compiler6')and type(deadline)in(int,float)and math.isfinite(deadline)and time.monotonic()<deadline,'explicit fixed mode and original caller deadline');carrier,cache,lock,git_dir=(Path(p).absolute()for p in(carrier,cache,lock,git_dir));p=profile(mode,deadline);name={'native248':'native-inputs.lock.json','desktop574':'desktop574-inputs.lock.json','compiler6':'original-extension.lock.json'}[mode];L.need(L.pin(L.read(lock,deadline,1024**2))==p['files'][name],'whole selected original input lock')
 if mode=='compiler6':
  path=carrier/'archive6-policy.json';L.need(L.pin(L.read(path,deadline,65536))==p['files']['archive6-policy.json'],'whole original compiler policy');policy=module(HERE/'compiler_policy.py',POLICY,deadline).policy(path,lock)
  receipt=L.prefill(carrier,cache,policy,deadline,git_dir=git_dir,profile_dir=HERE);proof=receipt['carrier_source_proof']
 else:
  L.need(not any(q.is_symlink()for q in(cache,*cache.parents)),'ordinary existing owned cache ancestry');s=cache.lstat();L.need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o700,'existing caller-owned0700 cache')
  proof=L.prove(carrier,git_dir,p,deadline);seed=module(carrier/'seed.py',p['files']['seed.py'],deadline);receipt=seed.seed(lock,cache,mode,deadline);v=receipt['cache'];L.need(v['fresh_cache']is False and v['all_previous_inode_metadata_bytes_unchanged']is True and v['before_identity']==v['after_previous_identity'],'all prior original package/rootfs/keyring identities and bytes preserved')
 L.need(receipt['actual_authority']is False,'cache DATA never native authority');return dict(status='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY',mode=mode,source=p['source'],carrier=proof,receipt=receipt,authentication='UNCHANGED_ORIGINAL_POLICY_CLI_INDEX_GPG_METADATA_ACQUIRE_BUILD_AND_RUNTIME_GATES_REQUIRED',actual=None,hardware='NOT_RUN',release='NOT_ADMITTED')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--carrier',type=Path,required=True);p.add_argument('--cache',type=Path,required=True);p.add_argument('--mode',choices=('native248','desktop574','compiler6'),required=True);p.add_argument('--lock',type=Path,required=True);p.add_argument('--deadline',type=float,required=True,help='absolute monotonic deadline from the original source-owned caller');p.add_argument('--git-dir',type=Path,required=True);a=p.parse_args();print(json.dumps(prepare(a.carrier,a.cache,a.mode,a.lock,a.deadline,a.git_dir),sort_keys=True))
