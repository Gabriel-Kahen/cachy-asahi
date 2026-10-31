#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit Apps13 repair source from full235 parent; never run emitted actors."""
import argparse,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import prepare as F
NAME='apps13-repair235';PROFILE_PIN={'bytes': 174673, 'sha256': 'd63a51d4ba3c55f7c27a903def8db4edc0bb1304fdab9db0ca61e76364ce788e'}
PREFIX='apps13-repair';LANES=('scripts/ci/apps7-full574-repair-native','scripts/ci/apps7-full574-repair16k','scripts/ci/apps7-full574-repair16k-ci')
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-apps7-full574-repair16k.yml')
enc=lambda v:(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def inputs():
 raw=F.ordinary(HERE/'apps13-profile.json');F.need(F.pin(raw)==PROFILE_PIN,'whole fixed Apps13 profile');p=json.loads(raw)
 F.need(p['profile']==NAME and all(len(p[k])==235 for k in('before','after','null'))and len(p['held'])==197 and len(p['removed'])==25 and len(p['payload'])==38,'whole235 Apps13 membership/inverse')
 payload={n:F.ordinary(HERE/'apps13-payload'/F.relative(n))for n in p['payload']};F.need(F.files(HERE/'apps13-payload')==p['payload'],'whole38 used readable Apps13 payloads')
 F.need({n:w for n,w in p['before'].items()if p['after'].get(n)==w}==p['held']and set(p['removed'])==set(p['before'])-set(p['after']),'whole197 held25 removed')
 return p,payload

def null_view(planned):
 # Regenerate only the same seven source-owned selection/seal operands.
 planned=dict(planned);profile=PREFIX+'/carrier-profile.json';p=json.loads(planned[profile])
 for n in('source','ref','publication','git_authorization','files','archives','native_source','native_run','acceptance','archive'):p[n]=None
 p['status']='NULL_APPS13_REPAIR_INPUT_SELECTION_REQUIRES_ROOT_PAIR_AND_PUBLICATION';planned[profile]=enc(p)
 successor=PREFIX+'/successor.json';s=json.loads(planned[successor]);s['after'][profile]=F.pin(planned[profile]);planned[successor]=enc(s)
 ci=LANES[2]+'/source-manifest.json';old=F.pin(planned[ci])['sha256']
 for lane in LANES:
  n=lane+'/source-manifest.json';m=json.loads(planned[n]);m['files']={k:F.pin(planned[k])for k in m['files']};planned[n]=enc(m)
 new=F.pin(planned[ci])['sha256']
 for n in WORKFLOWS:
  text=planned[n].decode();F.need(text.count(old)==1 and text.count('d96be268f3b24af6e94cfbf662c131303d22931c')==1,'one NULL stamp and carrier operand');planned[n]=text.replace(old,new,1).replace('d96be268f3b24af6e94cfbf662c131303d22931c','APPS13_CARRIER_NULL_UNPUBLISHED',1).encode()
 return planned

def prepare(base,output,profile=None,carrier=None):
 F.need(profile==NAME,'explicit --profile apps13-repair235 required');base=Path(base).absolute();output=Path(output).absolute()
 F.need(not any(p.is_symlink()for p in(output,*output.parents))and not output.exists()and output.parent.is_dir(),'fresh ordinary source output')
 for root in(base,HERE):F.need(not output.is_relative_to(root)and not root.is_relative_to(output),'disjoint source/factory/output')
 p,payload=inputs();F.need(F.files(base)==p['before'],'whole exact Apps12 parent235');planned={n:F.ordinary(base/F.relative(n))for n in p['before']if n not in p['removed']};planned.update(payload)
 F.need({n:F.pin(b)for n,b in planned.items()}==p['after'],'whole selected235 before output')
 if carrier is None:planned=null_view(planned);wanted=p['null']
 else:
  carrier=Path(carrier).absolute();F.need(not output.is_relative_to(carrier)and not carrier.is_relative_to(output),'disjoint carrier/output');F.need(F.files(carrier)==p['carrier_files']and len(p['carrier_files'])==94,'whole exact Root accepted Apps13 carrier94');wanted=p['after']
 F.need({n:F.pin(b)for n,b in planned.items()}==wanted,'whole exact235 selected or NULL source')
 policy=json.loads(planned[LANES[1]+'/source-pins.json']);F.need(policy['actual_source']is policy['actual_ref']is None and all(x is None for x in policy['actual_runs'].values()),'all current actualsNULL')
 F.need(F.files(base)==p['before'],'whole fresh parent before output')
 output.mkdir(mode=0o700)
 for n,raw in sorted(planned.items()):
  target=output/F.relative(n);target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('xb')as stream:stream.write(raw)
 F.need(F.files(output)==wanted and F.files(base)==p['before'],'whole emitted235 and parent-after bytes')
 if carrier is not None:F.need(F.files(carrier)==p['carrier_files'],'whole carrier-after bytes')
 return dict(status='SOURCE_ONLY_EXACT_APPS13_REPAIR235',profile=NAME,files=wanted,selected=carrier is not None,expected_fixture_source=p['source_after']if carrier is not None else None,source=None,ref=None,run_ids=dict.fromkeys(('repair-bytes','repair-missing')),repair_acceptance=None,native_fit='UNKNOWN',hardware='NOT_RUN',clocks='UNCHANGED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--profile',choices=(NAME,),required=True);p.add_argument('--base-root',type=Path,required=True);p.add_argument('--carrier',type=Path);p.add_argument('--output',type=Path,required=True);p.add_argument('--authorization',type=Path,required=True);a=p.parse_args();auth=a.authorization.absolute();out=a.output.absolute();F.need(not auth.exists()and auth.parent.is_dir()and not any(q.is_symlink()for q in(auth,*auth.parents))and not auth.is_relative_to(out),'fresh separate authorization');F.need(all(not auth.is_relative_to(root.absolute())for root in [HERE,a.base_root,*([a.carrier]if a.carrier is not None else[])]),'authorization outside all input roots');v=prepare(a.base_root,out,a.profile,a.carrier)
 with auth.open('xb')as stream:stream.write(enc(v))
 print(json.dumps({k:v[k]for k in('status','profile','selected','source','ref','run_ids')},sort_keys=True))
