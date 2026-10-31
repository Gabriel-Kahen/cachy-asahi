#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit correctness resource profile; no actors or native qualification."""
import argparse,json
from pathlib import Path
import cost210 as F
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 71485, 'sha256': '3385c418570fa11522594b60468d659479dace8ab5a94934e8d5573c92947dd3'}
NAME='correctness9000';GUEST=F.BRIDGE+'/guest.py'
def inputs():
 raw=F.read(HERE/'correctness9000-profile.json');F.need(F.pin(raw)==PROFILE,'whole correctness9000 profile pin');p=json.loads(raw);F.need(p['profile']==NAME and len(p['before'])==len(p['after'])==210 and p['before'].keys()==p['after'].keys()and set(p['changed'])=={F.ADAPTER,GUEST,F.TEST,F.BM,F.MF,*F.WORKFLOWS},'finite seven-change exact210 profile')
 F.need(p['helper']=={'cost210.py':F.pin(F.read(HERE/'cost210.py'))},'whole existing physical source reader/helper pin');old,_=F.inputs();F.need(p['before']==old['after'],'complete existing diagnostic output remains unchanged')
 F.need(p['actual']is None and all(v is None for v in p['run_ids'].values())and p['guest_copy_seconds']==[9000,9010]and p['shared_owner_cap_seconds']==18000 and p['job_seconds']==21000 and p['native_prepare_seconds']==[2400,2410]and p['readonly_seconds']==2400 and p['product_seconds']==[600,610],'finite guest resource composition; other caps held');F.need(p['old4800_fit'].startswith('FAILED_')and p['old6000_fit'].startswith('FAILED_')and p['performance']=='NOT_CLAIMED','failed historical fits cannot transfer');return p

def derive(name,raw):
 text=raw.decode()
 if name in(F.ADAPTER,F.TEST):
  copies,backends=(3,2)if name==F.ADAPTER else(4,4);F.need(text.count('4800')==copies and text.count('4810')==backends and '9000'not in text and '9010'not in text,'exact original guest clock operands');text=text.replace('4800','9000').replace('4810','9010').replace('GUEST_COPY_COLD_VALIDATION_9000','GUEST_COPY_CORRECTNESS_9000')
 else:
  F.need(name==GUEST,'only three source clock/receipt/test bodies');text=F.once(text,"guest_copy_profile='REPAIR_GENERIC16K_GUEST_COPY_COLD_VALIDATION_4800_V1',guest_prepare_copy_seconds=[4800,4810]","guest_copy_profile='REPAIR_GENERIC16K_GUEST_COPY_CORRECTNESS_9000_V1',guest_prepare_copy_seconds=[9000,9010]")
 compile(text,name,'exec');return text.encode()

def prepare(base,output,profile=None):
 F.need(profile==NAME,'explicit --profile correctness9000 required; no resource default');p=inputs();base=F.path(base);output=F.path(output);F.need(not output.exists()and output.parent.is_dir()and not output.is_relative_to(base)and not base.is_relative_to(output),'fresh separate source-only output');F.need(F.files(base)==p['before'],'whole exact published62c7 source210 required');planned={n:F.read(base/F.relative(n))for n in p['before']};F.need({n:F.pin(v)for n,v in planned.items()}==p['before'],'all original210 physical bytes')
 for name in(F.ADAPTER,GUEST,F.TEST):planned[name]=derive(name,planned[name])
 bridge=json.loads(planned[F.BM])
 for name in(F.ADAPTER,GUEST,F.TEST):F.need(bridge['files'][name]==p['before'][name],'original bridge source stamp');bridge['files'][name]=F.pin(planned[name])
 planned[F.BM]=F.enc(bridge);manifest=json.loads(planned[F.MF])
 for name in(F.ADAPTER,GUEST,F.TEST,F.BM):F.need(manifest['files'][name]==p['before'][name],'original closed source stamp');manifest['files'][name]=F.pin(planned[name])
 planned[F.MF]=F.enc(manifest);before=p['before'][F.MF]['sha256'].encode();after=F.pin(planned[F.MF])['sha256'].encode()
 for name in F.WORKFLOWS:F.need(planned[name].count(before)==1,'one held workflow source stamp');planned[name]=planned[name].replace(before,after,1)
 F.need({n:F.pin(v)for n,v in planned.items()}==p['after'],'whole exact published6402 source210 emission');actual=json.loads(planned[F.BRIDGE+'/source-pins.json']);F.need(actual['actual_source']is actual['actual_ref']is None and all(v is None for v in actual['actual_runs'].values()),'all emitted actualsNULL');F.need(F.files(base)==p['before'],'full physical input reread before output')
 output.mkdir(mode=0o700)
 for name,raw in planned.items():
  target=output/F.relative(name);target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('xb')as stream:stream.write(raw)
  target.chmod(0o644)
 F.need(F.files(output)==p['after']and F.files(base)==p['before'],'whole output and unchanged source-after equality');return dict(status='SOURCE_ONLY_EXACT210_CORRECTNESS9000_PENDING_NATIVE',profile=NAME,files=p['after'],expected_fixture_source=p['source_after'],source=None,ref=None,run_ids=p['run_ids'],guest_copy_seconds=p['guest_copy_seconds'],shared_owner_cap_seconds=18000,job_seconds=21000,old4800_fit=p['old4800_fit'],old6000_fit=p['old6000_fit'],correctness9000='NATIVE_PENDING',performance='NOT_CLAIMED',hardware='NOT_RUN',release='NOT_ADMITTED')
if __name__=='__main__':
 q=argparse.ArgumentParser(description=__doc__);q.add_argument('--profile',choices=(NAME,),required=True);q.add_argument('--base-root',type=Path,required=True);q.add_argument('--output',type=Path,required=True);q.add_argument('--authorization',type=Path,required=True);a=q.parse_args();authorization=F.path(a.authorization.absolute());output=a.output.absolute();F.need(not authorization.exists()and authorization.parent.is_dir()and not authorization.is_relative_to(output),'fresh separate authorization');value=prepare(a.base_root.absolute(),output,a.profile)
 with authorization.open('xb')as stream:stream.write(F.enc(value))
 print(json.dumps({k:value[k]for k in('status','profile','source','ref','run_ids')},sort_keys=True))
