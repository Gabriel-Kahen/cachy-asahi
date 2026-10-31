# SPDX-License-Identifier: MIT
"""Exact Apps16 current606 source; original guards stay in emitted source."""
import importlib.util,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_apps8_held_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
PROFILE={'bytes': 458427, 'sha256': 'e791fa080b6dc5c45747d6535d84db0ccabf83998b6ea29c9c76ba3feb2d6e13'}
enc=lambda v:(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def normalized(path):
 path=F.ordinary(path);F.need(path==path.resolve(),'normalized ordinary input/output required');return path

def inputs():
 F.need(not __import__('sys').flags.optimize,'optimized source checks refused');raw=F.read(HERE/'apps16-profile.json');F.need(F.pin(raw)==PROFILE,'whole fixed Apps16 profile');p=json.loads(raw)
 F.need(p['profile']=='SOURCE_ONLY_EXACT_APPS16_CURRENT606389'and all(len(p[k])==389 for k in('before','after','null'))and len(p['held'])==364 and len(p['removed'])==9 and len(p['payload'])==25 and len(p['null_payload'])==9,'finite389 Apps16 source closure')
 F.need({n:w for n,w in p['before'].items()if p['after'].get(n)==w}==p['held']and set(p['removed'])==set(p['before'])-set(p['after']),'complete364 held9 removed')
 return p,F.source(HERE/'apps16-payload',p['payload']),F.source(HERE/'apps16-null-payload',p['null_payload'])

def emit(parent,carrier,output):
 parent,output=map(normalized,(parent,output));carrier=normalized(carrier)if carrier is not None else None
 F.need(not os.path.lexists(output)and output.parent.is_dir(),'fresh ordinary Apps16 output')
 for root in(parent,HERE,*([carrier]if carrier is not None else[])):F.need(not output.is_relative_to(root)and not root.is_relative_to(output),'disjoint source/carrier/factory/output')
 p,payload,null_payload=inputs();old=F.source(parent,p['before']);planned={n:b for n,b in old.items()if n not in p['removed']}|payload;F.need({n:F.pin(b)for n,b in planned.items()}==p['after'],'whole selected389 in memory')
 if carrier is not None:F.source(carrier,p['carrier_files']);wanted=p['after']
 else:
  planned.update(null_payload);n='apps16/successor.json';s=json.loads(planned[n]);s['archive_authority']=None;s['edits']=p['null_successor_edits'];s['helpers']=p['null_successor_helpers'];planned[n]=enc(s);wanted=p['null']
 F.need({n:F.pin(b)for n,b in planned.items()}==wanted,'whole bound or NULL389 before output');authority=json.loads(planned['apps16/carrier-profile.json']);F.need(authority['actual']is authority['Root_acceptance']is None,'no current actual authority')
 if carrier is None:F.need(all(authority[k]is None for k in('source','ref','publication','git_authorization','files','archives','native_source','native_run','acceptance','archive')),'all ten selection authority fieldsNULL')
 F.source(parent,p['before'])
 output.mkdir(mode=0o700)
 for n,b in sorted(planned.items()):
  target=output/n;target.parent.mkdir(parents=True,exist_ok=True)
  with target.open('xb')as stream:stream.write(b)
 F.source(output,wanted);F.source(parent,p['before'])
 if carrier is not None:F.source(carrier,p['carrier_files'])
 return dict(status='SOURCE_ONLY_EXACT_APPS16_CURRENT606389',files=389,source=None,ref=None,run=None,expected_fixture_source=p['source_after']if carrier is not None else None,selected=carrier is not None,held=364,changed=16,removed=9,added=9,current606_acceptance=None,native='NOT_RUN',hardware='NOT_RUN')
