#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit the separate Apps6 fresh installer from two finite source closures; no actors."""
import argparse,ast,hashlib,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/expanded604-current-management-installer';NEW='scripts/ci/expanded604-apps6-installer'
COMP='scripts/ci/expanded604-apps6'
BEFORE='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5'
AFTER='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3'
MODULES=('contract.py','adapter.py','ci.py','gate.py','freeze.py')
OWN=('prepare.py','policy.json','source-pins.json','test_lane.py','README.md')
WF='.github/workflows/native-arm-expanded604-apps6-installer.yml'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def source(repo,composition):
 groups=json.loads((HERE/'source-pins.json').read_bytes())['groups'];need(set(groups)=={'original','composition'},'two explicit source roles required');result={}
 for role,root in (('original',repo),('composition',composition)):
  rows=groups[role];need(0<len(rows)<=512,'finite source closure')
  for n,row in rows.items():
   p=root/n;need(not any(q.is_symlink() for q in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and p.stat().st_size<=16*1024**2 and pin(p.read_bytes())==row,'pinned source differs: '+role+':'+n)
   raw=p.read_bytes();need(n not in result or result[n]==raw,'incompatible source roles');result[n]=raw
 return result

def adapt(raw,name):
 text=raw.decode();ledger=[]
 def r(a,b,count=1):
  nonlocal text
  need(text.count(a)==count,'fresh Apps6 anchor '+name+': '+a[:100]);text=text.replace(a,b);ledger.append(dict(before=a,after=b,count=count))
 # Namespace/target facts only; original runtime bodies are not imported from artifacts.
 for a,b in ((OLD,NEW),('expanded604-current-management-installer','expanded604-apps6-installer'),('expanded604-current-management/','expanded604-apps6/'),("'expanded604-current-management'","'expanded604-apps6'"),(BEFORE,AFTER),('ROOT_BOUND_CURRENT604_NATIVE_ACCEPTANCE','ROOT_BOUND_APPS6_CURRENT604_NATIVE_ACCEPTANCE'),('ROOT_ACCEPTED_NATIVE_CURRENT604_COMPOSITION','ROOT_ACCEPTED_NATIVE_APPS6_CURRENT604_COMPOSITION'),('PASS_CURRENT604_INSTALLER','PASS_APPS6_CURRENT604_INSTALLER'),('GENERIC4K_CURRENT_SIGNED604_FRESH_INSTALLER_SOFTWARE_ONLY','GENERIC4K_APPS6_SIGNED604_FRESH_INSTALLER_SOFTWARE_ONLY')):
  if a in text:r(a,b,text.count(a))
 if name=='contract.py':r("'setup_source','welcome_source')","'setup_source','welcome_source','apps6_source','apps6_native_source')")
 if name=='ci.py':r('args.welcome_source,args.implementation)','args.welcome_source,args.implementation,args.apps6_source,args.apps6_native_source)')
 if name=='gate.py':r("fresh600_decisions=policy['fresh600']['carrier_source']","apps6_source=composition['apps6']['carrier_source'],apps6_native_source=composition['apps6']['native_source'],\n             fresh600_decisions=policy['fresh600']['carrier_source']")
 if name=='adapter.py':
  r("NEW='expanded604-apps6-installer'","NEW='expanded604-apps6-installer'")
  # The held transformer still derives the exact original guest driver. Change only its output identities.
  r("'PASS_EXPANDED604_INSTALLER':'PASS_APPS6_CURRENT604_INSTALLER'","'PASS_EXPANDED604_INSTALLER':'PASS_APPS6_CURRENT604_INSTALLER'")
 ast.parse(text);return text.encode(),ledger

def workflow(raw,owner,manifest):
 text=raw.decode().replace(OLD,NEW).replace('native-arm-expanded604-current-management-installer','native-arm-expanded604-apps6-installer')
 text=text.replace('expanded604-current-management-installer','expanded604-apps6-installer')
 old=json.loads((HERE/'source-pins.json').read_bytes())['groups']['original']
 for n,new in ((OLD+'/ci.py',owner),(OLD+'/source-manifest.json',manifest)):
  key=old[n]['sha256'];need(text.count(key)==1,'original workflow marker');text=text.replace(key,new)
 marker='      - name: Retrieve only the six original pinned audio inputs'
 # Checkout and path switches are mechanically bounded to the original workflow's existing carrier blocks.
 need(text.count(marker)==1,'fresh installer audio seam')
 extra=''
 for role,path in (('apps6_source','apps6-inputs'),('apps6_native_source','apps6-native')):
  extra+='      - name: Checkout exact '+role+'\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: ${{ steps.installer_policy.outputs.'+role+' }}\n          path: '+path+'\n          persist-credentials: false\n'
 text=text.replace(marker,extra+marker)
 anchor='--audio-inputs "$RUNNER_TEMP/audio-archives"';need(text.count(anchor)==2,'fresh gate and execution argv')
 text=text.replace(anchor,'--apps6-source "$GITHUB_WORKSPACE/apps6-inputs/payload" --apps6-native-source "$GITHUB_WORKSPACE/apps6-native" \\\n            '+anchor)
 return text.encode()

def emit(repo,composition,output):
 rows=source(repo,composition);need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary source output');output.mkdir(mode=0o700)
 for n,raw in rows.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
 lane=output/NEW;lane.mkdir(parents=True);changes={}
 for n in OWN:(lane/n).write_bytes((HERE/n).read_bytes())
 for n in MODULES:raw,changes[n]=adapt(rows[OLD+'/'+n],n);(lane/n).write_bytes(raw)
 lock=rows[COMP+'/expected604.lock'];need(pin(lock)['sha256']==AFTER,'exact Apps6 lock');(lane/'expected604.lock').write_bytes(lock);(lane/'input-policy.json').write_bytes((HERE/'policy.json').read_bytes())
 files={n:pin(raw) for n,raw in rows.items()};files.update({p.relative_to(output).as_posix():pin(p.read_bytes()) for p in lane.iterdir() if p.is_file()})
 manifest=lane/'source-manifest.json';manifest.write_bytes(encoded(dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCE',files=files,native='NOT_RUN',hardware='NOT_RUN',scope='APPS6_FRESH_ONLY_UNBOUND')))
 wf=output/WF;wf.parent.mkdir(parents=True,exist_ok=True);wf.write_bytes(workflow(rows['.github/workflows/native-arm-expanded604-current-management-installer.yml'],pin((lane/'ci.py').read_bytes())['sha256'],pin(manifest.read_bytes())['sha256']))
 result=dict(status='SOURCE_ONLY_APPS6_FRESH_INSTALLER_UNBOUND',target_sha256=AFTER,original604=BEFORE,changes=changes,source_rows=len(files),actors='NOT_RUN',hardware='NOT_RUN');(output/'fresh-adaptation.json').write_bytes(encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','composition','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.composition.absolute(),a.output.absolute()),sort_keys=True))
