#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite separate public-pair604 source emitter; original223 gate stays untouched."""
import argparse,ast,hashlib,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/expanded604-apps6';NEW='scripts/ci/expanded604-apps6-public-pairs'
WF='.github/workflows/native-arm-expanded604-apps6-public-pairs.yml'
MODULES=('contract.py','inputs.py','materializer.py','lifecycle.py','installed_shells.py','run.py','gate.py','current_inputs.py','held-pins.json','expected587.lock','expected604.lock')
OWN=('prepare.py','apps_inputs.py','pair_packet.py','policy.json','source-pins.json','test_lane.py','README.md','hooks.json')
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def source(root):
 rows=json.loads((HERE/'source-pins.json').read_bytes())['files']
 for n,p in rows.items():
  q=root/n;need(not any(x.is_symlink() for x in (q,*q.parents)) and q.is_file() and q.stat().st_nlink==1 and pin(q.read_bytes())==p,'exact held Apps6 source differs: '+n)
 return rows

def adapt(raw,name):
 text=raw.decode();ledger=[]
 def replace(a,b,count=1):
  nonlocal text
  need(text.count(a)==count,'public pair counted anchor: '+name+': '+a[:80]);text=text.replace(a,b);ledger.append(dict(before=a,after=b,count=count))
 if name=='contract.py':
  replace('org.cachy-asahi.expanded604.apps6.job','org.cachy-asahi.expanded604.apps6-public-pairs.job')
  replace('ROOT_BOUND_APPS6_CURRENT604_NATIVE_INPUTS','ROOT_BOUND_PUBLIC_PAIRS_APPS6_CURRENT604_NATIVE_INPUTS')
  replace("(apps6_native,value['apps6']['native_source'])","(apps6_native,value['apps6']['authority_source'])")
 if name in ('contract.py','run.py','gate.py'):
  count=text.count('args.apps6_native_source');replace('args.apps6_native_source','args.apps6_authority_source',count) if count else None
 if name in ('run.py','gate.py'):replace("'welcome_source','apps6_source')","'welcome_source','apps6_source','apps6_authority_source')")
 if name=='run.py':
  replace("*CARRIERS,'apps6_native_source','audio_inputs'","*CARRIERS,'audio_inputs'")
  replace('PASS_NATIVE_APPS6_CURRENT604_COMPOSITION','PASS_NATIVE_PUBLIC_PAIRS_APPS6_CURRENT604_COMPOSITION')
 if name=='gate.py':
  replace(";parser.add_argument('--apps6-native-source',type=Path)",'')
  replace("apps6_native_source=policy['apps6']['native_source']","apps6_authority_source=policy['apps6']['authority_source']")
  replace('exact Apps6 native source required','exact public byte-case authority required')
 if name=='inputs.py':
  replace("        for rows,root in ((result['management'].values(),management),([result['setup']],setup),([result['welcome']],welcome)):","        for held in ('cachy-asahi-repository-runtime','cachy-asahi-cache','cachy-asahi-orphans'):\n            C.need({k:result['management'][held]['files']['a'][k] for k in ('bytes','sha256')}==result['management']['cachy-asahi-apps']['public_pair_inputs'][held]['archive'],'other603 selected public archive differs: '+held)\n        for rows,root in ((result['management'].values(),management),([result['setup']],setup),([result['welcome']],welcome)):")
  replace('retention(eight,seven,management,setup,welcome,legacy,policy,apps6)','retention(eight,seven,management,setup,welcome,legacy,policy,apps6,apps6_native)',2)
  replace("('apps6_source',Path(apps6),policy['apps6']['index'],False)):","('apps6_source',Path(apps6),policy['apps6']['index'],False),\n        ('apps6_authority_source',Path(apps6_native),policy['apps6']['byte_case_decision'],False)):")
 if name in ('contract.py','lifecycle.py'):
  count=text.count('PASS_APPS6_CURRENT604_METADATA_LIFECYCLE');replace('PASS_APPS6_CURRENT604_METADATA_LIFECYCLE','PASS_PUBLIC_PAIRS_APPS6_CURRENT604_METADATA_LIFECYCLE',count)
 ast.parse(text) if name.endswith('.py') else None
 return text.encode(),ledger

def workflow(raw,oldrun,oldmanifest,newrun,newmanifest):
 text=raw.decode();ledger=[]
 def replace(a,b,count=1):
  nonlocal text
  need(text.count(a)==count,'public pair workflow anchor: '+a[:80]);text=text.replace(a,b);ledger.append(dict(before=a,after=b,count=count))
 replace(OLD,NEW,text.count(OLD));replace(oldrun,newrun);replace(oldmanifest,newmanifest)
 replace('native-arm-expanded604-apps6','native-arm-expanded604-apps6-public-pairs',text.count('native-arm-expanded604-apps6'))
 replace('Checkout Root bound Apps6 public native evidence','Checkout exact public659 native pairs')
 replace('Checkout exact accepted Apps6 native guards','Checkout accepted public native byte-case authority')
 replace('steps.policy604.outputs.apps6_native_source','steps.policy604.outputs.apps6_authority_source')
 replace('expanded604-apps6-native','expanded604-apps6-bytecase-authority',text.count('expanded604-apps6-native'))
 replace('--apps6-native-source','--apps6-authority-source',2)
 return text.encode(),ledger

def emit(root,output):
 rows=source(root);need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary source overlay')
 # Prove every anchor before creating the output.
 derived={};ledger={}
 for n in MODULES:derived[n],ledger[n]=adapt((root/OLD/n).read_bytes(),n)
 output.mkdir(mode=0o700)
 for n in rows:p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((root/n).read_bytes())
 lane=output/NEW;lane.mkdir(parents=True)
 for n in OWN:(lane/n).write_bytes((HERE/n).read_bytes())
 for n,data in derived.items():(lane/n).write_bytes(data)
 (lane/'input-policy.json').write_bytes((HERE/'policy.json').read_bytes())
 files={n:pin((output/n).read_bytes()) for n in rows};files.update({p.relative_to(output).as_posix():pin(p.read_bytes()) for p in lane.iterdir() if p.is_file()});manifest=dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCE',files=files,scope='PUBLIC659_PAIR_PLUS_NATIVE_BYTECASE_ONLY_NEW604_UNBOUND',native='NOT_RUN',hardware='NOT_RUN');(lane/'source-manifest.json').write_bytes(encoded(manifest))
 wf,ledger['workflow']=workflow((root/'.github/workflows/native-arm-expanded604-apps6.yml').read_bytes(),pin((root/OLD/'run.py').read_bytes())['sha256'],pin((root/OLD/'source-manifest.json').read_bytes())['sha256'],pin((lane/'run.py').read_bytes())['sha256'],pin((lane/'source-manifest.json').read_bytes())['sha256']);(output/WF).write_bytes(wf)
 result=dict(status='SOURCE_ONLY_PUBLIC_PAIR_APPS6_CURRENT604_UNBOUND',files=len(files),source_manifest=pin(encoded(manifest)),workflow=pin(wf),target_sha256='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3',other_packages_unchanged=603,raw223='NOT_CONSUMED',anchors=ledger,native='NOT_RUN',fresh='UNBOUND',update='UNBOUND',VM='UNBOUND',hardware='NOT_RUN');(output/'adaptation.json').write_bytes(encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.output.absolute()),sort_keys=True))
