#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite public-pair composition/fresh/public-assets profile16K source assembly."""
import argparse,hashlib,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/current604-apps6-generic16k';NEW='scripts/ci/current604-public-pair-generic16k'
INSTALLER='scripts/ci/expanded604-apps6-public-pair-installer';ASSETS='scripts/ci/current604-public-gui-assets'
WF='.github/workflows/native-arm-current604-public-pair-generic16k.yml'
OWN=('contract.py','adapter.py','ci.py','gate.py','retain.py','context604.py','install604.py','prepare.py','test_lane.py','README.md','source-pins.json','input-policy.json','public-assets-policy.json')
def need(v,why):
 if not v:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def read(p):
 need(not any(q.is_symlink() for q in (p,*p.parents)),'source aliases refused');s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=16*1024**2,'bounded single-link source');raw=p.read_bytes();need(len(raw)==s.st_size,'source length drift');return raw

def source(source,installer,assets):
 groups=json.loads(read(HERE/'source-pins.json'))['groups'];need(set(groups)=={'original','installer','assets'},'three explicit source roles');rows={}
 for role,root in (('original',source),('installer',installer),('assets',assets)):
  for n,pinrow in groups[role].items():
   need(not n.startswith('/') and all(x not in ('','.','..') for x in n.split('/')),'relative source path')
   # The asset helper's12 unchanged support pins live in the original checkout.
   origin=source if role=='assets' and not n.startswith(ASSETS+'/') else root
   raw=read(origin/n);need(pin(raw)==pinrow,'pinned source differs: '+role+':'+n)
   need(n not in rows or rows[n]==raw,'source roles conflict: '+n);rows[n]=raw
 need(len(rows)+len(OWN)+1<=512,'original finite source cap');return rows

def workflow(raw,rows,ci_sha,mf_sha):
 text=raw.decode()
 for n,new in (('ci.py',ci_sha),('source-manifest.json',mf_sha)):
  old=pin(rows[OLD+'/'+n])['sha256'];need(text.count(old)==1,'original workflow hash marker');text=text.replace(old,new)
 text=text.replace('current604-apps6-generic16k','current604-public-pair-generic16k').replace('apps6_native_source','apps6_authority_source').replace('apps6-native','apps6-authority')
 anchor='--gui-decisions "$GITHUB_WORKSPACE/expanded604-gui-decisions"\n'
 need(text.count(anchor)==1,'one early decisions gate');text=text.replace(anchor,'--gui-decisions "$GITHUB_WORKSPACE/expanded604-gui-decisions" \\\n            --welcome-source "$GITHUB_WORKSPACE/expanded604-welcome-source/payload"\n')
 anchor='      - name: Required actual ALPM604 current Welcome4 GUI in the separately owned16384 VM\n';need(text.count(anchor)==1,"one original VM entry");text=text.replace(anchor,'      - name: Checkout exact original signed QEMU tooling inputs\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        timeout-minutes: 2\n        with:\n          ref: 9c1fa9e6674ce24edb9655a56436d4c5c0985c54\n          path: current604-qemu-tooling\n          persist-credentials: false\n'+anchor)
 env='PYTHONDONTWRITEBYTECODE=1 RUNNER_TEMP="$RUNNER_TEMP" GITHUB_ACTIONS=true RUNNER_ARCH=ARM64';need(text.count(env)==1,"one original clean runtime environment");text=text.replace(env,env+' CACHY_ASAHI_QEMU_TOOLING_INPUTS="$GITHUB_WORKSPACE/current604-qemu-tooling/tooling-inputs"')
 return text.encode()

def emit(source_root,installer,assets,output):
 blobs=source(source_root,installer,assets)
 need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary output')
 for n in OWN:need(NEW+'/'+n not in blobs,'new namespace collision');blobs[NEW+'/'+n]=read(HERE/n)
 rows={n:pin(raw) for n,raw in blobs.items()}
 deps=encoded(dict(schema_version=1,files=rows));blobs[NEW+'/dependencies.json']=deps;rows[NEW+'/dependencies.json']=pin(deps)
 manifest=encoded(dict(schema_version=1,status='ROOT_FROZEN_SOURCE_ONLY',files=rows,scope='PUBLIC_PAIRS_APPS6_ONE_PROFILE_NOT_FULL60416K',native='NOT_RUN',hardware='NOT_RUN'))
 blobs[NEW+'/source-manifest.json']=manifest
 raw=blobs['.github/workflows/native-arm-current604-apps6-generic16k.yml'];blobs[WF]=workflow(raw,blobs,rows[NEW+'/ci.py']['sha256'],pin(manifest)['sha256'])
 output.mkdir(mode=0o700)
 for n,raw in blobs.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
 result=dict(status='SOURCE_ONLY_PUBLIC_PAIRS_APPS6_CURRENT604_PROFILE16K_UNBOUND',source_rows=len(rows),workflow=pin(blobs[WF]),profiles=['minimal','overlay'],native='UNBOUND',fresh='UNBOUND',GUI='UNBOUND_SEPARATE_PUBLIC_COMPONENT',full60416K='NOT_ACCEPTED',hardware='NOT_RUN')
 (output/'source-emission.json').write_bytes(encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','installer','assets','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.installer.absolute(),a.assets.absolute(),a.output.absolute()),sort_keys=True))
