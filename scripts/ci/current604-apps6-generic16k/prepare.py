#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit a finite Apps6-only604 profile16K overlay; no kernel, GUI or VM actors."""
import argparse,hashlib,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/expanded604-current-management-profile16k';NEW='scripts/ci/current604-apps6-generic16k'
COMPOSITION='scripts/ci/expanded604-apps6';INSTALLER='scripts/ci/expanded604-apps6-installer'
OWN=('contract.py','adapter.py','ci.py','gate.py','retain.py','context604.py','install604.py','prepare.py','test_lane.py','README.md','source-pins.json','input-policy.json')
WF='.github/workflows/native-arm-current604-apps6-generic16k.yml'
def need(v,why):
 if not v:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def read(path):
 need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary source required');info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=16*1024**2,'bounded single-link source');raw=path.read_bytes();need(len(raw)==info.st_size,'source length drift');return raw

def workflow(raw,ci_sha,mf_sha):
 text=raw.decode().replace('expanded604-current-management-profile16k','current604-apps6-generic16k')
 def r(a,b,count=1):
  nonlocal text
  need(text.count(a)==count,'exact Apps6 WF anchor: '+a[:70]);text=text.replace(a,b)
 r('37416eeef5941935f9f043419c9d98ecccf3ea94ef537ae504f9422eb128b12f',ci_sha);r('15ef4311cb1b52636424714b1be1caa5f25d2b252e9af8081981258f5503baab',mf_sha)
 r('      - name: Checkout the exact current Welcome4 GUI decision and public inputs', '''      - name: Checkout the new Apps6 fresh604 Root decision
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ steps.managed_policy.outputs.fresh604_decisions }}
          path: expanded604-apps6-fresh604-decisions
          persist-credentials: false
      - name: Checkout the exact Apps6 accepted public carrier
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ steps.managed_policy.outputs.apps6_source }}
          path: expanded604-apps6-inputs
          persist-credentials: false
      - name: Checkout the exact Apps6 native source guards
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ steps.managed_policy.outputs.apps6_native_source }}
          path: expanded604-apps6-native
          persist-credentials: false
      - name: Checkout the exact current Welcome4 GUI decision and public inputs''')
 r('--native604-decisions "$GITHUB_WORKSPACE/expanded604-native604-decisions" \\', '--native604-decisions "$GITHUB_WORKSPACE/expanded604-native604-decisions" \\\n            --fresh604-decisions "$GITHUB_WORKSPACE/expanded604-apps6-fresh604-decisions" \\',3)
 r('--welcome-source "$GITHUB_WORKSPACE/expanded604-welcome-source/payload" \\', '--welcome-source "$GITHUB_WORKSPACE/expanded604-welcome-source/payload" \\\n            --apps6-source "$GITHUB_WORKSPACE/expanded604-apps6-inputs/payload" --apps6-native-source "$GITHUB_WORKSPACE/expanded604-apps6-native" \\',2)
 r('-p test_profile.py -v','-p test_lane.py -v');return text.encode()

def emit(source,composition,installer,output):
 need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary source output')
 spec=json.loads(read(HERE/'source-pins.json'));rows={};blobs={}
 def add(root,n,row):
  raw=read(root/n);need(pin(raw)==row,'pinned Apps6 profile source differs: '+n)
  if n in rows:need(rows[n]==row and blobs[n]==raw,'conflicting support source: '+n)
  rows[n]=row;blobs[n]=raw;need(len(rows)<=500,'source closure512 bound reserved for manifest')
 for n,row in spec['files'].items():
  raw=read(source/n);need(pin(raw)==row,'exact original706 source provenance: '+n)
  # Its bound local policy/manifest are provenance, never runtime authority or
  # required historical-file overwrites. New modules already contain the
  # narrow profile adaptations and read only their own UNBOUND policy.
  if not n.startswith(OLD+'/') and n!='.github/workflows/native-arm-expanded604-current-management-profile16k.yml':add(source,n,row)
 for root,prefix in ((composition,COMPOSITION),(installer,INSTALLER)):
  manifest=json.loads(read(root/prefix/'source-manifest.json'));need(manifest['status']=='FROZEN_ROOT_FINAL_SOURCE' and 1<=len(manifest['files'])<=512,'Root composition/fresh source closure required')
  for n,row in manifest['files'].items():add(root,n,row)
  add(root,prefix+'/source-manifest.json',pin(read(root/prefix/'source-manifest.json')))
 for n,row in spec['apps6_sources'].items():add(composition,n,row)
 for name in OWN:
  n=NEW+'/'+name;raw=read(HERE/name);need(n not in rows,'own namespace collision');rows[n]=pin(raw);blobs[n]=raw
 need(len(rows)+1<=512,'complete profile source512 bound')
 dependencies=encoded(dict(schema_version=1,files=rows));rows[NEW+'/dependencies.json']=pin(dependencies);blobs[NEW+'/dependencies.json']=dependencies
 output.mkdir(mode=0o700)
 for n,raw in blobs.items():path=output/n;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
 manifest=encoded(dict(schema_version=1,status='ROOT_FROZEN_SOURCE_ONLY',files=rows,native='NOT_RUN',hardware='NOT_RUN',scope='APPS6_SINGLE_PROFILE_NO_NATIVE_FRESH_GUI_OR_16K_CREDIT'))
 (output/NEW/'source-manifest.json').write_bytes(manifest)
 raw=read(source/'.github/workflows/native-arm-expanded604-current-management-profile16k.yml');wf=workflow(raw,rows[NEW+'/ci.py']['sha256'],pin(manifest)['sha256']);path=output/WF;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(wf)
 return dict(status='SOURCE_ONLY_APPS6_CURRENT604_PROFILE16K_UNBOUND',source_rows=len(rows),workflow=pin(wf),target604_sha256='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3',profiles=['minimal','overlay'],native='NOT_RUN',fresh='UNBOUND',GUI='PUBLICATION_APPROVAL_HELD',full60416K='NOT_ACCEPTED',hardware='NOT_RUN')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','composition','installer','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.composition.absolute(),a.installer.absolute(),a.output.absolute()),sort_keys=True))
