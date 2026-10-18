#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact KSM source roles and a NULL default owner; no Git or actors."""
import argparse,json,re,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

def workflow(raw,root,policy):
 text=raw.decode();old='native-arm-current606-dns-sysctl2';C.need(text.count(old)==2,'two dedicated identity seams');text=text.replace(old,'native-arm-current606-ksm2-owned-copy')
 text=text.replace('expanded604-code/','expanded604-code/held606/').replace('CURRENT604_NATIVE_SOURCE: ${{ github.workspace }}/expanded604-code','CURRENT604_NATIVE_SOURCE: ${{ github.workspace }}/expanded604-code/held606');lane='expanded604-code/'+C.LANE
 marker='          set -euo pipefail\n';at=text.index(marker,text.index('id: policy604'))
 insert="          printf '%s  %s\\n' '"+C.pin((root/C.LANE/'owner.py').read_bytes())['sha256']+"' '"+lane+"/owner.py' '"+C.pin((root/C.LANE/'source-manifest.json').read_bytes())['sha256']+"' '"+lane+"/source-manifest.json' | sha256sum --check\n          python3 -B "+lane+"/owner.py --source-preflight\n          python3 -B "+lane+"/owner.py --require-selection\n"
 text=text[:at]+text[at:].replace(marker,marker+insert,1)
 command='python3 -B "'+ '$GITHUB_WORKSPACE/'+lane+'/owner.py"'
 text=text.replace('python3 -B "$GITHUB_WORKSPACE/expanded604-code/held606/scripts/ci/current606-native/run.py"',command)
 C.need(text.count(command)==1,'one actual closed owner CLI');text=text.replace(command,command+' --ksm-packet "$GITHUB_WORKSPACE/ksm2-native-pairs"')
 text=text.replace('sha256sum '+lane+'/owner.py','sha256sum expanded604-code/held606/scripts/ci/current606-native/run.py')
 marker='      - name: Checkout fixed legacy public input source';C.need(text.count(marker)==1,'one public source seam')
 commands="      - name: Check KSM copy source and NULL authority before actors\n        run: |\n          python3 -B "+lane+"/owner.py --source-preflight\n          python3 -B "+lane+"/owner.py --require-selection\n"
 if policy['native_pair_source']is not None:
  commands+="      - name: Checkout exact published KSM native input DATA\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: "+policy['native_pair_source']+"\n          path: ksm2-native-pairs\n          persist-credentials: false\n      - name: Verify exact accepted KSM pair before secrets\n        run: python3 -B "+lane+"/owner.py --native-inputs --ksm-packet \"$GITHUB_WORKSPACE/ksm2-native-pairs\"\n"
 return text.replace(marker,commands+marker)

def emit(inputs,output,selection=None,publication=None):
 C.need(set(inputs)==set(C.ROLES),'three explicit complete source roots');C.need(output.is_absolute()and output.parent.is_dir()and not output.exists()and not any(p.is_symlink()for p in(output,*output.parents)),'fresh ordinary output')
 rows=C.read(C.HERE/'source-pins.json')
 for role,home in inputs.items():
  C.need(home.is_absolute()and home.is_dir()and not any(p.is_symlink()for p in(home,*home.parents)),'ordinary source root');wanted=rows[role]['files'];C.need(C.files(home)==set(wanted),'whole role closure')
  for n,row in wanted.items():C.checked(home/n,row)
 policy=C.read(C.HERE/'null-policy.json');C.need(policy['status']=='UNBOUND_SOURCE_TEMPLATE'and all(v is None for v in policy['current606'].values())and policy['native_pair_source']is policy['native_pair_index']is None,'default authority NULL')
 source=None
 if selection is not None:
  pins=C.read(inputs['copyworker']/'scripts/ci/current606-ksm2-copy/prerequisite-pins.json')
  C.need(type(publication)is dict and publication.get('status')=='PUBLISHED_VERIFIED_REMOTE'and re.fullmatch('[0-9a-f]{40}',publication.get('source')or'')and publication.get('index')==pins['index']and publication.get('files')==pins['files'],'Root exact public carrier publication required')
  C.need(selection.get('native_pair_source')==publication['source']and selection.get('native_pair_index')==pins['index'],'source-bound public tuple')
  import selection as S
  old=(S.PAIR_SOURCE,S.PAIR_INDEX);S.PAIR_SOURCE,S.PAIR_INDEX=publication['source'],pins['index']
  try:policy=C.authorize(selection)
  finally:S.PAIR_SOURCE,S.PAIR_INDEX=old
  source=publication['source']
 output.mkdir(mode=0o700)
 for role,home in inputs.items():
  for n in rows[role]['files']:
   p=output/role/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(home/n,p)
 lane=output/C.LANE;lane.mkdir(parents=True)
 for p in C.HERE.iterdir():
  if p.is_file()and p.name not in('input-policy.json','source-manifest.json'):shutil.copyfile(p,lane/p.name)
 if source is not None:
  p=lane/'selection.py';text=p.read_text();C.need(text.count('PAIR_SOURCE=None')==text.count('PAIR_INDEX=None')==1,'finite public identity seams');p.write_text(text.replace('PAIR_SOURCE=None','PAIR_SOURCE='+repr(source)).replace('PAIR_INDEX=None','PAIR_INDEX='+repr(policy['native_pair_index'])))
  raw=(lane/'selection.py').read_bytes();api=dict(path='/runner/owner/selection.py',**C.pin(raw));(output/'copyworker/scripts/ci/current606-ksm2-copy/owner-api.json').write_bytes(C.encoded(api));(output/'bridge/scripts/ci/current606-welcome5-source-bridge/owner-api.json').write_bytes(C.encoded(dict(path=api['path'],pin=C.pin(raw))))
 (lane/'input-policy.json').write_bytes(C.encoded(policy))
 # A publication binding changes only explicit source-owned API pins/metadata.
 from metadata import refresh
 refresh(output)
 return {p.relative_to(output).as_posix():C.pin(p.read_bytes())for p in sorted(output.rglob('*'))if p.is_file()}
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in C.ROLES:p.add_argument('--'+n+'-source',type=Path,required=True)
 for n in('selection','publication'):p.add_argument('--'+n,type=Path)
 p.add_argument('--output',type=Path,required=True);p.add_argument('--authorization',type=Path,required=True);a=p.parse_args()
 C.need(not a.authorization.exists(),'fresh authorization');a.authorization.write_bytes(C.encoded(emit({n:getattr(a,n+'_source').absolute()for n in C.ROLES},a.output.absolute(),None if a.selection is None else C.read(a.selection),None if a.publication is None else C.read(a.publication))))
