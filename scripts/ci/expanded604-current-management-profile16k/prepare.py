#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit additive finite profile lane; no producer, kernel, GUI or VM actor."""
import argparse,hashlib,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/expanded604-current-management-managed16k';NEW='scripts/ci/expanded604-current-management-profile16k'
WF='.github/workflows/native-arm-expanded604-current-management-profile16k.yml'
def need(v,why):
 if not v:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def ordinary(path):
 need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary source required');s=path.stat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=16*1024**2,'bounded single-link source required');return path.read_bytes()
def emit(source,output):
 need(not output.exists() and output.parent.is_dir(),'fresh independent profile source output required')
 rows=json.loads(ordinary(HERE/'dependencies.json'))['files']
 for n,r in rows.items():
  original=HERE/n.removeprefix(NEW+'/') if n.startswith(NEW+'/') else source/n
  need(pin(ordinary(original))==r,'source differs: '+n)
 output.mkdir(mode=0o700)
 for n in rows:
  original=HERE/n.removeprefix(NEW+'/') if n.startswith(NEW+'/') else source/n
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(ordinary(original))
 lane=output/NEW;(lane/'dependencies.json').write_bytes(ordinary(HERE/'dependencies.json'))
 manifest=dict(schema_version=1,status='ROOT_FROZEN_SOURCE_ONLY',files=rows|{NEW+'/dependencies.json':pin(ordinary(lane/'dependencies.json'))},native='NOT_RUN',hardware='NOT_RUN',scope='ONE_PROFILE_NOT_FULL60416K_ACCEPTANCE')
 (lane/'source-manifest.json').write_bytes(encoded(manifest))
 text=ordinary(source/'.github/workflows/native-arm-expanded604-current-management-managed16k.yml').decode()
 text=text.replace('expanded604-current-management-managed16k','expanded604-current-management-profile16k')
 anchor='      mode:\n';need(text.count(anchor)==1,'one manual profile selector insertion')
 text=text.replace(anchor,'      profile:\n        description: Exactly one original full604 management profile; two separate accepted runs required\n        required: true\n        type: choice\n        options: [minimal, overlay]\n'+anchor)
 text=text.replace('  group: native-arm-expanded604-current-management-profile16k\n','  group: native-arm-expanded604-current-management-profile16k-${{ inputs.profile }}\n')
 text=text.replace('    env:\n      SOURCE_COMMIT:', '    env:\n      GUI_PROFILE: ${{ inputs.profile }}\n      SOURCE_COMMIT:')
 for name in ('gate.py','ci.py'):
  lines=text.splitlines(keepends=True)
  hits=0
  for i,line in enumerate(lines):
   if line.lstrip().startswith('python3 ') and ('/'+name+'"' in line or '/'+name+' ' in line):
    need(line.rstrip().endswith('\\'),'continued exact owner/gate invocation required');lines[i]=line.rstrip()+'\n            --profile "$GUI_PROFILE" \\\n';hits+=1
  need(hits==(3 if name=='gate.py' else 1),'all finite gate/owner profile arguments required');text=''.join(lines)
 original=json.loads(ordinary(source/OLD/'source-manifest.json'))
 for name,newraw in (('ci.py',ordinary(lane/'ci.py')),('source-manifest.json',ordinary(lane/'source-manifest.json'))):
  before=pin(ordinary(source/OLD/name))['sha256'];need(text.count(before)==1,'held workflow digest stamp');text=text.replace(before,pin(newraw)['sha256'])
 text=text.replace('-p test_lane.py -v','-p test_profile.py -v')
 # Role transport is distinct for each profile; identical producer/runtime caps held.
 text=text.replace('name: expanded604-current-management-profile16k-${{ github.run_id }}','name: expanded604-current-management-profile16k-${{ inputs.profile }}-${{ github.run_id }}')
 path=output/WF;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
 return dict(status='SOURCE_ONLY_CURRENT604_PROFILE16K_UNBOUND',files=len(manifest['files']),workflow=pin(text.encode()),profiles=['minimal','overlay'],native='NOT_RUN',full60416K='NOT_ACCEPTED')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.output.absolute()),sort_keys=True))
