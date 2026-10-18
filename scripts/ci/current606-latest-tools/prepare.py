#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit whole historical roles, bounded joint worker/owner and NULL defaults."""
import argparse,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

def workflow(root):
 text=(root/'historical/welcome/.github/workflows/native-arm-build.yml').read_text();text=text.replace('native-arm-current606-welcome5-owned-copy','native-arm-current606-latest-tools-owned-copy')
 text=text.replace('expanded604-code/','expanded604-code/historical/welcome/')
 old='$GITHUB_WORKSPACE/expanded604-code/historical/welcome/scripts/ci/current606-welcome5-closed-owner/owner.py'
 actual='$GITHUB_WORKSPACE/expanded604-code/'+C.LANE+'/owner.py'
 C.need(text.count(old)==1,'one original actual c06 owner entry');text=text.replace(old,actual+'" --apps-packet "$GITHUB_WORKSPACE/apps7-native-pairs')
 marker='      - name: Checkout fixed legacy public input source';C.need(text.count(marker)==1,'one original prerequisite checkout seam')
 entry='expanded604-code/'+C.LANE
 insert='''      - name: Checkout exact public Apps7 and Runtime native pairs
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: 54352850a57a7e34e75c3a021fa20525eee59bf6
          path: apps7-native-pairs
          persist-credentials: false
      - name: Complete joint source and future qualification before secrets
        run: |
'''
 insert+='          printf \'%s  %s\\n\' \''+C.pin((root/C.LANE/'owner.py').read_bytes())['sha256']+"' '"+entry+"/owner.py' '"+C.pin((root/C.LANE/'source-manifest.json').read_bytes())['sha256']+"' '"+entry+"/source-manifest.json' | sha256sum --check\n"
 insert+='          python3 -I -B '+entry+'/owner.py --source-preflight\n          python3 -I -B '+entry+'/test_source.py\n          python3 -I -B '+entry+'/owner.py --require-selection\n          python3 -I -B '+entry+'/owner.py --native-inputs --apps-packet "$GITHUB_WORKSPACE/apps7-native-pairs"\n'
 return text.replace(marker,insert+marker)

def emit(*,apps,welcome,worker,bridge,output,qualification=None):
 C.need(output.is_absolute()and not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in(output,*output.parents)),'fresh ordinary source output')
 pins=C.read(C.HERE/'historical-pins.json');implementation=C.read(C.HERE/'implementation-pins.json')
 for name,root in [('apps',apps),('welcome',welcome)]:C.need(C.files(root)==pins[name],'entire committed historical role before output')
 for name,root in [('worker',worker),('bridge',bridge)]:C.need(C.files(root)==implementation[name],'entire source-owned implementation before output')
 policy=C.read(C.HERE/'null-policy.json');C.need(policy['status']=='UNBOUND_JOINT_SOURCE_TEMPLATE'and policy['joint_decisions']=={'apps606':None,'welcome606':None},'NULL future decision default')
 selection=(C.HERE/'selection-template.py').read_text()
 if qualification is not None:
  C.need(selection.count('EXPECTED_JOINT = None')==1,'one exact immutable qualification constant');selection=selection.replace('EXPECTED_JOINT = None','EXPECTED_JOINT = '+repr(qualification));ns={};exec(compile(selection,'<source-bound qualification>','exec'),ns);ns['_joint']({'joint_decisions':qualification});policy.update(status='ROOT_BOUND_CURRENT606_LATEST_TOOLS_INPUTS',joint_decisions=qualification)
 output.mkdir(mode=0o700)
 for name,root in [('historical/apps',apps),('historical/welcome',welcome),('worker',worker),('bridge',bridge)]:shutil.copytree(root,output/name,ignore=shutil.ignore_patterns('.git'))
 lane=output/C.LANE;lane.mkdir(parents=True)
 for p in C.HERE.iterdir():
  if p.is_file()and p.name not in('input-policy.json','source-manifest.json'):shutil.copyfile(p,lane/p.name)
 (lane/'selection.py').write_text(selection);(lane/'input-policy.json').write_bytes(C.encoded(policy))
 api=C.pin((lane/'selection.py').read_bytes());(output/'worker/scripts/ci/current606-latest-tools-copy/owner-api.json').write_bytes(C.encoded(dict(path='/runner/owner/selection.py',**api)))
 (output/'bridge/scripts/ci/current606-welcome5-source-bridge/owner-api.json').write_bytes(C.encoded(dict(path='/runner/owner/selection.py',pin=api)))
 (lane/'implementation-pins.json').write_bytes(C.encoded({name:C.files(output/name)for name in('worker','bridge')}))
 (lane/'source-manifest.json').write_bytes(C.encoded(dict(schema_version=1,status='SOURCE_ONLY_JOINT_LATEST_TOOLS_NOT_NATIVE',actual_source=None,actual_ref=None,actual_run=None,files=C.files(output))))
 text=workflow(output);wf=output/'.github/workflows/native-arm-current606-latest-tools-owned-copy.yml';wf.parent.mkdir(parents=True);wf.write_text(text);shutil.copyfile(wf,wf.with_name('native-arm-build.yml'))
 return C.files(output)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('apps','welcome','worker','bridge'):p.add_argument('--'+n,required=True,type=Path)
 p.add_argument('--qualification',type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--authorization',required=True,type=Path);a=p.parse_args()
 a.authorization.write_bytes(C.encoded(emit(**{n:getattr(a,n).absolute()for n in('apps','welcome','worker','bridge')},output=a.output.absolute(),qualification=None if a.qualification is None else C.read(a.qualification))))
