#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit separate whole-held604/tools roles and the finite606 lane; no Git/actors."""
import argparse,hashlib,json,shutil,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;LANE='scripts/ci/current606-native';OLD='scripts/ci/expanded604-apps6-public-pairs'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(p):
 raw=p.read_bytes();return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(p,v):p.write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
def copyrole(source,output,filename):
 rows=json.loads((HERE/filename).read_bytes())
 for name,row in rows.items():
  p=source/name;need(not any(q.is_symlink()for q in(p,*p.parents))and p.is_file()and pin(p)==row,'whole held role differs: '+name)
 for name in rows:p=output/name;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,p)
 return rows

def workflow(raw,runpin,mfpin):
 text=raw.decode();need(text.count('native-arm-expanded604-apps6-public-pairs')==2,'exact dedicated identity seams');text=text.replace('native-arm-expanded604-apps6-public-pairs','native-arm-current606-dns-sysctl2')
 text=text.replace('expanded604-code/scripts/','expanded604-code/held604/scripts/').replace('"$GITHUB_WORKSPACE/expanded604-code"','"$GITHUB_WORKSPACE/expanded604-code/held604"')
 for file in('run.py','gate.py'):text=text.replace('expanded604-code/held604/'+OLD+'/'+file,'expanded604-code/'+LANE+'/'+file)
 # Keep the historical source gate; add a whole new lane hash pair before its first command.
 marker='          set -euo pipefail\n';at=text.index(marker,text.index('id: policy604'));insertion="          printf '%s  %s\\n' '"+runpin+"' 'expanded604-code/"+LANE+"/run.py' '"+mfpin+"' 'expanded604-code/"+LANE+"/source-manifest.json' | sha256sum --check\n";text=text[:at]+text[at:].replace(marker,marker+insertion,1)
 # The old run hash refers to held source; the actual entry is separately hashed above.
 text=text.replace('sha256sum expanded604-code/'+LANE+'/run.py','sha256sum expanded604-code/held604/'+OLD+'/run.py')
 text=text.replace('          python3 -I -B expanded604-code/held604/'+OLD+'/test_lane.py','          python3 -B -m unittest discover -s expanded604-code/'+LANE+' -p test_lane.py')
 text=text.replace('Required signed604 dependency and restoration lifecycle','Required signed604 plus606 additions and restoration lifecycle')
 return text

def emit(base,tools,output,selection=None,metadata_source=None):
 need(output.is_absolute()and not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in(output,*output.parents)),'fresh ordinary source')
 p=json.loads((HERE/'default-input-policy.json').read_bytes());need(p['status']=='UNBOUND_SOURCE_TEMPLATE'and p['authorities']is p['base_source']is p['recipe_source']is None,'held NULL template')
 sys.path.insert(0,str(HERE));import contract as C
 rows=C.metadata();need(metadata_source is not None and metadata_source.is_dir()and not any(q.is_symlink()for q in(metadata_source,*metadata_source.parents)),'explicit b015 metadata source required')
 need({q.relative_to(metadata_source).as_posix()for q in metadata_source.rglob('*')if q.is_file()}==set(rows),'exact47 metadata input closure')
 for n,row in rows.items():C.checked(metadata_source/n,row)
 if selection is not None:
  sys.path.insert(0,str(HERE));import contract as C
  need(set(selection)=={'base_source','recipe_source','authorities'}and selection['base_source']==C.BASE and selection['recipe_source']==C.RECIPES,'explicit exact Root source selection');C.authorities(selection['authorities']);p.update(selection,status='ROOT_BOUND_ACCEPTED604_DNS2_SYSCTL2')
 # All held/source checks occur before copying any output.
 for root,filename in((base,'base-pins.json'),(tools,'build-pins.json')):
  for n,row in json.loads((HERE/filename).read_bytes()).items():need(pin(root/n)==row and not any(q.is_symlink()for q in(root/n,*(root/n).parents)),'held source byte drift')
 for role,product in p['products'].items():
  root=tools/product['recipe'];need({q.name for q in root.iterdir()}==set(product['source_files']),'flat exact recipe closure')
  for n,row in product['source_files'].items():need(pin(root/n)==row and not(root/n).is_symlink(),'exact recipe source')
 output.mkdir(mode=0o700);copyrole(base,output/'held604','base-pins.json');copyrole(tools,output/'held-tools','build-pins.json')
 for n in rows:
  dest=output/'held604'/n;need(not dest.exists(),'metadata cannot replace original151 source');dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(metadata_source/n,dest)
 for role in p['products']:shutil.copytree(tools/'packages/tools'/role,output/'held-tools/packages/tools'/role)
 lane=output/LANE;lane.mkdir(parents=True)
 for f in HERE.iterdir():
  if f.is_file()and f.name not in('input-policy.json','source-manifest.json'):shutil.copyfile(f,lane/f.name)
 save(lane/'input-policy.json',p);files={f.relative_to(output).as_posix():pin(f)for f in sorted(output.rglob('*'))if f.is_file()};save(lane/'source-manifest.json',dict(schema_version=1,status='SOURCE_ONLY606_NOT_ACTUAL',files=files,native='NOT_RUN',hardware='NOT_RUN'))
 text=workflow((base/'.github/workflows/native-arm-build.yml').read_bytes(),pin(lane/'run.py')['sha256'],pin(lane/'source-manifest.json')['sha256']);wf=output/'.github/workflows/native-arm-current606-dns-sysctl2.yml';wf.parent.mkdir(parents=True);wf.write_text(text);shutil.copyfile(wf,wf.with_name('native-arm-build.yml'))
 return dict(schema_version=1,status='SOURCE_ONLY606_NOT_ACTUAL',files={f.relative_to(output).as_posix():pin(f)for f in sorted(output.rglob('*'))if f.is_file()},actual_source=None,actual_ref=None,actual_run=None)
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--base604-source',type=Path,required=True);a.add_argument('--tools-source',type=Path,required=True);a.add_argument('--base604-metadata-source',type=Path,required=True);a.add_argument('--output',type=Path,required=True);a.add_argument('--authorization',type=Path,required=True);a.add_argument('--selection',type=Path);v=a.parse_args();save(v.authorization,emit(v.base604_source.absolute(),v.tools_source.absolute(),v.output.absolute(),None if v.selection is None else json.loads(v.selection.read_bytes()),v.base604_metadata_source.absolute()))
