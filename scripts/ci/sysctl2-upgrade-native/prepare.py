#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit finite native same-package upgrade source; optional real Git recipe binding."""
import argparse,hashlib,json,re,shutil,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent;LANE='scripts/ci/sysctl2-upgrade-native'
ROLES=('cachy-asahi-sysctl','cachy-asahi-sysctl2')
def need(ok,why):
 if not ok:raise ValueError(why)
def row(p):return dict(bytes=p.stat().st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
def save(p,v):p.write_text(json.dumps(v,sort_keys=True,indent=2)+'\n')
def prepare(source,output,recipes,refs=None):
 need(not output.exists()and output.is_absolute()and source.is_absolute()and output.parent.is_dir()and not any(p.is_symlink()for p in(output,*output.parents,source,*source.parents)),'fresh ordinary source/output')
 refs=refs or dict.fromkeys(ROLES);need(set(refs)==set(ROLES)and (all(v is None for v in refs.values())or all(re.fullmatch('[0-9a-f]{40}',v or '')for v in refs.values())),'both real recipe refs or both NULL')
 pins=json.loads((HERE/'original-pins.json').read_bytes());policy=json.loads((HERE/'input-policy.json').read_bytes())
 for n,r in pins.items():need(row(source/n)==r and not any(p.is_symlink()for p in(source/n,*(source/n).parents)),'whole original source pin: '+n)
 for role,recipe in zip(ROLES,recipes):
  expected=policy['products'][role]['source_files'];need({p.name for p in recipe.iterdir()}==set(expected)and all(p.is_file()and not p.is_symlink()and row(p)==expected[p.name]for p in recipe.iterdir()),'exact closed recipe8 source')
  if refs[role]:
   for n,r in expected.items():
    raw=subprocess.check_output(['git','-C',str(source),'show',refs[role]+':packages/tools/'+role+'/'+n],timeout=20);need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==r,'genuine recipe Git source differs')
 output.mkdir(mode=0o700)
 for n in pins:
  target=output/n;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/n,target)
 for role,recipe in zip(ROLES,recipes):shutil.copytree(recipe,output/'packages/tools'/role)
 target=output/LANE;target.mkdir(parents=True)
 for p in HERE.iterdir():
  if p.is_file()and p.name not in('input-policy.json','source-manifest.json','infrastructure-pins.json'):shutil.copyfile(p,target/p.name)
 policy.update(status='ROOT_BOUND_FINAL_VERSION_SOURCES'if refs[ROLES[0]]else'UNBOUND_SOURCE_TEMPLATE',recipe_sources=refs,actual_source=None,actual_ref=None,actual_run=None);save(target/'input-policy.json',policy);save(target/'infrastructure-pins.json',pins)
 workflow=output/'.github/workflows/native-arm-sysctl2-upgrade.yml';workflow.parent.mkdir(parents=True);text=(target/'workflow.yml.in').read_text()
 files={p.relative_to(output).as_posix():row(p)for p in output.rglob('*')if p.is_file()};need(len(files)<=128,'bounded original source manifest cap');save(target/'source-manifest.json',dict(schema_version=1,scope='SYSCTL_SAME_PACKAGE1_TO2_SIGNED_PRIVATE_MODEL_UPGRADE',native='NOT_RUN',files=files))
 for marker,path in(('@JOB_SHA256@',target/'job.py'),('@MANIFEST_SHA256@',target/'source-manifest.json')):need(text.count(marker)==1,'one exact workflow stamp');text=text.replace(marker,row(path)['sha256'])
 workflow.write_text(text);shutil.copyfile(workflow,workflow.with_name('native-arm-build.yml'))
 auth=dict(status='SOURCE_ONLY_NO_ACTUAL_AUTHORITY',source=None,ref=None,run_id=None,recipe_sources=refs,files={p.relative_to(output).as_posix():row(p)for p in sorted(output.rglob('*'))if p.is_file()},native='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED');save(output.parent/(output.name+'-authorization.json'),auth)
 return dict(status='SOURCE_ONLY_CLOSED',source_files=len(auth['files']),manifest_files=len(files),builders=4,consumers=6,recipe_sources=refs,actual_source=None,actual_ref=None,actual_run=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('source','output','baseline-recipe','candidate-recipe'):p.add_argument('--'+n,type=Path,required=True)
 for n in('baseline-source','candidate-source'):p.add_argument('--'+n)
 a=p.parse_args();print(json.dumps(prepare(a.source.absolute(),a.output.absolute(),[a.baseline_recipe.absolute(),a.candidate_recipe.absolute()],dict(zip(ROLES,[a.baseline_source,a.candidate_source]))),sort_keys=True))
