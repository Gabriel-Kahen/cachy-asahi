#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Exact client-v3 sources, unchanged Runtime1 dependency and owned payload DATA."""
import argparse,hashlib,json,re,shlex,stat
from pathlib import Path
PACKAGE='cachy-asahi-repository-client-v3';VERSION='0.1.0-1';PREFIX='usr/share/cachy-asahi/repository-runtime/'
HELPER={'bytes':29503,'sha256':'4cf428452d08ea212d8bb92d899329f3445d15877c5b79e5ff5f138b0a696e76'}
RUNTIME={'scripts/client/client.py':{'bytes':28669,'sha256':'48f936fc28536f8d5c2cac25c77ddb591b6bd029062d4b4fe2ce901533e8fdb7'},'scripts/release/release.py':{'bytes':41320,'sha256':'e4ab44f7cc020ae1d705b64362e8b1b05fa0c29c19ce64d886116055619c0435'},'scripts/release/source_delivery.py':{'bytes':16456,'sha256':'8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e'}}

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def ordinary(path):
 p=Path(path);s=p.lstat();need(not p.is_symlink()and stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=4*1024**2,'ordinary bounded source');return p.read_bytes()
def payload():
 rows={PREFIX+'scripts/client/client_v3.py':('client_v3.py',0o644),'usr/bin/cachy-asahi-repository-client':('cachy-asahi-repository-client',0o755)}
 for n in('README.md','source-provenance.json','helper-pins.json'):rows['usr/share/doc/'+PACKAGE+'/'+n]=(n,0o644)
 for n in('NOTICE','LICENSE'):rows['usr/share/licenses/'+PACKAGE+'/'+n]=(n,0o644)
 return rows

def check(root,stage=None,canonical_root=None,runtime_recipe=None):
 root=Path(root);recipe=ordinary(root/'PKGBUILD').decode();names=shlex.split(re.search(r'^source=\((.*?)\)',recipe,re.M|re.S)[1]);sums=shlex.split(re.search(r'^sha256sums=\((.*?)\)',recipe,re.M|re.S)[1]);need(len(names)==len(sums)==len(set(names))==11,'exact eleven local sources')
 for n,w in zip(names,sums):
  need(Path(n).name==n and re.fullmatch('[a-f0-9]{64}',w),'safe local source/digest');raw=ordinary(root/n);need(pin(raw)['sha256']==w,'package source differs: '+n)
  if n.endswith('.py')or n=='cachy-asahi-repository-client':compile(raw,n,'exec')
 pins=json.loads(ordinary(root/'helper-pins.json'));need(pins==dict(schema_version=1,files={'scripts/client/client_v3.py':HELPER},required_runtime=dict(package='cachy-asahi-repository-runtime',version='0.1.0-1',files=RUNTIME)),'exact versioned helper/dependency route');need(pin(ordinary(root/'client_v3.py'))==HELPER,'exact current v3 source')
 info={}
 for line in ordinary(root/'.SRCINFO').decode().splitlines():
  if line.strip():k,v=line.strip().split(' = ',1);info.setdefault(k,[]).append(v)
 need(info['source']==names and info['sha256sums']==sums and info['pkgname']==[PACKAGE]and info['pkgver']==['0.1.0']and info['pkgrel']==['1']and info['arch']==['any']and info['license']==['MIT']and info['depends']==['python>=3.11','cachy-asahi-repository-runtime=0.1.0-1'],'exact package metadata and dependency');need(not list(root.glob('*.install'))and 'Permission is hereby granted'in ordinary(root/'LICENSE').decode(),'MIT/no install hooks')
 if canonical_root is not None:need(ordinary(Path(canonical_root)/'scripts/client/client_v3.py')==ordinary(root/'client_v3.py'),'canonical maintained v3/package byte join')
 if runtime_recipe is not None:
  for n,w in RUNTIME.items():need(pin(ordinary(Path(runtime_recipe)/Path(n).name))==w,'unchanged original Runtime1 source '+n)
 if stage is not None:
  stage=Path(stage);rows=payload();actual={p.relative_to(stage).as_posix()for p in stage.rglob('*')if p.is_file()or p.is_symlink()};need(actual==set(rows),'exact seven-file v3-only installed namespace')
  for n,(source,mode)in rows.items():p=stage/n;need(stat.S_IMODE(p.lstat().st_mode)==mode and ordinary(p)==ordinary(root/source),'exact staged v3 bytes/mode '+n)
 return dict(status='PASS_EXACT_CLIENT_V3_COMPANION_SOURCE_AND_PAYLOAD',source_files=11,owned_payload_files=7,runtime='0.1.0-1_UNCHANGED',stage='DATA_JOIN_PASS'if stage else'NOT_RUN',native_build='NOT_RUN',installed_ALPM_lifecycle='NOT_RUN',automatic_legacy_switch=False)

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--recipe-root',type=Path,default=Path(__file__).resolve().parent);p.add_argument('--stage',type=Path);p.add_argument('--canonical-root',type=Path);p.add_argument('--runtime-recipe-root',type=Path);a=p.parse_args();print(json.dumps(check(a.recipe_root,a.stage,a.canonical_root,a.runtime_recipe_root),sort_keys=True))
