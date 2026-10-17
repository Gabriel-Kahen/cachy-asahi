# SPDX-License-Identifier: MIT
"""Finite data preparation for a signed604 cache, with no builder/guest actors."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def verify(source,runner):
    C=load('_managed604_cache_contract',source/'scripts/ci/expanded604-apps6-public-pairs/contract.py')
    manifest,ref,expected=C.target_manifest(runner/'ready604')
    receipt=C.read(runner/'context604.json')
    C.need(receipt['manifest']==ref and receipt['expected604_sha256']==C.TARGET_SHA,'staged604 cache binding differs')
    context=runner/'install-context'
    C.need({p.relative_to(context).as_posix() for p in context.rglob('*') if not p.is_dir()}=={r['path'] for r in receipt['context_files']},'closed install context differs')
    for row in receipt['context_files']:C.checked(context,row,256*1024**2)
    return manifest,expected

def selection(base,expected):
    """Keep573 original packages; replace only the pinned upstream FDK provider."""
    def need(ok,why):
        if not ok:raise ValueError(why)
    raw=lambda rows:''.join(n+' '+v+'\n' for n,v in sorted(rows.items())).encode()
    need(len(base)==574 and hashlib.sha256(raw(base)).hexdigest()=='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac','exact original574 inventory required')
    need(len(expected)==604 and hashlib.sha256(raw(expected)).hexdigest()=='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3','exact Apps6 target604 inventory required')
    need(base.keys()-expected.keys()=={'libfdk-aac'} and base['libfdk-aac']=='3.0.0-1' and expected.get('cachy-asahi-fdk-aac')=='3.0.0-1' and all(expected.get(n)==v for n,v in base.items() if n!='libfdk-aac'),'sole FDK replacement and573 unchanged packages required')
    incoming=expected.keys()-base.keys();need(len(incoming)==31,'exact31 incoming packages required')
    return incoming

def prepare(source,runner,ready):
    C=load('_managed604_staging_contract',source/'scripts/ci/expanded604-apps6-public-pairs/contract.py')
    manifest,ref,expected=C.target_manifest(ready)
    original=C.read(source/'scripts/ci/maintained-desktop574-inputs.json')
    base={r['name']:r['version'] for r in original['packages']}
    selected=selection(base,expected)
    incoming=[r for r in manifest['packages'] if r['name'] in selected];C.need(len(incoming)==31,'finite31 incoming packages required')
    C.need(not (runner/'ready604').exists(),'fresh owned604 bundle location required')
    shutil.move(str(ready),runner/'ready604');ready=runner/'ready604'
    context=runner/'install-context';context.mkdir(mode=0o700);bundle=context/'bundle';(bundle/'packages').mkdir(parents=True);(bundle/'keys').mkdir()
    for name in ('manifest.json','expected-installed.lock'):shutil.copyfile(ready/name,bundle/name)
    for row in manifest['keyrings']:shutil.copyfile(ready/row['path'],bundle/row['path'])
    checks=load('_managed604_package_checks',source/'scripts/checks/package_checks.py');payload=[]
    for row in incoming:
        for key in ('archive','signature'):shutil.copyfile(ready/row[key],bundle/row[key])
        report=checks.package(ready/row['archive']);C.need(report['sha256']==row['sha256'],'actual incoming archive identity differs')
        # Full604 materializer has independently validated each official/project archive;
        # retain every original member including complete numeric owner/mode/hash metadata.
        payload.append(dict(name=row['name'],version=row['version'],payload={n:r for n,r in report['members'].items() if r['type']!='5' and n not in ('.PKGINFO','.BUILDINFO','.MTREE')}))
    (context/'incoming.json').write_bytes(C.encoded(payload))
    for name in ('contract.py','lifecycle.py'):
        target=context/'code/scripts/ci/expanded604-apps6-public-pairs'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/'scripts/ci/expanded604-apps6-public-pairs'/name,target)
    target=context/'code/scripts/ci/full-root-upgrade/root_upgrade.py';target.parent.mkdir(parents=True);shutil.copyfile(source/'scripts/ci/full-root-upgrade/root_upgrade.py',target)
    for name in ('install604.py','context604.py'):shutil.copyfile(Path(__file__).with_name(name),context/name)
    rows=[]
    for p in sorted(context.rglob('*')):
        if p.is_file():rows.append(dict(path=p.relative_to(context).as_posix(),bytes=p.stat().st_size,sha256=C.sha(p)))
    C.need(len(rows)<=128,'finite604 context file count')
    (runner/'context604.json').write_bytes(C.encoded(dict(schema_version=1,manifest=ref,expected604_sha256=C.TARGET_SHA,context_files=rows)))
    desktop=next(r for r in incoming if r['name']=='cachy-asahi-hyprland-settings')
    (runner/'desktop-archive.json').write_bytes(C.encoded(dict(name=Path(desktop['archive']).name,sha256=desktop['sha256'])))
    verify(source,runner)
