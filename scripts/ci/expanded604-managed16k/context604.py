# SPDX-License-Identifier: MIT
"""Finite data preparation for a signed604 cache, with no builder/guest actors."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def verify(source,runner):
    C=load('_managed604_cache_contract',source/'scripts/ci/expanded604-composition/contract.py')
    manifest,ref,expected=C.target_manifest(runner/'ready604')
    receipt=C.read(runner/'context604.json')
    C.need(receipt['manifest']==ref and receipt['expected604_sha256']==C.TARGET_SHA,'staged604 cache binding differs')
    context=runner/'install-context'
    C.need({p.relative_to(context).as_posix() for p in context.rglob('*') if not p.is_dir()}=={r['path'] for r in receipt['context_files']},'closed install context differs')
    for row in receipt['context_files']:C.checked(context,row,256*1024**2)
    return manifest,expected

def prepare(source,runner,ready):
    C=load('_managed604_staging_contract',source/'scripts/ci/expanded604-composition/contract.py')
    manifest,ref,expected=C.target_manifest(ready)
    original=C.read(source/'scripts/ci/maintained-desktop574-inputs.json')
    base={r['name']:r['version'] for r in original['packages']}
    C.need(len(base)==574 and all(expected.get(n)==v for n,v in base.items()),'exact retained574 subset of604 required')
    incoming=[r for r in manifest['packages'] if r['name'] not in base];C.need(len(incoming)==30,'finite30 additions required')
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
        target=context/'code/scripts/ci/expanded604-composition'/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/'scripts/ci/expanded604-composition'/name,target)
    target=context/'code/scripts/ci/full-root-upgrade/root_upgrade.py';target.parent.mkdir(parents=True);shutil.copyfile(source/'scripts/ci/full-root-upgrade/root_upgrade.py',target)
    shutil.copyfile(Path(__file__).with_name('install604.py'),context/'install604.py')
    rows=[]
    for p in sorted(context.rglob('*')):
        if p.is_file():rows.append(dict(path=p.relative_to(context).as_posix(),bytes=p.stat().st_size,sha256=C.sha(p)))
    C.need(len(rows)<=128,'finite604 context file count')
    (runner/'context604.json').write_bytes(C.encoded(dict(schema_version=1,manifest=ref,expected604_sha256=C.TARGET_SHA,context_files=rows)))
    desktop=next(r for r in incoming if r['name']=='cachy-asahi-hyprland-settings')
    (runner/'desktop-archive.json').write_bytes(C.encoded(dict(name=Path(desktop['archive']).name,sha256=desktop['sha256'])))
    verify(source,runner)
