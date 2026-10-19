# SPDX-License-Identifier: MIT
"""Consume only the two successful native lane candidates, with exact source joins."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import stat
import sys

NAMES=('cachy-asahi-welcome','cachy-asahi-doctor')


def need(ok,message):
    if not ok:raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def regular(path,cap):
    need(not any(p.is_symlink() for p in (path,*path.parents)),'candidate/source symlink refused')
    value=path.lstat();need(stat.S_ISREG(value.st_mode) and value.st_size<=cap,'unsafe/oversized candidate evidence')
    return value


def read(path,cap=16*1024**2):regular(path,cap);return json.loads(path.read_text())


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module);return module


def verify_source(source):
    for name,pin in read(Path(__file__).with_name('source-pins.json')).items():
        path=source/name;regular(path,16*1024**2)
        need(digest(path)==pin,'source prerequisite differs: '+name)


def verify(source,assets):
    verify_source(source)
    transport=read(Path(__file__).with_name('transport.json'),65536)
    index_path=assets/'index.json';regular(index_path,65536)
    need(digest(index_path)==transport['index_sha256'],'frozen transport index hash differs')
    index=read(index_path,65536)
    need(index.get('schema_version')==1 and index.get('purpose')=='unselected-original-native-products-gui-inputs' and
         index.get('source_commit')==transport['producer_source'] and index.get('run_id')==transport['producer_run'] and
         index.get('native_build_pairs')=='PASS_BYTES_IDENTICAL' and index.get('installed_lifecycle')==transport['producer_lifecycle'] and
         index.get('release_selection') is False and index.get('signature')=='UNSIGNED_LOCAL_CANDIDATES' and
         index.get('GUI')==index.get('hardware')=='NOT_RUN','transport purpose/provenance/limits differ')
    need(len(index['recipe_sources'])==23 and len(index['files'])==4,'exact23 sources/four archive index required')
    for relative,row in index['recipe_sources'].items():
        path=Path(relative);need(not path.is_absolute() and '..' not in path.parts and
            any(path.is_relative_to(Path('packages/tools')/n) for n in NAMES),'unsafe recipe source path')
        value=source/path;info=regular(value,1024**2)
        need(info.st_size==row['bytes'] and digest(value)==row['sha256'],'current product source differs from native input')
    inventory=read(source/'scripts/ci/maintained-desktop574-inputs.json')
    lock=''.join(r['name']+' '+r['version']+'\n' for r in sorted(inventory['packages'],key=lambda r:r['name']))
    need(hashlib.sha256(lock.encode()).hexdigest()==index['base_inventory_sha256'],'producer/consumer held574 inventory differs')
    product=load('welcome_gui_native_contract',source/'scripts/ci/welcome-native/contract.py')
    checks=load('welcome_gui_package_checks',source/'scripts/checks/package_checks.py')
    sys.path.insert(0,str(source/'scripts/build'));sys.path.insert(0,str(source/'scripts/checks'))
    binding=load('welcome_gui_package_binding',source/'scripts/build/build.py')
    result={};allowed={'index.json','README.md'};total=0
    for name in NAMES:
        arch='aarch64' if name==NAMES[0] else 'any';filename=name+'-0.1.0-1-'+arch+'.pkg.tar.xz'
        reviewed=product.recipe(source,name);reports=[];archives=[]
        for side in ('a','b'):
            relative='packages/'+name+'-'+side+'/'+filename;allowed.add(relative)
            row=index['files'].get(relative,{});path=assets/relative;info=regular(path,8*1024**2);total+=info.st_size
            need(row.get('package')==name and row.get('build')==side and row.get('bytes')==info.st_size and
                 row.get('sha256')==digest(path),'frozen native archive hash/identity differs')
            checked=checks.package(path)
            need(not binding.bind_artifact(reviewed['metadata'],checked,reviewed['input_sha256']['PKGBUILD']),
                 'native candidate metadata/source binding failed')
            payload=product.payload(checked,source,name)
            if name==NAMES[0]:
                import tarfile
                with tarfile.open(path,'r:xz') as tar:
                    rows=[m for m in tar if checks.clean_name(m.name)=='usr/bin/'+name]
                    need(len(rows)==1 and rows[0].isfile() and rows[0].size<=4*1024**2,'bounded Welcome ELF required')
                    product.elf(tar.extractfile(rows[0]).read(),checks)
            reports.append(checked);archives.append(path)
        need(digest(archives[0])==digest(archives[1]) and reports[0]['members']==reports[1]['members'] and
             reports[0]['metadata']==reports[1]['metadata'],'retained native pair byte/content equality differs')
        result[name]=dict(archive=filename,sha256=digest(archives[0]),version='0.1.0-1',payload=payload,
            original_sources=reviewed['input_sha256'],producer_source=transport['producer_source'],
            producer_lifecycle=transport['producer_lifecycle'])
    need(total==68152,'exact native transport byte total differs')
    actual=set()
    for path in assets.rglob('*'):
        relative=path.relative_to(assets)
        if relative.parts[0]=='.git':continue
        need(not path.is_symlink() and (path.is_file() or path.is_dir()),'unsafe transport entry')
        if path.is_file():actual.add(str(relative))
    need(actual==allowed,'unexpected/missing input transport files')
    for name in allowed:regular(assets/name,8*1024**2)
    return result


def stage(source,assets,output):
    need(not output.exists() and not output.is_symlink(),'fresh candidate stage required')
    records=verify(source,assets);output.mkdir(mode=0o700)
    for name,row in records.items():shutil.copyfile(assets/'packages'/(name+'-a')/row['archive'],output/row['archive'])
    transport=read(Path(__file__).with_name('transport.json'),65536)
    lock=dict(status='VERIFIED_NATIVE_CANDIDATES',products=records,eligibility='PRIVATE_GUI_TRIAL_ONLY',
              producer_lifecycle=transport['producer_lifecycle'],transport=transport,GUI='NOT_RUN',hardware='NOT_RUN')
    (output/'candidate-lock.json').write_text(json.dumps(lock,indent=2)+'\n');return lock
