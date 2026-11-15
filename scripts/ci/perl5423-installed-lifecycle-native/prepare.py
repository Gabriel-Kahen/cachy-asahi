#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Seal one reviewed lifecycle Source as DATA; no signer, network or native role."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import resource
import stat
import tarfile
import tempfile
from types import SimpleNamespace

HERE=Path(__file__).resolve().parent
ACTUAL={k:None for k in ('source','ref','run','job','approval','authority','image','container','reader','artifact')}
FS_SHA='7c7b8ce846603d76da1db7de58573fa76642871aae7082fa36b32a54856585d7'

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec);__import__('sys').modules[name]=result;spec.loader.exec_module(result);return result

if hashlib.sha256((HERE/'filesystem.py').read_bytes()).hexdigest()!=FS_SHA:raise ValueError('held Source DATA filesystem helper changed')
fs=module('lifecycle_source_filesystem',HERE/'filesystem.py')
prereq=module('lifecycle_prerequisite_data',HERE/'prerequisites.py')

def encode(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def held_code(root):
    expected=json.loads((HERE/'held-source.json').read_bytes())['files'];rows={}
    for name,row in expected.items():
        fs.relative(name);raw,mode=fs.read(root/name)
        fs.need(dict(**fs.pin(raw),mode=mode)==row,'held lifecycle Source changed: '+name);rows[name]=(raw,mode)
    return rows


def capsule_tar(capsule):
    """Preserve admitted protected DATA modes in opaque deterministic tar, not Git modes."""
    buffer=io.BytesIO();descriptors={};total=0
    with tarfile.open(fileobj=buffer,mode='w:',format=tarfile.PAX_FORMAT) as output:
        for path in sorted(capsule.rglob('*')):
            if path.is_dir() and not path.is_symlink():continue
            name=path.relative_to(capsule).as_posix();fs.relative(name)
            raw=prereq.read(path,64*1024**2)[0];mode=stat.S_IMODE(path.stat().st_mode)
            fs.need(mode in (0o444,0o644),'exact held prepared DATA mode required')
            total+=len(raw);fs.need(total<=48*1024**2 and len(descriptors)<64,'finite lifecycle capsule bytes/members')
            item=tarfile.TarInfo('capsule/'+name);item.mode=mode;item.size=len(raw);item.mtime=1791748800;item.uid=item.gid=0
            output.addfile(item,io.BytesIO(raw));descriptors[name]=dict(**fs.pin(raw),mode=mode)
    return buffer.getvalue(),descriptors


def render(frozen,component,review_path,review_sha):
    # Missing/unreviewed actual archives/config/hooks/public trust stop before code imports/sealing.
    checked=prereq.validate(review_path,review_sha)
    code=held_code(component);expected=json.loads((HERE/'held-source.json').read_bytes())
    fs.MAX_FILES=320;before=fs.snapshot(frozen)
    fs.need(fs.pin(before['source-map.json'][0])['sha256']==expected['frozen_bootstrap_source_map_sha256'] and fs.descriptors({k:v for k,v in before.items() if k!='source-map.json'})==json.loads(before['source-map.json'][0])['files'],'complete frozen signed349 Source byte/mode/membership join')
    original={'original/'+n.removeprefix('original/'):row for n,row in before.items() if n.startswith('original/')};fs.need(len(original)==200,'exact original200 dependency bootstrap closure')
    with tempfile.TemporaryDirectory(prefix='lifecycle-seal-',dir=HERE/'work') as temporary:
        capsule=Path(temporary)/'capsule'
        maker=module('held_pinned_lifecycle_data_prepare',component/'prepare.py')
        maker.prepare(SimpleNamespace(**{k:str(v) for k,v in checked['paths'].items()},output=str(capsule)))
        joined=prereq.check_capsule_review(capsule,checked['review'])
        # The generated map inherits umask; explicitly seal this DATA file before tar.
        (capsule/'source-map.json').chmod(0o444)
        archive,descriptors=capsule_tar(capsule)
        inner_map=fs.pin((capsule/'source-map.json').read_bytes())['sha256']
    files=dict(original)
    files.update({'lifecycle-code/'+n:row for n,row in code.items()})
    code_map=encode(dict(schema=1,actual=ACTUAL,files=fs.descriptors(code)));files['lifecycle-code-map.json']=(code_map,0o644)
    component_sha=fs.pin(code_map)['sha256']
    for path in sorted((HERE/'payload').rglob('*')):
        if not path.is_file() or '__pycache__' in path.parts:continue
        name=path.relative_to(HERE/'payload').as_posix();raw,mode=fs.read(path)
        if name=='hosted/common.py':raw=raw.replace(b'__LIFECYCLE_CODE_MAP_SHA__',component_sha.encode())
        files[name]=(raw,mode)
    files['lifecycle-capsule.tar']=(archive,0o644)
    files['input-review.json']=(prereq.read(Path(review_path),4*1024**2)[0],0o644)
    for name in ('LICENSE','expected349.lock','policy.json','root-admission.TEMPLATE.json','prerequisites.TEMPLATE.json','held-source.json'):
        files[name]=fs.read(HERE/name)
    contract=dict(schema=1,operation='perl5423-installed-lifecycle-native-v1',inner_operation='perl5423-installed-lifecycle-v1',held_code_commit=expected['commit'],input_review_sha256=review_sha,capsule=dict(**fs.pin(archive),members=descriptors,source_map_sha256=inner_map),baseline_review_join=joined,actual=ACTUAL,signing='NO_SECRET_SIGNING_MATERIAL_OR_SIGNER_CREATION; Root external TEST signature/public bundle required',holds_preserved=True)
    files['contract.json']=(encode(contract),0o644)
    workflow=(HERE/'workflow.yml.in').read_bytes().replace(b'__COMMON_SHA__',fs.pin(files['hosted/common.py'][0])['sha256'].encode()).replace(b'__ENTRY_SHA__',fs.pin(files['hosted/entry.py'][0])['sha256'].encode())
    for name in ('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-perl5423-installed-lifecycle-v1.yml'):files[name]=(workflow,0o644)
    inverse=dict(schema=1,held=fs.descriptors(original),before_tree=fs.tree(original),additions=sorted(set(files)-set(original)|{'inverse.json','source-map.json'}),operation='REMOVE_EXACT_ADDITIONS_RESTORES_ORIGINAL200_BYTES_AND_GIT_MODES',actual=ACTUAL)
    files['inverse.json']=(encode(inverse),0o644);undo={n:v for n,v in files.items() if n not in inverse['additions']}
    fs.need(fs.descriptors(undo)==inverse['held'] and fs.tree(undo)==inverse['before_tree'],'complete inverse')
    files['source-map.json']=(encode(dict(schema=1,actual=ACTUAL,files=fs.descriptors(files),scope='REVIEWED_INPUTS_SOURCE_ONLY_NOT_RUNTIME_ADMISSION')),0o644)
    fs.need(len(files)<=320 and sum(len(b) for b,_ in files.values())<=96*1024**2,'bounded standalone Source packet')
    return files


def construct(frozen,component,review_path,review_sha,output):
    output=fs.absolute(output)
    fs.need(not any(output.is_relative_to(p) or p.is_relative_to(output) for p in (frozen,component,HERE/'payload')),'fresh disjoint Source output')
    files=render(frozen,component,review_path,review_sha);previous=fs.MAX_FILES
    try:fs.MAX_FILES=320;fs.publish(files,output)
    finally:fs.MAX_FILES=previous
    return dict(status='SEALED_LIFECYCLE_SOURCE_DATA_ONLY',files=len(files),bytes=sum(len(b) for b,_ in files.values()),source_map=fs.pin(files['source-map.json'][0]),prospective_tree=fs.tree(files),actual=ACTUAL)


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
    (HERE/'work').mkdir(mode=0o700,exist_ok=True)
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ('frozen-source','lifecycle-source','input-review','output'):parser.add_argument('--'+key,type=Path,required=True)
    parser.add_argument('--input-review-sha256',required=True);a=parser.parse_args()
    print(json.dumps(construct(a.frozen_source,a.lifecycle_source,a.input_review,a.input_review_sha256,a.output),sort_keys=True))
