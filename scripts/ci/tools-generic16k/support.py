# SPDX-License-Identifier: MIT
"""Pinned source-only reuse for the private script tools 16 KiB CLI trial."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
MAP_SHA='5c6aac7dc012a3ecabdbd15c5e0c66158656da15cb822789e1f52527024e73db'
TOOLS=('bash','env','uname','getconf','mount','python3','zsh','fish','cmp','mkdir','rm','ln')
SCOPE='PRIVATE_GENERIC_ARM64_16K_MAPPED_TOOLS_PTY_CLI_ONLY'


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(data):return hashlib.sha256(data).hexdigest()


def read(path,cap=1024**2):
    path=Path(path);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size<=cap,'regular bounded input required')
    with path.open('rb') as stream:raw=stream.read(cap+1)
    need(len(raw)<=cap,'input byte bound');return raw


def save(path,value,cap=2*1024**2):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode();need(len(raw)<=cap,'receipt byte bound')
    Path(path).write_bytes(raw)


def pins():return json.loads(read(HERE/'dependencies.json'))


def check_source(root):
    root=Path(root).resolve(strict=True)
    for name,row in pins()['files'].items():
        path=HERE/Path(name).name if name.startswith('scripts/ci/tools-generic16k/') else root/name
        need(not any(p.is_symlink() for p in (path,*path.parents)),'source alias refused')
        raw=read(path,2*1024**2)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'source pin differs: '+name)


def load(root,name):
    row=pins()['files'][name];path=HERE/Path(name).name if name.startswith('scripts/ci/tools-generic16k/') else Path(root)/name;raw=read(path,2*1024**2)
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'source module pin differs')
    spec=importlib.util.spec_from_file_location('tools16k_'+sha(name.encode())[:16],path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def mapping():
    raw=read(HERE/'payload-map.json');need(sha(raw)==MAP_SHA,'explicit source payload map differs')
    value=json.loads(raw);need(value['schema_version']==1 and len(value['products'])==4,'exact four script products required')
    return value


def products(root):
    value=mapping()
    for row in [*[r for p in value['products'].values() for r in p['payload'].values()],*value['fixtures'].values()]:
        path=Path(root)/row['source']
        need(not any(p.is_symlink() for p in (path,*path.parents)),'payload source alias refused')
        raw=read(path)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'mapped source payload differs: '+row['source'])
    return value['products']


def aligned(data,generic):
    interpreter,needed,loads=generic.elf(data)
    need(loads and all(a>=16384 and (v-o)%16384==0 for v,o,_,a in loads),'ELF not 16K aligned')
    return interpreter,needed
