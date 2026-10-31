# SPDX-License-Identifier: MIT
"""Pinned source-only reuse for the private Welcome/Doctor 16 KiB CLI trial."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
INPUT_SOURCE='8a38b3fd5963e61fc94707dd87e5dcd626a518a3'
INDEX='3d200c4cd19bd7ca15426ae34617bb4fad6c83b194f1d25533ad9f462c9c0580'
SCOPE='PRIVATE_GENERIC_ARM64_16K_WELCOME_DOCTOR_CLI_ONLY'


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
        path=root/name
        need(not any(p.is_symlink() for p in (path,*path.parents)),'source alias refused')
        raw=read(path,2*1024**2)
        need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'source pin differs: '+name)


def load(root,name):
    row=pins()['files'][name];path=Path(root)/name;raw=read(path,2*1024**2)
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'source module pin differs')
    spec=importlib.util.spec_from_file_location('welcome16k_'+sha(name.encode())[:16],path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def products(root,assets):
    need(sha(read(Path(assets)/'index.json',65536))==INDEX,'immutable product index differs')
    verifier=load(root,'scripts/ci/welcome-managed-gui/candidates.py')
    rows=verifier.verify(Path(root),Path(assets))
    need(set(rows)=={'cachy-asahi-welcome','cachy-asahi-doctor'},'exact two native products required')
    return rows


def aligned(data,generic):
    interpreter,needed,loads=generic.elf(data)
    need(loads and all(a>=16384 and (v-o)%16384==0 for v,o,_,a in loads),'ELF not 16K aligned')
    return interpreter,needed
