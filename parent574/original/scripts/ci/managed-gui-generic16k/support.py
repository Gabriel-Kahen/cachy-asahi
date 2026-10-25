# SPDX-License-Identifier: MIT
"""Exact source-only dependencies for the separate managed GUI 16K fixture."""
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys

HERE=Path(__file__).resolve().parent
PREFIX='scripts/ci/managed-gui-generic16k/'
SCOPE='GENERIC_ARM64_16K_MANAGED_WELCOME_GUI_DIAGNOSTIC_ONLY'
RELEASE='7.1.13-generic16k-managed-gui'


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def read(path,cap=16*1024**2):
    path=Path(path);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and not any(p.is_symlink() for p in (path,*path.parents)) and info.st_size<=cap,'bounded ordinary input required')
    with path.open('rb') as stream:raw=stream.read(cap+1)
    need(len(raw)==info.st_size and len(raw)<=cap,'input length differs');return raw


def save(path,value,cap=16*1024**2):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode();need(len(raw)<=cap,'receipt size bound');Path(path).write_bytes(raw)


def pins():return json.loads(read(HERE/'dependencies.json'))['files']


def source(root,name):return HERE/name.removeprefix(PREFIX) if name.startswith(PREFIX) else Path(root)/name


def check_source(root):
    for name,row in pins().items():
        raw=read(source(root,name));need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'source pin differs: '+name)


def load(root,name):
    row=pins()[name];path=source(root,name);raw=read(path)
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'source import pin differs: '+name)
    sys.path.insert(0,str(path.parent))
    spec=importlib.util.spec_from_file_location('gui16k_'+sha(name.encode())[:16],path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
