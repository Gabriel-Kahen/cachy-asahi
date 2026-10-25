# SPDX-License-Identifier: MIT
"""Private TEST authority; imports and the default policy authorize no actors."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys

HERE=Path(__file__).resolve().parent
LANE='scripts/ci/glibc-debian-maintained-installed16k'
NATIVE='scripts/ci/glibc-debian-maintained-public-provider-lifecycle'
PASS='PASS_DEBIAN_MAINTAINED_GENERIC16K_ALPM_PROVIDER_NORMAL_LIFECYCLE_AND_RECOVERY'
LABEL='org.cachy-asahi.debian-maintained-installed16k'
GIB=1024**3

def need(ok,why):
    if not ok:raise ValueError(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def read(path,cap=2*1024**2):
    path=Path(path);need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary path required')
    info=path.stat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=cap,'bounded ordinary file required')
    raw=path.read_bytes();need(len(raw)==info.st_size,'input changed');return raw

def decode(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate JSON key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))

def save(path,value):Path(path).write_text(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n')

def relative(name):
    need(type(name) is str and name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')),'closed relative path');return name

def ref(root,row,cap=2*1024**2):
    need(set(row)=={'path','bytes','sha256'},'closed reference required')
    path=Path(root)/relative(row['path']);raw=read(path,cap)
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'pinned file differs: '+row['path']);return path

def row(path):
    path=Path(path)
    with path.open('rb') as stream:digest=hashlib.file_digest(stream,'sha256').hexdigest()
    return dict(bytes=path.stat().st_size,sha256=digest)

def load(name,path):
    spec=importlib.util.spec_from_file_location('_debian_maintained_installed16k_'+name,path);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module

def check_source(source):
    for table in ('dependencies.json','source-manifest.json'):
        for name,pin in decode(read(HERE/table))['files'].items():ref(source,dict(path=name,**pin),16*1024**2)

def gate(acceptances):
    return load('maintained_installed_phase_gate',HERE/'phase_gate.py').validate(sys.modules[__name__],acceptances)
