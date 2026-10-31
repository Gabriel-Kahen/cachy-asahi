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
LANE='scripts/ci/glibc-gnu-provider-installed16k'
NATIVE='scripts/ci/glibc-gnu-provider-lifecycle'
PASS='PASS_GENERIC16K_ALPM_PROVIDER_NORMAL_LIFECYCLE_AND_RECOVERY'
LABEL='org.cachy-asahi.gnu-installed16k'
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
    spec=importlib.util.spec_from_file_location('_installed16k_'+name,path);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module

def check_source(source):
    for table in ('dependencies.json','source-manifest.json'):
        for name,pin in decode(read(HERE/table))['files'].items():ref(source,dict(path=name,**pin),16*1024**2)

def gate(acceptances):
    policy=decode(read(HERE/'input-policy.json',65536))
    need(policy['schema_version']==1 and policy['status']=='BOUND_BY_ROOT' and type(policy['binding']) is dict,'UNBOUND installed16K: no credentials, output or actors permitted')
    binding=policy['binding'];need(set(binding)=={'native_lifecycle','system16k'},'normal lifecycle and system-path runtime prerequisites only')
    expected={'native_lifecycle':'ROOT_ACCEPTED_CONVENTIONAL_PROVIDER_NORMAL_LIFECYCLE','system16k':'ROOT_ACCEPTED_GNU_PROVIDER_SYSTEM_PATHS_GENERIC16K'}
    result={}
    for kind,status in expected.items():
        value=decode(read(ref(acceptances,binding[kind])))
        package=value['package_sha256'] if kind=='system16k' else value['provider_archive_sha256']
        cleanup=value['cleanup'] if kind=='system16k' else value['ordered_cleanup']
        need(value['status']==status and value['hardware']=='NOT_RUN' and package=='b852e3fc647d63699c5f42003a748cbd2268991dc2615a494dc3cdda4d757d12' and cleanup=='PASS','actual Root decision for same provider required')
        need(re.fullmatch('[0-9a-f]{40}',value['source_sha']) and type(value['run_id']) in (str,int) and str(value['run_id']).isdecimal(),'actual run/source identity required')
        if kind=='system16k':need(value['page_size']==16384 and value['scope']=='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION' and value['ALPM_installation']=='NOT_RUN','actual staged16K prerequisite qualification required')
        result[kind]=value
    return result
