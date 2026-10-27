# SPDX-License-Identifier: MIT
"""Closed source/DATA proof; held original574 source and cleanup stay unchanged."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE=Path(__file__).resolve().parent
MANIFEST='scripts/ci/setup8-real-shells-native/source-manifest.json'
TEMPLATE='scripts/ci/setup8-real-shells-native/workflow.in'
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-setup8-real-shells.yml')
DATA='scripts/ci/setup8-real-shells-data'
HELD='scripts/ci/setup8-real-shells-held'


def need(ok,why):
    if not ok:raise ValueError(why)


def safe(path):
    p=Path(path);need(p.is_absolute() and '..' not in p.parts and not any(c in str(p) for c in ',\r\n') and not any(q.is_symlink() for q in (p,*p.parents)),'ordinary explicit absolute path required');return p


def read(path,cap=16*1024**2):
    p=safe(path);s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=cap,'bounded ordinary single-link source required')
    raw=p.read_bytes();a=p.lstat();need((s.st_ino,s.st_dev,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(a.st_ino,a.st_dev,a.st_size,a.st_mtime_ns,a.st_ctime_ns),'source changed during read');return raw


def digest(path):return hashlib.sha256(read(path)).hexdigest()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def files(root):
    result={}
    for directory,dirs,names in os.walk(safe(root)):
        parent=Path(directory)
        if parent==root:
            for external in ('.git','retained574'):
                if external in dirs:need(not (root/external).is_symlink(),'external DATA ancestry differs');dirs.remove(external)
        for d in dirs:need(not (parent/d).is_symlink(),'no source directory aliases')
        for name in names:
            path=parent/name;n=str(path.relative_to(root));result[n]=pin(read(path))
            need(len(result)<=256,'finite source/DATA closure required')
    return result


def verify(root,expected=None):
    root=safe(root);raw=read(root/MANIFEST)
    if expected is not None:need(pin(raw)['sha256']==expected,'reviewed manifest digest differs')
    m=json.loads(raw);need(m['schema_version']==1 and m['actual_source'] is m['actual_ref'] is m['actual_run'] is None,'source selectors must remain NULL')
    actual=files(root);need(set(actual)==set(m['files'])|set(WORKFLOWS)|{MANIFEST},'whole closed source/DATA membership differs')
    for name,row in m['files'].items():need(not Path(name).is_absolute() and '..' not in Path(name).parts and actual[name]==row,'source/DATA leaf differs: '+name)
    template=read(root/TEMPLATE).decode();rendered=template.replace('@MANIFEST_SHA256@',pin(raw)['sha256']).replace('@JOB_SHA256@',m['files']['scripts/ci/setup8-real-shells-native/job.py']['sha256'])
    need(all(read(root/n).decode()==rendered for n in WORKFLOWS),'complete rendered workflow/alias differs')
    need(m['held_context_sha256']=='3e1e1bf9ea6c3967b1cf3c1cee934641143eb909596ac6676b3ff5e36954c755' and digest(root/DATA/'context.json')==m['held_context_sha256'],'sealed154 context differs')
    association=json.loads(read(root/'scripts/ci/setup8-real-shells-native/data-association.json'))
    need(set(association['files'])=={n.removeprefix(DATA+'/') for n in actual if n.startswith(DATA+'/')},'every DATA leaf needs source/license association')
    need(association['actual'] is None,'DATA is not native authority')
    return m


def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def held_job(root):
    contract=load(root/'scripts/ci/setup8-native/contract.py','exact_setup8_contract')
    previous=sys.modules.get('contract');sys.modules['contract']=contract
    try:return load(root/'scripts/ci/tools-native/job.py','exact_tools_cleanup')
    finally:
        if previous is None:sys.modules.pop('contract',None)
        else:sys.modules['contract']=previous


def held_docker(root,image,name,output):
    contract=load(root/'scripts/ci/setup8-native/contract.py','exact_setup8_docker_contract')
    previous=sys.modules.get('contract');sys.modules['contract']=contract
    try:module=load(root/'scripts/ci/welcome-native/run.py','exact_welcome_docker')
    finally:
        if previous is None:sys.modules.pop('contract',None)
        else:sys.modules['contract']=previous
    return module.docker(image,name,output,root=True),contract.LABEL
