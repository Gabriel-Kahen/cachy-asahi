# SPDX-License-Identifier: MIT
"""Pinned existing IO/producer libraries; no launcher, network or authority."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import types

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent/'qt612-reference-native-source'
ORDER = ('gui_server','shadertools','svg','declarative','wayland')
LOCK_PIN = {'bytes': 45084, 'sha256': 'b46bfe8eb38a5c09ca550193b470bafc035d5c76097c15618959f94b44725e47'}


def need(value,why):
    if not value: raise ValueError(why)


def pin(raw): return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value): return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def _read(path,expected,cap=4*1024**2):
    path=Path(path)
    need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)), 'ORDINARY_PINNED_CODE')
    before=path.lstat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=cap
                            and before.st_uid in (0,os.geteuid()) and not before.st_mode&0o022,'BOUNDED_PINNED_CODE')
    raw=path.read_bytes()
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns)
    need(pin(raw)==expected and identity(before)==identity(path.lstat()),'WHOLE_PINNED_CODE')
    return raw


def load_lock():
    need(LOCK_PIN is not None,'FROZEN_FAMILY_LOCK_REQUIRED')
    value=json.loads(_read(HERE/'family.lock.json',LOCK_PIN))
    need(value['kind']=='QT612_COMPLETE_FAMILY_FROZEN_INPUTS_V1' and tuple(value['order'])==ORDER
         and set(value['components'])==set(ORDER) and value['Root_acceptance'] is None,'EXACT_FIVE_COMPONENT_LOCK')
    return value


def _parent(name):
    lock=load_lock()
    # All transitive local modules are checked before importing any parent code.
    for n,row in lock['parents'].items(): _read(PARENT/n,row)
    spec=importlib.util.spec_from_file_location('family_parent_'+name,PARENT/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def local(name):
    path=HERE/(name+'.py')
    spec=importlib.util.spec_from_file_location('qt612_family_'+name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def project_pkgbuild(raw,component):
    need(component in ORDER,'EXACT_COMPONENT')
    before=b'\n}\n\npackage() {'
    marker=('PASS_QT612_FAMILY_CHECK_'+component.upper()).encode()
    after=b"\n  printf '%s\\n' '"+marker+b"'\n}\n\npackage() {"
    need(raw.count(before)==1 and marker not in raw,'EXACT_NORMAL_CHECK_SUCCESS_SEAM')
    configure=b'cmake -C "$srcdir/configure.cmake"'
    serial=b'cmake -DCMAKE_AUTOGEN_PARALLEL:STRING=1 -C "$srcdir/configure.cmake"'
    need(raw.count(configure)==1 and serial not in raw,'EXACT_SERIAL_CONFIGURE_SEAM')
    projected=raw.replace(before,after).replace(configure,serial)
    need(projected.replace(serial,configure).replace(after,before)==raw,'WHOLE_CHECK_AND_SERIAL_INVERSE')
    return projected


def read_source(root,source_map_sha256):
    root=M.ordinary(root); observed={};path=root/'source-map.json'
    need(re.fullmatch('[0-9a-f]{64}',source_map_sha256 or ''),'EXTERNAL_FAMILY_MAP_PIN')
    mapping=M.load(path,dict(bytes=path.lstat().st_size,sha256=source_map_sha256),observed)
    need(mapping['kind']=='QT612_COMPLETE_FAMILY_SOURCE_DATA_V1' and mapping['Root_acceptance'] is None
         and set(mapping['actual'])==set(M.ACTUAL) and all(v is None for v in mapping['actual'].values())
         and type(mapping['input_plan_complete'])is bool,'UNISSUED_FAMILY_SOURCE_ONLY')
    rows=mapping['files'];need(type(rows)is dict and len(rows)<=512 and sum(r['bytes'] for r in rows.values())<=256*1024**2,'FINITE_FAMILY_SOURCE')
    found=set();nodes=0
    for parent,dirs,names in os.walk(root,followlinks=False):
        for n in dirs+names:
            p=Path(parent)/n;nodes+=1
            need(nodes<=1024 and not p.is_symlink(),'ORDINARY_FAMILY_NAMESPACE')
            if n in names:need(p.is_file(),'ORDINARY_FAMILY_LEAF');found.add(p.relative_to(root).as_posix())
    need(found==set(rows)|{'source-map.json'},'COMPLETE_FAMILY_SOURCE_NAMESPACE')
    for name,row in rows.items():
        M.member(name);need(set(row)=={'bytes','sha256','mode'} and row['mode']==0o644,'EXACT_FAMILY_SOURCE_MODE')
        M.stream(root/name,{k:row[k] for k in ('bytes','sha256')},observed,cap=128*1024**2,mode=0o644)
    M.unchanged(observed)
    return mapping


M = _parent('prepare') if LOCK_PIN is not None else None
P = _parent('producer') if LOCK_PIN is not None else None
F = _parent('finish_pair') if LOCK_PIN is not None else None
