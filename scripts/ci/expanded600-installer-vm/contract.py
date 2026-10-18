# SPDX-License-Identifier: MIT
"""A separate600 installer selection; pending Root evidence cannot authorize actors."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

HERE=Path(__file__).resolve().parent
SEVEN='7fee76d68e5fd75437d8b49aaaced8376d2215cd'
LEGACY='b6b17e5f6b322f160f7eeb22c8a01380a3c854cd'
BEFORE='2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
AFTER='d263a3ca9089c204603f2e12b80dc4f209ee6e636f10da940a514040b636db79'
BUILDER='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
BANG='cachy-asahi-fish-bang-bang'
SCRIPTS={'cachy-asahi-welcome','cachy-asahi-doctor','cachy-asahi-mirrors','cachy-asahi-zsh-syntax-highlighting',
         'cachy-asahi-zsh-history-substring-search','cachy-asahi-fish-autopair','cachy-asahi-fish-done'}
AUDIO={'asahi-audio','alsa-ucm-conf-asahi','speakersafetyd','bankstown','triforce-lv2','lsp-plugins-lv2'}


def need(ok,why):
    if not ok:raise ValueError(why)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def safe(path):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n\0') and
        not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute path required');return path


def relative(name):
    need(type(name) is str and name and not name.startswith('/') and '\\' not in name and
         all(part not in ('','.','..') for part in name.split('/')) and all(32<=ord(c)<127 for c in name),
         'safe relative path required');return name


def ref(value,cap=16*1024**2):
    need(type(value) is dict and set(value)=={'path','bytes','sha256'} and type(value['bytes']) is int and
         0<value['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',value['sha256'] or ''),'exact bounded byte reference required')
    relative(value['path']);return value


def checked(root,value,cap=16*1024**2):
    ref(value,cap);path=safe(Path(root)/value['path']);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size==value['bytes'] and sha(path)==value['sha256'],
         'input identity differs: '+value['path']);return path


def read(path,cap=4*1024**2):
    safe(Path(path).absolute());need(Path(path).stat().st_size<=cap,'JSON byte bound')
    def pairs(rows):
        result={}
        for key,value in rows:need(key not in result,'duplicate JSON key');result[key]=value
        return result
    def constant(_):raise ValueError('nonfinite JSON')
    return json.loads(Path(path).read_bytes(),object_pairs_hook=pairs,parse_constant=constant)


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value


def revision(path):return subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True,timeout=15).strip()


def inventory(raw,count):
    rows=[line.split() for line in raw.decode().splitlines()]
    need(len(rows)==count and all(len(row)==2 for row in rows) and len(dict(rows))==count,'exact distinct package inventory required')
    return dict(rows)


def locks():
    before=(HERE/'expected587.lock').read_bytes();after=(HERE/'expected600.lock').read_bytes()
    need(hashlib.sha256(before).hexdigest()==BEFORE and hashlib.sha256(after).hexdigest()==AFTER,'fixed proposed inventory bytes differ')
    old,new=inventory(before,587),inventory(after,600)
    need(new.keys()-old.keys()==SCRIPTS|AUDIO and old.keys()<=new.keys() and
         old[BANG]=='0.1.0-1' and new[BANG]=='0.1.0-2' and
         {n:v for n,v in old.items() if n!=BANG}=={n:new[n] for n in old if n!=BANG} and
         new['cachy-asahi-setup']=='0.1.0-3' and new['cachy-asahi-update']=='4.4.2-2',
         'exact original587 plus13 additions and only bang2 required')
    return old,new


def policy(*,bound=True):
    value=read(HERE/'input-policy.json');locks()
    need(value.get('schema_version')==1 and value.get('legacy_source')==LEGACY and
         value.get('original587_sha256')==BEFORE and value.get('expected600_sha256')==AFTER and
         value.get('retained_seven_source')==SEVEN and value.get('retained_seven_index')==dict(path='index.json',bytes=71022,
         sha256='3cd0e37978614cd1c8b92da437dcb3125631f386f4f15a616868e7feb986c244'),
         'held setup3/updater2 source and exact600 inventory required')
    if bound:
        need(value.get('status')=='ROOT_BOUND_PREREQUISITES_AND_EIGHT_PAIRS',
             'pending Root587 observer, native600 acceptance and final eight-pair binding')
        need(re.fullmatch('[0-9a-f]{40}',value.get('eight_pair_source') or ''),'immutable final eight-pair source required')
        ref(value.get('eight_pair_index'),4*1024**2)
        need(set(value.get('prerequisites',{}))=={'observer587','native600'},'two Root prerequisite decisions required')
        for value_ in value['prerequisites'].values():ref(value_)
    return value


def legacy(root,*,git=True):
    safe(root)
    if git:need(revision(root)==LEGACY,'explicit old helper/setup3 source checkout required')
    pins=read(HERE/'legacy-pins.json')
    for name,row in pins.items():checked(root,dict(path=name,**row),4*1024**2)
    return pins


def prerequisites(root,value):
    observer=read(checked(root,value['prerequisites']['observer587']))
    native=read(checked(root,value['prerequisites']['native600']))
    need(observer.get('status')=='ROOT_ACCEPTED_FULL587_INSTALLER_SOFTWARE' and
         all(observer.get(k)=='PASS' for k in ('ordinary_parent_retired','independent_root_readback','cleanup')) and
         observer.get('hardware')=='NOT_RUN','original587 independent observer acceptance is pending/failed')
    need(native.get('status')=='ROOT_ACCEPTED_NATIVE_EXPANDED600_COMPOSITION' and native.get('package_count')==600 and
         native.get('expected600_sha256')==AFTER and native.get('bang_version')=='0.1.0-2' and
         all(native.get(k)=='PASS' for k in ('bang_pair_bytes_buildinfo','installed_lifecycle','installed_six_modules','cleanup')) and
         native.get('hardware')=='NOT_RUN','native600 composition/pair/coexistence acceptance is pending/failed')
    for decision in (observer,native):
        need(re.fullmatch('[0-9a-f]{40}',decision.get('source_sha') or '') and
             re.fullmatch('[0-9]+',decision.get('run_id') or ''),'Root decision actual run/source absent')
    return dict(observer587=observer,native600=native)
