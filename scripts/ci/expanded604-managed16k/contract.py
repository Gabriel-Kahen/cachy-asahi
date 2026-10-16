# SPDX-License-Identifier: MIT
"""Finite Root authority and ordinary pinned source inputs; no actor authority while UNBOUND."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
HERE=Path(__file__).resolve().parent
PREFIX='scripts/ci/expanded604-managed16k/'
TARGET='76c37db5eb097662f4a9ca0465680de285466b0443916a50255ea5b8f6d6c946'
SCOPE='GENERIC_ARM64_16384_ACTUAL_ALPM604_CURRENT_WELCOME2_MANAGEMENT_SOFTWARE_ONLY'
PASS='PASS_INSTALLED604_WELCOME2_MANAGEMENT_GENERIC16K_METADATA'
FINAL='PASS_INSTALLED604_GENERIC16K_GUI_PIXELS_PENDING_REVIEW'

def need(ok,why):
    if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(path,cap=16*1024**2):
    path=Path(path);need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary path required')
    info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=cap,'bounded ordinary file required')
    raw=path.read_bytes();need(len(raw)==info.st_size,'source length drift');return raw

def json_read(path,cap=4*1024**2):
    def pairs(items):
        out={}
        for k,v in items:need(k not in out,'duplicate JSON key');out[k]=v
        return out
    def constant(_):raise ValueError('nonfinite JSON')
    return json.loads(read(path,cap),object_pairs_hook=pairs,parse_constant=constant)
def save(path,value,cap=16*1024**2):
    raw=encoded(value);need(len(raw)<=cap,'receipt bound');Path(path).write_bytes(raw)
def revision(path):return subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True,timeout=15).strip()
def checked(root,row,cap=16*1024**2):
    need(set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int and 0<row['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',row['sha256'] or ''),'exact bounded reference required')
    p=Path(row['path']);need(not p.is_absolute() and p.parts and all(x not in ('..','.') for x in p.parts),'relative closed reference required')
    raw=read(Path(root)/p,cap);need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'input byte identity differs');return Path(root)/p

def policy(bound=True):
    v=json_read(HERE/'input-policy.json');need(v['schema_version']==1 and v['expected604_sha256']==TARGET,'exact604 policy required')
    if bound:
        need(v['status']=='ROOT_BOUND_NATIVE604_AND_WELCOME2_GUI','native604/current Welcome2 GUI acceptance UNBOUND; no secrets or actors')
        for key in ('native604','welcome2_gui'):
            row=v[key];need(all(re.fullmatch('[0-9a-f]{40}',row.get(k) or '') for k in ('source_sha','carrier_source')) and re.fullmatch('[1-9][0-9]{0,19}',row.get('run_id') or '') and row.get('decision') is not None,'actual decision binding required')
        need(v['welcome2_gui']['asset_root'] is not None and v['welcome2_gui'].get('assets_index') is not None,'actual current GUI candidate carrier subdirectory required')
    return v

def decisions(native,gui,value):
    out={}
    for root,key,status in ((native,'native604','ROOT_ACCEPTED_NATIVE_EXPANDED604_COMPOSITION'),(gui,'welcome2_gui','ROOT_ACCEPTED_NATIVE_WELCOME2_MANAGEMENT_GUI')):
        row=value[key];need(revision(root)==row['carrier_source'],'exact decision carrier revision required')
        doc=json_read(checked(root,row['decision'],4*1024**2))
        need(doc.get('status')==status and all(doc.get(k)==row[k] for k in ('source_sha','run_id')) and doc.get('cleanup')=='PASS' and doc.get('hardware')=='NOT_RUN' and doc.get('release')=='NOT_ADMITTED','actual Root decision differs')
        if key=='native604':need(doc.get('package_count')==604 and doc.get('expected604_sha256')==TARGET and all(doc.get(k)=='PASS' for k in ('installed_lifecycle','installed_six_modules')),'complete actual native604 decision required')
        else:need(doc.get('frames')==24 and doc.get('management_operations_per_profile')==17 and doc.get('profiles')==['minimal','overlay'] and doc.get('welcome_version')=='0.1.0-2' and doc.get('gui_contract')=='PASS','current actual Welcome2 GUI decision required')
        out[key]=doc
    return out

def pins():return json_read(HERE/'dependencies.json')['files']
def check_source(root):
    manifest=json_read(HERE/'source-manifest.json')
    need(manifest.get('status')=='ROOT_FROZEN_SOURCE_ONLY' and 1<=len(manifest.get('files',{}))<=512,'Root source freeze remains UNBOUND')
    files=manifest['files'];need(all(files.get(n)==r for n,r in pins().items()) and PREFIX+'dependencies.json' in files,'source/dependency closure differs')
    for name,row in files.items():checked(root,dict(path=name,**row))
def load(root,name):
    checked(root,dict(path=name,**pins()[name]));path=Path(root)/name;sys.path.insert(0,str(path.parent))
    spec=importlib.util.spec_from_file_location('managed604_'+sha(name.encode())[:16],path)
    mod=importlib.util.module_from_spec(spec);sys.modules[spec.name]=mod;spec.loader.exec_module(mod);return mod


def assets(root,binding):
    sub=Path(binding['asset_root']);need(not sub.is_absolute() and sub.parts and '..' not in sub.parts,'closed GUI asset directory required')
    directory=Path(root)/sub
    index=json_read(checked(root,binding['assets_index'],1024**2),1024**2)
    need(index.get('schema_version')==1 and index.get('purpose')=='ACTUAL_CURRENT_WELCOME2_GUI_PUBLIC_INPUTS','actual GUI input index purpose required')
    files=index['files'];need(type(files) is dict and len(files)==9,'exact three GUI archives/signatures plus3 public control files required')
    for name,row in files.items():checked(directory,dict(path=name,**row),8*1024**2)
    products=json_read(directory/'products.json');need(set(products)=={'cachy-asahi-welcome','cachy-asahi-doctor','cachy-asahi-orphans'},'exact current GUI products')
    expected={'products.json','control.json','TEST-public.asc'}
    for row in products.values():
        expected|={row['archive'],row['archive']+'.sig'}
        need(files[row['archive']]['sha256']==row['sha256'],'GUI archive/index hash differs')
    need(set(files)==expected,'closed actual GUI assets differ');return directory
