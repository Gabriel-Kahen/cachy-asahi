# SPDX-License-Identifier: MIT
"""Separate600 copied-root selection. Root alone binds actual prerequisite evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

HERE=Path(__file__).resolve().parent
BEFORE='d263a3ca9089c204603f2e12b80dc4f209ee6e636f10da940a514040b636db79'
AFTER='04fabc5702c8389b7b2a53f6ed6168cc45931f6628c158e7e74b073349327c35'
PAIR='79d8d2f53510e4f3a04f39c1b1e24c999aa32e44'
EIGHT='0d7ec3b5ec9b473c9a1b2557735f8dadd8de3f50'
PROBE='0bbf875369c816aab19945c3e4f63c9b1f0b61b0'
SOURCES={'normal':'de04c6b102890218da4f0b77e938315d601e824f',
         'precommit-exit86':'001f0484ab8b599ddc03a84e62fd81af315a2a03',
         'postcommit-exit87':'4b803ba7daa0eacd978a5bf86d62346363c3b6dc'}


def need(ok,why):
    if not ok:raise ValueError(why)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def safe(path):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n\0') and
        not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute path required');return path


def read(path,cap=4*1024**2):
    path=safe(Path(path).absolute());info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=cap,'bounded ordinary JSON required')
    def pairs(rows):
        value={}
        for key,item in rows:need(key not in value,'duplicate JSON key');value[key]=item
        return value
    return json.loads(path.read_bytes(),object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))


def checked(root,row,*,cap=4*1024**2):
    need(type(cap) is int and 0<cap<=8*1024**2 and type(row) is dict and
         set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int and 0<row['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',row['sha256'] or ''),'closed byte reference required')
    name=Path(row['path']);need(not name.is_absolute() and name.parts and all(p not in ('.','..') for p in name.parts),'relative reference required')
    path=safe(Path(root)/name);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size==row['bytes'] and sha(path)==row['sha256'],
         'input byte identity differs: '+str(name));return path


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module


def revision(root):return subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True,timeout=15).strip()


def locks():
    data=[(HERE/name).read_bytes() for name in ('before600.lock','after600.lock')]
    need([hashlib.sha256(raw).hexdigest() for raw in data]==[BEFORE,AFTER],'exact600 lock bytes required')
    rows=[[line.split() for line in raw.decode('ascii').splitlines()] for raw in data]
    need(all(len(group)==600 and all(len(row)==2 for row in group) and len(dict(group))==600 for group in rows),'600 distinct records required')
    before,after=map(dict,rows);need(before['cachy-asahi-setup']=='0.1.0-3' and
        after==before|{'cachy-asahi-setup':'0.1.0-5'} and before['cachy-asahi-update']=='4.4.2-2',
        'only genuine Setup3 to Setup5 selection permitted');return before,after


def policy():
    value=read(HERE/'input-policy.json');locks()
    need(value.get('schema_version')==1 and value.get('status')=='ROOT_BOUND_ACTUAL_PREREQUISITES',
         'Root native600, signed fresh600 and Setup5-on600 actual prerequisites remain unbound')
    need(value.get('before_sha256')==BEFORE and value.get('after_sha256')==AFTER and
         value.get('setup5_pair_source')==PAIR and value.get('eight_pair_source')==EIGHT,'fixed genuine input pins required')
    for key in ('installer_source','decision_source'):need(re.fullmatch('[0-9a-f]{40}',value.get(key) or ''),'Root immutable source binding required')
    need(set(value.get('prerequisites',{}))=={'native600','fresh600','setup5_600'},'three independent actual decisions required')
    return value


def prerequisites(root,value):
    decisions={key:read(checked(root,row)) for key,row in value['prerequisites'].items()}
    expected={'native600':'ROOT_ACCEPTED_NATIVE_EXPANDED600_COMPOSITION',
              'fresh600':'ROOT_ACCEPTED_SIGNED_EXPANDED600_FRESH_INSTALLER',
              'setup5_600':'ROOT_ACCEPTED_NATIVE_SETUP5_EXPANDED600_LIFECYCLE'}
    for key,record in decisions.items():
        need(record.get('status')==expected[key] and record.get('package_count')==600 and
             record.get('expected600_sha256')==BEFORE and record.get('cleanup')=='PASS' and
             record.get('hardware')=='NOT_RUN' and re.fullmatch('[0-9]+',str(record.get('run_id',''))) and
             re.fullmatch('[0-9a-f]{40}',record.get('source_sha') or ''),'Root actual acceptance missing/failed: '+key)
    need(len({str(record['run_id']) for record in decisions.values()})==3,'three distinct actual prerequisite runs required')
    need(decisions['setup5_600'].get('package_sha256')=='1aafee365e3bcb04e1fce694c110a997914a07f4359697df5e017375897385fc',
         'actual Setup5 archive binding required');return decisions
