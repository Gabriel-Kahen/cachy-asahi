# SPDX-License-Identifier: MIT
"""Bounded canonical operands for the separate proposed runtime diagnostic."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

HERE=Path(__file__).resolve().parent
OPERATION='perl5423-native-namespace-v1'
DOMAIN_SHA='6c6bdc29acf59e8ea911167f08d4d66a993777c121b2399211cec030e2a5b804'
OLD_SOURCE='3937d8b9f3210f4e9868bf19f01dfa22de64ddfe'
OWNED_SHA='eaf9a46630e4fe4ca0a8f94a6dc2de4a881a6ad7e8b4dd0810b3347c0d7038d5'


def need(value,why):
    if not value:raise ValueError(why)


def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def decode(raw):
    need(type(raw) is bytes and len(raw)<=1024**2,'bounded JSON operand')
    def pairs(rows):
        result={}
        for name,value in rows:need(name not in result,'duplicate JSON key');result[name]=value
        return result
    def invalid(value):raise ValueError('floating or nonfinite JSON refused')
    return json.loads(raw,object_pairs_hook=pairs,parse_float=invalid,parse_constant=invalid)


def read(path,cap=1024**2):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts,'absolute canonical operand')
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            other=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=other
        leaf=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        try:
            before=os.fstat(leaf)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded ordinary single-link DATA')
            chunks=[];size=0
            while block:=os.read(leaf,min(65536,cap+1-size)):
                size+=len(block);need(size<=cap,'DATA cap');chunks.append(block)
            key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
            need(size==before.st_size and key(before)==key(os.fstat(leaf))==key(os.stat(path.name,dir_fd=fd,follow_symlinks=False)),'stable whole DATA read')
            return b''.join(chunks)
        finally:os.close(leaf)
    finally:os.close(fd)


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def admission(a):
    need(type(a) is dict and set(a)=={'schema','operation','source','run','job','image','approval','source_map_sha256','domain_sha256','token','container','volume','inputs'},'closed external Root diagnostic admission')
    need(type(a['schema']) is int and a['schema']==1 and a['operation']==OPERATION,'separate operation')
    for key,length in [('source',40),('approval',64),('source_map_sha256',64),('token',24)]:need(type(a[key]) is str and re.fullmatch('[0-9a-f]{'+str(length)+'}',a[key]),'actual Root binding '+key)
    need(a['source']!=OLD_SOURCE,'Source3937 ordinary Docker RUN cannot qualify this domain')
    need(all(type(a[k]) is str and re.fullmatch('[1-9][0-9]{0,19}',a[k]) for k in ('run','job')),'actual run/job')
    need(type(a['image']) is str and re.fullmatch('sha256:[0-9a-f]{64}',a['image']) and a['domain_sha256']==DOMAIN_SHA,'actual native image/domain')
    name='perl-namespace-'+a['run']+'-'+a['token'][:12]
    need(a['container']==name and a['volume']==name+'-work','Root-owned unique diagnostic resources')
    need(type(a['inputs']) is str and re.fullmatch('/[A-Za-z0-9._+/-]{1,240}',a['inputs']) and all(p not in ('','.','..') for p in a['inputs'].split('/')[1:]),'canonical host input bind path')
    return a


def verify_source(root,expected):
    raw=read(root/'source-map.json');need(pin(raw)['sha256']==expected,'Root-bound complete diagnostic Source map')
    m=decode(raw);need(m['schema']==1 and m['actual']==dict(source=None,ref=None,run=None,job=None,approval=None,artifact=None,image=None),'unpublished proposed Source map')
    files=m['files'];need(type(files) is dict and 1<=len(files)<=24,'finite Source leaves')
    names=set(files)|{'source-map.json','admission.json','host.json'}
    nodes=list(root.rglob('*'));need(len(nodes)<=32 and all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in nodes),'finite ordinary diagnostic inputs')
    need({str(p.relative_to(root)) for p in nodes if p.is_file()}==names,'closed actual inputs')
    directories={str(parent) for name in names for parent in Path(name).parents if str(parent)!='.'}
    need({str(p.relative_to(root)) for p in nodes if p.is_dir()}==directories,'no unrecorded Source directories')
    for name,row in files.items():
        need(re.fullmatch('[A-Za-z0-9._+/-]{1,128}',name) and all(p not in ('','.','..') for p in name.split('/')),'safe relative Source leaf')
        path=root/name;body=read(path)
        need(dict(**pin(body),mode=stat.S_IMODE(path.stat().st_mode))==row,'actual Source leaf differs: '+name)
    need(pin(read(root/'domain.json'))['sha256']==DOMAIN_SHA,'exact held adapter domain bytes')
    return m
