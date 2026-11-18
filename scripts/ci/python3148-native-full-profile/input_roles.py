# SPDX-License-Identifier: MIT
"""Exact scheduled HTTPS DATA and same-byte staging for the Python build."""
import json
import os
from pathlib import Path
import stat
import sys
import time
import urllib.request

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import preflight as P

PIN_SHA='b1e9bbb7e26ae0e6fe2b0e6414571d9952af3db67ff2bc7fe5a97559ea8e9643'
TOTAL=28592620
RESERVE=64<<20
MAX_SECONDS=120
CA='https://ca.us.mirror.archlinuxarm.org/aarch64/extra/'
BLUEZ='https://mirror.iscas.ac.cn/archlinuxarm/aarch64/extra/'
PYTHON='https://www.python.org/ftp/python/3.14.8/Python-3.14.8.tar.xz'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None


def pins():
    raw=P.read(HERE/'material-pins.json',16<<10)
    P.need(P.pin(raw)['sha256']==PIN_SHA,'exact whole Python transport pin map')
    expected={name:item for name,item in json.loads(raw).items()
              if name==P.SRC or '.pkg.tar.xz' in name}
    P.need(len(expected)==9 and sum(item['bytes'] for item in expected.values())==TOTAL,
           'exact nine bounded public operand leaves')
    return expected


def urls(expected):
    return {name:PYTHON if name==P.SRC else (BLUEZ if name.startswith('bluez-') else CA)+name
            for name in expected}


def reader(name,url,digest,deadline,opener):
    remaining=deadline-time.monotonic()
    P.need(0<remaining<=MAX_SECONDS,'finite exact input acquisition deadline')
    request=urllib.request.Request(url,headers={'Accept-Encoding':'identity'})
    with opener.open(request,timeout=min(20,remaining)) as response:
        P.need(response.status==200 and response.geturl()==url
               and response.headers.get('Content-Encoding','identity')=='identity',
               'exact successful no-redirect public operand')
        claimed=response.headers.get('Content-Length')
        P.need(claimed is None or claimed.isdecimal() and int(claimed)==digest['bytes'],'bounded transport length')
        chunks=[];used=0
        while True:
            P.need(time.monotonic()<deadline,'whole bounded public input acquisition')
            block=response.read(min(65536,digest['bytes']+1-used))
            if not block:break
            chunks.append(block);used+=len(block)
            P.need(used<=digest['bytes'],'exact operand download cap')
    raw=b''.join(chunks)
    P.need(P.pin(raw)==digest,'whole downloaded operand differs: '+name)
    return raw


def room(output):
    target=output.parent
    info=target.stat(); fs=os.statvfs(target)
    P.need(output.is_absolute() and output==output.resolve() and not output.exists()
           and stat.S_ISDIR(info.st_mode) and not info.st_mode&0o022
           and fs.f_frsize*fs.f_bavail>=RESERVE and fs.f_favail>=32,
           'fresh private Python transport staging with independent byte/inode reserve')


def materialize(output, operands, expected):
    room(output)
    destination=output
    destination.mkdir(mode=0o700)
    for name,raw in operands.items():
        P.need(P.pin(raw)==expected[name],'same verified staged operand')
        P.put(destination/name,raw,0o400)
    P.need(set(operands)==set(expected),'whole transport material namespace')


def fetch(output, opener=None):
    room(output)
    P.need(os.getuid()==os.geteuid()>0,'ordinary user transport only')
    expected=pins()
    browser=opener or urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    deadline=time.monotonic()+MAX_SECONDS
    selected={name:reader(name,url,expected[name],deadline,browser) for name,url in urls(expected).items()}
    materialize(output,selected,expected)


def accept(source):
    expected=pins()
    P.need({path.name for path in source.iterdir()}==set(expected),'closed separate Python DATA input role')
    return {name:P.read(source/name,max(row['bytes'],1),row) for name,row in expected.items()}


def stage(source,dest,uid,gid):
    room(dest)
    P.need(type(uid) is int and uid>0 and type(gid) is int and gid>0,'ordinary build coordinator identity')
    values=accept(source)
    dest.mkdir(mode=0o700)
    delta=dest/'builder-delta';delta.mkdir(mode=0o700)
    cache=dest/'source-cache';cache.mkdir(mode=0o700)
    for child in ('objects','receipts','.partial'):
        (cache/child).mkdir(mode=0o700)
    P.put(cache/'FORMAT',P.read(HERE/'cache-FORMAT.data',128),0o600)
    P.put(cache/'receipts'/f'{P.CATALOG_SHA}-{P.SOURCE_ID}.json',P.read(HERE/'cache-receipt.json',8192),0o600)
    for name,raw in values.items():
        if name==P.SRC:
            P.put(cache/'objects'/P.pin(raw)['sha256'],raw,0o600)
        else:
            P.put(delta/name,raw,0o400)
    for path in sorted(dest.rglob('*'),reverse=True):
        os.chown(path,uid,gid,follow_symlinks=False)
    os.chown(dest,uid,gid,follow_symlinks=False)
