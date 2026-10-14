# SPDX-License-Identifier: MIT
"""Explicit Root worker entry; default use refuses, no native selection here.

Root's existing Source/270 and process guardian admit this entry before launch.
All numeric endpoints belong to the same original host monotonic clock domain.
The stdout record is PRIVATE and requires Root's observed worker retirement.
"""
import argparse
import hashlib
import json
import math
import os
import stat
import sys
import time
from types import ModuleType

RETAINED=[]

def need(ok,code):
    if not ok:raise ValueError(code)

def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def bounded_source(path,pin,E):
    slot={'fd':None,'path':path,'uncertainty':'open-outcome-unproved'};first=None;raw=None;stopped=False;last=None
    def gate():
        nonlocal stopped,last
        need(not stopped,'worker-bootstrap-stopped')
        try:
            now=time.monotonic()
            need(type(now) in (int,float) and math.isfinite(now) and 0<now<E and (last is None or now>=last),'worker-original-E')
            last=now
        except BaseException:stopped=True;raise
    gate();need(os.path.isabs(path) and '..' not in path.split('/'),'worker-canonical-source')
    need(type(pin)is str and len(pin)==64 and all(c in '0123456789abcdef' for c in pin),'worker-source-sha')
    gate();RETAINED.append(slot)
    try:
        gate();before=os.lstat(path);gate()
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=1024**2,'worker-source-file')
        gate();slot['fd']=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);gate()
        slot['uncertainty']=None;gate();opened=os.fstat(slot['fd']);gate()
        need(identity(opened)==identity(before),'worker-source-open-drift');data=bytearray()
        while len(data)<before.st_size:
            gate();block=os.pread(slot['fd'],min(65536,before.st_size-len(data)),len(data));gate()
            need(block,'worker-source-short');data.extend(block)
        gate();held=os.fstat(slot['fd']);gate();named=os.lstat(path);gate()
        need(identity(before)==identity(held)==identity(named),'worker-source-drift')
        gate();need(hashlib.sha256(data).hexdigest()==pin,'worker-source-pin');gate();raw=bytes(data)
    except BaseException as error:first=error
    if slot['fd'] is not None:
        try:gate();os.close(slot['fd']);slot['fd']=None;slot['closed']=True;gate()
        except BaseException as error:
            slot['uncertainty']=error
            if first is None:first=error
    if slot.get('closed'):
        try:RETAINED.remove(slot)
        except BaseException as error:
            slot['uncertainty']=error
            if first is None:first=error
    if first is not None:
        try:first.retained_worker_bootstrap=slot
        except BaseException:pass
        raise first
    gate();return raw

def private_packet(handoff):
    """Serialize evidence, retain resources in this worker until actual exit."""
    need(handoff['status']=='PRIVATE_ROOT_CONTAINMENT_REQUIRED' and handoff['publication_allowed'] is False,'worker-private-status')
    helper=handoff['helper_cleanup']
    serial={k:v for k,v in handoff.items() if k not in ('retained_session','helper_cleanup')}
    serial['helper_cleanup']={'status':helper['status'],'publication_allowed':False,
        'retained_mapping_count':len(helper.get('retained_mappings',())),
        'retained_context_count':len(helper.get('retained_contexts',())),
        'retained_uncertainty_count':len(helper.get('retained_uncertainties',()))}
    raw=json.dumps(serial,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    need(len(raw)<=1024**2,'worker-private-record-bound');return raw+b'\n'

def main(argv=None):
    parser=argparse.ArgumentParser()
    for name in ('packet','packet-sha','driver','driver-sha','original-entry','original-J'):
        parser.add_argument('--'+name,required=True)
    args=parser.parse_args(argv);start=float(args.original_entry);J=float(args.original_J)
    need(math.isfinite(start) and math.isfinite(J) and start>0 and J==start+7200,'worker-original-clock')
    E=J-360;need(start<=time.monotonic()<E,'worker-original-bootstrap')
    packet_raw=bounded_source(args.packet,args.packet_sha,E)
    packet=json.loads(packet_raw);need(type(packet)is dict and set(packet)=={'value','pins'},'worker-closed-packet')
    value=packet['value'];need(value['original_entry']==start and value['workflow_end']==J,'worker-packet-original-clock')
    source=bounded_source(args.driver,args.driver_sha,E)
    need(time.monotonic()<E and not RETAINED,'worker-source-compile-eligibility')
    driver=ModuleType('root_admitted_integrated_pair_driver')
    need(time.monotonic()<E,'worker-source-module-late')
    code=compile(source,args.driver,'exec',dont_inherit=True)
    need(time.monotonic()<E,'worker-source-compile-late')
    exec(code,driver.__dict__)
    need(time.monotonic()<E,'worker-source-initialization-late')
    handoff=driver.execute(value,packet['pins'],dict(os.environ))
    handoff['packet_sha256']=args.packet_sha;handoff['driver_sha256']=args.driver_sha
    raw=private_packet(handoff);need(time.monotonic()<J,'worker-original-publication')
    count=sys.stdout.buffer.write(raw)
    need(time.monotonic()<J,'worker-private-write-late')
    need(count==len(raw),'worker-private-write-short')
    need(time.monotonic()<J,'worker-private-flush-eligibility');sys.stdout.buffer.flush()
    need(time.monotonic()<J,'worker-private-write-late')
    # Root captures stdout under its existing held process owner. This worker
    # publishes no PASS and cannot prove its own exit, absence or unmapping.
    return 0

if __name__=='__main__':raise SystemExit(main())
