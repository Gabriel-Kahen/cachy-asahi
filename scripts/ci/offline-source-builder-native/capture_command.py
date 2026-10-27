#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture only the finite observer's inspect/kill CLI with separate bounded streams."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import subprocess
import sys
DOCKER=('/usr/bin/docker','--host=unix:///var/run/docker.sock')
CAP=4*1024**2


def allowed(argv):
    if type(argv)is not list or not all(type(v)is str for v in argv)or tuple(argv[:2])!=DOCKER:return False
    return len(argv)==5 and re.fullmatch('cachy-asahi-[0-9a-f]{16}',argv[-1])and(argv[2:4]in(['container','inspect'],['kill','--signal=KILL']))


def execute(request,output):
    if type(request)is not dict or set(request)!={'argv','timeout'}or not allowed(request['argv'])or type(request['timeout'])is not int or not 1<=request['timeout']<=15:
        raise ValueError('finite observed Docker command required')
    output=Path(output).absolute()
    if output.exists()or output!=output.resolve()or not output.parent.is_dir():raise ValueError('fresh ordinary capture output')
    output.mkdir(mode=0o700)
    def limits():resource.setrlimit(resource.RLIMIT_FSIZE,(CAP,CAP))
    with(output/'stdout').open('xb')as out,(output/'stderr').open('xb')as err:
        result=subprocess.run(request['argv'],stdin=subprocess.DEVNULL,stdout=out,stderr=err,timeout=request['timeout'],preexec_fn=limits)
    if type(result.returncode)is not int:raise ValueError('exact capture return code required')
    pins={}
    for name in('stdout','stderr'):
        raw=(output/name).read_bytes()
        if len(raw)>CAP:raise ValueError('capture stream bound')
        pins[name]={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    receipt={'schema_version':1,'argv':request['argv'],'returncode':result.returncode,'streams':pins}
    (output/'receipt.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    return receipt


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--request',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:print(json.dumps(execute(json.loads(a.request.read_text()),a.output),sort_keys=True))
    except(OSError,ValueError,KeyError,subprocess.SubprocessError)as e:print(str(e),file=sys.stderr);raise SystemExit(1)
