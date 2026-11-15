#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Fixed same-child pre-exec and inner observations. No policy repair."""
import argparse
import importlib.util
import os
from pathlib import Path
import stat
import sys

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('perl_ns_probe_data',HERE/'data.py');data=importlib.util.module_from_spec(spec);spec.loader.exec_module(data)
observe=data.load('perl_ns_probe_observe',HERE/'observe.py')
CASES=('bwrap-user-mount-net','unshare-mapped-root')
FRAME=b'PERL_NATIVE_NAMESPACE_V1 '


def arguments(case,admission_sha,map_sha,token,mode='--inner'):
    data.need(case in CASES,'fixed namespace case')
    inner=['/usr/bin/python3','-I','-B','/inputs/probe.py',mode,'--case',case,'--admission-sha256',admission_sha,'--source-map-sha256',map_sha,'--token',token]
    if mode=='--exec-probe':return inner
    if case==CASES[0]:return ['/usr/bin/bwrap','--die-with-parent','--unshare-net','--ro-bind','/','/','--proc','/proc','--dev','/dev','--tmpfs','/home','--tmpfs','/var/lib/pacman','--chdir','/tmp','--',*inner]
    return ['/usr/bin/unshare','--user','--map-root-user','--',*inner]


def emit(value):
    raw=FRAME+data.encode(value);data.need(len(raw)<=256*1024,'bounded process frame')
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()


def execute(args):
    a=data.decode(data.read(HERE/'admission.json'));data.admission(a)
    data.need(data.pin(data.encode(a))['sha256']==args.admission_sha256 and a['source_map_sha256']==args.source_map_sha256 and a['token']==args.token,'same Root-bound diagnostic child')
    data.verify_source(HERE,a['source_map_sha256'])
    argv=arguments(args.case,args.admission_sha256,args.source_map_sha256,args.token)
    frame=dict(schema=1,operation=data.OPERATION,case=args.case,phase='inner' if args.inner else 'exec',admission_sha256=args.admission_sha256,source_map_sha256=args.source_map_sha256,token=args.token,context=observe.context())
    if args.inner:emit(frame);return
    data.need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1001 and os.getcwd()=='/work/recipe','exact unprivileged wrapper runtime')
    binary=Path(argv[0]);raw=data.read(binary,4*1024**2);info=binary.stat()
    frame.update(argv=argv,executable=dict(**data.pin(raw),mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid));emit(frame)
    try:os.execve(argv[0],argv,dict(os.environ))
    except OSError as error:
        emit(dict(schema=1,operation=data.OPERATION,case=args.case,phase='exec-error',admission_sha256=args.admission_sha256,source_map_sha256=args.source_map_sha256,token=args.token,errno=error.errno));raise SystemExit(126)


if __name__=='__main__':
    data.need(sys.flags.isolated and not sys.flags.optimize,'isolated unoptimized child')
    parser=argparse.ArgumentParser(description=__doc__);mode=parser.add_mutually_exclusive_group(required=True);mode.add_argument('--exec-probe',action='store_true');mode.add_argument('--inner',action='store_true')
    parser.add_argument('--case',choices=CASES,required=True)
    for key in ('admission-sha256','source-map-sha256','token'):parser.add_argument('--'+key,required=True)
    execute(parser.parse_args())
