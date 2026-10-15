#!/usr/bin/env python3
"""Authenticate corrected seed93 archives in a fresh credential-isolated runtime."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).absolute().parent
ENV = {'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8','LANG':'C.UTF-8'}
SOURCE_COMMIT = '2643e1755d402399035976d1f12cd4e8296148bd'


def module(name, relative):
    path = HERE/relative
    spec = importlib.util.spec_from_file_location(name,path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def save(path, value):
    raw = (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def private_runtime(path):
    path = Path(path).absolute()
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,os.getuid()) or info.st_mode&0o022:
            raise ValueError('unsafe runtime ancestor')
    path.mkdir(mode=0o700)  # exclusive; an old/partial run is never resumed
    for name in ['tmp','tmp/home','tmp/runtime','tmp/cachy-asahi-seed93-auth-cache','work','supervisor']:
        (path/name).mkdir(mode=0o700)
    return path


def worker(caller):
    # The profile digest is only a binding operand for RealOperations.
    # Source identities/hash/signature/observation policies are checked by caller.
    return caller.authenticate_inside('/source','/work',caller.PROFILE)


def supervise(layout, runtime, caller, supervisor):
    argv = caller.namespace(runtime,layout,HERE,
        ['/usr/bin/python3','-I','-B','/caller/run.py','--worker'])
    result = caller.supervise_selected(supervisor,argv,runtime/'supervisor')
    save(runtime/'process-result.json',result)
    return 0 if (result['status']=='PASS_PROCESS_ENVELOPE' and
                 result['returncode']==0 and result['cleanup_verified'] is True and
                 result['cleanup_uncertainty'] is False and result['cancelled'] is False) else 1


def guarded_argv(layout, runtime):
    return ['/usr/bin/timeout','--signal=TERM','--kill-after=10s','1800s',
            '/usr/bin/python3','-I','-B',str(HERE/'run.py'),
            '--guarded','--layout',str(layout),'--runtime',str(runtime)]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--layout',type=Path,help='corrected physical46 frozen directory')
    parser.add_argument('--runtime',type=Path,help='new private output directory; must not exist')
    parser.add_argument('--worker',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--guarded',action='store_true',help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.worker:
        if args.guarded or args.layout is not None or args.runtime is not None:
            parser.error('worker takes no external paths')
        worker(module('seed93_development_caller','caller.py'))
        return 0
    if args.layout is None or args.runtime is None:
        parser.error('--layout and --runtime are required')
    layout,runtime = args.layout.absolute(),args.runtime.absolute()
    if any(p.is_symlink() for p in [layout,*layout.parents]) or not layout.is_dir():
        raise ValueError('layout must be a physical directory')
    if args.guarded:
        return supervise(layout,runtime,module('seed93_development_caller','caller.py'),
                         module('seed93_development_supervisor','guardian/supervisor.py'))
    runtime = private_runtime(runtime)
    command = guarded_argv(layout,runtime)
    save(runtime/'invocation.json',dict(argv=command,source_commit=SOURCE_COMMIT,
         profile_sha256='2f32684073cd945843a5685ca72d951435bb96c252d43344368193c5d3ca9155',
         source_manifest_sha256='bd72c0d2da36117071b0a1683ed96857c71e50f73a220488f5d20f6463ba906e',
         automatic_retry=False,installation=False))
    print('Authentication runtime: '+str(runtime),flush=True)
    # Become the GNU guardian so Ctrl-C and timeout retain its normal process
    # group semantics; no detached parent waits or second work budget.
    with (runtime/'stdout.log').open('xb') as stdout,(runtime/'stderr.log').open('xb') as stderr:
        os.dup2(stdout.fileno(),1)
        os.dup2(stderr.fileno(),2)
    os.execve(command[0],command,ENV)



if __name__=='__main__':
    raise SystemExit(main())
