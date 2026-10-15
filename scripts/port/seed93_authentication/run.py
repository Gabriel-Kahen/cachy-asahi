#!/usr/bin/env python3
"""Authenticate corrected seed93 archives in a fresh credential-isolated runtime."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).absolute().parent
ENV = {'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8','LANG':'C.UTF-8'}
SOURCE_COMMIT = '2643e1755d402399035976d1f12cd4e8296148bd'
PROFILE = '2f32684073cd945843a5685ca72d951435bb96c252d43344368193c5d3ca9155'


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



def seed_cache(layout, destination, directories):
    """Copy selected pinned public bytes; never reuse reports, links or GPG state."""
    if not directories:
        return 0
    directories = [Path(path).absolute() for path in directories]
    for directory in directories:
        if not directory.is_dir() or any(p.is_symlink() for p in [directory,*directory.parents]):
            raise ValueError('seed cache must be a physical directory')
    profile = (Path(layout)/'profile.json').read_bytes()
    if hashlib.sha256(profile).hexdigest()!=PROFILE:
        raise ValueError('seed profile pin mismatch')
    rows = json.loads(profile)['packages']
    expected = {}
    for row in rows:
        for suffix,size,digest in [('',row['size'],row['sha256']),
                                   ('.sig',row['signature_size'],row['signature_sha256'])]:
            name = row['filename']+suffix
            if Path(name).name!=name or name in expected:
                raise ValueError('seed filename must be selected and unique')
            expected[name] = (size,digest)
    copied = 0
    def identity(info):
        return (info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_size,
                info.st_mtime_ns,info.st_ctime_ns)
    for name,(size,digest) in expected.items():
        for directory in directories:
            source = directory/name
            if not os.path.lexists(source):
                continue
            target = Path(destination)/name
            created = False
            try:
                source_fd = os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
                with os.fdopen(source_fd,'rb') as incoming:
                    before = os.fstat(incoming.fileno())
                    if not stat.S_ISREG(before.st_mode) or before.st_size!=size:
                        raise ValueError('seed must be a regular file of the selected size: '+name)
                    target_fd = os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                    created = True
                    with os.fdopen(target_fd,'wb') as outgoing:
                        hasher = hashlib.sha256()
                        remaining = size
                        while remaining:
                            chunk = incoming.read(min(1048576,remaining))
                            if not chunk:
                                raise ValueError('seed truncated: '+name)
                            outgoing.write(chunk)
                            hasher.update(chunk)
                            remaining -= len(chunk)
                        if (incoming.read(1) or hasher.hexdigest()!=digest or
                            identity(before)!=identity(os.fstat(incoming.fileno())) or
                            identity(before)!=identity(source.lstat())):
                            raise ValueError('seed hash or identity mismatch: '+name)
                        outgoing.flush()
                        os.fsync(outgoing.fileno())
            except BaseException:
                if created:
                    target.unlink()
                raise
            copied += 1
            break
    return copied


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


def guarded_argv(layout, runtime, seed_directories=()):
    command = ['/usr/bin/timeout','--signal=TERM','--kill-after=10s','1800s',
            '/usr/bin/python3','-I','-B',str(HERE/'run.py'),
            '--guarded','--layout',str(layout),'--runtime',str(runtime)]
    for directory in seed_directories:
        command += ['--seed-cache',str(Path(directory).absolute())]
    return command


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--layout',type=Path,help='corrected physical46 frozen directory')
    parser.add_argument('--runtime',type=Path,help='new private output directory; must not exist')
    parser.add_argument('--seed-cache',type=Path,action='append',default=[],help='public archive/signature source directory; repeatable')
    parser.add_argument('--worker',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--guarded',action='store_true',help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    os.umask(0o077)
    if args.worker:
        if args.guarded or args.layout is not None or args.runtime is not None or args.seed_cache:
            parser.error('worker takes no external paths')
        worker(module('seed93_development_caller','caller.py'))
        return 0
    if args.layout is None or args.runtime is None:
        parser.error('--layout and --runtime are required')
    layout,runtime = args.layout.absolute(),args.runtime.absolute()
    if any(p.is_symlink() for p in [layout,*layout.parents]) or not layout.is_dir():
        raise ValueError('layout must be a physical directory')
    if args.guarded:
        copied = seed_cache(layout,runtime/'tmp/cachy-asahi-seed93-auth-cache',args.seed_cache)
        print('Copied pinned cache files: '+str(copied),flush=True)
        return supervise(layout,runtime,module('seed93_development_caller','caller.py'),
                         module('seed93_development_supervisor','guardian/supervisor.py'))
    runtime = private_runtime(runtime)
    command = guarded_argv(layout,runtime,args.seed_cache)
    save(runtime/'invocation.json',dict(argv=command,source_commit=SOURCE_COMMIT,
         profile_sha256=PROFILE,
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
