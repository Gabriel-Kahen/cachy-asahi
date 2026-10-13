# SPDX-License-Identifier: MIT
"""Captured parent launcher for one inherited TEST-agent listener; no key work."""
import argparse
import hashlib
import math
import os
import re
from pathlib import Path
import stat
import time


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--listener-fd',type=int,required=True)
    parser.add_argument('--agent-sha256',required=True)
    parser.add_argument('--keyhome',type=Path,required=True)
    parser.add_argument('--deadline-at',type=float,required=True)
    args=parser.parse_args()
    if not math.isfinite(args.deadline_at) or time.monotonic()>=args.deadline_at:
        raise ValueError('signer-entry-deadline')
    if args.listener_fd<3 or not re.fullmatch('[0-9a-f]{64}',args.agent_sha256):raise ValueError('signer-entry-arguments')
    home=args.keyhome.lstat()
    if args.keyhome!=args.keyhome.resolve() or not stat.S_ISDIR(home.st_mode) or home.st_uid!=os.getuid() or home.st_gid!=os.getgid() or stat.S_IMODE(home.st_mode)!=0o700:
        raise ValueError('signer-entry-keyhome')
    before=Path('/usr/bin/gpg-agent').lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_gid!=0 or before.st_nlink!=1 or stat.S_IMODE(before.st_mode)!=0o755 or not 0<before.st_size<=64*1024**2:
        raise ValueError('signer-entry-tool')
    fd=os.open('/usr/bin/gpg-agent',os.O_RDONLY|os.O_NOFOLLOW)
    try:
        opened=os.fstat(fd)
        digest=hashlib.sha256();count=0
        while block:=os.read(fd,65536):
            if time.monotonic()>=args.deadline_at:raise ValueError('signer-entry-deadline')
            count+=len(block)
            if count>64*1024**2:raise ValueError('signer-entry-tool-bound')
            digest.update(block)
        after=os.fstat(fd);named=Path('/usr/bin/gpg-agent').lstat()
        fields=('st_dev','st_ino','st_size','st_mode','st_nlink','st_mtime_ns','st_ctime_ns')
        if digest.hexdigest()!=args.agent_sha256 or any(getattr(before,k)!=getattr(item,k) for item in (opened,after,named) for k in fields):
            raise ValueError('signer-entry-pin')
    finally:os.close(fd)
    listener=os.fstat(args.listener_fd)
    if not stat.S_ISSOCK(listener.st_mode):raise ValueError('signer-entry-listener')
    os.dup2(args.listener_fd,3,inheritable=True)
    if args.listener_fd!=3:os.close(args.listener_fd)
    env=dict(os.environ);env.update(LISTEN_PID=str(os.getpid()),LISTEN_FDS='1',LISTEN_FDNAMES='std')
    argv=['/usr/bin/gpg-agent','--no-options','--homedir',str(args.keyhome),'--supervised',
        '--disable-scdaemon','--extra-socket','none','--browser-socket','none','--allow-loopback-pinentry','--no-allow-external-cache']
    if time.monotonic()>=args.deadline_at:raise ValueError('signer-entry-deadline')
    os.execve('/usr/bin/gpg-agent',argv,env)


if __name__=='__main__':main()
