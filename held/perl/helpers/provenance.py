#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retain complete bounded recipe/source/build maps and actual environment."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat


def pin(path):
    body=path.read_bytes();return dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())


def tree(root):
    rows={};total=0
    if not root.is_dir():return rows
    for path in sorted(root.rglob('*')):
        info=path.lstat();name=path.relative_to(root).as_posix()
        row=dict(mode=stat.S_IMODE(info.st_mode))
        if path.is_symlink():row.update(type='symlink',target=os.readlink(path))
        elif path.is_dir():row.update(type='directory')
        else:
            if not stat.S_ISREG(info.st_mode) or info.st_size>64*1024**2:raise ValueError('ordinary bounded build file required')
            row.update(type='file',**pin(path));total+=info.st_size
        rows[name]=row
        if len(rows)>20000 or total>1024**3:raise ValueError('bounded Perl tree required')
    return rows


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--exit',type=int,required=True);args=parser.parse_args()
    out=Path('/work/output');recipe=Path('/work/recipe');source=recipe/'src/perl5-bc3dab4d4f66de5ea67dda34e5feb5230a54c603'
    for name,root in [('recipe-input-map',Path('/inputs/recipe')),('built-tree-map',source)]:
        (out/(name+'.json')).write_text(json.dumps(tree(root),sort_keys=True,indent=2)+'\n')
    for name in ('config.sh','config.h','Makefile','regexec.c','regexp.h'):
        if (source/name).is_file():shutil.copyfile(source/name,out/('source-'+name))
    environment={'makepkg_exit':args.exit,'uid':os.getuid(),'gid':os.getgid(),'uname':list(os.uname()),
        'page_bytes':os.sysconf('SC_PAGE_SIZE'),'environment':{k:os.environ[k] for k in ['PATH','LC_ALL','TZ','MAKEFLAGS','SOURCE_DATE_EPOCH','CACHY_ASAHI_PERL_BUILD','HOME','TMPDIR','PKGDEST']},
        'cgroup':{n:Path('/sys/fs/cgroup/'+n).read_text().strip() for n in ['cpu.max','memory.max','memory.swap.max','pids.max']},
        'mountinfo':Path('/proc/self/mountinfo').read_text(),'status':Path('/proc/self/status').read_text(),
        'makepkg_configuration':Path('/etc/makepkg.conf').read_text()}
    (out/'environment.json').write_text(json.dumps(environment,sort_keys=True,indent=2)+'\n')


if __name__=='__main__':main()
