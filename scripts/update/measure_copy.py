#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy bounded container filesystem data, then measure that explicitly scoped copy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

import full_root as roots
from capacity import check as check_capacity
from supervision import run

RUNTIME = {'proc','sys','dev','run','tmp','inputs','out','source','workspace'}


def need(ok,reason):
    if not ok:raise ValueError(reason)


def copy_data(source,target,*,limits,excluded=(),reserve_bytes=16*1024**2,reserve_inodes=1024,shape_examples=0):
    """No source mutation. Symlinks/hardlinks are preserved as data, never followed."""
    limits.tick()
    need(type(shape_examples) is int and 0 <= shape_examples <= 16,'bounded shape samples required')
    special_examples=[]
    source,target=Path(source),Path(target)
    need(not target.exists() and not target.is_symlink(),'fresh private copy required')
    # Reserve the configured upper bound before allocating any copy content.
    check_capacity([dict(path=str(target.parent),bytes=limits.max_bytes+limits.max_nodes*4096+reserve_bytes,
                         inodes=limits.max_nodes+reserve_inodes)])
    excluded=set(excluded)
    need(all(name and not name.startswith('/') and '..' not in name.split('/') for name in excluded),'contained exclusions required')
    report=dict(source_nodes=0,copied_nodes=0,logical_bytes=0,source_hardlink_entries=0,source_allocated_bytes=0,excluded=[],unsupported_counts={},copy_complete=True)
    source_fd=roots._open_root(source)
    root_stat=os.fstat(source_fd)
    target.mkdir(mode=0o700)
    destination_fd=os.open(target,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    hardlinks={};allocated_inodes=set()
    def identity(info):return roots._identity(info)
    def metadata(fd,info):
        os.fchown(fd,info.st_uid,info.st_gid);os.fchmod(fd,stat.S_IMODE(info.st_mode))
    def walk(src,dst,prefix='',depth=0):
        limits.tick();need(depth<=limits.max_depth,'copy depth limit')
        before=os.fstat(src)
        for name in sorted(os.listdir(src)):
            limits.tick();path=prefix+name
            info=os.stat(name,dir_fd=src,follow_symlinks=False)
            if path in excluded:
                report['excluded'].append(path);report['copy_complete']=False;continue
            need(info.st_dev==root_stat.st_dev,'unexcluded cross-device source')
            report['source_nodes']+=1;need(report['source_nodes']<=limits.max_nodes,'copy node limit')
            if stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                report['copied_nodes']+=1
            if stat.S_ISDIR(info.st_mode):
                child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=src)
                os.mkdir(name,mode=0o700,dir_fd=dst)
                output=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dst)
                try:
                    need(identity(os.fstat(child))==identity(info),'source directory drift')
                    walk(child,output,path+'/',depth+1);metadata(output,info)
                finally:os.close(output);os.close(child)
            elif stat.S_ISREG(info.st_mode):
                need(info.st_size<=limits.max_file_bytes,'copy file byte limit')
                report['logical_bytes']+=info.st_size;need(report['logical_bytes']<=limits.max_bytes,'copy byte limit')
                if info.st_nlink>1:report['source_hardlink_entries']+=1
                inode=(info.st_dev,info.st_ino)
                if inode not in allocated_inodes:
                    allocated_inodes.add(inode);report['source_allocated_bytes']+=info.st_blocks*512
                if info.st_nlink>1 and inode in hardlinks:
                    os.link(hardlinks[inode],path,src_dir_fd=destination_fd,dst_dir_fd=destination_fd,follow_symlinks=False)
                else:
                    old=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=src)
                    new=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dst)
                    try:
                        need(identity(os.fstat(old))==identity(info),'source file drift')
                        total=0
                        while True:
                            limits.tick();data=os.read(old,1024**2)
                            if not data:break
                            total+=len(data);need(total<=info.st_size,'growing copy source')
                            view=memoryview(data)
                            while view:view=view[os.write(new,view):]
                        need(total==info.st_size and identity(os.fstat(old))==identity(info),'changed copy source')
                        metadata(new,info)
                    finally:os.close(new);os.close(old)
                    if info.st_nlink>1:hardlinks[inode]=path
            elif stat.S_ISLNK(info.st_mode):
                os.symlink(os.readlink(name,dir_fd=src),name,dir_fd=dst)
                os.chown(name,info.st_uid,info.st_gid,dir_fd=dst,follow_symlinks=False)
            else:
                key='special-node';report['unsupported_counts'][key]=report['unsupported_counts'].get(key,0)+1
                if shape_examples and len(special_examples)<shape_examples:
                    kind = ('socket' if stat.S_ISSOCK(info.st_mode) else 'fifo' if stat.S_ISFIFO(info.st_mode)
                            else 'character-device' if stat.S_ISCHR(info.st_mode) else 'block-device' if stat.S_ISBLK(info.st_mode)
                            else 'other-special')
                    special_examples.append({'path':path[:1024],'path_truncated':len(path)>1024,'kind':kind})
                report['copy_complete']=False
            need(identity(os.stat(name,dir_fd=src,follow_symlinks=False))==identity(info),'named copy source drift')
        need(identity(os.fstat(src))==identity(before),'source directory content drift')
    try:
        walk(source_fd,destination_fd)
        need(identity(os.fstat(source_fd))==identity(root_stat),'source root drift')
    finally:os.close(destination_fd);os.close(source_fd)
    observation=roots.observe(target,limits=limits,shape_examples=shape_examples)
    report.update(footprint=observation['footprint'],observation_complete=observation['complete'],
                  unsupported_observation=observation['unsupported_counts'],
                  unsupported_examples=observation['unsupported'],eligible=observation['eligible'] and report['copy_complete'])
    if shape_examples:
        report['shape_diagnostics']=observation['shape_diagnostics']
        count=report['unsupported_counts'].get('special-node',0)
        report['source_special_samples']={'count':count,'examples':special_examples,
            'examples_complete':count<=shape_examples and not any(x['path_truncated'] for x in special_examples),
            'sample_limit':shape_examples,'sample_path_char_limit':1024}
    return report


def lock(raw):
    rows={}
    for line in raw.decode().splitlines():
        name,version=line.split()
        need(name not in rows,'duplicate inventory entry');rows[name]=version
    need(len(rows)==587 and {'glibc','pacman','linux-aarch64','cachy-asahi-update'}<=rows.keys(),
         'actual composition inventory required')
    return rows


def copied_inventory(root):
    local=roots._open_root(Path(root)/'var/lib/pacman/local');rows={}
    try:
        for name in os.listdir(local):
            info=os.stat(name,dir_fd=local,follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode):
                need(name=='ALPM_DB_VERSION' and stat.S_ISREG(info.st_mode),'unexpected local database node')
                continue
            directory=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=local)
            try:
                desc=os.open('desc',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
                try:
                    need(stat.S_ISREG(os.fstat(desc).st_mode),'ordinary package descriptor required')
                    raw=os.read(desc,65537);need(len(raw)<=65536,'package descriptor bound')
                finally:os.close(desc)
            finally:os.close(directory)
            fields=raw.decode().splitlines()
            need(fields.count('%NAME%')==fields.count('%VERSION%')==1,'unique package descriptor identity required')
            package,version=fields[fields.index('%NAME%')+1],fields[fields.index('%VERSION%')+1]
            need(package not in rows and len(rows)<587,'bounded unique copied package inventory')
            rows[package]=version
    finally:os.close(local)
    return rows


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--expected-lock',type=Path,required=True)
    parser.add_argument('--expected-lock-sha256',required=True)
    parser.add_argument('--max-bytes',type=int,required=True);parser.add_argument('--max-nodes',type=int,required=True)
    parser.add_argument('--max-file-bytes',type=int,required=True);parser.add_argument('--seconds',type=int,default=900)
    parser.add_argument('--shape-examples-per-category',type=int,default=0,help='Optional bounded path/kind and target-class diagnostics; no target values')
    args=parser.parse_args();workspace=args.workspace
    need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file()
         and re.fullmatch('[0-9a-f]{32}',os.environ.get('CACHY_ASAHI_BOUND_UPDATE','')),'marked native owned container required')
    need(workspace.is_absolute() and workspace.is_dir() and not any(p.is_symlink() for p in (workspace,*workspace.parents))
         and workspace.stat().st_uid==0 and stat.S_IMODE(workspace.stat().st_mode)==0o700,'owned private workspace required')
    interfaces={line.split(':',1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines() if ':' in line}
    need(interfaces=={'lo'} and os.environ.get('PATH')=='/usr/bin:/bin','network-none clean container required')
    need(type(args.shape_examples_per_category) is int and 0<=args.shape_examples_per_category<=16,'bounded shape samples required')
    need(0<args.seconds<=3600 and 0<args.max_bytes<=64*1024**3 and 0<args.max_nodes<=4000000
         and 0<args.max_file_bytes<=args.max_bytes,'finite copy bounds required')
    raw=roots.installer.bounded_read(args.expected_lock,1024**2);need(hashlib.sha256(raw).hexdigest()==args.expected_lock_sha256,
                                            'pinned exact composition lock required')
    expected=lock(raw)
    def actual():
        row=run(['/usr/bin/pacman','-Q'],env={'PATH':'/usr/bin:/bin','HOME':str(workspace),'LC_ALL':'C'},
                cwd=workspace,timeout=30,output_limit=1024**2)
        need(row['termination'] is None and row['returncode']==0,'read-only actual package query failed')
        value=lock(row['stdout']);need(value==expected,'actual composition lock differs');return value
    before=actual()
    excluded=set(RUNTIME)
    source_root_readonly=False
    for row in Path('/proc/self/mountinfo').read_text().splitlines():
        point=row.split()[4]
        need('\\' not in point,'escaped mount names require explicit review')
        if point=='/':source_root_readonly='ro' in row.split()[5].split(',')
        else:excluded.add(point.lstrip('/'))
    excluded.add(workspace.as_posix().lstrip('/'))
    limits=roots.Limits(deadline=time.monotonic()+args.seconds,max_nodes=args.max_nodes,
                        max_bytes=args.max_bytes,max_file_bytes=args.max_file_bytes)
    report=copy_data(Path('/'),workspace/'root',limits=limits,excluded=excluded,shape_examples=args.shape_examples_per_category)
    need(actual()==before,'package inventory changed during copy')
    copied=copied_inventory(workspace/'root')
    need(copied==expected,'copied package database differs from actual587 lock')
    report.update(status='MEASURED_SCOPED_COPY',inventory_count=587,inventory_sha256=args.expected_lock_sha256,
                  source='owned native container filesystem data; mounted/runtime paths excluded',
                  consistency='per-file identity checks and stable actual/copied package inventory; not an atomic snapshot',
                  source_root_mount_readonly=source_root_readonly,source_operations='READ ONLY',
                  copied_metadata='contents, modes, UID/GID, symlinks and internal hardlinks; xattrs/timestamps omitted',
                  whole_root_copy=False,transaction_acceptance='NOT ESTABLISHED')
    (workspace/'footprint.json').write_text(json.dumps(report,sort_keys=True)+'\n')
    print(json.dumps(report,sort_keys=True))
    return 0


if __name__=='__main__':raise SystemExit(main())
