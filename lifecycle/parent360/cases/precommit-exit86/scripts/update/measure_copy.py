#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy bounded container filesystem data, then measure that explicitly scoped copy."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

import full_root as roots
from capacity import check as check_capacity
from supervision import run

RUNTIME = {'proc','sys','dev','run','tmp','inputs','out','source','workspace'}


def need(ok,reason):
    if not ok:raise ValueError(reason)


@contextmanager
def _descriptors():
    held=[]
    try:
        yield held
    finally:
        original=sys.exc_info()[1];failed=False
        for fd in reversed(held):
            try:os.close(fd)
            except OSError:failed=True
        if failed:
            if original is not None:original.add_note('copy descriptor cleanup failed')
            else:raise ValueError('copy descriptor cleanup failed')


def _write(fd,data,limits):
    view=memoryview(data)
    while view:
        limits.tick();written=os.write(fd,view)
        need(0<written<=len(view),'copy write made no progress')
        view=view[written:]


def _metadata_equal(info,node):
    need((stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid)==
         (node['mode'],node['uid'],node['gid']),'copy metadata differs')


@contextmanager
def _parent(root,path,mount,identities,limits,expected=None):
    roots.installer.relative(path)
    parts=path.split('/');need(len(parts)<=limits.max_depth+1,'copy depth limit')
    with _descriptors() as held:
        fd=os.dup(root);held.append(fd);chain=[];prefix=[]
        need(roots._mount_id(fd,limits)==mount,'copy mount crossing')
        for part in parts[:-1]:
            limits.tick();child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);held.append(child)
            info=os.fstat(child);prefix.append(part);name='/'.join(prefix)
            need(roots._mount_id(child,limits)==mount,'copy mount crossing')
            inode=(info.st_dev,info.st_ino)
            need(identities.setdefault(name,inode)==inode,'copy parent rebound')
            if expected is not None:
                need(expected.get(name,{}).get('type')=='directory','copy source parent differs')
                _metadata_equal(info,expected[name])
            chain.append((fd,part,child,roots._identity(info)));fd=child
        yield fd,parts[-1]
        for parent,name,child,identity in chain:
            limits.tick();current=roots._identity(os.fstat(child))
            need(current==roots._identity(os.stat(name,dir_fd=parent,follow_symlinks=False))
                 and roots._mount_id(child,limits)==mount,'copy parent path drift')
            need(expected is None or current==identity,'copy source parent drift')


def _root_check(path,fd,identity,mount,limits):
    with _descriptors() as held:
        named=roots._open_root(path);held.append(named)
        need(roots._identity(os.fstat(fd))==identity==roots._identity(os.fstat(named))
             and roots._mount_id(fd,limits)==mount==roots._mount_id(named,limits),'copy root path drift')


def _source_alias(root,name,mount,identities,nodes,identity,limits):
    with _parent(root,name,mount,identities,limits,nodes) as (parent,base),_descriptors() as held:
        fd=os.open(base,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent);held.append(fd)
        need(roots._identity(os.fstat(fd))==identity==
             roots._identity(os.stat(base,dir_fd=parent,follow_symlinks=False))
             and roots._mount_id(fd,limits)==mount,'copy source alias drift')


def _copy_internal(source,target,limits,reserve_bytes,reserve_inodes,shape_examples,absolute_paths):
    need(source.is_absolute() and target.is_absolute() and '..' not in source.parts+target.parts,'absolute contained copy paths required')
    need(not target.is_relative_to(source) and not source.is_relative_to(target),'overlapping copy roots')
    need(not target.exists() and not target.is_symlink(),'fresh private copy required')
    mode='generic-development-internal'
    with _descriptors() as held:
        src=roots._open_root(source);held.append(src)
        parent=roots._open_root(target.parent);held.append(parent)
        src_info=os.fstat(src);parent_info=os.fstat(parent)
        need(parent_info.st_uid==os.geteuid() and not stat.S_IMODE(parent_info.st_mode)&0o022,'owned non-writable-by-others copy parent required')
        src_mount=roots._mount_id(src,limits);parent_mount=roots._mount_id(parent,limits)
        need((src_info.st_dev,src_info.st_ino)!=(parent_info.st_dev,parent_info.st_ino),'overlapping copy roots')
        need(src_info.st_dev!=parent_info.st_dev or src_mount==parent_mount,'ambiguous copy bind scope')
        before=roots.observe(source,limits=limits,hardlinks=mode)
        nodes=roots.require_eligible(before)
        _root_check(source,src,roots._identity(src_info),src_mount,limits)
        check_capacity([dict(path=str(target.parent),bytes=limits.max_bytes+limits.max_nodes*4096+reserve_bytes,
                             inodes=limits.max_nodes+reserve_inodes)])
        _root_check(target.parent,parent,roots._identity(parent_info),parent_mount,limits)
        os.mkdir(target.name,mode=0o700,dir_fd=parent)
        dst=os.open(target.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);held.append(dst)
        parent_final=roots._identity(os.fstat(parent));dst_mount=roots._mount_id(dst,limits)
        need(dst_mount==parent_mount and os.fstat(dst).st_dev==parent_info.st_dev,'copy destination mount drift')
        source_dirs={};dest_dirs={}
        directories=sorted((name for name,value in nodes.items() if value['type']=='directory'),key=lambda name:(name.count('/'),name))
        for name in directories:
            limits.tick()
            with _parent(dst,name,dst_mount,dest_dirs,limits) as (directory,base),_descriptors() as opened:
                os.mkdir(base,mode=0o700,dir_fd=directory)
                child=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory);opened.append(child)
                need(roots._mount_id(child,limits)==dst_mount,'copy mount crossing')
                info=os.fstat(child);dest_dirs[name]=(info.st_dev,info.st_ino)
        copied=set()
        for name,value in sorted(nodes.items()):
            limits.tick()
            if value['type']!='file' or name in copied:continue
            members=before['hardlink_groups'][value['hardlink_group']]['members'] if 'hardlink_group' in value else (name,)
            copied.update(members)
            with _parent(src,name,src_mount,source_dirs,limits,nodes) as (old_parent,old_base), \
                    _parent(dst,name,dst_mount,dest_dirs,limits) as (new_parent,new_base),_descriptors() as opened:
                old=os.open(old_base,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=old_parent);opened.append(old)
                info=os.fstat(old);identity=roots._identity(info)
                need(stat.S_ISREG(info.st_mode) and info.st_size==value['bytes'] and info.st_nlink==len(members)
                     and info.st_dev==src_info.st_dev and roots._mount_id(old,limits)==src_mount,'copy source group differs')
                _metadata_equal(info,value)
                new=os.open(new_base,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=new_parent);opened.append(new)
                total=0;digest=hashlib.sha256()
                while True:
                    limits.tick();data=os.read(old,min(1024**2,info.st_size-total+1))
                    if not data:break
                    total+=len(data);need(total<=info.st_size,'growing copy source');digest.update(data);_write(new,data,limits)
                need(total==info.st_size and digest.hexdigest()==value['sha256'] and roots._identity(os.fstat(old))==identity,'copy source content drift')
                os.fchown(new,info.st_uid,info.st_gid);os.fchmod(new,stat.S_IMODE(info.st_mode))
                anchor=os.fstat(new);anchor_inode=(anchor.st_dev,anchor.st_ino)
                need(roots._mount_id(new,limits)==dst_mount,'copy destination file mount drift')
                for index,member in enumerate(members):
                    limits.tick();_source_alias(src,member,src_mount,source_dirs,nodes,identity,limits)
                    current=os.fstat(new);_metadata_equal(current,value)
                    need((current.st_dev,current.st_ino)==anchor_inode and current.st_nlink==max(1,index)
                         and current.st_size==value['bytes'] and roots._identity(current)==
                         roots._identity(os.stat(new_base,dir_fd=new_parent,follow_symlinks=False)),'copy anchor drift')
                    if member!=name:
                        with _parent(dst,member,dst_mount,dest_dirs,limits) as (directory,base),_descriptors() as linked:
                            os.link(new_base,base,src_dir_fd=new_parent,dst_dir_fd=directory,follow_symlinks=False)
                            alias=os.open(base,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory);linked.append(alias)
                            need(roots._mount_id(alias,limits)==dst_mount and roots._identity(os.fstat(alias))==roots._identity(os.fstat(new))
                                 and os.fstat(new).st_nlink==index+1,'copy destination alias drift')
                for member in members:_source_alias(src,member,src_mount,source_dirs,nodes,identity,limits)
                need(roots._identity(os.fstat(old))==identity,'copy source group drift')
        for name,value in sorted(nodes.items()):
            limits.tick()
            if value['type']!='symlink':continue
            with _parent(src,name,src_mount,source_dirs,limits,nodes) as (directory,base):
                info=os.stat(base,dir_fd=directory,follow_symlinks=False)
                need(stat.S_ISLNK(info.st_mode) and os.readlink(base,dir_fd=directory)==value['target'],'copy source symlink drift');_metadata_equal(info,value)
                with _parent(dst,name,dst_mount,dest_dirs,limits) as (output,leaf):
                    os.symlink(value['target'],leaf,dir_fd=output);os.chown(leaf,value['uid'],value['gid'],dir_fd=output,follow_symlinks=False)
                need(roots._identity(os.stat(base,dir_fd=directory,follow_symlinks=False))==roots._identity(info),'copy source symlink drift')
        for name in reversed(directories):
            limits.tick();value=nodes[name]
            with _parent(dst,name,dst_mount,dest_dirs,limits) as (directory,base),_descriptors() as opened:
                fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory);opened.append(fd)
                need((os.fstat(fd).st_dev,os.fstat(fd).st_ino)==dest_dirs[name] and roots._mount_id(fd,limits)==dst_mount,'copy directory drift')
                os.fchown(fd,value['uid'],value['gid']);os.fchmod(fd,value['mode']);_metadata_equal(os.fstat(fd),value)
        final_dst=roots._identity(os.fstat(dst))
        observation=roots.observe(target,limits=limits,shape_examples=shape_examples,hardlinks=mode,absolute_paths=absolute_paths)
        need(roots.require_eligible(observation)==nodes,'copy destination nodes differ')
        roots.check_hardlink_preservation(before,observation,protected_paths=(),limits=limits)
        footprint=before['footprint']
        report=dict(source_nodes=len(nodes),copied_nodes=len(nodes),logical_bytes=footprint['bytes'],
                    source_hardlink_entries=footprint['hardlink_entries'],source_allocated_bytes=footprint['allocated_bytes'],
                    excluded=[],unsupported_counts={},copy_complete=True)
        report=_copy_report(report,observation,shape_examples,[]);del observation
        after=roots.observe(source,limits=limits,hardlinks=mode)
        need(roots.require_eligible(after)==nodes,'copy source nodes changed')
        roots.check_hardlink_preservation(before,after,protected_paths=(),limits=limits)
        _root_check(source,src,roots._identity(src_info),src_mount,limits)
        _root_check(target.parent,parent,parent_final,parent_mount,limits)
        _root_check(target,dst,final_dst,dst_mount,limits)
    return report


def copy_data(source,target,*,limits,excluded=(),reserve_bytes=16*1024**2,reserve_inodes=1024,shape_examples=0,hardlinks='refuse',absolute_paths=False):
    """No source mutation. Symlinks/hardlinks are preserved as data, never followed."""
    limits.tick()
    need(type(shape_examples) is int and 0 <= shape_examples <= 16,'bounded shape samples required')
    need(type(absolute_paths) is bool,'boolean absolute path diagnostic required')
    need(type(hardlinks) is str and hardlinks in ('refuse','generic-development-internal'),'invalid copy hardlink mode')
    if hardlinks == 'generic-development-internal':
        need(not excluded and not limits.allow_cross_device,'complete single-mount copy scope required')
        return _copy_internal(Path(source),Path(target),limits,reserve_bytes,reserve_inodes,shape_examples,absolute_paths)
    special_examples=[]
    source,target=Path(source),Path(target)
    need(not target.exists() and not target.is_symlink(),'fresh private copy required')
    # Reserve the configured upper bound before allocating any copy content.
    check_capacity([dict(path=str(target.parent),bytes=limits.max_bytes+limits.max_nodes*4096+reserve_bytes,
                         inodes=limits.max_nodes+reserve_inodes)])
    excluded=set(excluded)
    need(all(name and not name.startswith('/') and '..' not in name.split('/') for name in excluded),'contained exclusions required')
    report=dict(source_nodes=0,copied_nodes=0,logical_bytes=0,source_hardlink_entries=0,source_allocated_bytes=0,excluded=[],unsupported_counts={},copy_complete=True)
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
                with _descriptors() as held:
                    child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=src);held.append(child)
                    os.mkdir(name,mode=0o700,dir_fd=dst)
                    output=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=dst);held.append(output)
                    need(identity(os.fstat(child))==identity(info),'source directory drift')
                    walk(child,output,path+'/',depth+1);metadata(output,info)
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
                    with _descriptors() as held:
                        old=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=src);held.append(old)
                        new=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=dst);held.append(new)
                        need(identity(os.fstat(old))==identity(info),'source file drift')
                        total=0
                        while True:
                            limits.tick();data=os.read(old,1024**2)
                            if not data:break
                            total+=len(data);need(total<=info.st_size,'growing copy source')
                            view=memoryview(data)
                            _write(new,view,limits)
                        need(total==info.st_size and identity(os.fstat(old))==identity(info),'changed copy source')
                        metadata(new,info)
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
    with _descriptors() as held:
        source_fd=roots._open_root(source);held.append(source_fd)
        root_stat=os.fstat(source_fd)
        target.mkdir(mode=0o700)
        destination_fd=os.open(target,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);held.append(destination_fd)
        walk(source_fd,destination_fd)
        need(identity(os.fstat(source_fd))==identity(root_stat),'source root drift')
    observation=roots.observe(target,limits=limits,shape_examples=shape_examples,absolute_paths=absolute_paths)
    return _copy_report(report,observation,shape_examples,special_examples)


def _copy_report(report,observation,shape_examples,special_examples=()):
    report.update(footprint=observation['footprint'],observation_complete=observation['complete'],
                  unsupported_observation=observation['unsupported_counts'],
                  unsupported_examples=observation['unsupported'],eligible=observation['eligible'] and report['copy_complete'])
    if 'absolute_chain_paths' in observation:
        report['absolute_chain_paths']=observation['absolute_chain_paths']
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
    parser.add_argument('--absolute-chain-paths',action='store_true',help='Bounded exact absolute-chain paths/classes; diagnostic only, no target values')
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
    report=copy_data(Path('/'),workspace/'root',limits=limits,excluded=excluded,shape_examples=args.shape_examples_per_category,absolute_paths=args.absolute_chain_paths)
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
