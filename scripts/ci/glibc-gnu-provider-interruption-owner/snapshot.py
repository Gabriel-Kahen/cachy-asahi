#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded Docker-export data extraction/observation in an owned native observer."""
import argparse
from decimal import Decimal
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import shutil
import stat
import sys
import tarfile
import time

DATA=Path('/data');ROOT=DATA/'original574';OUT=Path('/out')
MAX_NODES=500000;MAX_BYTES=8*1024**3;MAX_TAR=12*1024**3
RUNTIME={'proc','sys','dev','run','tmp'}


def need(ok,why):
    if not ok:raise ValueError(why)


def name(value):
    if value in ('.','./',''):return ''
    if value.startswith('./'):value=value[2:]
    value=value.rstrip('/')
    need(len(os.fsencode(value))<=4096 and len(value.split('/'))<=128 and value and not value.startswith('/') and all(p not in ('','.','..') for p in value.split('/')) and '\x00' not in value,'safe Docker export path')
    return value


def records(archive):
    result={};total=0;excluded=[]
    with tarfile.open(archive,mode='r|') as stream:
        for member in stream:
            n=name(member.name)
            if not n:need(member.isdir(),'ordinary archive root');continue
            if n.split('/')[0] in RUNTIME and '/' in n:
                excluded.append(n);need(len(excluded)<=4096,'bounded excluded transient image entries');continue
            if n in RUNTIME:need(member.isdir(),'literal empty runtime directory boundary')
            need(n not in result and len(result)<MAX_NODES and (member.isfile() or member.isdir() or member.issym() or member.islnk()),'bounded ordinary archive nodes')
            need(member.uid>=0 and member.gid>=0 and math.isfinite(member.mtime) and 0<=member.mode<=0o7777 and set(member.pax_headers)<={'path','linkpath','mtime','atime','ctime'},'plain archive metadata; xattrs/unknown PAX refused')
            if member.isfile():
                total+=member.size;need(member.size<=1024**3 and total<=MAX_BYTES,'bounded Docker export payload')
            if member.islnk():name(member.linkname)
            if member.issym():need(len(os.fsencode(member.linkname))<=4096 and '\x00' not in member.linkname,'bounded literal link data')
            result[n]=member
    for n,m in result.items():
        parts=n.split('/')
        for i in range(1,len(parts)):
            ancestor='/'.join(parts[:i]);need(ancestor in result and result[ancestor].isdir(),'archive parent must be declared ordinary directory')
        if m.islnk():
            target=name(m.linkname);need(target in result and result[target].isfile(),'hardlink to one declared ordinary file only')
            need((m.uid,m.gid,m.mode)==(result[target].uid,result[target].gid,result[target].mode),'hardlink metadata agrees')
    need(RUNTIME<=set(result),'all runtime directory boundaries present')
    return result,total,excluded


def mtime_ns(member):return int(Decimal(member.pax_headers.get('mtime',str(member.mtime)))*1000000000)


def extract(archive,target,expected_sha=None):
    before=archive.stat();need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=MAX_TAR,'bounded ordinary root export')
    with archive.open('rb') as source:archive_sha=hashlib.file_digest(source,'sha256').hexdigest()
    need(expected_sha is None or archive_sha==expected_sha,'exact stopped-container export archive hash')
    members,total,excluded=records(archive)
    need(not target.exists() and not target.is_symlink(),'fresh source data root')
    target.mkdir(mode=0o700);s=target.stat()
    (DATA/'snapshot-owner.json').write_text(json.dumps(dict(root=[s.st_dev,s.st_ino],token=os.environ['OWNER_TOKEN']))+'\n')
    for n,m in sorted(members.items(),key=lambda pair:(pair[0].count('/'),pair[0])):
        if m.isdir():(target/n).mkdir(mode=0o700)
    with tarfile.open(archive,mode='r|') as stream:
        for m in stream:
            n=name(m.name)
            if not n or n not in members or not m.isfile():continue
            path=target/n
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            with os.fdopen(fd,'wb') as output,stream.extractfile(m) as source:
                copied=0
                while block:=source.read(1024**2):output.write(block);copied+=len(block);need(copied<=m.size,'archive member bound')
                need(copied==m.size,'archive member truncated');os.fchown(output.fileno(),m.uid,m.gid);os.fchmod(output.fileno(),m.mode)
            os.utime(path,ns=(mtime_ns(m),mtime_ns(m)),follow_symlinks=False)
    for n,m in members.items():
        if m.islnk():os.link(target/name(m.linkname),target/n,follow_symlinks=False)
        elif m.issym():os.symlink(m.linkname,target/n);os.lchown(target/n,m.uid,m.gid);os.utime(target/n,ns=(mtime_ns(m),mtime_ns(m)),follow_symlinks=False)
    for n,m in sorted(members.items(),key=lambda pair:pair[0].count('/'),reverse=True):
        if m.isdir():os.chown(target/n,m.uid,m.gid);os.chmod(target/n,m.mode);os.utime(target/n,ns=(mtime_ns(m),mtime_ns(m)))
    after=archive.stat();need((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'export changed during extraction')
    with archive.open('rb') as source:need(hashlib.file_digest(source,'sha256').hexdigest()==archive_sha,'export bytes unchanged after extraction')
    return dict(archive_sha256=archive_sha,nodes=len(members),logical_bytes=total,transient_boundaries=sorted(RUNTIME),excluded_transient_entries=excluded,metadata='uid/gid/mode/mtime/symlink/internal-hardlink preserved; PAX/xattrs and special nodes refused')


def observe(source):
    sys.path.insert(0,str(source/'scripts/ci/glibc-gnu-provider-interruption'))
    import common as C
    api=C.helpers(source);budget=api['roots'].Limits(deadline=time.monotonic()+600,max_packages=574,max_nodes=MAX_NODES,max_bytes=MAX_BYTES,max_file_bytes=1024**3)
    value=api['roots'].observe(ROOT,limits=budget,hardlinks='generic-development-internal')
    need(value['complete'] is True and set(value['unsupported_counts'])<={'absolute-symlink','auxiliary-present'},'complete original574 root observation')
    rows=api['db'].database(ROOT,max_packages=574,max_files=100000,max_nodes=MAX_NODES)
    actual=''.join(p['name']+' '+p['version']+'\n' for p in sorted(rows,key=lambda r:r['name'])).encode()
    need(len(rows)==574 and C.sha(actual)==C.BASE_LOCK,'exact original574 database from stopped-image export')
    # Keep the same exact source auxiliary/link policy used by the lifecycle copier.
    import root_link_selection,aux_checkpoint
    root_link_selection.check(value,budget);aux_checkpoint.checkpoint(ROOT,value,budget)
    raw=json.dumps(value,sort_keys=True,separators=(',',':')).encode();compressed=gzip.compress(raw,mtime=0)
    need(len(raw)<=256*1024**2 and len(compressed)<=64*1024**2,'source observation export bound')
    (OUT/'original574-root.json.gz').write_bytes(compressed)
    return dict(node_sha256=C.sha(json.dumps(value['nodes'],sort_keys=True).encode()),observation_sha256=C.sha(raw),compressed_sha256=C.sha(compressed),nodes=len(value['nodes']),
        database_sha256=C.sha(actual),packages=574,shape='COMPLETE_SELECTED_ORIGINAL574_WITH_HELD_AUXILIARY_AND_INTERNAL_LINKS')


def cleanup():
    need(shutil.rmtree.avoids_symlink_attacks,'fd-safe cleanup available')
    marker=DATA/'snapshot-owner.json'
    if marker.exists():
        value=json.loads(marker.read_text());s=ROOT.lstat()
        need(value['token']==os.environ['OWNER_TOKEN'] and stat.S_ISDIR(s.st_mode) and not ROOT.is_mount() and value['root']==[s.st_dev,s.st_ino],'exact owned source-root inode')
        shutil.rmtree(ROOT)
    else:need(not ROOT.exists() and not ROOT.is_symlink(),'unknown source root preserved')
    need(not ROOT.exists() and not ROOT.is_symlink(),'source data root absent')
    os.chown(DATA,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--cleanup',action='store_true');args=parser.parse_args()
    need(os.getuid()==os.geteuid()==0 and platform.machine()=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_GNU_PROVIDER_SNAPSHOT')=='1','owned native observer only')
    need(DATA.is_mount() and not DATA.is_symlink() and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'explicit private data bind/offline namespace')
    if args.cleanup:cleanup();return
    result=dict(status='FAIL',snapshot_point='NEVER_STARTED_READONLY_CONTAINER_OF_EXACT_FRESH_OWNED574_IMAGE',hardware='NOT_RUN')
    try:
        result['extraction']=extract(DATA/'source.tar',ROOT,os.environ['SOURCE_TAR_SHA256']);result['observation']=observe(Path('/source'));result['status']='PASS_ORIGINAL574_DATA_SNAPSHOT'
    except BaseException as error:result.update(error_type=type(error).__name__,error=str(error)[:512])
    finally:
        (OUT/'snapshot.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
        uid,gid=int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID'])
        for path in OUT.iterdir():
            need(path.is_file() and not path.is_symlink(),'ordinary snapshot evidence');os.chown(path,uid,gid)
        for path in DATA.glob('*.json'):os.chown(path,uid,gid)
    need(result['status']=='PASS_ORIGINAL574_DATA_SNAPSHOT','source snapshot failed')

if __name__=='__main__':main()
