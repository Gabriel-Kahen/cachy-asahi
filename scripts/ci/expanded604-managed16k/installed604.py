#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read actual ALPM9 ownership and every owned payload node, never declared counts alone."""
import hashlib
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import time
SELECTED={'cachy-asahi-doctor','cachy-asahi-orphans'}
CAP=64*1024**2

def need(ok,why):
    if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def read(path):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size<=CAP,'bounded ordinary snapshot required');return json.loads(path.read_bytes())
def load_db(path):
    spec=importlib.util.spec_from_file_location('managed604_actual_alpm',path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def observe(root,helper,expected,*,deadline=600):
    end=time.monotonic()+deadline;rows=helper.database(root,max_packages=604)
    need({r['name']:r['version'] for r in rows}==expected and len(rows)==604,'exact actual604 ALPM inventory required')
    def records():
        result={}
        for row in rows:
            base='var/lib/pacman/local/'+row['name']+'-'+row['version']
            with helper.directory(root,base) as parent:
                for name in sorted(os.listdir(parent)):
                    need(name in ('desc','files','mtree','install'),'unknown ALPM record')
                    result[base+'/'+name]=digest(helper.read_record(parent,name,4*1024**2))
        return result
    initial_database=records()
    @contextmanager
    def directory(name):
        if name:
            with helper.directory(root,name) as fd:yield fd
        else:
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:yield fd
            finally:os.close(fd)
    root_identity=helper.identity(root.lstat())
    nodes={};owners={};groups={};total=0
    for row in rows:
        need(row['name'] not in owners,'duplicate actual owner');owners[row['name']]=row['files']
        for name in row['files']:
            need(name not in nodes and time.monotonic()<end,'overlap/deadline in complete actual payload')
            parent,_,leaf=name.rpartition('/')
            with directory(parent) as parentfd:
                before=os.stat(leaf,dir_fd=parentfd,follow_symlinks=False)
                value=dict(mode=stat.S_IMODE(before.st_mode),uid=before.st_uid,gid=before.st_gid)
                if stat.S_ISLNK(before.st_mode):value.update(type='symlink',target=os.readlink(leaf,dir_fd=parentfd))
                else:
                    need(stat.S_ISREG(before.st_mode) and before.st_size<=1024**3,'ordinary bounded owned payload required')
                    fd=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parentfd)
                    try:
                        need(helper.identity(before)==helper.identity(os.fstat(fd)),'payload descriptor identity differs')
                        h=hashlib.sha256();size=0
                        while raw:=os.read(fd,1024**2):
                            size+=len(raw);need(time.monotonic()<end and size<=before.st_size,'payload deadline/length');h.update(raw)
                        need(size==before.st_size and helper.identity(before)==helper.identity(os.fstat(fd)),'payload drift')
                    finally:os.close(fd)
                    total+=size;need(total<=6*1024**3,'original full payload byte bound')
                    value.update(type='file',bytes=size,sha256=h.hexdigest())
                    if before.st_nlink>1:groups.setdefault((before.st_dev,before.st_ino),[]).append((name,before.st_nlink))
                need(helper.identity(before)==helper.identity(os.stat(leaf,dir_fd=parentfd,follow_symlinks=False)),'named payload drift')
                nodes[name]=value;need(len(nodes)<=200000,'original full payload node bound')
    links=[]
    for members in groups.values():
        need(len(members)==members[0][1] and len({n for _,n in members})==1,'complete actual payload hardlink set required')
        links.append(sorted(name for name,_ in members))
    need(helper.database(root,max_packages=604)==rows and records()==initial_database and root_identity==helper.identity(root.lstat()) and time.monotonic()<end,'database/root drift or deadline across complete payload read')
    selected_prefixes=tuple('var/lib/pacman/local/'+r['name']+'-'+r['version']+'/' for r in rows if r['name'] in SELECTED)
    database={n:v for n,v in initial_database.items() if not n.startswith(selected_prefixes)}
    return dict(schema_version=1,packages=expected,ownership=owners,nodes=nodes,hardlinks=sorted(links),nonselected_database=database,
                payload_bytes=total,qualification='ACTUAL_INSTALLED_PAYLOAD_AND_ALPM_METADATA_NOT_ARCHIVE_OR_HARDWARE_ATTESTATION')

def verify(actual,baseline):
    need(actual==baseline,'complete installed inventory/payload/hardlink/nonselected DB preservation differs');return True

def main():
    mode,root,helper_path,expected_path,snapshot_path=sys.argv[1:]
    need(mode in ('capture','verify') and os.geteuid()==0,'owned fixture/guarded guest root only')
    expected=dict(line.split() for line in Path(expected_path).read_text().splitlines())
    actual=observe(Path(root),load_db(Path(helper_path)),expected)
    snapshot=Path(snapshot_path)
    if mode=='capture':
        need(not snapshot.exists(),'fresh snapshot required');raw=encoded(actual);need(len(raw)<=CAP,'snapshot64MiB bound');snapshot.write_bytes(raw);snapshot.chmod(0o444)
    else:verify(actual,read(snapshot))
    print(json.dumps(dict(status='PASS_COMPLETE_ACTUAL604_'+mode.upper(),packages=604,nodes=len(actual['nodes']),
        payload_bytes=actual['payload_bytes'],snapshot_sha256=digest(snapshot.read_bytes()),hardware='NOT_RUN')))
if __name__=='__main__':main()
