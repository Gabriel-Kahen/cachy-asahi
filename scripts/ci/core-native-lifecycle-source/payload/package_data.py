# SPDX-License-Identifier: MIT
"""Exact original archive observer with one fixed accepted setgid directory."""
import hashlib,os,stat,re,tarfile
from pathlib import Path

def need(ok,why):
    if not ok:raise ValueError(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def read(path,cap=2*1024**2):
    path=Path(path)
    need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary input path')
    info=path.stat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=cap,'bounded ordinary input')
    raw=path.read_bytes();need(len(raw)==info.st_size,'input truncated');return raw

def relative(name):
    need(type(name) is str and name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')),'closed relative path')
    return name

def fields(raw):
    result={}
    for line in raw.decode().splitlines():
        if line and not line.startswith('#'):
            key,value=line.split(' = ',1);result.setdefault(key,[]).append(value)
    return result

def archive(path):
    nodes={};data={};hardlinks={};total=0
    with tarfile.open(path,mode='r:*') as stream:
        for m in stream:
            n=relative(m.name.rstrip('/'));need(n not in nodes and len(nodes)<60000 and m.uid==m.gid==0 and(not m.mode&0o7000 or(m.isdir()and n=='var/log/journal'and m.mode==0o2755)),'package member identity/mode')
            need(m.isfile() or m.isdir() or m.issym() or m.islnk(),'ordinary package member')
            need(set(m.pax_headers)<={'path','linkpath','mtime','atime','ctime'},'provider/held package xattrs or unknown PAX refused')
            row=dict(type='directory' if m.isdir() else 'symlink' if m.issym() else 'file',mode=m.mode,uid=m.uid,gid=m.gid)
            if m.issym():
                need('\x00'not in m.linkname and(not m.linkname.startswith('/')or(n,m.linkname)in(('usr/share/licenses/systemd/MIT-0.txt','/usr/share/doc/systemd/LICENSES/MIT-0.txt'),('usr/share/licenses/python-pytest/LICENSE','/usr/lib/python3.14/site-packages/pytest-9.1.1.dist-info/licenses/LICENSE'))),'only original relative links or exact accepted systemd license link');row['target']=m.linkname
            elif m.islnk():
                target=relative(m.linkname)
                need('\0' not in n+target and not n.startswith('.') and not target.startswith('.') and m.size==0,
                     'ordinary payload hardlink header')
                need(len(hardlinks)<16384,'package hardlink alias bound');hardlinks[n]=target
            elif m.isfile():
                total+=m.size;need(m.size<=64*1024**2 and total<=512*1024**2,'package byte bound')
                raw=stream.extractfile(m).read(m.size+1);need(len(raw)==m.size,'package byte count')
                row.update(bytes=m.size,sha256=sha(raw));data[n]=raw
            nodes[n]=row
    # Resolve only archive-owned regular bytes; never ask tarfile or the host to follow a link.
    resolved={n:n for n in data};groups={}
    for name in hardlinks:
        trail=[];seen=set();target=name
        while target not in resolved:
            need(target in hardlinks and target not in seen,'missing/special/cyclic package hardlink target')
            seen.add(target);trail.append(target);target=hardlinks[target]
        origin=resolved[target];source=nodes[origin]
        for alias in trail:
            need(all(nodes[alias][k]==source[k] for k in ('mode','uid','gid')),'package hardlink metadata differs')
            for member in (alias,origin):
                parts=member.split('/')
                need(all('/'.join(parts[:i]) not in nodes or nodes['/'.join(parts[:i])]['type']=='directory'
                         for i in range(1,len(parts))),'package hardlink ancestor is not directory')
            total+=source['bytes'];need(total<=512*1024**2,'package byte bound')
            nodes[alias].update(bytes=source['bytes'],sha256=source['sha256']);data[alias]=data[origin];resolved[alias]=origin
            members=groups.setdefault(origin,{origin});members.add(alias)
            need(len(groups)<=4096 and len(members)<=4096,'package hardlink group bound')
    for members in groups.values():
        key=min(members)
        for name in members:nodes[name]['hardlink_group']=key
    need({'.PKGINFO','.BUILDINFO','.MTREE'}<=set(data),'complete package metadata')
    return dict(nodes={n:r for n,r in nodes.items() if not n.startswith('.')},data=data,metadata=fields(data['.PKGINFO']),buildinfo=fields(data['.BUILDINFO']))
