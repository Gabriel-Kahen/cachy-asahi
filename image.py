# SPDX-License-Identifier: MIT
"""Bounded read-only ext4 inventory; no exported bodies or tool execution."""
import base64
import hashlib
import importlib.util
import math
import os
from pathlib import Path
import re
import stat
import time

HERE=Path(__file__).resolve().parent
MIB=1024**2
PROFILE=(4096,0x22c2,0x46b,256)


def module(name):
    spec=importlib.util.spec_from_file_location('rust_image_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def scan(raw,deadline,guard=None):
    """Return legacy namespace rows, bounded ALPM text, and reader accounting.

    The unchanged frozen parser owns the filesystem profile and 2GiB read
    budget. Unsupported profiles fail closed. Filesystem integrity remains the
    caller's separate readonly e2fsck requirement.
    """
    K=module('contracts');O=module('ownership')
    K.need(type(deadline) in (int,float) and math.isfinite(deadline) and time.monotonic()<deadline,'finite image deadline required')
    K.need(guard is None or callable(guard),'image guard must be callable')
    last=[None]
    def tick(force=False):
        now=time.monotonic()
        if now>=deadline:raise TimeoutError('image scan deadline exhausted')
        if guard is not None and (force or last[0] is None or now-last[0]>=.5):
            guard();last[0]=time.monotonic()
            if last[0]>=deadline:raise TimeoutError('image guard exhausted deadline')
    tick(True)
    raw=K.ordinary(raw);before=raw.lstat()
    K.need(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'ordinary single-link raw DATA required')
    def identity(info):
        return tuple(getattr(info,key) for key in ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
    frozen=K.helper('independent_readback.py')
    class Reader(frozen.Ext4Reader):
        read_bytes=0;read_calls=0
        def read(self,offset,length):
            tick();data=super().read(offset,length)
            self.read_bytes+=len(data);self.read_calls+=1;tick();return data
        def chunks(self,fields,data):
            for chunk in super().chunks(fields,data):
                tick();yield chunk
    with Reader(raw,max_nodes=150000,max_file_bytes=256*MIB) as reader:
        K.need(identity(before)==identity(os.fstat(reader.fd))==identity(raw.lstat()),'raw identity changed before scan')
        K.need((reader.blocksize,reader.incompat,reader.rocompat,reader.inode_size)==PROFILE,'unreviewed ext4 image profile')
        observed=reader.inventory();rows=observed['nodes'];nodes={};file_bytes=0;files=0
        K.need(type(rows) is dict and len(rows)<=150000 and rows.get('.',{}).get('type')=='directory','bounded rooted image namespace required')
        for name,row in rows.items():
            tick()
            if name=='.':continue
            O.passive(name);mode=row['mode'];K.need(type(mode) is int and 0<=mode<=0o7777,'image inode mode bound')
            kind=row['type']
            if kind=='directory':node=dict(kind='dir',mode=mode)
            elif kind=='file':
                size=row['size'];digest=row['sha256']
                K.need(type(size) is int and 0<=size<=256*MIB and re.fullmatch('[0-9a-f]{64}',digest or ''),'image regular file bound')
                node=dict(kind='file',mode=mode,bytes=size,sha256=digest);file_bytes+=size;files+=1
            else:
                K.need(kind=='symlink','unsupported image node')
                target=base64.b64decode(row['target_b64'],validate=True).decode('utf-8')
                K.need(0<len(target.encode())<=4096 and not any(c in target for c in '\0\n\r\t'),'literal bounded image symlink target required')
                node=dict(kind='link',mode=mode,target=target)
            nodes[name]=node;K.need(file_bytes<=3*1024**3,'image namespace content bound')
        db='var/lib/pacman/local';K.need(nodes.get(db,{}).get('kind')=='dir','actual local ALPM directory required')
        records={};record_bytes=0
        for name,node in nodes.items():
            tick()
            if not name.startswith(db+'/') or '/' in name[len(db)+1:]:continue
            directory=name[len(db)+1:]
            if directory=='ALPM_DB_VERSION':
                K.need(node['kind']=='file','ordinary ALPM database version required');continue
            K.need(node['kind']=='dir','ordinary ALPM package directory required');record={}
            for kind in ('desc','files'):
                path=name+'/'+kind;entry=nodes.get(path,{})
                K.need(entry.get('kind')=='file' and entry['bytes']<=4*MIB,'bounded regular ALPM record required')
                record_bytes+=entry['bytes'];K.need(record_bytes<=16*MIB,'aggregate ALPM text bound')
                old=rows[path];fields,data=reader.inode(old['inode'])
                K.need(fields=={key:value for key,value in old.items() if key!='sha256'},'ALPM inode changed during scan')
                body=bytearray()
                for chunk in reader.chunks(fields,data):
                    body.extend(chunk);K.need(len(body)<=entry['bytes'],'ALPM record overflow')
                K.need(len(body)==entry['bytes'] and hashlib.sha256(body).hexdigest()==entry['sha256'],'ALPM record differs from inventory')
                record[kind]=body.decode('utf-8')
            records[directory]=record
        tick(True)
        K.need(identity(before)==identity(os.fstat(reader.fd))==identity(raw.lstat()),'raw identity changed during scan')
        profile=dict(reader=observed['reader'],image_bytes=reader.size,block_bytes=reader.blocksize,incompat=reader.incompat,rocompat=reader.rocompat,inode_bytes=reader.inode_size,nodes=len(nodes),files=files,file_bytes=file_bytes,read_bytes=reader.read_bytes,read_calls=reader.read_calls,record_bytes=record_bytes)
    return dict(nodes=nodes,records=records,profile=profile)
