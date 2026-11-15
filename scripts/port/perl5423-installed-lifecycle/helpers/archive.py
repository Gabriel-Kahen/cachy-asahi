#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Bounded DATA inspection of this Perl archive, including its core hardlinks."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import time

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module


def need(value,message):
    if not value:raise ValueError(message)


def read_rows(path):
    source=HERE/'archive_stream.py'
    need(hashlib.sha256(source.read_bytes()).hexdigest()=='10f1a4c0ac5b98852d9ebb150af28f9ce345c800935a64fa463bc90f72fcb838','existing bounded decoder changed')
    api=load('perl_archive_stream',source)
    limits=api.Limits(compressed_bytes=64*1024**2,total_compressed_bytes=64*1024**2,decoded_bytes=160*1024**2,
        members=12000,file_bytes=32*1024**2,window_bytes=128*1024**2,deadline=time.monotonic()+90)
    need(path.is_file() and not path.is_symlink() and 0<path.stat().st_size<=limits.compressed_bytes,'ordinary bounded archive')
    headers=0;end=False
    class Info(tarfile.TarInfo):
        @classmethod
        def _fromtarfile(cls,archive,*,dircheck=True):
            nonlocal headers,end
            api.tick(limits);raw=archive.fileobj.read(512)
            if raw==bytes(512):end=True
            else:headers+=1;need(headers<=limits.members,'member budget')
            item=cls._frombuf(raw,archive.encoding,archive.errors,dircheck=dircheck)
            item.offset=archive.fileobj.tell()-512;return item._proc_member(archive)
        def _proc_pax(self,archive):
            need(0<=self.size<=65536,'PAX budget');return super()._proc_pax(archive)
        def _proc_gnulong(self,archive):
            need(0<=self.size<=65536,'long-name budget');return super()._proc_gnulong(archive)
        def _proc_sparse(self,*args):raise ValueError('sparse archive refused')
        _proc_gnusparse_00=_proc_sparse;_proc_gnusparse_01=_proc_sparse;_proc_gnusparse_10=_proc_sparse
    rows={}
    with path.open('rb') as compressed,tempfile.TemporaryFile() as decoded:
        identity=lambda info:(info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        before=identity(os.fstat(compressed.fileno()));need(before==identity(path.stat(follow_symlinks=False)),'opened archive identity differs')
        stream=api.Decoded(compressed,limits,0)
        while block:=stream.read(65536):decoded.write(block)
        need(stream.done,'complete single compressed frame required');decoded.seek(0)
        with tarfile.open(fileobj=decoded,mode='r:',tarinfo=Info) as archive:
            for member in archive:
                api.tick(limits)
                name=api.relative(member.name.removeprefix('./').rstrip('/'))
                need(name not in rows and member.uid==member.gid==0,'unique root-owned archive entry')
                need(not member.sparse and 0<=member.size<=limits.file_bytes,'ordinary bounded archive entry')
                row=dict(mode=member.mode,uid=member.uid,gid=member.gid,mtime=member.mtime)
                if member.isdir():row['type']='directory'
                elif member.isfile():
                    digest=hashlib.sha256();size=0;prefix=b''
                    with archive.extractfile(member) as body:
                        while block:=body.read(65536):
                            api.tick(limits);digest.update(block);size+=len(block)
                            if not prefix:prefix=block[:64]
                    need(size==member.size,'complete regular payload')
                    row.update(type='file',bytes=size,sha256=digest.hexdigest())
                    if prefix.startswith(b'\x7fELF'):
                        need(len(prefix)>=20 and prefix[4:6]==b'\x02\x01','ELF64 little-endian required')
                        row['ELF_machine']=int.from_bytes(prefix[18:20],'little')
                elif member.issym():row.update(type='symlink',target=member.linkname)
                elif member.islnk():
                    target=api.relative(member.linkname)
                    need(rows.get(target,{}).get('type')=='file','prior ordinary hardlink target required')
                    row.update(type='hardlink',target=target,bytes=rows[target]['bytes'],sha256=rows[target]['sha256'])
                else:raise ValueError('special archive entry refused')
                rows[name]=row
            need(end,'complete tar end marker required')
            tail=archive.fileobj.read();need(len(tail)>=512 and not any(tail) and stream.total%512==0,'only complete zero padding may follow tar')
        for name,row in rows.items():
            if row['type']=='symlink':need(api.resolve(rows,name,limits) in rows,'dangling/escaping symlink')
        need(before==identity(path.stat(follow_symlinks=False))==identity(os.fstat(compressed.fileno())),'archive changed during inspection')
    return rows
