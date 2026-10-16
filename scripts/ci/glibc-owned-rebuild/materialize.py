#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate a complete pinned GNU Git tree and render an offline recipe bundle.

Only data hashing/tar inspection/copying occurs here. No recipe is sourced or run.
The missing full source archive is a hard prerequisite, never a SKIP checksum.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path,PurePosixPath
import re
import shutil
import tarfile
import time


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(path):
    with Path(path).open('rb') as file:return hashlib.file_digest(file,'sha256').hexdigest()


def blob(data):return hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()


def inspect(path,expected_tree,limits):
    need(Path(path).is_file() and not Path(path).is_symlink() and Path(path).stat().st_size<=limits['source_compressed'],'bounded ordinary source archive required')
    deadline=time.monotonic()+limits['seconds'];entries={};total=0;root=None;directories=set()
    class Decoded:
        def __init__(self,stream):self.stream=stream;self.count=0
        def read(self,size):
            need(time.monotonic()<deadline and 0<=size<=1024**2,'bounded source decoder request')
            data=self.stream.read(size);self.count+=len(data)
            need(self.count<=limits['source_bytes']+limits['source_members']*1024,'decoded tar byte bound')
            return data
    with gzip.open(path,'rb') as stream,tarfile.open(fileobj=Decoded(stream),mode='r|') as archive:
        for count,member in enumerate(archive,1):
            need(time.monotonic()<deadline and count<=limits['source_members'],'source member/deadline bound')
            need(not member.mode&0o7000,'ordinary source mode required')
            parts=PurePosixPath(member.name).parts
            need(parts and not member.name.startswith('/') and '..' not in parts and '\0' not in member.name and
                 member.name.rstrip('/')=='/'.join(parts),'canonical archive member required')
            if root is None:root=parts[0];need(re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',root),'source root name differs')
            need(parts[0]==root,'one source root required')
            if len(parts)==1:need(member.isdir(),'source root must be directory');continue
            name='/'.join(parts[1:]);need(name not in entries and name not in directories,'duplicate source path')
            if member.isdir():directories.add(name);continue
            need(not member.sparse and not member.islnk() and (member.isfile() or member.issym()) and not member.mode&0o7000,'ordinary source file/link required')
            need(member.size<=limits['source_file'],'source file bound');total+=member.size;need(total<=limits['source_bytes'],'source bytes bound')
            if member.issym():
                data=member.linkname.encode();target=PurePosixPath(name).parent/PurePosixPath(member.linkname)
                need(not member.linkname.startswith('/') and '\0' not in member.linkname,'relative source link required')
                depth=0
                for part in target.parts:
                    depth+=-1 if part=='..' else 0 if part=='.' else 1
                    need(depth>=0,'source link escapes root')
                mode='120000'
            else:
                data=archive.extractfile(member).read(limits['source_file']+1);need(len(data)==member.size,'source file changed/truncated')
                mode='100755' if member.mode&0o111 else '100644'
            entries[name]=(mode,blob(data))
    tree={}
    for name,(mode,digest) in entries.items():
        node=tree
        for part in name.split('/')[:-1]:
            need(not (part in node and not isinstance(node[part],dict)),'source parent alias')
            node=node.setdefault(part,{})
        need(name.split('/')[-1] not in node,'source leaf/directory collision');node[name.split('/')[-1]]=(mode,digest)
    def encode(node):
        rows=[]
        for name,value in node.items():
            directory=isinstance(value,dict);mode,digest=('40000',encode(value)) if directory else value
            rows.append(((name+('/' if directory else '')).encode(),mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(digest)))
        data=b''.join(value for _,value in sorted(rows));return hashlib.sha1(b'tree '+str(len(data)).encode()+b'\0'+data).hexdigest()
    actual=encode(tree);need(actual==expected_tree,'complete upstream Git tree differs')
    parents={str(parent) for name in entries for parent in PurePosixPath(name).parents if str(parent)!='.'}
    need(directories<=parents,'unexpected empty source directories')
    need(all(name in entries for name in ('configure','Makefile','COPYINGv2','COPYING.LESSERv2','COPYING.LIB','LICENSES')),'complete source/license roots required')
    return dict(root=root,git_tree=actual,files=len(entries),bytes=total,sha256=sha(path))


def materialize(recipe,archive,output):
    recipe=Path(recipe).resolve(strict=True);lock=json.loads((recipe/'source-lock.json').read_bytes())
    need(lock['upstream_commit']=='8362e8ce10b24068bacc19552c128dd10e082fd9' and lock['upstream_git_tree']=='912828afc79878e39e0e771d461f11080c25b715','exact GNU revision required')
    need(not Path(output).exists(),'fresh source bundle required')
    for row in lock['retained_inputs']:
        need(Path(row['path']).name==row['path'] and row['path'] not in ('.','..'),'flat retained input required')
        path=recipe/row['path'];need(path.is_file() and not path.is_symlink() and path.stat().st_size==row['bytes'] and sha(path)==row['sha256'],'retained input differs: '+row['path'])
    need(archive is not None,'MISSING_PREREQUISITE: complete primary GNU8362e8ce source archive; partial audit files are insufficient')
    observed=inspect(archive,lock['upstream_git_tree'],lock['limits'])
    template=(recipe/'PKGBUILD.in').read_text();rendered=template.replace('@UPSTREAM_SHA256@',observed['sha256']).replace('@SOURCE_ROOT@',observed['root'])
    need('@UPSTREAM_SHA256@' not in rendered and '@SOURCE_ROOT@' not in rendered,'unresolved recipe tokens')
    output=Path(output);output.mkdir(mode=0o700)
    try:
        for path in recipe.iterdir():
            need(path.is_file() and not path.is_symlink(),'flat ordinary recipe input required')
            shutil.copyfile(path,output/path.name)
        shutil.copyfile(archive,output/'glibc-source.tar.gz');(output/'PKGBUILD').write_text(rendered)
        lock['source'].update(status='COMPLETE_GIT_TREE_VERIFIED',sha256=observed['sha256'])
        (output/'source-lock.json').write_text(json.dumps(lock,sort_keys=True,indent=2)+'\n')
        files={path.name:dict(bytes=path.stat().st_size,sha256=sha(path)) for path in sorted(output.iterdir())}
        receipt=dict(schema_version=1,status='SOURCE_BUNDLE_READY',commit=lock['upstream_commit'],tree=observed['git_tree'],
                     source=observed,files=files,build='NOT RUN',recipe_execution='NOT RUN')
        (output/'bundle.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n');return receipt
    except BaseException:
        shutil.rmtree(output);raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe',type=Path,required=True);parser.add_argument('--upstream-archive',type=Path);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:print(json.dumps(materialize(args.recipe,args.upstream_archive,args.output),sort_keys=True))
    except BaseException as error:
        print(json.dumps(dict(status='REFUSED_INPUT_PREREQUISITE',error_type=type(error).__name__,error=str(error)[:256])),flush=True);raise SystemExit(1)
