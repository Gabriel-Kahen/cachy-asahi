#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned-container-only candidate extraction and explicit smoke input manifest."""
import argparse,hashlib,json,os,posixpath,re
from pathlib import Path,PurePosixPath
import tarfile,time

NAME='cachy-asahi-glibc-official-release'
VERSION='2.43.caa1-3'
PREFIX='opt/caa/g243a1'

def need(ok,reason):
    if not ok:raise ValueError(reason)

def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def local_link(name,target,hard=False):
    need(target and not target.startswith('/') and '\x00' not in target,'relative candidate link required')
    resolved=posixpath.normpath(target if hard else posixpath.join(posixpath.dirname(name),target))
    need(resolved.startswith(PREFIX+'/') or resolved.startswith('usr/share/licenses/'+NAME+'/'),'candidate link escapes private package paths')
    return resolved


def package_identity(info,buildinfo,recipe_sha256):
    need(re.fullmatch('[0-9a-f]{64}',recipe_sha256),'concrete recipe hash required')
    def one(text,key,value):
        return [line.split(' = ',1)[1] for line in text.splitlines() if line.startswith(key+' = ')]==[value]
    need(one(info,'pkgname',NAME) and one(info,'pkgver',VERSION) and one(info,'arch','aarch64') and
         not any(line.startswith(('provides = ','replaces = ','conflict = ')) for line in info.splitlines()),'distinct unselected package identity required')
    need(one(buildinfo,'pkgname',NAME) and one(buildinfo,'pkgver',VERSION) and one(buildinfo,'pkgarch','aarch64') and
         one(buildinfo,'pkgbuild_sha256sum',recipe_sha256),'BUILDINFO concrete recipe binding required')


def stage(package,output,recipe_sha256):
    need(os.getenv('CACHY_ASAHI_GLIBC_BUILD')=='1' and os.uname().machine=='aarch64' and not Path(output).exists(),'explicit owned native staging required')
    total=0;seen=set();deadline=time.monotonic()+60
    with tarfile.open(package,'r:xz') as archive:
        members=[]
        for member in archive:
            name=member.name.rstrip('/');parts=PurePosixPath(name).parts
            need(time.monotonic()<deadline and len(seen)<60000 and name and not name.startswith('/') and '..' not in parts and
                 '/'.join(parts)==name and name not in seen,'bounded canonical package member required');seen.add(name)
            need(member.isfile() or member.isdir() or member.issym() or member.islnk(),'special package member refused')
            need(not member.mode&0o7000 and not member.sparse and member.size<=256*1024**2,'package mode/file bound')
            total+=member.size;need(total<=2*1024**3,'package payload bound')
            metadata=name in ('.PKGINFO','.BUILDINFO','.MTREE')
            need(not metadata or member.isfile(),'ordinary package metadata required')
            ancestors=member.isdir() and (PREFIX.startswith(name+'/') or ('usr/share/licenses/'+NAME).startswith(name+'/'))
            need(metadata or ancestors or name==PREFIX or name.startswith(PREFIX+'/') or name=='usr/share/licenses/'+NAME or
                 name.startswith('usr/share/licenses/'+NAME+'/'),'candidate writes outside private package paths')
            if member.issym() or member.islnk():
                local_link(name,member.linkname,member.islnk())
            members.append(member)
        def metadata_text(name):
            member=archive.getmember(name)
            need(member.isfile() and member.size<=65536,'bounded ordinary package metadata required')
            return archive.extractfile(member).read(65537).decode('utf-8','strict')
        package_identity(metadata_text('.PKGINFO'),metadata_text('.BUILDINFO'),recipe_sha256)
        Path(output).mkdir(mode=0o700)
        archive.extractall(output,members=members,filter='data')
    root=Path(output)/PREFIX;libraries={}
    for key,name in (('loader','ld-linux-aarch64.so.1'),('libc','libc.so.6'),('libm','libm.so.6')):
        path=root/'usr/lib'/name;resolved=path.resolve(strict=True)
        need(resolved.is_relative_to(root.resolve()) and resolved.is_file(),'candidate library escapes stage')
        libraries[key]=dict(path='usr/lib/'+name,sha256=sha(resolved))
    need((root/'usr/lib/gconv/ISO8859-1.so').is_file() and (root/'usr/lib/locale/C.utf8').is_dir(),'candidate gconv and C.utf8 data required')
    value=dict(schema_version=1,stage_root=str(root),**libraries,library_directories=['usr/lib'],gconv_directory='usr/lib/gconv',locale_directory='usr/lib/locale')
    return value

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--package',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--recipe-sha256',required=True)
    args=parser.parse_args();args.manifest.write_text(json.dumps(stage(args.package,args.output,args.recipe_sha256),sort_keys=True,indent=2)+'\n')
