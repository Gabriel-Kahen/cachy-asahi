#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned-container-only candidate extraction and explicit smoke input manifest."""
import argparse,hashlib,json,os,posixpath,re,sys
from pathlib import Path,PurePosixPath
import tarfile,time

sys.path.insert(0,str(Path(__file__).resolve().parent))
import metadata
import ownership
import provider_stage

NAME=metadata.NAME
VERSION=metadata.VERSION


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def allowed(name,directory=False):
    return (directory and name in ('usr','etc','usr/bin','usr/include','usr/lib','usr/share') or
            name in ('etc/gai.conf','etc/rpc') or
            name.startswith(('usr/bin/','usr/include/','usr/lib/','usr/share/')))


def local_link(name,target,hard=False):
    need(target and not target.startswith('/') and '\x00' not in target,'relative candidate link required')
    resolved=posixpath.normpath(target if hard else posixpath.join(posixpath.dirname(name),target))
    need(allowed(resolved),'candidate link escapes conventional provider paths')
    return resolved


package_identity=metadata.package_identity


def stage(package,output,recipe_sha256,expected_lock,audit_output,ownership_output):
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
            need(metadata or allowed(name,member.isdir()),'candidate writes outside conventional provider paths')
            if member.issym() or member.islnk():
                local_link(name,member.linkname,member.islnk())
            members.append(member)
        def metadata_text(name):
            member=archive.getmember(name)
            need(member.isfile() and member.size<=65536,'bounded ordinary package metadata required')
            return archive.extractfile(member).read(65537).decode('utf-8','strict')
        package_identity(metadata_text('.PKGINFO'),metadata_text('.BUILDINFO'),recipe_sha256)
        output=Path(output);output.mkdir(mode=0o700)
        root=output/'root';root.mkdir(mode=0o700)
        payload=[]
        for member in members:
            if member.name in ('.PKGINFO','.BUILDINFO','.MTREE'):
                need(member.size<=2*1024**2,'package metadata bound')
                (output/member.name).write_bytes(archive.extractfile(member).read(2*1024**2+1))
            else:payload.append(member)
        archive.extractall(root,members=payload,filter='data')
    audited=provider_stage.audit(root)
    owned=ownership.check(Path('/var/lib/pacman/local'),expected_lock,
                          {n for n,p in provider_stage.inventory(root)[1].items() if not p.is_dir()})
    Path(audit_output).write_text(json.dumps(audited,sort_keys=True,indent=2)+'\n')
    Path(ownership_output).write_text(json.dumps(owned,sort_keys=True,indent=2)+'\n')
    libraries={}
    for key,name in (('loader','ld-linux-aarch64.so.1'),('libc','libc.so.6'),('libm','libm.so.6')):
        path=root/'usr/lib'/name;resolved=path.resolve(strict=True)
        need(resolved.is_relative_to(root.resolve()) and resolved.is_file(),'candidate library escapes stage')
        libraries[key]=dict(path='usr/lib/'+name,sha256=sha(resolved))
    need((root/'usr/lib/gconv/ISO8859-1.so').is_file() and (root/'usr/lib/locale/C.utf8').is_dir(),'candidate gconv and C.utf8 data required')
    value=dict(schema_version=1,stage_root=str(root),**libraries,library_directories=['usr/lib'],gconv_directory='usr/lib/gconv',locale_directory='usr/lib/locale')
    return value

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--package',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--recipe-sha256',required=True)
    parser.add_argument('--expected-lock',type=Path,required=True);parser.add_argument('--audit-output',type=Path,required=True);parser.add_argument('--ownership-output',type=Path,required=True)
    args=parser.parse_args();args.manifest.write_text(json.dumps(stage(args.package,args.output,args.recipe_sha256,args.expected_lock,args.audit_output,args.ownership_output),sort_keys=True,indent=2)+'\n')
