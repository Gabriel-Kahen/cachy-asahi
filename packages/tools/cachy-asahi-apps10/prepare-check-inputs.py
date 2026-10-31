#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Materialize only the closed, pinned, data-only application check inputs."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile

REPOSITORY={'scripts/client/client.py','scripts/release/release.py','scripts/release/source_delivery.py','scripts/release/test_release.py','LICENSE'}
RUNTIME={'PKGBUILD','.SRCINFO','client.py','release.py','source_delivery.py','helper-pins.json','check_source.py','README.md','source-provenance.json','NOTICE','LICENSE'}
MEMBERS={'repository/'+n for n in REPOSITORY}|{'runtime-recipe/'+n for n in RUNTIME}


def need(ok,message):
    if not ok:raise ValueError(message)


def read(path,cap):
    path=Path(path).absolute();need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary check input path required')
    info=path.stat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=cap,'bounded regular check input required')
    raw=path.read_bytes();need(len(raw)==info.st_size,'check input changed');return raw


def digest(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def prepare(archive,index,output):
    value=json.loads(read(index,65536));need(set(value)=={'schema_version','purpose','license','archive','files'} and
        type(value['schema_version']) is int and value['schema_version']==1 and value['purpose']=='apps-local-check-inputs' and value['license']=='MIT' and
        set(value['files'])==MEMBERS,'exact16 check source members required')
    raw=read(archive,1024**2);need(digest(raw)==value['archive'],'check archive SHA256/size differs')
    blobs={};total=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as stream:
        for member in stream:
            need(member.name in MEMBERS and member.name not in blobs and member.type==tarfile.REGTYPE and
                 member.mode==0o644 and member.uid==member.gid==member.mtime==0 and
                 not member.pax_headers and not member.linkname and member.size<=65536,'noncanonical/nonregular/duplicate check member')
            content=stream.extractfile(member).read(65537);total+=len(content)
            need(total<=512*1024 and len(content)==member.size and digest(content)==value['files'][member.name]['content'],
                 'check source bytes differ or exceed bound')
            blobs[member.name]=content
    need(set(blobs)==MEMBERS,'missing check source member')
    output=Path(output).absolute()
    need(not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)) and output.parent.is_dir(),'fresh ordinary check workspace required')
    output.mkdir(mode=0o700)
    for name,content in sorted(blobs.items()):
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as target:target.write(content)
        path.chmod(0o644)
    return dict(status='PASS_CLOSED_LOCAL_CHECK_INPUTS',files=len(blobs),bytes=total,archive=value['archive'],code_execution='NONE')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('archive','index','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();print(json.dumps(prepare(args.archive,args.index,args.output),sort_keys=True))
