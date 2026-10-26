# SPDX-License-Identifier: MIT
"""Exact retained setup4 public pair; no fetch and no unbounded extraction."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile

SOURCE='93bc9bfac7343ee3b443ae3332c0942ed1ba5b55'
ARCHIVE_SHA='1637452a84733fdf059d7dbc10c5b6dddd11c589c4f97ebb6a4655aedd12359f'
PACKAGE='cachy-asahi-setup-0.1.0-4-any.pkg.tar.xz'
PACKAGE_SHA='c817c01aad875fcf5a34073d4c9d0e830c577301189148b3c0e0969f001bea1a'
HERE=Path(__file__).resolve().parent


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def unpack(source,target):
    need(source.is_file() and not any(p.is_symlink() for p in (source,*source.parents)) and source.stat().st_size==69776 and sha(source)==ARCHIVE_SHA,'exact retained setup4 public bundle required')
    need(not target.exists() and not any(p.is_symlink() for p in (target,*target.parents)),'fresh ordinary retained output required')
    # Same bounded member gate as the full installer workflow's Unpack setup4 step.
    with tarfile.open(source,'r:xz') as archive:
        members=archive.getmembers()
        need(len(members)==64 and sum(item.size for item in members)<4*1024**2 and len({item.name for item in members})==64,'closed64 retained pair required')
        for item in members:
            name=PurePosixPath(item.name)
            need(item.isfile() and not name.is_absolute() and '..' not in name.parts and name.parts[0] in ('build-1','build-2'),'ordinary bounded setup4 member required')
        target.mkdir(mode=0o700);archive.extractall(target,filter='data')
    verify(target)


def verify(root):
    pins=json.loads((HERE/'retained-inputs.json').read_text())
    need(len(pins)==64 and sum(r['bytes'] for r in pins.values())<4*1024**2,'exact retained source index required')
    nodes=list(root.rglob('*'))
    need(all(not p.is_symlink() and (p.is_dir() or p.is_file()) for p in nodes),'ordinary closed retained tree required')
    actual={str(p.relative_to(root)) for p in nodes if p.is_file()}
    need(actual==set(pins),'closed retained64 membership differs')
    for name,row in pins.items():
        path=root/name
        need(path.is_file() and not any(p.is_symlink() for p in (path,*path.parents)) and path.stat().st_size==row['bytes'] and sha(path)==row['sha256'],'retained source/pair bytes differ: '+name)
    for side in (1,2):
        package=root/f'build-{side}'/'artifacts'/PACKAGE
        need(package.stat().st_size==22632 and sha(package)==PACKAGE_SHA,'exact retained setup4 package required')
    return root/'build-1/artifacts'/PACKAGE


def stage(root,target,checks,bind):
    archive=verify(root);metadata=checks.metadata((root/'build-1/inputs/.SRCINFO').read_text())
    report=checks.package(archive)
    need(not report['errors'] and not report['elf'] and not bind.bind_artifact(metadata,report,sha(root/'build-1/inputs/PKGBUILD')),'retained setup4 artifact/source binding differs')
    fields=report['metadata']['.PKGINFO'];need(fields['pkgname']==['cachy-asahi-setup'] and fields['pkgver']==['0.1.0-4'] and fields['license']==['MIT'] and sorted(fields['depend'])==['gnupg','pacman','python>=3.11'],'retained setup4 metadata differs')
    target.mkdir();shutil.copyfile(archive,target/PACKAGE)
    payload={n:r for n,r in report['members'].items() if r['type']!='5' and n not in ('.PKGINFO','.BUILDINFO','.MTREE')}
    need(len(payload)==6 and all(r['type']=='0' and r['uid']==r['gid']==0 for r in payload.values()),'six ordinary retained setup4 payload files required')
    (target/'product.json').write_text(json.dumps(dict(archive=PACKAGE,sha256=PACKAGE_SHA,version='0.1.0-4',payload=payload),indent=2)+'\n')
    return target/PACKAGE


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();unpack(a.source.absolute(),a.output.absolute())
