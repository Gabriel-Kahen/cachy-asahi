# SPDX-License-Identifier: MIT
"""Owned static build validator. No actor, signing or Root observation schema.

The owner executes this CLI through its supervisor: the held zstd decoder, if
needed, is a descendant of that same actual owned command. Never source recipes.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

FAMILY='scripts/ci/first-login-enrollment-native-source'
PROFILE_PIN=dict(bytes=21679,sha256='8ad3641649e395b1202363e3368f713f65252a743b12e3a8d69430e4f82bc171')
SEAM=b"sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'checks'))\nfrom package_checks import digest, package, recipe, conflicts, metadata, FIELDS, ARCH_FIELDS"
REPLACEMENT=b"digest, package, recipe, conflicts, metadata, FIELDS, ARCH_FIELDS = (__held_checks.digest, __held_checks.package, __held_checks.recipe, __held_checks.conflicts, __held_checks.metadata, __held_checks.FIELDS, __held_checks.ARCH_FIELDS)"


def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def ordinary(path,cap=16*1024**2):
    path=Path(path);need(path.is_absolute() and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute validation DATA')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded single-link validation DATA')
        parts=[];size=0
        while block:=os.read(fd,min(65536,cap+1-size)):
            parts.append(block);size+=len(block);need(size<=cap,'validation file byte cap')
        identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns)
        need(size==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'validation DATA changed')
        return b''.join(parts)
    finally:os.close(fd)


def module(name,path,raw,extra=None):
    spec=importlib.util.spec_from_file_location(name,path);result=importlib.util.module_from_spec(spec)
    if extra:result.__dict__.update(extra)
    exec(compile(raw,str(path),'exec'),result.__dict__);return result


def project_build(raw):
    need(raw.count(SEAM)==1 and REPLACEMENT not in raw,'one held builder import seam')
    projected=raw.replace(SEAM,REPLACEMENT)
    need(projected.replace(REPLACEMENT,SEAM)==raw,'exact builder import projection inverse');return projected


def helpers(source,profile):
    bodies={}
    for name in ('scripts/checks/package_checks.py','scripts/build/build.py','scripts/build/container-entry.sh'):
        raw=ordinary(source/name,128*1024);row=profile['helpers'][name]
        need(dict(mode=stat.S_IMODE((source/name).lstat().st_mode),**pin(raw))==row,'whole pinned static helper/entry bytes and mode')
        bodies[name]=raw
    P=module('private_pinned_package_checks',source/'scripts/checks/package_checks.py',bodies['scripts/checks/package_checks.py'])
    B=module('private_pinned_build_predicates',source/'scripts/build/build.py',project_build(bodies['scripts/build/build.py']),{'__held_checks':P})
    return P,B,pin(bodies['scripts/build/container-entry.sh'])['sha256']


def validate(*,source_root,kind,build_directory,expected_inventory,source_date_epoch):
    source=Path(source_root);directory=Path(build_directory);inventory=Path(expected_inventory)
    profile_raw=ordinary(source/(FAMILY+'/successor_v2/profile.json'),65536)
    need(pin(profile_raw)==PROFILE_PIN,'whole maintained current profile')
    profile=json.loads(profile_raw);need(kind in ('enrollment','first-login','ui') and type(source_date_epoch) is int and source_date_epoch>=0,'one exact private package/epoch')
    recipe=profile['packages'][kind];P,B,entry_sha=helpers(source,profile)
    need(directory.is_absolute() and not any(p.is_symlink() for p in (directory,*directory.parents)) and
         directory!=source and source not in directory.parents and directory not in source.parents,'disjoint private build directory')
    snapshot=directory/'inputs';artifacts=directory/'artifacts'
    need(snapshot.is_dir() and not snapshot.is_symlink() and artifacts.is_dir() and not artifacts.is_symlink(),'actual ordinary build snapshot/artifacts')
    need({p.name for p in snapshot.iterdir()}==set(recipe['files']),'complete exact recipe snapshot namespace')
    for name,row in recipe['files'].items():
        need(dict(mode=stat.S_IMODE((snapshot/name).lstat().st_mode),**pin(ordinary(snapshot/name)))==row,'whole recipe snapshot bytes/mode')
        need(pin(ordinary(source/recipe['path']/name))=={k:row[k] for k in ('bytes','sha256')},'snapshot agrees with selected Source recipe')
    reviewed=P.recipe(snapshot/'PKGBUILD');need(reviewed['errors']==[] and reviewed['input_sha256']=={
        name:row['sha256'] for name,row in recipe['files'].items()},'actual static recipe/source hashes and metadata')
    expected=json.loads(ordinary(source/'reviewed'/(kind+'.json'),1024**2))
    need(expected==reviewed['input_sha256'],'whole independently reviewed recipe hash set')
    lock=ordinary(inventory,1024**2)
    need(lock and lock.endswith(b'\n') and lock==b''.join(sorted(lock.splitlines(keepends=True))) and
         ordinary(directory/'expected-packages.lock',1024**2)==ordinary(artifacts/'packages.lock',1024**2)==lock,'actual unchanged complete builder inventory')
    required=('environment.txt','packages.lock','config.sha256','makepkg.conf','pacman.conf','generated.SRCINFO')
    for name in required:ordinary(artifacts/name)
    ordinary(directory/'build.log',1024**2)
    need(not any(p.is_symlink() or not p.is_file() for p in artifacts.iterdir()),'ordinary flat artifact namespace')
    B.bind_generated(reviewed['metadata'],P.metadata(ordinary(artifacts/'generated.SRCINFO',1024**2).decode()))
    paths=[p for p in artifacts.glob('*.pkg.tar.*') if not p.name.endswith('.sig')]
    need(len(paths)==1 and paths[0].name==recipe['archive'],'one exact actual package archive')
    ordinary(paths[0]);reports=[P.package(paths[0])]
    errors=P.conflicts(reports)+[error for report in reports for error in report['errors']]
    errors+=B.bind_artifact(reviewed['metadata'],reports[0],reviewed['input_sha256']['PKGBUILD'])
    for name in ('.PKGINFO','.BUILDINFO'):
        need(reports[0]['metadata'][name].get('builddate')==[str(source_date_epoch)],'actual stable source epoch package metadata')
    validation=dict(artifacts=reports,errors=errors);body=encoded(validation)
    need(len(body)<=4*1024**2,'finite complete package validation report')
    with (directory/'validation.json').open('xb') as stream:os.fchmod(stream.fileno(),0o600);stream.write(body)
    need(not errors,'actual package static validation failed: '+'; '.join(errors)[:1024])
    return dict(status='PASS_DELEGATED_BUILD_STATIC_VALIDATION',recipe_inputs=reviewed['input_sha256'],recipe_metadata=reviewed['metadata'],
        entry_script_sha256=entry_sha,artifacts={recipe['archive']:P.digest(paths[0])},validation_pin=pin(body))


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source-root','kind','build-directory','expected-inventory'):p.add_argument('--'+name,required=True)
    p.add_argument('--source-date-epoch',type=int,required=True);a=p.parse_args()
    need(sys.flags.isolated and sys.dont_write_bytecode and __debug__,'isolated unoptimized owned validator')
    print(json.dumps(validate(source_root=a.source_root,kind=a.kind,build_directory=a.build_directory,
        expected_inventory=a.expected_inventory,source_date_epoch=a.source_date_epoch),sort_keys=True))


if __name__=='__main__':main()
