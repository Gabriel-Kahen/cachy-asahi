#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Construct a fresh bounded context from retained local source and accepted archive."""
import argparse
import io
import os
from pathlib import Path
import re
import shutil
import sys
import tarfile
import zipfile
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C


def construct(source, accepted, output):
    source, accepted, output = map(C.ordinary, (source, accepted, output))
    C.need(not output.exists() and output.parent.is_dir(), 'fresh context required')
    C.need(os.getuid() == os.geteuid() > 0, 'ordinary constructor required')
    if accepted.suffix == '.zip':
        with zipfile.ZipFile(accepted) as z:
            members = [n for n in z.namelist() if n == 'packages/cachy-asahi-setup8-a/cachy-asahi-setup-0.3.0-1-any.pkg.tar.xz']
            C.need(len(members) == 1 and z.getinfo(members[0]).file_size == 33900, 'exact retained Setup8 member required')
            raw = z.read(members[0])
    else: raw = accepted.read_bytes()
    C.need(len(raw) == 33900 and C.sha(raw) == C.SETUP_SHA, 'accepted Setup8 0.3.0-1 archive pin differs')
    output.mkdir(mode=0o755); (output/'setup8.pkg.tar.xz').write_bytes(raw)
    stage = output/'stage'; stage.mkdir()
    setup_source = source/'packages/tools/cachy-asahi-setup8'
    C.need(C.digest(setup_source/'test_delivery.py')==C.DELIVERY_SHA,'accepted delivery source pin differs')
    payload = __import__('json').loads((setup_source/'payload-map.json').read_bytes())
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:xz') as archive:
        files = {m.name.removeprefix('./'):m for m in archive if m.isfile() and not m.name.removeprefix('./').startswith('.')}
        C.need(set(files) == set(payload), 'exact ten-file accepted Setup8 payload required')
        for name, row in payload.items():
            member = files[name]
            C.need(member.size < 256*1024 and member.mode == row['mode'], 'bounded accepted payload mode differs')
            data = archive.extractfile(member).read()
            C.need(data == (setup_source/row['source']).read_bytes(), 'accepted package/source join differs: '+name)
            path = stage/name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); path.chmod(row['mode'])
    for name in ('test_delivery.py','payload-map.json','PKGBUILD'):
        target = output/'setup-source'/name; target.parent.mkdir(exist_ok=True); shutil.copyfile(setup_source/name,target)
    packages = {}
    for component, directory in C.PACKAGES.items():
        original = source/directory; target = output/'sources'/Path(directory).name
        target.mkdir(parents=True)
        # Copy only the recipe's declared local sources, not unrelated audit/build trees.
        listed=C.command(['bash','-e','-c','source "$1"; printf \'%s\\n\' "${source[@]}"','list',original/'PKGBUILD']).stdout.decode().splitlines()
        C.need(0<len(listed)<40 and all('/' not in n and n not in ('.','..') for n in listed),'finite local recipe sources required')
        for name in dict.fromkeys(['PKGBUILD',*listed]):
            path=original/name
            C.need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024**2,'ordinary bounded recipe source required')
            shutil.copyfile(path,target/name)
        script = '''set -e
source "$1/PKGBUILD"
[[ ${#source[@]} == ${#sha256sums[@]} ]]
for ((i=0;i<${#source[@]};i++)); do
  [[ ${source[i]} != */* && ${sha256sums[i]} =~ ^[0-9a-f]{64}$ ]]
  printf '%s  %s\n' "${sha256sums[i]}" "$1/${source[i]}" | sha256sum -c --status
done
srcdir=$1; pkgdir=$2; package
printf '%s %s-%s' "$pkgname" "$pkgver" "$pkgrel"
'''
        result = C.command(['bash','-e','-c',script,'stage',target,stage],env=dict(PATH='/usr/bin:/bin',HOME=str(output)))
        package, version = result.stdout.decode().split()
        packages[component] = dict(package=package, version=version, source=str(target.relative_to(output)))
    for name in ('common.py','trial.py','native.py'):
        shutil.copyfile(Path(__file__).parent/name, output/name)
    record = dict(schema_version=1, components=list(C.COMPONENTS), packages=packages,
        setup_archive_sha256=C.SETUP_SHA, setup_version='0.3.0-1', accepted_run=40490674681,
        source_commit=C.command(['git','-C',source,'rev-parse','HEAD']).stdout.decode().strip(),
        stage_tree=C.payload_tree(stage), files={}, scope='LOCAL_PACKAGE_STAGE; NOT_ALPM_INSTALLATION',
        migration_kind='EXACT_PAYLOAD_RELOCATION; NO_CHANGED_RELEASE_CLAIM')
    for path in sorted(output.rglob('*')):
        if path.is_file():record['files'][str(path.relative_to(output))] = dict(bytes=path.stat().st_size,sha256=C.digest(path))
    C.save(output/'context.json', record); C.verify_context(output)
    return record


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('source','accepted','output'):p.add_argument('--'+n,type=Path,required=True)
    a=p.parse_args(); r=construct(a.source.absolute(),a.accepted.absolute(),a.output.absolute())
    print(__import__('json').dumps(dict(status='PASS_CONTEXT_CONSTRUCTED',files=len(r['files']),packages=len(r['packages'])+1)))
