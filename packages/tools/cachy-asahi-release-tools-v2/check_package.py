#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Validate exact local sources, frozen runtime and pure staged payload."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import stat

NAME = 'cachy-asahi-release-tools'
SOURCES = (NAME, 'release_sbom.py', 'source_delivery.py', 'recipe_source_delivery.py',
           'recipe_source_delivery_v2.py', 'archive_stream.py', 'package_checks.py',
           'compare_sboms.py', 'check_package.py', 'test_package.py', 'README.md', 'comparing-sboms.md',
           'source-provenance.json', 'payload-map.json', 'export-v2.json', 'NOTICE', 'LICENSE')
FROZEN = {
    'release_sbom.py': '1a53831128858c6c629f2449a7276a52846e52ebf426baa6f1c010aa209af486',
    'source_delivery.py': '8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e',
    'recipe_source_delivery.py': '779f8147a13d3f90d11b9e5610f2d7d74fce28d0732797331fc832f0e87323be',
    'recipe_source_delivery_v2.py': 'cbc13a6e2d604dfec9d0090cb22d279952f2c96b3d1196c2e8a18ee83ad922ae',
    'archive_stream.py': '10f1a4c0ac5b98852d9ebb150af28f9ce345c800935a64fa463bc90f72fcb838',
    'package_checks.py': 'e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8',
    'compare_sboms.py': '219296c46902257f64203e3b3b41ece42a2e21a7d818f305bac858767aeff1b4',
}
RUNTIME = {**{f'usr/lib/cachy-asahi/release-tools-v2/scripts/release/{leaf}': leaf for leaf in
              ('release_sbom.py', 'source_delivery.py', 'recipe_source_delivery.py', 'recipe_source_delivery_v2.py', 'compare_sboms.py')},
           'usr/lib/cachy-asahi/release-tools-v2/scripts/update/archive_stream.py': 'archive_stream.py',
           'usr/lib/cachy-asahi/release-tools-v2/scripts/checks/package_checks.py': 'package_checks.py'}
PAYLOAD = {f'usr/bin/{NAME}': {'source': NAME, 'mode': 0o755}}
PAYLOAD.update({key: {'source': leaf, 'mode': 0o644} for key, leaf in RUNTIME.items()})
PAYLOAD.update({f'usr/share/doc/{NAME}/{leaf}': {'source': leaf, 'mode': 0o644}
                for leaf in ('README.md', 'comparing-sboms.md', 'source-provenance.json', 'payload-map.json', 'export-v2.json')})
PAYLOAD.update({f'usr/share/licenses/{NAME}/{leaf}': {'source': leaf, 'mode': 0o644}
                for leaf in ('NOTICE', 'LICENSE')})


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def metadata(raw):
    result = {}
    for line in raw.splitlines():
        if line.strip() and not line.lstrip().startswith('#'):
            key, value = line.strip().split(' = ', 1)
            result.setdefault(key, []).append(value)
    return result


def check_source(root):
    literal = {}
    for match in re.finditer(r'^([a-z][a-z0-9_]*)=(\([^)]*\)|[^\n]+)', (root / 'PKGBUILD').read_text(), re.M):
        key, value = match.groups()
        need('$' not in value and '`' not in value and key not in literal, 'literal recipe required')
        literal[key] = shlex.split(value[1:-1] if value.startswith('(') else value, comments=True)
    info = metadata((root / '.SRCINFO').read_text())
    need(info == dict(literal, pkgbase=[NAME]), 'SRCINFO/recipe differ')
    expected = dict(pkgname=[NAME], pkgver=['0.2.0'], pkgrel=['1'], arch=['any'], license=['MIT'],
                    depends=['python>=3.14', 'zstd'], options=['!strip', '!debug'])
    for key, value in expected.items():
        need(info.get(key) == value, 'package field mismatch: ' + key)
    need(set(info) == set(expected) | {'pkgbase', 'pkgdesc', 'url', 'source', 'sha256sums'}, 'unexpected recipe metadata')
    need(info['source'] == list(SOURCES) and len(info['sha256sums']) == len(SOURCES), 'source set differs')
    for leaf, checksum in zip(SOURCES, info['sha256sums']):
        path = root / leaf
        need(path.is_file() and not path.is_symlink() and re.fullmatch('[0-9a-f]{64}', checksum), 'source type/pin')
        need(sha(path) == checksum, 'source checksum differs: ' + leaf)
        if leaf.endswith('.py') or leaf == NAME:
            compile(path.read_bytes(), leaf, 'exec')
    need(not list(root.glob('*.hook')) and not list(root.glob('*.install')), 'unexpected hooks')
    provenance = json.loads((root / 'source-provenance.json').read_bytes())
    need(provenance['package'] == NAME and provenance['version'] == '0.2.0-1', 'provenance identity')
    need(set(provenance['runtime_closure']) == set(FROZEN), 'runtime closure differs')
    for leaf, checksum in FROZEN.items():
        row = provenance['runtime_closure'][leaf]
        need(row['sha256'] == checksum == sha(root / leaf) and row['bytes'] == (root / leaf).stat().st_size
             and row['license'] == 'MIT', 'frozen runtime differs: ' + leaf)
    need(provenance['license']['sha256'] == sha(root / 'LICENSE'), 'license pin')
    need(provenance['launcher_sha256'] == sha(root / NAME), 'launcher pin')
    need(provenance['future_native_build_pair']['actual_binding'] is None, 'proposal actual binding must remain null')
    payload = json.loads((root / 'payload-map.json').read_bytes())
    need(payload['files'] == PAYLOAD and payload['package'] == NAME, 'payload map differs')
    exports = json.loads((root / 'export-v2.json').read_bytes())
    need(exports['schema_version'] == 2 and exports['package'] == NAME and exports['version'] == '0.2.0-1'
         and exports['canonical_directory'] == 'packages/tools/cachy-asahi-release-tools-v2'
         and exports['source_files'] == ['PKGBUILD', '.SRCINFO', *SOURCES]
         and exports['runtime_exports'] == RUNTIME, 'versioned export list differs')


def check_stage(root, stage, archive=False):
    expected_dirs = {str(parent) for leaf in PAYLOAD for parent in Path(leaf).parents if str(parent) != '.'}
    files, dirs = set(), set()
    extra = {'.PKGINFO', '.BUILDINFO', '.MTREE'} if archive else set()
    for path in stage.rglob('*'):
        need(not path.is_symlink(), 'staged symlink')
        name = path.relative_to(stage).as_posix()
        if path.is_dir():
            dirs.add(name)
            need(stat.S_IMODE(path.stat().st_mode) == 0o755, 'directory mode')
        else:
            need(path.is_file(), 'staged nonregular file'); files.add(name)
    need(files == set(PAYLOAD) | extra and dirs == expected_dirs, 'staged path set differs')
    for name, row in PAYLOAD.items():
        path = stage / name
        need(stat.S_IMODE(path.stat().st_mode) == row['mode'] and path.read_bytes() ==
             (root / row['source']).read_bytes(), 'staged bytes/mode differ: ' + name)
    for name in extra:
        need(stat.S_IMODE((stage / name).stat().st_mode) == 0o644, 'archive metadata mode')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, default=Path(__file__).resolve().parent)
    stages = parser.add_mutually_exclusive_group()
    stages.add_argument('--stage', type=Path)
    stages.add_argument('--archive-stage', type=Path)
    args = parser.parse_args()
    try:
        check_source(args.recipe_root)
        stage = args.stage or args.archive_stage
        if stage:
            check_stage(args.recipe_root, stage, args.archive_stage is not None)
    except (OSError, ValueError, KeyError, TypeError, IndexError, SyntaxError) as error:
        print(json.dumps(dict(status='REFUSED', reason=str(error)), sort_keys=True))
        return 2
    print(json.dumps(dict(status='PASS_SOURCE_AND_PAYLOAD' if stage else 'PASS_SOURCE',
                         sources=len(SOURCES), payload_files=len(PAYLOAD), native_ARM='NOT RUN', ALPM='NOT RUN', M2='NOT RUN')))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
