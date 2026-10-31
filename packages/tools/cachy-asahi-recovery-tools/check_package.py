#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Check pinned originals, literal package metadata and exact installed payload."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import shlex
import stat
import tarfile

NAME = 'cachy-asahi-recovery-tools'
BASE = '852d1b7324e4ad840fa94ea7c9fc994b1aa07280'
SOURCES = ('private-source.tar.gz', NAME, 'check_package.py', 'test_package.py',
           'README.md', 'offline-recovery-bundle.md', 'source-provenance.json',
           'payload-map.json', 'NOTICE', 'LICENSE')
FIELDS = {'pkgname', 'pkgver', 'pkgrel', 'pkgdesc', 'arch', 'url', 'license',
          'depends', 'options', 'source', 'sha256sums'}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, limit=8 * 1024**2):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
         'single-link bounded regular source required: ' + str(path))
    raw = path.read_bytes()
    need(len(raw) == info.st_size, 'source size changed')
    return raw


def metadata(text):
    result = {}
    for line in text.splitlines():
        if line.strip():
            key, value = line.strip().split(' = ', 1)
            result.setdefault(key, []).append(value)
    return result


def check(root, installed=None):
    text = read(root / 'PKGBUILD').decode()
    values = {}
    for match in re.finditer(r'^([a-z][a-z0-9_]*)=(\([^)]*\)|[^\n]+)', text, re.M):
        key, value = match.groups()
        need(key not in values and '$' not in value and '`' not in value, 'literal metadata required')
        values[key] = shlex.split(value[1:-1] if value.startswith('(') else value)
    need(set(values) == FIELDS, 'unexpected package metadata')
    need(metadata(read(root / '.SRCINFO').decode()) == dict(values, pkgbase=[NAME]), '.SRCINFO differs')
    expected = dict(pkgname=[NAME], pkgver=['0.1.0'], pkgrel=['1'], arch=['any'],
                    license=['MIT'], depends=['python>=3.14', 'gnupg', 'glibc'],
                    options=['!strip', '!debug'], source=list(SOURCES))
    need(all(values[key] == value for key, value in expected.items()), 'unsupported package metadata')
    need(len(values['sha256sums']) == len(SOURCES), 'source checksum count differs')
    for name, pin in zip(SOURCES, values['sha256sums']):
        raw = read(root / name)
        need(re.fullmatch('[0-9a-f]{64}', pin) and sha(raw) == pin, 'source checksum differs: ' + name)
        if name.endswith('.py') or name == NAME:
            compile(raw, name, 'exec')
    provenance = json.loads(read(root / 'source-provenance.json'))
    need(provenance['package'] == NAME and provenance['version'] == '0.1.0-1'
         and provenance['source_revision'] == BASE and provenance['upstream_repairs'] == []
         and provenance['original_source_bytes_preserved'] is True
         and provenance['runtime_dependencies'] == expected['depends'], 'original provenance differs')
    originals = provenance['sources']
    need(len(originals) == 18, 'original source count differs')
    wanted = {}
    runtime = {}
    for rel, row in originals.items():
        need(row['source_commit'] == BASE and row['license'] == 'MIT'
             and type(row['bytes']) is int and 0 < row['bytes'] <= 8 * 1024**2
             and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'original binding differs')
        if rel.startswith('scripts/'):
            need(row['packaged_as'] == 'private/' + rel and '..' not in Path(rel).parts,
                 'private source path differs')
            wanted[row['packaged_as']] = row
        if row['installed']:
            need(rel.startswith('scripts/') and rel.endswith('.py'), 'unsupported runtime source')
            runtime[rel] = row['sha256']
    bodies = {}
    with tarfile.open(root / 'private-source.tar.gz', 'r:gz') as archive:
        for member in archive:
            need(member.name in wanted and member.name not in bodies and member.isfile()
                 and member.mode == 0o644 and member.size == wanted[member.name]['bytes'],
                 'private source member differs')
            with archive.extractfile(member) as stream:
                raw = stream.read(8 * 1024**2 + 1)
            need(len(raw) == member.size and sha(raw) == wanted[member.name]['sha256'],
                 'private original bytes differ')
            compile(raw, member.name, 'exec')
            bodies[member.name] = raw
    need(set(bodies) == set(wanted) and len(runtime) == 15, 'private source set differs')
    for rel in ('LICENSE', 'docs/port/offline-recovery-bundle.md'):
        row = originals[rel]
        raw = read(root / row['packaged_as'])
        need(len(raw) == row['bytes'] and sha(raw) == row['sha256'], 'original document differs')
    tree = ast.parse(read(root / NAME))
    pins = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'PINS' for target in node.targets)]
    need(pins == [runtime], 'launcher source pins differ')
    payload = {f'usr/lib/cachy-asahi/recovery-tools/{rel}': {'source': 'private/' + rel, 'mode': 0o644}
               for rel in runtime}
    payload[f'usr/bin/{NAME}'] = dict(source=NAME, mode=0o755)
    payload.update({f'usr/share/doc/{NAME}/{name}': dict(source=name, mode=0o644)
                    for name in ('README.md', 'offline-recovery-bundle.md', 'source-provenance.json', 'payload-map.json')})
    payload.update({f'usr/share/licenses/{NAME}/{name}': dict(source=name, mode=0o644)
                    for name in ('NOTICE', 'LICENSE')})
    need(json.loads(read(root / 'payload-map.json')) == payload, 'declared payload differs')
    installs = {}
    for line in text.splitlines():
        if line.strip().startswith('install -Dm'):
            _, mode, source, target, *tail = shlex.split(line.strip())
            need(tail == ['||', 'return'] and source.startswith('$srcdir/')
                 and target.startswith('$pkgdir/'), 'installation command differs')
            target = target.removeprefix('$pkgdir/')
            need(target not in installs, 'duplicate installation')
            installs[target] = dict(source=source.removeprefix('$srcdir/'), mode=int(mode[3:], 8))
    need(installs == payload, 'recipe installation differs')
    need(not list(root.glob('*.install')) and not list(root.glob('*.hook')), 'unexpected host mutation hook')
    if installed is not None:
        actual = {path.relative_to(installed).as_posix() for path in installed.rglob('*')
                  if not path.is_dir() or path.is_symlink()}
        need(actual == set(payload), 'installed file set differs')
        for rel, row in payload.items():
            path = installed / rel
            raw = read(path)
            original = bodies[row['source']] if row['source'].startswith('private/') else read(root / row['source'])
            need(raw == original and stat.S_IMODE(path.stat().st_mode) == row['mode'], 'installed bytes/mode differ: ' + rel)
    return dict(status='PASS', original_files=len(originals), runtime_files=len(runtime), payload_files=len(payload))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, required=True)
    parser.add_argument('--installed', type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.recipe_root, args.installed), sort_keys=True))
