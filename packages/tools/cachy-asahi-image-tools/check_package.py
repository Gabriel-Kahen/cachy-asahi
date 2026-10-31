#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Check exact original sources, literal recipe and staged payload bytes."""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import shlex
import stat
import tarfile

NAME = 'cachy-asahi-image-tools'
SOURCES = ('private-source.tar.gz', NAME, 'check_package.py', 'test_package.py',
           'README.md', 'source-provenance.json', 'payload-map.json', 'NOTICE', 'LICENSE')
DEPENDENCIES = ['python>=3.14', 'libarchive', 'e2fsprogs', 'gnupg', 'glibc']


def need(value, reason):
    if not value:
        raise ValueError(reason)


def read(path):
    path = Path(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 8*1024**2,
         'bounded-single-link-source:' + str(path))
    raw = path.read_bytes()
    need(len(raw) == info.st_size, 'source-drift')
    return raw


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def metadata(raw):
    result = {}
    for line in raw.decode().splitlines():
        if line.strip():
            key, value = line.strip().split(' = ', 1)
            result.setdefault(key, []).append(value)
    return result


def check(root, installed=None):
    root = Path(root)
    text = read(root/'PKGBUILD').decode()
    values = {}
    for match in re.finditer(r'^([a-z][a-z0-9_]*)=(\([^)]*\)|[^\n]+)', text, re.M):
        key, value = match.groups()
        need(key not in values and '$' not in value and '`' not in value, 'literal-metadata')
        values[key] = shlex.split(value[1:-1] if value.startswith('(') else value)
    need(set(values) == {'pkgname','pkgver','pkgrel','pkgdesc','arch','url','license',
                         'depends','options','source','sha256sums'}, 'recipe-metadata-set')
    expected = dict(pkgname=[NAME], pkgver=['0.1.0'], pkgrel=['1'], arch=['any'],
                    license=['MIT'], depends=DEPENDENCIES, options=['!strip','!debug'], source=list(SOURCES))
    need(all(values[k] == v for k,v in expected.items()), 'recipe-metadata-value')
    need(metadata(read(root/'.SRCINFO')) == dict(values, pkgbase=[NAME]), 'srcinfo-mismatch')
    need(len(values['sha256sums']) == len(SOURCES), 'checksum-count')
    for name, digest in zip(SOURCES, values['sha256sums']):
        need(re.fullmatch('[0-9a-f]{64}', digest) and sha(read(root/name)) == digest, 'source-pin:' + name)
    provenance = json.loads(read(root/'source-provenance.json'))
    need(provenance['package'] == NAME and provenance['version'] == '0.1.0-1'
         and provenance['original_source_bytes_preserved'] is True
         and provenance['runtime_dependencies'] == DEPENDENCIES
         and re.fullmatch('[0-9a-f]{40}', provenance['source_revision']), 'provenance-shape')
    originals = provenance['sources']
    need(len(originals) == 65, 'finite-original-closure')
    wanted = {row['packaged_as']: row for row in originals.values() if row['packaged_as'].startswith('private/')}
    runtime = {rel: row['sha256'] for rel,row in originals.items() if row['installed']}
    need(len(runtime) == 60 and len(wanted) == 63, 'runtime-and-test-closure')
    bodies = {}
    with tarfile.open(root/'private-source.tar.gz', 'r:gz') as archive:
        for member in archive:
            need(member.name in wanted and member.name not in bodies and member.isfile()
                 and member.mode == 0o644 and member.uid == member.gid == 0
                 and member.mtime == 1700000000 and not member.pax_headers,
                 'original-archive-member')
            row = wanted[member.name]
            need(member.size == row['bytes'] <= 2*1024**2, 'original-size')
            with archive.extractfile(member) as stream:
                raw = stream.read(member.size + 1)
            need(len(raw) == member.size and sha(raw) == row['sha256'], 'original-pin:' + member.name)
            if member.name.endswith('.py'):
                compile(raw, member.name, 'exec')
            bodies[member.name] = raw
    need(set(bodies) == set(wanted), 'original-file-set')
    for rel,row in originals.items():
        need(row['source_commit'] == provenance['source_revision'] and row['license'] == 'MIT', 'original-authority')
        if not row['packaged_as'].startswith('private/'):
            need(sha(read(root/row['packaged_as'])) == row['sha256'], 'license-pin')
    tree = ast.parse(read(root/NAME))
    pins = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == 'PINS' for target in node.targets)]
    need(pins == [runtime], 'launcher-pin-set')
    payload = {'usr/lib/cachy-asahi/image-tools/' + rel: dict(source='private/' + rel, mode=0o644) for rel in runtime}
    payload['usr/bin/' + NAME] = dict(source=NAME, mode=0o755)
    payload.update({'usr/share/doc/' + NAME + '/' + name: dict(source=name, mode=0o644)
                    for name in ('README.md','source-provenance.json','payload-map.json')})
    payload.update({'usr/share/licenses/' + NAME + '/' + name: dict(source=name, mode=0o644)
                    for name in ('LICENSE','NOTICE')})
    need(json.loads(read(root/'payload-map.json')) == payload, 'payload-map')
    installs = {}
    for line in text.splitlines():
        if line.strip().startswith('install -Dm'):
            _, mode, source, target, *tail = shlex.split(line.strip())
            need(tail == ['||','return'] and source.startswith('$srcdir/') and target.startswith('$pkgdir/'), 'install-shape')
            rel = target.removeprefix('$pkgdir/')
            need(rel not in installs, 'duplicate-install')
            installs[rel] = dict(source=source.removeprefix('$srcdir/'), mode=int(mode[3:],8))
    need(installs == payload and not list(root.glob('*.install')) and not list(root.glob('*.hook')), 'install-closure')
    if installed is not None:
        installed = Path(installed)
        found = {p.relative_to(installed).as_posix() for p in installed.rglob('*') if not p.is_dir() or p.is_symlink()}
        need(found == set(payload), 'installed-file-set')
        for rel,row in payload.items():
            path = installed/rel
            original = bodies[row['source']] if row['source'].startswith('private/') else read(root/row['source'])
            need(read(path) == original and stat.S_IMODE(path.stat().st_mode) == row['mode'], 'installed-byte-mode:' + rel)
    return dict(status='PASS', original_files=len(originals), runtime_files=len(runtime), payload_files=len(payload))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, required=True)
    parser.add_argument('--installed', type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.recipe_root, args.installed), sort_keys=True))
