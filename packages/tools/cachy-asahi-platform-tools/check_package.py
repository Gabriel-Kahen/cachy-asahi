#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit the finite package inputs without executing the bundled helpers."""
import argparse
import hashlib
import json
from pathlib import Path
import tarfile


def require(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def audit(root):
    source = json.loads((root / 'source-provenance.json').read_bytes())
    runtime = json.loads((root / 'runtime-map.json').read_bytes())
    require(source['license'] == 'MIT' and sha((root / 'LICENSE').read_bytes()) == source['license_sha256'], 'license pin differs')
    require(len(source['runtime_files']) == 16 and len(source['files']) == 18, 'source closure differs')
    require(runtime['files'] == {name: source['files'][name]['sha256'] for name in source['runtime_files']}, 'runtime/source pins differ')
    require(runtime['launcher_sha256'] == sha((root / 'cachy-asahi-platform-tools').read_bytes()), 'launcher pin differs')
    found = set()
    with tarfile.open(root / 'private-source.tar.gz', 'r:gz') as archive:
        for member in archive:
            name = member.name.removeprefix('private/')
            require(member.name == 'private/' + name and name in source['files'] and name not in found,
                    'unexpected/duplicate private source')
            row = source['files'][name]
            require(member.isfile() and not member.pax_headers and member.mode == row['mode'] == 0o644
                    and member.size == row['bytes'] and member.uid == member.gid == member.mtime == 0, 'unsafe source member')
            with archive.extractfile(member) as stream:
                require(sha(stream.read(4 * 1024**2)) == row['sha256'], 'source member digest differs')
            found.add(name)
    require(found == set(source['files']), 'whole source closure required')
    mapping = json.loads((root / 'payload-map.json').read_bytes())['files']
    expected = {'usr/lib/cachy-asahi/platform-tools/' + name: {'sha256': row['sha256'], 'mode': row['mode']}
                for name, row in source['files'].items() if name in source['runtime_files']}
    for local, target, mode in direct_files():
        expected[target] = {'sha256': sha((root / local).read_bytes()), 'mode': mode}
    require(mapping == expected, 'payload map differs')
    return {'status': 'PASS-exact-package-sources', 'runtime_sources': 16, 'test_sources': 2,
            'payload_files': len(expected), 'system_mutation': False}


def direct_files():
    return [('cachy-asahi-platform-tools', 'usr/bin/cachy-asahi-platform-tools', 0o755),
            ('runtime-map.json', 'usr/lib/cachy-asahi/platform-tools/runtime-map.json', 0o644),
            *[(name, 'usr/share/doc/cachy-asahi-platform-tools/' + name, 0o644)
              for name in ('README.md', 'source-provenance.json', 'private-platform-transition-prepare.md')],
            *[(name, 'usr/share/licenses/cachy-asahi-platform-tools/' + name, 0o644) for name in ('LICENSE', 'NOTICE')]]


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, required=True)
    print(json.dumps(audit(parser.parse_args().recipe_root), sort_keys=True))
