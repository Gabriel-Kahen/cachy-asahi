#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check fixed recipe sources, private closure and exact installed payload."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile


def sha(raw): return hashlib.sha256(raw).hexdigest()

def check(root, stage=None):
    expected = json.loads((root / 'source-provenance.json').read_bytes())['files']
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress((root / 'private-source.tar.gz').read_bytes())), mode='r:') as archive:
        rows = archive.getmembers()
        assert len(rows) == len(expected) == 11
        assert {node.name for node in rows} == {'private/' + name for name in expected}
        for node in rows:
            name = node.name.removeprefix('private/')
            assert node.isfile() and node.mode == 0o644
            raw = archive.extractfile(node).read()
            assert (sha(raw), len(raw)) == (expected[name]['sha256'], expected[name]['bytes']), name
    if stage is None:
        import re
        info = (root / '.SRCINFO').read_text()
        sources = re.findall(r'^\s+source = (.+)$', info, re.M)
        sums = re.findall(r'^\s+sha256sums = (.+)$', info, re.M)
        assert len(sources) == len(sums) and len(set(sources)) == len(sources)
        for name, pin in zip(sources, sums):
            path = root / name
            assert path.is_file() and not path.is_symlink() and sha(path.read_bytes()) == pin, name
    else:
        mapping = json.loads((root / 'payload-map.json').read_bytes())['files']
        own = 'usr/share/doc/cachy-asahi-source-tools/payload-map.json'
        mapping[own] = dict(sha256=sha((root / 'payload-map.json').read_bytes()), bytes=(root / 'payload-map.json').stat().st_size, mode=0o644)
        files = {}
        for path in stage.rglob('*'):
            info = path.lstat()
            assert not path.is_symlink() and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)), str(path)
            if path.is_file():
                assert info.st_nlink == 1
                files[path.relative_to(stage).as_posix()] = dict(sha256=sha(path.read_bytes()), bytes=info.st_size, mode=stat.S_IMODE(info.st_mode))
        assert files == mapping, (set(files) ^ set(mapping), [key for key in files.keys() & mapping.keys() if files[key] != mapping[key]])
    return dict(status='PASS', private_source_files=len(expected), payload_files=len(mapping) if stage is not None else None)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, required=True)
    parser.add_argument('--stage', type=Path)
    args = parser.parse_args()
    print(json.dumps(check(args.recipe_root, args.stage), sort_keys=True))
