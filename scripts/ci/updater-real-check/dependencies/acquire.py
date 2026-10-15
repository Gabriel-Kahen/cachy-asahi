#!/usr/bin/env python3
"""Acquire only five pinned public archives/signatures as data; never install."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
lock = json.loads((HERE/'inputs.lock.json').read_text())
assert len(lock['packages']) == 5
assert sum(p['size'] + p['signature_size'] for p in lock['packages']) < 1024**2
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source-root', type=Path, required=True)
parser.add_argument('--cache', type=Path, required=True)
parser.add_argument('--keydir', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
source = args.source_root.resolve(strict=True)
for relative, sha256 in {
    'scripts/port/authenticate.py': '241cd67370eb593bdf948a25788f006ecf470c645ba5d198bc9c318119ebfe10',
    'scripts/port/preview.py': 'd737c51474e05cc2c4db2e87fc021f50328eea7744983dd4076d44751fce7383',
    'scripts/ci/native_arm.py': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898',
}.items():
    assert hashlib.sha256((source/relative).read_bytes()).hexdigest() == sha256, 'tested source helper pin mismatch'
sys.path.insert(0, str(source/'scripts/port'))
import authenticate as auth

cache = args.cache.resolve()
assert not args.cache.is_symlink()
args.output.mkdir(parents=True, exist_ok=True)
cache.mkdir(mode=0o700, exist_ok=True)
assert not cache.is_symlink() and cache.stat().st_uid == os.getuid() and cache.stat().st_mode & 0o077 == 0
keys = args.keydir
for item in lock['keyring_files']:
    src = keys/item['filename']
    assert src.is_file() and src.stat().st_size == item['size'] and auth.native.sha(src) == item['sha256']
    target = cache/item['filename']
    assert not target.is_symlink()
    if target.exists():
        assert target.is_file() and target.read_bytes() == src.read_bytes()
    else:
        target.write_bytes(src.read_bytes())

def fetch(item):
    auth.fetch(item, cache)
    auth.fetch(auth.native.signature_item(item), cache)

with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
    list(pool.map(fetch, lock['packages']))
observations = args.output/'observations'
observations.mkdir(exist_ok=True)
rows = []
with tempfile.TemporaryDirectory(prefix='gpg-', dir=args.output) as tmp:
    gpg = ['/usr/bin/gpg', '--batch', '--no-options', '--homedir', tmp,
           '--no-auto-key-retrieve', '--no-autostart']
    imported = subprocess.run(gpg+['--import',str(cache/'archlinuxarm.gpg')], capture_output=True, text=True, timeout=30)
    assert imported.returncode == 0
    for item in lock['packages']:
        result = subprocess.run(gpg+['--status-fd','1','--verify',str(cache/(item['filename']+'.sig')),
                                    str(cache/item['filename'])], capture_output=True, text=True, timeout=30)
        auth.status(result)
        observed = auth.observe(cache/item['filename'], item)
        auth.native.save(observations/(item['name']+'.json'), observed)
        rows.append({'name':item['name'], 'version':item['version'], 'archive_sha256':item['sha256'],
                     'signature_sha256':item['signature_sha256'], 'size':item['size'],
                     'signature_status':'PASS: pinned official signer, archive/hash/size, PKGINFO',
                     'package_execution':'NOT RUN'})
auth.native.save(args.output/'acquisition.json', {'status':'PASS', 'packages':rows,
    'installation':'NOT RUN', 'public_only_gpg_home_removed':True,
    'signer_fingerprint':lock['signer_fingerprint'],
    'scope':'pinned upstream binary archives read as data; not corresponding-source/license closure'})
print('PASS: five pinned archives/signatures authenticated; package execution NOT RUN')
