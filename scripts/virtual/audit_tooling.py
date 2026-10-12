#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Authenticate a pinned tooling extension as data; never install or execute it."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import urllib.request
from common import digest, json_load, require, save, relative


def fetch(row, cache, download):
    path = cache / relative(row['filename'])
    require(path.parent == cache, 'flat cache filename required')
    if not path.exists():
        require(download and row['url'].startswith('https://'), 'missing input; explicit HTTPS download required')
        temporary = path.with_suffix(path.suffix + '.partial')
        require(not temporary.exists(), 'partial cache input exists')
        try:
            with urllib.request.urlopen(row['url'], timeout=60) as response, temporary.open('xb') as out:
                require(response.url.startswith('https://'), 'insecure redirect')
                size = 0
                while data := response.read(1024 ** 2):
                    size += len(data)
                    require(size <= row['size'], 'input exceeds pinned size')
                    out.write(data)
            temporary.rename(path)
        finally:
            temporary.unlink(missing_ok=True)
    require(not path.is_symlink() and path.is_file() and path.stat().st_size == row['size'] and digest(path) == row['sha256'], 'cache hash/size differs: ' + row['filename'])
    return path


def signature(row):
    return {'filename': row['filename'] + '.sig', 'url': row['url'] + '.sig',
            'size': row['signature_size'], 'sha256': row['signature_sha256']}


def verify(records, fingerprint):
    rows = [line.split()[1:] for line in records.splitlines() if line.startswith('[GNUPG:] ')]
    require(not any(r[0] in ('BADSIG', 'ERRSIG', 'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'KEYREVOKED', 'NO_PUBKEY', 'NODATA', 'FAILURE') for r in rows), 'invalid/revoked/expired signature')
    valid = [r for r in rows if r[0] == 'VALIDSIG']
    require(len(valid) == 1 and len(valid[0]) == 11 and valid[0][1] == fingerprint and valid[0][-1] == fingerprint, 'signature differs from expected primary signer')


def inspect(path, row):
    metadata, hooks, installed, build = {}, {}, [], {}
    with tarfile.open(path, 'r|xz') as archive:
        seen = set()
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            relative(name)
            require(name not in seen, 'duplicate archive member')
            seen.add(name)
            if not name.startswith('.'):
                installed.append(name)
            if name in ('.PKGINFO', '.BUILDINFO', '.INSTALL') or name.startswith(('usr/share/libalpm/hooks/', 'etc/pacman.d/hooks/')) and member.isfile():
                require(member.isfile() and member.size <= 1024 ** 2, 'unsafe package metadata/hook')
                text = archive.extractfile(member).read().decode()
                if name in ('.PKGINFO', '.BUILDINFO'):
                    result = {}
                    for line in text.splitlines():
                        if line and not line.startswith('#'):
                            key, value = line.split(' = ', 1)
                            result.setdefault(key, []).append(value)
                    if name == '.PKGINFO':
                        metadata = result
                    else:
                        build = result
                else:
                    hooks[name] = text
    for key, field in [('pkgname', 'name'), ('pkgver', 'version'), ('arch', 'arch'), ('license', 'license'), ('depend', 'depends'), ('provides', 'provides'), ('conflict', 'conflicts'), ('replaces', 'replaces')]:
        expected = row[field]
        require(sorted(metadata.get(key, [])) == sorted(expected if isinstance(expected, list) else [expected]), 'authenticated archive differs from resolved metadata: ' + key)
    return {'metadata': metadata, 'buildinfo': build, 'hooks': hooks, 'installed_paths': installed, 'archive_sha256': digest(path)}


def validate_lock(lock):
    """Keep historical data audits, and require both modules in the corrected closure."""
    packages = lock['packages']
    names = {row['name'] for row in packages}
    require(lock['schema_version'] == 1 and lock['base_package_count'] == 341 and
            len(packages) in (19, 21) and len(names) == len(packages) and
            lock['expected_package_count'] == 341 + len(packages), 'wrong tooling lock')
    if len(packages) == 21:
        require({'qemu-hw-display-virtio-gpu', 'qemu-hw-display-virtio-gpu-pci'} <= names,
                'both 2D GPU modules required')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--lock', type=Path, required=True)
    ap.add_argument('--lock-sha256', required=True)
    ap.add_argument('--cache', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--download', action='store_true')
    args = ap.parse_args()
    require(digest(args.lock) == args.lock_sha256 and not args.output.exists(), 'reviewed lock/fresh report required')
    args.cache.mkdir(parents=True, exist_ok=True)
    require(not args.cache.is_symlink(), 'symlink cache refused')
    lock = json_load(args.lock)
    validate_lock(lock)
    report = {'status': 'FAILED', 'tooling_lock_sha256': args.lock_sha256, 'packages': {}, 'native_execution': 'NOT RUN', 'hardware_validation': 'NOT RUN'}
    try:
        downloads = lock['keyring_files'] + [i for p in lock['packages'] for i in (p, signature(p))]
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            # Inspect every result; do not silently skip a failed package.
            paths = list(pool.map(lambda row: fetch(row, args.cache, args.download), downloads))
        with tempfile.TemporaryDirectory(prefix='cachy-virtual-key-') as temporary:
            home = Path(temporary)
            home.chmod(0o700)
            subprocess.run(['gpg', '--batch', '--no-autostart', '--homedir', str(home), '--import', str(args.cache / 'archlinuxarm.gpg')], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            for row in lock['packages']:
                result = subprocess.run(['gpg', '--batch', '--no-autostart', '--homedir', str(home), '--status-fd', '1', '--verify', str(args.cache / (row['filename'] + '.sig')), str(args.cache / row['filename'])], text=True, capture_output=True, timeout=30)
                require(result.returncode == 0, 'GPG rejected ' + row['name'])
                verify(result.stdout, lock['signer_fingerprint'])
                report['packages'][row['name']] = inspect(args.cache / row['filename'], row)
                report['packages'][row['name']]['signature_status'] = result.stdout
        report['status'] = 'PASS'
    except Exception as exc:
        report['error'] = str(exc)
        raise
    finally:
        save(args.output, report)


if __name__ == '__main__':
    main()
