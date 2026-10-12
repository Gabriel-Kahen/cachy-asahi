#!/usr/bin/env python3
"""Freeze an already resolved ALARM transaction as data; execute no recipes/installers."""
import argparse
import base64
import hashlib
import json
import tarfile
from pathlib import Path


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def fields(text):
    result = {}
    for chunk in text.split('\n\n'):
        lines = chunk.strip().splitlines()
        if lines:
            result[lines[0].strip('%')] = lines[1:]
    return result


def freeze(audit):
    by, databases, malformed = {}, [], []
    for repo in ('core', 'extra', 'alarm', 'aur'):
        path = audit / (repo + '.db')
        databases.append({'name': repo, 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/' + repo + '/' + repo + '.db',
                          'sha256': sha(path), 'size': path.stat().st_size, 'signed': False})
        with tarfile.open(path) as archive:
            rows = {}
            for member in archive:
                if member.name.endswith(('/desc', '/depends')):
                    rows.setdefault(member.name.split('/')[0], {}).update(fields(archive.extractfile(member).read().decode()))
            for name, row in rows.items():
                if 'NAME' not in row:
                    malformed.append(repo + '/' + name)
                    continue
                by[repo, row['NAME'][0]] = row
    packages = []
    for line in (audit / 'transaction.txt').read_text().splitlines():
        repo, name, version, filename, url = line.split()
        data = by[repo, name]
        if data['VERSION'] != [version] or data['FILENAME'] != [filename]:
            raise ValueError('resolved transaction differs from frozen database metadata')
        signature = base64.b64decode(data['PGPSIG'][0], validate=True)
        row = {'name': name, 'version': version, 'arch': data['ARCH'][0], 'filename': filename,
               'url': url, 'sha256': data['SHA256SUM'][0], 'size': int(data['CSIZE'][0]),
               'signature_sha256': hashlib.sha256(signature).hexdigest(), 'signature_size': len(signature)}
        for target, source in [('license', 'LICENSE'), ('source_url', 'URL'), ('depends', 'DEPENDS'),
                               ('provides', 'PROVIDES'), ('conflicts', 'CONFLICTS'), ('replaces', 'REPLACES')]:
            row[target] = data.get(source, [])
        packages.append(row)
    commit = '29432c01130efc4ad297dfe8f487d5b79cbaf8e9'
    keys = [{'filename': name, 'url': 'https://raw.githubusercontent.com/archlinuxarm/PKGBUILDs/' + commit + '/core/archlinuxarm-keyring/' + name,
             'sha256': sha(audit / name), 'size': (audit / name).stat().st_size}
            for name in ('archlinuxarm.gpg', 'archlinuxarm-trusted', 'archlinuxarm-revoked')]
    rootfs = audit / 'ArchLinuxARM-2026.08-aarch64-rootfs.tar.gz'
    return {'schema_version': 1, 'status': 'candidate-inputs', 'snapshot_id': 'alarm-official-mirror-2026-10-11-transaction',
            'source_date_epoch': 1791748800, 'rootfs': {'filename': rootfs.name,
            'url': 'https://ca.us.mirror.archlinuxarm.org/os/multi/' + rootfs.name, 'sha256': sha(rootfs),
            'size': rootfs.stat().st_size, 'signature_sha256': sha(Path(str(rootfs) + '.sig')),
            'signature_size': Path(str(rootfs) + '.sig').stat().st_size}, 'keyring_commit': commit,
            'signer_fingerprint': '68B3537F39A313B3E574D06777193F152BDBE6A6', 'keyring_files': keys,
            'repository_databases': databases, 'malformed_unselected_db_entries': malformed,
            'resolver_transaction': (audit / 'transaction.txt').read_text().splitlines(),
            'rootfs_packages': json.loads((audit / 'rootfs-inventory.json').read_text()),
            'packages': sorted(packages, key=lambda row: row['name']), 'native_build': 'NOT RUN',
            'installation': 'NOT RUN', 'hardware_validation': 'NOT RUN'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('audit', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    with args.output.open('x') as stream:
        json.dump(freeze(args.audit), stream, indent=2, sort_keys=True)
        stream.write('\n')
