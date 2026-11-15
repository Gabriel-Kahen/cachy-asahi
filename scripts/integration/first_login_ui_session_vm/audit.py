#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recheck frozen archives/public signatures and read package metadata as DATA."""
import argparse, hashlib, json, os, subprocess, tarfile
from pathlib import Path
from intake import descriptor, exact, sha

def metadata(path):
    result = {}
    with tarfile.open(path, 'r:*') as archive:
        for index, member in enumerate(archive):
            if index > 32:
                raise ValueError('bounded package metadata prefix exceeded')
            if member.name in {'.PKGINFO', '.BUILDINFO'}:
                assert member.isfile() and member.size <= 128 * 1024, 'metadata member shape'
                data = archive.extractfile(member).read(128 * 1024 + 1)
                assert len(data) == member.size
                fields = {}
                for line in data.decode().splitlines():
                    if line.startswith('#') or not line.strip():
                        continue
                    key, value = line.split(' = ', 1)
                    fields.setdefault(key, []).append(value)
                result[member.name] = {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'fields': fields}
            if set(result) == {'.PKGINFO', '.BUILDINFO'}:
                break
    assert set(result) == {'.PKGINFO', '.BUILDINFO'}, 'required real archive metadata absent'
    return result

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--descriptor', type=Path, default=Path(__file__).with_name('closure.json'))
    p.add_argument('--intake', type=Path, required=True)
    p.add_argument('--catalogs', type=Path, required=True)
    p.add_argument('--keyring', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    assert __debug__ and os.geteuid() != 0
    contract = descriptor(a.descriptor); assert sha(a.keyring) == contract['keyring_sha256']
    catalogs = {}
    for repo, pin in contract['catalogs'].items():
        db = a.catalogs / (repo + '.db'); assert sha(db) == pin
        with tarfile.open(db, 'r:*') as archive:
            for member in archive:
                if member.name.endswith('/desc'):
                    assert member.isfile() and member.size <= 128 * 1024
                    fields = {v.splitlines()[0]: v.splitlines()[1:] for v in archive.extractfile(member).read().decode().strip().split('\n\n')}
                    catalogs[fields['%NAME%'][0]] = fields
    a.output.mkdir(mode=0o700, exist_ok=False)
    home = a.output / 'public-gpg'; home.mkdir(mode=0o700)
    binary = a.output / 'official-public.gpg'
    subprocess.run(['gpg', '--homedir', str(home), '--batch', '--dearmor', '--output', str(binary), str(a.keyring.resolve())], capture_output=True, check=True, timeout=15)
    report = {'schema_version': 1, 'status': 'HOLD', 'input_intake_sha256': sha(a.intake / 'intake.json'),
              'descriptor_sha256': sha(a.descriptor), 'original_public_keyring_sha256': sha(a.keyring), 'dearmored_public_keyring_sha256': sha(binary),
              'scope': 'exact signed x86 package DATA only; no payload/source execution, installation, guest or hardware credit',
              'holds': ['retained keyring does not establish current trust/revocation freshness', 'PKGINFO license/URL and BUILDINFO recipe hash are declarations; corresponding source/notice/license acceptance NOT established', 'x86 reference inputs do not qualify ARM/M2/release'], 'records': []}
    for row in contract['official']:
        record = dict(row); report['records'].append(record)
        try:
            path = a.intake / 'packages' / row['filename']; signature = path.with_name(path.name + '.sig')
            exact(path, row['bytes'], row['sha256']); exact(signature, row['catalog_signature_bytes'], row['catalog_signature_sha256'])
            cat = catalogs[row['name']]
            assert cat['%VERSION%'] == [row['version']] and cat['%FILENAME%'] == [row['filename']] and cat['%SHA256SUM%'] == [row['sha256']] and cat['%CSIZE%'] == [str(row['bytes'])]
            r = subprocess.run(['gpgv', '--homedir', str(home), '--keyring', str(binary.resolve()), '--status-fd', '1', str(signature), str(path)], capture_output=True, timeout=15)
            status = r.stdout.decode(); signers = [line.split()[2] for line in status.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
            record['signature'] = {'exit': r.returncode, 'signers': signers, 'status': status, 'diagnostic': r.stderr.decode(errors='replace')[:2048]}
            assert r.returncode == 0 and len(signers) == 1, 'real detached signature refusal'
            record['metadata'] = metadata(path)
            pkg = record['metadata']['.PKGINFO']['fields']
            assert pkg['pkgname'] == [row['name']] and pkg['pkgver'] == [row['version']] and pkg['arch'] in [['x86_64'], ['any']], 'PKGINFO identity refusal'
            assert sorted(pkg.get('depend', [])) == sorted(cat.get('%DEPENDS%', [])), 'catalog/PKGINFO dependency mismatch'
            assert sorted(pkg.get('license', [])) == sorted(cat.get('%LICENSE%', [])), 'catalog/PKGINFO license mismatch'
            record['installed_bytes'] = int(cat['%ISIZE%'][0]); record['source_authority'] = 'UNBOUND to complete retained source/notice materials; declared URL/license and recipe digest retained as DATA'
            record['status'] = 'BYTE_SIGNATURE_METADATA_VERIFIED'
        except Exception as e:
            record.update(status='HOLD', failure={'category': type(e).__name__, 'message': str(e)[:1024]})
        (a.output / 'audit.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    report['verified'] = sum(r['status'] == 'BYTE_SIGNATURE_METADATA_VERIFIED' for r in report['records'])
    report['archive_bytes'] = sum(r['bytes'] for r in report['records'])
    report['installed_bytes'] = sum(r.get('installed_bytes', 0) for r in report['records'])
    if report['verified'] == 125:
        report['status'] = 'BYTE_SIGNATURE_METADATA_VERIFIED_WITH_SOURCE_FRESHNESS_NATIVE_HOLDS'
    (a.output / 'audit.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: report[k] for k in ['status', 'verified', 'archive_bytes', 'installed_bytes']}))
    return 0 if report['verified'] == 125 else 1
if __name__ == '__main__':
    raise SystemExit(main())
