#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded exact frozen Arch archive intake. DATA only; never install or execute."""
import argparse, concurrent.futures, hashlib, json, os, re, shutil, subprocess, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
BUDGET = 256 * 1024**2

def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def exact(path, size, digest):
    if not path.is_file() or path.is_symlink() or path.stat().st_size != size or sha(path) != digest:
        raise ValueError('size/SHA256 refusal: ' + path.name)

def descriptor(path):
    value = json.loads(path.read_text())
    assert value['snapshot'] == '2026/11/09' and value['architecture'] == 'x86_64'
    rows = value['official']
    assert len(rows) == 125 and len({r['name'] for r in rows}) == len(rows)
    assert sum(r['bytes'] for r in rows) <= BUDGET
    for row in rows:
        assert row['repo'] in {'core', 'extra'}
        assert re.fullmatch(r'[A-Za-z0-9@+_.:-]+\.pkg\.tar\.(zst|xz)', row['filename'])
        assert '/' not in row['filename'] and '..' not in row['filename']
        assert 0 < row['bytes'] <= 64 * 1024**2
        assert 0 < row['catalog_signature_bytes'] <= 4096
        for key in ['sha256', 'catalog_signature_sha256']:
            assert re.fullmatch('[a-f0-9]{64}', row[key])
    return value

def retrieve(url, target, size, digest, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('overall 600s acquisition deadline')
    partial = target.with_name(target.name + '.partial')
    args = ['curl', '--fail', '--silent', '--show-error', '--location', '--max-redirs', '2',
            '--proto', '=https', '--proto-redir', '=https', '--connect-timeout', '15',
            '--max-time', str(min(90, remaining)), '--max-filesize', str(size),
            '--output', str(partial), '--write-out', '%{url_effective}', url]
    result = subprocess.run(args, capture_output=True, timeout=min(95, remaining + 1))
    try:
        if result.returncode:
            raise RuntimeError('HTTPS refusal ' + str(result.returncode) + ': ' + result.stderr.decode(errors='replace')[:400])
        if not result.stdout.decode().startswith('https://archive.archlinux.org/'):
            raise ValueError('nonofficial redirect refused')
        exact(partial, size, digest)
        partial.rename(target)
    finally:
        partial.unlink(missing_ok=True)
    return {'url': url, 'final_url': result.stdout.decode(), 'bytes': size, 'sha256': digest}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--allow-exact-frozen-downloads', action='store_true')
    parser.add_argument('--descriptor', type=Path, default=HERE / 'closure.json')
    parser.add_argument('--retained-coverage', type=Path, required=True)
    parser.add_argument('--retained-signatures', type=Path, required=True)
    parser.add_argument('--keyring', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert __debug__ and os.geteuid() != 0, 'ordinary user, assertions enabled required'
    contract = descriptor(args.descriptor)
    assert sha(args.keyring) == contract['keyring_sha256'], 'retained public keyring drift'
    coverage = json.loads(args.retained_coverage.read_text())
    retained = {r['filename']: r['retained_matching_paths'][0] for r in coverage['found']}
    assert len(retained) == 17 and len(coverage['missing']) == 108
    missing = {r['filename'] for r in contract['official']} - retained.keys()
    assert missing == {r['filename'] for r in coverage['missing']}
    assert sum(r['bytes'] for r in contract['official'] if r['filename'] in missing) == 126484897
    if missing and not args.allow_exact_frozen_downloads:
        parser.error('explicit exact frozen download opt-in required')
    available = int(dict(l.split(':', 1) for l in Path('/proc/meminfo').read_text().splitlines())['MemAvailable'].split()[0]) * 1024
    assert available >= 1024**3 and shutil.disk_usage(args.output.parent).free >= BUDGET + 2 * 1024**3
    args.output.mkdir(mode=0o700, exist_ok=False)
    packages = args.output / 'packages'; packages.mkdir(mode=0o700)
    home = args.output / 'public-gpg'; home.mkdir(mode=0o700)
    binary_keyring = args.output / 'official-public.gpg'
    subprocess.run(['gpg', '--homedir', str(home), '--batch', '--yes', '--dearmor', '--output', str(binary_keyring), str(args.keyring.resolve())], capture_output=True, check=True, timeout=15)
    deadline = time.monotonic() + 600
    report = {'schema_version': 1, 'status': 'HOLD', 'scope': 'exact frozen public x86 archive DATA intake; no install/build/guest',
              'descriptor_sha256': sha(args.descriptor), 'keyring_sha256': sha(args.keyring), 'dearmored_keyring_sha256': sha(binary_keyring), 'controls': {'workers': 4, 'overall_seconds': 600, 'request_seconds': 90, 'archive_budget': BUDGET, 'MemAvailable': available}, 'records': []}
    def one(row):
        record = dict(row)
        archive = packages / row['filename']; signature = packages / (row['filename'] + '.sig')
        try:
            if row['filename'] in retained:
                source = Path(retained[row['filename']]); exact(source, row['bytes'], row['sha256'])
                shutil.copyfile(source, archive)
                source_sig = args.retained_signatures / signature.name
                exact(source_sig, row['catalog_signature_bytes'], row['catalog_signature_sha256'])
                shutil.copyfile(source_sig, signature)
                record['archive_provenance'] = {'kind': 'retained exact bytes', 'path': str(source)}
                record['signature_provenance'] = {'kind': 'retained frozen database PGPSIG', 'path': str(source_sig)}
            else:
                url = 'https://archive.archlinux.org/repos/2026/11/09/' + row['repo'] + '/os/x86_64/' + row['filename']
                record['archive_provenance'] = retrieve(url, archive, row['bytes'], row['sha256'], deadline)
                record['signature_provenance'] = retrieve(url + '.sig', signature, row['catalog_signature_bytes'], row['catalog_signature_sha256'], deadline)
            result = subprocess.run(['gpgv', '--homedir', str(home), '--keyring', str(binary_keyring.resolve()), '--status-fd', '1', str(signature), str(archive)], capture_output=True, timeout=15)
            status = result.stdout.decode(errors='replace')
            valid = [line.split()[2] for line in status.splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
            record['signature'] = {'exit': result.returncode, 'valid_signers': valid, 'status': status, 'diagnostic': result.stderr.decode(errors='replace')[:2048], 'trust_freshness': 'retained keyring mathematical verification; current trust/revocation freshness NOT established'}
            assert result.returncode == 0 and len(valid) == 1, 'detached signature refusal'
            record['status'] = 'BYTE_AND_SIGNATURE_VERIFIED'
        except Exception as error:
            record['status'] = 'HOLD'; record['failure'] = {'category': type(error).__name__, 'message': str(error)[:1024]}
        return record
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            for record in pool.map(one, contract['official']):
                report['records'].append(record)
                (args.output / 'intake.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
        if all(r['status'] == 'BYTE_AND_SIGNATURE_VERIFIED' for r in report['records']):
            report['status'] = 'BYTE_AND_SIGNATURE_VERIFIED'
    finally:
        (args.output / 'intake.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': report['status'], 'verified': sum(r['status'] != 'HOLD' for r in report['records']), 'total': len(report['records']), 'report': str(args.output / 'intake.json')}))
    return 0 if report['status'] != 'HOLD' else 1
if __name__ == '__main__':
    raise SystemExit(main())
