#!/usr/bin/env python3
"""Retain bounded JSON build evidence in logs; exclude payloads and key homes."""
import argparse
import base64
import gzip
import hashlib
import json
import os
import re
from pathlib import Path
import sys
import stat

BASE = Path(__file__).resolve().parent
# Bind the bootstrap contract from source bytes before any project import.
import types
_contract_path = BASE / 'contract.py'
_contract_info = _contract_path.lstat()
if not stat.S_ISREG(_contract_info.st_mode) or _contract_info.st_nlink != 1 or _contract_info.st_size > 65536:
    raise ValueError('successor-bootstrap-contract-type')
_contract_fd = os.open(_contract_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
try:
    _contract_raw = os.read(_contract_fd, 65537)
finally:
    os.close(_contract_fd)
if hashlib.sha256(_contract_raw).hexdigest() != 'c84168539130394f9fe51bf440d036f44813ff2b923c1e9d77748f97f755c922':
    raise ValueError('successor-bootstrap-contract-pin')
c = types.ModuleType('contract')
c.__file__ = str(_contract_path)
exec(compile(_contract_raw, str(_contract_path), 'exec'), c.__dict__)


def collect(job, inputs):
    native = job / 'private/producer'
    paths = ['public/status.json', 'private/result.json', 'private/native-worker.json']
    paths += ['private/producer/' + n for n in ('result.json', 'acquisition.json', 'cache-checksums.json', 'bootstrap.json')]
    recipes = c.decode(c.pinned(BASE / 'native/scripts/ci/recipes.lock.json', c.RECIPES))
    for path in recipes:
        name = Path(path).name
        paths += [f'private/producer/{name}-{n}/provenance.json' for n in (1, 2)]
        paths += [f'private/producer/{name}-compare.json']
    records, size = {}, 0
    for name in paths:
        path = job / name
        if not path.exists(): continue
        raw = c.read(path, 4 * 1024**2); c.decode(raw); size += len(raw)
        c.need(size <= 8 * 1024**2, 'successor-metadata-size')
        # Preserve raw-file identity, not arbitrary private fields or error text.
        records[name] = {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}
    public = job / 'public/status.json'
    if public.exists():
        value = c.decode(c.read(public, 65536))
        keys = {'schema_version', 'baseline_id', 'lineage', 'packet_sha256', 'source_commit', 'inputs_sha256',
                'inventory_sha256', 'native_sha256', 'recipes_sha256', 'status', 'native_build', 'phase',
                'first_cause', 'cancelled', 'hardware', 'installation', 'public_admission',
                'source_redistribution', 'legacy_docker_cache_absence', 'owned_image_absence'}
        c.need(set(value) == keys and type(value['schema_version']) is int and value['schema_version'] == 1
               and value['baseline_id'] == c.ID and value['lineage'] == 'SUCCESSOR_NOT_HISTORICAL_ORIGINAL'
               and value['inputs_sha256'] == c.INPUTS and value['inventory_sha256'] == c.INVENTORY
               and value['native_sha256'] == c.NATIVE and value['recipes_sha256'] == c.RECIPES
               and value['hardware'] == value['installation'] == 'NOT RUN' and value['public_admission'] is False
               and value['source_redistribution'] == 'UNRESOLVED' and value['legacy_docker_cache_absence'] == 'NOT CLAIMED', 'successor-metadata-status-binding')
        c.need(value['status'] in ('PASS', 'FAIL') and value['native_build'] == ('PASS' if value['status'] == 'PASS' else 'NOT ACCEPTED')
               and value['phase'] in ('preflight', 'cache', 'native', 'cleanup', 'complete')
               and all(type(value[k]) is bool for k in ('cancelled', 'owned_image_absence'))
               and type(value['source_commit']) is str and re.fullmatch('[0-9a-f]{40}', value['source_commit'])
               and type(value['packet_sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['packet_sha256']), 'successor-metadata-status-type')
        failures = {'successor-preflight-failed', 'successor-cache-failed', 'successor-native-failed', 'successor-cleanup-failed',
                    'successor-cancelled', 'successor-runner-close-failed', 'successor-finalization-failed', 'successor-publication-failed'}
        c.need((value['status'] == 'PASS' and value['first_cause'] is None and not value['cancelled']
                and value['owned_image_absence'] and value['phase'] == 'complete')
               or (value['status'] == 'FAIL' and type(value['first_cause']) is str and value['first_cause'] in failures), 'successor-metadata-admission')
        records['public/status.json']['json'] = value
    signature_path = native / 'signatures.json'
    if signature_path.exists():
        raw = c.read(signature_path, 4 * 1024**2); signatures = c.decode(raw)
        allowed = {p['filename'] for p in [inputs['rootfs'], *inputs['packages']]}
        c.need(set(signatures) <= allowed, 'successor-metadata-signatures')
        safe = {}
        for name, row in signatures.items():
            c.need(type(row) is dict and type(row.get('exit_code')) is int and -128 <= row['exit_code'] <= 255
                   and type(row.get('status')) is str and len(row['status']) <= 65536, 'successor-metadata-signature-type')
            valid = [line.split() for line in row['status'].splitlines() if line.startswith('[GNUPG:] VALIDSIG ')]
            for words in valid:
                c.need(len(words) == 12 and words[2] == words[-1] == inputs['signer_fingerprint']
                       and all(re.fullmatch('[A-Za-z0-9:._-]{1,128}', word) for word in words[2:]), 'successor-metadata-signature-status')
            c.need(len(valid) <= 1, 'successor-metadata-signature-count')
            safe[name] = {'exit_code': row['exit_code'], 'validsig': [' '.join(words) for words in valid]}
        records['private/producer/signatures-sanitized.json'] = {'raw_sha256': hashlib.sha256(raw).hexdigest(), 'json': safe}
    raw = json.dumps({'schema_version': 1, 'baseline_id': c.ID,
                      'payloads_and_key_homes': 'EXCLUDED', 'records': records}, sort_keys=True, allow_nan=False).encode()
    c.need(len(raw) <= 8 * 1024**2, 'successor-metadata-size')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packet-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    inputs, _ = c.verify(BASE, args.packet_sha256)
    raw = collect(args.output.absolute(), inputs)
    encoded = base64.b64encode(gzip.compress(raw, mtime=0)).decode()
    print('MAINTAINED_NATIVE_METADATA_GZIP_BASE64_SHA256=' + hashlib.sha256(raw).hexdigest())
    for offset in range(0, len(encoded), 4096): print('MAINTAINED_NATIVE_METADATA=' + encoded[offset:offset+4096])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
