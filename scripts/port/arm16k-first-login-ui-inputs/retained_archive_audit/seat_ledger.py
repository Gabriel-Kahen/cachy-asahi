#!/usr/bin/env python3
"""Project authenticated seat DATA for Root; never issue a consumer manifest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import stat
import time

import audit

HERE = Path(__file__).resolve().parent


class HashedPath:
    """One bounded hash/decode read, retaining the full source identity."""
    def __init__(self, path, expected, limits, budget):
        self.path, self.expected, self.budget = path, expected, budget
        if path.is_symlink() or any(p.is_symlink() for p in path.parents):
            raise ValueError('linked source')
        if expected['bytes'] > limits['archive_object_bytes'] or budget['compressed_allowance'] + expected['bytes'] > limits['compressed_archive_read_allowance']:
            raise ValueError('projection aggregate compressed cap')
        self.count, self.digest = 0, hashlib.sha256()

    def open(self, mode):
        if mode != 'rb': raise ValueError('read only')
        self.source = os.fdopen(os.open(self.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb')
        self.before = os.fstat(self.source.fileno())
        if not stat.S_ISREG(self.before.st_mode) or self.before.st_size != self.expected['bytes']:
            self.source.close(); raise ValueError('projection source size/type')
        return self

    def __enter__(self): return self

    def read(self, size):
        if not 0 <= size <= 65536: raise ValueError('projection bounded read')
        if time.monotonic() >= self.budget['deadline']: raise TimeoutError('projection deadline')
        if self.budget['compressed_allowance'] + size > 536870912: raise ValueError('projection compressed read cap')
        data = self.source.read(size)
        self.count += len(data); self.digest.update(data)
        self.budget['compressed_allowance'] += len(data)
        self.budget['compressed_observed_snapshot_bytes'] += len(data)
        if self.count > self.expected['bytes']: raise ValueError('projection source grew')
        return data

    def __exit__(self, kind, value, trace):
        after = os.fstat(self.source.fileno()); self.source.close()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if kind is None and (identity(after) != identity(self.before) or self.count != self.expected['bytes'] or self.digest.hexdigest() != self.expected['sha256']):
            raise ValueError('projection full hash/source identity')


def build(output):
    started = time.monotonic()
    config = json.loads((HERE/'seat-inputs.json').read_text())
    refs = json.loads((HERE/'ledger-inputs.json').read_text())
    limits = config['limits']
    resource.setrlimit(resource.RLIMIT_AS, (limits['worker_AS'], limits['worker_AS']))
    signal.alarm(850)
    contract = json.loads(audit.checked_bytes(refs['contract']))
    report = json.loads(audit.checked_bytes(refs['report']))
    execution = json.loads(audit.checked_bytes(refs['execution']))
    proposal = json.loads(audit.checked_bytes(config['seat_proposal']))
    if contract['consumer_kind'] != 'ARM16K_VIRTIO_SEAT_ADDITIONS_V1' or execution['exit'] != 0 or not execution['natural_retirement']:
        raise ValueError('contract/execution binding')
    packages = {r['name']: r for r in report['packages']}
    materials = {r['name']: r for r in proposal['materials']}
    if len(packages) != 44 or set(packages) != set(materials): raise ValueError('exact44 identities')
    archives = {}
    for name, row in packages.items():
        if (row['status'] != 'PASS_BYTE_SIGNATURE_METADATA_SCAN' or row['BUILDINFO_status'] != 'PASS_IDENTITY'
            or row['signer_role'] != 'OFFICIAL_PINNED_PRIMARY_MATHEMATICS'
            or any(o['status'] != 'PASS_STATIC_ELF' for o in row['ELF_objects'])):
            raise ValueError('package authentication/geometry hold: '+name)
        audit.signature_status(row['gpgv_call']['exit'], '\n'.join(row['signature']['status_lines']), config['official_primary'])
        source = row['archive']
        archives[name] = {'filename': source['filename'], 'version': row['version'],
            'archive': {k: source[k] for k in ('bytes', 'sha256')},
            'signature': {'bytes': source['signature_bytes'], 'sha256': source['signature_sha256']},
            'expected_signer': config['official_primary'], 'official_repository': True,
            'metadata': row['metadata']['/.PKGINFO']['fields'],
            'source_provenance': {'proposal': config['seat_proposal'], 'audit_report': refs['report'],
                'archive_path': row['bytes_authentication']['path'],
                'signature_path': next(c['signature'] for c in row['candidates'] if c['archive'] == row['bytes_authentication']['path']),
                'catalog_observations': materials[name]['observations'], 'gpgv': row['gpgv_call'],
                'signature_status': row['signature']}}
    modules = audit.modules(config)
    budget = {**report['budget'], 'deadline': started+890-config['carried_elapsed_seconds']-execution['seconds']}
    required = refs['required_addition_paths']; namespace = {}; projections = []
    for name in sorted(set(required.values())):
        paths = {'/'+p for p, owner in required.items() if owner == name}
        row = packages[name]
        source = HashedPath(Path(row['bytes_authentication']['path']), row['archive'], limits, budget)
        scanned, entries = audit.inspect(source, materials[name], modules, limits, budget, paths)
        if scanned['PKGINFO_status'] != 'PASS_EXACT_PLAN' or scanned['BUILDINFO_status'] != 'PASS_IDENTITY' or scanned['metadata']['/.PKGINFO'] != row['metadata']['/.PKGINFO']:
            raise ValueError('projection metadata differs')
        if any(o['status'] != 'PASS_STATIC_ELF' or 'ELF' not in entries[o['path']]['payload'] for o in scanned['ELF_objects'] if o['path'] in paths):
            raise ValueError('required projected ELF geometry absent')
        for path in paths:
            if path not in entries or 'payload' not in entries[path]: raise ValueError('required actual addition path missing')
            namespace[path[1:]] = {'owner': name, 'payload': entries[path]['payload']}
        projections.append({'package': name, 'full_compressed_bytes': source.count, 'sha256': source.digest.hexdigest(),
                            'logical_bytes': scanned['logical_bytes'], 'raw_headers': scanned['raw_headers']})
    policy = audit.checked_bytes(refs['policy'])
    policy_record = namespace['usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy']['payload']
    if policy_record['sha256'] != audit.sha(policy) or policy_record['bytes'] != len(policy): raise ValueError('policy binding differs')
    key = audit.checked_bytes(config['official_binary_keyring'])
    output.mkdir(mode=0o700, exist_ok=False)
    (output/'archlinuxarm.gpg').write_bytes(key)
    (output/'networkmanager-original-policy.data').write_bytes(policy)
    ledger = {'kind': 'ARM16K_VIRTIO_SEAT_AUTHENTICATED_ADDITIONS_LEDGER_V1',
        'status': 'AUTHENTICATED_DATA_FOR_ROOT_REVIEW_ONLY', 'consumer_kind': contract['consumer_kind'],
        'contract': refs['contract'], 'archives': archives,
        'keyring': {'filename': 'archlinuxarm.gpg', 'pin': {k: config['official_binary_keyring'][k] for k in ('bytes','sha256')}},
        'metadata_prepare': proposal['metadata_prepare'], 'required_namespace': namespace,
        'external_fields_not_supplied': ['Root issued_by/status', 'baseline_prepared verification', 'baseline_metadata',
            'baseline_metadata_provenance', 'original_file_pins', 'two baseline Gio/GLib typelib namespace records'],
        'NM_policy': report['NM_policy'], 'projection_reads': projections,
        'budget': {k:v for k,v in budget.items() if k != 'deadline'},
        'projection_seconds': round(time.monotonic()-started,3),
        'aggregate_seconds': round(config['carried_elapsed_seconds']+execution['seconds']+time.monotonic()-started,3),
        'rusage_historical_peak_bytes': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,
        'memory_accounting': 'RLIMIT_AS192MiB enforced before report/archive reads; rusage historical peak may carry pre-exec parent high-water mark',
        'process_memory': {line.split(':')[0]: line.split(':')[1].strip() for line in Path('/proc/self/status').read_text().splitlines()
                           if line.startswith(('VmPeak:', 'VmHWM:', 'VmRSS:', 'VmSize:'))},
        'limits': limits, 'baseline111_payload_read': False, 'network_install_payload_native_actors': False,
        'full_symbol_ABI_runtime_M2': 'HOLD; see unchanged original reports/reconciliations'}
    text = json.dumps(ledger, indent=2, sort_keys=True)+'\n'
    if len(text.encode()) > limits['retained_report_bytes']: raise ValueError('ledger report cap')
    (output/'authenticated-ledger.json').write_text(text)
    print(json.dumps({'status': ledger['status'], 'archives': len(archives), 'namespace_paths':len(namespace), 'budget':ledger['budget'], 'seconds':ledger['aggregate_seconds']}))


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if not args.output.resolve().is_relative_to(Path('/tmp')): parser.error('new private output required below/tmp')
    build(args.output.resolve())
