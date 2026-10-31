#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One optional setup4 scoped-copy measurement; never a package transaction."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time
import subprocess

SOURCES = {
    'scripts/install/local_transaction.py': '14381d049506b52770059bf7af415f7a079f69872543e74417aca11ce24ac3c5',
    'scripts/update/capacity.py': 'dcb9899cd24daa21f75e6da6b0214393f093d140a70769092da091e0cfdf7c87',
    'scripts/update/full_root.py': 'cece1c597b2e2eb98b0e3087cc7e7c148b54332f8a1c4f18e04e4552a71fb51d',
    'scripts/update/measure_copy.py': 'e582245bd114b0b9d83f2de4fdc81a35d2f48493ba6147879871af794476813b',
    'scripts/update/supervision.py': 'f18bcbd2a6279cff8fe6c7e9c9f80fc01c9818844b01df8c4e97b83d61704b10',
}
LIMITS = {'max_bytes': 8 * 1024**3, 'max_nodes': 500000,
          'max_file_bytes': 1024**3, 'seconds': 900}
EXPECTED = 'dbfe042f77bf61ce8e15a63c53391bcc4f04b94f18e99eeffdfdf85e68aa26ac'
LABEL = 'org.cachy-asahi.purpose=full-composition-footprint'
PUBLIC_LIMIT = 2 * 1024**2


def need(ok, reason):
    if not ok: raise ValueError(reason)


PHASES = ('selection', 'inventory-before', 'mounts', 'source-pins', 'database-before',
          'workspace', 'worker', 'worker-report', 'inventory-after', 'database-after',
          'public-report', 'completed')
ERRORS = {
    'insufficient or unknown filesystem free inode count': 'capacity-inodes',
    'insufficient future transaction bytes/inodes': 'capacity-bytes-or-inodes',
    'copy node limit': 'copy-node-limit', 'copy byte limit': 'copy-byte-limit',
    'copy file byte limit': 'copy-file-limit', 'copy depth limit': 'copy-depth-limit',
    'root observation deadline': 'copy-observation-deadline',
    'unexcluded cross-device source': 'copy-cross-device',
    **{message: 'copy-source-drift' for message in ('source directory drift', 'source file drift',
       'growing copy source', 'changed copy source', 'named copy source drift',
       'source directory content drift', 'source root drift')},
    'actual composition lock differs': 'inventory-drift',
    'package inventory changed during copy': 'inventory-drift',
    'copied package database differs from actual587 lock': 'copied-database-drift',
    'read-only actual package query failed': 'inventory-query',
    'package descriptor bound': 'database-descriptor-limit',
    'escaped mount names require explicit review': 'mount-encoding',
    'fixed footprint selection differs': 'selection', 'exact setup4/updater2 target required': 'selection',
    'measurement checkpoint differs': 'inventory-drift',
    'reviewed disk-backed volume mount required': 'disk-mount',
    'read-only measurement source required': 'source-mount',
    'mounted measurement source differs': 'source-pin',
    'bounded ordinary source database required': 'database-observation',
    'source database baseline unavailable': 'database-baseline-unavailable',
    'source database bytes changed': 'database-drift',
    'source inventory changed or unknown': 'inventory-drift-or-unknown',
    'owned measurement marker required': 'marker',
    'bounded public footprint required': 'report-size', 'scoped footprint result differs': 'report-shape',
}
ERRNOS = {2: 'missing-path', 13: 'permission', 20: 'non-directory', 28: 'disk-full',
          30: 'read-only-filesystem', 40: 'symlink-loop', 122: 'disk-quota'}
ERROR_TYPES = ('ValueError', 'OSError', 'PermissionError', 'FileNotFoundError', 'FileExistsError',
               'NotADirectoryError', 'JSONDecodeError', 'KeyError', 'TypeError', 'IndexError',
               'ImportError', 'RuntimeError', 'TimeoutError', 'UnicodeDecodeError')


def error_category(error):
    """Recognize fixed error text/errno; never return exception or worker text."""
    if isinstance(error, OSError): return ERRNOS.get(error.errno, 'filesystem-error')
    if isinstance(error, bytes):
        lines = error[-8192:].splitlines()
        text = lines[-1].decode('utf-8', errors='replace') if lines else ''
        match = re.fullmatch(r'(?:OSError|PermissionError|FileNotFoundError|NotADirectoryError): \[Errno ([0-9]{1,3})\].*', text)
        if match: return ERRNOS.get(int(match[1]), 'filesystem-error')
        if text.startswith('ValueError: '): text = text[len('ValueError: '):]
    else:
        text = str(error)
        if isinstance(error, json.JSONDecodeError): return 'report-json'
    return ERRORS.get(text, 'unrecognized')


def failure(summary, phase, error, category=None):
    diagnostic = {'phase': phase if phase in PHASES else 'selection',
                  'error_type': type(error).__name__ if type(error).__name__ in ERROR_TYPES else 'other',
                  'error_category': category or error_category(error)}
    if 'error_type' not in summary: summary.update(diagnostic)
    elif len(summary.setdefault('postcheck_failures', [])) < 2:
        summary['postcheck_failures'].append(diagnostic)
    summary['status'] = 'FAIL'


def worker_diagnostic(summary, row):
    code, termination = row.get('returncode'), row.get('termination')
    summary['worker_returncode'] = code if type(code) is int and -128 <= code <= 255 else 'UNKNOWN'
    summary['worker_termination'] = ('none' if termination is None else termination
        if termination in ('timeout', 'output-limit', 'interrupted') else 'UNKNOWN')
    if summary['worker_termination'] in ('timeout', 'output-limit', 'interrupted'):
        return 'worker-' + summary['worker_termination']
    return error_category(row.get('stderr', b''))


def prepare(repository, destination):
    for name, expected in SOURCES.items():
        source = repository / name
        need(source.is_file() and not source.is_symlink() and source.stat().st_size <= 512 * 1024,
             'ordinary bounded measurement source required')
        data = source.read_bytes()
        need(hashlib.sha256(data).hexdigest() == expected, 'adopted measurement source differs')
        target = destination / name; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def docker(*args):
    row = subprocess.run(['docker', *args], stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    need(row.returncode == 0 and len(row.stdout) + len(row.stderr) <= 65536, 'owned volume operation failed')
    return row.stdout


def volume_name(name):
    need(re.fullmatch('cachy-asahi-footprint-[0-9a-f]{32}', name), 'exact owned volume name required')


def volume_present(name):
    volume_name(name)
    names = docker('volume', 'ls', '--filter', 'name=' + name, '--format', '{{.Name}}').decode().splitlines()
    return [value for value in names if value == name]


def inspect_volume(name):
    values = json.loads(docker('volume', 'inspect', name))
    need(len(values) == 1, 'one owned volume required')
    row = values[0]
    need(row['Name'] == name and row['Driver'] == 'local' and row['Scope'] == 'local'
         and not row.get('Options') and row.get('Labels', {}).get(LABEL.split('=')[0]) == LABEL.split('=')[1]
         and row['Labels'].get('org.cachy-asahi.nonce') == name.rsplit('-', 1)[1], 'owned local volume identity differs')


def create_volume(name):
    need(volume_present(name) == [], 'fresh volume required')
    docker('volume', 'create', '--driver', 'local', '--label', LABEL,
           '--label', 'org.cachy-asahi.nonce=' + name.rsplit('-', 1)[1], name)
    inspect_volume(name)


def remove_volume(name):
    present = volume_present(name)
    if present:
        need(present == [name], 'exact volume lookup required'); inspect_volume(name)
        docker('volume', 'rm', name)
    need(volume_present(name) == [], 'owned volume absence unverified')


def database(roots):
    limits = roots.Limits(deadline=time.monotonic() + 30, max_nodes=20000,
                          max_bytes=256 * 1024**2, max_file_bytes=32 * 1024**2)
    row = roots.observe(Path('/var/lib/pacman/local'), limits=limits)
    need(row['complete'] and row['eligible'], 'bounded ordinary source database required')
    data = json.dumps(row['nodes'], sort_keys=True, separators=(',', ':')).encode()
    return {'sha256': hashlib.sha256(data).hexdigest(), 'nodes': row['footprint']['nodes'],
            'bytes': row['footprint']['bytes']}


def collect(plan, expected, source, composition):
    """Record a bounded result; caller still completes setup4 removal/rollback."""
    summary = {'status': 'FAIL', 'whole_root_copy': False, 'transaction_acceptance': 'NOT ESTABLISHED',
               'source_inventory_preserved': 'UNKNOWN', 'source_database_preserved': 'UNKNOWN',
               'phase': 'selection', 'error_category': 'none',
               'worker_returncode': 'NOT_RUN', 'worker_termination': 'NOT_RUN'}
    before, before_db, public = None, None, None
    roots, phase, category = None, 'selection', None
    try:
        need(plan['footprint'] == {'limits': LIMITS, 'sources': SOURCES}, 'fixed footprint selection differs')
        need(plan['setup4']['expected_inventory_sha256'] == EXPECTED
             and expected.get('cachy-asahi-setup') == '0.1.0-4'
             and expected.get('cachy-asahi-update') == '4.4.2-2', 'exact setup4/updater2 target required')
        phase = 'inventory-before'
        before = composition.inventory(); need(before == expected, 'measurement checkpoint differs')
        phase = 'mounts'
        mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
        selected = [row for row in mounts if row[4] == '/measurement']
        need(len(selected) == 1 and selected[0][selected[0].index('-') + 1] in ('ext4', 'xfs', 'btrfs')
             and 'rw' in selected[0][5].split(','), 'reviewed disk-backed volume mount required')
        source_mount = [row for row in mounts if row[4] == '/measurement-source']
        need(len(source_mount) == 1 and 'ro' in source_mount[0][5].split(','), 'read-only measurement source required')
        phase = 'source-pins'
        root = Path('/measurement-source')
        for name, digest in SOURCES.items():
            path = root / name
            need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 512 * 1024
                 and hashlib.sha256(path.read_bytes()).hexdigest() == digest, 'mounted measurement source differs')
        spec = importlib.util.spec_from_file_location('footprint_roots', root / 'scripts/update/full_root.py')
        roots = importlib.util.module_from_spec(spec); sys.modules[spec.name] = roots; spec.loader.exec_module(roots)
        phase = 'database-before'
        before_db = database(roots)
        phase = 'workspace'
        workspace = Path('/measurement/private'); workspace.mkdir(mode=0o700)
        marker = os.environ.get('CACHY_ASAHI_COMPOSITION', '')
        need(re.fullmatch('[0-9a-f]{32}', marker), 'owned measurement marker required')
        supervisor = composition.load('footprint_supervision', root / 'scripts/update/supervision.py')
        command = ['/usr/bin/python3', '-B', str(root / 'scripts/update/measure_copy.py'),
                   '--workspace', str(workspace), '--expected-lock', str(source / 'expected-setup4.lock'),
                   '--expected-lock-sha256', plan['setup4']['expected_inventory_sha256']]
        for key, value in LIMITS.items(): command.extend(['--' + key.replace('_', '-'), str(value)])
        command.extend(['--shape-examples-per-category', '8', '--absolute-chain-paths'])
        phase = 'worker'
        summary.update(worker_returncode='UNKNOWN', worker_termination='UNKNOWN')
        row = supervisor.run(command, env={'PATH': '/usr/bin:/bin', 'HOME': str(workspace), 'TMPDIR': '/tmp',
            'LC_ALL': 'C', 'LANG': 'C', 'CACHY_ASAHI_BOUND_UPDATE': marker}, cwd=str(workspace),
            timeout=960, output_limit=1024**2)
        category = worker_diagnostic(summary, row)
        need(summary['worker_termination'] == 'none' and summary['worker_returncode'] == 0,
             'bounded measurement worker failed')
        category, phase = None, 'worker-report'
        report = json.loads(row['stdout'])
        need(report['status'] == 'MEASURED_SCOPED_COPY' and report['inventory_count'] == 587
             and report['inventory_sha256'] == plan['setup4']['expected_inventory_sha256']
             and report['whole_root_copy'] is False and report['transaction_acceptance'] == 'NOT ESTABLISHED'
             and len(report['unsupported_examples']) <= 64
             and all(set(item) == {'reason', 'path'} and len(item['path']) <= 4096
                     for item in report['unsupported_examples']) and 'nodes' not in report,
             'scoped footprint result differs')
        public = json.dumps(report, sort_keys=True).encode() + b'\n'
        need(len(public) <= PUBLIC_LIMIT, 'bounded public footprint required')
        summary.update(status='MEASURED_SCOPED_COPY', inventory_sha256=report['inventory_sha256'],
                       copy_complete=report['copy_complete'], observation_complete=report['observation_complete'],
                       eligible=report['eligible'], artifact='setup4-footprint.json')
    except Exception as error:
        failure(summary, phase, error, category)
    finally:
        try:
            after = composition.inventory()
            if before is not None: summary['source_inventory_preserved'] = after == before == expected
            need(summary['source_inventory_preserved'] is True, 'source inventory changed or unknown')
        except Exception as error:
            failure(summary, 'inventory-after', error)
        try:
            need(roots is not None and before_db is not None, 'source database baseline unavailable')
            summary['source_database_preserved'] = database(roots) == before_db
            need(summary['source_database_preserved'], 'source database bytes changed')
            summary['source_database'] = before_db
        except Exception as error:
            failure(summary, 'database-after', error)
    if summary['status'] == 'MEASURED_SCOPED_COPY':
        try:
            report['source_database_before_after'] = before_db
            public = json.dumps(report, sort_keys=True).encode() + b'\n'
            need(len(public) <= PUBLIC_LIMIT, 'bounded public footprint required')
            Path('/out/setup4-footprint.json').write_bytes(public)
        except Exception as error: failure(summary, 'public-report', error)
    if summary['status'] == 'MEASURED_SCOPED_COPY': summary['phase'] = 'completed'
    return summary
