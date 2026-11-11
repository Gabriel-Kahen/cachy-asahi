#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Finite producer receipt gates and data-only public export; no commands run."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[3]
INPUTS_SHA = '3c16c37d1b12cc84a88572e82ab8ad59e7f3b5ed0d08f09ddf72a69f4711d650'
RECIPES_SHA = '20d846cdf289bfc233b0051bf33b677fd6e94e9f05d91a33595a2829a196fa63'
INVENTORY_SHA = '89bdb06fea1862b5a6e02b77a4b98f6e04755b02327d875a716bd792929f3a4f'
NATIVE_SCRIPT_SHA = 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898'
EPOCH = 1791748800
NAMES = {'cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
         'cachy-asahi-zsh-config', 'cachy-asahi-setup'}
PIN = re.compile(r'[0-9a-f]{64}\Z')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}\Z')
MAX_FILE = 64 * 1024 ** 2
PUBLIC_FILES = {'producer-summary.json', 'acquisition.json', 'signatures.json',
                'inputs.lock.json', 'recipes.lock.json', 'export-manifest.json'}

PRODUCER_PHASES = {'preflight', 'base-probe', 'host-probe', 'acquisition', 'gpg-import',
                   'gpg-verify', 'bootstrap', 'original-build', 'original-compare', 'complete'}
PRODUCER_OUTCOMES = {'not-run', 'started', 'pass', 'command-failed', 'delegate-refused', 'runner-failed', 'cancelled'}
PRODUCER_FAILURE_CODES = ({'producer-before-' + phase + '-failed' for phase in PRODUCER_PHASES} |
                          {'producer-during-' + phase + '-failed' for phase in PRODUCER_PHASES} |
                          {'producer-after-' + phase + '-failed' for phase in PRODUCER_PHASES} |
                          {'producer-' + phase + '-' + outcome for phase in PRODUCER_PHASES
                           for outcome in ('command-failed', 'delegate-refused', 'runner-failed', 'cancelled')})

BASE_PROBE_CALLS = {'docker-info', 'docker-version', 'docker-context', 'image-inspect',
                    'inventory-probe', 'unclassified'}
# Literal predicate labels from the reviewed broker/runtime sources; never raw error text.
BASE_PROBE_POLICY_CODES = {
    'base-build-already-reserved', 'base-build-command', 'base-build-unknown-image',
    'base-cleanup-cancellation-uncertain', 'base-cleanup-deadline', 'base-container-cleanup',
    'base-container-image-missing', 'base-container-journal-binding',
    'base-container-journal-count', 'base-container-journal-path', 'base-context-count',
    'base-context-deadline', 'base-context-directory', 'base-context-drift', 'base-context-file',
    'base-context-path', 'base-context-required', 'base-context-size', 'base-context-symlink',
    'base-docker-version', 'base-expected-daemon', 'base-image-absence-uncertain',
    'base-image-context-binding', 'base-image-journal-binding', 'base-image-journal-size',
    'base-image-reservation', 'base-job-path', 'base-job-root', 'base-legacy-builder-env',
    'base-lock-probe-command', 'base-lock-probe-inventory', 'base-new-iidfile',
    'base-owned-image-absence', 'base-owned-image-binding', 'base-owned-image-inspect',
    'base-owned-image-list', 'base-owned-image-remove', 'command-timeout', 'deadline-exhausted',
    'docker-binary-drift', 'docker-binary-path', 'docker-binary-pin', 'docker-build-command',
    'docker-build-env', 'docker-build-mounts', 'docker-build-options', 'docker-build-policy',
    'docker-build-timeout', 'docker-capture-command', 'docker-cleanup-failed', 'docker-config',
    'docker-container-command', 'docker-container-mounts', 'docker-container-ownership',
    'docker-container-resources', 'docker-create-absence-uncertain', 'docker-create-unknown',
    'docker-daemon-chunk-framing', 'docker-daemon-connect', 'docker-daemon-drift',
    'docker-daemon-http-framing', 'docker-daemon-http-invalid', 'docker-daemon-http-status',
    'docker-daemon-http-trailing', 'docker-daemon-http-truncated', 'docker-daemon-output-bound',
    'docker-daemon-send', 'docker-daemon-timeout', 'docker-duplicate-json-key', 'docker-endpoint',
    'docker-environment', 'docker-expected-daemon', 'docker-home', 'docker-image-binding',
    'docker-image-drift', 'docker-image-pin', 'docker-image-query', 'docker-image-volumes',
    'docker-input-size', 'docker-journal-binding', 'docker-journal-container',
    'docker-journal-path', 'docker-journal-size', 'docker-local-pin-drift', 'docker-mount-path',
    'docker-name-reservation', 'docker-native-daemon', 'docker-nonce', 'docker-ordinary-user',
    'docker-owned-absence', 'docker-owned-inspect', 'docker-owned-list', 'docker-owned-remove',
    'docker-probe-failed', 'docker-probe-identity-inventory', 'docker-regular-input',
    'docker-reserved-name-exists', 'docker-socket', 'docker-uninitialized', 'invalid-argv',
    'invalid-environment', 'invalid-output-bound', 'invalid-time-bound', 'output-bound',
    'process-cleanup', 'threaded-runner', 'unsafe-log-directory', 'unsafe-log-path'
}
BASE_PROBE_ERROR_TYPES = {'os-error', 'unicode-error', 'key-error', 'type-error', 'value-error',
                          'subprocess-error', 'unknown-error', 'cancelled'}
BASE_PROBE_REFUSALS = BASE_PROBE_POLICY_CODES | BASE_PROBE_ERROR_TYPES
BASE_PROBE_FAILURE_CODES = (
    {'producer-' + point + '-base-probe-' + call + '-failed' for call in BASE_PROBE_CALLS
     for point in ('before', 'during', 'after')} |
    {'producer-base-probe-' + call + '-' + failure for call in BASE_PROBE_CALLS
     for failure in BASE_PROBE_REFUSALS | {'command-failed', 'delegate-refused', 'runner-failed', 'cancelled'}})
PRODUCER_FAILURE_CODES |= BASE_PROBE_FAILURE_CODES

WORKER_BOUNDARY_FIELDS = {'schema_version', 'last_recipe', 'last_command', 'last_command_zero',
    'comparisons_completed', 'native_delegate_zero', 'worker_status', 'worker_cancelled',
    'worker_cleanup_status', 'worker_cleanup_absence', 'worker_cleanup_cancelled'}
OUTER_BOUNDARY_FIELDS = {'worker_return_zero', 'outer_gate', 'outer_outcome', 'outer_reason'}
OUTER_BOUNDARY_GATES = {'UNOBSERVED', 'worker-exit', 'worker-receipt', 'worker-status', 'worker-cancelled',
    'worker-cleanup-status', 'worker-cleanup-absence', 'producer-receipts', 'original-result-retention', 'accepted'}
OUTER_BOUNDARY_REASONS = BASE_PROBE_ERROR_TYPES | {
    'boundary-invalid', 'worker-exit-nonzero', 'worker-return-invalid', 'worker-receipt-invalid', 'worker-status-not-pass',
    'worker-cancelled', 'worker-cleanup-not-pass', 'worker-cleanup-absence-unverified',
    'producer-acquisition-counts', 'producer-acquisition-incomplete', 'producer-acquisition-row',
    'producer-acquisition-set', 'producer-bootstrap', 'producer-bootstrap-schema', 'producer-build-binding',
    'producer-build-container', 'producer-build-file-pin', 'producer-build-files', 'producer-build-inventory',
    'producer-build-schema', 'producer-cache-checksums', 'producer-comparison-schema', 'producer-file',
    'producer-identity', 'producer-input-count', 'producer-input-name', 'producer-inventory', 'producer-json',
    'producer-original-artifact', 'producer-original-artifact-set', 'producer-original-comparison',
    'producer-original-independence', 'producer-original-package-metadata', 'producer-original-source-metadata',
    'producer-original-validation', 'producer-package-audit-set', 'producer-package-metadata', 'producer-path',
    'producer-pin', 'producer-race', 'producer-recipe-review', 'producer-recipe-snapshot', 'producer-recipes',
    'producer-relative-path', 'producer-result', 'producer-result-schema', 'producer-rootfs-inventory',
    'producer-signature-exit', 'producer-signature-fingerprint', 'producer-signature-invalid',
    'producer-signature-set', 'producer-signature-status', 'producer-validation-schema'}
BOUNDARY_REASON_GATES = {
    'worker-exit-nonzero': {'worker-exit'}, 'worker-return-invalid': {'worker-exit'},
    'worker-receipt-invalid': {'worker-receipt'}, 'boundary-invalid': {'worker-receipt','original-result-retention'},
    'worker-status-not-pass': {'worker-status'}, 'worker-cancelled': {'worker-cancelled'},
    'worker-cleanup-not-pass': {'worker-cleanup-status'},
    'worker-cleanup-absence-unverified': {'worker-cleanup-absence'}}


def new_boundary(worker=False):
    value = {key: 'UNOBSERVED' for key in WORKER_BOUNDARY_FIELDS}
    value.update(schema_version=1, comparisons_completed=0)
    if not worker:
        value.update(worker_return_zero='UNOBSERVED', outer_gate='UNOBSERVED',
                     outer_outcome='UNOBSERVED', outer_reason='none')
    return value


def producer_boundary(value, worker=False):
    """Only fixed enums, bounded counts and observed booleans cross this boundary."""
    fields = WORKER_BOUNDARY_FIELDS | (set() if worker else OUTER_BOUNDARY_FIELDS)
    if type(value) is not dict or set(value) != fields:
        return None
    if not (type(value['schema_version']) is int and value['schema_version'] == 1 and
            type(value['comparisons_completed']) is int and 0 <= value['comparisons_completed'] <= 4):
        return None
    enums = {'last_recipe': NAMES | {'UNOBSERVED'}, 'last_command': {'UNOBSERVED','build-1','build-2','compare'},
             'worker_status': {'UNOBSERVED','PASS','FAIL'}, 'worker_cleanup_status': {'UNOBSERVED','PASS','FAIL'}}
    if any(type(value[key]) is not str or value[key] not in choices for key, choices in enums.items()):
        return None
    booleans = {'last_command_zero','native_delegate_zero','worker_cancelled',
                'worker_cleanup_absence','worker_cleanup_cancelled'} | (set() if worker else {'worker_return_zero'})
    if any(type(value[key]) is not bool and not (type(value[key]) is str and value[key] == 'UNOBSERVED')
           for key in booleans):
        return None
    if (value['last_recipe'] == 'UNOBSERVED') != (value['last_command'] == 'UNOBSERVED') or (
            value['last_command'] == 'UNOBSERVED' and value['last_command_zero'] != 'UNOBSERVED'):
        return None
    if not worker:
        gate, outcome, reason = value['outer_gate'], value['outer_outcome'], value['outer_reason']
        if not (type(gate) is type(outcome) is type(reason) is str and gate in OUTER_BOUNDARY_GATES and
                outcome in {'UNOBSERVED','STARTED','PASS','FAIL'} and reason in OUTER_BOUNDARY_REASONS | {'none'}):
            return None
        if (gate == 'UNOBSERVED') != (outcome == 'UNOBSERVED') or (outcome == 'FAIL') != (reason != 'none'):
            return None
        allowed_gates = BOUNDARY_REASON_GATES.get(reason)
        if allowed_gates is not None and gate not in allowed_gates or (
                reason.startswith('producer-') and gate != 'producer-receipts'):
            return None
        observed_failures = {'worker-exit-nonzero': ('worker_return_zero', False),
                             'worker-return-invalid': ('worker_return_zero', 'UNOBSERVED')}
        if reason in observed_failures:
            key, expected = observed_failures[reason]
            if type(value[key]) is not type(expected) or value[key] != expected: return None
        if any(reason == code and value[key] == contradicted for code,key,contradicted in (
                ('worker-status-not-pass','worker_status','PASS'), ('worker-cancelled','worker_cancelled',False),
                ('worker-cleanup-not-pass','worker_cleanup_status','PASS'),
                ('worker-cleanup-absence-unverified','worker_cleanup_absence',True))):
            return None
        if gate == 'worker-exit' and outcome == 'PASS' and value['worker_return_zero'] is not True:
            return None
        passed = {'worker-status': ('worker_status','PASS'), 'worker-cancelled': ('worker_cancelled',False),
                  'worker-cleanup-status': ('worker_cleanup_status','PASS'),
                  'worker-cleanup-absence': ('worker_cleanup_absence',True)}
        if outcome == 'PASS' and gate in passed:
            key, expected = passed[gate]
            if value[key] != 'UNOBSERVED' and (type(value[key]) is not type(expected) or value[key] != expected):
                return None
        if gate == 'accepted' and not (outcome == 'PASS' and value['worker_return_zero'] is True and
                value['native_delegate_zero'] is True and value['worker_status'] == 'PASS' and
                value['worker_cancelled'] is False and value['worker_cleanup_status'] == 'PASS' and
                value['worker_cleanup_absence'] is True and value['worker_cleanup_cancelled'] is not True and
                value['comparisons_completed'] == 4 and value['last_command'] == 'compare' and
                value['last_command_zero'] is True):
            return None
    return dict(value)


def boundary_reason(error):
    if isinstance(error, ValueError) and error.args and type(error.args[0]) is str and error.args[0] in OUTER_BOUNDARY_REASONS:
        return error.args[0]
    if type(error).__name__ in ('Cancelled', 'KeyboardInterrupt'):
        return 'cancelled'
    for kind, code in ((UnicodeError,'unicode-error'), (OSError,'os-error'), (KeyError,'key-error'),
                       (TypeError,'type-error'), (ValueError,'value-error'), (subprocess.SubprocessError,'subprocess-error')):
        if isinstance(error, kind): return code
    return 'unknown-error'


def producer_diagnostic(value):
    if not (type(value) is dict and set(value) in ({'phase', 'outcome'}, {'phase', 'outcome', 'call', 'refusal_code'}) and
            type(value['phase']) is str and value['phase'] in PRODUCER_PHASES and
            type(value['outcome']) is str and value['outcome'] in PRODUCER_OUTCOMES):
        return None
    if 'call' in value:
        if not (value['phase'] == 'base-probe' and type(value['call']) is str and value['call'] in BASE_PROBE_CALLS and
                type(value['refusal_code']) is str and value['refusal_code'] in BASE_PROBE_REFUSALS | {'none'} and
                (value['outcome'] not in ('not-run', 'started', 'pass') or value['refusal_code'] == 'none')):
            return None
    return dict(value)


def producer_failure_code(report):
    diagnostic = producer_diagnostic(report.get('producer_diagnostic'))
    if report.get('work_phase') != 'producer' or diagnostic is None:
        return 'fdk-native-job-failed'
    phase, outcome = diagnostic['phase'], diagnostic['outcome']
    call = diagnostic.get('call')
    if call is not None:
        refusal = diagnostic['refusal_code']
        if outcome in ('not-run', 'started', 'pass'):
            point = {'not-run': 'before', 'started': 'during', 'pass': 'after'}[outcome]
            return 'producer-' + point + '-base-probe-' + call + '-failed'
        return 'producer-base-probe-' + call + '-' + (refusal if refusal != 'none' else outcome)
    if outcome in ('not-run', 'started', 'pass'):
        point = {'not-run': 'before', 'started': 'during', 'pass': 'after'}[outcome]
        return 'producer-' + point + '-' + phase + '-failed'
    return 'producer-' + phase + '-' + outcome


def need(ok, code):
    if not ok:
        raise ValueError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, limit=MAX_FILE):
    path = Path(path).absolute()
    need('..' not in path.parts and all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents), 'producer-path')
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit, 'producer-file')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino), 'producer-race')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        need(len(data) <= limit and (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) ==
             (after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'producer-race')
        need((path.lstat().st_dev, path.lstat().st_ino) == (opened.st_dev, opened.st_ino), 'producer-race')
        return data
    finally:
        os.close(fd)


def decode(data):
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'producer-json')
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique,
                      parse_constant=lambda _: need(False, 'producer-json'))


def load(path, pin=None, limit=MAX_FILE):
    data = read(path, limit)
    if pin is not None:
        need(PIN.fullmatch(pin or '') and sha(data) == pin, 'producer-pin')
    return decode(data)


def relative(name):
    need(type(name) is str and name and '\\' not in name and all(32 <= ord(c) < 127 for c in name), 'producer-relative-path')
    need(not name.startswith('/') and all(p not in ('', '.', '..') for p in name.split('/')), 'producer-relative-path')
    return Path(name)


def source_inputs(directory):
    return load(Path(directory) / 'inputs.lock.json', INPUTS_SHA, 1024 ** 2)


def input_items(inputs):
    result = {}
    for item in inputs['keyring_files'] + [inputs['rootfs']] + inputs['packages']:
        filename = item['filename']
        need(re.fullmatch(r'[A-Za-z0-9._+@:~-]{1,255}', filename) and filename not in result, 'producer-input-name')
        result[filename] = {'expected_sha256': item['sha256'], 'expected_bytes': item['size']}
        if 'signature_sha256' in item:
            result[filename + '.sig'] = {'expected_sha256': item['signature_sha256'], 'expected_bytes': item['signature_size']}
    need(len(result) == 501, 'producer-input-count')
    return result


def acquisition(directory, inputs, require_pass=False):
    record = load(Path(directory) / 'acquisition.json', limit=1024 ** 2)
    expected = input_items(inputs)
    need(type(record) is dict and type(record.get('schema_version')) is int and record['schema_version'] == 1 and
         type(record.get('inputs')) is dict and set(record['inputs']) == set(expected), 'producer-acquisition-set')
    rows, counts = {}, {'total': 501, 'pass': 0, 'fail': 0, 'pending': 0}
    for name, pins in sorted(expected.items()):
        row = record['inputs'][name]
        need(type(row) is dict and all(row.get(k) == v for k, v in pins.items()) and type(row.get('expected_bytes')) is int and
             row.get('status') in ('PASS', 'FAIL', 'PENDING'), 'producer-acquisition-row')
        status = row['status']
        counts[status.lower()] += 1
        rows[name] = {**pins, 'status': status}
        if status == 'FAIL':
            code = row.get('http_status')
            if type(code) is int and 100 <= code <= 599:
                rows[name]['http_status'] = code
                rows[name]['error_code'] = 'http-failure'
            else:
                rows[name]['error_code'] = 'input-acquisition-failed'
    state = 'IN_PROGRESS' if counts['pending'] else 'FAIL' if counts['fail'] else 'PASS'
    need(type(record.get('counts')) is dict and all(type(v) is int for v in record['counts'].values()) and
         record['counts'] == counts and record.get('acquisition') == state and
         record.get('signature_authentication') == 'NOT RUN', 'producer-acquisition-counts')
    if require_pass:
        need(state == 'PASS', 'producer-acquisition-incomplete')
    return {'schema_version': 1, 'acquisition': state, 'signature_authentication': 'NOT RUN',
            'counts': counts, 'inputs': rows}


def valid_signature(text, signer):
    need(type(text) is str and len(text.encode()) <= 65536, 'producer-signature-status')
    rows = [line.split()[1:] for line in text.splitlines() if line.startswith('[GNUPG:] ')]
    need(all(row and row[0] not in ('EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY') for row in rows), 'producer-signature-invalid')
    valid = [row for row in rows if row[0] == 'VALIDSIG']
    need(len(valid) == 1 and len(valid[0]) == 11 and valid[0][1] == signer and valid[0][-1] == signer,
         'producer-signature-fingerprint')


def signatures(directory, inputs):
    raw = load(Path(directory) / 'signatures.json', limit=16 * 1024 ** 2)
    expected = {row['filename'] for row in [inputs['rootfs']] + inputs['packages']}
    need(type(raw) is dict and set(raw) == expected and len(expected) == 249, 'producer-signature-set')
    result = {}
    for name in sorted(expected):
        row = raw[name]
        need(type(row) is dict and type(row.get('exit_code')) is int and row['exit_code'] == 0, 'producer-signature-exit')
        valid_signature(row.get('status'), inputs['signer_fingerprint'])
        result[name] = {'status': 'PASS', 'primary_fingerprint': inputs['signer_fingerprint']}
    return {'status': 'PASS', 'verified_payloads': 249, 'inputs': result}


def original_build(directory, name, reviewed, image):
    record = load(directory / 'provenance.json', limit=4 * 1024 ** 2)
    need(type(record) is dict, 'producer-build-schema')
    need(record.get('status') == 'built-package-static-pass' and record.get('mode') == 'native' and
         record.get('network') == 'none' and record.get('image') == record.get('image_id') == image and
         type(record.get('source_date_epoch')) is int and record['source_date_epoch'] == EPOCH and record.get('recipe_inputs') == reviewed and
         record.get('expected_packages_sha256') == INVENTORY_SHA and
         type(record.get('exit_code')) is int and record['exit_code'] == 0 and
         record.get('builder_host_arch') in ('aarch64', 'arm64'), 'producer-build-binding')
    container = record.get('clean_environment_id', '')
    need(re.fullmatch(r'cachy-asahi-[0-9a-f]{16}', container), 'producer-build-container')
    files = record.get('files', {})
    required = {'build.log', 'validation.json', 'expected-packages.lock', 'artifacts/packages.lock',
                'artifacts/generated.SRCINFO', 'artifacts/environment.txt', 'artifacts/config.sha256',
                'artifacts/makepkg.conf', 'artifacts/pacman.conf'}
    need(type(files) is dict and required <= set(files) and len(files) <= 2048, 'producer-build-files')
    for path, pin in files.items():
        need(PIN.fullmatch(pin or '') and sha(read(directory / relative(path))) == pin, 'producer-build-file-pin')
    for path, pin in reviewed.items():
        need(PIN.fullmatch(pin or '') and sha(read(directory / 'inputs' / relative(path))) == pin, 'producer-recipe-snapshot')
    artifacts = record.get('artifacts', {})
    need(type(artifacts) is dict and len(artifacts) == 1, 'producer-original-artifact-set')
    filename, pin = next(iter(artifacts.items()))
    need(re.fullmatch(re.escape(name) + r'-[A-Za-z0-9.+_:~-]+-any\.pkg\.tar\.xz', filename) and
         PIN.fullmatch(pin or '') and sha(read(directory / 'artifacts' / filename)) == pin,
         'producer-original-artifact')
    need({p.name for p in (directory / 'artifacts').glob('*.pkg.tar.*')} == {filename}, 'producer-original-artifact-set')
    need(sha(read(directory / 'expected-packages.lock')) == sha(read(directory / 'artifacts/packages.lock')) == INVENTORY_SHA,
         'producer-build-inventory')
    validation = load(directory / 'validation.json')
    need(type(validation) is dict, 'producer-validation-schema')
    need(validation.get('errors') == [] and len(validation.get('artifacts', [])) == 1, 'producer-original-validation')
    artifact = validation['artifacts'][0]
    need(artifact.get('artifact') == filename and artifact.get('sha256') == pin and
         artifact.get('errors') == [] and artifact.get('status') == 'artifact-static-pass' and
         artifact['metadata']['.BUILDINFO'].get('pkgbuild_sha256sum') == [reviewed['PKGBUILD']] and
         artifact['metadata']['.PKGINFO'].get('pkgname') == [name], 'producer-original-validation')
    metadata = {}
    for line in read(directory / 'inputs' / '.SRCINFO', 65536).decode().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*([A-Za-z0-9_]+) = (.*)', line)
        need(match is not None, 'producer-original-source-metadata')
        metadata.setdefault(match[1], []).append(match[2])
    need(record.get('recipe_metadata') == metadata, 'producer-original-source-metadata')
    version = metadata['pkgver'][0] + '-' + metadata['pkgrel'][0]
    if metadata.get('epoch', ['0'])[0] != '0':
        version = metadata['epoch'][0] + ':' + version
    pkg = artifact['metadata']['.PKGINFO']
    for key, values in {'pkgname': metadata['pkgname'], 'pkgbase': metadata.get('pkgbase', metadata['pkgname']),
                        'pkgver': [version], 'arch': metadata['arch'], 'license': metadata['license']}.items():
        need(sorted(pkg.get(key, [])) == sorted(values), 'producer-original-package-metadata')
    for source, target in [('depends', 'depend'), ('makedepends', 'makedepend'), ('checkdepends', 'checkdepend'),
                           ('optdepends', 'optdepend'), ('provides', 'provides'), ('conflicts', 'conflict'),
                           ('replaces', 'replaces'), ('backup', 'backup')]:
        values = metadata.get(source, []) + metadata.get(source + '_aarch64', [])
        need(sorted(pkg.get(target, [])) == sorted(values), 'producer-original-package-metadata')
    return {'filename': filename, 'sha256': pin, 'container': container,
            'receipt_sha256': sha(read(directory / 'provenance.json'))}


def validate_producer(directory, image, native_script_sha, reviewedrecipes):
    directory = Path(directory)
    need(IMAGE.fullmatch(image or '') and native_script_sha == NATIVE_SCRIPT_SHA, 'producer-identity')
    inputs = source_inputs(directory)
    reviews = load(reviewedrecipes, RECIPES_SHA, 1024 ** 2)
    need(type(reviews) is dict and {Path(path).name for path in reviews} == NAMES and len(reviews) == 4, 'producer-recipes')
    result = load(directory / 'result.json', limit=65536)
    need(type(result) is dict, 'producer-result-schema')
    need(result.get('native_build') == 'PASS' and result.get('mode') == 'build' and
         result.get('status') == 'native-builds-and-byte-comparison-pass' and
         result.get('reviewed_inputs_sha256') == INPUTS_SHA and result.get('reviewed_recipes_sha256') == RECIPES_SHA and
         result.get('bootstrap_script_sha256') == native_script_sha and result.get('verified_signed_packages') == 248,
         'producer-result')
    acquired = acquisition(directory, inputs, True)
    signed = signatures(directory, inputs)
    expected = input_items(inputs)
    need(load(directory / 'cache-checksums.json') == {n: v['expected_sha256'] for n, v in expected.items()}, 'producer-cache-checksums')
    need(load(directory / 'rootfs-inventory.json') == inputs['rootfs_packages'], 'producer-rootfs-inventory')
    audit = load(directory / 'package-audit.json')
    need(type(audit) is dict and set(audit) == {row['filename'] for row in inputs['packages']}, 'producer-package-audit-set')
    for item in inputs['packages']:
        metadata = audit[item['filename']]['metadata']
        for target, source in [('pkgname', 'name'), ('pkgver', 'version'), ('arch', 'arch'), ('license', 'license'),
                               ('depend', 'depends'), ('provides', 'provides'), ('conflict', 'conflicts'), ('replaces', 'replaces')]:
            value = item[source]
            need(sorted(metadata.get(target, [])) == sorted(value if type(value) is list else [value]), 'producer-package-metadata')
    bootstrap = load(directory / 'bootstrap.json', limit=65536)
    need(type(bootstrap) is dict, 'producer-bootstrap-schema')
    # Docker's iidfile may omit the terminal LF; accept only these two exact byte forms.
    need(bootstrap.get('status') == 'image-provisioned' and bootstrap.get('image_id') == image and
         bootstrap.get('inputs_sha256') == INPUTS_SHA and bootstrap.get('packages_lock_sha256') == INVENTORY_SHA and
         read(directory / 'image-id', 256) in (image.encode(), (image + '\n').encode()), 'producer-bootstrap')
    versions = {r['name'][0]: r['version'][0] for r in inputs['rootfs_packages']}
    versions.update({r['name']: r['version'] for r in inputs['packages']})
    lock = ''.join(f'{n} {v}\n' for n, v in sorted(versions.items())).encode()
    need(len(versions) == 341 and sha(lock) == INVENTORY_SHA and read(directory / 'packages.lock', 65536) == lock,
         'producer-inventory')
    original = {}
    for path, hashes in sorted(reviews.items()):
        name = Path(path).name
        need(load(directory / (name + '-review.json')) == hashes, 'producer-recipe-review')
        builds = [original_build(directory / (name + '-' + str(n)), name, hashes, image) for n in (1, 2)]
        need(builds[0]['container'] != builds[1]['container'] and builds[0]['filename'] == builds[1]['filename'] and
             builds[0]['sha256'] == builds[1]['sha256'], 'producer-original-independence')
        comparison = load(directory / (name + '-compare.json'), limit=65536)
        need(type(comparison) is dict, 'producer-comparison-schema')
        filename = builds[0]['filename']
        need(comparison.get('status') == 'contents-reproduced' and comparison.get('errors') == [] and
             set(comparison.get('packages', {})) == {filename} and
             all(comparison['packages'][filename].get(k) is True for k in
                 ('bytes_equal', 'installed_contents_equal', 'pkginfo_equal')), 'producer-original-comparison')
        original[name] = {'status': 'PASS', 'artifact_sha256': builds[0]['sha256'],
                          'attempt_receipts_sha256': [b['receipt_sha256'] for b in builds],
                          'bytes_equal': True, 'installed_contents_equal': True, 'pkginfo_equal': True,
                          'buildinfo_equal_recorded': comparison['packages'][filename].get('buildinfo_equal') is True}
    return {'schema_version': 1, 'status': 'PASS', 'native_build': 'PASS', 'image_id': image,
            'inputs_sha256': INPUTS_SHA, 'recipes_sha256': RECIPES_SHA, 'native_script_sha256': native_script_sha,
            'acquired_inputs': acquired['counts']['pass'], 'authenticated_payloads': signed['verified_payloads'],
            'signed_packages': 248, 'builder_packages': 341, 'originals': original,
            'audit_receipts_sha256': {name: sha(read(directory / name)) for name in
                ('acquisition.json', 'signatures.json', 'rootfs-inventory.json', 'package-audit.json', 'cache-checksums.json', 'bootstrap.json')},
            'hardware': 'NOT RUN', 'installation': 'NOT RUN', 'binary_publication': 'NOT RUN'}


def public_status(report):
    report = report if type(report) is dict else {}
    cleanup = report.get('cleanup', {})
    cleanup = cleanup if type(cleanup) is dict else {}
    producer = report.get('producer', {})
    fdk = report.get('fdk', {})
    producer = producer.get('status') if type(producer) is dict else None
    fdk = fdk.get('status') if type(fdk) is dict else None
    producer = producer if producer in ('PASS', 'FAIL', 'NOT RUN') else 'NOT RUN'
    fdk = fdk if fdk in ('PASS', 'FAIL', 'NOT RUN') else 'NOT RUN'
    clean = cleanup.get('status') == 'PASS' and cleanup.get('owned_image_absence') is True
    source = report.get('source', {})
    source = source if type(source) is dict else {}
    finished = (report.get('phase') == 'complete' and report.get('cancelled') is False and clean and
                source.get('status') == 'PASS')
    accepted = report.get('status') == 'PASS' and finished and producer == fdk == 'PASS'
    boundary = producer_boundary(report.get('producer_boundary'))
    if 'producer_boundary' in report and (boundary is None or boundary['outer_gate'] != 'accepted'):
        accepted = False
    if not finished:
        producer = 'NOT ACCEPTED' if producer == 'PASS' else producer
        fdk = 'NOT ACCEPTED' if fdk == 'PASS' else fdk
    commit, packet_pin = source.get('source_commit'), source.get('packet_sha256')
    result = {'schema_version': 1, 'stage': 'fdk-native-job', 'status': 'PASS' if accepted else 'FAIL',
            'source_commit': commit if type(commit) is str and re.fullmatch('[0-9a-f]{40}', commit) else None,
            'source_packet_sha256': packet_pin if type(packet_pin) is str and PIN.fullmatch(packet_pin) else None,
            'phase': report.get('phase') if report.get('phase') in
                ('preflight', 'source', 'producer', 'fdk', 'cleanup', 'complete') else 'preflight',
            'cancelled': report.get('cancelled') is True, 'owned_image_absence': clean,
            'producer_status': producer, 'fdk_status': fdk, 'error_code': None if accepted else producer_failure_code(report),
            'hardware': 'NOT RUN', 'installation': 'NOT RUN', 'binary_publication': 'NOT RUN'}
    if boundary is not None:
        result['producer_boundary'] = boundary
    return result


def publish(directory, publicdir, image, native_script_sha, reviewedrecipes, job_report):
    directory, publicdir = Path(directory), Path(publicdir).absolute()
    need('..' not in publicdir.parts and not publicdir.is_symlink() and not publicdir.resolve().is_relative_to(directory.resolve()), 'producer-public-output')
    need(all(stat.S_ISDIR(p.lstat().st_mode) for p in publicdir.parents), 'producer-public-parent')
    need(not publicdir.exists() or publicdir.is_dir() and not list(publicdir.iterdir()), 'producer-public-existing')
    status = public_status(job_report)
    try:
        summary = validate_producer(directory, image, native_script_sha, reviewedrecipes)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, AttributeError):
        summary = {'schema_version': 1, 'status': 'FAIL', 'native_build': 'NOT ACCEPTED',
                   'error_code': 'producer-evidence-incomplete-or-invalid', 'binary_publication': 'NOT RUN'}
    if summary['status'] != 'PASS':
        status['status'] = 'FAIL'
    summary['authoritative_job_status'] = status['status']
    if status['status'] != 'PASS':
        summary['recorded_native_build'] = summary['native_build']
        summary['native_build'] = 'NOT ACCEPTED'
        summary['status'] = 'FAIL'
    exports = {'producer-summary.json': summary}
    try:
        inputs = source_inputs(directory)
        exports['acquisition.json'] = acquisition(directory, inputs)
        exports['inputs.lock.json'] = decode(read(directory / 'inputs.lock.json', 1024 ** 2))
        exports['recipes.lock.json'] = load(reviewedrecipes, RECIPES_SHA, 1024 ** 2)
        if summary.get('recorded_native_build', summary['native_build']) == 'PASS':
            exports['signatures.json'] = signatures(directory, inputs)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, AttributeError):
        exports = {'producer-summary.json': summary}
    need(set(exports) <= PUBLIC_FILES, 'producer-public-allowlist')
    if not publicdir.exists():
        publicdir.mkdir(mode=0o755)
    hashes = {}
    for name, value in sorted(exports.items()):
        data = (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
        with (publicdir / name).open('xb') as stream:
            stream.write(data)
        hashes[name] = sha(data)
    manifest = {'schema_version': 1, 'status': summary['status'], 'files': hashes,
                'binary_publication': 'NOT RUN'}
    with (publicdir / 'export-manifest.json').open('x') as stream:
        stream.write(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
    return manifest
