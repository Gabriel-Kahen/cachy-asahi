#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Project the authoritative inventory and nine exact public operation names.

The caller binds receipts to the accepted image/source and uses the unchanged
generic exporter. Unknown fields survive, and operation file bytes never change.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

PURPOSE = 'disposable-generic-repository-test'
LIMIT = 4 * 1024**2
CONTRACT_FIELDS = ('nonce', 'image_id', 'daemon_arch', 'script_sha256', 'upgrade_kind')
SPEC = importlib.util.spec_from_file_location('repository_inventory_validation', Path(__file__).with_name('lifecycle_inventory.py'))
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)

RESET = 'revoked-A-sync-cache-reset'
REJECTION = 'revoked-A-repository-rejected'
FINAL = 'unrevoked-B-final-full-upgrade'
RELATION = 'dependency-consistency'
DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def need(condition, message):
    if not condition:
        raise ValueError(message)


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate repository JSON key')
            result[key] = value
        return result

    def constant(_value):
        raise ValueError('nonfinite repository JSON refused')

    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=unique, parse_constant=constant)
    except RecursionError:
        raise ValueError('repository JSON nesting refused') from None


def read_public(raw, name, digest):
    """Read a single exact, bound producer file; never traverse private trees."""
    need(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9._-]{1,160}', name)
         and isinstance(digest, str) and DIGEST.fullmatch(digest), 'repository file binding invalid')
    inventory.real_directories(raw)
    path = raw / name
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= LIMIT,
         'repository public file must be bounded singly linked regular data')
    identity = lambda value: tuple(getattr(value, key) for key in
                                  ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                                   'st_size', 'st_mtime_ns', 'st_ctime_ns'))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        need(identity(os.fstat(stream.fileno())) == identity(info), 'repository file changed before read')
        data = stream.read(LIMIT + 1)
        need(identity(os.fstat(stream.fileno())) == identity(info), 'repository file changed while reading')
    need(identity(path.lstat()) == identity(info) and len(data) == info.st_size
         and hashlib.sha256(data).hexdigest() == digest, 'repository file bytes differ from receipt')
    return data


def operation_files(raw, result, contract):
    """Validate the exact completed reset/relation protocol and return nine aliases.

    Original bytes and receipt references remain unchanged. Each public reference
    is explicit in the returned index. This grants no permission to other paths.
    Partial failed runs receive no aliases and remain subject to the generic guard.
    """
    if 'sync_cache_reset' not in result:
        return {}, None
    validate_contract(result, contract)
    raw = Path(raw)
    need(raw.is_absolute(), 'absolute repository evidence directory required')
    evidence = result.get('evidence_sha256')
    need(isinstance(evidence, dict), 'repository evidence hash map required')
    captured = {}

    def read(name, digest=None):
        pin = evidence.get(name)
        need(digest is None or pin == digest, 'repository evidence and operation hashes differ')
        return read_public(raw, name, pin)

    commands = result.get('commands')
    need(isinstance(commands, list) and len(commands) <= 2048, 'bounded repository commands required')
    labels = ('gpg-revoked-A-status', REJECTION, 'inventory-' + RESET + '-before',
              'inventory-' + RESET + '-after', FINAL, RELATION)
    found = {}
    for position, row in enumerate(commands):
        need(isinstance(row, dict), 'repository command object required')
        if row.get('label') in labels:
            need(row['label'] not in found, 'duplicate repository operation label')
            found[row['label']] = (position, row)
    need(set(found) == set(labels), 'complete repository operation commands required')
    need([found[label][0] for label in labels] == sorted(found[label][0] for label in labels),
         'repository reset/relation command order differs')

    def command(label, positive=False):
        position, row = found[label]
        name = f'{position:03d}-{label}.txt'
        need(row.get('log') == name and type(row.get('exit_code')) is int, 'repository operation command identity differs')
        if positive:
            need(type(row.get('expected')) is int and row['expected'] == row['exit_code'] == 0
                 and row.get('positive_diagnostics') == 'PASS', 'repository positive operation did not pass')
        return row, read(name, row.get('sha256'))

    rejected, rejection_text = command(REJECTION)
    need(rejected.get('expected') == 'nonzero' and rejected['exit_code'] != 0,
         'actual revoked-A rejection required')
    proof, status_text = command('gpg-revoked-A-status')
    need(proof.get('expected') is None and proof['exit_code'] == 0,
         'repository revocation-status command policy differs')
    identities = result.get('public_TEST_identities', {})
    signer = identities.get('signer-A', {}) if isinstance(identities, dict) else {}
    fingerprint = signer.get('fingerprint')
    need(isinstance(fingerprint, str) and re.fullmatch(r'[0-9A-F]{40}', fingerprint)
         and b'signature from "TEST ONLY disposable repository signer-A <signer-A@test.invalid>" is invalid' in rejection_text
         and ('[GNUPG:] REVKEYSIG ' + fingerprint[-16:] + ' ').encode() in status_text
         and ('[GNUPG:] VALIDSIG ' + fingerprint + ' ').encode() in status_text,
         'repository revoked-A proof differs')
    cases = result.get('cases')
    need(isinstance(cases, list) and len(cases) >= 2 and
         cases[-2:] == [{'name': REJECTION, 'result': 'PASS', 'expected_signature_rejection': True},
                       {'name': FINAL, 'result': 'PASS', 'expected_signature_rejection': False}],
         'repository final rejection/upgrade cases differ')
    command(FINAL, True)
    ref = result['sync_cache_reset']
    need(isinstance(ref, dict) and set(ref) == {'receipt', 'sha256'} and ref['receipt'] == RESET + '.json',
         'exact repository reset receipt reference required')
    receipt_data = read(ref['receipt'], ref['sha256'])
    receipt = strict_json(receipt_data)
    need(isinstance(receipt, dict) and set(receipt) == {'status', 'scope', 'prior_rejection_log_sha256',
         'revocation_status_log_sha256', 'removed', 'absence', 'installed_state_unchanged'}
         and receipt['status'] == receipt['absence'] == 'PASS' and receipt['installed_state_unchanged'] is True
         and receipt['scope'] == 'two private copied-root sync files after revoked-A rejection'
         and receipt['prior_rejection_log_sha256'] == rejected['sha256']
         and receipt['revocation_status_log_sha256'] == proof['sha256'], 'repository reset receipt differs')
    aliases = strict_json(read('TEST-repository-aliases.json'))
    need(isinstance(aliases, dict) and aliases.get('active') == {'kind': 'directory', 'target': 'updated-B'},
         'repository final active endpoint differs')

    def pair(stage):
        need(isinstance(aliases, dict), 'repository aliases object required')
        value = {}
        for name in ('integration.db', 'integration.db.sig'):
            row = aliases.get(stage + '/' + name)
            need(isinstance(row, dict) and set(row) == {'kind', 'target', 'regular_copy_sha256'}
                 and row['kind'] == 'file' and row['target'] == stage + '/' +
                 ('integration.db.tar.gz' if name == 'integration.db' else 'integration.db.tar.gz.sig')
                 and isinstance(row['regular_copy_sha256'], str) and DIGEST.fullmatch(row['regular_copy_sha256']),
                 'repository database/signature alias differs')
            value[name] = row['regular_copy_sha256']
        return value

    need(receipt['removed'] == pair('baseline-A') and result.get('final_sync_cache') == pair('updated-B'),
         'repository reset/final database pair differs')
    baseline = contract.get('baseline')
    versions = inventory.overlay(baseline)
    expected_inputs = {row['name']: {key: row[key] for key in ('sha256', 'version')} for row in baseline}
    need(result.get('original_inputs', {}).get('baseline') == expected_inputs, 'repository baseline archive authority differs')
    base = result.get('base_versions')
    if isinstance(base, list):
        need(all(isinstance(row, dict) and set(row) == {'name', 'version'} for row in base), 'repository base rows differ')
        need(len({row['name'] for row in base}) == len(base), 'duplicate repository base row')
        base = {row['name']: row['version'] for row in base}
    base = inventory.validate_map(base)
    need(not set(base) & (set(versions) | {'cachy-asahi-repository-test-fixture'}), 'repository base overlaps overlay')
    expected_inventory = {**base, **versions, 'cachy-asahi-repository-test-fixture': '1-1'}
    inventory_data = ''.join(f'{name} {expected_inventory[name]}\n' for name in sorted(expected_inventory)).encode()
    expected_files = {}
    for row in baseline:
        payload = row.get('payload_sha256')
        need(isinstance(payload, dict) and payload, 'repository accepted payload hashes required')
        for name, digest in payload.items():
            need(name not in expected_files and isinstance(digest, str) and DIGEST.fullmatch(digest),
                 'repository payload authority differs')
            expected_files[name] = {'type': 'regular', 'uid': 0, 'gid': 0,
                                    'mode': 0o755 if name in {'usr/bin/cachy-asahi-setup', 'usr/bin/cachy-asahi-screenshot'} else 0o644,
                                    'sha256': digest}
    expected_files['usr/share/cachy-asahi-repository-TEST/fixture.txt'] = {
        'type': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644,
        'sha256': hashlib.sha256(b'SYNTHETIC TEST fixture version 1\n').hexdigest()}
    expected_snapshot = {'inventory': inventory_data.decode(), 'files': expected_files}

    def snapshot(data):
        value = strict_json(data)
        need(isinstance(value, dict) and isinstance(value.get('files'), dict)
             and all(isinstance(row, dict) and all(type(row.get(key)) is int for key in ('uid', 'gid', 'mode'))
                     for row in value['files'].values()) and value == expected_snapshot,
             'repository installed snapshot differs from baseline authority')

    snapshot(read(REJECTION + '-after-snapshot.json'))
    for phase in ('before', 'after'):
        label = 'inventory-' + RESET + '-' + phase
        row, data = command(label, True)
        need(data == inventory_data, 'repository reset inventory differs')
        stderr = row['log'][:-4] + '-stderr.txt'
        need(row.get('stderr_log') == stderr and read(stderr, row.get('stderr_sha256')) == b'',
             'repository reset stderr differs')
        public_label = 'inventory-revoked-A-sync-reset-' + phase
        prefix = row['log'].split('-', 1)[0]
        captured[row['log']] = (prefix + '-' + public_label + '.txt', data)
        captured[stderr] = (prefix + '-' + public_label + '-stderr.txt', b'')
        snapshot_name = RESET + '-' + phase + '-snapshot.json'
        data = read(snapshot_name)
        snapshot(data)
        captured[snapshot_name] = ('revoked-A-sync-reset-' + phase + '-snapshot.json', data)
    row, data = command(RELATION, True)
    need(data == b'No database errors have been found!\n', 'repository relation-check diagnostic differs')
    stderr = row['log'][:-4] + '-stderr.txt'
    need(row.get('stderr_log') == stderr and read(stderr, row.get('stderr_sha256')) == b'',
         'repository relation-check stderr differs')
    prefix = row['log'].split('-', 1)[0]
    captured[row['log']] = (prefix + '-installed-relation-check.txt', data)
    captured[stderr] = (prefix + '-installed-relation-check-stderr.txt', b'')
    captured[ref['receipt']] = ('revoked-A-sync-reset.json', receipt_data)
    index = {'schema_version': 1, 'purpose': 'validated-repository-operation-aliases',
             'generic_content_guard': 'UNCHANGED', 'original_bytes_preserved': True,
             'files': {name: {'public_path': public, 'original_sha256': hashlib.sha256(data).hexdigest(),
                              'public_sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                       for name, (public, data) in captured.items()}}
    return captured, index


def validate_contract(value, contract):
    """Bind a parsed receipt to the caller's accepted generated manifest."""
    if (not isinstance(value, dict) or type(value.get('schema_version')) is not int
            or value['schema_version'] != 1 or value.get('purpose') != PURPOSE):
        raise ValueError('repository receipt requires known schema1/purpose')
    if not isinstance(contract, dict) or value.get('source_commit') != contract.get('source_commit'):
        raise ValueError('repository receipt source differs from accepted contract')
    if 'source_commit' not in contract or any(key not in contract for key in CONTRACT_FIELDS):
        raise ValueError('complete accepted repository contract required')
    observed = value.get('input_contract')
    expected = {key: contract[key] for key in CONTRACT_FIELDS}
    if not isinstance(observed, dict) or set(observed) != set(CONTRACT_FIELDS) or observed != expected:
        raise ValueError('repository receipt input contract differs from exact accepted manifest')


def project_result(value, base):
    """Return a deepcopy, transforming only known, complete base_versions maps.

    Other purposes and early failure receipts without base_versions are copied
    unchanged. A malformed present field under this purpose fails; it cannot be
    encoded into a permissive representation. Unknown fields always survive for
    the generic exporter's independent refusal checks.
    """
    if not isinstance(value, dict):
        raise ValueError('repository result must be a JSON object')
    result = copy.deepcopy(value)
    if result.get('purpose') != PURPOSE:
        return result
    if type(result.get('schema_version')) is not int or result['schema_version'] != 1:
        raise ValueError('repository projection requires exact known schema1')
    if 'base_versions' not in result:
        return result
    expected = inventory.validate_map(base)
    observed = inventory.validate_map(result['base_versions'])
    if observed != expected:
        raise ValueError('repository base inventory differs from complete accepted authority')
    result['base_versions'] = [{'name': name, 'version': observed[name]} for name in sorted(observed)]
    return result


def project(data, base, contract=None):
    """Parse bounded original bytes strictly, then return the projected object.

    Use this entry point rather than an ordinary json.loads call, which would
    discard duplicate-key evidence. Original bytes are never changed or hashed
    here; the caller may publish their hash/count only after this validation.
    """
    if not isinstance(data, bytes) or not 0 < len(data) <= LIMIT:
        raise ValueError('bounded nonempty repository result bytes required')

    value = strict_json(data)
    if contract is not None:
        validate_contract(value, contract)
    return project_result(value, base)
