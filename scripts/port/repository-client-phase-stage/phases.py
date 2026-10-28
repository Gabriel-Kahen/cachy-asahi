#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind native observations and independently recheck snapshot/terminal crypto."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import time

import dependencies

PIN = re.compile(r'[0-9a-f]{64}\Z')
ENVELOPE = {'schema_version', 'purpose', 'status', 'request', 'receipt'}
PHASE_KEYS = {'path', 'signature', 'signer', 'data_sha256', 'signature_sha256', 'status_sha256',
              'machine_status', 'status_bytes', 'stderr_sha256', 'stderr_bytes', 'phase', 'fingerprint',
              'digest_algorithm', 'integrity', 'authorization'}
NEGATIVE_KEYS = (PHASE_KEYS - {'fingerprint', 'digest_algorithm'}) | {'expected_fingerprint'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    need(isinstance(raw, bytes) and 0 < len(raw) <= 16 * 1024**2, 'bounded-phase-json-required')
    def pairs(rows):
        result = {}
        for name, value in rows:
            need(name not in result, 'duplicate-phase-json-field')
            result[name] = value
        return result
    def invalid(_):
        raise ValueError('phase-json-float-refused')
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(isinstance(value, dict), 'phase-json-object-required')
    return value


def relative(name):
    need(isinstance(name, str) and 0 < len(name) <= 512 and re.fullmatch(r'[A-Za-z0-9_./+:-]+', name)
         and not PurePosixPath(name).is_absolute() and PurePosixPath(name).as_posix() == name
         and all(part not in ('', '.', '..') for part in name.split('/')), 'phase-relative-path-required')
    return name


def signature_facts(raw):
    if isinstance(raw, bytes):
        raw = raw.decode('utf-8', errors='strict')
    rows = [line.split()[1:] for line in raw.splitlines() if line.startswith('[GNUPG:] ')]
    facts = {key: [row for row in rows if row and row[0] == key] for key in ('VALIDSIG', 'SIG_ID')}
    need(len(facts['VALIDSIG']) == len(facts['SIG_ID']) == 1, 'signature-packet-facts-required')
    return facts


def native_argv(role, data):
    home = '/test-home/' + role
    return ['gpg', '--batch', '--no-options', '--homedir', home, '--no-default-keyring', '--keyring',
            home + '/pubring.gpg', '--no-auto-key-retrieve', '--status-fd', '1', '--verify', data + '.sig', data]


def native_target(path, prefix, role):
    need(path.startswith(prefix), 'native-public-prefix-differs')
    name = path[len(prefix):]
    if name == 'TEST-repository-aliases.json':
        need(role == 'signer-B', 'alias-signer-role-differs')
        return '/out/TEST-repository-aliases.json', 'verify-signer-B'
    parts = PurePosixPath(relative(name)).parts
    expected = 'baseline-A' if role == 'signer-A' else 'updated-B'
    need(len(parts) == 3 and parts[:2] == ('TEST-repositories', expected), 'native-repository-path-differs')
    label = 'verify-database-' + expected if parts[2] in ('integration.db.tar.gz', 'integration.files.tar.gz') else 'verify-' + role
    return '/scratch/repos/' + expected + '/' + parts[2], label


def validate(authority, files, get, roles, public_prefix, publicmap, ordered_signed_objects, repository, *, repo_root):
    """Called only after the surrounding gate has checked all native predicates."""
    envelope = authority.get('crypto')
    need(isinstance(envelope, dict) and set(envelope) == ENVELOPE and type(envelope['schema_version']) is int
         and envelope['schema_version'] == 2 and envelope['purpose'] == 'external-repository-cryptographic-phase-acceptance'
         and envelope['status'] == 'PASS', 'phase-aware-authority-required-v1-refused')
    modules = dependencies.load_collector(repo_root)
    common, crypto = modules['common'], modules['crypto']
    with common.cancellation_handlers():
        return _validate(authority, files, get, roles, public_prefix, publicmap, ordered_signed_objects,
                         repository, modules)


def _validate(authority, files, get, roles, public_prefix, publicmap, ordered_signed_objects, repository, modules):
    common, crypto = modules['common'], modules['crypto']
    fetch = get if callable(get) else get.__getitem__
    def mapped(name):
        relative(name)
        need(name in files, 'phase-file-not-in-authority')
        row, data = files[name], fetch(name)
        need(isinstance(row, dict) and set(row) == {'sha256', 'bytes'} and isinstance(row['sha256'], str)
             and PIN.fullmatch(row['sha256']) and type(row['bytes']) is int and 0 <= row['bytes'] <= 16 * 1024**2
             and isinstance(data, bytes) and len(data) == row['bytes'] and digest(data) == row['sha256'], 'phase-file-binding-differs')
        return data
    def reference(role):
        row = authority['crypto'][role]
        need(isinstance(row, dict) and set(row) == {'path', 'sha256', 'bytes'}
             and files.get(row['path']) == {key: row[key] for key in ('sha256', 'bytes')}, 'phase-reference-map-differs')
        return mapped(row['path'])
    request_raw, receipt_raw = reference('request'), reference('receipt')
    request, receipt = decode(request_raw), decode(receipt_raw)
    need(set(request) == crypto.FIELDS and type(request['schema_version']) is int and request['schema_version'] == 2
         and request['purpose'] == receipt.get('purpose') == 'repository-cryptographic-phases'
         and type(receipt.get('schema_version')) is int and receipt['schema_version'] == 2 and receipt.get('status') == 'PASS',
         'version2-crypto-records-required')
    for key, pattern in (('source_commit', r'[0-9a-f]{40}'), ('run_id', r'[1-9][0-9]{0,19}'),
                         ('nonce', r'[0-9a-f]{32}'), ('image_id', r'sha256:[0-9a-f]{64}')):
        need(isinstance(authority.get(key), str) and re.fullmatch(pattern, authority[key])
             and request.get(key) == receipt.get(key) == authority[key], 'phase-run-identity-differs')
    prefix = public_prefix.rstrip('/')
    if prefix:
        relative(prefix)
    need(request['public_prefix'] == prefix, 'phase-public-prefix-differs')
    prefix = prefix + '/' if prefix else ''
    need(isinstance(roles, dict) and set(roles) == {'signer-A', 'signer-B', 'verifier'}, 'phase-signer-roles-required')
    expected_signers = {role: {'fingerprint': row['fingerprint'], 'certificate': row['certificate'],
                              **({'revoked_certificate': prefix + 'TEST-signer-A-revoked-public.asc'} if role == 'signer-A' else {})}
                        for role, row in roles.items()}
    need(request['signers'] == expected_signers, 'phase-certificate-role-binding-differs')
    expected = []
    need(isinstance(ordered_signed_objects, list) and len(ordered_signed_objects) == 15, 'phase-exact15-objects-required')
    for row in ordered_signed_objects:
        need(isinstance(row, dict) and set(row) in ({'path', 'signature', 'signer'}, {'path', 'signature', 'signer', 'status'}), 'phase-signed-object-shape')
        expected.append({key: row[key] for key in ('path', 'signature', 'signer')})
    need(expected == sorted(expected, key=lambda row: row['path']) and len({row['path'] for row in expected}) == 15
         and sum(row['signer'] == 'signer-A' for row in expected) == 7
         and sum(row['signer'] == 'signer-B' for row in expected) == 8 and request['signed_objects'] == expected,
         'phase-complete-ordered-healthy-set-differs')
    request_files = request['files']
    need(isinstance(request_files, dict) and 0 < len(request_files) <= 1024
         and all(files.get(name) == row for name, row in request_files.items()), 'phase-request-map-not-authority-subset')
    captures = {name: mapped(name) for name in request_files}
    need(sum(map(len, captures.values())) <= 64 * 1024**2, 'phase-request-total-bound')
    public_names = {prefix + name for name in publicmap}
    need(all(request_files.get(prefix + name) == row for name, row in publicmap.items()), 'phase-public-map-differs')
    need({name for name in request_files if name.startswith(prefix) and (name[len(prefix):].startswith('TEST-'))} == public_names,
         'phase-public-map-extra-or-missing')
    need(receipt.get('request_sha256') == digest(request_raw)
         and receipt.get('artifact_map_sha256') == common.digest(common.encoded(request_files))
         and receipt.get('public_artifact_map_sha256') == common.digest(common.encoded(publicmap)), 'phase-receipt-map-binding-differs')
    need(receipt.get('current_A_authorization') == 'REVOKED' and receipt.get('original_local_certification') == 'native-receipts-only'
         and receipt.get('native_observation_boundary') == 'retained-native-observations-only'
         and receipt.get('private_work_cleanup') == 'PASS' and receipt.get('public_only_agent_sockets_absent') is True
         and receipt.get('hardware_validation') == receipt.get('production_trust') == 'NOT RUN'
         and receipt.get('source_authentication') == 'caller-authenticated-snapshot-required', 'phase-receipt-boundary-differs')
    source_pins = {name + '.py': common.digest(common.read(Path(modules[name].__file__))) for name in ('common', 'crypto')}
    need(receipt.get('source_sha256') == source_pins, 'phase-receipt-authenticated-source-differs')
    tools = receipt.get('tool_sha256')
    need(isinstance(tools, dict) and set(tools) == {'gpg', 'gpgconf', 'gpg-connect-agent'}
         and all(isinstance(pin, str) and PIN.fullmatch(pin) for pin in tools.values()), 'phase-receipt-tool-pins-required')
    environment = receipt.get('actual_software_environment')
    need(isinstance(environment, dict) and set(environment) == {'architecture', 'page_size', 'execution'}
         and isinstance(environment['architecture'], str) and 0 < len(environment['architecture']) <= 64
         and type(environment['page_size']) is int and 1024 <= environment['page_size'] <= 65536
         and environment['execution'] == 'local-bounded-private-processes', 'phase-receipt-observed-environment-required')
    observed, completed, now = receipt.get('observed_at'), receipt.get('completed_at'), int(time.time())
    expiry, certificates = receipt.get('certificate_expiry'), receipt.get('signer_certificates')
    need(type(observed) is int and type(completed) is int and 0 < observed <= completed <= now
         and isinstance(expiry, dict) and set(expiry) == set(roles)
         and all(type(value) is int and completed < value and now < value for value in expiry.values()), 'phase-certificate-current-expiry-required')
    expected_certificates = {role: {'fingerprint': row['fingerprint'], 'certificate': row['certificate'],
                                   'certificate_sha256': files[row['certificate']]['sha256'], 'expires_at': expiry[role],
                                   **({'revoked_certificate': prefix + 'TEST-signer-A-revoked-public.asc',
                                       'revoked_certificate_sha256': files[prefix + 'TEST-signer-A-revoked-public.asc']['sha256']}
                                      if role == 'signer-A' else {})} for role, row in roles.items()}
    need(certificates == expected_certificates, 'phase-current-certificate-binding-differs')
    need(receipt.get('native_verifications') == request['native_verifications']
         and receipt.get('native_revocation') == request['native_revocation'], 'phase-native-request-receipt-differs')
    snapshot, terminal, negatives = receipt.get('snapshot_integrity'), receipt.get('terminal_authorization'), receipt.get('negative_verifications')
    need(isinstance(snapshot, list) and isinstance(terminal, list) and len(snapshot) == len(terminal) == 15
         and isinstance(negatives, list) and len(negatives) == 14, 'phase-complete-receipt-checks-required')
    all_rows = snapshot + negatives + terminal
    command_rows = receipt.get('commands')
    need(isinstance(command_rows, list) and 0 < len(command_rows) <= 128, 'phase-bounded-command-receipt-required')
    verification_commands = []
    work_prefix = None
    for command in command_rows:
        need(isinstance(command, dict) and set(command) == {'argv', 'exit_code', 'stdout_sha256', 'stderr_sha256', 'stdout_bytes', 'stderr_bytes'}
             and isinstance(command['argv'], list) and command['argv'] and all(isinstance(value, str) for value in command['argv'])
             and type(command['exit_code']) is int and all(type(command[key]) is int and 0 <= command[key] <= 1024**2
                 for key in ('stdout_bytes', 'stderr_bytes')) and command['stdout_bytes'] + command['stderr_bytes'] <= 1024**2
             and all(isinstance(command[key], str) and PIN.fullmatch(command[key]) for key in ('stdout_sha256', 'stderr_sha256')),
             'phase-command-record-binding-required')
        need(not any(value.startswith(('--faked-system-time', '--ignore-time-conflict', '--ignore-valid-from'))
                     for value in command['argv']), 'phase-fake-clock-or-validity-bypass-refused')
        if '--verify' in command['argv']:
            verification_commands.append(command)
    need(len(verification_commands) == len(all_rows), 'phase-verification-command-count-differs')
    def phase_row(row, command, expected_object=None, authorization=None):
        need(isinstance(row, dict), 'phase-machine-status-row-required')
        rejected = row.get('phase') == 'expected-tamper'
        need(set(row) == (NEGATIVE_KEYS if rejected else PHASE_KEYS), 'phase-machine-status-row-shape')
        role, path, signature = row['signer'], row['path'], row['signature']
        need(role in roles and signature == path + '.sig' and path in captures and signature in captures
             and row['data_sha256'] == files[path]['sha256'] and row['signature_sha256'] == files[signature]['sha256'],
             'phase-signed-byte-binding-differs')
        if expected_object is not None:
            need({key: row[key] for key in ('path', 'signature', 'signer')} == expected_object
                 and row['authorization'] == authorization and row['phase'] == ('revoked' if authorization == 'REVOKED' else 'positive'),
                 'phase-object-authorization-differs')
        need(isinstance(row['machine_status'], str) and type(row['stderr_bytes']) is int and 0 <= row['stderr_bytes'] <= 1024**2,
             'phase-machine-status-types-required')
        raw = row['machine_status'].encode('utf-8')
        need(type(row['status_bytes']) is int and len(raw) == row['status_bytes'] <= 1024**2
             and row['status_sha256'] == digest(raw) and command['stdout_sha256'] == row['status_sha256']
             and command['stdout_bytes'] == row['status_bytes'] and command['stderr_sha256'] == row['stderr_sha256']
             and command['stderr_bytes'] == row['stderr_bytes'], 'phase-raw-status-command-binding-differs')
        argv = command['argv']
        need(len(argv) == 14 and PurePosixPath(argv[0]).name == 'gpg' and PurePosixPath(argv[0]).is_absolute(), 'phase-gpg-command-shape')
        work = PurePosixPath(argv[5]).parent
        nonlocal work_prefix
        work_prefix = work_prefix or work
        need(work.is_absolute() and work == work_prefix and argv[1:5] == ['--batch', '--no-options', '--no-autostart', '--homedir']
             and argv[5] == str(work / role) and argv[6:12] == ['--no-auto-key-retrieve', '--auto-key-locate', 'clear', '--status-fd', '1', '--verify']
             and argv[12:] == [str(work / 'captured' / signature), str(work / 'captured' / path)], 'phase-exact-captured-gpg-argv-required')
        if rejected:
            rows = [line.split()[1:] for line in row['machine_status'].splitlines() if line.startswith('[GNUPG:] ')]
            need(role == 'signer-B' and row['expected_fingerprint'] == roles[role]['fingerprint'] and row['integrity'] == 'INVALID'
                 and row['authorization'] == 'REJECTED' and command['exit_code'] != 0
                 and len([value for value in rows if value and value[0] == 'BADSIG' and value[1] == roles[role]['fingerprint'][-16:]]) == 1
                 and not any(value and value[0] in {'VALIDSIG', 'ERRSIG', 'NO_PUBKEY'} for value in rows), 'phase-expected-tamper-proof-differs')
        else:
            proof = crypto.verify_phase(raw, roles[role]['fingerprint'], row['phase'], command['exit_code'])
            need(row['fingerprint'] == proof['fingerprint'] and row['digest_algorithm'] == proof['digest_algorithm']
                 and row['integrity'] == proof['integrity'], 'phase-machine-status-semantics-differ')
    for index, obj in enumerate(expected):
        phase_row(snapshot[index], verification_commands[index], obj, 'SNAPSHOT_ONLY')
        phase_row(terminal[index], verification_commands[29 + index], obj, 'REVOKED' if obj['signer'] == 'signer-A' else 'VALID_AT_OBSERVATION')
    for row, command in zip(negatives, verification_commands[15:29]):
        phase_row(row, command)
    # Native proof paths bind the producer's actual private repository layout;
    # a matching basename or fingerprint in an unrelated log never suffices.
    raw_prefix = str(PurePosixPath(authority['refs']['repository']).parent)
    raw_prefix = '' if raw_prefix == '.' else raw_prefix + '/'
    commands, evidence = repository['commands'], repository['evidence_sha256']
    need(isinstance(commands, list) and all(isinstance(row, dict) for row in commands), 'native-command-records-required')
    def native_command(index, label, argv, status_log=None, exit_code=0, expected_exit=0):
        need(type(index) is int and 0 <= index < len(commands), 'native-command-index-invalid')
        row = commands[index]
        filename = f'{index:03d}-{label}.txt'
        need(row.get('label') == label and row.get('argv') == argv and row.get('log') == filename
             and type(row.get('exit_code')) is int and row['exit_code'] == exit_code
             and (row.get('expected') is None if expected_exit is None else type(row.get('expected')) is int and row['expected'] == expected_exit)
             and row.get('sha256') == evidence.get(filename) == files.get(raw_prefix + filename, {}).get('sha256'), 'native-command-exact-binding-differs')
        need(status_log is None or status_log == raw_prefix + filename, 'native-status-log-path-differs')
        return mapped(raw_prefix + filename)
    imports = []
    for role, label in (('signer-A', 'revoke-A-signing-home'), ('verifier', 'revoke-A-verification-home')):
        indices = [index for index, row in enumerate(commands) if row.get('label') == label]
        need(len(indices) == 1, 'native-revocation-import-required')
        home = '/test-home/' + role
        argv = native_argv(role, 'unused')[:9] + ['--import', '/test-home/TEST-revocation.asc']
        native_command(indices[0], label, argv)
        imports.append(indices[0])
    revoked = request['native_revocation']
    need(set(revoked) == {'status_log', 'exit_code', 'command_index'} and imports[0] < imports[1] < revoked['command_index'], 'native-revocation-order-differs')
    raw = native_command(revoked['command_index'], 'gpg-revoked-A-status', native_argv('verifier', '/scratch/repos/baseline-A/integration.db.tar.gz'),
                         revoked['status_log'], revoked['exit_code'], None)
    crypto.verify_phase(raw, roles['signer-A']['fingerprint'], 'revoked', revoked['exit_code'])
    revoked_object = prefix + 'TEST-repositories/baseline-A/integration.db.tar.gz'
    revoked_matches = [row for row in terminal if row['path'] == revoked_object]
    need(len(revoked_matches) == 1 and signature_facts(raw) == signature_facts(revoked_matches[0]['machine_status']),
         'native-revoked-signature-packet-status-differs')
    native = request['native_verifications']
    need(isinstance(native, list) and len(native) == 15 and all(isinstance(row, dict) and isinstance(row.get('path'), str) for row in native)
         and len({row['path'] for row in native}) == 15, 'native-complete15-observations-required')
    by_path = {row['path']: row for row in native}
    for index, obj in enumerate(expected):
        row, role = by_path[obj['path']], obj['signer']
        need(set(row) == {'path', 'status_log', 'exit_code', 'command_index', 'native_phase'}
             and row['native_phase'] == ('pre-A-revocation' if role == 'signer-A' else 'unrevoked-B')
             and (role != 'signer-A' or row['command_index'] < imports[0]), 'native-positive-phase-order-differs')
        data, label = native_target(obj['path'], prefix, role)
        raw = native_command(row['command_index'], label, native_argv(role, data), row['status_log'], row['exit_code'])
        crypto.verify_phase(raw, roles[role]['fingerprint'], exit_code=row['exit_code'])
        need(signature_facts(raw) == signature_facts(snapshot[index]['machine_status']), 'native-signature-packet-status-differs')
    # Recreate only the request's exact mapped tree, never the broader authority.
    temporary = None
    fresh = None
    try:
        with common.defer_cancellation():
            temporary = Path(tempfile.mkdtemp(prefix='repository-phase-recheck-'))
        inputs = temporary / 'inputs'; inputs.mkdir(mode=0o700)
        for name, data in captures.items():
            path = inputs / name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            common.write_new(path, data)
        fresh = crypto.attest(inputs, request_raw, digest(request_raw), temporary / 'output')
        need(fresh.get('status') == 'PASS' and fresh.get('private_work_cleanup') == 'PASS', 'independent-real-gpg-phase-recheck-refused')
        need(set(receipt) == set(fresh), 'phase-receipt-schema-differs')
        stable = ('schema_version', 'purpose', 'source_commit', 'run_id', 'nonce', 'image_id', 'request_sha256',
                  'artifact_map_sha256', 'public_artifact_map_sha256', 'current_A_authorization', 'certificate_expiry',
                  'signer_certificates', 'source_sha256', 'source_authentication', 'public_only_agent_sockets_absent',
                  'native_verifications', 'native_revocation', 'native_observation_boundary', 'original_local_certification',
                  'hardware_validation', 'production_trust', 'private_work_cleanup')
        need(all(receipt[key] == fresh[key] for key in stable), 'independent-stable-phase-proof-differs')
        for key in ('snapshot_integrity', 'terminal_authorization', 'negative_verifications'):
            for stored, current in zip(receipt[key], fresh[key]):
                need(isinstance(stored, dict) and isinstance(current, dict)
                     and set(stored) == (NEGATIVE_KEYS if stored.get('phase') == 'expected-tamper' else PHASE_KEYS)
                     and set(current) == (NEGATIVE_KEYS if current.get('phase') == 'expected-tamper' else PHASE_KEYS)
                     and set(stored) == set(current), 'independent-object-phase-proof-differs')
                keys = set(stored) - {'machine_status', 'status_sha256', 'status_bytes', 'stderr_sha256', 'stderr_bytes'}
                need({name: stored[name] for name in keys} == {name: current[name] for name in keys}, 'independent-object-phase-proof-differs')
                if stored['integrity'] == 'VALID':
                    need(signature_facts(stored['machine_status']) == signature_facts(current['machine_status']), 'independent-signature-packet-facts-differ')
        for name, data in captures.items():
            need(mapped(name) == data, 'phase-input-drift-after-recheck')
        need(reference('request') == request_raw and reference('receipt') == receipt_raw, 'phase-crypto-record-drift-after-recheck')
    finally:
        if temporary is not None:
            with common.defer_cancellation():
                shutil.rmtree(temporary)
                need(not temporary.exists(), 'phase-private-copy-cleanup-absence-required')
    lineage = [{'path': row['path'], 'signature': row['signature'], 'signer': row['signer'],
                'data_sha256': row['data_sha256'], 'signature_sha256': row['signature_sha256'], 'fingerprint': row['fingerprint'],
                'certificate_sha256': fresh['signer_certificates'][row['signer']]['certificate_sha256'],
                'snapshot_integrity': 'VALID', 'snapshot_authorization': 'SNAPSHOT_ONLY',
                'terminal_authorization': terminal[index]['authorization']} for index, row in enumerate(snapshot)]
    return {'schema_version': 2, 'purpose': 'accepted-repository-cryptographic-phases', 'status': 'PASS',
            'phase_request_sha256': digest(request_raw), 'phase_receipt_sha256': digest(receipt_raw), 'lineage': lineage,
            'current_A_authorization': 'REVOKED', 'snapshot_integrity': receipt['snapshot_integrity'],
            'terminal_authorization': receipt['terminal_authorization'], 'negative_verifications': receipt['negative_verifications'],
            'certificate_expiry': fresh['certificate_expiry'], 'signer_certificates': fresh['signer_certificates'],
            'original_local_certification': 'native-receipts-only', 'verification': 'independent-real-gpg-phase-recheck',
            'recheck_observed_at': fresh['observed_at'], 'recheck_completed_at': fresh['completed_at'],
            'recheck_tool_sha256': fresh['tool_sha256'], 'recheck_source_sha256': fresh['source_sha256'],
            'recheck_actual_software_environment': fresh['actual_software_environment'],
            'private_recheck_cleanup': 'PASS', 'hardware_validation': 'NOT RUN', 'production_trust': 'NOT RUN'}
