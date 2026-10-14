#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Data-only acceptance of an externally authenticated DEVELOPMENT input packet.

The authority digest must come from the coordinator, not this input directory.
Cryptography is an explicitly external attestation: this reader never executes,
signs, imports keys, installs, or promotes anything. Returned paths are observed
hash bindings; consumers must recheck the bytes they copy or execute.
"""
import hashlib
import copy
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

ORIGINALS = frozenset(('cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
                      'cachy-asahi-zsh-config', 'cachy-asahi-setup'))
PROBE = 'cachy-asahi-repository-test-fixture'
CASES = (
    ('untrusted-A-rejected', True), ('trusted-baseline-full-install', False),
    ('untrusted-rotation-B-rejected', True), ('trusted-rotation-full-upgrade', False),
    ('full-rollback-to-retained-A', False), ('tampered-package-signature-rejected', True),
    ('tampered-database-signature-rejected', True), ('missing-package-signature-rejected', True),
    ('missing-database-signature-rejected', True), ('revoked-A-repository-rejected', True),
    ('unrevoked-B-final-full-upgrade', False),
)
LABELS = ('baseline-A', 'updated-B', 'tampered-package-B', 'tampered-database-B',
          'missing-package-signature-B', 'missing-database-signature-B')
HASH = re.compile(r'[0-9a-f]{64}\Z')
PACKAGES_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
INPUTS_SHA = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
REFS = frozenset(('aggregate', 'repository', 'repository_contract', 'reset', 'public_manifest',
                  'public_acceptance', 'cleanup', 'bootstrap', 'packages', 'current_inputs',
                  'fixture_manifest', 'integration_lock', 'recipes_lock', 'projection', 'projected_repository', 'runner'))
FIELDS = frozenset(('schema_version', 'purpose', 'status', 'development_only', 'selected_for_release',
                    'run_id', 'source_commit', 'recipe_source_commit', 'nonce', 'image_id',
                    'bootstrap_sha256', 'packages_sha256', 'current_inputs_sha256',
                    'repository_source_sha256', 'integration_lock_sha256', 'recipes_lock_sha256',
                    'fixture_manifest_sha256', 'archive_role', 'files', 'refs', 'archives', 'crypto'))
LIMIT, TOTAL, COUNT = 8 * 1024**2, 64 * 1024**2, 1024
STRICT_CONFIG = ('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\n'
                 'LocalFileSigLevel = Required TrustedOnly\nParallelDownloads = 1\n'
                 '[integration]\nSigLevel = Required TrustedOnly\nServer = file:///scratch/repos/active\n').encode()
LEGACY_LOGS = {'gpg-untrusted-A-status': 'signature-untrusted-A-status',
               'gpg-tampered-package-status': 'signature-tampered-package-status',
               'gpg-tampered-database-status': 'signature-tampered-database-status',
               'gpg-revoked-A-status': 'signature-revoked-A-status',
               'revoke-A-signing-home': 'revoke-A-signing-context',
               'revoke-A-verification-home': 'revoke-A-verification-context'}
RESET = 'revoked-A-sync-cache-reset'


def operation_projection(repository, contract, base, reset, raw_prefix, projected_prefix, files, get):
    """Bind the current six legacy logs and nine exact operation copies."""
    evidence, commands = repository.get('evidence_sha256'), repository.get('commands')
    need(isinstance(evidence, dict) and 0 < len(evidence) <= 2048
         and all(isinstance(pin, str) and HASH.fullmatch(pin) for pin in evidence.values()), 'native evidence pins required')
    for name in evidence: relative(name)
    need(isinstance(commands, list) and 0 < len(commands) <= 2048, 'bounded operation commands required')
    labels = ('gpg-revoked-A-status', 'revoked-A-repository-rejected', 'inventory-' + RESET + '-before',
              'inventory-' + RESET + '-after', 'unrevoked-B-final-full-upgrade', 'dependency-consistency')
    found = {}
    for label in set(labels) | set(LEGACY_LOGS):
        matches = [(position, row) for position, row in enumerate(commands) if isinstance(row, dict) and row.get('label') == label]
        need(len(matches) == 1, 'unique complete projection commands required')
        found[label] = matches[0]
    positions = [found[label][0] for label in labels]
    need(positions == sorted(positions), 'operation command order differs')
    def raw(name, pin=None):
        need(raw_prefix + name in files and evidence.get(name) == files[raw_prefix + name]['sha256']
             and (pin is None or pin == evidence[name]), 'operation native hash binding differs')
        return get(raw_prefix + name)
    def command(label, positive=False):
        position, row = found[label]
        need(row.get('log') == f'{position:03d}-{label}.txt' and type(row.get('exit_code')) is int,
             'operation command identity differs')
        if positive:
            need(type(row.get('expected')) is int and row['expected'] == row['exit_code'] == 0
                 and row.get('positive_diagnostics') == 'PASS', 'positive operation did not pass')
        return row, raw(row['log'], row.get('sha256'))
    captures = {}
    for label, alias in LEGACY_LOGS.items():
        row, data = command(label)
        captures[row['log']] = (row['log'].split('-', 1)[0] + '-' + alias + '.txt', data)
    proof, _ = command(labels[0])
    rejection, diagnostic = command(labels[1])
    need(proof.get('expected') is None and proof['exit_code'] == 0 and rejection.get('expected') == 'nonzero'
         and rejection['exit_code'] != 0 and b'signature from "TEST ONLY disposable repository signer-A <signer-A@test.invalid>" is invalid' in diagnostic,
         'actual projection rejection policy differs')
    command(labels[4], True)
    need(repository.get('sync_cache_reset') == {'receipt': RESET + '.json', 'sha256': digest(raw(RESET + '.json'))}
         and obj(raw(RESET + '.json')) == reset and set(reset) == {'status', 'scope', 'prior_rejection_log_sha256',
             'revocation_status_log_sha256', 'removed', 'absence', 'installed_state_unchanged'}, 'exact operation reset reference differs')
    baseline = contract.get('baseline')
    need(isinstance(baseline, list) and len(baseline) == 4 and {row.get('name') for row in baseline} == ORIGINALS,
         'operation baseline authority differs')
    need(repository.get('original_inputs', {}).get('baseline') == {row['name']: {key: row[key] for key in ('sha256', 'version')} for row in baseline},
         'operation original input hashes differ')
    versions = {**base, **{row['name']: row['version'] for row in baseline}, PROBE: '1-1'}
    inventory_data = ''.join(f'{name} {versions[name]}\n' for name in sorted(versions)).encode()
    payload = {}
    for row in baseline:
        need(isinstance(row.get('payload_sha256'), dict) and row['payload_sha256'], 'operation payload authority differs')
        for name, pin in row['payload_sha256'].items():
            relative(name)
            need(name not in payload and isinstance(pin, str) and HASH.fullmatch(pin), 'operation payload hash differs')
            payload[name] = {'type': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o755 if name == 'usr/bin/cachy-asahi-setup' else 0o644, 'sha256': pin}
    payload['usr/share/cachy-asahi-repository-TEST/fixture.txt'] = {'type': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644,
                                                             'sha256': digest(b'SYNTHETIC TEST fixture version 1\n')}
    snapshot = {'inventory': inventory_data.decode(), 'files': payload}
    def matches_snapshot(data):
        value = obj(data)
        return (isinstance(value.get('files'), dict) and all(isinstance(row, dict)
                and all(type(row.get(key)) is int for key in ('uid', 'gid', 'mode')) for row in value['files'].values())
                and value == snapshot)
    need(matches_snapshot(raw('revoked-A-repository-rejected-after-snapshot.json')), 'operation baseline snapshot differs')
    operations = {}
    for phase in ('before', 'after'):
        row, data = command('inventory-' + RESET + '-' + phase, True)
        stderr = row['log'][:-4] + '-stderr.txt'
        need(data == inventory_data and row.get('stderr_log') == stderr and raw(stderr, row.get('stderr_sha256')) == b'', 'operation inventory or stderr differs')
        prefix = row['log'].split('-', 1)[0] + '-inventory-revoked-A-sync-reset-' + phase
        operations[row['log']], operations[stderr] = (prefix + '.txt', data), (prefix + '-stderr.txt', b'')
        name = RESET + '-' + phase + '-snapshot.json'
        data = raw(name)
        need(matches_snapshot(data), 'operation reset snapshot differs')
        operations[name] = ('revoked-A-sync-reset-' + phase + '-snapshot.json', data)
    row, data = command('dependency-consistency', True)
    stderr = row['log'][:-4] + '-stderr.txt'
    need(data == b'No database errors have been found!\n' and row.get('stderr_log') == stderr
         and raw(stderr, row.get('stderr_sha256')) == b'', 'operation relation diagnostic differs')
    prefix = row['log'].split('-', 1)[0] + '-installed-relation-check'
    operations[row['log']], operations[stderr] = (prefix + '.txt', data), (prefix + '-stderr.txt', b'')
    operations[RESET + '.json'] = ('revoked-A-sync-reset.json', raw(RESET + '.json'))
    index = {'schema_version': 1, 'purpose': 'validated-repository-operation-aliases', 'generic_content_guard': 'UNCHANGED',
             'original_bytes_preserved': True, 'files': {name: {'public_path': alias, 'original_sha256': digest(data),
                         'public_sha256': digest(data), 'bytes': len(data)} for name, (alias, data) in operations.items()}}
    need(projected_prefix + 'repository-operation-aliases.json' in files, 'operation index required')
    observed = obj(get(projected_prefix + 'repository-operation-aliases.json'))
    need(type(observed.get('schema_version')) is int and observed.get('original_bytes_preserved') is True
         and isinstance(observed.get('files'), dict) and all(isinstance(row, dict) and type(row.get('bytes')) is int for row in observed['files'].values())
         and observed == index,
         'exact operation index differs')
    captures.update(operations)
    for name, (alias, data) in captures.items():
        need(projected_prefix + alias in files and get(projected_prefix + alias) == data, 'projected operation bytes differ')
    return {name: alias for name, (alias, _) in captures.items()}


class Refused(ValueError):
    """Public-safe reason; untrusted input contents never enter diagnostics."""


def need(value, reason):
    if not value:
        raise Refused(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def obj(data):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    try:
        value = json.loads(data, object_pairs_hook=pairs,
                           parse_constant=lambda _: need(False, 'nonfinite JSON'))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise Refused('invalid bounded JSON') from None
    need(isinstance(value, dict), 'JSON object required')
    return value


def relative(name):
    need(isinstance(name, str) and 0 < len(name) <= 256 and
         re.fullmatch(r'[A-Za-z0-9_./+:-]+', name), 'invalid input path')
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name and
         all(part not in ('', '.', '..') for part in name.split('/')), 'unsafe input path')
    return path


def identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
                                               'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path, limit=LIMIT):
    """Walk all ancestors through no-follow dirfds; detect a replaced read path."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute safe input path required')
    dirs, fd = [], None
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        dirs.append(os.open('/', flags))
        for part in path.parts[1:-1]:
            dirs.append(os.open(part, flags, dir_fd=dirs[-1]))
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirs[-1])
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
             'bounded single-link regular input required')
        data = bytearray()
        while chunk := os.read(fd, min(65536, limit + 1 - len(data))):
            data.extend(chunk)
            need(len(data) <= limit, 'input byte bound')
        need(identity(before) == identity(os.fstat(fd)) and len(data) == before.st_size, 'input changed while reading')
        # A held fd is not proof that the current path still identifies that file.
        need(identity(before) == identity(path.lstat()) and
             not any(p.is_symlink() for p in path.parents), 'input path changed while reading')
        return bytes(data), identity(before)
    except OSError:
        raise Refused('missing or unsafe input file') from None
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(dirs):
            os.close(item)


def case_rows(rows):
    need(isinstance(rows, list) and len(rows) == len(CASES), 'all eleven repository cases required')
    for row, (name, negative) in zip(rows, CASES):
        fields = {'name', 'result', 'expected_signature_rejection'}
        if name == 'missing-database-signature-rejected':
            fields.add('rejection_contract')
            proof = row.get('rejection_contract', {}) if isinstance(row, dict) else {}
            need(isinstance(proof, dict) and proof.get('kind') == 'missing-required-local-database-signature'
                 and proof.get('missing') == ['integration.db.sig', 'integration.db.tar.gz.sig'], 'typed missing database proof required')
        need(isinstance(row, dict) and set(row) == fields and row.get('name') == name
             and row.get('result') == 'PASS' and row.get('expected_signature_rejection') is negative,
             'repository case order, result or boolean differs')


def inventory(data):
    try:
        lines = data.decode('ascii').splitlines(keepends=True)
    except UnicodeError:
        raise Refused('invalid builder inventory') from None
    need(len(lines) == 341 and lines == sorted(lines), 'complete sorted 341-package inventory required')
    rows = {}
    for line in lines:
        need(re.fullmatch(r'[a-z0-9][a-z0-9@._+-]{0,127} [A-Za-z0-9][A-Za-z0-9._+:~-]{0,255}\n', line), 'invalid inventory row')
        name, version = line[:-1].split(' ')
        need(name not in rows, 'duplicate inventory package')
        rows[name] = version
    return rows


def tree(root, expected):
    """Bound traversal; only declared files and their finite ancestors exist."""
    directories = {p.as_posix() for name in expected for p in relative(name).parents if p.as_posix() != '.'}
    found, visited = set(), 0
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    dirs = []
    def directory_id(info):
        return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid
    def visit(fd, prefix=''):
        nonlocal visited
        with os.scandir(fd) as items:
            for entry in items:
                visited += 1
                need(visited <= 4096, 'input tree bound')
                name = prefix + entry.name
                relative(name)
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    need(name in directories, 'undeclared input directory')
                    child = os.open(entry.name, flags, dir_fd=fd)
                    try:
                        need(directory_id(info) == directory_id(os.fstat(child)), 'input directory changed')
                        visit(child, name + '/')
                        need(directory_id(info) == directory_id(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)),
                             'input directory path changed')
                    finally:
                        os.close(child)
                else:
                    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and name in expected, 'undeclared or unsafe input entry')
                    found.add(name)
    try:
        need(root.is_absolute() and '..' not in root.parts and
             all(stat.S_ISDIR(p.lstat().st_mode) for p in (root, *root.parents)), 'real input directories required')
        dirs.append(os.open('/', flags))
        for part in root.parts[1:]:
            dirs.append(os.open(part, flags, dir_fd=dirs[-1]))
        initial = directory_id(os.fstat(dirs[-1]))
        visit(dirs[-1])
        need(initial == directory_id(root.lstat()) and not any(p.is_symlink() for p in root.parents),
             'input tree root changed')
    except OSError:
        raise Refused('unsafe input tree') from None
    finally:
        for fd in reversed(dirs):
            os.close(fd)
    need(found == set(expected), 'complete input file map required')


def public_files(manifest, authority, loaded):
    need(set(manifest) == {'development_only', 'selected_for_release', 'production_credentials_used', 'files',
                          'source_commit', 'purpose', 'cases', 'expected_negative_cases_retained'}
         and manifest['purpose'] == 'TEST-ONLY-offline-repository-case-verification'
         and manifest['source_commit'] == authority['source_commit'] and manifest['development_only'] is True
         and manifest['selected_for_release'] is False and manifest['production_credentials_used'] is False
         and manifest['expected_negative_cases_retained'] is True, 'public repository manifest scope differs')
    case_rows(manifest['cases'])
    files = manifest['files']
    prefix = str(relative(authority['refs']['public_manifest']).parent)
    prefix = '' if prefix == '.' else prefix + '/'
    need(isinstance(files, dict) and 0 < len(files) <= 512, 'complete finite public map required')
    for name, row in files.items():
        relative(name)
        need(prefix + name in loaded and authority['files'][prefix + name] == row, 'public export file binding differs')
    return prefix, files


def accept(root: Path, authority_raw: bytes, authority_sha256: str) -> dict:
    """Accept a SHA-pinned external authority and observed bytes, without execution."""
    try:
        return _accept(root, authority_raw, authority_sha256)
    except (KeyError, TypeError, AttributeError, OverflowError, RecursionError, UnicodeError):
        raise Refused('invalid acceptance evidence structure') from None


def _accept(root, authority_raw, authority_sha256):
    need(isinstance(authority_raw, bytes) and 0 < len(authority_raw) <= 4 * 1024**2 and
         isinstance(authority_sha256, str) and HASH.fullmatch(authority_sha256)
         and digest(authority_raw) == authority_sha256, 'external authority hash required')
    a = obj(authority_raw)
    need(set(a) == FIELDS and type(a['schema_version']) is int and a['schema_version'] == 1
         and a['purpose'] == 'accepted-repository-client-inputs' and a['status'] == 'PASS'
         and a['development_only'] is True and a['selected_for_release'] is False, 'accepted development authority required')
    for key, pattern in {'run_id': r'[1-9][0-9]{0,19}', 'source_commit': r'[0-9a-f]{40}',
                         'recipe_source_commit': r'[0-9a-f]{40}', 'nonce': r'[0-9a-f]{32}',
                         'image_id': r'sha256:[0-9a-f]{64}'}.items():
        need(isinstance(a[key], str) and re.fullmatch(pattern, a[key]), 'invalid accepted identity')
    for key in ('bootstrap_sha256', 'packages_sha256', 'current_inputs_sha256', 'repository_source_sha256',
                'integration_lock_sha256', 'recipes_lock_sha256', 'fixture_manifest_sha256'):
        need(isinstance(a[key], str) and HASH.fullmatch(a[key]), 'complete input pins required')
    need(a['packages_sha256'] == PACKAGES_SHA and a['current_inputs_sha256'] == INPUTS_SHA
         and a['archive_role'] in {'baseline', 'updated'}, 'accepted builder or archive role differs')
    refs, files, root = a['refs'], a['files'], Path(root).absolute()
    need(isinstance(refs, dict) and set(refs) == REFS and len(set(refs.values())) == len(REFS), 'complete distinct evidence references required')
    need(isinstance(files, dict) and 0 < len(files) <= COUNT, 'bounded input map required')
    for name, row in files.items():
        relative(name)
        need(isinstance(row, dict) and set(row) == {'sha256', 'bytes'} and isinstance(row['sha256'], str)
             and HASH.fullmatch(row['sha256']) and type(row['bytes']) is int and 0 <= row['bytes'] <= LIMIT,
             'invalid input map entry')
    need(all(isinstance(v, str) and v in files for v in refs.values()), 'referenced evidence missing from map')
    tree(root, files)
    loaded, identities, total = {}, {}, 0
    def get(name):
        nonlocal total
        if name not in loaded:
            data, observed = read(root / name)
            row = files[name]
            need(len(data) == row['bytes'] and digest(data) == row['sha256'], 'input map drift')
            total += len(data)
            need(total <= TOTAL, 'total input byte bound')
            loaded[name], identities[name] = data, observed
        return loaded[name]
    def record(role): return obj(get(refs[role]))
    # Reject an actual failed aggregate before reading archives or accepting crypto.
    aggregate = record('aggregate')
    need(type(aggregate.get('schema_version')) is int and aggregate['schema_version'] == 1
         and aggregate.get('purpose') == 'frozen-development-only-native-integration'
         and aggregate.get('status') == 'PASS' and aggregate.get('source_commit') == a['source_commit']
         and aggregate.get('base_image') == a['image_id'] and aggregate.get('development_only') is True
         and aggregate.get('selected_for_release') is False
         and aggregate.get('cancelled') is False
         and aggregate.get('hardware_validation') == aggregate.get('production_trust') == 'NOT RUN'
         and aggregate.get('owned_image_cleanup', {}).get('status') == 'PASS'
         and aggregate.get('owned_image_cleanup', {}).get('absence_verified') is True
         and aggregate.get('owned_image_cleanup', {}).get('cleanup_uncertain') is False
         and all(aggregate.get('stages', {}).get(name, {}).get('status') == 'PASS' for name in
                 ('fixtures', 'signer', 'lifecycle', 'repository', 'onboarding', 'desktop', 'source-suites')),
         'terminal aggregate PASS required')
    repository = record('repository')
    need(repository.get('status') == 'PASS' and repository.get('purpose') == 'disposable-generic-repository-test'
         and repository.get('source_commit') == a['source_commit'] and repository.get('test_private_state_removed') is True
         and repository.get('published') is False and repository.get('hardware_validation') == 'NOT RUN'
         and repository.get('stable_promotion') == 'NOT RUN', 'complete development repository PASS required')
    case_rows(repository.get('cases'))
    privileges = repository.get('guard', {}).get('privileges', {})
    need(all(type(privileges.get(name)) is int and privileges[name] == 0x400cb for name in ('CapEff', 'CapPrm', 'CapBnd'))
         and all(type(privileges.get(name)) is int and privileges[name] == value
                 for name, value in (('CapInh', 0), ('CapAmb', 0), ('NoNewPrivs', 1)))
         and repository.get('guard', {}).get('interfaces') == ['lo']
         and repository.get('guard', {}).get('docker_marker') is True
         and repository.get('environment', {}).get('architecture') == 'aarch64'
         and repository.get('environment', {}).get('execution') == 'native-disposable-container'
         and type(repository.get('environment', {}).get('uid')) is int
         and repository['environment']['uid'] == 0, 'actual native repository guard required')
    for name in files: get(name)
    contract = record('repository_contract')
    expected = {'nonce': a['nonce'], 'image_id': a['image_id'], 'daemon_arch': 'aarch64',
                'script_sha256': a['repository_source_sha256'], 'upgrade_kind': 'synthetic-changed-package-fixtures'}
    need(contract.get('source_commit') == a['source_commit'] and contract.get('execution') == 'native-aarch64-disposable-docker'
         and contract.get('allow_system_mutation') is True and all(contract.get(k) == v for k, v in expected.items())
         and repository.get('input_contract') == expected, 'repository input identity differs')
    for role, key in (('bootstrap', 'bootstrap_sha256'), ('packages', 'packages_sha256'), ('current_inputs', 'current_inputs_sha256'),
                      ('fixture_manifest', 'fixture_manifest_sha256'), ('integration_lock', 'integration_lock_sha256'), ('recipes_lock', 'recipes_lock_sha256')):
        need(files[refs[role]]['sha256'] == a[key], 'evidence reference pin differs')
    boot, runner, source = record('bootstrap'), record('runner'), record('integration_lock')
    need(boot.get('status') == 'image-provisioned' and boot.get('image_id') == a['image_id']
         and boot.get('inputs_sha256') == INPUTS_SHA and boot.get('packages_lock_sha256') == PACKAGES_SHA, 'bootstrap identity differs')
    base = inventory(get(refs['packages']))
    need(repository.get('base_versions') == base, 'repository complete base differs from accepted lock')
    need(runner.get('commit') == a['source_commit'] and runner.get('run_id') == a['run_id']
         and runner.get('kernel', {}).get('machine') in {'aarch64', 'arm64'}
         and runner.get('docker_server_arch') in {'aarch64', 'arm64'}, 'native run identity differs')
    need(source.get('recipe_source_commit') == a['recipe_source_commit'] and source.get('recipes_sha256') == a['recipes_lock_sha256']
         and source.get('source_files', {}).get('scripts/integration/repository.py', {}).get('sha256') == a['repository_source_sha256'], 'frozen source identity differs')
    fixture = record('fixture_manifest')
    need(fixture.get('source_commit') == a['recipe_source_commit'] and fixture.get('development_only') is True
         and fixture.get('selected_for_release') is False and set(fixture.get('packages', {})) == ORIGINALS
         and fixture.get('frozen_lock_sha256') == a['recipes_lock_sha256']
         and source.get('generated_fixture_files', {}).get('fixture-manifest.json', {}).get('sha256') == a['fixture_manifest_sha256'],
         'fixture source identity differs')
    cleanup = record('cleanup')
    need(cleanup.get('status') == 'PASS' and cleanup.get('absence_verified') is True
         and cleanup.get('container') == 'cachy-asahi-repository-' + a['nonce']
         and isinstance(cleanup.get('container_id'), str) and re.fullmatch(r'[0-9a-f]{64}', cleanup['container_id'])
         and cleanup.get('name_absence_verified') is True and cleanup.get('id_absence_verified') is True,
         'owned container name and ID absence required')
    reset = record('reset')
    need(reset.get('status') == 'PASS' and reset.get('absence') == 'PASS' and reset.get('installed_state_unchanged') is True
         and reset.get('scope') == 'two private copied-root sync files after revoked-A rejection'
         and set(reset.get('removed', {})) == {'integration.db', 'integration.db.sig'}
         and repository.get('sync_cache_reset', {}).get('sha256') == files[refs['reset']]['sha256']
         and repository.get('sync_cache_reset', {}).get('receipt') == Path(refs['reset']).name, 'verified cache reset required')
    projection = record('projection')
    need(projection.get('purpose') == 'validated-repository-inventory-projection' and projection.get('status_preserved') == 'PASS'
         and projection.get('package_count') == len(base) and projection.get('generic_content_guard') == 'UNCHANGED'
         and projection.get('original_sha256') == files[refs['repository']]['sha256']
         and projection.get('original_bytes') == files[refs['repository']]['bytes']
         and projection.get('projected_sha256') == files[refs['projected_repository']]['sha256']
         and projection.get('projected_bytes') == files[refs['projected_repository']]['bytes'], 'raw repository projection binding differs')
    projected = copy.deepcopy(repository)
    projected['base_versions'] = [{'name': name, 'version': base[name]} for name in sorted(base)]
    raw_prefix = str(relative(refs['repository']).parent)
    raw_prefix = '' if raw_prefix == '.' else raw_prefix + '/'
    projected_prefix = str(relative(refs['projected_repository']).parent)
    projected_prefix = '' if projected_prefix == '.' else projected_prefix + '/'
    aliases = operation_projection(repository, contract, base, reset, raw_prefix, projected_prefix, files, get)
    for row in projected.get('commands', []):
        if row.get('log') in aliases:
            row['public_log'] = aliases[row['log']]
        if row.get('stderr_log') in aliases:
            row['public_stderr_log'] = aliases[row['stderr_log']]
        if 'argv' in row:
            row['argv_sha256'] = digest(json.dumps(row.pop('argv'), sort_keys=True).encode())
    projected['sync_cache_reset']['public_receipt'] = 'revoked-A-sync-reset.json'
    projected['public_operation_index'] = 'repository-operation-aliases.json'
    need(projected == record('projected_repository'), 'unknown repository projection change')
    rows_by_role = {}
    for phase in ('baseline', 'upgrade'):
        rows = contract.get(phase)
        need(isinstance(rows, list) and len(rows) == 4 and {r.get('name') for r in rows} == ORIGINALS, 'complete original input roles required')
        rows_by_role[phase] = {r['name']: r for r in rows}
        for row in rows:
            need(isinstance(row.get('version'), str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+:~-]{0,255}', row['version'])
                 and isinstance(row.get('sha256'), str) and HASH.fullmatch(row['sha256'])
                 and isinstance(row.get('payload_sha256'), dict) and row['payload_sha256'], 'native archive input binding differs')
            metadata = fixture['packages'][row['name']]
            need(row['version'] == metadata['base_version' if phase == 'baseline' else 'upgrade_version'], 'fixture version differs')
    raw_prefix = str(relative(refs['repository']).parent)
    raw_prefix = '' if raw_prefix == '.' else raw_prefix + '/'
    commands = repository.get('commands')
    need(isinstance(commands, list) and 0 < len(commands) <= 2048, 'bounded raw command evidence required')
    command_logs = set()
    for row in commands:
        need(isinstance(row, dict) and isinstance(row.get('label'), str)
             and isinstance(row.get('log'), str) and re.fullmatch(r'[0-9]{3,4}-[A-Za-z0-9_-]+\.txt', row['log'])
             and row['log'] not in command_logs and raw_prefix + row['log'] in files
             and files[raw_prefix + row['log']]['sha256'] == row.get('sha256'), 'raw command file binding differs')
        command_logs.add(row['log'])
        need(('stderr_log' in row) == ('stderr_sha256' in row), 'paired stderr binding required')
        if 'stderr_log' in row:
            relative(row['stderr_log'])
            need(raw_prefix + row['stderr_log'] in files and files[raw_prefix + row['stderr_log']]['sha256'] == row['stderr_sha256'],
                 'raw stderr binding differs')
        if row.get('positive_diagnostics') == 'PASS':
            need(type(row.get('exit_code')) is int and type(row.get('expected')) is int
                 and row['exit_code'] == row['expected'] == 0, 'positive diagnostic command policy differs')
            diagnostics = [get(raw_prefix + row['log']).decode('utf-8', errors='replace')]
            if 'stderr_log' in row: diagnostics.append(get(raw_prefix + row['stderr_log']).decode('utf-8', errors='replace'))
            need(all(re.search(r'^(?:error\s*:|could not change (?:the root directory|directory)\b)', stream, re.I | re.M) is None for stream in diagnostics),
                 'positive raw diagnostics contain execution error')
    for label, reset_key in (('revoked-A-repository-rejected', 'prior_rejection_log_sha256'),
                             ('gpg-revoked-A-status', 'revocation_status_log_sha256')):
        logs = [row for row in repository.get('commands', []) if row.get('label') == label]
        need(len(logs) == 1, 'unique reset rejection evidence required')
        row = logs[0]
        need(reset.get(reset_key) == row.get('sha256') and raw_prefix + row['log'] in files
             and files[raw_prefix + row['log']]['sha256'] == row['sha256'], 'reset rejection log binding differs')
        if label == 'gpg-revoked-A-status':
            fingerprint = repository.get('public_TEST_identities', {}).get('signer-A', {}).get('fingerprint', '')
            text = get(raw_prefix + row['log']).decode('utf-8')
            need(re.fullmatch(r'[0-9A-F]{40}', fingerprint) and '[GNUPG:] REVKEYSIG ' + fingerprint[-16:] + ' ' in text
                 and '[GNUPG:] VALIDSIG ' + fingerprint + ' ' in text, 'revoked-A fingerprint evidence differs')
    cache_before = obj(get(raw_prefix + 'revoked-A-sync-cache-reset-before-snapshot.json'))
    cache_after = obj(get(raw_prefix + 'revoked-A-sync-cache-reset-after-snapshot.json'))
    need(cache_before == cache_after == obj(get(raw_prefix + 'revoked-A-repository-rejected-after-snapshot.json')),
         'cache reset installed snapshot differs')
    owned = {name for rows in rows_by_role.values() for row in rows.values() for name in row['payload_sha256']}
    probe_path = 'usr/share/cachy-asahi-repository-TEST/fixture.txt'
    owned.add(probe_path)
    state_role, previous = None, None
    for case, negative in CASES:
        command_rows = [r for r in repository.get('commands', []) if r.get('label') == case]
        need(len(command_rows) == 1, 'unique actual transaction command required')
        command = command_rows[0]
        need(type(command.get('exit_code')) is int and (command['exit_code'] != 0 if negative else command['exit_code'] == 0)
             and (command.get('expected') == 'nonzero' if negative else type(command.get('expected')) is int and command['expected'] == 0)
             and (negative or command.get('positive_diagnostics') == 'PASS'), 'transaction exit or diagnostic acceptance differs')
        relative(command['log'])
        need(raw_prefix + command['log'] in files and files[raw_prefix + command['log']]['sha256'] == command['sha256'], 'transaction raw log binding differs')
        if negative:
            diagnostic = get(raw_prefix + command['log']).decode('utf-8', errors='replace')
            if case == 'missing-database-signature-rejected':
                pattern = (r':: Synchronizing package databases\.\.\.\n integration downloading\.\.\.\n'
                           r"error: failed retrieving file 'integration\.db\.sig' from disk[ ]*: Could not open file "
                           r'/scratch/repos/active/integration\.db\.sig\nerror: failed to synchronize all databases \(download library error\)\n')
                need(command.get('signature_rejection_kind') == 'missing-required-local-database-signature'
                     and re.fullmatch(pattern, diagnostic), 'exact local missing database diagnostic required')
            else:
                need(re.search(r'(signature|public key|unknown trust|untrusted|revoked)', diagnostic, re.I),
                     'negative raw diagnostic lacks signature or trust rejection')
        before = obj(get(raw_prefix + case + '-before-snapshot.json'))
        after = obj(get(raw_prefix + case + '-after-snapshot.json'))
        need(set(before) == set(after) == {'inventory', 'files'} and set(before['files']) == set(after['files']) == owned,
             'complete owned snapshot required')
        if previous is None:
            need(before['inventory'] == ''.join(f'{name} {base[name]}\n' for name in sorted(base))
                 and all(isinstance(row, dict) and row.get('type') == 'missing'
                         and set(row) in ({'type'}, {'type', 'missing_parent'})
                         and ('missing_parent' not in row or relative(row['missing_parent']) in relative(name).parents)
                         for name, row in before['files'].items()), 'initial copied root differs')
        else:
            need(before == previous, 'transaction snapshot chain differs')
        if negative:
            need(before == after, 'negative transaction changed inventory or payload')
        else:
            state_role = 'baseline' if case in ('trusted-baseline-full-install', 'full-rollback-to-retained-A') else 'upgrade'
        desired = dict(base)
        if state_role is not None:
            desired.update({name: row['version'] for name, row in rows_by_role[state_role].items()})
            desired[PROBE] = '1-1' if state_role == 'baseline' else '2-1'
        need(after['inventory'] == ''.join(f'{name} {desired[name]}\n' for name in sorted(desired)), 'complete transaction inventory differs')
        if state_role is not None:
            hashes = {name: pin for row in rows_by_role[state_role].values() for name, pin in row['payload_sha256'].items()}
            hashes[probe_path] = digest(f'SYNTHETIC TEST fixture version {1 if state_role == "baseline" else 2}\n'.encode())
            for name, pin in hashes.items():
                need(after['files'][name].get('type') == 'regular' and after['files'][name].get('sha256') == pin, 'transaction payload differs')
        previous = after
    acceptance = record('public_acceptance')
    need(acceptance.get('status') == 'PASS' and acceptance.get('source_commit') == a['source_commit']
         and acceptance.get('run_id') == a['run_id'] and acceptance.get('nonce') == a['nonce']
         and acceptance.get('purpose') == 'accepted-repository-public-artifacts'
         and acceptance.get('manifest_sha256') == files[refs['public_manifest']]['sha256'], 'external public acceptance binding differs')
    prefix, public = public_files(record('public_manifest'), a, loaded)
    expected_public = {'TEST-signer-A-public.asc', 'TEST-signer-B-public.asc', 'TEST-verifier-public.asc',
                       'TEST-signer-A-revoked-public.asc', 'TEST-repository-aliases.json', 'TEST-repository-aliases.json.sig', 'TEST-pacman.conf'}
    expected_aliases = {'active': {'target': 'updated-B', 'kind': 'directory'}}
    for case_label in LABELS:
        phase = 'baseline' if case_label == 'baseline-A' else 'upgrade'
        package_names = {PurePosixPath(r['archive']).name for r in rows_by_role[phase].values()}
        package_names.add(PROBE + ('-1-1-any.pkg.tar.xz' if phase == 'baseline' else '-2-1-any.pkg.tar.xz'))
        names = package_names | {n + '.sig' for n in package_names} | {'integration.db.tar.gz', 'integration.db.tar.gz.sig',
                  'integration.files.tar.gz', 'integration.files.tar.gz.sig', 'integration.db', 'integration.db.sig', 'integration.files', 'integration.files.sig'}
        if case_label == 'missing-package-signature-B': names.remove(PROBE + '-2-1-any.pkg.tar.xz.sig')
        if case_label == 'missing-database-signature-B': names -= {'integration.db.tar.gz.sig', 'integration.db.sig'}
        expected_public.update('TEST-repositories/' + case_label + '/' + n for n in names)
        for alias, target in {'integration.db': 'integration.db.tar.gz', 'integration.db.sig': 'integration.db.tar.gz.sig',
                              'integration.files': 'integration.files.tar.gz', 'integration.files.sig': 'integration.files.tar.gz.sig'}.items():
            if alias not in names: continue
            first, second = 'TEST-repositories/' + case_label + '/' + alias, 'TEST-repositories/' + case_label + '/' + target
            need(public.get(first) == public.get(second), 'regular alias copy differs from target')
            expected_aliases[case_label + '/' + alias] = {'target': case_label + '/' + target, 'kind': 'file', 'regular_copy_sha256': public[first]['sha256']}
        for row in rows_by_role[phase].values():
            need(public.get('TEST-repositories/' + case_label + '/' + PurePosixPath(row['archive']).name, {}).get('sha256') == row['sha256'], 'repository original archive differs')
    need(set(public) == expected_public, 'exact six repository exports required')
    need(loaded[prefix + 'TEST-pacman.conf'] == STRICT_CONFIG, 'strict public pacman configuration required')
    need(obj(loaded[prefix + 'TEST-repository-aliases.json']) == expected_aliases, 'complete alias map differs')
    need(repository['evidence_sha256'].get('TEST-repository-aliases.json') == public['TEST-repository-aliases.json']['sha256'],
         'native alias map evidence binding differs')
    need(repository.get('final_sync_cache') == {name: public['TEST-repositories/updated-B/' + target]['sha256']
         for name, target in (('integration.db', 'integration.db.tar.gz'), ('integration.db.sig', 'integration.db.tar.gz.sig'))}, 'healthy final cache differs')
    need(reset['removed'] == {name: public['TEST-repositories/baseline-A/' + target]['sha256']
         for name, target in (('integration.db', 'integration.db.tar.gz'), ('integration.db.sig', 'integration.db.tar.gz.sig'))}, 'reset bytes differ from retained A')
    roles, pairs = {}, []
    certs = {'signer-A': 'TEST-signer-A-public.asc', 'signer-B': 'TEST-signer-B-public.asc', 'verifier': 'TEST-verifier-public.asc'}
    for role, name in certs.items():
        row = repository.get('public_TEST_identities', {}).get(role, {})
        need(isinstance(row.get('fingerprint'), str) and re.fullmatch(r'[0-9A-F]{40}', row['fingerprint'])
             and name in public and row.get('public_sha256') == public[name]['sha256'], 'public signer binding differs')
        roles[role] = {'fingerprint': row['fingerprint'], 'certificate': prefix + name}
    need(len({r['fingerprint'] for r in roles.values()}) == 3, 'distinct signer roles required')
    archives = a['archives']
    need(isinstance(archives, list) and len(archives) == 4 and all(isinstance(r, dict) for r in archives), 'exact four archives required')
    names, accepted = set(), []
    label, phase, signer = ('baseline-A', 'baseline', 'signer-A') if a['archive_role'] == 'baseline' else ('updated-B', 'upgrade', 'signer-B')
    rows = contract.get(phase, [])
    need(isinstance(rows, list) and len(rows) == 4 and {r.get('name') for r in rows} == ORIGINALS, 'complete original input roles required')
    for row in archives:
        need(set(row) in ({'name', 'path', 'version', 'sha256', 'bytes'}, {'name', 'path', 'version', 'sha256', 'bytes', 'provenance_ref'})
             and row.get('name') in ORIGINALS and row['name'] not in names, 'unknown or duplicate archive')
        names.add(row['name'])
        name = 'TEST-repositories/' + label + '/' + PurePosixPath(row['path']).name
        need(row['path'] == prefix + name and name in public and files[row['path']] == {k: row[k] for k in ('sha256', 'bytes')}
             and re.fullmatch(re.escape(row['name']) + '-' + re.escape(row['version']) + r'-any\.pkg\.tar\.(xz|gz|zst)', PurePosixPath(row['path']).name), 'archive identity differs')
        authority = next(r for r in rows if r['name'] == row['name'])
        need(authority.get('version') == row['version'] and authority.get('sha256') == row['sha256'], 'archive differs from native input role')
        if 'provenance_ref' in row: need(row['provenance_ref'] in files, 'archive provenance reference missing')
        accepted.append({**row, 'path': str(root / row['path']), 'original_signer': roles[signer]['fingerprint'],
                         'original_signature_sha256': files[row['path'] + '.sig']['sha256']})
    for case_label, role in (('baseline-A', 'signer-A'), ('updated-B', 'signer-B')):
        artifacts = [name for name in public if name.startswith('TEST-repositories/' + case_label + '/')
                     and (re.fullmatch(r'integration\.(db|files)\.tar\.(gz|xz|zst)', PurePosixPath(name).name)
                          or re.search(r'\.pkg\.tar\.(xz|gz|zst)$', name))]
        need(len(artifacts) == 7, 'five packages and two signed databases required')
        for name in artifacts:
            need(name + '.sig' in public, 'positive artifact signature missing')
            pairs.append({'path': prefix + name, 'signature': prefix + name + '.sig', 'signer': role, 'status': 'VALID'})
    need('TEST-repository-aliases.json' in public and 'TEST-repository-aliases.json.sig' in public
         and 'TEST-signer-A-revoked-public.asc' in public, 'signed aliases and revoked certificate required')
    pairs.append({'path': prefix + 'TEST-repository-aliases.json', 'signature': prefix + 'TEST-repository-aliases.json.sig', 'signer': 'signer-B', 'status': 'VALID'})
    crypto = a['crypto']
    need(isinstance(crypto, dict) and set(crypto) == {'purpose', 'status', 'boundary', 'source_commit', 'run_id', 'nonce',
           'image_id', 'artifact_map_sha256', 'signers', 'cases', 'signed_objects', 'revocation', 'original_local_certification'}
         and crypto['purpose'] == 'external-repository-cryptographic-acceptance' and crypto['status'] == 'PASS'
         and crypto['boundary'] == 'external-attestation-only' and crypto['original_local_certification'] == 'native-receipts-only'
         and all(crypto[k] == a[k] for k in ('source_commit', 'run_id', 'nonce', 'image_id'))
         and crypto['artifact_map_sha256'] == digest(canonical(public)) and crypto['signers'] == roles
         and crypto['cases'] == [{'name': n, 'status': 'PASS', 'expected_signature_rejection': negative} for n, negative in CASES]
         and crypto['signed_objects'] == sorted(pairs, key=lambda r: r['path'])
         and crypto['revocation'] == {'signer': 'signer-A', 'fingerprint': roles['signer-A']['fingerprint'], 'status': 'REVOKED',
                                      'certificate': prefix + 'TEST-signer-A-revoked-public.asc'}, 'complete externally accepted crypto attestation required')
    need(all(row['expected_signature_rejection'] is negative for row, (_, negative) in zip(crypto['cases'], CASES)), 'crypto case booleans differ')
    tree(root, files)
    for name, observed in identities.items():
        _, now = read(root / name)
        need(now == observed, 'input path changed before acceptance')
    return {'status': 'PASS-input-acceptance', 'development_only': True, 'selected_for_release': False,
            'source_commit': a['source_commit'], 'run_id': a['run_id'], 'nonce': a['nonce'], 'image_id': a['image_id'],
            'authority_sha256': authority_sha256, 'archive_role': a['archive_role'], 'archives': accepted,
            'base_versions': [{'name': name, 'version': base[name]} for name in sorted(base)],
            'signer_roles': {role: {**row, 'certificate_sha256': files[row['certificate']]['sha256']}
                             for role, row in roles.items()},
            'lineage': [{**row, 'data_sha256': files[row['path']]['sha256'],
                         'signature_sha256': files[row['signature']]['sha256']} for row in crypto['signed_objects']],
            'crypto_verification': 'external-attestation-only',
            'original_local_certification': 'native-receipts-only', 'consumers_recheck_required': True}
