#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Policy-selected offline detached-signature authentication and pristine staging.

No downloads, signing, system keyring, package transaction, scripts or mounts.
The operator policy is an external trust input, not independent owner approval.
"""
import argparse
import ast
import base64
import copy
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'operator-policy-offline-signed-pristine-v1'
SELECTION = 'EXACT_LOCAL_SIGNED_ARCHIVE_SELECTION_V1'
STATUS = 'PASS_POLICY_SIGNED_ARCHIVES_TO_PRISTINE_STAGING'
MAX_PACKAGES = 4096
MAX_JSON = 16*1024**2
FP = re.compile(r'(?:[0-9A-F]{40}|[0-9A-F]{64})\Z')
HEX = re.compile(r'[0-9a-f]{64}\Z')
PINS = {
    'intake': ('scripts/platform/archive_intake.py', 'dfc6e2d429b654359075bd135969c5948b12dd81db67f522ae46e1be61911a67'),
    'client': ('scripts/client/client.py', '48f936fc28536f8d5c2cac25c77ddb591b6bd029062d4b4fe2ce901533e8fdb7'),
    'public': ('scripts/release/offline_kit.py', '8f9cdb4ad26525fb1c4c906a752f56e8115a3c39b8aa758dd86dca7d032f54b3'),
    'owned': ('scripts/virtual/owned_process.py', '83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'),
    'image_bridge': ('scripts/platform/metadata_gated_ext4.py', '467cbb9562189b79926deb9d15d9b027d7c73d2a27ba07bc01d6740941567227'),
    'verifier': ('scripts/platform/verify_staging.py', '279201558a90ea6e429822fc7d5b63827e6bd47ef022f8aef3126109bdfaa711')}
BOUNDARIES = dict(independent_owner_trust=False, source_license_closure=False,
    complete_release_set=False, dependency_transaction=False, installed_state=False,
    scriptlets=False, hooks=False, trust_bootstrap=False, native_ARM=False,
    boot=False, M2=False, release=False)


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-json-key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite-json'))


def integer(value, maximum, minimum=0):
    return type(value) is int and minimum <= value <= maximum


def read(path, maximum=MAX_JSON):
    path = Path(path).absolute()
    need(path == path.resolve(), 'noncanonical-or-symlink-input')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= maximum, 'bounded-ordinary-input')
        raw = bytearray()
        while chunk := os.read(fd, min(65536, maximum + 1 - len(raw))):
            raw.extend(chunk)
            need(len(raw) <= maximum, 'input-byte-bound')
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(len(raw) == before.st_size and all(getattr(before, k) == getattr(os.fstat(fd), k)
             == getattr(path.lstat(), k) for k in fields), 'input-drift')
        return bytes(raw)
    finally:
        os.close(fd)


def pinned(path, digest, maximum=MAX_JSON):
    need(type(digest) is str and HEX.fullmatch(digest), 'sha256-required')
    raw = read(path, maximum)
    need(sha(raw) == digest, 'input-or-source-pin')
    return raw


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def extracted(raw, name, namespace):
    """Reuse one exact pure definition; do not import actors or their dependencies."""
    matches = [node for node in ast.parse(raw).body if isinstance(node, ast.FunctionDef) and node.name == name]
    need(len(matches) == 1, 'pinned-definition-shape:' + name)
    scope = dict(namespace)
    exec(compile(ast.Module(body=matches, type_ignores=[]), '<pinned-' + name + '>', 'exec'), scope)
    return scope[name]


def sources():
    raws = {key: pinned(ROOT / path, digest) for key, (path, digest) in PINS.items()}
    modules = {}
    for key in ('intake', 'owned'):
        module = types.ModuleType('_signed_' + key)
        module.__file__ = str(ROOT / PINS[key][0])
        exec(compile(raws[key], module.__file__, 'exec'), module.__dict__)
        modules[key] = module
    modules['signature_status'] = extracted(raws['client'], 'signature_status', dict(need=need, FINGERPRINT=FP))
    modules['public_packets'] = extracted(raws['public'], 'public_packets', dict(c=types.SimpleNamespace(need=need)))
    modules['verifier_raw'] = raws['verifier']
    return modules


def public_only(raw, packet_check):
    """Accept binary public exports or strict public armor, then existing packet gate.

    Armor decoding/CRC is transport framing; signature verification stays in GPG.
    The public packet allowlist is the pinned release offline-kit implementation.
    """
    if raw.startswith(b'-----'):
        lines = raw.decode('ascii').splitlines()
        need(lines and lines[0] == '-----BEGIN PGP PUBLIC KEY BLOCK-----'
             and lines[-1] == '-----END PGP PUBLIC KEY BLOCK-----', 'public-key-armor-only')
        need('' in lines, 'public-armor-separator')
        split = lines.index('')
        need(all(re.fullmatch(r'[A-Za-z0-9-]+: [\x20-\x7e]*', row) for row in lines[1:split]), 'armor-headers')
        rows = lines[split+1:-1]
        need(len(rows) >= 2 and re.fullmatch(r'=[A-Za-z0-9+/]{4}', rows[-1])
             and all(re.fullmatch(r'[A-Za-z0-9+/]+={0,2}', row) for row in rows[:-1]), 'public-armor-body')
        body = base64.b64decode(''.join(rows[:-1]), validate=True)
        crc = 0xb704ce
        for byte in body:
            crc ^= byte << 16
            for _ in range(8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= 0x1864cfb
        need((crc & 0xffffff).to_bytes(3, 'big') == base64.b64decode(rows[-1][1:], validate=True), 'armor-crc24')
    else:
        body = raw
    packet_check(body)
    return dict(status='PUBLIC_PACKET_ALLOWLIST_ONLY_NOT_CRYPTO', decoded_sha256=sha(body), secret_packets=False)


def fingerprint_lines(raw, trusted=False):
    result = set()
    for line in raw.decode('ascii').splitlines():
        if not line or line.startswith('#'):
            continue
        parts = line.split(':')
        need(FP.fullmatch(parts[0]) and len(line) <= 4096 and parts[0] not in result,
             'fingerprint-file-format')
        if trusted:
            need(len(parts) == 3 and parts[1] in {'1', '2', '3', '4', '5', '6'} and parts[2] == '', 'trusted-file-format')
        result.add(parts[0])
    return result


def selection_check(selection, core, intake):
    need(type(selection) is dict and set(selection) == {'schema_version', 'scope', 'release_set', 'packages'}
         and type(selection['schema_version']) is int and selection['schema_version'] == 1
         and selection['scope'] == SELECTION, 'selection-schema')
    release_set = selection['release_set']
    need(release_set is None or type(release_set) is dict and set(release_set) == {'record_sha256', 'release_id'}
         and type(release_set['record_sha256']) is str and HEX.fullmatch(release_set['record_sha256'])
         and type(release_set['release_id']) is str and re.fullmatch(r'[A-Za-z0-9._+-]{1,128}', release_set['release_id']),
         'release-set-association')
    rows = selection['packages']
    need(type(rows) is list and 0 < len(rows) <= MAX_PACKAGES, 'selected-package-bound')
    names, paths, total = set(), set(), 0
    for row in rows:
        need(type(row) is dict and set(row) == {'identity', 'archive', 'signature', 'primary_fingerprint', 'metadata'}, 'selection-row')
        identity = core.package_identity(row['identity'])
        need(identity['name'] not in names and FP.fullmatch(row['primary_fingerprint']), 'duplicate-package-or-signer')
        names.add(identity['name'])
        for key, limit in [('archive', core.ARCHIVE), ('signature', 65536)]:
            ref = core.reference(row[key], limit)
            need(ref['path'] not in paths, 'duplicate-operand-path')
            paths.add(ref['path'])
        metadata = intake.normalized_metadata(core, row['metadata'])
        need({key: metadata[key] for key in ('name', 'version', 'arch')} == identity, 'metadata-tuple-binding')
        total += row['archive']['size']
    need(3*total <= core.COMPRESSED, 'aggregate-compressed-work-bound')
    return rows


def policy_check(policy, selection_raw, selection, core, intake, now):
    need(type(policy) is dict and set(policy) == {'schema_version', 'profile', 'selection_sha256', 'release_set',
         'issued', 'expires', 'signers', 'gpg', 'public_keyring', 'trusted', 'revoked'}, 'operator-policy-schema')
    need(type(policy['schema_version']) is int and policy['schema_version'] == 1 and policy['profile'] == PROFILE
         and policy['selection_sha256'] == sha(selection_raw) and policy['release_set'] == selection['release_set'], 'policy-selection-binding')
    need(integer(policy['issued'], 2**53) and integer(policy['expires'], 2**53)
         and policy['issued'] <= now < policy['expires'] and 0 < policy['expires'] - policy['issued'] <= 7*86400,
         'policy-expired-future-or-lifetime')
    signers = policy['signers']
    need(type(signers) is list and 0 < len(signers) <= 64, 'signer-bound')
    approved = {}
    for signer in signers:
        need(type(signer) is dict and set(signer) == {'primary', 'signature_not_before', 'not_after'}
             and type(signer['primary']) is str and FP.fullmatch(signer['primary'])
             and signer['primary'] not in approved and integer(signer['signature_not_before'], 2**53)
             and integer(signer['not_after'], 2**53) and signer['signature_not_before'] < now < signer['not_after'],
             'signer-policy-window')
        approved[signer['primary']] = signer
    rows = selection_check(selection, core, intake)
    need({row['primary_fingerprint'] for row in rows} <= set(approved), 'unapproved-selected-signer')
    for name in ('gpg', 'public_keyring', 'trusted', 'revoked'):
        ref = policy[name]
        need(type(ref) is dict and set(ref) == {'path', 'bytes', 'sha256'} and type(ref['path']) is str
             and Path(ref['path']).is_absolute() and integer(ref['bytes'], 32*1024**2 if name == 'gpg' else 1024**2)
             and type(ref['sha256']) is str and HEX.fullmatch(ref['sha256']), 'policy-operand-reference')
    need(policy['gpg']['bytes'] > 0 and policy['public_keyring']['bytes'] > 0, 'empty-gpg-or-public-keyring')
    need(len({policy[name]['path'] for name in ('gpg', 'public_keyring', 'trusted', 'revoked')}) == 4, 'policy-path-alias')
    return rows, approved


def input_bytes(ref):
    raw = pinned(ref['path'], ref['sha256'], max(ref['bytes'], 1))
    need(len(raw) == ref['bytes'], 'operand-size-pin')
    return raw


def reference(core, path, budget):
    with core.opened(path, budget) as (_, info):
        return dict(path=str(path), size=info.st_size, sha256=sha(read(path, info.st_size)), identity=core.identity(info))


def snapshot(core, ref, target, budget):
    """GPG and parser consume the same fresh byte snapshot, never moving inputs."""
    digest, count = hashlib.sha256(), 0
    with core.opened(ref['path'], budget, ref['identity']) as (fd, _):
        with target.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            while chunk := os.read(fd, 65536):
                budget.check(); count += len(chunk)
                need(count <= ref['size'], 'snapshot-byte-bound')
                digest.update(chunk); stream.write(chunk)
            stream.flush(); os.fsync(stream.fileno())
    need(count == ref['size'] and digest.hexdigest() == ref['sha256'], 'snapshot-input-pin')
    info = target.lstat()
    return dict(path=str(target), size=count, sha256=digest.hexdigest(), identity=core.identity(info))


def command(owned, argv, home, logs, number, deadline):
    """One prepare-before-launch transfer; child output files have inherited caps."""
    remaining = min(30.0, deadline-time.monotonic())
    need(remaining > 2.0, 'authentication-deadline')
    env = dict(PATH='/usr/bin:/bin', HOME=str(home), GNUPGHOME=str(home), LC_ALL='C', TZ='UTC')
    prefix = logs / ('%04d' % number)
    old_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
    limit = 262144 if old_limit[1] == resource.RLIM_INFINITY else min(262144, old_limit[1])
    child = None
    with Path(str(prefix)+'.stdout').open('xb') as out, Path(str(prefix)+'.stderr').open('xb') as err:
        owned.prepare()
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, old_limit[1]))
            child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                env=env, start_new_session=True)
            result = owned.supervise(child, cap=remaining, retirement=1.0, grace=0.2, group=True, streams=(), max_output=0)
        except BaseException:
            if child is not None and child.returncode is None and getattr(child, '_child_created', False):
                owned.supervise(child, cap=3.0, retirement=1.0, grace=0.0, group=True, streams=(), max_output=0)
            raise
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, old_limit)
        out.flush(); err.flush(); os.fsync(out.fileno()); os.fsync(err.fileno())
    raw_out, raw_err = read(Path(str(prefix)+'.stdout'), limit), read(Path(str(prefix)+'.stderr'), limit)
    result.pop('output')
    record = dict(argv=argv, environment=env, supervision=result, cap_seconds=remaining,
        output_file_cap=limit, stdout=dict(bytes=len(raw_out), sha256=sha(raw_out)),
        stderr=dict(bytes=len(raw_err), sha256=sha(raw_err)), owned_source_sha256=PINS['owned'][1])
    write(Path(str(prefix)+'.json'), encoded(record))
    need(result['passed'] and result['reaped'] and result['ownership'] == 'REAPED' and result['exit'] == 0,
         'gpg-command-failed:' + str(number))
    return raw_out, record


def import_status(raw, approved):
    records = [line.split()[1:] for line in raw.decode('utf-8').splitlines() if line.startswith('[GNUPG:] ')]
    need(not any(row and row[0] in {'FAILURE', 'ERROR', 'NODATA', 'BADARMOR', 'IMPORT_PROBLEM'} for row in records), 'public-import-refused')
    imports = [row for row in records if row and row[0] == 'IMPORT_OK']
    need(imports and all(len(row) == 3 and row[1].isdigit() and not int(row[1]) & 16
         and row[2] in approved for row in imports) and {row[2] for row in imports} == set(approved), 'imported-primary-closure')


def generic_prepare(bridge):
    """Explicit capacity successor: only the pinned <=261 ceiling becomes4096.

    All owner/conflict/parent/link/body checks and aggregate byte/node limits are
    unchanged. No dependency module or its live globals are modified.
    """
    tree = ast.parse(bridge.__source_bytes__)
    function = copy.deepcopy(next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'prepare'))
    matches = [n for n in ast.walk(function) if isinstance(n, ast.Compare)
               and ast.dump(n) == ast.dump(ast.parse('0 < len(expected) <= 261', mode='eval').body)]
    need(len(matches) == 1, 'capacity-adapter-source-shape')
    matches[0].comparators[-1] = ast.Constant(value=MAX_PACKAGES)
    ast.fix_missing_locations(function)
    namespace = dict(bridge.__dict__)
    exec(compile(ast.Module(body=[function], type_ignores=[]), '<explicit-package-capacity-successor>', 'exec'), namespace)
    return namespace['prepare']


def generic_verifier(raw, pending=False):
    """Keep every serialized-node/body check; distinguish the new receipt status."""
    tree = ast.parse(raw)
    matches = [node for node in ast.walk(tree) if isinstance(node, ast.Constant)
               and node.value == 'PASS_EXACT_SELECTED_ARCHIVES_TO_STAGING_ONLY']
    need(len(matches) == 1, 'verifier-status-source-shape')
    matches[0].value = STATUS
    if pending:
        receipts = [node for node in ast.walk(tree) if isinstance(node, ast.Constant) and node.value == 'receipt.json']
        markers = [node for node in ast.walk(tree) if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not)
                   and ast.dump(node) == ast.dump(ast.parse("not (directory / 'INCOMPLETE.json').exists()", mode='eval').body)]
        need(len(receipts) == len(markers) == 1, 'pending-verifier-source-shape')
        receipts[0].value = 'verification-input.json'
        # A pending verifier requires the caller's marker instead of accepting a
        # completed receipt. Every tar/node/ownership/body check stays unchanged.
        markers[0].operand = ast.UnaryOp(op=ast.Not(), operand=markers[0].operand)
    module = types.ModuleType('_policy_signed_staging_verifier')
    module.__file__ = str(ROOT / PINS['verifier'][0])
    exec(compile(ast.fix_missing_locations(tree), module.__file__, 'exec'), module.__dict__)
    return module.verify


@contextmanager
def prepared(selection, policy, parent, seconds=180):
    """Fresh real authority plus inherited closed spool maps, valid in context only."""
    need(type(seconds) is int and 3 <= seconds <= 180, 'total-time-bound')
    original_selection, original_policy = encoded(selection), encoded(policy)
    services = sources()
    with services['intake'].runtime(parent) as engine:
        source_policy = engine.load(engine.RUNTIME / 'policy.py', engine.POLICY_SHA)
        admission = engine.load(engine.RUNTIME / 'real_admission.py', engine.ADMISSION_SHA)
        with source_policy.snapshot() as (raws, check):
            modules = source_policy.sources(raws)
            core, intake = modules['core'], modules['intake']
            # Policy selects semantic JSON bytes through this API; CLI keeps raw pins separately.
            now = int(time.time())
            rows, approved = policy_check(policy, original_selection, selection, core, intake, now)
            key_raw = {name: input_bytes(policy[name]) for name in ('public_keyring', 'trusted', 'revoked')}
            key_observation = public_only(key_raw['public_keyring'], services['public_packets'])
            trusted, revoked = fingerprint_lines(key_raw['trusted'], True), fingerprint_lines(key_raw['revoked'])
            need(set(approved) <= trusted and not (set(approved) & revoked), 'signer-untrusted-or-revoked')
            input_bytes(policy['gpg'])
            need(os.access(policy['gpg']['path'], os.X_OK), 'gpg-not-executable')
            deadline = time.monotonic() + seconds
            budget = core.Budget(deadline)
            snapshots = Path(parent) / 'operands'; snapshots.mkdir(mode=0o700)
            auth_dir = Path(parent) / 'authentication'; auth_dir.mkdir(mode=0o700)
            logs = Path(parent) / 'commands'; logs.mkdir(mode=0o700)
            for name, raw in key_raw.items():
                write(snapshots / name, raw)
            selected = []
            for row in rows:
                item = copy.deepcopy(row)
                for key in ('archive', 'signature'):
                    item[key] = snapshot(core, row[key], snapshots / (row['identity']['name'] + '.' + key), budget)
                selected.append(item)
            home = Path(tempfile.mkdtemp(prefix='gpg-home-', dir=parent))
            home_identity = (home.stat().st_dev, home.stat().st_ino)
            gpg = [policy['gpg']['path'], '--batch', '--no-tty', '--no-options', '--homedir', str(home),
                '--no-default-keyring', '--keyring', str(home/'public.gpg'), '--no-auto-key-retrieve',
                '--no-auto-key-import', '--auto-key-locate', 'clear', '--disable-dirmngr', '--no-autostart',
                '--no-auto-check-trustdb', '--status-fd', '1']
            authority, packages, separated = {}, [], {}
            try:
                imported, import_record = command(services['owned'], gpg + ['--import', str(snapshots/'public_keyring')], home, logs, 0, deadline)
                import_status(imported, approved)
                for index, row in enumerate(selected, 1):
                    input_bytes(policy['gpg']); budget.check(); check()
                    stdout, evidence = command(services['owned'], gpg + ['--verify', row['signature']['path'], row['archive']['path']], home, logs, index, deadline)
                    signer = row['primary_fingerprint']
                    observed_now = int(time.time())
                    policy_check(policy, original_selection, selection, core, intake, observed_now)
                    crypto = services['signature_status'](stdout, signer, datetime.fromtimestamp(observed_now, timezone.utc))
                    records = [line.split()[1:] for line in stdout.decode().splitlines() if line.startswith('[GNUPG:] ')]
                    valid = next(record for record in records if record and record[0] == 'VALIDSIG')
                    need(int(valid[3]) >= approved[signer]['signature_not_before'] and
                         crypto['signing_fingerprint'] not in revoked, 'signature-policy-time-or-revocation')
                    name = row['identity']['name']
                    envelope = dict(scope=PROFILE, identity=row['identity'], archive_sha256=row['archive']['sha256'],
                        signature_sha256=row['signature']['sha256'], policy_sha256=sha(original_policy),
                        selection_sha256=sha(original_selection), verification=crypto,
                        gpg_status_sha256=sha(stdout), command_receipt_sha256=sha(encoded(evidence)),
                        public_keyring_sha256=policy['public_keyring']['sha256'], signature_status='cryptographic-signature-valid',
                        new_gpg_verification_executed=True, independent_owner_trust_accepted=False)
                    write(auth_dir/(name+'.json'), encoded(envelope)); authority[name] = envelope
                # No parser runs until every selected signature has passed.
                with modules['spool'].Store(Path(parent)/'spool', core, budget) as store:
                    for row in selected:
                        name = row['identity']['name']
                        metadata = intake.normalized_metadata(core, row['metadata'])
                        metadata_path = auth_dir/(name+'.expected-metadata.json')
                        write(metadata_path, encoded(dict(scope='OPERATOR_EXPECTED_METADATA_NOT_SOURCE_OR_LICENSE_ADMISSION', metadata=metadata)))
                        parser_row = {key: row[key] for key in ('identity', 'archive', 'signature')}
                        parser_row.update(authentication=reference(core, auth_dir/(name+'.json'), budget),
                            source_admission=reference(core, metadata_path, budget))
                        with budget.job():
                            package = admission._bridge(core, intake)(parser_row, metadata, store, budget)
                        packages.append(package); separated[name] = engine.separation(core, package)
                    expected = [row['identity'] for row in selected]
                    generic_prepare(modules['bridge'])(core, modules['assembler'], packages, expected, store)
                    yield dict(modules=modules, packages=packages, expected=expected, store=store, budget=budget,
                        authentication=authority, separation=separated, engine=engine, services=services,
                        policy_sha256=sha(original_policy), selection_sha256=sha(original_selection),
                        public_import=dict(status_sha256=sha(imported), command_receipt_sha256=sha(encoded(import_record))),
                        key_observation=key_observation, release_set=selection['release_set'])
                    check(); budget.check()
                need(not os.path.lexists(Path(parent)/'spool') and not store.cleanup_errors, 'spool-cleanup')
                # Final check original operands; no hidden mutation/download/refresh.
                for row in rows:
                    for key in ('archive', 'signature'):
                        ref = row[key]
                        with core.opened(ref['path'], budget, ref['identity']) as (fd, _):
                            need(core.hashed(fd, ref['size'], budget) == ref['sha256'], 'original-operand-drift')
                for name in ('gpg', 'public_keyring', 'trusted', 'revoked'):
                    input_bytes(policy[name])
                policy_check(policy, original_selection, selection, core, intake, int(time.time()))
                need(encoded(selection) == original_selection and encoded(policy) == original_policy, 'caller-input-drift')
                check_sources(); check()
            finally:
                info = home.lstat()
                need(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) == home_identity
                     and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'gpg-home-identity')
                shutil.rmtree(home)


def assemble(session, destination, epoch=1700000000):
    modules, store, budget = session['modules'], session['store'], session['budget']
    core, assembler, bridge = (modules[name] for name in ('core', 'assembler', 'bridge'))
    nodes, bodies, pristine = generic_prepare(bridge)(core, assembler, session['packages'], session['expected'], store)
    nodes, bodies, deltas, links = assembler.configure(core, nodes, bodies, pristine, [])
    manifest = bridge.manifest_builder(assembler)(nodes, pristine, deltas, links, epoch)
    manifest.update(archive_authentication=session['authentication'], inert_separation=session['separation'],
        generic_signed_policy=dict(profile=PROFILE, policy_sha256=session['policy_sha256'],
            selection_sha256=session['selection_sha256'], release_set=session['release_set'],
            capacity_adapter=dict(package_ceiling=MAX_PACKAGES, inherited_ceiling=261,
                remaining_node_byte_path_owner_link_checks='UNCHANGED'), acceptance=BOUNDARIES),
        intake_metadata={p['identity']['name']: dict(controls={name: dict(bytes=row['ref']['size'],
            sha256=row['ref']['sha256'], parsed=row['parsed']) for name,row in sorted(p['metadata'].items())},
            facts=p['intake']) for p in session['packages']})
    bundle, charged = bridge.emit(core, assembler, nodes, bodies, manifest, epoch, destination, store, budget)
    return dict(manifest=manifest, manifest_sha256=sha(assembler.encoded(manifest)), bundle=bundle,
                output_bytes=charged.bytes, nodes=len(nodes))


def check_sources():
    for path, digest in PINS.values():
        pinned(ROOT/path, digest)
    pinned(Path(__file__), ENTRY_SHA)


def run(selection, policy, output, epoch=1700000000, seconds=180):
    need(type(epoch) is int and 0 <= epoch <= 2147483647, 'epoch-bound')
    # Require normalized selection bytes in the policy for both Python/CLI API.
    need(type(policy) is dict and policy.get('selection_sha256') == sha(encoded(selection)), 'canonical-selection-pin')
    output = Path(output).absolute()
    need(output.parent == output.parent.resolve(), 'output-parent')
    output.mkdir(mode=0o700)
    write(output/'INCOMPLETE.json', encoded(dict(status='INCOMPLETE_NOT_ACCEPTED')))
    try:
        with prepared(selection, policy, output, seconds) as session:
            with (output/'staging.tar').open('xb') as destination:
                result = assemble(session, destination, epoch)
                destination.flush(); os.fsync(destination.fileno())
            receipt = dict(status=STATUS, profile=PROFILE, policy_sha256=session['policy_sha256'],
                selection_sha256=session['selection_sha256'], bundle=result['bundle'], manifest_sha256=result['manifest_sha256'],
                archive_authentication=session['authentication'], separation=session['separation'],
                packages={p['identity']['name']: dict(nodes=len(p['nodes']), files=len(p['bodies'])) for p in session['packages']},
                public_packet_observation=session['key_observation'], release_set=selection['release_set'],
                public_import=session['public_import'],
                source_pins={name:dict(path=value[0],sha256=value[1]) for name,value in PINS.items()},
                entrypoint_sha256=ENTRY_SHA, acceptance=BOUNDARIES)
        receipt.update(spool_cleanup='PASS', private_runtime_cleanup='PASS', public_only_gpg_home_cleanup='PASS')
        write(output/'assembly.json', encoded(result['manifest']))
        write(output/'policy.json', encoded(policy)); write(output/'selection.json', encoded(selection))
        # The verifier uses a distinct new receipt status, never old proof spoofing.
        write(output/'verification-input.json', encoded(receipt))
        verified = generic_verifier(sources()['verifier_raw'], pending=True)(output)
        write(output/'staging-verification.json', encoded(verified))
        check_sources()
        write(output/'receipt.pending.json', encoded(receipt))
        (output/'INCOMPLETE.json').unlink()
        os.rename(output/'receipt.pending.json', output/'receipt.json')
        return receipt
    except BaseException as error:
        if not os.path.lexists(output/'INCOMPLETE.json'):
            write(output/'INCOMPLETE.json', encoded(dict(status='INCOMPLETE_NOT_ACCEPTED')))
        write(output/'failure.json', encoded(dict(status='REFUSED_NOT_ACCEPTED', error_type=type(error).__name__, error=str(error))))
        raise


def image_services():
    path, digest = PINS['image_bridge']
    bridge = types.ModuleType('_generic_image_bridge')
    bridge.__file__ = str(ROOT/path)
    exec(compile(pinned(ROOT/path, digest), bridge.__file__, 'exec'), bridge.__dict__)
    return bridge, bridge.sources()


def compose_image(selection, policy, tool_pins, metadata_pins, root_policy, output, epoch=1700000000):
    """Explicit opt-in DATA image composition; no old exact-two pipeline dispatch.

    Reuse its pinned metadata joins, generated-root proof, body reader and encoder.
    This API runs additional native tools and is separate from staging-only CLI.
    """
    bridge, modules = image_services()
    output = Path(output).absolute()
    need(output.parent == output.parent.resolve(), 'image-output-parent')
    output.mkdir(mode=0o700)
    write(output/'INCOMPLETE.json', encoded(dict(status='INCOMPLETE_NOT_ACCEPTED')))
    try:
        encoder, metadata = modules['encoder'], modules['metadata']
        encoder.ACTOR_DIRECTORY = output/'actors'; encoder.ACTOR_DIRECTORY.mkdir(mode=0o700)
        need(type(tool_pins) is dict and type(metadata_pins) is dict
             and tool_pins.get('schema_version') == metadata_pins.get('schema_version') == 2, 'image-profiles-v2-required')
        need(encoder.tool_pins(tool_pins.get('configuration')) == tool_pins and
             metadata.pins(metadata_pins.get('configuration')) == metadata_pins, 'image-native-profile-mismatch')
        retained = run(selection, policy, output/'staging', epoch)
        verification = generic_verifier(sources()['verifier_raw'])(output/'staging')
        manifest = decode(pinned(output/'staging/assembly.json', retained['manifest_sha256'], 32*1024**2))
        reports = {}
        native = output/'native-metadata'; native.mkdir(mode=0o700)
        for row in selection['packages']:
            report = metadata.complete(row['archive'], metadata_pins)
            report.update(identity=row['identity'], archive_reference=row['archive'], signature_reference=row['signature'])
            name = row['identity']['name']; reports[name] = report
            write(native/(name+'.json'), encoded(report))
        sidecar, bindings = metadata.join_metadata(manifest, reports, root_policy)
        write(output/'inode-metadata.json', encoded(sidecar))
        write(native/'member-and-inode-bindings.json', encoded(bindings))
        proof = bridge.root_proof(encoder, root_policy, tool_pins, epoch, output/'new-root-policy-proof')
        write(native/'root-policy-proof.json', encoded(proof))
        bodies = bridge.bundle_bodies(output/'staging', manifest, retained, encoder)
        image = encoder.encode(manifest, bodies, sidecar, tool_pins, output/'encoded')
        check_sources(); bridge.check_sources()
        result = dict(status='PASS_POLICY_SIGNED_DIRECT_METADATA_GATED_EXT4', intake=retained,
            staging_verification=verification, filesystem=image, direct_metadata_reports={name:sha(encoded(report))
                for name,report in sorted(reports.items())}, acceptance=BOUNDARIES,
            entrypoint_sha256=ENTRY_SHA, image_state='PRISTINE_DATA_ONLY_NO_BOOTSTRAP_OR_INSTALLED_STATE')
        write(output/'receipt.pending.json', encoded(result))
        (output/'INCOMPLETE.json').unlink(); os.rename(output/'receipt.pending.json', output/'receipt.json')
        return result
    except BaseException as error:
        if not os.path.lexists(output/'INCOMPLETE.json'):
            write(output/'INCOMPLETE.json', encoded(dict(status='INCOMPLETE_NOT_ACCEPTED')))
        write(output/'failure.json', encoded(dict(status='REFUSED_NOT_ACCEPTED', error_type=type(error).__name__, error=str(error))))
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('selection', 'policy'):
        parser.add_argument('--'+name, required=True)
        parser.add_argument('--'+name+'-sha256', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--epoch', type=int, default=1700000000)
    parser.add_argument('--seconds', type=int, default=180)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (2*1024**3, 2*1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (180, 180))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    selection_raw = pinned(args.selection, args.selection_sha256)
    policy_raw = pinned(args.policy, args.policy_sha256)
    selection, policy = decode(selection_raw), decode(policy_raw)
    need(selection_raw == encoded(selection) and policy_raw == encoded(policy), 'canonical-json-input-bytes-required')
    result = run(selection, policy, args.output, args.epoch, args.seconds)
    print(json.dumps(dict(status=result['status'], packages=len(result['packages']),
        receipt_sha256=sha(encoded(result)), acceptance=BOUNDARIES), sort_keys=True))


ENTRY_SHA = sha(Path(__file__).read_bytes())

if __name__ == '__main__':
    main()
