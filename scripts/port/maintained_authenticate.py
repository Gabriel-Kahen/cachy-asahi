#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind maintained233 archive authentication to the exact completed metadata query.

Preview by default. Execution retains the existing private-cache/GPG/PKGINFO
engine; it is not whole574 trust, source/legal, installation or Asahi admission.
A Root-selected external whole-invocation deadline/owned-group cleanup is required.
"""
import argparse
import ast
import concurrent.futures
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import types
import urllib.parse
import urllib.request

CURRENT = {'proposal.json': '882fcbf46f9e440d6327704ddc8385578b1e5bf6cf9c24e8676b10a976765dd7', 'builder-input.json': 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f', 'seed341.lock': 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25', 'archives233.json': '96bce50d99ebcc10ac3897f17f05e66ec185aad85e807e5d09928c1cbfa5c9a8', 'expected574.lock': 'fa6a871a60cd46a491c14554db5630962ea6c310fce0133065c5bdbbdb398922', 'worker.json': 'de2baf164e46c3e9fa416d5d59b31470f93e729e63915504378b266d21dbbf6e', 'parent.json': 'a17ef2e1e2a55c1a7b51444d2880d272c5d5c97b650d1c17350ca8b65fec3511', 'outer.json': '14c6f629448f4d2e0a955766de5332f4cb293f5afc2e1734b3cd9078f2237421', 'completion.json': '0a8ef5ee39adf37a8e7597a30c0d01a3b66ebfcac0af7790101a417bb6b7f30e'}
HELPERS = {'scripts/port/authenticate.py': '241cd67370eb593bdf948a25788f006ecf470c645ba5d198bc9c318119ebfe10', 'scripts/port/preview.py': 'd737c51474e05cc2c4db2e87fc021f50328eea7744983dd4076d44751fce7383', 'scripts/ci/native_arm.py': '1a5369e007193fafce355ca6d20f4e771a0f342e0176bfd80f95a718328a0d10'}
SCOPE = 'maintained-generic233-archive-authentication-v1'
LIMIT = 2 * 1024**2
ROOT = Path(__file__).resolve().parents[2]


def need(ok, code):
    if not ok: raise ValueError(code)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encoded(value): return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def document(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'duplicate-json'); result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'nonfinite-json'))


def read(path, pin):
    path = Path(path).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), 'input-path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and not before.st_mode & 0o022 and 0 < before.st_size <= LIMIT, 'input-shape')
        raw = stream.read(LIMIT + 1); after = os.fstat(stream.fileno()); named = path.lstat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(identity(before) == identity(after) == identity(named) and len(raw) == before.st_size and sha(raw) == pin, 'input-drift')
    return raw


def inventory(raw):
    rows = [line.split() for line in raw.decode().splitlines()]
    need(all(len(r) == 2 and re.fullmatch(r'[a-z0-9][a-z0-9+_.-]*', r[0]) and re.fullmatch(r'[^\s/]+', r[1]) for r in rows), 'inventory-row')
    need(len({r[0] for r in rows}) == len(rows), 'inventory-duplicate')
    return dict(rows)


def engine(source_root):
    """Compile exact held API definitions only; no adjacent import/PYC/CLI path."""
    raw = {path: read(Path(source_root) / path, pin) for path, pin in HELPERS.items()}
    native = types.ModuleType('maintained_native_helpers')
    native.__file__ = str(Path(source_root) / 'scripts/ci/native_arm.py')
    native.__dict__.update(hashlib=hashlib, json=json, re=re, urllib=urllib)
    preview = types.ModuleType('maintained_preview_helpers'); preview.__dict__.update(re=re)
    legacy = types.ModuleType('maintained_archive_engine')
    legacy.__file__ = str(Path(source_root) / 'scripts/port/authenticate.py')
    legacy.__dict__.update({k: globals()[k] for k in ('concurrent', 'hashlib', 'json', 'os', 'Path', 're', 'struct', 'subprocess', 'tarfile', 'tempfile', 'urllib')})
    legacy.__dict__.update(native=native, preview=preview)
    for path, module, names, constants in [
        ('scripts/ci/native_arm.py', native, {'sha', 'save', 'check_pin', 'signature_item', 'valid_signature', 'pkginfo'}, set()),
        ('scripts/port/preview.py', preview, {'need'}, {'NAME'}),
        ('scripts/port/authenticate.py', legacy, {'validate', 'fetch', 'observe', 'status', 'authenticate'}, {'SIGNER', 'CACHE', 'MAX_BYTES', 'KEY_FIELDS', 'ARCHIVE_FIELDS'})]:
        nodes = [n for n in ast.parse(raw[path]).body if isinstance(n, ast.FunctionDef) and n.name in names or isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id in constants for t in n.targets)]
        need({n.name for n in nodes if isinstance(n, ast.FunctionDef)} == names, 'helper-functions')
        exec(compile(ast.Module(nodes, type_ignores=[]), str(Path(source_root) / path), 'exec', dont_inherit=True), module.__dict__)
    return legacy


def validate_resolution(data, seed, final):
    proposal, builder, archives, worker, parent, outer, completion = (data[n] for n in ('proposal.json', 'builder-input.json', 'archives233.json', 'worker.json', 'parent.json', 'outer.json', 'completion.json'))
    need(proposal['builder_lock_sha256'] == worker['builder_input_sha256'] == CURRENT['builder-input.json'] and proposal['builder_inventory_sha256'] == worker['seed_inventory_sha256'] == CURRENT['seed341.lock'], 'maintained-input-binding')
    need(worker['unchanged233_archive_identity_sha256'] == CURRENT['archives233.json'] and parent['worker_receipt_sha256'] == CURRENT['worker.json'], 'resolution-binding')
    need(parent['status'] == worker['status'] == 'PASS-generic-maintained-metadata-resolution' and worker['phase'] == 'complete' and completion['status'] == 'PASS_ACTUAL_HOST_PRIVATE_MAINTAINED_METADATA_RESOLUTION', 'resolution-status')
    for record in (worker, parent, outer):
        need(record['first_failure' if record is not outer else 'failure'] is None and record['cancelled'] is False, 'resolution-failure')
    need(type(parent['worker_exit']) is type(outer['exit_code']) is int and parent['worker_exit'] == outer['exit_code'] == 0 and parent['natural_exit'] is parent['cleanup_verified'] is outer['natural_exit'] is outer['within_envelope'] is True and outer['signals_sent'] == [], 'resolution-terminal')
    for field in ('entered_monotonic', 'ended_monotonic', 'work_end', 'end'):
        need(type(outer[field]) in (int, float) and math.isfinite(outer[field]), 'resolution-clock')
    need(outer['work_end'] == outer['entered_monotonic'] + 300 and outer['end'] == outer['entered_monotonic'] + 304 and outer['entered_monotonic'] <= outer['ended_monotonic'] <= outer['work_end'], 'resolution-clock')
    need(worker['roots'] == proposal['roots'] and worker['provider_constraints'] == proposal['provider_constraints'] and worker['snapshots'] == proposal['snapshots'] == archives['repository_databases'], 'proposal-scope')
    need(len(proposal['roots']) == 45 and len(proposal['provider_constraints']) == 4 and builder['keyring_files'] == archives['keyring_files'] and builder['signer_fingerprint'] == archives['signer_fingerprint'], 'source-key-binding')
    additions = {r['name']: r for r in archives['packages']}
    need(len(seed) == 341 and len(final) == 574 and len(additions) == 233 and set(final) - set(seed) == set(additions) and all(final[n] == v for n, v in seed.items()) and not worker['removals'], 'inventory-binding')
    need(all(final[r['name']] == r['version'] for r in archives['packages']), 'addition-identity')
    candidates = {r['name'][0]: r for r in worker['full_candidate_inventory']}
    need(len(candidates) == len(worker['full_candidate_inventory']) == 574 and set(candidates) == set(final), 'candidate-inventory')
    for name, version in final.items(): need(candidates[name]['version'] == [version], 'candidate-version')
    fields = {'name':'name','version':'version','arch':'arch','filename':'archive_filename','sha256':'archive_sha256','license':'license_metadata','depends':'depends','provides':'provides','conflicts':'conflicts','replaces':'replaces','source_url':'upstream_url'}
    for name, item in additions.items():
        for key, target in fields.items(): need(candidates[name][target] == (item[key] if type(item[key]) is list else [item[key]]), 'archive-metadata')
        need(candidates[name]['repository'] == item['repo'], 'archive-repository')
    need(worker['changes'] == [dict(name=n, version=r['version'], kind='add', download_bytes=r['size']) for n, r in sorted(additions.items())], 'resolved-additions')
    relationships = worker['dependency_relationships']; need(len(relationships) == 2933 and not worker['unsatisfied'] and not worker['conflicts'], 'resolution-relations')
    need([(r['package'], r['relation']) for r in relationships] == [(n, d) for n, r in sorted(candidates.items()) for d in r['depends']] and all(r['provider'] in final for r in relationships), 'resolution-providers')
    deps = sorted({r['relation'] for r in relationships}); commands = worker['commands']; need(len(deps) == 743 and len(commands) == 5, 'resolution-commands')
    targets = [r['name'] + '=' + r['version'] for r in proposal['roots'] + proposal['provider_constraints']]
    for i, command in enumerate(commands):
        need(command['state'] == 'RETURNED' and type(command['exit']) is int and command['exit'] == 0 and command['natural_exit'] is command['cleanup_verified'] is True, 'command-terminal')
        argv = command['argv']; need(argv[0] == '/usr/bin/pacman' and argv[argv.index('--arch') + 1] == 'aarch64', 'command-scope')
        context = str(Path(commands[0]['argv'][commands[0]['argv'].index('--config') + 1]).parent)
        indexed_final = [name for name, row in completion['indexed_files'].items() if name.endswith('/final574.lock') and row['sha256'] == CURRENT['expected574.lock']]
        need(len(indexed_final) == 1 and Path(context).is_absolute() and '..' not in Path(context).parts and context.endswith('/' + str(Path(indexed_final[0]).parent/'private-context')), 'private-context')
        prefix = ['/usr/bin/pacman']
        for flag, name in (('--config','pacman.conf'),('--root','root'),('--dbpath','db'),('--cachedir','cache'),('--gpgdir','gpg'),('--hookdir','hooks'),('--logfile','pacman.log')): prefix += [flag, context + '/' + name]
        prefix += ['--arch','aarch64','--color','never']
        expected = prefix + (['--sync','--print','--needed','--noconfirm','--print-format','%n\t%v\t%r\t%a\t%s\t%h'] + targets if i == 0 else ['--deptest'] + deps[(i-1)*200:i*200])
        need(argv == expected, 'command-scope')
    need(completion['final_inventory_sha256'] == CURRENT['expected574.lock'] and completion['initial_count'] == 341 and completion['final_count'] == 574 and completion['additions'] == 233 and completion['changes_to_baseline'] == 0 and completion['natural_parent_and_worker'] is True and completion['new_source_signature_archive_installation_native_ARM_Asahi_hardware_release_admission'] is False, 'completion-scope')


def prepare(profile, blobs, legacy):
    need(type(profile) is dict and set(profile) == {'schema_version','scope','selected_for_release','files_sha256','helper_sha256','package_count','expected_final_count','actual_resolution_scope','trust_scope'}, 'profile-schema')
    need(type(profile['schema_version']) is int and profile['schema_version'] == 1 and profile['scope'] == SCOPE and profile['selected_for_release'] is False and profile['files_sha256'] == CURRENT and profile['helper_sha256'] == HELPERS and type(profile['package_count']) is int and profile['package_count'] == 233 and type(profile['expected_final_count']) is int and profile['expected_final_count'] == 574 and profile['actual_resolution_scope'] == 'x86-host private generic-aarch64 metadata only' and profile['trust_scope'] == 'actual archive authentication still required; no whole574/Asahi/M2/source/legal/release admission', 'profile-selection')
    need(set(blobs) == set(CURRENT) and all(type(blobs[n]) is bytes and 0 < len(blobs[n]) <= LIMIT and sha(blobs[n]) == pin for n, pin in CURRENT.items()), 'profile-inputs')
    data = {n: document(b) for n, b in blobs.items() if n.endswith('.json')}
    validate_resolution(data, inventory(blobs['seed341.lock']), inventory(blobs['expected574.lock']))
    effective = copy.deepcopy(data['archives233.json'])
    effective.update(proposal_sha256=CURRENT['proposal.json'], preview_receipt_sha256=CURRENT['worker.json'], builder_lock_sha256=CURRENT['builder-input.json'])
    legacy.validate(effective)
    return effective


def execute(profile, blobs, legacy, public_keys, output):
    effective = prepare(profile, blobs, legacy)
    need(os.getuid() == os.geteuid() != 0, 'ordinary-executor')
    output = Path(output).absolute()
    need(not output.exists() and not output.is_symlink() and not any(p.is_symlink() for p in output.parents), 'new-output')
    info = output.parent.stat(); need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022, 'owned-output-parent')
    public_keys = Path(public_keys).absolute()
    for key in effective['keyring_files']:
        # Revoked key lists can be empty; the held engine checks their exact pins.
        need(not any(p.is_symlink() for p in (public_keys, *public_keys.parents)) and not (public_keys/key['filename']).is_symlink(), 'public-key-path')
    output.mkdir(mode=0o700)
    receipt = dict(schema_version=1, scope=SCOPE, status='RUNNING', profile_canonical_sha256=sha(encoded(profile)), inputs_sha256=CURRENT, effective_archive_lock_sha256=sha(encoded(effective)), authenticated_count=0, whole574_trust='NOT_ESTABLISHED', Asahi_M2_source_legal_release='NOT_ESTABLISHED')
    try:
        result = legacy.authenticate(effective, legacy.CACHE, public_keys, output/'authentication', sha(encoded(effective)))
        receipt['authenticated_count'] = result.get('verified_count', 0)
        receipt['status'] = 'PASS-233-maintained-authenticated-archives' if result.get('status') == 'PASS-233-authenticated-generic-archives' and result.get('verified_count') == 233 and result.get('failures') == [] else 'FAIL'
    except BaseException as error:
        receipt.update(status='FAIL', error_kind=next((name for cls, name in ((ValueError, 'ValueError'), (OSError, 'OSError'), (KeyError, 'KeyError'), (KeyboardInterrupt, 'KeyboardInterrupt'), (SystemExit, 'SystemExit')) if type(error) is cls), 'OTHER'))
        try: legacy.native.save(output/'maintained-binding.json', receipt)
        except BaseException: pass  # Retain the original actor/control failure.
        raise
    legacy.native.save(output/'maintained-binding.json', receipt)
    return receipt


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--profile', type=Path, required=True); p.add_argument('--profile-sha256', required=True)
    p.add_argument('--inputs', type=Path, required=True); p.add_argument('--source-root', type=Path, default=ROOT)
    p.add_argument('--execute', action='store_true'); p.add_argument('--public-key-directory', type=Path); p.add_argument('--output', type=Path)
    args = p.parse_args(argv)
    try:
        profile = document(read(args.profile, args.profile_sha256)); blobs = {name: read(args.inputs/name, pin) for name, pin in CURRENT.items()}
        legacy = engine(args.source_root); effective = prepare(profile, blobs, legacy)
        if args.execute:
            need(args.public_key_directory is not None and args.output is not None, 'execution-paths')
            result = execute(profile, blobs, legacy, args.public_key_directory, args.output)
        else: result = dict(status='READY_FOR_SEPARATELY_BOUNDED_AUTHENTICATION', packages=233, projection=574, effective_archive_lock_sha256=sha(encoded(effective)), actual_authentication='NOT_RUN')
        print(json.dumps(result, sort_keys=True)); return int(result['status'] == 'FAIL')
    except (ValueError, OSError, KeyError, TypeError, RecursionError, subprocess.SubprocessError):
        print('REFUSED: maintained profile/input/terminal/metadata boundary'); return 2


if __name__ == '__main__': raise SystemExit(main())
