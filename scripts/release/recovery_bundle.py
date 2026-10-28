#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Materialize an explicitly selected offline predecessor and recovery data.

Selection SHA, kit signer/namespace/floor and checkpoint are external authority.
Retained recovery observations are rehashed/reinspected, not freshly signed or
freshly signature-verified. No transferred Python, recovery commands, package
hooks, network, disk, mount, installation or boot operations are executed.
"""
import argparse
import copy
import importlib.util
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


K = module('recovery_bundle_kit', HERE / 'offline_kit.py')
C = K.c
P = module('recovery_bundle_inputs', HERE.parent / 'platform/recovery_inputs.py')
RECEIPT = 'recovery-bundle.json'
INPUTS = {'certificate': P.MIB, 'image_inventory': C.MAX_JSON,
          'old_availability': C.MAX_JSON}
FIELDS = {'schema_version', 'purpose', 'kit_sha256', 'release_sha256', 'release_id',
          'base_sha256', 'policy_sha256', 'packages', 'protected_versions', 'recovery_receipt'}
LIMITS = dict(system_mutation=False, packages_installed=False,
              installed_system_recovered=False, boot_recovery_accepted=False,
              hardware_accepted=False, native_accepted=False, stable_accepted=False,
              fresh_recovery_signature_verification=False,
              independent_owner_trust_accepted=False)


def pinned(path, pin, maximum=C.MAX_JSON):
    C.reference('input', pin)
    raw = C.read_path(C.absolute(str(path)), maximum)
    C.need(C.digest(raw) == pin, 'external input SHA-256 differs')
    return raw


def bound(ref, maximum):
    C.need(set(ref) == {'path', 'size', 'sha256'} and type(ref['size']) is int
           and 0 < ref['size'] <= maximum, 'bounded exact reference required')
    raw = pinned(ref['path'], ref['sha256'], maximum)
    C.need(len(raw) == ref['size'], 'reference size differs')
    return raw


def recovery_json(raw):
    """Recovery observations include fractional timings; authority JSON stays strict."""
    def finite(text):
        value = float(text)
        C.need(math.isfinite(value), 'finite recovery observation number required')
        return value
    value = json.loads(raw, object_pairs_hook=P.auth.coverage.pairs, parse_float=finite,
                       parse_constant=lambda _: C.need(False, 'nonfinite recovery JSON refused'))
    C.need(isinstance(value, dict), 'recovery JSON object required')
    if value.get('kind') == 'exact-superseded-recovery-archive-data':
        rows = value.get('packages', [])
        C.need(isinstance(rows, list), 'recovery package observations must be a list')
        for row in rows:
            C.need(isinstance(row, dict), 'recovery package observation must be an object')
            for field in ('http_attempts', 'http_attempts_this_run'):
                attempts = row.get(field, [])
                C.need(isinstance(attempts, list), 'recovery timing observations must be a list')
                for attempt in attempts:
                    C.need(isinstance(attempt, dict), 'recovery timing observation must be an object')
                    for key in ('pace_wait_seconds', 'retry_after_seconds'):
                        if key in attempt:
                            duration = attempt[key]
                            C.need(type(duration) in (int, float) and duration >= 0,
                                   'invalid recovery timing observation')
    return value


def read(root, name, maximum=C.MAX_JSON):
    fd = C.directory(root)
    try:
        return C.read_member(fd, name, maximum)
    finally:
        os.close(fd)


def write(root, name, raw):
    C.relative(name)
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o400)


def selection(raw):
    value = C.decode(raw)
    C.need(set(value) == FIELDS and type(value['schema_version']) is int
           and value['schema_version'] == 1 and value['purpose'] == 'offline-recovery-selection',
           'unsupported explicit recovery selection')
    for key in ('kit_sha256', 'release_sha256', 'base_sha256', 'policy_sha256'):
        C.reference(key, value[key])
    C.need(isinstance(value['release_id'], str) and C.NAME.fullmatch(value['release_id']),
           'selected predecessor ID required')
    ref = value['recovery_receipt']
    C.need(isinstance(ref, dict) and set(ref) == {'path', 'size', 'sha256'}
           and type(ref['size']) is int and 0 < ref['size'] <= P.RECEIPT_LIMIT,
           'selected bounded recovery receipt reference required')
    C.absolute(ref['path'])
    C.reference('recovery_receipt', ref['sha256'])
    return value


def inspect_kit(kit, chosen, args):
    result = K.inspect(argparse.Namespace(kit=str(kit), kit_sha256=chosen['kit_sha256'],
        signer=args.signer, namespace=args.namespace, minimum_sequence=args.minimum_sequence,
        state_dir=args.state_dir))
    C.need(result['release_sha256'] == chosen['release_sha256'], 'selected predecessor release differs')
    release = C.decode(read(kit, 'release/release.json'))
    spec = C.decode(read(kit, 'release/spec.json'))
    C.need(release['release_id'] == chosen['release_id'] == spec['release_id'], 'predecessor identity differs')
    base_raw = read(kit, 'release/base.json')
    C.need(C.digest(base_raw) == chosen['base_sha256'] == spec['base']['sha256']
           == release['files']['base.json'], 'complete predecessor base inventory differs')
    C.need(C.digest(C.encoded(spec['policy'])) == chosen['policy_sha256'], 'protected platform policy differs')
    keys = ('name', 'version', 'arch', 'filename', 'sha256')
    packages = sorted(({key: row[key] for key in keys} for row in release['packages']), key=lambda r: r['name'])
    C.need(packages == chosen['packages'] and sorted(spec['policy']['selected_packages'])
           == [row['name'] for row in packages], 'exact selected release package inventory differs')
    base = C.decode(base_raw)
    C.need(base.get('target_arch') == 'aarch64' and base.get('kind') == 'complete-target-transaction',
           'complete aarch64 predecessor base required')
    rows = base['packages']
    C.need(isinstance(rows, list) and 0 < len(rows) <= C.MAX_FILES, 'bounded base inventory required')
    by_name = {row['name']: row for row in rows}
    C.need(len(by_name) == len(rows), 'duplicate base package')
    protected = spec['policy']['protected_packages']
    C.need(isinstance(protected, list) and protected and len(set(protected)) == len(protected),
           'explicit unique protected platform choices required')
    actual = {name: {key: by_name[name][key] for key in ('version', 'arch')} for name in protected}
    C.need(actual == chosen['protected_versions'], 'protected predecessor versions differ')
    return result, by_name


def local_ref(root, name, original):
    return dict(path=str(root / name), size=original['size'], sha256=original['sha256'])


def recovery_view(root, chosen, base, *, extract=False):
    """Resolve deterministic local copies; never follow paths inside retained JSON."""
    reference = chosen['recovery_receipt']
    raw = read(root, 'recovery/receipt.json', P.RECEIPT_LIMIT)
    C.need(len(raw) == reference['size'] and C.digest(raw) == reference['sha256'], 'selected recovery receipt differs')
    prior = recovery_json(raw)
    C.need(prior.get('status') == 'PASS-all-exact-old-recovery-archive-data'
           and prior.get('failures') == [], 'complete authenticated recovery inventory required')
    original = {key: value for key, value in prior['inputs'].items() if key != 'previous_receipt'}
    contract = copy.deepcopy(original)
    for key, maximum in INPUTS.items():
        item = original[key]
        data = read(root, 'recovery/inputs/' + key, maximum)
        C.need(len(data) == item['size'] and C.digest(data) == item['sha256'], 'recovery input copy differs')
        contract[key] = local_ref(root, 'recovery/inputs/' + key, item)
    # recovery_inputs.plan binds the exact known public certificate bytes. That
    # producer certificate is armored, unlike the kit's binary gpg --export
    # keyring; the kit packet parser is not applicable to this separate input.
    # The old availability document embeds an absolute image reference. Keep its
    # original bytes and verify that binding before producing an ephemeral view
    # for the existing planner. The workspace never stores relocation-dependent
    # rewritten evidence, and verification never opens the historical paths.
    availability = recovery_json(read(root, 'recovery/inputs/old_availability'))
    C.need(availability.get('inputs', {}).get('image_inventory') == original['image_inventory'],
           'original availability/image binding differs')
    availability['inputs']['image_inventory'] = contract['image_inventory']
    with tempfile.TemporaryDirectory(prefix='recovery-reference-view-', dir='/tmp') as temporary:
        path = Path(temporary) / 'availability.json'
        data = C.encoded(availability)
        path.write_bytes(data)
        contract['old_availability'] = dict(path=str(path), size=len(data), sha256=C.digest(data))
        # Existing fixed-profile image, certificate and exact 16-package checks.
        packages = P.plan(contract)
    prior_ref = local_ref(root, 'recovery/receipt.json', reference)
    P.previous(dict(original, previous_receipt=prior_ref), packages)
    C.need(prior['verified_count'] == prior['planned_count'] == len(packages), 'incomplete recovery count')
    wanted = {row['name']: row for row in packages}
    budget = dict(cache_bytes=0, metadata_bytes=0, external_retained_cache_bytes=0,
                  external_retained_metadata_bytes=0)
    observations = []
    for row in prior['packages']:
        item = wanted[row['name']]
        baseline = base.get(item['name'])
        C.need(baseline and (baseline['version'], baseline['arch']) == (item['version'], item['arch']),
               'recovery package does not match selected predecessor base')
        localized = copy.deepcopy(row)
        C.need(type(localized['signature_observation'].get('exit')) is int,
               'integer retained signature exit required')
        for field in ('archive', 'signature', 'operator_index', 'inspection'):
            name = 'recovery/packages/' + item['name'] + '/' + field
            localized[field].update(local_ref(root, name, row[field]))
        observed = P.reuse(localized, item, budget, prior_ref)
        C.need(observed['prior_data_rehashed_and_metadata_reinspected'] is True,
               'retained recovery reinspection missing')
        # Extract only bounded .PKGINFO bytes, never an archive tree or hooks.
        metadata = P.auth.pkginfo(Path(localized['archive']['path']))
        target = 'recovery/metadata/' + item['name'] + '.PKGINFO'
        if extract:
            write(root, target, metadata['text'].encode())
        C.need(read(root, target, P.MIB) == metadata['text'].encode(), 'extracted recovery metadata differs')
        observations.append(dict(name=item['name'], version=item['version'], arch=item['arch'],
            archive_sha256=row['archive']['sha256'], signature_sha256=row['signature']['sha256'],
            metadata_sha256=metadata['sha256'], fresh_signature_verification=False))
    return observations


def commands(chosen):
    """Argument arrays for review. Placeholders intentionally require real state."""
    return dict(purpose='review-only-existing-repository-recovery-plan', executed=False,
        prerequisites=['authenticated retained stable source', 'actual local endpoint generation',
                       'externally configured public-only GPG verification home'],
        argv=['python3', '<trusted-tool-root>/scripts/release/recover_repository.py',
              '--root', '<retained-stable-source-root>', '--endpoint', '<actual-repository-endpoint>',
              '--gpg-home', '<public-verification-home>', '--key', '<externally-pinned-stable-signer>',
              'plan', '--expected-current', '<observed-endpoint-generation>',
              '--target-release-id', chosen['release_id'], '--reason', '<operator-recovery-reason>'],
        development_kit_is_stable_source=False, plan_requires_external_review_and_signature=True)


def verify(args):
    root = C.absolute(args.workspace)
    state = C.absolute(args.state_dir)
    C.need(not root.is_relative_to(state) and not state.is_relative_to(root),
           'workspace and external receiver state must be disjoint')
    fd = C.directory(root)
    try:
        info = os.fstat(fd)
        C.need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
               'caller-owned private 0700 workspace required')
    finally:
        os.close(fd)
    raw = pinned(root / RECEIPT, args.receipt_sha256)
    receipt = C.decode(raw)
    C.need(set(receipt) == {'schema_version', 'purpose', 'selection_sha256', 'files', 'symlinks'}
           and type(receipt['schema_version']) is int and receipt['schema_version'] == 1
           and receipt['purpose'] == 'offline-recovery-data-workspace', 'unsupported recovery workspace')
    C.need(receipt['selection_sha256'] == args.selection_sha256, 'independently selected contract differs')
    files, links = K.inventory(root)
    C.need(files.pop(RECEIPT, None) == args.receipt_sha256 and files == receipt['files']
           and links == receipt['symlinks'], 'workspace changed, incomplete or has foreign members')
    chosen = selection(pinned(root / 'selection.json', args.selection_sha256))
    inspected, base = inspect_kit(root / 'predecessor', chosen, args)
    observations = recovery_view(root, chosen, base)
    C.need(read(root, 'commands.json') == C.encoded(commands(chosen)), 'recovery command review differs')
    after_files, after_links = K.inventory(root)
    C.need(after_files.pop(RECEIPT, None) == args.receipt_sha256 and after_files == files
           and after_links == links, 'workspace changed during verification')
    return dict(status='verified-offline-recovery-data', selection_sha256=args.selection_sha256,
        receipt_sha256=args.receipt_sha256, predecessor_release_sha256=inspected['release_sha256'],
        recovery_packages=observations, commands=commands(chosen), **LIMITS)


def materialize(args):
    output, kit = C.absolute(args.output), C.absolute(args.kit)
    state = C.absolute(args.state_dir)
    C.need(not output.is_relative_to(state) and not state.is_relative_to(output),
           'workspace and external receiver state must be disjoint')
    raw = pinned(C.absolute(args.selection), args.selection_sha256)
    chosen = selection(raw)
    C.need(not output.exists() and not output.is_symlink() and not output.is_relative_to(kit),
           'fresh destination outside predecessor kit required')
    # Authenticate before creating a workspace or accessing recovery archive paths.
    _, base = inspect_kit(kit, chosen, args)
    prior_raw = bound(chosen['recovery_receipt'], P.RECEIPT_LIMIT)
    prior = recovery_json(prior_raw)
    C.need(prior.get('status') == 'PASS-all-exact-old-recovery-archive-data'
           and prior.get('failures') == [], 'complete recovery receipt required')
    parent = C.directory(output.parent)
    try:
        info = os.fstat(parent)
        C.need(info.st_uid == os.geteuid() and not info.st_mode & 0o022,
               'caller-owned non-writable-by-others output parent required')
        with tempfile.TemporaryDirectory(prefix='.recovery-bundle-', dir=output.parent) as temporary:
            staging = Path(temporary) / 'workspace'
            staging.mkdir(mode=0o700)
            inode = staging.stat()
            write(staging, 'selection.json', raw)
            files, links = K.inventory(kit)
            source = C.directory(kit)
            try:
                for name, pin in files.items():
                    target = staging / 'predecessor' / name
                    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    actual, _ = C.hash_member(source, name, snapshot=target)
                    C.need(actual == pin, 'predecessor changed during copy')
                    target.chmod(0o400)
            finally:
                os.close(source)
            for name, target in links.items():
                (staging / 'predecessor' / name).symlink_to(target)
            write(staging, 'recovery/receipt.json', prior_raw)
            for key, maximum in INPUTS.items():
                write(staging, 'recovery/inputs/' + key, bound(prior['inputs'][key], maximum))
            rows = prior['packages']
            C.need(isinstance(rows, list) and len(rows) == P.OLD_COUNT, 'whole exact recovery inventory required')
            seen = set()
            total, metadata_total = 0, 0
            for row in rows:
                name = row['name']
                C.need(isinstance(name, str) and C.NAME.fullmatch(name) and name not in seen,
                       'unsafe/duplicate recovery package name')
                seen.add(name)
                for field, limit in (('archive', P.ARCHIVE_LIMIT), ('signature', P.SIGNATURE_LIMIT),
                                     ('operator_index', P.INDEX_LIMIT), ('inspection', P.METADATA_LIMIT)):
                    ref = P.ref_only(row[field])
                    if field in {'archive', 'signature'}:
                        total += ref['size']
                    else:
                        metadata_total += ref['size']
                    C.need(total <= P.CACHE_LIMIT and metadata_total <= P.METADATA_LIMIT,
                           'aggregate recovery quota exceeded')
                    write(staging, 'recovery/packages/' + name + '/' + field, bound(ref, limit))
            recovery_view(staging, chosen, base, extract=True)
            write(staging, 'commands.json', C.encoded(commands(chosen)))
            files, links = K.inventory(staging)
            receipt = dict(schema_version=1, purpose='offline-recovery-data-workspace',
                           selection_sha256=args.selection_sha256, files=files, symlinks=links)
            receipt_raw = C.encoded(receipt)
            C.need(len(receipt_raw) <= C.MAX_JSON, 'workspace receipt bound exceeded')
            write(staging, RECEIPT, receipt_raw)
            checked = verify(argparse.Namespace(**{**vars(args), 'workspace': str(staging),
                                                    'receipt_sha256': C.digest(receipt_raw)}))
            K.publish(staging, parent, output, (inode.st_dev, inode.st_ino))
    finally:
        os.close(parent)
    return dict(checked, status='materialized-offline-recovery-data', path=str(output))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    build = sub.add_parser('materialize')
    check = sub.add_parser('verify')
    for command in (build, check):
        for name in ('selection-sha256', 'signer', 'namespace', 'state-dir'):
            command.add_argument('--' + name, required=True)
        command.add_argument('--minimum-sequence', type=int, required=True)
    for name in ('selection', 'kit', 'output'):
        build.add_argument('--' + name, required=True)
    for name in ('workspace', 'receipt-sha256'):
        check.add_argument('--' + name, required=True)
    args = parser.parse_args(argv)
    try:
        result = materialize(args) if args.command == 'materialize' else verify(args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (C.Error, OSError, ValueError, TypeError, KeyError, OverflowError,
            subprocess.SubprocessError) as error:
        print('offline recovery bundle refused: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
