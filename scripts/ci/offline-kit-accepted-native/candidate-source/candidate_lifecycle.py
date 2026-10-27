#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite candidate ALPM lifecycle; target seed is database-only, not bootable."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
sys.dont_write_bytecode = True
BASE_LOCK_SHA = 'cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
PACKAGES = {'cachy-asahi-session-diagnostics': ('0.1.0-3', 'session'),
            'cachy-asahi-maintenance': ('0.1.0-2', 'maintenance')}
STEPS = ('install', 'reinstall', 'remove', 'reinstall-after-remove', 'final-remove')
FIXTURE = b'original user bytes\x00\xff\n'
SENTINEL = 'home/candidate-user/.config/cachy-asahi/user-sentinel'


def need(ok, message):
    if not ok: raise ValueError(message)


def sha(raw): return hashlib.sha256(raw).hexdigest()


def encoded(value): return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()


def save(path, value):
    path.write_bytes(encoded(value)); path.chmod(0o600)


def read(path, maximum=16 * 1024**2):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         not any(p.is_symlink() for p in (path, *path.parents)), 'canonical ordinary input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 < before.st_size <= maximum and not before.st_mode & 0o022,
             'bounded single ordinary input required')
        data = stream.read(maximum + 1); after = os.fstat(stream.fileno())
    identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mode, x.st_uid, x.st_gid,
                           x.st_nlink, x.st_mtime_ns, x.st_ctime_ns)
    need(identity(before) == identity(after) == identity(path.lstat()) and len(data) == before.st_size,
         'input changed while reading')
    return data


def reference(path, maximum=16 * 1024**2):
    path = Path(path); raw = read(path, maximum)
    return dict(path=str(path), size=len(raw), sha256=sha(raw))


def module(path, expected, name):
    raw = read(path, 128 * 1024)
    need(sha(raw) == expected, 'source execution pin differs: ' + str(path))
    spec = importlib.util.spec_from_file_location(name, path); value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    exec(compile(raw, str(path), 'exec'), value.__dict__)
    return value


def baseline(lock_raw):
    need(type(lock_raw) is bytes and sha(lock_raw) == BASE_LOCK_SHA, 'original574 lock pin required')
    rows = {}
    for line in lock_raw.decode().splitlines():
        name, version = line.split(' ', 1)
        need(name not in rows and re.fullmatch('[A-Za-z0-9@+_.-]+', name) and version and
             not re.search(r'[\s\x00]', version), 'literal unique base lock required')
        rows[name] = version
    need(len(rows) == 574 and lock_raw == ''.join(f'{n} {v}\n' for n, v in sorted(rows.items())).encode(),
         'exact sorted574 lock required')
    return rows


def phase_plan(name, version, original):
    need(name in PACKAGES and PACKAGES[name][0] == version and len(original) == 574 and name not in original,
         'one finite candidate and original574 base required')
    installed = dict(original, **{name: version}); rows = []
    for index, step in enumerate(STEPS):
        removing = step in ('remove', 'final-remove')
        before = original if index in (0, 3) else installed
        after = original if removing else installed
        rows.append(dict(phase=PACKAGES[name][1] + '-' + step, add=not removing,
                         before=dict(before), after=dict(after), remove={name: version} if removing else {}))
    return rows


def snapshot(root):
    """Preserve bytes, modes, owners and internal links; omit inode/mtime."""
    root = Path(root); rows = {}; total = 0
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix(); st = path.lstat()
        need(len(rows) < 20000, 'finite root node set required')
        common = dict(mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid)
        if stat.S_ISDIR(st.st_mode): row = dict(common, type='directory')
        elif stat.S_ISLNK(st.st_mode):
            target = os.readlink(path)
            need(not target.startswith('/') and path.resolve().is_relative_to(root.resolve()), 'internal user alias required')
            row = dict(common, type='symlink', target=target)
        else:
            need(stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'ordinary private tree required')
            raw = path.read_bytes(); total += len(raw)
            need(total <= 128 * 1024**2, 'finite private tree required')
            row = dict(common, type='file', bytes=len(raw), sha256=sha(raw))
        rows[name] = row
    return rows


def preserve(original, actual):
    for name, expected in original.items():
        need(actual.get(name) == expected, 'unrelated base database/user node changed: ' + name)


def seed(root, original, worker):
    """Copy actual metadata only; never invent base installed payload."""
    actual, _ = worker.candidate_database_records(Path('/'))
    need(actual == original, 'running image ALPM inventory differs from original574')
    source = Path('/var/lib/pacman/local'); destination = root / 'var/lib/pacman/local'
    destination.parent.mkdir(parents=True, mode=0o755)
    shutil.copytree(source, destination, symlinks=True)
    rows = snapshot(root)
    need(all(row['type'] != 'symlink' for name, row in rows.items() if name.startswith('var/')),
         'ordinary original ALPM metadata required')
    sentinel = root / SENTINEL; sentinel.parent.mkdir(parents=True, mode=0o700)
    sentinel.write_bytes(FIXTURE); sentinel.chmod(0o600)
    (sentinel.parent / 'user-alias').symlink_to('user-sentinel')
    observed, _ = worker.candidate_database_records(root)
    need(observed == original, 'copied ALPM database differs from original574')
    return snapshot(root)


def candidate_from_kit(args, k, expected):
    checked = k.inspect(args); fd = k.c.directory(Path(args.kit) / 'release')
    try:
        actual, release, raw = k.c.describe(fd)
        need(k.c.digest(raw) == checked['release_sha256'], 'release changed after kit authentication')
        spec_raw = k.c.read_member(fd, 'spec.json')
        need(k.c.digest(spec_raw) == release['files']['spec.json'], 'signed spec changed')
        sources = k.c.source_associations(fd, k.c.decode(spec_raw), release)
        need(sources is not None, 'exact declared recipe/source association required')
        targets = actual['targets']['packages']
        need(len(targets) == 1 and len(sources['packages']) == 1, 'single selected candidate kit required')
        target, source = targets[0], sources['packages'][0]
        package = {key: target[key] for key in ('name', 'version', 'arch', 'sha256')}
        need(package == expected['package'] == source['package'] and package['name'] in PACKAGES and
             package['version'] == PACKAGES[package['name']][0] and package['arch'] == 'any',
             'candidate identity differs from external selection/source')
        need(source['recipe']['sha256'] == expected['recipe_sha256'] and
             source['bundle']['sha256'] == expected['source_bundle_sha256'], 'candidate source pin differs')
        archive = Path(args.kit) / 'release' / target['path']; signature = Path(str(archive) + '.sig')
        artifact_ref, signature_ref = reference(archive), reference(signature, 65536)
        need(artifact_ref['sha256'] == package['sha256'] and
             signature_ref['sha256'] == release['files'][target['path'] + '.sig'] and
             artifact_ref == expected['archive'] and signature_ref == expected['signature'],
             'candidate consumed input selection differs')
    finally: os.close(fd)
    return checked, package, artifact_ref, signature_ref


def refusal_cases(args, checked):
    """Change only independent trust pins; never mutate authenticated media."""
    sequence = checked['sequence']
    need(type(sequence) is int and 1 <= sequence < 2**63 - 1, 'finite recovery sequence required')
    cases = []
    wrong_hash = ('0' if args.kit_sha256[0] != '0' else '1') + args.kit_sha256[1:]
    wrong_signer = '0' * 40 if args.signer != '0' * 40 else '1' * 40
    for label, field, value, refusal in (
            ('wrong-kit-pin', 'kit_sha256', wrong_hash, 'kit receipt differs from independently supplied SHA-256'),
            ('wrong-signer-pin', 'signer', wrong_signer, 'metadata namespace/signer differs from external pin'),
            ('sequence-floor', 'minimum_sequence', sequence + 1, 'metadata sequence below independently supplied floor')):
        changed = argparse.Namespace(**vars(args)); setattr(changed, field, value)
        cases.append((label, changed, refusal))
    return cases


def receiver_refusal(k, args, expected_reason):
    try:
        k.inspect(args)
    except (k.c.Error, ValueError) as error:
        need(expected_reason in str(error), 'offline refusal failed for an unrelated reason')
        return dict(type=type(error).__name__, reason=str(error))
    raise ValueError('offline refusal was unexpectedly accepted')


def offline_authentication_recovery(args, k, selected, checked, package, archive_ref,
                                    signature_ref, held_transport, held_state, seed_root, seed_nodes):
    """Observe real receiver refusals and recovery before any transaction.

    These are authentication failures, not failed ALPM commits or boot recovery.
    Only the pinned trusted receiver executes; package payload code never runs.
    """
    events = []
    for label, changed, expected_reason in refusal_cases(args, checked):
        failure = receiver_refusal(k, changed, expected_reason)
        need(k.inventory(Path(args.kit)) == held_transport and snapshot(Path(args.state_dir)) == held_state and
             snapshot(seed_root) == seed_nodes, 'offline refusal changed transport/checkpoint/disposable seed')
        current, candidate, archive, signature = candidate_from_kit(args, k, selected)
        need(current['metadata_sha256'] == checked['metadata_sha256'] and candidate == package and
             archive == archive_ref and signature == signature_ref,
             'restoring exact original trust pins did not recover the same authenticated candidate')
        need(k.inventory(Path(args.kit)) == held_transport and snapshot(Path(args.state_dir)) == held_state and
             snapshot(seed_root) == seed_nodes, 'offline recovery changed transport/checkpoint/disposable seed')
        events.append(dict(case=label, status='PASS_AUTHENTICATION_REFUSAL_AND_RECOVERY', failure=failure,
            original_candidate_reauthenticated=True, seed_unchanged=True, transport_unchanged=True,
            checkpoint_unchanged=True, transaction_started=False, committed=False))
    need(len(events) == 3, 'complete finite offline refusal/recovery cases required')
    return events


def run(args):
    """Execute five transitions only inside an independently selected actor."""
    need(args.execute and platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64') and
         os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0,
         'explicit ordinary native actor required')
    source = Path(args.source_root)
    need(source == Path('/source') and Path(args.selection) == Path('/inputs/candidate-selection.json'),
         'fixed source and independent selection paths required')
    raw = read(args.selection, 1024**2)
    need(sha(raw) == args.selection_sha256, 'external candidate selection pin differs')
    selection = json.loads(raw)
    for name, row in selection['sources'].items():
        path = source / name
        need(not Path(name).is_absolute() and '..' not in Path(name).parts, 'safe selected source path required')
        body = read(path, 128 * 1024)
        need(len(body) == row['size'] and sha(body) == row['sha256'], 'selected source closure differs')
    worker_path = source / 'candidate-worker.py'
    worker = module(worker_path, selection['sources']['candidate-worker.py']['sha256'], '_candidate_lifecycle_worker')
    profile = module(source / 'candidate_profile.py', selection['sources']['candidate_profile.py']['sha256'], '_candidate_lifecycle_profile')
    selection = profile.validate_selection(selection)
    profile.environment_authority(args.selection_sha256, selection['worker_sha256'], worker)
    original = profile.baseline()
    helper = 'receiver/scripts/release/offline_kit.py'
    k = module(source / helper, selection['sources'][helper]['sha256'], '_candidate_lifecycle_kit')
    selected = selection['candidate']; selected_kit = selection['kit']
    need(args.kit == selected_kit['path'] and args.state_dir == selected_kit['state_dir'] and
         args.kit_sha256 == selected_kit['kit_sha256'] and args.signer == selected_kit['signer'] and
         args.namespace == selected_kit['namespace'] and args.minimum_sequence == selected_kit['minimum_sequence'],
         'external selected trust inputs differ')
    checked, package, archive_ref, signature_ref = candidate_from_kit(args, k, selected)
    need(checked['kit_sha256'] == selected_kit['kit_sha256'] and checked['metadata_sha256'] == selected_kit['envelope_sha256'],
         'external selected envelope differs')
    keyring = reference(Path(args.kit) / 'public.gpg', 1024**2)
    need(keyring == selected['keyring'], 'external selected public keyring differs')
    held_transport = k.inventory(Path(args.kit)); held_state = snapshot(Path(args.state_dir))
    phases = phase_plan(package['name'], package['version'], original)
    previous = None; baseline_nodes = None; events = []; recovery = None
    for phase in phases:
        current, actual_package, actual_archive, actual_signature = candidate_from_kit(args, k, selected)
        need(current['metadata_sha256'] == checked['metadata_sha256'] and actual_package == package and
             actual_archive == archive_ref and actual_signature == signature_ref, 'authenticated candidate changed between phases')
        workspace = Path('/out') / ('phase-' + phase['phase']) / 'workspace'
        need(not workspace.parent.exists() and not workspace.parent.is_symlink(), 'fresh finite phase output required')
        workspace.parent.mkdir(mode=0o700); workspace.mkdir(mode=0o700); system = workspace / 'system'
        if previous is None:
            system.mkdir(mode=0o700); baseline_nodes = seed(system, original, worker)
        else: worker.copy_tree(previous, system)
        observed, _ = worker.candidate_database_records(system)
        need(observed == phase['before'], 'actual before database differs from planned transition')
        preserve(baseline_nodes, snapshot(system))
        if previous is None:
            recovery = offline_authentication_recovery(args, k, selected, checked, package,
                archive_ref, signature_ref, held_transport, held_state, system, baseline_nodes)
            save(Path('/out/offline-refusal-recovery.json'), dict(events=recovery,
                scope='AUTHENTICATION_REFUSAL_RECOVERY_ONLY', actual_alpm_failed_transaction=False,
                boot_recovery='NOT_RUN'))
        binding = dict(package=package, phase=phase['phase'], kit_sha256=selected_kit['kit_sha256'],
            envelope_sha256=selected_kit['envelope_sha256'], source_bundle_sha256=selected['source_bundle_sha256'],
            recipe_sha256=selected['recipe_sha256'], signer=args.signer)
        contract = dict(schema_version=4, scope='native-aarch64-real-candidate-development', architecture='aarch64',
            workspace=str(workspace), before=phase['before'], after=phase['after'], protected={},
            add=[dict(name=package['name'], version=package['version'], archive=archive_ref,
                      signature=signature_ref, signer=args.signer)] if phase['add'] else [],
            remove=phase['remove'], keyring=keyring, timeout_seconds=240,
            libalpm_sha256=worker.architecture_profile('aarch64')[0], profile_sha256=profile.PROFILE_SHA,
            input_selection_sha256=args.selection_sha256, candidate_binding=binding)
        worker.validate_contract(contract, args.selection_sha256)
        contract_path = workspace.parent / 'contract.json'; save(contract_path, contract)
        command = ['/usr/bin/python3', '-I', '-B', str(worker_path), '--contract', str(contract_path),
            '--contract-sha256', sha(contract_path.read_bytes()), '--output', str(workspace / 'evidence'),
            '--worker-source-sha256', selection['worker_sha256'], '--selection-sha256', args.selection_sha256,
            '--allow-disposable-payload-commit']
        env = worker.environment(CACHY_ASAHI_INSTALL_NONCE=selection['nonce'],
            CACHY_ASAHI_INSTALL_IMAGE=selection['image_id'])
        runtime = worker.runtime()
        runner = runtime.Runner(270, env, workspace.parent / 'supervisor-logs')
        with runtime.cancellation_handlers():
            completed = runner.run(command, timeout=270, limit=1024**2, log='worker.log')
        save(workspace.parent / 'worker-command.json', dict(argv=command, exit=completed.returncode,
             merged_output=completed.stdout.decode(errors='replace')))
        receipt_path = workspace / 'evidence/result.json'
        need(receipt_path.is_file(), 'actual guarded engine receipt missing')
        receipt = json.loads(read(receipt_path, 1024**2))
        need(completed.returncode == 0 and receipt['status'] == 'PASS-disposable-payload-transaction' and
             receipt['commit_started'] is True and receipt['committed'] is True and
             receipt['installed_payload_verified'] is True and receipt['parent_export_verified'] is True,
             'real guarded ALPM prepare/commit/export did not pass')
        exported = workspace / 'evidence/system-snapshot'; inventory, ownership = worker.candidate_database_records(exported)
        need(inventory == phase['after'] and receipt['before'] == phase['before'] and receipt['after'] == phase['after'],
             'actual post-commit/exported database differs')
        preserve(baseline_nodes, snapshot(exported))
        if not phase['add']:
            need(package['name'] not in inventory, 'candidate remains in remove export')
            payload = worker.archive_payload(read(archive_ref['path']))
            need(all(not (exported / name).exists() and not (exported / name).is_symlink()
                     for name, row in payload.items() if row['type'] != 'directory'), 'removed candidate payload remains')
        need(read(exported / SENTINEL) == FIXTURE, 'user sentinel changed')
        need(k.inventory(Path(args.kit)) == held_transport and snapshot(Path(args.state_dir)) == held_state,
             'read-only transport/checkpoint changed across transaction')
        previous = exported
        events.append(dict(phase=phase['phase'], status='PASS', inventory_count=len(inventory),
            actual_alpm_prepare=True, actual_alpm_commit=True, parent_export_verified=True, user_preserved=True,
            unrelated_base_database_nodes_preserved=True, engine_receipt_sha256=sha(receipt_path.read_bytes())))
    need(worker.candidate_database_records(previous)[0] == original, 'final original574 database was not restored')
    # Preserve safe internal user links across artifact upload as regular tar bytes.
    capsule=Path('/out/candidate-exports.tar.gz')
    with tarfile.open(capsule,'w:gz',dereference=False) as archive:
        for event in events:
            exported=Path('/out')/('phase-'+event['phase'])/'workspace/evidence/system-snapshot'
            snapshot(exported)
            archive.add(exported,arcname=event['phase'])
    need(capsule.stat().st_size<=16*1024**2,'bounded exported snapshot archive')
    report = dict(schema_version=1, status='PASS_FINITE_REAL_CANDIDATE_DISPOSABLE_ALPM_LIFECYCLE',
        export_capsule_sha256=sha(capsule.read_bytes()),selected_package=package, input_selection_sha256=args.selection_sha256, kit_sha256=selected_kit['kit_sha256'],
        events=events, offline_authentication_refusal_recovery=recovery, original574_database_restored=True, seed_scope='ALPM_DATABASE_ONLY_NOT_BOOTABLE_SYSTEM',
        full_base_payload_installed=False, host_mutation=False, user_preserved=True,
        hardware='NOT_RUN', generic16k='NOT_RUN', release='NOT_ADMITTED')
    save(Path('/out/candidate-lifecycle.json'), report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('kit', 'kit-sha256', 'signer', 'namespace', 'state-dir', 'selection', 'selection-sha256'):
        parser.add_argument('--' + key, required=True)
    parser.add_argument('--minimum-sequence', type=int, required=True)
    parser.add_argument('--source-root', default='/source'); parser.add_argument('--execute', action='store_true')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(run(args), sort_keys=True)); return 0
    except BaseException as error:
        print('real candidate lifecycle refused: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr); return 1


if __name__ == '__main__': raise SystemExit(main())
