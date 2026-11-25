#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compose existing offline kit/recovery workspaces into a held install handoff.

Run from a trusted checkout or authenticated finite operator runtime. Python
inside candidate/recovery kits is never executed. No package transaction, trust
enrollment, native actor or system operation runs.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('fresh_recovery_bundle', ROOT / 'scripts/release/recovery_bundle.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
K, C = R.K, R.C
spec = importlib.util.spec_from_file_location('fresh_operator_runtime', Path(__file__).with_name('runtime.py'))
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)
RECEIPT = 'handoff.json'
# Owning interfaces, selected helpers/templates and inventory, not an executable
# closure. Existing kit/recovery verification owns its own runtime/data closure.
SOURCES = (
    'manifests/packages.toml', 'scripts/install/local_transaction.py',
    'scripts/install/native_preflight.py', 'scripts/install/first_login.py',
    'scripts/repository/enroll.py', 'scripts/release/offline_kit.py',
    'scripts/release/recovery_bundle.py', 'scripts/platform/recovery_preflight.py',
    'packages/tools/cachy-asahi-first-login/PKGBUILD',
    'packages/tools/cachy-asahi-setup8/PKGBUILD',
    'packages/tools/cachy-asahi-setup8/cachy-asahi-setup',
    'packages/tools/cachy-asahi-repository-enrollment-v3/PKGBUILD',
    'packages/shells/cachy-asahi-fish-config/config.fish',
    'packages/shells/cachy-asahi-zsh-config/config.zsh',
    'packages/desktop/cachy-asahi-hyprland-settings011/hyprland.lua',
)
LIMITS = dict(packages_installed=False, trust_enrolled=False,
              fresh_recovery_signature_verification=True,
              native_preflight_run=False, boot_recovery_accepted=False,
              first_graphical_login='NOT RUN', native_arm='NOT RUN',
              m2_air_13='NOT RUN', m2_air_15='NOT RUN', release_accepted=False)


def need(ok, message):
    C.need(ok, message)


def selection(raw):
    value = C.decode(raw)
    need(set(value) == {'schema_version', 'purpose', 'source_commit', 'candidate', 'recovery'},
         'closed fresh handoff selection required')
    need(type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['purpose'] == 'development-fresh-install-handoff', 'development selection required')
    need(type(value['source_commit']) is str and re.fullmatch('[0-9a-f]{40}', value['source_commit']),
         'exact source commit required')
    for role, pins in (('candidate', {'kit_sha256', 'release_sha256'}),
                       ('recovery', {'receipt_sha256', 'selection_sha256', 'release_sha256'})):
        row = value[role]
        need(type(row) is dict and set(row) == pins | {'signer', 'namespace', 'minimum_sequence'},
             'closed independent ' + role + ' authority required')
        for field in pins:
            C.reference(field, row[field])
        need(type(row['signer']) is str and re.fullmatch('[0-9A-F]{40}', row['signer']), 'primary signer required')
        need(type(row['namespace']) is str and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', row['namespace']),
             'namespace required')
        need(type(row['minimum_sequence']) is int and row['minimum_sequence'] >= 1, 'positive sequence floor required')
    return value


def source_refs(commit):
    """Refuse a dirty owning interface; bind both Git body and trusted checkout."""
    lock = globals().get('DELIVERED_SOURCE_LOCK')
    if lock is not None:
        need(type(lock) is dict and set(lock) == {'schema_version', 'purpose', 'source_commit', 'source_refs'} and
             type(lock['schema_version']) is int and lock['schema_version'] == 1 and
             lock['purpose'] == 'fresh-handoff-owning-source-witnesses' and
             lock['source_commit'] == commit and type(lock['source_refs']) is dict and
             set(lock['source_refs']) == set(SOURCES), 'DELIVERED_SOURCE_LOCK_REFUSED')
        for name, row in lock['source_refs'].items():
            need(type(row) is dict and set(row) == {'size', 'sha256'} and type(row['size']) is int,
                 'DELIVERED_SOURCE_REFERENCE_REFUSED')
            raw = C.read_path(ROOT / name, C.MAX_JSON)
            need(len(raw) == row['size'] and C.digest(raw) == row['sha256'], 'DELIVERED_SOURCE_BODY_REFUSED: ' + name)
        return lock['source_refs']
    refs = {}
    for name in SOURCES:
        result = subprocess.run(['git', '-C', str(ROOT), 'show', commit + ':' + name],
                                capture_output=True, timeout=15, check=False)
        need(result.returncode == 0, 'source commit/member unavailable: ' + name)
        raw = C.read_path(ROOT / name, C.MAX_JSON)
        need(raw == result.stdout, 'trusted source differs from selected commit: ' + name)
        refs[name] = dict(sha256=C.digest(raw), size=len(raw))
    return refs


def checked_role(label, function):
    try:
        return function()
    except (C.Error, ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise C.Error(label + ': ' + str(error)) from error


def fresh_recovery(recovery, prior):
    return R.verify_recovery_signatures(recovery, prior['recovery_packages'])

def receiver_states(args):
    candidate = C.absolute(str(args.state_dir))
    recovery = getattr(args, 'recovery_state_dir', None)
    return candidate, candidate if recovery is None else C.absolute(str(recovery))


def inspect_inputs(candidate, recovery, chosen, states):
    candidate_state, recovery_state = states
    candidate_args = {key: chosen['candidate'][key] for key in
                      ('kit_sha256', 'signer', 'namespace', 'minimum_sequence')}
    checked = checked_role('CANDIDATE_AUTH_REFUSED',
        lambda: K.inspect(argparse.Namespace(kit=str(candidate), state_dir=str(candidate_state), **candidate_args)))
    need(checked['release_sha256'] == chosen['candidate']['release_sha256'], 'candidate release differs')
    recovery_args = {key: chosen['recovery'][key] for key in
                     ('receipt_sha256', 'selection_sha256', 'signer', 'namespace', 'minimum_sequence')}
    prior = checked_role('PREDECESSOR_AUTH_REFUSED',
        lambda: R.verify(argparse.Namespace(workspace=str(recovery), state_dir=str(recovery_state), **recovery_args)))
    need(prior['predecessor_release_sha256'] == chosen['recovery']['release_sha256'], 'predecessor release differs')
    need(chosen['candidate']['signer'] == chosen['recovery']['signer'],
         'SIGNER_TRANSITION_HELD: a separately reviewed signer transition is required')
    fresh_recovery(recovery, prior)
    # This first slice preserves the platform. A coordinated platform change
    # needs a separate qualified path rather than an arbitrary predecessor.
    candidate_spec = C.decode(R.read(candidate, 'release/spec.json'))
    base = C.decode(R.read(candidate, 'release/base.json'))
    recovery_selection = R.selection(R.read(recovery, 'selection.json'))
    protected = candidate_spec['policy']['protected_packages']
    need(type(protected) is list and protected and len(set(protected)) == len(protected),
         'explicit protected platform required')
    rows = {row['name']: row for row in base['packages']}
    need(len(rows) == len(base['packages']), 'duplicate candidate base package')
    versions = {name: {key: rows[name][key] for key in ('version', 'arch')} for name in protected}
    need(versions == recovery_selection['protected_versions'],
         'candidate/predecessor protected platform differs; coordinated platform change held')
    return checked, prior


def actions(chosen):
    """No shell interpolation, implicit apply, invented live installer or actor entry."""
    return [
        dict(step=1, state='OFFLINE_CHECK', action='Verify this handoff from the authenticated finite operator runtime or matching trusted checkout with external selection/receipt/runtime pins and receiver state.',
             hold='Successful byte/signature checks authorize no installation or production trust.'),
        dict(step=2, state='RETAIN', action='Keep recovery/ and a separate externally pinned copy reachable outside the target before any target mutation.',
             hold='Offline predecessor archives are retained data; boot/session restoration is NOT RUN.'),
        dict(step=3, state='HELD', action='After offline verification and recovery retention, start in macOS with verified backups and use the maintained installer for the selected Asahi base.',
             hold='Installer and base image authentication, disk/boot prerequisites, recovery access and the independent macOS-to-Asahi journey on each exact M2 Air remain open.'),
        dict(step=4, state='HELD', action='Obtain the coordinator-admitted native preflight and full selected Asahi transaction for this exact candidate.',
             tool='scripts/install/native_preflight.py; scripts/install/local_transaction.py',
             hold='Native preflight is an in-process admitted actor, not a general CLI. The transaction worker accepts explicit disposable fixtures only; do not point it at the live root.'),
        dict(step=5, state='HELD', action='Preview authenticated repository configuration using the reviewed enrollment package and independently authenticated endpoint/trust inputs.',
             tool='cachy-asahi-repository-enrollment configure --help',
             hold='No production endpoint or independent production trust is supplied. No enrollment/apply command is generated.'),
        dict(step=6, state='HELD', action='Install the exact complete release transaction only through its reviewed target installation path; retain before/after inventories.',
             release_sha256=chosen['candidate']['release_sha256'],
             hold='Development kit inspection is not package installation. Live Asahi installer integration and platform hooks remain unqualified.'),
        dict(step=7, state='USER_CONFIGURATION_ONLY', action='As the intended ordinary user, inspect then explicitly select installed components with the first-login tool.',
             preview_argv=['cachy-asahi-first-login', 'inspect'],
             select_preview_argv=['cachy-asahi-first-login', 'activate', '--components', 'fish', 'zsh'],
             hold='Apply is a separate user decision. Existing configuration is owned by Setup8; pending transactions must use its recover preview/apply with the original roots.'),
        dict(step=8, state='HELD', action='Keep the base session available; validate Hyprland configuration and select it through the retained base launcher. Exercise failure recovery.',
             hold='First graphical login, firmware/boot/kernel/Mesa/audio preservation and boot/session restoration on both M2 sizes are NOT RUN.'),
    ]


def instructions(chosen):
    lines = ['DEVELOPMENT FRESH INSTALL HANDOFF — HELD',
             'Candidate release SHA-256: ' + chosen['candidate']['release_sha256'],
             'Predecessor release SHA-256: ' + chosen['recovery']['release_sha256'],
             'Source commit: ' + chosen['source_commit'],
             'Candidate/recovery kits are offline DATA. Run the authenticated operator runtime or matching trusted checkout.',
             'This is not a supported installer, installation result or release admission.', '']
    for row in actions(chosen):
        lines += [f"{row['step']}. [{row['state']}] {row['action']}", '   Hold: ' + row['hold']]
        if 'tool' in row:
            lines.append('   Existing tool: ' + row['tool'])
        for key in ('preview_argv', 'select_preview_argv'):
            if key in row:
                lines.append('   Review argv: ' + json.dumps(row[key]))
    return ('\n'.join(lines) + '\n').encode()


def boundary(output, candidate, recovery, states):
    paths = [C.absolute(str(p)) for p in (output, candidate, recovery)]
    for i, first in enumerate(paths):
        for second in (*paths[i + 1:], *states):
            need(not first.is_relative_to(second) and not second.is_relative_to(first), 'handoff/input/state roots must be disjoint')
    return paths


def copy_data(source, target):
    files, links = K.inventory(source)
    fd = C.directory(source)
    try:
        for name, pin in files.items():
            destination = target / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            actual, _ = C.hash_member(fd, name, snapshot=destination)
            need(actual == pin, 'input changed during handoff copy')
            destination.chmod(0o400)
    finally:
        os.close(fd)
    for name, link in links.items():
        (target / name).symlink_to(link)
    need(K.inventory(target) == (files, links), 'input copy differs')


def report(chosen, pin, refs, runtime_pin):
    return dict(status='HELD_DEVELOPMENT_HANDOFF', receipt_sha256=pin,
                composer_sha256=C.digest(C.read_path(Path(__file__).resolve(), C.MAX_JSON)),
                runtime_sha256=runtime_pin,
                candidate_release_sha256=chosen['candidate']['release_sha256'],
                predecessor_release_sha256=chosen['recovery']['release_sha256'],
                source_commit=chosen['source_commit'], source_refs=refs,
                actions=actions(chosen), **LIMITS)


def verify(args):
    root, states = C.absolute(str(args.workspace)), receiver_states(args)
    for state in states:
        need(not root.is_relative_to(state) and not state.is_relative_to(root), 'receiver state must be outside handoff')
    fd = C.directory(root)
    try:
        info = os.fstat(fd)
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'caller-owned private 0700 handoff required')
    finally:
        os.close(fd)
    raw = R.pinned(root / RECEIPT, args.receipt_sha256)
    receipt = C.decode(raw)
    need(set(receipt) == {'schema_version', 'purpose', 'selection_sha256', 'files', 'symlinks', 'source_refs', 'composer_sha256', 'runtime_sha256'} and
         type(receipt['schema_version']) is int and receipt['schema_version'] == 2 and
         receipt['purpose'] == 'held-offline-fresh-install-handoff', 'unsupported handoff receipt')
    need(receipt['selection_sha256'] == args.selection_sha256, 'external selection differs')
    files, links = K.inventory(root)
    need(files.pop(RECEIPT, None) == args.receipt_sha256 and
         files == receipt['files'] and links == receipt['symlinks'], 'handoff changed/incomplete/foreign members')
    chosen = selection(R.pinned(root / 'selection.json', args.selection_sha256))
    refs = source_refs(chosen['source_commit'])
    need(refs == receipt['source_refs'], 'source references differ')
    lock = D.verify(root / 'operator', receipt['runtime_sha256'])
    need(lock['source_commit'] == chosen['source_commit'] and lock['source_refs'] == refs,
         'OPERATOR_SOURCE_BINDING_REFUSED')
    need(receipt['composer_sha256'] == C.digest(C.read_path(Path(__file__).resolve(), C.MAX_JSON)),
         'trusted composer differs from handoff')
    inspect_inputs(root / 'candidate', root / 'recovery', chosen, states)
    need(C.read_path(root / 'ACTIONS.txt', C.MAX_JSON) == instructions(chosen), 'operator instructions differ')
    after, after_links = K.inventory(root)
    need(after.pop(RECEIPT, None) == args.receipt_sha256 and after == files and after_links == links,
         'handoff changed during validation')
    return report(chosen, args.receipt_sha256, refs, receipt['runtime_sha256'])


def prepare(args):
    states = receiver_states(args)
    output, candidate, recovery = boundary(args.output, args.candidate, args.recovery, states)
    need(not output.exists() and not output.is_symlink(), 'fresh output required')
    raw = R.pinned(C.absolute(str(args.selection)), args.selection_sha256)
    chosen = selection(raw)
    refs = source_refs(chosen['source_commit'])
    inspect_inputs(candidate, recovery, chosen, states)
    parent = C.directory(output.parent)
    try:
        info = os.fstat(parent)
        need(info.st_uid == os.geteuid() and not info.st_mode & 0o022, 'private caller-owned output parent required')
        with tempfile.TemporaryDirectory(prefix='.fresh-handoff-', dir=output.parent) as temporary:
            staging = Path(temporary) / 'handoff'
            staging.mkdir(mode=0o700)
            created = staging.stat()
            copy_data(candidate, staging / 'candidate')
            copy_data(recovery, staging / 'recovery')
            runtime = D.stage(ROOT, staging / 'operator', chosen['source_commit'], refs)
            R.write(staging, 'selection.json', raw)
            R.write(staging, 'ACTIONS.txt', instructions(chosen))
            files, links = K.inventory(staging)
            receipt = dict(schema_version=2, purpose='held-offline-fresh-install-handoff',
                           selection_sha256=args.selection_sha256, source_refs=refs, files=files, symlinks=links,
                           runtime_sha256=runtime['runtime_sha256'],
                           composer_sha256=C.digest(C.read_path(Path(__file__).resolve(), C.MAX_JSON)))
            receipt_raw = C.encoded(receipt)
            need(len(receipt_raw) <= C.MAX_JSON, 'handoff receipt too large')
            R.write(staging, RECEIPT, receipt_raw)
            checked = verify(argparse.Namespace(workspace=str(staging), state_dir=states[0], recovery_state_dir=states[1],
                             selection_sha256=args.selection_sha256, receipt_sha256=C.digest(receipt_raw)))
            K.publish(staging, parent, output, (created.st_dev, created.st_ino))
    finally:
        os.close(parent)
    return dict(checked, path=str(output))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='operation', required=True)
    build = commands.add_parser('prepare')
    check = commands.add_parser('verify')
    for command in (build, check):
        command.add_argument('--selection-sha256', required=True)
        command.add_argument('--state-dir', required=True, type=Path)
        command.add_argument('--recovery-state-dir', type=Path,
                             help='external predecessor receiver state (defaults to --state-dir)')
    for name in ('selection', 'candidate', 'recovery', 'output'):
        build.add_argument('--' + name, required=True, type=Path)
    check.add_argument('--workspace', required=True, type=Path)
    check.add_argument('--receipt-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        result = prepare(args) if args.operation == 'prepare' else verify(args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (C.Error, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print('fresh handoff refused: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
