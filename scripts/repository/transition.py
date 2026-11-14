#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preview a dual-signed release handoff; --apply rotates local managed trust only."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


T = module('repository_release_transition', HERE.parent / 'release/signing_transition.py')


def load_rotation():
    # Each invocation owns its dependency instance; no shared/global patching.
    return module('repository_transition_rotation', HERE / 'rotate.py')


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def retained(paths, owner, E):
    """Freeze safe input identities; signed payload/content checks remain T.verify's job."""
    observed = {}
    host_root_owner = Path('/').lstat().st_uid
    for value in paths:
        root = E.canonical(str(value))
        E.directory(root, owner)
        for parent in root.parents:
            row = parent.lstat()
            E.need(stat.S_ISDIR(row.st_mode) and row.st_uid in (owner, host_root_owner),
                   'unsafe retained-input ancestor ownership/type')
            # A trusted sticky temporary ancestor protects its owned children.
            # host_root_owner differs from zero only in mapped-root test namespaces.
            E.need(not row.st_mode & 0o022 or row.st_mode & stat.S_ISVTX and row.st_uid == host_root_owner,
                   'writable retained-input ancestor')
            observed[parent] = (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid)
        members = [root]
        for path in root.rglob('*'):
            E.need(len(members) < 65536, 'retained input member bound')
            members.append(path)
        for path in members:
            row = path.lstat()
            E.need(row.st_uid == owner, 'retained input owner mismatch: ' + str(path))
            if stat.S_ISLNK(row.st_mode):
                target = os.readlink(path)
                E.need(path != root and row.st_nlink == 1 and '/' not in target and target not in ('', '.', '..') and
                       stat.S_ISREG((path.parent / target).lstat().st_mode), 'unsafe retained repository link')
            else:
                E.need(not row.st_mode & 0o022 and (stat.S_ISDIR(row.st_mode) or
                       stat.S_ISREG(row.st_mode) and row.st_nlink == 1), 'unsafe retained input: ' + str(path))
            observed[path] = E.identity(row)
    return observed


def current(selection, expected, certificate_sha256, E):
    E.need(selection['enabled'] and selection['managed'], 'transition requires an enabled managed repository')
    E.need(selection['managed']['fingerprint'] == expected and
           selection['managed']['key_sha256'] == certificate_sha256,
           'managed current fingerprint/certificate differs from signed predecessor')


@contextmanager
def handoff(selection, public, raw, apply, E):
    if not apply and public.is_relative_to(selection['root']):
        yield public
        return
    parent = selection['root'] / 'var/lib/pacman'
    E.parents(parent / '.transition', selection['root'], selection['owner'])
    E.directory(parent, selection['owner'])
    with tempfile.TemporaryDirectory(prefix='.cachy-asahi-transition-', dir=parent) as temporary:
        copied = Path(temporary) / 'successor-public.gpg'
        copied.write_bytes(raw)
        copied.chmod(0o400)
        E.parents(copied, selection['root'], selection['owner'])
        E.need(E.read(copied, selection['owner'])[0] == raw, 'private successor handoff changed')
        yield copied


def execute(root, bundle, before, after, expected_current, fingerprint, *, apply=False, as_of=None):
    rotation = load_rotation()
    E = rotation.E
    report = dict(status='preview', operation='authenticated-release-signing-key-transition',
                  config_changed=False, config_may_have_changed=False, keyring_may_have_changed=False,
                  keys_removed=False, old_trust_retained=True, packages_installed=False, network_used=False,
                  production_accepted=False, stable_eligibility_checked=False, snapshot_upgrade_accepted=False)
    rotated = None
    try:
        E.need(not apply or as_of is None, '--as-of is diagnostic preview only; apply uses real current UTC')
        E.need(not apply or os.geteuid() == 0, '--apply requires root; tests may use a disposable mapped root')
        selection = E.state(root, 'enroll')
        E.need(not apply or selection['owner'] == 0, '--apply requires root-owned selected root')
        for key in (expected_current, fingerprint):
            E.need(isinstance(key, str) and E.FPR.fullmatch(key), 'full uppercase primary fingerprint required')
        paths = tuple(E.canonical(str(path)) for path in (bundle, before, after))
        E.need(all(not left.is_relative_to(right) for i, left in enumerate(paths)
                   for j, right in enumerate(paths) if i != j), 'disjoint retained input directories required')
        observed = retained(paths, selection['owner'], E)
        bundle, before, after = paths
        checked = T.verify(bundle, before, after, expected_current, fingerprint, as_of or utc_now())
        record = checked['transition']
        current(selection, expected_current, record['certificates']['old'], E)
        E.need(record['before']['repo_name'] == E.REPO, 'transition names a different managed repository')
        public = bundle / 'new-public.asc'
        raw = T.read(public)
        E.need(E.sha(raw) == record['certificates']['new'], 'successor certificate differs from transition')
        report.update(transition_sha256=checked['transition_sha256'], before=record['before'], after=record['after'],
                      expected_current_fingerprint=expected_current, fingerprint=fingerprint,
                      snapshot_url=selection['managed']['url'], snapshot_url_retained=True,
                      as_of=checked['as_of'], current_revocation='UNKNOWN_OFFLINE_EXPORT')

        copied_path, copied_observed = None, None

        def unchanged():
            E.need(retained(paths, selection['owner'], E) == observed, 'retained transition inputs changed')
            E.stable(selection)
            if copied_path is not None:
                E.parents(copied_path, selection['root'], selection['owner'])
                E.need(E.read(copied_path, selection['owner']) == copied_observed,
                       'private successor handoff changed before mutation')

        unchanged()
        original_lock, original_run = E.lock, E.run
        authorized = False

        @contextmanager
        def guarded_lock(active):
            nonlocal authorized
            with original_lock(active):
                unchanged()
                current(active, expected_current, record['certificates']['old'], E)
                fresh = T.verify(bundle, before, after, expected_current, fingerprint, utc_now())
                E.need(fresh['transition_sha256'] == checked['transition_sha256'] and fresh['transition'] == record,
                       'transition authorization changed before mutation')
                unchanged()
                T.validate(record, expected_current, fingerprint, utc_now())
                report['as_of'] = fresh['as_of']
                authorized = True
                try:
                    yield
                finally:
                    authorized = False

        def guarded_run(argv, home):
            if argv[0] == '/usr/bin/pacman-key':
                E.need(apply and authorized and ('--add' in argv or '--lsign-key' in argv),
                       'trust mutation requires locked authenticated transition')
                # Reject a queued/stale overlap or observed input edit at each
                # actual mutation, even after the potentially lengthy verifier.
                T.validate(record, expected_current, fingerprint, utc_now())
                unchanged()
            return original_run(argv, home)

        # The unchanged rotation implementation always acquires E.lock before
        # any import/local-sign, then uses its own observed-current CAS.
        E.lock, E.run = guarded_lock, guarded_run
        with handoff(selection, public, raw, apply, E) as copied:
            copied_path = copied
            copied_observed = E.read(copied, selection['owner'])
            E.need(copied_observed[0] == raw, 'successor handoff body differs from verified certificate')
            rotated = rotation.execute(selection['root'], expected_current, copied, fingerprint, apply)
        for name in ('status', 'config_changed', 'config_may_have_changed', 'keyring_may_have_changed'):
            report[name] = rotated[name]
        report['rotation'] = rotated
        return report
    except BaseException as error:
        details = getattr(error, 'rotation_result', rotated)
        if details is not None:
            report['rotation'] = details
            for name in ('config_changed', 'config_may_have_changed', 'keyring_may_have_changed'):
                report[name] = details[name]
        report.update(status='failed', error=str(error) or type(error).__name__,
                      recovery='Inspect actual managed selection and keyring before retrying. Existing imports/local signatures '
                               'are retained; no trust rollback, snapshot switch or key removal is automatic.')
        error.transition_result = report
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path('/'), help='existing root; alternate roots are disposable-test only')
    parser.add_argument('--apply', action='store_true', help='rotate local trust after locked handoff verification')
    for name in ('bundle', 'before', 'after'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-current-fingerprint', required=True)
    parser.add_argument('--fingerprint', required=True, help='independently authenticated NEW primary fingerprint')
    parser.add_argument('--as-of', help='diagnostic preview UTC time only; forbidden with --apply')
    args = parser.parse_args(argv)
    try:
        result = execute(args.root, args.bundle, args.before, args.after, args.expected_current_fingerprint,
                         args.fingerprint, apply=args.apply, as_of=args.as_of)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (T.r.Error, T.expiry.Error, OSError, ValueError, KeyError, TypeError, RecursionError,
            subprocess.SubprocessError, KeyboardInterrupt) as error:
        print(json.dumps(getattr(error, 'transition_result', dict(status='failed', error=str(error))), sort_keys=True))
        return 1


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InterruptedError('interrupted by SIGTERM')))
    raise SystemExit(main())
