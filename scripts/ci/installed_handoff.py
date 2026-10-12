#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare a sanitized installed baseline inside a guarded disposable ARM root.

This wrapper never commits an image or invokes Docker. Only its controller may
commit after exit 0 and the independently reviewed READY receipt.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True  # No import cache writes before the environment guard.
LIFECYCLE = HERE / 'lifecycle.py' if HERE == Path('/runner') else HERE.parent / 'integration/lifecycle.py'
SPEC = importlib.util.spec_from_file_location('handoff_lifecycle', LIFECYCLE)
lifecycle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lifecycle)

INPUTS, RUNNER, OUTPUT, SYSTEM = Path('/inputs'), Path('/runner'), Path('/out'), Path('/')
PURPOSE = 'sanitized-baseline-image-handoff'
LIMIT = 4 * 1024**2
FIELDS = {'schema_version', 'purpose', 'source_commit', 'lifecycle_contract_sha256',
          'lifecycle_script_sha256', 'base_packages_sha256', 'baseline'}


class Cancelled(Exception):
    """Controlled cancellation, with no exception text exported."""


def image_tmp_view(observed):
    lifecycle.require(not any(path == '/tmp' or path.startswith('/tmp/') for path in observed['mounts']),
                      'handoff must inspect the image /tmp; mounted temporary view refused')


def inventory(text):
    rows = {}
    for line in text.splitlines():
        parts = line.split(' ')
        lifecycle.require(len(parts) == 2 and re.fullmatch(r'[A-Za-z0-9@._+:-]+', parts[0])
                          and re.fullmatch(r'[A-Za-z0-9._+:~-]+', parts[1])
                          and parts[0] not in rows, 'invalid/duplicate installed inventory')
        rows[parts[0]] = parts[1]
    lifecycle.require(bool(rows), 'empty installed inventory')
    return rows


def inventory_bytes(rows):
    return ''.join(f'{name} {rows[name]}\n' for name in sorted(rows)).encode('ascii')


def load(root, name, digest):
    path = lifecycle.pinned(root, name, digest)
    lifecycle.require(path.stat().st_size <= LIMIT, 'contract exceeds input bound')
    data = path.read_bytes()
    lifecycle.require(hashlib.sha256(data).hexdigest() == digest, 'input changed during contract read')
    return lifecycle.strict_json(data.decode('utf-8'))


def parents(path):
    lifecycle.require(path.is_relative_to(SYSTEM), 'system path escaped disposable root')
    for parent in (path.parent, *path.parent.parents):
        lifecycle.require(not parent.is_symlink() and parent.is_dir(), 'symlink/non-directory system ancestor')
        if parent == SYSTEM:
            break


class Handoff:
    def __init__(self, contract_path, digest):
        # Use the actual lifecycle guard before parsing even the commit input.
        observed = lifecycle.actual_environment()
        lifecycle.environment_guard(observed)
        image_tmp_view(observed)
        lifecycle.require(contract_path == INPUTS / 'commit.json', 'fixed commit input required')
        self.commit = load(INPUTS, 'commit.json', digest)
        lifecycle.require(isinstance(self.commit, dict) and set(self.commit) == FIELDS
                          and self.commit['schema_version'] == 1 and self.commit['purpose'] == PURPOSE,
                          'explicit exact commit contract required')
        lifecycle.require(isinstance(self.commit['source_commit'], str)
                          and re.fullmatch(r'[0-9a-f]{40}', self.commit['source_commit']), 'source commit required')
        self.contract = load(INPUTS, 'lifecycle.json', self.commit['lifecycle_contract_sha256'])
        lifecycle.validate_contract(self.contract)
        lifecycle.require(self.contract.get('baseline_handoff') is True
                          and self.contract['source_commit'] == self.commit['source_commit']
                          and self.contract['baseline'] == self.commit['baseline'], 'lifecycle baseline/source binding differs')
        lifecycle.pinned(RUNNER, 'lifecycle.py', self.commit['lifecycle_script_sha256'])
        lifecycle.require(Path(lifecycle.__file__).resolve() == RUNNER / 'lifecycle.py', 'guard must come from pinned runner snapshot')
        base_path = lifecycle.pinned(INPUTS, 'base-packages.lock', self.commit['base_packages_sha256'])
        lifecycle.require(base_path.stat().st_size <= LIMIT, 'base inventory exceeds bound')
        base_bytes = base_path.read_bytes()
        lifecycle.require(hashlib.sha256(base_bytes).hexdigest() == self.commit['base_packages_sha256'], 'base inventory read drift')
        self.base = inventory(base_bytes.decode('ascii'))
        lifecycle.require(not set(self.base) & set(lifecycle.PACKAGES), 'base already contains overlay')
        self.versions = {row['name']: row['version'] for row in self.contract['baseline']}
        self.payloads = {row['name']: row['payload_sha256'] for row in self.contract['baseline']}
        self.guard()
        lifecycle.require(OUTPUT.is_dir() and not OUTPUT.is_symlink(), 'existing real evidence mount required')
        self.receipt = OUTPUT / 'commit-receipt.json'
        self.lock = OUTPUT / 'installed-packages.lock'
        lifecycle.require(not self.receipt.exists() and not self.receipt.is_symlink()
                          and not self.lock.exists() and not self.lock.is_symlink()
                          and not (OUTPUT / 'lifecycle').exists() and not (OUTPUT / 'lifecycle').is_symlink(), 'fresh handoff output required')
        self.report = {'schema_version': 1, 'purpose': PURPOSE, 'status': 'FAIL',
                       'source_commit': self.commit['source_commit'], 'image_id': self.contract['image_id'],
                       'nonce': self.contract['nonce'], 'commit_contract_sha256': digest,
                       'lifecycle_contract_sha256': self.commit['lifecycle_contract_sha256'],
                       'lifecycle_script_sha256': self.commit['lifecycle_script_sha256'],
                       'base_packages_sha256': self.commit['base_packages_sha256'],
                       'package_versions': self.versions, 'payload_sha256': self.payloads,
                       'hardware_status': 'NOT RUN', 'checks': []}
        self.child = None
        self.cancelled = False

    def guard(self):
        observed = lifecycle.actual_environment()
        lifecycle.environment_guard(observed, self.contract['nonce'], self.contract['image_id'])
        image_tmp_view(observed)

    def cancel(self, *_):
        self.cancelled = True
        self.report.update(status='FAIL', cancelled=True)
        raise Cancelled()

    def stop_child(self):
        """Bounded attempts against only the session created by this wrapper.

        Container removal remains the controller's final boundary for processes
        outside this group; no additional capabilities are granted here.
        """
        child, self.child = self.child, None
        if child is None:
            return
        outcome = {'status': 'PASS', 'scope': 'bounded group signals and direct-child reap',
                   'container_removal_required': True, 'signals': []}
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(child.pid, sig)
                outcome['signals'].append(sig.name)
            except ProcessLookupError:
                pass
            except (Cancelled, KeyboardInterrupt, OSError, ValueError):
                outcome['status'] = 'FAIL'
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                outcome['status'] = 'FAIL' if sig == signal.SIGKILL else outcome['status']
            except (Cancelled, KeyboardInterrupt, subprocess.SubprocessError, OSError, ValueError):
                outcome['status'] = 'FAIL'
        for stream in (child.stdout, child.stderr):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    outcome['status'] = 'FAIL'
        self.report['child_group_cleanup'] = outcome
        if outcome['status'] != 'PASS':
            self.report['status'] = 'FAIL'

    def check(self, name, condition):
        self.report['checks'].append({'check': name, 'status': 'PASS' if condition else 'FAIL'})
        lifecycle.require(condition, name)

    def command(self, command, timeout=60):
        self.guard()
        try:
            # Block cancellation only until the child session is tracked. Restore
            # the child's mask before exec so TERM/INT remain effective there.
            mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
            try:
                self.child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
                                              preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, mask),
                                              env={'PATH': '/usr/bin:/bin', 'HOME': '/root', 'LC_ALL': 'C',
                                                   'PYTHONDONTWRITEBYTECODE': '1',
                                                   'CACHY_ASAHI_DISPOSABLE_LIFECYCLE': self.contract['nonce'],
                                                   'CACHY_ASAHI_IMAGE_ID': self.contract['image_id']})
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            stdout, stderr = self.child.communicate(timeout=timeout)
            code = self.child.returncode
            self.child = None
        except BaseException:
            # Ignore repeated termination while the bounded cleanup runs.
            previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGTERM, signal.SIGINT)}
            try:
                self.stop_child()
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
            raise
        self.check('bounded-command-output', len(stdout) <= LIMIT and len(stderr) <= LIMIT)
        self.check('command-exit-zero', code == 0)
        return stdout.decode('utf-8')

    def verify_installed(self):
        rows = inventory(self.command(['/usr/bin/pacman', '-Q']))
        self.check('exact-base-plus-originals-inventory', rows == {**self.base, **self.versions})
        for row in self.contract['baseline']:
            owned = set()
            directories = {str(parent) for path in row['payload_sha256']
                           for parent in PurePosixPath(path).parents if str(parent) != '.'}
            for line in self.command(['/usr/bin/pacman', '-Ql', row['name']]).splitlines():
                name, path = line.split(' ', 1)
                self.check('package-list-owner', name == row['name'] and path.startswith('/'))
                if path.endswith('/'):
                    relative = path[1:].rstrip('/')
                    lifecycle.safe_relative(relative)
                    self.check('owned-directory-scope', relative in directories)
                    continue
                relative = path[1:]
                lifecycle.safe_relative(relative)
                self.check('owned-path-scope', lifecycle.allowed_file(row['name'], relative) and relative not in owned)
                owned.add(relative)
            self.check('complete-pacman-owned-payload', owned == set(row['payload_sha256']))
            for relative, digest in row['payload_sha256'].items():
                lifecycle.safe_relative(relative)
                self.check('payload-scope', lifecycle.allowed_file(row['name'], relative))
                path = SYSTEM / relative
                parents(path)
                info = path.lstat()
                self.check('regular-root-owned-payload', stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                           and info.st_uid == info.st_gid == 0 and not info.st_mode & 0o6022)
                self.check('original-payload-hash', lifecycle.sha(path) == digest)
        self.command(['/usr/bin/pacman', '-Qk', *sorted(lifecycle.PACKAGES)])
        return rows

    def remove(self, path):
        self.guard()
        parents(path)
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISDIR(info.st_mode):
            lifecycle.require(shutil.rmtree.avoids_symlink_attacks, 'safe directory removal unavailable')
            shutil.rmtree(path)
        else:
            path.unlink()  # Includes symlinks; never follows their targets.

    def empty(self, relative):
        root = SYSTEM / relative
        parents(root)
        lifecycle.require(root.is_dir() and not root.is_symlink(), 'cleanup root is not a real directory')
        for entry in root.iterdir():
            self.remove(entry)

    def cleanup(self):
        self.guard()
        alarm = pwd.getpwnam('alarm')
        self.check('ordinary-alarm-account', alarm.pw_uid > 0 and alarm.pw_gid > 0 and alarm.pw_dir == '/home/alarm')
        self.remove(SYSTEM / 'etc/pacman.d/gnupg')
        for relative in ('root', 'home', 'tmp', 'var/cache/pacman/pkg'):
            self.empty(relative)
        for relative in ('var/log/pacman.log', 'var/lib/gnupg'):
            self.remove(SYSTEM / relative)
        self.guard()
        home = SYSTEM / 'home/alarm'
        home.mkdir(mode=0o700)
        os.chown(home, alarm.pw_uid, alarm.pw_gid)
        self.check('private-keyring-removed', not (SYSTEM / 'etc/pacman.d/gnupg').exists())
        self.check('root-empty', not any((SYSTEM / 'root').iterdir()))
        self.check('only-empty-alarm-home', list((SYSTEM / 'home').iterdir()) == [home] and not any(home.iterdir()))
        self.check('alarm-home-ownership', home.stat().st_uid == alarm.pw_uid and home.stat().st_gid == alarm.pw_gid)
        for relative in ('tmp', 'var/cache/pacman/pkg'):
            self.check('empty-' + relative, not any((SYSTEM / relative).iterdir()))
        self.check('system-gnupg-state-removed', not (SYSTEM / 'var/lib/gnupg').exists())
        for relative in ('etc/pacman.d', 'root', 'home', 'tmp', 'var/cache/pacman'):
            root = SYSTEM / relative
            parents(root)
            self.check('private-root-not-symlink', root.is_dir() and not root.is_symlink())
            for current, dirs, files in os.walk(root, followlinks=False):
                # Symlinks are inspected by name only, never dereferenced.
                self.check('no-private-key-state', all(not re.search(r'private-keys-v1\.d|secret|openpgp-revocs', name, re.I)
                                                      for name in (*dirs, *files)))
        self.report['private_cleanup'] = 'PASS; no private contents or hashes recorded'

    def execute(self):
        # Seed a failure receipt only after every source/contract pin has passed.
        with self.receipt.open('x') as stream:
            json.dump(self.report, stream, indent=2, sort_keys=True)
        previous = {sig: signal.signal(sig, self.cancel) for sig in (signal.SIGTERM, signal.SIGINT)}
        try:
            self.command(['/usr/bin/python3', '-B', str(RUNNER / 'lifecycle.py'), '--execute-disposable-container',
                          '--baseline-handoff', '--contract', str(INPUTS / 'lifecycle.json'),
                          '--contract-sha256', self.commit['lifecycle_contract_sha256'], '--output', str(OUTPUT / 'lifecycle')], 1800)
            result_path = OUTPUT / 'lifecycle/result.json'
            lifecycle.regular(result_path)
            lifecycle.require(result_path.stat().st_size <= LIMIT, 'lifecycle receipt exceeds bound')
            result = lifecycle.strict_json(result_path.read_text())
            self.check('successful-lifecycle-handoff', result.get('status') == 'PASS' and result.get('baseline_handoff_ready') is True)
            self.check('lifecycle-receipt-binding', result.get('source_commit') == self.commit['source_commit']
                       and result.get('image_id') == self.contract['image_id']
                       and result.get('contract_sha256') == self.commit['lifecycle_contract_sha256']
                       and result.get('handoff_package_versions') == self.versions
                       and result.get('handoff_payload_sha256') == self.payloads)
            self.verify_installed()
            self.cleanup()
            installed = self.verify_installed()
            self.guard()
            self.check('image-tmp-view-empty', not any((SYSTEM / 'tmp').iterdir()))
            data = inventory_bytes(installed)
            with self.lock.open('xb') as stream:
                stream.write(data)
            self.report.update(status='READY', installed_packages_sha256=hashlib.sha256(data).hexdigest(),
                               installed_package_count=len(installed))
            return 0
        except (Cancelled, KeyboardInterrupt, lifecycle.Error, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
            # Never put lifecycle stderr, rejected inputs or private paths in this receipt.
            self.cancelled |= isinstance(error, (Cancelled, KeyboardInterrupt))
            self.report.update(status='FAIL', error='handoff assertion, command or cleanup failed; review public check records')
            return 1
        finally:
            for sig in previous:
                signal.signal(sig, signal.SIG_IGN)
            try:
                self.stop_child()
                if self.cancelled:
                    self.report.update(status='FAIL', cancelled=True)
                self.receipt.write_text(json.dumps(self.report, indent=2, sort_keys=True) + '\n')
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--contract', required=True, type=Path)
    parser.add_argument('--contract-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        return Handoff(args.contract, args.contract_sha256).execute()
    except (Cancelled, KeyboardInterrupt, lifecycle.Error, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('Installed handoff refused before execution; no READY receipt.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
