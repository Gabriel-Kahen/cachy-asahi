#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source controls for the disposable guest adapter."""

import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('guest', Path(__file__).with_name('guest.py'))
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)
CHECK = Path(__file__).resolve().parents[1] / 'updater-optional-check/historical/real-check/real-check.py'


def forbid_actor(event, _args):
    if event.startswith(('subprocess.', 'socket.', 'os.exec', 'os.spawn', 'os.posix_spawn', 'os.fork')):
        raise AssertionError(f'actor forbidden in source controls: {event}')


def lock(rows):
    return ''.join(f'{name} {version}\n' for name, version in sorted(rows.items())).encode()


class GuestTests(unittest.TestCase):
    def test_offline_16k_boot_pin_required(self):
        sha = 'a' * 64
        boot = [0, 'aarch64', 16384, {'lo'}, f'cachy_updater16k={sha}', True, b'linux,dummy-virt\0']
        self.assertEqual(guest.boot_pin(*boot), sha)
        for i, alternate in enumerate((1000, 'x86_64', 4096, {'lo', 'eth0'},
                                       f'{boot[4]} {boot[4]}', False, b'apple,j413\0')):
            with self.subTest(i=i), self.assertRaises(ValueError):
                guest.boot_pin(*boot[:i], alternate, *boot[i+1:])

    def test_scoped_sudo_rejects_nosuid_and_other_policy(self):
        args = [0, stat.S_IFREG | 0o4755, 0, guest.SUDOERS]
        guest.sudo_boundary(*args)
        for i, alternate in enumerate((1000, stat.S_IFREG | 0o755, os.ST_NOSUID, b'ALL')):
            with self.subTest(i=i), self.assertRaisesRegex(ValueError, 'scoped guest sudo'):
                guest.sudo_boundary(*args[:i], alternate, *args[i+1:])

    def test_authority_checks_repo_closure_media_and_expiry(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            root.chmod(0o755)
            (root / 'repo').mkdir()
            for name in guest.FILES:
                (root / name).write_bytes(name.encode())
            runpy.run_path(str(CHECK))['write_package'](root / 'repo' / guest.REPO[2], guest.NEW)
            files = {name: guest.digest((root / name).read_bytes()) for name in guest.FILES}
            document = {'kind': 'cachy-asahi-updater16k-disposable-v1', 'valid_from': 1, 'expires': 60,
                        'signer': 'A' * 40, 'files': files}
            raw = json.dumps(document).encode()
            (root / 'plan.json').write_bytes(raw)
            with patch.multiple(guest, INPUT=root, UPDATER=files['updater.pkg'], Q3_LOCK=files['q3.lock']):
                pin = guest.digest(raw)
                self.assertEqual(guest.plan(pin, 59), (files, document['signer']))
                for attempt in ((pin, 60), ('a' * 64, 59)):
                    with self.assertRaises(ValueError):
                        guest.plan(*attempt)
                extra = root / 'repo/unexpected'
                extra.touch()
                with self.assertRaisesRegex(ValueError, 'fixture-only repository'):
                    guest.plan(pin, 59)
                extra.unlink()
                (root / 'repo/fixture.db.sig').write_bytes(b'changed signature')
                with self.assertRaisesRegex(ValueError, 'media digest differs'):
                    guest.plan(pin, 59)

    def test_fixture_refuses_extra_payload_and_install_script(self):
        fixture = runpy.run_path(str(CHECK))['package_data'](guest.NEW)
        for injected in ('.INSTALL', 'etc/unexpected'):
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
                for name, data in (fixture | {injected: b'x'}).items():
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))
            with self.subTest(member=injected), self.assertRaisesRegex(ValueError, 'archive member'):
                guest.verify_fixture_archive(buffer.getvalue())

    def test_only_exact_q3_supplements_and_fixture_delta(self):
        q3 = {f'baseline-{i}': '1-1' for i in range(356)}
        before = q3 | guest.SUPPLEMENTS | {'sudo': '1.9.17.p2-6'}
        self.assertEqual(guest.expected_inventories(lock(q3), lock(before)),
                         (before, before | {guest.NAME: guest.NEW}))
        for drift in ({'unexpected': '1-1'}, {'baseline-0': '3-1'}, {'pyalpm': '2-1'}):
            with self.subTest(drift=drift), self.assertRaisesRegex(ValueError, 'runtime closure'):
                guest.expected_inventories(lock(q3), lock(before | drift))

    def test_alpm_log_rejects_any_additional_action(self):
        log = f'[ALPM] upgraded {guest.NAME} ({guest.OLD} -> {guest.NEW})\n'
        guest.verify_actions(log)
        for invalid in ('', log + log, log + '[ALPM] removed baseline-0 (1-1)\n'):
            with self.subTest(log=invalid), self.assertRaises(ValueError):
                guest.verify_actions(invalid)

    def exercise(self, *, illicit_call=False, preview_drift=None, allow_removal=False):
        old, new = {guest.NAME: guest.OLD}, {guest.NAME: guest.NEW}
        pending = f'{guest.NAME} {guest.OLD} -> {guest.NEW}\n'.encode()
        calls = ['pacman --color never -Syu', guest.SERVICES]
        action = f'[ALPM] upgraded {guest.NAME} ({guest.OLD} -> {guest.NEW})\n'.encode()
        files = {'repo/' + guest.REPO[2]: 'a' * 64}
        preview = (f'UPDATER_SELECTION {guest.NAME} {guest.NEW} {"a" * 64} '
                   f'file://{guest.INPUT}/repo/{guest.REPO[2]}\n')
        if preview_drift == 'extra':
            preview = 'UPDATER_SELECTION unexpected 0-1\n' + preview
        elif preview_drift == 'archive':
            preview = preview.replace('a' * 64, 'b' * 64)
        elif preview_drift == 'url':
            preview = preview.replace('file://', 'https://')
        with patch.multiple(guest, verify_installed_entry=lambda: None, prepare_config=lambda: None,
                            write_shims=lambda: None), \
                patch.object(guest, 'read', side_effect=[b'', b'', guest.fixture_payload(guest.OLD),
                                    guest.fixture_payload(guest.OLD), guest.fixture_payload(guest.OLD),
                                    guest.fixture_payload(guest.NEW), action]), \
                patch.object(guest, 'expected_inventories', return_value=(old, new)), \
                patch.object(guest, 'checked', side_effect=['', preview, '']) as command, \
                patch.object(guest, 'run', return_value=subprocess.CompletedProcess([], 0 if allow_removal else 1)), \
                patch.object(guest, 'actual_inventory', side_effect=[old, old, old, new]), \
                patch.object(guest, 'local_db', return_value={'db': 'fixed'}), \
                patch.object(guest, 'installed_entry', side_effect=[
                    (21, ['pacman'] if illicit_call else [], [pending, pending]),
                    (22, [], [pending, pending]), (0, calls, [b'', b'']),
                ]) as entry:
            if illicit_call or preview_drift or allow_removal:
                with self.assertRaises(ValueError):
                    guest.trial(files, {})
                self.assertEqual(entry.call_count, 1 if illicit_call else 0)
            else:
                cases = {}
                guest.trial(files, cases)
                self.assertEqual(cases, {'unconfigured': 21, 'protected': 22, 'update': 0})
                self.assertEqual([call.args[0] for call in entry.call_args_list],
                                 ['unconfigured', 'protected', 'update'])
                self.assertEqual(command.call_args.args[0][-1], '-Dk')

    def test_refusals_precede_single_upgrade_and_checkpoint_verification(self):
        self.exercise()

    def test_illicit_elevation_or_preview_stops_before_update(self):
        self.exercise(illicit_call=True)
        self.exercise(allow_removal=True)
        for drift in ('extra', 'archive', 'url'):
            with self.subTest(drift=drift):
                self.exercise(preview_drift=drift)

    def test_hold_records_updated_database_after_post_policy_failure_and_cleans_state(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            (root / 'db' / f'{guest.NAME}-{guest.NEW}').mkdir(parents=True)
            def fail(_files, results):
                results.update(unconfigured=21, protected=22, update=23)
                raise ValueError('modeled postcommit refusal')
            with patch.multiple(guest, WORK=root / 'work', DB=root / 'db', trial=fail):
                receipt = guest.run_trial({})
            self.assertEqual(receipt['status'], 'HOLD')
            self.assertEqual(receipt['case_exits']['update'], 23)
            self.assertEqual(receipt['fixture_db_versions'], [guest.NEW])
            self.assertTrue(receipt['private_state_removed'])
            self.assertFalse((root / 'work').exists())

    def test_timeout_leaves_scratch_and_database_state_for_owner(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            with patch.multiple(guest, WORK=root / 'work', DB=root / 'db'), \
                    patch.object(guest, 'trial', side_effect=subprocess.TimeoutExpired([], 1)):
                receipt = guest.run_trial({})
            self.assertEqual(receipt['status'], 'HOLD')
            self.assertTrue(receipt['command_timed_out'])
            self.assertIsNone(receipt['fixture_db_versions'])
            self.assertFalse(receipt['private_state_removed'])
            self.assertTrue((root / 'work').is_dir())


if __name__ == '__main__':
    sys.addaudithook(forbid_actor)
    unittest.main()
