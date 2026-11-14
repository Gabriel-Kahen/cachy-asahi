#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit local guest-callable check using extracted actual package payloads.

The local callback checks the full runuser prefix but executes as the already
ordinary current user; actual native root-to-alarm switching remains NOT RUN.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import pwd
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


guest = load('installed_guest', HERE / 'first_login_installed_journey.py')
local = load('local_package_intake', HERE / 'first_login.py')
INPUTS = None


class InstalledGuestTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(INPUTS, 'Explicit reviewed inputs required; no fixture-code replacement or skips')
        self.assertNotEqual(os.geteuid(), 0, 'Local checks require the existing ordinary user')
        self.temp = tempfile.TemporaryDirectory(prefix='installed-first-login-guest-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out = self.root / 'records'; self.out.mkdir(mode=0o700)
        self.prefix = self.root / 'prefix'; self.prefix.mkdir(mode=0o700)
        self.home = self.root / 'home'; self.home.mkdir(mode=0o700)
        self.uid, self.gid = os.geteuid(), os.getegid()
        self.user = pwd.getpwuid(self.uid).pw_name
        env = {'HOME': str(self.home), 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'}
        self.runner = local.Runner(self.out, env, self.root, timeout=20, phase='installed-guest')
        local.extract(INPUTS, self.prefix, self.runner)
        self.start = len(self.runner.records)
        self.paths = {name: str(self.prefix / relative) for name, relative in (
            ('first_login', 'usr/bin/cachy-asahi-first-login'), ('setup', 'usr/bin/cachy-asahi-setup'))}
        self.paths.update(fish='/usr/bin/fish', zsh='/usr/bin/zsh', python3='/usr/bin/python3',
                          template_root=str(self.prefix / 'usr/share/cachy-asahi'),
                          template_owner=self.uid, user=self.user,
                          template_sha256={name: guest.digest(raw) for name, raw in guest.TEMPLATE_CONTENT.items()})

    def callback(self, step, argv, expected=0, cwd=None):
        self.assertEqual(argv[:6], ['/usr/bin/runuser', '-u', self.user, '--', '/usr/bin/env', '-i'])
        self.assertEqual(os.geteuid(), self.uid)
        self.runner.cwd = Path(cwd)
        self.runner.run(step, argv[4:], expected_code=expected)
        record = self.runner.records[-1]
        return (self.out / record['stdout_file']).read_bytes() + (self.out / record['stderr_file']).read_bytes()

    def test_actual_extracted_payloads_execute_ordinary_user_no_pty_workflow(self):
        report = guest.run(self.paths, self.home, self.callback, self.uid, self.gid, label='local')
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['command_count'], 27)
        self.assertEqual(report['shell_startups'], 10)
        self.assertEqual(report['pty'], 'NOT RUN')
        self.assertTrue(report['recovery_confirmed'])
        self.assertTrue(report['final_components_deactivated'])
        self.assertTrue(report['template_and_program_preservation'])
        records = self.runner.records[self.start:]
        self.assertEqual([row['step'] for row in records], report['ordered_steps'])
        self.assertTrue(all(row['terminal'] == 'captured process' and row['success'] for row in records))
        self.assertEqual(next(row['returncode'] for row in records if row['step'] == 'local-interrupted-setup'), 75)
        self.assertEqual(next(row['returncode'] for row in records if row['step'] == 'local-pending-new-selection-refused'), 2)
        self.assertTrue(all(row['uid'] == self.uid and row['gid'] == self.gid for row in report['final_user_state'].values()))
        for name, raw in guest.TEMPLATE_CONTENT.items():
            self.assertEqual((Path(self.paths['template_root']) / name).read_bytes(), raw)

    def test_changed_actual_template_refuses_before_first_user_command(self):
        path = Path(self.paths['template_root']) / 'fish/config.fish'
        path.write_bytes(path.read_bytes() + b'# unexpected profile change\n')
        with self.assertRaises(ValueError) as caught:
            guest.run(self.paths, self.home, self.callback, self.uid, self.gid)
        self.assertEqual(caught.exception.first_login_result['ordered_steps'], [])
        self.assertEqual(list(self.home.iterdir()), [])

    def test_root_identity_and_home_alias_are_refused_before_commands(self):
        with self.assertRaises(ValueError):
            guest.run(self.paths, self.home, self.callback, 0, 0)
        alias = self.root / 'home-alias'; alias.symlink_to(self.home)
        with self.assertRaises(ValueError) as caught:
            guest.run(self.paths, alias, self.callback, self.uid, self.gid)
        self.assertEqual(caught.exception.first_login_result['ordered_steps'], [])
        self.assertEqual(list(self.home.iterdir()), [])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--inputs-sha256', required=True)
    args, remaining = parser.parse_known_args()
    INPUTS = local.selection(args.inputs, args.inputs_sha256)
    unittest.main(argv=[__file__, *remaining])
