#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the exact no-argument updater with inert external commands."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
RECIPE = ROOT / 'packages/tools/cachy-asahi-update'
CHECK = ROOT / 'scripts/ci/updater-optional-check/historical/real-check/real-check.py'
UPDATE = ['sudo', 'pacman', '--color', 'never', '-Syu']
BEFORE_UPDATE = [
    ['checkupdates', '--nocolor'],
    ['curl', '--compressed', '-m', '10', '-Lfs', 'https://www.archlinux.org/news'],
    UPDATE,
]
AFTER_UPDATE = [['pacman', '-Qtdq'], ['paccache', '-dk3'], ['paccache', '-duk0']]
SERVICE_DISCOVERY = [
    'sudo', 'checkservices', '-F', '-P', '-R', '-i', 'gdm.service',
    '-i', 'plasmalogin.service', '-i', 'sddm.service', '-i', 'lightdm.service',
    '-i', 'lxdm.service', '-i', 'slim.service', '-i', 'xdm.service',
    '-i', 'greetd.service', '-i', 'nodm.service',
    '-i', 'ly.service', '-i', 'lemurs.service',
]


class FullUpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = os.environ.get('UPDATER_FULL_UPDATE_PATCHED_SOURCE')
        if not source:
            raise unittest.SkipTest('set UPDATER_FULL_UPDATE_PATCHED_SOURCE to the exact patched tree')
        cls.source = Path(source).resolve(strict=True)
        subprocess.run([sys.executable, '-I', '-B', str(RECIPE / 'verify-updater.py'),
                        '--source', str(cls.source)], check=True, capture_output=True, timeout=35)
        cls.policy_fixture = staticmethod(runpy.run_path(str(RECIPE / 'test-asahi-policy.py'))['fixture'])
        cls.check = runpy.run_path(str(CHECK))

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='updater-full-update-source-', dir='/tmp')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        config = self.work / 'config/arch-update'
        self.state = self.work / 'state/arch-update'
        self.runtime = self.work / 'runtime'
        bin_dir = self.work / 'bin'
        for path in (config, self.state, self.runtime / 'arch-update', bin_dir):
            path.mkdir(parents=True, mode=0o700)
        self.runtime.chmod(0o700)
        (config / 'arch-update.conf').write_text(self.check['OPTIONS'] + 'PrivilegeElevationCommand=sudo\n')
        self.env = {
            'PATH': str(bin_dir), 'HOME': str(self.work), 'XDG_CONFIG_HOME': str(config.parent),
            'XDG_STATE_HOME': str(self.state.parent), 'XDG_RUNTIME_DIR': str(self.runtime),
            'XDG_DATA_HOME': str(self.work / 'data'), 'XDG_DATA_DIRS': str(self.work / 'data'),
            'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC', 'TERM': 'dumb',
            'ARCH_UPDATE_LIBDIR': str(self.source / 'src/lib'),
        }
        for name in ('awk', 'cat', 'column', 'cut', 'date', 'flock', 'grep', 'mkdir',
                     'mktemp', 'realpath', 'rm', 'sed', 'stat', 'timeout', 'tr', 'wc'):
            path = Path('/usr/bin') / name
            self.assertTrue(path.is_file(), path)
            (bin_dir / name).symlink_to(path)
        (bin_dir / 'gettext.sh').write_text('eval_gettext() { printf "%s" "$1"; }\n')
        helper = self.work / 'policy-helper'
        helper.write_text(f'#!/usr/bin/bash\nexec /usr/bin/python3 -I -B '
                          f'{shlex.quote(str(RECIPE / "asahi-policy.py"))} "$@"\n')
        helper.chmod(0o700)
        self.env['CACHY_ASAHI_POLICY_HELPER'] = str(helper)
        self.pending = f"{self.check['NAME']} 0.1.0-1 -> 0.1.1-1\n"
        for name in ('last_updates_check', 'last_updates_check_packages'):
            (self.state / name).write_text(self.pending)
        (self.state / 'last_update_run').write_text('2000-01-01\n')
        self.log = self.work / 'calls.jsonl'
        self.bin_dir = bin_dir

    def pin(self, name, value):
        data = json.dumps(value, sort_keys=True).encode()
        path = self.work / f'{name}.json'
        path.write_bytes(data)
        self.env[f'CACHY_ASAHI_{name}_FILE'] = str(path)
        self.env[f'CACHY_ASAHI_{name}_SHA256'] = hashlib.sha256(data).hexdigest()

    def configure(self, change=None, omit_operation=None):
        policy, post = self.policy_fixture(change)
        pre = dict(post, phase='pre-transaction')
        if omit_operation:
            policy['permitted_operations'].remove(omit_operation)
        self.pin('POLICY', policy)
        self.pin('PRE_OBSERVATION', pre)
        self.pin('POST_OBSERVATION', post)

    def run_update(self, expected_exit, calls, *, pacman_status=0, service_report=''):
        responses = [
            (BEFORE_UPDATE[0], 0, self.pending), (BEFORE_UPDATE[1], 22, ''),
            (UPDATE, pacman_status, ''), (AFTER_UPDATE[0], 1, ''),
            (AFTER_UPDATE[1], 0, ''), (AFTER_UPDATE[2], 0, ''),
            (SERVICE_DISCOVERY, 0, service_report),
        ]
        actor = self.work / 'actor'
        actor.write_text('#!/usr/bin/python3 -I\nimport json, sys\nfrom pathlib import Path\n'
                         'argv = [Path(sys.argv[0]).name, *sys.argv[1:]]\n'
                         f'with open({str(self.log)!r}, "a") as log:\n'
                         '    log.write(json.dumps(argv) + "\\n")\n'
                         f'responses = {responses!r}\n'
                         'for args, status, output in responses:\n'
                         '    if argv == args:\n'
                         '        sys.stdout.write(output)\n'
                         '        sys.exit(status)\n'
                         'sys.exit(99)\n')
        actor.chmod(0o700)
        for name in {args[0] for args, _, _ in responses} | {'systemctl', 'reboot'}:
            (self.bin_dir / name).symlink_to(actor)
        result = subprocess.run(['/usr/bin/bash', str(self.source / 'src/arch-update.sh')],
                                cwd=self.work, env=self.env, input='Y\n\n', text=True,
                                capture_output=True, timeout=15)
        observed = [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []
        self.assertEqual(observed, calls, result.stdout + result.stderr)
        self.assertEqual(result.returncode, expected_exit, result.stdout + result.stderr)

    def assert_preflight_refusal(self, code):
        before = [self.check['snapshot'](path) for path in (self.state, self.runtime)]
        self.run_update(code, [])
        self.assertEqual([self.check['snapshot'](path) for path in (self.state, self.runtime)], before)

    def assert_applied_state(self):
        for name in ('last_updates_check', 'last_updates_check_packages'):
            self.assertEqual((self.state / name).read_bytes(), b'')
        self.assertRegex((self.state / 'last_update_run').read_text(), r'^\d{4}-\d\d-\d\d\n$')
        self.assertNotEqual((self.state / 'last_update_run').read_text(), '2000-01-01\n')

    def test_configured_generic_update_reaches_one_exact_upgrade_argv(self):
        self.configure()
        self.run_update(0, BEFORE_UPDATE + AFTER_UPDATE + [SERVICE_DISCOVERY])
        self.assert_applied_state()

    def test_unconfigured_policy_refuses_before_discovery(self):
        self.assert_preflight_refusal(21)

    def test_protected_platform_change_refuses_before_discovery(self):
        self.configure('platform')
        self.assert_preflight_refusal(22)

    def test_undeclared_cache_operation_refuses_before_discovery(self):
        self.configure(omit_operation='package-cache-removal')
        self.assert_preflight_refusal(22)

    def test_wrong_policy_pin_refuses_before_discovery(self):
        self.configure()
        self.env['CACHY_ASAHI_POLICY_SHA256'] = '0' * 64
        self.assert_preflight_refusal(23)

    def test_pacman_failure_keeps_pending_update(self):
        self.configure()
        self.run_update(5, BEFORE_UPDATE, pacman_status=1)
        for name in ('last_updates_check', 'last_updates_check_packages'):
            self.assertEqual((self.state / name).read_text(), self.pending)
        self.assertEqual((self.state / 'last_update_run').read_text(), '2000-01-01\n')

    def test_wrong_post_observation_pin_refuses_after_upgrade_argv(self):
        self.configure()
        self.env['CACHY_ASAHI_POST_OBSERVATION_SHA256'] = '0' * 64
        self.run_update(23, BEFORE_UPDATE + AFTER_UPDATE)
        self.assert_applied_state()

    def test_protected_service_refusal_happens_after_upgrade_argv(self):
        self.configure()
        self.run_update(22, BEFORE_UPDATE + AFTER_UPDATE + [SERVICE_DISCOVERY],
                        service_report="'speakersafetyd.service'\n")
        self.assert_applied_state()


if __name__ == '__main__':
    unittest.main()
