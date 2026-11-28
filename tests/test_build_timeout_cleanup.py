# SPDX-License-Identifier: MIT
"""Exercise the versioned builder timeout path with inert subprocess replies."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/build'))
import build
import build_v2
import build_v3


class TimeoutCleanupTests(unittest.TestCase):
    def test_timeout_cleanup_requires_a_successful_bounded_removal(self):
        image = 'sha256:' + 'a' * 64
        replies = (
            ('removed', 0, None),
            ('unconfirmed', 1, None),
            ('unconfirmed', None, subprocess.TimeoutExpired(['docker', 'rm'], 30)),
            ('unconfirmed', None, OSError('fixture cleanup launch failed')),
        )

        def capture(command):
            if command[1:3] == ['image', 'inspect']:
                return json.dumps([{'Architecture': 'arm64', 'Os': 'linux', 'Id': image}])
            self.assertEqual(command, ['docker', 'info', '--format', '{{.Architecture}}'])
            return 'aarch64'

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recipe = root / 'recipe'
            recipe.mkdir()
            payload = recipe / 'payload'
            payload.write_bytes(b'fixture\n')
            pkgbuild = recipe / 'PKGBUILD'
            pkgbuild.write_text("pkgname=fixture\npkgver=1\npkgrel=1\narch=('any')\nlicense=('MIT')\n"
                                f"source=('payload')\nsha256sums=('{build.digest(payload)}')\n")
            inputs = root / 'reviewed.json'
            report = build.recipe(pkgbuild)
            self.assertEqual(report['errors'], [])
            inputs.write_text(json.dumps(report['input_sha256']))
            lock = root / 'packages.lock'
            lock.write_text('base-devel 1-1\n')

            for builder in (build, build_v2, build_v3):
                for index, (status, exit_code, failure) in enumerate(replies):
                    with self.subTest(builder=builder.__name__, status=status, reply=index):
                        output = root / f'{builder.__name__}-{index}'
                        argv = [builder.__file__, str(recipe), '--image', image, '--output', str(output),
                                '--mode', 'native', '--source-date-epoch', '1', '--timeout', '2',
                                '--expected-packages', str(lock), '--reviewed-inputs', str(inputs)]

                        def execute(command, **options):
                            if command[1:3] == ['run', '--rm']:
                                options['stdout'].write(b'fixture build entered\n')
                                raise subprocess.TimeoutExpired(command, options['timeout'])
                            self.assertEqual(command[1:3], ['rm', '-f'])
                            if failure is not None:
                                raise failure
                            return subprocess.CompletedProcess(command, exit_code)

                        with (patch.object(sys, 'argv', argv),
                              patch.object(builder, 'capture', side_effect=capture),
                              patch.object(builder.subprocess, 'run', side_effect=execute) as run,
                              contextlib.redirect_stderr(io.StringIO()) as stderr):
                            self.assertEqual(builder.main(), 1)
                        self.assertTrue((output / 'provenance.json').is_file(), stderr.getvalue())
                        record = json.loads((output / 'provenance.json').read_bytes())
                        self.assertEqual(record['status'], 'failed')
                        self.assertNotIn('exit_code', record)
                        self.assertEqual((output / 'build.log').read_bytes(), b'fixture build entered\n')
                        self.assertIn('builder timeout', record['error'])
                        if status == 'removed':
                            self.assertIn('container was removed', record['error'])
                        else:
                            self.assertIn('removal unconfirmed', record['error'])
                        expected = {'status': status, 'exit_code': exit_code}
                        if failure is not None:
                            expected['error'] = type(failure).__name__
                        self.assertEqual(record['timeout_cleanup'], expected)
                        self.assertEqual(run.call_count, 2)
                        cleanup = run.call_args
                        self.assertEqual(cleanup.args[0], ['docker', 'rm', '-f', record['clean_environment_id']])
                        self.assertEqual(cleanup.kwargs['timeout'], 30)


if __name__ == '__main__':
    unittest.main()
