#!/usr/bin/env python3
"""Focused immutable handoff, failure and bounded-retention checks."""
import importlib.util
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock

spec = importlib.util.spec_from_file_location('composition_run', Path(__file__).with_name('run.py'))
run = importlib.util.module_from_spec(spec); spec.loader.exec_module(run)


class Handoff(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.build = self.root / 'build'; (self.build / 'artifacts').mkdir(parents=True)
        self.package = self.build / 'artifacts/package.pkg.tar.xz'; self.package.write_bytes(b'inert package fixture')
        self.record = {'status': 'built-package-static-pass', 'mode': 'native',
            'builder_host_arch': 'aarch64', 'image_id': 'sha256:' + 'a' * 64,
            'expected_packages_sha256': run.BASE, 'recipe_inputs': {'PKGBUILD': 'b' * 64},
            'exit_code': 0, 'artifacts': {self.package.name: run.sha(self.package)}}
        self.write()

    def write(self):
        (self.build / 'provenance.json').write_text(json.dumps(self.record))

    def accept(self):
        return run.standard(self.build, 'b' * 64, 'sha256:' + 'a' * 64)

    def test_verified_digest_is_retained(self):
        path, digest = self.accept()
        self.package.write_bytes(b'changed after handoff')
        self.assertNotEqual(run.sha(path), digest)
        self.assertEqual(digest, self.record['artifacts'][self.package.name])

    def test_different_builder_recipe_or_mode_refused(self):
        for key, value in (('image_id', 'other'), ('expected_packages_sha256', 'other'),
                           ('builder_host_arch', 'x86_64'), ('mode', 'emulated')):
            old = self.record[key]; self.record[key] = value; self.write()
            with self.subTest(key=key), self.assertRaises(AssertionError): self.accept()
            self.record[key] = old
        self.record['recipe_inputs']['PKGBUILD'] = 'c' * 64; self.write()
        with self.assertRaises(AssertionError): self.accept()

    def test_artifact_drift_refused(self):
        self.package.write_bytes(b'not the attested artifact')
        with self.assertRaises(AssertionError): self.accept()

    def test_timeout_stops_owned_process_group_and_propagates(self):
        process = MagicMock(); process.pid = 12345
        process.wait.side_effect = [subprocess.TimeoutExpired(['inert'], 1), 0]
        with patch.object(run.subprocess, 'Popen', return_value=process), patch.object(run.os, 'killpg') as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                run.command(['inert'], self.root / 'timeout.log', 1)
            kill.assert_called_once_with(12345, run.signal.SIGTERM)

    def test_retention_is_capped_and_excludes_private_inputs(self):
        raw = self.root / 'private'; (raw / 'desktop574').mkdir(parents=True)
        (raw / 'desktop574/build.log').write_bytes(b'x' * 70000)
        (raw / 'secret-key').write_bytes(b'private fixture')
        (raw / 'updater').mkdir()
        (raw / 'updater/build.log').write_bytes(b'private updater output fixture')
        public = self.root / 'public'; public.mkdir()
        run.retain(raw, public)
        self.assertEqual((public / 'diagnostics/desktop574/build.log').stat().st_size, 65536)
        self.assertEqual([p.name for p in public.rglob('*') if p.is_file()], ['build.log'])

    def test_workflow_updater_process_has_no_docker_environment(self):
        here = Path(__file__).resolve().parent
        workflow = here / 'proposed-workflow.yml'
        if not workflow.exists():
            workflow = here.parents[2] / '.github/workflows/native-arm-build.yml'
        step = workflow.read_text().split('      - name: Required signed complete development composition\n', 1)[1]
        step = step.split('      - name:', 1)[0]
        body = '\n'.join(line[10:] for line in step.split('        run: |\n', 1)[1].splitlines())
        prefix = re.search(r'(?ms)^env -i .*?(?=python3 -B )', body).group()
        probe = prefix + '/usr/bin/python3 -c ' + shlex.quote('import json,os; print(json.dumps(dict(os.environ)))')
        inherited = {'PATH': '/usr/bin:/bin', 'RUNNER_TEMP': str(self.root),
                     'DOCKER_CONFIG': '/inert/config', 'DOCKER_HOST': 'tcp://inert.invalid:1234',
                     'DOCKER_CONTEXT': 'inert', 'DOCKER_TLS_VERIFY': '1'}
        result = subprocess.run(['/bin/bash', '--noprofile', '--norc', '-euo', 'pipefail', '-c', probe],
                                env=inherited, capture_output=True, text=True, check=True, timeout=5)
        child = json.loads(result.stdout)
        self.assertFalse([name for name in child if name.startswith('DOCKER_')])
        self.assertEqual(child['HOME'], str(self.root / 'composition-home'))
        self.assertEqual(child['PYTHONDONTWRITEBYTECODE'], '1')


if __name__ == '__main__':
    unittest.main()
