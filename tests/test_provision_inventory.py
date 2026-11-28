"""Provisioning inventory controls with an inert shell and mocked Docker."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts/build'))
import provision


class InventoryTests(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        cache = self.root / 'inputs'
        cache.mkdir()
        archive = cache / 'fixture-1-1-any.pkg.tar.gz'
        signature = cache / (archive.name + '.sig')
        for path in (archive, signature):
            path.write_bytes(b'inert fixture')
        checksums = self.root / 'cache.json'
        checksums.write_text(json.dumps({path.name: provision.digest(path) for path in (archive, signature)}))
        self.output = self.root / 'context'
        self.argv = ['provision.py', '--base-image', 'registry.invalid/arm@sha256:' + 'a' * 64,
                     '--cache', str(cache), '--checksums', str(checksums), '--output', str(self.output)]

    def test_generated_run_requires_successful_nonempty_pacman_inventory(self):
        with patch.object(sys, 'argv', self.argv), patch.object(provision, 'capture') as capture, \
             patch.object(provision.subprocess, 'run') as run, patch('builtins.print'):
            self.assertEqual(provision.main(), 0)
        capture.assert_not_called()
        run.assert_not_called()
        command, = (line.removeprefix('RUN ') for line in (self.output / 'Dockerfile').read_text().splitlines()
                    if line.startswith('RUN '))
        lock = self.root / 'builder-packages.lock'
        command = command.replace('/builder-packages.lock', shlex.quote(str(lock)))
        stub = '''
pacman() {
    case "$1" in
        --config) return 0 ;;
        -Q) printf '%s' "$INVENTORY"; return "$QUERY_STATUS" ;;
        *) return 90 ;;
    esac
}
rm() { :; }
'''
        cases = [(24, '', False), (24, 'fixture 1-1\n', False), (0, '', False),
                 (0, 'zeta 2-1\nalpha 1-1\n', True)]
        for status, inventory, success in cases:
            with self.subTest(status=status, inventory=inventory):
                result = subprocess.run(['/bin/sh', '-c', stub + command],
                                        env=dict(os.environ, QUERY_STATUS=str(status), INVENTORY=inventory),
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                if success:
                    self.assertEqual(lock.read_text(), 'alpha 1-1\nzeta 2-1\n')
                else:
                    self.assertFalse(lock.exists())
                lock.unlink(missing_ok=True)

    def test_execute_refuses_empty_inventory_readback(self):
        image = 'sha256:' + 'b' * 64
        inspected = json.dumps([{'Architecture': 'arm64', 'Os': 'linux', 'Id': image}])

        def local_build(command, **kwargs):
            self.assertEqual(command[:2], ['docker', 'build'])
            (self.output / 'image-id').write_text(image + '\n')
            return subprocess.CompletedProcess(command, 0)

        with patch.object(sys, 'argv', [*self.argv, '--execute']), \
             patch.object(provision, 'capture', side_effect=[inspected, '']), \
             patch.object(provision.subprocess, 'run', side_effect=local_build), patch('builtins.print'):
            self.assertEqual(provision.main(), 1)
        record = json.loads((self.output / 'provision.json').read_text())
        self.assertEqual(record['status'], 'failed')
        self.assertIn('empty builder package inventory', record['error'])
        self.assertFalse((self.output / 'packages.lock').exists())


if __name__ == '__main__':
    unittest.main()
