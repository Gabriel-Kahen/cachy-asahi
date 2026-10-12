# SPDX-License-Identifier: MIT
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import common
import worker


class ProvisionFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.inputs = self.root / 'inputs'; self.inputs.mkdir()
        self.real_path = Path
        self.packet = b'archive'; self.sig = b'signature'
        (self.inputs / 'tool.pkg').write_bytes(self.packet); (self.inputs / 'tool.pkg.sig').write_bytes(self.sig)
        common.save(self.inputs / 'contract.json', {'base_inventory': 'base 1\n'})
        self.signer = '6' * 40
        self.dependencies = {'packages': [{'name': 'tool', 'filename': 'tool.pkg', 'sha256': hashlib.sha256(self.packet).hexdigest(),
            'signature_sha256': hashlib.sha256(self.sig).hexdigest()}], 'signer_fingerprint': self.signer,
            'expected_inventory': 'base 1\ntool 2\n'}
        self.labels = []; self.installed = False
        self.log_dir = self.root / 'logs'; self.log_dir.mkdir()

    def path(self, value):
        if str(value).startswith('/tmp/'):
            return self.real_path(self.root / str(value).lstrip('/'))
        if str(value).startswith('/usr/share/') or str(value).startswith('/etc/'):
            return self.root / 'nonexistent-hooks'
        return self.real_path(value)

    def command_run(self, argv, timeout=0, log=None):
        self.labels.append(log)
        data = b''
        if '--verify' in argv:
            data = ('[GNUPG:] VALIDSIG ' + self.signer + ' 2026-10-12 1 0 4 0 1 10 00 ' + self.signer + '\n').encode()
        if '-U' in argv: self.installed = True
        if '-Q' in argv: data = b'base 1\ntool 2\n' if self.installed else b'base 1\n'
        (self.log_dir / log).open('xb').close()
        return subprocess.CompletedProcess(argv, 0, data)

    def test_distinct_inventory_logs_allow_complete_provision(self):
        (self.root / 'tmp').mkdir()
        runner = type('Runner', (), {'log_dir': self.log_dir, 'run': self.command_run})()
        report = {'commands': []}
        with patch.object(worker, 'Path', side_effect=self.path), patch.object(worker, 'INPUTS', self.inputs):
            worker.provision(runner, report, self.dependencies)
        self.assertIn('inventory-before.log', self.labels)
        self.assertIn('inventory-after.log', self.labels)
        self.assertEqual(len(self.labels), len(set(self.labels)))
        self.assertEqual(report['base_inventory']['count'], 1)
        self.assertEqual(report['installed_inventory']['count'], 2)
        self.assertTrue(self.installed)

    def test_wrong_crypto_signer_blocks_install(self):
        (self.root / 'tmp').mkdir()
        self.dependencies['signer_fingerprint'] = '7' * 40
        runner = type('Runner', (), {'log_dir': self.log_dir, 'run': self.command_run})()
        with patch.object(worker, 'Path', side_effect=self.path), patch.object(worker, 'INPUTS', self.inputs):
            with self.assertRaises(ValueError): worker.provision(runner, {'commands': []}, self.dependencies)
        self.assertFalse(self.installed)


if __name__ == '__main__':
    unittest.main()
