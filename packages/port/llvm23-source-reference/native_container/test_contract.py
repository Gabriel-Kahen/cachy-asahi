# SPDX-License-Identifier: MIT
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('llvm23_native_contract', HERE/'contract.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


class ContractTests(unittest.TestCase):
    def test_distinct_unexecuted_domain_and_frozen_pins(self):
        data = c.contract()
        self.assertEqual(data['domain'], 'ROOT_NATIVE_CONTAINER_DOMAIN')
        self.assertEqual(data['status'], 'PROPOSAL_ONLY_NO_RUNTIME_ENTRY')
        self.assertEqual(data['nested_bwrap_unshare'], 'NOT_INVOKED_NOT_QUALIFIED')
        self.assertIn('reference.preflight', data['not_reused'])
        self.assertEqual(data['prefix'], '/opt/cachy-asahi/llvm23-source-reference')
        self.assertEqual(data['libdir'], 'lib')

    def test_fixed_phase_order_and_native_private_mounts(self):
        data = c.contract()
        for name in ('probe','tools','runtimes','check'):
            self.assertEqual(c.phase_command(name), ['/usr/bin/bash','--noprofile','--norc','/driver/build.sh',name])
            self.assertIn('ROOT_OBSERVED_DOMAIN_BOUND', data['phases'][name]['requires'])
        with self.assertRaises(ValueError):
            c.phase_command('fallback')
        mounts = {row['destination']:row for row in data['mounts']}
        self.assertTrue(mounts['/work']['writable'])
        self.assertFalse(mounts[data['prefix']]['writable'])
        self.assertFalse(mounts['/source']['writable'])
        self.assertFalse(mounts['/driver']['writable'])
        self.assertIn('TOOLS_STAGED', data['phases']['runtimes']['requires'])
        self.assertIn('STATIC_STAGE_PASS', data['phases']['check']['requires'])
        self.assertEqual(data['environment']['TMPDIR'], '/work/tmp')

    def test_missing_or_changed_source_refuses_without_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, 'frozen LLVM source contract changed'):
                c.contract(root)
            for name in c.contract()['frozen_files_sha256']:
                (root/name).write_text('changed synthetic DATA')
            with self.assertRaisesRegex(ValueError, 'frozen LLVM source contract changed'):
                c.contract(root)

    def test_static_inspector_cannot_return_domain_or_native_acceptance(self):
        checks = c.inspector()
        self.assertEqual(str(checks.PREFIX), c.contract()['prefix'])
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, 'private prefix missing'):
                c.inspect_stage(tmp)
        # The module exposes no runtime dispatcher or standalone CLI.
        self.assertFalse(hasattr(c, 'main'))
        self.assertFalse(hasattr(c, 'run'))


if __name__ == '__main__':
    unittest.main()
