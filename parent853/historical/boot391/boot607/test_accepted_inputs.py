# SPDX-License-Identifier: MIT
"""Real immutable public carrier and disposable hostile-copy controls only."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
PACKET = Path(os.environ['BOOT607_INPUT_PACKET']).absolute()
CHECKS = REPO/'held606/held-tools/scripts/checks/package_checks.py'

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value

A = load('boot607_accepted', HERE/'accepted_inputs.py')
C = load('boot607_source_owned_checks', CHECKS)

class Inputs(unittest.TestCase):
    def altered(self, mutate):
        with tempfile.TemporaryDirectory(prefix='carrier-control-', dir='/tmp') as temporary:
            packet = Path(temporary)/'payload'
            shutil.copytree(PACKET, packet)
            mutate(packet)
            with self.assertRaises((ValueError, OSError)):
                A.inspect(packet, C)

    def test_real_full123_35zip_79git_input_only(self):
        result = A.inspect(PACKET, C)
        self.assertEqual(result['source'], A.SOURCE)
        self.assertEqual(result['accepted_pair'], A.ARCHIVE)
        self.assertEqual(set(result['payload']), set(A.PAYLOAD))
        self.assertEqual(result['authority'], 'ACCEPTED_INPUTS_ONLY_NO_NEW_CURRENT606_OR_NATIVE_ACCEPTANCE')

    def test_untracked_leaf_refused(self):
        self.altered(lambda p: (p/'extra').write_bytes(b'not authorized'))

    def test_archive_byte_drift_refused(self):
        def mutate(p):
            d = json.loads((p/'index.json').read_bytes())
            f = p/d['package']['archives']['a']['path']
            f.write_bytes(f.read_bytes()[:-1]+b'x')
        self.altered(mutate)

    def test_source_alias_refused(self):
        def mutate(p):
            f = p/'source/packages/tools/cachy-asahi-boot-report/NOTICE'
            raw = f.read_bytes()
            f.unlink()
            (p/'alias-content').write_bytes(raw)
            f.symlink_to(p/'alias-content')
        self.altered(mutate)

    def test_hardlinked_input_refused(self):
        def mutate(p):
            f = p/'Root-component-acceptance.json'
            os.link(f, p.parent/'extra-link')
        self.altered(mutate)

    def test_failed_run_metadata_refused(self):
        def mutate(p):
            f = p/'original/run.json'
            d = json.loads(f.read_bytes())
            d['conclusion'] = 'failure'
            f.write_text(json.dumps(d))
        self.altered(mutate)

    def test_counterfeit_root_decision_refused(self):
        self.altered(lambda p: (p/'Root-component-acceptance.json').write_text('{}'))

    def test_operator_repin_refused(self):
        def mutate(p):
            d = json.loads((p/'index.json').read_bytes())
            f = p/'Root-component-acceptance.json'
            f.write_text('{}')
            d['files'][f.name] = A.pin(f.read_bytes())
            (p/'index.json').write_text(json.dumps(d))
        self.altered(mutate)

    def test_nofollow_ancestor_and_zero_byte_support(self):
        with tempfile.TemporaryDirectory(prefix='ordinary-control-', dir='/tmp') as temporary:
            p = Path(temporary)
            (p/'empty').write_bytes(b'')
            self.assertEqual(A.read(p/'empty'), b'')
            (p/'alias').symlink_to(p, target_is_directory=True)
            with self.assertRaises(OSError):
                A.read(p/'alias/empty')

if __name__ == '__main__':
    unittest.main(verbosity=2)
