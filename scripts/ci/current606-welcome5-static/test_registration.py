# SPDX-License-Identifier: MIT
"""Registration refusals only; no accepting606 or native lifecycle fixtures."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import preflight as P


class Registration(unittest.TestCase):
    def setUp(self):
        self.source = P.HERE.parents[2]
        self.pins = json.loads((P.HERE / 'source-pins.json').read_bytes())

    def test_exact_current_owner_namespace_default_null(self):
        P.validate(self.source, self.pins)

    def test_changed_owner_refuses_before_emitter_output(self):
        pins = copy.deepcopy(self.pins)
        pins['files'][P.LANE + '/builds.py']['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'canonical owner source differs'):
            P.validate(self.source, pins)

    def test_extra_namespace_leaf_or_policy_activation_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in self.pins['files']:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((self.source / name).read_bytes())
            extra = root / P.LANE / 'unexpected-private.json'
            extra.write_text('{}')
            with self.assertRaisesRegex(ValueError, 'exact canonical owner namespace'):
                P.validate(root, self.pins)
            extra.unlink()
            policy = root / P.LANE / 'input-policy.json'
            value = json.loads(policy.read_bytes())
            value['actual_run'] = 1
            policy.write_bytes(json.dumps(value).encode())
            pins = copy.deepcopy(self.pins)
            pins['files'][P.LANE + '/input-policy.json'] = P.pin(policy.read_bytes())
            with self.assertRaisesRegex(ValueError, 'canonical owner selection remains NULL'):
                P.validate(root, pins)

    def test_missing_whole_source_role_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / 'forbidden'
            with self.assertRaisesRegex(ValueError, 'ordinary source root'):
                P.emit(self.source, root, output)
            self.assertFalse(output.exists())

    def test_symlink_source_alias_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            alias = Path(directory) / 'alias'
            alias.symlink_to(self.source, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'ordinary source operand'):
                P.validate(alias, self.pins)


if __name__ == '__main__':
    unittest.main()
