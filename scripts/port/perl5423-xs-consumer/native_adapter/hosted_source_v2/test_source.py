# SPDX-License-Identifier: MIT
"""Pure DATA controls for the separate corrected Source lineage."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('xs_v2_source_controls', HERE / 'prepare.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.fork', 'os.posix_spawn'):
        raise AssertionError('actor forbidden in v2 constructor controls: ' + event)


sys.addaudithook(fence)


class Controls(unittest.TestCase):
    def test_new_workflow_requires_new_operation_and_preserves_queue(self):
        old = b'native-arm-perl5423-xs-v1\nperl5423-native-xs-v1\n' + b'a'*64 + b'\ngroup: native-arm-build\n  cancel-in-progress: false\n  queue: max\n'
        result = p.workflow(old, 'a'*64, 'b'*64)
        self.assertIn(b'native-arm-perl5423-xs-v2', result)
        self.assertIn(b'perl5423-native-xs-v2', result)
        self.assertNotIn(b'native-arm-perl5423-xs-v1', result)
        self.assertIn(b'group: native-arm-build\n  cancel-in-progress: false\n  queue: max', result)
        with self.assertRaises(ValueError):
            p.workflow(old.replace(b'queue: max', b'queue: other'), 'a'*64, 'b'*64)

    def test_wrong_profile_and_populated_actual_selectors_refuse_first(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            raw = p.encode(dict(schema=1, actual=dict(p.ACTUAL, run='MODELED_NOT_ACTUAL'),
                                operation=p.OPERATION, delegated_consumer_operation='perl5423-native-xs-v1'))
            (root/'profile.json').write_bytes(raw)
            with patch.object(p, 'HERE', root):
                for sha in ('0'*64, p.atomic.pin(raw)['sha256']):
                    with self.assertRaises(ValueError):
                        p.render(root/'MISSING_PREVIOUS', sha)

    def test_incomplete_or_wrong_parent_refuses(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root/'source-map.json').write_bytes(b'MODELED incomplete Source')
            with self.assertRaises(ValueError):
                p.previous(root)


if __name__ == '__main__':
    unittest.main(verbosity=2)
