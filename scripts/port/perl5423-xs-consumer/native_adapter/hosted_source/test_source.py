# SPDX-License-Identifier: MIT
"""Four Source DATA controls; no bootstrap, extraction, consumer or network role."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('xs_constructor_controls', HERE / 'prepare.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.fork', 'os.posix_spawn'):
        raise AssertionError('actor forbidden in hosted XS Source controls: ' + event)


sys.addaudithook(fence)


def workflow_data():
    # Deliberately modeled plain text exercises the rewrite seam, never a receipt.
    entry = b'MODELED SOURCE TEXT'
    text = '\n'.join(('native-arm-perl5423-v2', 'perl5423-native-pair-v2', 'perl5423-native-v2',
        'hosted/entry.py', 'hosted/common.py', 'original/bootstrap/', p.atomic.pin(entry)['sha256'],
        'Signed349 bootstrap and full ordinary native Perl pair', 'Retain only public audit and pair DATA',
        '${{ runner.temp }}/perl-hosted/hosted.json',
        '${{ runner.temp }}/perl-hosted/pair/**', 'group: native-arm-build\n  cancel-in-progress: false\n  queue: max'))
    return {'.github/workflows/native-arm-perl5423-v2.yml': (text.encode(), 0o644),
            'hosted/entry.py': (entry, 0o644)}


class SourceControls(unittest.TestCase):
    def test_new_workflow_and_exact_serialization(self):
        held = workflow_data()
        before = dict(held)
        result = p.workflow(held, '0' * 64)
        self.assertEqual(held, before)
        self.assertIn(b'perl5423-native-xs-v1', result)
        self.assertNotIn(b'perl5423-native-pair-v2', result)
        self.assertIn(b'xs/entry.py', result)
        self.assertIn(b'group: native-arm-build\n  cancel-in-progress: false\n  queue: max', result)

    def test_missing_serialization_or_held_guard_refuses(self):
        for target in (b'queue: max', b'hosted/entry.py'):
            held = workflow_data()
            name = '.github/workflows/native-arm-perl5423-v2.yml'
            held[name] = (held[name][0].replace(target, b'SUBSTITUTED'), 0o644)
            with self.assertRaises(ValueError):
                p.workflow(held, '0' * 64)

    def test_wrong_profile_or_nonnull_future_selectors_refuse_first(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            raw = p.encode(dict(actual=dict(p.ACTUAL, source='1' * 40), operation='perl5423-native-xs-v1'))
            (folder / 'profile.json').write_bytes(raw)
            with patch.object(p, 'HERE', folder):
                for digest in ('0' * 64, p.atomic.pin(raw)['sha256']):
                    with self.assertRaises(ValueError):
                        p.render(folder / 'MISSING_HELD', folder / 'MISSING_ARCHIVE', folder / 'MISSING_DECISION', digest)

    def test_incomplete_held_source_refuses(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            (folder / 'source-map.json').write_bytes(b'MODELED incomplete Source')
            with self.assertRaises(ValueError):
                p.snapshot_held(folder)


if __name__ == '__main__':
    unittest.main(verbosity=2)
