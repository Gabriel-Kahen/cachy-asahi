# SPDX-License-Identifier: MIT
"""Inherited MODEL crypto-boundary controls plus exact GUI namespace inverse."""
import sys


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
            'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn',
            'fcntl.flock', 'resource.setrlimit', 'os.kill', 'os.killpg'):
        raise RuntimeError('MODEL_ONLY_ACTOR_FENCE:' + event)


sys.addaudithook(fence)
import hashlib
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
raw = (HERE / 'signature-controls.py.DATA').read_bytes()
if len(raw) != 17800 or hashlib.sha256(raw).hexdigest() != '4c73fe2602b7ee6d810502099cc36918ae3f9b55f326a34503fa9b5b7b173bce':
    raise ValueError('unchanged MODEL signature controls whole pin')
controls = dict(__name__='GUI_INHERITED_SIGNATURE_MODEL', __file__=str(HERE/'test_trust.py'))
exec(compile(raw, str(HERE/'signature-controls.py.DATA'), 'exec'), controls)
T = controls['T']


class Projection(unittest.TestCase):
    def test_exact_GUI_scope_and_whole_inverse(self):
        raw = (HERE/'signature-shared.py.DATA').read_bytes()
        projected = T.project(raw)
        restored = projected.decode()
        for before, after in reversed(T.CHANGES):
            restored = restored.replace(after, before, 1)
        self.assertEqual(restored.encode(), raw)
        self.assertEqual(T.SCOPE, 'QT612_GUI18_PROJECT_TEST_SIGNATURE_ONLY_V1')
        with self.assertRaises(ValueError):
            T.project(raw+b'\n')


def load_tests(loader, tests, pattern):
    tests.addTests(loader.loadTestsFromTestCase(controls['ModelOnly']))
    return tests


if __name__ == '__main__':
    unittest.main()
