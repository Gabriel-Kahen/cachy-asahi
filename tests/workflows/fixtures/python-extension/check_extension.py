# SPDX-License-Identifier: MIT
"""Load the exact original compiled fixture; never search user import paths."""
import argparse
import importlib.machinery
import importlib.util
import inspect
import json
from pathlib import Path
import sys
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--extension', type=Path, required=True)
parser.add_argument('--expected-file', type=Path)
parser.add_argument('--run', action='store_true')
args = parser.parse_args()
spec = importlib.util.spec_from_file_location('cachy_extension', args.extension)
if spec is None or not isinstance(spec.loader, importlib.machinery.ExtensionFileLoader):
    raise ValueError('actual compiled extension loader required')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
identity = dict(module=str(Path(module.__file__).resolve()), greeting=module.greeting(),
                builtin=inspect.isbuiltin(module.greeting), loader=type(spec.loader).__name__,
                isolated=sys.flags.isolated, executable=sys.executable)
if args.run:
    print(json.dumps(identity, sort_keys=True))
else:
    class ExtensionTest(unittest.TestCase):
        def test_exact_compiled_module(self):
            self.assertEqual(Path(module.__file__).resolve(), args.extension.resolve())
            self.assertTrue(inspect.isbuiltin(module.greeting))
            self.assertEqual(sys.flags.isolated, 1)

        def test_greeting(self):
            expected = args.expected_file.read_text().rstrip('\n')
            self.assertEqual(module.greeting(), expected, 'INTENTIONAL_TEST_MISMATCH')

    result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(ExtensionTest))
    if not result.wasSuccessful():
        raise SystemExit(1)
    print('DEVELOPER_TEST_OK')
