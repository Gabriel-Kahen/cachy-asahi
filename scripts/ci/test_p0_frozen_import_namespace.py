"""Frozen importlib identity controls with checkout cwd; no native actors."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT/'scripts/ci/development/repository_handoff.py'
spec = importlib.util.spec_from_file_location('frozen_sdk_fixture', PATH)
S = importlib.util.module_from_spec(spec); sys.modules[spec.name] = S
spec.loader.exec_module(S)
BODY = b"import importlib.machinery as machinery\nHOOK = machinery.FileFinder.path_hook((machinery.SourceFileLoader, ['.py']))\n"


class FrozenNamespaceTests(unittest.TestCase):
    def setUp(self):
        self.previous = Path.cwd(); os.chdir(ROOT); self.addCleanup(os.chdir, self.previous)
        temporary = tempfile.TemporaryDirectory(prefix='frozen-test-', dir=ROOT); self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name)/'hook.py'; self.path.write_bytes(BODY)
        self.relative = self.path.relative_to(ROOT).as_posix()
        sdk_path = PATH.relative_to(ROOT).as_posix()
        self.source = S.Sources.__new__(S.Sources)
        self.source.root = ROOT; self.source.raw = {self.relative: BODY, sdk_path: PATH.read_bytes()}
        self.source.codes = {}; self.source.original_root = None; self.source.original_rows = None
        self.module = self.source.module('captured_hook_fixture', self.relative)
        self.hook = self.module.HOOK

    def namespace(self):
        self.source.graph_namespace(self.module, self.relative, {self.relative: self.module}, {}, {})

    def test_real_frozen_hook_accepts_checkout_cwd_and_retains_graph_tracking(self):
        self.assertTrue(S.frozen_import_function(self.hook))
        self.namespace()
        self.source.global_function(self.hook)
        self.source.graph_identity((self.module, self.hook))

    def test_acceptance_is_independent_of_cwd(self):
        os.chdir(ROOT.parent)
        self.namespace()
        self.assertTrue(S.frozen_import_function(self.hook))

    def test_forged_pseudo_filename_still_refuses(self):
        code = (lambda: None).__code__.replace(co_filename=self.hook.__code__.co_filename)
        fake = types.FunctionType(code, self.hook.__globals__)
        fake.__module__ = self.hook.__module__
        self.assertFalse(S.frozen_import_function(fake))
        self.module.HOOK = fake
        with self.assertRaisesRegex(S.Refused, '^callback-refused$'): self.namespace()
        with self.assertRaisesRegex(S.Refused, '^callback-refused$'): self.source.global_function(fake)

    def test_equal_frozen_code_with_foreign_globals_or_registry_refuses(self):
        fake = types.FunctionType(self.hook.__code__, dict(self.hook.__globals__), closure=self.hook.__closure__)
        fake.__module__ = self.hook.__module__
        self.assertFalse(S.frozen_import_function(fake))
        self.module.HOOK = fake
        with self.assertRaisesRegex(S.Refused, '^callback-refused$'): self.namespace()
        with mock.patch.dict(sys.modules, {'_frozen_importlib_external': types.ModuleType('foreign')}):
            self.assertFalse(S.frozen_import_function(self.hook))
            with self.assertRaisesRegex(S.Refused, '^callback-refused$'): self.source.global_function(self.hook)

    def test_project_code_transplanted_into_foreign_globals_still_refuses(self):
        code = compile('def injected(): return None', str(self.path), 'exec')
        namespace = {'__name__': self.module.__name__, '__file__': str(self.path)}
        exec(code, namespace)
        self.module.EXTRA = namespace['injected']
        with self.assertRaisesRegex(S.Refused, '^callback-refused$'): self.namespace()


if __name__ == '__main__':
    unittest.main()
