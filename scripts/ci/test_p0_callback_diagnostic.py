"""Fixed SDK code-boundary facts through the existing public codec; no actors."""
import importlib.util
from pathlib import Path
import sys
import time
import types
import unittest
from unittest import mock
import test_p0_image_diagnostic as existing

ROOT = Path(__file__).resolve().parents[2]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
D = load('callback_driver_fixture', ROOT/'scripts/ci/development/p0_ci.py')
S = load('callback_sdk_fixture', ROOT/'scripts/ci/development/repository_handoff.py')


class CallbackDiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.validate, cls.wanted = existing.workflow_codec()

    def setUp(self):
        self.boundaries = D.callback_code_boundaries(S)
        self.source = S.Sources.__new__(S.Sources)
        self.source.root = ROOT
        path = 'scripts/ci/development/repository_handoff.py'
        body = (ROOT/path).read_bytes()
        self.source.raw = {path: body}
        self.source.identities = {path: S.read(ROOT/path, time.monotonic()+5)[2]}
        self.source.grant = {'source_files': {path: {'mode': 0o644, 'sha256': S.digest(body)}},
            'callbacks': {'existing_consumers': {}}}
        self.source.codes = {}; self.source.original_root = None; self.source.original_rows = None

    def refused(self, action=None):
        try:
            if action is None: self.source.callback('existing_consumers', lambda: None, time.monotonic()+5)
            else: action()
        except S.Refused as error:
            return error
        self.fail('fixture did not refuse')

    def mark(self, error, boundaries=None):
        fields = ('args', '__cause__', '__context__', '__traceback__', '__suppress_context__')
        before = tuple(BaseException.__dict__[name].__get__(error) for name in fields)
        D.mark_callback_failure(error, S.Refused, self.boundaries if boundaries is None else boundaries)
        after = tuple(BaseException.__dict__[name].__get__(error) for name in fields)
        self.assertTrue(all(left is right for left, right in zip(before, after)))

    def test_real_sdk_callback_failure_survives_existing_five_field_workflow_codec(self):
        error = self.refused(); self.mark(error)
        existing.launcher.attach_diagnostic(error, 'pipeline', 'run-pipeline', 'pipeline')
        record = error.nativeci_diagnostic
        self.assertEqual(record, {'schema_version': 1, 'stage': 'pipeline',
            'operation': 'run-P0-sdk-callback', 'exception_type': 'UNKNOWN', 'refusal_code': 'callback-refused'})
        self.assertEqual(type(self).validate(record), record)
        self.assertEqual(len(type(self).validate.__globals__['DIAGNOSTIC_CODES']), 512)

    def test_deepest_real_sdk_boundary_and_nested_code_are_selected(self):
        code = (lambda: None).__code__.replace(co_filename='/outside_fixture/module.py')
        foreign = types.FunctionType(code, globals())
        error = self.refused(lambda: self.source.global_function(foreign)); self.mark(error)
        self.assertEqual(error.nativeci_pipeline_operation, 'run-P0-sdk-locate')
        error = self.refused(lambda: self.source.graph_identity((foreign,))); self.mark(error)
        self.assertEqual(error.nativeci_pipeline_operation, 'run-P0-sdk-graph_identity')

    def test_equal_code_with_forged_filename_is_not_a_trusted_identity(self):
        original = S.Sources.callback.__code__; forged = original.replace()
        self.assertEqual(forged, original); self.assertIsNot(forged, original)
        callback = types.FunctionType(forged, vars(S))
        error = self.refused(lambda: callback(self.source, 'existing_consumers', lambda: None, time.monotonic()+5))
        self.mark(error)
        self.assertNotIn('nativeci_pipeline_operation', vars(error))

    def test_other_errors_wrong_operands_and_prior_failures_keep_existing_fallback(self):
        class ForeignString(str):
            def __eq__(self, other): raise AssertionError('operand hook invoked')
        class ForeignRefusal(S.Refused): pass
        for error in (ValueError('callback-refused'), S.Refused('source-refused'),
            S.Refused(ForeignString('callback-refused')), ForeignRefusal('callback-refused')):
            self.mark(error)
            self.assertNotIn('nativeci_pipeline_operation', vars(error))
        error = self.refused(); error.nativeci_pipeline_operation = 'supervise-child'
        error.native_preflight_cancelled = True; error.native_preflight_cleanup_uncertain = True
        self.mark(error)
        self.assertEqual(error.nativeci_pipeline_operation, 'supervise-child')
        self.assertTrue(error.native_preflight_cancelled and error.native_preflight_cleanup_uncertain)

    def test_secondary_diagnostic_interrupt_preserves_primary_and_marks_custody(self):
        error = self.refused()
        with mock.patch.object(D, 'mark_pipeline_failure', side_effect=KeyboardInterrupt): self.mark(error)
        self.assertTrue(error.native_preflight_cancelled and error.native_preflight_cleanup_uncertain)

    def test_workflow_bootstrap_still_pins_the_actual_launcher(self):
        body = existing.LAUNCHER.read_bytes()
        self.assertEqual(type(self).wanted, {'bytes': len(body), 'mode': 0o644, 'sha256': S.digest(body)})


if __name__ == '__main__':
    unittest.main()
