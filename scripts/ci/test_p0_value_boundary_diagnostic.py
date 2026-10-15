"""Inert real Source guards through the existing fixed public codec."""
from pathlib import Path
import ast
import time
import types
import unittest
from unittest import mock
import test_p0_callback_diagnostic as prior
import test_p0_image_diagnostic as existing

ROOT = Path(__file__).resolve().parents[2]
D, S = prior.D, prior.S
B = prior.load('value_preflight_fixture', ROOT/'scripts/install/native_preflight.py')
E = prior.load('value_entry_fixture', ROOT/'scripts/install/p0_entry.py')
prior.load('packet', ROOT/'scripts/ci/development/packet.py')
prior.load('common', ROOT/'scripts/ci/development/common.py')
C = prior.load('value_controller_fixture', ROOT/'scripts/ci/development/controller.py')


class ValueBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.validate, cls.wanted = existing.workflow_codec()

    def setUp(self):
        self.session = S.Session.__new__(S.Session)
        self.session.source_graph = {'native_preflight': B, 'original': {}}
        self.session.p0_entry_module = E
        self.boundaries = D.p0_value_code_boundaries(C, S, self.session)

    def caught(self, action):
        try: action()
        except BaseException as error: return error
        self.fail('guard did not refuse')

    def mark(self, error, boundaries=None):
        fields = ('args', '__cause__', '__context__', '__traceback__', '__suppress_context__')
        before = tuple(BaseException.__dict__[name].__get__(error) for name in fields)
        D.mark_callback_failure(error, S.Refused,
            self.boundaries if boundaries is None else boundaries, value_error=True)
        after = tuple(BaseException.__dict__[name].__get__(error) for name in fields)
        self.assertTrue(all(a is b for a, b in zip(before, after)))

    def test_real_guards_keep_private_operands_out_of_existing_codec(self):
        cases = (
            (lambda: B.namespace(None, b'PRIVATE_BODY', 'PRIVATE_PIN'), 'preflight-namespace'),
            (lambda: B.image_handoff([], None, types.SimpleNamespace(input_selection=lambda _: ('a','b')),
                                     b'PRIVATE_INPUT', b'PRIVATE_PACKAGES'), 'preflight-L196'),
            (lambda: E.projection({'PRIVATE_RETURN': 'PRIVATE_VALUE'}), 'entry-projection'),
        )
        for action, operation in cases:
            with self.subTest(operation=operation):
                error = self.caught(action); self.assertIs(type(error), ValueError); self.mark(error)
                existing.launcher.attach_diagnostic(error, 'pipeline', 'run-pipeline', 'pipeline')
                record = error.nativeci_diagnostic
                self.assertEqual(record['operation'], 'run-P0-' + operation)
                self.assertEqual(record['exception_type'], 'ValueError')
                self.assertEqual(record['refusal_code'], 'UNKNOWN')
                self.assertEqual(type(self).validate(record), record)
                self.assertNotIn('PRIVATE', repr(record))
                self.assertEqual(set(record), {'schema_version','stage','operation','exception_type','refusal_code'})
                self.assertEqual(len(type(self).validate.__globals__['DIAGNOSTIC_CODES']), 512)

    def test_deepest_concrete_boundary_wins_and_generic_need_is_not_selected(self):
        error = self.caught(lambda: E.verified_bridge(b'PRIVATE_BODY'))
        self.mark(error)
        self.assertEqual(error.nativeci_pipeline_operation, 'run-P0-entry-authenticate')
        error = self.caught(lambda: B.namespace(None, b'PRIVATE', 'PRIVATE'))
        outer = ((ValueBoundaryTests.caught.__code__, 'run-P0-controller-consumer'),)
        self.mark(error, outer + self.boundaries)
        self.assertEqual(error.nativeci_pipeline_operation, 'run-P0-preflight-namespace')

    def test_exact_type_code_identity_and_missing_dynamic_modules_fail_closed(self):
        class ForeignValueError(ValueError): pass
        for error in (ForeignValueError('PRIVATE'), TypeError('PRIVATE'), ValueError('PRIVATE')):
            self.mark(error); self.assertNotIn('nativeci_pipeline_operation', vars(error))
        code = B.namespace.__code__.replace()
        self.assertEqual(code, B.namespace.__code__); self.assertIsNot(code, B.namespace.__code__)
        forged = types.FunctionType(code, vars(B))
        error = self.caught(lambda: forged(None, b'PRIVATE', 'PRIVATE')); self.mark(error)
        self.assertNotIn('nativeci_pipeline_operation', vars(error))
        self.assertTrue(D.p0_value_code_boundaries(C, S, None))
        self.session.source_graph = None
        self.assertTrue(D.p0_value_code_boundaries(C, S, self.session))

    def test_primary_and_sticky_cleanup_facts_survive_optional_diagnostic(self):
        error = self.caught(lambda: E.projection({}))
        error.nativeci_pipeline_operation = 'run-P0'
        error.native_preflight_cleanup_uncertain = True; error.native_preflight_cancelled = False
        self.mark(error)
        self.assertEqual(error.nativeci_pipeline_operation, 'run-P0')
        self.assertTrue(error.native_preflight_cleanup_uncertain)
        self.assertIs(error.native_preflight_cancelled, False)
        error = self.caught(lambda: E.projection({}))
        with mock.patch.object(D, 'mark_pipeline_failure', side_effect=KeyboardInterrupt): self.mark(error)
        self.assertTrue(error.native_preflight_cancelled and error.native_preflight_cleanup_uncertain)

    def test_exact_source_lines_and_functions_cover_every_preflight_call_site(self):
        raw = (ROOT/'scripts/install/native_preflight.py').read_text()
        calls = tuple(sorted({node.lineno for function in ast.parse(raw).body
            if isinstance(function, ast.FunctionDef) and function.name in D.P0_PREFLIGHT_FUNCTIONS
            for node in ast.walk(function) if isinstance(node, ast.Call)}))
        self.assertEqual(D.P0_PREFLIGHT_CALL_LINES, calls)
        cases = (
            (lambda: B.selection(None, None, types.SimpleNamespace(input_selection=lambda _: ('a','b')), None, 'PRIVATE_NONCE'), 223),
            (lambda: B.container_binding([], None, None, None, None, None, None), 251),
            (lambda: B.run(types.SimpleNamespace(sources=types.SimpleNamespace(grant={})), None, None,
                           deadline=time.monotonic()+60, nonce='PRIVATE', runtime_contract={}), 306),
        )
        for action, line in cases:
            with self.subTest(line=line), mock.patch.object(B, 'live', return_value={}):
                error = self.caught(action); self.assertIs(type(error), ValueError); self.mark(error)
                self.assertEqual(error.nativeci_pipeline_operation, 'run-P0-preflight-L'+str(line))
        for name in D.P0_PREFLIGHT_FUNCTIONS:
            record = {'schema_version':1, 'stage':'pipeline', 'operation':'run-P0-preflight-'+name,
                      'exception_type':'ValueError', 'refusal_code':'UNKNOWN'}
            self.assertEqual(type(self).validate(record), record)
        for line in calls:
            record = {'schema_version':1, 'stage':'pipeline', 'operation':'run-P0-preflight-L'+str(line),
                      'exception_type':'ValueError', 'refusal_code':'UNKNOWN'}
            self.assertEqual(type(self).validate(record), record)

    def test_modeled_daemon_guard_retains_primary_over_failed_descriptor_cleanup(self):
        fixture = prior.load('value_preflight_pipeline_fixture', ROOT/'scripts/install/test_native_preflight.py')
        model = fixture.PipelineModels()
        model.setUp()
        self.addCleanup(model.doCleanups)
        transport = model.session.source_graph['runtime']['transport']
        original_supervise = transport.supervise
        def refused_daemon(argv, **kwargs):
            value, observation = original_supervise(argv, **kwargs)
            if argv[1] == 'info': value['stdout'] = fixture.P.encoded({'Architecture':'PRIVATE_FOREIGN', 'OSType':'linux'})
            return value, observation
        def failed_close(self): raise ValueError('PRIVATE_CLOSE_FAILURE')
        transport.supervise = refused_daemon
        with mock.patch.object(transport.DockerTransport, 'close', failed_close):
            error = self.caught(model.run_model)
        self.assertIs(type(error), ValueError)
        self.assertEqual(error.args, ('NATIVE_LOCAL_DAEMON',))
        self.assertTrue(error.native_preflight_cleanup_uncertain)
        self.assertIs(error.native_preflight_cancelled, False)
        self.session.source_graph = {'native_preflight':fixture.P, 'original':{}}
        boundaries = D.p0_value_code_boundaries(C, S, self.session)
        self.mark(error, boundaries)
        self.assertEqual(error.nativeci_pipeline_operation, 'run-P0-preflight-L345')
        self.assertEqual(error.args, ('NATIVE_LOCAL_DAEMON',))
        self.assertTrue(error.native_preflight_cleanup_uncertain)
        self.assertEqual([row[0][0] for row in model.commands], ['info'])

    def test_workflow_pins_actual_launcher_and_all_fixed_operations_survive(self):
        body = existing.LAUNCHER.read_bytes()
        self.assertEqual(type(self).wanted, {'bytes': len(body), 'mode': 0o644, 'sha256': S.digest(body)})
        for name in D.P0_VALUE_OPERATIONS:
            record = {'schema_version':1, 'stage':'pipeline', 'operation':'run-P0-'+name,
                      'exception_type':'ValueError', 'refusal_code':'UNKNOWN'}
            self.assertEqual(type(self).validate(record), record)


if __name__ == '__main__': unittest.main()
