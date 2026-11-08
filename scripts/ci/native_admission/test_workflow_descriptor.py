"""Positive/hostile DATA controls; no workflow Source code is imported or run."""
import copy
from dataclasses import FrozenInstanceError
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

P = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('tested_workflow_descriptor', P / 'workflow_descriptor.py')
W = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = W
SPEC.loader.exec_module(W)
FIXTURE = (P / 'fixtures/d91-native-workflow.json.data').read_bytes()
INPUTS = json.loads((P / 'fixtures/d91-dispatch-inputs.json.data').read_bytes())


def literal():
    return {'name': 'data-only', 'on': {'workflow_dispatch': {'inputs': {}}},
            'permissions': {'contents': 'read'},
            'concurrency': {'group': 'native-arm-finite-example', 'cancel-in-progress': False},
            'jobs': {'native': {'runs-on': 'ubuntu-24.04-arm', 'steps': [{'run': 'NEVER EXECUTE'}]}}}


def encoded(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':')).encode()


class DescriptorTests(unittest.TestCase):
    def refuse(self, reason, raw, **kwargs):
        with self.assertRaisesRegex(W.DescriptorRefused, '^' + reason + '$'):
            W.describe_workflow(raw, **kwargs)

    def test_genuine_d91_raw_hash_group_and_exact_input_proof(self):
        self.assertEqual(len(FIXTURE), 118082)
        self.assertEqual(hashlib.sha256(FIXTURE).hexdigest(), '3d44fa32f528145458ed02424b99e7625608d246267a1e496a504393c2fe13a3')
        result = W.describe_workflow(FIXTURE, dispatch_inputs=INPUTS)
        self.assertEqual(result.workflow_sha256, hashlib.sha256(FIXTURE).hexdigest())
        self.assertEqual(result.job_runners, (('native', 'ubuntu-24.04-arm'),))
        self.assertEqual(result.concurrency_expression, W.D91_GROUP)
        self.assertEqual(result.concurrency_group, 'updater607-generic16k-d91ddd0673e1915678669b39dd9634277f4d044b-normal')
        self.assertFalse(result.cancel_in_progress)
        self.assertEqual(result.resolution, 'EXACT_D91_SOURCE_CASE_V1')
        self.assertEqual(dict(result.resolution_bindings), {'source': INPUTS['source'], 'case': 'normal'})
        self.assertEqual(result.dispatch_inputs_sha256, hashlib.sha256(encoded(dict(sorted(INPUTS.items())))).hexdigest())
        self.assertEqual(result.authority, 'DATA_ONLY_NO_RESOURCE_NATIVE_OR_COEXISTENCE_AUTHORITY')
        with self.assertRaises(FrozenInstanceError):
            result.runner_selector = 'self-hosted'

    def test_reviewed_fault_case_selectors_are_data_not_operations(self):
        for case in W.D91_CASES:
            with self.subTest(case=case):
                supplied = dict(INPUTS, case=case)
                result = W.describe_workflow(FIXTURE, dispatch_inputs=supplied)
                self.assertEqual(result.concurrency_group, 'updater607-generic16k-' + INPUTS['source'] + '-' + case)

    def test_literal_group_all_reviewed_labels_and_literal_true_are_reported(self):
        for runner in W.HOSTED_RUNNERS:
            value = literal(); value['jobs']['native']['runs-on'] = runner
            value['concurrency']['cancel-in-progress'] = True
            result = W.describe_workflow(encoded(value))
            self.assertEqual(result.runner_selector, runner)
            self.assertEqual(result.concurrency_group, 'native-arm-finite-example')
            self.assertEqual(result.concurrency_expression, result.concurrency_group)
            self.assertTrue(result.cancel_in_progress)
            self.assertEqual(result.resolution_bindings, ())
            self.assertEqual(result.dispatch_inputs_sha256, '')

    def test_raw_formatting_is_kept_in_hash_without_changing_grammar(self):
        value = literal(); a = encoded(value); b = json.dumps(value, indent=2).encode()
        x, y = W.describe_workflow(a), W.describe_workflow(b)
        self.assertNotEqual(x.workflow_sha256, y.workflow_sha256)
        self.assertEqual(x.concurrency_expression, y.concurrency_expression)

    def test_missing_full_dispatch_inputs_never_guess_defaults(self):
        self.refuse('dispatch-inputs-required', FIXTURE)
        for missing in ('source', 'case', 'integration_sha256'):
            supplied = dict(INPUTS); supplied.pop(missing)
            self.refuse('exact-dispatch-input-fields', FIXTURE, dispatch_inputs=supplied)
        self.refuse('exact-dispatch-input-fields', FIXTURE, dispatch_inputs=dict(INPUTS, unknown='x'))

    def test_typed_dispatch_source_case_and_other_choices(self):
        for source in ('A' * 40, '0' * 39, '${{ inputs.source }}', '../PRIVATE'):
            self.refuse('source-input-sha', FIXTURE, dispatch_inputs=dict(INPUTS, source=source))
        self.refuse('dispatch-input-choice', FIXTURE, dispatch_inputs=dict(INPUTS, case='$(PRIVATE)'))
        self.refuse('dispatch-input-choice', FIXTURE, dispatch_inputs=dict(INPUTS, mode='shell'))
        for value in (True, 1, None, ['x'], 'x' * 201, 'PRIVATE\x00'):
            self.refuse('dispatch-input-value', FIXTURE, dispatch_inputs=dict(INPUTS, source=value))
        self.refuse('exact-dispatch-input-fields', FIXTURE, dispatch_inputs=list(INPUTS.items()))

    def test_exact_group_grammar_rejects_added_expressions_functions_and_spacing(self):
        for group in (W.D91_GROUP + '-${{ github.run_id }}', W.D91_GROUP.replace('inputs.case', 'format(inputs.case)'),
                      W.D91_GROUP.replace('inputs.source', 'secrets.source'), W.D91_GROUP.replace(' }}', '}}'),
                      'native-${{ inputs.source }}', '${{ inputs.group }}', 'x\nPRIVATE', ''):
            value = json.loads(FIXTURE); value['concurrency']['group'] = group
            reason = 'concurrency-types' if not group else 'unreviewed-concurrency-expression'
            self.refuse(reason, encoded(value), dispatch_inputs=INPUTS)

    def test_reviewed_source_and_case_definition_contract(self):
        changes = [('source', 'type', 'choice', 'input-choice-options'),
                   ('source', 'required', False, 'reviewed-source-input-definition'),
                   ('case', 'required', False, 'reviewed-case-input-definition'),
                   ('case', 'default', 'precommit-exit86', 'reviewed-case-input-definition'),
                   ('case', 'options', ['normal', 'precommit-exit86', 'postcommit-exit87', 'extra'], 'reviewed-case-input-definition')]
        for name, key, selected, reason in changes:
            value = json.loads(FIXTURE); value['on']['workflow_dispatch']['inputs'][name][key] = selected
            self.refuse(reason, encoded(value), dispatch_inputs=INPUTS)

    def test_duplicate_json_keys_at_root_job_and_opaque_script_scope(self):
        for raw in (b'{"jobs":{},"jobs":{}}',
                    encoded(literal()).replace(b'"runs-on":"ubuntu-24.04-arm"', b'"runs-on":"ubuntu-24.04-arm","runs-on":"self-hosted"'),
                    encoded(literal()).replace(b'"run":"NEVER EXECUTE"', b'"run":"NEVER EXECUTE","run":"PRIVATE"')):
            self.refuse('duplicate-json-key', raw)

    def test_nonfinite_and_integer_caps_even_in_opaque_steps(self):
        for number in (b'NaN', b'Infinity', b'-Infinity', b'1e9999'):
            raw = encoded(literal()).replace(b'"NEVER EXECUTE"', number)
            self.refuse('nonfinite-json-number', raw)
        self.refuse('json-integer-cap', encoded(literal()).replace(b'"NEVER EXECUTE"', b'9' * 65))

    def test_full_json_utf8_syntax_surrogate_and_trailing_refusals(self):
        self.refuse('invalid-json', b'{"x":"\xff"}')
        self.refuse('invalid-json', encoded(literal()) + b' {}')
        self.refuse('invalid-json', b'{"name":')
        self.refuse('json-surrogate', encoded(literal()).replace(b'NEVER EXECUTE', b'\\ud800'))
        self.refuse('unsupported-format', b'[]')

    def test_size_exact_bytes_type_and_structure_caps(self):
        for value in (b'', b'{' + b' ' * W.MAX_BYTES, bytearray(encoded(literal())), encoded(literal()).decode()):
            self.refuse('workflow-byte-cap', value)
        value = literal(); nested = []
        for _ in range(W.MAX_DEPTH): nested = [nested]
        value['jobs']['native']['steps'][0]['data'] = nested
        self.refuse('json-structure-cap', encoded(value))
        value = literal(); value['jobs']['native']['steps'][0]['data'] = [0] * W.MAX_NODES
        self.refuse('json-structure-cap', encoded(value))

    def test_held_literal_yaml_is_explicitly_unsupported_not_guessed(self):
        raw = (P / 'fixtures/literal-release-workflow.yml.data').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), '1333c92f4423e46b6b73daf53671e4d5ec7609b1a4f695e8a9c2e29c4389d5b3')
        self.refuse('unsupported-format', raw)

    def test_runner_lists_objects_dynamic_self_hosted_and_mixed_are_refused(self):
        for runner in ('self-hosted', '${{ matrix.os }}', 'ubuntu-24.04-arm ', ['ubuntu-24.04-arm'],
                       ['self-hosted', 'ARM64'], {'labels': 'ubuntu-24.04-arm'}, True, None):
            value = literal(); value['jobs']['native']['runs-on'] = runner
            self.refuse('runner-selector', encoded(value))
        value = literal(); value['jobs']['second'] = copy.deepcopy(value['jobs']['native'])
        value['jobs']['second']['runs-on'] = 'ubuntu-24.04'
        self.refuse('mixed-runner-selectors', encoded(value))

    def test_same_selector_multiple_jobs_preserves_each_exact_job(self):
        value = literal(); value['jobs']['second'] = copy.deepcopy(value['jobs']['native'])
        result = W.describe_workflow(encoded(value))
        self.assertEqual(result.job_runners, (('native', 'ubuntu-24.04-arm'), ('second', 'ubuntu-24.04-arm')))

    def test_unknown_relevant_keys_and_reusable_jobs_refused(self):
        for scope, extra, reason in (('root', 'unknown', 'workflow-fields'), ('job', 'uses', 'job-fields'),
                                    ('job', 'strategy', 'job-fields'), ('concurrency', 'queue', 'concurrency-fields'),
                                    ('event', 'push', 'event-scope'), ('dispatch', 'unknown', 'dispatch-fields')):
            value = literal()
            target = {'root': value, 'job': value['jobs']['native'], 'concurrency': value['concurrency'],
                      'event': value['on'], 'dispatch': value['on']['workflow_dispatch']}[scope]
            target[extra] = 'PRIVATE'; self.refuse(reason, encoded(value))
        value = json.loads(FIXTURE); value['on']['workflow_dispatch']['inputs']['source']['unknown'] = 'PRIVATE'
        self.refuse('input-definition-fields', encoded(value), dispatch_inputs=INPUTS)

    def test_literal_cancel_and_job_scope_types(self):
        for cancel in ('false', 0, None, '${{ inputs.cancel }}'):
            value = literal(); value['concurrency']['cancel-in-progress'] = cancel
            self.refuse('concurrency-types', encoded(value))
        for key, selected, reason in (('steps', {}, 'steps-shape'), ('env', [], 'job-env-type'),
                                     ('if', True, 'job-if-type'), ('name', 3, 'job-label-type'),
                                     ('timeout-minutes', True, 'job-timeout-type'), ('timeout-minutes', 0, 'job-timeout-type')):
            value = literal(); value['jobs']['native'][key] = selected
            self.refuse(reason, encoded(value))

    def test_empty_jobs_step_and_job_caps(self):
        value = literal(); value['jobs'] = {}; self.refuse('jobs-cap', encoded(value))
        value = literal(); value['jobs']['native']['steps'] = []; self.refuse('steps-shape', encoded(value))
        value = literal(); value['jobs']['native']['steps'] = [{}] * (W.MAX_STEPS + 1)
        self.refuse('steps-shape', encoded(value))
        value = literal(); value['jobs'] = {'j' + str(i): value['jobs']['native'] for i in range(W.MAX_JOBS + 1)}
        self.refuse('jobs-cap', encoded(value))

    def test_no_expression_execution_io_process_network_or_source_import(self):
        value = literal(); value['jobs']['native']['steps'][0]['run'] = "__import__('os').system('PRIVATE')"
        value['jobs']['native']['env'] = {'UNUSED': '${{ arbitrary.function(secrets.PRIVATE) }}'}
        raw = encoded(value); active = [True]; seen = []
        def audit(event, args):
            if active[0] and (event in ('open', 'exec', 'compile', 'import', 'os.system') or event.startswith(('socket.', 'subprocess.'))):
                seen.append(event); raise AssertionError('Unexpected parser side effect')
        sys.addaudithook(audit)
        try: result = W.describe_workflow(raw)
        finally: active[0] = False
        self.assertEqual(seen, [])
        self.assertEqual(result.resolution, 'LITERAL')

    def test_dispatch_mapping_and_key_subclasses_are_not_coerced(self):
        class Mapping(dict): pass
        class Key(str): pass
        self.refuse('exact-dispatch-input-fields', FIXTURE, dispatch_inputs=Mapping(INPUTS))
        supplied = dict(INPUTS); selected = supplied.pop('source'); supplied[Key('source')] = selected
        self.refuse('exact-dispatch-input-fields', FIXTURE, dispatch_inputs=supplied)

    def test_input_fingerprint_and_resolution_use_one_snapshot(self):
        supplied = dict(INPUTS)
        original = W._dispatch_inputs
        def mutate_caller_after_fingerprint(value, definitions):
            fingerprint = original(value, definitions)
            supplied['source'] = '0' * 40
            return fingerprint
        with patch.object(W, '_dispatch_inputs', side_effect=mutate_caller_after_fingerprint):
            result = W.describe_workflow(FIXTURE, dispatch_inputs=supplied)
        self.assertEqual(supplied['source'], '0' * 40)
        self.assertEqual(dict(result.resolution_bindings)['source'], INPUTS['source'])
        self.assertEqual(result.dispatch_inputs_sha256, hashlib.sha256(encoded(dict(sorted(INPUTS.items())))).hexdigest())

    def test_relevant_scope_type_and_permission_refusals(self):
        for key, selected, reason in (('permissions', 'read-all', 'permissions-fields'),
                                     ('concurrency', [], 'concurrency-fields'),
                                     ('jobs', [], 'jobs-cap'), ('on', [], 'event-scope'),
                                     ('name', None, 'workflow-name')):
            value = literal(); value[key] = selected
            self.refuse(reason, encoded(value))
        value = literal(); value['permissions']['unknown'] = 'read'
        self.refuse('permissions-fields', encoded(value))
        value = literal(); value['permissions']['contents'] = True
        self.refuse('permissions-value', encoded(value))
        value = json.loads(FIXTURE); value['on']['workflow_dispatch']['inputs']['source']['required'] = 'true'
        self.refuse('input-required-type', encoded(value), dispatch_inputs=INPUTS)
        value = json.loads(FIXTURE); value['on']['workflow_dispatch']['inputs']['case']['options'] = ['normal', 'normal']
        self.refuse('input-choice-options', encoded(value), dispatch_inputs=INPUTS)

    def test_errors_do_not_echo_private_values(self):
        value = literal(); value['concurrency']['group'] = '${{ secrets.PRIVATE }}'
        with self.assertRaises(W.DescriptorRefused) as caught: W.describe_workflow(encoded(value))
        self.assertEqual(str(caught.exception), 'unreviewed-concurrency-expression')
        self.assertNotIn('PRIVATE', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
