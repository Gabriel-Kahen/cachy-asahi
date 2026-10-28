# SPDX-License-Identifier: MIT
import copy
import importlib.util
import json
from pathlib import Path
import unittest

import evidence


def binding():
    return {'source_commit': 'a' * 40, 'stage_lock_sha256': 'b' * 64,
        'output_name_sha256': 'c' * 64, 'run_id': '1', 'run_attempt': '2', 'nonce': 'd' * 32,
        'accepted_result_sha256': 'e' * 64, 'bootstrap_sha256': 'f' * 64,
        'inputs_sha256': '1' * 64, 'base_inventory_sha256': '2' * 64}


class ChildEvidenceTests(unittest.TestCase):
    def receiver(self):
        path = Path(__file__).resolve().parents[1] / 'kernel-native-job/public.py'
        spec = importlib.util.spec_from_file_location('kernel_child_public_fixture', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_pending_projection_binds_only_digest_not_private_inputs(self):
        row = evidence.initial(binding()); projected = evidence.project(row)
        self.assertNotIn('binding', projected)
        self.assertNotIn('source_commit', projected)
        self.assertNotIn('nonce', projected)
        self.assertEqual(projected['commands']['provision'], {'kind': 'NOT_RUN', 'code': None})
        self.assertLessEqual(len(evidence.encoded(row)), 4096)
        self.assertEqual(self.receiver().child_project(row), projected)

    def test_completed_diagnostic_requires_observed_zero_each_command_and_cleanup(self):
        row = evidence.initial(binding())
        row['current_predicate'] = 'COMPLETE'
        with self.assertRaises(ValueError): evidence.project(row)
        row['commands'] = {name: evidence.exit_record(0) for name in evidence.ACTIONS}
        with self.assertRaises(ValueError): evidence.project(row)
        row['cleanup'] = {'status': 'PASS', 'category': 'NONE'}
        self.assertEqual(evidence.project(row)['current_predicate'], 'COMPLETE')
        for name in evidence.ACTIONS:
            altered = copy.deepcopy(row); altered['commands'][name] = evidence.exit_record(125)
            with self.subTest(command=name), self.assertRaises(ValueError): evidence.project(altered)

    def test_first_predicate_stays_fixed_across_cleanup_and_finalization_cancellation(self):
        row = evidence.initial(binding()); row['current_predicate'] = 'PROVISION_COMMAND'
        row['commands']['provision'] = evidence.exit_record(125)
        evidence.failure(row, 'COMMAND_NONZERO')
        row['cleanup'] = {'status': 'FAIL', 'category': 'UNCERTAIN_MUTATION'}
        evidence.failure(row, 'CANCELLED', 'FINALIZATION')
        self.assertEqual((row['first_failed_predicate'], row['failure_category']),
                         ('PROVISION_COMMAND', 'COMMAND_NONZERO'))
        self.assertEqual(self.receiver().child_project(row), evidence.project(row))

    def test_complete_late_cancel_preserves_completed_commands_without_claiming_pass(self):
        row = evidence.initial(binding())
        row.update(current_predicate='COMPLETE', commands={name: evidence.exit_record(0) for name in evidence.ACTIONS},
                   cleanup={'status': 'PASS', 'category': 'NONE'})
        evidence.failure(row, 'CANCELLED', 'FINALIZATION')
        self.assertEqual(evidence.project(row)['failure_category'], 'CANCELLED')
        self.assertEqual(row['commands']['candidate'], evidence.exit_record(0))

    def test_exit_codes_are_actual_integers_and_unobserved_is_not_zero(self):
        for code in (True, False, None, 256, -65, '0'):
            with self.subTest(code=code), self.assertRaises(ValueError): evidence.exit_record(code)
        for row in ({'kind': 'EXIT_ZERO', 'code': None}, {'kind': 'UNOBSERVED', 'code': 0},
                    {'kind': 'EXIT_SIGNAL', 'code': 1}, {'kind': 'EXIT_ZERO', 'code': True}):
            with self.subTest(row=row), self.assertRaises(ValueError): evidence.validate_exit(row)
        for code in (-15, 0, 125): self.assertEqual(evidence.validate_exit(evidence.exit_record(code)), evidence.exit_record(code))

    def test_closed_error_categories_never_export_arbitrary_exception_data(self):
        self.assertEqual(evidence.error_category(ValueError('private/secret/path')), 'INVALID_DATA')
        self.assertEqual(evidence.error_category(OSError('token data')), 'IO')
        self.assertEqual(evidence.error_category(ValueError('command-timeout')), 'TIMEOUT')
        self.assertEqual(evidence.error_category(ValueError('deadline-exhausted')), 'DEADLINE')
        self.assertEqual(evidence.error_category(ValueError('output-bound')), 'OUTPUT_BOUND')
        self.assertEqual(evidence.error_category(RuntimeError('secret')), 'UNCLASSIFIED')
        self.assertEqual(evidence.error_category(KeyboardInterrupt()), 'CANCELLED')

    def test_cleanup_categories_preserve_cancel_unknown_mutation_without_raw_errors(self):
        self.assertEqual(evidence.cleanup_category([{'uncertain_commit': True}]), 'UNCERTAIN_MUTATION')
        self.assertEqual(evidence.cleanup_category([{'cancelled': True, 'errors': ['secret']}]), 'CANCELLED')
        self.assertEqual(evidence.cleanup_category([{'status': 'FAIL', 'errors': ['secret/path']}]), 'ABSENCE_UNVERIFIED')

    def test_child_receiver_schema_agreement_on_meaningful_poison_matrix(self):
        receiver = self.receiver()
        changes = [lambda r: r.update(schema_version=True), lambda r: r.update(extra='secret'),
            lambda r: r.update(current_predicate='private/path'), lambda r: r.update(failure_category='secret'),
            lambda r: r['commands']['provision'].update(code=True), lambda r: r['commands'].pop('candidate'),
            lambda r: r['cleanup'].update(status='PASS', category='IO'),
            lambda r: r['cleanup'].update(status='FAIL', category='NONE'),
            lambda r: r['binding'].update(nonce='private nonce'), lambda r: r['binding'].update(run_id='../secret'),
            lambda r: r['binding'].update(run_attempt=True), lambda r: r['binding'].update(source_commit='b' * 64),
            lambda r: r['binding'].update(extra='secret'), lambda r: r.update(commands=[])]
        for change in changes:
            row = evidence.initial(binding()); change(row)
            with self.subTest(change=change):
                with self.assertRaises(ValueError): evidence.project(row)
                with self.assertRaises(ValueError): receiver.child_project(row)
        row = evidence.initial(binding()); row['binding']['source_commit'] = 'x' * 5000
        with self.assertRaises(ValueError): evidence.project(row)
        with self.assertRaises(ValueError): receiver.child_project(row)



class OperationEvidenceTests(unittest.TestCase):
    receiver = ChildEvidenceTests.receiver
    def test_schema1_has_exact_historical_bytes_and_schema3_is_closed(self):
        legacy = evidence.initial(binding())
        expected = {'schema_version': 1, 'binding': binding(), 'current_predicate': 'SNAPSHOT',
            'first_failed_predicate': 'NONE', 'failure_category': 'NONE',
            'commands': {name: {'kind': 'NOT_RUN', 'code': None} for name in evidence.ACTIONS},
            'cleanup': {'status': 'NOT_RUN', 'category': 'NONE'}}
        self.assertEqual(evidence.encoded(legacy), evidence.encoded(expected))
        fresh = evidence.initial(binding(), evidence.Trace())
        self.assertEqual(fresh['schema_version'], 3)
        self.assertEqual(self.receiver().child_project(fresh), evidence.project(fresh))
        for row in (dict(legacy, operation=fresh['operation']), {k:v for k,v in fresh.items() if k != 'operation'}):
            for validate in (evidence.project, self.receiver().child_project):
                with self.assertRaises(ValueError): validate(row)

    def test_operation_poison_types_privacy_and_discriminated_returns(self):
        for key, value in [('gate', 'private/path'), ('predicate', 'docker-private-token'),
                           ('action', True), ('create', 'OWNED'), ('start', 'COMPLETE')]:
            row = evidence.initial(binding(), evidence.Trace()); row['operation']['current'][key] = value
            for validate in (evidence.project, self.receiver().child_project):
                with self.subTest(key=key), self.assertRaises(ValueError): validate(row)
        for slot, value in [('daemon_return', {'kind':'EXIT_ZERO','code':0}),
            ('query_return', {'kind':'HTTP_STATUS','code':200}),
            ('daemon_return', {'kind':'HTTP_STATUS','code':True}),
            ('daemon_return', {'kind':'HTTP_STATUS','code':99}),
            ('daemon_return', {'kind':'HTTP_STATUS','code':600})]:
            row = evidence.initial(binding(), evidence.Trace()); row['operation']['current'][slot] = value
            for validate in (evidence.project, self.receiver().child_project):
                with self.subTest(slot=slot,value=value), self.assertRaises(ValueError): validate(row)
        for value in ({'kind':'EXIT_ZERO','code':0}, {'kind':'HTTP_STATUS','code':201}):
            row = evidence.initial(binding(), evidence.Trace())
            row['operation']['current'].update(query='IMAGE_COMMIT', query_return=value)
            if value['kind']=='HTTP_STATUS': self.assertEqual(evidence.project(row),self.receiver().child_project(row))
            else:
                with self.assertRaises(ValueError): evidence.project(row)
        row['operation']['current']['raw'] = 'secret'
        with self.assertRaises(ValueError): self.receiver().child_project(row)

    def test_first_and_cleanup_are_deep_sticky_snapshots_unknown_text_omitted(self):
        trace = evidence.Trace(); trace.current['action']='provision'; trace.begin('CREATE')
        try:
            with trace.scope('QUERY_EXEC'): raise ValueError('unreviewed token/private/path')
        except ValueError: pass
        first = trace.snapshot()['first_failure']
        with trace.scope('QUERY_RETURN'): trace.returned(0)
        trace.current['create']='CID_OBSERVED'
        try:
            with trace.scope('CLEANUP_REMOVE','cleanup'): raise OSError('secret cleanup')
        except OSError: pass
        result = trace.snapshot(); result['first_failure']['query_return']['code']=123
        self.assertEqual(trace.snapshot()['first_failure'],first)
        self.assertEqual(first['predicate'],'UNKNOWN')
        self.assertEqual(trace.snapshot()['cleanup_failure']['gate'],'CLEANUP_REMOVE')
        self.assertNotIn('secret',json.dumps(trace.snapshot()))
        self.assertNotIn('private/path',json.dumps(trace.snapshot()))

    def test_static_whitelist_matches_reviewed_literal_guards_only(self):
        import ast
        labels={'deadline-exhausted','command-timeout','output-bound','kernel worker exit failed'}
        for name in ('broker.py','image.py','runtime.py'):
            for node in ast.walk(ast.parse((Path(evidence.__file__).parent/name).read_bytes())):
                if isinstance(node,ast.Call) and isinstance(node.func,ast.Name):
                    position=1 if node.func.id=='need' else 0 if node.func.id=='ValueError' else None
                    if position is not None and len(node.args)>position:
                        arg=node.args[position]
                        if isinstance(arg,ast.Constant) and type(arg.value) is str:labels.add(arg.value)
        self.assertEqual(evidence.REFUSALS,labels)
        self.assertEqual(self.receiver().CHILD_REFUSALS,labels)

    def test_cancel_and_action_change_are_truthful_without_erasing_first_failure(self):
        trace=evidence.Trace();trace.action('baseline');trace.begin('START');trace.returned(0)
        trace.current['create']='CID_OBSERVED'
        trace.action('candidate')
        self.assertEqual(trace.current['start'],'NOT_ATTEMPTED')
        try:
            with trace.scope('QUERY_EXEC'):raise evidence.Cancelled(15)
        except evidence.Cancelled:pass
        first=trace.snapshot()['first_failure']
        self.assertEqual(first['category'],'CANCELLED')
        trace.action('cleanup')
        self.assertEqual(trace.snapshot()['first_failure'],first)

    def test_schema2_complete_cannot_hide_operation_failure_and_total_4k_bound(self):
        trace=evidence.Trace()
        try:
            with trace.scope('QUERY_EXEC','provision'): raise ValueError('docker-create-unknown')
        except ValueError: pass
        row=evidence.initial(binding(),trace)
        row.update(current_predicate='COMPLETE',commands={n:evidence.exit_record(0) for n in evidence.ACTIONS},
                   cleanup={'status':'PASS','category':'NONE'})
        for validate in (evidence.project,self.receiver().child_project):
            with self.assertRaises(ValueError):validate(row)
        row['current_predicate']='PROVISION_COMMAND'; evidence.failure(row,'INVALID_DATA')
        self.assertLessEqual(len(evidence.encoded(row)),4096)
        row['binding']['run_id']='1'*5000
        with self.assertRaises(ValueError):evidence.project(row)



class ResourceSchemaTests(unittest.TestCase):
    receiver = ChildEvidenceTests.receiver
    def diagnostic(self):
        trace=evidence.Trace();trace.current['action']='provision'
        with trace.scope('INSPECT_RESOURCES'):
            trace.resources_refused({'Memory':'private-secret'},{'Memory':14},())
            trace.fail(ValueError('docker-container-resources'))
        row=evidence.initial(binding(),trace);row.update(current_predicate='PROVISION_COMMAND')
        evidence.failure(row,'INVALID_DATA');return row

    def test_new_closed_projection_matches_receiver_and_stays_bounded(self):
        row=self.diagnostic();out=evidence.project(row)
        self.assertEqual(out,self.receiver().child_project(row));self.assertEqual(out['schema_version'],3)
        self.assertLessEqual(len(evidence.encoded(out)),4096);self.assertNotIn('private-secret',json.dumps(out))
        self.assertEqual(out['operation']['first_failure']['resource_mismatch'],{'field':'Memory','kind':'TYPE'})

    def test_mismatch_unknown_keys_values_types_context_and_missing_slots_refuse(self):
        bads=[{'field':'private-secret','kind':'VALUE'},{'field':'Memory','kind':'private-secret'},
            {'field':True,'kind':'VALUE'},{'field':'Memory','kind':False},
            {'field':'Memory','kind':'VALUE','actual':'private-secret'},['private-secret'],
            {'field':'Devices','kind':'MISSING'},{'field':'Memory','kind':'PRESENT'}]
        for bad in bads:
            row=self.diagnostic();row['operation']['first_failure']['resource_mismatch']=bad
            for project in (evidence.project,self.receiver().child_project):
                with self.subTest(bad=bad),self.assertRaises(ValueError):project(row)
        for slot in ('current','first_failure'):
            row=self.diagnostic();row['operation'][slot].pop('resource_mismatch')
            for project in (evidence.project,self.receiver().child_project):
                with self.assertRaises(ValueError):project(row)
        row=self.diagnostic();row['operation']['first_failure']['gate']='INSPECT_OWNERSHIP'
        for project in (evidence.project,self.receiver().child_project):
            with self.assertRaises(ValueError):project(row)

    def test_legacy_shapes_stay_exact_and_schema3_missing_cannot_be_downgraded_silently(self):
        modern=self.diagnostic();legacy=__import__('copy').deepcopy(modern);legacy['schema_version']=2
        for row in legacy['operation'].values():
            if row is not None:row.pop('resource_mismatch')
        self.assertEqual(evidence.project(legacy),self.receiver().child_project(legacy))
        legacy['operation']['current']['resource_mismatch']=None
        for project in (evidence.project,self.receiver().child_project):
            with self.assertRaises(ValueError):project(legacy)
        modern['schema_version']=2
        with self.assertRaises(ValueError):evidence.project(modern)


class InnerFailureProjectionTests(unittest.TestCase):
    receiver = ChildEvidenceTests.receiver
    def inner_group(self):
        import inner_result
        expected = {'nonce': 'd' * 32, 'action': 'baseline',
                    'contract_sha256': '3' * 64, 'worker_sha256': '4' * 64}
        row = inner_result.initial(expected)
        inner_result.phase(row, 'KERNEL'); inner_result.issued(row, 'KERNEL')
        inner_result.returned(row, 7); inner_result.failure(row, ValueError('private-secret'))
        raw = json.dumps({'status': 'FAIL', 'action': 'baseline', 'nonce': expected['nonce'],
                          'cancelled': False, 'inner_diagnostic': row}).encode()
        return inner_result.capture(raw, expected)

    def failed(self):
        trace = evidence.Trace(); trace.action('baseline')
        row = evidence.initial(binding(), trace)
        row['commands']['baseline'] = evidence.exit_record(1)
        evidence.failure(row, 'COMMAND_NONZERO', 'BASELINE_COMMAND')
        return row

    def test_failure_only_version4_matches_self_contained_receiver(self):
        row = self.failed(); first = copy.deepcopy(row['operation']['first_failure'])
        evidence.inner_failure(row, 'baseline', self.inner_group())
        projected = evidence.project(row)
        self.assertEqual(projected, self.receiver().child_project(row))
        self.assertEqual(row['schema_version'], 4)
        self.assertEqual(row['operation']['first_failure'], first)
        self.assertEqual(row['commands']['baseline'], evidence.exit_record(1))
        self.assertEqual(projected['inner']['baseline']['diagnostic']['natural_return'],
                         {'kind': 'RETURNED', 'code': 7})
        self.assertNotIn('private-secret', json.dumps(projected))
        self.assertNotIn('nonce', json.dumps(projected))
        self.assertLessEqual(len(evidence.encoded(row)), 4096)

    def test_failed_attachment_is_transactional_and_does_not_change_business(self):
        row = self.failed(); before = copy.deepcopy(row); group = self.inner_group()
        group['diagnostic']['phase'] = 'private-secret'
        with self.assertRaises(ValueError): evidence.inner_failure(row, 'baseline', group)
        self.assertEqual(row, before)
        row['commands']['baseline'] = evidence.exit_record(0)
        with self.assertRaises(ValueError): evidence.inner_failure(row, 'baseline', self.inner_group())

    def test_prebyte_refusal_or_missing_has_no_invented_diagnostic(self):
        for availability, reason in (('UNAVAILABLE', 'MISSING'), ('REFUSED', 'INVALID')):
            row = self.failed()
            group = {'availability': availability, 'reason': reason, 'raw_sha256': None, 'diagnostic': None}
            evidence.inner_failure(row, 'baseline', group)
            self.assertEqual(evidence.project(row), self.receiver().child_project(row))
            self.assertIsNone(row['inner']['baseline']['diagnostic'])

    def test_both_boundaries_refuse_inner_poison_and_legacy_downgrade(self):
        original = self.failed(); evidence.inner_failure(original, 'baseline', self.inner_group())
        poisons = [lambda x:x['inner']['baseline']['diagnostic'].update(extra='private'),
            lambda x:x['inner']['baseline']['diagnostic'].update(write_failed=True),
            lambda x:x['inner']['baseline']['diagnostic']['natural_return'].update(code=True),
            lambda x:x['inner']['baseline']['diagnostic'].update(attempt='NOT_ISSUED'),
            lambda x:x['inner']['baseline'].update(raw_sha256=None),
            lambda x:x['inner']['baseline'].update(reason='MISSING'),
            lambda x:x.update(schema_version=3), lambda x:x.pop('inner'),
            lambda x:x.update(current_predicate='COMPLETE'),
            lambda x:x['commands'].update(baseline=evidence.exit_record(0)),
            lambda x:x['inner'].update(candidate=copy.deepcopy(x['inner']['baseline'])),
            lambda x:x['inner']['baseline']['diagnostic']['first_failure'].update(error_kind='raw-error')]
        for mutate in poisons:
            row = copy.deepcopy(original); mutate(row)
            for project in (evidence.project, self.receiver().child_project):
                with self.subTest(poison=mutate, project=project), self.assertRaises((ValueError, KeyError)):
                    project(row)

    def test_helper_and_both_group_validators_agree_on_valid_and_poison(self):
        import inner_result
        groups = [self.inner_group(), {'availability': 'REFUSED', 'reason': 'INVALID', 'raw_sha256': None, 'diagnostic': None}]
        for group in groups:
            for validate in (inner_result.validate_group, evidence.validate_inner_group,
                             self.receiver().child_validate_inner_group):
                self.assertEqual(validate(copy.deepcopy(group)), group)
        for code in (True, 256, -65, '0'):
            group = self.inner_group(); group['diagnostic']['natural_return']['code'] = code
            for validate in (inner_result.validate_group, evidence.validate_inner_group,
                             self.receiver().child_validate_inner_group):
                with self.assertRaises(ValueError): validate(group)


if __name__ == '__main__': unittest.main()
