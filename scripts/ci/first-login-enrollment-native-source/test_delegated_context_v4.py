#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""MODEL-only inert API controls. No native build, Root signing or API calls."""
import copy
from datetime import datetime, timezone
import importlib.util
import os
from pathlib import Path
import resource
import sys
import tempfile
import unittest


def fence(event, args):
    if event.startswith(('subprocess.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn', 'os.system', 'socket.', 'ctypes.', 'fcntl.')):
        raise AssertionError('MODEL DATA fence: '+event)


sys.addaudithook(fence)
resource.setrlimit(resource.RLIMIT_AS, (128*1024**2, 128*1024**2))
HERE = Path(__file__).resolve().parent
PROGRAM = HERE/'payload/native/delegated_context_v4.py'
SPEC = importlib.util.spec_from_file_location('model_context_v4', PROGRAM)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
NOW = 1800000000

# Run the exact committed v3 suite, with exact v3 bytes, on ordinary MODEL files.
# The fixture is DATA, not a relaxed successor or a dependency on another checkout.
BASE = tempfile.TemporaryDirectory(prefix='MODEL-v3-predecessor-')
BASE_PATH = Path(BASE.name)
(BASE_PATH/'delegated_context_v3.py').write_bytes(M._PREDECESSOR)
V3_TEST_RAW = (HERE/'fixtures/delegated-context-v3-tests.py.data').read_bytes()
V3_TEST_PIN = M.pin(V3_TEST_RAW)
need_pin = dict(bytes=19670, sha256='3d69be396b96a9f50b2d727407ff30fbec105f474cf38415feb7cb380c0f2608')
M.need(V3_TEST_PIN == need_pin, 'exact original v3 regression suite DATA')
(BASE_PATH/'test_delegated_context_v3.py').write_bytes(V3_TEST_RAW)
spec = importlib.util.spec_from_file_location('model_original_v3_tests', BASE_PATH/'test_delegated_context_v3.py')
V3 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V3)

# The same portable baseline suite, finitely adapted for explicitly V4 identities.
# Full inverse means no predecessor assertion is silently dropped.
text = V3_TEST_RAW.decode()
edits = [('delegated_context_v3.py', 'delegated_context_v4.py'),
         ("schema=3", "schema=4"), ('DELEGATED_CURRENT_OWNER_V3', 'DELEGATED_CURRENT_OWNER_V4'),
         ('DELEGATED_CURRENT_ONBOARDING_PAIR_V3', 'DELEGATED_CURRENT_ONBOARDING_PAIR_V4'),
         ('DELEGATED_CURRENT_ONBOARDING_TEST_PROOF_V3', 'DELEGATED_CURRENT_ONBOARDING_TEST_PROOF_V4')]
adapted = text
for before, after in edits:
    M.need(before in adapted and after not in adapted, 'exact v4 baseline test seam')
    adapted = adapted.replace(before, after)
inverse = adapted
for before, after in reversed(edits):
    inverse = inverse.replace(after, before)
M.need(inverse == text, 'full baseline test inverse')
(BASE_PATH/'delegated_context_v4.py').write_bytes(PROGRAM.read_bytes())
scope = dict(__file__=str(BASE_PATH/'model_baseline.py'), __name__='model_v4_baseline')
exec(compile(adapted, scope['__file__'], 'exec'), scope)
Baseline = scope['ContextTests']


class SelectedComponentTests(Baseline):
    def setUp(self):
        super().setUp()
        # Baseline's global M is the same whole v4 file in the private MODEL
        # carrier; this module exercises the public API from the actual file.
        self.files['programs/context-v3.py'] = M._PREDECESSOR
        self.reseal()
        self.d['binding']['source_lock'] = M.pin(self.map_raw)

    def fixture(self, version=4, different_workspace=False, *, producer_stage='backend', consumer_stage='ui', component=None):
        producer = copy.deepcopy(self.d)
        producer['stage'] = producer['capability']['stage'] = producer_stage
        producer['hosted'].update(job_key=producer_stage, job_name='MODEL '+producer_stage+' producer')
        producer_env = dict(self.env, GITHUB_JOB=producer_stage)
        producer_jobs = copy.deepcopy(self.jobs)
        producer_jobs['jobs'][0]['name'] = producer['hosted']['job_name']
        producer_response = dict(self.response(), body=M.encoded(producer_jobs))
        if version == 3:
            producer['schema'] = 3
            producer['kind'] = V3.M.DELEGATION
            producer['programs']['context'] = dict(member='programs/context-v3.py', **M.pin(M._PREDECESSOR))
            core = V3.M
        else:
            core = M
        producer_raw = M.encoded(producer)
        if version == 3:
            # Exact program identity, still the real v3 implementation.
            spec = importlib.util.spec_from_file_location('model_source_v3', self.root/'programs/context-v3.py')
            core = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(core)
        pc = core.capture_context(producer_raw, M.pin(producer_raw)['sha256'], self.root,
                                  environ=producer_env, jobs_response=producer_response, now=NOW)
        if different_workspace:
            newroot = self.root.with_name('MODEL-consumer-source')
            self.root.rename(newroot)
            self.root = newroot
        consumer = copy.deepcopy(self.d)
        # The completed producer can be expired and its observation aged. It
        # never becomes a current execution grant. Decisions and consumer are fresh.
        issued = NOW+8000
        consumer.update(stage=consumer_stage, nonce='d'*64, issued_epoch=issued, expires_epoch=issued+1000)
        consumer['capability'].update(stage=consumer_stage, allow_pair_adoption=False, allow_selected_pair_adoption=True)
        consumer['hosted'].update(job_key=consumer_stage, job_name='MODEL '+consumer_stage+' fixture')
        component = dict(name='cachy-asahi-first-login', version='0.1.0-3', architecture='any') if component is None else component
        archives = [b'MODEL native archive bytes\n']*2
        signatures = [b'MODEL detached signature A\n', b'MODEL detached signature B\n']
        common = dict(schema=version, issuer='DELEGATED_CURRENT_OWNER_V'+str(version), binding=pc['binding'],
                      nonce=producer['nonce'], program_pin=M.descriptor(producer['programs']['owner']),
                      policy_pin=M.descriptor(producer['policy']), **M.FINAL)
        pair = dict(common, kind='DELEGATED_CURRENT_ONBOARDING_PAIR_V'+str(version), component=component,
                    package=component['name'], version=component['version'],
                    archives=list(map(M.pin, archives)), matching_pair=True)
        pair_raw = M.encoded(pair)
        jobs = copy.deepcopy(producer_jobs)
        iso = lambda n: datetime.fromtimestamp(n, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        jobs['jobs'][0].update(status='completed', conclusion='success', started_at=iso(NOW-1), completed_at=iso(NOW+20))
        completion = dict(schema=1, kind='CURRENT_ONBOARDING_COMPLETED_PRODUCER_V4', producer_binding=pc['binding'],
                          producer_delegation_pin=M.pin(producer_raw), producer_context_pin=M.pin(M.encoded(pc)),
                          observed_epoch=NOW+30, jobs_response=dict(self.response(), body=M.encoded(jobs).decode(), received_epoch=NOW+30))
        completion_raw = M.encoded(completion)
        s = dict(schema=1, kind=M.SELECTION, producer_binding=pc['binding'], component=component,
                 producer_delegation_pin=M.pin(producer_raw), producer_context_pin=M.pin(M.encoded(pc)),
                 completion_pin=M.pin(completion_raw), pair_pin=M.pin(pair_raw), archives=list(map(M.pin, archives)),
                 signatures=list(map(M.pin, signatures)), public_test_key_pin=M.pin(self.files['inputs/public-test.asc']),
                 test_fingerprint='E'*40, max_producer_age_seconds=86400)
        dc = {k: s[k] for k in ('producer_binding', 'producer_delegation_pin', 'producer_context_pin',
                               'completion_pin', 'component', 'pair_pin', 'archives')}
        component_decision = dict(schema=4, kind=M.COMPONENT_DECISION, issuer='Root', approved=True, operation=M.OPERATION,
                                 scope='CURRENT_PRIVATE_COMPONENT_ONLY', issued_epoch=issued-5, expires_epoch=issued+1000,
                                 Root_final_acceptance=None, hardware_acceptance=False, release_acceptance=False, **dc)
        test_decision = dict(component_decision, kind=M.TEST_DECISION, signatures=s['signatures'],
                             public_test_key_pin=s['public_test_key_pin'], test_fingerprint=s['test_fingerprint'], trust_scope='TEST_ONLY')
        root_component_raw, root_test_raw = M.encoded(component_decision), M.encoded(test_decision)
        s.update(root_component_decision_pin=M.pin(root_component_raw), root_test_decision_pin=M.pin(root_test_raw))
        consumer['pair_selection'] = s
        env = dict(self.env, GITHUB_RUN_ID='23456', GITHUB_JOB=consumer_stage, GITHUB_WORKSPACE=str(self.root))
        jobs = copy.deepcopy(self.jobs)
        jobs['jobs'][0].update(id=78901, run_id=23456, name=consumer['hosted']['job_name'],
             run_url='https://api.github.com/repos/example/inert/actions/runs/23456',
             url='https://api.github.com/repos/example/inert/actions/jobs/78901',
             html_url='https://github.com/example/inert/actions/runs/23456/job/78901')
        response = dict(self.response(), url='https://api.github.com/repos/example/inert/actions/runs/23456/jobs?filter=latest&per_page=100',
                        body=M.encoded(jobs), received_epoch=issued)
        context = self.capture(consumer, env=env, response=response, now=issued)
        args = dict(producer_delegation_raw=producer_raw, producer_context=pc, completion_raw=completion_raw, pair_raw=pair_raw,
                    root_component_raw=root_component_raw, root_test_raw=root_test_raw, archive_bodies=archives,
                    signature_bodies=signatures, public_test_key_raw=self.files['inputs/public-test.asc'], now=issued)
        return consumer, context, args

    def adopt(self, d, c, args):
        return M.adopt_selected_pair(d, c, **args)

    def reobserve(self, d, c):
        response = dict(c['jobs_response'], body=c['jobs_response']['body'].encode())
        return M.capture_context(M.encoded(d), M.pin(M.encoded(d))['sha256'], self.root,
             environ=c['hosted'], jobs_response=response, now=c['observed_epoch'])

    def test_selected_completed_producer_v3_and_v4_are_distinct_historical_runs(self):
        for version in (3, 4):
            with self.subTest(version=version):
                d, c, args = self.fixture(version)
                result = self.adopt(d, c, args)
                self.assertEqual(result['binding']['run'], '23456')
                self.assertEqual(result['producer_binding']['run'], '12345')
                self.assertEqual({k: result[k] for k in M.FINAL}, M.FINAL)
                self.assertTrue(result['current_stage_gpg_required'])
                self.assertEqual(result['issuer'], M.ISSUER)
                self.assertIsNone(d['binding']['run'])
                self.assertIsNone(d['binding']['job'])
                self.assertEqual(args['producer_context']['observed_epoch'], NOW)
                self.assertEqual(result['root_test_decision_pin'], M.pin(args['root_test_raw']))

    def test_historical_workspace_need_not_exist_and_remains_unmodified(self):
        d, c, args = self.fixture(3, different_workspace=True)
        oldpath = args['producer_context']['source_root']
        self.assertFalse(Path(oldpath).exists())
        self.adopt(d, c, args)
        self.assertEqual(args['producer_context']['source_root'], oldpath)
        self.assertNotEqual(c['source_root'], oldpath)

    def test_multiple_explicit_component_roles_require_an_unambiguous_selection(self):
        d, c, args = self.fixture()
        selected = d.pop('pair_selection')
        d['pair_selections'] = dict(enrollment=selected, first_login=copy.deepcopy(selected))
        c = self.reobserve(d, c)
        self.refuses(lambda: self.adopt(d, c, args))
        result = self.adopt(d, c, dict(args, selection_role='enrollment'))
        self.assertEqual(result['component'], selected['component'])
        self.refuses(lambda: self.adopt(d, c, dict(args, selection_role='unselected')))
        d['pair_selection'] = selected
        self.refuses(lambda: self.reobserve(d, c))

    def test_completed_ui_producer_to_lifecycle_keeps_original_v3_or_v4_identity(self):
        ui = dict(name='cachy-asahi-first-login-ui', version='0.2.0-2', architecture='any')
        for version in (3, 4):
            with self.subTest(version=version):
                d, c, args = self.fixture(version, producer_stage='ui', consumer_stage='lifecycle', component=ui)
                pc = copy.deepcopy(args['producer_context'])
                root_bytes = (args['root_component_raw'], args['root_test_raw'])
                result = self.adopt(d, c, args)
                self.assertEqual(pc['stage'], 'ui')
                self.assertEqual(pc['hosted']['GITHUB_JOB'], 'ui')
                self.assertEqual(pc['schema'], version)
                self.assertEqual(pc['issuer'], 'DELEGATED_CONTEXT_PROGRAM_V'+str(version))
                self.assertEqual(c['stage'], 'lifecycle')
                self.assertEqual(result['component'], ui)
                self.assertEqual(result['producer_binding'], pc['binding'])
                self.assertNotEqual(result['binding']['run'], pc['binding']['run'])
                self.assertEqual(args['producer_context'], pc)
                self.assertEqual(root_bytes, (args['root_component_raw'], args['root_test_raw']))
                self.assertLess(M.decode(args['producer_delegation_raw'])['expires_epoch'], args['now'])
                self.assertEqual({k: result[k] for k in M.FINAL}, M.FINAL)
                self.assertIs(result['current_stage_gpg_required'], True)
        enrollment = dict(name='cachy-asahi-repository-enrollment', version='0.4.0-1', architecture='any')
        d, c, args = self.fixture(consumer_stage='lifecycle', component=enrollment)
        self.assertEqual(self.adopt(d, c, args)['component'], enrollment)

    def test_only_exact_current_component_to_producer_stage_mapping_is_allowed(self):
        enrollment = dict(name='cachy-asahi-repository-enrollment', version='0.4.0-1', architecture='any')
        cli = dict(name='cachy-asahi-first-login', version='0.1.0-3', architecture='any')
        ui = dict(name='cachy-asahi-first-login-ui', version='0.2.0-2', architecture='any')
        self.assertEqual(M.COMPONENT_PRODUCER_STAGES, {
            (enrollment['name'], enrollment['version'], 'any'): 'backend',
            (cli['name'], cli['version'], 'any'): 'backend', (ui['name'], ui['version'], 'any'): 'ui'})
        for component, producer_stage in ((enrollment, 'ui'), (cli, 'ui'), (ui, 'backend'), (ui, 'lifecycle')):
            with self.subTest(component=component, stage=producer_stage):
                d, c, args = self.fixture(producer_stage=producer_stage, consumer_stage='lifecycle', component=component)
                self.refuses(lambda: self.adopt(d, c, args))
        for component in (dict(name='cachy-asahi-setup', version='0.3.0-1', architecture='any'),
                          dict(ui, version='0.2.0-1'), dict(ui, architecture='aarch64'),
                          dict(ui, name='MODEL-arbitrary-package')):
            self.refuses(lambda: self.fixture(producer_stage='ui', consumer_stage='lifecycle', component=component))
        self.refuses(lambda: self.fixture(producer_stage='ui', consumer_stage='ui', component=ui))

    def test_ui_root_selection_and_separate_decisions_cannot_select_another_component_or_tuple(self):
        ui = dict(name='cachy-asahi-first-login-ui', version='0.2.0-2', architecture='any')
        d, c, args = self.fixture(producer_stage='ui', consumer_stage='lifecycle', component=ui)
        d['pair_selection']['component'] = dict(name='cachy-asahi-first-login', version='0.1.0-3', architecture='any')
        self.refuses(lambda: self.adopt(d, self.reobserve(d, c), args))
        for key, change in (('root_component_raw', 'component'), ('root_component_raw', 'job'),
                            ('root_component_raw', 'pair'), ('root_test_raw', 'fingerprint'),
                            ('root_test_raw', 'expiry'), ('root_test_raw', 'approval')):
            with self.subTest(key=key, change=change):
                d, c, args = self.fixture(producer_stage='ui', consumer_stage='lifecycle', component=ui)
                value = M.decode(args[key])
                if change == 'component': value['component'] = dict(ui, version='0.2.0-1')
                if change == 'job': value['producer_binding']['job'] = '99999'
                if change == 'pair': value['pair_pin'] = M.pin(b'MODEL other pair')
                if change == 'fingerprint': value['test_fingerprint'] = 'F'*40
                if change == 'expiry': value['expires_epoch'] = args['now']-1
                if change == 'approval': value['approved'] = False
                args[key] = M.encoded(value)
                pin_key = 'root_component_decision_pin' if key == 'root_component_raw' else 'root_test_decision_pin'
                d['pair_selection'][pin_key] = M.pin(args[key])
                self.refuses(lambda: self.adopt(d, self.reobserve(d, c), args))
        d, c, args = self.fixture(producer_stage='ui', consumer_stage='lifecycle', component=ui)
        del args['root_component_raw']
        self.refuses(lambda: self.adopt(d, c, args))

    def test_ui_actual_owner_pair_fields_completed_job_and_source_joins_remain_strict(self):
        ui = dict(name='cachy-asahi-first-login-ui', version='0.2.0-2', architecture='any')
        for key, wrong in (('package', 'cachy-asahi-first-login'), ('version', '0.2.0-1'),
                           ('program_pin', M.pin(b'MODEL wrong owner')), ('policy_pin', M.pin(b'MODEL wrong policy')),
                           ('issuer', 'Root'), ('schema', 3)):
            with self.subTest(pair_field=key):
                d, c, args = self.fixture(producer_stage='ui', consumer_stage='lifecycle', component=ui)
                pair = M.decode(args['pair_raw'])
                pair[key] = wrong
                args['pair_raw'] = M.encoded(pair)
                selected = d['pair_selection']
                selected['pair_pin'] = M.pin(args['pair_raw'])
                # Independently modeled Root re-selection of whole bytes still
                # cannot authorize contradictory observed owner identity fields.
                for raw_key, pin_key in (('root_component_raw', 'root_component_decision_pin'), ('root_test_raw', 'root_test_decision_pin')):
                    decision = M.decode(args[raw_key])
                    decision['pair_pin'] = selected['pair_pin']
                    args[raw_key] = M.encoded(decision)
                    selected[pin_key] = M.pin(args[raw_key])
                self.refuses(lambda: self.adopt(d, self.reobserve(d, c), args))
        for key, wrong in (('status', 'in_progress'), ('conclusion', 'failure'), ('run_attempt', 2),
                           ('name', 'MODEL backend producer')):
            d, c, args = self.fixture(producer_stage='ui', consumer_stage='lifecycle', component=ui)
            completion = M.decode(args['completion_raw'])
            jobs = M.decode(completion['jobs_response']['body'].encode())
            jobs['jobs'][0][key] = wrong
            completion['jobs_response']['body'] = M.encoded(jobs).decode()
            args['completion_raw'] = M.encoded(completion)
            d['pair_selection']['completion_pin'] = M.pin(args['completion_raw'])
            self.refuses(lambda: self.adopt(d, self.reobserve(d, c), args))
        for key, wrong in (('source', 'f'*40), ('ref', 'refs/heads/MODEL-wrong')):
            d, c, args = self.fixture(producer_stage='ui', consumer_stage='lifecycle', component=ui)
            args['producer_context']['binding'][key] = wrong
            self.refuses(lambda: self.adopt(d, c, args))

    def test_all_actual_bodies_and_whole_external_pins_required(self):
        for key in ('producer_delegation_raw', 'completion_raw', 'pair_raw', 'root_component_raw', 'root_test_raw', 'public_test_key_raw'):
            d, c, args = self.fixture()
            args[key] += b'changed'
            self.refuses(lambda: self.adopt(d, c, args))
        for key in ('archive_bodies', 'signature_bodies'):
            for bodies in ([], [b'MODEL'], [b'MODEL', b'OTHER'], [None, None]):
                d, c, args = self.fixture()
                args[key] = bodies
                self.refuses(lambda: self.adopt(d, c, args))
        d, c, args = self.fixture()
        args['producer_context']['Root_final_acceptance'] = True
        self.refuses(lambda: self.adopt(d, c, args))

    def test_selected_tuple_and_component_cannot_be_changed_even_in_new_authorized_grant(self):
        for key, bad in [('run', '77777'), ('job', '77777'), ('attempt', 2), ('source', 'f'*40),
                         ('ref', 'refs/heads/wrong'), ('source_lock', M.pin(b'other map'))]:
            d, c, args = self.fixture()
            d['pair_selection']['producer_binding'] = dict(d['pair_selection']['producer_binding'], **{key: bad})
            self.refuses(lambda: self.adopt(d, self.reobserve(d, c), args))
        for key in ('name', 'version', 'architecture'):
            d, c, args = self.fixture()
            d['pair_selection']['component'][key] = 'other'
            self.refuses(lambda: self.adopt(d, self.reobserve(d, c), args))

    def test_missing_or_ambiguous_selection_and_future_producer_ids_refuse(self):
        for change in ('selection', 'capability', 'same_run_flag', 'run', 'job', 'unknown_field'):
            d, c, args = self.fixture()
            if change == 'selection': del d['pair_selection']
            if change == 'capability': d['capability']['allow_selected_pair_adoption'] = False
            if change == 'same_run_flag': d['capability']['allow_pair_adoption'] = True
            if change in ('run', 'job'): d['pair_selection']['producer_binding'][change] = None
            if change == 'unknown_field': d['pair_selection']['anything'] = 'unreviewed'
            self.refuses(lambda: self.adopt(d, self.reobserve(d, c), args))

    def test_rejoined_but_invalid_completion_decision_pair_and_context_refuse(self):
        changes = [('completion_raw', 'not_completed'), ('completion_raw', 'wrong_job'), ('completion_raw', 'too_late'),
                   ('completion_raw', 'bad_timestamp'), ('completion_raw', 'wrong_url'), ('completion_raw', 'incomplete'),
                   ('root_component_raw', 'no_root'), ('root_component_raw', 'wrong_pair'), ('root_component_raw', 'no_approval'),
                   ('root_test_raw', 'expired'), ('root_test_raw', 'wrong_signature'), ('root_test_raw', 'wrong_key'),
                   ('root_test_raw', 'production'), ('root_test_raw', 'future_issue'), ('root_test_raw', 'final_acceptance'),
                   ('pair_raw', 'no_match'), ('pair_raw', 'forged_root'), ('pair_raw', 'wrong_owner'), ('pair_raw', 'wrong_policy')]
        pin_names = dict(completion_raw='completion_pin', root_component_raw='root_component_decision_pin',
                         root_test_raw='root_test_decision_pin', pair_raw='pair_pin')
        for key, change in changes:
            with self.subTest(change=change):
                d, c, args = self.fixture()
                value = M.decode(args[key])
                if change in ('not_completed', 'wrong_job', 'bad_timestamp', 'wrong_url', 'incomplete'):
                    jobs = M.decode(value['jobs_response']['body'].encode())
                    if change == 'not_completed': jobs['jobs'][0]['status'] = 'in_progress'
                    if change == 'wrong_job': jobs['jobs'][0]['id'] = 99999
                    if change == 'bad_timestamp': jobs['jobs'][0]['completed_at'] = 'future'
                    if change == 'wrong_url': jobs['jobs'][0]['run_url'] = 'https://other.invalid'
                    if change == 'incomplete': jobs['total_count'] = 2
                    value['jobs_response']['body'] = M.encoded(jobs).decode()
                if change == 'too_late': value['observed_epoch'] = args['now']+1
                if change == 'no_root': value['issuer'] = 'MODEL-peer'
                if change == 'wrong_pair': value['pair_pin'] = M.pin(b'wrong pair')
                if change == 'no_approval': value['approved'] = False
                if change == 'expired': value['expires_epoch'] = args['now']-1
                if change == 'future_issue': value['issued_epoch'] = args['now']+1
                if change == 'wrong_signature': value['signatures'][0] = M.pin(b'wrong signature')
                if change == 'wrong_key': value['test_fingerprint'] = 'F'*40
                if change == 'production': value['trust_scope'] = 'PRODUCTION'
                if change == 'final_acceptance': value['Root_final_acceptance'] = True
                if change == 'no_match': value['matching_pair'] = False
                if change == 'forged_root': value['issuer'] = 'Root'
                if change == 'wrong_owner': value['program_pin'] = M.pin(b'wrong owner')
                if change == 'wrong_policy': value['policy_pin'] = M.pin(b'wrong policy')
                args[key] = M.encoded(value)
                d['pair_selection'][pin_names[key]] = M.pin(args[key])
                self.refuses(lambda: self.adopt(d, self.reobserve(d, c), args))

    def test_age_limits_and_same_run_entry_do_not_accept_cross_run_capability(self):
        d, c, args = self.fixture()
        d['pair_selection']['max_producer_age_seconds'] = 1
        self.refuses(lambda: self.adopt(d, self.reobserve(d, c), args))
        d, c, args = self.fixture()
        self.refuses(lambda: M.adopt_pair(d, c, producer_delegation_raw=args['producer_delegation_raw'],
             producer_context=args['producer_context'], pair_raw=args['pair_raw'], test_raw=args['root_test_raw'], now=args['now']))

    def test_whole_predecessor_inverse_and_source_program_mutation_refuse(self):
        self.assertEqual(M.pin(M._PREDECESSOR), M.PREDECESSOR_PIN)
        d, c, args = self.fixture(3)
        path = self.root/'programs/context-v3.py'
        path.write_bytes(path.read_bytes()+b'# changed\n')
        self.refuses(lambda: self.adopt(d, c, args))


def load_tests(loader, tests, pattern):
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(V3.ContextTests))
    suite.addTests(loader.loadTestsFromTestCase(SelectedComponentTests))
    return suite


if __name__ == '__main__':
    try:
        unittest.main()
    finally:
        BASE.cleanup()
