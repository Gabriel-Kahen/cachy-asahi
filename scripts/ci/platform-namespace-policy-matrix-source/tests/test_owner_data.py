# SPDX-License-Identifier: MIT
"""Twelve new bounded DATA controls of the exact sealed owner/export code.

All actor, Git, daemon and capsule transport observations are synthetic. The
proposed complete Source exists only in the fixture's RAM storage port.
"""
import argparse
import copy
import os
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fake_owner as ports

COMPLETE = 'DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_COMPLETE'
UNKNOWN = 'DIAGNOSTIC_NAMESPACE_POLICY_MATRIX_UNKNOWN'
RUNNER_TEMP = None
OBSERVATIONS = []


def save(path, value):
    path.write_bytes(ports.encoded(value))
    path.chmod(0o600)


def raw_payloads(f):
    return {str(p.relative_to(f.work/'public')):p.read_bytes()
            for p in (f.work/'public').rglob('*') if p.is_file()}


def expected(f):
    return dict(binding=copy.deepcopy(f.own), source_parent='05df8c71ea2bcb525bb1cfbc59983452062a1e97',
        source_map_sha256=ports.MAP, body_sha256=ports.MODULE_SHA,
        contract_sha256=f.metadata['native/platform-namespace-policy-v1.json']['sha256'],
        image=f.image, engine_id='SYNTHETIC_DATA_ENGINE')


def source_proof(f):
    return ports.load(f.work/'public/namespace-policy/source-proof.json')


def outer_data(f, unknown=False):
    """Two invented final absence returnrows; never invoke the original actor."""
    directory = f.work/'retirement-actors'
    directory.mkdir(mode=0o700)
    actors = []
    absence = {}
    for kind, suffix in [('containers',['ps','-aq','--no-trunc']),
                         ('images',['image','ls','--no-trunc','-q'])]:
        path = directory/(kind+'.log')
        path.write_bytes(b''); path.chmod(0o600)
        row = dict(argv=f.module.DOCKER+suffix+['--filter','label='+f.legacy+'='+f.own['token']],
                   log=str(path), log_pin=f.module.pin(b''), status='PASS', exit=0,
                   natural_exit=True, group_absent=True, exit_observed_via_waitpid=True,
                   leader_held_until_group_inspection=True, retirement='REAPED',
                   ownership_lost=False, forced_cleanup=False)
        actors.append(row); absence[kind] = dict(actor=row, output='')
    if unknown:
        actors[0]['ownership_lost'] = True
    cleanup = dict(status='PASS_EXACT_OWNED_RESOURCES_RETIRED', actors=actors,
        daemon_absence=absence, image_retirement=dict(status='PASS_EXACT_OWNED_IMAGE_ALIASES_RETIRED',
        binding=f.own, source_map_sha256=ports.MAP))
    receipt = dict(binding=f.own, source_map_sha256=ports.MAP, operation=f.module.OPERATION,
        status=COMPLETE, native='NOT_ADMITTED', acceptance=False, namespace_policy=f.diagnostic)
    save(f.work/'public/cleanup.json', cleanup)
    save(f.work/'public/receipt.json', receipt)


def project(f, unknown=False):
    outer_data(f, unknown)
    projection = f.provision.project_matrix(f.root, f.work, f.own, ports.MAP)
    directory = f.work/'matrix-projection'
    payloads = {str(p.relative_to(directory)):p.read_bytes()
                for p in directory.rglob('*') if p.is_file()}
    return projection, payloads


def read(f, payloads, authority=None):
    selectors = {k:f.own[k] for k in ('source','ref','run')}
    selectors['map_sha256'] = ports.MAP
    with f.capsule_view(payloads):
        return f.provision.read_matrix_capsule('SYNTHETIC-TRANSPORT-NO-REAL-CAPSULE',
            selectors, expected(f) if authority is None else authority)


def repin(f, payloads, name, value):
    """Let forged DATA honestly repin itself; inner semantic joins must refuse."""
    result = dict(payloads); result[name] = ports.encoded(value)
    projection = json.loads(result['matrix-projection.json'])
    projection['selected'][name].update(f.module.pin(result[name]))
    result['matrix-projection.json'] = ports.encoded(projection)
    manifest = json.loads(result['artifacts.json'])
    for leaf in (name,'matrix-projection.json'):
        manifest['files'][leaf].update(f.module.pin(result[leaf]))
    result['artifacts.json'] = ports.encoded(manifest)
    return result


class OwnerData(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='policy-owner-NEW-DATA-', dir=RUNNER_TEMP)
        cls.serial = 0

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def fixture(self, fault=None):
        type(self).serial += 1
        return ports.Fixture(Path(self.directory.name)/str(self.serial), fault)

    def observe(self, f, extra=None):
        OBSERVATIONS.append(dict(test=self._testMethodName, fault=f.fault,
            synthetic_actor_calls=len(f.calls), diagnostic=f.diagnostic['status'],
            first_failure=f.diagnostic['first_failure'], cleanup=f.diagnostic['cleanup'],
            actual_actor_calls=0, Source_constructor_calls=0, **(extra or {})))

    def assert_unknown(self, f):
        self.assertEqual(f.diagnostic['status'], UNKNOWN)
        self.assertEqual(f.diagnostic['interpretation']['status'], 'UNKNOWN')
        self.assertFalse(f.diagnostic['acceptance'])
        self.assertEqual(f.diagnostic['native'], 'NOT_ADMITTED')

    def test_01_four_cases_prefix_registry_runtime_inverse(self):
        f = self.fixture()
        with f.ports():
            f.run()
            self.assertEqual(f.diagnostic['status'], COMPLETE)
            self.assertEqual(f.callback_calls, 2)
            self.assertEqual([r['id'] for r in f.result['cases']], list(f.module.CASES))
            self.assertEqual([r['returncode'] for r in f.result['cases']], [1,0,1,0])
            self.assertEqual(len({r['container'] for r in f.result['cases']}), 4)
            self.assertFalse(f.containers); self.assertFalse(f.image_exists)
            self.assertTrue(f.owner['prepared_ledger']['created'])
            self.assertTrue(f.owner['prepared_ledger']['retired'])
            self.assertEqual(set(f.ledger['created']), {'base'})
            build = next(c for c in f.calls if c['argv'][2:3] == ['build'])
            self.assertEqual(build['stdout_limit'], 16*1024**2)
            self.assertLessEqual(build['timeout'], 600)
            self.assertIn('namespace-policy-prepared', build['argv'])
            for c in f.calls:
                if c['argv'][2:4] == ['start','-a']:
                    self.assertEqual(c['stdout_limit'], 65536)
                    self.assertLessEqual(c['timeout'], 30)
                if c['argv'][2:3] == ['rm']:
                    self.assertEqual(len(c['argv']), 4)
                self.assertNotIn('--force', c['argv'])
            qualified = f.module.validate_runtime_evidence(f.owner, f.result, raw_payloads(f),
                expected(f), source_proof(f))
            self.assertTrue(qualified)
            self.observe(f, dict(runtime_qualification=qualified))

    def test_02_immutable_image_identity_required_before_registration(self):
        for fault in ('foreign_image', 'alias_rebound'):
            with self.subTest(fault=fault):
                f = self.fixture(fault)
                with f.ports():
                    original = f.respond
                    def response(argv):
                        body, rc = original(argv)
                        if fault == 'alias_rebound' and argv[2:4] == ['image','ls'] and f.image_exists:
                            body = ('sha256:'+'c'*64+'\n').encode()
                        return body, rc
                    with patch.object(f,'respond',response): f.run()
                    self.assert_unknown(f)
                    self.assertFalse(f.owner['prepared_ledger']['created'])
                    self.assertFalse(any(c['argv'][2:3] == ['create'] for c in f.calls))
                    self.assertFalse(any(c['argv'][2:4] == ['image','rm'] for c in f.calls))
                    self.assertTrue(f.image_exists)
                    self.observe(f)

    def test_03_foreign_prepared_labels_never_registered_or_removed(self):
        f = self.fixture('foreign_labels')
        with f.ports():
            f.run(); self.assert_unknown(f)
            self.assertFalse(f.owner['prepared_ledger']['created'])
            self.assertFalse(any(c['argv'][2:3] in (['create'],['rm']) or
                c['argv'][2:4] == ['image','rm'] for c in f.calls))
            self.observe(f)

    def test_04_foreign_cid_labels_refused_without_removal(self):
        f = self.fixture()
        with f.ports():
            original = f.respond
            def response(argv):
                body, rc = original(argv)
                if argv[2:3] == ['inspect']:
                    value = json.loads(body)
                    value[0]['Config']['Labels'][f.module.LABEL+'.source'] = 'f'*40
                    body = ports.encoded(value)
                return body, rc
            with patch.object(f, 'respond', response): f.run()
            self.assert_unknown(f)
            self.assertEqual(len(f.containers), 1)
            self.assertFalse(any(c['argv'][2:3] in (['rm'],['start']) for c in f.calls))
            self.assertFalse(any(c['argv'][2:4] == ['image','rm'] for c in f.calls))
            self.observe(f)

    def test_05_running_container_not_stopped_killed_or_removed(self):
        f = self.fixture('running_retire')
        with f.ports():
            f.run(); self.assert_unknown(f)
            self.assertEqual(len(f.containers), 1)
            self.assertEqual(len(f.owner['retirement_intents']), 1)
            self.assertFalse(any(c['argv'][2:3] in (['rm'],['stop'],['kill']) for c in f.calls))
            self.assertEqual(f.diagnostic['cleanup']['status'], 'UNKNOWN')
            self.observe(f)

    def test_06_uncertain_child_ownership_blocks_prepared_registration(self):
        f = self.fixture('unknown_lifecycle')
        with f.ports():
            f.run(); self.assert_unknown(f)
            self.assertFalse(f.owner['prepared_ledger']['created'])
            self.assertFalse(any(c['argv'][2:3] == ['create'] for c in f.calls))
            self.assertFalse(any(c['argv'][2:4] == ['image','rm'] for c in f.calls))
            self.observe(f)

    def test_07_uncertain_removal_never_retried_preserves_first_failure(self):
        f = self.fixture('removal_error')
        with f.ports():
            f.run(); self.assert_unknown(f)
            removes = [c for c in f.calls if c['argv'][2:3] == ['rm']]
            self.assertEqual(len(removes), 1)
            self.assertEqual(len(f.owner['retirement_intents']), 1)
            self.assertEqual(f.diagnostic['first_failure']['phase'], 'remove-baseline')
            self.assertIn('no retry', json.dumps(f.diagnostic['cleanup']))
            self.observe(f)

    def test_08_context_and_policy_forgery_remain_unknown(self):
        for fault in ('context_mismatch', 'policy_mismatch'):
            with self.subTest(fault=fault):
                f = self.fixture(fault)
                with f.ports():
                    f.run(); self.assert_unknown(f)
                    self.assertIsNotNone(f.diagnostic['first_failure'])
                    self.observe(f)

    def test_09_full_source_parent_mode_body_and_contract_authority(self):
        f = self.fixture()
        with f.ports():
            f.run(); proof = source_proof(f); authority = expected(f)
            good = f.module.validate_source_proof(proof, f.root, authority)
            self.assertEqual(good['files'], 201)
            self.assertEqual(good['current_tree'], '6225879650afde24a93fd33905819e779384c550')
            alterations = []
            value = copy.deepcopy(proof); value['parent_files']['native/common.py']['blob'] = '0'*40
            alterations.append(('parent',value,authority))
            value = copy.deepcopy(proof); value['files']['native/common.py']['mode'] = '100755'
            alterations.append(('mode',value,authority))
            value = copy.deepcopy(proof); value['files'][f.module.MODULE]['sha256'] = '0'*64
            alterations.append(('body',value,authority))
            value = copy.deepcopy(authority); value['contract_sha256'] = '0'*64
            alterations.append(('contract',proof,value))
            for kind, value, auth in alterations:
                with self.subTest(forgery=kind), self.assertRaises(ValueError):
                    f.module.validate_source_proof(value, f.root, auth)
            self.observe(f, dict(source_qualification=good, refused_forgeries=[r[0] for r in alterations]))

    def test_10_export_reader_complete_and_inner_semantic_forgery(self):
        f = self.fixture()
        with f.ports():
            f.run(); projection, payloads = project(f)
            self.assertEqual(projection['diagnostic_status'], COMPLETE)
            result = read(f, payloads)
            self.assertEqual(result['projection_status'], COMPLETE)
            self.assertFalse(result['acceptance'])
            self.assertEqual(result['source_qualification']['files'], 201)
            self.assertTrue(result['runtime_qualification'])
            # Forged raw prepared-image observation with all outer body pins
            # recomputed still fails the exact producer/runtime inverse.
            call = next(c for c in f.owner['calls'] if c['role'] == 'prepared-image-inspect')
            name = 'namespace-policy/'+call['public_log']
            value = json.loads(payloads[name]); value[0]['Config']['Labels'][f.module.LABEL] = 'FOREIGN_DATA'
            forged = repin(f,payloads,name,value)
            owner = copy.deepcopy(f.owner)
            entry = next(c for c in owner['calls'] if c['role'] == 'prepared-image-inspect')
            entry['log_pin'] = entry['actor']['log_pin'] = f.module.pin(forged[name])
            forged = repin(f,forged,'namespace-policy/owner.json',owner)
            with self.assertRaisesRegex(ValueError, 'actual immutable prefix image/body/labels/environment'):
                f.module.validate_runtime_evidence(owner,f.result,forged,expected(f),source_proof(f))
            refused = read(f,forged)
            self.assertEqual(refused['projection_status'], UNKNOWN)
            self.assertEqual(refused['interpretation']['status'], 'UNKNOWN')
            # A self-consistent projection cannot claim another local producer.
            forged = dict(payloads); value = json.loads(forged['matrix-projection.json'])
            value['source_producers']['native/provision.py']['sha256'] = '0'*64
            forged['matrix-projection.json'] = ports.encoded(value)
            manifest = json.loads(forged['artifacts.json'])
            manifest['files']['matrix-projection.json'].update(f.module.pin(forged['matrix-projection.json']))
            forged['artifacts.json'] = ports.encoded(manifest)
            with self.assertRaises(ValueError): read(f,forged)
            self.observe(f,dict(export_reader=result['status'],
                synthetic_interpretation=result['interpretation'], semantic_refusals=refused['join_refusals']))

    def test_11_outer_ownership_unknown_preserves_raw_data_no_effect(self):
        f = self.fixture()
        with f.ports():
            f.run(); projection, payloads = project(f, unknown=True)
            self.assertEqual(projection['diagnostic_status'], UNKNOWN)
            result = read(f,payloads)
            self.assertEqual(result['projection_status'], UNKNOWN)
            self.assertEqual(result['raw_result'], f.result)
            self.assertEqual(result['interpretation']['status'], 'UNKNOWN')
            self.assertFalse(result['acceptance'])
            # Independent Root contract authority is required before transport.
            auth = expected(f); auth['contract_sha256'] = '0'*64
            with self.assertRaises(ValueError): read(f,payloads,auth)
            self.observe(f,dict(export_join_refusals=result['join_refusals']))

    def test_12_incomplete_attach_output_fails_closed_and_retires(self):
        f = self.fixture()
        with f.ports():
            original = f.respond
            def response(argv):
                body, rc = original(argv)
                if argv[2:4] == ['start','-a']:
                    body = body[:100]
                return body, rc
            with patch.object(f,'respond',response): f.run()
            self.assert_unknown(f)
            self.assertEqual(f.diagnostic['cleanup']['status'], 'PASS_EXACT_MATRIX_OWNED_RESOURCES_RETIRED')
            self.assertFalse(f.containers); self.assertFalse(f.image_exists)
            self.assertEqual(f.diagnostic['first_failure']['phase'], 'matrix')
            self.observe(f)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--basis', type=Path, required=True, help='Existing exact actual05df Source199 root, not older genuine191')
    parser.add_argument('--result', type=Path, required=True, help='Fresh absolute result file under existing writable RUNNER_TEMP')
    args = parser.parse_args()
    RUNNER_TEMP = Path(os.environ['RUNNER_TEMP'])
    assert RUNNER_TEMP.is_absolute() and RUNNER_TEMP.resolve(strict=True) == RUNNER_TEMP and RUNNER_TEMP.is_dir()
    assert RUNNER_TEMP.stat().st_uid == os.geteuid() and os.access(RUNNER_TEMP, os.W_OK)
    assert not RUNNER_TEMP.stat().st_mode & 0o022
    checkout = Path(__file__).resolve().parents[4]
    assert not RUNNER_TEMP.is_relative_to(checkout) and not checkout.is_relative_to(RUNNER_TEMP)
    assert args.result.is_absolute() and args.result.is_relative_to(RUNNER_TEMP) and not os.path.lexists(args.result)
    assert args.result.parent.resolve(strict=True) == args.result.parent and args.result.parent.is_dir()
    assert args.result.parent.stat().st_uid == os.geteuid() and not args.result.parent.stat().st_mode & 0o022
    assert not RUNNER_TEMP.is_relative_to(args.basis) and not args.result.is_relative_to(args.basis)
    # Basis may live elsewhere under RUNNER_TEMP; fixture work is a fresh sibling.
    ports.configure_basis(args.basis)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(OwnerData)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    evidence = dict(schema=1, synthetic_DATA_only=True, tests=result.testsRun,
        passed=result.testsRun-len(result.failures)-len(result.errors),
        failed=len(result.failures)+len(result.errors),
        failures=[dict(test=str(test), traceback=body) for test,body in result.failures+result.errors],
        observations=OBSERVATIONS, blocked_effect_attempts=ports.DENIED,
        old86_replayed=False, old18_replayed=False, Source_constructor_calls=0, actual_actor_calls=0)
    calls = sum(row['synthetic_actor_calls'] for row in OBSERVATIONS)
    guards = dict(exact12=result.testsRun == 12, exact14_collections=len(OBSERVATIONS) == 14,
        exact395_synthetic_calls=calls == 395, no_effect_attempts=not ports.DENIED)
    evidence.update(qualification_guards=guards, synthetic_actor_calls=calls,
        owner_collections=len(OBSERVATIONS), basis=str(args.basis), work_parent=str(RUNNER_TEMP))
    with args.result.open('xb') as stream:
        stream.write(ports.encoded(evidence))
    args.result.chmod(0o600)
    raise SystemExit(not (result.wasSuccessful() and all(guards.values())))
