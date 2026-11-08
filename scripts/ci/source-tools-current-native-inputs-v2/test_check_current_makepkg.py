# SPDX-License-Identifier: MIT
"""Synthetic parser fixtures only. No process, native actor, makepkg or network."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('current_makepkg_data_checker',
    Path(__file__).resolve().with_name('check_current_makepkg.py'))
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def fixture():
    contract = dict(checks=dict(checker.CHECKS), recipe=dict(files={
        name: dict(bytes=1, sha256=hashlib.sha256(name.encode()).hexdigest(), mode=0o644)
        for name in checker.FILES}))
    files = contract['recipe']['files']
    cli = dict(status='PASS', tests=9, failures=0, errors=0,
        evidence='PURE_DATA_FOCUSED_CLI_CONTROLS', current_launcher_sha256=files['cachy-asahi-source-tools']['sha256'],
        packed_private_source_sha256=files['private-source.tar.gz']['sha256'], native_build='NOT_RUN',
        alpm_installation='NOT_RUN', namespace_probe='NOT_RUN', hardware='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED')
    catalog = dict(status='PASS', tests=9, failures=0, errors=0, skipped=0,
        helper_sha256=files['source_mirror_catalog.py']['sha256'], exact_materialized_contexts=4,
        fixtures='TWO_PACKAGES_LEGACY_CURRENT_SYNTHETIC_ARCHIVES_REAL_ORIGINAL_RECIPE_BYTES',
        native='NOT_RUN', installation='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')
    packaged = dict(status='PASS', staged_payload_files=18, checkout_hidden=True, moved_prefix=True,
        network_namespace='loopback-only', removal='EXACT_FILE_INVERSE_USER_CONTENT_PRESERVED',
        alpm_installation='NOT_RUN', native_build='NOT_RUN', workflow=dict(status='PASS', controls=17,
            exact_contexts=4, packages_per_release=2, retained_releases=2, source_execution='NOT_RUN',
            commands=[dict(synthetic_observation=index) for index in range(17)]))
    return contract, [cli, catalog, dict(status='PASS', payload_files=None, private_source_files=11),
        dict(status='PASS', payload_files=18, private_source_files=11), packaged]


def log(results):
    return (b'SYNTHETIC_NOT_NATIVE\n==> Starting check()...\n' +
        b'\n'.join(json.dumps(value, sort_keys=True, indent=2 if index == 0 else None).encode()
                   for index, value in enumerate(results)) + b'\n==> Finished synthetic parser fixture\n')


class CurrentCheckControls(unittest.TestCase):
    def setUp(self):
        self.contract, self.results = fixture()

    def refused(self, results=None, contract=None, raw=None):
        with self.assertRaises((ValueError, UnicodeError)):
            checker.check_result(log(self.results if results is None else results) if raw is None else raw,
                self.contract if contract is None else contract)

    def test_current_five_rows_bind_multiline_cli_without_native_credit(self):
        result = checker.check_result(log(self.results), self.contract)
        self.assertEqual(result['status'], 'BOUND_CURRENT_CHECK_OUTPUT_DATA')
        self.assertEqual(result['check_rows'], 5)
        self.assertEqual(result['results'], self.results)
        self.assertEqual(result['native_acceptance'], 'NOT_GRANTED')
        self.assertEqual(result['actual_native_execution'], 'NOT_ASSERTED')

    def test_frozen_old_three_row_and_seventeen_payload_refuse(self):
        self.refused([self.results[2], dict(status='PASS', payload_files=17, private_source_files=11),
                      dict(self.results[4], staged_payload_files=17)])
        self.results[3]['payload_files'] = 17
        self.refused()

    def test_missing_catalog_extra_row_and_wrong_order_refuse(self):
        self.refused(self.results[:1]+self.results[2:])
        self.refused(self.results+[dict(status='PASS')])
        self.refused([self.results[1], self.results[0], *self.results[2:]])

    def test_focus_failures_errors_skips_and_wrong_counts_refuse(self):
        for index in (0, 1):
            for key, value in (('status','FAIL'),('failures',1),('errors',1),('skipped',1),('tests',8),('tests',True)):
                with self.subTest(index=index,key=key,value=value):
                    changed = copy.deepcopy(self.results);changed[index][key] = value;self.refused(changed)

    def test_changed_catalog_launcher_and_private_source_pins_refuse(self):
        for index, key in ((0,'current_launcher_sha256'),(0,'packed_private_source_sha256'),(1,'helper_sha256')):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.results);changed[index][key] = '0'*64;self.refused(changed)

    def test_incomplete_context_and_source_payload_checks_refuse(self):
        for index,key,value in ((1,'exact_materialized_contexts',3),(2,'private_source_files',12),
                                (2,'payload_files',18),(3,'private_source_files',10),(3,'payload_files',None)):
            with self.subTest(index=index,key=key):
                changed = copy.deepcopy(self.results);changed[index][key] = value;self.refused(changed)

    def test_missing_original_package_observations_and_hidden_offline_controls_refuse(self):
        for key,value in (('checkout_hidden',False),('moved_prefix',False),('network_namespace','host'),
                          ('staged_payload_files',17),('removal','skipped')):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.results);changed[4][key] = value;self.refused(changed)
        for key,value in (('controls',16),('exact_contexts',3),('packages_per_release',1),
                          ('retained_releases',1),('commands',[{}]*16),('commands',[None]*17)):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.results);changed[4]['workflow'][key] = value;self.refused(changed)

    def test_false_native_or_release_credit_refuses(self):
        for index,key in ((0,'native_build'),(0,'namespace_probe'),(0,'release'),(1,'native'),
                          (1,'installation'),(1,'release'),(4,'native_build'),(4,'alpm_installation')):
            with self.subTest(index=index,key=key):
                changed = copy.deepcopy(self.results);changed[index][key] = 'PASS';self.refused(changed)

    def test_old_recipe_incomplete_flat_files_and_contract_counts_refuse(self):
        changed = copy.deepcopy(self.contract);changed['recipe']['files'].pop('source_mirror_catalog.py');self.refused(contract=changed)
        changed = copy.deepcopy(self.contract);changed['recipe']['files']['../foreign.py'] = changed['recipe']['files'].pop('source_mirror_catalog.py');self.refused(contract=changed)
        for key in checker.CHECKS:
            with self.subTest(key=key):
                changed = copy.deepcopy(self.contract);changed['checks'][key] += 1;self.refused(contract=changed)

    def test_missing_marker_ambiguous_frame_or_oversize_log_refuses(self):
        raw = log(self.results)
        self.refused(raw=raw.replace(b'Starting check()',b'other'))
        self.refused(raw=b'Starting check()\n'+raw)
        self.refused(raw=b'x'*(checker.MAX_LOG+1))
        self.refused(raw=bytearray(raw))

    def test_duplicate_json_keys_malformed_or_trailing_json_refuse(self):
        raw = log(self.results)
        self.refused(raw=raw.replace(b'"tests": 9',b'"tests": 9, "tests": 9',1))
        self.refused(raw=raw.replace(b'{\n',b'{bad\n',1))
        self.refused(raw=raw.replace(b'}\n==> Finished',b'} extra\n==> Finished'))
        self.refused(raw=raw+b'[]\n')

    def test_results_before_check_frame_and_nonfinite_values_refuse(self):
        raw = log(self.results)
        self.refused(raw=b'{}\n'+raw)
        self.refused(raw=raw.replace(b'"tests": 9',b'"tests": NaN',1))


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CurrentCheckControls)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps(dict(status='PASS' if result.wasSuccessful() else 'FAIL', tests=result.testsRun,
        failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
        evidence='SYNTHETIC_NOT_NATIVE_CURRENT_CHECK_PARSER', native='NOT_RUN',
        actor_imports=0, process_network_calls=0, source_constructor_calls=0,
        checker_sha256=hashlib.sha256(Path(checker.__file__).read_bytes()).hexdigest()), sort_keys=True))
    raise SystemExit(not result.wasSuccessful() or bool(result.skipped))
