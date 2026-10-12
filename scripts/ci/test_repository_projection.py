"""Strict repository field projection; pure fixtures, no GPG/Docker/native work."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


projection = module('repository_projection')
exporter = module('integration_export')


class RepositoryProjectionTests(unittest.TestCase):
    def setUp(self):
        self.base = {'glibc': '2.43-2', 'libsecret': '0.21.8.2-1', 'pacman': '7.1.0.r7-1'}
        self.result = {'schema_version': 1, 'purpose': projection.PURPOSE, 'status': 'PASS',
                       'source_commit': 'a' * 40, 'hardware_validation': 'NOT RUN',
                       'stable_promotion': 'NOT RUN', 'published': False,
                       'input_contract': {'image_id': 'sha256:' + 'b' * 64, 'upgrade_kind': 'synthetic-changed-package-fixtures'},
                       'commands': [{'label': 'public', 'exit_code': 0}], 'cases': [{'name': 'fixture', 'result': 'PASS'}],
                       'base_versions': copy.deepcopy(self.base), 'test_private_state_removed': True}

    def data(self, value=None):
        return (json.dumps(self.result if value is None else value, indent=2, sort_keys=True) + '\n').encode()

    def export(self, value):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); raw = root / 'raw'; raw.mkdir()
            (raw / 'result.json').write_bytes(self.data(value))
            return exporter.export_evidence(raw, root / 'public')

    def test_real_libsecret_false_positive_becomes_explicit_complete_rows(self):
        original = self.data()
        self.assertEqual(exporter.PRIVATE_CONTENT.search(original.decode()).group(0), 'secret": "0.21.8.2-1",')
        value = projection.project(original, self.base)
        self.assertEqual(value['base_versions'], [{'name': name, 'version': self.base[name]} for name in sorted(self.base)])
        self.assertEqual(self.export(value)['evidence_export'], 'PASS')
        self.assertEqual(original, self.data())
        self.assertEqual(self.result['base_versions'], self.base)

    def test_other_fields_preserved_exactly_as_deepcopy(self):
        original = copy.deepcopy(self.result)
        value = projection.project_result(self.result, self.base)
        for name in self.result:
            if name != 'base_versions':
                self.assertEqual(value[name], original[name])
        value['commands'][0]['exit_code'] = 1
        value['input_contract']['image_id'] = 'changed'
        self.assertEqual(self.result, original)

    def test_unknown_credential_content_stays_present_and_generic_export_refuses(self):
        for extra in ({'password': 'DO-NOT-PUBLISH'}, {'unknown': {'secret': 'DO-NOT-PUBLISH'}},
                      {'unknown': '-----BEGIN PGP PRIVATE KEY BLOCK-----'}):
            raw = copy.deepcopy(self.result); raw.update(extra)
            value = projection.project(self.data(raw), self.base)
            for key, content in extra.items():
                self.assertEqual(value[key], content)
            self.assertEqual(self.export(value)['evidence_export'], 'FAIL')

    def test_missing_extra_changed_or_empty_inventory_refused(self):
        missing = dict(self.base); del missing['libsecret']
        for base in ({}, missing, {**self.base, 'unaccepted': '1-1'}, {**self.base, 'libsecret': '0.21.8.2-2'}):
            raw = copy.deepcopy(self.result); raw['base_versions'] = base
            with self.subTest(base=base), self.assertRaises(ValueError):
                projection.project(self.data(raw), self.base)

    def test_malformed_credentials_controls_nonscalar_inventory_refused(self):
        for value in ('password=DO-NOT-PUBLISH', '-----BEGIN RSA PRIVATE KEY-----', '1\0-1',
                      '1\n-1', '1\x1b[31m', '1​-1', True, 1, None, ['1-1'], {'password': 'x'}):
            raw = copy.deepcopy(self.result); raw['base_versions']['libsecret'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                projection.project(self.data(raw), self.base)
        raw = copy.deepcopy(self.result); raw['base_versions']['password'] = 'DO-NOT-PUBLISH'
        with self.assertRaises(ValueError):
            projection.project(self.data(raw), self.base)

    def test_wrong_base_authority_refused(self):
        for base in ({}, {**self.base, 'unaccepted': '1-1'}, {**self.base, 'libsecret': 'password=x'}):
            with self.subTest(base=base), self.assertRaises(ValueError):
                projection.project(self.data(), base)

    def test_duplicate_json_keys_at_all_depths_and_nonfinite_refused(self):
        for data in (b'{"purpose":"a","purpose":"b"}', b'{"unknown":{"key":1,"key":2}}',
                     b'{"base_versions":{"libsecret":"1-1","libsecret":"2-1"}}',
                     b'{"unknown":NaN}', b'{"unknown":Infinity}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                projection.project(data, self.base)

    def test_invalid_utf8_nonobject_wrong_schema_and_bounds_refused(self):
        for data in (b'', b'\xff', b'[]', b'123', b'null', b'"secret"', b' ' * (projection.LIMIT + 1)):
            with self.subTest(data=data[:20]), self.assertRaises(ValueError):
                projection.project(data, self.base)
        for schema in (True, False, '1', 2, None):
            raw = copy.deepcopy(self.result); raw['schema_version'] = schema
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                projection.project(self.data(raw), self.base)

    def test_other_purpose_is_not_projected_or_sanitized(self):
        raw = copy.deepcopy(self.result); raw['purpose'] = 'unknown-purpose'
        value = projection.project(self.data(raw), self.base)
        self.assertEqual(value, raw)
        self.assertIsInstance(value['base_versions'], dict)
        self.assertEqual(self.export(value)['evidence_export'], 'FAIL')

    def test_early_failure_without_inventory_passes_unchanged_without_completeness_claim(self):
        raw = copy.deepcopy(self.result); del raw['base_versions']; raw['status'] = 'FAIL'
        value = projection.project(self.data(raw), self.base)
        self.assertEqual(value, raw)
        self.assertEqual(value['status'], 'FAIL')

    def contract(self):
        return {'schema_version': 1, 'purpose': projection.PURPOSE, 'source_commit': 'a' * 40,
                'nonce': 'c' * 32, 'image_id': 'sha256:' + 'b' * 64, 'daemon_arch': 'aarch64',
                'script_sha256': 'd' * 64, 'upgrade_kind': 'synthetic-changed-package-fixtures'}

    def bound_result(self):
        result = copy.deepcopy(self.result)
        result['input_contract'] = {key: self.contract()[key] for key in projection.CONTRACT_FIELDS}
        return result

    def test_exact_source_and_generated_input_contract_binding(self):
        result = self.bound_result()
        projection.validate_contract(result, self.contract())
        public = projection.project(self.data(result), self.base, self.contract())
        self.assertIsInstance(public['base_versions'], list)
        self.assertEqual(public['input_contract'], result['input_contract'])

    def test_nonce_script_source_image_arch_kind_and_unknown_fields_refused_before_projection(self):
        cases = []
        for key, value in (('nonce', 'f' * 32), ('image_id', 'sha256:' + 'f' * 64),
                           ('daemon_arch', 'x86_64'), ('script_sha256', 'f' * 64),
                           ('upgrade_kind', 'stable-release')):
            result = self.bound_result(); result['input_contract'][key] = value; cases.append(result)
        result = self.bound_result(); result['source_commit'] = 'f' * 40; cases.append(result)
        result = self.bound_result(); result['input_contract']['unexpected'] = 'value'; cases.append(result)
        for key in projection.CONTRACT_FIELDS:
            result = self.bound_result(); del result['input_contract'][key]; cases.append(result)
        for result in cases:
            with self.subTest(result=result['input_contract']), \
                    patch.object(projection, 'project_result', side_effect=AssertionError('unbound receipt transformed')), \
                    self.assertRaises(ValueError):
                projection.project(self.data(result), self.base, self.contract())

    def test_wrong_purpose_schema_or_incomplete_manifest_refused(self):
        for key, value in (('purpose', 'unknown'), ('schema_version', True), ('schema_version', 2)):
            result = self.bound_result(); result[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                projection.project(self.data(result), self.base, self.contract())
        for key in ('source_commit', *projection.CONTRACT_FIELDS):
            contract = self.contract(); del contract[key]
            with self.subTest(missing=key), self.assertRaises(ValueError):
                projection.project(self.data(self.bound_result()), self.base, contract)

    def test_valid_binding_does_not_sanitize_unknown_credentials(self):
        result = self.bound_result(); result['unknown'] = {'password': 'DO-NOT-PUBLISH'}
        public = projection.project(self.data(result), self.base, self.contract())
        self.assertEqual(public['unknown'], result['unknown'])
        self.assertEqual(self.export(public)['evidence_export'], 'FAIL')
