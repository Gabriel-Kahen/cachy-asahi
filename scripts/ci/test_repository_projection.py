"""Strict repository field projection; pure fixtures, no GPG/Docker/native work."""
import copy
import hashlib
import importlib.util
import json
import os
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


def operation_fixture(raw):
    """Small producer-shaped fixture; all byte bindings are real temporary files."""
    raw.mkdir(exist_ok=True)
    sha = lambda data: hashlib.sha256(data).hexdigest()
    encode = lambda value: (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()
    contract = {'source_commit': 'a' * 40, 'nonce': 'c' * 32, 'image_id': 'sha256:' + 'b' * 64,
                'daemon_arch': 'aarch64', 'script_sha256': 'd' * 64,
                'upgrade_kind': 'synthetic-changed-package-fixtures',
                'baseline': [{'name': name, 'version': '0.1.0-1', 'sha256': 'e' * 64,
                              'payload_sha256': {'usr/share/cachy-asahi/' + name + '.txt': 'f' * 64}}
                             for name in sorted(projection.inventory.PACKAGES)]}
    result = {'schema_version': 1, 'purpose': projection.PURPOSE, 'source_commit': contract['source_commit'],
              'input_contract': {key: contract[key] for key in projection.CONTRACT_FIELDS},
              'status': 'PASS', 'base_versions': {'base': '1-1', 'libsecret': '1-1'},
              'commands': [], 'cases': [{'name': projection.REJECTION, 'result': 'PASS', 'expected_signature_rejection': True},
                                       {'name': projection.FINAL, 'result': 'PASS', 'expected_signature_rejection': False}],
              'public_TEST_identities': {'signer-A': {'fingerprint': 'A' * 40}},
              'original_inputs': {'baseline': {row['name']: {key: row[key] for key in ('sha256', 'version')}
                                               for row in contract['baseline']}}}
    def put(name, data):
        (raw / name).write_bytes(data)
        return sha(data)
    def command(label, data, positive=True):
        name = f'{len(result["commands"]):03d}-{label}.txt'
        row = {'label': label, 'log': name, 'sha256': put(name, data), 'exit_code': 0, 'expected': 0}
        if positive:
            row.update(positive_diagnostics='PASS', stderr_log=name[:-4] + '-stderr.txt',
                       stderr_sha256=put(name[:-4] + '-stderr.txt', b''))
        result['commands'].append(row)
        return row
    proof = command('gpg-revoked-A-status', ('[GNUPG:] REVKEYSIG ' + 'A' * 16 + ' TEST\n[GNUPG:] VALIDSIG ' + 'A' * 40 + ' TEST\n').encode(), False)
    proof['expected'] = None
    rejected = command(projection.REJECTION, b'error: signature from "TEST ONLY disposable repository signer-A <signer-A@test.invalid>" is invalid\n', False)
    rejected.update(expected='nonzero', exit_code=1)
    versions = {**result['base_versions'], **{row['name']: row['version'] for row in contract['baseline']},
                'cachy-asahi-repository-test-fixture': '1-1'}
    inventory = ''.join(f'{name} {versions[name]}\n' for name in sorted(versions)).encode()
    files = {name: {'type': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'sha256': digest}
             for row in contract['baseline'] for name, digest in row['payload_sha256'].items()}
    files['usr/share/cachy-asahi-repository-TEST/fixture.txt'] = {
        'type': 'regular', 'uid': 0, 'gid': 0, 'mode': 0o644, 'sha256': sha(b'SYNTHETIC TEST fixture version 1\n')}
    snapshot = encode({'inventory': inventory.decode(), 'files': files})
    put(projection.REJECTION + '-after-snapshot.json', snapshot)
    for phase in ('before', 'after'):
        command('inventory-' + projection.RESET + '-' + phase, inventory)
        put(projection.RESET + '-' + phase + '-snapshot.json', snapshot)
    command(projection.FINAL, b'complete upgrade\n')
    command(projection.RELATION, b'No database errors have been found!\n')
    aliases = {stage + '/' + name: {'kind': 'file', 'target': stage + '/' + target, 'regular_copy_sha256': pin * 64}
               for stage, pin in (('baseline-A', '1'), ('updated-B', '2'))
               for name, target in (('integration.db', 'integration.db.tar.gz'), ('integration.db.sig', 'integration.db.tar.gz.sig'))}
    aliases['active'] = {'kind': 'directory', 'target': 'updated-B'}
    put('TEST-repository-aliases.json', encode(aliases))
    reset = {'status': 'PASS', 'scope': 'two private copied-root sync files after revoked-A rejection',
             'prior_rejection_log_sha256': rejected['sha256'], 'revocation_status_log_sha256': proof['sha256'],
             'removed': {name: '1' * 64 for name in ('integration.db', 'integration.db.sig')},
             'absence': 'PASS', 'installed_state_unchanged': True}
    name = projection.RESET + '.json'
    result['sync_cache_reset'] = {'receipt': name, 'sha256': put(name, encode(reset))}
    result['final_sync_cache'] = {name: '2' * 64 for name in ('integration.db', 'integration.db.sig')}
    result['evidence_sha256'] = {path.name: sha(path.read_bytes()) for path in raw.iterdir()}
    put('result.json', encode(result))
    return result, contract


class RepositoryOperationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.raw = Path(self.temporary.name) / 'raw'
        self.result, self.contract = operation_fixture(self.raw)

    def operations(self):
        return projection.operation_files(self.raw, self.result, self.contract)

    def rebind(self, name, data):
        (self.raw / name).write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        self.result['evidence_sha256'][name] = digest
        for row in self.result['commands']:
            for key, pin in (('log', 'sha256'), ('stderr_log', 'stderr_sha256')):
                if row.get(key) == name:
                    row[pin] = digest
        if name == projection.RESET + '.json':
            self.result['sync_cache_reset']['sha256'] = digest

    def test_exact_nine_aliases_preserve_all_original_bytes_and_hashes(self):
        before = {path.name: path.read_bytes() for path in self.raw.iterdir()}
        files, index = self.operations()
        self.assertEqual(len(files), 9)
        self.assertEqual(len(set(alias for alias, _ in files.values())), 9)
        for name, (alias, data) in files.items():
            self.assertEqual(data, before[name])
            self.assertIsNone(exporter.SENSITIVE_PATH.search(alias))
            self.assertEqual(index['files'][name]['original_sha256'], self.result['evidence_sha256'][name])
            self.assertEqual(index['files'][name]['public_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(before, {path.name: path.read_bytes() for path in self.raw.iterdir()})

    def test_original_generic_export_still_refuses_exact_nine_names(self):
        manifest = exporter.export_evidence(self.raw, Path(self.temporary.name) / 'public')
        self.assertEqual(manifest['evidence_export'], 'FAIL')
        self.assertEqual({row['path'] for row in manifest['rejected'] if row['reason'].startswith('sensitive-path')}, set(self.operations()[0]) | {'000-gpg-revoked-A-status.txt'})

    def test_wrong_contract_refused(self):
        self.contract['nonce'] = '0' * 32
        with self.assertRaises(ValueError): self.operations()

    def test_duplicate_or_missing_operation_commands_refused(self):
        for rows in (self.result['commands'] + [self.result['commands'][2]], self.result['commands'][:-1]):
            with patch.dict(self.result, commands=rows), self.assertRaises(ValueError): self.operations()

    def test_forged_positive_status_exit_expected_and_filename_refused(self):
        row = self.result['commands'][2]
        for key, value in (('exit_code', True), ('exit_code', 1), ('expected', False),
                           ('positive_diagnostics', 'FAIL'), ('log', 'unbound-cache.txt')):
            with patch.dict(row, {key: value}), self.subTest(key=key), self.assertRaises(ValueError): self.operations()

    def test_reordered_cases_false_rejection_and_final_pair_refused(self):
        for key, value in (('cases', list(reversed(self.result['cases']))),
                           ('final_sync_cache', {'integration.db': '9' * 64})):
            with patch.dict(self.result, {key: value}), self.assertRaises(ValueError): self.operations()
        with patch.dict(self.result['commands'][1], exit_code=0), self.assertRaises(ValueError): self.operations()

    def test_reset_semantic_forgery_refused_even_after_rehash(self):
        name = projection.RESET + '.json'; original = (self.raw / name).read_bytes()
        for key, value in (('absence', 'FAIL'), ('installed_state_unchanged', 1), ('scope', 'other'),
                           ('removed', {'integration.db': '1' * 64}), ('prior_rejection_log_sha256', '0' * 64),
                           ('unknown', 'public-looking')):
            reset = json.loads(original); reset[key] = value
            self.rebind(name, json.dumps(reset).encode())
            with self.subTest(key=key), self.assertRaises(ValueError): self.operations()

    def test_duplicate_and_nonfinite_reset_json_refused_after_rehash(self):
        name = projection.RESET + '.json'; data = (self.raw / name).read_bytes()
        for forged in (data.replace(b'"status": "PASS"', b'"status":"FAIL","status":"PASS"'),
                       data.replace(b'"installed_state_unchanged": true', b'"installed_state_unchanged": NaN')):
            self.rebind(name, forged)
            with self.assertRaises(ValueError): self.operations()

    def test_changed_snapshot_payload_inventory_metadata_or_extra_field_refused(self):
        name = projection.RESET + '-after-snapshot.json'; original = json.loads((self.raw / name).read_bytes())
        for key, value in (('inventory', 'base 2-1\n'), ('files', {}), ('unknown', 'public-looking')):
            forged = copy.deepcopy(original); forged[key] = value
            self.rebind(name, json.dumps(forged).encode())
            with self.subTest(key=key), self.assertRaises(ValueError): self.operations()

    def test_rehashed_positive_error_and_nonempty_stderr_refused(self):
        row = self.result['commands'][-1]
        self.rebind(row['log'], b'No database errors have been found!\nerror: fixture\n')
        with self.assertRaises(ValueError): self.operations()
        self.rebind(row['log'], b'No database errors have been found!\n')
        self.rebind(row['stderr_log'], b'error: fixture\n')
        with self.assertRaises(ValueError): self.operations()

    def test_file_hash_drift_symlink_and_hardlink_refused(self):
        name = projection.RESET + '.json'; path = self.raw / name; original = path.read_bytes()
        path.write_bytes(b'drift')
        with self.assertRaises(ValueError): self.operations()
        path.write_bytes(original); other = self.raw / 'other.json'; path.rename(other); path.symlink_to(other)
        with self.assertRaises(ValueError): self.operations()
        path.unlink(); os.link(other, path)
        with self.assertRaises(ValueError): self.operations()

    def test_changed_baseline_authority_refused(self):
        self.contract['baseline'][0]['version'] = '2-1'
        with self.assertRaises(ValueError): self.operations()

    def test_rehashed_database_alias_and_final_endpoint_forgery_refused(self):
        name = 'TEST-repository-aliases.json'; original = json.loads((self.raw / name).read_bytes())
        for key, value in (('active', {'kind': 'directory', 'target': 'baseline-A'}),
                           ('baseline-A/integration.db', {'kind': 'file', 'target': 'baseline-A/integration.db.tar.gz',
                                                        'regular_copy_sha256': '0' * 64}),
                           ('updated-B/integration.db.sig', {'kind': 'file', 'target': '../other.sig',
                                                           'regular_copy_sha256': '2' * 64})):
            aliases = copy.deepcopy(original); aliases[key] = value
            self.rebind(name, json.dumps(aliases).encode())
            with self.subTest(key=key), self.assertRaises(ValueError): self.operations()

    def test_rehashed_snapshot_boolean_metadata_and_duplicate_keys_refused(self):
        name = projection.RESET + '-before-snapshot.json'; data = (self.raw / name).read_bytes()
        for forged in (data.replace(b'"uid": 0', b'"uid": false'),
                       data.replace(b'"mode": 420', b'"mode": 420,"mode": 420'),
                       data.replace(b'"files": {', b'"unknown": Infinity,"files": {')):
            self.rebind(name, forged)
            with self.assertRaises(ValueError): self.operations()

    def test_wrong_full_fingerprint_refused_despite_rehashed_status(self):
        row = self.result['commands'][0]
        self.rebind(row['log'], b'[GNUPG:] REVKEYSIG AAAAAAAAAAAAAAAA TEST\n[GNUPG:] VALIDSIG ' + b'B' * 40 + b' TEST\n')
        with self.assertRaises(ValueError): self.operations()

    def test_symlink_evidence_ancestor_refused(self):
        alias = Path(self.temporary.name) / 'linked'; alias.symlink_to(self.raw, target_is_directory=True)
        with self.assertRaises(ValueError): projection.operation_files(alias, self.result, self.contract)

    def test_absent_reset_never_grants_aliases(self):
        del self.result['sync_cache_reset']
        self.assertEqual(self.operations(), ({}, None))


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
