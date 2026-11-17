# SPDX-License-Identifier: MIT
"""Adversarial byte-transport MODEL controls; no packages or native Qt run."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('qt612_artifact_transport', HERE / 'transport.py')
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)
REFUSAL = (ValueError, KeyError, TypeError, OSError)


class TransportModelControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='qt612-transport-MODEL-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.source = self.base / 'source'
        self.source.mkdir()
        self.receipt_path = self.base / 'C-producer-receipt.json'
        self.output = self.base / 'export'
        self.b = T.basis()
        self.package = 'artifacts/' + self.b['filename']
        self.check_log = 'artifacts/' + self.b['filename'].removesuffix('.pkg.tar.xz') + '-check.log'
        self.check_log_raw = b'MODEL original check phase log\n'
        self.archive = b'\xfd7zXZ\0MODEL: externally pinned inert bytes, NOT a package or native result\n'
        archive_sha = T.sha(self.archive)
        self.documents = {}
        normal_external = ('build.log', 'expected-packages.lock', 'artifacts/packages.lock',
                           'artifacts/generated.SRCINFO', 'artifacts/environment.txt',
                           'artifacts/config.sha256', 'artifacts/makepkg.conf', 'artifacts/pacman.conf')
        for attempt in T.ATTEMPTS:
            prefix = attempt + '/'
            self.write(prefix + self.package, self.archive)
            self.document(prefix + 'validation.json', {'errors': [], 'artifacts': [
                {'sha256': archive_sha, 'errors': []}]})
            self.document(prefix + 'stage-contract.json', {
                'status': 'PASS_QT612_DESTDIR_CONTRACT_ONLY', 'architecture': 'aarch64',
                'evidence_scope': 'STAGED_AARCH64_ELF_ONLY', 'files': {}, 'symlinks': {},
                'directories': {}, 'elf': {}, 'payload_bytes': 1, 'native_execution': 'NOT_ESTABLISHED',
                'installation': 'NOT_RUN', 'hardware': 'NOT_RUN'})
            self.document(prefix + 'check-receipt.json', {
                'schema': 1, 'status': 'PASS_QT612_OFFSCREEN_API_SMOKE_ONLY',
                'normal_makepkg_check': True, 'recipe_commit': self.b['recipe_commit'],
                'archive_sha256': archive_sha, 'check_log': {'operand': self.check_log,
                    'bytes': len(self.check_log_raw), 'sha256': T.sha(self.check_log_raw)}})
            self.document(prefix + 'license-receipt.json', {
                'status': 'PASS_QT612_SOURCE_NOTICES_ONLY', 'notices': 173, 'bytes': 636122,
                'notice_policy_sha256': self.b['notice_policy_sha256'], 'archive_sha256': archive_sha})
            files = {name: T.sha(('MODEL external ' + name).encode()) for name in normal_external}
            files['validation.json'] = T.sha((self.source / (prefix + 'validation.json')).read_bytes())
            files[self.package] = archive_sha  # Normal provenance may name the archive in both maps.
            files[self.check_log] = T.sha(self.check_log_raw)
            self.document(prefix + 'provenance.json', {
                'fixture_scope': 'MODEL_ONLY_NOT_NATIVE_ACCEPTANCE',
                'status': 'built-package-static-pass', 'mode': 'native', 'network': 'none',
                'exit_code': 0, 'builder_host_arch': 'aarch64',
                'recipe_inputs': copy.deepcopy(self.b['recipe_inputs']),
                'artifacts': {self.b['filename']: archive_sha}, 'files': files,
                'clean_environment_id': 'MODEL-clean-' + attempt,
                'image': 'MODEL-image@sha256:' + T.sha(b'MODEL image'),
                'image_id': 'sha256:' + T.sha(b'MODEL image id'), 'source_date_epoch': 1,
                'expected_packages_sha256': T.sha(b'MODEL package lock'),
                'entry_script_sha256': T.sha(b'MODEL entry script'),
                'recipe_metadata': copy.deepcopy(self.b['recipe_metadata']), 'source_material': {'scope': 'MODEL'},
                'full_unpruned_detail': {'retain_this_unknown_field': ['MODEL', 1, False]}})
        self.document('pair/comparison.json', {
            'status': 'contents-reproduced', 'errors': [], 'hardware_status': 'NOT RUN',
            'independence_limit': 'Distinct recorded container runs; independent machine execution is not attested.',
            'packages': {self.b['filename']: {
                'installed_contents_equal': True, 'pkginfo_equal': True,
                'bytes_equal': True, 'buildinfo_equal': True}}})
        self.receipt = {
            'schema': 1, 'kind': 'QT612_REFERENCE_PAIR_TRANSPORT_RECEIPT_V1',
            'recipe_commit': self.b['recipe_commit'],
            'recipe_contract_sha256': self.b['recipe_contract_sha256'],
            'producer': {'source_commit': '0' * 40, **{key: T.sha(('MODEL ' + key).encode())
                         for key in ('source_map_sha256', 'program_sha256', 'finisher_sha256', 'contract_sha256')}},
            'run': {'repository': 'Gabriel-Kahen/cachy-asahi', 'head_sha': '0' * 40,
                    'run_id': '1', 'run_attempt': '1', 'job_id': '1'},
            'files': {}, 'provenance_operands': {},
            'external_retention': {'store_id': 'MODEL-public-store', 'receipt_sha256': T.sha(b'MODEL external receipt')},
            'pair_checks': dict.fromkeys(T.FLAGS, True), 'Root_acceptance': None}
        self.partition()
        self.seal()

    def write(self, name, raw):
        path = self.source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o644)

    def document(self, name, value):
        self.documents[name] = value
        self.write(name, T.encoded(value))

    def partition(self):
        for attempt in T.ATTEMPTS:
            p = self.documents[attempt + '/provenance.json']
            operands = dict(p['files'])
            operands.update({'artifacts/' + name: digest for name, digest in p['artifacts'].items()})
            operands.update({'inputs/' + name: digest for name, digest in p['recipe_inputs'].items()})
            rows = {}
            for name, digest in operands.items():
                aliases = {'artifacts/qt612-stage-contract.json': 'stage-contract.json',
                           'artifacts/qt612-check-receipt.json': 'check-receipt.json',
                           'artifacts/qt612-license-receipt.json': 'license-receipt.json'}
                target = attempt + '/' + aliases.get(name, name)
                if target in T.payload_names(self.b):
                    rows[name] = {'bytes': (self.source / target).stat().st_size, 'sha256': digest,
                                  'disposition': 'included', 'transport_path': target}
                else:
                    rows[name] = {'bytes': len(self.check_log_raw) if name == self.check_log else 17,
                                  'sha256': digest, 'disposition': 'external_retained',
                                  'external_store_key': T.sha(('MODEL store ' + target).encode())}
            self.receipt['provenance_operands'][attempt] = rows

    def seal(self):
        attempts = {}
        for attempt in T.ATTEMPTS:
            prefix = attempt + '/'
            attempts[attempt] = {
                'archive': {'bytes': len(self.archive), 'sha256': T.sha(self.archive)},
                'provenance_sha256': T.sha((self.source / (prefix + 'provenance.json')).read_bytes()),
                'stage_canonical_sha256': T.sha(T.encoded(self.documents[prefix + 'stage-contract.json'])),
                'check_receipt_sha256': T.sha((self.source / (prefix + 'check-receipt.json')).read_bytes()),
                'license_receipt_sha256': T.sha((self.source / (prefix + 'license-receipt.json')).read_bytes())}
        self.document('pair/qt-pair-finisher.json', {
            'schema': 1, 'kind': 'QT612_REFERENCE_PAIR_FINISHER_V1',
            'status': 'PASS_QT612_REFERENCE_PAIR_ONLY', 'recipe_commit': self.b['recipe_commit'],
            'recipe_contract_sha256': self.b['recipe_contract_sha256'],
            'comparison_sha256': T.sha((self.source / 'pair/comparison.json').read_bytes()), 'attempts': attempts})
        self.receipt['files'] = {name: {'bytes': (self.source / name).stat().st_size,
                                      'sha256': T.sha((self.source / name).read_bytes()), 'mode': 0o644}
                                 for name in T.payload_names(self.b)}
        self.pin_receipt()

    def pin_receipt(self, raw=None):
        raw = T.encoded(self.receipt) if raw is None else raw
        self.receipt_path.write_bytes(raw)
        self.receipt_path.chmod(0o644)
        self.receipt_sha = T.sha(raw)

    def collect(self, output=None):
        return T.collect(self.source, self.receipt_path, self.receipt_sha, output or self.output)

    def refuse_collect(self):
        with self.assertRaises(REFUSAL):
            self.collect()
        self.assertFalse(self.output.exists(), 'refusal must not create a completed or partial export')

    def test_complete_transport_keeps_full_provenance_and_no_acceptance(self):
        result = self.collect()
        self.assertEqual(result['status'], 'PASS_TRANSPORT_BYTES_ONLY')
        self.assertEqual(result['files'], 16)
        self.assertGreater(result['external_operands'], 0)
        self.assertTrue(result['external_readback_required'])
        self.assertFalse(result['offline_comparison_complete'])
        self.assertFalse(result['native_acceptance'])
        self.assertIsNone(result['Root_acceptance'])
        names = {str(path.relative_to(self.output)) for path in self.output.rglob('*') if path.is_file()}
        self.assertEqual(names, T.payload_names(self.b) | {'producer-receipt.json', 'transport-manifest.json'})
        for name in self.receipt['files']:
            self.assertEqual((self.output / name).read_bytes(), (self.source / name).read_bytes())
            self.assertEqual((self.output / name).stat().st_mode & 0o7777, 0o644)
        readback = T.verify(self.output, result['manifest_sha256'], self.receipt_sha)
        self.assertEqual(readback, result)

    def test_stage_canonical_hash_does_not_replace_whole_raw_pin(self):
        name = 'build-1/stage-contract.json'
        raw = json.dumps(self.documents[name], separators=(',', ':')).encode()
        self.write(name, raw)
        self.seal()
        self.collect()
        self.assertEqual((self.output / name).read_bytes(), raw)
        self.assertNotEqual(T.sha(raw), T.sha(T.encoded(self.documents[name])))

    def test_external_pins_are_required_and_receipt_replay_refuses(self):
        for pin in ('', None, 'f' * 64):
            with self.subTest(pin=pin), self.assertRaises(REFUSAL):
                T.collect(self.source, self.receipt_path, pin, self.output)
            self.assertFalse(self.output.exists())
        result = self.collect()
        for manifest_pin, receipt_pin in (('', self.receipt_sha), (None, self.receipt_sha),
                                          ('f' * 64, self.receipt_sha), (result['manifest_sha256'], 'f' * 64)):
            with self.subTest(manifest=manifest_pin, receipt=receipt_pin), self.assertRaises(REFUSAL):
                T.verify(self.output, manifest_pin, receipt_pin)
        self.receipt['run']['run_id'] = '2'
        self.pin_receipt()
        with self.assertRaises(REFUSAL):
            T.verify(self.output, result['manifest_sha256'], self.receipt_sha)

    def test_missing_unexpected_and_empty_directory_refuse(self):
        name = 'build-1/check-receipt.json'
        raw = (self.source / name).read_bytes()
        (self.source / name).unlink()
        self.refuse_collect()
        self.write(name, raw)
        extra = self.source / 'unexpected.txt'
        extra.write_bytes(b'MODEL extra')
        self.refuse_collect()
        extra.unlink()
        (self.source / 'unexpected-empty-directory').mkdir()
        self.refuse_collect()

    def test_symlink_hardlink_and_fifo_refuse_without_opening_payloads(self):
        path = self.source / ('build-1/' + self.package)
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                path.unlink()
                alias = self.base / ('alias-' + kind)
                if kind == 'symlink':
                    alias.write_bytes(self.archive)
                    path.symlink_to(alias)
                elif kind == 'hardlink':
                    alias.write_bytes(self.archive)
                    os.link(alias, path)
                else:
                    os.mkfifo(path, 0o644)
                with patch.object(T.Tree, 'stream', side_effect=AssertionError('must reject before any payload read')):
                    self.refuse_collect()
                path.unlink()
                self.write('build-1/' + self.package, self.archive)

    def test_unsafe_file_and_directory_modes_refuse(self):
        path = self.source / ('build-1/' + self.package)
        for mode in (0o600, 0o664, 0o755, 0o4755):
            with self.subTest(mode=mode):
                path.chmod(mode)
                self.refuse_collect()
        path.chmod(0o644)
        self.source.chmod(0o777)
        self.refuse_collect()
        self.source.chmod(0o755)

    def test_root_alias_and_output_reuse_refuse(self):
        alias = self.base / 'source-alias'
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(REFUSAL):
            T.collect(alias, self.receipt_path, self.receipt_sha, self.output)
        self.output.mkdir()
        self.refuse_collect_exists()

    def refuse_collect_exists(self):
        with self.assertRaises(REFUSAL):
            self.collect()
        self.assertEqual(list(self.output.iterdir()), [])

    def test_truncated_payload_and_receipt_refuse(self):
        path = self.source / ('build-1/' + self.package)
        path.write_bytes(self.archive[:-1])
        self.refuse_collect()
        path.write_bytes(self.archive)
        self.pin_receipt(self.receipt_path.read_bytes()[:-4])
        self.refuse_collect()

    def test_sparse_over_128mib_refuses_before_payload_read_or_copy(self):
        path = self.source / ('build-1/' + self.package)
        with path.open('r+b') as stream:
            stream.truncate(128 * 1024**2 + 1)
        with patch.object(T.Tree, 'stream', side_effect=AssertionError('oversize must reject before reads')):
            self.refuse_collect()

    def test_complete_byte_budget_includes_receipt_and_manifest(self):
        self.collect()
        total = sum(path.stat().st_size for path in self.output.rglob('*') if path.is_file())
        exact = self.base / 'exact-budget-export'
        with patch.object(T, 'MAX_BYTES', total):
            self.collect(exact)
        too_small = self.base / 'too-small-budget-export'
        with patch.object(T, 'MAX_BYTES', total - 1), self.assertRaises(REFUSAL):
            self.collect(too_small)
        self.assertFalse(too_small.exists())

    def test_file_count_boundary_and_4097_names_refuse(self):
        root = self.base / 'two-files'
        root.mkdir()
        for name in ('a', 'b'):
            (root / name).write_bytes(b'MODEL')
            (root / name).chmod(0o644)
        with patch.object(T, 'MAX_FILES', 2):
            tree = T.Tree(root, {'a', 'b'})
            tree.close()
        with patch.object(T, 'MAX_FILES', 1), self.assertRaises(REFUSAL):
            T.Tree(root, {'a', 'b'})
        with self.assertRaises(REFUSAL):
            T.Tree(root, {f'file-{number}' for number in range(4097)})

    def test_descriptor_boolean_bytes_and_modes_refuse(self):
        name = 'build-1/' + self.package
        original = copy.deepcopy(self.receipt['files'][name])
        for key in ('bytes', 'mode'):
            with self.subTest(key=key):
                self.receipt['files'][name] = dict(original, **{key: True})
                self.pin_receipt()
                self.refuse_collect()

    def test_nonmatching_recipe_and_false_buildinfo_refuse_even_with_new_pins(self):
        original = self.receipt['recipe_commit']
        self.receipt['recipe_commit'] = 'f' * 40
        self.pin_receipt()
        self.refuse_collect()
        self.receipt['recipe_commit'] = original
        name = 'pair/comparison.json'
        self.documents[name]['packages'][self.b['filename']]['buildinfo_equal'] = False
        self.document(name, self.documents[name])
        self.seal()
        self.refuse_collect()

    def test_missing_external_partition_operand_and_retention_receipt_refuse(self):
        partition = self.receipt['provenance_operands']['build-1']
        name = 'inputs/PKGBUILD'
        original = partition.pop(name)
        self.pin_receipt()
        self.refuse_collect()
        partition[name] = original
        self.receipt['external_retention']['receipt_sha256'] = ''
        self.pin_receipt()
        self.refuse_collect()

    def test_external_operand_sizes_are_separate_from_channel_budget(self):
        row = self.receipt['provenance_operands']['build-1']['build.log']
        for size in (0, 2 * 1024**3):
            with self.subTest(size=size):
                row['bytes'] = size
                self.pin_receipt()
                result = self.collect(self.base / ('external-size-' + str(size)))
                self.assertTrue(result['external_readback_required'])
                self.assertFalse(result['offline_comparison_complete'])
        row['bytes'] = 2 * 1024**3 + 1
        self.pin_receipt()
        self.refuse_collect()

    def test_included_operand_cannot_be_reclassified_as_external(self):
        partition = self.receipt['provenance_operands']['build-1']
        row = partition[self.package]
        row.pop('transport_path')
        row.update(disposition='external_retained', external_store_key=T.sha(b'MODEL hiding included archive'))
        self.pin_receipt()
        self.refuse_collect()

    def test_original_stage_alias_is_included_and_cannot_be_hidden_externally(self):
        name = 'build-1/provenance.json'
        alias = 'artifacts/qt612-stage-contract.json'
        self.documents[name]['files'][alias] = T.sha((self.source / 'build-1/stage-contract.json').read_bytes())
        self.document(name, self.documents[name])
        self.partition()
        self.seal()
        self.collect(self.base / 'accepted-stage-alias')
        row = self.receipt['provenance_operands']['build-1'][alias]
        row.pop('transport_path')
        row.update(disposition='external_retained', external_store_key=T.sha(b'MODEL hidden stage alias'))
        self.pin_receipt()
        self.refuse_collect()

    def test_original_check_log_cannot_be_changed_or_omitted(self):
        name = 'build-1/check-receipt.json'
        original = copy.deepcopy(self.documents[name])
        changed = copy.deepcopy(original)
        changed['check_log']['sha256'] = 'f' * 64
        self.document(name, changed)
        self.seal()
        self.refuse_collect()
        omitted = copy.deepcopy(original)
        omitted.pop('check_log')
        self.document(name, omitted)
        self.seal()
        self.refuse_collect()
        self.document(name, original)
        provenance = 'build-1/provenance.json'
        self.documents[provenance]['files'].pop(self.check_log)
        self.document(provenance, self.documents[provenance])
        self.partition()
        self.seal()
        self.refuse_collect()

    def test_conflicting_provenance_archive_aliases_refuse(self):
        name = 'build-1/provenance.json'
        self.documents[name]['files'][self.package] = 'f' * 64
        self.document(name, self.documents[name])
        self.seal()
        self.refuse_collect()

    def test_required_normal_provenance_operand_cannot_be_pruned(self):
        name = 'build-1/provenance.json'
        self.documents[name]['files'].pop('build.log')
        self.document(name, self.documents[name])
        self.partition()
        self.seal()
        self.refuse_collect()

    def test_distinct_clean_attempt_and_identical_input_bindings_required(self):
        name = 'build-2/provenance.json'
        original = copy.deepcopy(self.documents[name])
        for field, value in (('clean_environment_id', 'MODEL-clean-build-1'), ('image_id', 'different-MODEL-image')):
            with self.subTest(field=field):
                self.document(name, dict(original, **{field: value}))
                self.seal()
                self.refuse_collect()

    def test_booleans_cannot_substitute_for_integer_or_boolean_receipt_fields(self):
        for location, field, value in (('build-1/provenance.json', 'exit_code', False),
                                        ('build-1/check-receipt.json', 'schema', True),
                                        ('build-1/check-receipt.json', 'normal_makepkg_check', 1)):
            with self.subTest(location=location, field=field):
                original = copy.deepcopy(self.documents[location])
                self.document(location, dict(original, **{field: value}))
                self.seal()
                self.refuse_collect()
                self.document(location, original)
        self.receipt['schema'] = True
        self.pin_receipt()
        self.refuse_collect()

    def test_hardware_and_stage_scope_cannot_be_upgraded(self):
        stage = 'build-1/stage-contract.json'
        comparison = 'pair/comparison.json'
        for location, field, value in ((comparison, 'hardware_status', 'PASS'),
                                        (comparison, 'independence_limit', 'Independent machines attested'),
                                        (stage, 'architecture', 'x86_64'), (stage, 'hardware', 'PASS'),
                                        (stage, 'evidence_scope', 'HOST_X86_64_STAGE_ONLY'),
                                        (stage, 'native_execution', 'PASS'),
                                        (stage, 'files', []), (stage, 'payload_bytes', True)):
            with self.subTest(location=location, field=field):
                original = copy.deepcopy(self.documents[location])
                self.document(location, dict(original, **{field: value}))
                self.seal()
                self.refuse_collect()
                self.document(location, original)

    def test_duplicate_nonfinite_and_unsafe_member_json_refuse(self):
        original = T.encoded(self.receipt)
        for raw in (b'{"schema": 1,' + original[1:], original.replace(b'"schema": 1', b'"schema": NaN', 1)):
            with self.subTest(raw=raw[:35]):
                self.pin_receipt(raw)
                self.refuse_collect()
        for name in ('../escape', '/absolute', 'a//b', 'a/../b', 'a\\b'):
            with self.subTest(name=name), self.assertRaises(REFUSAL):
                T.member(name)

    def test_export_namespace_and_manifest_semantics_are_independently_checked(self):
        result = self.collect()
        path = self.output / 'extra-file'
        path.write_bytes(b'MODEL extra')
        with self.assertRaises(REFUSAL):
            T.verify(self.output, result['manifest_sha256'], self.receipt_sha)
        path.unlink()
        manifest_path = self.output / 'transport-manifest.json'
        manifest = json.loads(manifest_path.read_bytes())
        for field, value in (('native_acceptance', 0), ('offline_comparison_complete', 0), ('schema', True)):
            with self.subTest(field=field):
                raw = T.encoded(dict(manifest, **{field: value}))
                manifest_path.write_bytes(raw)
                with self.assertRaises(REFUSAL):
                    T.verify(self.output, T.sha(raw), self.receipt_sha)

    def test_fragment_has_finite_three_day_retention_without_acceptance_step(self):
        fragment = (HERE / 'workflow.fragment.yml').read_text()
        self.assertIn('retention-days: 3', fragment)
        self.assertIn('overwrite: false', fragment)
        self.assertIn('include-hidden-files: false', fragment)
        self.assertIn('if-no-files-found: error', fragment)

    def test_source_change_after_validation_cannot_complete_export(self):
        original = T.validate
        path = self.source / ('build-1/' + self.package)

        def changed(tree, receipt, basis):
            external = original(tree, receipt, basis)
            path.write_bytes(self.archive[:-1] + b'X')
            return external

        with patch.object(T, 'validate', side_effect=changed), self.assertRaises(REFUSAL):
            self.collect()
        self.assertFalse((self.output / 'transport-manifest.json').exists())

    def test_replaced_output_directory_cannot_write_through_symlink(self):
        outside = self.base / 'outside-export'
        outside.mkdir()
        parked = self.base / 'parked-export'
        original = T.Export.put
        swapped = False

        def replaced(writer, *args, **kwargs):
            nonlocal swapped
            if not swapped:
                swapped = True
                self.output.rename(parked)
                self.output.symlink_to(outside, target_is_directory=True)
            return original(writer, *args, **kwargs)

        with patch.object(T.Export, 'put', replaced), self.assertRaises(REFUSAL):
            self.collect()
        self.assertTrue(swapped, 'the output mutation hook must execute')
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((parked / 'transport-manifest.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
