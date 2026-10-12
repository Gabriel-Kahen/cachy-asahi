#!/usr/bin/env python3
"""Receipt projection tests; temp data only, no build/container operations."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('public_evidence', BASE / 'public-evidence.py')
public = importlib.util.module_from_spec(spec)
spec.loader.exec_module(public)
H = 'a' * 64
POISON = 'Bearer TOP_SECRET_PASSWORD api_key=credential-value'


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='updater-public-tests-')
        self.root = Path(self.temp.name)
        self.raw = self.root / 'raw';self.raw.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, value):
        path = self.raw / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value))

    def project(self):
        output = self.root / 'projected'
        result = public.project_evidence(self.raw, output)
        return result, output

    def test_cancelled_failure_survives_without_any_success_artifacts(self):
        self.write('result.json', {'schema_version': 1, 'native_pair': 'FAIL', 'stage': 'finalized',
            'failed_stage': 'worker-1', 'error_type': 'BuildCancelled', 'cancelled': True,
            'cancel_signal': 'SIGTERM', 'error': POISON, 'publication': 'NOT ACCEPTED', 'hardware': 'NOT RUN'})
        record, output = self.project()
        self.assertEqual(record['projection'], 'PASS')
        result = json.loads((output / 'native-result.json').read_text())
        self.assertEqual(result['native_pair'], 'FAIL')
        self.assertTrue(result['cancelled'])
        self.assertEqual(result['failed_stage'], 'worker-1')
        self.assertNotIn('error', result)
        self.assertIn('comparison.json', record['missing'])

    def test_poison_env_logs_sources_binaries_never_scanned_or_exported(self):
        self.write('result.json', {'native_pair': 'FAIL', 'error': POISON, 'environment': {'TOKEN': POISON}})
        for path in ['cache/secrets.json', 'vendor/source.rs', 'inputs/raw-env.json', 'build.log', 'binary.pkg.tar.zst']:
            target = self.raw / path;target.parent.mkdir(parents=True, exist_ok=True);target.write_text(POISON)
        (self.raw / 'vendor/host-link').symlink_to('/etc')
        with patch.object(public, 'read_selected', wraps=public.read_selected) as reads:
            record, output = self.project()
        names = [call.args[1] for call in reads.call_args_list]
        self.assertNotIn('build.log', names)
        self.assertEqual({p.name for p in output.iterdir()}, {'native-result.json', 'projection.json'})
        self.assertNotIn(POISON, ''.join(p.read_text() for p in output.iterdir()))
        self.assertEqual(record['projection'], 'PASS')

    def test_cleanup_failure_types_and_flags_retained_prose_dropped(self):
        self.write('result.json', {'native_pair': 'FAIL', 'worker_cleanup_errors': [
            {'worker': 1, 'error_type': 'TimeoutExpired', 'error': POISON}]})
        self.write('build-1/provenance.json', {'native_compilation': 'FAIL-container-cleanup',
            'stage': 'finalized', 'failed_stage': 'container-cleanup', 'container_cleanup_error_type': 'TimeoutExpired',
            'container_cleanup_error': POISON, 'container_absence_error_type': 'ValueError',
            'worker_launch_attempted': True, 'container_cleanup_attempted': True, 'container_removal_succeeded': False,
            'container_absence_verified': False, 'container_cleanup_complete': False, 'command': [POISON]})
        _, output = self.project()
        result = json.loads((output / 'build-1-status.json').read_text())
        self.assertFalse(result['container_cleanup_complete'])
        self.assertEqual(result['container_cleanup_error_type'], 'TimeoutExpired')
        self.assertNotIn(POISON, ''.join(p.read_text() for p in output.iterdir()))

    def test_compiler_units_semantic_ids_features_only(self):
        self.write('build-1/artifacts/target-metadata/compilation-units.json', {'schema_version': 1,
            'compiler_artifacts': [{'package_id': 'registry+https://github.com/rust-lang/crates.io-index#gettext-sys@0.27.0',
                'features': ['gettext-system'], 'fresh': False, 'filenames': [POISON], 'executable': POISON,
                'profile': {'environment': POISON}, 'target': {'kind': ['lib'], 'crate_types': ['lib'], 'edition': '2015', 'src_path': POISON}}],
            'build_script_runs': [{'package_id': 'registry+https://github.com/rust-lang/crates.io-index#gettext-sys@0.27.0',
                                  'env': [['TOKEN', POISON]], 'out_dir': POISON, 'linked_paths': [POISON]}]})
        record, output = self.project()
        self.assertEqual(record['projection'], 'PASS')
        text = (output / 'build-1-compilation-units.json').read_text()
        self.assertIn('gettext-system', text)
        self.assertNotIn(POISON, text)
        self.assertNotIn('out_dir', text)

    def test_encoded_or_unknown_ids_features_statuses_refused_without_echo(self):
        for handler, value in [(public.cargo_identity, 'path+file:///home/secret#arch-update-tray@4.4.2'),
                               (public.feature, 'QmVhcmVyIHNlY3JldA'),
                               (public.feature, 'credential-value'), (public.native_result, {'native_pair': POISON})]:
            with self.subTest(value=value), self.assertRaises(public.Invalid):
                handler(value)

    def test_partial_valid_receipt_retained_when_another_is_malformed(self):
        self.write('result.json', {'native_pair': 'FAIL', 'error_type': 'ValueError'})
        self.write('build-1/provenance.json', {'native_compilation': POISON})
        record, output = self.project()
        self.assertEqual(record['projection'], 'FAIL')
        self.assertTrue((output / 'native-result.json').exists())
        self.assertEqual(record['rejected'], [{'receipt': 'build-1-status.json', 'reason': 'invalid-schema-or-file'}])
        self.assertNotIn(POISON, (output / 'projection.json').read_text())

    def test_validated_inventory_and_spurious_package_refused(self):
        name, version = sorted(public.INVENTORY_ROWS)[0]
        row = public.inventory(f'{name} {version}\n'.encode())
        self.assertEqual(row['packages'], [{'name': name, 'version': version}])
        with self.assertRaises(public.Invalid):
            public.inventory(b'fake-package 1.0\n')
        with self.assertRaises(public.Invalid):
            public.inventory(f'{name} {version}\n{name} {version}\n'.encode())

    def test_package_elf_metadata_without_payload_or_buildinfo_environment(self):
        self.write('build-1/package-validation.json', {'artifacts': [{'sha256': H, 'status': 'artifact-static-pass',
            'metadata': {'.PKGINFO': {'pkgname': ['cachy-asahi-update'], 'pkgver': ['4.4.2-1'], 'arch': ['aarch64'],
                'license': ['GPL-3.0-or-later', 'MIT'], 'packager': POISON}, '.BUILDINFO': {'buildenv': [POISON]}},
            'members': {POISON: {'sha256': H}}, 'elf': {'usr/lib/arch-update/arch-update-tray': {'machine': 183,
                'load_segments': 4, 'errors': [], 'hardware_status': 'NOT RUN'}}}], 'errors': []})
        record, output = self.project()
        self.assertEqual(record['projection'], 'PASS')
        text = (output / 'build-1-package.json').read_text()
        self.assertIn('183', text)
        self.assertNotIn(POISON, text)
        self.assertNotIn('members', text)

    def test_materializer_partial_cancelled_projection(self):
        materialized = self.root / 'materialized';materialized.mkdir()
        (materialized / 'materializer-result.json').write_text(json.dumps({'schema_version': 1,
            'status': 'CANCELLED', 'phase': 'fetch-registry', 'runner_inputs_sha256': H,
            'source_hashes': {'original': H, 'sanitized': H, 'vendor': H},
            'downloads': {'count': 3, 'bytes': 100}, 'error_type': 'KeyboardInterrupt',
            'error': POISON, 'public_export_policy': POISON, 'native_compilation': 'NOT RUN'}))
        output = self.root / 'projected'
        record = public.project_evidence(self.raw, output, materialized)
        self.assertEqual(record['projection'], 'PASS')
        projected = json.loads((output / 'materializer.json').read_text())
        self.assertEqual(projected['status'], 'CANCELLED')
        self.assertEqual(projected['downloads']['count'], 3)
        self.assertNotIn(POISON, (output / 'materializer.json').read_text())

    def test_acquisition_failure_identified_by_hash_not_untrusted_filename(self):
        self.write('acquisition.json', {'schema_version': 1, 'acquisition': 'FAIL', 'signature_authentication': 'NOT RUN',
            'counts': {'total': 1, 'pass': 0, 'fail': 1, 'pending': 0}, 'inputs': {POISON: {'status': 'FAIL',
                'expected_sha256': H, 'expected_bytes': 99, 'error_type': 'AcquisitionError', 'http_status': 404,
                'error': POISON, 'url': POISON}}})
        record, output = self.project()
        self.assertEqual(record['projection'], 'PASS')
        text = (output / 'acquisition.json').read_text()
        self.assertNotIn(POISON, text)
        self.assertIn('404', text)
        self.assertIn(H, text)

    def test_materializer_numeric_cancellation_and_failure_hashes(self):
        record = public.materializer({'schema_version': 1, 'status': 'CANCELLED', 'phase': 'regenerate-sanitized',
            'failure_code': 'sanitized-reproduction', 'cancel_signal': 15, 'error_type': 'Cancelled',
            'regenerated': {'sanitized_sha256': H}, 'generator': {'python': '3.14.7', 'zlib_build': '1.3.1.zlib-ng'}})
        self.assertEqual(record['cancel_signal'], 15)
        self.assertEqual(record['regenerated']['sanitized_sha256'], H)
        with self.assertRaises(public.Invalid):
            public.materializer({'generator': {'python': '1.2.QmVhcmVyIHNlY3JldA'}})

    def test_portable_materializer_receipt_projects_only_bounded_metadata(self):
        materialized = self.root / 'materialized';materialized.mkdir()
        receipt = {'schema_version': 1, 'status': 'PASS', 'phase': 'complete',
            'publication': 'NOT ACCEPTED', 'native_compilation': 'NOT RUN',
            'regenerated': {'sanitized_sha256': H, 'vendor_sha256': H,
                'sanitized_tar_sha256': 'b' * 64, 'vendor_tar_sha256': 'c' * 64,
                'vendor_bytes': 323117000, 'registry_sources': 167, 'private_source': POISON},
            'limits': {'file_bytes': 512 * 1024**2},
            'generator': {'python': '3.14.8', 'transport': 'gzip-stored-v1', 'environment': POISON}}
        (materialized / 'materializer-result.json').write_text(json.dumps(receipt))
        record = public.project_evidence(self.raw, self.root / 'projected', materialized)
        self.assertEqual(record['projection'], 'PASS')
        projected = json.loads((self.root / 'projected/materializer.json').read_text())
        self.assertEqual(projected['regenerated']['vendor_bytes'], 323117000)
        self.assertEqual(projected['regenerated']['vendor_tar_sha256'], 'c' * 64)
        self.assertEqual(projected['regenerated']['sanitized_tar_sha256'], 'b' * 64)
        self.assertEqual(projected['generator']['transport'], 'gzip-stored-v1')
        self.assertNotIn(POISON, json.dumps(projected))

    def test_portable_caps_unknown_transport_and_tar_hash_refused(self):
        cap = 512 * 1024**2
        self.assertEqual(public.materializer({'regenerated': {'vendor_bytes': cap},
                                              'limits': {'file_bytes': cap}}),
                         {'regenerated': {'vendor_bytes': cap}, 'limits': {'file_bytes': cap}})
        for invalid in ({'regenerated': {'vendor_bytes': cap + 1}},
                        {'limits': {'file_bytes': cap + 1}},
                        {'regenerated': {'vendor_bytes': True}},
                        {'generator': {'transport': 'gzip-unknown-v2'}},
                        {'generator': {'transport': POISON}},
                        {'regenerated': {'vendor_tar_sha256': POISON}},
                        {'regenerated': {'sanitized_tar_sha256': 'a' * 63}}):
            with self.subTest(value=invalid), self.assertRaises(public.Invalid):
                public.materializer(invalid)

    def test_historical_materializer_projection_needs_no_transport_or_tar_hash(self):
        receipt = {'schema_version': 1, 'status': 'PASS', 'phase': 'complete',
            'regenerated': {'sanitized_sha256': H, 'vendor_sha256': H,
                            'vendor_bytes': 46238716, 'registry_sources': 167},
            'limits': {'file_bytes': 134217728},
            'generator': {'python': '3.14.7', 'zlib_build': '1.3.1.zlib-ng', 'zlib_runtime': '1.3.1.zlib-ng'}}
        self.assertEqual(public.materializer(receipt), receipt)

    def test_portable_recipe_filenames_are_explicit_hash_only_allowlist(self):
        names = {'portable-gzip.py', 'test-portable-gzip.py',
                 'fixtures/native-arm-reviewed.py', 'transport-revision.json'}
        self.assertTrue(names <= public.RECIPE_FILES)
        hashes = {name: H for name in names}
        self.assertEqual(public.recipe_hashes(hashes), hashes)
        self.assertEqual(public.recipe_hashes({'fixtures/native-arm-original.py': H}),
                         {'fixtures/native-arm-original.py': H})
        for name in ('portable-unreviewed.py', 'fixtures/native-arm-unknown.py', '../portable-gzip.py'):
            with self.subTest(name=name), self.assertRaises(public.Invalid):
                public.recipe_hashes({name: H})

    def test_json_duplicates_bool_numbers_symlinks_hardlinks_and_budget_refused(self):
        with self.assertRaises(public.Invalid):public.load(b'{"native_pair":"PASS","native_pair":"FAIL"}')
        with self.assertRaises(public.Invalid):public.integer()(True)
        self.write('result.json', {'native_pair': 'FAIL'})
        (self.raw / 'comparison.json').symlink_to(self.raw / 'result.json')
        os.link(self.raw / 'result.json', self.raw / 'linked')
        record, _ = self.project()
        self.assertEqual(record['projection'], 'FAIL')
        self.assertEqual(len(record['accepted']), 0)
        self.assertEqual(len(record['rejected']), 2)

    def test_read_budget_and_no_output_reuse(self):
        self.write('result.json', {'native_pair': 'FAIL'})
        with patch.object(public, 'TOTAL_INPUT_LIMIT', 1):
            result, output = self.project()
        self.assertEqual(result['projection'], 'FAIL')
        with self.assertRaises(FileExistsError):public.project_evidence(self.raw, output)

    def test_unchanged_generic_credential_guard_accepts_projection(self):
        spec = importlib.util.spec_from_file_location('generic_export', BASE.parents[2] / 'scripts/ci/integration_export.py')
        generic = importlib.util.module_from_spec(spec);spec.loader.exec_module(generic)
        self.write('result.json', {'native_pair': 'FAIL', 'error': POISON})
        _, projected = self.project()
        record = generic.export_evidence(projected, self.root / 'public')
        self.assertEqual(record['evidence_export'], 'PASS')
        poisoned = self.root / 'poisoned';poisoned.mkdir()
        (poisoned / 'bad.json').write_text(json.dumps({'token': 'credential-value'}))
        rejected = generic.export_evidence(poisoned, self.root / 'blocked')
        self.assertEqual(rejected['evidence_export'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
