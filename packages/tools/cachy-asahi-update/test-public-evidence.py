#!/usr/bin/env python3
"""Receipt projection tests; temp data only, no build/container operations."""
import importlib.util
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('public_evidence', BASE / 'public-evidence.py')
public = importlib.util.module_from_spec(spec)
spec.loader.exec_module(public)
H = 'a' * 64
POISON = 'Bearer TOP_SECRET_PASSWORD api_key=credential-value'
WORKER_FIELDS = ('worker_run_returncode', 'worker_check', 'worker_failure_code', 'worker_container_state')


def observed_worker(code=0):
    return {'schema_version': 1, 'native_compilation': 'FAIL',
            'image_id': 'sha256:' + H, 'controller_sha256': 'b' * 64,
            'worker_run_returncode': code, 'worker_check': 'worker-run-result',
            'worker_failure_code': None, 'worker_container_state': {
                'schema_version': 1, 'container_id': 'c' * 64, 'image_id': 'sha256:' + H,
                'controller_sha256': 'b' * 64, 'name_sha256': 'd' * 64, 'nonce_sha256': 'e' * 64,
                'status': 'exited', 'running': False, 'paused': False, 'restarting': False,
                'dead': False, 'oom_killed': False, 'state_error_present': False, 'exit_code': 0}}


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

    def test_historical_failure_cli_retains_no_new_observation_claim(self):
        value = {'schema_version': 1, 'native_compilation': 'FAIL',
                 'stage': 'finalized', 'failed_stage': 'worker-inspection',
                 'worker_launch_attempted': True, 'error_type': 'ValueError',
                 'cancelled': False, 'error': POISON}
        self.write('build-1/provenance.json', value)
        output = self.root / 'cli-public'
        result = subprocess.run([sys.executable, '-B', str(BASE / 'public-evidence.py'),
                                 '--raw', str(self.raw), '--output', str(output)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        projected = json.loads((output / 'build-1-status.json').read_text())
        self.assertEqual(projected, {key: item for key, item in value.items() if key != 'error'})
        self.assertFalse(any(key.startswith('worker_') and key != 'worker_launch_attempted'
                             for key in projected))
        self.assertNotIn(POISON, result.stdout + result.stderr +
                         ''.join(path.read_text() for path in output.iterdir()))

    def test_parent_observation_preserves_actual_state_without_compiler_inference(self):
        value = observed_worker(137)
        value['worker_failure_code'] = 'worker-nonzero-returncode'
        projected = public.provenance(value)
        self.assertEqual(projected, value)
        self.assertFalse(projected['worker_container_state']['oom_killed'])
        self.assertEqual(projected['worker_container_state']['exit_code'], 0)
        self.assertNotIn('compiler_invocation', projected)
        value['worker_run_returncode'] = 1
        value['worker_container_state']['oom_killed'] = True
        value['worker_container_state']['exit_code'] = 137
        self.assertEqual(public.provenance(value), value)

    def test_typed_worker_observation_failure_remains_projectable(self):
        value = observed_worker(1)
        value.update(worker_failure_code='worker-nonzero-returncode', error_type='ValueError')
        self.assertEqual(public.provenance(value), value)
        value['error_type'] = 'WorkerObservationError'
        with self.assertRaises(public.Invalid):public.provenance(value)

    def test_parent_observation_complete_is_not_native_compilation_pass(self):
        value = observed_worker()
        value['worker_check'] = 'complete'
        self.assertEqual(public.provenance(value), value)
        self.assertEqual(public.provenance(value)['native_compilation'], 'FAIL')
        for update in ({'worker_failure_code': 'worker-nonzero-returncode'},
                       {'worker_run_returncode': 1}):
            broken = copy.deepcopy(value);broken.update(update)
            with self.subTest(update=update), self.assertRaises(public.Invalid):
                public.provenance(broken)
        for key, item in [('status', 'running'), ('exit_code', 1),
                          ('running', True), ('paused', True), ('restarting', True),
                          ('dead', True), ('oom_killed', True), ('state_error_present', True)]:
            broken = copy.deepcopy(value);broken['worker_container_state'][key] = item
            with self.subTest(key=key), self.assertRaises(public.Invalid):
                public.provenance(broken)

    def test_worker_observation_group_requires_all_four_fields(self):
        value = observed_worker()
        for mask in range(1, 15):
            broken = {key: item for key, item in value.items() if key not in WORKER_FIELDS}
            broken.update({key: value[key] for number, key in enumerate(WORKER_FIELDS) if mask & (1 << number)})
            with self.subTest(mask=mask), self.assertRaises(public.Invalid):
                public.provenance(broken)

    def test_worker_client_returncode_exact_types_bounds_and_truthful_null(self):
        for code in (None, -64, -15, 0, 125, 137, 255):
            value = observed_worker(code);value['worker_container_state'] = None
            value['worker_check'] = 'worker-run'
            self.assertEqual(public.provenance(value)['worker_run_returncode'], code)
        for code in (True, False, -65, 256, 1.0, '137', [], {}, POISON):
            value = observed_worker(code);value['worker_container_state'] = None
            value['worker_check'] = 'worker-run'
            with self.subTest(code=code), self.assertRaises(public.Invalid):
                public.provenance(value)

    def test_worker_not_started_requires_truthful_empty_observations(self):
        value = observed_worker(None)
        value.update(worker_check='not-started', worker_container_state=None)
        self.assertEqual(public.provenance(value), value)
        for key, item in [('worker_run_returncode', 0), ('worker_failure_code', 'worker-run-failed'),
                          ('worker_container_state', observed_worker()['worker_container_state'])]:
            broken = copy.deepcopy(value);broken[key] = item
            with self.subTest(key=key), self.assertRaises(public.Invalid):
                public.provenance(broken)

    def test_worker_state_closed_shape_and_scalar_type_poison_refused(self):
        value = observed_worker()
        state = value['worker_container_state']
        for key in state:
            broken = copy.deepcopy(value);del broken['worker_container_state'][key]
            with self.subTest(missing=key), self.assertRaises(public.Invalid):
                public.provenance(broken)
        for key in ('Env', 'Name', 'nonce', 'Error', 'raw_inspect', POISON):
            broken = copy.deepcopy(value);broken['worker_container_state'][key] = POISON
            with self.subTest(extra=key), self.assertRaises(public.Invalid):
                public.provenance(broken)
        invalid = {'schema_version': (True, 0, 2, 1.0),
                   'container_id': (None, 'c' * 63, 'C' * 64, POISON),
                   'image_id': (H, 'sha256:' + 'A' * 64, POISON),
                   'controller_sha256': (None, 'b' * 63, POISON),
                   'name_sha256': (None, POISON), 'nonce_sha256': (None, POISON),
                   'status': (None, True, 'oom-killed', POISON),
                   'exit_code': (None, True, False, -1, 256, 137.0, '137')}
        invalid.update({key: (None, 0, 1, 'true', [], {}) for key in
                        ('running', 'paused', 'restarting', 'dead', 'oom_killed', 'state_error_present')})
        for key, values in invalid.items():
            for item in values:
                broken = copy.deepcopy(value);broken['worker_container_state'][key] = item
                with self.subTest(key=key, item=item), self.assertRaises(public.Invalid):
                    public.provenance(broken)

    def test_worker_state_image_controller_binding_and_observation_phase_required(self):
        value = observed_worker()
        for key in ('image_id', 'controller_sha256'):
            broken = copy.deepcopy(value);del broken[key]
            with self.subTest(missing=key), self.assertRaises(public.Invalid):
                public.provenance(broken)
            broken = copy.deepcopy(value)
            broken[key] = ('sha256:' if key == 'image_id' else '') + 'f' * 64
            with self.subTest(mismatch=key), self.assertRaises(public.Invalid):
                public.provenance(broken)
        for check in ('not-started', 'worker-run'):
            broken = copy.deepcopy(value);broken['worker_check'] = check
            with self.subTest(check=check), self.assertRaises(public.Invalid):
                public.provenance(broken)
        broken = copy.deepcopy(value);broken['worker_run_returncode'] = None
        with self.assertRaises(public.Invalid):public.provenance(broken)

    def test_worker_fixed_checks_failure_codes_and_phase_mismatch(self):
        phases = {
            'worker-run': ('worker-run-launch-failed', 'worker-run-timeout', 'worker-run-cancelled',
                           'worker-run-failed', 'worker-returncode-invalid'),
            'container-inspection': ('inspection-launch-failed', 'inspection-command-failed',
                'inspection-timeout', 'inspection-output-limit', 'inspection-json-invalid',
                'inspection-schema-invalid', 'inspection-identity-mismatch', 'inspection-id-drift',
                'inspection-state-invalid', 'inspection-cancelled', 'inspection-io-failed', 'inspection-cleanup-failed'),
            'worker-run-result': ('worker-nonzero-returncode', 'worker-container-state-unaccepted'),
            'worker-inventory': ('worker-inventory-unavailable', 'worker-inventory-mismatch', 'worker-observation-cancelled'),
            'worker-artifact-shape': ('worker-output-symlink', 'worker-output-observation-failed', 'worker-observation-cancelled')}
        for phase, codes in phases.items():
            for code in codes:
                value = observed_worker(1)
                value.update(worker_check=phase, worker_failure_code=code)
                if phase in ('worker-run', 'container-inspection'):
                    value['worker_container_state'] = None
                if code == 'worker-returncode-invalid':value['worker_run_returncode'] = None
                if phase in ('worker-inventory', 'worker-artifact-shape'):
                    value['worker_run_returncode'] = 0
                if code == 'worker-container-state-unaccepted':
                    value['worker_run_returncode'] = 0
                    value['worker_container_state']['oom_killed'] = True
                self.assertEqual(public.provenance(value), value)
                broken = copy.deepcopy(value);broken['worker_check'] = 'complete'
                with self.subTest(code=code), self.assertRaises(public.Invalid):
                    public.provenance(broken)
        for key in ('worker_check', 'worker_failure_code'):
            for item in (True, 1, [], {}, POISON, 'unknown'):
                value = observed_worker();value[key] = item
                with self.subTest(key=key, item=item), self.assertRaises(public.Invalid):
                    public.provenance(value)

    def test_worker_failure_observations_cannot_contradict_completed_prior_checks(self):
        cases = []
        value = observed_worker();value['worker_failure_code'] = 'worker-nonzero-returncode';cases.append(value)
        value = observed_worker(1);value['worker_failure_code'] = 'worker-container-state-unaccepted';cases.append(value)
        value = observed_worker();value['worker_failure_code'] = 'worker-container-state-unaccepted';cases.append(value)
        value = observed_worker(1)
        value.update(worker_check='worker-run', worker_failure_code='worker-returncode-invalid', worker_container_state=None)
        cases.append(value)
        for phase in ('worker-run-result', 'worker-inventory', 'worker-artifact-shape', 'complete'):
            value = observed_worker();value.update(worker_check=phase, worker_container_state=None);cases.append(value)
        for phase in ('worker-inventory', 'worker-artifact-shape'):
            value = observed_worker(1);value['worker_check'] = phase;cases.append(value)
            value = observed_worker();value['worker_check'] = phase
            value['worker_container_state']['oom_killed'] = True;cases.append(value)
        for number, value in enumerate(cases):
            with self.subTest(case=number), self.assertRaises(public.Invalid):
                public.provenance(value)

    def test_native_pass_with_observations_requires_complete_parent_checks(self):
        for status in ('PASS', 'PASS-private-native-package-static-checks'):
            historical = {'native_compilation': status}
            self.assertEqual(public.provenance(historical), historical)
            value = observed_worker();value.update(native_compilation=status, worker_check='complete')
            self.assertEqual(public.provenance(value), value)
            for phase in ('worker-run-result', 'worker-inventory', 'worker-artifact-shape'):
                broken = copy.deepcopy(value);broken['worker_check'] = phase
                with self.subTest(status=status, phase=phase), self.assertRaises(public.Invalid):
                    public.provenance(broken)
            broken = observed_worker(125)
            broken.update(native_compilation=status, worker_failure_code='worker-nonzero-returncode')
            with self.subTest(status=status, case='actual-regression'), self.assertRaises(public.Invalid):
                public.provenance(broken)

    def test_unattempted_worker_launch_refuses_later_observation_phases(self):
        value = observed_worker(None)
        value.update(worker_launch_attempted=False, worker_check='not-started', worker_container_state=None)
        self.assertEqual(public.provenance(value), value)
        self.assertEqual(public.provenance({'native_compilation': 'FAIL', 'worker_launch_attempted': False}),
                         {'native_compilation': 'FAIL', 'worker_launch_attempted': False})
        for phase in ('worker-run', 'container-inspection', 'worker-run-result',
                      'worker-inventory', 'worker-artifact-shape', 'complete'):
            broken = observed_worker();broken.update(worker_launch_attempted=False, worker_check=phase)
            if phase in ('worker-run', 'container-inspection'):broken['worker_container_state'] = None
            with self.subTest(phase=phase), self.assertRaises(public.Invalid):
                public.provenance(broken)

    def test_cancelled_observation_cannot_claim_native_success(self):
        value = observed_worker();value.update(worker_check='complete', cancelled=True, cancel_signal='SIGTERM')
        self.assertEqual(public.provenance(value), value)
        for status in ('PASS', 'PASS-private-native-package-static-checks'):
            broken = copy.deepcopy(value);broken['native_compilation'] = status
            with self.subTest(status=status), self.assertRaises(public.Invalid):
                public.provenance(broken)

    def test_worker_observation_full_cli_accepts_only_bounded_actual_scalars(self):
        value = observed_worker(137)
        value.update(worker_failure_code='worker-nonzero-returncode',
                     error=POISON, command=[POISON], environment={'TOKEN': POISON},
                     raw_inspect={'Config': {'Env': [POISON]}, 'Name': '/private/' + POISON})
        self.write('build-1/provenance.json', value)
        output = self.root / 'cli-public'
        result = subprocess.run([sys.executable, '-B', str(BASE / 'public-evidence.py'),
                                 '--raw', str(self.raw), '--output', str(output)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        projected = json.loads((output / 'build-1-status.json').read_text())
        self.assertEqual(projected, observed_worker(137) | {'worker_failure_code': 'worker-nonzero-returncode'})
        self.assertFalse(projected['worker_container_state']['oom_killed'])
        all_text = result.stdout + result.stderr + ''.join(path.read_text() for path in output.iterdir())
        for secret in (POISON, 'TOKEN', 'raw_inspect', 'Config', 'Env', '/private/'):
            self.assertNotIn(secret, all_text)

    def test_worker_observation_full_cli_refuses_poison_without_echo(self):
        value = observed_worker()
        value['worker_container_state']['oom_killed'] = POISON
        value['error'] = POISON
        self.write('build-1/provenance.json', value)
        self.write('result.json', {'native_pair': 'FAIL'})
        output = self.root / 'cli-public'
        result = subprocess.run([sys.executable, '-B', str(BASE / 'public-evidence.py'),
                                 '--raw', str(self.raw), '--output', str(output)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertFalse((output / 'build-1-status.json').exists())
        manifest = json.loads((output / 'projection.json').read_text())
        self.assertEqual(manifest['rejected'], [{'receipt': 'build-1-status.json', 'reason': 'invalid-schema-or-file'}])
        self.assertNotIn(POISON, result.stdout + result.stderr +
                         ''.join(path.read_text() for path in output.iterdir()))

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
