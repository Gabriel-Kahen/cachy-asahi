#!/usr/bin/env python3
"""Receipt projection tests; temp data only, no build/container operations."""
import ast
import re
import importlib.util
import copy
import hashlib
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
            'metadata': {'.PKGINFO': {'pkgname': ['cachy-asahi-update'], 'pkgver': ['4.4.2-2'], 'arch': ['aarch64'],
                'license': ['GPL-3.0-or-later', 'MIT'], 'packager': POISON}, '.BUILDINFO': {'buildenv': [POISON]}},
            'members': {POISON: {'sha256': H}}, 'elf': {'usr/lib/arch-update/arch-update-tray': {'machine': 183,
                'load_segments': 4, 'errors': [], 'hardware_status': 'NOT RUN'}}}], 'errors': []})
        record, output = self.project()
        self.assertEqual(record['projection'], 'PASS')
        text = (output / 'build-1-package.json').read_text()
        self.assertIn('183', text)
        self.assertNotIn(POISON, text)
        self.assertNotIn('members', text)

    def test_package_projection_refuses_previous_recipe_version(self):
        with self.assertRaises(public.Invalid):
            public.package_validation({'artifacts': [{'sha256': H, 'status': 'artifact-static-pass',
                'metadata': {'.PKGINFO': {'pkgname': ['cachy-asahi-update'], 'pkgver': ['4.4.2-1']}}}]})

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


class DiagnosticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('public_test_diagnostic', BASE / 'worker-diagnostic.py')
        cls.helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.helper)

    def record(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); root.chmod(0o700)
            recorder = self.helper.Recorder(root, {'controller_sha256': 'b' * 64,
                'image_id': 'sha256:' + H, 'entry_script_sha256': 'f' * 64})
            recorder.fail('source-pins', ValueError(POISON))
            return recorder.snapshot()

    def test_closed_schema_matches_helper_and_proposal(self):
        for name in ('OPERATIONS', 'PREDICATES', 'COMMANDS', 'ERROR_KINDS', 'FIELDS', 'LIMIT', 'LOG_LIMIT'):
            self.assertEqual(getattr(public, 'DIAGNOSTIC_' + name), getattr(self.helper, name))
        value = self.record()
        self.assertEqual(public.diagnostic(value), value)
        self.assertLessEqual(len(public.diagnostic_encoded(value)), 4096)
        self.assertNotIn(POISON, json.dumps(value))

    def test_parent_binds_actual_launch_and_observed_container(self):
        value = self.record(); state = observed_worker()['worker_container_state']
        kwargs = dict(controller_sha256='b' * 64, image_id='sha256:' + H,
                      entry_script_sha256='f' * 64, observed_state=state)
        self.assertEqual(public.bound_worker_diagnostic(value, **kwargs), value)
        for key, replacement in [('controller_sha256', '0' * 64),
                ('image_id', 'sha256:' + '0' * 64), ('entry_script_sha256', '0' * 64)]:
            changed = kwargs | {key: replacement}
            with self.subTest(key=key), self.assertRaises(ValueError):
                public.bound_worker_diagnostic(value, **changed)
        for key in ('controller_sha256', 'image_id'):
            changed = copy.deepcopy(state); changed[key] = ('sha256:' if key == 'image_id' else '') + '0' * 64
            with self.subTest(state=key), self.assertRaises(ValueError):
                public.bound_worker_diagnostic(value, **(kwargs | {'observed_state': changed}))

    def test_unbound_startup_is_finite_but_not_parent_bound(self):
        value = self.record(); value['controller_sha256'] = None
        self.assertEqual(public.diagnostic(value), value)
        with self.assertRaises(ValueError):
            public.bound_worker_diagnostic(value, controller_sha256='b' * 64,
                image_id='sha256:' + H, entry_script_sha256='f' * 64,
                observed_state=observed_worker()['worker_container_state'])
        value['controller_validated'] = True
        with self.assertRaises(ValueError): public.diagnostic(value)

    def test_unknown_text_and_boolean_numbers_are_refused(self):
        value = self.record()
        changes = [('schema_version', True), ('operation', POISON), ('status', POISON),
                   ('compiler_returncode', True), ('extra', POISON)]
        for key, item in changes:
            changed = copy.deepcopy(value); changed[key] = item
            with self.subTest(key=key), self.assertRaises(ValueError): public.diagnostic(changed)
        for key in ('predicate', 'error_kind'):
            changed = copy.deepcopy(value); changed['first_failure'][key] = POISON
            with self.subTest(failure=key), self.assertRaises(ValueError): public.diagnostic(changed)

    def test_cancelled_status_requires_flag_even_with_ordinary_first_failure(self):
        value = self.record()
        self.assertEqual(value['first_failure']['error_kind'], 'ValueError')
        value.update(status='CANCELLED', cancelled=False)
        kwargs = dict(controller_sha256='b' * 64, image_id='sha256:' + H,
            entry_script_sha256='f' * 64, observed_state=observed_worker()['worker_container_state'])
        for validator in (self.helper.validate, public.diagnostic,
                lambda record: public.bound_worker_diagnostic(record, **kwargs)):
            with self.subTest(validator=validator), self.assertRaises(ValueError): validator(value)
        first = copy.deepcopy(value['first_failure'])
        value['cancelled'] = True
        self.assertEqual(self.helper.validate(value), value)
        self.assertEqual(public.bound_worker_diagnostic(value, **kwargs), value)
        self.assertEqual(value['first_failure'], first)

    def test_compiler_attempt_return_acceptance_are_distinct(self):
        value = self.record(); value['compiler_launch_attempted'] = True
        self.assertEqual(public.diagnostic(value), value)
        for changes in ({'compilation_accepted': True}, {'compiler_return_observed': True},
                        {'compiler_returncode': 0}, {'compiler_returncode': -65, 'compiler_return_observed': True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                public.diagnostic(value | changes)
        value.update(compiler_return_observed=True, compiler_returncode=0, compilation_accepted=True)
        self.assertEqual(public.diagnostic(value), value)
        self.assertEqual(value['status'], 'FAIL')

    def test_only_fixed_diagnostic_selectors_and_bounded_data_are_exported(self):
        selectors = [row for row in public.selectors() if row[2] is public.diagnostic]
        self.assertEqual([(row[0], row[1]) for row in selectors], [
            ('build-1/artifacts/worker-diagnostic.json', 'build-1-diagnostic.json'),
            ('build-2/artifacts/worker-diagnostic.json', 'build-2-diagnostic.json')])
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); raw = root / 'raw'; folder = raw / 'build-1/artifacts'
            folder.mkdir(parents=True); value = self.record()
            (folder / 'worker-diagnostic.json').write_text(json.dumps(value))
            (folder / 'makepkg.stderr').write_text(POISON)
            result = public.project_evidence(raw, root / 'public')
            self.assertEqual(result['projection'], 'PASS')
            exported = (root / 'public/build-1-diagnostic.json').read_bytes()
            self.assertNotIn(POISON.encode(), exported)
            self.assertEqual(json.loads(exported), value)
            self.assertFalse((root / 'public/makepkg.stderr').exists())
            (folder / 'worker-diagnostic.json').write_bytes(b' ' * 4097)
            result = public.project_evidence(raw, root / 'refused')
            self.assertEqual(result['projection'], 'FAIL')
            self.assertFalse((root / 'refused/build-1-diagnostic.json').exists())

    def test_diagnostic_failure_cannot_forge_success_or_export_opaque_fields(self):
        value = self.record()
        with self.assertRaises(ValueError): public.diagnostic(value | {'status': 'PASS'})
        value['first_failure']['command'] = {'kind': 'cargo-build', 'launch_attempted': True,
            'return_observed': False, 'returncode': None, 'stdout': {'bytes': 1, 'sha256': H}, 'stderr': None}
        self.assertEqual(public.diagnostic(value), value)
        value['first_failure']['command']['stdout']['path'] = POISON
        with self.assertRaises(ValueError): public.diagnostic(value)


class ParentDiagnosticTests(unittest.TestCase):
    """Synthetic provenance plus real finite Recorder; no native actors."""
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('parent_test_diagnostic', BASE / 'worker-diagnostic.py')
        cls.helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.helper)

    def record(self, success=False):
        with tempfile.TemporaryDirectory() as temp:
            recorder = self.helper.Recorder(Path(temp), {'controller_sha256': 'b' * 64,
                'image_id': 'sha256:' + H, 'entry_script_sha256': 'f' * 64})
            recorder.controller_validated()
            if success:
                recorder.command_start('cargo-build')
                recorder.command_result('cargo-build', True, True, 0)
                recorder.compiler_accepted(); recorder.finish(True)
            else:
                recorder.fail('source-pins', ValueError(POISON))
            return recorder.snapshot()

    def bound(self, success=False):
        value = observed_worker(0 if success else 1)
        value.update(worker_launch_attempted=True, entry_script_sha256='f' * 64,
            worker_diagnostic_status='BOUND', worker_diagnostic_reason='bound')
        value['worker_container_state']['exit_code'] = value['worker_run_returncode']
        record = self.record(success)
        # Preserve the hash of original private bytes, including their formatting.
        value['worker_diagnostic_sha256'] = hashlib.sha256(json.dumps(record, indent=2).encode()).hexdigest()
        value['worker_diagnostic'] = record
        if success:
            value.update(worker_check='complete', native_compilation='PASS-private-native-package-static-checks')
        else:
            value['worker_failure_code'] = 'worker-nonzero-returncode'
        return value

    def test_historical_absent_group_remains_valid_without_new_claims(self):
        for success in (False, True):
            value = observed_worker()
            if success: value.update(worker_check='complete', native_compilation='PASS')
            self.assertEqual(public.provenance(value), value)
            self.assertEqual(public.worker_diagnostic_observation(value), {})

    def test_parent_group_is_all_or_none(self):
        value = self.bound(); fields = sorted(public.WORKER_DIAGNOSTIC_FIELDS)
        for mask in range(1, 15):
            changed = {key:item for key,item in value.items() if key not in fields}
            changed.update({key:value[key] for index,key in enumerate(fields) if mask & (1 << index)})
            with self.subTest(mask=mask), self.assertRaises(public.Invalid): public.provenance(changed)

    def test_not_observed_requires_not_started_empty_group(self):
        value = observed_worker(None)
        value.update(worker_check='not-started', worker_container_state=None, worker_launch_attempted=False,
            worker_diagnostic_status='NOT OBSERVED', worker_diagnostic_reason='not-started',
            worker_diagnostic_sha256=None, worker_diagnostic=None)
        self.assertEqual(public.provenance(value), value)
        for changes in ({'worker_launch_attempted':True}, {'worker_diagnostic_reason':'missing'},
                        {'worker_diagnostic_sha256':H}, {'worker_diagnostic':self.record()}):
            with self.subTest(changes=changes), self.assertRaises(public.Invalid): public.provenance(value | changes)

    def test_unknown_retains_only_finite_reason_and_nullable_original_hash(self):
        value = self.bound()
        value.update(worker_diagnostic_status='UNKNOWN', worker_diagnostic=None)
        for reason in ('state-unavailable','missing','unavailable','source-invalid','invalid','unbound'):
            for checksum in (None,H):
                changed = value | {'worker_diagnostic_reason':reason,'worker_diagnostic_sha256':checksum}
                self.assertEqual(public.provenance(changed), changed)
        for changes in ({'worker_diagnostic_reason':'bound'}, {'worker_diagnostic_reason':'not-started'},
                        {'worker_diagnostic_reason':POISON}, {'worker_diagnostic':self.record()},
                        {'worker_diagnostic_sha256':True}, {'worker_diagnostic_sha256':POISON}):
            with self.subTest(changes=changes), self.assertRaises(public.Invalid): public.provenance(value | changes)

    def test_bound_failure_is_diagnosis_and_does_not_imply_success(self):
        value = self.bound()
        self.assertEqual(public.provenance(value), value)
        self.assertFalse(public.accepted_worker_diagnostic(value['worker_diagnostic']))
        self.assertEqual(value['worker_diagnostic']['first_failure']['predicate'], 'source-pins')
        self.assertNotEqual(value['worker_diagnostic_sha256'], hashlib.sha256(public.diagnostic_encoded(value['worker_diagnostic'])).hexdigest())
        self.assertNotIn(POISON, json.dumps(public.provenance(value)))
        # A completed compiler can still be followed by an entry/package failure.
        value['worker_diagnostic'].update(compiler_launch_attempted=True,
            compiler_return_observed=True, compiler_returncode=0, compilation_accepted=True)
        self.assertEqual(public.provenance(value), value)
        self.assertFalse(public.accepted_worker_diagnostic(value['worker_diagnostic']))

    def test_parent_refuses_cancellation_contradiction_without_erasing_first_cause(self):
        value = self.bound()
        first = copy.deepcopy(value['worker_diagnostic']['first_failure'])
        value['worker_diagnostic'].update(status='CANCELLED', cancelled=False)
        with self.assertRaises(public.Invalid): public.worker_diagnostic_observation(value)
        with self.assertRaises(public.Invalid): public.provenance(value)
        value['worker_diagnostic']['cancelled'] = True
        self.assertEqual(public.provenance(value), value)
        self.assertEqual(value['worker_diagnostic']['first_failure'], first)
        self.assertFalse(public.accepted_worker_diagnostic(value['worker_diagnostic']))

    def test_later_cancellation_keeps_issued_business_failure_through_parent_binding(self):
        with tempfile.TemporaryDirectory() as temp:
            recorder = self.helper.Recorder(Path(temp), {'controller_sha256':'b'*64,
                'image_id':'sha256:'+H, 'entry_script_sha256':'f'*64})
            with recorder.step('compile-copy'):
                recorder.fail('compile-binary-drift', OSError(POISON))
            first = copy.deepcopy(recorder.snapshot()['first_failure'])
            recorder.fail('UNKNOWN', KeyboardInterrupt())
            record = recorder.snapshot()
            self.assertTrue(record['cancelled'])
            self.assertEqual(record['first_failure'], first)
            self.assertEqual(self.helper.validate(record), record)
            value = self.bound(); value['worker_diagnostic'] = record
            self.assertEqual(public.provenance(value), value)
            self.assertEqual(public.provenance(value)['worker_diagnostic']['first_failure'], first)
            self.assertNotIn(POISON, json.dumps(public.provenance(value)))

    def test_bound_requires_original_launch_full_state_and_three_matching_bindings(self):
        value = self.bound()
        for key in ('controller_sha256','image_id','entry_script_sha256'):
            for location in ('parent','diagnostic'):
                changed = copy.deepcopy(value)
                target = changed if location == 'parent' else changed['worker_diagnostic']
                target[key] = ('sha256:' if key == 'image_id' else '') + '0'*64
                with self.subTest(key=key, location=location), self.assertRaises(public.Invalid): public.provenance(changed)
        for changes in ({'worker_launch_attempted':False}, {'worker_container_state':None},
                        {'worker_diagnostic_sha256':None}, {'worker_diagnostic_reason':'unbound'}):
            with self.subTest(changes=changes), self.assertRaises(public.Invalid): public.provenance(value | changes)
        for key in ('controller_sha256','image_id'):
            changed = copy.deepcopy(value)
            changed['worker_container_state'][key] = ('sha256:' if key == 'image_id' else '') + '0'*64
            with self.subTest(state=key), self.assertRaises(public.Invalid): public.provenance(changed)
        for key in WORKER_FIELDS:
            changed = copy.deepcopy(value); del changed[key]
            with self.subTest(missing=key), self.assertRaises(public.Invalid): public.provenance(changed)

    def test_modern_success_requires_complete_bound_compiler_acceptance(self):
        value = self.bound(True)
        self.assertEqual(public.provenance(value), value)
        self.assertTrue(public.accepted_worker_diagnostic(value['worker_diagnostic']))
        for key, item in [('controller_validated',False), ('status','RUNNING'),
                ('compiler_launch_attempted',False), ('compiler_return_observed',False),
                ('compiler_returncode',None), ('compilation_accepted',False),
                ('cancelled',True), ('diagnostic_write_failed',True)]:
            changed = copy.deepcopy(value); changed['worker_diagnostic'][key] = item
            with self.subTest(key=key), self.assertRaises(public.Invalid): public.provenance(changed)
        changed = copy.deepcopy(value); changed.update(worker_diagnostic_status='UNKNOWN',
            worker_diagnostic_reason='missing', worker_diagnostic=None, worker_diagnostic_sha256=None)
        with self.assertRaises(public.Invalid): public.provenance(changed)
        changed = copy.deepcopy(value); changed['worker_diagnostic'] = self.record()
        with self.assertRaises(public.Invalid): public.provenance(changed)

    def test_diagnostic_gate_failure_requires_zero_successful_worker_return_state(self):
        value = self.bound(True)
        value.update(worker_check='worker-diagnostic', worker_failure_code='worker-diagnostic-incomplete', native_compilation='FAIL',
            worker_diagnostic_status='UNKNOWN', worker_diagnostic_reason='missing', worker_diagnostic_sha256=None, worker_diagnostic=None)
        self.assertEqual(public.provenance(value), value)
        for changes in ({'worker_run_returncode':1}, {'worker_failure_code':'worker-nonzero-returncode'}):
            with self.subTest(changes=changes), self.assertRaises(public.Invalid): public.provenance(value | changes)
        changed = copy.deepcopy(value); changed['worker_container_state']['exit_code'] = 1
        with self.assertRaises(public.Invalid): public.provenance(changed)

    def test_nested_unknown_fields_or_opaque_payloads_are_refused_without_export(self):
        value = self.bound(); value['worker_diagnostic']['raw_error'] = POISON
        with self.assertRaises(public.Invalid): public.provenance(value)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); raw = root / 'raw'; folder = raw / 'build-1'; folder.mkdir(parents=True)
            (folder / 'provenance.json').write_text(json.dumps(value))
            result = public.project_evidence(raw, root / 'public')
            self.assertEqual(result['projection'], 'FAIL')
            self.assertFalse((root / 'public/build-1-status.json').exists())
            self.assertNotIn(POISON, ''.join(path.read_text() for path in (root / 'public').iterdir()))


class ElfPredicateProjectionTests(unittest.TestCase):
    def test_exact_fixed_leaf_enum_only_preserves_closed_failure_schema(self):
        leaves = {'UNKNOWN','elf-read-symlink','elf-read-type-link-size','elf-read-bound','elf-read-drift',
                  'elf-header','elf-machine','elf-program-headers','elf-load-alignment','elf-load-bounds','elf-load-absent'}
        helper_spec = importlib.util.spec_from_file_location('leaf_projection_recorder', BASE / 'worker-diagnostic.py')
        helper = importlib.util.module_from_spec(helper_spec); helper_spec.loader.exec_module(helper)
        build_spec = importlib.util.spec_from_file_location('leaf_projection_build', BASE / 'worker-build.py')
        build = importlib.util.module_from_spec(build_spec); build_spec.loader.exec_module(build)
        self.assertEqual(build.ELF_PREDICATES, leaves)
        self.assertEqual(public.DIAGNOSTIC_PREDICATES, helper.PREDICATES)
        self.assertEqual({p for p in helper.PREDICATES if p == 'UNKNOWN' or p.startswith('elf-')}, leaves)
        with tempfile.TemporaryDirectory() as temporary:
            recorder = helper.Recorder(Path(temporary)); recorder.operation = 'compile-elf'
            recorder.fail('elf-header', ValueError(POISON)); original = recorder.snapshot()
        for tag in leaves:
            value = copy.deepcopy(original); value['first_failure']['predicate'] = tag
            self.assertEqual(public.diagnostic(value), value)
            self.assertFalse(public.accepted_worker_diagnostic(value))
            self.assertLessEqual(len(public.diagnostic_encoded(value)), 4096)
            self.assertNotIn(POISON, json.dumps(value))
        for tag in ('elf-unregistered', POISON, True, None):
            value = copy.deepcopy(original); value['first_failure']['predicate'] = tag
            with self.subTest(tag=tag), self.assertRaises(ValueError): public.diagnostic(value)
        value = copy.deepcopy(original); value['elf_header'] = {'machine':183}
        with self.assertRaises(ValueError): public.diagnostic(value)



class MakepkgObservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        DiagnosticTests.setUpClass.__func__(cls)
        path=BASE.parents[2]/'scripts/port/updater-native-stage/stage.py'
        tree=ast.parse(path.read_bytes())
        names={'native_diagnostic_need','native_diagnostic_encoded','native_diagnostic_nullable_hash',
               'native_diagnostic_command','native_diagnostic_makepkg','native_diagnostic'}
        nodes=[n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in names or
               isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id.startswith('NATIVE_DIAGNOSTIC_') for t in n.targets)]
        scope=dict(json=json,re=re,need=lambda value, _reason: public.need(value))
        exec(compile(ast.Module(nodes,type_ignores=[]),'finite-stage-diagnostic-projector','exec'),scope)
        cls.stage=staticmethod(scope['native_diagnostic'])

    record=DiagnosticTests.record

    def validators(self):return (self.helper.validate,public.diagnostic,self.stage)

    def test_old17_new18_and_all_closed_phase_event_code_combinations(self):
        original=self.record(); old=copy.deepcopy(original);old.pop('makepkg')
        for validator in self.validators():
            self.assertEqual(validator(old),old)
            self.assertEqual(validator(original),original)
        for selector in ('srcinfo','verify-source','build-package'):
            cases=[('config-setup','issued',None)]
            cases += [(phase,event,code) for phase in ('recipe-load','prepare','build','check','package')
                      for event,code in [('enter',None),('return',0),('return',255)]]
            for phase,event,code in cases:
                value=copy.deepcopy(original);value['makepkg']=dict(selector=selector,phase=phase,event=event,returncode=code)
                for validator in self.validators():
                    with self.subTest(selector=selector,phase=phase,event=event,code=code,validator=validator):
                        self.assertEqual(validator(value),value)
                        self.assertFalse(public.accepted_worker_diagnostic(value))

    def test_malformed_sensitive_extra_and_boolean_observations_are_refused_everywhere(self):
        original=self.record(); valid=dict(selector='build-package',phase='build',event='enter',returncode=None)
        bad=[True,False,[],POISON,{}, valid|{'extra':POISON}]
        for key in valid:
            row=valid.copy();row.pop(key);bad.append(row)
            bad.extend([valid|{key:item} for item in (True,False,[],{},POISON)])
        bad += [valid|{'phase':'config-setup'},valid|{'event':'issued'},valid|{'event':'return'},
                valid|{'returncode':0},valid|{'event':'return','returncode':-1},
                valid|{'event':'return','returncode':256},valid|{'event':'return','returncode':1.0},
                valid|{'phase':'config-setup','event':'return','returncode':0}]
        for observation in bad:
            value=copy.deepcopy(original);value['makepkg']=observation
            for validator in self.validators():
                with self.subTest(observation=observation,validator=validator),self.assertRaises(ValueError):validator(value)
        value=copy.deepcopy(original);value['raw_stderr']=POISON
        for validator in self.validators():
            with self.assertRaises(ValueError):validator(value)

    def test_observation_preserves_first_failure_compiler_and_binding_projection(self):
        value=self.record();first=copy.deepcopy(value['first_failure'])
        value.update(compiler_launch_attempted=True,compiler_return_observed=True,compiler_returncode=0,compilation_accepted=True,
                     makepkg=dict(selector='build-package',phase='check',event='return',returncode=4))
        for validator in self.validators():
            checked=validator(copy.deepcopy(value));self.assertEqual(checked,value)
            self.assertEqual(checked['first_failure'],first);self.assertTrue(checked['compilation_accepted'])
        kwargs=dict(controller_sha256='b'*64,image_id='sha256:'+H,entry_script_sha256='f'*64,
                    observed_state=observed_worker()['worker_container_state'])
        self.assertEqual(public.bound_worker_diagnostic(value,**kwargs),value)
        self.assertFalse(public.accepted_worker_diagnostic(value))
        self.assertNotIn(POISON,json.dumps(value))


if __name__ == '__main__':
    unittest.main()
