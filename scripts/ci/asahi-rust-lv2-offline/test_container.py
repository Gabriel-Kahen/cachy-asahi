"""Inert Rust schema/failure/isolation controls; no compiler, Docker or plugins."""
import copy
import importlib.util
import json
import math
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'scripts/ci/asahi-lsp-offline/container.py').is_file())
spec = importlib.util.spec_from_file_location('rust_container_test', HERE / 'container.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
COMMON = c.s.held('container', ROOT / 'scripts/ci/asahi-lsp-offline')
TMP = HERE / 'tmp'; TMP.mkdir(exist_ok=True)


def passing():
    plugins = []
    for uri in c.s.URIS:
        symbols = list(dict.fromkeys(k for p in c.s.PROFILES[uri].values() for k in p))
        controls = [{'symbol': name, 'index': i + 4, 'default': 200 if name == 'final_hp' else 0,
                     'minimum': -100, 'maximum': 20000, 'integer': False, 'toggled': False, 'enum_values': []}
                    for i, name in enumerate(symbols)]
        plugins.append({'uri': uri, 'port_count': 12, 'required_features': [c.s.FEATURE],
                        'audio_inputs': ['in_l', 'in_r'] if uri == c.s.BANK else ['in_1', 'in_2', 'in_3'],
                        'audio_outputs': ['out_l', 'out_r'] if uri == c.s.BANK else ['out'], 'controls': controls})
    cases = []
    for uri, profile, rate, fixture in sorted(c.s.grid()):
        bank = uri == c.s.BANK
        role = fixture if bank and fixture in ('channel-exchange', 'sign-reversal', 'wet-amount-scaling') else 'repeat'
        cases.append({'uri': uri, 'profile': profile, 'rate_hz': rate, 'fixture': fixture, 'pair_role': role,
                      'frames_per_instance': 24576 if bank else 32768, 'latency_frames': None,
                      'peak': 0 if fixture == 'zero' else .0625, 'rms': 0 if fixture == 'zero' else .01,
                      'max_oracle_error': 0, 'max_repeat_error': 0 if role == 'repeat' else None,
                      'wet_energy': .02 if fixture == 'wet-amount-scaling' else 0,
                      'wet_rms': [.001, .001] if fixture == 'wet-amount-scaling' else [0, 0],
                      'sample_fnv1a64': ['0123456789abcdef'] * 2, 'status': 'PASS'})
    return {'schema_version': 1, 'mode': 'processing', 'status': 'PASS', 'failure_class': None,
            'control_binding_count': 16, 'plugins': plugins, 'cases': cases, 'case_count': 60, 'instance_count': 120,
            'audio_devices': 'NOT USED', 'hardware': 'NOT RUN', 'optimization_acceptance': 'NOT RUN'}


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.patch = patch.object(c, 'common', return_value=COMMON); self.patch.start(); self.addCleanup(self.patch.stop)

    def rejects(self, value):
        with self.assertRaises(COMMON.Failure): c.project_processing(json.dumps(value).encode())

    def test_complete_two_plugin_grid_and_pair_roles(self):
        value = passing(); self.assertEqual(c.project_processing(json.dumps(value).encode()), value)
        self.assertEqual(len([x for x in value['cases'] if x['uri'] == c.s.BANK]), 56)
        self.assertEqual(len([x for x in value['cases'] if x['uri'] == c.s.TRI]), 4)
        self.assertEqual(sum(x['frames_per_instance'] * 2 for x in value['cases']), 3014656)

    def test_grid_cannot_skip_duplicate_or_import_lsp_rates(self):
        for mutate in (lambda v: v['cases'].pop(),
                       lambda v: v['cases'].__setitem__(1, copy.deepcopy(v['cases'][0])),
                       lambda v: v['cases'][-1].update(rate_hz=44100),
                       lambda v: v.update(instance_count=96)):
            value = passing(); mutate(value); self.rejects(value)

    def test_no_fake_latency_atom_or_repeat_credit(self):
        for mutate in (lambda v: v['cases'][0].update(latency_frames=0),
                       lambda v: v['plugins'][0].update(optional_null_atoms=['in_ui']),
                       lambda v: next(x for x in v['cases'] if x['pair_role'] != 'repeat').update(max_repeat_error=0),
                       lambda v: next(x for x in v['cases'] if x['uri'] == c.s.TRI).update(frames_per_instance=24576),
                       lambda v: v.update(observed_covariance_updates=2)):
            value = passing(); mutate(value); self.rejects(value)

    def test_wet_floor_is_per_channel_and_not_just_total_energy(self):
        for rms in ([.001, .0000999], [0, .02], [.0000999, .001]):
            value = passing(); row = next(x for x in value['cases'] if x['fixture'] == 'wet-amount-scaling')
            row.update(wet_rms=rms, wet_energy=100); self.rejects(value)
        value = passing()
        for row in value['cases']:
            if row['fixture'] == 'wet-amount-scaling': row['wet_rms'] = [.0001, .0001]
        c.project_processing(json.dumps(value).encode())

    def test_independent_oracle_and_nonzero_gates(self):
        for fixture, changes in (('bypass', {'max_oracle_error': .001}),
                                 ('common-mode-dc', {'max_oracle_error': .0625}),
                                 ('common-mode-quarter-wave', {'max_oracle_error': .001}),
                                 ('configured', {'rms': 0}), ('unequal', {'rms': 0}),
                                 ('zero', {'peak': .001})):
            value = passing(); next(x for x in value['cases'] if x['fixture'] == fixture).update(changes)
            self.rejects(value)

    def test_corrupt_finite_repeat_and_metamorphic_maxima_are_refused(self):
        for fixture, field in (('configured', 'max_repeat_error'), ('common-mode-dc', 'max_repeat_error'),
                               ('channel-exchange', 'max_oracle_error'), ('sign-reversal', 'max_oracle_error'),
                               ('wet-amount-scaling', 'max_oracle_error')):
            value = passing(); next(x for x in value['cases'] if x['fixture'] == fixture)[field] = 1e6
            self.rejects(value)
        for fixture in ('zero', 'configured', 'unequal'):
            value = passing(); next(x for x in value['cases'] if x['fixture'] == fixture)['max_oracle_error'] = 1e-12
            self.rejects(value)

    def test_conservative_maximum_error_boundaries(self):
        for fixture, field in (('configured', 'max_repeat_error'), ('channel-exchange', 'max_oracle_error'),
                               ('sign-reversal', 'max_oracle_error'), ('wet-amount-scaling', 'max_oracle_error')):
            value = passing(); row = next(x for x in value['cases'] if x['fixture'] == fixture)
            bound = 1e-6 + 1e-5 * (2 * row['peak'] + 1 / 16 if fixture == 'wet-amount-scaling' else row['peak'])
            row[field] = bound; c.project_processing(json.dumps(value).encode())
            row[field] = math.nextafter(bound, math.inf); self.rejects(value)

    def test_wet_energy_and_rms_must_describe_consistent_stimulus_subset(self):
        value = passing(); row = next(x for x in value['cases'] if x['fixture'] == 'wet-amount-scaling')
        minimum = 8192 * sum(x * x for x in row['wet_rms'])
        row['wet_energy'] = math.nextafter(minimum, 0)
        c.project_processing(json.dumps(value).encode())  # One-ULP reconstruction roundoff.
        row['wet_energy'] = minimum * (1 - 1e-8); self.rejects(value)
        row['wet_energy'] = 0; self.rejects(value)
        for field, corrupt in (('wet_energy', 1e-20), ('wet_rms', [1e-10, 0])):
            value = passing(); next(x for x in value['cases'] if x['fixture'] == 'configured')[field] = corrupt
            self.rejects(value)

    def test_feature_defaults_ranges_and_nonfinite_metadata_are_closed(self):
        for mutate in (lambda v: v['plugins'][0].update(required_features=[]),
                       lambda v: v['plugins'][1]['controls'][0].update(maximum=1),
                       lambda v: next(x for x in v['plugins'][0]['controls'] if x['symbol'] == 'final_hp').update(default=199),
                       lambda v: v['plugins'][0]['controls'][1].update(index=4),
                       lambda v: v['cases'][0].update(peak=float('nan')),
                       lambda v: v['cases'][0].update(extra='/private/log')):
            value = passing(); mutate(value); self.rejects(value)

    def test_known_child_failure_survives_without_private_error_body(self):
        for mode, code in (('processing', 'wet-rms-gate-failed'), ('processing', 'direct-oracle-failed'),
                           ('loader', 'dlopen-failed')):
            value = {'schema_version': 1, 'mode': mode, 'status': 'FAIL', 'failure_class': code,
                     'audio_devices': 'NOT USED', 'hardware': 'NOT RUN', 'optimization_acceptance': 'NOT RUN'}
            with self.assertRaises(COMMON.Failure) as caught: c.document(json.dumps(value).encode(), mode)
            self.assertEqual(caught.exception.code, 'host_' + code)
            value['failure_class'] = '/private/source-error'
            with self.assertRaises(COMMON.Failure) as caught: c.document(json.dumps(value).encode(), mode)
            self.assertEqual(caught.exception.code, 'host_schema')

    def test_loader_hashes_observed_candidate_and_discards_private_paths(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp:
            library = Path(tmp) / 'bankstown.lv2/bankstown.so'; library.parent.mkdir(); library.write_bytes(b'inert')
            value = {'schema_version': 1, 'mode': 'loader', 'status': 'PASS', 'failure_class': None,
                     'selected_uris': [c.s.BANK], 'descriptor_count': 1, 'loaded_basenames': ['bankstown.so', 'linux-vdso.so.1'],
                     'loaded_paths': [str(library), None], 'audio_devices': 'NOT USED', 'hardware': 'NOT RUN',
                     'optimization_acceptance': 'NOT RUN'}
            output = c.project_loader(json.dumps(value).encode(), c.s.BANK, library)
            self.assertEqual(output['loaded_libraries'][0]['sha256'], COMMON.digest(library))
            self.assertNotIn(str(library), json.dumps(output)); self.assertNotIn('loaded_paths', output)
            for mutate in (lambda v: v.update(descriptor_count=2),
                           lambda v: v.update(selected_uris=[c.s.TRI]),
                           lambda v: v.update(loaded_paths=['/etc/passwd', None])):
                bad = copy.deepcopy(value); mutate(bad)
                with self.assertRaises(COMMON.Failure): c.project_loader(json.dumps(bad).encode(), c.s.BANK, library)

    def test_inventory_after_failure_is_still_attempted(self):
        with tempfile.TemporaryDirectory(dir=TMP) as tmp, patch.object(c, 'OUT', Path(tmp)), \
             patch.object(COMMON, 'assert_isolation'), patch.object(COMMON, 'mount_readonly', return_value=True), \
             patch.object(COMMON, 'inventory', return_value=c.s.LOCK) as inventory, \
             patch.object(COMMON, 'digest', side_effect=RuntimeError('/private/compiler-error')):
            self.assertEqual(c.main(), 1)
            value = json.loads((Path(tmp) / 'observations.json').read_text())
            self.assertEqual(value['failure_class'], 'internal_error'); self.assertTrue(value['inventory']['unchanged'])
            self.assertEqual(inventory.call_count, 2); self.assertNotIn('/private', json.dumps(value))


if __name__ == '__main__': unittest.main()
