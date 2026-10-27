# SPDX-License-Identifier: MIT
"""Pure sysfs/clock controls; real host collection is a separate retained receipt."""
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('platform_metrics', HERE / 'platform_metrics.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MetricsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sys = self.root / 'sys'
        self.battery = self.sys / 'class/power_supply/macsmc-battery'
        self.hwmon = self.sys / 'class/hwmon/hwmon7'
        self.thermal = self.sys / 'class/thermal/thermal_zone42'
        for path, fields in (
            (self.battery, {'type': 'Battery', 'status': 'Discharging', 'present': '1',
                            'energy_now': '1000000', 'power_now': '1000000', 'capacity': '80',
                            'current_now': '-10000', 'temp': '250'}),
            (self.hwmon, {'name': 'soc_sensor', 'power1_input': '1000000', 'power1_label': 'SoC',
                         'power1_average': '2000000', 'energy2_input': '1000000',
                         'temp3_input': '51000', 'temp3_label': 'die', 'update_interval': '1000'}),
            (self.thermal, {'type': 'apple_soc', 'temp': '42000'})):
            path.mkdir(parents=True)
            for name, value in fields.items():
                (path / name).write_text(value + '\n')
        self.inventory = m.discover(self.sys)

    def sensor(self, name, family='hwmon'):
        return next(s for s in self.inventory['sensors'] if s['family'] == family and s['attribute'] == name)

    def row(self, sample, name, family='hwmon'):
        return next(r for r in sample['readings'] if r['id'] == self.sensor(name, family)['id'])

    def series(self, offsets=(0, 1, 3), powers=(1000000, 3000000, 5000000),
               energies=(1000000, 2000000, 5000000), stored=(1000000, 999000, 997000),
               status=('Discharging', 'Discharging', 'Discharging')):
        result = []
        for sequence, offset in enumerate(offsets):
            (self.hwmon / 'power1_input').write_text(str(powers[sequence]) + '\n')
            (self.hwmon / 'energy2_input').write_text(str(energies[sequence]) + '\n')
            (self.battery / 'energy_now').write_text(str(stored[sequence]) + '\n')
            (self.battery / 'status').write_text(status[sequence] + '\n')
            row = m.snapshot(self.inventory, sequence)
            start = 10_000_000_000 + round(offset * 1e9)
            row['start'] = {k: start for k in row['start']}
            row['end'] = {k: start + 1000 for k in row['end']}
            for r in row['readings']:
                for reading in [r['reading'], *r['context_before'].values(), *r['context_after'].values()]:
                    reading['monotonic_start_ns'], reading['monotonic_end_ns'] = start + 100, start + 300
            result.append(row)
        return result

    def summary_sensor(self, samples, name='power1_input', family='hwmon', gap=2.5):
        report = m.summarize(self.inventory, samples, gap)
        return next(s for s in report['sensors'] if s['id'] == self.sensor(name, family)['id'])

    def test_discovery_uses_actual_names_paths_labels_and_units(self):
        self.assertEqual(self.sensor('energy_now', 'power_supply')['unit'], 'uWh')
        self.assertEqual(self.sensor('energy2_input')['unit'], 'uJ')
        self.assertEqual(self.sensor('temp', 'power_supply')['unit'], 'tenths_C')
        self.assertEqual(self.sensor('temp', 'thermal')['unit'], 'mC')
        self.assertEqual(self.sensor('temp3_input')['unit'], 'unreviewed_hwmon_temp')
        self.assertEqual(self.sensor('power1_input')['identity']['power1_label']['raw'], 'SoC\n')
        self.assertEqual(self.sensor('power1_input')['metadata']['update_interval']['raw'], '1000\n')
        self.assertIn('macsmc-battery', self.sensor('energy_now', 'power_supply')['id'])
        self.assertEqual(len(self.inventory['devices']), 3)
        self.assertTrue(all(s['domain'].startswith('unreviewed') for s in self.inventory['sensors']))

    def test_empty_and_absent_classes_are_explicit_no_zero_energy(self):
        empty = self.root / 'empty'; empty.mkdir()
        inventory = m.discover(empty)
        self.assertEqual({v['status'] for v in inventory['classes'].values()}, {'absent'})
        samples = [m.snapshot(inventory, 0)]
        report = m.summarize(inventory, samples, 1)
        self.assertEqual(report['sensors'], [])
        (empty / 'class/power_supply').mkdir(parents=True)
        self.assertEqual(m.discover(empty)['classes']['power_supply']['status'], 'absent')

    def test_directory_denied_is_retained(self):
        original = os.scandir
        def denied(path):
            if Path(path) == self.hwmon:
                raise PermissionError(errno.EACCES, 'fixture denial')
            return original(path)
        with patch.object(m.os, 'scandir', side_effect=denied):
            inventory = m.discover(self.sys)
        self.assertEqual(next(d['status'] for d in inventory['devices'] if d['path'] == str(self.hwmon)), 'denied')

    def test_absent_denied_io_unknown_and_invalid_read_states(self):
        missing = m.observe(self.sensor('voltage_now', 'power_supply'))
        self.assertEqual(missing['status'], 'absent'); self.assertIsNone(missing['value'])
        original = os.open
        for code, state in ((errno.EACCES, 'denied'), (errno.EPERM, 'denied'),
                            (errno.EIO, 'unavailable'), (errno.ENODATA, 'unavailable')):
            def failed(path, flags, *args):
                if Path(path) == self.hwmon / 'power1_input':
                    raise OSError(code, 'fixture')
                return original(path, flags, *args)
            with self.subTest(code=code), patch.object(m.os, 'open', side_effect=failed):
                self.assertEqual(m.observe(self.sensor('power1_input'))['status'], state)
        (self.hwmon / 'power1_input').write_text('not-an-integer\n')
        self.assertEqual(m.observe(self.sensor('power1_input'))['status'], 'invalid')

    def test_numeric_bounds_charge_current_and_temperature_units(self):
        for name, family, value in (('power1_input', 'hwmon', '-1'), ('capacity', 'power_supply', '101'),
                                    ('present', 'power_supply', '2'), ('energy2_input', 'hwmon', str(2**63)),
                                    ('temp', 'thermal', '-273151'), ('temp', 'power_supply', '-2732')):
            with self.subTest(name=name, value=value), self.assertRaises(m.Invalid):
                m.numeric(value, self.sensor(name, family))
        self.assertEqual(m.numeric('-999', self.sensor('current_now', 'power_supply')), -999)
        self.assertEqual(m.numeric('-20000', self.sensor('temp', 'thermal')), -20000)
        with self.assertRaises(m.Invalid): m.numeric('1.5', self.sensor('power1_input'))

    def test_raw_byte_empty_nonascii_and_fifo_controls(self):
        path = self.root / 'raw'
        for raw in (b'1' * 513, b'', b'\xff'):
            path.write_bytes(raw)
            self.assertEqual(m.read_text(path)['status'], 'invalid')
        path.unlink(); os.mkfifo(path)
        self.assertEqual(m.read_text(path)['status'], 'invalid')

    def test_identity_and_resolved_path_changes_are_unknown(self):
        sensor = self.sensor('power1_input')
        (self.hwmon / 'name').write_text('replaced_chip\n')
        self.assertEqual(m.observe(sensor)['status'], 'unknown')
        (self.hwmon / 'name').write_text('soc_sensor\n')
        (self.hwmon / 'power1_label').write_text('different_domain\n')
        self.assertEqual(m.observe(sensor)['status'], 'unknown')
        changed = copy.deepcopy(sensor); changed['resolved_directory'] += '-old'
        self.assertEqual(m.observe(changed)['status'], 'unknown')

    def test_identity_unreadable_does_not_grant_numeric_coverage(self):
        (self.hwmon / 'name').unlink()
        self.inventory = m.discover(self.sys)
        row = m.observe(self.sensor('power1_input'))
        self.assertEqual(row['status'], 'unknown'); self.assertIsNone(row['value'])

    def test_identity_changed_during_read_is_rejected(self):
        original = m.read_text
        def changed(path):
            row = original(path)
            if path == self.hwmon / 'power1_input':
                (self.hwmon / 'name').write_text('new_chip\n')
            return row
        with patch.object(m, 'read_text', side_effect=changed):
            self.assertEqual(m.observe(self.sensor('power1_input'))['status'], 'unknown')

    def test_present_disabled_fault_and_state_race(self):
        (self.battery / 'present').write_text('0\n')
        self.assertEqual(m.observe(self.sensor('energy_now', 'power_supply'))['status'], 'absent')
        (self.hwmon / 'power1_enable').write_text('0\n')
        self.assertEqual(m.observe(self.sensor('power1_input'))['status'], 'unavailable')
        (self.hwmon / 'power1_enable').write_text('1\n')
        (self.hwmon / 'power1_fault').write_text('1\n')
        self.assertEqual(m.observe(self.sensor('power1_input'))['status'], 'unavailable')
        (self.battery / 'present').write_text('1\n')
        (self.battery / 'online').write_text('2\n')
        self.assertEqual(m.observe(self.sensor('power_now', 'power_supply'))['status'], 'invalid')
        (self.battery / 'online').unlink()
        original = m.read_text
        def transition(path):
            row = original(path)
            if path == self.battery / 'energy_now':
                (self.battery / 'status').write_text('Charging\n')
            return row
        with patch.object(m, 'read_text', side_effect=transition):
            self.assertEqual(m.observe(self.sensor('energy_now', 'power_supply'))['status'], 'unknown')

    def test_power_trapezoid_uses_actual_uneven_times(self):
        row = self.summary_sensor(self.series())
        self.assertEqual(row['status'], 'complete')
        self.assertAlmostEqual(row['contiguous_observed_span_energy_j'], 10)
        self.assertAlmostEqual(row['covered_seconds'], 3)
        self.assertAlmostEqual(row['observed_span_average_w'], 10/3)
        self.assertEqual(row['boundary_unobserved_ns'], {'start': 200, 'end': 800})

    def test_energy_counter_delta_is_microjoules_not_power(self):
        row = self.summary_sensor(self.series(), 'energy2_input')
        self.assertEqual(row['contiguous_observed_span_energy_j'], 4)
        self.assertIn('counter deltas', row['method'])

    def test_stored_energy_delta_uses_uwh_and_discharge_status(self):
        row = self.summary_sensor(self.series(), 'energy_now', 'power_supply')
        self.assertAlmostEqual(row['contiguous_observed_span_energy_j'], 10.8)
        self.assertAlmostEqual(row['observed_span_average_w'], 3.6)
        self.assertIn('not power integration', row['method'])

    def test_battery_instantaneous_power_rejects_charging_and_status_transitions(self):
        for status in (('Discharging', 'Charging', 'Discharging'), ('Charging',) * 3, ('Unknown',) * 3):
            row = self.summary_sensor(self.series(status=status), 'power_now', 'power_supply')
            self.assertIsNone(row['contiguous_observed_span_energy_j'])
            self.assertIsNone(row['accepted_interval_energy_j'])
        row = self.summary_sensor(self.series(), 'power_now', 'power_supply')
        self.assertEqual(row['contiguous_observed_span_energy_j'], 3)

    def test_battery_identity_metadata_change_and_offline_supply_rejected(self):
        (self.battery / 'model_name').write_text('replacement\n')
        self.assertEqual(m.observe(self.sensor('energy_now', 'power_supply'))['status'], 'unknown')
        (self.battery / 'type').write_text('Mains\n')
        (self.battery / 'online').write_text('0\n')
        self.inventory = m.discover(self.sys)
        row = self.summary_sensor(self.series(), 'power_now', 'power_supply')
        self.assertIsNone(row['contiguous_observed_span_energy_j'])
        self.assertEqual(row['gaps'][0]['reason'], 'power supply offline')

    def test_charge_voltage_current_capacity_and_average_are_never_synthetic_energy(self):
        samples = self.series()
        for name, family in (('charge_now', 'power_supply'), ('voltage_now', 'power_supply'),
                             ('current_now', 'power_supply'), ('capacity', 'power_supply'),
                             ('power1_average', 'hwmon'), ('temp3_input', 'hwmon')):
            with self.subTest(name=name):
                row = self.summary_sensor(samples, name, family)
                self.assertIsNone(row['accepted_interval_energy_j'])
                self.assertIsNone(row['contiguous_observed_span_energy_j'])

    def test_counter_reset_and_wrap_not_bridged(self):
        row = self.summary_sensor(self.series(energies=(1000000, 1, 1000001)), 'energy2_input')
        self.assertIsNone(row['contiguous_observed_span_energy_j'])
        self.assertEqual(row['accepted_interval_energy_j'], 1)
        self.assertEqual(row['covered_seconds'], 2)
        self.assertEqual(len(row['gaps']), 1)
        self.assertIn('reset', row['gaps'][0]['reason'])

    def test_energy_rise_during_discharge_rejected(self):
        row = self.summary_sensor(self.series(stored=(1000000, 1000001, 999001)), 'energy_now', 'power_supply')
        self.assertIsNone(row['contiguous_observed_span_energy_j'])
        self.assertIn('increased/reset', row['gaps'][0]['reason'])

    def test_charging_unknown_status_and_nonbattery_no_discharge_energy(self):
        for state in ('Charging', 'Unknown', 'Full', 'Not charging'):
            row = self.summary_sensor(self.series(status=('Discharging', state, 'Discharging')), 'energy_now', 'power_supply')
            self.assertIsNone(row['accepted_interval_energy_j'])
        (self.battery / 'type').write_text('Mains\n')
        self.inventory = m.discover(self.sys)
        row = self.summary_sensor(self.series(), 'energy_now', 'power_supply')
        self.assertIsNone(row['accepted_interval_energy_j'])

    def test_missing_samples_gap_no_zero_and_partial_exposed_separately(self):
        samples = self.series(powers=(1000000, -1, 5000000))
        row = self.summary_sensor(samples)
        self.assertIsNone(row['contiguous_observed_span_energy_j'])
        self.assertIsNone(row['accepted_interval_energy_j'])
        self.assertEqual(row['covered_seconds'], 0)
        self.assertEqual(row['sample_states'], {'ok': 2, 'invalid': 1})
        row = self.summary_sensor(self.series(offsets=(0, 1, 4)), gap=2.5)
        self.assertEqual(row['accepted_interval_energy_j'], 2)
        self.assertEqual(row['covered_seconds'], 1)
        self.assertIsNone(row['contiguous_observed_span_energy_j'])

    def test_zero_is_only_reported_from_readable_real_zero_values(self):
        row = self.summary_sensor(self.series(powers=(0, 0, 0)))
        self.assertEqual(row['contiguous_observed_span_energy_j'], 0)
        self.assertEqual(row['observed_span_average_w'], 0)

    def test_all_clock_reversals_and_sequence_gaps_refused(self):
        for key in ('monotonic_ns', 'boottime_ns', 'realtime_ns'):
            samples = self.series(); samples[1]['start'][key] = samples[0]['end'][key] - 1
            with self.subTest(key=key), self.assertRaises(m.Invalid):
                m.summarize(self.inventory, samples, 2.5)
        samples = self.series(); samples[1]['sequence'] = 2
        with self.assertRaises(m.Invalid): m.summarize(self.inventory, samples, 2.5)
        samples = self.series(); self.row(samples[1], 'power1_input')['reading']['monotonic_end_ns'] = 0
        with self.assertRaises(m.Invalid): m.summarize(self.inventory, samples, 2.5)

    def test_suspend_and_wall_step_gaps_are_not_integrated(self):
        for clock in ('boottime_ns', 'realtime_ns'):
            samples = self.series()
            for s in samples[1:]:
                for phase in ('start', 'end'): s[phase][clock] += 10_000_000_000
            row = self.summary_sensor(samples)
            self.assertIsNone(row['contiguous_observed_span_energy_j'])
            self.assertEqual(row['accepted_interval_energy_j'], 8)
            self.assertEqual(row['gaps'][0]['reason'], 'clock discontinuity/suspend gap')

    def test_window_clip_does_not_interpolate_or_extrapolate(self):
        samples = self.series()
        start = samples[0]['end']['monotonic_ns']
        end = samples[-1]['end']['monotonic_ns']
        report = m.summarize(self.inventory, samples, 2.5, start, end)
        row = next(r for r in report['sensors'] if r['id'] == self.sensor('power1_input')['id'])
        self.assertEqual(row['contiguous_observed_span_energy_j'], 8)
        self.assertEqual(row['boundary_unobserved_ns']['start'], 999999200)
        with self.assertRaises(m.Invalid): m.summarize(self.inventory, samples, 2.5, start - 10**12, end)

    def test_one_sample_has_no_energy_or_average(self):
        row = self.summary_sensor(self.series(offsets=(0,)))
        self.assertIsNone(row['accepted_interval_energy_j'])
        self.assertIsNone(row['contiguous_observed_span_energy_j'])
        self.assertIsNone(row['observed_span_average_w'])

    def test_cached_value_unit_status_and_sensor_order_tampering_refused(self):
        samples = self.series(); self.row(samples[1], 'power1_input')['value'] = 999
        with self.assertRaises(m.Invalid): m.summarize(self.inventory, samples, 2.5)
        samples = self.series(); self.row(samples[1], 'power1_input')['status'] = 'absent'
        with self.assertRaises(m.Invalid): m.summarize(self.inventory, samples, 2.5)
        samples = self.series(); samples[1]['readings'].reverse()
        with self.assertRaises(m.Invalid): m.summarize(self.inventory, samples, 2.5)
        inventory = copy.deepcopy(self.inventory); inventory['sensors'][0]['unit'] = 'W'
        with self.assertRaises(m.Invalid): m.summarize(inventory, self.series(), 2.5)

    def test_file_pins_symlinks_and_existing_outputs_refused(self):
        directory = self.root / 'capture'; directory.mkdir()
        inventory_data, samples = m.encoded(self.inventory), self.series()
        samples_data = b''.join(m.encoded(s) for s in samples)
        capture = {'schema': m.SCHEMA, 'completed': True, 'files': {
            'inventory.json': m.pin_bytes(inventory_data), 'samples.jsonl': m.pin_bytes(samples_data)}}
        m.fresh_file(directory / 'inventory.json', inventory_data)
        m.fresh_file(directory / 'samples.jsonl', samples_data)
        m.fresh_file(directory / 'capture.json', m.encoded(capture))
        self.assertEqual(m.load_capture(directory)[2], samples)
        with self.assertRaises(FileExistsError): m.fresh_file(directory / 'inventory.json', b'overwrite')
        (directory / 'inventory.json').write_bytes(b'{}')
        with self.assertRaises(m.Invalid): m.load_capture(directory)
        (directory / 'capture.json').unlink()
        (directory / 'capture.json').symlink_to(directory / 'inventory.json')
        with self.assertRaises(OSError): m.load_capture(directory)

    def test_discovery_and_sampling_caps_and_nonfinite_gap(self):
        with patch.object(m, 'MAX_SENSORS', 1), self.assertRaises(m.Invalid): m.discover(self.sys)
        with patch.object(m, 'MAX_ENTRIES', 1), self.assertRaises(m.Invalid): m.discover(self.sys)
        for value in (float('nan'), float('inf'), 0, -1, 121):
            with self.subTest(value=value), self.assertRaises(m.Invalid):
                m.summarize(self.inventory, self.series(), value)
        with patch.object(m, 'MAX_SAMPLES', 1), self.assertRaises(m.Invalid):
            m.summarize(self.inventory, self.series(), 2.5)

    def test_cli_invalid_capture_arguments_do_not_create_output(self):
        output = self.root / 'no-create'
        for duration, interval in (('nan', '1'), ('1', 'inf'), ('3601', '1'), ('1', '0'), ('3600', '0.1')):
            self.assertEqual(m.main(['capture', '--output', str(output), '--duration', duration,
                                     '--interval', interval, '--machine-label', 'fixture']), 2)
            self.assertFalse(output.exists())

    def test_interrupted_capture_retains_partial_raw_and_cannot_be_summarized(self):
        output = self.root / 'interrupted'
        original = m.snapshot
        def interrupted(inventory, sequence):
            if sequence == 1:
                raise m.Invalid('fixture read failure')
            return original(inventory, sequence)
        with patch.object(m, 'discover', return_value=self.inventory), patch.object(m, 'snapshot', side_effect=interrupted):
            self.assertEqual(m.main(['capture', '--output', str(output), '--duration', '0.2',
                                     '--interval', '0.1', '--machine-label', 'fixture']), 2)
        self.assertFalse(json.loads((output / 'capture.json').read_text())['completed'])
        self.assertEqual(len((output / 'samples.jsonl').read_text().splitlines()), 1)
        self.assertFalse((output / 'summary.json').exists())
        with self.assertRaises(m.Invalid): m.load_capture(output)

    def test_capture_byte_bound_preserves_incomplete_receipt(self):
        output = self.root / 'byte-bound'
        with patch.object(m, 'discover', return_value=self.inventory), patch.object(m, 'MAX_BYTES', 1):
            self.assertEqual(m.main(['capture', '--output', str(output), '--duration', '0.1',
                                     '--interval', '0.1', '--machine-label', 'fixture']), 2)
        self.assertFalse(json.loads((output / 'capture.json').read_text())['completed'])
        self.assertEqual((output / 'samples.jsonl').stat().st_size, 0)
        self.assertFalse((output / 'summary.json').exists())

    def test_real_fixture_capture_offline_replay_and_private_modes(self):
        output = self.root / 'live-fixture'
        reference = self.root / 'machine-record.json'
        reference.write_text('{"machine":"fixture"}\n')
        with patch.object(m, 'discover', return_value=self.inventory):
            self.assertEqual(m.main(['capture', '--output', str(output), '--duration', '0.1',
                                     '--interval', '0.1', '--machine-label', 'fixture, not hardware evidence',
                                     '--reference', str(reference)]), 0)
        record, inventory, samples = m.load_capture(output)
        self.assertEqual(record['references'], [{'path': str(reference), **m.pin_bytes(reference.read_bytes())}])
        self.assertTrue(record['completed']); self.assertEqual(record['sample_count'], len(samples))
        self.assertEqual((output.stat().st_mode & 0o777), 0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in output.iterdir()))
        replay = self.root / 'replay.json'
        self.assertEqual(m.main(['summarize', '--capture', str(output), '--output', str(replay)]), 0)
        expected = json.loads((output / 'summary.json').read_text())
        got = json.loads(replay.read_text()); got.pop('inputs')
        self.assertEqual(got, expected)
        self.assertEqual(m.main(['summarize', '--capture', str(output), '--output', str(replay)]), 2)


if __name__ == '__main__':
    unittest.main()
