#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded, read-only Linux platform sidecar. No workload or subprocess control."""
import argparse
from collections import Counter
import errno
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

SCHEMA = 'cachy-asahi-platform-metrics-v1'
MAX_DEVICES, MAX_ENTRIES, MAX_SENSORS = 128, 1024, 128
MAX_SAMPLES, MAX_BYTES, MAX_LINE = 10000, 128 * 1024**2, 512 * 1024
STATES = {'ok', 'absent', 'denied', 'unavailable', 'unknown', 'invalid'}
LIMITS = {'max_devices_per_class': MAX_DEVICES, 'max_entries_per_device': MAX_ENTRIES,
          'max_sensors': MAX_SENSORS, 'max_samples': MAX_SAMPLES,
          'max_capture_bytes': MAX_BYTES, 'max_attribute_bytes': 512}
SUPPLY = {
    'power_now': ('uW', 'power'), 'energy_now': ('uWh', 'stored_energy'),
    'charge_now': ('uAh', 'charge'), 'voltage_now': ('uV', 'voltage'),
    'current_now': ('uA', 'current'), 'capacity': ('percent', 'capacity'),
    'temp': ('tenths_C', 'temperature'), 'online': ('boolean', 'state'),
    'present': ('boolean', 'state'),
}


class Invalid(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Invalid(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def pin_bytes(data):
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


def clocks():
    return {'monotonic_ns': time.monotonic_ns(), 'boottime_ns': time.clock_gettime_ns(time.CLOCK_BOOTTIME),
            'realtime_ns': time.time_ns()}


def error_state(error):
    return ('absent' if error.errno in (errno.ENOENT, errno.ENODEV) else
            'denied' if error.errno in (errno.EACCES, errno.EPERM) else 'unavailable')


def read_text(path):
    start = time.monotonic_ns()
    row = {'status': 'unknown', 'raw': None, 'monotonic_start_ns': start}
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            need(stat.S_ISREG(os.fstat(fd).st_mode), 'attribute is not a regular sysfs file')
            data = os.read(fd, 513)
        finally:
            os.close(fd)
        need(len(data) <= 512, 'attribute byte limit')
        row['raw'] = data.decode('ascii')
        need(bool(row['raw'].strip()), 'empty attribute')
        row['status'] = 'ok'
    except OSError as error:
        row.update(status=error_state(error), errno=error.errno)
    except (UnicodeError, Invalid) as error:
        row.update(status='invalid', reason=str(error)[:100])
    row['monotonic_end_ns'] = time.monotonic_ns()
    return row


def signature(row):
    return {key: row.get(key) for key in ('status', 'raw', 'errno')}


def listing(path, limit):
    try:
        result = []
        with os.scandir(path) as entries:
            for entry in entries:
                need(len(result) < limit, 'directory entry bound: ' + str(path))
                result.append(entry.name)
        return sorted(result), 'ok'
    except OSError as error:
        return [], error_state(error)


def spec(family, name):
    if family == 'power_supply':
        return SUPPLY.get(name)
    if family == 'thermal':
        return ('mC', 'temperature') if name == 'temp' else None
    match = re.fullmatch(r'(temp|power|energy)([1-9][0-9]*)_(input|average)', name)
    if family != 'hwmon' or not match or (match[1] != 'power' and match[3] != 'input'):
        return None
    if match[1] == 'temp':
        # Some ADC/thermistor drivers export millivolts here. Do not guess.
        return 'unreviewed_hwmon_temp', 'raw_temperature_channel'
    return ('uJ', 'energy_counter') if match[1] == 'energy' else (
        'uW', 'power' if match[3] == 'input' else 'averaged_power')


def discover(root=Path('/sys')):
    root = Path(root).absolute()
    result = {'schema': SCHEMA, 'sysfs_root': str(root), 'classes': {}, 'sensors': [],
              'devices': [], 'limits': LIMITS, 'inventory_policy': 'fixed at capture start; new devices not followed'}
    for family in ('power_supply', 'thermal', 'hwmon'):
        base = root / 'class' / family
        names, state = listing(base, MAX_ENTRIES)
        devices = [name for name in names if family == 'power_supply' or re.fullmatch(
            r'thermal_zone[0-9]+' if family == 'thermal' else r'hwmon[0-9]+', name)]
        need(len(devices) <= MAX_DEVICES, 'device count bound')
        result['classes'][family] = {'path': str(base), 'status': state if state != 'ok' else (
            'ok' if devices else 'absent'), 'devices': devices}
        for name in devices:
            directory = base / name
            fields, directory_state = listing(directory, MAX_ENTRIES)
            # Supply fields are deliberately attempted even when absent.
            candidates = sorted(SUPPLY) if family == 'power_supply' else (
                ['temp'] if family == 'thermal' else fields)
            identity_name = 'type' if family != 'hwmon' else 'name'
            identity_fields = [identity_name] + (['manufacturer', 'model_name', 'technology'] if family == 'power_supply' else [])
            identity = {key: signature(read_text(directory / key)) for key in identity_fields}
            result['devices'].append({'path': str(directory), 'resolved_path': str(directory.resolve()),
                                      'status': directory_state, 'identity': identity})
            for field in candidates:
                definition = spec(family, field)
                if definition is None:
                    continue
                stem = field.rsplit('_', 1)[0]
                extra = [stem + '_label', stem + '_type'] if family == 'hwmon' else []
                guards = dict(identity)
                guards.update({key: signature(read_text(directory / key)) for key in extra})
                context = (['status', 'present', 'online'] if family == 'power_supply' else
                           [stem + '_enable', stem + '_fault'] if family == 'hwmon' else [])
                metadata = ['manufacturer', 'model_name', 'technology', 'energy_full',
                            'energy_full_design', 'charge_full', 'charge_full_design', 'cycle_count'] if family == 'power_supply' else (
                            ['update_interval', 'update_interval_us', stem + '_average_interval'] if family == 'hwmon' else [])
                result['sensors'].append({'id': str(directory / field), 'family': family,
                    'attribute': field, 'unit': definition[0], 'kind': definition[1],
                    'directory': str(directory), 'resolved_directory': str(directory.resolve()),
                    'directory_status': directory_state, 'identity': guards, 'identity_required': identity_name,
                    'context_fields': context,
                    'metadata': {key: signature(read_text(directory / key)) for key in metadata},
                    'domain': 'unreviewed; do not infer CPU/package/system or add domains'})
                need(len(result['sensors']) <= MAX_SENSORS, 'sensor count bound')
    return result


def numeric(raw, sensor):
    need(isinstance(raw, str) and len(raw.encode('ascii')) <= 512 and
         re.fullmatch(r'[+-]?[0-9]+', raw.strip()) is not None, 'invalid integer')
    value = int(raw.strip())
    need(-(2**63) <= value < 2**63, 'outside signed 64-bit bound')
    kind, unit = sensor['kind'], sensor['unit']
    if kind not in ('current', 'temperature', 'raw_temperature_channel'):
        need(value >= 0, 'negative unsigned reading')
    if unit == 'percent':
        need(value <= 100, 'capacity outside 0..100')
    if unit == 'boolean':
        need(value in (0, 1), 'state outside 0..1')
    if unit in ('mC', 'tenths_C'):
        need(value >= (-273150 if unit == 'mC' else -2731), 'below absolute zero')
    return value


def observe(sensor):
    directory = Path(sensor['directory'])
    before = {key: signature(read_text(directory / key)) for key in sensor['identity']}
    resolved = str(directory.resolve())
    context_before = {key: read_text(directory / key) for key in sensor['context_fields']}
    reading = read_text(Path(sensor['id']))
    context_after = {key: read_text(directory / key) for key in sensor['context_fields']}
    after = {key: signature(read_text(directory / key)) for key in sensor['identity']}
    row = {'id': sensor['id'], 'reading': reading, 'value': None,
           'context_before': context_before, 'context_after': context_after,
           'identity_before': before, 'identity_after': after, 'resolved_directory': resolved}
    row['status'], row['reason'] = assess(sensor, row)
    if row['status'] == 'ok':
        row['value'] = numeric(reading['raw'], sensor)
    return row


def assess(sensor, row):
    r = row['reading']
    need(r['status'] in STATES, 'unknown attribute state')
    if r['status'] != 'ok':
        return r['status'], 'attribute read ' + r['status']
    if row['resolved_directory'] != sensor['resolved_directory'] or any(
            row[key] != sensor['identity'] for key in ('identity_before', 'identity_after')):
        return 'unknown', 'identity changed'
    if sensor['identity'][sensor['identity_required']]['status'] != 'ok':
        return 'unknown', 'required device identity unreadable'
    try:
        numeric(r['raw'], sensor)
    except (Invalid, UnicodeError):
        return 'invalid', 'invalid numeric reading'
    left, right = row['context_before'], row['context_after']
    if {k: signature(v) for k, v in left.items()} != {k: signature(v) for k, v in right.items()}:
        return 'unknown', 'state changed during read'
    for key, value in left.items():
        state, raw = value['status'], (value['raw'] or '').strip()
        if state not in ('ok', 'absent'):
            return 'unknown', 'context unreadable: ' + key
        if state == 'absent':
            continue
        if key in ('present', 'online') or key.endswith('_enable'):
            if raw not in ('0', '1'):
                return 'invalid', 'invalid presence/enable state'
            if raw == '0' and key != 'online':
                return 'absent' if key == 'present' else 'unavailable', 'not present/enabled'
        if key.endswith('_fault') and raw != '0':
            return 'unavailable', 'channel fault'
    return 'ok', None


def snapshot(inventory, sequence):
    start = clocks()
    rows = [observe(sensor) for sensor in inventory['sensors']]
    return {'sequence': sequence, 'start': start, 'end': clocks(), 'readings': rows}


def valid_clock(value):
    need(isinstance(value, dict) and set(value) == {'monotonic_ns', 'boottime_ns', 'realtime_ns'} and
         all(type(v) is int and v >= 0 for v in value.values()), 'invalid clock record')


def validate_inventory(inventory):
    need(inventory['schema'] == SCHEMA, 'unsupported inventory schema')
    sensors = inventory['sensors']
    need(isinstance(sensors, list) and len(sensors) <= MAX_SENSORS, 'sensor count bound')
    need(len({s['id'] for s in sensors}) == len(sensors), 'duplicate sensor id')
    for s in sensors:
        need(spec(s['family'], s['attribute']) == (s['unit'], s['kind']), 'sensor unit/kind mismatch')
        need(s['id'] == str(Path(s['directory']) / s['attribute']), 'sensor path mismatch')
        need(s['identity_required'] in s['identity'], 'required identity missing')


def validate_samples(inventory, samples):
    validate_inventory(inventory)
    need(0 < len(samples) <= MAX_SAMPLES, 'sample count bound')
    previous = None
    for sequence, sample in enumerate(samples):
        need(type(sample['sequence']) is int and sample['sequence'] == sequence, 'sample sequence gap')
        for key in ('start', 'end'):
            valid_clock(sample[key])
        start, end = sample['start'], sample['end']
        need(all(end[k] >= start[k] for k in start), 'clock reversal inside snapshot')
        if previous:
            need(all(start[k] > previous[k] for k in start), 'clock reversal/overlapping snapshots')
        previous = end
        need(len(sample['readings']) == len(inventory['sensors']), 'missing/extra sensor row')
        for sensor, row in zip(inventory['sensors'], sample['readings']):
            need(row['id'] == sensor['id'], 'sensor order/identity mismatch')
            for reading in [row['reading'], *row['context_before'].values(), *row['context_after'].values()]:
                need(reading['status'] in STATES and (reading['raw'] is None or (
                    isinstance(reading['raw'], str) and len(reading['raw'].encode()) <= 512)), 'raw attribute bound/state')
                a, b = reading['monotonic_start_ns'], reading['monotonic_end_ns']
                need(type(a) is int and type(b) is int and start['monotonic_ns'] <= a <= b <= end['monotonic_ns'],
                     'attribute timestamps outside snapshot or reversed')
            need(set(row['context_before']) == set(row['context_after']) == set(sensor['context_fields']), 'context fields differ')
            state, reason = assess(sensor, row)
            need((state, reason) == (row['status'], row['reason']), 'cached reading status mismatch')
            value = numeric(row['reading']['raw'], sensor) if state == 'ok' else None
            need(row['value'] == value and (value is None or type(row['value']) is int), 'cached numeric value mismatch')


def midpoint(row):
    r = row['reading']
    return (r['monotonic_start_ns'] + r['monotonic_end_ns']) // 2


def interval_energy(sensor, a, b, dt):
    kind = sensor['kind']
    x, y = a['value'], b['value']
    if sensor['family'] == 'power_supply':
        if any(signature(a['context_after'][key]) != signature(b['context_before'][key])
               for key in sensor['context_fields']):
            return None, 'power supply state transition between endpoints'
        online = a['context_after']['online']
        if online['status'] == 'ok' and online['raw'].strip() == '0':
            return None, 'power supply offline'
        identity = sensor['identity'][sensor['identity_required']]['raw'].strip()
        if identity == 'Battery' and not all(r['status'] == 'ok' and r['raw'].strip() == 'Discharging'
                for row in (a, b) for r in (row['context_before']['status'], row['context_after']['status'])):
            return None, 'battery not confirmed discharging at both endpoints'
    if kind == 'power':
        return (x + y) * 0.5 * dt / 1e6, None
    if kind == 'energy_counter':
        return ((y - x) / 1e6, None) if y >= x else (None, 'energy counter reset/wrap/decrease')
    if kind == 'stored_energy':
        if identity != 'Battery':
            return None, 'battery not confirmed discharging at both endpoints'
        return ((x - y) * 0.0036, None) if x >= y else (None, 'stored energy increased/reset while discharging')
    return None, None


def summarize(inventory, samples, max_gap_seconds, start_ns=None, end_ns=None):
    validate_samples(inventory, samples)
    need(type(max_gap_seconds) in (int, float) and math.isfinite(max_gap_seconds) and
         0 < max_gap_seconds <= 120, 'max gap must be finite and in (0,120]')
    capture_start, capture_end = samples[0]['start']['monotonic_ns'], samples[-1]['end']['monotonic_ns']
    start_ns = capture_start if start_ns is None else start_ns
    end_ns = capture_end if end_ns is None else end_ns
    need(type(start_ns) is int and type(end_ns) is int and capture_start <= start_ns < end_ns <= capture_end,
         'summary window outside captured range')
    report = {'schema': SCHEMA, 'max_gap_seconds': max_gap_seconds,
              'window_monotonic_start_ns': start_ns, 'window_monotonic_end_ns': end_ns,
              'sensor_count': len(inventory['sensors']), 'sensors': [],
              'scope': 'per-source observed intervals only; no extrapolation, domain sum, whole-system attribution or acceptance'}
    for index, sensor in enumerate(inventory['sensors']):
        selected = [(s, s['readings'][index]) for s in samples if start_ns <= midpoint(s['readings'][index]) <= end_ns]
        values = [r['value'] for _, r in selected if r['status'] == 'ok']
        energy_kind = sensor['kind'] in ('power', 'energy_counter', 'stored_energy')
        gaps, covered, total = [], 0.0, 0.0
        for pair, ((sa, a), (sb, b)) in enumerate(zip(selected, selected[1:])):
            dt = (midpoint(b) - midpoint(a)) / 1e9
            reason = None
            if a['status'] != 'ok' or b['status'] != 'ok':
                reason = 'invalid/missing endpoint'
            elif dt > max_gap_seconds or max((r['reading']['monotonic_end_ns'] - r['reading']['monotonic_start_ns']) / 1e9 for r in (a, b)) > max_gap_seconds:
                reason = 'sampling/read gap'
            elif any(abs((sb['start'][clock] - sa['start'][clock]) - (
                    sb['start']['monotonic_ns'] - sa['start']['monotonic_ns'])) > 50_000_000
                    for clock in ('boottime_ns', 'realtime_ns')) or any(abs((s['end'][clock] - s['start'][clock]) - (
                    s['end']['monotonic_ns'] - s['start']['monotonic_ns'])) > 50_000_000 for s in (sa, sb) for clock in ('boottime_ns', 'realtime_ns')):
                reason = 'clock discontinuity/suspend gap'
            delta = None
            if reason is None and energy_kind:
                delta, reason = interval_energy(sensor, a, b, dt)
            if reason:
                gaps.append({'pair': pair, 'reason': reason, 'seconds': dt})
            else:
                covered += dt
                if delta is not None:
                    total += delta
        first = midpoint(selected[0][1]) if selected else None
        last = midpoint(selected[-1][1]) if selected else None
        span = (last - first) / 1e9 if selected else 0.0
        complete = len(selected) >= 2 and not gaps and len(values) == len(selected)
        report['sensors'].append({'id': sensor['id'], 'kind': sensor['kind'], 'unit': sensor['unit'],
            'status': 'complete' if complete else 'incomplete' if selected else 'unavailable',
            'sample_states': dict(Counter(r['status'] for _, r in selected)), 'valid_samples': len(values),
            'observed_min_raw': min(values) if values else None, 'observed_max_raw': max(values) if values else None,
            'first_read_monotonic_ns': first, 'last_read_monotonic_ns': last,
            'boundary_unobserved_ns': {'start': first - start_ns, 'end': end_ns - last} if selected else None,
            'span_seconds': span, 'covered_seconds': covered, 'coverage_fraction': covered / span if span else None,
            'gaps': gaps, 'accepted_interval_energy_j': total if energy_kind and covered > 0 else None,
            'contiguous_observed_span_energy_j': total if energy_kind and complete else None,
            'observed_span_average_w': total / covered if energy_kind and complete and covered else None,
            'method': {'power': 'trapezoids over actual per-read midpoint time',
                       'energy_counter': 'nondecreasing cumulative counter deltas; no wrap correction',
                       'stored_energy': 'stored-energy decrease with discharging endpoint states; not power integration',
                       'averaged_power': 'raw context only; driver averaging windows not integrated'}.get(sensor['kind'], 'raw context only')})
    return report


def fresh_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


def ordinary(path, cap=MAX_BYTES):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'ordinary input file required')
        data = stream.read(cap + 1)
    need(len(data) <= cap, 'input byte bound')
    return data


def load_capture(directory):
    capture = json.loads(ordinary(directory / 'capture.json', MAX_LINE))
    need(capture['schema'] == SCHEMA and capture['completed'] is True, 'capture not completed')
    inventory_data = ordinary(directory / 'inventory.json', 2 * 1024**2)
    samples_data = ordinary(directory / 'samples.jsonl')
    need(pin_bytes(inventory_data) == capture['files']['inventory.json'] and
         pin_bytes(samples_data) == capture['files']['samples.jsonl'], 'capture file pin mismatch')
    lines = samples_data.splitlines()
    need(len(lines) <= MAX_SAMPLES and all(len(line) <= MAX_LINE for line in lines), 'sample line/count bound')
    return capture, json.loads(inventory_data), [json.loads(line) for line in lines]


def capture(args):
    need(sys.platform == 'linux' and hasattr(time, 'CLOCK_BOOTTIME'), 'Linux boottime clock required')
    need(math.isfinite(args.duration) and 0.1 <= args.duration <= 3600, 'duration must be 0.1..3600 seconds')
    need(math.isfinite(args.interval) and 0.1 <= args.interval <= 60, 'interval must be 0.1..60 seconds')
    need(math.ceil(args.duration / args.interval) + 1 <= MAX_SAMPLES, 'requested sample count bound')
    need(isinstance(args.machine_label, str) and 0 < len(args.machine_label) <= 200, 'machine label required')
    need(len(args.note) <= 16 and all(0 < len(n) <= 500 for n in args.note), 'note bound')
    need(len(args.reference) <= 16, 'reference count bound')
    references = [{'path': str(path.absolute()), **pin_bytes(ordinary(path, 2 * 1024**2))}
                  for path in args.reference]
    inventory = discover()
    inventory_data = encoded(inventory)
    args.output.mkdir(mode=0o700)  # Must be new; parent must already exist.
    fresh_file(args.output / 'inventory.json', inventory_data)
    record = {'schema': SCHEMA, 'completed': False, 'machine_label': args.machine_label,
              'machine_label_source': 'operator; not hardware authentication', 'notes': args.note,
              'references': references,
              'machine': {'architecture': os.uname().machine, 'kernel_release': os.uname().release,
                          'kernel_version': os.uname().version, 'page_bytes': os.sysconf('SC_PAGE_SIZE'),
                          'model': signature(read_text(Path('/sys/firmware/devicetree/base/model'))),
                          'device_tree_compatible': signature(read_text(Path('/sys/firmware/devicetree/base/compatible'))),
                          'boot_id': signature(read_text(Path('/proc/sys/kernel/random/boot_id'))),
                          'dmi_product_name': signature(read_text(Path('/sys/class/dmi/id/product_name')))},
              'collector': pin_bytes(ordinary(Path(__file__), 2 * 1024**2)),
              'duration_seconds_requested': args.duration, 'interval_seconds_requested': args.interval,
              'max_gap_seconds': min(120, args.interval * 2.5), 'start': clocks(), 'limits': LIMITS}
    fresh_file(args.output / 'started.json', encoded(record))
    samples, size = [], 0
    began = time.monotonic_ns()
    deadline = began + round(args.duration * 1e9)
    fd = os.open(args.output / 'samples.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            for sequence in range(MAX_SAMPLES):
                row = snapshot(inventory, sequence)
                data = encoded(row)
                need(len(data) <= MAX_LINE and size + len(data) <= MAX_BYTES, 'capture byte bound')
                stream.write(data); stream.flush()
                samples.append(row); size += len(data)
                now = time.monotonic_ns()
                if now >= deadline:
                    break
                # Never burst to catch up after slow reads or scheduling gaps.
                wake = min(deadline, max(began + round((sequence + 1) * args.interval * 1e9), now + round(args.interval * 1e9)))
                time.sleep(max(0, (wake - time.monotonic_ns()) / 1e9))
            else:
                raise Invalid('sample count exhausted before duration')
        summary = summarize(inventory, samples, record['max_gap_seconds'])
        record.update(completed=True, sample_count=len(samples))
    except (Invalid, OSError, KeyboardInterrupt) as error:
        record['failure'] = type(error).__name__ + ': ' + str(error)[:200]
        raise
    finally:
        record['end'] = clocks()
        record['files'] = {name: pin_bytes(ordinary(args.output / name)) for name in ('inventory.json', 'samples.jsonl')}
        fresh_file(args.output / 'capture.json', encoded(record))
    fresh_file(args.output / 'summary.json', encoded(summary))
    return {'output': str(args.output), 'sample_count': len(samples), 'sensor_count': len(inventory['sensors']),
            'completed': True, 'acceptance': 'none; host read-only component observation only'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    run = sub.add_parser('capture')
    run.add_argument('--output', type=Path, required=True)
    run.add_argument('--duration', type=float, required=True)
    run.add_argument('--interval', type=float, default=1)
    run.add_argument('--machine-label', required=True)
    run.add_argument('--note', action='append', default=[])
    run.add_argument('--reference', type=Path, action='append', default=[])
    summary = sub.add_parser('summarize')
    summary.add_argument('--capture', type=Path, required=True)
    summary.add_argument('--output', type=Path, required=True)
    summary.add_argument('--start-monotonic-ns', type=int)
    summary.add_argument('--end-monotonic-ns', type=int)
    args = parser.parse_args(argv)
    try:
        if args.command == 'capture':
            result = capture(args)
        else:
            record, inventory, samples = load_capture(args.capture)
            result = summarize(inventory, samples, record['max_gap_seconds'], args.start_monotonic_ns, args.end_monotonic_ns)
            result['inputs'] = record['files']
            fresh_file(args.output, encoded(result))
            result = {'output': str(args.output), 'sensor_count': len(inventory['sensors'])}
        print(json.dumps(result, sort_keys=True, allow_nan=False))
        return 0
    except (Invalid, OSError, KeyError, TypeError, ValueError, OverflowError) as error:
        print(type(error).__name__ + ': ' + str(error)[:200], file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
