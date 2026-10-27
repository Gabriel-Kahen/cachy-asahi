#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Opt-in benchmark platform capture with exclusive wait ownership.

No child PID is passed to the sensor thread. Legacy RSS stays unavailable.
"""
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time

COLLECTOR_SHA256 = 'bf3d80c3e5a7d8e8a67c393e2cabf19c2a45945fd023628bdb5dcb5b03b2b4f2'
OWNER_SHA256 = '83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
SCHEMA = 'benchmark-platform-metrics-v1'
_active = None
_unresolved = None


class Invalid(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise Invalid(reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dependencies():
    here = Path(__file__).resolve().parent
    paths = {'collector': here / 'platform_metrics.py',
             'owner': here.parent / 'virtual/owned_process.py'}
    for key, expected in (('collector', COLLECTOR_SHA256), ('owner', OWNER_SHA256)):
        need(paths[key].is_file() and not paths[key].is_symlink() and digest(paths[key]) == expected,
             key + ' differs from reviewed source pin')
    return paths


def load_dependencies():
    modules = {}
    for name, path in dependencies().items():
        spec = importlib.util.spec_from_file_location('platform_sidecar_' + name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules[name] = module
    return modules['collector'], modules['owner']


def validate_config(config, timeout):
    need(type(config) is dict and set(config) == {'interval_seconds'},
         'platform_metrics must contain only interval_seconds')
    interval = config['interval_seconds']
    need(type(interval) in (int, float) and math.isfinite(interval) and 0.1 <= interval <= 10,
         'platform metrics interval must be 0.1..10 seconds')
    need(type(timeout) in (int, float) and math.isfinite(timeout) and 0 < timeout <= 3600 and
         math.ceil((timeout + 0.5) / interval) + 3 <= 10000, 'platform capture duration/sample bound')


def source_paths():
    return [Path(__file__).resolve(), *dependencies().values()]


def machine(collector):
    boot = collector.read_text(Path('/proc/sys/kernel/random/boot_id'))
    need(boot['status'] == 'ok' and re.fullmatch(r'[0-9a-f-]{36}', boot['raw'].strip()),
         'readable boot identity required for clock correlation')
    return {'boot_id': boot['raw'].strip(), 'architecture': os.uname().machine,
            'kernel_release': os.uname().release, 'page_bytes': os.sysconf('SC_PAGE_SIZE')}


def binding_check(capture, samples, binding):
    need(capture['schema'] == SCHEMA and capture['completed'] is True, 'incomplete/unsupported platform capture')
    need(capture['collector_sha256'] == COLLECTOR_SHA256 and capture['owner_sha256'] == OWNER_SHA256,
         'capture source mismatch')
    need(capture['machine_before'] == capture['machine_after'] == binding['machine_before'] == binding['machine_after'],
         'capture/workload machine or boot mismatch')
    need(binding['start'] == capture['workload']['start'] and binding['end'] == capture['workload']['end'],
         'capture/workload boundary mismatch')
    start, end = binding['start'], binding['end']
    for key in ('monotonic_ns', 'boottime_ns', 'realtime_ns'):
        need(type(start[key]) is int and type(end[key]) is int and end[key] > start[key], 'workload clock reversal')
    elapsed = end['monotonic_ns'] - start['monotonic_ns']
    need(all(abs((end[key] - start[key]) - elapsed) <= 50_000_000 for key in ('boottime_ns', 'realtime_ns')),
         'workload clock discontinuity/suspend')
    need(samples and samples[0]['end']['monotonic_ns'] <= start['monotonic_ns'] < end['monotonic_ns'] <= samples[-1]['start']['monotonic_ns'],
         'capture does not bracket workload')
    for point, observed in ((start, samples[0]['end']), (end, samples[-1]['start'])):
        need(all(abs((point[key] - point['monotonic_ns']) - (
                     observed[key] - observed['monotonic_ns'])) <= 50_000_000
                 for key in ('boottime_ns', 'realtime_ns')), 'capture/workload clock origin mismatch')
    for key in ('argv_sha256', 'cwd'):
        need(binding[key] == capture['workload'][key], 'capture/workload ' + key + ' mismatch')


def unavailable_legacy(start):
    return {'monotonic_ns': start, 'thermal': [], 'power': [], 'battery': [],
            'memory': {'root_rss_kib': None, 'lifecycle': 'unknown'},
            'missing': ['memory', 'thermal', 'power', 'battery'],
            'reason': 'opt-in platform metrics are separate; no legacy PID sampler under shared owner API'}


def execute(argv, cwd, env, directory, timeout, legacy_interval, config, summarize_legacy):
    global _active, _unresolved
    need(threading.current_thread() is threading.main_thread(), 'main thread required')
    need(os.geteuid() != 0, 'root workload refused')
    need(_active is None or not _active.is_alive(), 'previous platform sampler still blocked; end this process')
    need(_unresolved is None, 'prior owned wait remains unresolved; no further workloads')
    validate_config(config, timeout)
    collector, owner = load_dependencies()
    identity = machine(collector)
    inventory = collector.discover()
    interval = config['interval_seconds']
    raw = Path(directory) / 'platform-metrics'
    raw.mkdir(mode=0o700)
    collector.fresh_file(raw / 'inventory.json', collector.encoded(inventory))
    samples, accounting = [], {'bytes': 0, 'error': None, 'snapshot_seconds': []}
    stopped = threading.Event()
    stream_fd = os.open(raw / 'samples.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
    stream = os.fdopen(stream_fd, 'wb')

    def sample():
        row = collector.snapshot(inventory, len(samples))
        data = collector.encoded(row)
        need(len(samples) < collector.MAX_SAMPLES and len(data) <= collector.MAX_LINE and
             accounting['bytes'] + len(data) <= collector.MAX_BYTES, 'platform raw capture bound')
        if stopped.is_set():
            return
        stream.write(data); stream.flush()
        samples.append(row)
        accounting['bytes'] += len(data)
        accounting['snapshot_seconds'].append((row['end']['monotonic_ns'] - row['start']['monotonic_ns']) / 1e9)

    def collect():
        try:
            while not stopped.wait(interval):
                sample()
        except Exception as error:
            accounting['error'] = type(error).__name__ + ': ' + str(error)[:200]

    worker, result, binding, child = None, None, None, None
    launch_error = None
    capture = {'schema': SCHEMA, 'completed': False, 'machine_before': identity,
               'collector_sha256': COLLECTOR_SHA256, 'owner_sha256': OWNER_SHA256,
               'adapter_sha256': digest(Path(__file__)), 'max_gap_seconds': min(120, 2.5 * interval),
               'interval_seconds_requested': interval}
    collector.fresh_file(raw / 'started.json', collector.encoded(capture))
    previous_term = signal.getsignal(signal.SIGTERM)
    def interrupt(signum, frame):
        raise KeyboardInterrupt('platform workload interrupted')
    try:
        sample()  # Completed prelaunch observation; setup can overrun before any child exists.
        owner.prepare()
        worker = threading.Thread(target=collect, daemon=True, name='benchmark-platform-metrics')
        _active = worker
        worker.start()
        before = machine(collector)
        start = collector.clocks()
        signal.signal(signal.SIGTERM, interrupt)
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            # No poll/wait/context-manager/finally signal after custody transfer.
            result = owner.supervise(child, cap=timeout + 0.5, retirement=0.5, grace=0.1)
        except BaseException as failure:
            launch_error = type(failure).__name__ + ': ' + str(failure)[:200]
            # Only a Popen never accepted by supervise can still have this state.
            # A transferred UNKNOWN/unreaped Popen disables _child_created; a reaped
            # one has a real returncode. Neither is numerically touched here.
            if child is not None and child.returncode is None and child._child_created:
                result = owner.supervise(child, cap=1.0, retirement=0.5, grace=0.1)
            else:
                raise
        finally:
            signal.signal(signal.SIGTERM, previous_term)
        if not result['reaped'] and result['ownership'] == 'OWNED':
            _unresolved = (child, result)  # Retain the raw wait obligation, without any new signals/probes.
        end = collector.clocks()
        binding = {'machine_before': before, 'machine_after': machine(collector), 'start': start, 'end': end,
                   'argv_sha256': hashlib.sha256(collector.encoded(argv)).hexdigest(), 'cwd': str(Path(cwd).resolve())}
    finally:
        stopped.set()
        if worker is not None:
            worker.join(timeout=0.25)
        if worker is None or not worker.is_alive():
            # The single writer is now stopped. A separate final snapshot brackets the end.
            if binding is not None:
                stopped.clear()
                try:
                    sample()
                except Exception as error:
                    accounting['error'] = type(error).__name__ + ': ' + str(error)[:200]
                finally:
                    stopped.set()
            stream.close()
        else:
            accounting['error'] = 'platform sampler blocked after workload retirement; raw remains incomplete'
        capture.update(machine_after=machine(collector), workload=binding, sampling=accounting,
                       worker_stopped=worker is None or not worker.is_alive(),
                       supervision={key: value for key, value in result.items() if key != 'output'} if result else None,
                       unresolved_wait_pid=child.pid if _unresolved is not None else None)
        if capture['worker_stopped']:
            capture['files'] = {name: collector.pin_bytes(collector.ordinary(raw / name))
                                for name in ('inventory.json', 'samples.jsonl')}
        if result is None or not capture['worker_stopped']:
            capture['failure'] = 'workload or sampler did not produce a completed observation'
            collector.fresh_file(raw / 'capture.json', collector.encoded(capture))
    need(result is not None and capture['worker_stopped'], 'incomplete workload/platform worker')
    serial_result = {key: value for key, value in result.items() if key != 'output'}
    collector.fresh_file(Path(directory) / 'stdout.txt', result['output'])
    collector.fresh_file(Path(directory) / 'stderr.txt', b'')
    error = launch_error or result['error'] or ('owned workload timeout/retirement incomplete' if not result['passed'] else None)
    capture.update(completed=accounting['error'] is None and result['reaped'], supervision=serial_result,
                   log_scope='stdout.txt contains bounded combined stdout/stderr in observed order; stderr.txt empty')
    try:
        binding_check(capture, samples, binding)
        summary = collector.summarize(inventory, samples, capture['max_gap_seconds'],
                                      binding['start']['monotonic_ns'], binding['end']['monotonic_ns'])
    except (ValueError, KeyError, TypeError) as failure:
        capture.update(completed=False, failure=type(failure).__name__ + ': ' + str(failure)[:200])
        collector.fresh_file(raw / 'capture.json', collector.encoded(capture))
        raise Invalid('platform capture binding/summarization failed: ' + str(failure))
    collector.fresh_file(raw / 'capture.json', collector.encoded(capture))
    collector.fresh_file(raw / 'summary.json', collector.encoded(summary))
    legacy = unavailable_legacy(binding['start']['monotonic_ns'])
    collector.fresh_file(Path(directory) / 'telemetry.jsonl', collector.encoded(legacy))
    return {'elapsed_ns': binding['end']['monotonic_ns'] - binding['start']['monotonic_ns'],
            'monotonic_start_ns': binding['start']['monotonic_ns'], 'monotonic_end_ns': binding['end']['monotonic_ns'],
            'returncode': result['exit'], 'error': error,
            'sampling_status': {'worker_stopped': True, 'workload_reaped': result['reaped'],
                                'error': accounting['error'], 'dropped_samples': 0},
            'sample_count': 1, 'metrics': summarize_legacy([legacy]),
            'timing_scope': 'spawn through owned group retirement; includes concurrent platform logging overhead; setup/final snapshot excluded',
            'platform_metrics': {'schema': SCHEMA, 'binding': binding, 'capture': 'platform-metrics/capture.json',
                                 'summary': 'platform-metrics/summary.json', 'source_pins': {
                                     'collector_sha256': COLLECTOR_SHA256, 'owner_sha256': OWNER_SHA256,
                                     'adapter_sha256': digest(Path(__file__))},
                                 'legacy_interval_seconds_ignored': legacy_interval,
                                 'overhead_scope': 'concurrent read/log costs included; no with/without logging estimate',
                                 'optimization_acceptance': 'NOT RUN'}}


def verify_trial(directory, trial, config=None):
    collector, _ = load_dependencies()
    need(trial.get('platform_metrics', {}).get('schema') == SCHEMA, 'trial lacks declared platform capture')
    need(trial['platform_metrics']['source_pins'] == {'collector_sha256': COLLECTOR_SHA256,
         'owner_sha256': OWNER_SHA256, 'adapter_sha256': digest(Path(__file__))}, 'trial platform source mismatch')
    raw = Path(directory) / 'platform-metrics'
    capture = json.loads(collector.ordinary(raw / 'capture.json', collector.MAX_LINE))
    need(capture['adapter_sha256'] == digest(Path(__file__)), 'capture adapter source mismatch')
    need(capture['worker_stopped'] is True and capture['sampling']['error'] is None, 'capture worker incomplete')
    supervision = capture['supervision']
    need(supervision['reaped'] is True and supervision['ownership'] == 'REAPED' and
         supervision['exit'] == trial['returncode'] and trial['sampling_status']['workload_reaped'] is True,
         'trial/capture wait result mismatch')
    if config is not None:
        validate_config(config, 1)
        interval = config['interval_seconds']
        need(capture['interval_seconds_requested'] == interval and
             capture['max_gap_seconds'] == min(120, 2.5 * interval), 'capture sampling differs from frozen plan')
    inventory_data = collector.ordinary(raw / 'inventory.json', 2 * 1024**2)
    samples_data = collector.ordinary(raw / 'samples.jsonl')
    need(capture['files'] == {'inventory.json': collector.pin_bytes(inventory_data),
                            'samples.jsonl': collector.pin_bytes(samples_data)}, 'platform capture pin mismatch')
    lines = samples_data.splitlines()
    need(len(lines) <= collector.MAX_SAMPLES and all(len(row) <= collector.MAX_LINE for row in lines), 'platform raw count/line bound')
    samples = [json.loads(row) for row in lines]
    binding = trial['platform_metrics']['binding']
    need(trial['monotonic_start_ns'] == binding['start']['monotonic_ns'] and
         trial['monotonic_end_ns'] == binding['end']['monotonic_ns'], 'trial/platform clock mismatch')
    need(trial['cwd'] == binding['cwd'] and hashlib.sha256(collector.encoded(trial['argv'])).hexdigest() == binding['argv_sha256'],
         'trial/platform workload mismatch')
    binding_check(capture, samples, binding)
    expected = collector.summarize(json.loads(inventory_data), samples, capture['max_gap_seconds'],
                                  trial['monotonic_start_ns'], trial['monotonic_end_ns'])
    need(json.loads(collector.ordinary(raw / 'summary.json', 4 * 1024**2)) == expected, 'platform derived summary mismatch')
    return expected
