#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Versioned legacy-format capture: shared wait owner, PID-free sensor worker."""
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import stat
import subprocess
import threading
import time

SCHEMA = 'benchmark-owned-retirement-v2'
OWNER_SHA256 = '83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
MAX_OUTPUT = 512 * 1024
MAX_LINE = 128 * 1024
MAX_TELEMETRY = 16 * 1024**2
MAX_SAMPLES = 4096
RETIREMENT = .5
_worker = None
_unresolved = None


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def pin(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 256 * 1024,
         'bounded ordinary owned-retirement source required')
    raw = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def owner_path():
    path = Path(__file__).resolve().parents[1] / 'virtual/owned_process.py'
    need(pin(path)['sha256'] == OWNER_SHA256, 'owned process source differs from reviewed pin')
    return path


def owner_module():
    spec = importlib.util.spec_from_file_location('benchmark_v2_wait_owner', owner_path())
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + '\n').encode()


def fresh(path, raw):
    with Path(path).open('xb') as stream:
        stream.write(raw)


def ordinary(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_size <= cap, 'bounded ordinary raw file required')
        raw = stream.read(cap + 1)
    need(len(raw) <= cap and len(raw) == info.st_size, 'raw file grew/changed during bounded read')
    return raw


def raw_files(directory):
    directory = Path(directory)
    files = {name: ordinary(directory / name, cap) for name, cap in (
        ('stdout.txt', MAX_OUTPUT), ('stderr.txt', 0), ('telemetry.jsonl', MAX_TELEMETRY),
        ('owned-retirement.json', 16 * 1024**2))}
    lines = files['telemetry.jsonl'].splitlines()
    need(len(lines) <= MAX_SAMPLES and all(len(line) <= MAX_LINE for line in lines), 'raw telemetry line/sample bound')
    return files


def declaration(interval):
    return dict(schema=SCHEMA, raw='owned-retirement.json', owner_sha256=OWNER_SHA256,
                adapter_sha256=pin(__file__)['sha256'], interval_seconds=interval,
                log_scope='stdout.txt is bounded combined stdout/stderr; stderr.txt empty')


def execute(argv, cwd, env, directory, timeout, interval, sensors, summarize, rss_metrics):
    """sensors takes NO PID; only the pinned owner may touch numeric children."""
    global _worker, _unresolved
    need(threading.current_thread() is threading.main_thread(), 'main thread required')
    need(_worker is None or not _worker.is_alive(), 'prior sensor worker blocked; end this process')
    need(_unresolved is None, 'prior wait custody unresolved; no further workload in this process')
    need(type(timeout) in (int, float) and math.isfinite(timeout) and timeout > 0 and
         type(interval) in (int, float) and math.isfinite(interval) and .01 <= interval <= 60 and
         math.ceil((timeout + RETIREMENT) / interval) + 3 <= MAX_SAMPLES,
         'owned retirement timeout/interval/sample bound')
    need(type(argv) is list and argv and all(type(part) is str and '\0' not in part for part in argv)
         and Path(argv[0]).is_absolute(), 'trusted absolute argv required')
    owner = owner_module()
    owner.prepare()  # Before launch; reject inherited/custom SIGCHLD.
    directory = Path(directory)
    started = time.monotonic_ns()
    samples = []
    accounting = dict(error=None, dropped_samples=0, worker_stopped=True, workload_reaped=False)
    stopped = threading.Event()
    output = (directory / 'telemetry.jsonl').open('xb')
    used = 0

    def collect():
        nonlocal used
        try:
            while not stopped.is_set():
                row = sensors()  # No child identity enters this thread.
                data = encoded(row)
                need(len(samples) < MAX_SAMPLES and len(data) <= MAX_LINE and
                     used + len(data) <= MAX_TELEMETRY, 'legacy telemetry byte/sample bound')
                if stopped.is_set():
                    break
                output.write(data)
                output.flush()
                samples.append(row)
                used += len(data)
                stopped.wait(interval)
        except Exception as exc:
            accounting['error'] = type(exc).__name__ + ': ' + str(exc)[:300]
        finally:
            try:
                output.close()  # The writer owns its FD, even after a blocked join.
            except OSError as exc:
                accounting['error'] = accounting['error'] or type(exc).__name__ + ': ' + str(exc)[:300]

    child, result, launch_error, cancelled = None, None, None, []
    launch_attempted, spawn_timeout = False, False
    previous_term = signal.getsignal(signal.SIGTERM)

    def interrupt(signum, frame):
        cancelled.append(signum)
        raise KeyboardInterrupt('interrupted by SIGTERM')

    try:
        _worker = threading.Thread(target=collect, daemon=True, name='benchmark-v2-sensors')
        _worker.start()
        signal.signal(signal.SIGTERM, interrupt)
        remaining = timeout - (time.monotonic_ns() - started) / 1e9
        need(remaining > .001, 'timeout before owned workload launch')
        launch_attempted = True
        child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        remaining = timeout - (time.monotonic_ns() - started) / 1e9
        spawn_timeout = remaining <= 0
        result = owner.supervise(child, cap=max(.001, remaining) + RETIREMENT, retirement=RETIREMENT,
                                 grace=.1, rss_interval=interval, max_output=MAX_OUTPUT)
    except BaseException as exc:
        launch_error = type(exc).__name__ + ': ' + str(exc)[:300]
        # Only a never-transferred Popen can enter this fallback. UNKNOWN and
        # unresolved transfers disable _child_created; raw-reaped ones have truth.
        if child is not None and child.returncode is None and child._child_created:
            result = owner.supervise(child, cap=1, retirement=RETIREMENT, grace=.1,
                                     rss_interval=interval, max_output=MAX_OUTPUT)
    finally:
        # Retain custody BEFORE any restoration, join or logging can fail.
        if ((child is not None and (result is None or not result['reaped']))
                or (launch_attempted and child is None)):
            _unresolved = (child, result)
        signal.signal(signal.SIGTERM, previous_term)
        stopped.set()
        if _worker is not None and _worker.ident is not None:
            _worker.join(timeout=.25)
        accounting['worker_stopped'] = _worker is None or not _worker.is_alive()
        if accounting['worker_stopped']:
            if not samples:
                row = dict(monotonic_ns=time.monotonic_ns(), thermal=[], power=[], battery=[],
                           memory=dict(root_rss_kib=None, lifecycle='unknown'),
                           missing=['thermal', 'power', 'battery', 'memory'],
                           reason='no completed PID-free sensor snapshot')
                samples.append(row)
                with (directory / 'telemetry.jsonl').open('ab') as fallback:
                    fallback.write(encoded(row))
            output.close()
        else:
            accounting['error'] = accounting['error'] or 'sensor worker blocked after owned retirement'
    ended = time.monotonic_ns()
    serial = {key: value for key, value in result.items() if key != 'output'} if result else None
    raw_output = result['output'] if result else b''
    fresh(directory / 'stdout.txt', raw_output)
    fresh(directory / 'stderr.txt', b'')
    accounting['workload_reaped'] = bool(result and result['reaped'])
    record = declaration(interval) | dict(monotonic_start_ns=started, monotonic_end_ns=ended,
        supervision=serial, sampling_status=dict(accounting),
        output_sha256=hashlib.sha256(raw_output).hexdigest())
    data = encoded(record)
    need(len(data) <= 16 * 1024**2, 'owned retirement receipt bound')
    fresh(directory / 'owned-retirement.json', data)
    error = launch_error or (result['error'] if result else 'no owned wait result')
    if spawn_timeout or (result and result['timeout']):
        error = 'timeout'
    if cancelled:
        error = 'interrupted by SIGTERM'
    if accounting['error'] or not accounting['worker_stopped'] or not result or not result['passed']:
        error = error or 'telemetry/owned retirement incomplete'
    measured = summarize(samples) if accounting['worker_stopped'] else summarize([])
    if result and 'rss' in result:
        measured.update(rss_metrics(result['rss'], started, ended, interval))
    return dict(elapsed_ns=ended-started, monotonic_start_ns=started, monotonic_end_ns=ended,
                returncode=result['exit'] if result else None, error=error,
                sampling_status=accounting, sample_count=len(samples), metrics=measured,
                timing_scope='spawn through owned retirement and bounded PID-free sensor join; new v2 baseline required',
                owned_retirement=declaration(interval))


def verify(directory, trial, interval, samples, summarize, rss_metrics):
    """Offline replay; never probe a numeric child or reinterpret old trials."""
    directory = Path(directory)
    files = raw_files(directory)
    raw = json.loads(files['owned-retirement.json'])
    need(trial.get('owned_retirement') == declaration(interval), 'owned retirement trial binding differs')
    need(all(raw.get(key) == value for key, value in declaration(interval).items()), 'owned retirement source/scope/config differs')
    need(raw['monotonic_start_ns'] == trial['monotonic_start_ns'] and
         raw['monotonic_end_ns'] == trial['monotonic_end_ns'] and
         raw['sampling_status'] == trial['sampling_status'], 'owned retirement clock/status differs')
    supervision = raw['supervision']
    need(supervision and supervision['reaped'] is True and supervision['ownership'] == 'REAPED'
         and supervision['exit'] == trial['returncode'], 'owned raw wait truth unavailable/different')
    need(hashlib.sha256(files['stdout.txt']).hexdigest() == raw['output_sha256'], 'owned output scope/byte pin differs')
    measured = summarize(samples) | rss_metrics(supervision['rss'], trial['monotonic_start_ns'],
                                               trial['monotonic_end_ns'], interval)
    if trial.get('valid') is True:
        need(supervision['passed'] is True and supervision['timeout'] is False and
             supervision['signals'] == [] and supervision['error'] is None and
             supervision['output_complete'] is True and supervision['group_census'] == 'RESERVED_LEADER_ONLY'
             and supervision['rss']['status'] == 'complete' and measured['root_rss_kib'] is not None
             and measured['process_group_sampled_rss_kib'] is not None, 'valid trial contradicts owned measurement/retirement')
    return measured
