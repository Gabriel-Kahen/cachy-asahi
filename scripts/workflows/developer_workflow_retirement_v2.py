#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit pinned reserved-leader v2 command runner; no legacy caller mutation."""
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
CORE_PIN='d1a09f0989afe97a3ea84a20eb6608d282c6a95e2d1e665185e47366f408a16e'

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def load_core():
    path = ROOT / 'scripts/virtual/owned_process_retirement_v2.py'
    raw = path.read_bytes()
    if pin(raw)['sha256'] != CORE_PIN:
        raise ValueError('reviewed retirement-v2 core pin differs')
    spec = importlib.util.spec_from_file_location('_developer_retirement_v2', path)
    module = importlib.util.module_from_spec(spec)
    # Execute the exact verified bytes, avoiding a second path read/pyc lookup.
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


class Failure(ValueError):
    pass


class RetirementCommands:
    """Single main-thread wait owner. Logs are written only after supervision."""
    def __init__(self, output, home, tool_path, timeout=15, total=180, max_output=128*1024):
        if (type(max_output) is not int or not 0 <= max_output <= 1024*1024
                or not all(type(x) in (int, float) and math.isfinite(x)
                           for x in (timeout, total)) or not 2 <= timeout <= total <= 600):
            raise ValueError('finite command budgets and output cap required before launch')
        self.output = Path(output)
        self.env = dict(PATH=tool_path, HOME=str(home), LC_ALL='C.UTF-8', TZ='UTC',
                        GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                        GIT_TERMINAL_PROMPT='0', GIT_ALLOW_PROTOCOL='file',
                        PYTHONDONTWRITEBYTECODE='1')
        self.timeout, self.max_output = timeout, max_output
        self.deadline = time.monotonic() + total
        self.records = []
        self.core = load_core()
        self.cancelled = []

    def run(self, step, argv, cwd, expected=0):
        if self.cancelled:
            raise Failure('cancellation requested; prior child already retired')
        remaining = min(self.timeout, self.deadline - time.monotonic())
        if remaining <= 1.1:
            raise Failure('workflow deadline exhausted before launch')
        if not isinstance(argv, list) or not argv or any(type(a) is not str for a in argv):
            raise ValueError('explicit argv list required')
        if not Path(argv[0]).is_absolute():
            raise ValueError('absolute executable path required')
        self.core.prepare()
        handlers = {sig: signal.signal(sig, lambda number, frame: self.cancelled.append(number))
                    for sig in (signal.SIGINT, signal.SIGTERM)}
        result = None
        row = dict(step=step, argv=argv, cwd=str(cwd), expected=expected, success=False)
        try:
            # No context manager/poll/wait/communicate: core owns every wait.
            child = subprocess.Popen(argv, cwd=cwd, env=self.env,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            result = self.core.supervise(child, cap=remaining, retirement=1,
                                         grace=.2, max_output=self.max_output)
        except OSError as error:
            row['launch_error'] = str(error)
        finally:
            for sig, handler in handlers.items():
                signal.signal(sig, handler)
        raw = result.pop('output') if result is not None else b''
        log = '%03d-%s.log' % (len(self.records), step)
        # Late logging failure never gains a PID or cleanup authority.
        (self.output / log).write_bytes(raw)
        row.update(log=log, log_pin=pin(raw), supervision=result,
                   channels='stdout+stderr combined in pipe order')
        if result is not None:
            retired = (result['reaped'] and result['ownership'] == 'REAPED'
                       and result['group_census'] == 'RESERVED_LEADER_ONLY'
                       and result['output_complete'] and not result['timeout']
                       and not result['signals'] and result['error'] is None
                       and result['seconds'] < remaining)
            matched = result['exit'] > 0 if expected == 'nonzero' and result['exit'] is not None else result['exit'] == expected
            row['success'] = bool(retired and matched and not self.cancelled)
        self.records.append(row)
        save(self.output / 'commands.json', self.records)
        if not row['success']:
            raise Failure('command failed or retirement unknown: ' + step)
        return raw
