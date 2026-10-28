#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only sections() microbenchmark of two explicitly reviewed inventory sources."""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

MAX_SOURCE = 128 * 1024
MAX_RECORD = 1024 * 1024
MAX_VALUES = 16384
MAX_JSON = 64 * 1024


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def read(path, cap):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= cap, 'bounded ordinary input required')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(cap + 1)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(os.stat(path, follow_symlinks=False)), 'input changed during read')
        return raw
    finally:
        os.close(fd)


def parser(raw, label):
    # Avoid module imports/initializers: execute only these two reviewed functions.
    tree = ast.parse(raw, filename=label)
    selected = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ('need', 'sections')]
    need(sorted(n.name for n in selected) == ['need', 'sections'], 'unique need/sections functions required')
    for node in selected:
        need(not node.decorator_list and not node.args.defaults and not node.args.kw_defaults and
             not node.args.vararg and not node.args.kwarg and not node.args.posonlyargs and
             not node.args.kwonlyargs and len(node.args.args) == 2 and node.returns is None and
             all(a.annotation is None for a in node.args.args), 'plain two-argument parser functions required')
    namespace = {'re': re, '__builtins__': {'ValueError': ValueError, 'any': any, 'ord': ord, 'set': set}}
    exec(compile(ast.Module(body=selected, type_ignores=[]), label, 'exec'), namespace)
    return namespace['sections']


def outcome(function, raw, allowed):
    try:
        # Include mapping insertion order as well as every ordered value list.
        return dict(status='PARSED', value=list(function(raw, set(allowed)).items()))
    except (ValueError, UnicodeError) as error:
        return dict(status='REFUSED', type=type(error).__name__, message=str(error))


def fixture(count):
    need(type(count) is int and 1 <= count <= MAX_VALUES, 'fixture values must be1..16384')
    return ('%FILES%\n' + ''.join('usr/share/parser-fixture/file-%05d\n' % i for i in range(count)) + '\n').encode()


def benchmark(baseline, candidate, *, record=None, values=MAX_VALUES, repeats=4,
              sections=('FILES', 'BACKUP'), machine_label='', execution_context='unknown'):
    need(type(repeats) is int and 2 <= repeats <= 20 and repeats % 2 == 0, 'repeats must be even2..20')
    need(0 < len(sections) <= 32 and len(set(sections)) == len(sections) and
         all(re.fullmatch('[A-Z][A-Z0-9_]*', s) and len(s) <= 32 for s in sections), 'bounded distinct section names required')
    need(len(machine_label) <= 128 and execution_context in ('unknown', 'physical', 'vm'), 'bounded operator context required')
    paths = dict(baseline=Path(baseline).absolute(), candidate=Path(candidate).absolute())
    sources = {k: read(p, MAX_SOURCE) for k, p in paths.items()}
    functions = {k: parser(raw, str(paths[k])) for k, raw in sources.items()}
    record_path = Path(record).absolute() if record is not None else None
    raw = read(record_path, MAX_RECORD) if record_path is not None else fixture(values)
    need(len(raw) <= MAX_RECORD and raw.count(b'\n') <= MAX_VALUES + 64, 'record byte/line bound')
    started = datetime.now(timezone.utc).isoformat()
    load_before = os.getloadavg()
    # Require equivalence for actual operand and known duplicate/refusal seams before any timing.
    controls = [
        (b'%FILES%\na\nb\n\n', {'FILES'}),
        (b'%FILES%\na\na\n\n', {'FILES'}),
        (b'%DEPENDS%\na\na\nb\n\n', {'DEPENDS'}),
        (b'%FILES%\na', {'FILES'}),
        (b'%UNKNOWN%\na\n\n', {'FILES'}),
        (b'%FILES%\na\x00\n\n', {'FILES'}),
        (b'%FILES%\na\n\n%FILES%\nb\n\n', {'FILES'}),
        (b'%FILES%\n\xff\n\n', {'FILES'}),
    ]
    for data, allowed in controls:
        need(outcome(functions['baseline'], data, allowed) == outcome(functions['candidate'], data, allowed),
             'parser control outputs/refusals differ; timing refused')
    expected = outcome(functions['baseline'], raw, sections)
    need(expected == outcome(functions['candidate'], raw, sections), 'workload outputs/refusals differ; timing refused')
    rows = []
    for repeat in range(repeats):
        order = ('baseline', 'candidate') if repeat % 2 == 0 else ('candidate', 'baseline')
        for role in order:
            start = time.perf_counter_ns()
            result = outcome(functions[role], raw, sections)
            elapsed = time.perf_counter_ns() - start
            need(result == expected, 'timed parser outcome changed')
            rows.append(dict(repeat=repeat, role=role, elapsed_ns=elapsed))
    need(all(read(paths[k], MAX_SOURCE) == v for k, v in sources.items()), 'parser source changed during benchmark')
    if record_path is not None:
        need(read(record_path, MAX_RECORD) == raw, 'record changed during benchmark')
    uname = os.uname()
    report = dict(
        schema_version=1, kind='APPS_INVENTORY_SECTIONS_MICROBENCHMARK',
        qualification='SYNTHETIC_RECORD_MICROBENCHMARK' if record_path is None else 'EXPLICIT_RECORD_PARSER_MICROBENCHMARK',
        hardware_acceptance='NOT_ESTABLISHED', full_inventory_performance='NOT_MEASURED',
        sources={k: dict(path=str(paths[k]), **pin(v)) for k, v in sources.items()},
        workload=dict(origin='DETERMINISTIC_UNIQUE_FILES' if record_path is None else 'READONLY_EXPLICIT_RECORD',
                      path=None if record_path is None else str(record_path), **pin(raw),
                      lf_count=raw.count(b'\n'), generated_values=values if record_path is None else None,
                      allowed_sections=list(sections), outcome_status=expected['status'],
                      outcome=pin(encoded(expected))),
        equivalence=dict(control_cases=len(controls), exact_outputs_and_refusals=True,
                         untimed_workload_checks_per_variant=1, timed_outcomes_checked=True),
        context=dict(python=sys.version, executable=sys.executable,
                     uname=dict(zip(('sysname','nodename','release','version','machine'), uname)),
                     page_size=os.sysconf('SC_PAGE_SIZE'), machine_label=machine_label,
                     execution_context=execution_context, utc_start=started,
                     utc_end=datetime.now(timezone.utc).isoformat(), load_before=load_before, load_after=os.getloadavg()),
        timing=dict(clock='perf_counter_ns', scope='sections call plus identical outcome/refusal capture; comparison and hashing excluded',
                    order='ALTERNATING_AB_BA', repeats_per_variant=repeats, samples=rows,
                    cache='WARM_AFTER_UNTIMED_EQUIVALENCE_CHECKS', isolation='SAME_PROCESS_NO_CPU_PINNING_OR_THERMAL_CONTROL'))
    need(len(encoded(report)) <= MAX_JSON, 'bounded JSON report required')
    return report


def main(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--baseline', required=True, type=Path)
    cli.add_argument('--candidate', required=True, type=Path)
    workload = cli.add_mutually_exclusive_group()
    workload.add_argument('--record', type=Path)
    workload.add_argument('--values', type=int, default=MAX_VALUES)
    cli.add_argument('--repeats', type=int, default=4)
    cli.add_argument('--sections', nargs='+', default=['FILES', 'BACKUP'])
    cli.add_argument('--machine-label', default='')
    cli.add_argument('--execution-context', choices=('unknown', 'physical', 'vm'), default='unknown')
    args = cli.parse_args(argv)
    try:
        result = benchmark(**vars(args))
        print(encoded(result).decode())
    except (OSError, ValueError, SyntaxError, TypeError, KeyError) as error:
        print('parser benchmark refused: ' + str(error)[:512], file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
