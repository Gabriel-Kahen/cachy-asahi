#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Versioned owned-retirement paired slots, correctness, warmups and timing.

Trusted argv only; not a sandbox. Control-only plans grant no ARM/target credit.
"""
import argparse
import json
import importlib.util
import stat
import os
from pathlib import Path
import platform
import re
import signal
from types import SimpleNamespace
import sys
import tempfile
import time
from uuid import uuid4

def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


B = _load('paired_v2_benchmark', 'benchmark_v2.py')
_legacy = _load('paired_v2_historical_benchmark', 'benchmark.py')
# The unchanged workload adapter imports its historical preparation dependency.
# Scope that import to this private adapter instance; never replace an existing
# caller's module or bind an old frozen plan to the new execution layer.
_missing = object()
_previous = sys.modules.get('benchmark', _missing)
sys.modules['benchmark'] = _legacy
try:
    Z = _load('paired_v2_zlib_workload', 'zlib_workload.py')
finally:
    if _previous is _missing:
        del sys.modules['benchmark']
    else:
        sys.modules['benchmark'] = _previous

ABBA = ['baseline', 'candidate', 'candidate', 'baseline']
BAAB = ['candidate', 'baseline', 'baseline', 'candidate']
ORDER = ABBA + BAAB + ABBA
ARM_ARGV_FILE_OPERANDS = (2, 5, 7, 9)


def need(ok, why):
    if not ok:
        raise ValueError(why)


def ordinary(path, cap=2 * 1024**2):
    need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents))
         and path.is_file() and path.stat().st_size <= cap, 'bounded absolute ordinary file required')
    raw = path.read_bytes()
    need(len(raw) <= cap, 'input byte bound')
    return raw


def pin(path):
    raw = ordinary(path)
    return dict(path=str(path), bytes=len(raw), sha256=Z.sha(raw))


def balanced(order):
    need(type(order) is list and 12 <= len(order) <= 40 and len(order) % 4 == 0
         and all(order[i:i + 4] == (ABBA if i // 4 % 2 == 0 else BAAB)
                 for i in range(0, len(order), 4)), '12..40 alternating ABBA/BAAB slots required')


def workload_report(raw, expected, control_only):
    r = json.loads(raw)
    need(type(r) is dict and r.get('status') == 'PASS' and r.get('optimization_acceptance') == 'NOT RUN'
         and r.get('hardware_validation') == 'NOT RUN', 'successful scoped workload report required')
    need(r.get('minigzip') == expected and r.get('minigzip_sha256') == Z.sha(Z.file_bytes(Path(expected))),
         'executed artifact identity differs')
    Z.bounds(r.get('payload_bytes'), r.get('iterations'))
    need(all(isinstance(r.get(key), str) and re.fullmatch('[a-f0-9]{64}', r[key])
             for key in ('payload_sha256', 'heldout_sha256')), 'complete workload/corpus digests required')
    need(type(r.get('checks')) is list and len(r['checks']) == r['iterations']
         and type(r.get('compression_level')) is int and r['compression_level'] == 6
         and all(type(c) is dict and type(c.get('iteration')) is int and c['iteration'] == i
                 and c.get('decoded_sha256') == r['payload_sha256']
                 and isinstance(c.get('encoded_sha256'), str)
                 and re.fullmatch('[a-f0-9]{64}', c.get('encoded_sha256', ''))
                 for i, c in enumerate(r['checks'])), 'complete per-iteration correctness report required')
    need(r.get('control_only') is True if control_only else
         r.get('control_only', False) is False and r.get('experiment') in Z.EXPERIMENTS,
         'explicit fixture or original ARM experiment scope required')
    return r


def workload_check(plan):
    config = plan['config']
    control_only = config['paired_zlib'] == 'control-only'
    identity = payload_sha256 = None
    if not control_only:
        values = dict(zip(config['argv'][4::2], config['argv'][5::2]))
        corpus = Path(values['--corpus-manifest'])
        archive = Path(values['--archive-manifest'])
        size, iterations = int(values['--payload-bytes']), int(values['--iterations'])

    def check(raw, variant):
        nonlocal identity, payload_sha256
        report = workload_report(raw, config['change'][variant], control_only)
        if not control_only:
            experiment, _, heldout = Z.materials(corpus.parent.parent, archive)
            if payload_sha256 is None:
                payload_sha256 = Z.sha((heldout * ((size + len(heldout) - 1) // len(heldout)))[:size])
            need(report['experiment'] == experiment and report['heldout_sha256'] == Z.sha(heldout)
                 and report['payload_sha256'] == payload_sha256 and report['payload_bytes'] == size
                 and report['iterations'] == iterations, 'original workload output joins differ')
        observed = tuple(report[key] for key in ('payload_sha256', 'payload_bytes', 'heldout_sha256', 'iterations'))
        need(identity is None or observed == identity, 'paired workload/corpus identity differs')
        identity = observed
        return report

    return check


def validate(plan, control_only, *, replay=False):
    c = plan['config']
    need(c.get('paired_zlib') == ('control-only' if control_only else 'exact-arm'),
         'paired workload verification scope must be frozen')
    need(str(Path(__file__).resolve()) in c['inputs'], 'paired runner source must be frozen')
    declared = set(c['inputs']) | {p for paths in c.get('variant_inputs', {}).values() for p in paths}
    declared |= {str(Path(B.__file__).resolve()), str(Path(B.process_group_memory.__file__).resolve())}
    need(declared <= {r['path'] for r in plan['inputs']}, 'declared input lacks actual frozen pin row')
    balanced(c['order'])
    need(c['minimum_trials'] >= 6 and not c.get('allowed_state_changes'), 'six trials/variant and unchanged base required')
    need(c.get('variant_env') == {v: {'ZLIB_MINIGZIP': c['change'][v]} for v in ('baseline', 'candidate')}
         and c['change'].get('environment_key') == 'ZLIB_MINIGZIP', 'sole artifact environment delta required')
    for v in ('baseline', 'candidate'):
        need(c.get('variant_inputs', {}).get(v) == [c['change'][v]] and (replay or os.access(c['change'][v], os.X_OK)),
             'exact executable variant pin required')
    need((replay or not any(k.startswith(('LD_', 'DYLD_', 'QEMU_')) for k in os.environ))
         and not any(k.startswith(('LD_', 'DYLD_', 'QEMU_')) for k in c.get('env', {})), 'loader/emulation override refused')
    if control_only:
        need(c['execution_context'] != 'physical', 'control-only cannot represent physical measurement')
        return
    need(c['execution_context'] == 'physical' and (replay or platform.machine() == 'aarch64'), 'physical native ARM required')
    need(all(s['architecture'] == 'aarch64' and s['page_size_bytes'] == 16384
             and s['m2_air_size'] in ('13-inch', '15-inch') for s in plan['states'].values()),
         'exact 16K M2 Air state required')
    argv = c['argv']
    need(set(c.get('argv_file_operands', [])) == set(ARM_ARGV_FILE_OPERANDS),
         'exact zlib workload requires explicit driver, archive and corpus file operands')
    need(argv[1:4] == ['-B', str(Path(Z.__file__).resolve()), 'run']
         and (replay or argv[0] == str(Path(sys.executable).resolve())),
         'unchanged zlib workload driver required')
    keys = ['--archive-manifest', '--corpus-manifest', '--input', '--payload-bytes', '--iterations']
    need(len(argv) == 14 and argv[4::2] == keys, 'closed zlib argv required')
    values = dict(zip(keys, argv[5::2]))
    corpus = Path(values['--corpus-manifest'])
    experiment, root, _ = Z.materials(corpus.parent.parent, Path(values['--archive-manifest']))
    need(corpus == root / 'corpus/manifest.json' and Path(values['--input']) == root / 'corpus/heldout-source.bin',
         'original held-out corpus paths required')
    Z.bounds(int(values['--payload-bytes']), int(values['--iterations']))
    required = {argv[0], str(Path(__file__).resolve()), str(Path(Z.__file__).resolve()),
                str(Path(B.__file__).resolve()), str(Path(_legacy.__file__).resolve()),
                str(corpus), str(root / 'corpus/heldout-source.bin'), values['--archive-manifest']}
    need(required <= set(c['inputs']), 'workload/artifact/corpus source pins required')
    need(c['change']['baseline'] == str(root / 'baseline-1/minigzip')
         and c['change']['candidate'] == str(root / (Z.EXPERIMENTS[experiment][0] + '-1/minigzip')),
         'exact original baseline and candidate required')


def schedule(config, blocks):
    need(type(blocks) is int and 1 <= blocks <= 2, 'one or two excluded warmup blocks required')
    steps = [('correctness', 0, 'baseline'), ('correctness', 1, 'candidate')]
    steps += [('warmup', i, v) for i, v in enumerate((ABBA + BAAB)[:4 * blocks])]
    steps += [('measured', i, v) for i, v in enumerate(config['order'])]
    return [dict(phase=p, index=i, variant=v, slot=i if p == 'measured' else config['order'].index(v),
                 name=f'{p}-{i:02d}') for p, i, v in steps]


def save_session(output, value):
    with tempfile.TemporaryDirectory(prefix='.session-', dir=output) as staging:
        temp = Path(staging) / 'session.json'
        with temp.open('x') as stream:
            json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
            stream.write('\n')
        temp.replace(output / 'session.json')


def wait_for_observation(path, config, step, requested_at, deadline):
    while True:
        remaining = deadline - time.monotonic()
        need(remaining > 0, 'session deadline waiting for conditions: ' + path.name)
        try:
            raw = B.read_observed_conditions(path)
        except FileNotFoundError:
            time.sleep(min(.25, remaining))
            continue
        received_at = B.now()
        receipt = dict(requested_at=requested_at, received_at=received_at, sha256=Z.sha(raw))
        conditions = json.loads(raw)
        B.validate_observed_conditions(conditions, step, receipt, received_at)
        B.validate_conditions(config, conditions)
        return receipt, dict(path=str(path), bytes=len(raw), **receipt)


def run(args):
    need(os.getuid() == os.geteuid() > 0, 'ordinary nonroot measurement only')
    plan_path = args.plan.absolute()
    ordinary(plan_path)
    plan = B.load_plan(plan_path)
    validate(plan, args.control_only)
    c = plan['config']
    mode = args.conditions_mode
    need(mode == 'observed' or (mode == 'prewritten' and args.control_only),
         'physical paired zlib requires observed conditions; prewritten mode is control-only')
    steps = schedule(c, args.warmup_blocks)
    B.number(args.session_seconds, 'session_seconds', c['timeout_seconds'] + 2, 14400)
    output = args.output.absolute()
    need(not output.exists() and not any(p.is_symlink() for p in output.parents), 'fresh ordinary session directory required')
    conditions_root = args.conditions_root.absolute()
    need(conditions_root.is_dir() and not any(p.is_symlink() for p in (conditions_root, *conditions_root.parents))
         and not output.is_relative_to(conditions_root) and not conditions_root.is_relative_to(output),
         'ordinary separate conditions directory required')
    conditions = {}
    if mode == 'prewritten':
        for step in steps:
            path = conditions_root / (step['name'] + '.json')
            raw = ordinary(path)
            B.validate_conditions(c, json.loads(raw))
            conditions[step['name']] = dict(path=str(path), bytes=len(raw), sha256=Z.sha(raw))
    need(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'session requires its own inactive deadline timer')
    output.mkdir(mode=0o700)
    (output / 'plan.json').write_bytes(ordinary(plan_path))
    session = dict(schema_version=1, session_id=uuid4().hex, status='RUNNING', plan=pin(plan_path), started_at=B.now(),
                   conditions_mode=mode, session_seconds=args.session_seconds,
                   scope='CONTROL_ONLY' if args.control_only else 'EXACT_ARM_PAIRED_MEASUREMENT_PENDING_REVIEW',
                   schedule=steps, completed=[], warmups_excluded=True, environment_sha256=B.canonical(dict(os.environ)),
                   hardware_validation='NOT RUN', optimization_acceptance='NOT RUN', release='NOT ADMITTED',
                   limitations=['Elapsed includes Python, startup, file I/O, verification and telemetry.',
                                'Conditions are operator declarations; missing sensors remain unavailable.',
                                'No population, energy, final-system or model-wide gain is inferred.'])
    if mode == 'observed':
        session['conditions_max_age_seconds'] = B.OBSERVED_CONDITIONS_MAX_AGE
        session['conditions_max_bytes'] = B.OBSERVED_CONDITIONS_MAX_BYTES
    cpu = B.text_file('/proc/cpuinfo') or ''
    fields = {'processor', 'model name', 'CPU architecture', 'CPU implementer', 'CPU part', 'Features', 'Hardware'}
    B.write_json(output / 'environment.json', dict(architecture=platform.machine(), kernel=platform.release(),
        page_size=os.sysconf('SC_PAGE_SIZE'), python=sys.version, uid=os.getuid(), euid=os.geteuid(),
        affinity=sorted(os.sched_getaffinity(0)), logical_cpus=os.cpu_count(),
        cpu=[line for line in cpu.splitlines() if line.split(':', 1)[0].strip() in fields],
        measurement='read-only observation; no affinity, frequency, power or kernel changes'))
    session['environment'] = pin(output / 'environment.json')
    save_session(output, session)
    started, measured = time.monotonic(), []
    launch_deadline = started + args.session_seconds - c['timeout_seconds'] - 2
    previous_alarm = signal.getsignal(signal.SIGALRM)
    def expired(*_):
        raise KeyboardInterrupt('paired session deadline')
    signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, args.session_seconds)
    try:
        check_workload = workload_check(plan)
        for step in steps:
            need(time.monotonic() <= launch_deadline,
                 'session deadline: retain completed and partial evidence')
            need(pin(plan_path) == session['plan'], 'frozen plan changed within session')
            work, raw = output / (step['name'] + '-work'), output / step['name']
            work.mkdir(mode=0o700)
            state = Path(plan[step['variant'] + '_binding']['path'])
            binding_step = dict(session_id=session['session_id'], phase=step['phase'], index=step['index'])
            condition = conditions_root / (step['name'] + '.json')
            receipt = None
            if mode == 'observed':
                requested_at = B.now()
                session['awaiting_conditions'] = dict(**binding_step, name=step['name'], variant=step['variant'],
                                                      slot=step['slot'], filename=condition.name, requested_at=requested_at)
                save_session(output, session)
                receipt, binding = wait_for_observation(condition, c, binding_step, requested_at, launch_deadline)
            else:
                binding = conditions[step['name']]
                need(pin(condition) == binding, 'conditions changed after schedule validation')
            need(time.monotonic() <= launch_deadline,
                 'session deadline: insufficient time to start ' + step['name'])
            status = B.run(plan_path, step['slot'], state, condition, work, raw,
                           paired=binding_step, check_workload=check_workload, conditions_receipt=receipt)
            trial_path = raw / 'trial.json'
            trial = json.loads(ordinary(trial_path))
            need(status == 0, 'failed workload: ' + step['name'] + ': ' + (trial.get('error') or 'invalid trial'))
            report = trial['paired_zlib']['report']
            session.pop('awaiting_conditions', None)
            session['completed'].append(dict(**step, conditions=binding, trial=pin(trial_path), workload=report))
            if step['phase'] == 'measured':
                measured.append(raw)
            save_session(output, session)
        comparison_code = B.compare(plan_path, measured, output / 'comparison.json')
        session['preliminary_result'] = B.read_json(output / 'comparison.json')['preliminary_result']
        session['comparison_exit_code'] = comparison_code
        session.update(status='COMPLETE_CONTROL_ONLY' if args.control_only else 'COMPLETE_PAIRED_MEASUREMENT_PENDING_REVIEW',
                       comparison=pin(output / 'comparison.json'), finished_at=B.now())
    except BaseException as error:
        session.update(status='FAIL', error_type=type(error).__name__, error=str(error)[:512], finished_at=B.now())
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_alarm)
        session['elapsed_seconds'] = time.monotonic() - started
        if session['elapsed_seconds'] > args.session_seconds:
            session.update(status='FAIL', error='session deadline exceeded; retained all available evidence')
        save_session(output, session)
    return session


def stage(args):
    """Reuse the original closed artifact selector; copy exact bytes, never build."""
    root = Path(__file__).resolve().parents[2]
    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, root / path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    selector = load('retained_arm_select', 'scripts/ci/arm-experiments-generic16k/prepare.py')
    generic = load('retained_arm_elf', 'scripts/virtual/generic16k/fixture.py')
    files, selection = selector.select(args.input_root.absolute(), args.experiment, generic)
    output = args.output.absolute()
    need(not output.exists() and not any(p.is_symlink() for p in output.parents), 'fresh ordinary staged artifact root required')
    index = json.loads((root / 'scripts/ci/arm-experiments-generic16k/retained-inputs.json').read_bytes())
    manifest = index['experiments'][args.experiment]['archive_manifest']
    raw = selector.read(args.input_root.absolute() / manifest['path'], 128 * 1024)
    output.mkdir(mode=0o700)
    for name, (mode, data) in files.items():
        target = output / name.removeprefix('experiments/')
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(data)
        target.chmod(stat.S_IMODE(mode))
    (output / 'archive-manifest.json').write_bytes(raw)
    Z.materials(output, output / 'archive-manifest.json', args.experiment)
    B.write_json(output / 'staging.json', dict(status='EXACT_ORIGINAL_BYTES_STAGED_NOT_EXECUTED', selection=selection,
        archive_manifest=pin(output / 'archive-manifest.json'), hardware='NOT RUN', performance='NOT MEASURED'))
    return dict(status='EXACT_ORIGINAL_BYTES_STAGED_NOT_EXECUTED', artifact_root=str(output))


def prepare(args):
    """Compose the existing exact-artifact config adapter and frozen-plan API."""
    output = args.output.absolute()
    need(not output.exists() and not any(p.is_symlink() for p in output.parents), 'fresh plan directory required')
    output.mkdir(mode=0o700)
    config_args = SimpleNamespace(**vars(args))
    config_args.output = output / 'original-config.json'
    c = Z.prepare_config(config_args)
    c['paired_zlib'] = 'exact-arm'
    c['argv_file_operands'] = list(ARM_ARGV_FILE_OPERANDS)
    balanced(c['order'])
    need(c['minimum_trials'] >= 6, 'six measured trials per variant required')
    # Original-config records the unchanged artifact adapter and historical pure
    # preparation dependency. The new config additionally pins both new actors.
    for source in (Path(__file__).resolve(), Path(B.__file__).resolve()):
        if str(source) not in c['inputs']:
            c['inputs'].append(str(source))
    B.write_json(output / 'config.json', c)
    B.freeze(output / 'config.json', args.baseline_state, args.candidate_state, output / 'plan.json')
    return dict(status='PREPARED_NOT_EXECUTED', plan=str(output / 'plan.json'))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    commands = p.add_subparsers(dest='command', required=True)
    staging = commands.add_parser('stage', help='Export the exact original final ELF/corpus selection; no execution')
    staging.add_argument('--experiment', choices=Z.EXPERIMENTS, required=True)
    staging.add_argument('--input-root', type=Path, required=True)
    staging.add_argument('--output', type=Path, required=True)
    prep = commands.add_parser('prepare', help='Compose original zlib config and benchmark_v2.freeze; no execution')
    prep.add_argument('--experiment', choices=Z.EXPERIMENTS, required=True)
    for name in ('artifact-root', 'archive-manifest', 'operator-config', 'baseline-state', 'candidate-state', 'output'):
        prep.add_argument('--' + name, type=Path, required=True)
    prep.add_argument('--payload-bytes', type=int, default=32 * 1024**2)
    prep.add_argument('--iterations', type=int, default=8)
    runner = commands.add_parser('run')
    for name in ('plan', 'conditions-root', 'output'):
        runner.add_argument('--' + name, type=Path, required=True)
    runner.add_argument('--warmup-blocks', type=int, default=1)
    runner.add_argument('--session-seconds', type=float, default=7200)
    runner.add_argument('--conditions-mode', choices=('observed', 'prewritten'), default='observed',
                        help='request fresh observations for each slot, or use prewritten control fixtures')
    runner.add_argument('--control-only', action='store_true')
    def interrupted(*_):
        raise KeyboardInterrupt('paired session interrupted')
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        args = p.parse_args(argv)
        r = stage(args) if args.command == 'stage' else prepare(args) if args.command == 'prepare' else run(args)
        print(json.dumps(dict(status=r['status'], scope=r.get('scope', 'PREPARED_NOT_EXECUTED'),
                              preliminary_result=r.get('preliminary_result', 'NOT RUN'), optimization_acceptance='NOT RUN')))
        return 2 if r['status'] == 'FAIL' else 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print('paired zlib refused: ' + str(error), file=sys.stderr)
        return 2
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    raise SystemExit(main())
