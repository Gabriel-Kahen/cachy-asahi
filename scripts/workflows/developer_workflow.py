#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Finite local developer journey; Linux component evidence, no acceptance grant.

Only original checked-in fixtures are executed. No shell command strings,
network repositories, package installs, sourced environments or host mutations.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/workflows/fixtures/developer'
CORE_PIN = '80547f753dc7d13819d727783c669d10a56b7bf832dc05084b5c4b5302cb79d9'
MAX_SOURCE = 128 * 1024
FLAGS = ('-Wall', '-Wextra', '-Werror', '-O2')
ORIGINAL = b'Hello from cachy-asahi\n'
EDITED = b'Edited developer workflow\n'
REQUIRED = ('git', 'cc', 'c++', 'vim', 'python3')
OPTIONAL = ('make', 'cmake', 'meson', 'ninja')


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def file_pin(path):
    path = Path(path)
    h = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        for raw in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(raw)
            if size > 256 * 1024**2:
                raise ValueError('tool/file exceeds 256MiB pin cap')
            h.update(raw)
    return dict(bytes=size, sha256=h.hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n')


def load_core():
    path = ROOT / 'scripts/virtual/owned_process.py'
    raw = path.read_bytes()
    if pin(raw)['sha256'] != CORE_PIN:
        raise ValueError('reviewed owned-process core pin differs')
    spec = importlib.util.spec_from_file_location('_developer_owned_process', path)
    module = importlib.util.module_from_spec(spec)
    # Execute the exact verified bytes, avoiding a second path read/pyc lookup.
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


class Failure(ValueError):
    pass


class Commands:
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
                       and result['group_census'] == 'EMPTY_TWICE'
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


class OnboardingAdapter:
    """The C/editor slice of current606 journey, with a bounded argv executor.

    Existing journey owns setup/shell/PTY acceptance and is not called wholesale.
    This adapter retains its C source, flags, Vim isolation and exact first output.
    """
    source_pin = 'fc4d365017395544876cf526639d8dfa1b4f6784d7f92887ee35c40146f749b5'

    @staticmethod
    def edit(commands, vim, source):
        return commands.run('edit-' + source.suffix[1:],
                            [vim, '-Nu', 'NONE', '-n', '-i', 'NONE', '-es', str(source),
                             '-c', '%s/Hello from cachy-asahi/Edited developer workflow/g',
                             '-c', 'wq'], source.parent)

    @staticmethod
    def compile_argv(compiler, source, target):
        return [compiler, *FLAGS, str(source), '-o', str(target)]


class IncrementalBuild:
    """Content-keyed direct-argv rebuild; never runs Make/Ninja shell recipes."""
    def __init__(self, commands):
        self.commands = commands
        self.records = []

    def build(self, step, compiler, source, target, expected=0):
        state = target.with_suffix('.state.json')
        inputs = dict(source=file_pin(source), compiler=file_pin(compiler),
                      argv=OnboardingAdapter.compile_argv(compiler, source, target))
        fingerprint = pin(json.dumps(inputs, sort_keys=True).encode())
        snapshot = 'build-source-%02d%s' % (len(self.records), source.suffix)
        raw = source.read_bytes()
        if pin(raw) != inputs['source']:
            raise Failure('source changed before compile snapshot')
        (self.commands.output / snapshot).write_bytes(raw)
        def record(outcome, **extra):
            self.records.append(dict(step=step, outcome=outcome, inputs=fingerprint,
                                     input_files=inputs, source_snapshot=snapshot, **extra))
            save(self.commands.output / 'builds.json', self.records)
        if expected == 0 and state.exists() and target.exists():
            prior = json.loads(state.read_text())
            if prior['inputs'] == fingerprint and prior['binary'] == file_pin(target):
                record('UNCHANGED', binary=prior['binary'])
                return
        # A failed compile cannot leave a stale executable eligible for a run.
        target.unlink(missing_ok=True)
        state.unlink(missing_ok=True)
        try:
            self.commands.run(step, OnboardingAdapter.compile_argv(compiler, source, target),
                              source.parent, expected=expected)
        except BaseException:
            target.unlink(missing_ok=True)
            record('UNEXPECTED_FAILURE')
            raise
        if expected == 'nonzero':
            target.unlink(missing_ok=True)
            record('EXPECTED_COMPILE_FAILURE')
            return
        if not target.is_file():
            raise Failure('compiler reported success without an executable')
        receipt = dict(inputs=fingerprint, binary=file_pin(target))
        save(state, receipt)
        record('BUILT', binary=receipt['binary'])


def fixture_files():
    names = ('hello.c', 'hello.cpp', 'hello.py', 'test_hello.py', 'LICENSE')
    files = {}
    for name in names:
        path = FIXTURES / name
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size > MAX_SOURCE:
            raise Failure('bounded original ordinary fixture required: ' + name)
        files[name] = path.read_bytes()
    if pin(files['hello.c'])['sha256'] != OnboardingAdapter.source_pin:
        raise Failure('held onboarding C source differs')
    return files


def journey(commands, tools, output):
    seed, clone, empty = output / 'origin', output / 'checkout', output / 'empty-template'
    seed.mkdir(); empty.mkdir()
    files = fixture_files()
    for name, raw in files.items():
        (seed / name).write_bytes(raw)
    git = [tools['git'], '-c', 'core.hooksPath=' + str(empty), '-c', 'commit.gpgsign=false',
           '-c', 'user.name=Developer Fixture', '-c', 'user.email=fixture@invalid']
    commands.run('git-init', git + ['init', '--template=' + str(empty), str(seed)], output)
    commands.run('git-add', git + ['add', '--', *files], seed)
    commands.run('git-commit', git + ['commit', '-m', 'Original MIT developer fixture'], seed)
    revision = commands.run('git-revision', git + ['rev-parse', 'HEAD'], seed).strip().decode('ascii')
    if len(revision) != 40 or any(c not in '0123456789abcdef' for c in revision):
        raise Failure('unexpected local Git revision')
    commands.run('git-local-clone', git + ['clone', '--local', '--no-hardlinks', '--template=' + str(empty),
                                         str(seed), str(clone)], output)
    commands.run('git-checkout', git + ['checkout', '--detach', revision], clone)
    if any((clone / name).read_bytes() != raw for name, raw in files.items()):
        raise Failure('local clone bytes differ')
    build = IncrementalBuild(commands)
    bin_dir = clone / 'build'; bin_dir.mkdir()
    outputs = {}
    for name, compiler in (('hello.c', tools['cc']), ('hello.cpp', tools['c++'])):
        source = clone / name
        target = bin_dir / name.replace('.', '-')
        kind = source.suffix[1:]
        build.build('compile-' + kind, compiler, source, target)
        first = file_pin(target)
        if commands.run('run-' + kind, [str(target)], clone) != ORIGINAL:
            raise Failure('initial compiled output mismatch')
        build.build('unchanged-' + kind, compiler, source, target)
        old = source.read_bytes()
        OnboardingAdapter.edit(commands, tools['vim'], source)
        wanted = old.replace(ORIGINAL[:-1], EDITED[:-1])
        if old == wanted or source.read_bytes() != wanted:
            raise Failure('scripted Vim edit differs')
        build.build('rebuild-' + kind, compiler, source, target)
        changed = file_pin(target)
        if changed == first or commands.run('run-edited-' + kind, [str(target)], clone) != EDITED:
            raise Failure('modified source did not cause changed binary/output')
        source.write_bytes(wanted + b'\n#error INTENTIONAL_DEVELOPER_WORKFLOW_FAILURE\n')
        build.build('intentional-failure-' + kind, compiler, source, target, expected='nonzero')
        if target.exists() or target.with_suffix('.state.json').exists():
            raise Failure('failed compile retained stale runnable state')
        source.write_bytes(wanted)
        build.build('repair-' + kind, compiler, source, target)
        if commands.run('run-repaired-' + kind, [str(target)], clone) != EDITED:
            raise Failure('repaired build output mismatch')
        outputs[name] = dict(original_binary=first, changed_binary=changed,
                             edited_source=file_pin(source), changed_output=pin(EDITED),
                             compile_failure='OBSERVED_NONZERO_NO_STALE_EXECUTABLE')
    venv = output / 'venv'
    commands.run('python-venv', [tools['python3'], '-I', '-B', '-m', 'venv', '--without-pip', str(venv)], clone)
    python = str(venv / 'bin/python')
    if commands.run('python-run', [python, '-I', '-B', str(clone / 'hello.py')], clone) != ORIGINAL:
        raise Failure('venv Python output mismatch')
    # -I excludes cwd; explicit fixed private fixture path enables only this test.
    harness = ('import sys,unittest;sys.path.insert(0,sys.argv[1]);'
               's=unittest.defaultTestLoader.discover(sys.argv[1],pattern="test_hello.py");'
               'r=unittest.TextTestRunner().run(s);'
               'sys.exit(0 if r.wasSuccessful() and r.testsRun==1 else 1)')
    commands.run('python-test', [python, '-I', '-B', '-c', harness, str(clone)], clone)
    commands.run('git-diff', git + ['diff', '--exit-code', '--', 'hello.py', 'test_hello.py'], clone)
    return dict(local_revision=revision, fixtures={n: pin(v) for n, v in files.items()},
                builds=build.records, compiled=outputs, python_venv='PASS_WITHOUT_PIP_OR_ACTIVATION',
                python_test_count=1, editor='SCRIPTED_VIM_NO_GUI_USABILITY_CLAIM')


def run(output, tool_path=os.defpath, timeout=15, total=180):
    if (not all(type(x) in (int, float) and math.isfinite(x) for x in (timeout, total))
            or not 2 <= timeout <= 60 or not timeout <= total <= 600):
        raise ValueError('require 2 <= command timeout <= 60, timeout <= total <= 600')
    if not tool_path or any(not p or not Path(p).is_absolute() for p in tool_path.split(os.pathsep)):
        raise ValueError('tool search path must contain only nonempty absolute directories')
    output = Path(output).absolute()
    if any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('output aliases refused')
    output.mkdir(mode=0o700, exist_ok=False)
    home = output / 'home'; home.mkdir(mode=0o700)
    report = dict(schema=1, status='FAIL', architecture=platform.machine(),
                  kernel=platform.release(), page_size=os.sysconf('SC_PAGE_SIZE'),
                  uid=os.getuid(), python=dict(version=sys.version, path=sys.executable,
                                              file=file_pin(sys.executable)),
                  evidence_scope='LOCAL_USERSPACE_COMPONENT_ONLY',
                  native_ARM='NOT_QUALIFIED', native_16K='NOT_QUALIFIED', installed='NOT_RUN',
                  physical_M2='NOT_RUN', independent_user='NOT_RUN', package_rebuild='NOT_RUN',
                  performance='NOT_MEASURED', release='NOT_ADMITTED', tools={},
                  sources={'runner': file_pin(__file__),
                           'owned_process': file_pin(ROOT / 'scripts/virtual/owned_process.py'),
                           'fixtures': {n: pin(v) for n, v in fixture_files().items()}})
    save(output / 'result.json', report)
    commands = None
    try:
        commands = Commands(output, home, tool_path, timeout, total)
        tools = {}
        for name in (*REQUIRED, *OPTIONAL):
            executable = shutil.which(name, path=tool_path)
            if executable is None:
                report['tools'][name] = dict(status='MISSING_REQUIRED' if name in REQUIRED else 'MISSING_OPTIONAL')
                continue
            resolved = str(Path(executable).resolve())
            tools[name] = resolved
            version = commands.run('version-' + name.replace('+', 'p'), [resolved, '--version'], output)
            report['tools'][name] = dict(status='PRESENT', path=executable, resolved=resolved,
                                         file=file_pin(resolved), version=version.decode(errors='replace').splitlines(),
                                         workflow='VERSION_ONLY_WORKFLOW_NOT_RUN')
        missing = [name for name in REQUIRED if name not in tools]
        if missing:
            report.update(status='MISSING_TOOLS', missing_required=missing)
        else:
            report['journey'] = journey(commands, tools, output)
            for name in REQUIRED:
                report['tools'][name]['workflow'] = 'EXECUTED'
            report['status'] = 'PASS_LOCAL_DEVELOPER_COMPONENT'
    except (OSError, ValueError, KeyboardInterrupt) as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        report['commands'] = commands.records if commands is not None else []
        save(output / 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='new private directory, retained in full')
    parser.add_argument('--tool-path', default=os.defpath, help='absolute tool directories, separated by colon')
    parser.add_argument('--command-timeout', type=float, default=15)
    parser.add_argument('--total-timeout', type=float, default=180)
    args = parser.parse_args()
    try:
        report = run(args.output, args.tool_path, args.command_timeout, args.total_timeout)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'architecture', 'page_size')}))
    return 0 if report['status'] == 'PASS_LOCAL_DEVELOPER_COMPONENT' else 2


if __name__ == '__main__':
    raise SystemExit(main())
