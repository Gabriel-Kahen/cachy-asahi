#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Finite local developer journey; Linux component evidence, no acceptance grant.

Only original checked-in fixtures are executed. Make/Ninja interpret fixed
project-owned recipes; no arbitrary shell input, network repositories, package
installs, sourced environments or host mutations.
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
CORE_PIN = '83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
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



class BuildProject:
    """Real Make/Ninja graph plus a source/binary-bound post-build execution gate."""
    def __init__(self, backend, commands, tools, output):
        self.backend, self.commands, self.tools = backend, commands, tools
        self.root = output / (backend + '-project')
        self.root.mkdir()
        self.source = self.root / 'hello.c'
        self.object = self.root / 'build/hello.o'
        self.binary = self.root / 'build/hello'
        self.graph = self.root / ('Makefile' if backend == 'make' else 'build.ninja')
        self.usable = False
        self.verified = None
        self.records = []
        self.value = dict(status='RUNNING', backend=backend, records=self.records,
                          fixture_files={}, recipe_scope='FIXED_ORIGINAL_BUILD_SYSTEM_RECIPES',
                          shell='BUILD_SYSTEM_INTRINSIC_SHELL_NO_ARBITRARY_RUNNER_SHELL_INPUT')
        for name, raw in project_fixture_files().items():
            (self.root / name).write_bytes(raw)
            self.value['fixture_files'][name] = pin(raw)

    def inputs(self):
        return {p.name: file_pin(p) for p in (self.source, self.root / 'configure.py',
                self.root / 'LICENSE', self.graph, self.root / 'configuration.json') if p.exists()}

    def artifacts(self):
        rows = {}
        for path in (self.object, self.binary):
            if path.exists():
                metadata = path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
                    raise Failure('project artifact must be ordinary: ' + str(path))
                rows[path.name] = dict(file=file_pin(path), mtime_ns=metadata.st_mtime_ns,
                                       inode=metadata.st_ino)
        return rows

    def record(self, step, outcome, before, **extra):
        directory = self.commands.output / 'project-sources' / self.backend / ('%02d-' % len(self.records) + step)
        directory.mkdir(parents=True)
        snapshots = {}
        for path in (self.source, self.root / 'configure.py', self.root / 'LICENSE',
                     self.graph, self.root / 'configuration.json'):
            if path.exists():
                raw = path.read_bytes()
                destination = directory / path.name
                destination.write_bytes(raw)
                snapshots[str(destination.relative_to(self.commands.output))] = pin(raw)
        self.records.append(dict(step=step, outcome=outcome, before=before,
                                 after=self.artifacts(), inputs=self.inputs(),
                                 source_snapshots=snapshots, **extra))
        save(self.commands.output / ('project-' + self.backend + '.json'), self.value)

    def configure(self):
        self.commands.run(self.backend + '-configure', [self.tools['python3'], '-I', '-B',
                          str(self.root / 'configure.py'), '--backend', self.backend,
                          '--cc', self.tools['cc']], self.root)
        reply = json.loads((self.root / 'configuration.json').read_text())
        if (reply['backend'] != self.backend or reply['compiler'] != self.tools['cc']
                or reply['graph_pin'] != file_pin(self.graph)
                or reply['source'] != file_pin(self.source)):
            raise Failure('configured graph/source/compiler pin mismatch')
        self.record('configure', 'CONFIGURED', {})

    def argv(self, target):
        if self.backend == 'make':
            return [self.tools['make'], '-rR', '-s', '--no-print-directory', '-j1', target]
        return [self.tools['ninja'], '--quiet', '-j1', target]

    def build(self, step, expected=0):
        before = self.artifacts()
        self.usable = False
        try:
            raw = self.commands.run(self.backend + '-' + step, self.argv('all'), self.root, expected)
            if expected == 'nonzero':
                if b'INTENTIONAL_PROJECT_COMPILE_FAILURE' not in raw:
                    raise Failure('failed project build did not report intentional compiler error')
                self.record(step, 'EXPECTED_COMPILE_FAILURE', before)
                return
            after = self.artifacts()
            if set(after) != {'hello', 'hello.o'}:
                raise Failure('successful project build missing artifacts')
            self.verified = dict(inputs=self.inputs(), binary=file_pin(self.binary))
            self.usable = True
            self.record(step, 'BUILT', before)
        except BaseException:
            self.usable = False
            self.record(step, 'UNEXPECTED_FAILURE', before)
            raise

    def require_usable(self):
        if (not self.usable or self.verified is None or self.inputs() != self.verified['inputs']
                or not self.binary.is_file() or file_pin(self.binary) != self.verified['binary']):
            self.usable = False
            raise Failure('project executable has no successful build for these exact inputs')

    def run(self, step, expected):
        self.require_usable()
        self.usable = False
        raw = self.commands.run(self.backend + '-' + step, [str(self.binary)], self.root)
        if raw != expected:
            raise Failure('project executable output mismatch')
        self.record(step, 'EXACT_OUTPUT', self.artifacts(), output=pin(raw))
        self.usable = True

    def test(self, step, expected):
        self.require_usable()
        self.usable = False
        before = self.artifacts()
        try:
            raw = self.commands.run(self.backend + '-' + step, self.argv('test'), self.root)
            if raw != b'PROJECT_TEST_OK:' + expected:
                raise Failure('project test target output mismatch')
            if self.artifacts() != before:
                raise Failure('unchanged project test rebuilt or changed artifacts')
            self.record(step, 'GRAPH_TEST_PASS', before, output=pin(raw))
        except BaseException:
            self.record(step, 'GRAPH_TEST_FAILURE', before)
            raise
        self.usable = True

    def change_source(self, raw):
        # Both build tools use timestamps. Make the observed source timestamp
        # newer than both products, then verify the filesystem retained it.
        stamp = max(time.time_ns(), *(r['mtime_ns'] + 1 for r in self.artifacts().values()),
                    self.source.stat().st_mtime_ns + 1)
        self.source.write_bytes(raw)
        os.utime(self.source, ns=(stamp, stamp))
        if self.source.stat().st_mtime_ns < stamp:
            raise Failure('filesystem did not retain required project edit timestamp')
        self.usable = False

    def journey(self):
        original = b'Project version one\n'
        edited = b'Project version two\n'
        self.configure()
        self.build('initial-build')
        first = self.artifacts()
        self.run('initial-run', original)
        self.test('initial-test', original)
        self.build('unchanged-build')
        if self.artifacts() != first:
            raise Failure('unchanged graph rebuilt its artifacts')
        self.records[-1]['outcome'] = 'UNCHANGED_NO_ARTIFACT_WRITES'
        self.test('repeat-test', original)
        source = self.source.read_bytes()
        wanted = source.replace(original[:-1], edited[:-1])
        self.commands.run(self.backend + '-edit', [self.tools['vim'], '-Nu', 'NONE', '-n', '-i',
                          'NONE', '-es', str(self.source), '-c',
                          '%s/Project version one/Project version two/g', '-c', 'wq'], self.root)
        if wanted == source or self.source.read_bytes() != wanted:
            raise Failure('project Vim edit differs')
        self.change_source(wanted)
        self.build('edited-build')
        changed = self.artifacts()
        if any(changed[name]['file'] == first[name]['file'] for name in ('hello.o', 'hello')):
            raise Failure('project source edit did not change object and binary')
        self.run('edited-run', edited)
        self.test('edited-test', edited)
        self.change_source(wanted + b'\n#error INTENTIONAL_PROJECT_COMPILE_FAILURE\n')
        self.build('broken-build', expected='nonzero')
        if not self.binary.is_file() or file_pin(self.binary) != changed['hello']['file']:
            raise Failure('expected old executable was not retained by failed graph build')
        # Prove the adapter rejects execution even though old binary bytes exist.
        count = len(self.commands.records)
        try:
            self.run('forbidden-stale-run', edited)
        except Failure:
            pass
        else:
            raise Failure('stale project executable accepted after compiler failure')
        if len(self.commands.records) != count:
            raise Failure('stale rejection attempted to launch an executable')
        raw = self.commands.run(self.backend + '-broken-test', self.argv('test'), self.root, 'nonzero')
        if b'INTENTIONAL_PROJECT_COMPILE_FAILURE' not in raw or b'PROJECT_TEST_OK:' in raw:
            raise Failure('broken graph test failed to reject stale executable')
        self.record('broken-test', 'GRAPH_AND_GATE_REJECT_STALE_EXECUTABLE', changed,
                    stale_binary=file_pin(self.binary), stale_run_attempts=0)
        self.change_source(wanted)
        self.build('recovery-build')
        self.run('recovery-run', edited)
        self.test('recovery-test', edited)
        self.value.update(status='PASS_REAL_PROJECT_WORKFLOW',
                          graph=file_pin(self.graph), final_binary=file_pin(self.binary),
                          unchanged_build='NO_OBJECT_OR_BINARY_WRITES',
                          edit='CHANGED_SOURCE_OBJECT_BINARY_AND_OUTPUT',
                          compile_failure='OBSERVED_NONZERO_STALE_BINARY_REJECTED',
                          recovery='BUILD_RUN_TEST_PASS')
        save(self.commands.output / ('project-' + self.backend + '.json'), self.value)
        return self.value


def project_fixture_files():
    files = {}
    for name in ('configure.py', 'hello.c', 'LICENSE'):
        path = FIXTURES / 'project' / name
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size > MAX_SOURCE:
            raise Failure('bounded ordinary project fixture required: ' + name)
        files[name] = path.read_bytes()
    return files


def project_workflows(commands, tools, output, reports):
    for backend in ('make', 'ninja'):
        if backend not in tools:
            reports[backend] = dict(status='MISSING_OPTIONAL', workflow='NOT_RUN')
            continue
        project = BuildProject(backend, commands, tools, output)
        reports[backend] = project.value
        try:
            project.journey()
        except BaseException:
            project.value['status'] = 'FAIL'
            save(commands.output / ('project-' + backend + '.json'), project.value)
            raise


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
                           'fixtures': {n: pin(v) for n, v in fixture_files().items()},
                           'project_fixtures': {n: pin(v) for n, v in project_fixture_files().items()}})
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
            report['base_command_count'] = len(commands.records)
            for name in REQUIRED:
                report['tools'][name]['workflow'] = 'EXECUTED'
            report['project_workflows'] = {}
            project_workflows(commands, tools, output, report['project_workflows'])
            for backend, result in report['project_workflows'].items():
                if result['status'] == 'PASS_REAL_PROJECT_WORKFLOW':
                    report['tools'][backend]['workflow'] = 'EXECUTED_REAL_PROJECT'
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
