#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Finite original CMake/Meson journeys; unprivileged local component evidence."""
import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import shlex
import shutil
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/workflows/fixtures/developer/build-systems'
WORKFLOW_PIN = '531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba'


def load_workflow():
    path = ROOT / 'scripts/workflows/developer_workflow.py'
    raw = path.read_bytes()
    import hashlib
    if hashlib.sha256(raw).hexdigest() != WORKFLOW_PIN:
        raise ValueError('reviewed Make/Ninja workflow helper pin differs')
    spec = importlib.util.spec_from_file_location('_build_system_workflow', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


W = load_workflow()
Failure, pin, file_pin, save = W.Failure, W.pin, W.file_pin, W.save
NAMES = ('main.c', 'greeting.cpp', 'greeting.h', 'expected.txt',
         'CMakeLists.txt', 'meson.build', 'LICENSE')
ORIGINAL, EDITED = b'Developer version one\n', b'Developer version two\n'
NEEDS = {'cmake': ('cmake', 'ctest', 'ninja', 'cc', 'c++'),
         'meson': ('meson', 'ninja', 'cc', 'c++')}


def compiler_environment(tools):
    return dict(CC=shlex.quote(tools['cc']), CXX=shlex.quote(tools['c++']))


def ordinary_pin(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink():
        raise Failure('ordinary file required: ' + str(path))
    return file_pin(path)


def fixture_files():
    files = {}
    for name in NAMES:
        path = FIXTURES / name
        if path.lstat().st_size > 128 * 1024:
            raise Failure('fixture exceeds source cap')
        ordinary_pin(path)
        files[name] = path.read_bytes()
    return files


class Project:
    """Trusted fixed project, with source/tool/product-bound execution custody."""
    def __init__(self, backend, commands, tools, output):
        if backend not in NEEDS:
            raise ValueError('unknown build system')
        self.backend, self.commands, self.tools = backend, commands, tools
        self.root = output / (backend + '-project'); self.root.mkdir()
        self.source = self.root / 'source'; self.source.mkdir()
        self.build_dir = self.root / 'build'
        self.prefix = self.root / 'prefix'
        if self.prefix.exists():
            raise Failure('install prefix must be absent')
        for name, raw in fixture_files().items():
            (self.source / name).write_bytes(raw)
        self.binary = self.build_dir / 'developer-demo'
        self.library = self.build_dir / 'libgreeting.so'
        self.verified = self.installed = None
        self.usable = False
        self.value = dict(status='RUNNING', backend=backend, records=[],
                          installed_prefix=str(self.prefix), install_scope='FRESH_PRIVATE_PREFIX')

    def inputs(self):
        return dict(sources={n: ordinary_pin(self.source / n) for n in NAMES},
                    tools={n: file_pin(self.tools[n]) for n in NEEDS[self.backend]})

    def artifacts(self):
        rows = {}
        if not self.build_dir.exists():
            return rows
        # Include products and compiled objects to prove a real unchanged build.
        paths = [self.binary, self.library, *sorted(self.build_dir.rglob('*.o'))]
        for path in paths:
            if path.exists():
                info = path.lstat()
                rows[str(path.relative_to(self.build_dir))] = dict(
                    file=ordinary_pin(path), mtime_ns=info.st_mtime_ns, inode=info.st_ino)
        return rows

    def record(self, step, outcome, before=None, **extra):
        directory = self.commands.output / 'sources' / self.backend / ('%02d-' % len(self.value['records']) + step)
        directory.mkdir(parents=True)
        snapshots = {}
        for name in NAMES:
            raw = (self.source / name).read_bytes()
            target = directory / name; target.write_bytes(raw)
            snapshots[str(target.relative_to(self.commands.output))] = pin(raw)
        self.value['records'].append(dict(step=step, outcome=outcome, before=before,
                                         after=self.artifacts(), inputs=self.inputs(),
                                         source_snapshots=snapshots, **extra))
        save(self.commands.output / ('project-' + self.backend + '.json'), self.value)

    def argv(self, action):
        t, b, s = self.tools, str(self.build_dir), str(self.source)
        if self.backend == 'cmake':
            return {'configure': [t['cmake'], '-S', s, '-B', b, '-G', 'Ninja',
                                  '-DCMAKE_MAKE_PROGRAM=' + t['ninja'],
                                  '-DCMAKE_C_COMPILER=' + t['cc'], '-DCMAKE_CXX_COMPILER=' + t['c++'],
                                  '-DCMAKE_BUILD_TYPE=RelWithDebInfo',
                                  '-DCMAKE_INSTALL_PREFIX=' + str(self.prefix)],
                    'build': [t['cmake'], '--build', b, '--parallel', '1'],
                    'test': [t['ctest'], '--test-dir', b, '--verbose', '--no-tests=error'],
                    'install': [t['cmake'], '--install', b]}[action]
        return {'configure': [t['meson'], 'setup', b, s, '--backend=ninja',
                              '--prefix=' + str(self.prefix), '--libdir=lib', '--wrap-mode=nodownload'],
                'build': [t['meson'], 'compile', '-C', b, '-j', '1'],
                'test': [t['meson'], 'test', '-C', b, '--no-rebuild', '--verbose', '--print-errorlogs'],
                'install': [t['meson'], 'install', '-C', b, '--no-rebuild']}[action]

    def command(self, step, argv, expected=0, cwd=None):
        return self.commands.run(self.backend + '-' + step, argv, cwd or self.root, expected)

    def configure(self):
        self.usable = False
        self.installed = None
        self.command('configure', self.argv('configure'))
        self.record('configure', 'CONFIGURED')

    def build(self, step, expected=0):
        before, inputs = self.artifacts(), self.inputs()
        self.usable = False
        self.installed = None
        try:
            raw = self.command(step, self.argv('build'), expected)
            if inputs != self.inputs():
                raise Failure('inputs changed while building')
            if expected == 'nonzero':
                if b'INTENTIONAL_COMPILE_FAILURE' not in raw:
                    raise Failure('compile failure lacks deliberate diagnostic')
                self.record(step, 'EXPECTED_COMPILE_FAILURE', before)
                return
            products = self.artifacts()
            if not {'developer-demo', 'libgreeting.so'} <= products.keys() or len(products) < 4:
                raise Failure('missing C/C++ products')
            self.verified = dict(inputs=inputs, products=products)
            self.usable = True
            self.record(step, 'BUILT', before)
        except BaseException:
            self.usable = False
            self.record(step, 'BUILD_FAILURE', before)
            raise

    def require_usable(self):
        if (not self.usable or self.verified is None or self.inputs() != self.verified['inputs']
                or self.artifacts() != self.verified['products']):
            self.usable = False
            raise Failure('no successful build for these exact sources/tools/products')

    def run(self, step, expected):
        self.require_usable()
        self.usable = False
        raw = self.command(step, [str(self.binary)])
        if raw != expected:
            raise Failure('executable output mismatch')
        self.record(step, 'EXACT_OUTPUT', output=pin(raw))
        self.usable = True

    def test(self, step, expected=0):
        self.require_usable()
        before = self.artifacts()
        self.usable = False
        self.installed = None
        try:
            raw = self.command(step, self.argv('test'), expected)
            marker = b'INTENTIONAL_TEST_MISMATCH' if expected == 'nonzero' else b'DEVELOPER_TEST_OK'
            if marker not in raw or (expected == 'nonzero' and b'DEVELOPER_TEST_OK' in raw):
                raise Failure('test result lacks expected diagnostic')
            if self.artifacts() != before or self.inputs() != self.verified['inputs']:
                raise Failure('test changed build products or inputs')
            self.record(step, 'EXPECTED_TEST_FAILURE' if expected == 'nonzero' else 'TEST_PASS', before)
            self.usable = expected == 0
        except BaseException:
            self.record(step, 'TEST_FAILURE', before)
            raise

    def change(self, name, raw):
        products = self.artifacts()
        path = self.source / name
        stamp = max(time.time_ns(), path.stat().st_mtime_ns + 1,
                    *(v['mtime_ns'] + 1 for v in products.values()))
        path.write_bytes(raw); os.utime(path, ns=(stamp, stamp))
        if path.stat().st_mtime_ns < stamp:
            raise Failure('filesystem lost edit timestamp')
        self.usable = False
        self.installed = None

    def refuse_stale(self, step):
        before = len(self.commands.records)
        try:
            self.run(step, EDITED)
        except Failure:
            pass
        else:
            raise Failure('stale execution was accepted')
        if len(self.commands.records) != before:
            raise Failure('stale execution launched a process')
        self.record(step, 'REFUSED_BEFORE_LAUNCH', attempted_launches=0)

    def installed_tree(self):
        result = {}
        for path in sorted(self.prefix.rglob('*')):
            if path.is_dir() and not path.is_symlink():
                continue
            result[str(path.relative_to(self.prefix))] = ordinary_pin(path)
        return result

    def install(self):
        self.require_usable()
        self.installed = None
        if self.prefix.exists():
            raise Failure('installation requires a fresh prefix')
        self.command('install', self.argv('install'))
        tree = self.installed_tree()
        if set(tree) != {'bin/developer-demo', 'lib/libgreeting.so',
                         'share/licenses/developer-fixture/LICENSE'}:
            raise Failure('unexpected private installation tree')
        if tree['share/licenses/developer-fixture/LICENSE'] != file_pin(self.source / 'LICENSE'):
            raise Failure('installed license differs')
        self.installed = dict(inputs=self.inputs(), tree=tree)
        save(self.commands.output / ('installed-' + self.backend + '.json'), self.installed)
        self.record('install', 'PRIVATE_TREE_VERIFIED', tree=tree)

    def require_installed(self):
        if (self.installed is None or self.inputs() != self.installed['inputs']
                or self.installed_tree() != self.installed['tree']):
            self.installed = None
            raise Failure('installed tree/source custody differs')

    def installed_runtime(self):
        self.require_installed()
        receipt, self.installed = self.installed, None
        held_build, held_source = self.root / 'build-withheld', self.root / 'source-withheld'
        self.build_dir.rename(held_build)
        try:
            self.source.rename(held_source)
            try:
                raw = self.command('installed-run-without-build-source',
                                   [str(self.prefix / 'bin/developer-demo')], cwd=self.prefix)
                if raw != EDITED:
                    raise Failure('installed output differs')
                library = self.prefix / 'lib/libgreeting.so'
                hidden = library.with_suffix('.withheld')
                library.rename(hidden)
                try:
                    raw = self.command('installed-missing-library-control',
                                       [str(self.prefix / 'bin/developer-demo')], 'nonzero', cwd=self.prefix)
                    if b'libgreeting.so' not in raw:
                        raise Failure('missing-library control lacks loader diagnostic')
                finally:
                    hidden.rename(library)
                raw = self.command('installed-restored-library-run',
                                   [str(self.prefix / 'bin/developer-demo')], cwd=self.prefix)
                if raw != EDITED:
                    raise Failure('restored installed output differs')
            finally:
                held_source.rename(self.source)
        finally:
            held_build.rename(self.build_dir)
        self.installed = receipt
        self.require_installed()
        self.record('installed-runtime', 'BUILD_SOURCE_WITHHELD_LIBRARY_REQUIRED_AND_RESTORED',
                    environment_loader_overrides=False, tree=self.installed_tree())

    def journey(self):
        self.configure(); self.build('initial-build')
        self.run('initial-run', ORIGINAL); self.test('initial-test')
        first = self.artifacts()
        self.build('unchanged-build')
        if self.artifacts() != first:
            raise Failure('unchanged build wrote products')
        self.record('unchanged-check', 'NO_PRODUCT_WRITES', first)
        original = (self.source / 'greeting.cpp').read_bytes()
        edited = original.replace(b'version one', b'version two')
        self.change('greeting.cpp', edited); self.change('expected.txt', EDITED)
        self.refuse_stale('edited-before-build-refusal')
        self.build('changed-build')
        changed = self.artifacts()
        if changed['libgreeting.so']['file'] == first['libgreeting.so']['file']:
            raise Failure('changed C++ source did not change shared library')
        cpp_objects = [name for name in first if name.endswith('greeting.cpp.o')]
        c_objects = [name for name in first if name.endswith('main.c.o')]
        if (len(cpp_objects) != 1 or len(c_objects) != 1
                or changed[cpp_objects[0]]['file'] == first[cpp_objects[0]]['file']
                or changed[c_objects[0]] != first[c_objects[0]]):
            raise Failure('incremental rebuild did not isolate changed C++ object')
        self.record('changed-check', 'CPP_OBJECT_AND_LIBRARY_CHANGED_C_OBJECT_UNTOUCHED', first)
        self.run('changed-run', EDITED); self.test('changed-test')
        self.change('greeting.cpp', edited + b'\n#error INTENTIONAL_COMPILE_FAILURE\n')
        self.build('broken-build', 'nonzero')
        if self.artifacts() != changed:
            raise Failure('failed compile did not retain previous products')
        self.refuse_stale('compile-failure-refusal')
        self.change('greeting.cpp', edited)
        self.build('compile-recovery-build'); self.run('compile-recovery-run', EDITED)
        self.test('compile-recovery-test')
        self.change('expected.txt', b'Deliberately wrong expectation\n')
        self.build('test-failure-build'); self.test('broken-test', 'nonzero')
        self.refuse_stale('test-failure-refusal')
        self.change('expected.txt', EDITED)
        self.build('test-recovery-build'); self.test('test-recovery-test')
        self.run('test-recovery-run', EDITED)
        self.install(); self.installed_runtime()
        self.value.update(status='PASS_REAL_PROJECT_WORKFLOW',
                          unchanged='NO_OBJECT_LIBRARY_BINARY_WRITES',
                          compile_failure='REAL_NONZERO_STALE_EXECUTION_REFUSED',
                          test_failure='REAL_NONZERO_EXECUTION_REVOKED',
                          installed='PASS_PRIVATE_PREFIX_RUNTIME')
        save(self.commands.output / ('project-' + self.backend + '.json'), self.value)
        return self.value


def project_workflows(commands, tools, output, reports):
    for backend, needs in NEEDS.items():
        missing = sorted(set(needs) - tools.keys())
        if missing:
            reports[backend] = dict(status='NOT_RUN', missing=missing)
            continue
        project = Project(backend, commands, tools, output)
        reports[backend] = project.value
        try:
            project.journey()
        except BaseException:
            project.value['status'] = 'FAIL'
            save(output / ('project-' + backend + '.json'), project.value)
            raise


def run(output, tool_path=os.defpath, timeout=30, total=240):
    if (not all(type(n) in (int, float) and math.isfinite(n) for n in (timeout, total))
            or not 2 <= timeout <= 60 or not timeout <= total <= 600):
        raise ValueError('require 2 <= command timeout <= 60 and timeout <= total <= 600')
    if not tool_path or any(not p or not Path(p).is_absolute() for p in tool_path.split(os.pathsep)):
        raise ValueError('absolute nonempty tool directories required')
    output = Path(output).absolute()
    if any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('output aliases refused')
    output.mkdir(mode=0o700, exist_ok=False)
    home = output / 'home'; home.mkdir(mode=0o700)
    temporary = output / 'tmp'; temporary.mkdir(mode=0o700)
    report = dict(schema=1, status='FAIL', architecture=platform.machine(),
                  kernel=platform.release(), page_size=os.sysconf('SC_PAGE_SIZE'), uid=os.getuid(),
                  python=dict(path=sys.executable, version=sys.version, file=file_pin(sys.executable)),
                  scope='LOCAL_TRUSTED_FIXTURE_COMPONENT', native_ARM='NOT_RUN', native_16K='NOT_RUN',
                  Asahi_installed='NOT_RUN', physical_M2='NOT_RUN', independent_user='NOT_RUN',
                  performance='NOT_MEASURED', release='NOT_ADMITTED', tools={}, project_workflows={},
                  temporary_directory=str(temporary),
                  sources=dict(runner=file_pin(__file__), helper=file_pin(W.__file__),
                               owned_process=file_pin(ROOT / 'scripts/virtual/owned_process.py'),
                               fixtures={n: pin(raw) for n, raw in fixture_files().items()}))
    save(output / 'result.json', report)
    commands = None
    try:
        commands = W.Commands(output, home, tool_path, timeout, total, max_output=256*1024)
        commands.env['TMPDIR'] = str(temporary)
        tools = {}
        for name in ('cmake', 'ctest', 'meson', 'ninja', 'cc', 'c++'):
            found = shutil.which(name, path=tool_path)
            if found is None:
                report['tools'][name] = dict(status='MISSING', workflow='NOT_RUN')
                continue
            resolved = str(Path(found).resolve()); tools[name] = resolved
            raw = commands.run('version-' + name.replace('+', 'p'), [resolved, '--version'], output)
            report['tools'][name] = dict(status='PRESENT', path=found, resolved=resolved,
                                         file=file_pin(resolved), version=raw.decode(errors='replace').splitlines())
        # Meson uses these exact compiler paths; CMake receives equivalent cache argv.
        if 'cc' in tools and 'c++' in tools:
            commands.env.update(compiler_environment(tools))
        project_workflows(commands, tools, output, report['project_workflows'])
        statuses = [r['status'] for r in report['project_workflows'].values()]
        report['status'] = ('PASS_AVAILABLE_LOCAL_WORKFLOWS' if 'PASS_REAL_PROJECT_WORKFLOW' in statuses
                            else 'NOT_RUN_NO_BUILD_SYSTEM')
    except (OSError, ValueError, KeyboardInterrupt) as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        report['commands'] = [] if commands is None else commands.records
        save(output / 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--tool-path', default=os.defpath)
    parser.add_argument('--command-timeout', type=float, default=30)
    parser.add_argument('--total-timeout', type=float, default=240)
    args = parser.parse_args()
    try:
        report = run(args.output, args.tool_path, args.command_timeout, args.total_timeout)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps(dict(status=report['status'], projects={n: r['status'] for n, r in report['project_workflows'].items()})))
    return 0 if report['status'] == 'PASS_AVAILABLE_LOCAL_WORKFLOWS' else 2


if __name__ == '__main__':
    raise SystemExit(main())
