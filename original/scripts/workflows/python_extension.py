#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Finite CMake CPython extension journey; private host component evidence only."""
import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/workflows/fixtures/python-extension'
PINS = {'scripts/workflows/developer_build_systems.py': '8c5025f3d748fb2e5aebb304310852158ebaac0bcaf9ef44cad8676ed5963fbc',
        'scripts/checks/package_checks.py': 'e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8'}
NAMES = ('CMakeLists.txt', 'extension.c', 'check_extension.py', 'expected.txt', 'LICENSE')
ORIGINAL, EDITED = b'Compiled Python version one\n', b'Compiled Python version two\n'


def load_pinned(name):
    import hashlib
    path = ROOT / name; raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PINS[name]:
        raise ValueError('reviewed dependency pin differs: ' + name)
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location('_extension_' + path.stem, path))
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


B = load_pinned('scripts/workflows/developer_build_systems.py')
PC = load_pinned('scripts/checks/package_checks.py')
W = B.W
Failure, pin, file_pin, save = B.Failure, B.pin, B.file_pin, B.save


def ordinary_pin(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024**2:
        raise Failure('bounded ordinary file required: ' + str(path))
    return file_pin(path)


def fixture_files():
    files = {}
    for name in NAMES:
        path = FIXTURES / name
        ordinary_pin(path)
        if path.stat().st_size > 128 * 1024:
            raise Failure('fixture exceeds source cap')
        files[name] = path.read_bytes()
    return files


IDENTITY = '''import json, os, platform, sys, sysconfig
print(json.dumps(dict(executable=sys.executable, version=sys.version,
    implementation=sys.implementation.name, machine=platform.machine(),
    page_size=os.sysconf('SC_PAGE_SIZE'), include=sysconfig.get_path('include'),
    platinclude=sysconfig.get_path('platinclude'), isolated=sys.flags.isolated,
    no_site=sys.flags.no_site, config={k:sysconfig.get_config_var(k) for k in
    ('EXT_SUFFIX','SOABI','CC','CFLAGS','LDSHARED','LDLIBRARY','LIBDIR','MULTIARCH','Py_GIL_DISABLED')})))'''


def selected_executable(path):
    if path is None:
        return None
    path = Path(path)
    if not path.is_absolute():
        raise ValueError('select executable with an absolute path')
    return str(path.resolve()) if path.is_file() and os.access(path, os.X_OK) else None


def header_inputs(identity):
    """Finite one-tree CPython header profile; retain exact bytes before CMake."""
    if identity['implementation'] != 'cpython' or identity['machine'] not in ('x86_64', 'aarch64'):
        return dict(status='NOT_RUN_UNSUPPORTED_INTERPRETER_PROFILE'), {}
    include, platinclude = Path(identity['include']), Path(identity['platinclude'])
    if not include.is_absolute() or not platinclude.is_absolute():
        raise Failure('interpreter returned nonabsolute header directories')
    missing = [str(include / name) for name in ('Python.h', 'pyconfig.h') if not (include / name).is_file()]
    if missing:
        return dict(status='NOT_RUN_MISSING_HEADERS', missing=missing), {}
    if include.resolve() != platinclude.resolve():
        return dict(status='NOT_RUN_UNSUPPORTED_SPLIT_HEADERS', include=str(include), platinclude=str(platinclude)), {}
    suffix = identity['config']['EXT_SUFFIX']
    if (not isinstance(suffix, str) or '/' in suffix or not suffix.endswith('.so')
            or not identity['config']['SOABI']):
        return dict(status='NOT_RUN_UNSUPPORTED_EXTENSION_ABI'), {}
    files, total = {}, 0
    for path in sorted(include.rglob('*')):
        if path.is_dir() and not path.is_symlink():
            continue
        ordinary_pin(path)
        raw = path.read_bytes(); total += len(raw)
        if total > 8 * 1024**2 or len(files) >= 512:
            raise Failure('header snapshot exceeds finite file/byte cap')
        files[str(path.relative_to(include))] = raw
    return dict(status='PRESENT', include=str(include), platinclude=str(platinclude),
                files={n: pin(raw) for n, raw in files.items()}, bytes=total), files


class ExtensionProject(B.Project):
    """Reuse owned CMake commands, tests, edits and generic custody APIs."""
    def __init__(self, commands, tools, identity, headers, output):
        self.backend, self.commands, self.tools = 'cmake', commands, tools
        self.identity = identity
        self.root = output / 'extension-project'; self.root.mkdir()
        self.source = self.root / 'source'; self.source.mkdir()
        self.build_dir = self.root / 'build'
        self.prefix = self.root / 'unused-prefix'
        self.include = self.root / 'python-headers'; self.include.mkdir()
        self.header_names = set(headers)
        for name, raw in headers.items():
            path = self.include / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        for name, raw in fixture_files().items():
            (self.source / name).write_bytes(raw)
        self.checker = self.root / 'check-installed.py'
        self.checker.write_bytes((self.source / 'check_extension.py').read_bytes())
        self.identity_file = self.root / 'python-identity.json'; save(self.identity_file, identity)
        self.extension = self.build_dir / 'module' / ('cachy_extension' + identity['config']['EXT_SUFFIX'])
        self.verified = self.installed = None
        self.usable = False
        self.value = dict(status='RUNNING', records=[], install_scope='FRESH_PRIVATE_CMAKE_PREFIX',
                          header_snapshot=str(self.include), python_identity=identity)

    def inputs(self):
        headers = {str(p.relative_to(self.include)): ordinary_pin(p) for p in sorted(self.include.rglob('*'))
                   if not p.is_dir() or p.is_symlink()}
        if set(headers) != self.header_names:
            raise Failure('private header snapshot file set differs')
        return dict(sources={n: ordinary_pin(self.source / n) for n in NAMES}, headers=headers,
                    tools={n: file_pin(path) for n, path in self.tools.items()},
                    python_identity=ordinary_pin(self.identity_file), checker=ordinary_pin(self.checker))

    def artifacts(self):
        result = {}
        paths = [self.extension, *sorted(self.build_dir.rglob('*.o'))]
        for name in ('CMakeCache.txt', 'build.ninja', 'compile_commands.json'):
            paths.append(self.build_dir / name)
        for path in paths:
            if path.exists():
                info = path.lstat()
                result[str(path.relative_to(self.build_dir))] = dict(
                    file=ordinary_pin(path), inode=info.st_ino, mtime_ns=info.st_mtime_ns)
        return result

    def record(self, step, outcome, before=None, **extra):
        directory = self.commands.output / 'snapshots' / ('%02d-' % len(self.value['records']) + step)
        directory.mkdir(parents=True)
        snapshots = {}
        for name in NAMES:
            raw = (self.source / name).read_bytes(); (directory / name).write_bytes(raw)
            snapshots[str((directory / name).relative_to(self.commands.output))] = pin(raw)
        self.value['records'].append(dict(step=step, outcome=outcome, before=before,
              after=self.artifacts(), inputs=self.inputs(), source_snapshots=snapshots, **extra))
        save(self.commands.output / 'project.json', self.value)

    def argv(self, action):
        if action == 'configure':
            return [self.tools['cmake'], '-S', str(self.source), '-B', str(self.build_dir), '-G', 'Ninja',
                    '-DCMAKE_MAKE_PROGRAM=' + self.tools['ninja'],
                    '-DCMAKE_C_COMPILER=' + self.tools['cc'], '-DCMAKE_BUILD_TYPE=RelWithDebInfo',
                    '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-DPython3_EXECUTABLE=' + self.tools['python'],
                    '-DPython3_INCLUDE_DIR=' + str(self.include)]
        if action == 'install':
            return [self.tools['cmake'], '--install', str(self.build_dir), '--prefix', str(self.prefix)]
        if action == 'build':
            return [self.tools['cmake'], '--build', str(self.build_dir), '--parallel', '1']
        if action == 'test':
            return [self.tools['ctest'], '--test-dir', str(self.build_dir), '--verbose', '--no-tests=error']
        raise ValueError('unknown extension build action')

    def inspect_elf(self, path):
        ordinary_pin(path)
        result = PC.elf_check(path.read_bytes())
        machine = {'x86_64': 62, 'aarch64': 183}[self.identity['machine']]
        allowed = {'PT_LOAD fails structural 16K alignment check',
                   'ELF machine %d, expected AArch64 (183)' % machine}
        if (result is None or result.get('machine') != machine or not result.get('load_segments')
                or any(error not in allowed for error in result['errors'])):
            raise Failure('extension ELF is malformed or differs from selected interpreter architecture')
        return dict(file=file_pin(path), package_check=result,
                    aarch64_16k_structure='FAIL_TARGET_PROFILE' if result['errors'] else 'PASS_STRUCTURE_ONLY',
                    native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN')

    def build(self, step, expected=0):
        before, inputs = self.artifacts(), self.inputs()
        self.usable = False; self.installed = None
        try:
            raw = self.command(step, self.argv('build'), expected)
            if inputs != self.inputs():
                raise Failure('source/tool/header inputs changed while building')
            if expected == 'nonzero':
                if b'INTENTIONAL_COMPILE_FAILURE' not in raw:
                    raise Failure('unrelated compiler failure')
                self.record(step, 'EXPECTED_COMPILE_FAILURE', before)
                return
            products = self.artifacts()
            if not self.extension.is_file() or len([n for n in products if n.endswith('.o')]) != 1:
                raise Failure('missing actual extension or compiled object')
            elf = self.inspect_elf(self.extension)
            self.verified = dict(inputs=inputs, products=products)
            self.usable = True
            self.record(step, 'BUILT_REAL_EXTENSION', before, elf=elf)
        except BaseException:
            self.usable = False
            self.record(step + '-error', 'BUILD_FAILED_CUSTODY_REVOKED', before)
            raise

    def run(self, step, expected):
        self.require_usable()
        self.usable = False
        raw = self.command(step, [self.tools['python'], '-I', '-S', '-B', str(self.checker),
                                  '--extension', str(self.extension), '--run'])
        identity = json.loads(raw)
        self.check_import(identity, self.extension, expected)
        if self.inputs() != self.verified['inputs'] or self.artifacts() != self.verified['products']:
            raise Failure('inputs/products changed during import')
        self.record(step, 'EXACT_COMPILED_EXTENSION_IMPORT', import_identity=identity)
        self.usable = True

    def check_import(self, identity, extension, expected):
        if (Path(identity['module']) != extension or identity['greeting'].encode() + b'\n' != expected
                or not identity['builtin'] or identity['loader'] != 'ExtensionFileLoader'
                or identity['isolated'] != 1 or Path(identity['executable']).resolve() != Path(self.tools['python'])):
            raise Failure('actual compiled extension identity/output differs')

    def refuse_stale(self, step):
        before = len(self.commands.records)
        try:
            self.run('forbidden-stale-import', EDITED)
        except (OSError, ValueError):
            pass
        else:
            raise Failure('stale extension import was accepted')
        if len(self.commands.records) != before:
            raise Failure('stale import launched a process')
        self.record(step, 'REFUSED_BEFORE_LAUNCH', attempted_launches=0)

    def install_and_import(self, step, expected):
        self.require_usable()
        self.installed = None
        self.prefix = self.root / 'prefixes' / step
        if self.prefix.exists():
            raise Failure('private installation prefix must be fresh')
        self.command(step + '-install', self.argv('install'))
        installed_extension = self.prefix / 'lib' / self.extension.name
        tree = self.installed_tree()
        if (set(tree) != {'lib/' + self.extension.name, 'share/licenses/python-extension-fixture/LICENSE'}
                or file_pin(installed_extension) != file_pin(self.extension)
                or file_pin(self.prefix / 'share/licenses/python-extension-fixture/LICENSE') != file_pin(self.source / 'LICENSE')):
            raise Failure('private installed extension/license tree differs')
        self.installed = dict(inputs=self.inputs(), tree=tree)
        self.require_installed()
        receipt, self.installed = self.installed, None
        self.usable = False
        expectation = self.root / (step + '-installed-expectation.txt')
        expectation.write_bytes(expected)
        held_build, held_source = self.root / 'build-withheld', self.root / 'source-withheld'
        self.build_dir.rename(held_build)
        try:
            self.source.rename(held_source)
            try:
                raw = self.command(step + '-installed-import', [self.tools['python'], '-I', '-S', '-B',
                     str(self.checker), '--extension', str(installed_extension), '--run'])
                tests = self.command(step + '-installed-tests', [self.tools['python'], '-I', '-S', '-B',
                     str(self.checker), '--extension', str(installed_extension), '--expected-file', str(expectation)])
            finally:
                held_source.rename(self.source)
        finally:
            held_build.rename(self.build_dir)
        identity = json.loads(raw); self.check_import(identity, installed_extension, expected)
        if (b'Ran 2 tests' not in tests or b'DEVELOPER_TEST_OK' not in tests
                or ordinary_pin(expectation) != pin(expected)
                or self.inputs() != self.verified['inputs'] or self.artifacts() != self.verified['products']):
            raise Failure('installed tests or source/product custody differs')
        self.usable = True
        self.installed = receipt
        self.require_installed(); self.require_usable()
        self.record(step, 'PRIVATE_INSTALLED_IMPORT_SOURCE_AND_BUILD_WITHHELD',
                    prefix=str(self.prefix), installed=self.installed,
                    elf=self.inspect_elf(installed_extension), import_identity=identity,
                    installed_unit_tests='PASS_2_TESTS_SOURCE_AND_BUILD_WITHHELD',
                    expectation=dict(path=str(expectation), file=pin(expected)))

    def journey(self):
        self.configure(); self.build('initial-build')
        self.run('initial-import', ORIGINAL); self.test('initial-test')
        self.install_and_import('initial', ORIGINAL)
        first = self.artifacts()
        self.build('unchanged-build')
        if self.artifacts() != first:
            raise Failure('unchanged CMake/Ninja build wrote extension/object/graph')
        self.record('unchanged-check', 'NO_EXTENSION_OBJECT_OR_GRAPH_WRITES', first)
        original = (self.source / 'extension.c').read_bytes()
        edited = original.replace(ORIGINAL.rstrip(), EDITED.rstrip())
        if edited == original:
            raise Failure('C source edit had no effect')
        self.change('extension.c', edited); self.change('expected.txt', EDITED)
        self.refuse_stale('edited-source-refusal')
        self.build('edited-build'); changed = self.artifacts()
        products = [n for n in first if n.endswith(('.o', '.so'))]
        if len(products) != 2 or any(first[n]['file'] == changed[n]['file'] for n in products):
            raise Failure('source edit did not change compiled object and extension')
        self.run('edited-import', EDITED); self.test('edited-test')
        self.install_and_import('edited', EDITED)
        self.change('extension.c', edited + b'\n#error INTENTIONAL_COMPILE_FAILURE\n')
        self.build('broken-build', expected='nonzero')
        if self.artifacts() != changed:
            raise Failure('failed compile did not retain prior products')
        self.refuse_stale('compile-failure-refusal')
        self.change('extension.c', edited)
        self.build('compile-recovery-build'); self.test('compile-recovery-test')
        self.run('compile-recovery-import', EDITED)
        self.change('expected.txt', b'INTENTIONAL_WRONG_EXPECTATION\n')
        self.build('test-failure-build'); self.test('broken-test', expected='nonzero')
        self.refuse_stale('test-failure-refusal')
        self.change('expected.txt', EDITED)
        self.build('test-recovery-build'); self.test('test-recovery-test')
        self.run('test-recovery-import', EDITED)
        self.install_and_import('recovery', EDITED)
        self.value.update(status='PASS_LOCAL_COMPILED_PYTHON_WORKFLOW',
                          unchanged='NO_EXTENSION_OBJECT_OR_GRAPH_WRITES',
                          edit='CHANGED_C_SOURCE_OBJECT_EXTENSION_AND_IMPORT_OUTPUT',
                          failures='REAL_COMPILER_AND_UNIT_FAILURES_RECOVERED_STALE_IMPORTS_REFUSED',
                          final_extension=self.inspect_elf(self.extension))
        save(self.commands.output / 'project.json', self.value)
        return self.value


def run(output, python, cmake=None, ninja=None, cc=None, ctest=None, timeout=30, total=240):
    if (not all(type(n) in (int, float) and math.isfinite(n) for n in (timeout, total))
            or not 2 <= timeout <= 60 or not timeout <= total <= 600):
        raise ValueError('require finite 2 <= timeout <= 60 and timeout <= total <= 600')
    selected = dict(python=python, cmake=cmake, ninja=ninja, cc=cc, ctest=ctest)
    tools = {name: selected_executable(path) for name, path in selected.items()}
    output = Path(output).absolute()
    if any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('output aliases refused')
    output.mkdir(mode=0o700, exist_ok=False)
    home = output / 'home'; home.mkdir(mode=0o700)
    temporary = output / 'tmp'; temporary.mkdir(mode=0o700)
    report = dict(schema=1, status='FAIL', scope='LOCAL_TRUSTED_CPYTHON_EXTENSION_COMPONENT',
                  architecture=platform.machine(), page_size=os.sysconf('SC_PAGE_SIZE'), uid=os.getuid(),
                  native_ARM='NOT_QUALIFIED', native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN',
                  system_install='NOT_RUN', independent_user='NOT_RUN', performance='NOT_MEASURED',
                  release='NOT_ADMITTED', selected=selected, tools={}, project=None,
                  sources=dict(runner=file_pin(__file__), build_systems=file_pin(B.__file__),
                      workflow=file_pin(W.__file__), package_checks=file_pin(PC.__file__),
                      owned_process=file_pin(ROOT / 'scripts/virtual/owned_process.py'),
                      fixtures={n: pin(raw) for n, raw in fixture_files().items()}))
    save(output / 'result.json', report)
    commands = project = None
    try:
        commands = W.Commands(output, home, os.defpath, timeout, total, max_output=256*1024)
        commands.env['TMPDIR'] = str(temporary)
        for name, path in tools.items():
            report['tools'][name] = dict(status='PRESENT' if path else 'MISSING', selected=selected[name])
            if path:
                report['tools'][name].update(path=path, file=file_pin(path))
        if tools['python'] is None:
            report['status'] = 'NOT_RUN_MISSING_INTERPRETER'
        else:
            identity = json.loads(commands.run('python-sysconfig', [tools['python'], '-I', '-S', '-B', '-c', IDENTITY], output))
            report['python_identity'] = identity
            headers_report, headers = header_inputs(identity)
            report['headers'] = headers_report
            missing = [n for n, path in tools.items() if path is None]
            if headers_report['status'] != 'PRESENT':
                report['status'] = headers_report['status']
            elif missing:
                report.update(status='NOT_RUN_MISSING_EXPLICIT_TOOLS', missing=missing)
            else:
                for name in ('cmake', 'ninja', 'cc', 'ctest'):
                    raw = commands.run('version-' + name, [tools[name], '--version'], output)
                    report['tools'][name]['version'] = raw.decode(errors='replace').splitlines()
                project = ExtensionProject(commands, tools, identity, headers, output)
                report['project'] = project.value
                report['project'] = project.journey()
                report['status'] = 'PASS_LOCAL_COMPILED_PYTHON_WORKFLOW'
    except (OSError, ValueError, KeyboardInterrupt) as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        if project is not None:
            project.value['status'] = 'FAIL'; save(output / 'project.json', project.value)
    finally:
        report['commands'] = commands.records if commands is not None else []
        save(output / 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--python', required=True, help='absolute selected CPython executable')
    for name in ('cmake', 'ninja', 'cc', 'ctest'):
        parser.add_argument('--' + name, help='absolute explicitly selected tool; omitted means NOT_RUN')
    parser.add_argument('--command-timeout', type=float, default=30)
    parser.add_argument('--total-timeout', type=float, default=240)
    args = parser.parse_args()
    try:
        report = run(args.output, args.python, args.cmake, args.ninja, args.cc, args.ctest,
                     args.command_timeout, args.total_timeout)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'architecture', 'page_size')}))
    return 0 if report['status'] == 'PASS_LOCAL_COMPILED_PYTHON_WORKFLOW' else 2


if __name__ == '__main__':
    raise SystemExit(main())
