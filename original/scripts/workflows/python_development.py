#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Finite offline Python fixture journey in a fresh private venv; component evidence."""
import argparse
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'tests/workflows/fixtures/python-development'
WORKFLOW_PIN = '531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba'
UV_VERSION = '0.11.28'
NAMES = ('pyproject.toml', 'LICENSE', 'test_demo.py',
         'src/cachy_python_demo/__init__.py', 'src/cachy_python_demo/__main__.py')
ORIGINAL = b'Python developer version one\n'
EDITED = b'Python developer version two\n'


def load_workflow():
    import hashlib
    path = ROOT / 'scripts/workflows/developer_workflow.py'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != WORKFLOW_PIN:
        raise ValueError('reviewed developer workflow helper pin differs')
    module = importlib.util.module_from_spec(importlib.util.spec_from_file_location('_python_workflow', path))
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


W = load_workflow()
Failure, pin, file_pin, save = W.Failure, W.pin, W.file_pin, W.save


def ordinary_pin(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 128 * 1024:
        raise Failure('bounded ordinary project file required: ' + str(path))
    return file_pin(path)


def fixture_files():
    result = {}
    for name in NAMES:
        path = FIXTURES / name
        ordinary_pin(path)
        result[name] = path.read_bytes()
    return result


def executable(path):
    path = Path(path)
    if not path.is_absolute() or not path.is_file() or not os.access(path, os.X_OK):
        raise ValueError('select an existing executable with an absolute path')
    return str(path.resolve())


IDENTITY = '''import json, os, platform, sys, sysconfig
print(json.dumps(dict(executable=sys.executable, base_executable=sys._base_executable,
    version=sys.version, implementation=sys.implementation.name, prefix=sys.prefix,
    base_prefix=sys.base_prefix, machine=platform.machine(), page_size=os.sysconf('SC_PAGE_SIZE'),
    stdlib=sysconfig.get_path('stdlib'), purelib=sysconfig.get_path('purelib'),
    isolated=sys.flags.isolated, user_site=sys.flags.no_user_site)))'''

INSTALLED = '''import importlib.metadata as m, json, pathlib, sys
import cachy_python_demo
d = m.distribution('cachy-python-demo')
print(json.dumps(dict(version=d.version, dependencies=d.requires or [],
    module=cachy_python_demo.__file__, prefix=sys.prefix,
    files=sorted(str(pathlib.Path(d.locate_file(p)).resolve()) for p in d.files))))'''


class Project:
    """Source/tool/wheel/install-bound custody; no stale launch after failures."""
    def __init__(self, commands, python, uv, output):
        self.commands, self.python, self.uv, self.root = commands, python, uv, output
        self.source = output / 'project'; self.source.mkdir()
        for name, raw in fixture_files().items():
            path = self.source / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.venv = output / 'venv'
        self.env_python = str(self.venv / 'bin/python')  # Preserve venv invocation, never resolve it.
        self.built = self.installed = None
        self.tested = False
        self.value = dict(status='RUNNING', records=[], build='NOT_RUN', install='NOT_RUN')

    def record(self, step, outcome, **extra):
        directory = self.root / 'snapshots' / ('%02d-' % len(self.value['records']) + step)
        directory.mkdir(parents=True)
        sources = {}
        for name in NAMES:
            raw = (self.source / name).read_bytes()
            target = directory / name; target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            sources[name] = dict(file=pin(raw), retained=str(target.relative_to(self.root)))
        self.value['records'].append(dict(step=step, outcome=outcome, sources=sources, **extra))
        save(self.root / 'project.json', self.value)

    def command(self, step, argv, expected=0):
        return self.commands.run(step, argv, self.source, expected)

    def create_environment(self):
        self.command('create-venv', [self.python, '-I', '-B', '-m', 'venv', '--without-pip', str(self.venv)])
        identity = json.loads(self.command('venv-identity', [self.env_python, '-I', '-B', '-c', IDENTITY]))
        if (Path(identity['prefix']) != self.venv or identity['prefix'] == identity['base_prefix']
                or not identity['isolated'] or not identity['user_site']
                or Path(identity['base_executable']).resolve() != Path(self.python)):
            raise Failure('created environment is not bound to the selected isolated interpreter')
        config = (self.venv / 'pyvenv.cfg').read_text()
        if 'include-system-site-packages = false' not in config:
            raise Failure('venv inherited host packages')
        self.value['environment'] = dict(identity=identity, config=ordinary_pin(self.venv / 'pyvenv.cfg'),
                                         executable=file_pin(self.env_python), pip_seeded=False)
        self.record('environment', 'CREATED_FRESH_VENV_WITHOUT_PIP')

    def inputs(self):
        return dict(sources={n: ordinary_pin(self.source / n) for n in NAMES},
                    python=file_pin(self.python), uv=file_pin(self.uv),
                    venv_executable=file_pin(self.env_python),
                    venv_config=ordinary_pin(self.venv / 'pyvenv.cfg'))

    def uv_argv(self, *args):
        return [self.uv, '--offline', '--no-config', '--no-python-downloads',
                '--cache-dir', str(self.root / 'cache'), *args]

    def require_built(self):
        if (self.built is None or self.inputs() != self.built['inputs']
                or file_pin(Path(self.built['wheel'])) != self.built['wheel_pin']):
            self.tested = False
            raise Failure('no successful wheel build for these exact inputs')

    def build(self, step, expected=0):
        inputs = self.inputs()
        if expected == 0 and self.built is not None and inputs == self.built['inputs']:
            self.require_built()
            self.record(step, 'UNCHANGED_NO_BUILD_OR_INSTALL_LAUNCH', inputs=inputs, attempted_launches=0,
                        wheel=self.built['wheel_pin'])
            return
        self.built = self.installed = None
        self.tested = False
        dist = self.root / 'dist' / ('%02d' % len(self.value['records']))
        dist.mkdir(parents=True)
        try:
            raw = self.command(step, self.uv_argv('build', '--wheel', '--python', self.env_python,
                              '--no-index', '--no-create-gitignore', '--out-dir', str(dist), str(self.source)), expected)
            if inputs != self.inputs():
                raise Failure('project or tools changed during build')
            if expected == 'nonzero':
                if b'INTENTIONAL_BUILD_FAILURE' not in raw:
                    raise Failure('unrelated build failure')
                self.record(step, 'EXPECTED_REAL_BUILD_FAILURE', inputs=inputs)
                return
            wheels = list(dist.iterdir())
            if len(wheels) != 1 or wheels[0].name != 'cachy_python_demo-0.1.0-py3-none-any.whl':
                raise Failure('expected exactly one actual fixture wheel')
            wheel = wheels[0]
            with zipfile.ZipFile(wheel) as archive:
                if archive.read('cachy_python_demo/__init__.py') != (self.source / NAMES[3]).read_bytes():
                    raise Failure('built wheel source differs')
                metadata = archive.read('cachy_python_demo-0.1.0.dist-info/METADATA')
                if b'Requires-Dist:' in metadata or b'Version: 0.1.0\n' not in metadata:
                    raise Failure('wheel metadata or dependency-free contract differs')
            self.built = dict(inputs=inputs, wheel=str(wheel), wheel_pin=file_pin(wheel))
            self.value['build'] = 'PASS_REAL_UV_WHEEL'
            self.record(step, 'BUILT_REAL_WHEEL', **self.built)
        except BaseException:
            self.record(step + '-error', 'BUILD_FAILED_CUSTODY_REVOKED')
            raise

    def installed_files(self):
        return {name: ordinary_pin(self.venv / name) for name in self.installed['files']}

    def require_installed(self):
        self.require_built()
        if self.installed is None or self.installed_files() != self.installed['files']:
            self.tested = False
            raise Failure('no verified current private installation')

    def install(self, step):
        self.require_built()
        self.installed = None; self.tested = False
        self.command(step, self.uv_argv('pip', 'install', '--python', self.env_python,
                     '--no-index', '--no-deps', '--reinstall', '--link-mode', 'copy', self.built['wheel']))
        identity = json.loads(self.command(step + '-identity', [self.env_python, '-I', '-B', '-c', INSTALLED]))
        if (identity['version'] != '0.1.0' or identity['dependencies']
                or Path(identity['prefix']) != self.venv or not identity['files']):
            raise Failure('private installed distribution identity differs')
        files = {}
        for name in identity['files']:
            path = Path(name)
            if not path.is_relative_to(self.venv):
                raise Failure('installed distribution escaped private environment')
            files[str(path.relative_to(self.venv))] = ordinary_pin(path)
        module = Path(identity['module'])
        if not module.is_relative_to(self.venv) or module.read_bytes() != (self.source / NAMES[3]).read_bytes():
            raise Failure('import did not load exact installed project bytes')
        self.installed = dict(files=files, identity=identity)
        self.value['install'] = 'PASS_LOCAL_WHEEL_IN_FRESH_PRIVATE_VENV'
        self.record(step, 'INSTALLED_REAL_WHEEL', installed=self.installed)

    def test(self, step, expected_output, expected=0):
        self.require_installed()
        self.tested = False
        self.commands.env['DEMO_EXPECTED'] = expected_output.decode().rstrip('\n')
        raw = self.command(step, [self.env_python, '-I', '-B', str(self.source / 'test_demo.py')], expected)
        self.require_installed()
        if b'Ran 1 test' not in raw or (expected == 0 and not raw.endswith(b'OK\n')):
            raise Failure('actual unit test did not finish successfully')
        if expected == 'nonzero':
            if b'INTENTIONAL_TEST_MISMATCH' not in raw or b'FAILED (failures=1)' not in raw:
                raise Failure('unrelated unit test failure')
            self.record(step, 'EXPECTED_REAL_UNIT_TEST_FAILURE', expected_output=pin(expected_output))
            return
        self.tested = True
        self.record(step, 'PASS_INSTALLED_UNIT_TEST', expected_output=pin(expected_output))

    def run(self, step, expected, console=False):
        self.require_installed()
        if not self.tested:
            raise Failure('current installation has no passing test')
        self.tested = False
        argv = ([str(self.venv / 'bin/cachy-python-demo')] if console
                else [self.env_python, '-I', '-B', '-m', 'cachy_python_demo'])
        raw = self.command(step, argv)
        self.require_installed()
        if raw != expected:
            raise Failure('installed CLI output differs')
        self.tested = True
        self.record(step, 'EXACT_INSTALLED_CLI_OUTPUT', output=pin(raw), console_entrypoint=console)

    def refuse_stale(self, step):
        before = len(self.commands.records)
        try:
            self.run('forbidden-stale-run', EDITED)
        except (ValueError, OSError):
            pass
        else:
            raise Failure('stale installation was accepted')
        if len(self.commands.records) != before:
            raise Failure('stale gate attempted a launch')
        self.record(step, 'STALE_EXECUTION_REFUSED', attempted_launches=0)

    def journey(self):
        self.build('initial-build'); self.install('initial-install')
        self.test('initial-test', ORIGINAL)
        self.run('initial-module', ORIGINAL); self.run('initial-console', ORIGINAL, console=True)
        first = dict(self.built)
        before = len(self.commands.records)
        self.build('unchanged-build')
        if self.built != first or len(self.commands.records) != before:
            raise Failure('unchanged content caused build/install work')
        source = self.source / NAMES[3]
        wanted = source.read_bytes().replace(ORIGINAL.rstrip(), EDITED.rstrip())
        if wanted == source.read_bytes():
            raise Failure('edit did not change source')
        source.write_bytes(wanted)
        self.refuse_stale('edited-source-stale-control')
        self.build('edited-build')
        if self.built['wheel_pin'] == first['wheel_pin']:
            raise Failure('edited source did not change wheel')
        self.install('edited-install'); self.test('edited-test', EDITED)
        self.run('edited-console', EDITED, console=True)
        self.test('deliberate-test-failure', ORIGINAL, expected='nonzero')
        self.refuse_stale('failed-test-stale-control')
        self.test('test-recovery', EDITED); self.run('test-recovery-module', EDITED)
        metadata = self.source / 'pyproject.toml'; original = metadata.read_bytes()
        metadata.write_bytes(original.replace(b'version = "0.1.0"', b'version = "INTENTIONAL_BUILD_FAILURE"'))
        self.build('deliberate-build-failure', expected='nonzero')
        self.refuse_stale('failed-build-stale-control')
        metadata.write_bytes(original)
        self.build('recovery-build'); self.install('recovery-install')
        self.test('recovery-test', EDITED)
        self.run('recovery-module', EDITED); self.run('recovery-console', EDITED, console=True)
        self.value.update(status='PASS_LOCAL_PYTHON_WORKFLOW', final_wheel=self.built,
                          final_installed=self.installed, unchanged='NO_BUILD_OR_INSTALL_LAUNCH',
                          edit='CHANGED_SOURCE_WHEEL_INSTALLED_MODULE_AND_CLI_OUTPUT',
                          failure_recovery='REAL_BUILD_AND_UNIT_FAILURES_RECOVERED')
        save(self.root / 'project.json', self.value)
        return self.value


def run(output, python, uv=None, timeout=20, total=180):
    if (not all(type(x) in (int, float) and math.isfinite(x) for x in (timeout, total))
            or not 2 <= timeout <= 60 or not timeout <= total <= 600):
        raise ValueError('require finite 2 <= command timeout <= 60 and timeout <= total <= 600')
    python = executable(python)
    uv = executable(uv) if uv is not None else None
    output = Path(output).absolute()
    if any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError('output aliases refused')
    output.mkdir(mode=0o700, exist_ok=False)
    home = output / 'home'; home.mkdir(mode=0o700)
    temporary = output / 'tmp'; temporary.mkdir(mode=0o700)
    report = dict(schema=1, status='FAIL', scope='LOCAL_USERSPACE_PYTHON_COMPONENT_ONLY',
                  architecture=platform.machine(), page_size=os.sysconf('SC_PAGE_SIZE'),
                  kernel=platform.release(), uid=os.getuid(), native_ARM='NOT_QUALIFIED',
                  native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN', system_install='NOT_RUN',
                  independent_user='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED',
                  sources=dict(runner=file_pin(__file__), workflow=file_pin(W.__file__),
                               owned_process=file_pin(ROOT / 'scripts/virtual/owned_process.py'),
                               fixtures={n: pin(raw) for n, raw in fixture_files().items()}),
                  selected_python=dict(path=python, file=file_pin(python)), uv=None)
    save(output / 'result.json', report)
    commands = project = None
    try:
        commands = W.Commands(output, home, os.defpath, timeout, total)
        commands.env.update(TMPDIR=str(temporary), UV_OFFLINE='1', UV_PYTHON_DOWNLOADS='never',
                            UV_NO_CONFIG='1', PYTHONNOUSERSITE='1', SOURCE_DATE_EPOCH='1700000000')
        report['selected_python']['identity'] = json.loads(commands.run('python-identity', [python, '-I', '-B', '-c', IDENTITY], output))
        project = Project(commands, python, uv, output)
        project.create_environment()
        report['project'] = project.value
        if uv is None:
            report['status'] = 'NOT_RUN_MISSING_EXPLICIT_UV'
            project.value.update(status='NOT_RUN', reason='No selected real offline build tool; no wheel or install fabricated')
            save(output / 'project.json', project.value)
        else:
            version = commands.run('uv-version', [uv, '--version'], output)
            report['uv'] = dict(path=uv, file=file_pin(uv), version=version.decode().strip(),
                                backend='uv_build==' + UV_VERSION)
            if version.decode().split()[:2] != ['uv', UV_VERSION]:
                report['status'] = 'NOT_RUN_INCOMPATIBLE_OFFLINE_BACKEND'
                project.value.update(status='NOT_RUN', reason='Selected uv must match exact fixture uv_build version')
                save(output / 'project.json', project.value)
            else:
                report['uv']['inputs'] = 'BUILT_IN_UV_BACKEND_NO_EXTERNAL_CACHE'
                report['project'] = project.journey()
                report['status'] = 'PASS_LOCAL_PYTHON_WORKFLOW'
    except (OSError, ValueError, KeyboardInterrupt) as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        if project is not None:
            project.value['status'] = 'FAIL'
            save(output / 'project.json', project.value)
    finally:
        report['commands'] = commands.records if commands is not None else []
        save(output / 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new private directory retained in full')
    parser.add_argument('--python', required=True, help='absolute path to explicitly selected interpreter')
    parser.add_argument('--uv', help='absolute path to uv with matching built-in backend; never downloaded')
    parser.add_argument('--command-timeout', type=float, default=20)
    parser.add_argument('--total-timeout', type=float, default=180)
    args = parser.parse_args()
    try:
        report = run(args.output, args.python, args.uv, args.command_timeout, args.total_timeout)
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'architecture', 'page_size')}))
    return 0 if report['status'] == 'PASS_LOCAL_PYTHON_WORKFLOW' else 2


if __name__ == '__main__':
    raise SystemExit(main())
