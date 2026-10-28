# SPDX-License-Identifier: MIT
"""Real offline PEP517 successor; original Python fixture/workflow stays held."""
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import need, pin, read, save, uv_policy


def original(root):
    path = root / 'scripts/workflows/python_development.py'; body = read(path)
    need(pin(body)['sha256'] == '3587267a38e77e9ca93301accf7fe0c6d73f5664320ee11635b0c17734e3004b', 'held Python workflow source')
    spec = importlib.util.spec_from_file_location('_python_original', path)
    module = importlib.util.module_from_spec(spec); exec(compile(body, str(path), 'exec'), module.__dict__)
    return module


def backend_argv(argv, uv, wheelhouse):
    if argv[0] == uv and 'build' in argv:
        need('--offline' in argv and '--no-index' in argv and '--wheel' in argv, 'original offline wheel command')
        return [*argv, '--force-pep517', '--no-build-isolation', '--verbose']
    return argv


def inputs(root, uv):
    policy = uv_policy(root)
    front = next(r for r in policy['artifacts'] if r['role'] == 'frontend')
    back = next(r for r in policy['artifacts'] if r['role'] == 'backend')
    need(pin(read(Path(uv), cap=front['member']['bytes'])) == {k: front['member'][k] for k in ('bytes', 'sha256')}, 'exact extracted ARM uv frontend')
    wheel = root / back['path']; raw = read(wheel, cap=back['bytes'])
    need(pin(raw) == {k: back[k] for k in ('bytes', 'sha256')}, 'exact separate uv_build wheel')
    need({p.name for p in wheel.parent.iterdir()} == {wheel.name}, 'closed one-wheel backend wheelhouse')
    with zipfile.ZipFile(wheel) as archive:
        metadata = archive.read('uv_build-0.11.28.dist-info/METADATA')
        need(b'Version: 0.11.28\n' in metadata and b'Requires-Dist:' not in metadata, 'dependency-free exact backend wheel metadata')
        need('uv_build/__init__.py' in archive.namelist(), 'real importable PEP517 backend package')
    return policy, wheel.parent


BACKEND_IDENTITY = '''import importlib.metadata as m, json, pathlib, shutil, sys, uv_build
d=m.distribution('uv_build')
print(json.dumps(dict(version=d.version, module=uv_build.__file__, builtin_frontend=uv_build.USE_UV_EXECUTABLE,
    backend=shutil.which('uv-build'), files=[str(pathlib.Path(d.locate_file(p)).resolve()) for p in d.files])))'''


def run(root, output, python='/usr/bin/python3', uv='/opt/native-developer-tools/uv', timeout=45, total=600):
    need(all(type(n) in (int, float) and math.isfinite(n) for n in (timeout, total))
         and 2 <= timeout <= 60 and timeout <= total <= 600, 'finite original workflow budgets')
    p = original(root); python, uv = p.executable(python), p.executable(uv)
    policy, wheelhouse = inputs(root, uv)
    need(not any(q.is_symlink() for q in (output, *output.parents)), 'ordinary private output')
    output.mkdir(mode=0o700); home = output / 'home'; home.mkdir()
    temporary = output / 'tmp'; temporary.mkdir()
    class Commands(p.W.Commands):
        backend_files = None
        def check_backend(self):
            if self.backend_files is not None:
                need(all(Path(name).is_file() and not Path(name).is_symlink()
                     and p.file_pin(Path(name)) == row for name,row in self.backend_files.items()), 'installed backend bytes changed around actor')
        def run(self, step, argv, cwd, expected=0):
            self.check_backend()
            raw = super().run(step, backend_argv(argv, uv, wheelhouse), cwd, expected)
            self.check_backend()
            return raw
    commands = Commands(output, home, os.defpath, timeout, total)
    commands.env.update(TMPDIR=str(temporary), UV_OFFLINE='1', UV_PYTHON_DOWNLOADS='never',
        UV_NO_CONFIG='1', PYTHONNOUSERSITE='1', SOURCE_DATE_EPOCH='1700000000')
    report = dict(schema=1, status='FAIL', scope='REAL_OFFLINE_PEP517_PYTHON_COMPONENT',
        architecture=platform.machine(), page_size=os.sysconf('SC_PAGE_SIZE'),
        frontend=dict(path=uv, file=p.file_pin(uv)), backend=next(r for r in policy['artifacts'] if r['role']=='backend'),
        build_protocol='FORCE_PEP517_PRIVATE_PINNED_UV_BUILD_NO_BUILD_ISOLATION_NO_INDEX',
        source=p.file_pin(__file__), original=p.file_pin(p.__file__), native_16K='NOT_QUALIFIED',
        physical_M2='NOT_RUN', system_install='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED')
    save(output / 'result.json', report)
    try:
        report['selected_python'] = json.loads(commands.run('python-identity', [python, '-I', '-B', '-c', p.IDENTITY], output))
        version = commands.run('uv-version', [uv, '--version'], output)
        need(version.decode().split()[:2] == ['uv', '0.11.28'], 'actual exact uv version')
        project = p.Project(commands, python, uv, output)
        project.create_environment(); report['project'] = project.value
        wheel = next(row for row in policy['artifacts'] if row['role'] == 'backend')
        commands.run('backend-install', project.uv_argv('pip', 'install', '--python', project.env_python,
            '--no-index', '--no-deps', '--reinstall', '--link-mode', 'copy', str(root / wheel['path'])), project.source)
        commands.env['PATH'] = str(project.venv / 'bin') + os.pathsep + os.defpath
        backend = json.loads(commands.run('backend-identity', [project.env_python, '-I', '-B', '-c', BACKEND_IDENTITY], project.source))
        need(backend['version'] == '0.11.28' and backend['builtin_frontend'] is False
             and Path(backend['backend']) == project.venv / 'bin/uv-build'
             and Path(backend['module']).is_relative_to(project.venv), 'separately installed backend shim and binary identity')
        commands.backend_files = {}
        for name in backend['files']:
            path = Path(name)
            need(path.is_relative_to(project.venv) and path.is_file() and not path.is_symlink(), 'ordinary backend file inside private venv')
            commands.backend_files[name] = p.file_pin(path)
        for member in wheel['verified_members']:
            target = project.venv / 'bin/uv-build' if member['name'].endswith('.data/scripts/uv-build') else Path(backend['module']).parent / member['name'].removeprefix('uv_build/')
            need(p.file_pin(target) == {k:member[k] for k in ('bytes','sha256')}, 'installed backend equals pinned wheel payload')
        report['installed_backend'] = dict(identity=backend, files=commands.backend_files)
        report['project'] = project.journey()
        report['status'] = 'PASS_LOCAL_PYTHON_PEP517_WORKFLOW'
    except (OSError, ValueError, KeyboardInterrupt) as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        report['commands'] = commands.records
        save(output / 'result.json', report)
    return report
