#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Fixed v1 Python CLI adapter for184's exact ARM frontend/separate backend."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from installed_tools_v1 import PREFIX, load_packaged_workflow, need, pin

FRONTEND = '/opt/native-developer-tools/uv'
PYTHON_ROOT = Path('/out/journey/python')
IDENTITY = '''import importlib.metadata as m,json,pathlib,shutil,uv_build
d=m.distribution('uv_build')
print(json.dumps(dict(version=d.version,module=uv_build.__file__,builtin_frontend=uv_build.USE_UV_EXECUTABLE,
 backend=shutil.which('uv-build'),files=[str(pathlib.Path(d.locate_file(p)).resolve()) for p in d.files])))'''


def plan(argv):
    if argv == ['--version']:
        return dict(action='version', argv=[FRONTEND, '--version'])
    prefix = ['--offline', '--no-config', '--no-python-downloads', '--cache-dir', str(PYTHON_ROOT / 'cache')]
    need(argv[:5] == prefix, 'fixed original offline flags/cache required')
    tail = argv[5:]
    python = str(PYTHON_ROOT / 'venv/bin/python')
    if tail[:1] == ['build']:
        need(len(tail) == 9 and tail[:7] == ['build','--wheel','--python',python,'--no-index','--no-create-gitignore','--out-dir']
             and re.fullmatch(re.escape(str(PYTHON_ROOT / 'dist')) + r'/[0-9]{2}', tail[7])
             and tail[8:] == [str(PYTHON_ROOT / 'project')], 'fixed original fixture build argv required')
        return dict(action='build', argv=[FRONTEND,*argv,'--force-pep517','--no-build-isolation','--verbose'])
    need(len(tail) == 10 and tail[:9] == ['pip','install','--python',python,'--no-index','--no-deps','--reinstall','--link-mode','copy']
         and re.fullmatch(re.escape(str(PYTHON_ROOT / 'dist')) + r'/[0-9]{2}/cachy_python_demo-0\.1\.0-py3-none-any\.whl', tail[-1]),
         'fixed original fixture wheel install argv required')
    return dict(action='install', argv=[FRONTEND,*argv])


def main():
    selected = plan(sys.argv[1:])
    policy = json.loads((PREFIX / 'uv-inputs.json').read_text())
    frontend = next(r for r in policy['artifacts'] if r['role'] == 'frontend')
    wheel = next(r for r in policy['artifacts'] if r['role'] == 'backend')
    need(pin(Path(FRONTEND)) == {k:frontend['member'][k] for k in ('bytes','sha256')}, 'held exact ARM uv frontend required')
    wheel_path = PREFIX / 'uv_build-0.11.28-py3-none-manylinux_2_28_aarch64.whl'
    need(pin(wheel_path) == {k:wheel[k] for k in ('bytes','sha256')}, 'held exact ARM uv_build wheel required')
    if selected['action'] != 'build':
        os.execv(FRONTEND, selected['argv'])
    W = load_packaged_workflow()
    evidence = Path('/out/journey/backend-v1')
    if not evidence.exists():
        evidence.mkdir(mode=0o700); (evidence / 'home').mkdir(mode=0o700)
    commands = W.Commands(evidence, evidence / 'home', str(PYTHON_ROOT / 'venv/bin') + ':/usr/bin:/bin', timeout=25, total=50)
    prior = evidence / 'result.json'
    if prior.exists():
        old = json.loads(prior.read_text()); commands.records = old['commands']
        need(old['status'] == 'PASS_PINNED_INSTALLED_PEP517_ADAPTER_V1'
             and len(commands.records) <= 32, 'finite prior serial backend custody required')
        for row in commands.records:
            need(row['success'] and pin(evidence / row['log']) == row['log_pin'], 'prior adapter command custody differs')
    commands.env.update(UV_OFFLINE='1', UV_NO_CONFIG='1', UV_PYTHON_DOWNLOADS='never', TMPDIR=str(PYTHON_ROOT / 'tmp'))
    python = str(PYTHON_ROOT / 'venv/bin/python')
    result = None
    try:
        # Do not reinstall backend after the first build: preserve and recheck its
        # original exact installed payload on every invocation.
        if not prior.exists():
            commands.run('backend-install', [FRONTEND,'--offline','--no-config','--no-python-downloads',
                'pip','install','--python',python,'--no-index','--no-deps','--link-mode','copy',str(wheel_path)], PYTHON_ROOT)
        identity = json.loads(commands.run('backend-identity', [python,'-I','-B','-c',IDENTITY], PYTHON_ROOT))
        need(identity['version'] == '0.11.28' and identity['builtin_frontend'] is False
             and identity['backend'] == str(PYTHON_ROOT / 'venv/bin/uv-build')
             and Path(identity['module']).is_relative_to(PYTHON_ROOT / 'venv'), 'actual separate private backend required')
        members = {}
        for member in wheel['verified_members']:
            path = PYTHON_ROOT / 'venv/bin/uv-build' if member['name'].endswith('.data/scripts/uv-build') else Path(identity['module']).parent / member['name'].removeprefix('uv_build/')
            need(not path.is_symlink() and pin(path) == {k:member[k] for k in ('bytes','sha256')}, 'exact backend shim/binary payload required')
            members[str(path)] = pin(path)
        broken = b'version = "INTENTIONAL_BUILD_FAILURE"' in (PYTHON_ROOT / 'project/pyproject.toml').read_bytes()
        raw = commands.run('force-pep517-build', selected['argv'], PYTHON_ROOT / 'project', 'nonzero' if broken else 0)
        need(all(pin(Path(name)) == row for name,row in members.items()), 'backend changed during build')
        result = dict(status='PASS_PINNED_INSTALLED_PEP517_ADAPTER_V1', commands=commands.records,
            identity=identity, members=members, frontend=frontend['member'], wheel=wheel,
            protocol='FORCE_PEP517_PRIVATE_PINNED_UV_BUILD_NO_BUILD_ISOLATION_NO_INDEX')
        prior.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        sys.stdout.buffer.write(raw)
        return 1 if broken else 0
    finally:
        if result is None:
            prior.write_text(json.dumps(dict(status='FAIL',commands=commands.records),indent=2,sort_keys=True)+'\n')


if __name__ == '__main__':
    raise SystemExit(main())
