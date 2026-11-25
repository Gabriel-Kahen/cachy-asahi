#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private offline venv/ensurepip/local-wheel/PEP668 journey for the pinned candidate."""
import argparse
import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import zipfile

HERE = Path(__file__).resolve().parent
SUPPORT = HERE.parent / 'python314-consumers/probe.py'
SUPPORT_COMMIT = '0e41b50a20d089ca1c35b7a246c7fb7aa433fd1c'
SUPPORT_SHA256 = 'b2bf0d64c60e63e6420533712765144223d80679e4814b4ebe3d1b13d0bfd739'
support_raw = SUPPORT.read_bytes()
if hashlib.sha256(support_raw).hexdigest() != SUPPORT_SHA256:
    raise ValueError('reviewed consumer support pin differs')
spec = importlib.util.spec_from_file_location('consumer_support', SUPPORT)
support = importlib.util.module_from_spec(spec)
exec(compile(support_raw, str(SUPPORT), 'exec'), support.__dict__)
require, Refusal, sha = support.require, support.Refusal, support.sha


def system_snapshot():
    """Read-only custody of system executables, shared library, headers and stdlib/site-packages."""
    selected = [Path('/usr/bin') / name for name in
                ('python', 'python3', 'python3.14', 'python-config', 'python3-config', 'python3.14-config')]
    selected += list(Path('/usr/lib').glob('libpython3.14*'))
    for root in (Path('/usr/include/python3.14'), Path('/usr/lib/python3.14')):
        selected.append(root)
        selected.extend(root.rglob('*'))
    require(len(selected) <= 30000, 'system snapshot file bound exceeded')
    result, size = {}, 0
    for path in sorted(set(selected)):
        mode = path.lstat().st_mode
        entry = {'mode': stat.S_IMODE(mode)}
        if stat.S_ISLNK(mode):
            entry['link'] = str(path.readlink())
        elif stat.S_ISREG(mode):
            size += path.stat().st_size
            require(size <= 512 * 1024**2, 'system snapshot size bound exceeded')
            entry['sha256'] = sha(path)
        else:
            require(stat.S_ISDIR(mode), 'unexpected system Python special file')
            entry['directory'] = True
        result[str(path)] = entry
    return result


def wheel(output):
    name = 'cachy_asahi_env_demo-0.1.0.dist-info'
    files = {
        'cachy_asahi_env_demo.py': (HERE / 'demo.py').read_bytes(),
        f'{name}/METADATA': b'Metadata-Version: 2.4\nName: cachy-asahi-env-demo\nVersion: 0.1.0\nLicense-Expression: MIT\n\nOriginal offline fixture.\n',
        f'{name}/WHEEL': b'Wheel-Version: 1.0\nGenerator: cachy-asahi-original-fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n',
        f'{name}/entry_points.txt': b'[console_scripts]\ncachy-asahi-env-demo = cachy_asahi_env_demo:main\n',
        f'{name}/licenses/LICENSE': (HERE.parents[2] / 'LICENSE').read_bytes()
    }
    rows = []
    for path, data in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
        rows.append([path, 'sha256=' + digest, str(len(data))])
    rows.append([f'{name}/RECORD', '', ''])
    record = io.StringIO(newline='')
    csv.writer(record, lineterminator='\n').writerows(rows)
    files[f'{name}/RECORD'] = record.getvalue().encode()
    target = output / 'cachy_asahi_env_demo-0.1.0-py3-none-any.whl'
    with zipfile.ZipFile(target, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path, data in sorted(files.items()):
            entry = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, data)
    return target


def guard(base, seal, executable, venv=None, config_sha=None):
    expected = (venv or base) / 'bin/python3.14'
    require(executable == expected, 'wrong selected interpreter')
    support.gate(base, seal, base / 'bin/python3.14')
    require(sha(executable) == sha(base / 'bin/python3.14'), 'interpreter bytes changed')
    if venv:
        require(sha(venv / 'pyvenv.cfg') == config_sha, 'venv configuration changed')


def run_journey(evidence, original, output):
    runner = support.Runner(output)
    # Fresh environment, no inherited pip config/indexes, and no network options.
    runner.env.update({'PIP_CONFIG_FILE': '/dev/null', 'PIP_NO_INDEX': '1',
                       'PIP_DISABLE_PIP_VERSION_CHECK': '1', 'PIP_NO_CACHE_DIR': '1'})
    system = system_snapshot()
    original_archive = evidence / 'export/python-3.14.8-1.1-x86_64.pkg.tar.zst'
    require(sha(original / 'host-probe-report.json') == support.REPORT_SHA, 'original core report changed')
    original_seal = support.inventory(original / 'stage/usr')
    stage, provenance = support.extract_full(evidence, output)
    seal = support.inventory(stage)
    copied = output / 'initial-base'
    shutil.copytree(stage, copied, symlinks=True)
    base = output / 'private-base'
    copied.rename(base)
    base_python = base / 'bin/python3.14'
    venv = output / 'venv'
    env_python = venv / 'bin/python3.14'
    guard(base, seal, base_python)

    def identity(executable, prefix, expected_base=base, allowed=(0,)):
        return runner.run([executable, '-I', '-B', HERE / 'identity.py', prefix,
                           expected_base, executable], base, allowed)

    _, base_data = identity(base_python, base)
    require(json.loads(base_data)['pip_origin'] is None, 'candidate unexpectedly packages pip frontend')
    require(not list((base / 'bin').glob('pip*')), 'candidate unexpectedly packages pip scripts')
    runner.run([base_python, '-I', '-B', '-m', 'venv', '--copies', '--without-pip', venv], base)
    config_sha = sha(venv / 'pyvenv.cfg')

    def checked(argv, allowed=(0,)):
        guard(base, seal, env_python, venv, config_sha)
        identity(env_python, venv)
        return runner.run(argv, base, allowed)

    _, fresh_data = identity(env_python, venv)
    require(json.loads(fresh_data)['pip_origin'] is None, 'fresh venv unexpectedly has pip')
    checked([env_python, '-I', '-B', '-m', 'ensurepip', '--default-pip'])
    _, pip_data = identity(env_python, venv)
    bootstrapped = json.loads(pip_data)
    require(Path(bootstrapped['pip_origin']).is_relative_to(venv) and
            bootstrapped['pip_version'] == '26.2.1', 'foreign pip bootstrap')
    bundle = base / 'lib/python3.14/ensurepip/_bundled/pip-26.2.1-py3-none-any.whl'
    require(bundle.is_file(), 'expected bundled offline pip wheel absent')
    local = wheel(output)
    wheel_sha = sha(local)

    def wheel_guard():
        require(sha(local) == wheel_sha, 'local wheel bytes changed')

    # Candidate deliberately has no base pip frontend. Inject the exact bundled
    # wheel on sys.path in one read-only/refused command; install nothing in base.
    pep_code = """import runpy,sys
from pathlib import Path
base, bundled, wheel = map(Path, sys.argv[1:4])
if sys.version_info[:3] != (3,14,8) or Path(sys.prefix) != base or sys.prefix != sys.base_prefix:
    raise RuntimeError('PEP668 interpreter identity refused')
if not bundled.is_relative_to(base) or not (base/'lib/python3.14/EXTERNALLY-MANAGED').is_file():
    raise RuntimeError('PEP668 inputs refused')
sys.path.insert(0, str(bundled))
sys.argv=['pip','--isolated','--disable-pip-version-check','--no-cache-dir','install','--no-index','--no-deps','--no-compile',str(wheel)]
runpy.run_module('pip', run_name='__main__')
"""
    guard(base, seal, base_python)
    wheel_guard()
    _, pep_output = runner.run([base_python, '-I', '-B', '-c', pep_code, base, bundle, local], base, (1,))
    require('externally-managed-environment' in pep_output and
            'managed by the system package manager' in pep_output, 'PEP668 refusal absent')
    guard(base, seal, base_python)
    pip = [env_python, '-I', '-B', '-m', 'pip', '--isolated', '--disable-pip-version-check', '--no-cache-dir']
    wheel_guard()
    checked([*pip, 'install', '--no-index', '--no-deps', '--no-compile', local])
    _, imported = checked([env_python, '-I', '-B', '-c',
                           'import cachy_asahi_env_demo as d; d.main()'])
    imported = json.loads(imported)
    require(imported['version'] == '0.1.0' and imported['answer'] == 42 and
            Path(imported['module']).is_relative_to(venv), 'installed wheel identity refused')
    console = venv / 'bin/cachy-asahi-env-demo'
    script = console.read_text()
    require(script.startswith(f'#!{env_python}\n') or
            script.startswith('#!/bin/sh\n') and f"'''exec' {env_python} \"$0\" \"$@\"" in script,
            'console interpreter binding refused')
    _, console_output = checked([console])
    require(json.loads(console_output) == imported, 'console/import identities differ')
    checked([*pip, 'uninstall', '-y', 'cachy-asahi-env-demo'])
    absent = """import importlib.util,importlib.metadata,json
if importlib.util.find_spec('cachy_asahi_env_demo') is not None:
    raise RuntimeError('wheel import survived uninstall')
try: importlib.metadata.version('cachy-asahi-env-demo')
except importlib.metadata.PackageNotFoundError: pass
else: raise RuntimeError('wheel metadata survived uninstall')
print(json.dumps({'import_and_metadata_absent':True}))
"""
    checked([env_python, '-I', '-B', '-c', absent])
    require(not console.exists(), 'console survived uninstall')
    controls = []

    def refusal(name, action, expected):
        try:
            action()
        except Refusal as exc:
            require(expected in str(exc), f'unexpected refusal: {exc}')
            controls.append({'name': name, 'reason': str(exc), 'result': 'PASS'})
        else:
            raise Refusal(f'{name} did not refuse')

    refusal('wrong selected interpreter', lambda: guard(base, seal, Path('/usr/bin/python3')),
            'wrong selected interpreter')
    _, wrong = identity(Path('/usr/bin/python3'), venv, allowed=(1,))
    require(any(message in wrong for message in ('wrong interpreter version',
            'wrong interpreter/base prefix', 'wrong interpreter executable')),
            'system interpreter was not refused')
    controls.append({'name': 'actual system interpreter refused', 'result': 'PASS', 'exit': 1})
    _, wrong = identity(env_python, venv, Path('/usr'), (1,))
    require('wrong interpreter/base prefix' in wrong, 'wrong expected base was not refused')
    controls.append({'name': 'actual wrong expected base prefix', 'result': 'PASS', 'exit': 1})
    config = venv / 'pyvenv.cfg'
    config_bytes = config.read_bytes()
    try:
        changed = config_bytes.replace(str(base / 'bin').encode(), b'/usr/bin')
        require(changed != config_bytes, 'venv home pattern absent')
        config.write_bytes(changed)
        refusal('tampered venv configuration', lambda: guard(base, seal, env_python, venv, config_sha),
                'venv configuration changed')
        _, wrong = identity(env_python, venv, allowed=(1,))
        require('wrong interpreter/base prefix' in wrong, 'actual changed venv home was not refused')
        controls.append({'name': 'actual altered venv home refused', 'result': 'PASS', 'exit': 1})
    finally:
        config.write_bytes(config_bytes)
    library = base / 'lib/libpython3.14.so.1.0'
    withheld = output / 'withheld-library'
    library.rename(withheld)
    try:
        refusal('missing library', lambda: guard(base, seal, env_python, venv, config_sha), 'missing candidate library')
        code, wrong = identity(env_python, venv, allowed=(1, 127))
        require(code == 1 and 'wrong interpreter version' in wrong or
                code == 127 and 'libpython3.14.so.1.0' in wrong, 'unexpected library refusal')
        controls.append({'name': 'actual missing-library/fallback refusal', 'result': 'PASS', 'exit': code})
    finally:
        withheld.rename(library)
    marker = base / 'lib/python3.14/EXTERNALLY-MANAGED'
    marker_bytes = marker.read_bytes()
    try:
        marker.write_bytes(marker_bytes + b'changed\n')
        refusal('tampered base marker', lambda: guard(base, seal, base_python), 'changed')
    finally:
        marker.write_bytes(marker_bytes)
    with local.open('ab') as stream:
        stream.write(b'changed')
    try:
        refusal('tampered local wheel', wheel_guard, 'local wheel bytes changed')
    finally:
        with local.open('r+b') as stream:
            stream.truncate(local.stat().st_size - 7)
    wheel_guard()
    checked([env_python, '-I', '-B', '-c', absent])
    _, final_data = identity(env_python, venv)
    guard(base, seal, base_python)
    require(support.inventory(stage) == seal, 'extracted input stage changed')
    require(support.inventory(original / 'stage/usr') == original_seal and
            sha(original / 'host-probe-report.json') == support.REPORT_SHA, 'original core evidence changed')
    require(sha(original_archive) == support.FULL_ARCHIVE_SHA, 'original full archive changed')
    require(system_snapshot() == system, 'system Python snapshot changed')
    for name, data in [('system-python-seal.json', system), ('base-seal.json', seal)]:
        (output / name).write_text(json.dumps(data, sort_keys=True, indent=2) + '\n')
    result = {'schema_version': 1, 'status': 'PASS bounded private environment journey',
              'input': provenance, 'base_identity': json.loads(base_data),
              'fresh_venv': json.loads(fresh_data), 'bootstrapped_venv': json.loads(pip_data),
              'final_venv': json.loads(final_data), 'import_and_console': imported,
              'PEP668': {'status': 'PASS actual outside-venv install refused',
                         'limited_injection': str(bundle), 'bundle_sha256': sha(bundle),
                         'base_pip_frontend': 'ABSENT before and after; injected bundled wheel only'},
              'wheel': {'path': str(local), 'sha256': sha(local), 'uninstall': 'PASS import/metadata/console absent'},
              'controls': controls, 'commands': runner.commands,
              'system_Python': {'status': 'UNCHANGED selected executables/library/headers/entire stdlib and site-packages',
                                'nodes': len(system), 'seal_sha256': sha(output / 'system-python-seal.json')},
              'original_core': 'UNCHANGED HOLD missing Tk', 'original_full_archive': 'UNCHANGED',
              'base_seal_sha256': sha(output / 'base-seal.json'),
              'sources': {p.name: sha(p) for p in sorted(HERE.iterdir()) if p.is_file()},
              'reused_support': {'path': str(SUPPORT), 'sha256': SUPPORT_SHA256, 'commit': SUPPORT_COMMIT},
              'limits': {'overall_seconds': 300, 'child_seconds': 60, 'child_cpu_seconds': 45,
                         'child_address_space_bytes': 1024**3, 'private_HOME_XDG_TMPDIR': True,
                         'network_commands': False, 'host_installs': False},
              'holds': ['x86_64 host workflow only', 'native ARM/native16K/M2/GUI/performance NOT RUN',
                        'source/signature/legal/full-system/trust/release gates unchanged',
                        'original core HOLD and prior full-Tk C consumer results remain separate']}
    (output / 'report.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full-evidence', type=Path, required=True)
    parser.add_argument('--original-core', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(os.geteuid() != 0, 'ordinary user required')
    evidence, original = args.full_evidence.resolve(strict=True), args.original_core.resolve(strict=True)
    require(args.output.is_absolute() and not any(c.isspace() for c in str(args.output)),
            'absolute output without whitespace required')
    output = args.output.parent.resolve(strict=True) / args.output.name
    require(not output.is_relative_to(evidence) and not output.is_relative_to(original), 'output overlaps evidence')
    require(not output.exists() and not output.is_symlink(), 'fresh output required')
    output.mkdir(mode=0o700)
    def deadline(signum, frame):
        raise Refusal('overall 300-second journey deadline exceeded')
    old_handler = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(300)
    try:
        result = run_journey(evidence, original, output)
    except BaseException as exc:
        (output / 'failure.json').write_text(json.dumps({'status': 'FAIL', 'error': str(exc)}) + '\n')
        raise
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)
    print(json.dumps({'status': result['status'], 'report': str(output / 'report.json'),
                      'controls': len(result['controls']), 'system_Python': 'UNCHANGED'}))


if __name__ == '__main__':
    main()
