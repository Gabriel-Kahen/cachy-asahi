#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""One finite, disposable x86_64 diagnostic for the frozen Python recipe."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = 'archlinux@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae'
RUNTIME_SHA = '253494be99c21c83743b384b2c06cd1627023ffaf54f0cbbd271bde80572f70a'
LIMITS = ['--cpus=2', '--memory=4g', '--memory-swap=4g', '--pids-limit=256']
HOLDS = ['x86_64 host diagnostic only; native ARM NOT RUN', 'original ALARM build NOT reconstructed',
         'source/legal/policy acceptance remains separate', 'GUI, hardware and M2 NOT RUN']


def identity(path):
    path = Path(path)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('ordinary file required')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return {'bytes': path.stat().st_size, 'sha256': digest.hexdigest()}


def verify_inputs(recipe, archive):
    pins = json.loads((HERE / 'inputs.json').read_text())
    if {p.name for p in recipe.iterdir() if p.name != '__pycache__'} != set(pins['files']):
        raise ValueError('recipe namespace differs from frozen input')
    for name, expected in pins['files'].items():
        if identity(recipe / name) != expected:
            raise ValueError('recipe input changed: ' + name)
    if identity(archive) != {k: pins['source'][k] for k in ('bytes', 'sha256')}:
        raise ValueError('source archive changed')
    return pins


def build_options(name, image, volume, snapshot):
    return ['docker', 'create', '--name', name, '--label', 'cachy-asahi.operation=python314-tk-host',
            *LIMITS, '--init', '--read-only', '--network=none', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--user=1000:1000',
            '--ulimit=nofile=1024:1024', '--ulimit=core=0:0',
            '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,uid=1000,gid=1000',
            '--tmpfs=/run:rw,noexec,nosuid,nodev,size=8m,uid=1000,gid=1000',
            '--mount', f'type=volume,src={volume},dst=/work',
            '--mount', f'type=bind,src={snapshot},dst=/inputs,readonly',
            '--entrypoint=/usr/bin/bash', image, '/inputs/build.sh']


def validate_actor(value):
    host, config = value['HostConfig'], value['Config']
    assert host['NanoCpus'] == 2000000000 and host['Memory'] == 4 * 1024**3
    assert host['MemorySwap'] == 4 * 1024**3 and host['PidsLimit'] == 256
    assert host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] and host['Init']
    assert config['User'] == '1000:1000' and host['CapDrop'] == ['ALL']
    assert 'no-new-privileges' in host['SecurityOpt']
    assert not host['Privileged'] and not host['Devices']
    mounts = value['Mounts']
    assert len(mounts) == 2
    assert {m['Destination']: (m['Type'], m['RW']) for m in mounts} == {
        '/inputs': ('bind', False), '/work': ('volume', True)}
    return {k: host[k] for k in ('NanoCpus', 'Memory', 'MemorySwap', 'PidsLimit',
                               'NetworkMode', 'ReadonlyRootfs', 'Init', 'CapDrop', 'SecurityOpt')}


def check_export(path, pins):
    if (path / 'makepkg-exit.txt').read_text().strip() != '0':
        raise ValueError('ordinary makepkg failed; inspect retained log')
    info = (path / 'PKGINFO').read_text()
    build = (path / 'BUILDINFO').read_text()
    for line in ('pkgname = python', 'pkgver = 3.14.8-1.1', 'arch = x86_64'):
        if line not in info.splitlines():
            raise ValueError('incorrect diagnostic archive identity')
    if 'pkgbuild_sha256sum = ' + pins['files']['PKGBUILD']['sha256'] not in build.splitlines():
        raise ValueError('archive recipe binding mismatch')
    tk = json.loads((path / 'tk-headless.json').read_text())
    if tk['status'] != 'PASS headless Tcl only' or tk['Tk_loaded']:
        raise ValueError('headless Tcl result absent or unexpected Tk window profile')
    archive = path / 'python-3.14.8-1.1-x86_64.pkg.tar.zst'
    if not 1024 < archive.stat().st_size < 128 * 1024**2:
        raise ValueError('archive size bound')
    return {'archive': {'name': archive.name, **identity(archive)}, 'Tk': tk}


def cleanup_absent(argv, output):
    """Only a precise missing owned name is benign after an interrupted create."""
    prefix = 'Error response from daemon: '
    name = argv[-1]
    expected = {'rm': prefix + 'No such container: ' + name,
                'volume': prefix + 'get ' + name + ': no such volume',
                'image': prefix + 'No such image: ' + name}
    return output.strip() == expected.get(argv[1])


def main():
    if not sys.flags.isolated or sys.flags.optimize:
        raise ValueError('run with python3 -I without optimization')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    recipe = ROOT / 'packages/port/python3148-source-candidate'
    pins = verify_inputs(recipe, args.source)
    runtime_path = ROOT / 'scripts/port/fdk-native-stage/runtime.py'
    if identity(runtime_path)['sha256'] != RUNTIME_SHA:
        raise ValueError('finite runner changed')
    spec = importlib.util.spec_from_file_location('finite_runtime', runtime_path)
    runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)
    out = args.output.absolute()
    if out.exists() or any(p.is_symlink() for p in (out, *out.parents)):
        raise ValueError('new ordinary private output required')
    out.mkdir(mode=0o700)
    (out / 'logs').mkdir(mode=0o700)
    snapshot = out / 'inputs'; snapshot.mkdir(mode=0o755)
    for name in pins['files']:
        shutil.copyfile(recipe / name, snapshot / name)
    shutil.copyfile(args.source, snapshot / pins['source']['name'])
    for name in ('build.sh', 'tk_headless.py'):
        shutil.copyfile(HERE / name, snapshot / name)
    for path in snapshot.iterdir():
        path.chmod(0o444)
    token = uuid.uuid4().hex[:16]
    provision = 'python314-tk-provision-' + token
    actor = 'python314-tk-build-' + token
    init = 'python314-tk-init-' + token
    volume = 'python314-tk-work-' + token
    image = 'cachy-asahi-python314-tk-host:' + token
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'XDG_RUNTIME_DIR', 'DOCKER_HOST', 'DOCKER_CONTEXT')}
    runner = runtime.Runner(2700, env, out / 'logs')
    report = {'schema': 1, 'status': 'HOLD', 'base': BASE, 'inputs': pins,
              'helper_files': {p.name: identity(p) for p in HERE.iterdir() if p.is_file()},
              'holds': HOLDS, 'operations': [], 'cleanup': []}

    def command(argv, timeout=60, check=True):
        try:
            result = runner.run(argv, timeout=timeout, log=f"{len(report['operations']):02d}.log")
        except BaseException as error:
            report['operations'].append({'argv': argv, 'failure': type(error).__name__ + ': ' + str(error)})
            raise
        report['operations'].append({'argv': argv, 'returncode': result.returncode})
        if check and result.returncode:
            raise ValueError('command failed; retained operation ' + str(len(report['operations']) - 1))
        return result

    try:
        with runtime.cancellation_handlers():
            inspected = json.loads(command(['docker', 'image', 'inspect', BASE]).stdout)[0]
            if inspected['Id'] != 'sha256:' + BASE.split('sha256:')[1] or inspected['Architecture'] != 'amd64':
                raise ValueError('pinned official x86_64 image unavailable')
            command(['docker', 'create', '--name', provision, *LIMITS, '--network=host',
                     '--mount', f'type=bind,src={HERE},dst=/driver,readonly',
                     '--entrypoint=/usr/bin/bash', BASE, '/driver/provision.sh'])
            command(['docker', 'start', '--attach', provision], timeout=900)
            report['provisioned_image'] = command(['docker', 'commit', provision, image], timeout=120).stdout.decode().strip()
            command(['docker', 'volume', 'create', volume])
            command(['docker', 'create', '--name', init, '--network=none', '--cap-drop=ALL',
                     '--cap-add=CHOWN', '--read-only', '--security-opt=no-new-privileges',
                     *LIMITS, '--mount', f'type=volume,src={volume},dst=/work',
                     '--entrypoint=/usr/bin/chown', image, '1000:1000', '/work'])
            command(['docker', 'start', '--attach', init])
            command(build_options(actor, image, volume, snapshot))
            details = json.loads(command(['docker', 'inspect', actor]).stdout)[0]
            report['actor'] = validate_actor(details)
            result = command(['docker', 'start', '--attach', actor], timeout=1500, check=False)
            command(['docker', 'cp', actor + ':/work/output', str(out / 'export')], timeout=120)
            report['build_returncode'] = result.returncode
            report['result'] = check_export(out / 'export', pins)
            verify_inputs(recipe, args.source)
            report['status'] = 'PASS full recipe/check/package and headless Tcl; x86_64 only'
    except BaseException as error:
        report['failure'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        # Docker daemon jobs outlive their CLI: explicitly remove only these owned
        # names even after cancellation/deadline, before removing the owned volume.
        cleanup = runtime.Runner(120, env, out / 'logs')
        with runtime.defer_signals():
            # Register all names before contacting Docker, so cancellation after
            # daemon-side creation but before CLI completion cannot skip cleanup.
            actions = [['docker', 'rm', '-f', name] for name in (actor, init, provision)]
            actions += [['docker', 'volume', 'rm', volume], ['docker', 'image', 'rm', image]]
            for argv in actions:
                try:
                    result = cleanup.run(argv, timeout=20)
                    output = result.stdout.decode(errors='replace')
                    report['cleanup'].append({'argv': argv, 'returncode': result.returncode,
                                              'absent': cleanup_absent(argv, output), 'output': output[-2048:]})
                except BaseException as error:
                    report['cleanup'].append({'argv': argv, 'error': str(error)})
        if any(c.get('returncode') != 0 and not c.get('absent') for c in report['cleanup']):
            report['status'] = 'HOLD cleanup requires review'
        report['export_files'] = {p.name: identity(p) for p in sorted((out / 'export').glob('*')) if p.is_file()}
        (out / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(report['status'])
    return 0 if report['status'].startswith('PASS ') else 2


if __name__ == '__main__':
    raise SystemExit(main())
