#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""One x86_64 disposable TEST-signed private-root Python package lifecycle."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = 'archlinux@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae'
ARCHIVE_SHA = '8474bf623e6efe46f02ef5dd65b7707b2f526a7a612661b33819920e451b016e'
RUNTIME_SHA = '253494be99c21c83743b384b2c06cd1627023ffaf54f0cbbd271bde80572f70a'
REPOSITORY_SHA = 'fdfd3611ca8d3fab7584594ccaf627f42a9ae31898372925af1bcae173d55cd7'
LIMITS = ['--cpus=2', '--memory=4g', '--memory-swap=4g', '--pids-limit=256']


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def runtime():
    path = ROOT / 'scripts/port/fdk-native-stage/runtime.py'
    need(sha(path) == RUNTIME_SHA, 'finite process runtime changed')
    spec = importlib.util.spec_from_file_location('finite_runtime', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def actor_options(name, image, volume):
    return ['docker', 'create', '--name', name, '--label', 'cachy-asahi.operation=python314-lifecycle',
            *LIMITS, '--read-only', '--network=none', '--cap-drop=ALL',
            '--cap-add=CHOWN', '--cap-add=SYS_CHROOT', '--security-opt=no-new-privileges',
            '--ulimit=nofile=1024:1024', '--ulimit=core=0:0',
            '--tmpfs=/tmp:rw,nosuid,nodev,size=64m', '--tmpfs=/run:rw,nosuid,nodev,size=8m',
            '--tmpfs=/test-home:rw,nosuid,nodev,noexec,size=32m,mode=700',
            '--mount', f'type=volume,src={volume},dst=/scratch',
            '--entrypoint=/usr/bin/sleep', image, '1000']


def validate_actor(value):
    host = value['HostConfig']
    need(value['Config']['User'] in ('', '0', '0:0'), 'container root only for private ALPM root')
    need(host['NanoCpus'] == 2_000_000_000 and host['Memory'] == host['MemorySwap'] == 4 * 1024**3
         and host['PidsLimit'] == 256, 'runtime resource limits differ')
    need(host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] and not host.get('Init', False)
         and not host['Privileged'] and not host['Devices'] and not host.get('Binds'), 'unsafe runtime isolation')
    need(host['CapDrop'] == ['ALL'] and {c.removeprefix('CAP_') for c in host['CapAdd']} == {'CHOWN', 'SYS_CHROOT'}
         and 'no-new-privileges' in host['SecurityOpt'], 'runtime capability contract differs')
    need([(m['Destination'], m['Type'], m['RW']) for m in value['Mounts']] == [('/scratch', 'volume', True)],
         'only an owned Docker volume may be mounted; no host bind mounts')
    return {k: host.get(k) for k in ('NanoCpus', 'Memory', 'MemorySwap', 'PidsLimit', 'NetworkMode',
                                 'ReadonlyRootfs', 'Init', 'CapDrop', 'CapAdd', 'SecurityOpt')}


def missing(argv, text):
    name = argv[-1]
    expected = {'rm': 'No such container: ' + name,
                'volume': 'get ' + name + ': no such volume', 'image': 'No such image: ' + name}
    return text.strip() == 'Error response from daemon: ' + expected.get(argv[1], '')


def main():
    need(sys.flags.isolated and not sys.flags.optimize, 'run with python3 -I without optimization')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    need(args.archive.is_file() and not args.archive.is_symlink() and sha(args.archive) == ARCHIVE_SHA,
         'exact full-Tk second-run archive required')
    need(sha(ROOT / 'scripts/integration/repository.py') == REPOSITORY_SHA, 'repository helpers changed')
    out = args.output.absolute()
    need(not out.exists() and not any(p.is_symlink() for p in (out, *out.parents)), 'fresh private output required')
    out.mkdir(mode=0o700)
    packet = out / 'inputs'
    packet.mkdir()
    sources = {'actor.py': HERE / 'actor.py', 'provision.sh': HERE / 'provision.sh',
               'runtime.py': ROOT / 'scripts/port/fdk-native-stage/runtime.py',
               'repository.py': ROOT / 'scripts/integration/repository.py',
               'check_runtime.py': ROOT / 'packages/port/python3148-source-candidate/check_runtime.py',
               'full.c': ROOT / 'scripts/compat/python314-consumers/full.c',
               args.archive.name: args.archive}
    pins = {}
    for name, path in sources.items():
        shutil.copyfile(path, packet / name)
        pins[name] = sha(path)
    (packet / 'inputs.json').write_text(json.dumps(pins, sort_keys=True) + '\n')
    token = uuid.uuid4().hex[:16]
    provision, actor = 'python314-life-provision-' + token, 'python314-life-actor-' + token
    volume, image = 'python314-life-work-' + token, 'cachy-asahi-python314-life:' + token
    mod = runtime()
    env = {k: v for k, v in os.environ.items() if k in
           ('PATH', 'HOME', 'XDG_RUNTIME_DIR', 'DOCKER_HOST', 'DOCKER_CONTEXT')}
    runner = mod.Runner(1800, env, out / 'logs')
    report = {'schema_version': 1, 'status': 'HOLD', 'base': BASE, 'input_sha256': pins,
              'operations': [], 'cleanup': [], 'holds': ['x86_64 disposable private-root evidence only',
              'native ARM/native16K/Asahi/M2 NOT RUN', 'source/legal/trust/release gates unchanged']}

    def command(argv, timeout=60, check=True):
        result = runner.run(argv, timeout=timeout, log=f'{len(report["operations"]):02d}.txt')
        report['operations'].append({'argv': argv, 'exit': result.returncode})
        need(not check or result.returncode == 0, 'operation failed: ' + str(len(report['operations']) - 1))
        return result.stdout.decode(errors='replace'), result.returncode

    error = None
    try:
        with mod.cancellation_handlers():
            text, _ = command(['docker', 'image', 'inspect', BASE])
            inspected = json.loads(text)[0]
            need(inspected['Id'] == 'sha256:' + BASE.split('sha256:')[1] and inspected['Architecture'] == 'amd64',
                 'pinned x86_64 base image required')
            command(['docker', 'create', '--name', provision, *LIMITS, '--network=host',
                     '--security-opt=no-new-privileges', '--entrypoint=/usr/bin/sleep', BASE, '1200'])
            command(['docker', 'start', provision])
            # Inputs enter the owned container through Docker copy, never host mounts.
            command(['docker', 'cp', str(packet), provision + ':/opt/python314-inputs'], timeout=120)
            command(['docker', 'exec', provision, '/usr/bin/bash', '/opt/python314-inputs/provision.sh'], timeout=900)
            command(['docker', 'cp', provision + ':/opt/python314-inputs/baseline',
                     str(out / 'retained-baseline')], timeout=120)
            retained = out / 'retained-baseline'
            expected_baseline = {
                'python-3.14.9-1-x86_64.pkg.tar.zst': 'e7b28e851f8f94bc4083774c4931741c5cf35573875e31d6ac52c2649da12c55',
                'python-3.14.9-1-x86_64.pkg.tar.zst.sig': '9261278f2a855d6ae8f7b148ef84300030a120d11ddcf66e93835f705656925d'}
            need({p.name: sha(p) for p in retained.iterdir()} == expected_baseline, 'retained baseline copy differs')
            report['retained_baseline_sha256'] = expected_baseline
            report['provisioned_image'], _ = command(['docker', 'commit', provision, image], timeout=120)
            command(['docker', 'volume', 'create', volume])
            command(actor_options(actor, image, volume))
            text, _ = command(['docker', 'inspect', actor])
            report['actor'] = validate_actor(json.loads(text)[0])
            command(['docker', 'start', actor])
            _, code = command(['docker', 'exec', actor, '/usr/bin/python3', '-I', '-B',
                               '-Werror::ResourceWarning', '/opt/python314-inputs/actor.py'], timeout=750, check=False)
            command(['docker', 'cp', actor + ':/scratch/output', str(out / 'export')], timeout=120)
            report['actor_exit'] = code
            need(code == 0, 'runtime actor failed; inspect export/failure.json and command logs')
            result = json.loads((out / 'export/result.json').read_text())
            need(result['status'].startswith('PASS'), 'lifecycle did not pass')
            report['result'] = result
            report['status'] = 'PASS TEST-signed x86_64 private-root lifecycle; not native/Asahi acceptance'
            need(sha(args.archive) == ARCHIVE_SHA, 'original archive changed')
    except BaseException as exc:
        error = exc
        report['status'] = 'FAIL disposable lifecycle run'
        report['failure'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        cleanup = mod.Runner(150, env, out / 'logs')
        with mod.defer_signals():
            actions = [['docker', 'rm', '-f', name] for name in (actor, provision)]
            actions += [['docker', 'volume', 'rm', volume], ['docker', 'image', 'rm', image]]
            for argv in actions:
                try:
                    result = cleanup.run(argv, timeout=30)
                    text = result.stdout.decode(errors='replace')
                    report['cleanup'].append({'argv': argv, 'exit': result.returncode,
                                              'already_absent': missing(argv, text), 'output': text[-1024:]})
                except BaseException as exc:
                    report['cleanup'].append({'argv': argv, 'error': str(exc)})
        if any(row.get('exit') != 0 and not row.get('already_absent') for row in report['cleanup']):
            report['status'] = 'HOLD cleanup failed'
        report['export_sha256'] = {p.relative_to(out / 'export').as_posix(): sha(p)
                                  for p in sorted((out / 'export').rglob('*')) if p.is_file()}
        (out / 'report.json').write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
    if error:
        raise error
    print(json.dumps({'status': report['status'], 'report': str(out / 'report.json')}))
    return 0 if report['status'].startswith('PASS') else 2


if __name__ == '__main__':
    raise SystemExit(main())
