#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Exact historical x86_64 Python7->candidate8->Python7 private-root lane."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


old = load('completed_lifecycle_controller', HERE.parent / 'python314_candidate/run.py')
acquire = load('exact_historical_acquisition', HERE / 'acquire.py')
need, sha = old.need, old.sha
BORROWED = {'run.py': '594705bdc3c02f272cb68a98d38b46cb2a43db4cf10e5f6e5e258e49738da605',
            'actor.py': 'df43694c49ffe4b092f529142c76eb1fe1af6cfb2b4fa93358c3d08fdf92c9d1',
            'provision.sh': 'a74c136d27c416da641eec68ecbd4443fd00f257898236992a08e3ba28c531c2'}


def main():
    need(sys.flags.isolated and not sys.flags.optimize, 'run with isolated non-optimized Python')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--historical-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    acquire.verify(args.historical_dir)
    need(sha(args.candidate) == old.ARCHIVE_SHA and not args.candidate.is_symlink(), 'exact full-Tk candidate required')
    for name, digest in BORROWED.items():
        need(sha(HERE.parent / 'python314_candidate' / name) == digest, 'completed lane source changed')
    need(sha(ROOT / 'scripts/integration/repository.py') == old.REPOSITORY_SHA, 'repository helper drift')
    out = args.output.absolute()
    need(not out.exists() and not any(p.is_symlink() for p in (out, *out.parents)), 'fresh private output required')
    out.mkdir(mode=0o700)
    packet = out / 'inputs'
    packet.mkdir()
    sources = {name: HERE / name for name in ('actor.py', 'provision.sh', 'caller.c')}
    sources.update({'downgrade_actor.py': HERE.parent / 'python314_candidate/actor.py',
                    'base_provision.sh': HERE.parent / 'python314_candidate/provision.sh',
                    'runtime.py': ROOT / 'scripts/port/fdk-native-stage/runtime.py',
                    'repository.py': ROOT / 'scripts/integration/repository.py',
                    'check_runtime.py': ROOT / 'packages/port/python3148-source-candidate/check_runtime.py',
                    'full.c': ROOT / 'scripts/compat/python314-consumers/full.c',
                    args.candidate.name: args.candidate})
    sources.update({name: args.historical_dir / name for name in acquire.PINS})
    pins = {}
    for name, path in sources.items():
        shutil.copyfile(path, packet / name)
        pins[name] = sha(path)
    (packet / 'inputs.json').write_text(json.dumps(pins, sort_keys=True) + '\n')
    token = uuid.uuid4().hex[:16]
    provision, actor = 'python314-up-provision-' + token, 'python314-up-actor-' + token
    volume, image = 'python314-up-work-' + token, 'cachy-asahi-python314-up:' + token
    runtime = old.runtime()
    env = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'XDG_RUNTIME_DIR', 'DOCKER_HOST', 'DOCKER_CONTEXT')}
    runner = runtime.Runner(1800, env, out / 'logs')
    report = {'schema_version': 1, 'status': 'HOLD', 'input_sha256': pins, 'historical_official_inputs': acquire.PINS,
              'controller_sha256': sha(HERE / 'run.py'), 'borrowed_source_pins': BORROWED,
              'operations': [], 'cleanup': [], 'base': old.BASE,
              'holds': ['host analogue only; not Asahi ARM', 'all native16K/M2/source/legal/production trust/release gates unchanged']}

    def command(argv, timeout=60, check=True):
        process = runner.run(list(map(str, argv)), timeout=timeout, log=f'{len(report["operations"]):02d}.txt')
        report['operations'].append({'argv': list(map(str, argv)), 'exit': process.returncode})
        need(not check or process.returncode == 0, 'finite operation failed: ' + str(len(report['operations']) - 1))
        return process.stdout.decode(errors='replace'), process.returncode

    error = None
    stage = 'prerequisites'
    try:
        with runtime.cancellation_handlers():
            text, _ = command(['docker', 'image', 'inspect', old.BASE])
            value = json.loads(text)[0]
            need(value['Id'] == 'sha256:' + old.BASE.split('sha256:')[1] and value['Architecture'] == 'amd64', 'exact image required')
            command(['docker', 'create', '--name', provision, *old.LIMITS, '--network=host',
                     '--security-opt=no-new-privileges', '--entrypoint=/usr/bin/sleep', old.BASE, '1200'])
            command(['docker', 'start', provision])
            command(['docker', 'cp', str(packet), provision + ':/opt/python314-inputs'], 120)
            command(['docker', 'exec', provision, '/usr/bin/bash', '/opt/python314-inputs/provision.sh'], 900)
            command(['docker', 'cp', provision + ':/opt/python314-inputs/historical-gates.txt', str(out / 'historical-gates.txt')])
            need((out / 'historical-gates.txt').read_text().startswith('PASS public Arch signature'), 'public signature/closure gate absent')
            stage = 'upgrade-runtime'
            text, _ = command(['docker', 'commit', provision, image], 120)
            report['provisioned_image'] = text.strip()
            command(['docker', 'volume', 'create', volume])
            command(old.actor_options(actor, image, volume))
            text, _ = command(['docker', 'inspect', actor])
            report['actor'] = old.validate_actor(json.loads(text)[0])
            command(['docker', 'start', actor])
            _, code = command(['docker', 'exec', actor, '/usr/bin/python3', '-I', '-B',
                               '-Werror::ResourceWarning', '/opt/python314-inputs/actor.py'], 750, check=False)
            report['actor_exit'] = code
            command(['docker', 'cp', actor + ':/scratch/output', str(out / 'export')], 120)
            need(code == 0, 'upgrade actor failed; inspect bounded export/failure.json')
            result = json.loads((out / 'export/result.json').read_text())
            need(result['status'].startswith('PASS') and result['private_TEST_state_removed'], 'actor acceptance/cleanup refused')
            acquire.verify(args.historical_dir)
            need(sha(args.candidate) == old.ARCHIVE_SHA, 'original candidate changed')
            report.update(status='PASS genuine historical x86_64 Python3.14.7 -> candidate3.14.8 upgrade and rollback', result=result)
    except BaseException as exc:
        error = exc
        report.update(status='HOLD exact historical prerequsite unavailable' if stage == 'prerequisites' else 'FAIL host upgrade run',
                      failure=type(exc).__name__ + ': ' + str(exc), stage=stage)
    finally:
        cleanup = runtime.Runner(150, env, out / 'logs')
        with runtime.defer_signals():
            actions = [['docker', 'rm', '-f', name] for name in (actor, provision)]
            actions += [['docker', 'volume', 'rm', volume], ['docker', 'image', 'rm', image]]
            for argv in actions:
                try:
                    p = cleanup.run(argv, timeout=30)
                    text = p.stdout.decode(errors='replace')
                    report['cleanup'].append({'argv': argv, 'exit': p.returncode,
                                              'already_absent': old.missing(argv, text), 'output': text[-1024:]})
                except BaseException as exc:
                    report['cleanup'].append({'argv': argv, 'error': str(exc)})
        if any(c.get('exit') != 0 and not c.get('already_absent') for c in report['cleanup']):
            report['status'] = 'HOLD owned resource cleanup failed'
        report['export_sha256'] = {p.relative_to(out / 'export').as_posix(): sha(p)
                                  for p in sorted((out / 'export').rglob('*')) if p.is_file()}
        (out / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    if error:
        raise error
    print(json.dumps({'status': report['status'], 'report': str(out / 'report.json')}))
    return 0 if report['status'].startswith('PASS') else 2


if __name__ == '__main__':
    raise SystemExit(main())
