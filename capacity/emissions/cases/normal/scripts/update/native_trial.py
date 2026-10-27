#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bootstrap the signed native ARM base and run one isolated tiny updater suite."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
SELECTED = ('scripts/update', 'scripts/client', 'scripts/release', 'scripts/install',
            'packages/tools/cachy-asahi-update/asahi-policy.py',
            'packages/tools/cachy-asahi-update/test-asahi-policy.py',
            'packages/tools/cachy-asahi-update/test-upstream.py')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


sys.path.insert(0, str(ROOT / 'scripts/experiments'))
bootstrap = module('updater_existing_bootstrap', ROOT / 'scripts/experiments/native_trial.py')
native = bootstrap.native


def command(argv, *, timeout=30):
    row = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    need(row.returncode == 0 and len(row.stdout) + len(row.stderr) <= 1024**2, 'bounded command failed')
    return row.stdout.decode().strip()


def preflight(args):
    need(platform.system() == 'Linux' and platform.machine() == 'aarch64'
         and os.getuid() == os.geteuid() > 0, 'ordinary native ARM coordinator required')
    need(not any(key.startswith('DOCKER_') for key in os.environ), 'Docker overrides refused')
    need(re.fullmatch('[0-9a-f]{40}', args.source_commit), 'exact product commit required')
    need(command(['git', '-C', str(ROOT), 'rev-parse', 'HEAD']) == args.source_commit, 'checkout differs from product')
    command(['git', '-C', str(ROOT), 'diff', '--exit-code', 'HEAD', '--', *SELECTED,
             'scripts/ci', 'scripts/experiments'])
    for path in (args.output, args.cache):
        need(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents))
             and not any(c in str(path) for c in ',\n\r'), 'canonical owned paths required')
    need(args.cache.is_dir() and args.cache.stat().st_uid == os.getuid(), 'owned seeded cache required')
    need(not args.output.exists() if not args.cleanup_only else args.output.is_dir(), 'fresh output required')
    paths = (ROOT, args.output, args.cache)
    need(all(not a.is_relative_to(b) and not b.is_relative_to(a)
             for i, a in enumerate(paths) for b in paths[i + 1:]), 'source/output/cache must be separate')
    if args.cleanup_only:
        need(args.output.stat().st_uid == os.getuid() and args.output.stat().st_mode & 0o777 == 0o700, 'owned cleanup output required')
    return native.load_pinned(ROOT / 'scripts/ci/inputs.lock.json', bootstrap.INPUTS_SHA)


def container_command(docker, image, name, nonce, source, workspace, *, scale_fixtures=False):
    return docker + ['run', '--init', '--name', name, '--pull=never', '--platform=linux/arm64', '--user=0:0',
        '--network=none', '--ipc=private', '--cap-drop=ALL', '--cap-add=CHOWN', '--cap-add=DAC_OVERRIDE',
        '--cap-add=FOWNER', '--security-opt=no-new-privileges', '--read-only', '--pids-limit=128', '--memory=1g', '--cpus=2',
        '--tmpfs=/tmp:rw,nosuid,nodev,exec,size=256m,mode=1777',
        '--mount', f'type=bind,src={source},dst=/source,readonly',
        '--mount', f'type=bind,src={workspace},dst=/workspace', '--entrypoint=/usr/bin/env', image,
        '-i', 'PATH=/usr/bin:/bin', 'HOME=/tmp/home', 'TMPDIR=/tmp', 'LC_ALL=C',
        'CACHY_ASAHI_BOUND_UPDATE=' + nonce, '/usr/bin/python3', '-B', '/source/scripts/update/native_container.py',
        *(['--scale-fixtures'] if scale_fixtures else [])]


def cleanup(output, docker, state):
    result = {'status': 'PASS', 'container': 'NOT CREATED', 'image': 'NOT CREATED'}
    try:
        if state.get('container'):
            name = state['container']
            need(re.fullmatch('cachy-asahi-bound-[0-9a-f]{32}', name), 'owned container name required')
            query = docker + ['container', 'ls', '-a', '--filter', 'name=^/' + name + '$', '--format', '{{.Names}}']
            before = command(query)
            need(before in ('', name), 'unexpected owned container query')
            if before:
                command(docker + ['rm', '-f', name])
            need(command(query) == '', 'owned container remains')
            result['container'] = {'absence_verified': True, 'name': name}
    except Exception:
        result.update(status='FAIL', container={'absence_verified': False, 'status': 'UNKNOWN'})
    try:
        imagefile = output / 'private/bootstrap/image-id'
        image = imagefile.read_text().strip() if imagefile.exists() else state.get('image')
        if image:
            state['image'] = image
            need(re.fullmatch('sha256:[0-9a-f]{64}', image), 'owned immutable image ID required')
            query = docker + ['image', 'ls', '-a', '--no-trunc', '-q']
            if image in command(query).splitlines():
                command(docker + ['image', 'rm', '--no-prune', image])
            need(image not in command(query).splitlines(), 'owned image remains')
            result['image'] = {'absence_verified': True, 'id': image}
            native.save(output / 'owned.json', state)
        elif state.get('bootstrap_started'):
            raise ValueError('bootstrap started without immutable image ID')
    except Exception:
        result.update(status='FAIL', image={'absence_verified': False, 'status': 'UNKNOWN'})
    home = output / 'private/bootstrap/gpg'
    try:
        if home.is_dir():
            command(['gpgconf', '--homedir', str(home), '--kill', 'all'])
        if result['status'] == 'PASS' and (output / 'private').exists():
            shutil.rmtree(output / 'private')
    except Exception:
        result.update(status='FAIL', private_cleanup='FAIL')
    result['private_data_removed'] = not (output / 'private').exists()
    return result


def snapshot(commit, target):
    archive = subprocess.run(['git', '-C', str(ROOT), 'archive', commit, *SELECTED], capture_output=True, timeout=30)
    need(archive.returncode == 0 and len(archive.stdout) <= 16 * 1024**2, 'bounded tracked source archive required')
    target.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as stream:
        for member in stream:
            need(not member.name.startswith('/') and '..' not in Path(member.name).parts
                 and (member.isdir() or member.isfile()), 'ordinary tracked source required')
            path = target / member.name
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(stream.extractfile(member).read())
                path.chmod(0o444)


def run(args):
    inputs = preflight(args)
    output = args.output
    if not args.cleanup_only:
        output.mkdir(mode=0o700)
    result_path, state_path = output / 'result.json', output / 'owned.json'
    result = json.loads(result_path.read_text()) if args.cleanup_only and result_path.exists() else dict(
        status='FAIL', source_commit=args.source_commit, workflow_sha=os.environ.get('WORKFLOW_SHA'),
        native_tests='NOT RUN', full587='NOT RUN', production='NOT ESTABLISHED', hardware='NOT RUN')
    state = json.loads(state_path.read_text()) if args.cleanup_only else {'bootstrap_started': False}
    docker = ['docker', '--host=unix:///var/run/docker.sock']
    previous = {sig: signal.signal(sig, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
                for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        if not args.cleanup_only:
            private = output / 'private'; private.mkdir(mode=0o700)
            base = private / 'bootstrap'; base.mkdir()
            native.save(base / 'inputs.lock.json', inputs)
            probe = native.probe(base)
            docker = ['docker', '--host=' + probe['docker_endpoint']]
            result['docker_endpoint'] = probe['docker_endpoint']
            native.audit(inputs, args.cache, base)
            state['bootstrap_started'] = True; native.save(state_path, state)
            image = native.build(inputs, args.cache, base, {})
            need(native.sha(base / 'packages.lock') == bootstrap.PACKAGES_SHA, '341-package inventory differs')
            source, workspace = private / 'source', private / 'workspace'
            snapshot(args.source_commit, source); workspace.mkdir(mode=0o700)
            nonce = os.urandom(16).hex(); name = 'cachy-asahi-bound-' + nonce
            state['container'] = name; native.save(state_path, state)
            argv = container_command(docker, image, name, nonce, source, workspace, scale_fixtures=getattr(args, 'scale_fixtures', False))
            with (private / 'container.log').open('wb') as log:
                row = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=240)
            raw = (workspace / 'result.json').read_bytes()
            need(len(raw) <= 32768, 'public result bound')
            record = json.loads(raw)
            result['native_tests'] = record
            log = (workspace / 'tests.log').read_bytes(); need(len(log) <= 32768, 'public log bound')
            (output / 'tests.log').write_bytes(log)
            expected = 106 if getattr(args, 'scale_fixtures', False) else 39
            need(record.get('status') == 'PASS' and record.get('tests') == expected and record.get('architecture') == 'aarch64'
                 and not any(record.get(key) for key in ('failures', 'errors', 'skips')) and row.returncode == 0,
                 'native tiny checks failed')
            result.update(status='PASS', native_tests=record, image=image, packages_sha256=bootstrap.PACKAGES_SHA)
    except BaseException as error:
        result.update(status='FAIL', error_type=type(error).__name__)
    finally:
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
        try:
            result['cleanup'] = cleanup(output, docker, state)
            if signal.sigpending() & {signal.SIGTERM, signal.SIGINT}:
                result.update(status='FAIL', cancelled=True)
            if result['cleanup']['status'] != 'PASS':
                result['status'] = 'FAIL'
            native.save(result_path, result)
        finally:
            for sig, handler in previous.items():
                signal.signal(sig, handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
    return int(result['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cleanup-only', action='store_true')
    parser.add_argument('--scale-fixtures', action='store_true', help='Also run the synthetic scale backend cases')
    return run(parser.parse_args())


if __name__ == '__main__':
    raise SystemExit(main())
