#!/usr/bin/env python3
"""Own only this LSP job's 574 preparation, private scratch and image."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys

HERE = Path(__file__).resolve().parent
SECRET_NAMES = (
    'CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_01', 'CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_02',
    'CACHY_RETAINED_BUBBLEWRAP_V1_SIGNATURE_01', 'CACHY_OLD_FOUR_JBIGKIT_01',
    'CACHY_OLD_FOUR_JBIGKIT_02', 'CACHY_OLD_FOUR_JBIGKIT_SIG_01',
    *('CACHY_OLD_FOUR_LIBTIFF_' + f'{i:02d}' for i in range(1, 16)),
    'CACHY_OLD_FOUR_LIBTIFF_SIG_01',
)
ENV = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'LANG': 'C.UTF-8',
       'LC_ALL': 'C.UTF-8', 'TZ': 'UTC', 'PYTHONDONTWRITEBYTECODE': '1'}


class CommandExit(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__('phase-command-failed')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def save(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def capture(argv):
    return subprocess.check_output(argv, text=True, stderr=subprocess.DEVNULL, timeout=20).strip()


def caller():
    spec = importlib.util.spec_from_file_location('lsp_reviewed_caller', HERE / 'run.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def command(argv, log, env, limit):
    with log.open('wb') as stream:
        proc = subprocess.Popen(list(map(str, argv)), env=env, stdin=subprocess.DEVNULL,
                                stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = proc.wait(timeout=limit)
            if code:
                raise CommandExit(code)
        finally:
            if proc.poll() is None:
                for sig, seconds in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
                    try:
                        os.killpg(proc.pid, sig)
                    except ProcessLookupError:
                        pass
                    try:
                        proc.wait(timeout=seconds)
                        break
                    except subprocess.TimeoutExpired:
                        continue


def setup(args):
    api = caller()
    need(platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64') and
         os.getuid() == os.geteuid() > 0, 'native-ordinary-user-required')
    for path in (args.root, args.source, args.product, args.desktop):
        api.ordinary(path)
    need(all(not args.root.is_relative_to(path) and not path.is_relative_to(args.root)
             for path in (args.source, args.product, args.desktop)), 'job-root-must-be-separate')
    need(re.fullmatch(r'[0-9a-f]{40}', args.source_commit), 'exact-source-required')
    for path, pin in ((args.source, args.source_commit), (args.product, api.PRODUCT), (args.desktop, api.DESKTOP)):
        need(capture(['git', '-C', str(path), 'rev-parse', 'HEAD']) == pin, 'checkout-pin-differs')
    need(HERE == args.source / 'scripts/ci/asahi-lsp-build', 'source-path-differs')
    for name, pin in api.API.items():
        need(sha(args.product / name) == pin, 'product-api-differs')
    need(sha(args.product / 'scripts/ci/log_evidence.py') ==
         'a25f0089759c12afae3eea23bab8b22fa05cf5bbaa9eddc1611ce78b0405f8f5', 'transport-differs')
    for name, pin in {
        'maintained_desktop574.py': api.HELPER,
        'maintained-desktop574-inputs.json': api.INPUTS,
        'old_four_seed.py': 'a14e0318549d24a9bc91ceeb03ec2c1fa2d12f2b3a4f9b0a4cccfb64be34b2b7',
    }.items():
        need(sha(args.desktop / 'scripts/ci' / name) == pin, 'desktop-code-differs')
    need(not args.root.exists() and not any(k.startswith('DOCKER_') for k in os.environ), 'fresh-local-job-required')
    need(capture(['docker', 'context', 'show']) == 'default', 'local-default-daemon-required')
    info = json.loads(capture(['docker', 'context', 'inspect', 'default']))[0]
    need(info['Endpoints']['docker']['Host'] == 'unix:///var/run/docker.sock', 'local-daemon-required')
    need(capture(['docker', 'info', '--format', '{{.Architecture}}']) in ('aarch64', 'arm64'), 'native-daemon-required')
    need(shutil.which('zstd') is not None, 'host-zstd-required')
    args.root.mkdir(mode=0o700)
    (args.root / 'home').mkdir(mode=0o700)
    before = capture(['docker', 'image', 'ls', '-a', '--no-trunc', '-q']).splitlines()
    save(args.root / 'state.json', {'source_commit': args.source_commit, 'before_images': sorted(set(before)),
         'seed': 'NOT STARTED', 'build': 'NOT STARTED', 'trial': 'NOT STARTED'})


def phase(args):
    path = args.root / 'state.json'
    state = json.loads(path.read_text())
    need(state[args.mode] == 'NOT STARTED', 'fresh-phase-required')
    state[args.mode] = 'STARTED'
    save(path, state)
    env = dict(ENV, HOME=str(args.root / 'home'), TMPDIR=str(args.root))
    if args.mode == 'seed':
        need(len(SECRET_NAMES) == 22 and all(os.environ.get(name) for name in SECRET_NAMES), 'seed-secrets-missing')
        env.update({name: os.environ[name] for name in SECRET_NAMES})
        env.update(CACHY_OLD_FOUR_SCHEMA='1', CACHY_OLD_FOUR_SOURCE_EPOCH='1791748800')
    if args.mode in ('seed', 'build'):
        argv = [sys.executable, '-I', '-B', args.desktop / 'scripts/ci/maintained_desktop574.py', args.mode,
                '--inputs', args.desktop / 'scripts/ci/maintained-desktop574-inputs.json',
                '--output', args.root / 'base']
        limit = 100 if args.mode == 'seed' else 2300
    else:
        argv = [sys.executable, '-I', '-B', HERE / 'run.py', '--product', args.product,
                '--desktop', args.desktop, '--builder', args.root / 'base',
                '--private', args.root / 'private', '--output', args.root / 'public']
        limit = 5700
    try:
        command(argv, args.root / (args.mode + '.log'), env, limit)
        state[args.mode] = 'PASS'
    except (KeyboardInterrupt, OSError, ValueError, subprocess.SubprocessError) as error:
        state[args.mode] = 'FAIL'
        state['failure'] = {'phase': args.mode, 'kind': type(error).__name__}
        if isinstance(error, CommandExit):
            state['failure']['exit_code'] = error.code
        raise
    finally:
        save(path, state)


def cleanup(args, interrupted):
    api = caller()
    public = args.root / 'public'
    public.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = public / 'result.json'
    result = json.loads(path.read_text()) if path.is_file() else {'status': 'FAIL', 'scope': 'PRIVATE-BUILD-ONLY',
        'native_build': 'NOT COMPLETED', 'audio': 'NOT RUN', 'hardware': 'NOT RUN', 'selected_for_release': False}
    state_path = args.root / 'state.json'
    state = json.loads(state_path.read_text()) if state_path.is_file() else {}
    report = {'status': 'PASS', 'phases': {key: state.get(key, 'UNKNOWN') for key in ('seed', 'build', 'trial')},
              'image': 'NOT CREATED', 'bootstrap_retirement': 'NOT STARTED', 'private_removed': False}
    if not state:
        report.update(status='FAIL', bootstrap_retirement='UNKNOWN')
    if 'failure' in state:
        report['failure'] = state['failure']
    private = args.root / 'private'
    failure = state.get('failure', {})
    uncertain_trial = state.get('trial') == 'STARTED' or (failure.get('phase') == 'trial' and
        (failure.get('kind') != 'CommandExit' or failure.get('exit_code', -1) < 0))
    if uncertain_trial:
        report.update(status='FAIL', trial_controller_retirement='UNKNOWN')
    elif private.exists():
        report['trial_cleanup'] = api.cleanup(private, [private / 'build-1', private / 'build-2'])
        if report['trial_cleanup']['status'] != 'PASS':
            report['status'] = 'FAIL'
    base = args.root / 'base'
    iid = base / 'image-id'
    if state.get('build') in ('STARTED', 'FAIL'):
        # The unchanged helper has no daemon-side build/probe ownership handles.
        report.update(status='FAIL', bootstrap_retirement='UNKNOWN')
    elif state.get('build') == 'PASS':
        try:
            image = iid.read_text().strip()
            need(re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'owned-image-id-required')
            base_report = json.loads((base / 'report.json').read_text())
            need(base_report['status'] == 'PASS_NATIVE_OFFLINE_574_TRANSACTION' and
                 base_report['image'] == image and base_report['native_build'] == 'PASS' and
                 base_report['build_returncode'] == 0 and not base_report['failures'] and
                 base_report['acquired'] == 1153 and sha(base / 'installed-packages.lock') == api.LOCK,
                 'base-proof-differs')
            report['base'] = {'report_sha256': sha(base / 'report.json'), 'input_sha256': api.INPUTS,
                'helper_sha256': api.HELPER, 'installed_lock_sha256': api.LOCK,
                'authenticated_input_objects': 1153, 'package_count': 574,
                'signature_policy': 'unchanged-required-pinned-keyring-offline-transaction',
                'native_build': base_report['native_build'], 'status': base_report['status']}
            need(report['status'] == 'PASS', 'trial-retirement-uncertain')
            need(image not in state['before_images'], 'preexisting-image-preserved')
            need(capture(['docker', 'container', 'ls', '-a', '--filter', 'ancestor=' + image,
                          '--format', '{{.Names}}']) == '', 'image-still-referenced')
            subprocess.run(['docker', 'image', 'rm', '--no-prune', image], check=True,
                           capture_output=True, timeout=30)
            need(image not in capture(['docker', 'image', 'ls', '-a', '--no-trunc', '-q']).splitlines(),
                 'owned-image-remains')
            report.update(image={'id': image, 'absence_verified': True}, bootstrap_retirement='PASS-normal-completion')
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
            report.update(status='FAIL', image='PRESERVED-OR-UNKNOWN', image_error_kind=type(error).__name__)
    if report['status'] == 'PASS':
        # Only this fresh job root is mutable; keep the public four-file directory.
        for child in args.root.iterdir():
            if child == public:
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        report['private_removed'] = set(args.root.iterdir()) == {public}
    if report['status'] != 'PASS' or not report['private_removed'] or state.get('trial') != 'PASS':
        result['status'] = 'FAIL'
    result['owner_cleanup'] = report
    result['source_commit'] = state.get('source_commit')
    if interrupted:
        result.update(status='FAIL', cancelled=True)
    save(path, result)
    if interrupted:
        result.update(status='FAIL', cancelled=True)
        save(path, result)
    allowed = {'result.json', 'build-1.json', 'build-2.json', 'comparison.json'}
    need(all(p.is_file() and not p.is_symlink() and p.name in allowed for p in public.iterdir()), 'public-file-set-differs')
    need(sum(p.stat().st_size for p in public.iterdir()) <= 16 * 1024 * 1024, 'public-output-oversized')
    return int(result['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('init', 'seed', 'build', 'trial', 'cleanup'))
    for name in ('root', 'source', 'product', 'desktop'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    args = parser.parse_args()
    os.umask(0o077)
    interrupted = []
    def cancel(*_):
        raise KeyboardInterrupt()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, (lambda signum, _: interrupted.append(signum)) if args.mode == 'cleanup' else cancel)
    try:
        if args.mode == 'init':
            setup(args)
        elif args.mode == 'cleanup':
            return cleanup(args, interrupted)
        else:
            phase(args)
        return 0
    except (KeyboardInterrupt, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        if args.mode == 'cleanup':
            public = args.root / 'public'
            public.mkdir(parents=True, exist_ok=True, mode=0o700)
            save(public / 'result.json', {'status': 'FAIL', 'scope': 'PRIVATE-BUILD-ONLY',
                'owner_cleanup': {'status': 'FAIL', 'error_kind': type(error).__name__, 'private_removed': False},
                'audio': 'NOT RUN', 'hardware': 'NOT RUN', 'selected_for_release': False})
        # Raw diagnostics stay in private files; no error body/source excerpt.
        print(json.dumps({'phase': args.mode, 'status': 'FAIL', 'kind': type(error).__name__}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
