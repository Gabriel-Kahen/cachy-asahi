#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Narrow trial adapter; existing owner keeps seed/build/retrieval/image cleanup."""
import json
import base64
import os
from pathlib import Path
import sys
import re

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deps as d

PUBLIC_SEED_COMMIT = '04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd'
PUBLIC_SEED_PINS = {
    'seed.py': 'a7857658af224984065e575f6ffed8308ea85027d46eace8bda146d9033e93b3',
    'index.json': 'a388c8c8ba8e06cb92fd2be598b86e433c4e403b6e71a0f15b1eaec381bb7300',
}


def verify_public_seed(root):
    for name, pin in PUBLIC_SEED_PINS.items():
        path = root/name
        d.need(path.is_file() and not path.is_symlink() and not root.is_symlink(), 'public seed regular input required')
        with path.open('rb') as stream:
            raw = stream.read(256*1024 + 1)
        d.need(len(raw) <= 256*1024 and d.sha(raw) == pin, 'public seed identity differs: ' + name)
    return {'source_commit': PUBLIC_SEED_COMMIT, 'files': dict(PUBLIC_SEED_PINS)}


def bootstrap_diagnostics(root):
    """Only fixed owner metadata and a bounded log tail; no acquisition or cleanup."""
    result = {}
    path = root/'base/report.json'
    if path.is_file() and not path.is_symlink() and not (root/'base').is_symlink():
        try:
            with path.open('rb') as stream:
                raw = stream.read(1024**2 + 1)
            d.need(len(raw) <= 1024**2, 'bootstrap report bound')
            value = json.loads(raw)
            failures = value.get('failures', [])
            d.need(type(value) is dict and type(failures) is list and len(failures) <= 1153,
                   'bootstrap report shape')
            projected = {'bytes':len(raw), 'sha256':d.sha(raw), 'failures':[],
                         'failure_count':len(failures), 'failures_truncated':len(failures) > 32}
            for key in ('status', 'native_build', 'error_kind', 'host_arch', 'daemon_arch'):
                if key in value:
                    text = value[key]
                    d.need(type(text) is str and re.fullmatch('[A-Za-z0-9_-]{1,80}', text), 'bootstrap text field')
                    projected[key] = text
            for key in ('packages', 'acquired', 'build_returncode'):
                if key in value:
                    number = value[key]
                    d.need(type(number) is int and -255 <= number <= 1153, 'bootstrap numeric field')
                    projected[key] = number
            for row in failures[:32]:
                filename, kind, status = row['filename'], row['kind'], row['http_status']
                d.need(type(filename) is str and re.fullmatch('[A-Za-z0-9._+@:~-]{1,255}', filename) and
                       type(kind) is str and re.fullmatch('[A-Za-z0-9_]{1,80}', kind) and
                       (status is None or type(status) is int and 100 <= status <= 599), 'bootstrap failure row')
                projected['failures'].append({'filename':filename, 'kind':kind, 'http_status':status})
            result['report'] = projected
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            result['report'] = {'status':'REFUSED_BOUNDED_PROJECTION'}
    else:
        result['report'] = {'status':'ABSENT_OR_NONREGULAR'}
    for name, key in (('build.log', 'build_log'), ('public-seed.log', 'public_seed_log')):
        log = root/name
        if log.is_file() and not log.is_symlink():
            try:
                with log.open('rb') as stream:
                    size = log.stat().st_size
                    stream.seek(max(0, size-8192)); tail = stream.read(8192)
                result[key] = {'bytes':size, 'tail_bytes':len(tail), 'tail_sha256':d.sha(tail),
                               'tail_base64':base64.b64encode(tail).decode('ascii')}
            except OSError:
                result[key] = {'status':'UNAVAILABLE'}
    return result


def public_runtime(args, kernel, owner, passed):
    private_public = args.root/'audio-public'
    runtime = {'scope': 'generic ARM64 16KiB existing Rust LV2 software properties', 'status': 'FAIL'}
    for name in ('native', 'vm', 'result'):
        path = private_public/(name + '.json')
        if path.is_file():
            raw = path.read_bytes(); d.need(len(raw) <= 128*1024, 'bounded trial receipt required')
            runtime['trial' if name == 'result' else name] = json.loads(raw)
    runtime['log_tails'] = {}
    for name in ('capture.tail.txt', 'native-compile.tail.txt', 'uart.tail.txt'):
        path = private_public/name
        if path.is_file():
            raw = path.read_bytes(); d.need(len(raw) <= 8192, 'bounded log tail required')
            runtime['log_tails'][name] = {'bytes': len(raw), 'sha256': d.sha(raw),
                                        'base64': base64.b64encode(raw).decode('ascii')}
    if kernel.is_file():
        raw = kernel.read_bytes(); d.need(len(raw) <= 65536, 'bounded kernel receipt required')
        runtime['kernel'] = json.loads(raw)
        config = Path(runtime['kernel']['config']['path']).read_bytes()
        d.need(len(config) <= 65536 and d.sha(config) == runtime['kernel']['config']['sha256'], 'kernel config differs')
        runtime['kernel_config'] = config.decode('ascii')
    if passed:
        d.need(runtime.get('trial', {}).get('status') == 'PASS_GENERIC_16K_AUDIO_SOFTWARE_ONLY', 'new trial failed')
        runtime['status'] = 'PASS_GENERIC_16K_AUDIO_SOFTWARE_ONLY'
    raw = (json.dumps(runtime, sort_keys=True, indent=2) + '\n').encode()
    d.need(len(raw) <= 512*1024, 'public runtime bound')
    public = args.root/'public'; public.mkdir(mode=0o700, exist_ok=True)
    (public/'runtime.json').write_bytes(raw)
    owner.save(public/'result.json', {'status': 'PASS' if passed else 'FAIL', 'scope': runtime['scope'],
               'audio16k_status': runtime['status'], 'fresh_C_host_compilations': 1 if 'native' in runtime else 'NOT OBSERVED',
               'Rust_package_rebuilds': 0, 'cases': 60 if passed else 'NOT ACCEPTED',
               'instances': 120 if passed else 'NOT ACCEPTED',
               'hardware': 'NOT RUN', 'audio_devices': 'NOT USED', 'performance': 'NOT RUN'})


def bind(owner, root):
    prior_phase = owner.phase
    prior_cleanup = owner.cleanup
    def phase(args):
        if args.mode != 'trial':
            return prior_phase(args)
        state_path = args.root/'state.json'
        state = json.loads(state_path.read_text())
        d.need(state['trial'] == 'NOT STARTED' and state.get('retrieval') == 'PASS', 'fresh retrieved trial required')
        kernel = Path(os.environ.get('AUDIO16K_KERNEL_RECEIPT', ''))
        d.need(kernel.is_absolute() and kernel.is_file(), 'same-job diagnostic kernel receipt required')
        state['trial'] = 'STARTED'; owner.save(state_path, state)
        argv = [sys.executable, '-B', d.HERE/'run.py', '--source-root', args.source,
                '--product', args.product, '--desktop', args.desktop, '--builder', args.root/'base',
                '--private', args.root/'private', '--output', args.root/'audio-public',
                '--archives', args.root/'incoming/audio-archives', '--kernel-receipt', kernel, '--execute']
        env = dict(owner.ENV, HOME=str(args.root/'home'), TMPDIR=str(args.root))
        try:
            owner.command(argv, args.root/'trial.log', env, 1300)
            public_runtime(args, kernel, owner, True)
            state['trial'] = 'PASS'
        except BaseException as error:
            state.update(trial='FAIL', failure={'phase':'trial', 'kind':type(error).__name__})
            if isinstance(error, owner.CommandExit):
                state['failure']['exit_code'] = error.code
            raise
        finally:
            if state['trial'] != 'PASS':
                try:
                    public_runtime(args, kernel, owner, False)
                except Exception:
                    state['public_failure'] = 'bounded failure receipt unavailable'
            owner.save(state_path, state)
    owner.phase = phase
    def cleanup(args, interrupted):
        diagnostic = bootstrap_diagnostics(args.root)  # Snapshot before the unchanged owner may remove its work.
        code = prior_cleanup(args, interrupted)
        path = args.root/'public/result.json'
        if path.is_file():
            result = json.loads(path.read_text())
            result.update(scope='generic ARM64 16KiB existing Rust LV2 software properties',
                          historical_host_reproduction='NOT CLAIMED', performance='NOT RUN',
                          bootstrap_diagnostics=diagnostic)
            owner.save(path, result)
        return code
    owner.cleanup = cleanup
    return owner


def main():
    root = Path(__file__).resolve().parents[3]
    for name in d.POLICY['dependencies']:
        d.source(root, name)
    rust_job = d.load(root, 'scripts/ci/asahi-rust-lv2-offline/job.py')
    retrieval = len(sys.argv) > 1 and sys.argv[1] == 'retrieve'
    if retrieval:
        sys.argv[1] = 'trial'
    owner = rust_job.bind(rust_job.s.held('job'), retrieval)
    if not retrieval:
        owner = bind(owner, root)
    return owner.main()


if __name__ == '__main__':
    raise SystemExit(main())
