#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Narrow trial adapter; existing owner keeps seed/build/retrieval/image cleanup."""
import json
import base64
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deps as d


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
        code = prior_cleanup(args, interrupted)
        path = args.root/'public/result.json'
        if path.is_file():
            result = json.loads(path.read_text())
            result.update(scope='generic ARM64 16KiB existing Rust LV2 software properties',
                          historical_host_reproduction='NOT CLAIMED', performance='NOT RUN')
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
