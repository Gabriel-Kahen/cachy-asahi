#!/usr/bin/env python3
"""Narrow Rust trial routing through the unchanged hash-held 574 job owner."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

spec = importlib.util.spec_from_file_location('rust_support', Path(__file__).with_name('support.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)


def bind(owner, retrieval=False):
    setup, phase, cleanup = owner.setup, owner.phase, owner.cleanup

    def rust_setup(args):
        s.need(s.HERE == args.source / 'scripts/ci/asahi-rust-lv2-offline', 'rust-source-path-differs')
        setup(args)
        (args.root / 'incoming').mkdir(mode=0o700)

    def rust_phase(args):
        if args.mode != 'trial':
            return phase(args)  # The exact old seed/build command and secret boundary.
        path = args.root / 'state.json'; state = json.loads(path.read_text())
        s.need(state['trial'] == 'NOT STARTED', 'fresh-phase-required')
        env = dict(owner.ENV, HOME=str(args.root / 'home'), TMPDIR=str(args.root))
        if retrieval:
            pins = s.inputs(); helper = args.source / 'scripts/ci/full-development-composition/retrieve_audio.py'
            token = os.environ.pop('GH_TOKEN', '')
            if (pins['retrieval_status'] != 'REVIEWED_ROOT_PIN' or s.sha(helper) != pins['retrieval_sha256'] or
                    not token or any(x in token for x in ('\r', '\n'))):
                state['retrieval'] = 'BLOCKED-ROOT-PIN-OR-TOKEN'; s.save(path, state)
                raise ValueError('reviewed-retrieval-dependency-required')
            s.need(state.get('retrieval') != 'PASS', 'fresh-retrieval-required')
            env.update(RUNNER_TEMP=str(args.root / 'incoming'), GH_TOKEN=token)
            argv = [sys.executable, '-I', '-B', helper, '--output', args.root / 'incoming/audio-archives']
            limit = 650  # Existing helper's internal total budget is600 seconds.
        else:
            s.need(state.get('retrieval') == 'PASS', 'accepted-input-retrieval-not-passed')
            argv = [sys.executable, '-I', '-B', s.HERE / 'run.py', '--product', args.product,
                    '--desktop', args.desktop, '--builder', args.root / 'base',
                    '--private', args.root / 'private', '--output', args.root / 'public']
            limit = 550  # Retrieval+trial controllers total1200 seconds.
        # Reuse the owner's trial-retirement state for either controller. An
        # interrupted retrieval is therefore preserved UNKNOWN, never deleted live.
        state['trial'] = 'STARTED'
        if retrieval: state['retrieval'] = 'STARTED'
        s.save(path, state)
        try:
            owner.command(argv, args.root / ('retrieval.log' if retrieval else 'trial.log'), env, limit)
            state['trial'] = 'NOT STARTED' if retrieval else 'PASS'
            if retrieval: state['retrieval'] = 'PASS'
        except (KeyboardInterrupt, OSError, ValueError, subprocess.SubprocessError) as error:
            state['trial'] = 'FAIL'
            if retrieval: state['retrieval'] = 'FAIL'
            state['failure'] = {'phase': 'trial', 'kind': type(error).__name__}
            if isinstance(error, owner.CommandExit): state['failure']['exit_code'] = error.code
            raise
        finally:
            env.pop('GH_TOKEN', None)
            s.save(path, state)

    def rust_cleanup(args, interrupted):
        state = json.loads((args.root / 'state.json').read_text()) if (args.root / 'state.json').is_file() else {}
        code = cleanup(args, interrupted)
        path = args.root / 'public/result.json'; result = json.loads(path.read_text())
        result.update(scope='PRIVATE-ASAHI-RUST-LV2-PROPERTIES', native_rebuilds=0,
                      package_pair_repeated=False, retrieval=state.get('retrieval', 'NOT STARTED'))
        s.need(all(p.is_file() and not p.is_symlink() and p.name in s.PUBLIC
                   for p in path.parent.iterdir()), 'rust-public-file-set-differs')
        if interrupted: result.update(status='FAIL', cancelled=True)
        s.save(path, result)
        if interrupted: result.update(status='FAIL', cancelled=True); s.save(path, result)
        return int(code != 0 or result.get('status') != 'PASS')

    owner.setup, owner.phase, owner.cleanup = rust_setup, rust_phase, rust_cleanup
    return owner


def main():
    # Literal alias only; the original owner still parses/guards all five paths,
    # pins Source/API/base, traps signals, and owns image/container cleanup.
    retrieval = len(sys.argv) > 1 and sys.argv[1] == 'retrieve'
    if retrieval: sys.argv[1] = 'trial'
    return bind(s.held('job'), retrieval).main()


if __name__ == '__main__':
    raise SystemExit(main())
