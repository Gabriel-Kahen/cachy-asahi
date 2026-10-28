# SPDX-License-Identifier: MIT
"""Owned Alacritty child: real Vim edit, native C execution and Unicode clipboard."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


T = load('terminal_worker_contract', 'terminal_workflow.py')


def wait_marker(path, nonce, seconds):
    deadline = time.monotonic() + seconds
    while not path.exists():
        T.need(time.monotonic() < deadline, 'owned terminal marker deadline')
        time.sleep(.1)
    marker = json.loads(T.read(path))
    T.need(marker.get('nonce') == nonce, 'owned marker nonce differs')
    return marker


def exercise(base, workspace, stage, nonce, terminal_pid, env, pty):
    """Dependency injection permits inert controls; CLI supplies the guarded helper."""
    records, commands, transcript = [], [], []
    original_emit = base.emit
    base.emit = lambda event, **values: records.append(dict(event=event, **values))
    owner = None
    first = None

    def say(value):
        transcript.append(value)
        print(value, flush=True)

    def run(argv, name, timeout):
        commands.append(dict(name=name, argv=argv))
        return base.command(argv, env, workspace, name, timeout=timeout)

    try:
        T.need(not any((workspace / n).exists() for n in ('main.c', 'edit.vim', 'probe')), 'fresh owned workspace required')
        (workspace / 'main.c').write_bytes(T.SEED)
        before = T.read(workspace / 'main.c', 4096)
        (workspace / 'edit.vim').write_text('set nomodeline noexrc noswapfile noundofile\n'
            '%s/UNEDITED/Cachy Asahi native C/\n%s/, 0);/, 6 * 7);/\nwrite\nquit\n')
        say('CACHY ASAHI | GENERIC ARM TERMINAL WORKFLOW')
        say('Vim Ex: editing owned main.c, with user configuration disabled')
        run(['/usr/bin/vim', '-N', '-u', 'NONE', '-U', 'NONE', '-i', 'NONE', '-n', '-es',
             '--noplugin', '-S', str(workspace / 'edit.vim'), str(workspace / 'main.c')], 'vim-edit', 30)
        edited = T.read(workspace / 'main.c', 4096)
        T.need(edited == T.EDITED, 'Vim did not produce exact edited source')
        say('VIM EDIT PASS | source changed and saved')
        say(edited.decode().strip())
        run(['/usr/bin/cc', '-std=c11', '-O0', '-Wall', '-Wextra', '-Werror',
             str(workspace / 'main.c'), '-o', str(workspace / 'probe')], 'compile', 60)
        executable = T.read(workspace / 'probe', 1024**2);T.elf(executable)
        output = run([str(workspace / 'probe')], 'native-run', 10).encode()
        T.need(output == T.OUTPUT, 'native C output differs')
        say('NATIVE AARCH64 BUILD/RUN PASS')
        say(output.decode().strip())
        owner = base.Logged(['/usr/bin/wl-copy', '--foreground', '--paste-once', '--type', T.MIME],
                            'clipboard-owner', workspace, env, stdin=subprocess.PIPE)
        commands.append(dict(name='clipboard-owner', argv=['/usr/bin/wl-copy', '--foreground', '--paste-once', '--type', T.MIME]))
        owner.process.stdin.write(T.CLIPBOARD);owner.process.stdin.close()
        deadline = time.monotonic() + 30
        for attempt in range(10):
            owner.healthy();T.need(time.monotonic() < deadline, 'clipboard type readiness deadline')
            probe = base.Logged(['/usr/bin/wl-paste', '--list-types'], 'types-' + str(attempt), workspace, env)
            probe_error = None
            try:
                probe.process.wait(timeout=3)
            except BaseException as error:
                probe_error = error
            finally:
                for cleanup in (lambda: base.terminate(probe.process), probe.finish):
                    try:cleanup()
                    except BaseException as error:
                        if probe_error is None:probe_error = error
            if probe_error is not None:raise probe_error
            if probe.process.returncode == 0 and T.MIME in probe.paths[0].read_text().splitlines():
                break
            time.sleep(.1)
        else:
            raise ValueError('clipboard MIME type not offered')
        pasted = run(['/usr/bin/wl-paste', '--no-newline', '--type', T.MIME], 'paste', 10).encode()
        T.need(pasted == T.CLIPBOARD, 'cross-process Unicode clipboard differs')
        owner.process.wait(timeout=10)
        T.need(owner.process.returncode == 0, 'clipboard owner did not finish its one paste cleanly')
        say('UNICODE CLIPBOARD PASS | separate wl-copy -> wl-paste')
        say(pasted.decode().strip())
        say('Config preserved by explicit paths; no physical keyboard/hardware claim')
        say('READY FOR OWNED QMP CAPTURE')
    except BaseException as error:
        first = error
    finally:
        if owner:
            for cleanup in (lambda: base.terminate(owner.process), owner.finish):
                try:
                    cleanup()
                except BaseException as error:
                    if first is None:first = error
        base.emit = original_emit
    if first is not None:
        first.workflow_diagnostics = dict(commands=commands, processes=records,
                                          transcript='\n'.join(transcript) + '\n')
        raise first
    for data in records:
        T.need(data.get('event') == 'process_exit', 'unexpected worker event')
    result = dict(status='PASS_TERMINAL_EDITOR_NATIVE_C_CLIPBOARD', stage=stage, nonce=nonce,
        terminal_pid=terminal_pid, worker_pid=os.getpid(), architecture=platform.machine(),
        terminal_isatty=os.isatty(0) and os.isatty(1), pty=pty,
        editor_mode='Vim Ex, no user configuration', clipboard_processes='separate wl-copy/wl-paste',
        executable=dict(bytes=len(executable), sha256=T.sha(executable), header_base64=T.b64(executable[:64])),
        commands=commands, processes=records, transcript='\n'.join(transcript) + '\n',
        thunar='CORESIDENT_SEPARATE_OWNED_APP', physical_keyboard='NOT_RUN', hardware='NOT_RUN')
    for name, value in (('source_before', before), ('source_after', edited), ('native_stdout', output), ('clipboard', pasted)):
        result[name] = dict(bytes=len(value), sha256=T.sha(value), base64=T.b64(value))
    T.validate_result(result, stage, nonce, terminal_pid)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--nonce', required=True)
    parser.add_argument('--stage', choices=('minimal', 'overlay'), required=True)
    args = parser.parse_args()
    base = load('terminal_worker_base', 'base_guest.py');base.guard(False)
    T.need('cachy_asahi_terminal_workflow=1' in Path('/proc/cmdline').read_text().split(), 'terminal fixture marker required')
    T.need(re.fullmatch('[0-9a-f]{32}', args.nonce), 'invalid owned nonce')
    workspace = args.workspace
    expected = Path('/home/desktop574') / ('terminal-' + args.stage + '-' + args.nonce)
    T.need(workspace == expected and not workspace.is_symlink() and workspace.stat().st_uid == os.getuid()
           and workspace.stat().st_mode & 0o777 == 0o700 and Path.cwd() == workspace,
           'private owned terminal workspace required')
    os.umask(0o077)
    start = wait_marker(workspace / 'start.json', args.nonce, 120)
    T.need(start.get('terminal_pid') == os.getppid(), 'terminal child parent identity differs')
    T.need(os.isatty(0) and os.isatty(1), 'owned terminal PTY required')
    try:
        result = exercise(base, workspace, args.stage, args.nonce, os.getppid(), dict(os.environ), os.ttyname(1))
        T.publish(workspace / 'result.json', result)
        wait_marker(workspace / 'release.json', args.nonce, 450)
        return 0
    except BaseException as error:
        if not (workspace / 'result.json').exists():
            T.publish(workspace / 'result.json', dict(status='FAIL', stage=args.stage, nonce=args.nonce,
                      reason=str(error)[:512], error_type=type(error).__name__,
                      diagnostics=getattr(error, 'workflow_diagnostics', {})))
        print('WORKFLOW FAILED: ' + str(error)[:512], flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
