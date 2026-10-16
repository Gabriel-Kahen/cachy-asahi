#!/usr/bin/env python3
"""Finite opt-in Zsh/PTY fixtures; never use the caller's HOME or install files."""
# SPDX-License-Identifier: MIT
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import pty
import resource
import select
import shutil
import signal
import stat
import subprocess
import termios
import time


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pinned(path, expected):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 131072:
        raise ValueError('bounded regular selected source required')
    if path != path.resolve() or digest(path) != expected:
        raise ValueError('selected source pin/path mismatch')


def quoted(path):
    return "'" + str(path).replace("'", "'\\''") + "'"


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**2, 1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def environment(home):
    return dict(PATH='/usr/bin:/bin', HOME=str(home), ZDOTDIR=str(home),
                TERM='xterm', LANG='C', LC_ALL='C')


class Terminal:
    def __init__(self, zsh, home):
        self.master, slave = pty.openpty()
        self.output = bytearray()
        self.closed = False
        def start():
            limits(); os.setsid(); fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        self.command = [zsh, '-f', '-i']
        try:
            self.process = subprocess.Popen(self.command, stdin=slave, stdout=slave,
                stderr=slave, env=environment(home), cwd=home, preexec_fn=start)
        except BaseException:
            os.close(self.master); raise
        finally:
            os.close(slave)

    def send(self, data):
        if len(data) > 4096:
            raise ValueError('fixture input bound')
        if os.write(self.master, data) != len(data):
            raise ValueError('short fixture input')

    def wait(self, predicate):
        deadline = time.monotonic() + 5
        while not predicate():
            if time.monotonic() >= deadline:
                raise ValueError('fixture wait deadline')
            if select.select([self.master], [], [], .05)[0]:
                try: data = os.read(self.master, 4096)
                except OSError: data = b''
                self.output.extend(data)
                if len(self.output) > 65536:
                    raise ValueError('terminal output bound')
                if not data and not predicate():
                    raise ValueError('fixture terminal closed')

    def drain(self):
        deadline = time.monotonic() + 5
        while select.select([self.master], [], [], .1)[0]:
            if time.monotonic() >= deadline:
                raise ValueError('fixture terminal settling deadline')
            data = os.read(self.master, 4096)
            if not data:
                raise ValueError('fixture terminal closed')
            self.output.extend(data)
            if len(self.output) > 65536:
                raise ValueError('terminal output bound')

    def close(self):
        if self.closed:
            return
        try:
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGTERM)
                try: self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL); self.process.wait(timeout=1)
        finally:
            os.close(self.master); self.closed = True


def fixture(root, name):
    home = root / name; home.mkdir(mode=0o700)
    for startup in ('.zshenv', '.zshrc'):
        (home / startup).write_text('print -r -- unexpected > "$HOME/startup-read"\n')
    history = home / 'history'; history.write_text('print -r -- fixture-suggestion\n'); history.chmod(0o600)
    return home, (history.read_bytes(), history.stat().st_mode)


def unchanged(home, before):
    history = home / 'history'
    assert (history.read_bytes(), history.stat().st_mode) == before, 'fixture history changed'
    assert not (home / 'startup-read').exists(), 'disabled startup file was read'


def noninteractive(zsh, wrapper, root):
    home, before = fixture(root, 'noninteractive')
    script = '''typeset -g ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE=fg=2
HISTFILE=$HOME/history; SAVEHIST=0
fixture_user_function() { :; }
source WRAPPER; source WRAPPER
(( ! ${+functions[_zsh_autosuggest_start]} )) || exit 11
[[ $ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE == fg=2 && $HISTFILE == $HOME/history ]] || exit 12
(( ${+functions[fixture_user_function]} && SAVEHIST == 0 )) || exit 13
'''.replace('WRAPPER', quoted(wrapper))
    command = [zsh, '-f', '-c', script]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env=environment(home), cwd=home, preexec_fn=limits, timeout=5)
    assert len(result.stdout) <= 65536 and result.returncode == 0, 'noninteractive guard failed'
    unchanged(home, before)
    (home / 'stdout.log').write_bytes(result.stdout)
    return dict(command=command, returncode=result.returncode, output_bytes=len(result.stdout))


def interactive(zsh, wrapper, root, *, preloaded=False, interrupted=False):
    name = 'preloaded' if preloaded else 'interrupt' if interrupted else 'editing'
    home, before = fixture(root, name)
    setup = '''PROMPT='CAA> '; RPROMPT=''; HISTFILE=$HOME/history; SAVEHIST=0; HISTSIZE=20
typeset -g ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE=fg=2
typeset -ga ZSH_AUTOSUGGEST_STRATEGY=(history)
unset ZSH_AUTOSUGGEST_USE_ASYNC
bindkey -e
typeset -gi fixture_hits=0 fixture_seq=0
fixture_user_widget() { (( fixture_hits += 1 )); BUFFER=user-widget-preserved; CURSOR=$#BUFFER; }
zle -N fixture-user-widget fixture_user_widget
bindkey '^X^U' fixture-user-widget
typeset -g fixture_binding=$(bindkey '^X^U')
PRELOADED
source WRAPPER; source WRAPPER
unset ZSH_AUTOSUGGEST_USE_ASYNC
[[ $ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE == fg=2 && $(bindkey '^X^U') == $fixture_binding ]] || exit 21
POSTLOAD
fixture_snapshot() {
 (( fixture_seq += 1 ))
 print -rn -- "$BUFFER"$'\\0'"$POSTDISPLAY"$'\\0'"$CURSOR"$'\\0'"$fixture_hits" > "$HOME/snapshot-$fixture_seq"
}
zle -N fixture-snapshot fixture_snapshot
ZSH_AUTOSUGGEST_IGNORE_WIDGETS+=(fixture-snapshot)
bindkey '^X^D' fixture-snapshot
fc -R "$HOME/history"
print -r -- ready > "$HOME/ready"
'''.replace('WRAPPER', quoted(wrapper))
    setup = setup.replace('PRELOADED', '_zsh_autosuggest_start() { :; }' if preloaded else '')
    setup = setup.replace('POSTLOAD',
        '(( ! ${+functions[_zsh_autosuggest_fetch]} )) || exit 22' if preloaded else
        '(( ${+functions[_zsh_autosuggest_fetch]} )) || exit 23')
    path = home / 'setup.zsh'; path.write_text(setup)
    terminal = Terminal(zsh, home)
    actions = []
    try:
        terminal.send(('source ' + quoted(path) + '\n').encode())
        terminal.wait(lambda: (home / 'ready').exists() and b'CAA> ' in terminal.output)
        def snapshot(number, data):
            terminal.send(data); terminal.drain(); terminal.send(b'\x18\x04')
            target = home / f'snapshot-{number}'
            terminal.wait(target.exists)
            raw = target.read_bytes(); assert len(raw) <= 4096
            values = raw.decode().split('\0'); assert len(values) == 4
            actions.append(dict(input_hex=data.hex(), snapshot=values))
            return values
        if preloaded:
            values = snapshot(1, b'\x18\x15')
            assert values[0] == 'user-widget-preserved' and values[3] == '1'
        elif interrupted:
            values = snapshot(1, b'print -r -- fix')
            assert values[:2] == ['print -r -- fix', 'ture-suggestion']
            os.killpg(terminal.process.pid, signal.SIGINT)
            terminal.drain(); terminal.send(b'\x15')
            values = snapshot(2, b'\x18\x15')
            assert values[0] == 'user-widget-preserved' and values[3] == '1'
            actions.append(dict(signal='SIGINT', result='same private shell/widget remains usable'))
        else:
            values = snapshot(1, b'print -r -- fix')
            assert values[:2] == ['print -r -- fix', 'ture-suggestion'], 'real suggestion missing'
            values = snapshot(2, b'\x1b[C')
            assert values[:2] == ['print -r -- fixture-suggestion', ''], 'ZLE acceptance failed'
            values = snapshot(3, b'\x7f')
            assert values[0] == 'print -r -- fixture-suggestio', 'real editing failed'
            values = snapshot(4, b'\x18\x15')
            assert values[0] == 'user-widget-preserved' and values[3] == '1', 'user widget lost'
        terminal.send(b'\x15exit 0\n'); terminal.process.wait(timeout=5)
        assert terminal.process.returncode == 0, 'fixture shell failed'
        unchanged(home, before)
        return dict(command=terminal.command, setup_sha256=digest(path), actions=actions,
                    returncode=terminal.process.returncode, output_bytes=len(terminal.output))
    finally:
        terminal.close(); (home / 'terminal.log').write_bytes(terminal.output)
        assert terminal.closed and terminal.process.poll() is not None, 'fixture cleanup failed'


def removal_guard(zsh, root):
    home, before = fixture(root, 'removal')
    missing = home / 'removed-package' / 'opt-in.zsh'
    user_line = home / 'user-opt-in.zsh'
    user_line.write_text('[[ -r ' + quoted(missing) + ' ]] && source ' + quoted(missing) + '\n')
    user_line.chmod(0o600)
    saved = (user_line.read_bytes(), user_line.stat().st_mode)
    script = 'source ' + quoted(user_line) + '''
typeset -g guarded_status=$?
(( guarded_status == 1 && ! ${+functions[_zsh_autosuggest_start]} )) || exit 11
'''
    command = [zsh, '-f', '-c', script]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env=environment(home), cwd=home, preexec_fn=limits, timeout=5)
    assert result.returncode == 0 and result.stdout == b'', 'absent package source guard failed'
    assert (user_line.read_bytes(), user_line.stat().st_mode) == saved, 'user source line changed'
    unchanged(home, before)
    return dict(command=command, returncode=result.returncode, absent_source_guard_status=1,
                user_line_sha256=digest(user_line), package_removal='SIMULATED absent owned path')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wrapper', type=Path, required=True)
    parser.add_argument('--wrapper-sha256', required=True)
    parser.add_argument('--module-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    wrapper = args.wrapper.absolute(); module = wrapper.parent / 'zsh-autosuggestions.zsh'
    pinned(wrapper, args.wrapper_sha256); pinned(module, args.module_sha256)
    zsh = shutil.which('zsh', path='/usr/bin:/bin')
    if zsh is None:
        raise ValueError('installed Zsh unavailable; installation is not permitted')
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = dict(status='FAIL', architecture=platform.machine(), zsh_path=zsh,
        zsh_sha256=digest(Path(zsh).resolve()), wrapper_sha256=digest(wrapper), module_sha256=digest(module),
        bounds=dict(case_seconds=5, cpu_seconds=10, address_space_bytes=256*1024**2,
                    terminal_output_bytes=65536, input_bytes=4096),
        environment_keys=sorted(environment(args.output)), tests=[], native_arm='NOT RUN',
        target_installation='NOT RUN', page16k='NOT RUN', m2_hardware='NOT RUN')
    version_command = [zsh, '--version']
    version = subprocess.run(version_command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, env=environment(args.output), timeout=5)
    if len(version.stdout) > 4096 or version.returncode != 0:
        raise ValueError('bounded Zsh identity probe failed')
    report.update(version_command=version_command, zsh_version=version.stdout.decode().strip())
    checks = [('noninteractive-noop', lambda: noninteractive(zsh, wrapper, args.output)),
              ('real-zle-suggest-accept-edit-coexist-repeat', lambda: interactive(zsh, wrapper, args.output)),
              ('preloaded-module-preserved', lambda: interactive(zsh, wrapper, args.output, preloaded=True)),
              ('sigint-owned-fixture-cleanup', lambda: interactive(zsh, wrapper, args.output, interrupted=True)),
              ('absent-package-removal-guard', lambda: removal_guard(zsh, args.output))]
    for name, check in checks:
        try: report['tests'].append(dict(name=name, status='PASS', **check()))
        except (AssertionError, ValueError, OSError, subprocess.SubprocessError) as error:
            report['tests'].append(dict(name=name, status='FAIL', error=str(error)[:256]))
    pinned(wrapper, args.wrapper_sha256); pinned(module, args.module_sha256)
    if all(row['status'] == 'PASS' for row in report['tests']): report['status'] = 'PASS-host-fixtures'
    (args.output / 'receipt.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: report[key] for key in ('status', 'zsh_version', 'architecture', 'tests')}, sort_keys=True))
    return 0 if report['status'] == 'PASS-host-fixtures' else 1


if __name__ == '__main__':
    raise SystemExit(main())
