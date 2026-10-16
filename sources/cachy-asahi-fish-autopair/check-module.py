#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded real Fish PTY fixtures; private HOME and no package installation."""
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
import shlex
import shutil
import signal
import subprocess
import termios
import time


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**2, 1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def environment(home):
    return dict(PATH='/usr/bin:/bin', HOME=str(home), XDG_CONFIG_HOME=str(home/'config'),
                XDG_DATA_HOME=str(home/'data'), XDG_CACHE_HOME=str(home/'cache'),
                TERM='xterm', LANG='C.UTF-8', LC_ALL='C.UTF-8')


class Terminal:
    def __init__(self, fish, home, setup):
        self.master, slave = pty.openpty()
        self.output = bytearray()
        def start():
            limits()
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        try:
            self.process = subprocess.Popen([fish, '--no-config', '--interactive', '--init-command',
                'function fish_prompt; printf BOOT; end'], stdin=slave, stdout=slave, stderr=slave,
                env=environment(home), cwd=home, preexec_fn=start)
        finally:
            os.close(slave)

    def send(self, data):
        need(len(data) <= 4096 and os.write(self.master, data) == len(data), 'bounded PTY write')

    def wait(self, predicate):
        end = time.monotonic()+5
        while not predicate():
            need(time.monotonic() < end and self.process.poll() is None, 'PTY timeout/early exit: '+str(self.process.poll()))
            if select.select([self.master], [], [], .02)[0]:
                data = os.read(self.master, 4096)
                self.output.extend(data)
                need(len(self.output) <= 65536, 'PTY output cap')
                if b'\x1b[0c' in data:
                    self.send(b'\x1b[?1;2c')
                if b'\x1b[6n' in data:
                    self.send(b'\x1b[1;1R')

    def close(self):
        try:
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGTERM)
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL)
                    self.process.wait(timeout=2)
        finally:
            os.close(self.master)


def private(root, name):
    home = root/name
    home.mkdir(mode=0o700)
    (home/'config/fish').mkdir(parents=True)
    (home/'config/fish/config.fish').write_text('touch "$HOME/unexpected-rc"\n')
    (home/'data/fish').mkdir(parents=True)
    (home/'data/fish/fish_history').write_bytes(b'preserve private existing history\n')
    return home


def preserved(home):
    need(not (home/'unexpected-rc').exists() and not (home/'PWNED').exists(), 'rc/data execution')
    need((home/'data/fish/fish_history').read_bytes() == b'preserve private existing history\n', 'history changed')


def noninteractive(fish, wrapper, root):
    home = private(root, 'noninteractive')
    script = '''function custom; true; end
set -g autopair_left preserve
set -l before (functions --all --names)
source WRAPPER; source WRAPPER
test "$autopair_left" = preserve; or exit 11
test "$(functions --all --names)" = "$(string join \\n -- $before)"; or exit 12
functions --query _autopair_backspace; and exit 13
exit 0
'''.replace('WRAPPER', shlex.quote(str(wrapper)))
    result = subprocess.run([fish, '--no-config', '-c', script], env=environment(home), cwd=home,
                            capture_output=True, timeout=5, preexec_fn=limits)
    need(result.returncode == 0 and not result.stdout and not result.stderr, 'noninteractive no-op: '+repr(result))
    preserved(home)
    return dict(exit=0)


def interactive(fish, wrapper, root, kind):
    home = private(root, kind)
    mode = 'insert' if kind in ('vi', 'hybrid') else 'default'
    keyset = {'vi': 'fish_vi_key_bindings', 'hybrid': 'fish_hybrid_key_bindings'}.get(kind, 'fish_default_key_bindings')
    preloads = {
        'custom-key': "bind -M default '(' 'commandline --insert CUSTOM'",
        'custom-prefix': "bind -M default '(,x' 'commandline --insert CUSTOM'",
        'custom-generic': "bind -M default '' 'commandline --insert CUSTOM'",
        'custom-tab': "bind -M default tab 'commandline --insert CUSTOM'",
        'preset-key': "bind --preset -M default '(' self-insert",
        'existing-function': 'function _autopair_backspace; true; end',
        'existing-autoload': 'set -p fish_function_path "$HOME/autoload"',
        'existing-variable': 'set -g autopair_pairs preserve',
        'custom-keymap': 'set -g fish_key_bindings user_custom_map',
        'existing-wrapper': 'function _caa_autopair_enable; true; end',
    }
    if kind == 'existing-autoload':
        (home/'autoload').mkdir()
        (home/'autoload/_autopair_insert_left.fish').write_text('function _autopair_insert_left; true; end\n')
    skip = kind in preloads
    setup = '''set -g fish_history ''
set -g fish_key_bindings KEYSET
KEYSET
function fixture_snapshot
    set -g fixture_n (math $fixture_n + 1)
    printf '%s\\0%s' (commandline | string collect) (commandline --cursor) > "$HOME/snapshot-$fixture_n"
    printf done > "$HOME/snapshot-$fixture_n.done"
end
function fixture_reset
    commandline --replace ''
    commandline --cursor 0
    set -g fixture_reset_n (math $fixture_reset_n + 1)
    printf '%s' $fixture_reset_n > "$HOME/reset"
end
function fixture_repeat
    printf start > "$HOME/repeat-start"
    bind --user --all > "$HOME/bindings-before"
    source WRAPPER; or exit 31
    printf sourced > "$HOME/repeat-sourced"
    bind --user --all > "$HOME/bindings-after"
    command cmp "$HOME/bindings-before" "$HOME/bindings-after"; or exit 32
    printf done > "$HOME/repeated"
end
function fish_prompt
    printf READY > "$HOME/ready"
    printf 'PAIR> '
end
set -g fixture_n 0
set -g fixture_reset_n 0
bind -M MODE ctrl-g fixture_snapshot
bind -M MODE ctrl-x fixture_reset
bind -M MODE ctrl-f fixture_repeat
bind -M MODE ctrl-o 'exit 0'
PRELOAD
set -g fixture_bindings (bind --all)
set -g fixture_functions (functions --all --names)
source WRAPPER; or exit 21
VERIFY
'''.replace('WRAPPER', shlex.quote(str(wrapper))).replace('KEYSET', keyset).replace('MODE', mode).replace('PRELOAD', preloads.get(kind, ''))
    verify = '''functions --query _autopair_insert_same; or exit 22
functions --query _autopair_fish_key_bindings; and exit 23
functions --query _autopair_uninstall; and exit 24
'''
    if skip:
        verify = '''test "$(bind --all)" = "$(string join \\n -- $fixture_bindings)"; or exit 25
test "$(functions --all --names)" = "$(string join \\n -- $fixture_functions)"; or exit 26
functions --query _autopair_insert_same; and exit 27
'''
    setup = setup.replace('VERIFY', verify+'\ntrue\n')
    setup_path = home/'setup.fish'
    setup_path.write_text(setup)
    term = Terminal(fish, home, setup_path)
    snapshots = []
    try:
        term.wait(lambda: b']133;B' in term.output)
        term.send(('source '+shlex.quote(str(setup_path))+"; printf '%s' $status > \"$HOME/source-status\"\n").encode())
        term.wait(lambda: (home/'source-status').exists() and (home/'ready').exists() and term.output.count(b']133;B') >= 2)
        need((home/'source-status').read_text() == '0', 'setup verification failed')
        if not skip:
            term.send(b'\x06')
            term.wait(lambda: (home/'repeated').exists())
            # Each case edits only the real command buffer; never press Enter.
            cases = [
                ('round-open', b'(', '()', 1),
                ('square-open', b'[', '[]', 1),
                ('brace-open', b'{', '{}', 1),
                ('double-open', b'"', '""', 1),
                ('single-open', b"'", "''", 1),
                ('nested', b'([{', '([{}])', 3),
                ('closer-skip', b'()', '()', 2),
                ('quote-skip', b'""', '""', 2),
                ('pair-backspace', b'(\x7f', '', 0),
                ('pair-ctrl-h', b'[\x08', '', 0),
                ('brace-delete', b'{\x7f', '', 0),
                ('quote-delete', b'"\x7f', '', 0),
                ('single-delete', b"'\x7f", '', 0),
                ('nested-skip', b'([{}])', '([{}])', 6),
                ('text-delete', b'"a\x7f', '""', 1),
                ('escaped-quote', b'\\"', '\\"', 2),
                ('escaped-bracket', b'\\(', '\\()', 2),
                ('quoted-data', b'"$HOME $(touch PWNED)', '"$HOME $(touch PWNED)"', 21),
                ('tab-basic', b'zz_no_such_command_123\t', 'zz_no_such_command_123', 22),
            ]
            for index, (label, keys, buffer, cursor) in enumerate(cases, 1):
                term.send(b'\x18')
                term.wait(lambda: (home/'reset').exists() and (home/'reset').read_text() == str(index))
                term.send(keys+b'\x07')
                snap = home/f'snapshot-{index}'
                term.wait(lambda: snap.with_suffix('.done').exists())
                actual, position = snap.read_bytes().split(b'\0')
                need((actual.decode(), int(position)) == (buffer, cursor),
                     f'{kind}/{label}: {(actual,position)!r} != {(buffer,cursor)!r}')
                snapshots.append(dict(case=label, buffer=buffer, cursor=cursor))
        # Clean command buffer before normal shell exit, never execute typed data.
        term.send(b'\x18')
        expected_reset = len(snapshots)+1
        term.wait(lambda: (home/'reset').exists() and (home/'reset').read_text() == str(expected_reset))
        term.send(b'\x0f')
        term.process.wait(timeout=5)
        need(term.process.returncode == 0, 'normal Fish exit failed')
    finally:
        (home/'terminal.log').write_bytes(term.output)
        term.close()
    preserved(home)
    return dict(exit=0, activation='yielded' if skip else 'enabled', snapshots=snapshots)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    fish = shutil.which('fish')
    need(fish is not None, 'fish unavailable')
    source = args.source.resolve()
    root = args.output.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    receipt = dict(status='RUNNING', platform=platform.machine(), fish=subprocess.check_output([fish, '--version'], text=True).strip(),
                   wrapper_sha256=hashlib.sha256((source/'opt-in.fish').read_bytes()).hexdigest(), cases={})
    try:
        receipt['cases']['noninteractive'] = noninteractive(fish, source/'opt-in.fish', root)
        for kind in ('default', 'vi', 'hybrid', 'custom-key', 'custom-prefix', 'custom-generic', 'custom-tab',
                     'preset-key', 'existing-function', 'existing-autoload', 'existing-variable', 'custom-keymap', 'existing-wrapper'):
            receipt['cases'][kind] = interactive(fish, source/'opt-in.fish', root, kind)
        receipt['status'] = 'PASS'
    except BaseException as error:
        receipt['status'] = 'FAIL'
        receipt['error'] = str(error)
        raise
    finally:
        (root/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(dict(status='PASS', cases=len(receipt['cases']), receipt=str(root/'receipt.json'))))


if __name__ == '__main__':
    main()
