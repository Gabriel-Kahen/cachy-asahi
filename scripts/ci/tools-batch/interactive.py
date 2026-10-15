#!/usr/bin/env python3
"""Finite real PTY and owned-process probes; run as an unprivileged fixture user."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import shlex
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from urllib.parse import unquote


def need(value, message):
    if not value:
        raise ValueError(message)


def fingerprint(home):
    return {str(p.relative_to(home)): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mode,
            p.stat().st_uid, p.stat().st_gid, p.stat().st_mtime_ns) for p in home.rglob('*') if p.is_file()}


class Terminal:
    def __init__(self, argv, home):
        self.master, slave = pty.openpty()
        self.output = bytearray()
        self.attribute_replies = 0
        self.end = time.monotonic() + 15
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 160, 0, 0))
        env = dict(PATH='/usr/bin:/bin', HOME=str(home), ZDOTDIR=str(home), TERM='xterm',
                   LANG='C.UTF-8', LC_ALL='C.UTF-8', XDG_CONFIG_HOME=str(home / '.config'),
                   XDG_DATA_HOME=str(home / '.local/share'), XDG_CACHE_HOME='/tmp/probe-cache')
        def session():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        try:
            self.process = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                            cwd=home, env=env, preexec_fn=session)
        except BaseException:
            os.close(self.master)
            raise
        finally:
            os.close(slave)

    def send(self, data):
        need(len(data) <= 4096 and os.write(self.master, data) == len(data), 'PTY input bound/write')

    def until(self, predicate):
        while not predicate():
            need(time.monotonic() < self.end, 'PTY deadline: ' + repr(bytes(self.output[-256:])))
            if select.select([self.master], [], [], 0.05)[0]:
                try:
                    data = os.read(self.master, 4096)
                except OSError:
                    data = b''
                need(data, 'PTY closed before expected state')
                self.output.extend(data)
                need(len(self.output) <= 131072, 'PTY output bound')
                queries = self.output.count(b'\x1b[0c')
                need(queries <= 32, 'terminal query bound')
                while self.attribute_replies < queries:
                    self.send(b'\x1b[?1;2c')
                    self.attribute_replies += 1

    def finish(self):
        # Expanded buffers never receive Enter. Clear them; submit only this fixed exit.
        self.send(b'\x15exit 0\n')
        self.process.wait(timeout=3)
        need(self.process.returncode == 0, 'interactive shell failed')

    def close(self):
        try:
            # A shell may exit while a descendant still owns the PTY/group.
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 0.2
            while time.monotonic() < deadline:
                self.process.poll()
                try:
                    os.killpg(self.process.pid, 0)
                except ProcessLookupError:
                    break
                select.select([], [], [], 0.01)
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            self.process.wait(timeout=1)
        finally:
            os.close(self.master)


def zsh_probe(home, work, wrapper):
    expected = "printf '%s\\n' CAA_SUGGESTION"
    history = work / 'zsh-history'
    history.write_text(expected + '\n')
    history.chmod(0o600)
    before = fingerprint(work)
    setup = work / 'setup.zsh'
    setup.write_text('''PROMPT='CAA_READY> '; RPROMPT=''; SAVEHIST=0; HISTSIZE=20
HISTFILE=@HISTORY@
bindkey -e
typeset -g ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE=fg=2
typeset -ga ZSH_AUTOSUGGEST_STRATEGY=(history)
fixture_user() { BUFFER=CAA_USER_WIDGET; CURSOR=$#BUFFER; }
zle -N fixture-user fixture_user; bindkey '^X^U' fixture-user
typeset -g original_binding=$(bindkey '^X^U')
source @WRAPPER@
typeset -g original_function=$(typeset -f _zsh_autosuggest_start)
source @WRAPPER@
[[ $(typeset -f _zsh_autosuggest_start) == $original_function && $(bindkey '^X^U') == $original_binding ]] || exit 21
unset ZSH_AUTOSUGGEST_USE_ASYNC
typeset -gi fixture_seq=0
fixture_snapshot() {
 (( fixture_seq += 1 ))
 print -rn -- "$BUFFER"$'\\0'"$POSTDISPLAY" > @SNAPSHOT@-$fixture_seq
 print -r -- CAA_SNAPSHOT_$fixture_seq
}
zle -N fixture-snapshot fixture_snapshot
ZSH_AUTOSUGGEST_IGNORE_WIDGETS+=(fixture-snapshot)
bindkey '^G' fixture-snapshot
fc -R "$HISTFILE"
print ready > @READY@
'''.replace('@HISTORY@', shlex.quote(str(history))).replace('@WRAPPER@', shlex.quote(str(wrapper)))
       .replace('@SNAPSHOT@', shlex.quote(str(work / 'snapshot'))).replace('@READY@', shlex.quote(str(work / 'ready'))))
    terminal = Terminal(['/usr/bin/zsh', '-dfi'], home)
    states = []
    try:
        terminal.send(('source ' + shlex.quote(str(setup)) + '\n').encode())
        terminal.until(lambda: (work / 'ready').exists() and b'CAA_READY> ' in terminal.output)
        terminal.send(b"printf '%s\\n' CAA_")
        # Observe actual displayed suffix before requesting a ZLE state snapshot.
        terminal.until(lambda: b'SUGGESTION' in terminal.output)
        for index, keys in enumerate((b'', b'\x1b[C', b'\x7f', b'\x18\x15'), 1):
            terminal.send(keys + b'\x07')
            path = work / ('snapshot-' + str(index))
            terminal.until(lambda: ('CAA_SNAPSHOT_' + str(index)).encode() in terminal.output and path.exists())
            fields = path.read_bytes().decode().split('\0')
            need(len(fields) == 2, 'ZLE snapshot fields')
            states.append(fields)
        need(states[0] == ["printf '%s\\n' CAA_", 'SUGGESTION'], 'Zsh suggestion state: ' + repr(states[0]))
        need(states[1] == [expected, ''], 'Zsh right-arrow acceptance: ' + repr(states[1]))
        need(states[2][0] == expected[:-1], 'Zsh backspace editing')
        need(states[3][0] == 'CAA_USER_WIDGET', 'Zsh user widget preservation')
        terminal.finish()
        need(fingerprint(work)['zsh-history'] == before['zsh-history'], 'synthetic Zsh history changed')
        return dict(suggestion=states[0], accepted=states[1], edited=states[2][0],
                    user_widget=states[3][0], repeated_opt_in=True, expanded_enter=False)
    finally:
        terminal.close()


def fish_probe(home, wrapper, argument=False):
    previous = "printf '%s\\n' \"two words\"" if argument else "printf '%s\\n' CAA_FISH_PREVIOUS"
    expected = previous
    typed = b"printf '%s\\n' !$" if argument else b'!!'
    setup = '''function fish_greeting; end; function fish_prompt; printf 'CAA_READY> '; end; function fish_right_prompt; end
set -g fish_key_bindings fish_default_key_bindings; fish_default_key_bindings
function __caa_user; commandline --replace CAA_USER_WIDGET; end
bind ctrl-x,ctrl-u __caa_user
source @WRAPPER@
set -l original_function (functions caa_history_bang | string collect)
set -l original_bindings (bind --user | string collect)
source @WRAPPER@
test "$original_function" = "$(functions caa_history_bang | string collect)"; or exit 21
test "$original_bindings" = "$(bind --user | string collect)"; or exit 22
function __caa_capture
 printf '\\nCAA_BUFFER__%s__CAA_END\\n' (string escape --style=url -- "$(commandline -b)")
 commandline --replace ''
end
bind ctrl-g __caa_capture
builtin history append -- PREVIOUS
'''.replace('@WRAPPER@', shlex.quote(str(wrapper))).replace('PREVIOUS', shlex.quote(previous))
    terminal = Terminal(['/usr/bin/fish', '--no-config', '--private', '--interactive', '--init-command', setup], home)
    try:
        terminal.until(lambda: b'CAA_READY> ' in terminal.output)
        def capture(keys, count):
            terminal.send(keys + b'\x07')
            matches = lambda: re.findall(rb'CAA_BUFFER__(.*?)__CAA_END', terminal.output)
            terminal.until(lambda: len(matches()) >= count)
            return unquote(matches()[count - 1].decode('ascii'))
        actual = capture(typed, 1)
        need(actual == expected, 'Fish expansion: ' + repr(actual) + '; terminal=' + repr(bytes(terminal.output[-2048:])))
        user = capture(b'\x18\x15', 2)
        need(user == 'CAA_USER_WIDGET', 'Fish user binding preservation')
        terminal.finish()
        return dict(typed=typed.decode(), expanded=actual, user_widget=user,
                    repeated_opt_in=True, expanded_enter=False)
    finally:
        terminal.close()


def topmem_probe(executable):
    allocation = 96 * 1024**2
    program = ('import os,sys\n' + f'memory=bytearray({allocation})\n' +
               'for offset in range(0,len(memory),4096): memory[offset]=1\n' +
               'print(os.getpid(),flush=True)\nsys.stdin.read()\n')
    child = subprocess.Popen([sys.executable, '-I', '-c', program], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        need(select.select([child.stdout], [], [], 5)[0], 'resident helper readiness')
        pid = int(child.stdout.readline())
        need(pid == child.pid, 'owned helper PID')
        status = dict(line.split(':', 1) for line in Path('/proc', str(pid), 'status').read_text().splitlines() if ':' in line)
        need(int(status['Uid'].split()[0]) == os.getuid(), 'owned helper real UID')
        rss, unit = status['VmRSS'].split()
        need(unit == 'kB' and int(rss) * 1024 >= allocation, 'controlled allocation not resident')
        proc_rss = int(rss) * 1024
        snapshots = []
        for limit in (50, 1, 2):
            result = subprocess.check_output([str(executable), '--json', '--limit', str(limit)], text=True, timeout=5)
            value = json.loads(result)
            need(value['uid'] == os.getuid() and value['scope'] == 'current-real-uid', 'Topmem UID/scope')
            rows = value['processes']
            need(0 < len(rows) <= limit and all(row['rss_bytes'] > 0 for row in rows), 'Topmem limit/RSS')
            helper = next((row for row in rows if row['pid'] == pid), None)
            if limit == 50:
                need(helper is not None and helper['rss_bytes'] >= allocation, 'resident helper absent/underreported')
            need([row['rss_bytes'] for row in rows] == sorted((row['rss_bytes'] for row in rows), reverse=True), 'Topmem ordering')
            if limit in (1, 2):
                need(len(rows) == limit, 'Topmem exact populated limit')
            snapshots.append(dict(limit=limit, returned=len(rows), helper_pid=pid, helper_rss_bytes=helper['rss_bytes'] if helper else None))
        return dict(uid=os.getuid(), allocated_bytes=allocation, proc_rss_bytes=proc_rss, snapshots=snapshots)
    finally:
        child.stdin.close()
        try:
            child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=2)
        child.stdout.close()
        child.stderr.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--zsh-wrapper', type=Path, default=Path('/usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh'))
    parser.add_argument('--fish-wrapper', type=Path, default=Path('/usr/share/cachy-asahi/fish-bang-bang/opt-in.fish'))
    parser.add_argument('--topmem', type=Path, default=Path('/usr/bin/cachy-asahi-topmem'))
    args = parser.parse_args()
    need(os.getuid() == os.geteuid() != 0, 'unprivileged interactive probes required')
    home = args.home.resolve()
    before = fingerprint(home)
    with tempfile.TemporaryDirectory(prefix='caa-interactive-') as directory:
        zsh = zsh_probe(home, Path(directory), args.zsh_wrapper)
        fish = [fish_probe(home, args.fish_wrapper), fish_probe(home, args.fish_wrapper, argument=True)]
        topmem = topmem_probe(args.topmem)
    need(fingerprint(home) == before, 'user config/history fingerprint changed')
    print(json.dumps(dict(status='TOOLS_INTERACTIVE_PASS', zsh=zsh, fish=fish, topmem=topmem,
                          user_files_preserved=True), sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
