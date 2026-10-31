#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded real Fish completion and notification-invocation fixtures; private HOME and no package installation."""
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
    resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2, 512 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**2, 1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def environment(home):
    return dict(PATH=str(home/'bin'), HOME=str(home), XDG_CONFIG_HOME=str(home/'config'),
                XDG_DATA_HOME=str(home/'data'), XDG_CACHE_HOME=str(home/'cache'),
                DBUS_SESSION_BUS_ADDRESS='unix:path='+str(home/'not-a-real-bus'), TERM='xterm', LANG='C.UTF-8', LC_ALL='C.UTF-8')


class Terminal:
    def __init__(self, fish, home):
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
            if self.process.poll() is not None:
                need(predicate(), 'PTY early exit: '+str(self.process.returncode))
                return
            need(time.monotonic() < end, 'PTY timeout')
            if select.select([self.master], [], [], .02)[0]:
                try:
                    data = os.read(self.master, 4096)
                except OSError as error:
                    if error.errno != 5:
                        raise
                    data = b'' 
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
    need((home/'config/fish/config.fish').read_text() == 'touch \"$HOME/unexpected-rc\"\n', 'config changed')


def prepare(root, name, missing=None):
    home = private(root, name)
    (home/'bin').mkdir()
    for command in ('sleep', 'sh', 'timeout', 'kill'):
        if command != missing:
            (home/'bin'/command).symlink_to(shutil.which(command))
    if missing != 'notify-send':
        shim = home/'bin/notify-send'
        shim.write_text('''#!/usr/bin/python3
import json,os,signal,time
from pathlib import Path
h=Path(os.environ['HOME'])
f=os.open(h/'notifications.jsonl',os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
b=(json.dumps(dict(argv=__import__('sys').argv[1:],pid=os.getpid()))+'\\n').encode()
assert len(b)<4096
os.write(f,b);os.close(f)
mode=(h/'notify-mode').read_text() if (h/'notify-mode').exists() else ''
if mode=='hang':
 signal.signal(signal.SIGTERM,signal.SIG_IGN)
 time.sleep(20)
raise SystemExit(9 if mode=='fail' else 0)
''')
        shim.chmod(0o700)
    return home


def rows(home):
    path = home/'notifications.jsonl'
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def noninteractive(fish, wrapper, root):
    home = prepare(root, 'noninteractive')
    script = '''function custom; true; end
set -g __done_version preserve
set -l before (functions --all --names)
source WRAPPER; source WRAPPER
printf '%s' $status > "$HOME/source-status"
test "$__done_version" = preserve; or exit 11
test "$(functions --all --names)" = "$(string join \\n -- $before)"; or exit 12
functions --query __done_ended; and exit 13
true
'''.replace('WRAPPER', shlex.quote(str(wrapper)))
    result = subprocess.run([fish, '--no-config', '-c', script], env=environment(home), cwd=home,
                            capture_output=True, timeout=5, preexec_fn=limits)
    need(result.returncode == 0 and not result.stdout and not result.stderr, 'noninteractive no-op')
    need(not rows(home) and (home/'source-status').read_text() == '0', 'noninteractive notification/status')
    preserved(home)
    return dict(exit=0, notifications=0)


class Session:
    def __init__(self, fish, wrapper, root, kind):
        missing = kind if kind in ('notify-send', 'timeout') else None
        self.home = home = prepare(root, kind, missing)
        self.term = term = Terminal(fish, home)
        self.sequence = 1
        preloads = {
            'existing-function': 'function __done_ended --on-event fish_postexec; true; end',
            'existing-autoload': 'set -p fish_function_path "$HOME/autoload"',
            'existing-variable': 'set -g __done_version preserve',
            'existing-wrapper': 'function _caa_done_enable; true; end',
            'existing-public': 'function caa_done_watch; true; end',
            'no-bus': 'set -e DBUS_SESSION_BUS_ADDRESS',
        }
        self.skip = kind in preloads or missing is not None
        if kind == 'existing-autoload':
            (home/'autoload').mkdir()
            (home/'autoload/__done_ended.fish').write_text('function __done_ended; true; end\n')
        setup = '''set -g fish_history ''
set -g fish_key_bindings fish_default_key_bindings
fish_default_key_bindings
set -g caa_done_min_duration 80
set -g fixture_command_n 0
function fixture_post --on-event fish_postexec
    set -g fixture_command_n (math $fixture_command_n + 1)
    printf 'POST %s\\n' "$argv[1]" >> "$HOME/events"
end
function fixture_pre --on-event fish_preexec
    printf 'PRE %s\\n' "$argv[1]" >> "$HOME/events"
end
function fixture_binding
    commandline --replace CUSTOM-BINDING
    printf '%s' (commandline) > "$HOME/custom-binding"
    commandline --replace ''
end
bind ctrl-g fixture_binding
bind ctrl-o 'exit 0'
function fish_prompt
    set -l result $status
    if not test -e "$HOME/status-$fixture_command_n"
        printf '%s' $result > "$HOME/status-$fixture_command_n"
    end
    printf done > "$HOME/prompt-$fixture_command_n"
    printf 'DONE> '
end
PRELOAD
bind --all > "$HOME/bindings-before"
functions --handlers > "$HOME/handlers-before"
set -g fixture_functions (functions --all --names)
source WRAPPER
set -l load_status $status
bind --all > "$HOME/bindings-after"
functions --handlers > "$HOME/handlers-after"
printf '%s' $load_status > "$HOME/load-status"
VERIFY
true
'''.replace('PRELOAD', preloads.get(kind, '')).replace('WRAPPER', shlex.quote(str(wrapper)))
        verify = 'functions --query __done_ended caa_done_watch caa_done_disable; or return 21'
        if self.skip:
            verify = '''test "$(functions --all --names)" = "$(string join \\n -- $fixture_functions)"; or return 22
functions --query __done_notify; and return 23'''
        setup = setup.replace('VERIFY', verify)
        setup_path = home/'setup.fish'
        setup_path.write_text(setup)
        term.wait(lambda: b']133;B' in term.output)
        term.send(('source '+shlex.quote(str(setup_path))+"; printf '%s' $status > \"$HOME/setup-status\"\n").encode())
        term.wait(lambda: (home/'prompt-1').exists() and term.output.count(b']133;B') >= 2)
        need((home/'setup-status').read_text() == '0' and (home/'load-status').read_text() == '0', 'setup/load status')
        need((home/'bindings-before').read_bytes() == (home/'bindings-after').read_bytes(), 'custom keymap changed')
        if self.skip:
            need((home/'handlers-before').read_bytes() == (home/'handlers-after').read_bytes(), 'existing event namespace changed')
        self.initial = len(rows(home))

    def run(self, command, expected=0):
        self.sequence += 1
        self.term.send((command+'\n').encode())
        self.term.wait(lambda: (self.home/f'prompt-{self.sequence}').exists())
        status = (self.home/f'status-{self.sequence}').read_text()
        need(status == str(expected), f'command status {command!r}: {status} != {expected}')
        return rows(self.home)

    def close(self):
        self.term.send(b'\x0f')
        self.term.wait(lambda: self.term.process.poll() is not None)
        self.term.process.wait(timeout=1)
        need(self.term.process.returncode == 0, 'normal Fish exit')
        (self.home/'terminal.log').write_bytes(self.term.output)
        self.term.close()
        preserved(self.home)


def invocation(row, failed=False, kind='Foreground command', private=True):
    args = row['argv']
    need(len(args) == 8 and args[:5] == ['--hint=int:transient:1', '--urgency='+('critical' if failed else 'normal'),
         '--icon=utilities-terminal', '--app-name=fish', '--expire-time=3000'] and args[5] == '--', 'notify-send argv contract')
    need(args[6].startswith('Failed (' if failed else 'Done in '), 'completion title')
    if private:
        need(args[7] == kind+' completed.', 'default notification disclosed command/directory')
    return dict(argv=args)


def interactive(fish, wrapper, root, kind):
    session = None
    try:
        session = Session.__new__(Session)
        session.__init__(fish, wrapper, root, kind)
        home, term = session.home, session.term
        baseline = len(rows(home))
        proofs = []
        if session.skip:
            session.run('sleep .12')
            need(len(rows(home)) == baseline, 'yielded module notified')
            return dict(exit=0, activation='yielded', notifications=0)
        if kind == 'foreground':
            result = session.run('sleep .12')
            need(len(result) == baseline+1, 'long success did not notify once')
            proofs.append(invocation(result[-1]))
            result = session.run("sh -c 'sleep .12; exit 7'", 7)
            need(len(result) == baseline+2, 'failure did not notify once')
            proofs.append(invocation(result[-1], failed=True))
            need('Failed (7)' in result[-1]['argv'][6], 'wrong foreground exit status')
            session.run('true')
            need(len(rows(home)) == baseline+2, 'short command notified')
            session.run("set -g caa_done_exclude '^sleep'; sleep .12")
            # Exclusions match the complete submitted command, as upstream does.
            session.run('sleep .12')
            excluded = len(rows(home))
            need(excluded == baseline+3, 'exclude did not suppress the matching submitted command')
            session.run('set -e caa_done_exclude')
            session.run('set -g caa_done_min_duration invalid; sleep .12')
            need(len(rows(home)) == excluded, 'invalid threshold notified')
            session.run('set -g caa_done_min_duration 80')
        elif kind == 'background':
            session.run('sleep .22 &; set -g watched $last_pid; caa_done_watch $watched; caa_done_watch $watched')
            term.wait(lambda: len(rows(home)) == baseline+1)
            proofs.append(invocation(rows(home)[-1], kind='Watched job'))
            session.run('not functions --query __done_job_$watched')
            session.run('caa_done_watch $watched', 1)
            session.run("sh -c 'sleep .22; exit 7' &; caa_done_watch $last_pid")
            term.wait(lambda: len(rows(home)) == baseline+2)
            proofs.append(invocation(rows(home)[-1], failed=True, kind='Watched job'))
            need('Failed (7)' in rows(home)[-1]['argv'][6], 'wrong background exit status')
            session.run('sleep .3 &; set -g watched $last_pid; caa_done_watch $watched')
            session.run('sleep .10; kill -TERM $watched')
            term.wait(lambda: any('Failed (143)' in r['argv'][6] for r in rows(home)[baseline:]))
            proofs.append(invocation(next(r for r in rows(home)[baseline:] if 'Failed (143)' in r['argv'][6]), failed=True, kind='Watched job'))
        elif kind == 'watch-rejection':
            session.run('caa_done_watch', 2)
            session.run('caa_done_watch not-a-pid', 2)
            session.run('caa_done_watch $fish_pid', 1)
            session.run('sleep .22 | sleep .22 &; caa_done_watch $last_pid', 1)
            session.run('wait')
            # wait itself may notify as foreground work; rejected job must not.
            need(all(r['argv'][7] != 'Watched job completed.' for r in rows(home)[baseline:]), 'rejected watch notified')
        elif kind == 'disown':
            session.run('sleep .18 &; set -g watched $last_pid; caa_done_watch $watched; disown $watched')
            session.run('sleep .22')
            need(not any(r['argv'][7] == 'Watched job completed.' for r in rows(home)[baseline:]), 'disowned job notified')
            session.run('caa_done_disable')
            session.run('not functions --query __done_job_$watched')
        elif kind == 'repeat-preserve':
            session.run('functions --handlers > "$HOME/repeat-before"')
            session.run('function fixture_source; source '+shlex.quote(str(wrapper))+'; printf continued > "$HOME/continued"; end; fixture_source')
            session.run('functions --handlers > "$HOME/repeat-after"')
            need((home/'continued').read_text() == 'continued', 'repeat ended caller')
            need((home/'repeat-before').read_bytes() == (home/'repeat-after').read_bytes(), 'repeat duplicated handlers')
            term.send(b'\x07')
            term.wait(lambda: (home/'custom-binding').exists())
            need((home/'custom-binding').read_text() == 'CUSTOM-BINDING', 'preexisting binding changed')
            session.run('sleep .12')
            need(len(rows(home)) == baseline+1, 'repeat duplicate completion notification')
        elif kind == 'command-data':
            session.run('set -g caa_done_show_command 1')
            session.run('sleep .12 # <tag> $HOME $(touch PWNED) --leading')
            need(len(rows(home)) == baseline+1, 'optional command notification')
            proof = invocation(rows(home)[-1], private=False)
            need('&lt;tag&gt; $HOME $(touch PWNED) --leading' in rows(home)[-1]['argv'][7], 'command text evaluated or markup not escaped')
            proofs.append(proof)
        elif kind in ('transport-failure', 'transport-timeout'):
            (home/'notify-mode').write_text('fail' if kind == 'transport-failure' else 'hang')
            started = time.monotonic()
            session.run('sleep .12')
            elapsed = time.monotonic()-started
            need(len(rows(home)) == baseline+1 and elapsed < 4.5, 'notification transport not bounded')
            if kind == 'transport-timeout':
                pid = rows(home)[-1]['pid']
                need(not Path(f'/proc/{pid}').exists(), 'timed-out notification process survived')
            proofs.append(dict(elapsed_seconds=round(elapsed, 3), invocation=invocation(rows(home)[-1])))
        elif kind == 'disable':
            session.run('sleep .22 &; caa_done_watch $last_pid')
            session.run('caa_done_disable')
            session.run('wait')
            session.run('sleep .12')
            need(len(rows(home)) == baseline, 'disabled completion/watch notified')
            session.run('not functions --query caa_done_watch __done_ended __done_notify')
        else:
            raise ValueError('unknown control')
        events = (home/'events').read_text()
        need('PRE ' in events and 'POST sleep' in events, 'preexisting event handlers lost')
        return dict(exit=0, activation='enabled', notifications=len(rows(home))-baseline, proofs=proofs)
    finally:
        if session is not None:
            try:
                session.close()
            except BaseException:
                (session.home/'terminal.log').write_bytes(session.term.output)
                session.term.close()
                raise


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
    receipt = dict(status='RUNNING', machine=platform.machine(), fish=subprocess.check_output([fish, '--version'], text=True, timeout=5).strip(),
                   wrapper_sha256=hashlib.sha256((source/'opt-in.fish').read_bytes()).hexdigest(),
                   runtime_sha256=hashlib.sha256((source/'done.fish').read_bytes()).hexdigest(),
                   scope='local notify-send process shim invocation only; no actual notification manager or visual display', cases={})
    try:
        receipt['cases']['noninteractive'] = noninteractive(fish, source/'opt-in.fish', root)
        for kind in ('foreground', 'background', 'watch-rejection', 'disown', 'repeat-preserve', 'command-data',
                     'transport-failure', 'transport-timeout', 'disable', 'existing-function', 'existing-autoload',
                     'existing-variable', 'existing-wrapper', 'existing-public', 'no-bus', 'notify-send', 'timeout'):
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
