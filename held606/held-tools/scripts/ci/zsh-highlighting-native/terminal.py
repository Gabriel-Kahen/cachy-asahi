#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Isolated Zsh/PTY integration fixtures; no package installation or caller HOME."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import pty
import resource
import select
import shutil
import signal
import subprocess
import tempfile
import termios
import time


def quote(path):
    return "'" + str(path).replace("'", "'\\''") + "'"


def environment(home):
    return dict(PATH='/usr/bin:/bin', HOME=str(home), ZDOTDIR=str(home),
                TERM='xterm', LANG='C', LC_ALL='C')


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_AS, (256*1024**2, 256*1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (1024**2, 1024**2))


class Terminal:
    def __init__(self, home, zsh):
        self.master, slave = pty.openpty(); self.output = bytearray()
        def start():
            limits(); os.setsid(); fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
        try:
            self.process = subprocess.Popen([zsh, '-f', '-i'], stdin=slave,
                stdout=slave, stderr=slave, env=environment(home), cwd=home, preexec_fn=start)
        except BaseException:
            os.close(self.master); raise
        finally:
            os.close(slave)

    def send(self, data):
        assert len(data) <= 8192 and os.write(self.master, data) == len(data)

    def wait(self, condition):
        end = time.monotonic() + 5
        while not condition():
            if time.monotonic() >= end:raise AssertionError('terminal fixture deadline')
            if select.select([self.master], [], [], .05)[0]:
                try:raw = os.read(self.master, 4096)
                except OSError:raw = b''
                self.output.extend(raw)
                assert len(self.output) <= 65536, 'terminal output bound'
                if not raw and not condition():raise AssertionError('terminal closed early')

    def settle(self):
        end = time.monotonic() + 5
        while select.select([self.master], [], [], .1)[0]:
            assert time.monotonic() < end, 'terminal settle deadline'
            raw = os.read(self.master, 4096);assert raw
            self.output.extend(raw);assert len(self.output) <= 65536

    def close(self):
        try:
            if self.process.poll() is None:
                os.killpg(self.process.pid, signal.SIGTERM)
                try:self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    os.killpg(self.process.pid, signal.SIGKILL);self.process.wait(timeout=1)
        finally:os.close(self.master)
        assert self.process.poll() is not None, 'private shell not reaped'


def home_at(root, name):
    home = root/name;home.mkdir(mode=0o700)
    for startup in ('.zshrc', '.zshenv'):
        (home/startup).write_text('print unexpected > "$HOME/startup-read"\n')
    (home/'history').write_text('print -r -- fixture-suggestion\n')
    return home


def run(zsh, home, script, interactive=False):
    result = subprocess.run([zsh, '-f', *(['-i'] if interactive else []), '-c', script],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        env=environment(home), cwd=home, preexec_fn=limits, timeout=5)
    assert len(result.stdout) <= 65536 and result.returncode == 0, result.stdout.decode(errors='replace')
    assert not (home/'startup-read').exists()


def terminal_case(root, zsh, wrapper, autosuggestions=None):
    home = home_at(root, 'coexist' if autosuggestions else 'editing')
    before = (home/'history').read_bytes()
    script = '''PROMPT='CAA> '; RPROMPT=''; HISTFILE=$HOME/history; SAVEHIST=0
bindkey -e
typeset -gi fixture_hits=0 fixture_seq=0 fixture_redraws=0
fixture_user_widget() { (( fixture_hits += 1 )); BUFFER='print -r -- custom'; CURSOR=$#BUFFER; }
zle -N fixture-user-widget fixture_user_widget
bindkey '^X^U' fixture-user-widget
typeset -g fixture_binding=$(bindkey '^X^U')
fixture_user_redraw() { (( fixture_redraws += 1 )); }
autoload -Uz add-zle-hook-widget
add-zle-hook-widget line-pre-redraw fixture_user_redraw
typeset -ga ZSH_HIGHLIGHT_HIGHLIGHTERS=(main brackets)
typeset -gA ZSH_HIGHLIGHT_STYLES
ZSH_HIGHLIGHT_STYLES[builtin]=fg=4
ZSH_HIGHLIGHT_STYLES[unknown-token]=fg=1
ZSH_HIGHLIGHT_STYLES[single-quoted-argument]=fg=6
@AUTOSUGGEST@
source WRAPPER
(( ${+functions[_zsh_highlight_load_highlighters]} )) || exit 11
typeset -g fixture_hook_before=$(typeset -p zle_line_pre_redraw_functions)
source WRAPPER
[[ $(typeset -p zle_line_pre_redraw_functions) == $fixture_hook_before ]] || exit 12
[[ $ZSH_HIGHLIGHT_STYLES[builtin] == fg=4 && $ZSH_HIGHLIGHT_HIGHLIGHTERS == 'main brackets' ]] || exit 13
[[ $(bindkey '^X^U') == $fixture_binding ]] || exit 14
fixture_snapshot() {
 (( fixture_seq += 1 ))
 print -rn -- "$BUFFER"$'\0'"$POSTDISPLAY"$'\0'"${(j:|:)region_highlight}"$'\0'"$fixture_hits"$'\0'"$fixture_redraws" > "$HOME/snapshot-$fixture_seq"
}
zle -N fixture-snapshot fixture_snapshot
bindkey '^X^D' fixture-snapshot
[[ -n ${ZSH_AUTOSUGGEST_IGNORE_WIDGETS+x} ]] && ZSH_AUTOSUGGEST_IGNORE_WIDGETS+=(fixture-snapshot)
fc -R "$HOME/history"
print ready > "$HOME/ready"
'''.replace('WRAPPER', quote(wrapper)).replace('@AUTOSUGGEST@',
    ('source '+quote(autosuggestions)+'\nunset ZSH_AUTOSUGGEST_USE_ASYNC\nZSH_AUTOSUGGEST_IGNORE_WIDGETS+=(fixture-snapshot)') if autosuggestions else '')
    setup = home/'setup.zsh';setup.write_text(script)
    terminal = Terminal(home, zsh);snapshots=[]
    try:
        terminal.send(('source '+quote(setup)+'\n').encode())
        terminal.wait(lambda: (home/'ready').exists() and b'CAA> ' in terminal.output)
        def snapshot(data):
            terminal.send(data);terminal.settle();terminal.send(b'\x18\x04')
            target=home/('snapshot-'+str(len(snapshots)+1));terminal.wait(target.exists)
            values=target.read_text().split('\0');assert len(values)==5
            snapshots.append(values);return values
        if autosuggestions:
            row=snapshot(b'print -r -- fix');assert row[:2]==['print -r -- fix','ture-suggestion'],row
            row=snapshot(b'\x1b[C');assert row[:2]==['print -r -- fixture-suggestion',''],row
        else:
            row=snapshot(b'print -r -- \'hello\'');assert row[0]=="print -r -- 'hello'" and 'fg=blue' in row[2] and 'fg=cyan' in row[2],row
            row=snapshot(b'\x15caa_fixture_nonexistent_7e1');assert 'fg=red' in row[2],row
            row=snapshot(b'\x7f');assert row[0]=='caa_fixture_nonexistent_7e',row
        row=snapshot(b'\x18\x15');assert row[0]=='print -r -- custom' and row[3]=='1' and int(row[4])>0,row
        terminal.send(b'\x15exit 0\n');terminal.process.wait(timeout=5)
        assert terminal.process.returncode==0
        assert (home/'history').read_bytes()==before and not (home/'startup-read').exists()
        return dict(snapshots=snapshots, terminal_bytes=len(terminal.output))
    finally:terminal.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wrapper',type=Path,required=True)
    parser.add_argument('--autosuggestions',type=Path,required=True)
    parser.add_argument('--work-root',type=Path,required=True)
    args=parser.parse_args();zsh=shutil.which('zsh',path='/usr/bin:/bin')
    assert zsh,'existing Zsh required; no installation permitted'
    wrapper=args.wrapper.resolve();autosuggestions=args.autosuggestions.resolve()
    assert wrapper.is_file() and autosuggestions.is_file()
    results=[]
    with tempfile.TemporaryDirectory(prefix='fixtures-',dir=args.work_root) as work:
        root=Path(work).resolve()
        home=home_at(root,'noninteractive')
        run(zsh,home,'source '+quote(wrapper)+'; source '+quote(wrapper)+'''
(( ! ${+functions[_zsh_highlight]} )) || exit 11
''');results.append(dict(name='noninteractive-noop',status='PASS'))
        home=home_at(root,'preloaded')
        run(zsh,home,'''_zsh_highlight() { : user-module; }
typeset -g original=$functions[_zsh_highlight]
'''+ 'source '+quote(wrapper)+'; source '+quote(wrapper)+'''
[[ $functions[_zsh_highlight] == $original ]] || exit 11
(( ! ${+functions[_zsh_highlight_load_highlighters]} )) || exit 12
''',interactive=True);results.append(dict(name='existing-user-module-wins',status='PASS'))
        results.append(dict(name='real-zle-colours-editing-bindings-hooks-repeat',status='PASS',**terminal_case(root,zsh,wrapper)))
        results.append(dict(name='autosuggestions-before-highlighting',status='PASS',**terminal_case(root,zsh,wrapper,autosuggestions)))
        home=home_at(root,'lifecycle');installed=home/'installed';shutil.copytree(wrapper.parent,installed)
        line='[[ -r '+quote(installed/'opt-in.zsh')+' ]] && source '+quote(installed/'opt-in.zsh')+'\n'
        startup=home/'opt-in-line';startup.write_text(line);before=startup.read_bytes()
        run(zsh,home,'source '+quote(startup)+'\n(( ${+functions[_zsh_highlight]} )) || exit 11',interactive=True)
        installed.rename(home/'removed')
        run(zsh,home,'source '+quote(startup)+'\n(( ! ${+functions[_zsh_highlight]} )) || exit 12',interactive=True)
        (home/'removed').rename(installed)
        run(zsh,home,'source '+quote(startup)+'\n(( ${+functions[_zsh_highlight]} )) || exit 13',interactive=True)
        assert startup.read_bytes()==before and (home/'history').read_text()=='print -r -- fixture-suggestion\n'
        results.append(dict(name='guarded-optin-remove-reinstall-simulated',status='PASS'))
    print(json.dumps(dict(status='PASS',architecture=platform.machine(),zsh=zsh,tests=results,
        package_build='NOT RUN',native_ARM_Zsh_terminal=platform.machine()=='aarch64',target_installation='NOT RUN',M2='NOT RUN'),sort_keys=True))


if __name__=='__main__':main()
