#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite real Zsh/ZLE PTY controls in a private HOME; never install a package."""
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
import stat
import subprocess
import termios
import time

UPSTREAM='0b864862a3b48992d7316cc7e585a1315fa389d730c17bf16e2f2bd5918089f3'


def need(ok,reason):
    if not ok:raise ValueError(reason)


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def q(value):return shlex.quote(str(value))


def env(home):return dict(PATH='/usr/bin:/bin',HOME=str(home),ZDOTDIR=str(home),TERM='xterm',LANG='C',LC_ALL='C')


def limits():
    resource.setrlimit(resource.RLIMIT_CPU,(10,10));resource.setrlimit(resource.RLIMIT_AS,(256*1024**2,256*1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE,(1024**2,1024**2));resource.setrlimit(resource.RLIMIT_CORE,(0,0))


class Terminal:
    def __init__(self,zsh,home):
        self.master,slave=pty.openpty();self.output=bytearray()
        def start():limits();os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
        try:self.process=subprocess.Popen([zsh,'-d','-f','-i'],stdin=slave,stdout=slave,stderr=slave,
            env=env(home),cwd=home,preexec_fn=start)
        except BaseException:os.close(self.master);raise
        finally:os.close(slave)

    def send(self,raw):
        need(len(raw)<=4096 and os.write(self.master,raw)==len(raw),'bounded PTY write')

    def read(self):
        if select.select([self.master],[],[],.05)[0]:
            try:data=os.read(self.master,4096)
            except OSError:data=b''
            self.output.extend(data);need(len(self.output)<=65536,'PTY output limit')
            return bool(data)
        return True

    def wait(self,predicate):
        end=time.monotonic()+5
        while not predicate():
            need(time.monotonic()<end and self.read(),'PTY readiness deadline/exit; status='+str(self.process.poll()))

    def close(self):
        try:
            if self.process.poll() is None:
                os.killpg(self.process.pid,signal.SIGTERM)
                try:self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:os.killpg(self.process.pid,signal.SIGKILL);self.process.wait(timeout=2)
        finally:os.close(self.master)


def home(root,name):
    path=root/name;path.mkdir(mode=0o700)
    for file in ('.zshrc','.zshenv'):(path/file).write_text('print -r -- bad > "$HOME/unexpected-rc"\n')
    (path/'history').write_bytes(b'preserve existing on-disk history\n');(path/'history').chmod(0o600)
    return path


def preserved(path):
    need((path/'history').read_bytes()==b'preserve existing on-disk history\n' and
         stat.S_IMODE((path/'history').stat().st_mode)==0o600 and not (path/'unexpected-rc').exists() and
         not (path/'PWNED').exists(),'history/rc/quoted-data preservation')


def noninteractive(zsh,wrapper,root):
    path=home(root,'noninteractive')
    script='''HISTFILE=$HOME/history; SAVEHIST=0
fixture_user() { :; }
typeset -g HISTORY_SUBSTRING_SEARCH_GLOBBING_FLAGS='custom'
typeset -g before_functions=$(typeset -f)
typeset -g before_options=$(setopt)
source WRAPPER; source WRAPPER
[[ $(typeset -f) == $before_functions && $(setopt) == $before_options ]] || exit 11
[[ $HISTORY_SUBSTRING_SEARCH_GLOBBING_FLAGS == custom && $HISTFILE == $HOME/history && $SAVEHIST == 0 ]] || exit 12
(( ! ${+parameters[_history_substring_search_query]} )) || exit 13
'''.replace('WRAPPER',q(wrapper))
    row=subprocess.run([zsh,'-d','-f','-c',script],env=env(path),cwd=path,stdin=subprocess.DEVNULL,
        capture_output=True,timeout=5,preexec_fn=limits)
    need(row.returncode==0 and not row.stdout and not row.stderr,'noninteractive no-op failed');preserved(path)
    return dict(exit=0)


def interactive(zsh,wrapper,root,kind,highlight=None):
    path=home(root,kind);preload=''
    if kind=='preexisting-function':preload='history-substring-search-up() { print -r -- preserve; }; typeset -g saved=$functions[history-substring-search-up]'
    if kind=='preexisting-widget':preload='zle -N history-substring-search-up fixture_up; typeset -g saved=$widgets[history-substring-search-up]'
    if kind=='preexisting-private':preload='_history-substring-search-begin() { :; }; typeset -g saved=$functions[_history-substring-search-begin]'
    if highlight:preload='source '+q(highlight)+'\ntypeset -g saved_highlight=$functions[_zsh_highlight]'
    verify='(( ${+functions[history-substring-search-down]} )) || exit 21'
    if kind=='preexisting-function':verify='[[ $functions[history-substring-search-up] == $saved ]] && (( ! ${+functions[history-substring-search-down]} )) || exit 22'
    if kind=='preexisting-widget':verify='[[ $widgets[history-substring-search-up] == $saved ]] && (( ! ${+functions[history-substring-search-down]} )) || exit 23'
    if kind=='preexisting-private':verify='[[ $functions[_history-substring-search-begin] == $saved ]] && (( ! ${+functions[history-substring-search-up]} )) || exit 24'
    if highlight:verify+='\n[[ $functions[_zsh_highlight] == $saved_highlight ]] || exit 25'
    setup='''PROMPT='SUB> '; RPROMPT=''; HISTFILE=$HOME/history; SAVEHIST=0; HISTSIZE=100
bindkey -e
typeset -g HISTORY_SUBSTRING_SEARCH_HIGHLIGHT_FOUND='' HISTORY_SUBSTRING_SEARCH_HIGHLIGHT_NOT_FOUND='' HISTORY_SUBSTRING_SEARCH_GLOBBING_FLAGS=''
fixture_up() { BUFFER=custom-up; CURSOR=$#BUFFER; }
fixture_down() { BUFFER=custom-down; CURSOR=$#BUFFER; }
fixture_multi() { BUFFER=$'first line\\nsecond line'; CURSOR=16; }
typeset -gi sequence=0 prompt_sequence=0
fixture_snapshot() { (( sequence += 1 )); print -rn -- "$BUFFER"$'\\0'"$CURSOR" > "$HOME/snapshot-$sequence"; print -r -- done > "$HOME/snapshot-$sequence.done"; }
fixture_line_init() { (( prompt_sequence += 1 )); print -r -- $prompt_sequence > "$HOME/prompt-sequence"; }
zle -N fixture-up fixture_up; zle -N fixture-down fixture_down
zle -N fixture-multi fixture_multi; zle -N fixture-snapshot fixture_snapshot
zle -N zle-line-init fixture_line_init
bindkey '^[[A' fixture-up; bindkey '^[[B' fixture-down
bindkey '^X^M' fixture-multi; bindkey '^X^D' fixture-snapshot
PRELOAD
typeset -g saved_bindings=$(bindkey -L)
typeset -g saved_widget=$widgets[fixture-up] saved_insert=$widgets[self-insert]
source WRAPPER || exit 26
typeset -g saved_hooks=$(zle -l -L)
source WRAPPER || exit 27
[[ $(bindkey -L) == $saved_bindings && $widgets[fixture-up] == $saved_widget && $widgets[self-insert] == $saved_insert && $(zle -l -L) == $saved_hooks ]] || exit 28
VERIFY
SEED
MANUAL_BINDINGS
print -r -- ready > "$HOME/ready"
'''.replace('PRELOAD',preload).replace('WRAPPER',q(wrapper)).replace('VERIFY',verify)
    history=['printf plain-last','printf needle-old','printf unrelated','printf needle-new',
             "printf 'quoted [a]*? $HOME $(touch PWNED)'",'printf multi-needle\nprintf second-line']
    setup=setup.replace('SEED','\n'.join('print -sr -- '+q(line) for line in history))
    setup=setup.replace('MANUAL_BINDINGS',"bindkey '^X^U' history-substring-search-up; bindkey '^X^N' history-substring-search-down" if kind in ('editing','coexist') else '')
    source=path/'setup.zsh';source.write_text(setup);terminal=Terminal(zsh,path);snapshots=[]
    try:
        terminal.send(('source '+q(source)+'\n').encode());terminal.wait(lambda:(path/'ready').exists() and (path/'prompt-sequence').exists())
        def reset():
            before=int((path/'prompt-sequence').read_text());terminal.send(b'\x03')
            terminal.wait(lambda:int((path/'prompt-sequence').read_text() or '0')>before)
        def snap(raw):
            number=len(snapshots)+1;target=path/('snapshot-'+str(number));terminal.send(raw+b'\x18\x04');terminal.wait(target.exists)
            terminal.wait(lambda:target.with_name(target.name+'.done').exists())
            data=target.read_bytes();need(len(data)<=4096,'snapshot byte limit');values=data.decode().split('\0');need(len(values)==2,'snapshot shape')
            snapshots.append(dict(input_hex=raw.hex(),buffer=values[0],cursor=int(values[1])));return values[0],int(values[1])
        if kind in ('editing','coexist'):
            need(snap(b'needle\x18\x15')[0]=='printf multi-needle\nprintf second-line','latest substring/multiline history missing')
            need(snap(b'\x18\x15')[0]=='printf needle-new','older substring match missing')
            need(snap(b'\x18\x15')[0]=='printf needle-old','oldest substring match missing')
            need(snap(b'\x18\x0e')[0]=='printf needle-new','forward substring match missing')
            reset()
            literal=b"'quoted [a]*? $HOME $(touch PWNED)'"
            need(snap(literal+b'\x18\x15')[0]==history[4],'literal glob/dollar/quoted search differs')
            reset()
            need(snap(b'unmatched-token\x18\x15')[0]=='unmatched-token','unmatched current input lost')
            reset()
            before=snap(b'\x18\x0d');after=snap(b'\x18\x15')
            need(before[0]==after[0]=='first line\nsecond line' and after[1]<before[1],'current multiline cursor movement differs')
            reset()
        need(snap(b'\x1b[A')[0]=='custom-up','custom ordinary Up binding lost')
        need(snap(b'\x1b[B')[0]=='custom-down','custom ordinary Down binding lost')
        reset();terminal.send(b'exit 0\n');terminal.process.wait(timeout=5)
        need(terminal.process.returncode==0,'natural private Zsh exit failed');preserved(path)
        return dict(exit=0,snapshots=snapshots,output_bytes=len(terminal.output),highlighting=bool(highlight))
    finally:terminal.close();(path/'terminal.log').write_bytes(terminal.output)


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--module-dir',type=Path,required=True)
    parser.add_argument('--work',type=Path,required=True);parser.add_argument('--highlight-wrapper',type=Path);args=parser.parse_args()
    module=args.module_dir.resolve(strict=True);work=args.work.resolve(strict=True);wrapper=module/'opt-in.zsh'
    need(work.is_dir() and work.stat().st_uid==os.getuid() and stat.S_IMODE(work.stat().st_mode)==0o700 and not list(work.iterdir()),'fresh private fixture workspace required')
    need(sha(module/'zsh-history-substring-search.zsh')==UPSTREAM,'exact upstream module hash required')
    zsh=shutil.which('zsh',path='/usr/bin:/bin');need(zsh,'existing Zsh required')
    version=subprocess.run([zsh,'--version'],capture_output=True,timeout=5);need(version.returncode==0 and len(version.stdout)<4096,'Zsh identity query')
    report=dict(status='FAIL',host_architecture=platform.machine(),zsh_version=version.stdout.decode().strip(),zsh_sha256=sha(Path(zsh).resolve()),
        upstream_sha256=UPSTREAM,wrapper_sha256=sha(wrapper),tests=[],native_ARM='NOT RUN',page16K='NOT RUN',hardware='NOT RUN',system_install='NOT RUN')
    cases=[('noninteractive',lambda:noninteractive(zsh,wrapper,work))]
    cases.extend((name,lambda name=name:interactive(zsh,wrapper,work,name)) for name in ('editing','preexisting-function','preexisting-widget','preexisting-private'))
    if args.highlight_wrapper:cases.append(('coexist',lambda:interactive(zsh,wrapper,work,'coexist',args.highlight_wrapper.resolve(strict=True))))
    for name,check in cases:
        try:report['tests'].append(dict(name=name,status='PASS',**check()))
        except Exception as error:report['tests'].append(dict(name=name,status='FAIL',reason=str(error)[:256],error_type=type(error).__name__))
    if all(row['status']=='PASS' for row in report['tests']):report['status']='PASS_HOST_ZSH_PTY_CONTROLS'
    (work/'receipt.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps(dict(status=report['status'],cases=len(cases),host_architecture=report['host_architecture'])))
    return int(report['status']=='FAIL')


if __name__=='__main__':
    def interrupted(*_):raise KeyboardInterrupt
    signal.signal(signal.SIGTERM,interrupted)
    raise SystemExit(main())
