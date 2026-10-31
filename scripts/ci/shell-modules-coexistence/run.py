#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite real host PTYs for three Fish and three Zsh opt-in modules together."""
import argparse
import types
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import re
import shlex
import shutil
import subprocess
import time

FISH={'bang':'packages/shells/cachy-asahi-fish-bang-bang/opt-in.fish',
      'autopair':'packages/tools/cachy-asahi-fish-autopair/opt-in.fish',
      'done':'packages/tools/cachy-asahi-fish-done/opt-in.fish'}
ZSH={'autosuggest':'packages/shells/cachy-asahi-zsh-autosuggestions/opt-in.zsh',
     'highlight':'packages/tools/cachy-asahi-zsh-syntax-highlighting/opt-in.zsh',
     'substring':'packages/tools/cachy-asahi-zsh-history-substring-search/opt-in.zsh'}


def need(ok,why):
    if not ok:raise ValueError(why)


def q(value):return shlex.quote(str(value))


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def binding_subset(before,after):
    bindings=lambda p:{line for line in p.read_text().splitlines() if line.startswith('bind ')}
    return bindings(before)<=bindings(after)


def combined(root,name,paths):
    path=root/name;path.write_text('\n'.join('source '+q(p) for p in paths)+'\n');return path


def fish_case(D,source,root,order):
    key='fish-'+'-'.join(order);wrapper=combined(root,key+'.fish',[source/FISH[n] for n in order])
    session=D.Session.__new__(D.Session);observations={};issues=[]
    try:
        session.__init__(shutil.which('fish'),wrapper,root,key)
        home,term=session.home,session.term
        session.run('functions --query caa_history_bang _autopair_insert_same caa_done_watch')
        session.run('set -g coex_n 0; function coex_snapshot; set -g coex_n (math $coex_n + 1); printf "%s\\0%s" (commandline | string collect) (commandline --cursor) > "$HOME/coex-$coex_n"; printf done > "$HOME/coex-$coex_n.done"; end; bind ctrl-x coex_snapshot')
        def snap(keys):
            n=len(observations.get('snapshots',[]))+1;term.send(keys+b'\x18');target=home/f'coex-{n}'
            term.wait(lambda:target.with_suffix('.done').exists());raw=target.read_bytes();need(len(raw)<4096,'snapshot cap');buffer,cursor=raw.split(b'\0')
            row=dict(input_hex=keys.hex(),buffer=buffer.decode(),cursor=int(cursor));observations.setdefault('snapshots',[]).append(row);return row
        def clear():
            marker=home/'custom-binding'
            if marker.exists():marker.unlink()
            term.send(b'\x07');term.wait(marker.exists)
        session.run('builtin history clear')
        need(snap(b'!!')['buffer']=='!!','empty history expansion changed');clear()
        need(snap(b'([{')['buffer']=='([{}])','combined bracket nesting failed');clear()
        need(snap(b'"a\x7f')['buffer']=='""','combined quote deletion failed');clear()
        session.run('set -g fish_history coex')
        previous="printf '%s\\n' 'coex-literal [a]*? $HOME $(touch PWNED)'"
        session.run(previous)
        need(snap(b'!!')['buffer']==previous,'typed previous-command expansion differs');clear()
        before=len(D.rows(home));session.run('sleep .12');result=D.rows(home)
        need(len(result)==before+1,'combined Done did not invoke once');observations['notification']=D.invocation(result[-1])
        session.run('bind --all > "$HOME/repeat-bindings-before"; functions caa_history_bang _autopair_insert_same __done_ended > "$HOME/repeat-functions-before"; functions --handlers > "$HOME/repeat-hooks-before"')
        session.run('function coex_caller; source '+q(wrapper)+'; printf continued > "$HOME/caller-continued"; end; coex_caller')
        observations['caller_continued']=(home/'caller-continued').exists()
        if not observations['caller_continued']:issues.append('repeat sourcing cut off the calling function')
        session.run('bind --all > "$HOME/repeat-bindings-after"; functions caa_history_bang _autopair_insert_same __done_ended > "$HOME/repeat-functions-after"; functions --handlers > "$HOME/repeat-hooks-after"')
        for field in ('bindings','functions','hooks'):
            same=(home/f'repeat-{field}-before').read_bytes()==(home/f'repeat-{field}-after').read_bytes();observations[field+'_preserved']=same
            if not same:issues.append('repeat changed '+field)
        clear();need((home/'custom-binding').read_text()=='CUSTOM-BINDING','custom key lost')
        need('POST sleep .12' in (home/'events').read_text(),'custom postexec hook lost')
        return dict(status='FAIL' if issues else 'PASS',order=list(order),observations=observations,issues=issues)
    finally:
        if hasattr(session,'term'):
            try:
                session.close()
                observations['shell_pid']=session.term.process.pid
                observations['shell_exit']=session.term.process.returncode
            except BaseException:
                session.term.close()
                raise
        if hasattr(session,'home'):need(not (session.home/'PWNED').exists(),'history data executed')


def zsh_case(Z,source,root,order):
    key='zsh-'+'-'.join(order);home=Z.home(root,key);wrapper=combined(root,key+'.zsh',[(root/'highlight-runtime/opt-in.zsh') if n=='highlight' else source/ZSH[n] for n in order]);term=Z.Terminal(shutil.which('zsh'),home);snaps=[]
    setup='''PROMPT='COEX> '; RPROMPT=''; HISTFILE=$HOME/history; SAVEHIST=0; HISTSIZE=100
bindkey -e
fixture_custom() { BUFFER=custom-key; CURSOR=$#BUFFER; }
fixture_snapshot() { (( coex_n += 1 )); print -rn -- "$BUFFER"$'\\0'"$POSTDISPLAY"$'\\0'"$CURSOR"$'\\0'"${(j:,:)region_highlight}" > "$HOME/coex-$coex_n"; print done > "$HOME/coex-$coex_n.done"; }
fixture_init() { (( prompt_n += 1 )); print -r -- $prompt_n > "$HOME/prompt-n"; }
zle -N fixture-custom fixture_custom; zle -N fixture-snapshot fixture_snapshot; zle -N zle-line-init fixture_init
typeset -gi coex_n=0 prompt_n=0
bindkey '^G' fixture-custom; bindkey '^X^B' fixture-snapshot
typeset -g bindings_before=$(bindkey -L)
typeset -ga ZSH_AUTOSUGGEST_IGNORE_WIDGETS=(fixture-\\* zle-\\*)
source WRAPPER || exit 21
unset ZSH_AUTOSUGGEST_USE_ASYNC
(( ${+functions[_zsh_highlight]} && ${+functions[_zsh_autosuggest_start]} && ${+functions[history-substring-search-up]} )) || exit 22
[[ $(bindkey -L) == $bindings_before ]] || exit 23
bindkey '^X^U' history-substring-search-up; bindkey '^X^N' history-substring-search-down
bindkey '^F' autosuggest-accept
typeset -g bindings_before=$(bindkey -L)
print -sr -- 'echo coexistence'
print -sr -- 'printf substring-older'
print -sr -- 'printf substring-newer'
print -sr -- "echo 'literal [a]*? \\$HOME \\$(touch PWNED)'"
print ready > "$HOME/ready"
'''.replace('WRAPPER',q(wrapper))
    # Literal history is inserted as data, never evaluated while seeding it.
    path=home/'setup.zsh';path.write_text(setup)
    try:
        term.send(('source '+q(path)+'\n').encode());term.wait(lambda:(home/'ready').exists() and (home/'prompt-n').exists())
        def reset():
            n=int((home/'prompt-n').read_text());offset=len(term.output);term.send(b'\x03')
            term.wait(lambda:int((home/'prompt-n').read_text() or '0')>n and b'\x1b[?2004h' in term.output[offset:])
            until=time.monotonic()+.05;term.wait(lambda:time.monotonic()>=until)
        def snap(keys):
            n=len(snaps)+1;term.send(keys+b'\x18\x02');target=home/f'coex-{n}';term.wait(lambda:target.with_suffix('.done').exists())
            raw=target.read_bytes();need(len(raw)<4096,'Zsh snapshot cap');buffer,post,cursor,regions=raw.decode().split('\0')
            row=dict(input_hex=keys.hex(),buffer=buffer,suggestion=post,cursor=int(cursor),highlight=regions);snaps.append(row);return row
        # Send typed bytes separately from the snapshot so the real self-insert
        # widget fetches after its input queue drains.
        term.send(b'echo co');until=time.monotonic()+.1;term.wait(lambda:time.monotonic()>=until)
        first=snap(b'');need(first['buffer']=='echo co' and first['suggestion']=='existence','typed history prefix suggestion absent')
        need('memo=zsh-syntax-highlighting' in first['highlight'] and 'fg=' in first['highlight'],'actual highlighting spans absent')
        accepted=snap(b'\x06');need(accepted['buffer']=='echo coexistence' and not accepted['suggestion'],'suggestion acceptance failed');need(bool(accepted['highlight']),'highlighting absent')
        reset();empty=snap(b'');need(not empty['buffer'] and not empty['suggestion'],'empty state suggested')
        need(snap(b'no-match-coex')['suggestion']=='','unmatched prefix suggested');reset()
        need(snap(b'substring\x18\x15')['buffer']=='printf substring-newer','substring newest failed')
        need(snap(b'\x18\x15')['buffer']=='printf substring-older','substring older failed');reset()
        literal=b"'literal [a]*? $HOME $(touch PWNED)'";need(snap(literal+b'\x18\x15')['buffer']=="echo "+literal.decode(),'literal history changed');reset()
        need(snap(b'\x07')['buffer']=='custom-key','custom key behavior changed');reset()
        command='typeset -g saved_suggest=$functions[_zsh_autosuggest_start] saved_highlight=$functions[_zsh_highlight] saved_substring=$functions[history-substring-search-up] saved_custom=$widgets[fixture-custom]; coex_caller() { source '+q(wrapper)+'; print continued > "$HOME/caller-continued"; }; coex_caller; [[ $(bindkey -L) == $bindings_before && $functions[_zsh_autosuggest_start] == $saved_suggest && $functions[_zsh_highlight] == $saved_highlight && $functions[history-substring-search-up] == $saved_substring && $widgets[fixture-custom] == $saved_custom ]] || exit 24; print repeated > "$HOME/repeated"'
        term.send((command+'\n').encode());term.wait(lambda:(home/'repeated').exists());need((home/'caller-continued').exists(),'Zsh caller cut off')
        term.send(b'exit 0\n');term.process.wait(timeout=5);need(term.process.returncode==0,'Zsh normal exit');Z.preserved(home)
        return dict(status='PASS',order=list(order),snapshots=snaps,caller_continued=True,bindings_preserved=True,namespaces_widgets_preserved=True,shell_pid=term.process.pid,shell_exit=0)
    finally:
        term.close();(home/'terminal.log').write_bytes(term.output)


def noninteractive(D,Z,source,root,shell):
    home=D.prepare(root,shell+'-noninteractive') if shell=='fish' else Z.home(root,shell+'-noninteractive')
    paths=FISH if shell=='fish' else ZSH;wrapper=combined(root,shell+'-noninteractive.'+shell,[source/n for n in paths.values()])
    if shell=='fish':
        script='function caller; source '+q(wrapper)+'; printf continued > "$HOME/caller-continued"; end; caller; functions --query caa_history_bang _autopair_insert_same caa_done_watch; and exit 11; true'
        argv=[shutil.which(shell),'--no-config','-c',script];env=D.environment(home)
    else:
        script='caller() { source '+q(wrapper)+'; print continued > "$HOME/caller-continued"; }; caller; (( ! ${+functions[_zsh_autosuggest_start]} && ! ${+functions[_zsh_highlight]} && ! ${+functions[history-substring-search-up]} ))'
        argv=[shutil.which(shell),'-d','-f','-c',script];env=Z.env(home)
    result=subprocess.run(argv,env=env,cwd=home,capture_output=True,timeout=5,preexec_fn=D.limits)
    need(result.returncode==0 and not result.stdout and not result.stderr,'silent noninteractive no-op failed')
    if shell=='fish':D.preserved(home);need(not D.rows(home),'noninteractive notification emitted')
    else:Z.preserved(home)
    preserved=(home/'caller-continued').exists()
    return dict(status='PASS' if preserved else 'FAIL',caller_continued=preserved,config_history_preserved=True,notifications=0,shell_exit=0,issues=[] if preserved else ['noninteractive source cut off caller'])



def freeze_inputs(source,root,overlay=None):
    frozen=root/'source';inputs={};total=0
    for directory in sorted({str(Path(n).parent) for n in (*FISH.values(),*ZSH.values())}):
        selected=overlay/directory if overlay is not None and (overlay/directory).exists() else source/directory
        for file in sorted(selected.iterdir()):
            need(file.is_file() and not file.is_symlink(),'flat ordinary package source required')
            raw=file.read_bytes();total+=len(raw);need(len(raw)<=1024**2 and total<=16*1024**2 and len(inputs)<128,'bounded source closure')
            name=str(Path(directory)/file.name);dest=frozen/name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw)
            inputs[name]=hashlib.sha256(raw).hexdigest();need(file.read_bytes()==raw,'source changed while freezing')
        text=(frozen/directory/'PKGBUILD').read_text()
        sources=shlex.split(re.search(r'^source=\((.*?)\)',text,re.M|re.S)[1]);hashes=shlex.split(re.search(r'^sha256sums=\((.*?)\)',text,re.M|re.S)[1])
        need(len(sources)==len(hashes) and all(inputs[directory+'/'+n]==digest for n,digest in zip(sources,hashes)),'package local source checksum differs')
    return frozen,inputs

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--overlay',type=Path);args=parser.parse_args()
    source=args.source.resolve(strict=True);root=args.output.absolute();need(not root.exists() and not any(p.is_symlink() for p in (root,*root.parents)),'fresh ordinary output required');root.mkdir(mode=0o700,parents=True)
    declared_source=str(source);overlay=args.overlay.resolve(strict=True) if args.overlay else None
    source,inputs=freeze_inputs(source,root,overlay)
    D=types.ModuleType('coex_done_fixture');fixture=source/'packages/tools/cachy-asahi-fish-done/check-module.py';raw=fixture.read_text()
    anchor="need((home/'bindings-before').read_bytes() == (home/'bindings-after').read_bytes(), 'custom keymap changed')"
    replacement="need(binding_subset(home/'bindings-before',home/'bindings-after'), 'preexisting keymap changed')"
    need(raw.count(anchor)==1,'exact reused fixture keymap anchor required')
    D.__dict__['binding_subset']=binding_subset;exec(compile(raw.replace(anchor,replacement),str(fixture),'exec'),D.__dict__)
    Z=load('coex_zsh_fixture',source/'packages/tools/cachy-asahi-zsh-history-substring-search/check-module.py')
    highlight=source/Path(ZSH['highlight']).parent;stage=root/'highlight-runtime';stage.mkdir()
    for name in ('opt-in.zsh','zsh-syntax-highlighting.zsh','.version','.revision-hash'):shutil.copyfile(highlight/name,stage/name)
    for file in highlight.glob('*-highlighter.zsh'):
        target=stage/'highlighters'/file.name.removesuffix('-highlighter.zsh')/file.name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(file,target)
    versions={shell:subprocess.check_output([shutil.which(shell),'--version'],env=D.environment(D.prepare(root,'version-'+shell)),timeout=5,text=True).strip() for shell in ('fish','zsh')}
    report=dict(status='FAIL',versions=versions,interpreter_sha256={shell:hashlib.sha256(Path(shutil.which(shell)).resolve().read_bytes()).hexdigest() for shell in versions},uid=os.getuid(),source=declared_source,module_overlay=str(overlay) if overlay else None,machine=platform.machine(),page_size=os.sysconf('SC_PAGE_SIZE'),inputs=inputs,cases={},native_ARM='NOT_RUN',page16K='NOT_RUN',M2='NOT_RUN',real_notifications='NOT_RUN')
    jobs=[('fish-bang-auto-done',lambda:fish_case(D,source,root,('bang','autopair','done'))),('fish-done-auto-bang',lambda:fish_case(D,source,root,('done','autopair','bang'))),
          ('zsh-auto-highlight-substring',lambda:zsh_case(Z,source,root,('autosuggest','highlight','substring'))),('zsh-highlight-substring-auto',lambda:zsh_case(Z,source,root,('highlight','substring','autosuggest')))]
    jobs.extend((shell+'-noninteractive',lambda shell=shell:noninteractive(D,Z,source,root,shell)) for shell in ('fish','zsh'))
    def deadline(*_):raise TimeoutError('finite30s composed case deadline')
    old_handler=signal.signal(signal.SIGALRM,deadline)
    try:
        for name,job in jobs:
            signal.setitimer(signal.ITIMER_REAL,30)
            try:report['cases'][name]=job()
            except Exception as error:report['cases'][name]=dict(status='FAIL',error_type=type(error).__name__,reason=str(error))
            finally:signal.setitimer(signal.ITIMER_REAL,0)
    finally:signal.signal(signal.SIGALRM,old_handler)
    if all(row['status']=='PASS' for row in report['cases'].values()):report['status']='PASS_HOST_COMPOSED_SHELLS'
    (root/'receipt.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(status=report['status'],cases=len(report['cases']),receipt=str(root/'receipt.json'))));return int(report['status']=='FAIL')


if __name__=='__main__':raise SystemExit(main())
