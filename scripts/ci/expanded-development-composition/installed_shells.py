#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed installed-path adapter for Root's bounded six-case coexistence driver."""
import argparse
import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import types
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

RUNTIME={
 'bang':'/usr/share/cachy-asahi/fish-bang-bang/opt-in.fish',
 'autopair':'/usr/share/cachy-asahi/fish-autopair/opt-in.fish',
 'done':'/usr/share/cachy-asahi/fish-done/opt-in.fish',
 'autosuggest':'/usr/share/cachy-asahi/zsh-autosuggestions/opt-in.zsh',
 'highlight':'/usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh',
 'substring':'/usr/share/cachy-asahi/zsh-history-substring-search/opt-in.zsh'}
CASES={'fish-bang-auto-done','fish-done-auto-bang','zsh-auto-highlight-substring',
       'zsh-highlight-substring-auto','fish-noninteractive','zsh-noninteractive'}


def installed_join(source,driver):
    # Every runtime source belongs to the same immutable source closure as the fixtures.
    # package() relocates only highlighting's files; no package recipe is evaluated.
    for key,relative in {**driver.FISH,**driver.ZSH}.items():
        directory=source/Path(relative).parent;target=Path(RUNTIME[key]).parent
        sources=__import__('shlex').split(__import__('re').search(r'^source=\((.*?)\)',
                    (directory/'PKGBUILD').read_text(),__import__('re').M|__import__('re').S)[1])
        runtime=[]
        for name in sources:
            if name.endswith(('.fish','.zsh')) or name in ('.version','.revision-hash'):
                installed=target/name
                if key=='highlight' and name.endswith('-highlighter.zsh'):
                    installed=target/'highlighters'/name.removesuffix('-highlighter.zsh')/name
                C.need(installed.is_file() and not installed.is_symlink() and C.sha(installed)==C.sha(directory/name),
                       'actual installed shell input differs: '+str(installed));runtime.append(str(installed))
        C.need(runtime,'runtime source join is empty')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();source=C.safe(args.source);root=C.safe(args.output)
    C.need(os.getuid()>0 and platform.machine()=='aarch64' and Path('/.dockerenv').is_file() and
           not Path('/dev/snd').exists() and not root.exists(),'ordinary installed native container user required')
    root.mkdir(mode=0o700)
    driver=C.load('expanded_host_coexistence',source/'scripts/ci/shell-modules-coexistence/run.py')
    frozen,pins=driver.freeze_inputs(source,root)
    installed_join(frozen,driver)
    D=types.ModuleType('expanded_done_fixture');fixture=frozen/'packages/tools/cachy-asahi-fish-done/check-module.py'
    raw=fixture.read_text();anchor="need((home/'bindings-before').read_bytes() == (home/'bindings-after').read_bytes(), 'custom keymap changed')"
    replacement="need(binding_subset(home/'bindings-before',home/'bindings-after'), 'preexisting keymap changed')"
    C.need(raw.count(anchor)==1,'exact accepted Done fixture anchor changed')
    D.__dict__['binding_subset']=driver.binding_subset
    exec(compile(raw.replace(anchor,replacement),str(fixture),'exec'),D.__dict__)
    Z=driver.load('expanded_zsh_fixture',frozen/'packages/tools/cachy-asahi-zsh-history-substring-search/check-module.py')
    raw=inspect.getsource(driver.zsh_case);anchor="(root/'highlight-runtime/opt-in.zsh')"
    C.need(raw.count(anchor)==1,'exact highlighting installed path anchor changed')
    raw=raw.replace(anchor,"Path('/usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh')")
    exec(compile(ast.parse(raw),'<accepted-coexistence-installed-highlight-adapter>','exec'),driver.__dict__)
    driver.FISH={k:RUNTIME[k] for k in driver.FISH};driver.ZSH={k:RUNTIME[k] for k in driver.ZSH}
    report=dict(status='FAIL',scope='ACTUAL_INSTALLED_SIX_MODULES',cases={},runtime=RUNTIME,source_inputs=pins,
        machine=platform.machine(),page_size=os.sysconf('SC_PAGE_SIZE'),uid=os.getuid(),
        notification_delivery='NOT_RUN',notification_scope='PRIVATE_NOTIFY_SEND_RECORDER_ONLY',hardware='NOT_RUN',defaults_enabled=False)
    report['interpreters']={name:dict(version=subprocess.check_output([shutil.which(name),'--version'],timeout=5,text=True).strip(),
        sha256=C.sha(Path(shutil.which(name)).resolve())) for name in ('fish','zsh')}
    jobs=[('fish-bang-auto-done',lambda:driver.fish_case(D,frozen,root,('bang','autopair','done'))),
          ('fish-done-auto-bang',lambda:driver.fish_case(D,frozen,root,('done','autopair','bang'))),
          ('zsh-auto-highlight-substring',lambda:driver.zsh_case(Z,frozen,root,('autosuggest','highlight','substring'))),
          ('zsh-highlight-substring-auto',lambda:driver.zsh_case(Z,frozen,root,('highlight','substring','autosuggest')))]
    jobs += [(shell+'-noninteractive',lambda shell=shell:driver.noninteractive(D,Z,frozen,root,shell)) for shell in ('fish','zsh')]
    def timeout(*_):raise TimeoutError('accepted finite30s coexistence case')
    prior=signal.signal(signal.SIGALRM,timeout)
    try:
        for name,job in jobs:
            signal.setitimer(signal.ITIMER_REAL,30)
            try:report['cases'][name]=job()
            except BaseException as error:report['cases'][name]=dict(status='FAIL',error_type=type(error).__name__,reason=str(error)[:1024])
            finally:signal.setitimer(signal.ITIMER_REAL,0)
    finally:signal.signal(signal.SIGALRM,prior)
    if set(report['cases'])==CASES and all(row['status']=='PASS' for row in report['cases'].values()):
        report['status']='PASS_INSTALLED_SIX_MODULE_SHELL_COEXISTENCE'
    (root/'receipt.json').write_bytes(C.encoded(report))
    return int(report['status']=='FAIL')


if __name__=='__main__':raise SystemExit(main())
