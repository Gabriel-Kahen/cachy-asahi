#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Ordinary-user installed CLI controls; inert module fixtures, no shell execution."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

CLI='/usr/bin/cachy-asahi-setup'
MODULES=('fish-bang-bang','fish-autopair','fish-done','zsh-autosuggestions','zsh-syntax-highlighting','zsh-history-substring-search')
BASE=('fish','zsh','hyprland')
CRASH='''import importlib.machinery,importlib.util,os,sys
from pathlib import Path
loader=importlib.machinery.SourceFileLoader('installed_setup',sys.argv[1]);m=importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name,loader));loader.exec_module(m)
e=m.Setup(Path(sys.argv[2]),Path(sys.argv[3]));original=e.fs.atomic
checkpoint=e.state_path if sys.argv[4]=='commit' else e.targets['fish']
def atomic(path,data,expected,private=False):
 if path==checkpoint and sys.argv[4]=='before':os._exit(71)
 original(path,data,expected,private)
 if path==checkpoint and sys.argv[4]!='before':os._exit(71)
e.fs.atomic=atomic
e.run(sys.argv[5],sys.argv[6:],True)
'''


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(root):
    rows={}
    for path in sorted(root.rglob('*')):
        need(len(rows)<128,'bounded private user tree required');info=path.lstat()
        need(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode),'unexpected private fixture node')
        rows[str(path.relative_to(root))]=(info.st_mode,info.st_uid,info.st_gid,info.st_mtime_ns,os.readlink(path) if path.is_symlink() else sha(path) if path.is_file() else None)
    return rows


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--phase',choices=('legacy','upgrade','rollback','forward'),required=True);p.add_argument('--profile',required=True);p.add_argument('--home',type=Path,required=True);p.add_argument('--templates',type=Path,required=True);p.add_argument('--missing',type=Path,required=True);p.add_argument('--helper-sha256',required=True);a=p.parse_args()
    need(os.getuid()==os.geteuid()>0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_ASAHI_SETUP6_USER')=='1','dedicated ordinary native container user required')
    need(sha(Path(CLI))==a.helper_sha256,'actual installed CLI identity differs')
    home=a.home;templates=a.templates;cases={}
    env=dict(PATH='/usr/bin:/bin',HOME=str(home),LANG='C.UTF-8',LC_ALL='C.UTF-8',XDG_CONFIG_HOME=str(home/'.config'),XDG_STATE_HOME=str(home/'.local/state'),XDG_DATA_HOME=str(home/'.local/share'),XDG_CACHE_HOME=str(home/'.cache'),ZDOTDIR=str(home),PYTHONDONTWRITEBYTECODE='1')
    def invoke(operation,components=(),apply=False,expected=0,target=home,root=templates):
        argv=[CLI,operation,'--home',str(target),'--template-root',str(root)]
        if components:argv+=['--components',*components]
        if apply:argv+=['--apply']
        row=subprocess.run(argv,env=env,capture_output=True,timeout=10)
        need(len(row.stdout)+len(row.stderr)<=65536 and row.returncode==expected,'installed setup CLI outcome differs')
        return json.loads(row.stdout) if not row.returncode else row.stderr
    def journal(target=home):return target/'.local/state/cachy-asahi/setup/journal.json'
    def state(target=home):return json.loads((target/'.local/state/cachy-asahi/setup/state.json').read_text())
    def crash(operation,components,point,target=home):
        row=subprocess.run(['/usr/bin/python3','-I','-B','-c',CRASH,CLI,str(target),str(templates),point,operation,*components],env=env,capture_output=True,timeout=10)
        need(row.returncode==71 and not row.stdout and not row.stderr and journal(target).is_file(),'actual installed helper interruption checkpoint absent')
    nested=home/'new-interruption'
    if a.phase=='legacy':
        before=snapshot(home);invoke('activate',BASE);need(snapshot(home)==before,'legacy preview wrote user state')
        if a.profile in ('state','new-grouped-journal'):invoke('activate',BASE,True)
        elif a.profile=='remove-journal':invoke('activate',BASE,True);crash('remove',(),'after')
        else:crash('activate',BASE,{'journal-before':'before','journal-after':'after','journal-commit':'commit'}[a.profile])
        cases['legacy-state-journal']='PASS'
    elif a.phase=='upgrade':
        if journal().exists():invoke('recover',apply=True);need(not journal().exists(),'legacy journal was not retired')
        invoke('activate',BASE,True);old={k:v for k,v in state()['components'].items()}
        before=snapshot(home);invoke('activate',MODULES);need(snapshot(home)==before,'module preview wrote')
        cases['preview-readonly']='PASS';invoke('activate',tuple(reversed(MODULES)),True)
        need(set(state()['components'])==set(BASE+MODULES) and all(state()['components'][k]==v for k,v in old.items()),'new module selection lost legacy ownership')
        cases['apply']='PASS';before=snapshot(home);invoke('activate',MODULES,True);need(snapshot(home)==before,'module repeat changed user state');cases['repeat']='PASS'
        for relative,prefix in (('.config/fish/config.fish','# original custom Fish\n'),('.zshrc','# original custom Zsh\n')):
            path=home/relative;need(path.read_text().startswith(prefix) and stat.S_IMODE(path.stat().st_mode)==0o640,'custom config bytes/mode lost')
        text=(home/'.zshrc').read_text();positions=[text.index('# >>> cachy-asahi setup '+n+' v1 >>>') for n in MODULES[3:]];need(positions==sorted(positions),'highlighting-before-substring order absent');cases['custom-config']='PASS'
        before=snapshot(home)
        for apply,key in ((False,'missing-preview'),(True,'missing-module')):
            error=invoke('activate',MODULES,apply,1,root=a.missing);need(b'zsh-history-substring-search' in error and snapshot(home)==before,'missing selected module mutated state or lacked named refusal');cases[key]='PASS'
        fish=home/'.config/fish/config.fish';text=fish.read_text();source='    source '+str(templates/'fish-done/opt-in.fish')
        need(text.count(source)==1,'owned Done fixture block absent');fish.write_text(text.replace(source,'    # user edited module source',1))
        before=snapshot(home);invoke('remove',('fish-done',),True,2);need(snapshot(home)==before,'edited module was overwritten');cases['edited-module']='PASS'
        nested.mkdir(mode=0o700);crash('activate',MODULES,'after',nested)
        need(journal(nested).is_file(),'new grouped journal absent');cases['legacy-state-journal']='PASS'
    elif a.phase=='rollback':
        before=snapshot(home);invoke('remove',apply=True,expected=1);invoke('recover',apply=True,expected=1,target=nested)
        need(snapshot(home)==before,'old CLI rollback changed new ownership/journal');cases['rollback-refusal']='PASS'
    else:
        invoke('recover',apply=True,target=nested);need(not journal(nested).exists() and set(state(nested)['components'])==set(MODULES),'new grouped interruption did not recover')
        before=snapshot(nested);invoke('activate',MODULES,True,target=nested);need(snapshot(nested)==before,'recovered module repeat changed')
        cases['new-interruption-recovery']='PASS'
        # Keep the deliberate primary user edit and ownership; no reset/ignore.
        before=snapshot(home);invoke('remove',('fish-done',),True,2);need(snapshot(home)==before,'forward upgrade lost conflict preservation')
    print(json.dumps(dict(status='PASS',phase=a.phase,profile=a.profile,cases=cases,uid=os.getuid(),installed_helper_sha256=sha(Path(CLI)),fixture_scope='INERT_NAMESPACED_MODULE_FIXTURES_ONLY')))


if __name__=='__main__':main()
