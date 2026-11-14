#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real finite PTY shell journey with delivered payloads, hidden checkout and fresh HOME."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import sys
import tempfile
from types import ModuleType

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from terminal import Terminal,capture,need

PROGRAMS=('fish','zsh','python3','bsdtar','bwrap','ls','mkdir','basename')


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path,cap=8*1024**2,single=True):
    path=Path(path);need(path.is_absolute() and path.resolve()==path,'canonical regular input required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        row=os.fstat(stream.fileno())
        need(stat.S_ISREG(row.st_mode) and (not single or row.st_nlink==1) and 0<=row.st_size<=cap,'bounded ordinary input')
        raw=stream.read(cap+1)
        identity=lambda r:(r.st_dev,r.st_ino,r.st_mode,r.st_nlink,r.st_size,r.st_mtime_ns,r.st_ctime_ns)
        need(len(raw)==row.st_size and identity(row)==identity(os.fstat(stream.fileno()))==identity(path.lstat()),'stable whole input read')
        return raw


def program(name,owner=0):
    path=Path('/usr/bin/'+name).resolve();row=path.stat()
    need(row.st_uid==owner and not row.st_mode&0o022 and row.st_mode&0o111,'safe installed system executable')
    raw=read(path,64*1024**2,single=False)
    identity=lambda r:(r.st_dev,r.st_ino,r.st_mode,r.st_nlink,r.st_size,r.st_mtime_ns,r.st_ctime_ns)
    need(identity(row)==identity(path.stat()),'stable whole executable pin')
    return dict(path=str(path),mode=stat.S_IMODE(row.st_mode),**pin(raw))


def load(path):
    raw=read(path);need(pin(raw)['sha256']=='b693fa64f6a23149df348469587193a2f1eb425b1eb9d68c58fcd2995ad13c76','fixed cancellation helper changed before import')
    module=ModuleType('fixed_onboarding_signals');module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__);return module


def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def q(text):
    text=str(text);need(re.fullmatch('[A-Za-z0-9_./-]+',text) is not None,'fixed journey path grammar');return "'"+text+"'"

def files(root):
    result={}
    for path in root.rglob('*'):
        row=path.lstat();need(row.st_uid==os.geteuid() and row.st_gid==os.getegid() and not row.st_mode&0o022,'private user ownership/mode')
        need(stat.S_ISREG(row.st_mode) or stat.S_ISDIR(row.st_mode),'ordinary user state only')
        item=dict(kind='directory',mode=stat.S_IMODE(row.st_mode),uid=row.st_uid,gid=row.st_gid)
        if path.is_file():item.update(kind='file',**pin(read(path)))
        result[str(path.relative_to(root))]=item
        need(len(result)<=256,'user state count bound')
    return result


def inside(root):
    need(os.geteuid()>0 and os.getegid()>0,'ordinary user only')
    profile=json.loads(read(root/'input/profile.json'));signals=load(root/'driver/onboarding.py')
    need(pin(read(root/'driver/onboarding.py'))==profile['signals'],'fixed cancellation helper pin')
    home,work,out=root/'home',root/'workspace',root/'out'
    need(not any(home.iterdir()) and not any(work.iterdir()),'fresh private HOME/workspace')
    need(not any(Path('/home').iterdir()),'source/real-home hidden before any shell')
    for path,row in profile['payloads'].items():need(pin(read(root/path))==row,'delivered payload/template pin')
    mapped_owner=Path('/usr').stat().st_uid
    need(mapped_owner in (0,65534),'known root ownership mapping in isolated host user namespace')
    program_pins={n:program(n,mapped_owner) for n in PROGRAMS}
    need(program_pins==profile['programs'],'actual host program pins')
    env=dict(HOME=str(home),XDG_CONFIG_HOME=str(home/'.config'),XDG_STATE_HOME=str(home/'.local/state'),XDG_CACHE_HOME=str(home/'.cache'),XDG_DATA_HOME=str(home/'.local/share'),ZDOTDIR=str(home),PATH='/usr/bin:/bin',LC_ALL='C.UTF-8',TZ='UTC',TERM='dumb',CACHY_ASAHI_ZSH_PROMPT='1')
    versions={name:capture(['/usr/bin/'+name,'--version'],env,work,signals)[0].decode().strip() for name in ('fish','zsh','python3')}
    first=root/'input/prefix/usr/bin/cachy-asahi-first-login';setup=root/'input/prefix/usr/bin/cachy-asahi-setup';templates=root/'input/prefix/usr/share/cachy-asahi'
    options=' --setup-helper '+q(setup)+' --home '+q(home)+' --template-root '+q(templates)
    select=' --components fish zsh'
    def cli(operation,*extra):
        argv=[str(first),operation,*extra,'--setup-helper',str(setup),'--home',str(home),'--template-root',str(templates)]
        raw,_=capture(argv,env,work,signals);return json.loads(raw)
    before=files(home);observed=cli('inspect');need(all(r['available'] for r in observed['components'] if r['component'] in ('fish','zsh')),'selected components unavailable')
    cli('activate','--components','fish','zsh');need(files(home)==before,'inspect/preview wrote HOME')
    sessions=[]
    def shell(kind,label,checks,activate=False,remove=False,interrupt=False,user_prompt=None,delivered_prompt=False):
        prompt='CAA_PTY_'+kind.upper()+'> '
        argv=['/usr/bin/fish','--private','--interactive'] if kind=='fish' else ['/usr/bin/zsh','-d','-i']
        with Terminal(label,argv,env,work,out,signals) as terminal:
            if user_prompt:terminal.expect(user_prompt,prompt=True)
            if delivered_prompt:
                terminal.send(b"[[ $PROMPT == '%n@%m %~ %# ' ]] && print -r -- CAA_DELIVERED_ZSH_PROMPT\n",'check-delivered-prompt')
                terminal.expect('CAA_DELIVERED_ZSH_PROMPT',line=True)
            if kind=='fish':terminal.send(b"function fish_prompt; printf 'CAA_PTY_FISH> '; end\n",'set-test-prompt')
            else:terminal.send(b"PROMPT='CAA_PTY_ZSH> '; RPROMPT=''\n",'set-test-prompt')
            terminal.expect(prompt,prompt=True)
            # This Python runs as a real foreground terminal child; no -c shell substitutes.
            identity="import os;assert all(os.isatty(fd) for fd in (0,1,2));assert os.getpgrp()==os.tcgetpgrp(0);print('CAA_TTY_CONFIRMED')"
            terminal.command('/usr/bin/python3 -I -c '+repr(identity),'CAA_TTY_CONFIRMED',prompt)
            if activate:
                terminal.command(q(first)+' activate'+select+' --apply'+options+("; and printf '\\n%s\\n' CAA_ACTIVATED" if kind=='fish' else " && printf '\\n%s\\n' CAA_ACTIVATED"),'CAA_ACTIVATED',prompt)
                need((home/'.config/fish/config.fish').is_file() and (home/'.zshrc').is_file(),'actual activation files absent')
            for command,marker in checks:terminal.command(command,marker,prompt)
            if interrupt:
                code="import time;print('CAA_FOREGROUND_WAIT',flush=True);time.sleep(30)"
                terminal.interrupt('/usr/bin/python3 -I -c '+repr(code),'CAA_FOREGROUND_WAIT',prompt)
                terminal.command("printf '%s\\n' CAA_AFTER_INTERRUPT",'CAA_AFTER_INTERRUPT',prompt)
            if remove:
                roots=' --home '+q(home)+' --template-root '+q(templates)
                terminal.command(q(setup)+' remove'+select+' --apply'+roots+" && printf '\\n%s\\n' CAA_DEACTIVATED",'CAA_DEACTIVATED',prompt)
            terminal.eof()
        sessions.append(terminal.record)
    shell('fish','01-activate',[],activate=True)
    fish="functions -q caa_ll caa_mcd; and caa_ll; and caa_mcd 'pty space'; and test (basename $PWD) = 'pty space'; and printf '%s\\n' CAA_FISH_ACTIVE"
    zsh="[[ -o interactive && $_CACHY_ASAHI_ZSH_LOADED == 1 && ${+_comps} == 1 && -n $_comps[cd] ]] && print -r -- CAA_ZSH_ACTIVE"
    (work/'sentinel-pty').write_text('private journey sentinel\n')
    fish_edit="printf '\\nset -g CAA_USER_KEPT yes\\nfunction fish_prompt; printf \"CAA_USER_FISH> \"; end\\n' >> "+q(home/'.config/fish/config.fish')+"; and printf '%s\\n' CAA_FISH_EDITED"
    shell('fish','02-active-fish',[(fish,'CAA_FISH_ACTIVE'),(fish_edit,'CAA_FISH_EDITED')],interrupt=True)
    need((work/'pty space').is_dir(),'typed Fish helper directory operation missing')
    need(b'sentinel-pty' in read(out/'02-active-fish.pty'),'typed Fish listing omitted workspace sentinel')
    zsh_edit="printf '\\ntypeset -g CAA_USER_KEPT=yes\\nPROMPT=\"CAA_USER_ZSH> \"\\n' >> "+q(home/'.zshrc')+" && print -r -- CAA_ZSH_EDITED"
    shell('zsh','03-active-zsh',[(zsh,'CAA_ZSH_ACTIVE'),(zsh_edit,'CAA_ZSH_EDITED')],interrupt=True,delivered_prompt=True)
    fish_config,zsh_config=home/'.config/fish/config.fish',home/'.zshrc'
    edited={p:p.read_bytes() for p in (fish_config,zsh_config)}
    shell('fish','04-repeat',[(fish+"; test $CAA_USER_KEPT = yes; and printf '%s\\n' CAA_EDIT_KEPT",'CAA_EDIT_KEPT')],activate=True,user_prompt='CAA_USER_FISH> ')
    need(all(p.read_bytes()==raw for p,raw in edited.items()),'repeat changed user edits')
    shell('zsh','05-edit-and-remove',[(zsh+"; [[ $CAA_USER_KEPT == yes ]] && print -r -- CAA_EDIT_KEPT",'CAA_EDIT_KEPT')],remove=True,user_prompt='CAA_USER_ZSH> ')
    user_only={str(p.relative_to(home)):p.read_bytes() for p in (fish_config,zsh_config)}
    need(all(b'CAA_USER_KEPT' in raw for raw in user_only.values()),'deactivation lost user edits')
    shell('fish','06-removed-fish',[("not functions -q caa_ll; and not functions -q caa_mcd; and test $CAA_USER_KEPT = yes; and printf '%s\\n' CAA_FISH_REMOVED",'CAA_FISH_REMOVED')],user_prompt='CAA_USER_FISH> ')
    shell('zsh','07-removed-zsh',[("(( ${+_CACHY_ASAHI_ZSH_LOADED} == 0 )) && [[ $CAA_USER_KEPT == yes ]] && print -r -- CAA_ZSH_REMOVED",'CAA_ZSH_REMOVED')],user_prompt='CAA_USER_ZSH> ')
    need(all((home/p).read_bytes()==raw for p,raw in user_only.items()),'later shell startup changed user edits')
    for path,row in profile['payloads'].items():need(pin(read(root/path))==row,'delivered input changed during journey')
    need({n:program(n,mapped_owner) for n in program_pins}==program_pins,'program changed during journey')
    report=dict(status='PASS',scope='extracted pinned host payloads; actual controlling PTY prompts/commands; checkout/real HOME hidden',host_architecture=platform.machine(),page_size=os.sysconf('SC_PAGE_SIZE'),uid=os.geteuid(),gid=os.getegid(),mapped_system_owner=mapped_owner,uid_map=Path('/proc/self/uid_map').read_text(),pty_sessions=len(sessions),Ctrl_C_foreground_journeys=2,natural_EOF_exits=len(sessions),source_hidden=True,delivered_zsh_opt_in_prompt=True,typed_user_prompt_edits_preserved=True,program_versions=versions,program_pins=program_pins,input_profile=profile,sessions=sessions,user_edits={n:pin(raw) for n,raw in user_only.items()},final_user_state=files(home),native_arm='NOT RUN',hardware='NOT RUN',graphical_session='NOT RUN',package_installation='NOT RUN',release_acceptance=False)
    save(out/'result.json',report);print(json.dumps(dict(status='PASS',pty_sessions=7,source_hidden=True)))


def stage(first_archive,setup_archive,scratch,signals,root):
    profile=dict(schema=1,archives={},payloads={},programs={},signals=pin(read(root/'scripts/integration/onboarding.py')))
    inp=scratch/'input';(inp/'prefix').mkdir(parents=True,mode=0o700)
    env=dict(PATH='/usr/bin:/bin',LC_ALL='C.UTF-8',HOME=str(scratch/'home'))
    selected=[('first_login',first_archive,'d4b7291afedc2af95d89f3975c77c45e417125bf23818cbfd1dc7d53fb464839',19471,'cachy-asahi-first-login','0.1.0-2',{
        'usr/bin/cachy-asahi-first-login':'a5e2b72ff58eac2763c0ad65f36c0c883a60ce20e97c38acc4bace9d30a18144',
        'usr/lib/cachy-asahi/first-login/first_login.py':'41ade792884afced7a078c6926d3f18d7a9e40fca50191c7d77d34678711921c'}),
        ('setup',setup_archive,'8de3bd0cf2d9333b41925fecdef5cbfe2ec6d40c3424d90746182142e0c7dc47',33900,'cachy-asahi-setup','0.3.0-1',{'usr/bin/cachy-asahi-setup':'724a37c9832d607455aeda1d929f0ee265ce268aecb64be5e00065c1edf85cf0'})]
    for key,archive,sha,size,name,version,members in selected:
        raw=read(archive);need(pin(raw)==dict(bytes=size,sha256=sha),'exact retained package archive required')
        profile['archives'][key]=dict(path=str(archive),**pin(raw),name=name,version=version)
        meta,_=capture(['/usr/bin/bsdtar','-xOf',str(archive),'.PKGINFO'],env,scratch,signals)
        need(('pkgname = '+name+'\n').encode() in meta and ('pkgver = '+version+'\n').encode() in meta and b'arch = any\n' in meta,'exact package identity')
        for member,expected in members.items():
            body,_=capture(['/usr/bin/bsdtar','-xOf',str(archive),member],env,scratch,signals)
            need(pin(body)['sha256']==expected,'exact delivered runtime member')
            target=inp/'prefix'/member;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700);target.write_bytes(body)
            target.chmod(0o755 if '/bin/' in member else 0o644);profile['payloads'][str(target.relative_to(scratch))]=pin(body)
        need(pin(read(archive))==dict(bytes=size,sha256=sha),'archive changed during retained member reads')
    for kind,expected in [('fish','223df59fe83948e1d83676f4571cd2d4ce186862adf1cc23da6d5bbd28370a1c'),('zsh','7639b938dca689c445b64cc307148e2d3f85c5399d51c8ce69072dcf835baa6f')]:
        body=read(root/('packages/shells/cachy-asahi-'+kind+'-config/config.'+kind));need(pin(body)['sha256']==expected,'exact selected template source')
        target=inp/('prefix/usr/share/cachy-asahi/'+kind+'/config.'+kind);target.parent.mkdir(parents=True,mode=0o700);target.write_bytes(body);target.chmod(0o644)
        profile['payloads'][str(target.relative_to(scratch))]=pin(body)
    for name in PROGRAMS:profile['programs'][name]=program(name)
    driver=scratch/'driver';driver.mkdir(mode=0o700)
    for name in ('journey.py','terminal.py'):shutil.copyfile(HERE/name,driver/name)
    shutil.copyfile(root/'scripts/integration/onboarding.py',driver/'onboarding.py')
    save(inp/'profile.json',profile);return profile


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside',type=Path,help=argparse.SUPPRESS)
    parser.add_argument('--first-login-archive',type=Path);parser.add_argument('--setup-archive',type=Path)
    parser.add_argument('--output',type=Path);parser.add_argument('--run-temporary-pty-journey',action='store_true')
    args=parser.parse_args()
    if args.inside:
        signals=load(args.inside/'driver/onboarding.py');signal.signal(signal.SIGTERM,signals.interrupt)
        inside(args.inside);return 0
    need(args.run_temporary_pty_journey and args.output and args.first_login_archive and args.setup_archive,'explicit temporary PTY operation and retained archives/output required')
    need(os.geteuid()>0 and os.getegid()>0,'ordinary user only')
    root=HERE.parents[2];signals=load(root/'scripts/integration/onboarding.py')
    need(pin(read(root/'scripts/integration/onboarding.py'))['sha256']=='b693fa64f6a23149df348469587193a2f1eb425b1eb9d68c58fcd2995ad13c76','frozen cancellation helper changed')
    previous=signal.signal(signal.SIGTERM,signals.interrupt)
    output=args.output;need(output.is_absolute() and output.resolve()==output,'canonical fresh output path');output.mkdir(mode=0o700)
    report=dict(status='FAIL',native_arm='NOT RUN',hardware='NOT RUN',release_acceptance=False)
    scratch=Path(tempfile.mkdtemp(prefix='first-login-pty-',dir='/var/tmp'));clean=False
    try:
        for name in ('home','workspace','out'):(scratch/name).mkdir(mode=0o700)
        profile=stage(args.first_login_archive,args.setup_archive,scratch,signals,root)
        argv=['/usr/bin/bwrap','--unshare-user','--unshare-pid','--unshare-net','--die-with-parent','--ro-bind','/','/','--tmpfs','/home','--tmpfs','/tmp','--proc','/proc','--dev','/dev','--bind',str(scratch),'/tmp/work','--ro-bind',str(scratch/'input'),'/tmp/work/input','--ro-bind',str(scratch/'driver'),'/tmp/work/driver','--chdir','/tmp/work/workspace','--clearenv','--setenv','PATH','/usr/bin:/bin','--setenv','LC_ALL','C.UTF-8','/usr/bin/python3','-I','-B','/tmp/work/driver/journey.py','--inside','/tmp/work']
        stdout,stderr=capture(argv,dict(PATH='/usr/bin:/bin',LC_ALL='C.UTF-8'),scratch,signals,seconds=180)
        (output/'driver.stdout').write_bytes(stdout);(output/'driver.stderr').write_bytes(stderr)
        report=json.loads(read(scratch/'out/result.json'));need(report['status']=='PASS','inner PTY journey failed')
        for p in (scratch/'out').iterdir():shutil.copyfile(p,output/p.name)
        save(output/'invocation.json',dict(argv=argv,programs=profile['programs'],input_profile=profile,driver_sha256=pin(read(HERE/'journey.py')),terminal_sha256=pin(read(HERE/'terminal.py')),source_hidden=True))
        clean=True;report['owned_private_workspace_removed']=True
        return 0
    except BaseException as error:
        report.update(error=type(error).__name__+': '+str(error),retained_failure_workspace=str(scratch))
        if hasattr(error,'pty_capture_stdout'):
            (output/'driver.stdout').write_bytes(error.pty_capture_stdout);(output/'driver.stderr').write_bytes(error.pty_capture_stderr)
        for p in (scratch/'out').iterdir():shutil.copyfile(p,output/p.name)
        raise
    finally:
        if clean:shutil.rmtree(scratch)
        save(output/'result.json',report);signal.signal(signal.SIGTERM,previous)


if __name__=='__main__':raise SystemExit(main())
