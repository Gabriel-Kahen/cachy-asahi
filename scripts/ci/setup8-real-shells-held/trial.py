#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Accepted Setup8 CLIs plus real packaged Fish/Zsh payloads and user files."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import platform
import pty
import select
import shlex
import shutil
import signal
import subprocess
import sys
import termios
import time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C

FISH = '''# existing user Fish profile
if status is-interactive
    set -g fish_greeting
    set -g fish_history ''
    set -g fish_key_bindings fish_default_key_bindings
    if not set -q _user_profile_initialized
        fish_default_key_bindings
        set -g _user_profile_initialized 1
    end
    set -g caa_done_min_duration 80
    function caa_ll; printf USER-LL; end
    function user_function; printf USER-FUNCTION; end
    function fish_prompt; set -g _user_prompt_n (math 0$_user_prompt_n + 1); printf 'USER-FISH> '; printf '%s' $_user_prompt_n > "$HOME/prompt-ready"; end
    function user_binding; commandline --replace custom-key; end
    bind ctrl-g user_binding
end
'''
ZSH = r'''# existing user Zsh profile
if [[ -o interactive ]]; then
  PROMPT='USER-ZSH> '; RPROMPT=''; HISTFILE=$HOME/history; SAVEHIST=0; HISTSIZE=100
  typeset -ga ZSH_AUTOSUGGEST_IGNORE_WIDGETS=(trial-\* zle-\*)
  user_function() { print -rn USER-FUNCTION; }
  user_binding() { BUFFER=custom-key; CURSOR=$#BUFFER; }
  user_precmd() { print -rn -- $(( ++user_prompt_n )) > "$HOME/prompt-ready"; }
  typeset -ga precmd_functions
  (( ${precmd_functions[(Ie)user_precmd]} )) || precmd_functions+=(user_precmd)
  zle -N user-binding user_binding
  bindkey -e; bindkey '^G' user-binding
fi
'''


def environment(home):
    return dict(PATH=str(home/'bin')+':/usr/bin:/bin', HOME=str(home),
        XDG_CONFIG_HOME=str(home/'.config'), XDG_DATA_HOME=str(home/'data'),
        XDG_CACHE_HOME=str(home/'cache'), XDG_STATE_HOME=str(home/'.local/state'),
        ZDOTDIR=str(home), TERM='xterm', LANG='C.UTF-8', LC_ALL='C.UTF-8',
        DBUS_SESSION_BUS_ADDRESS='unix:path='+str(home/'not-a-real-bus'), PYTHONDONTWRITEBYTECODE='1')


class Terminal:
    def __init__(self, shell, home):
        self.master, slave=pty.openpty();self.output=bytearray();self.home=home;self.shell=shell
        def start():
            os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
            import resource
            resource.setrlimit(resource.RLIMIT_CPU,(15,15));resource.setrlimit(resource.RLIMIT_CORE,(0,0))
            resource.setrlimit(resource.RLIMIT_FSIZE,(1024**2,1024**2))
        try:
            argv=[shutil.which(shell),'-i'] if shell=='fish' else [shutil.which(shell),'-d','-i']
            self.process=subprocess.Popen(argv,stdin=slave,stdout=slave,stderr=slave,env=environment(home),cwd=home,preexec_fn=start)
        finally:os.close(slave)

    def send(self, raw):
        C.need(len(raw)<4096 and os.write(self.master,raw)==len(raw),'bounded PTY write')

    def pump(self):
        if select.select([self.master],[],[],.02)[0]:
            try:raw=os.read(self.master,4096)
            except OSError:raw=b''
            self.output.extend(raw);C.need(len(self.output)<131072,'PTY output cap')
            if b'\x1b[6n' in raw:self.send(b'\x1b[1;1R')
            if b'\x1b[0c' in raw:self.send(b'\x1b[?1;2c')

    def wait(self, condition):
        until=time.monotonic()+7
        while not condition():
            C.need(self.process.poll() is None and time.monotonic()<until,'PTY readiness/exit deadline '+str(self.process.poll()))
            self.pump()

    def settle(self):
        until=time.monotonic()+.07
        while time.monotonic()<until:self.pump()

    def reset(self):
        if self.shell=='fish':
            self.send(b'\x05\x15');self.settle();return
        prompt=self.home/'prompt-ready'
        before=int(prompt.read_text());offset=len(self.output)
        self.send(b'\x03')
        def ready():
            try:return int(prompt.read_text())>before and b'\x1b[?2004h' in self.output[offset:]
            except ValueError:return False
        self.wait(ready);self.settle()

    def run(self, script, label):
        marker=self.home/label
        if marker.exists():marker.unlink()
        tail='; printf ready > "$HOME/'+label+'"\n'
        prompt=self.home/'prompt-ready'
        def count():
            try:return int(prompt.read_text())
            except (FileNotFoundError,ValueError):return 0
        before=count();offset=len(self.output)
        self.send((script+tail).encode());self.wait(lambda:marker.exists() and count()>before and b'\x1b[?2004h' in self.output[offset:]);self.settle()

    def close(self):
        try:
            if self.process.poll() is None:
                os.killpg(self.process.pid,signal.SIGTERM)
                try:self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:os.killpg(self.process.pid,signal.SIGKILL);self.process.wait(timeout=2)
        finally:os.close(self.master)


def probe(home, shell, label):
    """Actual startup file, without --no-config/-f, then actual line-editor keys."""
    ready=home/'prompt-ready'
    if ready.exists():ready.unlink()
    before=C.tree(home);term=Terminal(shell,home)
    try:
        term.wait(lambda:ready.exists() and ('USER-'+shell.upper()+'> ').encode() in term.output)
        if shell=='fish':
            term.run('test "$(caa_ll)" = USER-LL; or exit 31; test "$(user_function)" = USER-FUNCTION; or exit 32; functions --query caa_mcd caa_history_bang _autopair_insert_same caa_done_watch; or exit 33; functions fish_prompt > "$HOME/saved-prompt"; function trial_snapshot; printf "%s\\0%s" (commandline | string collect) (commandline --cursor) > "$HOME/key-snapshot"; end; bind ctrl-x trial_snapshot', 'checked')
            def snap(keys):
                path=home/'key-snapshot'
                if path.exists():path.unlink()
                term.send(keys+b'\x18');term.wait(path.exists)
                raw=path.read_bytes();C.need(b'\0' in raw,'complete Fish line snapshot required');return raw.split(b'\0')[0].decode()
            custom=snap(b'\x07');C.need(custom=='custom-key','custom Fish binding replaced')
            term.reset();term.run('true','clear1')
            brackets=snap(b'([{');C.need(brackets=='([{}])','actual packaged Fish pair editing failed')
            term.reset();term.run('builtin history clear','clear2')
            empty=snap(b'!!');C.need(empty=='!!','empty Fish history behavior differs')
            term.reset();term.run('true','clear3')
            marker=home/'notifications.jsonl';n=len(marker.read_text().splitlines()) if marker.exists() else 0
            term.run('sleep .12','slept')
            term.wait(lambda:marker.exists() and len(marker.read_text().splitlines())==n+1)
            term.run('source "$HOME/.config/fish/config.fish"; functions fish_prompt > "$HOME/repeated-prompt"','repeated')
            C.need((home/'saved-prompt').read_bytes()==(home/'repeated-prompt').read_bytes(),'Fish prompt changed on repeated source')
            observations=dict(custom_binding=custom,paired_buffer=brackets,empty_history_buffer=empty,notification_invocations=1)
        else:
            term.run('[[ $(user_function) == USER-FUNCTION && $PROMPT == "USER-ZSH> " ]] || exit 31; (( ${+functions[_zsh_autosuggest_start]} && ${+functions[_zsh_highlight]} && ${+functions[history-substring-search-up]} && ${+ZSH_AUTOSUGGEST_USE_ASYNC} )) || exit 32; typeset -g trial_bindings=$(bindkey -L); trial_snapshot() { print -rn -- "$BUFFER"$\'\\0\'"$POSTDISPLAY"$\'\\0\'"${(j:,:)region_highlight}" > "$HOME/key-snapshot"; }; zle -N trial-snapshot trial_snapshot; bindkey "^X^B" trial-snapshot; bindkey "^X^U" history-substring-search-up; print -sr -- "echo profile-marker"; print -sr -- "printf substring-older"; print -sr -- "printf substring-newer"', 'checked')
            def snap(keys, suggestion=False):
                path=home/'key-snapshot'
                if path.exists():path.unlink()
                term.send(keys)
                # Pump the actual asynchronous worker; no mode override.
                until=time.monotonic()+.25
                while time.monotonic()<until:term.pump()
                term.send(b'\x18\x02');term.wait(path.exists)
                raw=path.read_bytes();C.need(raw.count(b'\0')==2,'complete Zsh line snapshot required');return [p.decode() for p in raw.split(b'\0')]
            custom=snap(b'\x07')[0];C.need(custom=='custom-key','custom Zsh binding replaced')
            term.reset();term.run('true','clear1')
            suggestion=snap(b'echo prof')[1];C.need(suggestion=='ile-marker','actual async autosuggestion differs: '+suggestion)
            term.reset();term.run('true','clear2')
            substring=snap(b'substring\x18\x15')[0];C.need(substring=='printf substring-newer','actual substring key behavior differs')
            term.reset();term.run('true','clear3')
            highlight=snap(b'echo (')[2];C.need(highlight,'actual highlighting produced no regions')
            term.reset();term.run('source "$HOME/.zshrc"; [[ $PROMPT == "USER-ZSH> " ]] || exit 35','repeated')
            observations=dict(custom_binding=custom,async_suggestion=suggestion,substring_buffer=substring,highlight_regions=highlight)
        term.send(b'exit 0\n')
        deadline=time.monotonic()+7
        while term.process.poll() is None:
            C.need(time.monotonic()<deadline,'PTY exit deadline')
            term.pump()
        C.need(term.process.returncode==0,'shell probe exited unsuccessfully')
        return dict(status='PASS',shell=shell,label=label,observations=observations,startup_file_automatically_loaded=True,exit_code=0)
    finally:
        term.close();(home/(shell+'-'+label+'-terminal.log')).write_bytes(term.output)
        for name in ('.zshrc','.config/fish/config.fish'):
            row=before.get(name)
            if row:C.need(C.tree(home)[name]==row,'shell behavior rewrote user configuration')


def noninteractive(home,shell):
    target=home/('.config/fish/config.fish' if shell=='fish' else '.zshrc')
    q=shlex.quote(str(target));before=C.tree(home)
    if shell=='fish':
        script='function caller; source '+q+'; printf continued; end; caller; functions --query caa_mcd caa_history_bang _autopair_insert_same caa_done_watch; and exit 40; true'
        argv=[shutil.which(shell),'--no-config','-c',script]
    else:
        script='caller() { source '+q+'; printf continued; }; caller; (( ! ${+functions[_zsh_autosuggest_start]} && ! ${+functions[_zsh_highlight]} && ! ${+functions[history-substring-search-up]} ))'
        argv=[shutil.which(shell),'-d','-f','-c',script]
    r=C.command(argv,env=environment(home),cwd=home)
    C.need(r.stdout==b'continued' and not r.stderr and C.tree(home)==before,'noninteractive caller/no-op/preservation differs')
    return dict(status='PASS',caller_continued=True,config_unchanged=True,exit_code=0)


def make_trial(context, work, installed=False):
    meta=C.verify_context(context)
    D=C.load(context/'setup-source/test_delivery.py','accepted_setup8_delivery')
    root=Path('/') if installed else context/'stage'
    if installed:
        C.need(platform.machine()=='aarch64' and Path('/.dockerenv').is_file(),'native installed mode requires disposable aarch64 container')
        for relative,row in meta['stage_tree'].items():
            if row['kind']=='file':
                path=Path('/')/relative
                C.need(path.is_file() and not path.is_symlink() and C.digest(path)==row['sha256'] and path.stat().st_uid==0 and (path.stat().st_mode&0o777)==row['mode'],'installed payload join differs: '+relative)
        for name,version in [('cachy-asahi-setup','0.3.0-1')]+[(p['package'],p['version']) for p in meta['packages'].values()]:
            C.need(C.command(['/usr/bin/pacman','-Q',name]).stdout.decode().strip()==name+' '+version,'installed ALPM version differs')
            C.command(['/usr/bin/pacman','-Qkk',name])

    class Trial(D.Delivery):
        def __init__(self):
            super().__init__(root,work)
            # Fixture's finite set only: no production module is changed.
            self.module.ALL_COMPONENTS=C.COMPONENTS
            self.probes=[]

        def setup(self,operation,home,extra=(),expected=0,new=False):
            if operation=='status' and '--components' not in extra:extra=(*extra,'--components',*C.COMPONENTS)
            result=super().setup(operation,home,extra,expected,new)
            if operation=='remove' and expected==0 and home.name in D.PROFILES:
                for shell,prefix in (('fish',FISH),('zsh',ZSH)):
                    path=home/('.config/fish/config.fish' if shell=='fish' else '.zshrc')
                    original='' if home.name=='fresh' else prefix
                    wanted=(original+'# PRIVATE_FIXTURE_CANARY outside managed blocks\n').encode()
                    C.need(path.read_bytes()==wanted,'exact original profile/outside edit not restored')
                    if home.name!='fresh':C.need(path.stat().st_mode&0o777==0o640,'original user mode changed')
                C.need((home/'history').read_bytes()==b'preserved on-disk user history\n','on-disk user history changed')
                self.cases['exact-user-profile-history-restoration']='PASS'
            return result

        def namespace_control(self):
            home=self.work/'namespace-guard';home.mkdir(mode=0o700)
            prefix=ZSH+"bindkey '^X^U' history-substring-search-up\n"
            (home/'.zshrc').write_text(prefix)
            self.setup('activate',home,('--components','zsh',*C.COMPONENTS[5:],'--apply'))
            r=C.command([shutil.which('zsh'),'-d','-i','-c',
                '(( ! ${+functions[history-substring-search-up]} )) || exit 51; [[ $(bindkey "^X^U") == *history-substring-search-up* && $PROMPT == "USER-ZSH> " && $(user_function) == USER-FUNCTION ]] || exit 52'],env=environment(home),cwd=home)
            self.setup('remove',home,('--apply',))
            C.need((home/'.zshrc').read_text()==prefix,'namespace conflict profile was changed')
            self.probes.append(dict(status='PASS',label='preexisting-substring-widget-namespace',activation='DECLINED_EXISTING_NAMESPACE',binding_preserved=True,profile_restored=True))
            self.cases['existing-widget-namespace-preserved']='PASS'

        def initialize(self):
            C.need(not self.work.exists(),'fresh trial work required');self.work.mkdir(mode=0o700)
            for target in (self.old,self.new):shutil.copytree(root/'usr/share/cachy-asahi',target)
            manifest=dict(schema_version=1,id='setup8-real-shell-relocation',package='cachy-asahi-shell-composition',from_version='1.0-1',to_version='1.0-2',entries=[])
            for name in C.COMPONENTS:
                relative=self.module.TEMPLATES[name]
                manifest['entries'].append(dict(component=name,old=dict(root=str(self.old),sha256=C.digest(self.old/relative)),new=dict(root=str(self.new),sha256=C.digest(self.new/relative))))
            C.save(self.manifest_path,manifest)
            for profile in D.PROFILES:
                home=self.work/profile;home.mkdir(mode=0o700)
                (home/'bin').mkdir()
                recorder=home/'bin/notify-send';recorder.write_text('#!/usr/bin/python3\nimport json,os,sys\nwith open(os.environ["HOME"]+"/notifications.jsonl","a") as f:f.write(json.dumps(sys.argv[1:])+"\\n")\n');recorder.chmod(0o700)
                (home/'history').write_bytes(b'preserved on-disk user history\n')
                if profile!='fresh':
                    for relative,raw in (('.config/fish/config.fish',FISH),('.zshrc',ZSH)):
                        path=home/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(raw);path.chmod(0o640)
                before=C.tree(home)
                self.setup('activate',home,('--components',*C.COMPONENTS))
                C.need(C.tree(home)==before,'first-setup preview mutated home')
                self.setup('activate',home,('--components',*C.COMPONENTS,'--apply'))
                before=D.snapshot(home)
                self.setup('activate',home,('--components',*C.COMPONENTS,'--apply'))
                C.need(D.snapshot(home)==before,'real shell repeat activation changed home')
                if profile!='fresh':
                    for shell in ('fish','zsh'):self.probes.append(probe(home,shell,'first-setup'))
            self.namespace_control()
            self.cases['real-payload-first-and-repeat-setup']='PASS'

        def migrate(self,operation,home,expected=0):
            result=super().migrate(operation,home,expected)
            if expected==0 and result['status'] in ('applied','recovered') and home.name!='fresh':
                for shell in ('fish','zsh'):
                    self.probes.append(probe(home,shell,'after-'+operation))
                    self.probes.append(dict(shell=shell,label='noninteractive-'+operation,**noninteractive(home,shell)))
            return result

        def report(self,status):
            result=super().report(status)
            result['cases']={name.replace('installed','delivered'):status for name,status in result['cases'].items()}
            result.update(scope='REAL_PACKAGED_EIGHT_COMPONENT_SHELL_COMPOSITION',components=list(C.COMPONENTS),
                package_installation='NATIVE_ALPM_INSTALLED' if installed else 'HOST_PURE_PACKAGE_STAGE',
                migration_kind='EXACT_PAYLOAD_RELOCATION; NO_CHANGED_UPSTREAM_RELEASE',probes=self.probes,
                notification_scope='PRIVATE_NOTIFY_SEND_INVOCATION_RECORDER; NO_DESKTOP_DELIVERY',
                native_qualification='NATIVE_GENERIC_ARM' if installed else 'NOT_RUN')
            return result
    return Trial()


def run(context,work,installed=False,reinstall=False):
    C.need(os.getuid()==os.geteuid()>0,'ordinary intended user required')
    trial=make_trial(context,work,installed)
    if reinstall:report=trial.verify_reinstall()
    else:report=trial.controls()
    report['status']=('PASS_SETUP8_REAL_SHELL_REINSTALL' if installed else 'PASS_HOST_READONLY_REINSTALL_PROTOCOL_ONLY') if reinstall else 'PASS_SETUP8_REAL_SHELL_COMPOSITION'
    report['versions']={s:C.command([shutil.which(s),'--version']).stdout.decode().strip() for s in ('fish','zsh')}
    report['interpreters']={s:C.digest(Path(shutil.which(s)).resolve()) for s in ('fish','zsh')}
    report['context_sha256']=C.digest(context/'context.json')
    C.save(work/('reinstall-report.json' if reinstall else 'report.json'),report)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('context','work'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--installed',action='store_true');p.add_argument('--verify-reinstall',action='store_true')
    a=p.parse_args();r=run(a.context.absolute(),a.work.absolute(),a.installed,a.verify_reinstall)
    print(json.dumps(r,indent=2))
