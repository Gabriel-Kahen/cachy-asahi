#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One signed TEST package lifecycle and installed Zsh fixtures in disposable ARM Docker."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import tempfile

NAME='cachy-asahi-zsh-syntax-highlighting'
WRAPPER='/usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh'


def need(value,message):
    if not value:raise ValueError(message)


def run(args,data=None):
    p=subprocess.run(args,input=data,text=True,stdin=None if data is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=45)
    need(len(p.stdout)<=131072 and p.returncode==0,'fixed child command refused')
    return p.stdout


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory():return ''.join(sorted(run(['pacman','-Q']).splitlines(True)))


def fingerprint(home):
    return {str(p.relative_to(home)):(sha(p),stat.S_IMODE(p.stat().st_mode),p.stat().st_uid,p.stat().st_gid)
            for p in home.rglob('*') if p.is_file()}


def main():
    need(os.getuid()==0 and os.getpid()==1 and Path('/.dockerenv').is_file() and
         os.uname().machine=='aarch64','disposable native ARM container PID1 required')
    source=Path('/inputs');plan=json.loads((source/'package.json').read_text())
    need(plan['name']==NAME and len(plan['payload'])==17,'fixed single package required')
    archive=source/plan['archive'];need(archive.name==plan['archive'] and sha(archive)==plan['sha256'],'archive binding differs')
    base=(source/'packages.lock').read_text();need(len(base.splitlines())==574 and inventory()==base,'exact574 before inventory differs')
    expected=''.join(sorted((base+NAME+' '+plan['version']+'\n').splitlines(True)))
    result={'status':'FAIL','phase':'private-test-signing','baseline':574,'installed':575,
            'upgrade':'NOT RUN','boot_recovery':'NOT RUN','target':'NOT RUN','checkpoints':[]}
    with tempfile.TemporaryDirectory(prefix='highlighting-',dir='/tmp') as temporary:
        work=Path(temporary);signing=work/'test-signing';trust=work/'trust';hooks=work/'hooks'
        for path in (signing,trust,hooks):path.mkdir(mode=0o700)
        package=work/archive.name;shutil.copyfile(archive,package);need(sha(package)==plan['sha256'],'copied archive differs')
        gpg=['gpg','--batch','--no-options','--homedir',str(signing),'--no-auto-key-retrieve',
             '--pinentry-mode','loopback','--passphrase','']
        run(gpg+['--quick-generate-key','TEST ONLY Zsh highlighting <highlighting@test.invalid>','ed25519','sign','1d'])
        fingerprints=[l.split(':')[9] for l in run(gpg+['--with-colons','--list-keys']).splitlines() if l.startswith('fpr:')]
        need(len(fingerprints)==1 and re.fullmatch('[0-9A-F]{40}',fingerprints[0]),'one TEST signer required')
        public=work/'TEST-public.asc';public.write_text(run(gpg+['--armor','--export',fingerprints[0]]))
        run(gpg+['--output',str(package)+'.sig','--detach-sign',str(package)])
        verifier=['gpg','--batch','--no-options','--homedir',str(trust),'--no-auto-key-retrieve']
        run(verifier+['--import',str(public)]);run(verifier+['--import-ownertrust'],fingerprints[0]+':6:\n')
        run(verifier+['--verify',str(package)+'.sig',str(package)])
        result.update(test_signer=fingerprints[0],signature_sha256=sha(Path(str(package)+'.sig')))
        for directory in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks'):
            for hook in Path(directory).glob('*.hook'):
                need(re.fullmatch(r'[A-Za-z0-9_.@+-]+\.hook',hook.name),'unexpected hook name')
                target=hooks/hook.name
                if not target.is_symlink():target.symlink_to('/dev/null')
        conf=work/'pacman.conf';conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\n'
            'LocalFileSigLevel = Required\nGPGDir = '+str(trust)+'\nHookDir = '+str(hooks)+'\n')
        pacman=['pacman','--config',str(conf)]
        alarm=pwd.getpwnam('alarm');homes=[]
        for label in ('fresh','existing'):
            home=work/label;home.mkdir(mode=0o700)
            if label=='existing':
                for name,text in (('.zshrc','# existing user choices\n'),('.zsh_history','print preserved-history\n')):
                    (home/name).write_text(text);(home/name).chmod(0o600)
            for p in (home,*home.rglob('*')):os.chown(p,alarm.pw_uid,alarm.pw_gid)
            homes.append((home,fingerprint(home)))
        # Only this fixture workspace is traversable by its unprivileged test user.
        work.chmod(0o711)
        terminals=work/'terminal-fixtures';terminals.mkdir(mode=0o700);os.chown(terminals,alarm.pw_uid,alarm.pw_gid)
        def shell(home,code):
            return run(['runuser','-u','alarm','--','env','-i','PATH=/usr/bin:/bin','TERM=xterm',
                'HOME='+str(home),'ZDOTDIR='+str(home),'LC_ALL=C','zsh','-f','-i','-c',code])
        def preserved():
            need(all(fingerprint(h)==old for h,old in homes),'user startup/history/configuration changed')
        for label,operation in (('install','-U'),('remove','-R'),('reinstall','-U'),('remove-final','-R')):
            result['phase']=label
            run(pacman+['--noconfirm','--noscriptlet',operation,str(package) if operation=='-U' else NAME])
            need(inventory()==(expected if operation=='-U' else base),'transaction inventory differs')
            if operation=='-U':
                run(pacman+['-Dk']);run(pacman+['-Qkk',NAME])
                for relative,row in plan['payload'].items():
                    path=Path('/')/relative;node=path.lstat()
                    need(stat.S_ISREG(node.st_mode) and stat.S_IMODE(node.st_mode)==row['mode'] and
                         node.st_uid==node.st_gid==0 and sha(path)==row['sha256'],'installed payload differs')
                    need(run(pacman+['-Qoq',str(path)]).strip()==NAME,'installed file owner differs')
                for home,_ in homes:
                    shell(home,'source '+WRAPPER+'; source '+WRAPPER+'; (( ${+functions[_zsh_highlight]} ))')
                raw=run(['runuser','-u','alarm','--','env','-i','PATH=/usr/bin:/bin','LC_ALL=C','HOME='+str(terminals),
                    'python3','-I','-B','/terminal.py','--wrapper',WRAPPER,
                    '--autosuggestions','/fixture-autosuggestions/opt-in.zsh','--work-root',str(terminals)])
                terminal=json.loads(raw);need(terminal['status']=='PASS' and terminal['architecture']=='aarch64' and
                    terminal['native_ARM_Zsh_terminal'] is True and len(terminal['tests'])==5 and
                    all(r['status']=='PASS' for r in terminal['tests']),'installed native terminal fixtures failed')
                result[label+'_terminal']=terminal
            else:
                need(all(not os.path.lexists('/'+n) for n in plan['payload']),'package-owned path remained')
                for home,_ in homes:
                    shell(home,'[[ ! -r '+WRAPPER+' ]] || source '+WRAPPER+'; (( ! ${+functions[_zsh_highlight]} ))')
            preserved();result['checkpoints'].append({'operation':label,'inventory':575 if operation=='-U' else 574,
                                                       'user_files_preserved':True,'status':'PASS'})
        for directory in (signing,trust):run(['gpgconf','--homedir',str(directory),'--kill','all'])
        result.update(status='PASS',phase='exact574-restored',final_inventory_sha256=hashlib.sha256(base.encode()).hexdigest())
    print(json.dumps(result,sort_keys=True))


if __name__=='__main__':main()
