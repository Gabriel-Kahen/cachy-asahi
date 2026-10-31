#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real ALPM install/remove/reinstall and ordinary-user CLI/ZLE checks."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def main():
    C=load('tools_lifecycle_contract','/runner/contract.py')
    L=load('accepted_welcome_preservation','/accepted/lifecycle.py')
    L.need(os.getuid()==0 and os.getpid()==1 and Path('/.dockerenv').is_file() and os.uname().machine=='aarch64' and
           os.environ.get('CACHY_ASAHI_TOOLS_LIFECYCLE')=='1','dedicated native ARM container PID1 required')
    original=json.loads(Path('/inputs/base.json').read_text());products=json.loads(Path('/inputs/products.json').read_text())
    L.need(set(products)==set(C.NAMES) and len(original)==574 and L.inventory()==original,'exact574/three tool inputs required')
    for name,row in products.items():
        archive=Path('/inputs')/row['archive']
        L.need(archive.parent==Path('/inputs') and archive.is_file() and not archive.is_symlink() and
               L.sha(archive)==row['sha256'] and set(row['payload'])==set(C.files(name)),'exact archive/payload input required')
    hooks=Path('/tmp/tools-hooks');hooks.mkdir();masked=set()
    for parent in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks','/builder-disabled-hooks'):
        for path in Path(parent).glob('*.hook'):
            if path.name not in masked:(hooks/path.name).symlink_to('/dev/null');masked.add(path.name)
    config=Path('/tmp/tools-pacman.conf');config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Optional\nHookDir = '+str(hooks)+'\n')
    pacman=['/usr/bin/pacman','--config',str(config),'--noconfirm','--noscriptlet']
    protected={p:L.entry(p) for p in (Path('/etc/pacman.conf'),Path('/etc/pacman.d/mirrorlist'),Path('/etc/zsh/zshrc')) if os.path.lexists(p)}
    account=pwd.getpwnam('alarm');homes=[];sessions={};output_pins={};events=[]
    for kind in ('fresh','existing'):
        home=Path('/tmp')/('tools-home-'+kind);home.mkdir(mode=0o700)
        if kind=='existing':
            for name,text in (('.zshrc','# preserve custom bindings, theme, opt-ins\nbindkey -e\n'),
                              ('.zshenv','# preserve environment\n'),('.zsh_history','preserve history bytes\n'),
                              ('.config/pacman-mirrors/user-sentinel','preserve mirror preference\n')):
                path=home/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text);path.chmod(0o600)
            (home/'.config/alias').symlink_to('pacman-mirrors/user-sentinel')
        output=Path('/tmp')/('tools-output-'+kind);output.mkdir(mode=0o700);(output/'outside').write_text('preserve outside\n')
        sessions[home]=L.session_paths(home,output)
        for path in (home,*home.rglob('*'),output,*output.rglob('*')):os.chown(path,account.pw_uid,account.pw_gid,follow_symlinks=False)
        homes.append((home,L.snapshot(home),output,L.entry(output/'outside')))

    def user(home,argv,expected=0):
        environment=L.user_environment(home,sessions[home]);environment['TERM']='xterm'
        return L.command(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',
            *(key+'='+value for key,value in environment.items()),*argv],expected=expected,timeout=70)

    def preserve():
        for home,before,output,outside in homes:L.preservation_check(home,before,output,outside)
        L.need(all(L.entry(path)==pin for path,pin in protected.items()),'system mirror/Zsh configuration changed')
        L.need(all(L.entry(path)==pin for path,pin in output_pins.items()),'user candidate or receipt changed')

    def installed(label):
        desired=original|{n:products[n]['version'] for n in C.NAMES}
        L.need(L.inventory()==desired,'exact577 installed inventory differs')
        for name in C.NAMES:
            L.command(['/usr/bin/pacman','-Qkk',name]);owned=L.command(['/usr/bin/pacman','-Qql',name]).splitlines()
            L.need({p for p in owned if not p.endswith('/')}=={'/'+p for p in products[name]['payload']},'ownership list differs')
            for relative,row in products[name]['payload'].items():
                path=Path('/')/relative;info=path.lstat()
                L.need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==row['mode'] and info.st_uid==info.st_gid==0 and
                       L.sha(path)==row['sha256'],'installed exact source/license hash differs')
        observations=[]
        for home,_,output,_ in homes:
            work=output/label;work.mkdir(mode=0o700);os.chown(work,account.pw_uid,account.pw_gid)
            for name in ('mirrors','highlighting','substring'):
                directory=work/name;directory.mkdir(mode=0o700);os.chown(directory,account.pw_uid,account.pw_gid)
            mirrors=json.loads(user(home,['/usr/bin/python3','-I','-B','/runner/mirror_fixture.py',str(work/'mirrors')]))
            highlighting=json.loads(user(home,['/usr/bin/python3','-I','-B','/runner/highlighting_fixture.py',str(work/'highlighting')]))
            substring=json.loads(user(home,['/usr/bin/python3','-I','-B','/inputs/sources/'+C.NAMES[2]+'/check-module.py',
                '--module-dir','/usr/share/cachy-asahi/zsh-history-substring-search','--work',str(work/'substring'),
                '--highlight-wrapper','/usr/share/cachy-asahi/zsh-syntax-highlighting/opt-in.zsh']))
            receipt=work/'substring/receipt.json';proof=json.loads(receipt.read_text())
            L.need(proof['status']=='PASS_HOST_ZSH_PTY_CONTROLS' and proof['host_architecture']=='aarch64' and
                   len(proof['tests'])==6 and all(r['status']=='PASS' for r in proof['tests']),'installed substring PTY proof failed')
            for path in (work/'mirrors/candidate',receipt):output_pins[path]=L.entry(path)
            observations.append(dict(home=home.name,mirrors=mirrors,highlighting=highlighting,substring=substring,
                substring_proof=proof,substring_receipt_sha256=L.sha(receipt)))
        preserve();events.append(dict(phase=label,status='PASS',inventory_count=577,observations=observations,config_preserved=True))

    def absent(label):
        L.need(L.inventory()==original,'exact574 inventory not restored')
        for product in products.values():
            for relative in product['payload']:L.need(not os.path.lexists(Path('/')/relative),'removed tool payload remained')
        for home,_,_,_ in homes:
            user(home,['/usr/bin/zsh','-d','-f','-i','-c',
                'for f in /usr/share/cachy-asahi/{zsh-syntax-highlighting,zsh-history-substring-search}/opt-in.zsh; do '+
                '[[ ! -r $f ]] || exit 31; [[ -r $f ]] && source "$f"; done; '+
                '(( ! ${+functions[_zsh_highlight]} && ! ${+functions[history-substring-search-up]} ))'])
        preserve();events.append(dict(phase=label,status='PASS',inventory_count=574,config_preserved=True,guarded_opt_in_absent=True))

    archives=[str(Path('/inputs')/products[n]['archive']) for n in C.NAMES]
    for label in ('install','same-version-reinstall'):L.command(pacman+['-U',*archives]);installed(label)
    L.command(pacman+['-R',*C.NAMES]);absent('remove')
    L.command(pacman+['-U',*archives]);installed('reinstall-after-removal')
    L.command(pacman+['-R',*C.NAMES]);absent('final-remove')
    result=dict(status='PASS_TOOLS_INSTALLED_CLI_PTY_LIFECYCLE',events=events,base_count=574,installed_count=577,
        user_config_preserved=True,system_config_preserved=True,user_outputs_preserved=True,masked_hooks=len(masked),
        actual_page_size=os.sysconf('SC_PAGE_SIZE'),hardware='NOT_RUN',native_architecture='aarch64',
        trust='UNSIGNED_LOCAL_CANDIDATES_ONLY',mirror_network='OWNED_LOOPBACK_TLS_ONLY')
    C.validate_lifecycle(result);Path('/out/lifecycle.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
