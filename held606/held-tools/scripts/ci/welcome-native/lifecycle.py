# SPDX-License-Identifier: MIT
"""Offline product lifecycle, guarded inside the dedicated disposable container."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys

NAMES=('cachy-asahi-welcome','cachy-asahi-doctor')


def need(ok,message):
    if not ok:raise ValueError(message)


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv, *, expected=0, timeout=35):
    value=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    need(len(value.stdout)+len(value.stderr)<=128*1024,'lifecycle command output cap')
    need(value.returncode==expected,'lifecycle command failed: '+argv[0]+': '+value.stderr.decode(errors='replace')[-1024:])
    return value.stdout.decode()


def entry(path):
    info=path.lstat();kind='link' if stat.S_ISLNK(info.st_mode) else 'file' if stat.S_ISREG(info.st_mode) else 'dir'
    need(kind!='dir' or stat.S_ISDIR(info.st_mode),'special configuration entry')
    return dict(kind=kind,mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,
        mtime_ns=info.st_mtime_ns,value=os.readlink(path) if kind=='link' else sha(path) if kind=='file' else None)


def snapshot(root):
    result={}
    for path in sorted(root.rglob('*')):
        need(len(result)<128,'config entry cap')
        result[str(path.relative_to(root))]=entry(path)
    return result


def session_paths(home,output):
    # These are fixture-owned generated paths, not preexisting user settings.
    need(home.is_absolute() and output.is_absolute() and not output.is_relative_to(home) and
         not home.is_relative_to(output),'separate home/session roots required')
    (home/'.config').mkdir(mode=0o700,exist_ok=True)
    session=output/'session';session.mkdir(mode=0o700)
    for name in ('cache','data','state','runtime'):(session/name).mkdir(mode=0o700)
    return session


def user_environment(home,session):
    return dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',HOME=str(home),XDG_CONFIG_HOME=str(home/'.config'),
        XDG_CACHE_HOME=str(session/'cache'),XDG_DATA_HOME=str(session/'data'),XDG_STATE_HOME=str(session/'state'),
        XDG_RUNTIME_DIR=str(session/'runtime'),DISPLAY='',WAYLAND_DISPLAY='',DBUS_SESSION_BUS_ADDRESS='unix:path=/nonexistent')


def preservation_check(home,before,output,outside):
    try:
        after=snapshot(home);current=entry(output/'outside')
    except (OSError,ValueError) as error:
        print(json.dumps(dict(scope='user-preservation',home=home.name,error_kind=type(error).__name__)),flush=True)
        raise ValueError('user config/outside changed') from None
    changed=[]
    for path in sorted(before.keys()|after.keys()):
        fields=['added'] if path not in before else ['removed'] if path not in after else [
            field for field in before[path] if before[path][field]!=after[path][field]]
        if fields:changed.append(dict(path=path,fields=fields))
    outside_fields=[field for field in outside if outside[field]!=current[field]]
    if changed or outside_fields:
        # Paths/field names only: no config contents, link targets or hashes.
        bounded=[row for row in changed if len(row['path'])<=256 and row['path'].isprintable()][:32]
        print(json.dumps(dict(scope='user-preservation',home=home.name,changed=bounded,
            changed_count=len(changed),omitted=len(changed)-len(bounded),outside_fields=outside_fields),sort_keys=True),flush=True)
        raise ValueError('user config/outside changed')


def inventory():
    rows=command(['/usr/bin/pacman','-Q']).splitlines();data=dict(r.split() for r in rows)
    need(len(data)==len(rows),'duplicate package inventory');return data


def main():
    need(os.getuid()==0 and Path('/.dockerenv').is_file() and os.uname().machine=='aarch64' and
         os.environ.get('CACHY_ASAHI_PRODUCT_LIFECYCLE')=='1','dedicated ARM container required')
    original=json.loads(Path('/inputs/base.json').read_text());products=json.loads(Path('/inputs/products.json').read_text())
    need(set(products)==set(NAMES) and len(original)==574 and inventory()==original,'exact574/products required')
    for name in NAMES:
        row=products[name];path=Path('/inputs')/row['archive']
        need(path.parent==Path('/inputs') and path.is_file() and not path.is_symlink() and sha(path)==row['sha256'],
             'exact local development archive required')
    # Mask existing distro hooks only inside this disposable root. No services or cache helpers are invoked.
    hooks=Path('/tmp/product-hooks');hooks.mkdir();masked=set()
    for parent in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks','/builder-disabled-hooks'):
        for path in Path(parent).glob('*.hook'):
            if path.name not in masked:(hooks/path.name).symlink_to('/dev/null');masked.add(path.name)
    config=Path('/tmp/product-pacman.conf')
    config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Optional\nHookDir = '+str(hooks)+'\n')
    pacman=['/usr/bin/pacman','--config',str(config),'--noconfirm','--noscriptlet']
    account=pwd.getpwnam('alarm');homes=[];sessions={};receipts={};events=[]
    for kind in ('fresh','existing'):
        home=Path('/tmp')/('product-home-'+kind);home.mkdir(mode=0o700)
        if kind=='existing':
            for relative,text in (('.config/Thunar/user-sentinel','preserve Thunar\n'),
                                  ('.config/alacritty/alacritty.toml','# preserve terminal\n'),
                                  ('.vimrc','let g:preserved = 1\n')):
                path=home/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text);path.chmod(0o600)
            (home/'.config/alias').symlink_to('Thunar/user-sentinel')
        output=Path('/tmp')/('doctor-output-'+kind);output.mkdir(mode=0o700)
        (output/'outside').write_text('preserve outside report\n')
        sessions[home]=session_paths(home,output)
        for path in (home,*home.rglob('*'),output,*output.rglob('*')):os.chown(path,account.pw_uid,account.pw_gid,follow_symlinks=False)
        homes.append((home,snapshot(home),output,entry(output/'outside')))

    def user(home,argv,expected=0):
        environment=user_environment(home,sessions[home])
        return command(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',
            *(key+'='+value for key,value in environment.items()),*argv],expected=expected)

    def preserved():
        for home,before,output,outside in homes:
            preservation_check(home,before,output,outside)
            for path,pin in receipts.items():
                info=path.lstat()
                need(sha(path)==pin['sha256'] and stat.S_IMODE(info.st_mode)==0o600 and
                     info.st_uid==account.pw_uid and info.st_mtime_ns==pin['mtime_ns'],'user Doctor report changed')

    def installed(label):
        desired=original|{name:products[name]['version'] for name in NAMES}
        need(inventory()==desired,'installed exact576 inventory differs')
        for name in NAMES:
            command(['/usr/bin/pacman','-Qkk',name])
            owned=set(command(['/usr/bin/pacman','-Qql',name]).splitlines())
            expected_files={str(Path('/')/r) for r in products[name]['payload']}
            need({p for p in owned if not p.endswith('/')}==expected_files,'installed file ownership list differs')
            for relative,row in products[name]['payload'].items():
                path=Path('/')/relative;info=path.lstat()
                need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==row['mode'] and
                     info.st_uid==info.st_gid==0 and sha(path)==row['sha256'],'installed payload differs')
        observations=[]
        for home,_,output,_ in homes:
            raw=user(home,['/usr/bin/cachy-asahi-welcome','--status','--json']);data=json.loads(raw)
            need(data['architecture']==os.uname().machine=='aarch64' and data['kernel']==os.uname().release and
                 data['page_size']==os.sysconf('SC_PAGE_SIZE') and data['hardware_compatibility']=='not-assessed',
                 'Welcome actual machine fields differ')
            need(data['schema_version']==1 and data['welcome_version']=='0.1.0' and len(data['packages'])==6,'Welcome schema differs')
            for name,value in data['packages'].items():
                need(value==dict(state='installed' if name in desired else 'not-found',version=desired.get(name)),
                     'Welcome installed package observation differs')
            user(home,['/usr/bin/cachy-asahi-welcome','--status']);user(home,['/usr/bin/cachy-asahi-welcome','--help'])
            need(user(home,['/usr/bin/cachy-asahi-welcome','--version'])=='cachy-asahi Welcome 0.1.0\n','Welcome version differs')
            for guide in ('first-run','updates','recovery'):
                text=user(home,['/usr/bin/cachy-asahi-welcome','--guide',guide])
                need(hashlib.sha256(text.encode()).hexdigest()==products[NAMES[0]]['payload']['usr/share/doc/'+NAMES[0]+'/'+guide+'.txt']['sha256'],
                     'installed guide content differs')
            user(home,['/usr/bin/cachy-asahi-welcome','--guide','../../etc/shadow'],2)
            user(home,['/usr/bin/cachy-asahi-welcome'],1)
            doctor=json.loads(user(home,['/usr/bin/cachy-asahi-doctor','--json']))
            need(doctor.get('schema_version')==1 and doctor.get('tool')==NAMES[1] and doctor.get('scope')=='local observations only',
                 'Doctor schema/scope differs')
            checks={r['check']:r for r in doctor['checks']}
            need(checks['platform']['value']==dict(architecture='aarch64',kernel=os.uname().release,
                 page_size_bytes=os.sysconf('SC_PAGE_SIZE')),'Doctor actual platform differs')
            for name in NAMES:
                need(checks['package/'+name]['state']=='checked' and
                     checks['package/'+name]['value']==dict(group='project',presence='present',version=products[name]['version']),
                     'Doctor installed product observation differs')
            report=output/(label+'.json');published=json.loads(user(home,['/usr/bin/cachy-asahi-doctor','--json','--output',str(report)]))
            need(json.loads(report.read_text())==published and stat.S_IMODE(report.stat().st_mode)==0o600 and
                 report.stat().st_uid==account.pw_uid,'Doctor report publication differs')
            receipts[report]=dict(sha256=sha(report),mtime_ns=report.stat().st_mtime_ns)
            user(home,['/usr/bin/cachy-asahi-doctor','--output',str(report)],2)
            alias=output/(label+'-alias');alias.symlink_to('outside')
            user(home,['/usr/bin/cachy-asahi-doctor','--output',str(alias)],2)
            observations.append(dict(home=home.name,welcome=data,doctor=doctor,report_sha256=receipts[report]['sha256'],
                                     no_overwrite='PASS',report_mode='0600'))
        preserved();events.append(dict(phase=label,status='PASS',inventory_count=576,observations=observations,config_preserved=True))

    def absent(label):
        need(inventory()==original,'exact574 inventory not restored')
        for product in products.values():
            for relative in product['payload']:need(not os.path.lexists(Path('/')/relative),'product payload remained')
        preserved();events.append(dict(phase=label,status='PASS',inventory_count=574,config_preserved=True,reports_preserved=True))

    archives=[str(Path('/inputs')/products[n]['archive']) for n in NAMES]
    for label in ('install','same-version-reinstall'):
        command(pacman+['-U',*archives]);installed(label)
    command(pacman+['-R',*NAMES]);absent('remove')
    command(pacman+['-U',*archives]);installed('reinstall-after-removal')
    command(pacman+['-R',*NAMES]);absent('final-remove')
    result=dict(status='PASS_PRODUCTS_INSTALLED_CLI_LIFECYCLE',events=events,base_count=574,installed_count=576,
                user_config_preserved=True,user_reports_preserved=True,masked_hooks=len(masked),
                GUI='NOT_RUN',hardware='NOT_RUN',actual_page_size=os.sysconf('SC_PAGE_SIZE'))
    Path('/out/lifecycle.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
