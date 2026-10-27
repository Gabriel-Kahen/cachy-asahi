#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Five package transitions inside one explicitly guarded disposable ARM root."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import sys


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def main():
    sys.path.insert(0,str(Path(__file__).resolve().parent))
    S=load('mirror_signed_lifecycle',Path(__file__).with_name('signed_lifecycle.py'))
    C=load('mirror_contract','/runner/contract.py');L=load('original_preservation','/accepted/lifecycle.py')
    C.need(os.getuid()==0 and os.getpid()==1 and Path('/.dockerenv').is_file() and os.uname().machine=='aarch64' and
           os.environ.get('CACHY_ASAHI_TOOLS_LIFECYCLE')=='1','dedicated disposable native ARM PID1 required')
    original=json.loads(Path('/inputs/base.json').read_bytes());products=json.loads(Path('/inputs/products.json').read_bytes())
    C.need(len(original)==574 and set(products)==set(C.NAMES) and L.inventory()==original,'exact574/one mirror input required')
    name=C.NAMES[0];product=products[name];archive=Path('/inputs')/product['archive']
    C.need(archive.parent==Path('/inputs') and archive.is_file() and not archive.is_symlink() and C.digest(archive)==product['sha256'] and
           set(product['payload'])==set(C.files(name)),'exact candidate archive required')
    hooks=Path('/tmp/mirrors-hooks');hooks.mkdir();masked=set()
    for parent in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks','/builder-disabled-hooks'):
        for path in Path(parent).glob('*.hook'):
            if path.name not in masked:(hooks/path.name).symlink_to('/dev/null');masked.add(path.name)
    config=Path('/tmp/mirrors-pacman.conf');config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = /tmp/mirrors-TEST-verification/public-keyring\nHookDir = '+str(hooks)+'\n')
    pacman=['/usr/bin/pacman','--config',str(config),'--noconfirm','--noscriptlet']
    protected={p:L.entry(p) for p in (Path('/etc/pacman.conf'),Path('/etc/pacman.d/mirrorlist')) if os.path.lexists(p)}
    account=pwd.getpwnam('alarm');homes=[];sessions={};pins={};events=[]
    for kind in ('fresh','existing'):
        home=Path('/tmp')/('mirrors-home-'+kind);home.mkdir(mode=0o700)
        if kind=='existing':
            path=home/'.config/mirrors/user-sentinel';path.parent.mkdir(parents=True);path.write_bytes(b'original user bytes\x00\xff\n');path.chmod(0o600)
            (home/'.config/alias').symlink_to('mirrors/user-sentinel')
        output=Path('/tmp')/('mirrors-output-'+kind);output.mkdir(mode=0o700);(output/'outside').write_bytes(b'outside user bytes\x00\xff\n')
        sessions[home]=L.session_paths(home,output)
        for path in (home,*home.rglob('*'),output,*output.rglob('*')):os.chown(path,account.pw_uid,account.pw_gid,follow_symlinks=False)
        homes.append((home,L.snapshot(home),output,L.entry(output/'outside')))

    def user(home,args):
        env=L.user_environment(home,sessions[home]);return L.command(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',
            *(key+'='+value for key,value in env.items()),*args],timeout=120)

    def preserve():
        for home,before,output,outside in homes:L.preservation_check(home,before,output,outside)
        C.need(all(L.entry(p)==value for p,value in protected.items()),'system mirror/pacman configuration changed')
        C.need(all(L.entry(p)==value for p,value in pins.items()),'previous fixture output changed across package transitions')

    def observe(label,cli):
        gate.before_observation(label)
        observations=[]
        for home,_,output,_ in homes:
            work=output/label;work.mkdir(mode=0o700);os.chown(work,account.pw_uid,account.pw_gid)
            result=json.loads(user(home,['/usr/bin/python3','-I','-B','/runner/lifecycle.py','--cli',str(cli),'--work',str(work),'--report',str(work/'report.json')]))
            observations.append(dict(home=home.name,mirrors=result))
            for path in work.rglob('*'):
                if path.is_file() and not path.is_symlink() and path.name!='key.pem':pins[path]=L.entry(path)
        return observations

    def installed(label):
        C.need(L.inventory()==original|{name:product['version']},'exact575 installed inventory differs')
        L.command(['/usr/bin/pacman','-Qkk',name]);owned=L.command(['/usr/bin/pacman','-Qql',name]).splitlines()
        C.need({p for p in owned if not p.endswith('/')}=={'/'+p for p in product['payload']},'ALPM ownership differs')
        for relative,row in product['payload'].items():
            path=Path('/')/relative;info=path.lstat()
            C.need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==row['mode'] and info.st_uid==info.st_gid==0 and
                   C.digest(path)==row['sha256'],'installed payload differs')
        observations=observe(label,Path('/usr/bin')/name)
        preserve();events.append(dict(phase=label,status='PASS',inventory_count=575,observations=observations,config_preserved=True))

    def absent(label):
        C.need(L.inventory()==original,'exact574 inventory not restored')
        C.need(all(not os.path.lexists(Path('/')/p) for p in product['payload']),'removed package payload remained')
        preserve();events.append(dict(phase=label,status='PASS',inventory_count=574,config_preserved=True,removed_payload_absent=True))

    gate=S.prepare(C,L,Path('/inputs'),Path('/tmp/mirrors-TEST-verification'),original,product,hooks,config,Path('/out/signature-verification'))
    archive=gate.archive;pacman=gate.pacman
    try:
        stage=Path('/tmp/mirrors-staged-payload');stage.mkdir(mode=0o755)
        for relative,(original_source,mode) in C.files(name).items():
            raw=(Path('/inputs/sources')/name/original_source).read_bytes()
            import hashlib
            C.need(hashlib.sha256(raw).hexdigest()==product['payload'][relative]['sha256'],'data-stage bytes differ from verified package payload')
            path=stage/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(mode)
        staged=observe('staged-before-install',stage/'usr/bin'/name);preserve()
        for label in ('install','same-version-reinstall'):L.command(pacman+['-U',str(archive)]);installed(label)
        L.command(pacman+['-R',name]);absent('remove')
        L.command(pacman+['-U',str(archive)]);installed('reinstall-after-removal')
        L.command(pacman+['-R',name]);absent('final-remove')
    finally:
        gate.close()
    result=dict(status='PASS_MIRRORS_INSTALLED_LIFECYCLE',staged_observations=staged,events=events,base_count=574,installed_count=575,user_config_preserved=True,
        system_config_preserved=True,user_outputs_preserved=True,masked_hooks=len(masked),actual_page_size=os.sysconf('SC_PAGE_SIZE'),
        hardware='NOT_RUN',native_architecture='aarch64',trust='EPHEMERAL_TEST_SIGNED_LOCAL_CANDIDATE_ONLY',signature_verification=gate.receipt,mirror_network='OWNED_LOOPBACK_TLS_ONLY')
    C.validate_lifecycle(result);Path('/out/lifecycle.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
