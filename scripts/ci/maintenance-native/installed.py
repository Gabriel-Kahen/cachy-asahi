#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Five package transitions inside one explicitly guarded disposable ARM root."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat
import shutil
import time


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def sign_package(L,C,original):
    root=Path('/tmp/maintenance-package-signing');root.mkdir(mode=0o700)
    keyring=root/'keyring';keyring.mkdir(mode=0o700)
    archive=root/original.name;shutil.copyfile(original,archive)
    gpg=['/usr/bin/gpg','--no-options','--homedir',str(keyring),'--batch','--yes',
         '--pinentry-mode','loopback','--passphrase','']
    started=int(time.time())
    L.command(gpg+['--quick-generate-key','maintenance ALPM TEST <test@invalid>','ed25519','sign','1d'],timeout=45)
    listing=L.command(gpg+['--with-colons','--list-keys'])
    keys=[r.split(':')[9] for r in listing.splitlines() if r.startswith('fpr:')]
    C.need(len(keys)==1,'single TEST key required');key=keys[0]
    created=int(next(r.split(':')[5] for r in listing.splitlines() if r.startswith('pub:')))
    C.need(started<=created<=int(time.time()),'actual TEST package key time required')
    L.command(gpg+['--local-user',key,'--digest-algo','SHA256','--output',str(archive)+'.sig','--detach-sign',str(archive)])
    verification=L.command(gpg+['--status-fd','1','--verify',str(archive)+'.sig',str(archive)])
    C.need('[GNUPG:] VALIDSIG '+key+' ' in verification,'actual-time package signature verification required')
    certificate=root/'TEST-public.asc'
    L.command(gpg+['--armor','--output',str(certificate),'--export',key])
    (root/'verification.txt').write_text(verification)
    return dict(archive=str(archive),keyring=str(keyring),fingerprint=key,created_epoch=created,
        archive_sha256=C.digest(archive),signature_sha256=C.digest(Path(str(archive)+'.sig')),
        verified_epoch=int(time.time()),signature_verified_at_actual_time=True,private_key_removed=False,
        alpm_local_signature_policy='Required',production_trust='UNTOUCHED',fake_signature_time_used=False)


def publish(C,path,relative,public):
    C.need(not path.is_symlink() and path.is_file() and path.stat().st_size<=2*1024**2,
           'bounded regular public TEST file required')
    C.need(relative.startswith('fixture-evidence/') and '..' not in Path(relative).parts and
           not Path(relative).is_absolute() and relative not in public,'closed public TEST evidence path required')
    C.need(sum(row['bytes'] for row in public.values())+path.stat().st_size<=128*1024**2,
           'aggregate public TEST evidence bound')
    target=Path('/out')/relative;target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(path,target);target.chmod(0o644)
    public[relative]=dict(bytes=target.stat().st_size,sha256=C.digest(target))


def publish_fixture(C,work,label,home,result,public):
    rows=result['public_evidence']
    C.need(type(rows) is dict and len(rows)<=128 and sum(r['bytes'] for r in rows.values())<=16*1024**2,
           'finite observation public TEST evidence required')
    for relative,row in rows.items():
        C.need(not Path(relative).is_absolute() and '..' not in Path(relative).parts,'safe fixture evidence path required')
        path=work/relative
        C.need(path.stat().st_size==row['bytes'] and C.digest(path)==row['sha256'],'public TEST file pin differs')
        publish(C,path,'fixture-evidence/'+label+'/'+home+'/'+relative,public)
    publish(C,work/'report.json','fixture-evidence/'+label+'/'+home+'/report.json',public)


def finish(L,C,result,signing,public):
    root=Path(signing['archive']).parent
    for path in (Path(signing['archive']),Path(signing['archive']+'.sig'),root/'TEST-public.asc',root/'verification.txt'):
        publish(C,path,'fixture-evidence/package-signing/'+path.name,public)
    L.command(['/usr/bin/gpgconf','--homedir',signing['keyring'],'--kill','all'])
    shutil.rmtree(signing['keyring']);signing['private_key_removed']=not Path(signing['keyring']).exists()
    result['package_test_signing']=signing
    manifest=Path('/out/fixture-evidence-manifest.json');manifest.write_text(json.dumps(public,sort_keys=True,indent=2)+'\n')
    result['fixture_evidence_manifest_sha256']=C.digest(manifest)


def lifecycle():
    C=load('maintenance_contract','/runner/contract.py');L=load('original_preservation','/accepted/lifecycle.py')
    C.need(os.getuid()==0 and os.getpid()==1 and Path('/.dockerenv').is_file() and os.uname().machine=='aarch64' and
           os.environ.get('CACHY_ASAHI_TOOLS_LIFECYCLE')=='1','dedicated disposable native ARM PID1 required')
    original=json.loads(Path('/inputs/base.json').read_bytes());products=json.loads(Path('/inputs/products.json').read_bytes())
    C.need(len(original)==574 and set(products)==set(C.NAMES) and L.inventory()==original,'exact574/one maintenance input required')
    name=C.NAMES[0];product=products[name];archive=Path('/inputs')/product['archive']
    C.need(archive.parent==Path('/inputs') and archive.is_file() and not archive.is_symlink() and C.digest(archive)==product['sha256'] and
           set(product['payload'])==set(C.files(name)),'exact candidate archive required')
    package_signing=sign_package(L,C,archive)
    archive=Path(package_signing['archive'])
    hooks=Path('/tmp/maintenance-hooks');hooks.mkdir();masked=set()
    for parent in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks','/builder-disabled-hooks'):
        for path in Path(parent).glob('*.hook'):
            if path.name not in masked:(hooks/path.name).symlink_to('/dev/null');masked.add(path.name)
    config=Path('/tmp/maintenance-pacman.conf');config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+package_signing['keyring']+'\nHookDir = '+str(hooks)+'\n')
    pacman=['/usr/bin/pacman','--config',str(config),'--noconfirm','--noscriptlet']
    protected={p:L.entry(p) for p in (Path('/etc/pacman.conf'),Path('/etc/pacman.d/mirrorlist')) if os.path.lexists(p)}
    C.need(not any(p.pw_name=='maintenance-fixture' or p.pw_uid==2201 for p in pwd.getpwall()),'fresh fixture account required')
    L.command(['/usr/bin/useradd','--uid','2201','--user-group','--no-create-home','--no-log-init','maintenance-fixture'])
    homes=[];sessions={};accounts={};pins={};events=[];public={}
    for kind in ('fresh','existing'):
        account=pwd.getpwnam('alarm' if kind=='fresh' else 'maintenance-fixture')
        home=Path('/tmp')/('maintenance-home-'+kind);home.mkdir(mode=0o700)
        if kind=='existing':
            path=home/'.config/maintenance/user-sentinel';path.parent.mkdir(parents=True);path.write_bytes(b'original user bytes\x00\xff\n');path.chmod(0o600)
            (home/'.config/alias').symlink_to('maintenance/user-sentinel')
        output=Path('/tmp')/('maintenance-output-'+kind);output.mkdir(mode=0o700);(output/'outside').write_bytes(b'outside user bytes\x00\xff\n')
        sessions[home]=L.session_paths(home,output)
        for path in (home,*home.rglob('*'),output,*output.rglob('*')):os.chown(path,account.pw_uid,account.pw_gid,follow_symlinks=False)
        homes.append((home,L.snapshot(home),output,L.entry(output/'outside')));accounts[home]=account

    def user(home,args):
        env=L.user_environment(home,sessions[home]);return L.command(['/usr/bin/runuser','-u',accounts[home].pw_name,'--','/usr/bin/env','-i',
            *(key+'='+value for key,value in env.items()),*args],timeout=120)

    def preserve():
        for home,before,output,outside in homes:L.preservation_check(home,before,output,outside)
        C.need(all(L.entry(p)==value for p,value in protected.items()),'system maintenance/pacman configuration changed')
        C.need(all(L.entry(p)==value for p,value in pins.items()),'previous fixture output changed across package transitions')

    def observe(label,cli):
        observations=[]
        for home,_,output,_ in homes:
            account=accounts[home]
            work=output/label;work.mkdir(mode=0o700);os.chown(work,account.pw_uid,account.pw_gid)
            result=json.loads(user(home,['/usr/bin/python3','-I','-B','/runner/cli_fixture.py','--cli',str(cli),'--work',str(work),'--report',str(work/'report.json')]))
            C.validate_fixture(result,'aarch64',os.sysconf('SC_PAGE_SIZE'))
            publish_fixture(C,work,label,home.name,result,public)
            observations.append(dict(home=home.name,account=account.pw_name,uid=account.pw_uid,maintenance=result))
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

    stage=Path('/tmp/maintenance-staged-payload');stage.mkdir(mode=0o755)
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
    result=dict(status='PASS_MAINTENANCE_INSTALLED_LIFECYCLE',staged_observations=staged,events=events,base_count=574,installed_count=575,user_config_preserved=True,
        system_config_preserved=True,user_outputs_preserved=True,masked_hooks=len(masked),actual_page_size=os.sysconf('SC_PAGE_SIZE'),
        hardware='NOT_RUN',native_architecture='aarch64',trust='PRIVATE_ACTUAL_TIME_TEST_KEYRING_ONLY',network='NONE')
    finish(L,C,result,package_signing,public)
    C.validate_lifecycle(result);Path('/out/lifecycle.json').write_text(json.dumps(result,indent=2)+'\n')


def main():
    if not (os.getuid()==0 and os.getpid()==1 and Path('/.dockerenv').is_file() and
            os.uname().machine=='aarch64' and os.environ.get('CACHY_ASAHI_TOOLS_LIFECYCLE')=='1'):
        raise SystemExit('dedicated owned native ARM PID1 required')
    try:
        lifecycle()
    except BaseException as error:
        import subprocess
        keyring=Path('/tmp/maintenance-package-signing/keyring')
        cleanup='NOT_CREATED'
        if keyring.exists():
            try:
                subprocess.run(['/usr/bin/gpgconf','--homedir',str(keyring),'--kill','all'],
                    capture_output=True,check=True,timeout=15)
                shutil.rmtree(keyring);cleanup='REMOVED'
            except BaseException as caught:cleanup=type(caught).__name__+': '+str(caught)[:256]
        Path('/out/lifecycle.json').write_text(json.dumps(dict(status='FAIL',error_type=type(error).__name__,
            error=str(error)[:1024],signing_cleanup=cleanup,hardware='NOT_RUN'),sort_keys=True,indent=2)+'\n')
        raise


if __name__=='__main__':main()
