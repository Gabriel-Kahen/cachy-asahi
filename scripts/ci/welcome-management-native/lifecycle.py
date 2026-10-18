#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Dependency-checked signed577 install/reinstall/remove; only orphan assessments."""
import json
import os
from pathlib import Path
import pwd
import shlex
import stat
import shutil
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import installed as I
F=I.load('accepted_orphan_fixture','/runner/accepted/fixture.py')



def root_guard(L,C):
    """A separate source-bound UID0 control, never used by installed product commands."""
    L.need(os.getuid()==os.geteuid()==0,'actual root test identity required')
    source=Path('/guard-source');pins=C.product(C.NAME)['source_files']
    L.need(source.is_dir() and not source.is_symlink() and {p.name for p in source.iterdir()}==set(pins),'exact Root-bound guard source mount required')
    for name,row in pins.items():C.checked(source,name,row)
    binary=Path(C.ROOT_GUARD_BINARY);L.need(not os.path.lexists(binary),'fresh root test executable required')
    cflags=shlex.split(L.command(['/usr/bin/pkg-config','--cflags','gio-2.0']))
    libs=shlex.split(L.command(['/usr/bin/pkg-config','--libs','gio-2.0']))
    compile_command=C.root_guard_compile(cflags,libs)
    L.command(compile_command,timeout=90)
    info=binary.lstat();L.need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==0 and
        not stat.S_IMODE(info.st_mode)&0o022,'ordinary root-owned test executable required')
    binary_sha256=L.sha(binary);binary_entry=I.entry(L,binary);test_command=[str(binary),'-p','/management/root-guard']
    tap=L.command(test_command,timeout=30);facts=C.root_guard_tap(tap)
    for name,row in pins.items():C.checked(source,name,row)
    receipt=dict(status='PASS_NATIVE_REAL_ROOT_GUARD',uid=os.getuid(),euid=os.geteuid(),architecture=os.uname().machine,
        page_size=os.sysconf('SC_PAGE_SIZE'),scope='SEPARATE_SOURCE_BOUND_TEST_CONTROL_NOT_INSTALLED_PRODUCT_BEHAVIOR',hardware='NOT_RUN',
        source_files={name:pins[name] for name in C.ROOT_GUARD_SOURCES},binary_sha256=binary_sha256,
        compile_command=compile_command,pkg_config_cflags=cflags,pkg_config_libs=libs,test_command=test_command,**facts)
    C.validate_root_guard(receipt,tap)
    Path('/out/root-guard.tap').write_text(tap);Path('/out/root-guard.json').write_bytes(C.encoded(receipt))
    L.need(I.entry(L,binary)==binary_entry,'root guard executable changed')
    binary.unlink()
    return receipt


def main():
    C=I.load('management_installed_contract','/runner/native_contract.py');L,driver=I.apis();I.guard(L,'lifecycle')
    base=json.loads(Path('/inputs/base.json').read_bytes());products=json.loads(Path('/inputs/products.json').read_bytes())
    L.need(len(base)==574 and L.inventory()==base and set(products)==set(C.NAMES),'exact574 and three products required')
    L.need(not any(Path(p).exists() for p in ('/source','/repository-source','/.git','/workspace')),'installed behavior cannot depend on Git/source checkout')
    control=json.loads(Path('/inputs/control.json').read_bytes());pacman=I.pacman(L,control['signer'])
    state=I.base_state(L,driver);base_digest=I.preserve_base(L,state)
    guard_receipt=root_guard(L,C)
    L.need(I.preserve_base(L,state)==base_digest,'root test control changed original574 payload/database')
    for name,row in products.items():
        archive=Path('/inputs')/row['archive']
        L.need(archive.parent==Path('/inputs') and archive.is_file() and not archive.is_symlink() and L.sha(archive)==row['sha256'] and
            set(row['payload'])==set(C.files(name)) and row['version']==C.version(None,name),'exact signed candidate/payload required')
    account=pwd.getpwnam('alarm');homes=[];events=[];report_pins={};desired=base|{name:row['version'] for name,row in products.items()}
    Path('/out').chmod(0o755);reports=Path('/out/reports');reports.mkdir(mode=0o755)
    for kind in ('fresh','existing'):
        home=Path('/tmp')/('management-home-'+kind);home.mkdir(mode=0o700)
        if kind=='existing':
            for relative in ('.config/cachy-asahi/preferences','.zshrc','.cache/user-owned'):
                path=home/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('preserve '+relative+'\n');path.chmod(0o600)
            (home/'.config/alias').symlink_to('cachy-asahi/preferences')
        output=reports/kind;output.mkdir(mode=0o700);(output/'outside').write_text('preserve outside\n');session=L.session_paths(home,output)
        for path in (home,*home.rglob('*'),output,*output.rglob('*')):os.chown(path,account.pw_uid,account.pw_gid,follow_symlinks=False)
        homes.append((home,L.snapshot(home),output,L.entry(output/'outside'),session))
    def user(home,session,argv,expected=0):
        environment=L.user_environment(home,session)
        return L.command(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',*(k+'='+v for k,v in environment.items()),*argv],expected=expected,timeout=90)
    def preserve():
        L.need(I.preserve_base(L,state)==base_digest,'base574 preservation digest changed')
        for home,before,output,outside,_ in homes:L.preservation_check(home,before,output,outside)
        for name,expected in report_pins.items():L.need(I.entry(L,Path(name))==expected,'generated user report changed across package transitions')
    def installed(phase):
        L.need(L.inventory()==desired,'exact577 inventory differs');I.payloads(L,products);I.database_check(L,pacman)
        observations=[]
        for home,_,output,_,session in homes:
            work=output/phase;work.mkdir(mode=0o700);os.chown(work,account.pw_uid,account.pw_gid)
            observation=F.observe(L,C,lambda argv,expected=0:user(home,session,argv,expected),work,desired,base,account.pw_uid)
            observation['actual_default_count']=len(desired)
            observation.pop('default_database',None)
            raw=user(home,session,['/usr/bin/cachy-asahi-welcome','--status','--json']);status=json.loads(raw)
            L.need(status['architecture']==os.uname().machine=='aarch64' and status['kernel']==os.uname().release and
                status['page_size']==os.sysconf('SC_PAGE_SIZE') and status['hardware_compatibility']=='not-assessed','Welcome actual platform differs')
            for name,value in status['packages'].items():
                L.need(value==dict(state='installed' if name in desired else 'not-found',version=desired.get(name)),'Welcome package facts differ')
            doctor_path=work/'doctor.json'
            doctor=json.loads(user(home,session,['/usr/bin/cachy-asahi-doctor','--json','--output',str(doctor_path)]))
            L.need(doctor.get('tool')==C.DOCTOR and doctor.get('scope')=='local observations only' and
                doctor.get('schema_version')==1 and json.loads(doctor_path.read_bytes())==doctor and
                doctor_path.stat().st_uid==account.pw_uid and (doctor_path.stat().st_mode&0o777)==0o600,'Doctor actual scope/private report differs')
            facts={r['check']:r for r in doctor['checks']}
            L.need(facts['platform']['value']==dict(architecture='aarch64',kernel=os.uname().release,
                page_size_bytes=os.sysconf('SC_PAGE_SIZE')),'Doctor actual platform differs')
            welcome_path=work/'welcome-status.json';welcome_path.write_text(raw);welcome_path.chmod(0o600);os.chown(welcome_path,account.pw_uid,account.pw_gid)
            user(home,session,['/usr/bin/cachy-asahi-doctor','--json','--output',str(doctor_path)],2)
            for path in (welcome_path,doctor_path):observation['reports'][path.name]=L.sha(path)
            observation.update(home=home.name,welcome_status='PASS_ACTUAL_PLATFORM',doctor='PASS_ACTUAL_READONLY_JSON')
            observations.append(observation)
            for name,digest in observation['reports'].items():
                path=work/name;L.need(L.sha(path)==digest,'report identity differs');report_pins[str(path)]=I.entry(L,path)
        preserve();events.append(dict(phase=phase,count=577,base574_preserved=True,user_preserved=True,observations=observations))
    def absent(phase):
        L.need(L.inventory()==base,'exact original574 inventory not restored')
        for row in products.values():
            for path in row['payload']:L.need(not os.path.lexists(Path('/')/path),'removed package-owned payload remains')
        I.database_check(L,pacman);preserve();events.append(dict(phase=phase,count=574,base574_preserved=True,user_preserved=True,payloads_absent=True))
    for phase,operation in (('install','-U'),('same-version-reinstall','-U'),('remove','-R'),('reinstall-after-removal','-U'),('final-remove','-R')):
        operands=[str(Path('/inputs')/row['archive']) for row in products.values()] if operation=='-U' else list(C.NAMES)
        L.command(pacman+[operation,*operands],timeout=90)
        (installed if operation=='-U' else absent)(phase)
    value=dict(status='PASS_MANAGEMENT_INSTALLED_READONLY_LIFECYCLE',root_guard=guard_receipt,base_count=574,installed_count=577,base574_preserved=True,
        base_manifest_sha256=base_digest,user_preserved=True,reports_preserved=True,architecture=os.uname().machine,
        page_size=os.sysconf('SC_PAGE_SIZE'),hardware='NOT_RUN',removal='NOT_IMPLEMENTED',release='NOT_ADMITTED',events=events,
        preserved_nodes=len(state['nodes']),preserved_reports=len(report_pins))
    C.validate_lifecycle(value);Path('/out/lifecycle.json').write_bytes(C.encoded(value))
    public=Path('/out/public-reports');public.mkdir(mode=0o755)
    for home,_,output,_,_ in homes:
        for phase,count in C.PHASES:
            if count!=577:continue
            target=public/output.name/phase;target.mkdir(parents=True)
            for name in C.REPORTS:
                original=output/phase/name;copy=target/name;shutil.copyfile(original,copy);copy.chmod(0o644)
                L.need(L.sha(copy)==report_pins[str(original)]['value'],'public raw report copy differs')
    L.command(['/usr/bin/gpgconf','--homedir','/tmp/management-trust','--kill','all'])


if __name__=='__main__':main()
