#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Dependency-checked signed575 install/reinstall/remove; only orphan assessments."""
import json
import os
from pathlib import Path
import pwd
import shutil
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import installed as I
import fixture as F


def main():
    C=I.load('orphans_installed_contract','/runner/contract.py');L,driver=I.apis();I.guard(L,'lifecycle')
    base=json.loads(Path('/inputs/base.json').read_bytes());products=json.loads(Path('/inputs/products.json').read_bytes())
    L.need(len(base)==574 and L.inventory()==base and set(products)==set(C.NAMES),'exact574 and single product required')
    L.need(not any(Path(p).exists() for p in ('/source','/repository-source','/.git','/workspace')),'installed behavior cannot depend on Git/source checkout')
    control=json.loads(Path('/inputs/control.json').read_bytes());pacman=I.pacman(L,control['signer'])
    state=I.base_state(L,driver);base_digest=I.preserve_base(L,state)
    row=products[C.PRODUCT];archive=Path('/inputs')/row['archive']
    L.need(archive.parent==Path('/inputs') and archive.is_file() and not archive.is_symlink() and L.sha(archive)==row['sha256'] and
        set(row['payload'])==set(C.files(C.PRODUCT)) and row['version']=='0.1.0-1','exact signed candidate/payload required')
    account=pwd.getpwnam('alarm');homes=[];events=[];report_pins={};desired=base|{C.PRODUCT:row['version']}
    Path('/out').chmod(0o755);reports=Path('/out/reports');reports.mkdir(mode=0o755)
    for kind in ('fresh','existing'):
        home=Path('/tmp')/('orphans-home-'+kind);home.mkdir(mode=0o700)
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
        L.need(L.inventory()==desired,'exact575 inventory differs');I.payloads(L,products);I.database_check(L,pacman)
        observations=[]
        for home,_,output,_,session in homes:
            work=output/phase;work.mkdir(mode=0o700);os.chown(work,account.pw_uid,account.pw_gid)
            observation=F.observe(L,C,lambda argv,expected=0:user(home,session,argv,expected),work,desired,base,account.pw_uid)
            observation['home']=home.name;observations.append(observation)
            for name,digest in observation['reports'].items():
                path=work/name;L.need(L.sha(path)==digest,'report identity differs');report_pins[str(path)]=I.entry(L,path)
        preserve();events.append(dict(phase=phase,count=575,base574_preserved=True,user_preserved=True,observations=observations))
    def absent(phase):
        L.need(L.inventory()==base,'exact original574 inventory not restored')
        for path in row['payload']:L.need(not os.path.lexists(Path('/')/path),'removed package-owned payload remains')
        I.database_check(L,pacman);preserve();events.append(dict(phase=phase,count=574,base574_preserved=True,user_preserved=True,payloads_absent=True))
    for phase,operation in (('install','-U'),('same-version-reinstall','-U'),('remove','-R'),('reinstall-after-removal','-U'),('final-remove','-R')):
        L.command(pacman+[operation,str(archive) if operation=='-U' else C.PRODUCT],timeout=90)
        (installed if operation=='-U' else absent)(phase)
    value=dict(status='PASS_ORPHANS_INSTALLED_READONLY_LIFECYCLE',base_count=574,installed_count=575,base574_preserved=True,
        base_manifest_sha256=base_digest,user_preserved=True,reports_preserved=True,architecture=os.uname().machine,
        page_size=os.sysconf('SC_PAGE_SIZE'),hardware='NOT_RUN',removal='NOT_IMPLEMENTED',release='NOT_ADMITTED',events=events,
        preserved_nodes=len(state['nodes']),preserved_reports=len(report_pins))
    C.validate_lifecycle(value);Path('/out/lifecycle.json').write_bytes(C.encoded(value))
    public=Path('/out/public-reports');public.mkdir(mode=0o755)
    for home,_,output,_,_ in homes:
        for phase,count in C.PHASES:
            if count!=575:continue
            target=public/output.name/phase;target.mkdir(parents=True)
            for name in ('default-assessment.json','fixture-assessment.json','fixture-plan.json','fixture-observation.json'):
                original=output/phase/name;copy=target/name;shutil.copyfile(original,copy);copy.chmod(0o644)
                L.need(L.sha(copy)==report_pins[str(original)]['value'],'public raw report copy differs')
    L.command(['/usr/bin/gpgconf','--homedir','/tmp/orphans-trust','--kill','all'])


if __name__=='__main__':main()
