#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real package lifecycle; installed default helper lookup and readonly signed/catalog/cache CLI cases."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import installed as I


def main():
    C=I.load('apps_cache_installed_contract','/runner/contract.py');L,driver=I.apis();I.guard(L,'lifecycle')
    base=json.loads(Path('/inputs/base.json').read_bytes());products=json.loads(Path('/inputs/products.json').read_bytes())
    L.need(len(base)==574 and L.inventory()==base and set(products)==set(C.NAMES),'exact574/products required')
    L.need(not any(Path(path).exists() for path in ('/source','/repository-source','/.git','/workspace')),
        'installed CLI must not depend on a mounted Git/source checkout')
    control=json.loads(Path('/inputs/control.json').read_bytes());pacman=I.pacman(L,control['signer'])
    query=pacman[:-2]  # Keep the same config; transaction flags stay on -U/-R only.
    state=I.base_state(L,driver);base_digest=I.preserve_base(L,state)
    archives=[]
    for name,row in products.items():
        path=Path('/inputs')/row['archive'];L.need(path.parent==Path('/inputs') and path.is_file() and not path.is_symlink() and
            L.sha(path)==row['sha256'] and set(row['payload'])==set(C.files(name)),'accepted candidate archive/payload required')
        archives.append(str(path))
    selected={name:row['version'] for name,row in products.items()}
    account=pwd.getpwnam('alarm');homes=[];events=[];output_pins={}
    for kind in ('fresh','existing'):
        home=Path('/tmp')/('apps-cache-home-'+kind);home.mkdir(mode=0o700)
        if kind=='existing':
            for relative in ('.config/cachy-asahi/preferences','.zshrc','.cache/user-owned'):
                path=home/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('preserve '+relative+'\n');path.chmod(0o600)
            (home/'.config/alias').symlink_to('cachy-asahi/preferences')
        output=Path('/tmp')/('apps-cache-output-'+kind);output.mkdir(mode=0o700);(output/'outside').write_text('preserve outside\n')
        session=L.session_paths(home,output)
        for path in (home,*home.rglob('*'),output,*output.rglob('*')):os.chown(path,account.pw_uid,account.pw_gid,follow_symlinks=False)
        homes.append((home,L.snapshot(home),output,L.entry(output/'outside'),session))
    def user(home,session,argv,expected=0):
        environment=L.user_environment(home,session)
        return L.command(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',*(k+'='+v for k,v in environment.items()),*argv],expected=expected,timeout=60)
    def preserve():
        digest=I.preserve_base(L,state);L.need(digest==base_digest,'base574 preservation digest changed')
        for home,before,output,outside,_ in homes:L.preservation_check(home,before,output,outside)
        for path,expected in output_pins.items():L.need(L.entry(path)==expected,'preexisting generated user output changed')
    def installed(phase):
        L.need(L.inventory()==base|selected,'complete installed inventory differs')
        I.payloads(L,products);L.command(query+['-Dk'])
        for relative,digest in C.HELPERS.items():L.need(L.sha(C.RUNTIME/relative)==digest,'installed default runtime helper bytes differ')
        fixture=Path('/inputs/catalog-fixture');signed=json.loads((fixture/'control.json').read_bytes())
        observations=[]
        for home,_,output,_,session in homes:
            work=output/phase;work.mkdir(mode=0o700);os.chown(work,account.pw_uid,account.pw_gid)
            cli=['/usr/bin/cachy-asahi-apps','--release',str(fixture/'bundle'),'--release-sha256',signed['release_sha256'],
                '--catalog',str(fixture/'catalog.json'),'--catalog-sha256',signed['catalog_sha256'],'--catalog-signature',str(fixture/'catalog.json.sig'),
                '--keyring',str(fixture/'public.gpg'),'--signer',signed['signer']]
            commands=[]
            for verb in (['list'],['search','sYnThEtIc'],['show','fixture']):
                result=json.loads(user(home,session,cli+verb));L.need(result['applied']=='NOT_APPLIED' and result['synthetic'] is True and
                    result['installer_authority'] is False and result['applications'][0]['id']=='fixture','real signed installed catalog lookup failed');commands.append(verb[0])
            for operation,inventory in (('install','before'),('remove','selected')):
                declared=json.loads((fixture/('installed-'+inventory+'.json')).read_bytes())
                synthetic_db=work/('synthetic-'+operation)/'var/lib/pacman';local=synthetic_db/'local';local.mkdir(parents=True,mode=0o700)
                (local/'ALPM_DB_VERSION').write_text('9\n')
                for package in declared['packages']:
                    directory=local/(package['name']+'-'+package['version']);directory.mkdir(mode=0o700)
                    fields={'NAME':[package['name']],'VERSION':[package['version']],'ARCH':[package['arch']]}
                    fields.update({key:package.get(source,[]) for key,source in [('DEPENDS','depend'),('PROVIDES','provides'),('CONFLICTS','conflict'),('REPLACES','replaces')]})
                    (directory/'desc').write_text(''.join('%'+key+'%\n'+'\n'.join(values)+'\n\n' for key,values in fields.items() if values))
                    (directory/'files').write_text('%FILES%\n'+'\n'.join(package['files'])+'\n\n' if package['files'] else '')
                for path in (work/('synthetic-'+operation),*(work/('synthetic-'+operation)).rglob('*')):os.chown(path,account.pw_uid,account.pw_gid,follow_symlinks=False)
                snapshot=work/('synthetic-observed-'+operation+'.json')
                receipt=json.loads(user(home,session,['/usr/bin/cachy-asahi-apps','inventory','--dbpath',str(synthetic_db),'--output',str(snapshot)]))
                L.need(receipt['status']=='OBSERVED_LOCAL_DB_METADATA' and receipt['applied']=='NOT_APPLIED' and
                    receipt['package_count']==len(declared['packages']) and receipt['sha256']==L.sha(snapshot),'signed synthetic planning input must be collected from its explicit ALPM9 fixture')
                output_pins[snapshot]=L.entry(snapshot)
                args=cli+['--installed',str(snapshot),'--installed-sha256',receipt['sha256'],'plan',operation,'fixture']
                result=json.loads(user(home,session,args));L.need(result['status']=='PLANNED' and result['applied']=='NOT_APPLIED' and
                    result['installer_authority'] is False and result['synthetic'] is True,'installed signed planner claimed application')
                changes=result['plan']['additions' if operation=='install' else 'removals'];L.need([r['name'] for r in changes]==['fixture'],'explicit synthetic plan selection differs');commands.append('plan-'+operation)
            db_files=[p for p in Path('/var/lib/pacman/local').rglob('*') if p.is_file() or p.is_symlink()]
            L.need(len(db_files)<=4096,'bounded actual577 raw metadata fixture')
            db_before={str(path):I.entry(L,path) for path in db_files}
            inventory_path=work/'observed-inventory.json'
            collected=json.loads(user(home,session,['/usr/bin/cachy-asahi-apps','inventory','--dbpath','/var/lib/pacman','--output',str(inventory_path)]))
            observed=json.loads(inventory_path.read_bytes())
            L.need(collected['status']=='OBSERVED_LOCAL_DB_METADATA' and collected['applied']=='NOT_APPLIED' and
                collected['package_count']==len(base|selected) and collected['sha256']==L.sha(inventory_path) and
                {row['name']:row['version'] for row in observed['packages']}==base|selected and
                observed['observation']['payload_verified'] is False and observed['observation']['hardware_verified'] is False,
                'installed default-helper collector must observe exact live ALPM metadata without attestation inflation')
            annotation=observed['observation'];inputs=annotation['inputs']
            L.need(observed['kind']=='complete-installed-inventory' and observed['target_arch']=='aarch64' and
                all(row['arch'] in ('aarch64','any') and len(row['files'])==len(set(row['files'])) and
                    all(not Path(path).is_absolute() and '..' not in Path(path).parts and Path(path).as_posix()==path for path in row['files'])
                    for row in observed['packages']) and
                annotation['qualification']=='OBSERVED_LOCAL_DB_METADATA_NOT_PAYLOAD_OR_HARDWARE_ATTESTATION' and
                annotation['consistency']=='TWO_MATCHING_READS_NO_LOCK_NO_DETECTED_DRIFT' and
                annotation['database_sha256']==collected['database_sha256']==hashlib.sha256(C.encoded(inputs)).hexdigest() and
                annotation['packages_metadata_sha256']==hashlib.sha256(C.encoded(observed['packages'])).hexdigest(),
                'real577 architecture/relative ownership/raw-hash metadata annotation differs')
            L.need({str(Path('/var/lib/pacman')/name) for name in inputs}==set(db_before),'actual577 observation raw metadata closure differs')
            for name,pin in inputs.items():
                path=Path('/var/lib/pacman')/name
                L.need(name.startswith('local/') and not Path(name).is_absolute() and '..' not in Path(name).parts and
                    path.stat().st_size==pin['bytes'] and L.sha(path)==pin['sha256'],'actual577 raw metadata hash differs')
            L.need(set(db_before)=={str(p) for p in Path('/var/lib/pacman/local').rglob('*') if p.is_file() or p.is_symlink()} and
                all(I.entry(L,Path(path))==entry for path,entry in db_before.items()),'installed collector changed real577 database records')
            output_pins[inventory_path]=L.entry(inventory_path)
            user(home,session,['/usr/bin/cachy-asahi-apps','inventory','--dbpath','/var/lib/pacman','--output',str(inventory_path)],expected=1)
            L.need(L.entry(inventory_path)==output_pins[inventory_path],'collector overwrote an existing observed snapshot')
            # Only this disposable user-owned conventional target is eligible for the real Cache apply fixture.
            target=work/'target';cache=target/'var/cache/pacman/pkg';db=target/'var/lib/pacman'
            cache.mkdir(parents=True,mode=0o700);db.mkdir(parents=True,mode=0o700)
            (db/'local').mkdir(mode=0o700);(db/'local/ALPM_DB_VERSION').write_text('9\n');(db/'sentinel').write_text('preserve private database\n')
            keep='held-1-1-any.pkg.tar.xz';drop='selected-1-1-any.pkg.tar.xz'
            for name in (keep,drop):
                (cache/name).write_bytes(b'cache fixture archive\n');(cache/(name+'.sig')).write_bytes(b'cache fixture associated signature\n')
            policy=work/'protect.json';policy.write_text(json.dumps(dict(schema_version=1,cache=str(cache),protected={keep:dict(
                bytes=(cache/keep).stat().st_size,sha256=L.sha(cache/keep),signature=dict(bytes=(cache/(keep+'.sig')).stat().st_size,sha256=L.sha(cache/(keep+'.sig'))))})))
            policy.chmod(0o600)
            (cache/'unrelated.txt').write_text('preserve unrelated cache object\n')
            for path in (target,*target.rglob('*'),policy):os.chown(path,account.pw_uid,account.pw_gid,follow_symlinks=False)
            held={str(p):I.entry(L,p) for p in (cache,*cache.rglob('*'),db,*db.rglob('*'),policy)}
            listed=json.loads(user(home,session,['/usr/bin/cachy-asahi-cache','list','--cache',str(cache),'--dbpath',str(db),'--protect',str(policy)]))
            L.need(listed['status']=='READ_ONLY_CACHE_INVENTORY','installed cache list failed')
            plan=work/'cache-plan.json'
            planned=json.loads(user(home,session,['/usr/bin/cachy-asahi-cache','plan','--root',str(target),'--cache',str(cache),'--dbpath',str(db),'--protect',str(policy),
                '--select',drop,'--output',str(plan)]));verified=json.loads(user(home,session,['/usr/bin/cachy-asahi-cache','verify',str(plan)]))
            L.need(planned['status']==verified['status']=='NOT_APPLIED' and verified['verification']=='PASS_CURRENT_EXACT_SNAPSHOT','cache plan/verify claimed cleanup')
            L.need(all(I.entry(L,Path(path))==entry for path,entry in held.items()),'cache plan/verify altered archives/signatures/policy/database')
            output_pins[plan]=L.entry(plan)
            quarantine=work/'quarantine'
            applied=json.loads(user(home,session,['/usr/bin/cachy-asahi-cache','apply',str(plan),'--confirm','REMOVE_SELECTED_CACHE_ARCHIVES',
                '--plan-sha256',planned['plan_sha256'],'--quarantine',str(quarantine)]))
            L.need(applied['status']=='APPLIED' and applied['lock']=='OWN_LOCK_RELEASED' and
                applied['removed_objects']==sorted([drop,drop+'.sig']) and applied['reclaimed_bytes'] is None and
                applied['disk_space']=='NOT_MEASURED' and not os.path.lexists(db/'db.lck') and
                not os.path.lexists(cache/drop) and not os.path.lexists(cache/(drop+'.sig')),
                'real empty-ALPM-transaction cache apply boundary/selection/release failed')
            for path,entry in held.items():
                if entry['kind']!='dir' and Path(path).name not in (drop,drop+'.sig'):
                    L.need(I.entry(L,Path(path))==entry,'cache apply altered protected/unselected objects or non-lock database')
            journal_path=quarantine/'journal.json';journal=json.loads(journal_path.read_bytes())
            L.need(journal['phase']=='APPLIED' and journal['lock_release']=='OWN_LOCK_RELEASED' and
                journal['alpm']['version'].startswith('16.') and set(journal['purged'])=={drop,drop+'.sig'} and
                {p.name for p in quarantine.iterdir()}=={'journal.json'},'durable real-ALPM quarantine journal incomplete')
            output_pins[journal_path]=L.entry(journal_path)
            stale=json.loads(user(home,session,['/usr/bin/cachy-asahi-cache','verify',str(plan)],expected=1))
            L.need(stale['status']=='NOT_APPLIED' and stale['verification']=='REFUSED','applied cache plan must become stale')
            observations.append(dict(home=home.name,apps_commands=commands,default_helpers='PASS_INSTALLED_EXACT_THREE',signed_catalog='PASS_NOT_APPLIED',
                cache_plan_verify='PASS_NOT_APPLIED',inventory_collector='PASS_READONLY_OBSERVED_ALPM9',
                cache_cleanup='APPLIED_DISPOSABLE_FIXTURES_ONLY',cache_apply='PASS_REAL_ALPM16_EMPTY_TRANSACTION',
                cache_apply_result=applied,cache_journal=journal,inventory_observation=collected,real_database_inventory='PASS_EXACT577_OBSERVED_METADATA_RAW_HASHES_PRESERVED',plan_inventory_source='OBSERVED_SYNTHETIC_ALPM9_FIXTURE'))
        preserve();events.append(dict(phase=phase,count=len(base|selected),base574_preserved=True,user_preserved=True,
            installed_default_helpers='PASS',signed_catalog='PASS_NOT_APPLIED',cache_plan_verify='PASS_NOT_APPLIED',cache_apply='PASS_REAL_ALPM16_EMPTY_TRANSACTION',
            inventory_collector='PASS_READONLY_OBSERVED_ALPM9',observations=observations))
    def absent(phase):
        L.need(L.inventory()==base,'exact original574 inventory not restored')
        for row in products.values():
            for path in row['payload']:L.need(not os.path.lexists(Path('/')/path),'removed owned payload remains')
        preserve();events.append(dict(phase=phase,count=574,base574_preserved=True,user_preserved=True,payloads_absent=True))
    L.command(pacman+['-U',*archives],timeout=90);installed('install')
    L.command(pacman+['-U',*archives],timeout=90);installed('same-version-reinstall')
    L.command(pacman+['-R',*selected],timeout=90);absent('remove')
    L.command(pacman+['-U',*archives],timeout=90);installed('reinstall-after-removal')
    L.command(pacman+['-R',*selected],timeout=90);absent('final-remove')
    value=dict(status='PASS_APPS_CACHE_INSTALLED_LIFECYCLE',base_count=574,installed_count=len(base|selected),base574_preserved=True,
        base_manifest_sha256=base_digest,user_preserved=True,plans_applied='NOT_APPLIED',cache_cleanup='APPLIED_DISPOSABLE_FIXTURES_ONLY',cache_apply='PASS_REAL_ALPM16_EMPTY_TRANSACTION',
        architecture=os.uname().machine,page_size=os.sysconf('SC_PAGE_SIZE'),events=events,hardware='NOT_RUN',release='NOT_ADMITTED')
    C.validate_lifecycle(value);Path('/out/lifecycle.json').write_text(json.dumps(value,sort_keys=True)+'\n')
    L.command(['/usr/bin/gpgconf','--homedir','/tmp/apps-cache-trust','--kill','all'])


if __name__=='__main__':main()
