# SPDX-License-Identifier: MIT
"""Finite current-three adapter for the existing owned native callbacks.

No process/ALPM/crypto/actor on import. This is not an owner or a supervisor.
The held caller owns admission, natural command retirement, TEST key custody,
container identity, whole-state snapshots and final cleanup on every exception.
"""
import json
from pathlib import Path
import re

KINDS=('enrollment','first-login','ui')
VERSIONS={'enrollment':('cachy-asahi-repository-enrollment','0.4.0-1'),
          'first-login':('cachy-asahi-first-login','0.1.0-3'),
          'ui':('cachy-asahi-first-login-ui','0.2.0-2')}


def need(ok,why):
    if not ok:raise ValueError(why)


def policy(value):
    need(value['operation']=='first-login-enrollment-ui-current-v2' and set(value['packages'])==set(KINDS),'exact current-three operation')
    for kind,(name,version)in VERSIONS.items():
        row=value['packages'][kind];need((row['name'],row['version'])==(name,version),'exact current candidate: '+kind)
    need('cachy-asahi-first-login=0.1.0-3'in value['packages']['ui']['depends'] and
         'cachy-asahi-setup=0.3.0-1'in value['packages']['ui']['depends'],'UI exact backend/Setup8 dependency edges')
    return value


def missing_inputs(value):
    """NULL actual operands remain visible; this never returns an authority."""
    rows=[]
    def visit(item,path):
        if item is None:rows.append(path)
        elif isinstance(item,dict):
            for k,v in item.items():visit(v,path+'.'+k if path else k)
    visit(value,'')
    return dict(status='HOLD_MISSING_PROSPECTIVE_INPUTS'if rows else 'INPUT_FIELDS_POPULATED_NOT_QUALIFIED_OR_AUTHORIZED',missing=rows,native='NOT_RUN',lifecycle='NOT_RUN',Root_acceptance=None)


def build_vectors(root,profile,inputs,stage,output):
    """Return exact existing builder argv; caller must use its owned runner."""
    policy(profile);need(stage in('backend','ui'),'one explicit native build stage')
    need(inputs['Root_admission']is not None and inputs['Root_capacity']is not None and inputs['source']is not None and inputs['image_namespace_qualification']is not None,'Root must supply fresh source/capacity/namespace/admission inputs')
    prefix='ui_'if stage=='ui'else'';image=inputs[prefix+'builder_image'];inventory=inputs[prefix+'builder_inventory']
    need(type(image)is str and re.fullmatch('sha256:[0-9a-f]{64}',image) and type(inventory)is dict and set(inventory)=={'path','bytes','sha256','packages'},'explicit immutable image and complete Root-bound inventory')
    need(type(inventory['packages'])is dict and inventory['packages'].get('cachy-asahi-setup')=='0.3.0-1','real Setup8 preinstalled in selected offline builder')
    need(all(inputs['setup8'][n]is not None for n in('archive','signature','current_TEST_signature_verification')),'authentic signed Setup8 input missing; check-only fixture is not a dependency')
    required={'python','gnupg','pacman','coreutils','libarchive','bubblewrap','util-linux','fish','zsh'}
    if stage=='ui':
        required|={'gtk4','python-gobject'}
        need(inventory['packages'].get('cachy-asahi-first-login')=='0.1.0-3' and all(inputs['first_login_backend'][n]is not None for n in('native_pair','archive','signature','current_TEST_signature_verification')),'exact genuinely built and signed CLI03 backend required for UI02')
        need(all(inputs['official_ui_dependencies'][n]is not None for n in('exact_closure','archive_signature_inputs','verification')),'exact signed official GTK/GObject closure missing')
    need(required<=set(inventory['packages']),'selected image lacks declared build/check/runtime dependencies')
    epoch=inputs['source_date_epoch'];need(type(epoch)is int and epoch>=0,'explicit stable source epoch')
    cap=inputs['Root_capacity'];need(type(cap)is dict and type(cap.get('build_seconds'))is int and 0<cap['build_seconds']<=180 and cap.get('builder_cpus')==4 and cap.get('builder_memory_bytes')==4*1024**3 and cap.get('builder_pids')==512,'explicit unchanged generic-builder policy and bounded command cap; no v1 admission inheritance')
    root=Path(root);output=Path(output);need(root.is_absolute()and output.is_absolute()and root not in output.parents and output not in root.parents and root!=output,'separate explicit absolute source/output')
    rows=[]
    for kind in (('ui',)if stage=='ui'else('enrollment','first-login')):
        recipe=root/profile['packages'][kind]['path']
        for label in('a','b'):
            rows.append(dict(kind=kind,label=label,argv=['/usr/bin/python3','-I','-B',str(root/'scripts/build/build.py'),str(recipe),'--image',image,'--output',str(output/(kind+'-'+label)),'--mode','native','--source-date-epoch',str(epoch),'--network','none','--timeout',str(cap['build_seconds']),'--expected-packages',inventory['path'],'--reviewed-inputs',str(root/'reviewed'/(kind+'.json'))]))
        rows.append(dict(kind=kind,label='compare',argv=['/usr/bin/python3','-I','-B',str(root/'scripts/build/compare.py'),str(output/(kind+'-a')),str(output/(kind+'-b')),'--require-bytes']))
    return rows



def build_pairs(run,T,root,profile,inputs,stage,output):
    """Use the original owner callback and exact generic builder/compare code."""
    report={}
    for row in build_vectors(root,profile,inputs,stage,output):
        kind,label=row['kind'],row['label'];raw=run('current-'+kind+'-'+label,row['argv'])
        if label!='compare':
            log=T.ordinary(Path(output)/(kind+'-'+label)/'build.log',1024**2)
            check_log(log,kind,profile)
        else:
            observed=json.loads(raw);need(observed['status']=='contents-reproduced'and observed['errors']==[],'actual clean pair comparison must pass')
            packages=observed['packages'];need(set(packages)=={profile['packages'][kind]['archive']},'exact one current artifact per pair')
            observed_pair=packages[profile['packages'][kind]['archive']]
            need(set(observed_pair)=={'installed_contents_equal','pkginfo_equal','bytes_equal','buildinfo_equal'}and all(v is True for v in observed_pair.values()),'complete byte/content/PKGINFO/BUILDINFO equality')
            report[kind]=observed
    return dict(status='PASS_CURRENT_BUILD_PAIR_DATA_ONLY',pairs=report,Root_acceptance=None)

def check_log(raw,kind,profile):
    policy(profile);need(type(raw)is bytes and 0<len(raw)<=1024**2 and raw.count(b'Starting check()')==1,'one bounded actual makepkg check invocation')
    text=raw.decode('utf-8');need(not re.search(r'FAILED|ERROR:|\bskipped\b|expected failure',text,re.I),'no failed or skipped native recipe checks')
    row=profile['packages'][kind]
    if kind=='enrollment':
        reports=[]
        for line in text.splitlines():
            if line.startswith('{'):
                try:reports.append(json.loads(line))
                except ValueError:pass
        need(len(reports)==1 and reports[0]==profile['enrollment_check_report'],'full actual Enrollment04 source-hidden/refresh/transition/revocation report')
    else:
        expected=[str(n)for n in row['check_counts']]
        actual=re.findall(r'^Ran ([0-9]+) tests in [0-9.]+s$',text,re.M)
        need(actual==expected and text.splitlines().count('OK')==len(expected),'complete ordered current check suites: '+kind)
    return dict(status='PASS_ACTUAL_CURRENT_RECIPE_CHECKS_ONLY',kind=kind)


def strict_signature(status,fingerprint):
    # Exact held v1 ALPM signature predicate; no trust-policy relaxation.
    need(re.fullmatch('[0-9A-F]{40}',fingerprint or ''),'explicit TEST primary fingerprint')
    rows=[line.split()[1:] for line in status.splitlines() if line.startswith('[GNUPG:] ')]
    forbidden={'EXPSIG','EXPKEYSIG','REVKEYSIG','BADSIG','ERRSIG','NO_PUBKEY','KEYEXPIRED','SIGEXPIRED','KEYREVOKED','FAILURE','NODATA','TRUST_NEVER','TRUST_UNDEFINED'}
    need(not any(row and row[0] in forbidden for row in rows),'bad/expired/revoked/unknown TEST signature refused')
    valid=[row for row in rows if row and row[0]=='VALIDSIG']
    need(len(valid)==1 and len(valid[0])==11 and valid[0][1]==valid[0][-1]==fingerprint,'exact TEST primary signer required')
    need(any(row and row[0]=='TRUST_ULTIMATE' for row in rows),'explicitly trusted TEST primary required')


def lifecycle(run,T,profile,signed,pacman,verifier,fingerprint,verify_state):
    """Inside the existing owned signed-image actor, never on the host.

    T is the whole-pinned held tools helper. verify_state is the original owner's
    protected-state check (homes/global trust/config/cache) and must raise on
    drift. Signatures/payloads/records are not substitutes for that owner check.
    Every exception propagates to its original owner; no success on partial work.
    """
    policy(profile);need(set(signed)=={'setup8',*KINDS},'four exact signed project inputs')
    need(type(pacman)is list and len(pacman)==2 and pacman[0]=='--config','one original owner-created offline pacman config')
    config=T.ordinary(Path(pacman[1])).decode();lines=config.splitlines()
    need(len(lines)==7 and lines[:4]==['[options]','Architecture = aarch64','SigLevel = Required','LocalFileSigLevel = Required'] and lines[4].startswith('GPGDir = /tmp/')and lines[5]=='HookDir = /builder-disabled-hooks'and lines[6].startswith('LogFile = /tmp/'),'closed local-only required-signature config with private log')
    trust=lines[4][len('GPGDir = '):];home=Path(trust)
    need(home.is_absolute()and home.name=='trust'and home.parent.parent==Path('/tmp')and home.parent.name.startswith('build-tools-test-')and '..'not in home.parts,'original owned TEST trust path only')
    need(Path(pacman[1])==home.parent/'pacman.conf'and lines[6]=='LogFile = '+str(home.parent/'pacman.log'),'private config/log belongs to original TEST work')
    need(verifier==['/usr/bin/gpg','--homedir',trust,'--batch','--no-auto-key-retrieve','--auto-key-locate','clear'],'exact offline verifier uses original private TEST trust')
    need(callable(verify_state),'original whole-state restoration callback required')
    rows={k:dict(v)for k,v in signed.items()};baseline=run('current-baseline',['/usr/bin/pacman','-Q'])
    for key,row in rows.items():
        name,version=('cachy-asahi-setup','0.3.0-1')if key=='setup8'else VERSIONS[key]
        need((row['name'],row['version'])==(name,version) and row['archive_pin']is not None and row['signature_pin']is not None,'exact genuinely signed current package identity')
        expected=profile['setup8']if key=='setup8'else profile['packages'][key]
        need(row['payload_files']==expected['payload_files'],'exact source-bound current signed payload set')
        if key=='setup8':need(row['archive_pin']==expected['archive_pin'],'authentic prior Setup8 archive only')
        need(name+' 'not in baseline.decode(),'project input already installed; do not replace baseline packages')
        need(T.pin(Path(row['archive']))==row['archive_pin']and T.pin(Path(row['signature']))==row['signature_pin'],'whole actual archive/signature pins')
        status=run('current-signature-'+key,[*verifier,'--status-fd=1','--verify',row['signature'],row['archive']]).decode();strict_signature(status,fingerprint)
        # Metadata extraction is passive and bounded by the caller, never a
        # package import. Normal pacman below independently enforces dependencies.
        raw=run('current-pkginfo-'+key,['/usr/bin/bsdtar','-xOf',row['archive'],'.PKGINFO'])
        md=T._metadata(raw);need(md.get('pkgname')==[name]and md.get('pkgver')==[version]and md.get('arch')==['any'],'exact signed project archive metadata')
    report=dict(status='HOLD',inventories={},payloads={},native16K='NOT_RUN',GUI='NOT_RUN',M2='NOT_RUN',Root_acceptance=None)
    versions={'cachy-asahi-setup':'0.3.0-1'}
    def absent(label,items):
        for i,name in enumerate(sorted({name for row in items for name in row['payload_files']})):
            for flag in('-e','-L'):run(label+'-'+str(i)+flag,['/usr/bin/test','!',flag,'/'+name])
    def inventory(label,added):
        raw=b''.join(sorted(run(label,['/usr/bin/pacman','-Q']).splitlines(keepends=True)));expected=T.inventory_expected(baseline,added);need(raw==expected,'complete exact ALPM inventory '+label);report['inventories'][label]=T.data_pin(raw)
    run('current-install-setup8',['/usr/bin/pacman',*pacman,'--noconfirm','--asdeps','-U',rows['setup8']['archive']]);inventory('current-dependency-inventory',versions)
    report['payloads']['setup8']=T.check_payload(rows['setup8'],run,pacman,'current-setup8')
    for cycle in('install','reinstall'):
        run('current-'+cycle,['/usr/bin/pacman',*pacman,'--noconfirm','-U',*[rows[k]['archive']for k in KINDS]])
        inventory('current-'+cycle+'-inventory',versions|{name:version for name,version in VERSIONS.values()})
        report['payloads'][cycle]={k:T.check_payload(rows[k],run,pacman,'current-'+cycle+'-'+k)for k in KINDS}
        # Read-only ordinary-user help smoke is not a GUI or user journey.
        for kind in KINDS:run('current-'+cycle+'-help-'+kind,['/usr/bin/runuser','-u','alarm','--','/usr/bin/'+VERSIONS[kind][0],'--help'])
        run('current-remove-'+cycle,['/usr/bin/pacman',*pacman,'--noconfirm','-R',*[VERSIONS[k][0]for k in reversed(KINDS)]]);inventory('current-after-remove-'+cycle,versions);absent('current-absent-'+cycle,[rows[k]for k in KINDS])
    run('current-remove-setup8',['/usr/bin/pacman',*pacman,'--noconfirm','-R','cachy-asahi-setup']);inventory('current-final-inventory',{});absent('current-absent-setup8',[rows['setup8']])
    verify_state();report['status']='PASS_CURRENT_THREE_SIGNED_ALPM_DATA_ONLY';return report


if __name__=='__main__':raise SystemExit('Internal owned-callback adapter only; no standalone actor or authority')
