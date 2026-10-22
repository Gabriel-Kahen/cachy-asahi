# SPDX-License-Identifier: MIT
"""One setup5 candidate, fixed source/payload and installed transition contract."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import shutil
import types

HERE=Path(__file__).resolve().parent
PACKAGE='cachy-asahi-setup'
NAMES=(PACKAGE,)
NAME='NO_COMPILED_ADDON'
LABEL='org.cachy-asahi.setup5-native.job'
RECIPE='packages/settings/'+PACKAGE
INPUTS=('.SRCINFO','PKGBUILD','cachy-asahi-setup','README.md','NOTICE','LICENSE','source-provenance.json',
        'check-sync.py','test-sync.py','cachy-asahi-repository','repository-enrollment.md','check-packaged.py')
PHASES=(('install-setup4',575),('upgrade-setup5',575),('same-version-reinstall-setup5',575),
        ('rollback-setup4',575),('forward-setup5',575),('remove-setup5',574),('reinstall-setup5',575),('final-remove-setup5',574))
LEGACY=('state','journal-before','journal-after','journal-commit','remove-journal')
CASES=('preview-readonly','apply','repeat','custom-config','edited-module','missing-module','missing-preview',
       'legacy-state-journal','rollback-refusal','new-interruption-recovery')
OLD_PAIR=None


def need(ok,message):
    if not ok:raise ValueError(message)


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def safe(path):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n') and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute path required');return path


def pinned(root,name):
    pins=json.loads((HERE/'source-pins.json').read_text());p=safe(root/name)
    need(p.is_file() and p.stat().st_size<=16*1024**2 and digest(p)==pins.get(name),'pinned source differs: '+name);return p.read_text()


def verify_source(root):
    pins=json.loads((HERE/'source-pins.json').read_text())
    need(20<=len(pins)<=96,'closed setup5 source pins required')
    for name in pins:
        need(not Path(name).is_absolute() and '..' not in Path(name).parts,'safe source pin required');pinned(root,name)
    need(digest(root/'scripts/setup/setup.py')==digest(root/RECIPE/'cachy-asahi-setup'),'canonical/package setup5 mirror differs')
    recipe(root)


def build_source(root):
    raw=pinned(root,'scripts/ci/welcome-native/run.py');anchor="shutil.copytree(source/'packages/tools'/name,inputs)"
    need(raw.count(anchor)==1,'exact accepted build source adapter required')
    return raw.replace(anchor,'C.stage_recipe(source,inputs)')


def load(name,path):
    if path.name=='run.py' and path.parent.name=='welcome-native':
        value=types.ModuleType(name);value.__file__=str(path);exec(compile(build_source(path.parents[3]),str(path),'exec'),value.__dict__);return value
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def recipe(source,name=PACKAGE):
    need(name==PACKAGE,'one setup5 package required');root=source/RECIPE
    inputs={n:digest(root/n) for n in INPUTS}
    checks=load('setup5_recipe_checks',source/'scripts/checks/package_checks.py');meta=checks.metadata((root/'.SRCINFO').read_text())
    need(meta.get('pkgname')==[PACKAGE] and meta.get('pkgver')==['0.1.0'] and meta.get('pkgrel')==['5'] and meta.get('arch')==['any'] and meta.get('license')==['MIT'] and sorted(meta.get('depends',[]))==['gnupg','pacman','python>=3.11'] and len(meta.get('optdepends',[]))==9,'fixed setup5 any/MIT/dependency metadata required')
    text=(root/'PKGBUILD').read_text();names=shlex.split(re.search(r'^source=\((.*?)\)',text,re.M|re.S)[1]);hashes=shlex.split(re.search(r'^sha256sums=\((.*?)\)',text,re.M|re.S)[1])
    need(names==meta.get('source') and hashes==meta.get('sha256sums') and len(names)==len(hashes)==9 and set(names)==set(INPUTS)-{'.SRCINFO','PKGBUILD','check-packaged.py'},'nine literal local recipe/SRCINFO sources required')
    need(all(inputs[n]==h and re.fullmatch('[0-9a-f]{64}',h) for n,h in zip(names,hashes)),'setup5 local source checksum differs')
    provenance=json.loads((root/'source-provenance.json').read_text())
    need(provenance['sha256']==inputs['cachy-asahi-setup']==digest(source/'scripts/setup/setup.py') and provenance['license_sha256']==inputs['LICENSE']==digest(source/'LICENSE'),'source/helper/license provenance differs')
    return dict(metadata=meta,input_sha256=inputs)


def stage_recipe(source,target):
    target.mkdir(parents=True)
    for name in recipe(source)['input_sha256']:shutil.copyfile(source/RECIPE/name,target/name)


def stage_retained(context,checks,bind):
    need(OLD_PAIR is not None,'explicit retained setup4 pair required');import retained
    archive=retained.stage(OLD_PAIR,context/'setup4',checks,bind)
    old=json.loads((context/'setup4/product.json').read_text())
    need(set(old['payload'])==set(files()),'exact retained setup4 payload path set differs')
    for name,(original,mode) in files().items():
        row=old['payload'][name]
        need(row['mode']==mode and row['sha256']==digest(OLD_PAIR/'build-1/inputs'/original),'retained source/license/payload join differs')
    shutil.copytree(OLD_PAIR,context/'retained-setup4')


def version(source,name=PACKAGE):recipe(source,name);return '0.1.0-5'


def files(name=PACKAGE):
    need(name==PACKAGE,'unknown setup payload')
    return {**{'usr/bin/'+n:(n,0o755) for n in ('cachy-asahi-setup','cachy-asahi-repository')},
            **{'usr/share/doc/'+PACKAGE+'/'+n:(n,0o644) for n in ('README.md','repository-enrollment.md')},
            **{'usr/share/licenses/'+PACKAGE+'/'+n:(n,0o644) for n in ('NOTICE','LICENSE')}}


def payload(report,source,name=PACKAGE):
    need(not report['errors'] and not report['elf'],'setup script/data only package required')
    rows={n:r for n,r in report['members'].items() if r['type']!='5' and n not in ('.PKGINFO','.BUILDINFO','.MTREE')};expected=files(name)
    need(set(rows)==set(expected),'exact six setup payload files required')
    parents={str(p) for n in expected for p in Path(n).parents if str(p)!='.'}
    for n,r in report['members'].items():
        if r['type']=='5':need(n in parents,'unexpected empty setup payload directory')
    for n,(original,mode) in expected.items():
        r=rows[n];need(r['type']=='0' and r['mode']==mode and r['uid']==r['gid']==0 and r['sha256']==digest(source/RECIPE/original),'exact setup source/license/payload differs: '+n)
    return rows


def check_log(path,name=PACKAGE):
    need(name==PACKAGE and path.stat().st_size<=16*1024**2,'bounded setup build log required');text=path.read_text(errors='replace')
    need('Starting check()' in text and 'Ran 10 tests' in text and 'OK' in text and text.count('PASS: canonical and packaged helper/license bytes match pinned provenance')>=3,'actual recipe check/snapshot sync controls absent')
    return dict(status='PASS_CHECK_EXIT',sync_controls=10,installed_behavior='REQUIRED_SEPARATELY')


def validate_lifecycle(value):
    need(value.get('status')=='PASS_SETUP5_INSTALLED_LEGACY_LIFECYCLE' and value.get('base_count')==574 and value.get('native_architecture')=='aarch64' and type(value.get('actual_page_size')) is int and value['actual_page_size']>0 and value.get('fixture_scope')=='INERT_NAMESPACED_MODULE_FIXTURES_ONLY' and value.get('real_module_acceptance')=='NOT_RUN' and all(value.get(k) is True for k in ('system_config_preserved','user_state_preserved_on_alpm','full574_restored')),'setup5 installed lifecycle acceptance absent')
    events=value.get('events');need(type(events) is list and len(events)==len(PHASES),'all eight setup package transitions required')
    for event,(phase,count) in zip(events,PHASES):
        need(event.get('phase')==phase and event.get('inventory_count')==count and event.get('status')=='PASS' and event.get('homes_preserved') is True and event.get('database_check') is True,'setup package transition differs')
    proofs=value.get('proofs');need(type(proofs) is list and len(proofs)==6,'five legacy profiles and new grouped-journal profile required')
    need({p.get('profile') for p in proofs}==set(LEGACY)|{'new-grouped-journal'},'exact named legacy/new continuation profiles required')
    for proof in proofs:
        need(set(proof.get('cases',{}))==set(CASES) and all(v=='PASS' for v in proof['cases'].values()) and proof.get('uid',0)>0 and re.fullmatch('[0-9a-f]{64}',proof.get('installed_helper_sha256','')) and proof['installed_helper_sha256']==json.loads((HERE/'source-pins.json').read_text())[RECIPE+'/cachy-asahi-setup'],'ordinary installed setup5 cases/identity absent')

    observations=value.get('actual_observations');need(type(observations) is list and len(observations)==24,'all actual per-phase ordinary-user observations required')
    expected={(p,phase) for p in (*LEGACY,'new-grouped-journal') for phase in ('legacy','upgrade','rollback','forward')}
    need({(r.get('profile'),r.get('phase')) for r in observations}==expected,'actual named user observation set differs')
    joined={p:{} for p in (*LEGACY,'new-grouped-journal')}
    for row in observations:
        proof=row['proof'];phase=row['phase'];wanted='3e652bff75f6202cd3c13c327e50a298f7b25149b3c5cb55cdf4912d35af5919' if phase in ('legacy','rollback') else proofs[0]['installed_helper_sha256']
        need(proof['status']=='PASS' and proof['phase']==phase and proof['profile']==row['profile'] and proof['uid']>0 and proof['installed_helper_sha256']==row['sha256']==wanted and proof['fixture_scope']=='INERT_NAMESPACED_MODULE_FIXTURES_ONLY','actual installed user observation identity differs')
        phase_cases={'legacy':{'legacy-state-journal'},'upgrade':set(CASES)-{'rollback-refusal','new-interruption-recovery'},'rollback':{'rollback-refusal'},'forward':{'new-interruption-recovery'}}
        need(set(proof['cases'])==phase_cases[phase] and all(v=='PASS' for v in proof['cases'].values()),'actual phase case set differs')
        joined[row['profile']].update(proof['cases'])
    need(all(p['cases']==joined[p['profile']] for p in proofs),'aggregate user proof differs from actual phase observations')
