# SPDX-License-Identifier: MIT
"""Three original unselected products; unfinished recipe bytes never authorize actors."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

HERE=Path(__file__).resolve().parent
ROLES={'runtime':'cachy-asahi-repository-runtime','apps':'cachy-asahi-apps','cache':'cachy-asahi-cache'}
NAMES=tuple(ROLES.values());NAME='NO_ELF_PRODUCT_IN_THIS_LANE'
LABEL='org.cachy-asahi.apps-cache-native.job'
RUNTIME=Path('/usr/share/cachy-asahi/repository-runtime')
HELPERS={'scripts/client/client.py':'48f936fc28536f8d5c2cac25c77ddb591b6bd029062d4b4fe2ce901533e8fdb7',
 'scripts/release/release.py':'e4ab44f7cc020ae1d705b64362e8b1b05fa0c29c19ce64d886116055619c0435',
 'scripts/release/source_delivery.py':'8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e'}
BASE='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'


def need(ok,why):
    if not ok:raise ValueError(why)


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def safe(path):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\n\r\0') and
        not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute path required');return path


def read(path,cap=4*1024**2):
    safe(Path(path).absolute());info=Path(path).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=cap,'bounded regular JSON required')
    def pairs(rows):
        result={}
        for key,value in rows:need(key not in result,'duplicate JSON key');result[key]=value
        return result
    return json.loads(Path(path).read_bytes(),object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value


def checked(root,name,row):
    path=Path(name);need(not path.is_absolute() and path.parts and all(p not in ('.','..') for p in path.parts),'relative pinned path required')
    path=safe(root/path);info=path.lstat()
    need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and
        0<row['bytes']<=16*1024**2 and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and
        info.st_size==row['bytes'] and digest(path)==row['sha256'],'source byte identity differs: '+name);return path


def policy():
    value=read(HERE/'input-policy.json')
    need(value.get('status')=='ROOT_BOUND_FINAL_PRODUCT_SOURCES' and value.get('schema_version')==1,
         'Root final runtime/apps/cache sources, versions and payloads remain UNBOUND')
    need(value.get('base_inventory_sha256')==BASE and set(value.get('products',{}))==set(ROLES) and
        re.fullmatch('[0-9a-f]{40}',value.get('candidate_source') or ''),'exact final source/base selection required')
    need({n:r['sha256'] for n,r in value.get('helper_pins',{}).items()}==HELPERS,'exact unchanged three runtime helpers required')
    for role,name in ROLES.items():
        row=value['products'][role]
        need(row.get('name')==name and re.fullmatch('[A-Za-z0-9._+:-]{1,128}',row.get('version') or '') and
            re.fullmatch('[0-9a-f]{64}',row.get('recipe_sha256') or '') and row.get('source_files') and
            row.get('payload') and type(row.get('check_markers')) is list and row['check_markers'] and
            all(type(marker) is str and 0<len(marker)<=256 for marker in row['check_markers']),
            'complete final recipe/source/payload/check binding required: '+role)
    need(value.get('dependency') is None and value.get('dependency_source') is None,'final ctypes Cache requires no extra dependency input')
    return value


def verify_source(source):
    need(not sys.flags.optimize,'asserted inherited validators require ordinary Python')
    value=policy()
    for name,row in read(HERE/'infrastructure-pins.json').items():checked(source,name,row)
    for role,name in ROLES.items():
        product=value['products'][role];root=source/'packages/tools'/name
        actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
        need(actual==set(product['source_files']) and len(actual)<=64 and all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in root.rglob('*')),'closed ordinary candidate source set required')
        for relative,row in product['source_files'].items():checked(root,relative,row)
        need(digest(root/'PKGBUILD')==product['recipe_sha256'],'final recipe differs')
    for name,row in value['helper_pins'].items():checked(source,name,row)


def row(name):
    need(name in NAMES,'closed product name required');return next(r for r in policy()['products'].values() if r['name']==name)


def recipe(source,name):
    final=row(name);checks=load('apps_cache_recipe_checks',source/'scripts/checks/package_checks.py')
    result=checks.recipe(source/'packages/tools'/name/'PKGBUILD');meta=result['metadata']
    need(not result['errors'] and meta.get('pkgname')==[name] and meta.get('arch')==['any'] and
        meta.get('license')==['MIT'] and not any(meta.get(k) for k in ('install','provides','conflicts','replaces','backup')),
        'fixed original offline data/script recipe required')
    need(meta['pkgver'][0]+'-'+meta['pkgrel'][0]==final['version'] and
        result['input_sha256']=={p:r['sha256'] for p,r in final['source_files'].items()},'final metadata/source closure differs')
    need(all('://' not in item and Path(item).name==item for item in meta.get('source',[])), 'closed local source inputs required')
    need('check()' in (source/'packages/tools'/name/'PKGBUILD').read_text(),'native check() mandatory')
    if name==ROLES['apps']:need(ROLES['runtime']+'='+row(ROLES['runtime'])['version'] in meta.get('depends',[]),'exact runtime dependency required')
    if name==ROLES['cache']:need(meta.get('depends')==['python>=3.11','pacman'],'final ctypes Cache dependency set differs')
    return result


def version(source,name):return row(name)['version']


def files(name):return row(name)['payload']


def payload(report,source,name):
    need(not report['errors'] and not report['elf'],'data/script-only inspected package required');expected=files(name)
    actual={p:r for p,r in report['members'].items() if r['type']!='5' and p not in ('.PKGINFO','.BUILDINFO','.MTREE')}
    need(set(actual)==set(expected) and 1<=len(actual)<=32,'exact bound installed payload required')
    parents={str(p) for name in expected for p in Path(name).parents if str(p)!='.'}
    for path,node in report['members'].items():
        if node['type']=='5':need(path in parents,'unexpected empty payload directory')
    for path,(original,mode) in expected.items():
        need(path.startswith(('usr/bin/','usr/lib/cachy-asahi-apps/','usr/lib/cachy-asahi-cache/','usr/share/cachy-asahi/repository-runtime/','usr/share/doc/','usr/share/licenses/')) and
            not Path(path).is_absolute() and '..' not in Path(path).parts and Path(original).name==original and mode in (0o644,0o755),
            'reviewable original payload namespace required')
        node=actual[path];need(node['type']=='0' and node['mode']==mode and node['uid']==node['gid']==0 and
            node['sha256']==digest(source/'packages/tools'/name/original),'source/license/payload identity differs')
    if name==ROLES['runtime']:
        prefix=RUNTIME.relative_to('/').as_posix()+'/'
        need({p[len(prefix):]:n['sha256'] for p,n in actual.items() if p.startswith(prefix)}==HELPERS,
             'runtime must contain exactly three unchanged helper sources')
    return actual


def check_log(path,name):
    need(path.stat().st_size<=16*1024**2,'build log bound');text=path.read_text(errors='replace')
    need('Starting check()' in text and all(marker in text for marker in row(name)['check_markers']),
         'actual native check() completion markers absent')
    need(not re.search(r'\bskipped=[1-9]|\bOK \(skipped=',text),'native test skips forbidden')
    return dict(status='PASS_CHECK_EXIT_NO_SKIPS',method='makepkg check() exit0 plus bound markers; installed checks separate')


def validate_lifecycle(value):
    installed_count=574+len(NAMES)
    need(value.get('status')=='PASS_APPS_CACHE_INSTALLED_LIFECYCLE' and value.get('base_count')==574 and
        value.get('installed_count')==installed_count and value.get('base574_preserved') is True and value.get('user_preserved') is True and
        value.get('plans_applied')=='NOT_APPLIED' and value.get('cache_cleanup')=='APPLIED_DISPOSABLE_FIXTURES_ONLY' and value.get('cache_apply')=='PASS_REAL_ALPM16_EMPTY_TRANSACTION' and value.get('hardware')=='NOT_RUN' and
        value.get('architecture')=='aarch64' and type(value.get('page_size')) is int and value['page_size']>0,'installed native lifecycle proof absent')
    events=value.get('events');need(type(events) is list and len(events)==5,'five exact lifecycle transitions required')
    for event,(phase,count) in zip(events,(('install',installed_count),('same-version-reinstall',installed_count),('remove',574),('reinstall-after-removal',installed_count),('final-remove',574))):
        need(event.get('phase')==phase and event.get('count')==count and event.get('base574_preserved') is True and
            event.get('user_preserved') is True,'exact574/user lifecycle preservation absent')
        if count==installed_count:
            need(event.get('installed_default_helpers')=='PASS' and event.get('signed_catalog')=='PASS_NOT_APPLIED' and
                event.get('cache_plan_verify')=='PASS_NOT_APPLIED' and event.get('cache_apply')=='PASS_REAL_ALPM16_EMPTY_TRANSACTION' and
                event.get('inventory_collector')=='PASS_READONLY_OBSERVED_ALPM9','installed planner/collector/cache observations absent')
            observations=event.get('observations');need(type(observations) is list and len(observations)==2 and
                {r.get('home') for r in observations}=={'apps-cache-home-fresh','apps-cache-home-existing'},'two ordinary user cases required')
            for record in observations:
                need(record.get('apps_commands')==['list','search','show','plan-install','plan-remove'] and
                    record.get('default_helpers')=='PASS_INSTALLED_EXACT_THREE' and record.get('signed_catalog')=='PASS_NOT_APPLIED' and
                    record.get('cache_plan_verify')=='PASS_NOT_APPLIED' and record.get('cache_cleanup')=='APPLIED_DISPOSABLE_FIXTURES_ONLY' and
                    record.get('cache_apply')=='PASS_REAL_ALPM16_EMPTY_TRANSACTION' and record.get('inventory_collector')=='PASS_READONLY_OBSERVED_ALPM9' and
                    record.get('plan_inventory_source')=='OBSERVED_SYNTHETIC_ALPM9_FIXTURE' and
                    record.get('real_database_inventory')=='PASS_EXACT577_OBSERVED_METADATA_RAW_HASHES_PRESERVED','real default-helper signed planner/cache observations required')
                applied=record.get('cache_apply_result',{});journal=record.get('cache_journal',{})
                need(applied.get('status')=='APPLIED' and applied.get('lock')=='OWN_LOCK_RELEASED' and
                    applied.get('removed_objects')==['selected-1-1-any.pkg.tar.xz','selected-1-1-any.pkg.tar.xz.sig'] and
                    applied.get('reclaimed_bytes') is None and applied.get('disk_space')=='NOT_MEASURED' and
                    journal.get('phase')=='APPLIED' and journal.get('lock_release')=='OWN_LOCK_RELEASED' and
                    journal.get('alpm',{}).get('version','').startswith('16.'),'actual empty-ALPM transaction apply/journal evidence absent')
        else:need(event.get('payloads_absent') is True,'removed owned payloads remain')
