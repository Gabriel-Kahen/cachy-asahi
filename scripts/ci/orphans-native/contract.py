# SPDX-License-Identifier: MIT
"""One fixed, unselected readonly product; Root binding precedes every actor."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys

HERE=Path(__file__).resolve().parent
PRODUCT='cachy-asahi-orphans';NAMES=(PRODUCT,);NAME='NO_ELF_PRODUCT'
LABEL='org.cachy-asahi.orphans-native.job'
BASE='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
SCOPE='LOCAL_INSTALLED_METADATA_ONLY_NOT_PAYLOAD_RELEASE_REMOVAL_OR_HARDWARE_PROOF'
REPORTS=('default-assessment.json','fixture-assessment.json','fixture-plan.json','fixture-observation.json')
PHASES=(('install',575),('same-version-reinstall',575),('remove',574),('reinstall-after-removal',575),('final-remove',574))


def need(ok,reason):
    if not ok:raise ValueError(reason)


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()


def safe(path):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n\0') and
        not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute path required');return path


def read(path,cap=32*1024**2):
    path=safe(Path(path).absolute());info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=cap,'bounded regular JSON required')
    def pairs(rows):
        result={}
        for key,value in rows:need(key not in result,'duplicate JSON key');result[key]=value
        return result
    return json.loads(path.read_bytes(),object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value


def checked(root,name,row):
    path=Path(name);need(not path.is_absolute() and path.parts and '..' not in path.parts,'relative pinned path required')
    path=safe(root/path);info=path.lstat()
    need(type(row) is dict and set(row)=={'bytes','sha256'} and stat.S_ISREG(info.st_mode) and info.st_nlink==1 and
        0<info.st_size<=16*1024**2 and info.st_size==row['bytes'] and digest(path)==row['sha256'],'source byte identity differs: '+name)


def policy(bound=True):
    value=read(HERE/'input-policy.json')
    need(value.get('schema_version')==1 and value.get('base_inventory_sha256')==BASE and value.get('name')==PRODUCT and
        value.get('version')=='0.1.0-1' and len(value.get('source_files',{}))==8 and len(value.get('payload',{}))==5,
        'fixed final orphan source/base/payload binding required')
    if bound:need(value.get('status')=='ROOT_BOUND_FINAL_PRODUCT_SOURCE' and re.fullmatch('[0-9a-f]{40}',value.get('candidate_source') or ''),
        'orphan native policy remains UNBOUND until Root adoption/binding')
    return value


def verify_source(source):
    need(not sys.flags.optimize,'ordinary Python required for inherited validators');value=policy()
    for name,row in read(HERE/'infrastructure-pins.json').items():checked(source,name,row)
    root=source/'packages/tools'/PRODUCT
    need({p.name for p in root.iterdir()}==set(value['source_files']),'closed eight-file product source set required')
    for name,row in value['source_files'].items():checked(root,name,row)
    need(digest(root/'PKGBUILD')==value['recipe_sha256'],'fixed recipe identity required')


def recipe(source,name):
    need(name==PRODUCT,'unknown product');value=policy(False)
    checks=load('orphans_recipe_checks',source/'scripts/checks/package_checks.py');row=checks.recipe(source/'packages/tools'/name/'PKGBUILD');meta=row['metadata']
    need(not row['errors'] and meta.get('pkgname')==[name] and meta.get('pkgver')==['0.1.0'] and meta.get('pkgrel')==['1'] and
        meta.get('arch')==['any'] and meta.get('license')==['MIT'] and meta.get('depends')==['python>=3.11','pacman'] and
        not any(meta.get(k) for k in ('install','provides','conflicts','replaces','backup','makedepends','checkdepends')) and
        row['input_sha256']=={p:r['sha256'] for p,r in value['source_files'].items()},'exact offline script recipe required')
    need(len(meta.get('source',[]))==6 and all(Path(p).name==p and '://' not in p for p in meta['source']) and
        'check()' in (source/'packages/tools'/name/'PKGBUILD').read_text(),'mandatory check and six local inputs required')
    return row


def version(source,name):need(name==PRODUCT,'unknown version');return policy(False)['version']
def files(name):need(name==PRODUCT,'unknown payload');return policy(False)['payload']


def payload(report,source,name):
    need(not report['errors'] and not report['elf'],'script/data-only package required');expected=files(name)
    rows={p:r for p,r in report['members'].items() if r['type']!='5' and p not in ('.PKGINFO','.BUILDINFO','.MTREE')}
    need(set(rows)==set(expected),'exact five-file payload required')
    parents={str(p) for member in expected for p in Path(member).parents if str(p)!='.'}
    for path,row in report['members'].items():
        if row['type']=='5':need(path in parents,'unexpected empty payload directory')
    for path,(original,mode) in expected.items():
        need(path.startswith(('usr/bin/','usr/share/cachy-asahi-orphans/','usr/share/doc/','usr/share/licenses/')) and
            not Path(path).is_absolute() and '..' not in Path(path).parts and Path(original).name==original and mode in (0o644,0o755),'reviewable payload namespace required')
        row=rows[path];need(row['type']=='0' and row['mode']==mode and row['uid']==row['gid']==0 and
            row['sha256']==digest(source/'packages/tools'/name/original),'payload/source/license identity differs')
    return rows


def check_log(path,name):
    need(name==PRODUCT and path.stat().st_size<=16*1024**2,'build log bound');text=path.read_text(errors='replace')
    need('Starting check()' in text and re.search(r'^Ran 18 tests in [0-9.]+s$',text,re.M) and re.search(r'^OK$',text,re.M),
        'mandatory actual native eighteen-test check completion absent')
    need(not re.search(r'\bskipped=|\bOK \(|\bFAILED\b|\bERROR\b',text),'test skips/errors forbidden')
    return dict(status='PASS_18_CHECKS_NO_SKIPS',count=18)


def validate_lifecycle(value):
    need(value.get('status')=='PASS_ORPHANS_INSTALLED_READONLY_LIFECYCLE' and value.get('base_count')==574 and value.get('installed_count')==575 and
        value.get('base574_preserved') is True and value.get('user_preserved') is True and value.get('reports_preserved') is True and
        value.get('hardware')=='NOT_RUN' and value.get('removal')=='NOT_IMPLEMENTED' and value.get('architecture')=='aarch64' and
        type(value.get('page_size')) is int and value['page_size']>0,'installed readonly lifecycle proof absent')
    events=value.get('events');need(type(events) is list and len(events)==5,'five lifecycle transitions required')
    for event,(phase,count) in zip(events,PHASES):
        need(event.get('phase')==phase and event.get('count')==count and event.get('base574_preserved') is True and event.get('user_preserved') is True,
            'exact574/user lifecycle preservation absent')
        if count==574:need(event.get('payloads_absent') is True,'removed owned payload remains');continue
        observations=event.get('observations');need(type(observations) is list and len(observations)==2 and
            {r.get('home') for r in observations}=={'orphans-home-fresh','orphans-home-existing'},'two actual ordinary user cases required')
        for row in observations:
            need(type(row.get('reports')) is dict and set(row['reports'])==set(REPORTS) and all(type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin) for pin in row['reports'].values()),'four exact raw report hashes required')
            need(row.get('default_database')=='PASS_EXACT575_METADATA_ONLY' and row.get('base_protected') is True and row.get('default_root')=='/' and
                row.get('default_dbpath')=='/var/lib/pacman' and row.get('readonly_enforced')=='UNPRIVILEGED_NO_DB_WRITE_ACCESS' and
                row.get('fixture')=='PASS_VERSIONED_PROVIDED_OPTIONAL_CYCLE_PROTECTED' and row.get('plan_verify')=='PASS_NOT_APPLIED' and
                row.get('db_preserved') is True and row.get('foreign_lock')=='PASS_REFUSAL_PRESERVED' and row.get('apply_supported') is False,
                'real default/fixture readonly CLI evidence absent')
