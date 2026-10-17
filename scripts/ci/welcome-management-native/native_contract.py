# SPDX-License-Identifier: MIT
"""Three fixed, unselected products; Root final binding precedes every actor."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys

HERE=Path(__file__).resolve().parent
NAME='cachy-asahi-welcome';DOCTOR='cachy-asahi-doctor';ORPHANS='cachy-asahi-orphans'
NAMES=(NAME,DOCTOR,ORPHANS)
LABEL='org.cachy-asahi.welcome-management-native.job'
BASE='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
SCOPE='LOCAL_INSTALLED_METADATA_ONLY_NOT_PAYLOAD_RELEASE_REMOVAL_OR_HARDWARE_PROOF'
REPORTS=('welcome-status.json','doctor.json','default-assessment.json','fixture-assessment.json','fixture-plan.json','fixture-observation.json')
ROOT_GUARD_SOURCES=('test_management.c','management.c','management.h')
ROOT_GUARD_SKIP='ok 13 /management/root-guard # SKIP Root guard requires an actual root test process'
ROOT_GUARD_BINARY='/tmp/management-root-guard'
PHASES=(('install',577),('same-version-reinstall',577),('remove',574),('reinstall-after-removal',577),('final-remove',574))


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
    need(value.get('schema_version')==1 and value.get('base_inventory_sha256')==BASE and
         set(value.get('products',{}))==set(NAMES),'fixed three-product/574 policy required')
    for name,row in value['products'].items():
        need(row.get('version')=={DOCTOR:'0.1.0-1',ORPHANS:'0.1.0-2',NAME:'0.1.0-4'}[name] and
             row.get('arch')==('aarch64' if name==NAME else 'any') and
             all(type(row.get(k)) is dict for k in ('source_files','payload','dependencies')) and
             type(row.get('check_markers')) is list,'fixed product schema/version required')
    if bound:
        need(value.get('status')=='ROOT_BOUND_FINAL_PRODUCT_SOURCE' and
             re.fullmatch('[0-9a-f]{40}',value.get('candidate_source') or ''),
             'management native policy remains UNBOUND until Root final adoption/binding')
        for row in value['products'].values():
            need(row['source_files'] and row['payload'] and row['check_markers'] and row['dependencies'] and
                 re.fullmatch('[0-9a-f]{64}',row.get('recipe_sha256') or ''),'complete final product bindings required')
        ui=value.get('ui',{})
        need(set(ui.get('labels',{}))=={'management','doctor','orphans'} and
             set(ui.get('strings',{}))=={'running','complete','failure','unavailable'} and
             all(type(v) is str and 0<len(v)<=1024 for group in ('labels','strings') for v in ui[group].values()) and
             type(ui.get('raw_preview_suffix')) is str and 0<len(ui['raw_preview_suffix'])<=1024 and
             type(ui.get('max_output_bytes')) is int and 0<ui['max_output_bytes']<=1024**2 and
             type(ui.get('orphan_preview_bytes')) is int and ui['orphan_preview_bytes']==8192 and
             ui.get('orphan_preview_suffix')=='\n[Raw preview truncated at 8 KiB.]',
             'Root final UI strings/output policy remains UNBOUND')
        accepted=value['products'][DOCTOR].get('accepted_archive')
        need(type(accepted) is dict and set(accepted)=={'name','bytes','sha256','source_commit','producer_run'} and
             re.fullmatch(r'cachy-asahi-doctor-0\.1\.0-1-any\.pkg\.tar\.(xz|zst)',accepted['name']) and
             type(accepted['bytes']) is int and 0<accepted['bytes']<=8*1024**2 and
             re.fullmatch('[0-9a-f]{64}',accepted['sha256']) and re.fullmatch('[0-9a-f]{40}',accepted['source_commit']) and
             re.fullmatch('[1-9][0-9]{0,19}',accepted['producer_run']),'Root-pinned accepted Doctor archive/provenance required')
    return value


def product(name):
    need(name in NAMES,'unknown product');return policy(False)['products'][name]


def verify_source(source):
    need(not sys.flags.optimize,'ordinary Python required for inherited validators');value=policy()
    for name,row in read(HERE/'infrastructure-pins.json').items():checked(source,name,row)
    for name,row in value['products'].items():
        root=source/'packages/tools'/name
        need({p.name for p in root.iterdir()}==set(row['source_files']),'closed final product source set required')
        for filename,pin in row['source_files'].items():checked(root,filename,pin)
        need(digest(root/'PKGBUILD')==row['recipe_sha256'],'fixed recipe identity required')


def recipe(source,name):
    value=product(name);checks=load('management_recipe_checks',source/'scripts/checks/package_checks.py')
    row=checks.recipe(source/'packages/tools'/name/'PKGBUILD');meta=row['metadata']
    need(not row['errors'] and meta.get('pkgname')==[name] and
         meta.get('pkgver')==['0.1.0'] and meta.get('pkgrel')==[{DOCTOR:'1',ORPHANS:'2',NAME:'4'}[name]] and
         meta.get('arch')==[value['arch']] and meta.get('license')==['MIT'] and
         not any(meta.get(k) for k in ('install','provides','conflicts','replaces','backup')) and
         {key:meta.get(key,[]) for key in ('depends','makedepends','checkdepends','optdepends')}==value['dependencies'] and
         row['input_sha256']=={n:r['sha256'] for n,r in value['source_files'].items()},'exact offline final source recipe required')
    sources=meta.get('source',[])
    need(sources and all(Path(p).name==p and '://' not in p for p in sources) and
         'check()' in (source/'packages/tools'/name/'PKGBUILD').read_text(),'mandatory complete check and local sources required')
    return row


def version(source,name):return product(name)['version']
def files(name):return product(name)['payload']


def payload(report,source,name):
    need(not report['errors'] and set(report['elf'])==({'usr/bin/'+NAME} if name==NAME else set()),'exact ELF set required')
    expected=files(name);rows={p:r for p,r in report['members'].items() if r['type']!='5' and p not in ('.PKGINFO','.BUILDINFO','.MTREE')}
    need(set(rows)==set(expected),'exact Root-bound payload required')
    parents={str(p) for member in expected for p in Path(member).parents if str(p)!='.'}
    for path,row in report['members'].items():
        if row['type']=='5':need(path in parents,'unexpected empty payload directory')
    for path,(original,mode) in expected.items():
        need(path.startswith(('usr/bin/','usr/share/')) and not Path(path).is_absolute() and '..' not in Path(path).parts and
             Path(original).name==original and mode in (0o644,0o755),'reviewable payload namespace required')
        row=rows[path];need(row['type']=='0' and row['mode']==mode and row['uid']==row['gid']==0,'payload type/mode/owner differs')
        if path!='usr/bin/'+NAME:need(row['sha256']==digest(source/'packages/tools'/name/original),'payload/source/license identity differs')
    return rows


def check_log(path,name):
    need(path.stat().st_size<=16*1024**2,'build log cap');text=path.read_text(errors='replace')
    markers=product(name)['check_markers'];need(markers and 'Starting check()' in text,'mandatory check invocation absent')
    for marker in markers:
        need(type(marker) is str and 0<len(marker)<=256 and re.search(marker,text,re.M),'Root-bound complete native check marker absent')
    need(not re.search(r'\bskipped=|\bOK \(|\bFAILED\b|\bERROR\b|^not ok |^Bail out!',text,re.M),'unexpected test skip/error forbidden')
    directives=re.findall(r'^.*#\s*(?:SKIP|TODO)\b.*$',text,re.M|re.I)
    if name==NAME:
        need(directives==[ROOT_GUARD_SKIP] and len(re.findall(r'^ok [0-9]+ /[^\n]+$',text,re.M))==31,
             'exact35 ordinary passes and only the scoped nonroot root-guard skip required')
        return dict(status='PASS_35_ORDINARY_TESTS_AND_ONE_SCOPED_ROOT_GUARD_SKIP',markers=markers,check_enabled=True,
            passed=35,registered=36,skipped=1,expected_skip=ROOT_GUARD_SKIP,root_guard='REQUIRES_SEPARATE_REAL_UID0_CASE')
    need(not directives,'TAP skips/TODO forbidden outside the single Welcome root guard')
    return dict(status='PASS_COMPLETE_ROOT_BOUND_CHECKS_NO_SKIPS',markers=markers,check_enabled=True,skipped=0)


def root_guard_compile(cflags,libs):
    need(type(cflags) is list and type(libs) is list and len(cflags)+len(libs)<=128 and
         all(type(t) is str and 0<len(t)<=1024 and not any(c in t for c in '\0\r\n') for t in cflags+libs),
         'bounded native pkg-config arguments required')
    return ['/usr/bin/cc','-std=c11','-O2','-Wall','-Wextra','-Wformat=2','-Werror','-DMANAGEMENT_TEST',*cflags,
        '/guard-source/test_management.c','/guard-source/management.c','-o',ROOT_GUARD_BINARY,
        '-Wl,-z,max-page-size=16384',*libs]


def root_guard_tap(text):
    need(type(text) is str and 0<len(text.encode())<=128*1024 and '\0' not in text,'bounded root guard TAP required')
    need(not re.search(r'#\s*(?:SKIP|TODO)\b|^not ok |^Bail out!|\bERROR\b|\bFAILED\b',text,re.M|re.I) and
         re.findall(r'^1\.\.[0-9]+$',text,re.M)==['1..1'] and
         re.findall(r'^ok [^\n]+$',text,re.M)==['ok 1 /management/root-guard'],
         'one genuine root-guard PASS with no skips required')
    return dict(passed=1,skipped=0,tap_sha256=hashlib.sha256(text.encode()).hexdigest(),tap_bytes=len(text.encode()))


def validate_root_guard(value,tap=None):
    need(value.get('status')=='PASS_NATIVE_REAL_ROOT_GUARD' and type(value.get('uid')) is int and value['uid']==0 and
         type(value.get('euid')) is int and value['euid']==0 and value.get('architecture')=='aarch64' and
         type(value.get('page_size')) is int and value['page_size']>0 and value.get('passed')==1 and value.get('skipped')==0 and
         value.get('scope')=='SEPARATE_SOURCE_BOUND_TEST_CONTROL_NOT_INSTALLED_PRODUCT_BEHAVIOR' and value.get('hardware')=='NOT_RUN',
         'separate actual native UID0 root-guard evidence absent')
    need(value.get('source_files')=={name:product(NAME)['source_files'][name] for name in ROOT_GUARD_SOURCES} and
         re.fullmatch('[0-9a-f]{64}',value.get('binary_sha256','')) and re.fullmatch('[0-9a-f]{64}',value.get('tap_sha256','')) and
         type(value.get('tap_bytes')) is int and 0<value['tap_bytes']<=128*1024 and
         value.get('test_command')==[ROOT_GUARD_BINARY,'-p','/management/root-guard'] and
         value.get('compile_command')==root_guard_compile(value.get('pkg_config_cflags'),value.get('pkg_config_libs')),
         'root-guard source/command/binary/TAP identity differs')
    if tap is not None:
        need(all(value[k]==v for k,v in root_guard_tap(tap).items()),'root-guard retained raw TAP differs')
    return value


def elf(data,checks):
    accepted=load('management_accepted_welcome_elf',HERE.parent/'welcome-native/contract.py')
    return accepted.elf(data,checks)


def validate_lifecycle(value):
    need(value.get('status')=='PASS_MANAGEMENT_INSTALLED_READONLY_LIFECYCLE' and value.get('base_count')==574 and
         value.get('installed_count')==577 and value.get('base574_preserved') is True and value.get('user_preserved') is True and
         value.get('reports_preserved') is True and value.get('hardware')=='NOT_RUN' and value.get('removal')=='NOT_IMPLEMENTED' and
         value.get('architecture')=='aarch64' and type(value.get('page_size')) is int and value['page_size']>0,'installed readonly lifecycle proof absent')
    validate_root_guard(value.get('root_guard',{}))
    need(value['root_guard']['page_size']==value['page_size'],'root guard/lifecycle page size differs')
    events=value.get('events');need(type(events) is list and len(events)==5,'five lifecycle transitions required')
    for event,(phase,count) in zip(events,PHASES):
        need(event.get('phase')==phase and event.get('count')==count and event.get('base574_preserved') is True and event.get('user_preserved') is True,
             'exact574/user preservation absent')
        if count==574:need(event.get('payloads_absent') is True,'removed product payload remains');continue
        rows=event.get('observations');need(type(rows) is list and len(rows)==2 and
             {r.get('home') for r in rows}=={'management-home-fresh','management-home-existing'},'two actual ordinary user cases required')
        for row in rows:
            need(set(row.get('reports',{}))==set(REPORTS) and all(re.fullmatch('[0-9a-f]{64}',p) for p in row['reports'].values()) and
                 row.get('actual_default_count')==577 and row.get('db_preserved') is True and row.get('base_protected') is True and
                 row.get('readonly_enforced')=='UNPRIVILEGED_NO_DB_WRITE_ACCESS' and row.get('plan_verify')=='PASS_NOT_APPLIED' and
                 row.get('foreign_lock')=='PASS_REFUSAL_PRESERVED' and row.get('apply_supported') is False and
                 row.get('welcome_status')=='PASS_ACTUAL_PLATFORM' and row.get('doctor')=='PASS_ACTUAL_READONLY_JSON',
                 'actual three-product readonly CLI evidence absent')
