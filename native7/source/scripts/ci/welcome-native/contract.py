# SPDX-License-Identifier: MIT
"""Pinned inputs, original Welcome recipe and exact native payload gates."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import struct

NAME='cachy-asahi-welcome'
VERSION='0.1.0-7'
BOOT='cachy-asahi-boot-report'
NAMES=(NAME,)
HERE=Path(__file__).resolve().parent
RECIPE='packages/tools/cachy-asahi-welcome7'
RECIPES={NAME:RECIPE,BOOT:'packages/tools/cachy-asahi-boot-report'}
VERSIONS={NAME:VERSION,BOOT:'0.1.0-1'}
FILES={
 'usr/bin/'+NAME:('cachy-asahi-welcome',0o755),
 'usr/share/applications/io.github.GabrielKahen.CachyAsahiWelcome.desktop':('io.github.GabrielKahen.CachyAsahiWelcome.desktop',0o644),
 'usr/share/icons/hicolor/scalable/apps/'+NAME+'.svg':(NAME+'.svg',0o644),
 **{'usr/share/doc/'+NAME+'/'+n:(n,0o644) for n in ('first-run.txt','updates.txt','recovery.txt','README.md')},
 **{'usr/share/licenses/'+NAME+'/'+n:(n,0o644) for n in ('LICENSE','NOTICE')}}


def need(ok,message):
    if not ok:raise ValueError(message)


def digest(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
    return value


def safe(path):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n') and
         not any(p.is_symlink() for p in (path,*path.parents)), 'unsafe path')
    return path


def verify_source(source):
    pins=json.loads(Path(__file__).with_name('source-pins.json').read_text())
    for name,pin in pins.items():
        path=source/name
        need(path.is_file() and not path.is_symlink() and digest(path)==pin,'source dependency differs: '+name)


def recipe(source, name=NAME):
    need(name in NAMES,'unknown product')
    root=source/RECIPES[name]
    if name==BOOT:
        checks=load('boot_shared_recipe_check',source/'scripts/checks/package_checks.py')
        meta=checks.metadata((HERE/'boot-recipe.SRCINFO').read_text())
        actual={}
        text=(root/'PKGBUILD').read_text()
        for match in re.finditer(r'^([a-z_][a-z0-9_]*)=(\([^)]*\)|[^\n]*)',text,re.M):
            key,value=match.groups();need(key not in actual and not any(c in value for c in ('$','`',';','\\')),'constant Boot metadata required')
            actual[key]=shlex.split(value[1:-1]if value.startswith('(')else value,comments=True)
        need({k:v for k,v in meta.items()if k!='pkgbase'}==actual,'whole reviewed/generated Boot metadata differs')
        inputs={p.name:digest(p)for p in root.iterdir()if p.is_file()and not p.is_symlink()}
        need(set(inputs)=={'PKGBUILD',*meta['source']}and len(inputs)==6 and meta['pkgname']==[BOOT]and meta['pkgver']==['0.1.0']and meta['pkgrel']==['1']and meta['arch']==['any']and meta['license']==['MIT']and meta['depends']==['python>=3.11','systemd>=251']and not checks.platform_relations(meta),'exact six-input Boot recipe required')
        need(all(inputs[n]==pin for n,pin in zip(meta['source'],meta['sha256sums']))and len(meta['source'])==len(meta['sha256sums'])==5,'every local Boot source checksum required')
        return dict(metadata=meta,input_sha256=inputs)
    # Static data only. Shell bodies are separately frozen by the source proof.
    text=(root/'PKGBUILD').read_text();values={}
    keys=('pkgname','pkgver','pkgrel','pkgdesc','arch','url','license','depends','makedepends','checkdepends','optdepends','source','sha256sums')
    for match in re.finditer(r'^([a-z0-9_]+)=(\([^)]*\)|[^\n]*)',text,re.M):
        key,value=match.groups();need(key in keys and key not in values,'unexpected/duplicate recipe field')
        need(not any(x in value for x in ('$','`','\\',';','\n\n')), 'dynamic recipe field')
        values[key]=shlex.split(value[1:-1] if value.startswith('(') else value,comments=True)
    need(set(values)==set(keys) and values['pkgname']==[NAME] and values['arch']==['aarch64'] and
         values['pkgver']==['0.1.0'] and values['pkgrel']==['7'],'Welcome recipe identity differs')
    need('at-spi2-core' in values['depends'],'explicit audited ATK package dependency required')
    atk_dependency(source)
    names=values['source'];pins=values['sha256sums']
    need(len(names)==len(pins)==25 and len(set(names))==25,'exact original source set required')
    expected={'PKGBUILD','.SRCINFO',*names}
    need({p.name for p in root.iterdir()}==expected,'original recipe file set differs')
    for name,pin in zip(names,pins):
        need('/' not in name and name not in ('.','..') and re.fullmatch('[0-9a-f]{64}',pin) and
             (root/name).is_file() and not (root/name).is_symlink() and digest(root/name)==pin,'source checksum differs')
    checked=load('welcome_original_source_check',root/'check_source.py').check(root)
    need(checked['installed_files']==9,'original source/payload check differs')
    values['pkgbase']=[NAME]
    checks=load('welcome7_recipe_metadata',source/'scripts/checks/package_checks.py')
    need(checks.metadata((root/'.SRCINFO').read_text())==values,'whole declared Welcome7 metadata differs')
    return dict(metadata=values,input_sha256={n:digest(root/n) for n in sorted(expected)})


def elf(data, checks):
    result=checks.elf_check(data)
    need(result and not result['errors'] and result.get('machine')==183 and result.get('load_segments',0)>0,
         'native AArch64/16K structural ELF check failed')
    phoff=struct.unpack_from('<Q',data,32)[0];ents,count=struct.unpack_from('<HH',data,54)
    segments=[struct.unpack_from('<IIQQQQQQ',data,phoff+i*ents) for i in range(count)]
    interps=[data[s[2]:s[2]+s[5]] for s in segments if s[0]==3]
    need(len(interps)==1 and interps[0]==b'/lib/ld-linux-aarch64.so.1\0','ARM ELF interpreter differs')
    dynamic=[s for s in segments if s[0]==2];need(len(dynamic)==1,'one dynamic segment required')
    s=dynamic[0];need(s[5]<=65536 and s[5]%16==0 and s[2]+s[5]<=len(data),'invalid dynamic segment')
    entries=[struct.unpack_from('<qQ',data,i) for i in range(s[2],s[2]+s[5],16)]
    strings=[v for k,v in entries if k==5];sizes=[v for k,v in entries if k==10]
    need(len(strings)==len(sizes)==1 and sizes[0]<=65536,'dynamic string table differs')
    loads=[s for s in segments if s[0]==1 and s[3]<=strings[0] and strings[0]+sizes[0]<=s[3]+s[5]]
    need(len(loads)==1,'dynamic string table outside file-backed load')
    start=loads[0][2]+strings[0]-loads[0][3];table=data[start:start+sizes[0]];needed=[]
    for key,value in entries:
        if key==1:
            need(value<len(table) and b'\0' in table[value:],'invalid DT_NEEDED')
            name=table[value:table.index(b'\0',value)].decode('ascii')
            need(re.fullmatch('[A-Za-z0-9_.+-]{1,128}',name),'unsafe DT_NEEDED')
            needed.append(name)
    need({'libgtk-3.so.0','libglib-2.0.so.0','libc.so.6'}<=set(needed),'expected GTK/GLib/libc linkage absent')
    linkage(needed)
    return dict(**result,interpreter=interps[0][:-1].decode(),needed=needed,
                loads=[dict(offset=s[2],vaddr=s[3],filesz=s[5],memsz=s[6],alignment=s[7]) for s in segments if s[0]==1],
                actual_16k_execution='NOT_RUN')


def payload(report, source, name=NAME):
    need(name in NAMES and not report['errors'],'shared package checks failed')
    files=FILES if name==NAME else {
        'usr/bin/'+BOOT:(BOOT,0o755),
        'usr/share/doc/'+BOOT+'/README.md':('README.md',0o644),
        **{'usr/share/licenses/'+BOOT+'/'+n:(n,0o644) for n in ('LICENSE','NOTICE')}}
    rows={n:r for n,r in report['members'].items() if r['type']!='5' and n not in ('.PKGINFO','.BUILDINFO','.MTREE')}
    need(set(rows)==set(files) and set(report['elf'])==({'usr/bin/'+NAME} if name==NAME else set()),'exact product payload/ELF set required')
    directories={str(parent) for member in files for parent in Path(member).parents if str(parent)!='.'}
    for member,row in report['members'].items():
        if row['type']=='5':need(member in directories,'unexpected empty payload directory')
    for member,(original,mode) in files.items():
        row=rows[member]
        need(row['type']=='0' and row['mode']==mode and row['uid']==row['gid']==0,'payload type/mode/owner differs')
        if member!='usr/bin/'+NAME:need(row['sha256']==digest(source/RECIPES[name]/original),'installed data differs: '+member)
    return rows


def check_log(path, name=NAME):
    need(name==NAME and path.stat().st_size<=16*1024**2,'bounded Welcome7 build log required')
    text=path.read_text(errors='strict')
    cases=('status/installed','status/unavailable','status/duplicate','status/lookalike','status/malformed','status/oversized','status/json-controls',
      'management/boot-fixed-list-argv','management/dns-fixed-argv','management/dns-metadata-files','management/api','management/success','management/nonzero','management/missing','management/output-limit','management/timeout','management/cancel-detached','management/complete-detached','management/unrelated-child-isolation','management/environment','management/binary-output','management/invalid-utf8','management/root-guard',
      'report/json','report/unicode','report/refusal','report/bounds','report/dns/valid','report/dns/schema','report/dns/bounds','report/dns/versions','report/doctor/valid','report/doctor/schema','report/orphans/valid','report/orphans/schema',
      'report-work/copied-buffer-and-display','report-work/close-pending-lifetime','report-work/no-second-start',
      'boot-history/listed-empty-unavailable','boot-history/schema-refusals','boot-history/bounds-duplicate-full-json')
    rows=re.findall(r'^ok [1-9][0-9]* /([^\n]+)$',text,re.M)
    skip='management/root-guard # SKIP Root guard requires an actual root test process'
    need(len(rows)==41 and len(set(rows))==41 and set(rows) in (set(cases),(set(cases)-{'management/root-guard'})|{skip}),'all41 exact C cases required; only original UID0 guard may skip')
    need(re.findall(r'^1\.\.([0-9]+)$',text,re.M)==['7','16','12','3','3'],'complete C TAP plans required')
    need(re.findall(r'^Ran ([0-9]+) tests(?: in [0-9.]+s)?$',text,re.M)==['5'] and len(re.findall(r'^OK$',text,re.M))==1,'complete5 CLI controls required')
    need(not re.search(r'^not ok|^FAILED|^ERROR|skipped=',text,re.M) and text.count('# SKIP')==(1 if skip in rows else 0),'unexpected failure/skip refused')
    for marker in ('Starting check()','PASS_SOURCE_PAYLOAD_CONTRACT',"'pinned_sources': 25","'installed_files': 9"):
        need(marker in text,'full check() marker absent: '+marker)
    return dict(status='PASS_REQUIRED_WELCOME7_BUILD_CHECKS',C_cases=41,C_pass=40 if skip in rows else 41,CLI_cases=5,
      root_guard='NOT_EXERCISED_ORDINARY_UID_REQUIRES_UID0'if skip in rows else'ACTUAL_UID0_GUARD_PASS',
      source_payload='PASS',pinned_sources=25,check_enabled=True,GUI='NOT_RUN',installed_lifecycle='NOT_RUN')


def validate_lifecycle(value):
    need(value.get('status')=='PASS_PRODUCTS_INSTALLED_CLI_LIFECYCLE' and value.get('base_count')==574 and value.get('installed_count')==575 and value.get('user_config_preserved') is True and value.get('user_reports_preserved') is True and value.get('GUI')==value.get('hardware')=='NOT_RUN' and type(value.get('actual_page_size'))is int and value['actual_page_size']>0,'finite Boot lifecycle absent')
    need(value.get('history_completeness')=='UNKNOWN' and value.get('kernel_crash_diagnosis')=='NOT_ESTABLISHED','native fixture is not real history/crash authority')
    events=value['events'];need(len(events)==5,'five lifecycle phases required')
    fixture=load('boot_fixture_passive',HERE/'boot_fixture.py')
    journal_sha=digest(HERE/'boot-fixture/system.journal');expected=__import__('json').loads((HERE/'boot-fixture/decoded-records.json').read_text())[0]
    for event,(phase,count)in zip(events,(('install',575),('same-version-reinstall',575),('remove',574),('reinstall-after-removal',575),('final-remove',574))):
        need(event.get('phase')==phase and event.get('status')=='PASS'and event.get('inventory_count')==count and event.get('config_preserved')is True and event.get('reports_preserved')is True,'phase/inventory/preservation differs')
        if count==575:
            rows=event['observations'];need(len(rows)==2 and {r['home']for r in rows}=={'product-home-fresh','product-home-existing'},'fresh/existing ordinary users required')
            for row in rows:
                fixture.validate(row['boot'],journal_sha);need(row['boot']['record']==expected,'full decoded synthetic record differs')


def activation(source):
    import json
    value=json.loads((source/'scripts/ci/welcome-native/welcome7-policy.json').read_text())
    need(set(value)=={'schema_version','status','recipe','version','input_sha256','actual_source','actual_ref','actual_run'},'closed Boot policy required')
    need(value['schema_version']==1 and all(value[k]is None for k in ('actual_source','actual_ref','actual_run')),'actual identities must remain NULL')
    need(value['status']=='ROOT_SELECTED_WELCOME7_NATIVE_PAIR_SOURCE_ONLY'and value['recipe']==RECIPES[NAME]and value['version']==VERSIONS[NAME]and value['input_sha256']==recipe(source,NAME)['input_sha256'],'exact Boot selection remains UNBOUND/differs')
    return value


def linkage(needed):
    # Qualified native6 seven-soname set plus the single source-audited ATK addition.
    expected={'libgtk-3.so.0','libpango-1.0.so.0','libgio-2.0.so.0','libgobject-2.0.so.0','libglib-2.0.so.0','libc.so.6','ld-linux-aarch64.so.1','libatk-1.0.so.0'}
    need(len(needed)==len(expected) and set(needed)==expected,'exact qualified6 linkage plus audited libatk addition required')
    return needed


AUDITED_ATK_PACKAGE={'arch': 'aarch64', 'conflicts': ['at-spi2-atk<=2.38.0-2', 'atk<=2.38.0-2'], 'depends': ['bash', 'dbus', 'glib2', 'glibc', 'gsettings-desktop-schemas', 'libgcc', 'libx11', 'libxi', 'libxtst', 'systemd-libs', 'xorg-xprop'], 'filename': 'at-spi2-core-2.62.1-1-aarch64.pkg.tar.xz', 'license': ['LGPL-2.1-or-later'], 'name': 'at-spi2-core', 'provides': ['at-spi2-atk=2.62.1-1', 'atk=2.62.1-1', 'libatk-1.0.so=0-64', 'libatk-bridge-2.0.so=0-64', 'libatspi.so=0-64'], 'replaces': ['at-spi2-atk<=2.38.0-2', 'atk<=2.38.0-2'], 'sha256': '71efadc123171229c74281323db4b04c594c5e31ee0d7dfcb680bf5d8d98c74b', 'signature_sha256': '3386365fb23b962a5ce9612f8f5349c7cec9abee430bee2668334465e9ffd9c3', 'signature_size': 566, 'size': 547452, 'source_url': ['https://gitlab.gnome.org/GNOME/at-spi2-core'], 'url': 'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/at-spi2-core-2.62.1-1-aarch64.pkg.tar.xz', 'version': '2.62.1-1'}
AUDITED_ATK_LIBRARY={'soname': 'libatk-1.0.so.0', 'library': {'bytes': 198720, 'sha256': '230e593fee45b05b5d48cfac79f34960e3a3c3d67c66def596f46fb346b8c1be'}, 'links': {'usr/lib/libatk-1.0.so': 'libatk-1.0.so.0', 'usr/lib/libatk-1.0.so.0': 'libatk-1.0.so.0.26210.1'}, 'PKGINFO': {'bytes': 1091, 'sha256': '9fd333532bcab24a11b1732d82c7392278f608b51453d914c835e292558ec6db'}}


def atk_dependency(source):
    rows=json.loads((source/'scripts/ci/maintained-desktop574-inputs.json').read_bytes())['packages']
    matches=[r for r in rows if r.get('name')=='at-spi2-core']
    need(matches==[AUDITED_ATK_PACKAGE],'whole audited existing574 ATK package differs')
    return AUDITED_ATK_LIBRARY
