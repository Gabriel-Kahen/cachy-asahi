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
VERSION='0.1.0-1'
DOCTOR='cachy-asahi-doctor'
NAMES=(NAME,DOCTOR)
RECIPE='packages/tools/'+NAME
RECIPES={NAME:RECIPE,DOCTOR:'packages/tools/cachy-asahi-doctor2'}
VERSIONS={NAME:VERSION,DOCTOR:'0.2.0-2'}
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
    if name==DOCTOR:
        checks=load('doctor_shared_recipe_check',source/'scripts/checks/package_checks.py')
        report=checks.recipe(root/'PKGBUILD')
        need(not report['errors'] and len(report['input_sha256'])==9 and report['metadata']['pkgver']==['0.2.0'] and report['metadata']['pkgrel']==['2'] and
             report['metadata']['pkgname']==[DOCTOR] and report['metadata']['arch']==['any'], 'Doctor recipe differs')
        return dict(metadata=report['metadata'],input_sha256=report['input_sha256'])
    # Static data only. Shell bodies are separately frozen by the source proof.
    text=(root/'PKGBUILD').read_text();values={}
    keys=('pkgname','pkgver','pkgrel','pkgdesc','arch','url','license','depends','makedepends','checkdepends','optdepends','source','sha256sums')
    for match in re.finditer(r'^([a-z0-9_]+)=(\([^)]*\)|[^\n]*)',text,re.M):
        key,value=match.groups();need(key in keys and key not in values,'unexpected/duplicate recipe field')
        need(not any(x in value for x in ('$','`','\\',';','\n\n')), 'dynamic recipe field')
        values[key]=shlex.split(value[1:-1] if value.startswith('(') else value,comments=True)
    need(set(values)==set(keys) and values['pkgname']==[NAME] and values['arch']==['aarch64'] and
         values['pkgver']==['0.1.0'] and values['pkgrel']==['1'],'Welcome recipe identity differs')
    names=values['source'];pins=values['sha256sums']
    need(len(names)==len(pins)==15 and len(set(names))==15,'exact original source set required')
    expected={'PKGBUILD',*names}
    need({p.name for p in root.iterdir()}==expected,'original recipe file set differs')
    for name,pin in zip(names,pins):
        need('/' not in name and name not in ('.','..') and re.fullmatch('[0-9a-f]{64}',pin) and
             (root/name).is_file() and not (root/name).is_symlink() and digest(root/name)==pin,'source checksum differs')
    checked=load('welcome_original_source_check',root/'check_source.py').check(root)
    need(checked['installed_files']==9,'original source/payload check differs')
    values['pkgbase']=[NAME]
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
    return dict(**result,interpreter=interps[0][:-1].decode(),needed=needed,
                loads=[dict(offset=s[2],vaddr=s[3],filesz=s[5],memsz=s[6],alignment=s[7]) for s in segments if s[0]==1],
                actual_16k_execution='NOT_RUN')


def payload(report, source, name=NAME):
    need(name in NAMES and not report['errors'],'shared package checks failed')
    files=FILES if name==NAME else {
        'usr/bin/'+DOCTOR:(DOCTOR,0o755),
        'usr/share/doc/'+DOCTOR+'/README.md':('README.md',0o644),
        **{'usr/share/licenses/'+DOCTOR+'/'+n:(n,0o644) for n in ('LICENSE','NOTICE')}}
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
    need(path.stat().st_size<=16*1024**2,'build log cap')
    text=path.read_text(errors='replace')
    markers=('Starting check()', '1..7', 'ok 7 /status/json-controls', 'Ran 5 tests', 'PASS_SOURCE_PAYLOAD_CONTRACT') if name==NAME else ('Starting check()', 'Ran 16 tests', 'Ran 11 tests', 'Ran 20 tests', 'OK')
    for marker in markers:
        need(marker in text,'native check() result missing: '+marker)
    if name==DOCTOR:
        need(re.findall(r'^Ran ([0-9]+) tests(?: in [0-9.]+s)?$',text,re.M)==['16','11','20'] and len(re.findall(r'^OK$',text,re.M))==3 and not re.search(r'^FAILED|^ERROR|skipped=',text,re.M),'all three complete Doctor2 suites required without skips')
    return dict(status='PASS',glib_cases=7 if name==NAME else 0,cli_cases=5 if name==NAME else 0,
                doctor_fixtures=47 if name==DOCTOR else 0,source_payload='PASS' if name==NAME else 'PINNED_SHARED_RECIPE_CHECK',check_enabled=True)


def validate_lifecycle(value):
    need(value.get('status')=='PASS_PRODUCTS_INSTALLED_CLI_LIFECYCLE' and value.get('base_count')==574 and
         value.get('installed_count')==576 and value.get('user_config_preserved') is True and
         value.get('user_reports_preserved') is True and value.get('GUI')==value.get('hardware')=='NOT_RUN' and
         type(value.get('actual_page_size')) is int and value['actual_page_size']>0,'lifecycle acceptance absent')
    expected=[('install',576),('same-version-reinstall',576),('remove',574),('reinstall-after-removal',576),('final-remove',574)]
    events=value.get('events');need(type(events) is list and len(events)==5,'five exact lifecycle phases required')
    for event,(phase,count) in zip(events,expected):
        need(event.get('phase')==phase and event.get('status')=='PASS' and event.get('inventory_count')==count and
             event.get('config_preserved') is True,'lifecycle phase/inventory differs')
        if count==574:need(event.get('reports_preserved') is True,'reports lost after removal')
        else:
            rows=event.get('observations')
            need(type(rows) is list and {r.get('home') for r in rows}=={'product-home-fresh','product-home-existing'} and
                 len(rows)==2,'both fresh/existing user observations required')
            for row in rows:
                need(row.get('no_overwrite')=='PASS' and row.get('report_mode')=='0600' and
                     re.fullmatch('[0-9a-f]{64}',row.get('report_sha256','')),'private report proof absent')
                welcome=row['welcome'];doctor=row['doctor']
                need(welcome.get('architecture')=='aarch64' and welcome.get('page_size')==value['actual_page_size'] and
                     welcome.get('hardware_compatibility')=='not-assessed','Welcome actual platform qualification differs')
                need(doctor.get('tool')==DOCTOR and doctor.get('scope')=='local observations only','Doctor scope differs')
                validate_doctor2(doctor)
                validate_installed_comparison(row.get('installed_comparison'),
                    digest(Path(__file__).resolve().parents[3]/RECIPES[DOCTOR]/DOCTOR),phase,row['home'])


def validate_doctor2(doctor):
    need(doctor.get('version')=='0.2.0','installed Doctor2 version absent')
    rows=doctor.get('checks');need(type(rows)is list,'installed Doctor2 checks absent')
    audio=[r for r in rows if r.get('check')=='audio/default-output']
    need(len(audio)==1 and audio[0].get('state')=='unavailable' and audio[0].get('value')is None,'offline fixture must retain honest unavailable default-output observation')


def activation(source):
    value=json.loads((source/'scripts/ci/welcome-native/doctor2-policy.json').read_text())
    need(set(value)=={'schema_version','status','recipe','version','input_sha256','actual_source','actual_ref','actual_run'},'closed Doctor2 policy required')
    need(value['schema_version']==1 and all(value[k]is None for k in ('actual_source','actual_ref','actual_run')),'source/ref/run policy defaults must remain NULL')
    need(value['status']=='ROOT_SELECTED_DOCTOR2_NATIVE_PAIR' and value['recipe']==RECIPES[DOCTOR] and value['version']==VERSIONS[DOCTOR],'Doctor2 selection remains NULL/UNBOUND')
    need(value['input_sha256']==recipe(source,DOCTOR)['input_sha256'],'exact selected Doctor2 nine-input recipe required')
    return value


RETAINED574_SOURCE='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
RETAINED574_BEFORE=('bubblewrap-0.13.0-1-aarch64.pkg.tar.xz', 'bubblewrap-0.13.0-1-aarch64.pkg.tar.xz.sig', 'curl-8.22.0-1-aarch64.pkg.tar.xz', 'curl-8.22.0-1-aarch64.pkg.tar.xz.sig', 'jbigkit-2.1-8-aarch64.pkg.tar.xz', 'jbigkit-2.1-8-aarch64.pkg.tar.xz.sig', 'libarchive-3.8.9-1-aarch64.pkg.tar.xz', 'libarchive-3.8.9-1-aarch64.pkg.tar.xz.sig', 'libtiff-4.7.2-1-aarch64.pkg.tar.xz', 'libtiff-4.7.2-1-aarch64.pkg.tar.xz.sig', 'openssh-10.6p1-1-aarch64.pkg.tar.xz', 'openssh-10.6p1-1-aarch64.pkg.tar.xz.sig', 'pacman-7.1.0.r9.g54d9411-2-aarch64.pkg.tar.xz', 'pacman-7.1.0.r9.g54d9411-2-aarch64.pkg.tar.xz.sig', 'uwsm-0.27.0-1-any.pkg.tar.xz', 'uwsm-0.27.0-1-any.pkg.tar.xz.sig', 'xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz', 'xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz.sig', 'zlib-1:1.3.2-3-aarch64.pkg.tar.xz', 'zlib-1:1.3.2-3-aarch64.pkg.tar.xz.sig')


def validate_retained_inputs(value):
    source=Path(__file__).resolve().parents[3]
    lock_path=source/'scripts/ci/maintained-desktop574-inputs.json';raw=lock_path.read_bytes()
    need(len(raw)==623664 and hashlib.sha256(raw).hexdigest()=='b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9','retained original574 lock differs')
    expected={}
    for row in json.loads(raw)['packages']:
        expected[row['filename']]=dict(bytes=row['size'],sha256=row['sha256'])
        expected[row['filename']+'.sig']=dict(bytes=row['signature_size'],sha256=row['signature_sha256'])
    need(type(value)is dict and value.get('status')=='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY' and value.get('mode')=='desktop574' and value.get('source')==RETAINED574_SOURCE and value.get('actual')is None,'exact retained574 DATA receipt required')
    carrier=value.get('carrier',{});need(type(carrier)is dict,'typed retained carrier proof required')
    need(carrier.get('source')==RETAINED574_SOURCE and carrier.get('ref')=='codex/native574-complete-retained-inputs-v1' and carrier.get('tree')=='e21f947bac3afdfbd67e4e65c8234b35ae42b00f' and carrier.get('status')=='WHOLE_IMMUTABLE_SOURCE_GIT_JOIN_NO_NATIVE_AUTHORITY' and carrier.get('files')==carrier.get('blob_joins')==1154,'whole immutable retained574 carrier proof required')
    receipt=value.get('receipt',{});need(type(receipt)is dict,'typed retained receipt required');cache=receipt.get('cache',{});need(type(cache)is dict,'typed retained cache required')
    need(receipt.get('actual_authority')is False and receipt.get('status')=='EXACT_PUBLIC_CACHE_INPUTS_JOINED_NOT_AUTHENTICATED' and receipt.get('mode')=='desktop574' and receipt.get('original_lock')==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()),'retained cache is original-lock DATA only')
    need(len(expected)==1148 and receipt.get('inputs')==cache.get('after_files')==expected,'all1148 original package/signature cache pins required')
    wanted_before={name:expected[name] for name in RETAINED574_BEFORE}
    need(cache.get('before_files')==wanted_before and cache.get('added')==1128 and cache.get('fresh_cache')is False and cache.get('mode')==0o700 and cache.get('owner')=='CALLER_UID','exact existing20 plus1128 retained cache additions required')
    prior=cache.get('before_identity');directory=cache.get('directory_identity')
    need(type(directory)is list and len(directory)==6 and all(type(v)is int for v in directory) and directory[2]==0o40700,'ordinary retained cache directory identity required')
    need(type(prior)is dict and set(prior)==set(wanted_before) and cache.get('all_previous_inode_metadata_bytes_unchanged')is True and cache.get('after_previous_identity')==prior and cache.get('after_directory_identity')==cache.get('directory_identity'),'existing input/directory identities must be preserved')
    return dict(status='PASS_EXACT_RETAINED1148_DATA_NOT_AUTHENTICATION',files=1148,added=1128,preserved=20,actual_authority=False)


DIRECT_MODE='DIRECT_INSTALLED_EXECUTABLE'
GUARDED_MODE='INSTALLED_CODE_LOADER_NOT_DIRECT_EXEC'
COMPARISON_HASHES={'unchanged-json': 'caf3a2e23f7ee2d8e40695d3dcd2f0f8c96f00ea18342dfd86014d0fd5458e7f', 'changed-json': '6cfce9b4720e508d3c11875b863069360a9911a28c2e5dd5358a0a1ccbfc8c1a', 'unchanged-human': '44b1b755468696a5a685191ceb534bf9a830c5d75436c195d2c290fadc7bcb89', 'malformed-refused': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'unsupported-refused': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'existing-output-refused': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'input-output-alias-refused': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'private-output': '6cfce9b4720e508d3c11875b863069360a9911a28c2e5dd5358a0a1ccbfc8c1a', 'symlink-input-refused': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'guarded-unchanged': 'caf3a2e23f7ee2d8e40695d3dcd2f0f8c96f00ea18342dfd86014d0fd5458e7f', 'guarded-changed': '6cfce9b4720e508d3c11875b863069360a9911a28c2e5dd5358a0a1ccbfc8c1a', 'guarded-malformed': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
COMPARISON_CASES=(
    ('unchanged-json',DIRECT_MODE,0),('changed-json',DIRECT_MODE,0),
    ('unchanged-human',DIRECT_MODE,0),('malformed-refused',DIRECT_MODE,2),
    ('unsupported-refused',DIRECT_MODE,2),('existing-output-refused',DIRECT_MODE,2),
    ('input-output-alias-refused',DIRECT_MODE,2),('private-output',DIRECT_MODE,0),
    ('symlink-input-refused',DIRECT_MODE,2),('guarded-unchanged',GUARDED_MODE,0),
    ('guarded-changed',GUARDED_MODE,0),('guarded-malformed',GUARDED_MODE,2))


def validate_installed_comparison(value,payload_sha256,phase,home):
    """Require the finite installed-file gate; synthetic inputs carry no platform authority."""
    def need(ok,message):
        if not ok:raise ValueError(message)
    fields={'phase','home','status','fixture_scope','installed_path','installed_sha256','cases','direct_executable_cases',
        'guarded_installed_code_cases','input_existing_file_preservation','private_output_mode',
        'private_output_preserved','no_collection_process_network','comparison_oracle','GUI','hardware','real_audio'}
    need(type(value)is dict and set(value)==fields,'closed installed comparison receipt required')
    need(phase in ('install','same-version-reinstall','reinstall-after-removal') and
        home in ('product-home-fresh','product-home-existing') and value['phase']==phase and value['home']==home,
        'installed comparison phase/home context differs')
    need(value['status']=='PASS_INSTALLED_COMPARISON_SYNTHETIC_REPORT_INPUTS' and
        value['fixture_scope']=='SYNTHETIC_SUPPLIED_REPORTS_NOT_COLLECTED_OBSERVATIONS',
        'installed comparison synthetic report scope absent')
    need(type(payload_sha256)is str and re.fullmatch('[0-9a-f]{64}',payload_sha256) and
        value['installed_path']=='/usr/bin/cachy-asahi-doctor' and value['installed_sha256']==payload_sha256,
        'installed comparison executable/payload differs')
    need(type(value['direct_executable_cases'])is int and value['direct_executable_cases']==9 and
        type(value['guarded_installed_code_cases'])is int and value['guarded_installed_code_cases']==3,
        'finite direct/guarded installed comparison count differs')
    need(value['input_existing_file_preservation']is True and value['private_output_preserved']is True and
        value['private_output_mode']=='0600','comparison input/output preservation absent')
    need(value['no_collection_process_network']=='PASS_GUARDED_INSTALLED_CODE_CASES' and
        value['GUI']==value['hardware']==value['real_audio']=='NOT_RUN',
        'comparison guard scope or hardware boundary differs')
    oracle=value['comparison_oracle']
    need(type(oracle)is dict and set(oracle)=={'unchanged_count','changed_checks','change_count'} and
        type(oracle['unchanged_count'])is int and oracle['unchanged_count']==43 and
        type(oracle['change_count'])is int and oracle['change_count']==2 and
        oracle['changed_checks']==['audio/default-output','package/linux-asahi'],
        'finite synthetic comparison oracle differs')
    rows=value['cases'];need(type(rows)is list and len(rows)==12,'twelve ordered installed comparison cases required')
    need(set(COMPARISON_HASHES)=={name for name,_,_ in COMPARISON_CASES},'trusted comparison stdout pins incomplete')
    for row,(name,mode,code) in zip(rows,COMPARISON_CASES):
        expected={'case','mode','returncode','stdout_sha256'}|({'forbidden_calls'}if mode==GUARDED_MODE else set())
        need(type(row)is dict and set(row)==expected,'closed installed comparison case required')
        need(row['case']==name and row['mode']==mode and type(row['returncode'])is int and row['returncode']==code and
            row['stdout_sha256']==COMPARISON_HASHES[name],'installed comparison ordered result/exit/stdout differs')
        if mode==GUARDED_MODE:
            need(type(row['forbidden_calls'])is int and row['forbidden_calls']==0,
                'guarded installed comparison attempted collection/process/network')
    return dict(status='PASS_FINITE_INSTALLED_COMPARISON_SYNTHETIC_INPUTS_ONLY',direct_executable_cases=9,
        guarded_installed_code_cases=3,hardware='NOT_RUN',real_audio='NOT_RUN')
