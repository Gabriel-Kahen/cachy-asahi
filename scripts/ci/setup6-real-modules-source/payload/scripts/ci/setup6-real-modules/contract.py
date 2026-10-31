# SPDX-License-Identifier: MIT
"""Fixed seven retained candidates; unchanged legacy574/575 then explicit581/574."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import stat

HERE=Path(__file__).resolve().parent
LABEL='org.cachy-asahi.setup6-real-modules.job'
CLI_SHA='29d68d371071487ffd9b5453c2c056105e73f6b2971c98873731193eab6534b0'
VERSIONS={'cachy-asahi-setup':'0.1.0-6','cachy-asahi-fish-bang-bang':'0.1.0-2','cachy-asahi-fish-autopair':'0.1.0-1','cachy-asahi-fish-done':'0.1.0-2','cachy-asahi-zsh-autosuggestions':'0.7.1-1','cachy-asahi-zsh-syntax-highlighting':'0.8.1.dev.e6683f2-1','cachy-asahi-zsh-history-substring-search':'0.1.0-1'}
NAMES=tuple(VERSIONS)
MODULES=tuple(n.removeprefix('cachy-asahi-') for n in NAMES if n!='cachy-asahi-setup')
CASES={'fish-request-forward','fish-request-reverse','zsh-request-forward','zsh-request-reordered','fish-noninteractive','zsh-noninteractive'}
ROOTS=None
META={'.PKGINFO','.BUILDINFO','.MTREE'}


def need(ok,reason):
    if not ok:raise ValueError(reason)


def hash_bytes(raw):return hashlib.sha256(raw).hexdigest()
def digest(path):return hash_bytes(Path(path).read_bytes())
sha=digest


def safe(path):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n') and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute path required');return path


def read(path,cap=2*1024**2):
    path=safe(Path(path));info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_size<=cap,'bounded regular JSON required')
    def pairs(items):
        value={}
        for k,v in items:need(k not in value,'duplicate JSON key');value[k]=v
        return value
    return json.loads(path.read_bytes(),object_pairs_hook=pairs)


def checked(root,ref,cap=8*1024**2):
    need(set(ref)=={'path','bytes','sha256'} and isinstance(ref['path'],str) and not Path(ref['path']).is_absolute() and '..' not in Path(ref['path']).parts and type(ref['bytes']) is int and 0<=ref['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',ref['sha256']),'exact bounded relative reference required')
    path=safe(root/ref['path']);info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_size==ref['bytes'] and digest(path)==ref['sha256'],'retained input identity differs: '+ref['path']);return path


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def policy():
    value=read(HERE/'input-policy.json');need(value.get('status')=='ROOT_FINAL_INPUTS_BOUND' and value.get('schema_version')==1 and re.fullmatch('[0-9a-f]{40}',value.get('module_source_ref','')),'Root must freeze the actual module packet policy')
    return value


def original(root):
    return load('setup6_unchanged_real5',root/'scripts/ci/setup5-native-real-modules/contract.py')


def verify_source(root):
    global SOURCE
    SOURCE=root
    original(root).verify_source(root)
    for name,row in read(HERE/'source-closure.json')['files'].items():checked(root,dict(path=name,**row),16*1024**2)
    need(digest(root/'setup6-source/scripts/setup/setup.py')==CLI_SHA,'accepted6 source differs')



def module_rows(root,code,checks,bind):
    bound=policy();index=read(checked(root,bound['module_index']));rows=index['packages']
    need(index.get('schema_version')==1 and set(rows)==set(VERSIONS)-{'cachy-asahi-setup'},'exact six module pair rows required')
    references={}
    def collect(value):
        if type(value) is dict:
            if set(value)=={'path','bytes','sha256'}:
                path=checked(root,value);references[value['path']]=value
            else:
                for child in value.values():collect(child)
        elif type(value) is list:
            for child in value:collect(child)
    collect(index)
    nodes=list(root.rglob('*'));need(len(nodes)<512 and all(not p.is_symlink() and (p.is_file() or p.is_dir()) for p in nodes),'bounded ordinary six-pair tree required')
    actual={str(p.relative_to(root)) for p in nodes if p.is_file()};need(actual==set(references)|{'index.json'} and len(actual)==154 and len(references)==153 and sum(r['bytes'] for r in references.values())+checked(root,bound['module_index']).stat().st_size==1185898,'closed154 six-module packet differs')
    for name,row in rows.items():
        need(row['version']==VERSIONS[name] and re.fullmatch('[0-9a-f]{40}',row['native_source']) and type(row['native_run']) is int and row['native_run']>0 and row['qualification'].startswith('PASS') and set(row['files'])=={'a','b'},'exact retained module identity required')
        need(set(row['sources'])==set(row['recipe_inputs']) and 'PKGBUILD' in row['recipe_inputs'],'complete retained original recipe inputs required')
        sources=[checked(root,ref) for ref in row['sources'].values()]
        for n,ref in row['sources'].items():need(Path(n).name==n and ref['sha256']==row['recipe_inputs'][n],'retained source hash join differs')
        if '.SRCINFO' in row['sources']:bind.bind_generated(row['metadata'],checks.metadata(checked(root,row['sources']['.SRCINFO']).read_text()))
        pair=[]
        for ref in row['files'].values():
            path=checked(root,ref);package=checks.package(path)
            need(not package['errors'] and not package['elf'] and not bind.bind_artifact(row['metadata'],package,row['recipe_inputs']['PKGBUILD']),'retained module package/source metadata differs')
            payload={n:r for n,r in package['members'].items() if r['type']!='5' and n not in META}
            need(payload==row['payload'] and payload and all(n.startswith('usr/') and r['type']=='0' and r['uid']==r['gid']==0 and r['mode']==0o644 and not r['link'] for n,r in payload.items()),'ordinary source-only module payload required')
            need(not any(package['metadata']['.PKGINFO'].get(k) for k in ('install','conflict','replaces','backup')),'module system mutation refused')
            need(all(any(ref['sha256']==r['sha256'] and ref['bytes']==r['size'] for ref in row['sources'].values()) for r in payload.values()),'payload source/license join differs')
            pair.append(package)
        a,b=row['files'].values();need(a['path']!=b['path'] and a['bytes']==b['bytes'] and a['sha256']==b['sha256'] and pair[0]['metadata']==pair[1]['metadata'],'whole native pair bytes/metadata differ')
        for key in ('acceptance','evidence','raw_lifecycle'):
            if key in row:checked(root,row[key])
    return rows


def recipe(source,name):
    if name=='cachy-asahi-setup':return load('accepted_setup6_recipe',source/'setup6-source/scripts/ci/setup6-native/contract.py').recipe(source/'setup6-source')
    return dict(metadata=read(checked(ROOTS['modules'],policy()['module_index']))['packages'][name]['metadata'])


def stage_inputs(source,out,base,checks,bind):
    old=original(source);old.ROOTS={n:ROOTS[n] for n in ('setup5','modules','setup4')}
    context,products=old.stage_inputs(source,out,base,checks,bind)
    packet=ROOTS['setup6'];index=read(packet/'index.json');need(index['source']=='141ba835bb632483342c6a7f0246c7fe0f2bc5c3' and index['native_run']==39595642635 and len(index['source_files'])==73 and index['real_modules']=='NOT_RUN','accepted6 exact fixture-only source required')
    actual={str(p.relative_to(packet)) for p in packet.rglob('*') if p.is_file()};need(actual==set(index['files'])|{'index.json'} and len(actual)==384,'complete384 accepted6 input closure required')
    for n,r in index['files'].items():checked(packet,dict(path=n,**r),16*1024**2)
    acceptance=read(packet/'qualification/Root-component-acceptance.json');need(acceptance['status']=='ROOT_ACCEPTED_FINITE_NATIVE_SETUP6_PAIR_AND_INSTALLED_FIXTURE_LIFECYCLE' and acceptance['source']=='141ba835bb632483342c6a7f0246c7fe0f2bc5c3','Root accepted6 prerequisite absent')
    contract=load('setup6_exact_recipe',source/'setup6-source/scripts/ci/setup6-native/contract.py')
    meta=contract.recipe(source/'setup6-source');pairs={};inspected=[]
    for side in ('a','b'):
        ref=dict(path='native/packages/cachy-asahi-setup-'+side+'/cachy-asahi-setup-0.1.0-6-any.pkg.tar.xz',bytes=27188,sha256='a4fc772da0fd460f07380c4bc6bc1396688745907a993fe2591778082dae05c8');archive=checked(packet,ref)
        package=checks.package(archive);need(not bind.bind_artifact(meta['metadata'],package,meta['input_sha256']['PKGBUILD']),'accepted6 package/source binding differs');payload=contract.payload(package,source/'setup6-source');inspected.append(package)
        target=context/('pairs/cachy-asahi-setup6-'+side)/archive.name;target.parent.mkdir();shutil.copyfile(archive,target);pairs[side]=dict(path=str(target.relative_to(context)),bytes=27188,sha256=digest(target))
    need(inspected[0]['metadata']==inspected[1]['metadata'],'accepted6 full pair metadata differs')
    shutil.copyfile(archive,context/archive.name)
    products['cachy-asahi-setup']=dict(archive=archive.name,sha256=digest(archive),version='0.1.0-6',payload=payload,accepted_pair=dict(files=pairs,source='141ba835bb632483342c6a7f0246c7fe0f2bc5c3',run=39595642635,qualification='ROOT_ACCEPTED_SETUP6_PAIR_AND_INERT_LIFECYCLE_ONLY'))
    # products.json remains the exact original5 for the entire unchanged legacy8.
    (context/'modules.json').write_text(json.dumps(products,indent=2)+'\n');shutil.copyfile(HERE/'expected581.lock',context/'expected581.lock');shutil.copyfile(packet/'index.json',context/'accepted-setup6-index.json')
    return context,products


def expected():
    path=safe(HERE/'expected581.lock');need(path.is_file() and path.stat().st_size<65536,'bounded expected581 lock required');rows=[line.split() for line in path.read_text().splitlines()]
    need(len(rows)==581 and all(len(r)==2 for r in rows) and len(dict(rows))==581,'exact581 lock rows required');return dict(rows)


def validate_real(value):
    need(value.get('status')=='PASS_NATIVE_INSTALLED_SETUP6_REAL_MODULE_GENERATED_RCS' and value.get('scope')=='ACTUAL_INSTALLED_SETUP6_AND_SIX_MODULE_GENERATED_RCS' and value.get('machine')=='aarch64' and value.get('uid',0)>0 and value.get('zsh_mode')=='DEFAULT_ASYNC_PRESENCE_ASSERTED' and value.get('notification_delivery')=='NOT_RUN' and value.get('notification_scope')=='PRIVATE_NOTIFY_SEND_RECORDER_ONLY' and value.get('hardware')=='NOT_RUN' and value.get('defaults_enabled') is False,'actual installed native generated-RC proof required')
    need(value.get('installed_helper_sha256')==CLI_SHA and value.get('installed_runtime_join')==dict(status='PASS_SOURCE_IDENTICAL_RUNTIME',modules=list(MODULES)) and type(value.get('page_size')) is int and value['page_size']>0 and value.get('release')=='NOT_ADMITTED','exact installed helper/runtime/page identities required')
    need(set(value.get('cases',{}))==CASES and len(value.get('lifecycle',{}))==6 and value.get('conflicts',{}).get('status')=='PASS','all six behavior/lifecycle and edited conflict checks required')
    load('setup6_extension_gate',HERE/'real_recovery.py').validate(value['extension'])
    security=value.get('security',{});need(set(security)=={'CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs'} and all(int(security[k],16)==0 for k in ('CapInh','CapPrm','CapEff','CapAmb')) and int(security['CapBnd'],16)==0xdb and security['NoNewPrivs']=='1','actual ordinary capability and NNP readback required')
    for name,row in value['cases'].items():
        observed=row.get('observations',row);need(row.get('status')=='PASS' and observed.get('shell_exit')==0 and observed.get('caller_continued') is True,'normal exit and caller continuation required')
    for row in value['lifecycle'].values():need(set(row['activation']['selected'])==set(MODULES) and row['activation']['repeat_unchanged'] is True and row['activation']['preview_readonly'] is True and row['removal']['status']=='PASS' and row['removal']['user_bytes_modes_preserved'] is True and row['removal']['unrelated_user_files_preserved'] is True,'actual generated lifecycle preservation required')
    need(value['conflicts']['activate_remove_exit']==2 and set(value['conflicts']['retained_edited_components'])=={'fish-done','zsh-history-substring-search'} and value['conflicts']['other_components_removed']==4,'edited block preservation/refusal required')


def validate_lifecycle(value):
    need(value.get('status')=='PASS_NATIVE_SETUP6_LEGACY_AND_REAL_MODULES' and value.get('base_count')==574 and value.get('restored_count')==574 and value.get('products')==VERSIONS,'exact seven-product581 lifecycle required')
    legacy=load('accepted_setup5_legacy_gate',SOURCE/'scripts/ci/setup5-native/contract.py');legacy.validate_lifecycle(value['legacy'])
    need([(r['phase'],r['inventory_count']) for r in value['events']]==[('install-real-seven',581),('rollback-real-setup5',581),('forward-real-setup6',581),('remove-real-seven',574)] and all(r['status']=='PASS' and r['legacy_homes_preserved'] and r['system_preserved'] and r['database_check'] for r in value['events']),'normal581 install and exact574 restoration required')
    validate_real(value['real_modules']);need(value.get('installed_payloads_preserved') is True and value.get('new_user_state_preserved_on_remove') is True and value.get('ordinary_user_processes_absent') is True,'installed package payloads changed during behavior')


SOURCE=None


def borrowed_snapshot():
    need(ROOTS is not None,'explicit packet roots required');rows={};total=0
    for role,root in ROOTS.items():
        for path in sorted(root.rglob('*')):
            info=path.lstat();need(not path.is_symlink() and (path.is_file() or path.is_dir()),'ordinary borrowed input tree required')
            if path.is_file():
                total+=info.st_size;need(len(rows)<2048 and info.st_size<=16*1024**2 and total<=64*1024**2,'bounded borrowed packet closure required')
                rows[role+'/'+str(path.relative_to(root))]=dict(bytes=info.st_size,sha256=digest(path),mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid,mtime_ns=info.st_mtime_ns)
    return rows


BORROWED=None
