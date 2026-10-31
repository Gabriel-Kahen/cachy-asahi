# SPDX-License-Identifier: MIT
"""Original helper inputs plus genuine accepted Welcome5/DNS2 pairs, DATA only."""
import hashlib,importlib.util,json,re,shutil,stat,sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROLE='scripts/ci/welcome5-native-gui'
PROFILE=None
EXPECTED={'welcome5':('cachy-asahi-welcome','0.1.0-5','85ffec834fc72ef8764cdcae828a12ec8ddf7f20',39104384568),
          'dns2':('cachy-asahi-dns','0.1.0-2','59a9aee351226e93e22574fd14bd3e0b45c8368d',39101228683)}

def need(ok,message):
    if not ok:raise ValueError(message)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def read(path,cap=16*1024**2):
    path=Path(path);regular(path,cap)
    def pairs(rows):
        value={}
        for k,v in rows:need(k not in value,'duplicate JSON field');value[k]=v
        return value
    return json.loads(path.read_bytes(),object_pairs_hook=pairs)
def regular(path,cap):
    path=Path(path);need(path.is_absolute()and not any(p.is_symlink()for p in (path,*path.parents)),'ordinary absolute input required');s=path.lstat()
    need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=cap,'bounded ordinary input required');return s

def pinned(root,name,pin,cap=16*1024**2):
    path=Path(name);need(not path.is_absolute()and path.parts and '..'not in path.parts,'safe relative input required');path=root/path
    s=regular(path,cap);need(pin==dict(bytes=s.st_size,sha256=digest(path)),'input byte pin differs: '+name);return path

def verify_source(source):
    value=read(HERE/'source-manifest.json');need(value.get('schema_version')==1 and 100<=len(value['files'])<=512,'closed new GUI source required')
    for name,row in value['files'].items():pinned(source,name,row)

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def selection(source):
    verify_source(source);value=read(HERE/'input-policy.json')
    need(value.get('schema_version')==1 and value.get('status')=='ROOT_SELECTED_PUBLIC_NATIVE_INPUTS'and
        set(value.get('inputs',{}))=={'welcome5','dns2'}and all(value.get(k)is None for k in ('actual_source','actual_ref','minimal_run','overlay_run')),
        'new native pair carrier selection remains NULL; no GUI acceptance borrowed')
    for role,expected in EXPECTED.items():
        row=value['inputs'][role];need((row.get('name'),row.get('version'),row.get('native_source'),row.get('native_run'))==expected and
            re.fullmatch('[0-9a-f]{40}',row.get('carrier_source')or'')and re.fullmatch('refs/heads/codex/[a-z0-9-]+',row.get('carrier_ref')or''),
            'genuine public native source/run/carrier role required')
    load('welcome5_gui_renewal_selection',HERE/'renewal.py').selection(source)
    return value

def stage(source,assets,output):
    lock=stage_data(source,assets,output,selection(source))
    return load('welcome5_gui_renewed_signatures',HERE/'renewal.py').apply(source,assets,output,lock)

def stage_data(source,assets,output,policy):
    # Pure package/source inspection API also supports local source calibration.
    # The actor-facing stage() always runs the NULL/public selection guard first.
    need(not output.exists(),'fresh product staging required')
    # This checks the whole original three source-bound archive operands. Only
    # the two original helper products survive into the new installation set.
    oldC=load('welcome5_held_native_contract',source/'scripts/ci/welcome-management-native/native_contract.py')
    previous=sys.modules.get('native_contract')
    try:
        sys.modules['native_contract']=oldC;old=load('welcome5_held_candidates',source/'scripts/ci/welcome-management-native/candidates.py');old.C=oldC
    finally:
        if previous is None:sys.modules.pop('native_contract',None)
        else:sys.modules['native_contract']=previous
    lock=old.stage(source,assets/'held',output)
    products=lock['products'];products.pop('cachy-asahi-welcome')
    for filename in list(output.iterdir()):
        if filename.name.startswith('cachy-asahi-welcome-'):filename.unlink()
    trust=[dict(key='TEST-public.asc',signer=read(output/'control.json')['signer'])]
    checks=load('welcome5_gui_package_checks',source/'scripts/checks/package_checks.py')
    sys.path[:0]=[str(source/'scripts/build'),str(source/'scripts/checks')]
    build=load('welcome5_gui_build_binding',source/'scripts/build/build.py')
    for role,expected in EXPECTED.items():
        selection_row=policy['inputs'][role];carrier=assets/role
        index_path=pinned(carrier,selection_row['index_path'],selection_row['index_pin'],1024**2);index=read(index_path)
        need(index.get('schema_version')==1 and index.get('kind')=='PROJECT_WELCOME45_DNS2_NATIVE_PAIR_INPUTS_ONLY'and
            index.get('authority_scope')=='NATIVE_PAIRS_ONLY_NO_GUI_OR_CURRENT606_ACCEPTANCE','new carrier input-only scope differs')
        row=index['roles'][role];need((row['name'],row['version'],row['native_source'],row['native_run'])==expected,'native role identity differs')
        for relative,pin in row['source_files'].items():pinned(source,relative,pin)
        recipe=checks.recipe(source/row['recipe_directory']/'PKGBUILD');need(not recipe['errors'],'new role recipe invalid')
        decision_path=pinned(carrier,row['Root_decision'],index['files'][row['Root_decision']],131072)
        need(dict(bytes=decision_path.stat().st_size,sha256=digest(decision_path))==selection_row['decision_pin'],'Root native decision pin differs')
        decision=read(decision_path);need(decision.get('source')==expected[2]and decision.get('run_id'if role=='welcome5'else'run')==expected[3]and
            decision.get('architecture'if role=='welcome5'else'actual_architecture')=='aarch64'and decision.get('status')==selection_row['decision_status'],'exact genuine accepted native decision required')
        paths=[]
        for side in ('a','b'):
            path=pinned(carrier,row['files'][side],index['files'][row['files'][side]],8*1024**2);checked=checks.package(path)
            need(not checked['errors']and not build.bind_artifact(recipe['metadata'],checked,recipe['input_sha256']['PKGBUILD']),'complete archive/recipe metadata join failed')
            payload={k:v for k,v in checked['members'].items()if v['type']!='5'and k not in ('.PKGINFO','.BUILDINFO','.MTREE')}
            need(payload==row['payload'],'native payload/source index differs')
            need(checked['metadata']['.PKGINFO'].get('pkgname')==[expected[0]]and checked['metadata']['.PKGINFO'].get('pkgver')==[expected[1]],'actual package name/version differs')
            need(set(checked['elf'])==({'usr/bin/cachy-asahi-welcome'}if role=='welcome5'else set())and all(r.get('machine')==183 and not r.get('errors')for r in checked['elf'].values()),'exact native AArch64 ELF set required')
            paths.append((path,checked,payload))
        need(digest(paths[0][0])==digest(paths[1][0])and paths[0][1]['members']==paths[1][1]['members'],'full accepted pair equality differs')
        archive=paths[0][0].name;need(archive==expected[0]+'-'+expected[1]+('-aarch64'if role=='welcome5'else'-any')+'.pkg.tar.xz','fixed native archive filename required')
        sig=pinned(carrier,row['signature'],index['files'][row['signature']],16384);key=pinned(carrier,row['key'],index['files'][row['key']],65536)
        keyname=role+'-TEST.asc';shutil.copyfile(key,output/keyname);shutil.copyfile(paths[0][0],output/archive);shutil.copyfile(sig,output/(archive+'.sig'))
        need(re.fullmatch('[0-9A-F]{40}',row['signer']),'explicit TEST signer required');trust.append(dict(key=keyname,signer=row['signer']))
        products[expected[0]]=dict(archive=archive,version=expected[1],sha256=digest(paths[0][0]),payload=paths[0][2],native_source=expected[2],native_run=expected[3],input_only=True)
    lock.update(profile=PROFILE,products=products,producer_lifecycle='PASS_GENUINE_NATIVE_PAIR_INPUTS_ONLY_GUI_NOT_RUN',GUI='NOT_RUN',
        policy=dict(ui=lock['policy']['ui'],scope='HELD_UI_POLICY_WITH_NEW_NATIVE_INPUT_ROLES_NOT_OLD_WELCOME4_GUI_CREDIT',
            products={n:dict(version=r['version'],sha256=r['sha256'])for n,r in products.items()}))
    for name,value in (('products.json',products),('candidate-lock.json',lock),('trust.json',trust)):(output/name).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    shutil.copyfile(HERE/'trust.py',output/'trust.py');return lock
