# SPDX-License-Identifier: MIT
"""Finite signed341+fixed8 cache references; no acquisition, actors or authority."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit

API='BASE349_CACHE_REFERENCES_V3'
FAMILY='scripts/ci/first-login-enrollment-native-source'
FACTORY=FAMILY+'/profile.json'
INVENTORY='inputs/stages/baseline349.expected.lock'
FACTORY_PIN=dict(bytes=62259,sha256='ad874751a48cfd7e7d94f5d38d79caa138679be067cb113ead35150f0d3c78fa')
LOCK_PIN=dict(bytes=328101,sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f')
PROFILE_PIN=dict(bytes=168201,sha256='2c42c705654d31e639f389f9a868dada0d9df76813d865e766be7b7c08f8404c')
INVENTORY_PIN=dict(bytes=6800,sha256='579981195b654d8cdf142e4101dfc2bfffbc3576eed50f23796a06e90cf57453')
EXTRAS={'cmake','cppdap','jsoncpp','libuv','meson','ninja','python-tqdm','rhash'}
KEYRINGS={'archlinuxarm.gpg','archlinuxarm-trusted','archlinuxarm-revoked'}
ACTUAL=('source','ref','run','job','cache_provider','Root_trust','Root_resources','native_qualification','publication','dispatch')

class MissingInput(ValueError):
    def __init__(self,role):self.role=role;super().__init__('missing authoritative input: '+role)

def need(ok,why):
    if not ok:raise ValueError(why)

def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def decode(raw):
    def pairs(rows):
        result={}
        for k,v in rows:need(k not in result,'duplicate JSON key');result[k]=v
        return result
    value=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
    encoded(value);need(type(value)is dict,'JSON object');return value

def ordinary(path):
    path=Path(path);need(path.is_absolute()and '..'not in path.parts and str(path)==os.path.normpath(str(path))
        and not any(p.is_symlink()for p in(path,*path.parents)),'canonical ordinary ancestry');return path

def identity(info):return tuple(getattr(info,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def typed_pin(row,cap=2*1024**3):
    need(type(row)is dict and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<=row['bytes']<=cap
        and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'typed whole pin');return row

def stream(ref,observed,*,body=False,cap=2*1024**3):
    need(type(ref)is dict and set(ref)=={'path','bytes','sha256'},'explicit complete reference')
    typed_pin({k:ref[k]for k in('bytes','sha256')},cap);path=ordinary(ref['path'])
    if not path.exists():raise MissingInput(str(path))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and not before.st_mode&0o022
            and before.st_size==ref['bytes'],'exact ordinary single-link cache/DATA leaf')
        h=hashlib.sha256();size=0;parts=[]
        while block:=os.read(fd,1024**2):
            size+=len(block);need(size<=ref['bytes'],'bounded stream');h.update(block)
            if body:parts.append(block)
        need(size==ref['bytes']and h.hexdigest()==ref['sha256']and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable bytes/mode/inode')
    finally:os.close(fd)
    key=(before.st_dev,before.st_ino)
    need(all((info[0],info[1])!=key or name==str(path)for name,info in observed.items()),'no operand inode aliases')
    observed[str(path)]=identity(before)
    return b''.join(parts)if body else ref

def ref(path,p):return dict(path=str(path),**typed_pin(p))

def unchanged(observed):
    need(all(identity(ordinary(path).lstat())==before for path,before in observed.items()),'operand moved or changed after its one whole stream')

def filename(name):
    need(type(name)is str and re.fullmatch(r'[A-Za-z0-9._+@:~-]{1,255}',name)and name not in('.','..'),'fixed simple cache filename');return name

def url(value):
    need(type(value)is str and len(value)<=2048,'bounded pinned public URL');parts=urlsplit(value)
    need(parts.scheme=='https'and parts.hostname and not(parts.username or parts.password or parts.query or parts.fragment),'public HTTPS URL without credentials');return value

def inventory(raw):
    rows={}
    for line in raw.decode('ascii').splitlines():
        need(re.fullmatch(r'[a-z0-9][a-z0-9@._+-]* [^\s/]+',line),'typed inventory row')
        name,version=line.split(' ');need(name not in rows,'duplicate inventory name');rows[name]=version
    need(len(rows)==349 and raw==''.join(n+' '+v+'\n'for n,v in sorted(rows.items())).encode(),'complete exact sorted349 inventory');return rows

def metadata(*,source_root,source_map,base_lock,bootstrap_profile):
    """Read only explicit Source/lock/profile operands, never enumerate Source."""
    root=ordinary(source_root);need(root.is_dir(),'ordinary explicit Source root');observed={}
    need(source_map is not None,'explicit externally selected Source map reference')
    need(source_map['path']==str(root/'source-map.json'),'selected Source-map path')
    raw=stream(source_map,observed,body=True,cap=1024**2);mapping=decode(raw)
    alias=stream(ref(root/'source.lock.json',pin(raw)),observed,body=True,cap=1024**2);need(alias==raw,'byte-identical Source map/lock')
    need(mapping['kind']=='CURRENT_ONBOARDING_CLOSED_SOURCE_V3'and mapping['operation']=='first-login-enrollment-ui-current-v2'
        and mapping['actual']and all(v is None for v in mapping['actual'].values()),'held Source DATA, no fabricated actual fields')
    for member,wanted in((FACTORY,FACTORY_PIN),(INVENTORY,INVENTORY_PIN)):
        need(mapping['files'][member]==dict(wanted,mode=0o644),'fixed whole Source member descriptor')
    factory=decode(stream(ref(root/FACTORY,FACTORY_PIN),observed,body=True,cap=1024**2))
    for member,wanted in(('bootstrap/scripts/ci/inputs.lock.json',LOCK_PIN),('native/input-profile.json',PROFILE_PIN),('native/expected349.lock',INVENTORY_PIN)):
        need(factory['parent_files'][member]==dict(wanted,mode=0o644),'frozen parent bootstrap descriptor: '+member)
    for role,value,wanted in(('bootstrap/scripts/ci/inputs.lock.json',base_lock,LOCK_PIN),('native/input-profile.json',bootstrap_profile,PROFILE_PIN)):
        if value is None:raise MissingInput(role)
        need({k:value[k]for k in('bytes','sha256')}==wanted,'actual fixed parent operand: '+role)
    lock=decode(stream(base_lock,observed,body=True,cap=1024**2));profile=decode(stream(bootstrap_profile,observed,body=True,cap=1024**2))
    expected=inventory(stream(ref(root/INVENTORY,INVENTORY_PIN),observed,body=True,cap=1024**2))
    need(all(stat.S_IMODE((root/member).stat().st_mode)==0o644 for member in(FACTORY,INVENTORY)),'actual Source member modes join descriptors')
    need(len(lock['rootfs_packages'])==165 and len(lock['packages'])==248 and len(profile['additions']['rows'])==8
        and profile['additions']['count']==8 and profile['additions']['expected_augmented_package_count']==349 and not profile['additions']['unresolved'],'exact signed341 plus fixed8 profile')
    versions={};architectures={}
    for row in lock['rootfs_packages']:
        need(all(type(row[k])is list and len(row[k])==1 for k in('name','version','arch')),'typed complete rootfs record')
        n,v,a=(row[k][0]for k in('name','version','arch'));need(n not in versions and a in('any','aarch64'),'unique rootfs package/architecture');versions[n]=v;architectures[n]=a
    for row in lock['packages']:
        need(row['arch']in('any','aarch64'),'exact base architecture');versions[row['name']]=row['version'];architectures[row['name']]=row['arch']
    need(len(versions)==341 and profile['original341']['package_count']==341 and profile['original341']['packages']==versions,'authentic complete original341 union')
    extra=profile['additions']['rows'];need({r['name']for r in extra}==EXTRAS and len({r['name']for r in lock['packages']})==248,'exact fixed supplemental names and unique original package set')
    for row in extra:
        need(row['name']not in versions and row['arch']in('any','aarch64'),'additions never replace the original341');versions[row['name']]=row['version'];architectures[row['name']]=row['arch']
    need(versions==expected,'all349 real versions and architectures join expected inventory')
    files={};groups=dict(base_materials={},supplemental_materials={},keyring_materials={})
    def add(row,group,signature=False):
        name=filename(row['filename']+('.sig'if signature else''));wanted=dict(bytes=row['signature_size']if signature else row['size'],sha256=row['signature_sha256']if signature else row['sha256'])
        typed_pin(wanted);need(name not in files,'distinct consumed cache member');entry=dict(wanted,url=url(row['url']+('.sig'if signature else'')),group=group)
        files[name]=entry;groups[group][name]=wanted
    for row in[lock['rootfs'],*lock['packages']]:add(row,'base_materials');add(row,'base_materials',True)
    for row in extra:add(row,'supplemental_materials');add(row,'supplemental_materials',True)
    need(len(lock['keyring_files'])==3 and {r['filename']for r in lock['keyring_files']}==KEYRINGS,'exact original public keyring set')
    for row in lock['keyring_files']:add(row,'keyring_materials')
    need(len(files)==517 and re.fullmatch('[0-9A-F]{40}',lock['signer_fingerprint']),'complete517 inputs and fixed declared primary')
    unchanged(observed)
    return dict(schema=3,api=API,files=files,groups=groups,base_lock=base_lock,bootstrap_profile=bootstrap_profile,
        source_map=source_map,baseline_inventory=ref(root/INVENTORY,INVENTORY_PIN),rootfs=lock['rootfs'],supplement_rows=extra,
        packages={n:dict(version=versions[n],arch=architectures[n])for n in sorted(versions)},signer_fingerprint=lock['signer_fingerprint'],
        keyring_commit=lock['keyring_commit'],metadata_observations=observed,actual=dict.fromkeys(ACTUAL))

def cache_names(root):
    names=set()
    with os.scandir(root)as entries:
        for entry in entries:
            need(len(names)<518,'finite cache directory cap');names.add(entry.name)
    return names

def _selected_references(plan,materials):
    need(type(materials)is dict and set(materials)<=set(plan['files']),'only explicitly selected finite517 material names')
    paths=[]
    for name,value in materials.items():
        need(type(value)is dict and set(value)=={'path','bytes','sha256'},'explicit complete selected reference')
        need({k:value[k]for k in('bytes','sha256')}=={k:plan['files'][name][k]for k in('bytes','sha256')},'selected whole pin joins frozen metadata: '+name)
        paths.append(str(ordinary(value['path'])))
    need(len(paths)==len(set(paths)),'distinct selected operand paths')
    observed=dict(plan['metadata_observations']);groups={k:{}for k in plan['groups']}
    for name,value in sorted(materials.items()):
        stream(value,observed)
        need(Path(value['path']).stat().st_uid==os.geteuid(),'caller-owned selected leaf')
        groups[plan['files'][name]['group']][name]=dict(value)
    unchanged(observed)
    missing={name:row for name,row in sorted(plan['files'].items())if name not in materials}
    return dict(schema=3,kind='BASE349_REFERENCE_CHECKPOINT_DATA_V3',api=API,
        status='HOLD_MISSING_EXPLICIT_MATERIALS'if missing else'COMPLETE_WHOLE_REFERENCES_DATA_ONLY',complete=not missing,
        base_lock=plan['base_lock'],baseline_inventory=plan['baseline_inventory'],bootstrap_profile=plan['bootstrap_profile'],source_map=plan['source_map'],
        **groups,supplement_rows=plan['supplement_rows'],packages=plan['packages'],signer_fingerprint=plan['signer_fingerprint'],keyring_commit=plan['keyring_commit'],
        required_files=517,required_bytes=sum(r['bytes']for r in plan['files'].values()),missing_materials=missing,
        verified_files=len(materials),verified_bytes=sum(r['bytes']for r in materials.values()),archive_streams=len(materials),archive_copies=0,
        authentication='SEPARATE_CURRENT_ROOT_TRUST_AND_ACTUAL_GPG_REQUIRED',current_image_selector_compatible=False,
        required_consumer_field='supplemental_materials',actual=dict.fromkeys(ACTUAL))

def assess_selected_references(*,materials,source_root,source_map,base_lock,bootstrap_profile):
    """Stream only explicit selected refs; return all missing pins as HOLD DATA.

    A broader immutable carrier is allowed: no directory is enumerated. Unknown,
    stale, aliased or changed selected operands refuse rather than becoming HOLD.
    """
    plan=metadata(source_root=source_root,source_map=source_map,base_lock=base_lock,bootstrap_profile=bootstrap_profile)
    return _selected_references(plan,materials)

def _complete_references(plan,result):
    if not result['complete']:raise MissingInput('materials/'+next(iter(result['missing_materials'])))
    return dict(result,kind='VERIFIED_BASE349_CACHE_REFERENCES_DATA_V3',cache_files=result['verified_files'],cache_bytes=result['verified_bytes'],
        rootfs=result['base_materials'][plan['rootfs']['filename']],rootfs_signature=result['base_materials'][plan['rootfs']['filename']+'.sig'])

def build_selected_references(*,materials,source_root,source_map,base_lock,bootstrap_profile):
    """Complete517 handoff from explicit whole refs, including split carriers."""
    plan=metadata(source_root=source_root,source_map=source_map,base_lock=base_lock,bootstrap_profile=bootstrap_profile)
    need(type(materials)is dict,'explicit selected material map')
    missing=set(plan['files'])-set(materials)
    if missing:raise MissingInput('materials/'+sorted(missing)[0])
    return _complete_references(plan,_selected_references(plan,materials))

def build_references(*,cache_root,source_root,source_map,base_lock,bootstrap_profile,consumed_names=None):
    """Reference exactly517 existing files, once each; copy/write/execute nothing."""
    plan=metadata(source_root=source_root,source_map=source_map,base_lock=base_lock,bootstrap_profile=bootstrap_profile)
    wanted=set(plan['files'])
    if consumed_names is not None:need(type(consumed_names)is list and len(consumed_names)==len(set(consumed_names))and set(consumed_names)==wanted,'exact consumed operand set, no extras or omissions')
    cache=ordinary(cache_root)
    if not cache.exists():raise MissingInput('complete517_cache_root')
    before=cache.lstat();need(stat.S_ISDIR(before.st_mode)and before.st_uid==os.geteuid()and stat.S_IMODE(before.st_mode)==0o700,'existing owner0700 finite cache')
    found=cache_names(cache);missing=wanted-found
    if missing:raise MissingInput('cache/'+sorted(missing)[0])
    need(found==wanted,'extra consumed cache members refuse before body reads')
    materials={name:ref(cache/name,{k:row[k]for k in('bytes','sha256')})for name,row in plan['files'].items()}
    result=_complete_references(plan,_selected_references(plan,materials))
    need(cache_names(cache)==wanted and identity(before)==identity(cache.lstat()),'cache namespace/directory stayed fixed')
    return result

def assembler_fields(result):
    """Map complete reference DATA to operands; assembler independently checks all."""
    if result is None:raise MissingInput('complete517_reference_result')
    need(type(result)is dict and result['api']==API and result['kind']in('VERIFIED_BASE349_CACHE_REFERENCES_DATA_V3','BASE349_REFERENCE_CHECKPOINT_DATA_V3'),'reference result DATA')
    if result['missing_materials']:raise MissingInput('materials/'+sorted(result['missing_materials'])[0])
    need(result['complete']is True and result['verified_files']==517 and all(v is None for v in result['actual'].values()),'complete517 references with no substituted authority')
    for key,count in(('base_materials',498),('supplemental_materials',16),('keyring_materials',3)):
        need(type(result[key])is dict and len(result[key])==count,'complete distinct material group')
    return {key:result[key]for key in('base_lock','bootstrap_profile','base_materials','supplemental_materials','keyring_materials')}

def acquisition_plan(plan,*,cache_root,public14_root,retained_root,retained_git,helper_root,deadline):
    """Actual bounded argv/URLs as DATA only; no environment or secret reads."""
    need(plan['api']==API and type(deadline)in(int,float)and math.isfinite(deadline)and deadline>0,'explicit provider plan and finite caller deadline')
    cache=ordinary(cache_root);public=ordinary(public14_root);retained=ordinary(retained_root);git=ordinary(retained_git);helpers=ordinary(helper_root)
    secrets=['CACHY_OLD_FOUR_'+tag+'_%02d'%i for tag,count in(('JBIGKIT',2),('JBIGKIT_SIG',1),('LIBTIFF',15),('LIBTIFF_SIG',1))for i in range(1,count+1)]
    secrets+=['CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_01','CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_02','CACHY_RETAINED_BUBBLEWRAP_V1_SIGNATURE_01'];need(len(secrets)==22,'unchanged22 existing secret names')
    downloads=[]
    # The original parent-fetch fallback covers exactly rootfs2 + keyrings3.
    base5={plan['rootfs']['filename'],plan['rootfs']['filename']+'.sig',*KEYRINGS}
    for name in sorted(base5|set(plan['groups']['supplemental_materials'])):
        row=plan['files'][name];downloads.append(dict(filename=name,whole_pin={k:row[k]for k in('bytes','sha256')},
            argv=['curl','--fail','--show-error','--location','--proto','=https','--proto-redir','=https','--connect-timeout','15','--max-time','90','--output',str(cache/name),row['url']],
            requires_fresh_missing_destination=True,Root_transport_admission=None))
    return dict(schema=3,status='HOSTED_SEED_AND_ACQUISITION_COMMAND_DATA_NOT_EXECUTED',existing_secret_names=secrets,secret_values=None,
        private6=dict(entry='old_four_seed.seed_current_build_cache',lock_sha256=LOCK_PIN['sha256'],environment_expansion=False),
        public14=dict(source='04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd',seed_sha256='a7857658af224984065e575f6ffed8308ea85027d46eace8bda146d9033e93b3',
            index_sha256='a388c8c8ba8e06cb92fd2be598b86e433c4e403b6e71a0f15b1eaec381bb7300',argv=['python3','-I','-B',str(public/'seed.py'),'--cache',str(cache)]),
        native248=dict(source='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad',argv=['python3','-B',str(helpers/'prepare.py'),
            '--carrier',str(retained),'--git-dir',str(git),'--cache',str(cache),'--mode','native248','--lock',plan['base_lock']['path'],'--deadline',str(deadline)]),
        remaining_base5_and_supplement8=downloads,signature_verification='UNCHANGED_SEPARATE_ACTUAL_GPG_AND_METADATA_GATES',
        native_build=None,Root_admission=None,actual=dict.fromkeys(ACTUAL))

if __name__=='__main__':raise SystemExit('Pure bounded DATA callbacks only; no acquisition or actor entry')
