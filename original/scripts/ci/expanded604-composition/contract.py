# SPDX-License-Identifier: MIT
"""Separate finite604 development selection; unknown Welcome native inputs refuse first."""
import hashlib
import importlib.util
import json
import re
import stat
import subprocess
import sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
BASE_SHA=BEFORE='2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
TARGET_SHA=AFTER='76c37db5eb097662f4a9ca0465680de285466b0443916a50255ea5b8f6d6c946'
OLD600='d263a3ca9089c204603f2e12b80dc4f209ee6e636f10da940a514040b636db79'
BUILDER='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
LABEL='org.cachy-asahi.expanded604.job'
LEGACY='b6b17e5f6b322f160f7eeb22c8a01380a3c854cd'
SEVEN='7fee76d68e5fd75437d8b49aaaced8376d2215cd'
EIGHT='0d7ec3b5ec9b473c9a1b2557735f8dadd8de3f50'
BANG='cachy-asahi-fish-bang-bang'
SETUP='cachy-asahi-setup'
SCRIPTS={'cachy-asahi-welcome','cachy-asahi-doctor','cachy-asahi-mirrors','cachy-asahi-zsh-syntax-highlighting',
         'cachy-asahi-zsh-history-substring-search','cachy-asahi-fish-autopair','cachy-asahi-fish-done'}
AUDIO={'asahi-audio','alsa-ucm-conf-asahi','speakersafetyd','bankstown','triforce-lv2','lsp-plugins-lv2'}
MANAGEMENT={'cachy-asahi-apps':'0.1.0-5','cachy-asahi-repository-runtime':'0.1.0-1','cachy-asahi-cache':'0.2.0-1','cachy-asahi-orphans':'0.1.0-1'}
VERSIONS={**MANAGEMENT,'cachy-asahi-welcome':'0.1.0-2',SETUP:'0.1.0-5',BANG:'0.1.0-2'}
ADDITIONS=AUDIO|SCRIPTS|MANAGEMENT.keys()
UPGRADES={BANG:dict(before='0.1.0-1',after='0.1.0-2'),SETUP:dict(before='0.1.0-3',after='0.1.0-5')}
PHASES=('baseline587','install604','same-version604','remove-to587','restore604','final587')
LD_PHASES=('baseline587','install604','same-version604','remove-to587-upgraded','remove-to587','restore604','final587-upgraded','final587')


def need(ok,why):
    if not ok:raise ValueError(why)

def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()

def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def safe(path):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n\0') and
        not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute path required');return path

def relative(name):
    need(type(name) is str and name and not name.startswith('/') and '\\' not in name and
         all(part not in ('','.','..') for part in name.split('/')) and all(32<=ord(c)<127 for c in name),
         'safe relative path required');return name

def ref(value,cap=16*1024**2):
    need(type(value) is dict and set(value)=={'path','bytes','sha256'} and type(value['bytes']) is int and
         0<value['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',value['sha256'] or ''),'exact bounded byte reference required')
    relative(value['path']);return value

def checked(root,value,cap=16*1024**2):
    ref(value,cap);path=safe(Path(root)/value['path']);info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size==value['bytes'] and sha(path)==value['sha256'],
         'input identity differs: '+value['path']);return path

def read(path,cap=4*1024**2):
    safe(Path(path).absolute());need(Path(path).stat().st_size<=cap,'JSON byte bound')
    def pairs(rows):
        result={}
        for key,value in rows:need(key not in result,'duplicate JSON key');result[key]=value
        return result
    def constant(_):raise ValueError('nonfinite JSON')
    return json.loads(Path(path).read_bytes(),object_pairs_hook=pairs,parse_constant=constant)

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec)
    sys.modules[name]=value;spec.loader.exec_module(value);return value

def revision(path):return subprocess.check_output(['git','-C',str(path),'rev-parse','HEAD'],text=True,timeout=15).strip()

def lock(raw,count):
    rows=[line.split() for line in raw.decode().splitlines()]
    need(len(rows)==count and all(len(row)==2 for row in rows) and len(dict(rows))==count,'exact distinct package inventory required')
    return dict(rows)

def inventory_bytes(value):return ''.join(name+' '+version+'\n' for name,version in sorted(value.items())).encode()

def scoped_load(name,path,aliases=None):
    aliases=aliases or {};missing=object();previous={key:sys.modules.get(key,missing) for key in aliases}
    try:
        sys.modules.update(aliases);return load(name,path)
    finally:
        for key,value in previous.items():
            if value is missing:sys.modules.pop(key,None)
            else:sys.modules[key]=value


def locks():
    a=(HERE/'expected587.lock').read_bytes();b=(HERE/'expected604.lock').read_bytes()
    need(hashlib.sha256(a).hexdigest()==BASE_SHA and hashlib.sha256(b).hexdigest()==TARGET_SHA,'fixed587/604 lock bytes differ')
    before,after=lock(a,587),lock(b,604)
    need(after.keys()-before.keys()==ADDITIONS and before.keys()<=after.keys() and
         all(before[n]==v['before'] and after[n]==v['after'] for n,v in UPGRADES.items()) and
         all(after[n]==version for n,version in VERSIONS.items()) and
         all(after[n]==version for n,version in before.items() if n not in UPGRADES),'only17 additions and2 predecessor upgrades permitted')
    return before,after


def selected(before,incoming):
    old,new=locks()
    need(before==old and set(incoming)==ADDITIONS|UPGRADES.keys() and len(incoming)==19 and before|incoming==new,
         'exact finite19 incoming/604 dependency transaction required')
    return new


def policy(*,bound=True):
    value=read(HERE/'input-policy.json');locks()
    need(value.get('schema_version')==1 and value.get('legacy_source')==LEGACY and value.get('retained_seven_source')==SEVEN and
         value.get('eight_pair_source')==EIGHT and value.get('original587_sha256')==BEFORE and
         value.get('expected600_sha256')==OLD600 and value.get('expected604_sha256')==TARGET_SHA and
         value.get('native600_source')=='8cc0a67295dc68772fc86ad81148eac3bec9eb56','exact accepted587/600 and separate604 policy required')
    need(value.get('management')==read_policy_management() and value.get('setup')==dict(source='79d8d2f53510e4f3a04f39c1b1e24c999aa32e44',
         index=dict(path='index.json',bytes=25005,sha256='b1e4208d2f32935f2e5cb1c1e3535cc49f44c7bfe08e7d64692b8ac3781d5a5d')),
         'exact accepted four management/Setup5 carrier binding required')
    need(value.get('combined_materialization_source')==LEGACY and value.get('combined',{}).get('source')=='22c095c85cb6fd79d5de0f0ee43ca012c32c2aeb',
         'unchanged native600 driver provenance/materialization binding required')
    if bound:
        welcome=value.get('welcome',{})
        need(value.get('status')=='ROOT_BOUND_FINAL604_ACCEPTED_INPUTS' and
             welcome.get('status')=='ROOT_ACCEPTED_NATIVE_WELCOME2_PAIR_AND_CLI_LIFECYCLE' and
             re.fullmatch('[0-9a-f]{40}',welcome.get('source') or '') and re.fullmatch('[0-9a-f]{40}',welcome.get('carrier_source') or '') and
             welcome.get('candidate_source')=='96aa3e7a81840b7eba6ba07188481fd89631fb6b' and welcome.get('index') is not None,
             'Welcome2 native pair/CLI lifecycle inputs remain UNBOUND; no secrets or actors allowed')
        ref(welcome['index'],4*1024**2)
    return value


def read_policy_management():
    return dict(schema_version=1,status='ROOT_BOUND_NATIVE_INPUT_PACKET',packet_source='92e433fa79eb57bfb3e4038feb30e7a7c87c652f',
        packet_index=dict(path='index.json',bytes=104659,sha256='b60048aa1312d22b1012a5d2d2e4c5185c8087b3a8f2b6c410ff9ec6a1dddfcf'),versions=MANAGEMENT)


def held_source(root):
    pins=read(HERE/'held-pins.json');need(1<=len(pins)<=512,'bounded held helper closure required')
    for name,row in pins.items():checked(root,dict(path=name,**row),16*1024**2)
    return pins


def verify_source(root):
    policy();manifest=read(HERE/'source-manifest.json')
    need(manifest.get('schema_version')==1 and manifest.get('status')=='FROZEN_ROOT_FINAL_SOURCE' and
         1<=len(manifest.get('files',{}))<=512,'Root final604 source manifest remains UNBOUND')
    held_source(root)
    for name,row in manifest['files'].items():checked(root,dict(path=name,**row),16*1024**2)
    return manifest


def inputs(args,value):
    need(value==policy(),'complete current bound input policy required')
    bound_inputs(args.code,args.legacy_source,args.eight_source,args.seven_source,args.management_source,args.setup_source,args.welcome_source,value)
    module=scoped_load('_expanded604_inputs',HERE/'inputs.py',{'contract':sys.modules[__name__]})
    result=module.validate_inputs(args.code,args.legacy_source,args.eight_source,args.seven_source,args.management_source,args.setup_source,args.welcome_source,value)
    for name,pin in value['combined']['files'].items():
        need(pin['path']==name,'unchanged combined source path differs');checked(args.legacy_source,pin)
    legacy_contract=load('_604_preflight_legacy_contract',args.legacy_source/'scripts/ci/expanded-development-composition/contract.py')
    reader=scoped_load('_604_preflight_audio_reader',args.legacy_source/'scripts/ci/expanded-development-composition/inputs.py',{'contract':legacy_contract})
    paths=list(sys.path)
    try:audios=reader.audio(args.audio_inputs,args.legacy_source)
    finally:sys.path[:]=paths
    need(set(audios)==AUDIO,'all six held audio inputs required before producer mutation')
    result['audios']=audios
    result['summary'].update(combined_declared_source=value['combined']['source'],combined_materialized_from=LEGACY,
                             combined_source_files=len(value['combined']['files']),audio_inputs=6)
    return result


def bound_inputs(source,legacy,eight,seven,management,setup,welcome,value):
    need(value==policy(),'current final604 input policy required')
    for root,expected in ((legacy,LEGACY),(eight,EIGHT),(seven,SEVEN),
            (management,value['management']['packet_source']),(setup,value['setup']['source']),(welcome,value['welcome']['carrier_source'])):
        need(revision(root)==expected,'exact immutable input carrier/legacy checkout differs')
    old=load('_604_held_original600_contract',source/'scripts/ci/expanded600-installer-vm/contract.py')
    old.legacy(legacy,git=False)
    prerequisites(eight,value)


def prerequisites(root,value):
    observer=read(checked(root,value['prerequisites']['observer587']));native=read(checked(root,value['prerequisites']['native600']))
    need(observer.get('status')=='ROOT_ACCEPTED_FULL587_INSTALLER_SOFTWARE' and
         all(observer.get(k)=='PASS' for k in ('ordinary_parent_retired','independent_root_readback','cleanup')) and observer.get('hardware')=='NOT_RUN',
         'accepted original587 observer prerequisite missing')
    need(native.get('status')=='ROOT_ACCEPTED_NATIVE_EXPANDED600_COMPOSITION' and native.get('source_sha')==value['native600_source'] and
         native.get('package_count')==600 and native.get('expected600_sha256')==OLD600 and native.get('bang_version')=='0.1.0-2' and
         all(native.get(k)=='PASS' for k in ('bang_pair_bytes_buildinfo','installed_lifecycle','installed_six_modules','cleanup')) and native.get('hardware')=='NOT_RUN',
         'accepted native600 composition prerequisite missing')
    return dict(observer587=observer,native600=native)


def target_manifest(root):
    value=read(root/'manifest.json',1024**2);before,after=locks()
    need(value.get('schema_version')==1 and value.get('status')=='READY_SIGNED_EXPANDED604' and
         value.get('expected_lock')==dict(path='expected-installed.lock',sha256=TARGET_SHA),'exact604 manifest identity required')
    need(sha(root/'expected-installed.lock')==TARGET_SHA and lock((root/'expected-installed.lock').read_bytes(),604)==after and
         type(value.get('packages')) is list and len(value['packages'])==604 and
         len({r['name'] for r in value['packages']})==604 and {r['name']:r['version'] for r in value['packages']}==after,
         'complete604 target cache inventory differs')
    builder=value.get('builder_lock',{});need(builder.get('path')=='builder-packages.lock' and builder.get('sha256')==BUILDER,'original574 source-native builder provenance required')
    checked(root,dict(path=builder['path'],bytes=builder['size'],sha256=BUILDER),1024**2)
    lock((root/builder['path']).read_bytes(),574)
    roles=value['preparation']['signer_roles'];need(set(roles)=={'ephemeral_TEST','upstream_ALARM'} and len(set(roles.values()))==2 and
        all(re.fullmatch('[0-9A-F]{40}',v) for v in roles.values()),'same two exact public signer roles required')
    total=0
    for row in value['packages']:
        total+=row['size'];need(total<=4*1024**3,'original compressed cache aggregate bound')
        checked(root,dict(path=row['archive'],bytes=row['size'],sha256=row['sha256']),256*1024**2)
        need(row['signature']==row['archive']+'.sig' and row['signer'] in roles.values(),'fixed target detached signature/signer required')
        checked(root,dict(path=row['signature'],bytes=row['signature_size'],sha256=row['signature_sha256']),1024**2)
    need(len(value['keyrings'])==2,'two original public keyrings required')
    for key in value['keyrings']:checked(root,dict(path=key['path'],bytes=key['size'],sha256=key['sha256']),1024**2)
    return value,dict(path='manifest.json',bytes=(root/'manifest.json').stat().st_size,sha256=sha(root/'manifest.json')),after


def validate_result(value):
    need(value.get('status')=='PASS_EXPANDED604_METADATA_LIFECYCLE' and value.get('baseline_sha256')==BASE_SHA and value.get('target_sha256')==TARGET_SHA and
         value.get('package_count')==604 and value.get('restored_count')==587 and value.get('defaults_enabled') is False and
         all(value.get(k)=='NOT_RUN' for k in ('notification_delivery','services','audio_execution','hardware')) and
         value.get('apps_plan')==value.get('cache_removal')=='NOT_APPLIED','actual separate604 metadata lifecycle receipt required')
    ref(value.get('combined_shell'),1024**2)
    events=value.get('events',[]);need([e.get('phase') for e in events]==list(PHASES),'six exact604 checkpoints required')
    for e in events:
        installed=e['phase'] in ('install604','same-version604','restore604')
        need(e.get('status')=='PASS' and e.get('count')==(604 if installed else 587) and
             e.get('upgrades')=={n:v['after' if installed else 'before'] for n,v in UPGRADES.items()} and
             all(e.get(k) is True for k in ('signatures','dependencies','payload','ownership','originals_preserved','user_config_preserved')),
             'strict actual604 transition/preservation absent')
    interim=value.get('subtransactions',[]);need([e.get('phase') for e in interim]==['remove-to587-upgraded','final587-upgraded'] and
        all(e.get('status')=='PASS' and e.get('count')==587 and e.get('upgrades')=={n:v['after'] for n,v in UPGRADES.items()} for e in interim),
        'both predecessor-upgraded interim587 states required')
    states=value.get('ldconfig',[]);need([r.get('phase') for r in states]==list(LD_PHASES),'eight actual ldconfig/aux states required')
    for i,row in enumerate(states):
        need(row.get('helper_exit')=='NOT_OBSERVED' and row.get('transition',{}).get('kind') in ({'BASELINE'} if i==0 else {'RAW_EQUAL','EXACT_LOAD_SAVE_ORDER'}) and
            all(re.fullmatch('[0-9a-f]{64}',row.get(k) or '') for k in ('state_sha256','aux_sha256')),'unchanged raw ldconfig state/order qualification required')
    return value

def validate_combined(value):
    cases={'fish-bang-auto-done','fish-done-auto-bang','zsh-auto-highlight-substring',
           'zsh-highlight-substring-auto','fish-noninteractive','zsh-noninteractive'}
    need(value.get('status')=='PASS_INSTALLED_SIX_MODULE_SHELL_COEXISTENCE' and
         value.get('scope')=='ACTUAL_INSTALLED_SIX_MODULES' and value.get('machine')=='aarch64' and
         type(value.get('uid')) is int and value['uid']>0 and
         value.get('notification_delivery')=='NOT_RUN' and
         value.get('notification_scope')=='PRIVATE_NOTIFY_SEND_RECORDER_ONLY' and
         value.get('hardware')=='NOT_RUN' and value.get('defaults_enabled') is False and
         type(value.get('cases')) is dict and set(value['cases'])==cases,
         'actual installed six-module receipt required')
    for name,row in value['cases'].items():
        need(row.get('status')=='PASS','combined shell case failed')
        observations=row.get('observations',row)
        need(observations.get('shell_exit')==0 and observations.get('caller_continued') is True,
             'normal shell exit and caller continuation required')
        if name.startswith('fish-') and not name.endswith('noninteractive'):
            need(all(observations.get(k) is True for k in ('bindings_preserved','functions_preserved','hooks_preserved')) and
                 'notification' in observations,'Fish preservation/private recorder evidence absent')
        elif name.startswith('zsh-') and not name.endswith('noninteractive'):
            need(row.get('bindings_preserved') is True and row.get('namespaces_widgets_preserved') is True,
                 'Zsh preservation evidence absent')
        else:need(row.get('config_history_preserved') is True and row.get('notifications')==0,
                  'noninteractive no-op receipt incomplete')
