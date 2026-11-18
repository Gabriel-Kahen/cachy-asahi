# SPDX-License-Identifier: MIT
"""One explicit600 selection, thirteen additions and one exact bang-bang upgrade."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys

HERE=Path(__file__).resolve().parent
BASE_SHA='2198942a546f4714587c810fe174d4457121960f3a7b1dbaa276e9f970f322c7'
AUDIO_SHA='5dae018a1357708e85393048728a6fb44cd9c9eb02a78ab19e60435d370ffdf2'
SCRIPTS={'cachy-asahi-welcome','cachy-asahi-doctor','cachy-asahi-mirrors',
 'cachy-asahi-zsh-syntax-highlighting','cachy-asahi-zsh-history-substring-search',
 'cachy-asahi-fish-autopair','cachy-asahi-fish-done'}
AUDIO={'asahi-audio','alsa-ucm-conf-asahi','speakersafetyd','bankstown','triforce-lv2','lsp-plugins-lv2'}
UPGRADE='cachy-asahi-fish-bang-bang'
OLD='0.1.0-1'
NEW='0.1.0-2'
LABEL='org.cachy-asahi.expanded600.job'
LIFE={name:('PASS_PRODUCTS_INSTALLED_CLI_LIFECYCLE' if name in {'cachy-asahi-welcome','cachy-asahi-doctor'} else
 'PASS_TOOLS_INSTALLED_CLI_PTY_LIFECYCLE' if name in {'cachy-asahi-mirrors','cachy-asahi-zsh-syntax-highlighting','cachy-asahi-zsh-history-substring-search'} else
 'PASS_FISH_AUTOPAIR_INSTALLED_LIFECYCLE' if name=='cachy-asahi-fish-autopair' else
 'PASS_FISH_DONE_INSTALLED_LIFECYCLE' if name=='cachy-asahi-fish-done' else 'PASS_BANG_BANG_INSTALLED_LIFECYCLE') for name in SCRIPTS|{UPGRADE}}


def need(value,message):
    if not value:raise ValueError(message)


def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


def sha(path):
    with Path(path).open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def safe(path):
    path=Path(path)
    need(path.is_absolute() and '..' not in path.parts and not any(c in str(path) for c in ',\r\n') and
         not any(p.is_symlink() for p in (path,*path.parents)),'ordinary absolute path required');return path


def relative(name):
    path=Path(name);need(type(name) is str and name and not path.is_absolute() and str(path)==name and
        all(part not in ('','.','..') for part in name.split('/')),'safe relative input path required');return name


def checked(root,ref,cap=16*1024**2):
    need(set(ref)=={'path','bytes','sha256'} and type(ref['bytes']) is int and 0<ref['bytes']<=cap and
         re.fullmatch('[0-9a-f]{64}',ref['sha256']),'bounded exact input reference required')
    path=safe(Path(root)/relative(ref['path']));info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_size==ref['bytes'] and sha(path)==ref['sha256'],'input byte identity differs: '+ref['path']);return path


def read(path,cap=4*1024**2):
    safe(Path(path).absolute());need(Path(path).stat().st_size<=cap,'JSON byte bound')
    def pairs(items):
        value={}
        for key,item in items:
            need(key not in value,'duplicate JSON key');value[key]=item
        return value
    def constant(value):raise ValueError('nonfinite JSON')
    return json.loads(Path(path).read_bytes(),object_pairs_hook=pairs,parse_constant=constant)


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module


def lock(raw,count):
    rows=[line.split() for line in raw.decode().splitlines()]
    need(len(rows)==count and all(len(row)==2 for row in rows) and len(dict(rows))==count,'exact inventory lock count required');return dict(rows)


def inventory_bytes(value):return ''.join(name+' '+version+'\n' for name,version in sorted(value.items())).encode()


def policy():
    value=read(HERE/'input-policy.json')
    need(value.get('status')=='ROOT_FINAL_INPUTS_BOUND' and value.get('schema_version')==1,'pending Root accepted input binding')
    need(value.get('base_sha256')==BASE_SHA and value.get('audio_policy_sha256')==AUDIO_SHA and
         value.get('upgrade')==dict(name=UPGRADE,before=OLD,after=NEW),'exact baseline/audio/bang-bang selection required')
    need(re.fullmatch('[0-9a-f]{40}',value.get('script_source','')),'immutable accepted script source required')
    ref=value.get('script_index');need(type(ref) is dict and set(ref)=={'path','bytes','sha256'} and
         type(ref['bytes']) is int and 0<ref['bytes']<=4*1024**2 and re.fullmatch('[0-9a-f]{64}',ref['sha256']),
         'exact Root accepted seven-pair index binding required')
    need(re.fullmatch('[0-9a-f]{40}',value.get('bang_source') or '') and type(value.get('combined')) is dict,
         'exact bang2 source and combined installed-shell driver binding required')
    return value


def source(source_root):
    pins=read(HERE/'source-pins.json');need(pins,'source closure not frozen')
    for name,row in pins.items():checked(source_root,dict(path=name,**row))


def selected(before,audio,scripts):
    need(len(before)==587 and hashlib.sha256(inventory_bytes(before)).hexdigest()==BASE_SHA and
         before.get('cachy-asahi-setup')=='0.1.0-3' and before.get('cachy-asahi-update')=='4.4.2-2' and before.get(UPGRADE)==OLD,
         'exact initial587/setup3/updater2/bang1 checkpoint required')
    need(set(audio)==AUDIO and set(scripts)==SCRIPTS|{UPGRADE} and not (AUDIO|SCRIPTS)&before.keys() and scripts[UPGRADE]==NEW,
         'six audio, seven script additions and exact bang2 required')
    after=before|audio|scripts;need(len(after)==600 and {k:v for k,v in after.items() if k in before and k!=UPGRADE}==
         {k:v for k,v in before.items() if k!=UPGRADE},'only thirteen additions and one explicit upgrade allowed');return after


def accepted_index(root,value,authority=None,code=None):
    """Root's dict7 index is authoritative only after its enclosing byte pin."""
    need(value.get('schema_version')==1 and value.get('hardware')=='NOT_RUN' and
         value.get('release')=='NOT_ADMITTED' and value.get('scope')=='UNSELECTED_DEVELOPMENT_CANDIDATES_ONLY' and
         value.get('status')=='READY_SEVEN_RETAINED_WITH_IN_LANE_BANG_BUILD' and
         value.get('pending')=={UPGRADE:'IN_LANE_NATIVE_PAIR_REQUIRED'} and
         type(value.get('packages')) is dict and set(value['packages'])==SCRIPTS,
         'seven accepted retained pairs required')
    rows=value['packages']
    fields={'version','native_source','native_run','qualification','evidence','files','metadata',
            'recipe_inputs','sources','payload','raw_lifecycle','acceptance'}
    for name,row in rows.items():
        need(set(row)==fields and re.fullmatch('[0-9a-f]{40}',row['native_source']) and
             type(row['native_run']) is int and row['native_run']>0 and row['qualification'].startswith('PASS') and
             type(row['metadata']) is dict and type(row['payload']) is dict and row['payload'] and
             type(row['recipe_inputs']) is dict and 'PKGBUILD' in row['recipe_inputs'],
             'complete accepted source/metadata/payload references required')
        need(type(row['files']) is dict and set(row['files'])=={'a','b'},'two native builds required')
        paths=[checked(root,ref,8*1024**2) for ref in list(row['files'].values())]
        need(paths[0]!=paths[1] and list(row['files'].values())[0]['sha256']==list(row['files'].values())[1]['sha256'] and
             list(row['files'].values())[0]['bytes']==list(row['files'].values())[1]['bytes'],'whole native pair archives differ')
        prefix=name+'-'+row['version']+'-'+('aarch64' if name=='cachy-asahi-welcome' else 'any')+'.pkg.tar.'
        need(all(path.name in (prefix+'xz',prefix+'zst') for path in paths),'exact archive basename required')
        acceptance=read(checked(root,row['acceptance']))
        need(acceptance.get('name')==name and acceptance.get('version')==row['version'] and
             acceptance.get('archive_sha256')==list(row['files'].values())[0]['sha256'] and
             acceptance.get('source_sha')==row['native_source'] and
             re.fullmatch('[0-9]+',acceptance.get('run_id','')) and
             acceptance.get('native_pair')=='PASS_BYTES_IDENTICAL' and acceptance.get('native_lifecycle')=='PASS' and
             acceptance.get('qualification')==row['qualification'] and
             acceptance.get('status')=='ROOT_ACCEPTED_NATIVE_CANDIDATE' and
             acceptance.get('native_run')==row['native_run'] and acceptance.get('hardware')=='NOT_RUN' and
             acceptance.get('release_selection') is False,'Root acceptance differs or lifecycle did not pass')
        checked(root,row['evidence'])
        life=read(checked(root,row['raw_lifecycle']))
        need(life.get('status')==LIFE[name] and life.get('user_config_preserved') is True and
             type(life.get('events')) is list and len(life['events'])==5 and
             all(event.get('status')=='PASS' for event in life['events']) and
             acceptance.get('raw_lifecycle_sha256')==row['raw_lifecycle']['sha256'],
             'failed/incomplete raw lifecycle cannot be accepted through an export qualification')
        need(type(row['sources']) is dict and set(row['sources'])==set(row['recipe_inputs']),
             'complete original recipe/source/license closure required')
        for filename,ref in row['sources'].items():
            need(Path(filename).name==filename and checked(root,ref).is_file() and
                 ref['sha256']==row['recipe_inputs'][filename],'source/license byte join differs')
        for path,node in row['payload'].items():
            relative(path)
            need(path.startswith('usr/') and not path.endswith('.hook') and
                 set(node)=={'gid','link','mode','mtime','sha256','size','type','uid'} and
                 node['type']=='0' and node['uid']==node['gid']==0 and node['mode'] in (0o644,0o755) and
                 node['link']=='','ordinary closed retained payload required')
            need((name=='cachy-asahi-welcome' and path=='usr/bin/cachy-asahi-welcome') or
                 any(ref['sha256']==node['sha256'] and ref['bytes']==node['size'] for ref in row['sources'].values()),
                 'installed source/license bytes absent from recipe closure')
    return rows


def validate_result(value):
    need(value.get('status')=='PASS_EXPANDED600_METADATA_LIFECYCLE' and value.get('notification_delivery')==value.get('services')==
         value.get('audio_execution')==value.get('hardware')=='NOT_RUN' and value.get('defaults_enabled') is False and
         value.get('baseline_sha256')==BASE_SHA and value.get('package_count')==600 and value.get('restored_count')==587,
         'expanded600 acceptance/limits absent')
    need(type(value.get('combined_shell')) is dict and
         set(value['combined_shell'])=={'path','bytes','sha256'} and
         len(value.get('subtransactions',[]))==2 and
         [r.get('phase') for r in value['subtransactions']]==['remove-to587-bang2','final587-bang2'] and
         all(r.get('status')=='PASS' and r.get('count')==587 and r.get('bang_bang')==NEW for r in value['subtransactions']) and
         len(value.get('ldconfig',[]))==8, 'combined driver and all normal transaction checkpoints required')
    ld_phases=('baseline587','install600','same-version600','remove-to587-bang2','remove-to587',
               'restore600','final587-bang2','final587')
    for index,(row,phase) in enumerate(zip(value['ldconfig'],ld_phases)):
        need(row.get('phase')==phase and row.get('helper_exit')=='NOT_OBSERVED' and
             re.fullmatch('[0-9a-f]{64}',row.get('state_sha256','')) and
             re.fullmatch('[0-9a-f]{64}',row.get('aux_sha256','')) and
             row.get('transition',{}).get('kind') in ({'BASELINE'} if index==0 else {'RAW_EQUAL','EXACT_LOAD_SAVE_ORDER'}),
             'recorded ldconfig state/qualification incomplete')
    events=value.get('events');phases=(('baseline587',587,OLD),('install600',600,NEW),('same-version600',600,NEW),
        ('remove-to587',587,OLD),('restore600',600,NEW),('final587',587,OLD))
    need(type(events) is list and len(events)==len(phases),'six expanded composition checkpoints required')
    for event,(name,count,bang) in zip(events,phases):
        need(event.get('phase')==name and event.get('count')==count and event.get('bang_bang')==bang and event.get('status')=='PASS' and
             all(event.get(key) is True for key in ('signatures','dependencies','payload','ownership','originals_preserved','user_config_preserved')),
             'expanded checkpoint gate incomplete')


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


def verify_self(root):
    pins=read(HERE/'source-manifest.json')
    need(type(pins) is dict and pins,'expanded source closure absent')
    for name,ref in pins.items():checked(root,dict(path=name,**ref))
