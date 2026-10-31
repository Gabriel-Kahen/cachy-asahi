#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit target/base/effect policy for the opt-in live orphan backend.

No helper is executed here. Hooks and selected configuration/scriptlets remain
unsupported; reviewed ldconfig is a separately named, hash-bound effect.
"""
import fnmatch,os,re,stat
from pathlib import Path

SHA=re.compile(r'[0-9a-f]{64}\Z')
FLAGS=(1<<7)|(1<<10)
PLATFORM=('alsa-ucm-conf-asahi','asahi-audio','asahi-fwextract','linux-asahi','m1n1','mesa','speakersafetyd','u-boot')
BASE=('pacman','glibc','filesystem','bash','coreutils','systemd','python')
KEYS={'schema_version','profile','root','dbpath','supported_base','platform','transaction_flags','hooks','scriptlets','configuration','ldconfig'}
HOOK_DIRS=('usr/share/libalpm/hooks','etc/pacman.d/hooks')
LDCONF_DIRS=('etc/ld.so.conf.d','usr/lib/ld.so.conf.d')
MAX_HOOKS=512;MAX_EFFECT_BYTES=4*1024**2


def _policy(value,O):
    O.need(type(value) is dict and set(value)==KEYS,'exact live policy schema required')
    O.need(type(value['schema_version']) is int and value['schema_version']==1,'live policy schema version1 required')
    O.need(value['profile'] in ('asahi-alarm-m2','private-fixture'),'explicit supported policy profile required')
    for key in ('root','dbpath'):
        text=value[key];O.need(type(text) is str and not text.startswith('//') and str(O.absolute(text))==text,'ordinary explicit policy target required')
    O.need(Path(value['dbpath'])==Path(value['root'])/'var/lib/pacman','conventional explicit target DB required')
    O.need(value['profile']!='private-fixture' or value['root']!='/','fixture policy never authorizes the live root')
    for key in ('supported_base','platform'):
        rows=value[key];O.need(type(rows) is dict and len(rows)<=O.MAX_PACKAGES,'bounded policy package map required')
        O.need(all(type(n) is str and O.NAME.fullmatch(n) and type(v) is str and 0<len(v)<=256 and not any(c in v for c in '\r\n\0') for n,v in rows.items()),'exact protected package versions required')
    O.need(bool(value['supported_base']),'nonempty explicitly supported base required')
    O.need(all(value['supported_base'][n]==value['platform'][n] for n in value['supported_base'].keys()&value['platform'].keys()),'conflicting protected versions')
    if value['profile']=='asahi-alarm-m2':
        O.need(set(BASE)<=set(value['supported_base']) and set(PLATFORM)<=set(value['platform']),'complete explicit Asahi platform and core base policy required')
    O.need(type(value['transaction_flags']) is int and value['transaction_flags']==FLAGS,'fixed NOHOOKS|NOSCRIPTLET policy required')
    O.need(value['hooks']=='refuse-matching' and value['scriptlets']=='refuse' and value['configuration']=='refuse-selected','hooks/scriptlets/configuration policy unsupported')
    effect=value['ldconfig'];O.need(type(effect) is dict,'explicit ldconfig effect policy required')
    if effect.get('mode')=='forbid':O.need(set(effect)=={'mode'},'forbid helper policy has no extra fields')
    else:
        O.need(set(effect)=={'mode','executable_sha256','config_sha256','libalpm_sha256'} and effect.get('mode')=='reviewed','exact separately reviewed helper policy required')
        O.need(all(type(effect[n]) is str and SHA.fullmatch(effect[n]) for n in ('executable_sha256','config_sha256','libalpm_sha256')),'exact reviewed helper/runtime hashes required')
    return value


def read_policy(path,pin,O):
    O.need(type(pin) is str and SHA.fullmatch(pin),'reviewed policy SHA256 required')
    value,identity=O.json_file(path)
    O.need(identity['sha256']==pin,'reviewed policy bytes differ')
    return _policy(value,O),identity


def _directory_identity(info):
    return dict(dev=info.st_dev,ino=info.st_ino,mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid)


def validate_target(root,db,policy,O):
    _policy(policy,O);root,db=map(O.absolute,(root,db))
    O.need(str(root)==policy['root'] and str(db)==policy['dbpath'],'operator target differs from reviewed policy')
    O.need(db==root/'var/lib/pacman','explicit conventional target DB required')
    required_uid=0 if policy['profile']=='asahi-alarm-m2' else os.geteuid()
    rows={}
    for name,path in (('root',root),('dbpath',db)):
        with O.directory(path) as (fd,_):
            info=os.fstat(fd);O.need(info.st_uid==required_uid and not info.st_mode&0o022,'trusted non-writable target directory required')
            if name=='root' and policy['profile']=='private-fixture':O.need(stat.S_IMODE(info.st_mode)==0o700,'caller-private mode0700 fixture root required')
            rows[name+'_identity']=_directory_identity(info)
    return dict(root=str(root),dbpath=str(db),profile=policy['profile'],**rows)


def protect(policy,O):
    _policy(policy,O);return O.floor()|set(policy['supported_base'])|set(policy['platform'])


def is_platform_name(name):
    return type(name) is str and (name in PLATFORM or name in ('linux','linux-firmware','uboot','lib32-mesa','pipewire','wireplumber') or name.startswith(('asahi-','linux-','linux-firmware-','mesa-','lib32-mesa-','m1n1-','u-boot-','uboot-','speakersafetyd-','apple-','vulkan-','pipewire-','wireplumber-')))


def validate_inventory(policy,rows,O):
    _policy(policy,O);O.need(type(rows) is dict,'installed package map required')
    for name,version in (policy['supported_base']|policy['platform']).items():
        row=rows.get(name);actual=row.get('version') if type(row) is dict else row
        O.need(actual==version,'supported base/platform package absent or changed: '+name)


def _optional_directory(root,relative,O):
    path=root/relative
    try:
        with O.directory(path) as (fd,_):
            info=os.fstat(fd);O.need(info.st_uid in (0,os.geteuid()) and not info.st_mode&0o022,'unsafe policy-effect directory')
            return dict(kind='directory',**O.identity(info))
    except FileNotFoundError:return dict(kind='ABSENT')


def _read(root,relative,O,bounds,*,required=False,cap=256*1024):
    path=root/relative
    try:
        with O.directory(path.parent) as (fd,_):record,raw=O.read(fd,path.name,bounds,cap,True)
    except FileNotFoundError:
        O.need(not required,'required reviewed effect file absent: '+relative);return dict(kind='ABSENT'),None
    O.need(not record['mode']&0o022,'writable policy-effect file refused')
    O.need(bounds['bytes']<=MAX_EFFECT_BYTES,'policy-effect byte bound')
    return dict(kind='file',**record),raw


def _hook(text,O):
    """Bounded subset of ALPM hook syntax; unsupported semantics refuse."""
    triggers=[];action={};section=None;action_seen=False
    for raw in text.splitlines():
        line=raw.strip();O.need(len(line)<=4096,'hook line bound')
        if not line or line.startswith('#'):continue
        O.need('\\' not in line and '\0' not in line and '#' not in line,'ambiguous hook escape/continuation/comment refused')
        if line.startswith('['):
            O.need(line in ('[Trigger]','[Action]'),'unsupported hook section')
            section=line[1:-1]
            if section=='Trigger':triggers.append(dict(Operation=[],Target=[]));O.need(len(triggers)<=64,'hook trigger bound')
            else:O.need(not action_seen,'duplicate hook action section');action_seen=True
            continue
        O.need(section is not None,'hook option outside section')
        key,sep,value=line.partition('=');key=key.strip();value=value.strip()
        if section=='Trigger':
            O.need(sep and key in ('Operation','Type','Target') and value,'unsupported hook trigger option')
            row=triggers[-1]
            if key in ('Operation','Target'):row[key].append(value)
            else:O.need(key not in row,'duplicate hook Type');row[key]=value
        else:
            O.need(key in ('When','Description','Depends','Exec','AbortOnFail','NeedsTargets'),'unsupported hook action option')
            O.need((bool(sep) and bool(value)) if key not in ('AbortOnFail','NeedsTargets') else not sep,'ambiguous hook action value')
            if key=='Depends':action.setdefault(key,[]).append(value)
            else:O.need(key not in action,'duplicate hook action option');action[key]=value
    O.need(triggers,'triggerless/dummy hook override requires separate policy')
    O.need(action.get('When') in ('PreTransaction','PostTransaction') and bool(action.get('Exec')),'complete hook action required')
    for row in triggers:
        O.need(row.get('Type') in ('Package','Path','File') and row['Operation'] and set(row['Operation'])<={'Install','Upgrade','Remove'} and row['Target'],'complete supported hook trigger required')
        O.need(len(row['Target'])<=512 and all(len(p)<=512 and p.isascii() and not p.startswith('!') and '[' not in p and ']' not in p for p in row['Target']),'ambiguous negated/bracket hook patterns unsupported')
    return triggers


def _pacman_config(root,raw,selected,O,bounds):
    patterns=dict(HoldPkg=[],IgnorePkg=[]);includes={}
    if raw is None:return patterns,includes
    section=None
    for rawline in raw.decode('utf8').splitlines():
        line=rawline.partition('#')[0].strip()
        if not line:continue
        if line.startswith('['):
            O.need(line.endswith(']') and line.count('[')==line.count(']')==1,'ambiguous pacman configuration section')
            section=line;continue
        key,sep,value=line.partition('=');key=key.strip();value=value.strip()
        if section!='[options]':
            if key=='Include':
                O.need(sep and value.startswith('/') and not any(c in value for c in '*?[]\\'),'explicit repository include required')
                relative=Path(value).relative_to('/')
                O.need(relative.parent==Path('etc/pacman.d') and '..' not in relative.parts and '/'+str(relative)==value,'supported repository include path required')
                node,content=_read(root,str(relative),O,bounds,required=True)
                for included in content.decode('utf8').splitlines():
                    included=included.partition('#')[0].strip()
                    if not included:continue
                    directive,equals,server=included.partition('=')
                    O.need(equals and directive.strip() in ('Server','CacheServer') and server.strip(),'indirect frontend/options policy in repository include unsupported')
                includes[str(relative)]=node
            continue
        O.need(key not in ('HookDir','Include'),'custom/indirect hook policy in pacman.conf unsupported')
        O.need(key!='IgnoreGroup' or sep and not value,'configured IgnoreGroup requires group-aware policy')
        if key not in patterns:continue
        O.need(bool(sep),'ambiguous frontend protected-package option')
        targets=value.split();O.need(len(targets)<=512,'frontend protected-pattern bound')
        O.need(all(0<len(p)<=128 and re.fullmatch(r'[a-zA-Z0-9+_.?*\-]+',p) for p in targets),'ambiguous frontend protected-package patterns')
        patterns[key].extend(targets);O.need(len(patterns[key])<=512,'frontend protected-pattern count bound')
    patterns={key:sorted(set(value)) for key,value in patterns.items()}
    for key,targets in patterns.items():
        O.need(not any(fnmatch.fnmatchcase(name,pattern) for name in selected for pattern in targets),'selected package preserved by pacman '+key)
    return patterns,includes


def _runtime(pin,O):
    path=Path('/usr/lib/libalpm.so.16').resolve(strict=True)
    O.need(path.parent==Path('/usr/lib'),'trusted system libalpm16 path required')
    with O.directory(path.parent) as (fd,_):record,_=O.read(fd,path.name,O.limits(),32*1024**2)
    O.need(record['uid']==0 and not record['mode']&0o022 and record['sha256']==pin,'reviewed libalpm runtime differs')
    return dict(path=str(path),**record)


def _ldconfig_configuration(root,main,O,bounds):
    result={};allowed={'include /'+p+'/*.conf' for p in LDCONF_DIRS}
    def check(raw,*,included):
        for row in raw.decode('utf8').splitlines():
            line=row.strip()
            if not line or line.startswith('#'):continue
            if line.startswith('include '):O.need(not included and line in allowed,'unreviewed indirect ldconfig configuration')
            else:O.need(line.startswith('/') and '..' not in Path(line).parts and len(line)<=512 and not any(c in line for c in '\t\0'),'unsupported ldconfig directory/configuration syntax')
    check(main,included=False)
    for relative in LDCONF_DIRS:
        result[relative]=_optional_directory(root,relative,O)
        if result[relative]['kind']=='ABSENT':continue
        with O.directory(root/relative) as (fd,_):
            names=sorted(os.listdir(fd));O.need(len(names)<=MAX_HOOKS,'ldconfig configuration count bound')
        for name in names:
            O.need(name not in ('.','..') and '/' not in name,'ordinary configuration basename required')
            if name.endswith('.conf'):
                node,raw=_read(root,relative+'/'+name,O,bounds,required=True);check(raw,included=True);result[relative+'/'+name]=node
    return result


def effects(root,policy,selected,files,O):
    _policy(policy,O);root=O.absolute(root);O.need(str(root)==policy['root'],'effects target differs from policy')
    selected=list(selected);files=list(files)
    O.need(len(selected)<=O.MAX_PACKAGES and all(type(n) is str and O.NAME.fullmatch(n) for n in selected),'bounded exact effect selection required')
    O.need(len(files)<=32768 and all(type(n) is str and 0<len(n)<=512 and not n.startswith('/') and str(Path(n.rstrip('/')))==n.rstrip('/') and '..' not in Path(n).parts and '\0' not in n for n in files),'ordinary bounded selected ownership paths required')
    bounds=O.limits();snapshot=dict(policy='NOHOOKS_NOSCRIPTLET_REFUSE_MATCHING_HOOKS_AND_SELECTED_CONFIG',hook_directories={},hooks={},ldconfig={})
    node,raw=_read(root,'etc/pacman.conf',O,bounds);snapshot['pacman_configuration']=node;snapshot['frontend_protection'],snapshot['repository_include_inputs']=_pacman_config(root,raw,selected,O,bounds)
    seen=set();total=0
    for relative in HOOK_DIRS:
        directory=_optional_directory(root,relative,O);snapshot['hook_directories'][relative]=directory
        if directory['kind']=='ABSENT':continue
        with O.directory(root/relative) as (fd,_):names=sorted(os.listdir(fd));O.need(len(names)<=MAX_HOOKS,'hook directory count bound')
        for name in names:
            if not name.endswith('.hook'):continue
            O.need(name not in seen,'duplicate hook basename override requires separate policy');seen.add(name);total+=1;O.need(total<=MAX_HOOKS,'hook count bound')
            key=relative+'/'+name;node,raw=_read(root,key,O,bounds,required=True);triggers=_hook(raw.decode('utf8'),O)
            for row in triggers:
                if 'Remove' not in row['Operation']:continue
                targets=selected if row['Type']=='Package' else files
                O.need(not any(fnmatch.fnmatchcase(target,pattern) for target in targets for pattern in row['Target']),'selected removal requires unsupported hook: '+key)
            snapshot['hooks'][key]=node
    helper,helper_raw=_read(root,'usr/bin/ldconfig',O,bounds,cap=4*1024**2);config,config_raw=_read(root,'etc/ld.so.conf',O,bounds)
    effect=policy['ldconfig'];snapshot['ldconfig']=dict(mode=effect['mode'],executable=helper,configuration=config)
    if effect['mode']=='forbid':O.need(helper['kind']=='ABSENT','ldconfig helper present; separately reviewed effect policy required')
    else:
        O.need(helper['kind']=='file' and helper['mode']&0o111 and config['kind']=='file' and helper['sha256']==effect['executable_sha256'] and config['sha256']==effect['config_sha256'],'reviewed ldconfig executable/configuration differs')
        snapshot['ldconfig'].update(runtime=_runtime(effect['libalpm_sha256'],O),included_configuration=_ldconfig_configuration(root,config_raw,O,bounds),authorized_effects=['fixed usr/bin/ldconfig invocation by reviewed libalpm','may regenerate etc/ld.so.cache and var/cache/ldconfig/aux-cache','may regenerate library SONAME symlinks in reviewed configuration directories'])
    return snapshot
