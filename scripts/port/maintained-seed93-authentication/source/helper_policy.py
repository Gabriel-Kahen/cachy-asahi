"""Pinned low-level definitions and pure result policy; no CLI or operational grant."""
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import tarfile
import tempfile
from types import MappingProxyType, SimpleNamespace
import urllib.parse
import urllib.request

SIGNER='68B3537F39A313B3E574D06777193F152BDBE6A6'
MAX_TEXT=65536
MAX_OBSERVATION_BYTES=16*1024**2
SOURCE_PINS=MappingProxyType({
    'scripts/port/authenticate.py':(17452,'241cd67370eb593bdf948a25788f006ecf470c645ba5d198bc9c318119ebfe10'),
    'scripts/ci/native_arm.py':(28489,'1a5369e007193fafce355ca6d20f4e771a0f342e0176bfd80f95a718328a0d10'),
    'scripts/port/preview.py':(19736,'d737c51474e05cc2c4db2e87fc021f50328eea7744983dd4076d44751fce7383')})
# Each tuple pins both location-independent AST and exact definition text.
DEFINITION_PINS=MappingProxyType({
    'scripts/port/authenticate.py':MappingProxyType({
        'fetch':('1dd59753e0091c333ab3ed5077ebb8573b47c1173c052273d2d8619967e1df6e','39bbbcc8664a2d6a8c99dcde7eb18eb3ae4418ee264f6fa0b9a62783c3d6751d'),
        'observe':('534b713e03e9721f2239fd220ff96492cd8818c60c005d7fb746edeaac7b153d','565e4bd78f7e511cecbcbf2aebbce81ee8583126a2e655d90575fffdc06e01ed')}),
    'scripts/ci/native_arm.py':MappingProxyType({
        'sha':('0af77764f1a111a27fbdec4c793dbcf73a4c24797272a4ba947f584b7600fe59','06ba687c1f5e5d568bfbfbd809e166361a68be00c811ff22dd46a46c09a0f81e'),
        'pkginfo':('696733abdfe1040a511d11329fdbeb2e1898d7de446a8ef43a4c35db6e819d54','d53e4d567269d8eccfb924b451fd007c11e7e2f742d8bd7a9f2c883c2066e6ae'),
        'valid_signature':('2bdc329779315e2f780e3975f18d93cd5152fb3ca1ab3d0ec89f538c122af75c','7e8bbe91300645ccfc829ae0777a3c4ebc47d44f4b7fb92306a88718603a5c18'),
        'signature_item':('a0a13483636be76aedccce75e56f62adfb369a6798f1972391fd926db6b38a41','1edc92d9452200f0d4c386c4df4af97c9139675b4d0141314988cc8195bc08d2')}),
    'scripts/port/preview.py':MappingProxyType({'need':('a06f923ac6223241a70d80105c35b555016a9dccf5d416b0bf2596566ce088dd','4b3a697e0d6c229d054eb933137631f3eec63797433cf8a40cb5f41231911d04')})})

def need(ok,label):
    if not ok:raise ValueError(label)

def load_helpers(sourcebytesmapping):
    """Compile only seven pinned definitions; returned actors are not invoked here."""
    need(type(sourcebytesmapping)is dict and set(sourcebytesmapping)==set(SOURCE_PINS),'source roles')
    selected={}
    for path,(size,pin) in SOURCE_PINS.items():
        raw=sourcebytesmapping[path]
        need(type(raw)is bytes and len(raw)==size and hashlib.sha256(raw).hexdigest()==pin,'source bytes')
        text=raw.decode('utf-8');tree=ast.parse(text)
        definitions={n.name:n for n in tree.body if type(n)is ast.FunctionDef}
        nodes=[]
        for name,(ast_pin,body_pin) in DEFINITION_PINS[path].items():
            node=definitions[name]
            need(hashlib.sha256(ast.dump(node,include_attributes=False).encode()).hexdigest()==ast_pin and hashlib.sha256(ast.get_source_segment(text,node).encode()).hexdigest()==body_pin,'definition pins')
            need(not node.decorator_list and not node.args.defaults and not any(node.args.kw_defaults) and node.returns is None and all(a.annotation is None for a in node.args.args),'definition-time evaluation')
            nodes.append(node)
        selected[path]=ast.Module(body=nodes,type_ignores=[])
    builtins=MappingProxyType(dict(ValueError=ValueError,any=any,len=len,list=list,set=set,sorted=sorted,isinstance=isinstance,str=str))
    native={'__builtins__':builtins,'hashlib':hashlib}
    preview={'__builtins__':builtins}
    for path,namespace in [('scripts/ci/native_arm.py',native),('scripts/port/preview.py',preview)]:
        exec(compile(selected[path],'<pinned:'+path+'>','exec',dont_inherit=True),namespace)
    namespace={'__builtins__':builtins,'native':SimpleNamespace(sha=native['sha'],pkginfo=native['pkginfo'],urllib=SimpleNamespace(request=urllib.request)), 'preview':SimpleNamespace(need=preview['need']),'urllib':SimpleNamespace(parse=urllib.parse),'hashlib':hashlib,'os':os,'Path':Path,'struct':struct,'tarfile':tarfile,'tempfile':tempfile}
    exec(compile(selected['scripts/port/authenticate.py'],'<pinned:scripts/port/authenticate.py>','exec',dont_inherit=True),namespace)
    return MappingProxyType({name:namespace[name] for name in ['fetch','observe']}|{name:native[name] for name in ['pkginfo','valid_signature','signature_item']})

def text(value,limit,label):
    need(type(value)is str and '\x00' not in value,label)
    try:size=len(value.encode('utf-8'))
    except UnicodeError as error:raise ValueError(label) from error
    need(size<=limit,label)
    return value

def validate_gpg(result):
    """Validate captured status only, never run GPG or infer public key ownership."""
    need(type(result)is dict and set(result)=={'exit','status','diagnostic'},'GPG ABI')
    need(type(result['exit'])is int and result['exit']==0,'GPG exit')
    status=text(result['status'],MAX_TEXT,'GPG status');text(result['diagnostic'],MAX_TEXT,'GPG diagnostic')
    need(all(c=='\n' or ord(c)>=32 for c in status),'GPG status controls')
    allowed={'NEWSIG','KEY_CONSIDERED','SIG_ID','GOODSIG','VALIDSIG','TRUST_UNDEFINED','TRUST_MARGINAL','TRUST_FULLY','TRUST_ULTIMATE'}
    records=[]
    for line in status.splitlines():
        if not line:continue
        need(line.startswith('[GNUPG:] '),'GPG status prefix')
        row=line.split()[1:];need(row and row[0] in allowed,'adverse or unknown GPG status')
        if row[0]=='KEY_CONSIDERED':need(len(row)==3 and row[1]==SIGNER and row[2].isdigit(),'considered key')
        if row[0]=='GOODSIG':need(len(row)>=3 and row[1]==SIGNER[-16:],'GOODSIG selected key')
        records.append(row)
    valid=[r for r in records if r[0]=='VALIDSIG']
    need(len(valid)==1 and len(valid[0])==11,'one complete VALIDSIG')
    row=valid[0]
    need(row[1]==row[-1]==SIGNER and re.fullmatch(r'\d{4}-\d{2}-\d{2}',row[2])is not None and all(re.fullmatch('[0-9]+',v)is not None for v in row[3:9]) and re.fullmatch('[0-9A-Fa-f]{2}',row[9])is not None,'VALIDSIG selected primary and fields')
    need(row[5:8]==['4','0','1'] and row[8] in {'8','10'} and row[9]=='00','selected V4 RSA SHA256/SHA512 binary signature policy')
    return {'verified':True,'primary_fingerprint':SIGNER}

def path(value,label):
    text(value,4096,label)
    need(value and not value.startswith('/') and '..' not in Path(value).parts and '.' not in value.split('/'),label)
    return value

def sha256(value,label):
    need(type(value)is str and re.fullmatch('[0-9a-f]{64}',value)is not None,label)

def fields(value,label):
    need(type(value)is dict and len(value)<=256,label)
    for key,rows in value.items():
        text(key,256,label);need(key and type(rows)is list and len(rows)<=400000,label)
        for row in rows:text(row,MAX_TEXT,label)

def validate_observation(obs,expected):
    """Check held eleven-field observation ABI and eight PKGINFO comparisons."""
    keys={'metadata','buildinfo','installed_paths','path_count','links','ELF','hooks_and_scriptlets','license_notice_files','license_declaration','complete_corresponding_source_license_closure','package_execution'}
    need(type(obs)is dict and set(obs)==keys,'observation ABI')
    try:raw=json.dumps(obs,ensure_ascii=False,allow_nan=False).encode('utf-8')
    except (ValueError,TypeError,UnicodeError) as error:raise ValueError('observation JSON') from error
    need(len(raw)<=MAX_OBSERVATION_BYTES,'observation bytes')
    fields(obs['metadata'],'PKGINFO fields')
    mapping={'pkgname':'name','pkgver':'version','arch':'arch','depend':'depends','provides':'provides','conflict':'conflicts','replaces':'replaces','license':'license'}
    need(type(expected)is dict and set(mapping.values())<=set(expected),'expected metadata')
    for field,key in mapping.items():
        value=expected[key]
        need(type(value)is (str if key in {'name','version','arch'} else list),'expected field type')
        rows=value if type(value)is list else [value]
        for row in rows:text(row,MAX_TEXT,'expected string')
        need(sorted(obs['metadata'].get(field,[]))==sorted(rows),'PKGINFO mismatch '+field)
    paths=obs['installed_paths']
    need(type(paths)is list and len(paths)<=400000,'installed paths')
    for p in paths:path(p,'installed path')
    need(len(set(paths))==len(paths) and not set(paths)&{'.PKGINFO','.BUILDINFO','.MTREE','.INSTALL'} and type(obs['path_count'])is int and obs['path_count']==len(paths),'path count')
    for key in ['links','ELF','hooks_and_scriptlets','license_notice_files']:need(type(obs[key])is list and len(obs[key])<=400000,'observation list '+key)
    for link in obs['links']:
        need(type(link)is dict and set(link)=={'path','target','type'},'link ABI')
        path(link['path'],'link path');need(link['path'] in paths and type(link['type'])is str and link['type'] in {'symlink','hardlink'},'link identity')
        text(link['target'],4096,'link target')
        if link['type']=='hardlink':path(link['target'],'hardlink target')
    for elf in obs['ELF']:
        need(type(elf)is dict and set(elf)=={'path','class','machine','endianness','runtime','16K_load'},'ELF ABI')
        path(elf['path'],'ELF path');need(elf['path'] in paths and type(elf['class'])is int and elf['class'] in (32,64) and type(elf['machine'])is int and 0<=elf['machine']<=65535 and type(elf['endianness'])is str and elf['endianness'] in {'little','big'} and elf['runtime']==elf['16K_load']=='NOT RUN','ELF observation')
    for hook in obs['hooks_and_scriptlets']:
        need(type(hook)is dict and set(hook)=={'path','sha256','bytes','kind','executed'},'hook ABI')
        p=path(hook['path'],'hook path');sha256(hook['sha256'],'hook hash')
        need(type(hook['bytes'])is int and 0<=hook['bytes']<=1024**2 and hook['executed']is False,'hook must not execute')
        need((p=='.INSTALL' and hook['kind']=='install-scriptlet') or (p.startswith(('usr/share/libalpm/hooks/','etc/pacman.d/hooks/')) and p in paths and hook['kind']=='ALPM-hook'),'hook kind/path')
    for notice in obs['license_notice_files']:
        need(type(notice)is dict and set(notice)=={'path','bytes','sha256','legal_clearance'},'notice ABI')
        p=path(notice['path'],'notice path');sha256(notice['sha256'],'notice hash')
        need(p.startswith('usr/share/licenses/') and p in paths and type(notice['bytes'])is int and 0<=notice['bytes']<=1024**2 and notice['legal_clearance']=='NOT ESTABLISHED; retained notice observation','notice observation')
    build=obs['buildinfo']
    if build is not None:
        need(type(build)is dict and set(build)=={'sha256','bytes','fields'},'BUILDINFO ABI');sha256(build['sha256'],'BUILDINFO hash')
        need(type(build['bytes'])is int and 0<=build['bytes']<=1024**2,'BUILDINFO size');fields(build['fields'],'BUILDINFO fields')
    groups=[{row['path'] for row in obs[key]} for key in ['links','ELF','hooks_and_scriptlets','license_notice_files']]
    need(all(len(group)==len(obs[key]) for group,key in zip(groups,['links','ELF','hooks_and_scriptlets','license_notice_files'])) and sum(map(len,groups))==len(set().union(*groups)),'duplicate or conflicting observation nodes')
    need(obs['license_declaration']==obs['metadata'].get('license',[]) and obs['complete_corresponding_source_license_closure']=='NOT ESTABLISHED; declared package metadata only' and obs['package_execution']=='NOT RUN','observation acceptance limits')
    return copy.deepcopy(obs)
