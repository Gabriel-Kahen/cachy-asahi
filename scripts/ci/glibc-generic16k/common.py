# SPDX-License-Identifier: MIT
"""Finite data checks for one private-loader glibc16K trial."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE=Path(__file__).resolve().parent
PACKAGE='cachy-asahi-glibc-official-release-2.43.caa1-3-aarch64.pkg.tar.xz'
PACKAGE_BYTES=19400096
PACKAGE_SHA='04e481dc5b3ac711760ca42749044b0be85283b3aa9c9c631cb6738ac7d699fb'
PREFIX='opt/caa/g243a1'
LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
TOOLS=('bash','uname','getconf','mount','python3','mkdir','rm','ln')
CLIENTS=('plugin.so','smoke','exec-child')
CASES={'allocation','dlopen_dlsym','pthread_tls_join','utf8_iconv_locale','numeric_math',
       'fd_stat_clock_random','numeric_address_lookup','fork_exec_wait'}
ROLES={'loader':('usr/lib/ld-linux-aarch64.so.1','ccad4ffb91aefbbe13350aff6064aeb419e07e2dbaf3c13e761b6936590af89f'),
       'libc':('usr/lib/libc.so.6','c5893ec97def4f37c2043deff34926fba7ee0866dbabf24dd32de1559beb0ada'),
       'libm':('usr/lib/libm.so.6','a750d1b22f7388af5ad26f690dc2390b65fb894f37460b97b59ebdb173f6b3fc')}


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(data):return hashlib.sha256(data).hexdigest()


def safe(path):
    path=Path(path);need(path.is_absolute() and '..' not in path.parts and not any(c.isspace() or c in ':,\\' for c in str(path)) and
        not any(p.is_symlink() for p in (path,*path.parents)),'ordinary simple absolute path required');return path


def read(path,cap=1024**2):
    path=Path(path);info=path.lstat();need(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_size<=cap,'bounded regular file required')
    with path.open('rb') as stream:raw=stream.read(cap+1)
    need(len(raw)<=cap,'input byte cap');return raw


def decode(raw):
    def pairs(items):
        value={}
        for key,item in items:need(key not in value,'duplicate JSON key');value[key]=item
        return value
    def constant(_):raise ValueError('nonfinite JSON')
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)


def save(path,value,cap=2*1024**2):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode();need(len(raw)<=cap,'report byte cap');Path(path).write_bytes(raw)


def relative(name):
    need(type(name) is str and name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')) and
         all(32<=ord(c)<127 for c in name),'safe relative path required');return name


def checked(root,name,row,cap=64*1024**2):
    path=safe(Path(root)/relative(name));raw=read(path,cap)
    need(set(row)=={'bytes','sha256'} and len(raw)==row['bytes'] and sha(raw)==row['sha256'],'byte identity differs: '+name);return path


def dependencies():
    files=decode(read(HERE/'dependencies.json'))['files']
    cache=decode(read(HERE/'input-policy.json')).get('kernel_cache')
    if type(cache) is dict:files=files|cache['files']
    return files


def check_source(root):
    for name,row in dependencies().items():checked(root,name,row,2*1024**2)


def load(root,name):
    checked(root,name,dependencies()[name],2*1024**2)
    spec=importlib.util.spec_from_file_location('glibc16k_'+sha(name.encode())[:16],Path(root)/name)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module


def bindings(value=None):
    value=decode(read(HERE/'input-policy.json')) if value is None else value
    need(value.get('status')=='ROOT_BOUND_PAIR_AND_TOOLS_CACHE_HANDOFF' and type(value.get('kernel_cache')) is dict,
         'pending final Tools cache handoff/source binding')
    cache=value['kernel_cache']
    need(set(cache.get('files',{}))=={'scripts/ci/tools-generic16k/acquire_kernel.py','scripts/ci/tools-generic16k/retained_kernel.py','scripts/ci/tools-generic16k/dependencies.json'} and
         all(set(r)=={'bytes','sha256'} and type(r['bytes']) is int and r['bytes']>0 and
             re.fullmatch('[0-9a-f]{64}',r['sha256']) for r in cache['files'].values()) and
         value.get('kernel_helper_sha256')=='3c8695685dcae7eded7406ccbf0f8152f6f5820f87ef47f4e791b577c2d3b55a',
         'exact final shared cache/source bindings and derived kernel helper required')
    need(cache['files']['scripts/ci/tools-generic16k/acquire_kernel.py']==dict(bytes=8844,sha256='4a372e1f4bfbd1f8604579873fc6fbdec91ac2555bb36f028646017b44b8c23f') and
         cache['files']['scripts/ci/tools-generic16k/retained_kernel.py']==dict(bytes=5444,sha256='bddb14537790a484d770215e55cc2c59de50c764d15e4d677f6fbcaab84cd735'),
         'Root final cache/retained asset helpers differ')
    return value


def pair(root):
    policy=decode(read(HERE/'input-policy.json'));ref=policy['index']
    index=decode(read(checked(root,ref['path'],{k:ref[k] for k in ('bytes','sha256')})))
    need(index['schema_version']==1 and index['status']=='ROOT_ACCEPTED_UNSELECTED_NATIVE_GNU_PAIR_INPUTS' and
         index['native_run']==38915137670 and index['native_source']=='d1055cf95f7d236fc55396db36b432df5191ff2a' and
         index['package']=='cachy-asahi-glibc-official-release' and index['version']=='2.43.caa1-3' and
         index['prefix']=='/'+PREFIX and index['hardware']=='NOT_RUN' and index['release']=='NOT_ADMITTED',
         'exact accepted unselected GNU pair required')
    need(len(index['files'])==11,'closed original metadata/pair references required')
    for name,row in index['files'].items():checked(root,name,row,32*1024**2)
    paths=[Path(root)/('packages/'+side+'/'+PACKAGE) for side in ('a','b')]
    need(all(p.stat().st_size==PACKAGE_BYTES and sha(read(p,32*1024**2))==PACKAGE_SHA for p in paths),'accepted pair bytes differ')
    return index,paths


def spec():
    return dict(schema_version=1,stage_root='/'+PREFIX,library_directories=['usr/lib'],gconv_directory='usr/lib/gconv',
                locale_directory='usr/lib/locale',**{role:dict(path=path,sha256=digest) for role,(path,digest) in ROLES.items()})


def aligned(raw,generic):
    interpreter,needed,loads=generic.elf(raw)
    need(loads and all(a>=16384 and (v-o)%16384==0 for v,o,_,a in loads),'ELF closure requires16K alignment')
    return dict(interpreter=interpreter,needed=needed)


def elf_closure(elfs,files):
    for name,row in elfs.items():
        folders=(PREFIX+'/usr/lib/',) if row['scope']=='candidate' else ('usr/lib/','lib/')
        # Exact accepted gconv DSOs use DT_RUNPATH=$ORIGIN for their helper
        # libraries. Keep this lookup local to those pinned private importers.
        if row['scope']=='candidate' and name.startswith(PREFIX+'/usr/lib/gconv/'):
            folders+=(PREFIX+'/usr/lib/gconv/',)
        need(not row['interpreter'] or row['interpreter'].lstrip('/') in files,
             'captured interpreter absent: '+name)
        for lib in row['needed']:
            need(any(folder+lib in files for folder in folders),
                 'closed ELF dependency absent: '+name+' -> '+lib)


def stage(package,root,generic):
    """Data only. Flatten contained archive links to exact ordinary runtime bytes."""
    need(package.stat().st_size==PACKAGE_BYTES and sha(read(package,32*1024**2))==PACKAGE_SHA,'accepted package byte identity before staging')
    need(not root.exists(),'fresh private runtime stage required');root.mkdir(mode=0o700)
    files={};total=0
    archive=generic.Archive(package)
    try:
        for name,entry in sorted(archive.nodes.items()):
            if not name.startswith(PREFIX+'/') or entry.isdir():continue
            suffix=name[len(PREFIX)+1:]
            if not (suffix.startswith(('usr/lib/','l/'))) or suffix.endswith(('.o','.a')):continue
            relative(suffix);target,node=archive.resolve(name)
            need(target.startswith(PREFIX+'/') and node.uid==node.gid==0 and not node.mode&0o6000,'contained ordinary candidate runtime required')
            _,raw,mode=archive.read(name);total+=len(raw)
            need(len(files)<4096 and total<=256*1024**2 and len(raw)<=64*1024**2,'private runtime stage limits')
            out=root/suffix;out.parent.mkdir(mode=0o755,parents=True,exist_ok=True);out.write_bytes(raw);out.chmod(mode)
            files[suffix]=dict(bytes=len(raw),mode=mode,sha256=sha(raw))
    finally:archive.tar.close()
    for role,(name,digest) in ROLES.items():need(files[name]['sha256']==digest,'accepted candidate role differs: '+role)
    return files


def compile_receipt(value):
    need(value['status']=='COMPILED_ONCE_NOT_EXECUTED' and set(value['compiled_files'])==set(CLIENTS) and
         len(value['commands'])==13 and all(r['exit_code']==0 and r['group_absence_verified'] is True for r in value['commands']) and
         set(value['sources'])=={'abi_smoke.c','exec_child.c','probe.c','probe.h','plugin.c','runner.py'},
         'unchanged13-command native client compilation required')


def guest_receipt(value):
    need(value['status']=='PASS_PRIVATE_GLIBC_GENERIC16K_RUNTIME' and value['architecture']=='aarch64' and value['page_size']==16384 and
         value['uid']==value['gid']==23001 and value['groups']==[] and value['runtime']['page_size']==16384 and
         value['cases']==sorted(CASES) and len(value['commands'])==14 and
         all(r['exit_code']==0 and r['group_absence_verified'] is True for r in value['commands']) and
         value['owned_processes_absent'] is True and value['payload_preserved'] is True and value['sources_preserved'] is True and
         value['candidate_preserved'] is True,'all8cases/14commands/actual16K/ordinary groups/preservation required')

    records=value['runtime_records'];tests=[r for r in records if r.get('kind')=='test']
    identities=[r for r in records if r.get('kind')=='identity'];results=[r for r in records if r.get('kind')=='result']
    need(len(records)==12 and len(tests)==9 and
         {r.get('name') for r in tests if r.get('process')=='parent'}==CASES and
         [r.get('name') for r in tests if r.get('process')=='child']==['exec_child'] and
         all(r.get('status')=='PASS' for r in tests) and len(identities)==2 and
         {r.get('process') for r in identities}=={'parent','child'} and results==[value['runtime']] and
         value['runtime'].get('status')=='PASS' and value['runtime'].get('cases')==8,
         'complete attributable parent/child runtime records required')
    roles={'/'+PREFIX+'/'+name for name,_ in ROLES.values()}
    symbols={'malloc','pthread_create','iconv_open','snprintf','getaddrinfo','clock_gettime','getrandom','cos'}
    for group in identities:
        objects={r['path'] for r in group['objects']};mapped={r['path'] for r in group['mapped_files']}
        need(roles<=objects and roles<=mapped,'both processes must map exact private runtime roles')
        need(len(group['providers'])==8 and {r['symbol'] for r in group['providers']}==symbols and
             all(r['path']=='/'+PREFIX+'/'+ROLES['libm' if r['symbol']=='cos' else 'libc'][0] for r in group['providers']),
             'exact private symbol providers required')
        if group['process']=='parent':
            need('/work/clients/plugin.so' in objects and any(p.startswith('/'+PREFIX+'/usr/lib/gconv/') for p in mapped) and
                 any(p.startswith('/'+PREFIX+'/usr/lib/locale/') for p in mapped),'private plugin/gconv/locale mappings required')
    need(value.get('hardware')=='NOT_RUN' and value.get('performance')=='NOT_MEASURED' and
         value.get('installation')=='NOT_RUN' and value.get('security')=='NO_CREDIT' and value.get('release')=='NOT_ADMITTED',
         'generic private-loader scope only')
