# SPDX-License-Identifier: MIT
"""One conventional system-path runtime; UNBOUND inputs authorize no actors."""
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

HERE=Path(__file__).resolve().parent
SOURCE=Path(os.environ['GLIBC_SYSTEM16K_SOURCE_ROOT']) if 'GLIBC_SYSTEM16K_SOURCE_ROOT' in os.environ else (Path('/repo') if Path('/repo/scripts/ci/glibc-generic16k/common.py').is_file() else HERE.parents[2])

def _module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

BASE=_module('held_private16k_data_helpers',SOURCE/'scripts/ci/glibc-generic16k/common.py')
for _name in ('need','sha','safe','read','decode','save','relative','checked','aligned'):
    globals()[_name]=getattr(BASE,_name)
LOCK=BASE.LOCK
PREFIX='system'
CLIENTS=('smoke-normal','exec-child','plugin.so')
CASES=BASE.CASES
TOOLS=BASE.TOOLS
ROLES={'loader':'usr/lib/ld-linux-aarch64.so.1','libc':'usr/lib/libc.so.6','libm':'usr/lib/libm.so.6'}
PACKAGE_SHA=None
PACKET=None
INDEX=None
NORMAL_REFS=None
FIXTURE='tmp/provider-lifecycle'
HELD_SHA='8fac217e98c6e4342326726b2640ac254e8c82032f06f30bfa13ebbcc4fcb25b'


def dependencies():return decode(read(HERE/'dependencies.json'))['files']


def check_source(root):
    for name,row in dependencies().items():checked(root,name,row,2*1024**2)
    for name,row in decode(read(HERE/'source-manifest.json'))['files'].items():checked(root,name,row,2*1024**2)


def load(root,name):
    pins=dependencies()|decode(read(HERE/'source-manifest.json'))['files'];checked(root,name,pins[name],2*1024**2)
    return _module('system16k_'+sha(name.encode())[:16],Path(root)/name)


def bindings(value=None):
    value=decode(read(HERE/'input-policy.json')) if value is None else value
    need(value.get('status')=='BOUND_BY_ROOT' and value.get('schema_version')==1 and type(value.get('binding')) is dict,'UNBOUND conventional system16K inputs: actual accepted provider pair/probes required')
    row=value['binding'];need(re.fullmatch('[0-9a-f]{40}',row.get('source','')) and type(row.get('index')) is dict,'actual immutable provider input source/index required')
    BASE.bindings() # Exact current Tools archive-only cache/helper contract, unchanged.
    return value


def ref(root,row,cap=64*1024**2):
    need(set(row)=={'path','bytes','sha256'},'closed exact packet reference required')
    return checked(root,row['path'],{k:row[k] for k in ('bytes','sha256')},cap)


def normal_receipt(value,root,probes):
    sys.path.insert(0,str(SOURCE/'scripts/ci/glibc-gnu-provider'))
    normal=load(SOURCE,'scripts/ci/glibc-gnu-provider/normal_clients.py');original=normal.data
    def data(path,cap=4*1024**2):
        if path.parent==Path('/bound-normal/bin'):
            need(path.name in CLIENTS,'known normal artifact');return read(ref(root,probes[path.name],cap),cap)
        return original(path,cap)
    normal.data=data
    files=decode(read(SOURCE/'scripts/ci/glibc-owned-runtime/source-manifest.json'))['files']
    normal.validate(value,Path('/bound-normal'),files)
    return value


def pair(root):
    global PACKAGE_SHA,PACKET,INDEX,NORMAL_REFS
    policy=bindings()['binding'];index=decode(read(ref(root,policy['index'],2*1024**2),2*1024**2))
    need(index.get('schema_version')==1 and index.get('status')=='ROOT_ACCEPTED_PROVIDER_LIFECYCLE_INPUTS','actual conventional provider packet required')
    def walk(value):
        if type(value) is dict:
            if set(value)=={'path','bytes','sha256'}:ref(root,value,256*1024**2)
            else:
                for child in value.values():walk(child)
        elif type(value) is list:
            for child in value:walk(child)
    walk(index)
    need(8<=len(index['files'])<=256,'finite provider packet files required')
    for name,row in index['files'].items():checked(root,name,row,256*1024**2)
    accepted=decode(read(ref(root,index['provider_pair'])))
    need(accepted['status']=='ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR' and accepted['hardware']=='NOT_RUN' and accepted['provider_pkgbuild_sha256']==index['provider_pkgbuild_sha256'],'Root accepted NEW provider pair required')
    packages=[ref(root,index['archives'][side],256*1024**2) for side in ('a','b')]
    need(packages[0]!=packages[1] and sha(read(packages[0],256*1024**2))==sha(read(packages[1],256*1024**2))==accepted['archive_sha256'],'actual identical provider archives required')
    held=ref(root,index['held'],256*1024**2);need(sha(read(held,256*1024**2))==HELD_SHA,'exact held rollback archive required')
    owner=load(SOURCE,'scripts/ci/glibc-gnu-provider-lifecycle/common.py');generic=load(SOURCE,'scripts/virtual/generic16k/fixture.py')
    archive=generic.Archive(packages[0])
    try:
        meta=owner.fields(archive.read('.PKGINFO')[1]);build=owner.fields(archive.read('.BUILDINFO')[1])
        forbidden={'bin','lib','sbin','usr/sbin','etc/ld.so.conf','etc/nsswitch.conf','usr/bin/tzselect','usr/bin/zic','usr/bin/zdump'}
        need(not forbidden&set(archive.nodes) and all(n in ('.PKGINFO','.BUILDINFO','.MTREE','usr','etc','etc/gai.conf','etc/rpc') or n.startswith('usr/') for n in archive.nodes),'conventional provider filesystem ownership/layout required')
        need(all(m.isfile() or m.isdir() or m.issym() or m.islnk() for m in archive.nodes.values()),'ordinary provider package members')
        need(meta['pkgname']==['cachy-asahi-glibc-gnu-provider'] and meta['pkgver']==['2.43.caa1-1'] and meta['arch']==['aarch64'] and meta['provides']==['glibc=2.43'] and meta['conflict']==['glibc'] and not {'replace','replaces'}&set(meta) and meta['backup']==['etc/gai.conf'] and set(meta['depend'])=={'linux-api-headers>=4.10','filesystem','tzdata'},'exact provider metadata')
        need(build['pkgbuild_sha256sum']==[index['provider_pkgbuild_sha256']] and '.INSTALL' not in archive.nodes and all(not n.endswith('.hook') for n in archive.nodes),'bound BUILDINFO and no provider scriptlet/hooks')
    finally:archive.tar.close()
    probe=decode(read(ref(root,index['probe_receipt'])))
    need(set(index['probes'])==set(CLIENTS) and probe['status']=='ROOT_ACCEPTED_NORMAL_INTERPRETER_PROBES' and probe['files']==index['probes'] and probe['normal_source_sha256']=='a766bc7cd31cce18fe7e564432de4e4b63db49763608ae70ef8fab61cd29116c','Root accepted normal-parent/direct-child binaries required')
    need(set(probe['compile_receipts'])=={'a','b'},'both original13-command normal compiler receipts required')
    for side in ('a','b'):normal_receipt(decode(read(ref(root,probe['compile_receipts'][side]),2*1024**2)),root,index['probes'])
    PACKAGE_SHA=accepted['archive_sha256'];PACKET=root;INDEX=index;NORMAL_REFS=probe['compile_receipts'];return index,packages


def stage(package,root,generic):
    need(INDEX is not None and sha(read(package,256*1024**2))==PACKAGE_SHA and not root.exists(),'accepted provider/fresh system root required');root.mkdir(mode=0o700)
    archive=generic.Archive(package);files={};total=0
    try:
        for name,node in sorted(archive.nodes.items()):
            if node.isdir() or not (name.startswith(('usr/lib/','usr/share/locale/')) or name in ('usr/bin/iconv','usr/bin/locale','etc/gai.conf','etc/rpc')) or name.endswith(('.a','.o')):continue
            target,resolved=archive.resolve(name);need(target.startswith(('usr/','etc/')) and resolved.uid==resolved.gid==0 and not resolved.mode&0o7000,'contained conventional runtime bytes required')
            _,raw,mode=archive.read(name);total+=len(raw);need(len(files)<4096 and total<=256*1024**2 and len(raw)<=64*1024**2,'unchanged capture runtime limits')
            out=root/relative(name);out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(raw);out.chmod(mode);files[name]=dict(bytes=len(raw),mode=mode,sha256=sha(raw))
    finally:archive.tar.close()
    need(set(ROLES.values())|{'usr/lib/gconv/ISO8859-1.so','usr/lib/locale/C.utf8/LC_CTYPE','usr/bin/iconv','usr/bin/locale'}<=set(files),'complete standard roles/locale/gconv/CLI subset required')
    return files


def elf_closure(elfs,files):
    for name,row in elfs.items():
        prefix='system/' if name.startswith('system/') else ''
        def present(path):return prefix+path.lstrip('/') in files or (path.startswith('/lib/') and prefix+'usr/'+path.lstrip('/') in files)
        need(not row['interpreter'] or present(row['interpreter']),'same-root ELF interpreter absent: '+name)
        folders=[prefix+'usr/lib/',prefix+'lib/']
        if name.startswith('system/usr/lib/gconv/'):folders.append('system/usr/lib/gconv/')
        for lib in row['needed']:need(any(p+lib in files for p in folders),'same-root DT_NEEDED absent: '+name+' -> '+lib)


def guest_receipt(value):
    need(value['status']=='PASS_CONVENTIONAL_GNU_SYSTEM_PATHS_GENERIC16K_RUNTIME' and value['architecture']=='aarch64' and value['page_size']==16384 and value['uid']==value['gid']==23001 and value['groups']==[] and value['runtime']['page_size']==16384 and value['cases']==sorted(CASES),'actual16K ordinary conventional runtime required')
    need(len(value['commands'])==3 and all(r['exit_code']==0 and r['group_absence_verified'] for r in value['commands']) and all(value[k] is True for k in ('owned_processes_absent','payload_preserved','held_preserved','normal_parent_and_child')),'three real guest commands and preservation/group retirement required')
    need([r['argv'][:5] for r in value['commands']]==[['/usr/bin/python3','-I','-B','/enter-system.py',p] for p in ('/usr/bin/locale','/usr/bin/iconv','/'+FIXTURE+'/smoke-normal')],'direct normal-program command lineage required')
    records=value['runtime_records'];tests=[r for r in records if r.get('kind')=='test'];groups=[r for r in records if r.get('kind')=='identity']
    need(len(records)==12 and len(tests)==9 and {r['name'] for r in tests if r['process']=='parent'}==CASES and [r['name'] for r in tests if r['process']=='child']==['exec_child'] and all(r['status']=='PASS' for r in tests) and len(groups)==2 and {r['process'] for r in groups}=={'parent','child'},'full eight cases/child/two identity groups required')
    need([r for r in records if r.get('kind')=='result']==[value['runtime']] and value['runtime']['status']=='PASS' and value['runtime']['cases']==8 and value['runtime']['glibc_version']=='2.43','one exact successful runtime result')
    expected_roles={'/'+n for n in ROLES.values()};symbols={'malloc','pthread_create','iconv_open','snprintf','getaddrinfo','clock_gettime','getrandom','cos'}
    for group in groups:
        objects={r['path'] for r in group['objects']};mapped={r['path'] for r in group['mapped_files']}
        desired='/'+FIXTURE+'/'+('smoke-normal' if group['process']=='parent' else 'exec-child')
        need(group['executable']==desired and expected_roles<=objects and expected_roles<=mapped and not any(p.startswith('/opt/') or p.startswith('/system/') for p in objects|mapped),'normal executable and exact standard system role maps')
        need(len(group['providers'])==8 and {r['symbol'] for r in group['providers']}==symbols and all(r['path']=='/'+ROLES['libm' if r['symbol']=='cos' else 'libc'] for r in group['providers']),'exact standard symbol providers')
        if group['process']=='parent':need('/'+FIXTURE+'/plugin.so' in objects and any(p.startswith('/usr/lib/gconv/') for p in mapped) and any(p.startswith('/usr/lib/locale/') for p in mapped),'actual default plugin/gconv/locale mappings')
    need(value['scope']=='DATA_STAGED_PRIVATE_ROOT_NOT_ALPM_INSTALLATION' and value['hardware']=='NOT_RUN' and value['release']=='NOT_ADMITTED' and value['security']=='NO_CREDIT','system-path-only scope required')


def validator_source(root):
    import ast
    raw=read(Path(root)/'scripts/ci/glibc-gnu-provider-lifecycle/container.py').decode();tree=ast.parse(raw)
    chunks=[ast.get_source_segment(raw,n) for n in tree.body if isinstance(n,ast.FunctionDef) and n.name in ('role_identities','validate_runtime')]
    need(len(chunks)==2,'exact normal lifecycle identity/validator functions required')
    text='import os\nfrom pathlib import Path\n\n'+'\n\n'.join(chunks)+'\n';anchor="results[0]['page_size']==4096"
    need(text.count(anchor)==1,'one actual-page expectation required');return text.replace(anchor,"results[0]['page_size']==16384")
