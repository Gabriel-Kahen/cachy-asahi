# SPDX-License-Identifier: MIT
"""Closed conventional GNU provider lifecycle input policy; imports are inert."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tarfile

HERE=Path(__file__).resolve().parent
NAME='cachy-asahi-glibc-gnu-provider'
VERSION='2.43.caa1-1'
BASE_LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
HELD='glibc-2.43+r22+g8362e8ce10b2-2-aarch64.pkg.tar.xz'
HELD_SHA='8fac217e98c6e4342326726b2640ac254e8c82032f06f30bfa13ebbcc4fcb25b'
LABEL='org.cachy-asahi.glibc-gnu-provider-interruption'
CASES=('pristine','modified')
ROLES={'loader':'usr/lib/ld-linux-aarch64.so.1','libc':'usr/lib/libc.so.6','libm':'usr/lib/libm.so.6'}
CACHES={'etc/ld.so.cache','var/cache/ldconfig/aux-cache','usr/lib/gconv/gconv-modules.cache'}
ENV={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC','PYTHONDONTWRITEBYTECODE':'1'}


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def read(path,cap=2*1024**2):
    path=Path(path)
    need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary input path')
    info=path.stat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=cap,'bounded ordinary input')
    raw=path.read_bytes();need(len(raw)==info.st_size,'input truncated');return raw


def relative(name):
    need(type(name) is str and name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')),'closed relative path')
    return name


def ref(root,row,cap=256*1024**2):
    need(set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int and 0<row['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',row['sha256']),'exact input reference')
    path=root/relative(row['path']);raw=read(path,cap)
    need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'input bytes/hash differ');return path


def load(name,path):
    spec=importlib.util.spec_from_file_location('provider_lifecycle_'+name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module;spec.loader.exec_module(module);return module


def helpers(root):
    manifest=json.loads(read(HERE/'source-manifest.json'))
    for name,row in manifest['files'].items():
        raw=read(HERE/relative(name));need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'lifecycle source changed: '+name)
    dependencies=json.loads(read(HERE/'dependencies.json'))
    need({'scripts/apps/file_capabilities.py','scripts/ci/apps-full574-native/export_extract.py','scripts/ci/glibc-gnu-provider-lifecycle-owner/snapshot.py','scripts/ci/glibc-gnu-provider-lifecycle/capabilities.py','scripts/ci/glibc-gnu-provider-lifecycle/copy_scope.py','scripts/apps/full574_copy.py','scripts/ci/glibc-gnu-provider-lifecycle/proc_mount.py'}<=dependencies['files'].keys(),'capability-aware frozen helper closure required')
    for n,row in dependencies['files'].items():
        raw=read(root/relative(n));need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'held helper changed: '+n)
    sys.path.insert(0,str(root/'scripts/update'))
    import full_root,aux_copy
    return dict(proc_probe=load('proc_probe',root/'scripts/ci/glibc-gnu-provider-lifecycle/proc_mount.py'),caps=load('file_capabilities',root/'scripts/apps/file_capabilities.py'),capabilities=load('capability_bridge',root/'scripts/ci/glibc-gnu-provider-lifecycle/capabilities.py'),roots=full_root,copy=aux_copy,db=load('database',root/'scripts/ci/full-root-upgrade/root_upgrade.py'),
        runtime=load('runtime',root/'scripts/ci/glibc-owned-runtime/runner.py'))


def fields(raw):
    result={}
    for line in raw.decode().splitlines():
        if line and not line.startswith('#'):
            key,value=line.split(' = ',1);result.setdefault(key,[]).append(value)
    return result


def archive(path):
    nodes={};data={};hardlinks={};total=0
    with tarfile.open(path,mode='r:*') as stream:
        for m in stream:
            n=relative(m.name.rstrip('/'));need(n not in nodes and len(nodes)<60000 and m.uid==m.gid==0 and not m.mode&0o7000,'package member identity/mode')
            need(m.isfile() or m.isdir() or m.issym() or m.islnk(),'ordinary package member')
            need(set(m.pax_headers)<={'path','linkpath','mtime','atime','ctime'},'provider/held package xattrs or unknown PAX refused')
            row=dict(type='directory' if m.isdir() else 'symlink' if m.issym() else 'file',mode=m.mode,uid=m.uid,gid=m.gid)
            if m.issym():
                need(not m.linkname.startswith('/') and '\x00' not in m.linkname,'relative package link');row['target']=m.linkname
            elif m.islnk():
                target=relative(m.linkname)
                need('\0' not in n+target and not n.startswith('.') and not target.startswith('.') and m.size==0,
                     'ordinary payload hardlink header')
                need(len(hardlinks)<16384,'package hardlink alias bound');hardlinks[n]=target
            elif m.isfile():
                total+=m.size;need(m.size<=64*1024**2 and total<=512*1024**2,'package byte bound')
                raw=stream.extractfile(m).read(m.size+1);need(len(raw)==m.size,'package byte count')
                row.update(bytes=m.size,sha256=sha(raw));data[n]=raw
            nodes[n]=row
    # Resolve only archive-owned regular bytes; never ask tarfile or the host to follow a link.
    resolved={n:n for n in data};groups={}
    for name in hardlinks:
        trail=[];seen=set();target=name
        while target not in resolved:
            need(target in hardlinks and target not in seen,'missing/special/cyclic package hardlink target')
            seen.add(target);trail.append(target);target=hardlinks[target]
        origin=resolved[target];source=nodes[origin]
        for alias in trail:
            need(all(nodes[alias][k]==source[k] for k in ('mode','uid','gid')),'package hardlink metadata differs')
            for member in (alias,origin):
                parts=member.split('/')
                need(all('/'.join(parts[:i]) not in nodes or nodes['/'.join(parts[:i])]['type']=='directory'
                         for i in range(1,len(parts))),'package hardlink ancestor is not directory')
            total+=source['bytes'];need(total<=512*1024**2,'package byte bound')
            nodes[alias].update(bytes=source['bytes'],sha256=source['sha256']);data[alias]=data[origin];resolved[alias]=origin
            members=groups.setdefault(origin,{origin});members.add(alias)
            need(len(groups)<=4096 and len(members)<=4096,'package hardlink group bound')
    for members in groups.values():
        key=min(members)
        for name in members:nodes[name]['hardlink_group']=key
    need({'.PKGINFO','.BUILDINFO','.MTREE'}<=set(data),'complete package metadata')
    return dict(nodes={n:r for n,r in nodes.items() if not n.startswith('.')},data=data,metadata=fields(data['.PKGINFO']),buildinfo=fields(data['.BUILDINFO']))


def interpreter(raw):
    need(raw[:7]==b'\x7fELF\x02\x01\x01' and len(raw)>=64 and struct.unpack_from('<H',raw,18)[0]==183,'AArch64 ELF64 probe')
    off=struct.unpack_from('<Q',raw,32)[0];size,count=struct.unpack_from('<HH',raw,54)
    need(size==56 and count<=1024 and off+size*count<=len(raw),'bounded ELF program headers')
    values=[]
    for i in range(count):
        p=struct.unpack_from('<IIQQQQQQ',raw,off+i*size)
        if p[0]==3:
            need(1<p[5]<=128 and p[2]+p[5]<=len(raw),'PT_INTERP bound');values.append(raw[p[2]:p[2]+p[5]].rstrip(b'\0').decode())
    need(values in [['/lib/ld-linux-aarch64.so.1'],['/usr/lib/ld-linux-aarch64.so.1']],'normal system interpreter required')
    return values[0]


def configuration(inputs,pin):
    policy=json.loads(read(HERE/'input-policy.json',65536))
    need(policy['schema_version']==1 and policy['status']=='BOUND_BY_ROOT' and type(policy['binding']) is dict,'UNBOUND provider interruption: Root must bind accepted private16K/new native pair first')
    raw=read(inputs/'interruption-input.json');need(sha(raw)==pin==policy['binding']['index_sha256'],'frozen input index hash')
    value=json.loads(raw);need(value['schema_version']==1 and value['status']=='ROOT_BOUND_UNSELECTED_PROVIDER_INTERRUPTION','explicit future lifecycle input')
    need(value['package']==NAME and value['version']==VERSION and value['base_lock_sha256']==BASE_LOCK,'exact provider574 lane')
    need(re.fullmatch('sha256:[0-9a-f]{64}',value['image_id']) and re.fullmatch('[0-9a-f]{32}',value['token']),'immutable image and job token')
    need(value['token']==policy['binding']['token'] and value['image_id']==policy['binding']['image_id'],'frozen actor ownership binding')
    producer=json.loads(read(ref(inputs,value['producer_report'])))
    need(producer['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and producer['image']==value['image_id'] and producer['packages']==574 and producer['ownership']['token']==value['producer_token'],'existing owned original574 producer binding')
    need(re.fullmatch('[0-9a-f]{64}',value['source_nodes_sha256']),'frozen source node-map hash')
    capmap=value['source_capabilities'];capraw=(json.dumps(capmap,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    need(type(capmap) is dict and len(capraw)<=1024**2 and re.fullmatch('[0-9a-f]{64}',value['source_capabilities_sha256']) and sha(capraw)==value['source_capabilities_sha256'],'frozen complete original574 capability map/hash')
    lock=ref(inputs,value['base_lock'],65536);need(sha(read(lock,65536))==BASE_LOCK,'exact original574 lock')
    base=dict(line.split(' ',1) for line in read(lock).decode().splitlines());need(len(base)==574 and 'glibc' in base,'574 held provider baseline')
    private=json.loads(read(ref(inputs,value['private16k'])))
    need(private['status']=='ROOT_ACCEPTED_PRIVATE_GNU16K_RUNTIME' and private['page_size']==16384 and private['cases']==8 and private['runtime_records']==12 and
         private['ordered_cleanup']=='PASS' and private['actual_parent_child_providers']=='PASS' and private['hardware']=='NOT_RUN' and
         private['candidate_package_sha256']==value['private16k_archive_sha256'],'actual Root-accepted private GNU16K prerequisite')
    receipt=json.loads(read(ref(inputs,value['provider_pair'])))
    need(receipt['status']=='ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR' and receipt['archive_sha256']==value['provider_pair_archive_sha256'] and
         receipt['hardware']=='NOT_RUN','Root accepted NEW conventional provider pair')
    pair={lane:ref(inputs,value['archives'][lane]) for lane in ('a','b')}
    need(read(pair['a'],256*1024**2)==read(pair['b'],256*1024**2) and sha(read(pair['a'],256*1024**2))==value['provider_pair_archive_sha256'],'accepted byte-identical provider pair')
    candidate=archive(pair['a']);meta=candidate['metadata']
    need(meta['pkgname']==[NAME] and meta['pkgver']==[VERSION] and meta['arch']==['aarch64'] and meta['provides']==['glibc=2.43'] and meta['conflict']==['glibc'] and not {'replace','replaces'}&set(meta) and meta['backup']==['etc/gai.conf'],'exact conventional provider metadata')
    need(set(meta['depend'])=={'linux-api-headers>=4.10','filesystem','tzdata'},'exact dependencies and no self-provider dependency')
    forbidden={'bin','lib','sbin','usr/sbin','etc/ld.so.conf','etc/nsswitch.conf','usr/bin/tzselect','usr/bin/zic','usr/bin/zdump'}
    need(not forbidden&set(candidate['nodes']) and all(n in candidate['nodes'] for n in (*ROLES.values(),'usr/lib/gconv/ISO8859-1.so','usr/lib/locale/C.utf8/LC_CTYPE')),'conventional role/layout with preserved filesystem/tzdata ownership')
    need('.INSTALL' not in candidate['data'] and all(not n.endswith('.hook') for n in candidate['nodes']),'no candidate scriptlet/hook')
    need(candidate['buildinfo']['pkgbuild_sha256sum']==[value['provider_pkgbuild_sha256']],'accepted recipe BUILDINFO binding')
    held=ref(inputs,value['held']);need(held.name==HELD and sha(read(held,256*1024**2))==HELD_SHA,'exact held glibc rollback archive')
    old=archive(held);need(old['metadata']['pkgname']==['glibc'] and old['metadata']['pkgver']==[base['glibc']],'exact held version')
    expected_script=b'post_upgrade() {\n  locale-gen\n\n  ldconfig -r .\n\n  iconvconfig\n}\n'
    need(old['data'].get('.INSTALL')==expected_script,'actual held post_upgrade script bytes')
    for n in ('smoke-normal','exec-child','plugin.so'):ref(inputs,value['probes'][n],4*1024**2)
    for n in ('smoke-normal','exec-child'):interpreter(read(inputs/value['probes'][n]['path'],4*1024**2))
    normal=json.loads(read(HERE/'normal-exec-change.json'));probes=json.loads(read(ref(inputs,value['probe_receipt'])))
    need(probes['status']=='ROOT_ACCEPTED_NORMAL_INTERPRETER_PROBES' and probes['normal_source_sha256']==normal['after_sha256'] and probes['files']==value['probes'],'exact normal-probe source/compiler receipt')
    return value,base,candidate,old
