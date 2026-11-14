#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compose this exact Root namespace admission packet as DATA; never execute a role."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import namespace_guard as G

SOURCE_ROOT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261114/native-build-namespace-preflight-source-r2')
PIN=G.pin


def need(value, why):
    if not value: raise ValueError(why)


def encoded(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def read(path, cap=4*1024**2):
    path=Path(path)
    need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)), 'canonical ordinary packet operand')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=cap, 'bounded single-link DATA operand')
        with os.fdopen(os.dup(fd),'rb') as stream: raw=stream.read(cap+1)
        identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        need(len(raw)==before.st_size<=cap and identity(before)==identity(os.fstat(fd))==identity(path.lstat()), 'stable whole DATA operand')
        return raw
    finally: os.close(fd)


def obj(raw):
    def pairs(rows):
        result={}
        for key,value in rows:
            need(key not in result,'duplicate JSON key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda x:(_ for _ in ()).throw(ValueError('nonfinite JSON')))


def source_tree(root, rows):
    need(root.is_absolute() and root==root.resolve() and root.is_dir() and not any(p.is_symlink() for p in (root,*root.parents)), 'genuine canonical physical Source root')
    names=set();directories=set();total=0;nodes=0
    for directory,dirs,files in os.walk(root,followlinks=False):
        base=Path(directory)
        if base==root and '.git' in dirs: dirs.remove('.git')
        for name in dirs+files:
            p=base/name;relative=p.relative_to(root).as_posix()
            if relative=='.git':continue
            nodes+=1;need(nodes<=1200 and len(p.relative_to(root).parts)<=16 and not p.is_symlink(), 'bounded ordinary Source namespace')
            info=p.lstat()
            if stat.S_ISDIR(info.st_mode):directories.add(relative)
            else:
                need(stat.S_ISREG(info.st_mode) and relative in rows, 'unlisted or special physical Source file')
                body=read(p,32*1024**2);row=rows[relative];total+=len(body)
                need(total<=128*1024**2 and PIN(body)=={k:row[k] for k in ('bytes','sha256')} and
                     G.oid('blob',body)==row['oid'] and stat.S_IMODE(info.st_mode)==int(row['mode'],8)&511, 'every Source body/mode/blob matches Root full200')
                names.add(relative)
    expected_dirs={str(p) for n in rows for p in Path(n).parents if str(p)!='.'}
    need(names==set(rows) and directories==expected_dirs, 'complete physical Source200 without empty/unlisted directories')
    return total


def inputs(source_root, factory_binding=None, factory_sha256=None):
    templates={p.name:read(p) for p in (HERE/'templates').iterdir() if p.is_file()}
    held=obj(read(HERE/'held-source36.json'));base=Path(held['root'])
    for name,row in held['files'].items():need(PIN(read(base/name))==row, 'exact held Source36 operand '+name)
    old_index=obj(read(base/'input-seal.json'))
    need(type(old_index) is dict and len(old_index)==169, 'held complete169-input Source36 index')
    for name,row in old_index.items():need(PIN(read(Path(name),64*1024**2))==row, 'held external/local authority DATA pin')
    publication=obj(templates['source-publication.ACTUAL.json']);rows=obj(templates['source-full200.json'])
    G.publication(publication,templates['source.raw'],rows);source_bytes=source_tree(source_root,rows)
    external={name:row for name,row in old_index.items() if not Path(name).is_relative_to(base)}
    extra=obj(templates['Root-namespace-x86-certificates.json'])['certificates']
    for row in extra:
        body=read(Path(row['path']),65536);need(PIN(body)['sha256']==row['sha256'], 'independent Root extra certificate pin')
        value=obj(body);need(value.get('issuer')=='Root' and value.get('independently_classified') is True and
                            value.get('native_permission') is False and value.get('CI_success_claim') is False, 'Root classification only, never permission or CI-success grant')
        external[row['path']]=PIN(body)
    binding=None
    if factory_binding is not None:
        raw=read(factory_binding);need(PIN(raw)['sha256']==factory_sha256,'external Root whole factory-binding pin')
        binding=G.factory(obj(raw));external[str(factory_binding)]=PIN(raw)
        proofs=[]
        for key in ('factory_merge','factory_CI'):
            row=binding[key];body=read(Path(row['path']));need(PIN(body)=={k:row[k] for k in ('bytes','sha256')},'Root factory proof pin')
            external[row['path']]=PIN(body);proofs.append(obj(body))
        G.factory_proofs(binding,*proofs)
    else:need(factory_sha256 is None,'no pin without actual Root factory binding')
    return dict(templates=templates,external=external,binding=binding,source_root=str(source_root),rows=rows,source_bytes=source_bytes)


def render(data, output):
    """Pure packet rendering; publication and all Root roles remain separate."""
    output=Path(output);need(output.is_absolute() and output==output.resolve(),'canonical future packet path')
    files=dict(data['templates'])
    source_raw=files.pop('source.raw');files['publication/source.raw']=source_raw
    files['publication/publication.json']=files['source-publication.ACTUAL.json']
    parent=read(HERE.parent/'native-build-namespace-preflight/parent.raw',4096)
    need(G.oid('commit',parent)==G.PARENT,'exact genuine parent97 raw commit')
    files['publication/parent.raw']=parent
    files['namespace_guard.py']=read(HERE/'namespace_guard.py')
    files['factory-files.json']=read(HERE/'factory-files.json')
    facts=dict(schema=1,status='SOURCE_BOUND_FACTORY_PENDING_PR433' if data['binding'] is None else 'SOURCE_BOUND_ROOT_FACTORY_CI_MAIN_DATA',
               source=G.SOURCE,ref=G.REF,tree=G.TREE,parent=G.PARENT,map_sha256=G.MAP,operation=G.OPERATION,group=G.GROUP,
               source_root=data['source_root'],source_files=200,source_map_rows=199,reader=G.READER,helper=G.HELPER,
               factory_binding=data['binding'],factory_reviewed_correction='8d4ec359bf05dda455eb772077b4edf37de53002',
               observed_main_context='295d838936371ce7376fc5b71c47232b155bd0b3',
               Root_authority=None,Root_fresh_live_reservation=None,actual_run=None,actual_job=None,artifact=None,body=None,
               worker_Native_POSTs=0,worker_Original_GETs=0,worker_Reader_calls=0,acceptance=False)
    files['facts.json']=encoded(facts)
    closure=dict(schema=1,status='MATCHING_READER_SOURCE_DATA_ONLY_NOT_EXECUTED',source=G.SOURCE,ref=G.REF,tree=G.TREE,map_sha256=G.MAP,
                 reader=dict(**G.READER,mode='100644',oid=data['rows'][G.READER['path']]['oid']),
                 files=data['rows'],reader_calls=0,authority_issued=False,acceptance=False)
    files['matching-reader-closure.ACTUAL.json']=encoded(closure)
    binding=obj(files['strict-reader-binding.TEMPLATE.json']);binding['source_root']=data['source_root'];binding['full200']=str(output/'source-full200.json')
    files['strict-reader-binding.TEMPLATE.json']=encoded(binding)
    authority=obj(files['Root-authority.TEMPLATE.json']);need(authority['approved'] is authority['issued_at'] is None and
          all(v is None for v in authority['reviews'].values()) and authority['reservation']['held_by'] is None and
          authority['reservation']['active'] is authority['reservation']['pending'] is None, 'composer cannot issue resource authority')
    index=dict(data['external'])
    # No self-pinning cycle: top-level seal binds operators; input seal binds all dependencies.
    omitted={'ROOT-NATIVE-ONCE.py','ROOT-INDEPENDENT-PREFLIGHT.py'}
    for name,raw in files.items():
        if name not in omitted:index[str(output/name)]=PIN(raw)
    need(len(index)<=256,'finite held plus explicit new packet input closure')
    files['input-seal.json']=encoded(index)
    native=files['ROOT-NATIVE-ONCE.py'].replace(b'@INPUT_SEAL_SHA256@',PIN(files['input-seal.json'])['sha256'].encode())
    need(b'@INPUT_SEAL_SHA256@' not in native,'native input index fully bound as DATA');files['ROOT-NATIVE-ONCE.py']=native
    files['ROOT-INDEPENDENT-PREFLIGHT.py']=files['ROOT-INDEPENDENT-PREFLIGHT.py'].replace(b'@ROOT_OPERATOR_SHA256@',PIN(native)['sha256'].encode())
    for name,raw in files.items():
        if name.endswith('.py'):ast.parse(raw,filename=name)
    seal=dict(schema=1,status='SEALED_NAMESPACE_SOURCE_DATA_FACTORY_PENDING_NO_AUTHORITY' if data['binding'] is None else 'SEALED_NAMESPACE_SOURCE_ROOT_FACTORY_BOUND_UNISSUED',files={n:PIN(b) for n,b in files.items()})
    files['seal.json']=encoded(seal);digest=PIN(files['seal.json'])['sha256']
    commands=dict(status='UNENTERED_ROOT_ONLY_NO_AUTHORITY',Root_only=True,source=G.SOURCE,ref=G.REF,map_sha256=G.MAP,
                  packet_seal=PIN(files['seal.json']),factory_CI_Main_pending=data['binding'] is None,
                  preflight=dict(argv=['/usr/bin/python3','-I','-B',str(output/'ROOT-INDEPENDENT-PREFLIGHT.py'),'--seal',digest,'--index','0','--execute-root-preflight-once'],role='READONLY_SOURCE_AND_COMPLETE_LIVE_METADATA_NOT_AUTHORITY'),
                  native=dict(argv=['/usr/bin/python3','-I','-B',str(output/'ROOT-NATIVE-ONCE.py'),'--seal',digest,'--authority',None,'--authority-sha256',None],Root_resource_authority=None),
                  actual_run=None,actual_job=None,artifact=None,body=None,worker_Native_POSTs=0,worker_Original_GETs=0,worker_Reader_calls=0)
    files['root-commands.json']=encoded(commands)
    return files


def publish(files, output):
    output=Path(output);need(output.is_absolute() and output==output.resolve(),'canonical fresh packet path')
    parent=output.parent;info=parent.stat()
    need(info.st_uid==os.getuid() and not stat.S_IMODE(info.st_mode)&0o022 and not any(p.is_symlink() for p in (parent,*parent.parents)), 'owned safe packet parent')
    output.mkdir(mode=0o700)  # Atomic no-replace claim. Partial DATA is preserved; never reused.
    for name,raw in sorted(files.items(),key=lambda r:(r[0]=='seal.json',r[0])):
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw)
        need(read(path)==raw,'packet write differs')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root',type=Path,default=SOURCE_ROOT)
    p.add_argument('--factory-binding',type=Path);p.add_argument('--factory-binding-sha256')
    p.add_argument('--output',type=Path)
    a=p.parse_args();data=inputs(a.source_root,a.factory_binding,a.factory_binding_sha256)
    if a.output is not None:publish(render(data,a.output),a.output)
    print(json.dumps(dict(status='VALIDATED_NAMESPACE_ADMISSION_PREPARATION_DATA_ONLY',source=G.SOURCE,source_files=200,
         source_bytes=data['source_bytes'],factory_CI_Main_pending=data['binding'] is None,packet_written=a.output is not None,
         Native_POSTs=0,Original_GETs=0,Reader_calls=0,authority_issued=False),sort_keys=True))
