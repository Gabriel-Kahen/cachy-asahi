#!/usr/bin/env python3
"""Copy the sealed348 UI material bytes as inert DATA; no authentication or actor."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import time

HERE=Path(__file__).resolve().parent
PLAN={'bytes':132913,'sha256':'7730156f620ff21e3e4c4089cd51c5a2bafd6decef95555ea5a0f738465e8083'}
MANIFEST={'bytes':2256903,'sha256':'f88c15e6de5b36dd63ea5216a3e4ca19dc395dbec9ffcb9a405253c6ebf7b981'}
FILE_LIMIT=256*1024**2
READ_LIMIT=512*1024**2
CHUNK=65536
DIRFLAGS=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
LEAFFLAGS=os.O_NOFOLLOW|os.O_NONBLOCK


class Refused(ValueError): pass


def need(ok,reason):
    if not ok:raise Refused(reason)


def tick(deadline):need(time.monotonic()<deadline,'120second DATA deadline')


def identity(info):
    return {k:getattr(info,k) for k in ('st_dev','st_ino','st_size','st_mode','st_uid','st_gid','st_nlink','st_mtime_ns','st_ctime_ns')}


def directory_identity(info):return {k:getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid')}


def parent(path):
    """Anchor every absolute parent component with O_DIRECTORY|O_NOFOLLOW."""
    path=Path(path);need(path.is_absolute() and '..'not in path.parts,'absolute canonical source/destination path')
    fd=os.open('/',DIRFLAGS);chain=[directory_identity(os.fstat(fd))]
    try:
        for part in path.parts[1:-1]:
            child=os.open(part,DIRFLAGS,dir_fd=fd);os.close(fd);fd=child;chain.append(directory_identity(os.fstat(fd)))
        return fd,chain
    except BaseException:os.close(fd);raise


def source(path):
    fd,chain=parent(path)
    try:leaf=os.open(Path(path).name,os.O_RDONLY|LEAFFLAGS,dir_fd=fd)
    finally:os.close(fd)
    return leaf,chain


def read(fd,size,budget,deadline,category):
    tick(deadline);need(0<size<=CHUNK and budget['read_bytes']+size<=READ_LIMIT,'global DATA read-I/O cap')
    block=os.read(fd,size);budget['read_bytes']+=len(block);budget[category]+=len(block)
    return block


def checked_metadata(path,expected,maximum):
    need(expected['bytes']<=maximum,'metadata object cap');fd,chain=source(path)
    try:
        before=identity(os.fstat(fd));need(stat.S_ISREG(before['st_mode']) and before['st_size']==expected['bytes'],'metadata ordinary file/size')
        chunks=[];count=0
        while count<expected['bytes']:
            block=os.read(fd,min(CHUNK,expected['bytes']-count));need(block,'truncated metadata');chunks.append(block);count+=len(block)
        body=b''.join(chunks)
        need(identity(os.fstat(fd))==before and hashlib.sha256(body).hexdigest()==expected['sha256'],'metadata full pin/identity')
        verify,after_chain=source(path)
        try:need(identity(os.fstat(verify))==before and chain==after_chain,'metadata path association')
        finally:os.close(verify)
        return body
    finally:os.close(fd)


def validate_plan(plan,count=348):
    need(plan['kind']=='UI172_RETAINED_MATERIALS_PLAN_DATA_ONLY' and plan['copy_or_archive_reads_performed'] is False,'sealed DATA-plan kind')
    rows=plan['files'];need(len(rows)==count and 0<count<=348,'exact finite plan membership')
    names=set();total=0
    for row in rows:
        name=row['filename'];ref=row['pin'];path=Path(row['source_path'])
        need(isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9@._+:-]+',name) and name not in ('.','..') and name not in names,'unique flat material filename')
        need(isinstance(row['source_path'],str) and '\0' not in row['source_path'] and path.is_absolute() and '..'not in path.parts,'absolute source path');names.add(name)
        cap=65536 if name.endswith(('.sig','.gpg')) else 64*1024**2
        if name.startswith(('cachy-asahi-fish-config-','cachy-asahi-zsh-config-')):cap=1024**2
        need(set(ref)=={'bytes','sha256'} and type(ref['bytes']) is int and 0<ref['bytes']<=cap
             and isinstance(ref['sha256'],str) and re.fullmatch('[0-9a-f]{64}',ref['sha256']),'material per-object size/SHA cap')
        total+=ref['bytes'];need(total<=FILE_LIMIT,'global256MiB planned file-set cap')
    return rows,total


def preflight(rows,deadline):
    found={};missing=[]
    for row in rows:
        tick(deadline);fd=None
        try:
            fd,chain=source(row['source_path']);info=identity(os.fstat(fd))
            need(stat.S_ISREG(info['st_mode']) and info['st_size']==row['pin']['bytes'],'ordinary source file/exact size')
            found[row['filename']]={'identity':info,'parents':chain}
        except (OSError,Refused) as error:missing.append({'filename':row['filename'],'source_path':row['source_path'],'reason':str(error)})
        finally:
            if fd is not None:os.close(fd)
    return found,missing


def copy_one(row,directory,destination,expected,budget,deadline):
    name=row['filename'];ref=row['pin'];src=None;dst=None
    try:
        src,chain=source(row['source_path']);before=identity(os.fstat(src))
        need(before==expected['identity'] and chain==expected['parents'],'source changed after preflight')
        need(budget['file_bytes']+ref['bytes']<=FILE_LIMIT,'global256MiB copied file-set cap')
        # Reserve the full object even when a later read/hash check refuses.
        budget['file_bytes']+=ref['bytes']
        dst=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|LEAFFLAGS,0o600,dir_fd=directory)
        digest=hashlib.sha256();count=0
        while count<ref['bytes']:
            block=read(src,min(CHUNK,ref['bytes']-count),budget,deadline,'source_read_bytes');need(block,'truncated source')
            count+=len(block);digest.update(block);view=memoryview(block)
            while view:
                tick(deadline);written=os.write(dst,view);need(written>0,'short destination write');view=view[written:]
        need(digest.hexdigest()==ref['sha256'] and identity(os.fstat(src))==before,'source full SHA256/identity mismatch')
        os.fchmod(dst,0o644);os.fsync(dst);copied=identity(os.fstat(dst))
        need(copied['st_size']==ref['bytes'] and stat.S_IMODE(copied['st_mode'])==0o644
             and copied['st_uid']==os.geteuid(),'destination size/mode/owner')
        os.lseek(dst,0,os.SEEK_SET);digest=hashlib.sha256();count=0
        while count<ref['bytes']:
            block=read(dst,min(CHUNK,ref['bytes']-count),budget,deadline,'destination_read_bytes');need(block,'truncated destination')
            count+=len(block);digest.update(block)
        need(digest.hexdigest()==ref['sha256'] and identity(os.fstat(dst))==copied,'destination full SHA256/identity mismatch')
        verify,after_chain=source(row['source_path'])
        try:need(identity(os.fstat(verify))==before==identity(os.fstat(src)) and after_chain==chain,'source absolute path/mode/identity changed')
        finally:os.close(verify)
        verify,unused=source(destination/name)
        try:need(identity(os.fstat(verify))==copied,'destination absolute path association')
        finally:os.close(verify)
        return {'filename':name,'pin':ref,'source_path':row['source_path'],'source_identity_before_after':before,
                'source_parent_identity_before_after':chain,'destination_identity':copied,'mode':0o644,'full_source_and_destination_hash':'PASS'}
    finally:
        if dst is not None:os.close(dst)
        if src is not None:os.close(src)


def stage(rows,destination,budget,deadline):
    """Create a fresh owned0700 directory. On refusal, retain partial DATA/evidence."""
    records=[];result={'status':'HOLD_DATA_COPY_NOT_STARTED','completed':records,'missing_or_refused_sources':[]}
    directory=None;parent_fd=None
    try:
        expected,missing=preflight(rows,deadline);result['missing_or_refused_sources']=missing
        need(not missing,'missing or refused exact retained source paths')
        parent_fd,unused=parent(destination);os.mkdir(destination.name,0o700,dir_fd=parent_fd)
        directory=os.open(destination.name,DIRFLAGS,dir_fd=parent_fd);os.fchmod(directory,0o700)
        root=directory_identity(os.fstat(directory));need(root['st_uid']==os.geteuid() and stat.S_IMODE(root['st_mode'])==0o700,'owned0700 destination')
        for row in rows:
            result['active_filename']=row['filename'];records.append(copy_one(row,directory,destination,expected[row['filename']],budget,deadline))
        need(set(os.listdir(directory))=={r['filename'] for r in rows},'exact destination membership')
        for row in records:
            tick(deadline);need(identity(os.stat(row['filename'],dir_fd=directory,follow_symlinks=False))==row['destination_identity'],'final member identity/mode')
        verify,unused=source(destination/'.')
        try:need(directory_identity(os.fstat(verify))==root,'final absolute destination directory association')
        finally:os.close(verify)
        result.update(status='PASS_COMPLETE_MATERIAL_BYTES_DATA_ONLY',directory_identity=root,active_filename=None)
    except (OSError,Refused,TimeoutError,MemoryError) as error:
        result.update(status='HOLD_PARTIAL_OR_REFUSED_DATA_COPY',reason=type(error).__name__+': '+str(error))
    finally:
        if directory is not None:os.close(directory)
        if parent_fd is not None:os.close(parent_fd)
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination',type=Path,default=Path('/dev/shm/cachy-asahi-arm16k-ui172-materials-DATA-20261115-r1'))
    parser.add_argument('--receipt-dir',type=Path,default=Path('/tmp/cachy-ui172-materialization-DATA-20261115-r1'))
    args=parser.parse_args();destination=args.destination;output=args.receipt_dir
    need(re.fullmatch(r'/dev/shm/cachy-asahi-arm16k-ui172-materials-DATA-[0-9]{8}-r[1-9][0-9]*',str(destination)),'narrow fresh material directory')
    need(re.fullmatch(r'/tmp/cachy-ui172-materialization-DATA-[0-9]{8}-r[1-9][0-9]*',str(output)),'narrow fresh receipt directory')
    resource.setrlimit(resource.RLIMIT_AS,(128*1024**2,128*1024**2));started=time.monotonic();deadline=started+120
    signal.signal(signal.SIGALRM,lambda *_:(_ for _ in ()).throw(Refused('120second DATA watchdog')));signal.alarm(120)
    raw=checked_metadata(HERE/'results/materials-plan.DATA.json',PLAN,1024**2);plan=json.loads(raw);rows,total=validate_plan(plan)
    checked_metadata(HERE/'results/additions-manifest.UNISSUED.json',MANIFEST,4*1024**2)
    output.mkdir(mode=0o700,exist_ok=False)
    budget={'file_bytes':0,'read_bytes':PLAN['bytes']+MANIFEST['bytes'],'metadata_read_bytes':PLAN['bytes']+MANIFEST['bytes'],
            'source_read_bytes':0,'destination_read_bytes':0}
    result=stage(rows,destination,budget,deadline);signal.alarm(0)
    membership={r['filename']:r['pin'] for r in sorted(result['completed'],key=lambda r:r['filename'])}
    body=(json.dumps(membership,indent=2,sort_keys=True)+'\n').encode();(output/'membership.DATA.json').write_bytes(body)
    (output/'file-custody.DATA.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    receipt={'kind':'UI172_RETAINED_MATERIALS_DATA_COPY_RECEIPT_V1','status':result['status'],'destination':str(destination),
        'planned_files':348,'completed_files':len(result['completed']),'planned_file_bytes':total,'budget':budget,
        'limits':{'file_set_bytes':FILE_LIMIT,'read_IO_bytes':READ_LIMIT,'archive_object_bytes':64*1024**2,'signature_keyring_bytes':65536,
                  'template_bytes':1024**2,'wall_seconds':120,'address_space_bytes':128*1024**2},
        'membership':{'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()},'sealed_plan':PLAN,'unissued_manifest_reference':MANIFEST,
        'issued_by':None,'Root_approval':None,'valid_until_utc':None,'public_Source_selector':None,'runtime_authority':None,
        'GPG_network_daemon_lease_preparation_VM_ABI_claims':False,'original_paths_mutated':False,'seconds':round(time.monotonic()-started,3),
        'producer':{'bytes':Path(__file__).stat().st_size,'sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        'missing_or_refused_sources':result['missing_or_refused_sources'],'failure':result.get('reason')}
    (output/'receipt.DATA.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n');print(json.dumps(receipt))
    if result['status']!='PASS_COMPLETE_MATERIAL_BYTES_DATA_ONLY':raise SystemExit(1)


if __name__=='__main__':main()
