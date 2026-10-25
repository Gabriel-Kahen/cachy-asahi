#!/usr/bin/python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Observe ALPM9 metadata via readonly nofollow descriptors; never query pacman."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

QUALIFICATION='OBSERVED_LOCAL_DB_METADATA_NOT_PAYLOAD_OR_HARDWARE_ATTESTATION'
FIELDS={'NAME','VERSION','BASE','DESC','URL','ARCH','BUILDDATE','INSTALLDATE','PACKAGER','SIZE','ISIZE',
        'REASON','VALIDATION','LICENSE','GROUPS','DEPENDS','OPTDEPENDS','PROVIDES','CONFLICTS','REPLACES','XDATA'}
MAX_BYTES=64*1024**2
MAX_RECORD=4*1024**2
MAX_PACKAGES=4096
MAX_INSTALLED_JSON=16*1024**2
_RECORD_CONTROL=re.compile(r'[\x00-\x08\x0b-\x1f\x7f]')
_PATH_CONTROL=re.compile(r'[\x00-\x1f\x7f]')
_SECTION=re.compile(r'%[A-Z][A-Z0-9_]*%')


def need(ok,message):
    if not ok:raise ValueError(message)


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def identity(st):return (st.st_dev,st.st_ino,st.st_mode,st.st_nlink,st.st_uid,st.st_gid,st.st_size,st.st_mtime_ns,st.st_ctime_ns)


def sections(raw,allowed):
    text=raw.decode('utf-8','strict')
    need(not text or text.endswith('\n'),'ALPM record missing terminal LF')
    need(_RECORD_CONTROL.search(text)is None,'ALPM record control character')
    # A canonical file-list block is checked in full by the same C string/regex
    # operations and complete uniqueness set, without a Python call per value.
    # Uncertain headers, separators, duplicates or Unicode line breaks retain
    # the complete original ordered parser below. This is never an I/O cache.
    if (type(allowed)is set and allowed=={'FILES','BACKUP'} and
            text.startswith('%FILES%\n')and text.endswith('\n\n')and
            '\x85'not in text and'\u2028'not in text and'\u2029'not in text):
        blocks=text.split('\n\n')
        if len(blocks)in(2,3)and blocks[-1]=='':
            bulk={}
            for key,block in zip(('FILES','BACKUP'),blocks[:-1]):
                header='%'+key+'%\n'
                if not block.startswith(header):break
                values=block[len(header):]
                if not values or values.startswith(('%','\n'))or values.endswith('\n')or'\n%'in values:break
                values=values.split('\n')
                if len(values)!=len(set(values)):break
                bulk[key]=values
            else:return bulk
    result={};current=None;seen={}
    for line in text.splitlines():
        if not line:current=None
        elif line.startswith('%')and _SECTION.fullmatch(line):
            key=line[1:-1];need(current is None and key in allowed and key not in result,'unknown/duplicate/missing-separator ALPM section')
            result[key]=[];seen[key]=set();current=key
        else:
            need(current is not None and not line.startswith('%'),'malformed ALPM value')
            # Identical relations are idempotent ALPM lists (e.g. native parted).
            if line in seen[current]:
                need(current in {'DEPENDS','PROVIDES','CONFLICTS','REPLACES'},'duplicate ALPM value')
            else:result[current].append(line);seen[current].add(line)
    return result


def relative(value):
    need(type(value) is str and value and len(value)<=512 and
         _PATH_CONTROL.search(value)is None,'unsafe ALPM ownership path')
    directory=value.endswith('/');name=value[:-1] if directory else value
    parts=name.split('/')
    need(''not in parts and'.'not in parts and'..'not in parts,'noncanonical ALPM ownership path')
    return name,directory


def _owned_paths(paths,owners,name):
    # Batch only string predicates within this freshly read record. Invalid or
    # uncertain inputs retain the original ordered path validator below.
    if (paths and all(type(value)is str for value in paths) and
            min(map(len,paths))>0 and max(map(len,paths))<=512 and
            _PATH_CONTROL.search('/'.join(paths))is None):
        names=[value[:-1]if value.endswith('/')else value for value in paths]
        joined='/'+ '/'.join(names)+'/'
        if '//'not in joined and'/./'not in joined and'/../'not in joined:
            files=[value for value in paths if not value.endswith('/')]
            if len(files)==len(set(files)) and owners.keys().isdisjoint(files):
                owners.update(dict.fromkeys(files,name))
                return files
    files=[]
    for value in paths:
        item,is_directory=relative(value)
        if not is_directory:
            need(item not in owners,'duplicate regular file ownership');owners[item]=name;files.append(item)
    return files


def scan(dbpath,c,normalize,deadline):
    root=c.directory(dbpath);nodes={};inputs={};rows=[];spent=0
    def tick():need(time.monotonic()<deadline,'local database observation deadline exceeded')
    def lock():
        try:os.stat('db.lck',dir_fd=root,follow_symlinks=False)
        except FileNotFoundError:return
        raise ValueError('existing or uncertain ALPM db.lck; no stale-lock waiver')
    def names(fd,maximum):
        tick();result=[]
        with os.scandir(fd) as entries:
            for entry in entries:
                result.append(entry.name);need(len(result)<=maximum,'database entry bound exceeded')
        return sorted(result)
    def record(parent,name,path):
        nonlocal spent
        tick();before=os.stat(name,dir_fd=parent,follow_symlinks=False)
        raw=c.read_member(parent,name,MAX_RECORD)
        need(identity(before)==identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),'database record changed or replaced')
        spent+=len(raw);need(spent<=MAX_BYTES,'aggregate database byte bound exceeded')
        nodes[path]=identity(before);inputs[path]=dict(bytes=len(raw),sha256=digest(raw));return raw
    def directory(parent,name,path):
        fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        info=os.fstat(fd)
        if info.st_dev!=os.fstat(root).st_dev:os.close(fd);raise ValueError('database mount crossing refused')
        nodes[path]=identity(info);return fd
    try:
        tick();lock();root_before=identity(os.fstat(root));nodes['.']=root_before
        local=directory(root,'local','local')
        try:
            listing=names(local,MAX_PACKAGES+1);need('ALPM_DB_VERSION' in listing and len(listing)>1,'complete nonempty local ALPM database required')
            need(record(local,'ALPM_DB_VERSION','local/ALPM_DB_VERSION')==b'9\n','unsupported ALPM local database version')
            seen=set();owners={}
            for entry in listing:
                if entry=='ALPM_DB_VERSION':continue
                need(re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+:~-]{0,260}',entry) is not None,'unsafe local package directory')
                path='local/'+entry;package_fd=directory(local,entry,path)
                try:
                    entries=names(package_fd,4);need({'desc','files'}<=set(entries)<= {'desc','files','install','mtree'},'incomplete or unknown local package records')
                    data={n:record(package_fd,n,path+'/'+n) for n in entries}
                    desc=sections(data['desc'],FIELDS)
                    need(all(len(desc.get(k,[]))==1 for k in ('NAME','VERSION','ARCH')),'missing/repeated ALPM identity or architecture')
                    name,version,arch=(desc[k][0] for k in ('NAME','VERSION','ARCH'))
                    need(entry==name+'-'+version and name not in seen and arch in ('aarch64','any'),'duplicate/mismatched/non-ARM local package identity')
                    seen.add(name);raw=data['files'];owned=sections(raw,{'FILES','BACKUP'})
                    # Present zero-byte files is ALPM's exact fileless format.
                    paths=owned.get('FILES',[] if raw==b'' else None)
                    need(type(paths) is list and len(paths)<=32768,'missing/oversized ALPM file ownership')
                    files=_owned_paths(paths,owners,name)
                    for backup in owned.get('BACKUP',[]):
                        pieces=backup.split('\t');need(len(pieces)==2 and re.fullmatch('[0-9a-f]{32}',pieces[1]),'malformed ALPM backup')
                        item,is_directory=relative(pieces[0]);need(not is_directory and item in files,'backup absent from file ownership')
                    row=dict(name=name,version=version,arch=arch,files=files)
                    for section,field in (('DEPENDS','depend'),('PROVIDES','provides'),('CONFLICTS','conflict'),('REPLACES','replaces')):
                        row[field]=desc.get(section,[])
                    rows.append(normalize(row))
                    need(nodes[path]==identity(os.fstat(package_fd))==identity(os.stat(entry,dir_fd=local,follow_symlinks=False)) and
                         entries==names(package_fd,4),'local package directory drift')
                finally:os.close(package_fd)
            # owners is complete and immutable here; memoize only already
            # checked prefixes in THIS scan, never observations across scans.
            checked_ancestors=set()
            for path in owners:
                parent=path.rpartition('/')[0]
                while parent and parent not in checked_ancestors:
                    need(parent not in owners,'regular file/ancestor ownership conflict')
                    checked_ancestors.add(parent);parent=parent.rpartition('/')[0]
            need('.' not in owners,'regular file/ancestor ownership conflict')
            need(nodes['local']==identity(os.fstat(local))==identity(os.stat('local',dir_fd=root,follow_symlinks=False)) and
                 listing==names(local,MAX_PACKAGES+1),'local database directory drift')
        finally:os.close(local)
        lock();need(root_before==identity(os.fstat(root)),'ALPM database root changed during observation')
        reopened=c.directory(dbpath)
        try:need(root_before==identity(os.fstat(reopened)),'database root path substituted')
        finally:os.close(reopened)
        tick();return sorted(rows,key=lambda v:v['name']),inputs,nodes
    finally:os.close(root)


def _collect_encoded(dbpath,c,normalize):
    dbpath=Path(dbpath).absolute();deadline=time.monotonic()+30
    first=scan(dbpath,c,normalize,deadline);second=scan(dbpath,c,normalize,deadline)
    need(first==second,'local database drift between two complete readonly observations')
    rows,inputs,_=second;raw_sha=digest(encoded(inputs))
    observation=dict(qualification=QUALIFICATION,dbpath=str(dbpath),format='ALPM_LOCAL_DB_9',inputs=inputs,
        database_sha256=raw_sha,packages_metadata_sha256=digest(encoded(rows)),payload_verified=False,hardware_verified=False,
        consistency='TWO_MATCHING_READS_NO_LOCK_NO_DETECTED_DRIFT')
    result=dict(schema_version=1,kind='complete-installed-inventory',target_arch='aarch64',snapshot_id='alpm-local-db-'+raw_sha,
                packages=rows,observation=observation)
    raw=encoded(result)
    need(len(raw)<=MAX_INSTALLED_JSON,'inventory exceeds installed input byte bound')
    return result,raw


def collect(dbpath,c,normalize):
    return _collect_encoded(dbpath,c,normalize)[0]


def validate(value,normalize):
    observation=value['observation']
    need(type(observation) is dict and set(observation)=={'qualification','dbpath','format','inputs','database_sha256',
        'packages_metadata_sha256','payload_verified','hardware_verified','consistency'} and
        observation['qualification']==QUALIFICATION and observation['format']=='ALPM_LOCAL_DB_9' and
        observation['payload_verified'] is False and observation['hardware_verified'] is False and
        observation['consistency']=='TWO_MATCHING_READS_NO_LOCK_NO_DETECTED_DRIFT','unsupported inventory observation qualifier')
    need(type(observation['dbpath']) is str and Path(observation['dbpath']).is_absolute() and '..' not in Path(observation['dbpath']).parts,'invalid observed database source pointer')
    inputs=observation['inputs'];need(type(inputs) is dict and 3<=len(inputs)<=MAX_PACKAGES*4+1,'bounded raw metadata hash map required')
    for path,row in inputs.items():
        need(path.startswith('local/') and relative(path)[0]==path and type(row) is dict and set(row)=={'bytes','sha256'} and
            type(row['bytes']) is int and 0<=row['bytes']<=MAX_RECORD and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
            'invalid raw metadata input reference')
    need(sum(v['bytes'] for v in inputs.values())<=MAX_BYTES and digest(encoded(inputs))==observation['database_sha256'] and
         value['snapshot_id']=='alpm-local-db-'+observation['database_sha256'],'raw metadata snapshot hash mismatch')
    rows=[normalize(row) for row in value['packages']]
    need(rows==value['packages'] and not any('sha256' in row for row in value['packages']) and
         digest(encoded(rows))==observation['packages_metadata_sha256'],'observed package metadata hash mismatch')
    allowed={'local/ALPM_DB_VERSION'}|{'local/'+row['name']+'-'+row['version']+'/'+kind for row in rows for kind in ('desc','files','install','mtree')}
    need(set(inputs)<=allowed and inputs.get('local/ALPM_DB_VERSION')==dict(bytes=2,sha256=digest(b'9\n')),'unexpected observation input records')
    need('local/ALPM_DB_VERSION' in inputs and
         all('local/'+row['name']+'-'+row['version']+'/'+kind in inputs for row in rows for kind in ('desc','files')),
         'observed snapshot lacks exact package inputs')
    return QUALIFICATION


def publish(dbpath,output,c,normalize):
    dbpath=Path(dbpath).absolute();output=Path(output).absolute()
    need(not output.is_relative_to(dbpath),'inventory output must be outside the observed database')
    parent=c.directory(output.parent)
    try:
        info=os.fstat(parent);need(info.st_uid==os.geteuid() and not stat.S_IMODE(info.st_mode)&0o022,'ordinary caller-owned output parent required')
        try:os.stat(output.name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise ValueError('fresh inventory output required')
        value,raw=_collect_encoded(dbpath,c,normalize)
        reopened=c.directory(output.parent)
        try:need(identity(os.fstat(parent))==identity(os.fstat(reopened)),'inventory output parent changed')
        finally:os.close(reopened)
        fd=os.open(output.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        try:
            identity_created=(os.fstat(fd).st_dev,os.fstat(fd).st_ino)
            try:
                os.fchmod(fd,0o600)
                with os.fdopen(os.dup(fd),'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
                need(os.fstat(fd).st_nlink==1 and stat.S_IMODE(os.fstat(fd).st_mode)==0o600,'inventory output identity/mode changed')
                published=os.stat(output.name,dir_fd=parent,follow_symlinks=False)
                need((published.st_dev,published.st_ino)==identity_created and published.st_nlink==1,'inventory output substituted')
                os.fsync(parent)
            except BaseException:
                current=os.stat(output.name,dir_fd=parent,follow_symlinks=False)
                if (current.st_dev,current.st_ino)==identity_created:os.unlink(output.name,dir_fd=parent)
                raise
        finally:os.close(fd)
        return dict(status='OBSERVED_LOCAL_DB_METADATA',applied='NOT_APPLIED',qualification=QUALIFICATION,
            output=str(output),sha256=digest(raw),bytes=len(raw),package_count=len(value['packages']),database_sha256=value['observation']['database_sha256'])
    finally:os.close(parent)

# BEGIN_APPS10_OPTIONAL_STAGE_DIAGNOSTIC
# The full Apps13 inverse retains every original observation/publication check.
PHASES=('START','SCAN_FIRST','SCAN_SECOND','COMPARE_READS','ENCODE_INPUTS','ENCODE_ROWS','ENCODE_RESULT_BOUND','ENCODE_PUBLICATION','REOPEN_OUTPUT_PARENT','OPEN_OUTPUT','WRITE_OUTPUT','FSYNC_OUTPUT','VERIFY_OUTPUT','FSYNC_PARENT','DONE')
class _Stage:
    def __init__(self,parent,name):
        self.parent,self.name,self.started,self.sequence,self.phase=parent,name,time.monotonic(),-1,None
        self.previous=b''
        self.fd=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        try:
            os.fchmod(self.fd,0o600);s=os.fstat(self.fd);self.inode=(s.st_dev,s.st_ino);self('START')
        except BaseException:os.close(self.fd);raise
    def check(self):
        a=os.fstat(self.fd);b=os.stat(self.name,dir_fd=self.parent,follow_symlinks=False)
        for s in(a,b):need(stat.S_ISREG(s.st_mode)and(s.st_dev,s.st_ino)==self.inode and s.st_nlink==1 and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o600 and 0<=s.st_size<=1024,'diagnostic stage identity/mode/link changed')
        need(os.pread(self.fd,1025,0)==self.previous,'diagnostic stage content changed')
    def write(self,status,error_type=None):
        self.check();value=dict(schema=1,status=status,phase=self.phase,sequence=self.sequence,elapsed_seconds=time.monotonic()-self.started,authority='DIAGNOSTIC_ONLY_NOT_ACCEPTANCE')
        if error_type is not None:value['error_type']=error_type
        raw=encoded(value);need(len(raw)<=1024,'finite stage JSON bound');os.lseek(self.fd,0,os.SEEK_SET);view=memoryview(raw)
        while view:
            count=os.write(self.fd,view);need(count>0,'diagnostic stage short write');view=view[count:]
        os.ftruncate(self.fd,len(raw));self.previous=raw;self.check()
    def __call__(self,phase):
        need(phase in PHASES and PHASES.index(phase)==self.sequence+1,'finite ordered inventory diagnostic phase')
        self.phase=phase;self.sequence+=1;self.write('DONE'if phase=='DONE'else'RUNNING')
    def failed(self,error):
        name=type(error).__name__;allowed={'ValueError','OSError','FileNotFoundError','FileExistsError','PermissionError','Refusal','Error','KeyboardInterrupt','SystemExit'}
        self.write('FAILED',name if name in allowed else'OTHER')
    def close(self):os.close(self.fd)

def _collect_diagnostic_encoded(dbpath,c,normalize,stage):
    dbpath=Path(dbpath).absolute();deadline=time.monotonic()+30
    stage('SCAN_FIRST');first=scan(dbpath,c,normalize,deadline)
    stage('SCAN_SECOND');second=scan(dbpath,c,normalize,deadline)
    stage('COMPARE_READS')
    need(first==second,'local database drift between two complete readonly observations')
    rows,inputs,_=second;stage('ENCODE_INPUTS');raw_sha=digest(encoded(inputs))
    stage('ENCODE_ROWS')
    observation=dict(qualification=QUALIFICATION,dbpath=str(dbpath),format='ALPM_LOCAL_DB_9',inputs=inputs,
        database_sha256=raw_sha,packages_metadata_sha256=digest(encoded(rows)),payload_verified=False,hardware_verified=False,
        consistency='TWO_MATCHING_READS_NO_LOCK_NO_DETECTED_DRIFT')
    result=dict(schema_version=1,kind='complete-installed-inventory',target_arch='aarch64',snapshot_id='alpm-local-db-'+raw_sha,
                packages=rows,observation=observation)
    stage('ENCODE_RESULT_BOUND')
    raw=encoded(result)
    need(len(raw)<=MAX_INSTALLED_JSON,'inventory exceeds installed input byte bound')
    return result,raw

def _collect_diagnostic(dbpath,c,normalize,stage):
    return _collect_diagnostic_encoded(dbpath,c,normalize,stage)[0]

def _publish_diagnostic(dbpath,output,c,normalize,stage):
    dbpath=Path(dbpath).absolute();output=Path(output).absolute()
    need(not output.is_relative_to(dbpath),'inventory output must be outside the observed database')
    parent=c.directory(output.parent)
    try:
        info=os.fstat(parent);need(info.st_uid==os.geteuid() and not stat.S_IMODE(info.st_mode)&0o022,'ordinary caller-owned output parent required')
        try:os.stat(output.name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise ValueError('fresh inventory output required')
        value,raw=_collect_diagnostic_encoded(dbpath,c,normalize,stage);stage('ENCODE_PUBLICATION')
        stage('REOPEN_OUTPUT_PARENT')
        reopened=c.directory(output.parent)
        try:need(identity(os.fstat(parent))==identity(os.fstat(reopened)),'inventory output parent changed')
        finally:os.close(reopened)
        stage('OPEN_OUTPUT')
        fd=os.open(output.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent)
        try:
            identity_created=(os.fstat(fd).st_dev,os.fstat(fd).st_ino)
            try:
                os.fchmod(fd,0o600)
                with os.fdopen(os.dup(fd),'wb') as stream:
                    stage('WRITE_OUTPUT');stream.write(raw);stream.flush()
                    stage('FSYNC_OUTPUT');os.fsync(stream.fileno())
                stage('VERIFY_OUTPUT')
                need(os.fstat(fd).st_nlink==1 and stat.S_IMODE(os.fstat(fd).st_mode)==0o600,'inventory output identity/mode changed')
                published=os.stat(output.name,dir_fd=parent,follow_symlinks=False)
                need((published.st_dev,published.st_ino)==identity_created and published.st_nlink==1,'inventory output substituted')
                stage('FSYNC_PARENT');os.fsync(parent)
            except BaseException:
                current=os.stat(output.name,dir_fd=parent,follow_symlinks=False)
                if (current.st_dev,current.st_ino)==identity_created:os.unlink(output.name,dir_fd=parent)
                raise
        finally:os.close(fd)
        return dict(status='OBSERVED_LOCAL_DB_METADATA',applied='NOT_APPLIED',qualification=QUALIFICATION,
            output=str(output),sha256=digest(raw),bytes=len(raw),package_count=len(value['packages']),database_sha256=value['observation']['database_sha256'])
    finally:os.close(parent)

def publish_diagnostic(dbpath,output,c,normalize):
    """Opt-in fixed sibling stage file; normal publish/result are unchanged."""
    dbpath,output=Path(dbpath).absolute(),Path(output).absolute()
    need(not output.is_relative_to(dbpath),'inventory output must be outside the observed database')
    parent=c.directory(output.parent);stage=None
    try:
        s=os.fstat(parent);need(s.st_uid==os.geteuid()and not stat.S_IMODE(s.st_mode)&0o022,'ordinary caller-owned output parent required')
        try:os.stat(output.name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:pass
        else:raise ValueError('fresh inventory output required')
        stage=_Stage(parent,output.name+'.stage.json')
        try:
            result=_publish_diagnostic(dbpath,output,c,normalize,stage);stage('DONE');return result
        except BaseException as error:
            try:stage.failed(error)
            except Exception:pass # Keep the original refusal/interruption exact.
            raise
    finally:
        if stage is not None:stage.close()
        os.close(parent)
