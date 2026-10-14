# SPDX-License-Identifier: MIT
"""Local owned passive-result files only. No transport or admission API."""
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import time

CANDIDATE='SIGNER_PASSIVE_ADOPTION_CANDIDATE='
FINAL='SIGNER_PASSIVE_ADOPTION_FINAL='
MAX_RAW=4*1024**2
NAMES=('records.ndjson','candidate.json','final.json','completion.json')


class Refused(ValueError):pass
class Deadline(Refused):pass


def need(value,code):
    if not value:raise Refused(code)


def identity(row):
    return (row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink)


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def parse(raw,bound):
    need(type(raw) is bytes and 0<len(raw)<=bound,'retention-byte-bound')
    def unique(pairs):
        value={}
        for key,item in pairs:
            need(key not in value,'duplicate-JSON-field');value[key]=item
        return value
    value=json.loads(raw.decode('utf-8'),object_pairs_hook=unique,
                     parse_constant=lambda _:(_ for _ in ()).throw(Refused('nonfinite-JSON')))
    need(type(value) is dict and canonical(value)==raw,'canonical-JSON-required')
    return value


def descriptor(raw):
    return dict(bytes=len(raw),mode=0o600,sha256=hashlib.sha256(raw).hexdigest())


class NativeIO:
    """Deferred local syscalls; no native constructor side effects."""
    now=staticmethod(time.monotonic)
    uid=staticmethod(os.getuid)
    gid=staticmethod(os.getgid)
    euid=staticmethod(os.geteuid)
    egid=staticmethod(os.getegid)
    fstat=staticmethod(os.fstat)
    close=staticmethod(os.close)
    write=staticmethod(os.write)
    pread=staticmethod(os.pread)
    def parent(self,path):
        return os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    def mkdir(self,fd,name):os.mkdir(name,0o700,dir_fd=fd)
    def directory(self,fd,name):
        return os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
    def file(self,fd,name):
        result=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=fd)
        return result
    def named(self,fd,name):return os.stat(name,dir_fd=fd,follow_symlinks=False)


class Retention:
    """One fresh RUNNER_TEMP child; caller owns the trusted parent namespace.

    The fixed endpoint includes creation, writes, readback and all FD closes.
    Partials remain for failed-job transport; this object never removes paths.
    """
    def __init__(self,directory,*,endpoint,io=None,owner_uid=None,owner_gid=None):
        self.io=io if io is not None else NativeIO()
        self.endpoint=endpoint
        self.path=Path(directory)
        self._last=None;self._first=None;self.uncertain=False;self.cancelled=False
        self._handles={};self._parent=self._directory=None
        self._parent_identity=self._directory_identity=None
        self.used=False
        need(type(endpoint) in (int,float) and math.isfinite(endpoint) and endpoint>0,'original-endpoint')
        need(self.path.is_absolute() and '..' not in self.path.parts and re.fullmatch(
            r'signer-native-passive-([1-9][0-9]{0,19})-([1-9][0-9]{0,9})',self.path.name),'fixed-artifact-path')
        uid,gid=self.io.uid(),self.io.gid()
        self.uid=uid if owner_uid is None else owner_uid
        self.gid=gid if owner_gid is None else owner_gid
        need(type(self.uid) is int and type(self.gid) is int and self.uid==uid==self.io.euid()>0
             and self.gid==gid==self.io.egid()>0,'observer-file-owner')
        try:
            self._live()
            self._parent=self.io.parent(str(self.path.parent))
            self._handles[self._parent]=None
            row=self.io.fstat(self._parent);self._parent_identity=identity(row)
            self._handles[self._parent]=self._parent_identity
            need(stat.S_ISDIR(row.st_mode),'trusted-parent-directory')
            self._live();self.io.mkdir(self._parent,self.path.name);self._live()
            # Our new child may change the parent's link count. Bind the same
            # held parent object before adopting that permitted own effect.
            updated=identity(self.io.fstat(self._parent))
            need(updated[:5]==self._parent_identity[:5] and updated[5]>0,'parent-create-identity')
            self._parent_identity=updated
            self._handles[self._parent]=updated
            self._live()
            row=self.io.named(self._parent,self.path.name)
            self._directory_identity=identity(row)
            self._directory=self.io.directory(self._parent,self.path.name)
            self._handles[self._directory]=None
            opened=self.io.fstat(self._directory)
            self._handles[self._directory]=identity(opened)
            need(identity(opened)==self._directory_identity and stat.S_ISDIR(opened.st_mode)
                 and opened.st_uid==self.uid and opened.st_gid==self.gid
                 and stat.S_IMODE(opened.st_mode)==0o700,'fresh-owned-artifact-directory')
            self._live()
        except BaseException as error:
            self._remember(error);self._close_all();raise self._first

    def _remember(self,error):
        if self._first is None:self._first=error
        self.cancelled |= isinstance(error,KeyboardInterrupt)

    def _live(self):
        now=self.io.now()
        need(type(now) in (int,float) and math.isfinite(now) and now>=0
             and (self._last is None or now>=self._last),'retention-clock-domain')
        self._last=now
        if now>=self.endpoint:raise Deadline('retention-original-deadline')

    def _guard_directory(self):
        self._live()
        need(identity(self.io.fstat(self._parent))==self._parent_identity and
             identity(self.io.fstat(self._directory))==self._directory_identity and
             identity(self.io.named(self._parent,self.path.name))==self._directory_identity,
             'artifact-directory-drift')
        self._live()

    def _guard_file(self,fd,name,expected):
        self._guard_directory()
        row=self.io.fstat(fd)
        need(identity(row)==expected==identity(self.io.named(self._directory,name)) and
             stat.S_ISREG(row.st_mode) and row.st_uid==self.uid and row.st_gid==self.gid
             and row.st_nlink==1 and stat.S_IMODE(row.st_mode)==0o600,'owned-artifact-file')
        self._live()
        return row

    def _write(self,name,raw):
        self._guard_directory()
        fd=self.io.file(self._directory,name)
        self._handles[fd]=None
        row=self.io.fstat(fd);expected=identity(row)
        self._handles[fd]=expected
        need(row.st_size==0,'fresh-artifact-file')
        self._guard_file(fd,name,expected)
        position=0
        while position<len(raw):
            self._guard_file(fd,name,expected)
            value=self.io.write(fd,raw[position:position+65536])
            need(type(value) is int and 0<value<=min(65536,len(raw)-position),'artifact-write-progress')
            position+=value
            self._live()
        before=self._guard_file(fd,name,expected)
        need(before.st_size==len(raw),'artifact-final-size')
        observed=bytearray()
        while len(observed)<len(raw):
            self._guard_file(fd,name,expected)
            part=self.io.pread(fd,min(65536,len(raw)-len(observed)),len(observed))
            need(type(part) is bytes and 0<len(part)<=min(65536,len(raw)-len(observed)),'artifact-readback-progress')
            observed.extend(part);self._live()
        need(self.io.pread(fd,1,len(raw))==b'' and bytes(observed)==raw,'artifact-readback-bytes')
        after=self._guard_file(fd,name,expected)
        need(before.st_size==after.st_size and before.st_mtime_ns==after.st_mtime_ns
             and before.st_ctime_ns==after.st_ctime_ns,'artifact-readback-drift')
        self._live()
        return descriptor(raw)

    def _close_all(self):
        # Close only once. A refused/uncertain numeric FD is never retried.
        for fd,expected in reversed(tuple(self._handles.items())):
            del self._handles[fd]
            try:
                need(identity(self.io.fstat(fd))==expected,'original-retention-close-FD')
                self.io.close(fd)
                self._live()
            except BaseException as error:
                self.uncertain=True;self._remember(error)

    def publish(self,candidate_raw,final_raw,completion_metadata,*,endpoint):
        need(not self.used and self._first is None and type(endpoint) is type(self.endpoint)
             and endpoint==self.endpoint,'single-original-retention-endpoint')
        self.used=True;descriptors={}
        try:
            self._live()
            raw=parse(candidate_raw,MAX_RAW);final=parse(final_raw,4096)
            need(set(raw)=={'schema_version','purpose','source_pins','configuration','context','observation',
                'provenance','entry','deadline_at','selected','execution_grant_issued','compile_allowed'} and
                type(raw['schema_version']) is int and raw['schema_version']==1 and
                raw['purpose']=='SIGNER_NATIVE_PASSIVE_ADOPTION_V1' and type(raw['observation']) is dict
                and set(raw['observation'])=={'candidate','evidence'},'passive-result-shape')
            candidate,evidence=raw['observation']['candidate'],raw['observation']['evidence']
            need(type(candidate) is dict and type(evidence) is dict,'observation-shape')
            need(candidate.get('selected') is False and candidate.get('execution_grant_issued') is False
                 and evidence.get('executed_tools') is False and evidence.get('loaded_libraries') is False
                 and evidence.get('compile_allowed') is False and all(raw[k] is False for k in
                 ('selected','execution_grant_issued','compile_allowed')),'observation-only-files')
            need(set(final)=={'schema_version','purpose','status','candidate_sha256','context','entry',
                 'deadline_at','ended','selected','execution_grant_issued','compile_allowed'} and
                 type(final['schema_version']) is int and final['schema_version']==1 and
                 final['purpose']==raw['purpose'] and
                 final['status']=='OBSERVED_COMPLETE_NOT_SELECTED' and final['deadline_at']==endpoint and
                 final['candidate_sha256']==hashlib.sha256(candidate_raw).hexdigest() and
                 all(final[k] is False for k in ('selected','execution_grant_issued','compile_allowed')),
                 'terminal-observation-shape')
            need(type(completion_metadata) is dict and set(completion_metadata)=={'schema_version','purpose',
                 'status','context','source_packet_sha256','configuration_sha256','public_issuer_sha256',
                 'entry','deadline_at','observer_returncode','selected','execution_grant_issued','compile_allowed'},
                 'completion-metadata-shape')
            meta=parse(canonical(completion_metadata),16384)
            need(type(meta['schema_version']) is int and meta['schema_version']==1 and
                 meta['purpose']==raw['purpose'] and meta['status']=='RETAINED_COMPLETE_NOT_SELECTED' and
                 type(meta['observer_returncode']) is int and meta['observer_returncode']==0 and
                 all(meta[k] is False for k in ('selected','execution_grant_issued','compile_allowed')),
                 'completion-intended-observation-only')
            need(type(meta['entry']) in (int,float) and 0<meta['entry'] and meta['entry']+60==endpoint and
                 meta['entry']==raw['entry']==final['entry'] and meta['deadline_at']==raw['deadline_at']==endpoint
                 and evidence.get('deadline_at')==endpoint and
                 type(final['ended']) in (int,float) and meta['entry']<=final['ended']<endpoint,
                 'original-retention-frame')
            context=completion_metadata['context']
            need(type(context) is dict and context==raw['context']==final['context']==evidence.get('context') and
                 set(context)=={'source_commit','workflow_commit','run_id','run_attempt','machine','uid'} and
                 context['machine']=='aarch64' and type(context['uid']) is int and context['uid']==self.uid and
                 type(context['run_id']) is str and type(context['run_attempt']) is str and
                 type(context['source_commit']) is str and re.fullmatch('[0-9a-f]{40}',context['source_commit']) and
                 context['workflow_commit']==context['source_commit'] and
                 self.path.name=='signer-native-passive-'+context['run_id']+'-'+context['run_attempt'],
                 'retained-job-context')
            need(type(raw['source_pins']) is dict and 1<=len(raw['source_pins'])<=16,'Source-packet-shape')
            for row in raw['source_pins'].values():
                need(type(row) is dict and set(row)=={'bytes','mode','sha256'} and
                     type(row['bytes']) is int and 0<row['bytes']<=1024**2 and row['mode']==0o644
                     and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
                     'retained-Source-descriptor')
            need(meta['source_packet_sha256']==hashlib.sha256(canonical(raw['source_pins'])).hexdigest() and
                 meta['configuration_sha256']==hashlib.sha256(canonical(raw['configuration'])).hexdigest() and
                 type(meta['public_issuer_sha256']) is str and re.fullmatch('[0-9a-f]{64}',meta['public_issuer_sha256']),
                 'Root-rendered-packet-configuration')
            records=(CANDIDATE+base64.b64encode(candidate_raw).decode()+'\n'+FINAL+final_raw.decode()+'\n').encode()
            need(len(records)<=6*1024**2,'retention-record-budget');self._live()
            for name,body in (('records.ndjson',records),('candidate.json',candidate_raw),('final.json',final_raw)):
                descriptors[name]=self._write(name,body)
            self._live()
            completion=dict(meta,records_sha256=descriptors['records.ndjson']['sha256'],
                candidate_sha256=descriptors['candidate.json']['sha256'],
                final_sha256=descriptors['final.json']['sha256'],ended=self.io.now())
            need(meta['entry']<=completion['ended']<endpoint,'completion-original-end')
            completion_raw=canonical(completion)
            need(len(completion_raw)<=32768,'completion-file-budget')
            descriptors['completion.json']=self._write('completion.json',completion_raw)
        except BaseException as error:self._remember(error)
        finally:self._close_all()
        if self._first is not None:raise self._first
        self._live()
        return descriptors

    def publish_failure(self,failure_raw,*,endpoint):
        """Retain one bounded refusal record, never a candidate or natural exit proof."""
        need(not self.used and self._first is None,'single-unused-failure-retention')
        self.used=True;descriptors={}
        try:
            need(type(endpoint) is type(self.endpoint) and endpoint==self.endpoint,
                 'single-original-retention-endpoint')
            self._live()
            value=parse(failure_raw,16384)
            need(set(value)=={'schema_version','purpose','status','candidate_valid','first_phase',
                 'first_cause','first_reason','first_errno','cancelled','context','source_packet_sha256',
                 'configuration_sha256','public_issuer_sha256','entry','deadline_at','progress',
                 'observer_returncode','selected','execution_grant_issued','compile_allowed'},
                 'failure-record-shape')
            need(type(value['schema_version']) is int and value['schema_version']==1 and
                 value['purpose']=='SIGNER_NATIVE_PASSIVE_FAILURE_V1' and value['status']=='FAIL' and
                 type(value['observer_returncode']) is int and value['observer_returncode']==1 and
                 all(value[k] is False for k in ('candidate_valid','selected','execution_grant_issued',
                                                'compile_allowed')) and type(value['cancelled']) is bool,
                 'failure-only-intended-return')
            need(type(value['first_phase']) is str and re.fullmatch('[A-Za-z0-9_.:-]{1,80}',value['first_phase'])
                 and type(value['first_cause']) is str and re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,79}',value['first_cause'])
                 and (value['first_reason'] is None or type(value['first_reason']) is str and
                      re.fullmatch('[A-Za-z0-9_.:-]{1,160}',value['first_reason']))
                 and (value['first_errno'] is None or type(value['first_errno']) is int and
                      1<=value['first_errno']<=4095),'bounded-failure-cause')
            for name in ('source_packet_sha256','configuration_sha256','public_issuer_sha256'):
                need(type(value[name]) is str and re.fullmatch('[0-9a-f]{64}',value[name]),
                     'failure-Source-binding')
            need(type(value['entry']) in (int,float) and math.isfinite(value['entry']) and
                 value['entry']>0 and value['entry']+60==endpoint and
                 type(value['deadline_at']) in (int,float) and value['deadline_at']==endpoint,
                 'original-failure-frame')
            context=value['context']
            need(type(context) is dict and set(context)=={'source_commit','workflow_commit','run_id',
                 'run_attempt','machine','uid'} and context['machine']=='aarch64' and
                 type(context['uid']) is int and context['uid']==self.uid and
                 type(context['run_id']) is str and type(context['run_attempt']) is str and
                 type(context['source_commit']) is str and re.fullmatch('[0-9a-f]{40}',context['source_commit'])
                 and context['workflow_commit']==context['source_commit'] and
                 self.path.name=='signer-native-passive-'+context['run_id']+'-'+context['run_attempt'],
                 'retained-failure-job-context')
            progress=value['progress']
            need(type(progress) is dict and set(progress)=={'operation','path','completed_samples',
                 'completed_inventories','nodes','bytes_read'} and
                 progress['operation'] in (None,'sample','inventory','charge'), 'failure-progress-shape')
            path=progress['path']
            need(path is None or type(path) is str and 0<len(path)<=1024 and '\x00' not in path and
                 Path(path).is_absolute() and str(Path(path))==path and '..' not in Path(path).parts,
                 'failure-progress-path')
            for name in ('completed_samples','completed_inventories'):
                need(type(progress[name]) is int and 0<=progress[name]<=65536,'failure-progress-count')
            for name,bound in (('nodes',65536),('bytes_read',512*1024**2)):
                need(progress[name] is None or type(progress[name]) is int and
                     0<=progress[name]<=bound,'failure-progress-bound')
            self._live()
            descriptors['failure.json']=self._write('failure.json',failure_raw)
        except BaseException as error:self._remember(error)
        finally:self._close_all()
        if self._first is not None:raise self._first
        self._live()
        return descriptors
