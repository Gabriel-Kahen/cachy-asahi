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
import struct
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


def validate_elf_diagnostic(value):
    """Closed unaccepted same-sample facts; never a candidate or execution proof."""
    if value is None:return None
    keys={'schema_version','purpose','request_path','canonical','row','identity','header_hex','header',
          'phdr_count','phdrs_scanned','phdrs_truncated','phdr_bounds_ok','segments','dynamic'}
    need(type(value) is dict and set(value)==keys and type(value['schema_version']) is int
         and value['schema_version']==1 and value['purpose']=='SIGNER_PASSIVE_ELF_DIAGNOSTIC_V1',
         'closed-elf-diagnostic')
    def uint(number,bits=64):return type(number) is int and 0<=number<2**bits
    def closed_path(name):
        need(type(name) is str and 0<len(name)<=1024 and str(Path(name))==name and
             Path(name).is_absolute() and len(Path(name).parts)<=32 and '..' not in Path(name).parts
             and all(32<=ord(c)<127 for c in name) and (name in ('/','/usr') or
             any(name==root or name.startswith(root+'/') for root in
                 ('/usr/bin','/usr/lib','/usr/libexec','/usr/include','/lib'))),'elf-diagnostic-path')
    closed_path(value['request_path']);closed_path(value['canonical'])
    row=value['row'];ident=value['identity']
    need(type(row) is dict and set(row)=={'bytes','mode','sha256'} and uint(row['bytes']) and
         0<row['bytes']<=64*1024**2 and type(row['mode']) is int and row['mode'] in (0o644,0o755)
         and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),
         'elf-diagnostic-row')
    need(type(ident) is list and len(ident)==9 and all(uint(n) for n in ident) and
         ident[2]==stat.S_IFREG|row['mode'] and ident[3]==ident[4]==0 and ident[5]==1
         and ident[6]==row['bytes'],'elf-diagnostic-identity')
    raw=value['header_hex'];header=value['header'];count=value['phdr_count'];scanned=value['phdrs_scanned']
    segments=value['segments'];dynamic=value['dynamic']
    need(raw is None or type(raw) is str and re.fullmatch('[0-9a-f]{8,128}',raw) and
         len(raw)==2*min(row['bytes'],64) and raw.startswith('7f454c46'),'elf-diagnostic-header-hex')
    need(count is None or uint(count,16),'elf-diagnostic-phdr-count')
    need(uint(scanned) and scanned<=128 and type(value['phdrs_truncated']) is bool and
         (value['phdr_bounds_ok'] is None or type(value['phdr_bounds_ok']) is bool) and
         type(segments) is list and len(segments)<=16,'elf-diagnostic-phdr-bounds')
    header_widths={'e_type':16,'e_machine':16,'e_version':32,'e_entry':64,'e_phoff':64,'e_shoff':64,
                   'e_flags':32,'e_ehsize':16,'e_phentsize':16,'e_phnum':16,'e_shentsize':16,
                   'e_shnum':16,'e_shstrndx':16}
    if header is None:
        need(count is None and scanned==0 and segments==[] and dynamic is None and
             value['phdr_bounds_ok'] is None and value['phdrs_truncated'] is False,
             'elf-diagnostic-unavailable-header')
        need(raw is None or len(raw)<128 or not raw.startswith('7f454c460201'),
             'elf-diagnostic-missing-decodable-header')
    else:
        need(type(header) is dict and set(header)==set(header_widths) and
             all(uint(header[k],width) for k,width in header_widths.items()) and
             type(raw) is str and len(raw)==128 and raw.startswith('7f454c460201') and
             dict(zip(header_widths,struct.unpack_from('<HHIQQQIHHHHHH',bytes.fromhex(raw),16)))==header
             and count==header['e_phnum'],'elf-diagnostic-decoded-header')
        if header['e_phentsize']!=56:
            need(scanned==0 and segments==[] and dynamic is None and value['phdr_bounds_ok'] is None
                 and value['phdrs_truncated']==(count>0),'elf-diagnostic-unscanned-phdrs')
        else:
            available=max(0,(row['bytes']-header['e_phoff'])//56)
            need(scanned==min(count,128,available) and len(segments)<=scanned and
                 value['phdr_bounds_ok']==(header['e_phoff']+count*56<=row['bytes']) and
                 value['phdrs_truncated']==(count!=len(segments)),'elf-diagnostic-phdr-accounting')
    segment_keys={'index','p_type','p_flags','p_offset','p_vaddr','p_paddr','p_filesz','p_memsz','p_align'}
    for index,segment in enumerate(segments):
        need(type(segment) is dict and set(segment)==segment_keys and segment['index']==index and
             uint(segment['index']) and index<scanned and all(uint(segment[k],32 if k in
             ('p_type','p_flags') else 64) for k in segment_keys-{'index'}),'elf-diagnostic-segment')
    if dynamic is not None:
        keys={'segment_count','bytes','tags_scanned','terminated','needed_count','strtab_address',
              'strtab_bytes','strtab_count','strsz_count','load_match_count','truncated','bounds_ok',
              'search_override'}
        need(type(dynamic) is dict and set(dynamic)==keys and uint(dynamic['segment_count']) and
             0<dynamic['segment_count']<=scanned and type(dynamic['truncated']) is bool and
             type(dynamic['search_override']) is bool,'elf-diagnostic-dynamic-shape')
        for name in ('bytes','strtab_address','strtab_bytes'):
            need(dynamic[name] is None or uint(dynamic[name]),'elf-diagnostic-dynamic-uint')
        for name in ('terminated','bounds_ok'):
            need(dynamic[name] is None or type(dynamic[name]) is bool,'elf-diagnostic-dynamic-flag')
        for name in ('tags_scanned','needed_count','strtab_count','strsz_count'):
            need(uint(dynamic[name]) and dynamic[name]<=4096,'elf-diagnostic-dynamic-count')
        need(dynamic['needed_count']+dynamic['strtab_count']+dynamic['strsz_count']<=dynamic['tags_scanned']
             and (dynamic['terminated'] is not True or dynamic['tags_scanned']>0) and
             (dynamic['search_override'] is False or dynamic['tags_scanned']>0) and
             (dynamic['strtab_address'] is None)==(dynamic['strtab_count']==0) and
             (dynamic['strtab_bytes'] is None)==(dynamic['strsz_count']==0),
             'elf-diagnostic-dynamic-accounting')
        matches=dynamic['load_match_count']
        need(matches is None or uint(matches) and matches<=128,'elf-diagnostic-load-count')
        need((matches is None)==(dynamic['strtab_address'] is None or dynamic['strtab_bytes'] is None),
             'elf-diagnostic-load-availability')
    need(len(canonical(value))<=8192,'elf-diagnostic-byte-bound')
    return value


def validate_inventory_diagnostic(value):
    """Closed unaccepted same-held-row owner facts; never node admission."""
    if value is None:return None
    need(type(value) is dict and set(value)=={'schema_version','purpose','request_path','canonical',
         'directory_path','node_path','identity','node_kind','failed_terms'} and
         type(value['schema_version']) is int and value['schema_version']==1 and
         value['purpose']=='SIGNER_PASSIVE_INVENTORY_DIAGNOSTIC_V1','closed-inventory-diagnostic')
    for key in ('request_path','canonical','directory_path','node_path'):
        name=value[key]
        need(type(name) is str and 0<len(name)<=1024 and str(Path(name))==name and
             Path(name).is_absolute() and len(Path(name).parts)<=32 and '..' not in Path(name).parts
             and all(32<=ord(c)<127 for c in name) and (name in ('/','/usr') or
             any(name==root or name.startswith(root+'/') for root in
                 ('/usr/bin','/usr/lib','/usr/libexec','/usr/include','/lib'))),'inventory-diagnostic-path')
    directory=Path(value['directory_path']);node=Path(value['node_path'])
    need(directory.is_relative_to(value['canonical']) and node.parent==directory,
         'inventory-diagnostic-child-scope')
    ident=value['identity']
    need(type(ident) is list and len(ident)==9 and all(type(n) is int and 0<=n<2**64 for n in ident),
         'inventory-diagnostic-identity')
    mode=ident[2];kind=stat.S_IFMT(mode)
    need(0<=mode<=0o177777 and kind in (stat.S_IFDIR,stat.S_IFREG,stat.S_IFLNK,stat.S_IFBLK,
         stat.S_IFCHR,stat.S_IFIFO,stat.S_IFSOCK),'inventory-diagnostic-mode')
    label='directory' if kind==stat.S_IFDIR else 'regular' if kind==stat.S_IFREG else 'symlink' if kind==stat.S_IFLNK else 'other'
    need(value['node_kind']==label,'inventory-diagnostic-node-kind')
    terms=[]
    if ident[3]!=0:terms.append('uid')
    if ident[4]!=0:terms.append('gid')
    if kind!=stat.S_IFLNK and mode&0o022:terms.append('write-bits')
    need(type(value['failed_terms']) is list and value['failed_terms']==terms and len(terms)>0,
         'inventory-diagnostic-owner-terms')
    need(len(canonical(value))<=8192,'inventory-diagnostic-byte-bound')
    return value


def validate_package_diagnostic(value):
    """Closed unaccepted format-failure bytes; never package parse acceptance."""
    if value is None:return None
    keys={'schema_version','purpose','predicate','status_row','stanza_index','stanza_row','line_index',
          'line_bytes','line_sha256','line_b64','line_truncated','field_name','last_field','package_name'}
    need(type(value) is dict and set(value)==keys and type(value['schema_version']) is int and
         value['schema_version']==1 and value['purpose']=='SIGNER_PASSIVE_PACKAGE_FIELD_DIAGNOSTIC_V1'
         and value['predicate']=='colon-delimiter','closed-package-diagnostic')
    def digest(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value)
    def bounded(value,maximum):return type(value) is int and 1<=value<=maximum
    for name,bound in (('status_row',16*1024**2),('stanza_row',65536)):
        row=value[name]
        need(type(row) is dict and set(row)=={'bytes','sha256'} and bounded(row['bytes'],bound)
             and digest(row['sha256']),'package-diagnostic-buffer-row')
    need(value['stanza_row']['bytes']<=value['status_row']['bytes'] and
         bounded(value['stanza_index'],16384) and bounded(value['line_index'],65536) and
         type(value['line_bytes']) is int and 0<=value['line_bytes']<=8192 and value['line_bytes']<=value['stanza_row']['bytes'] and
         digest(value['line_sha256']),'package-diagnostic-line-index')
    encoded=value['line_b64']
    need(type(encoded) is str and 0<=len(encoded)<=5464,'package-diagnostic-prefix-bound')
    try:prefix=base64.b64decode(encoded,validate=True)
    except (ValueError,UnicodeError) as error:raise Refused('package-diagnostic-base64') from error
    need(base64.b64encode(prefix).decode('ascii')==encoded and
         len(prefix)==min(value['line_bytes'],4096) and type(value['line_truncated']) is bool and
         value['line_truncated']==(value['line_bytes']>4096),'package-diagnostic-prefix-shape')
    need(b':' not in prefix,'package-diagnostic-predicate')
    if value['line_truncated'] is False:
        need(hashlib.sha256(prefix).hexdigest()==value['line_sha256'],'package-diagnostic-full-line-hash')
    expected=None
    if b':' in prefix:
        key=prefix.split(b':',1)[0]
        if re.fullmatch(b'[A-Za-z][A-Za-z0-9-]{0,63}',key):expected=key.decode('ascii')
    field=value['field_name']
    need((field is None or type(field) is str and re.fullmatch('[A-Za-z][A-Za-z0-9-]{0,63}',field))
         and field==expected,'package-diagnostic-field-prefix')
    last=value['last_field'];package=value['package_name']
    need(last is None or type(last) is str and re.fullmatch('[A-Za-z][A-Za-z0-9-]{0,63}',last),
         'package-diagnostic-last-field')
    need(package is None or type(package) is str and re.fullmatch('[a-z0-9][a-z0-9+.-]{0,127}',package),
         'package-diagnostic-package-name')
    need(len(canonical(value))<=8192,'package-diagnostic-byte-bound')
    return value


def validate_file_diagnostic(value):
    """Unaccepted same-pre-open stat facts; no body or file admission."""
    if value is None:return None
    need(type(value) is dict and set(value)=={'schema_version','purpose','request_path','canonical',
         'identity','stage','predicate','failed_terms'} and type(value['schema_version']) is int and
         value['schema_version']==1 and value['purpose']=='SIGNER_PASSIVE_FILE_STAT_DIAGNOSTIC_V1'
         and value['stage']=='before-open' and value['predicate'] in ('sample-file-gate','sample-stdlib-source-file-gate'),
         'closed-file-diagnostic')
    for key in ('request_path','canonical'):
        name=value[key]
        need(type(name) is str and 0<len(name)<=1024 and str(Path(name))==name and
             Path(name).is_absolute() and len(Path(name).parts)<=32 and '..' not in Path(name).parts
             and all(32<=ord(c)<127 for c in name) and (name in ('/','/usr') or
             any(name==root or name.startswith(root+'/') for root in
                 ('/usr/bin','/usr/lib','/usr/libexec','/usr/include','/lib'))),'file-diagnostic-path')
    ident=value['identity']
    need(type(ident) is list and len(ident)==9 and all(type(n) is int and 0<=n<2**64 for n in ident),
         'file-diagnostic-identity')
    mode=ident[2]
    need(mode<=0o177777 and stat.S_IFMT(mode) in (stat.S_IFDIR,stat.S_IFREG,stat.S_IFLNK,
         stat.S_IFBLK,stat.S_IFCHR,stat.S_IFIFO,stat.S_IFSOCK),'file-diagnostic-mode')
    empty_allowed=(value['predicate']=='sample-stdlib-source-file-gate' and
                   all(value[key].startswith('/usr/lib/python3.12/') and Path(value[key]).suffix=='.py'
                       for key in ('request_path','canonical')) and
                   stat.S_IMODE(mode)==0o644 and ident[6]==0)
    terms=[term for term,failed in (('kind',not stat.S_ISREG(mode)),('uid',ident[3]!=0),
           ('gid',ident[4]!=0),('nlink',ident[5]!=1),('mode',stat.S_IMODE(mode) not in (0o644,0o755)),
           ('empty',ident[6]==0 and not empty_allowed),('size-cap',ident[6]>64*1024**2)) if failed]
    need(type(value['failed_terms']) is list and value['failed_terms']==terms and len(terms)>0,
         'file-diagnostic-failed-terms')
    need(len(canonical(value))<=8192,'file-diagnostic-byte-bound')
    return value


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
                 'observer_returncode','selected','execution_grant_issued','compile_allowed','elf_diagnostic','inventory_diagnostic','package_diagnostic','file_diagnostic'},
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
            validate_elf_diagnostic(value['elf_diagnostic'])
            validate_inventory_diagnostic(value['inventory_diagnostic'])
            validate_package_diagnostic(value['package_diagnostic'])
            validate_file_diagnostic(value['file_diagnostic'])
            self._live()
            descriptors['failure.json']=self._write('failure.json',failure_raw)
        except BaseException as error:self._remember(error)
        finally:self._close_all()
        if self._first is not None:raise self._first
        self._live()
        return descriptors
