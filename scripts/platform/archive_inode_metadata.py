#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pinned libarchive observations plus finite exact-USTAR metadata admission.
Native getter observations, member/body/header hashes and hardlink-group joins
are all required. Unknown/warning metadata is never converted to empty maps.
"""
import base64
import ctypes as C
import _ctypes
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import time

SUPPORTED_INTERFACE='libarchive-3-linux-lp64-tar-xz-v1'
ACL_TYPES=0x3f00
LIMIT=512*1024**2
CONTROLS={'.PKGINFO','.BUILDINFO','.MTREE','.INSTALL'}


def need(value,reason):
    if not value:raise ValueError(reason)


def sha(raw):return hashlib.sha256(raw).hexdigest()


def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()


def file_hash(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        while part:=f.read(65536):h.update(part)
    return h.hexdigest()


def validate_configuration(config):
    need(type(config)is dict and set(config)=={'interface','library','ldd','headers'} and
         config['interface']==SUPPORTED_INTERFACE,'unsupported-metadata-dependency-interface')
    need(type(config['headers'])is list and len(config['headers'])<=8,'optional-header-bound')
    paths=[config['library'],config['ldd']]+config['headers']
    need(all(type(p)is str and 0<len(p)<=4096 and Path(p).is_absolute() and '..' not in Path(p).parts
             for p in paths),'explicit-absolute-dependency-paths-required')
    return config


RUN_COMMAND=None


def pins(config):
    """Capture this host only; capture is not host-component qualification."""
    config=validate_configuration(config);library=config['library'];libraries={}
    need(callable(RUN_COMMAND),'reserved-command-runner-not-bound')
    need(not any(k.startswith('LD_') and v for k,v in os.environ.items()),'unsupported-loader-override-environment')
    need(sys.platform.startswith('linux') and C.sizeof(C.c_void_p)==C.sizeof(C.c_long)==8,'unsupported-native-ABI')
    for obj in (library,_ctypes.__file__,sys.executable):
        result=RUN_COMMAND([config['ldd'],obj],capture_output=True,check=True,timeout=10,
                              env={'PATH':'/usr/bin:/usr/sbin:/bin:/sbin','LC_ALL':'C'})
        need(b'not found' not in result.stdout+result.stderr,'dependency-closure-incomplete')
        output=result.stdout.decode()
        paths=re.findall(r'(?:=>\s+|^\s*)(/[^\s()]+)',output,re.M)
        need(paths,'dependency-closure-unknown')
        for path in paths:libraries[path]=file_hash(path)
    lib=C.CDLL(library);lib.archive_version_details.restype=C.c_char_p;lib.archive_version_number.restype=C.c_int
    version=lib.archive_version_number();need(version//1000000==3,'unsupported-libarchive-major-interface')
    return dict(schema_version=2,configuration=config,library_path=library,library_sha256=file_hash(library),
        ldd=dict(path=config['ldd'],sha256=file_hash(config['ldd'])),libraries=dict(sorted(libraries.items())),
        headers={p:file_hash(p) for p in config['headers']},
        ctypes={C.__file__:file_hash(C.__file__),_ctypes.__file__:file_hash(_ctypes.__file__)},
        python=dict(path=sys.executable,sha256=file_hash(sys.executable),version=list(sys.version_info[:3])),
        version_number=version,version_details=lib.archive_version_details().decode(),
        pointer_bytes=C.sizeof(C.c_void_p),long_bytes=C.sizeof(C.c_long),
        qualification='CAPTURED_IDENTITY_ONLY_REQUIRE_SEPARATE_HOST_COMPONENT_CHECK')


class Native:
    def __init__(self,expected):
        need(type(expected)is dict and expected.get('schema_version')==2,'metadata-dependency-profile-v2-required')
        need(expected==pins(expected.get('configuration')),'libarchive-pin-mismatch')
        need(expected['pointer_bytes']==expected['long_bytes']==8,'unsupported-native-ABI')
        self.lib=C.CDLL(expected['configuration']['library'])
        P=C.c_void_p;I=C.c_int;S=C.c_char_p;L=C.c_longlong;Z=C.c_size_t
        signatures={
          'archive_read_new':(P,[]),'archive_read_free':(I,[P]),
          'archive_read_support_filter_xz':(I,[P]),'archive_read_support_format_tar':(I,[P]),
          'archive_read_set_options':(I,[P,S]),'archive_read_open_fd':(I,[P,I,Z]),
          'archive_read_next_header':(I,[P,C.POINTER(P)]),'archive_read_data':(C.c_ssize_t,[P,P,Z]),
          'archive_error_string':(S,[P]),'archive_read_header_position':(L,[P]),
          'archive_format_name':(S,[P]),'archive_filter_count':(I,[P]),'archive_filter_code':(I,[P,I]),
          'archive_read_has_encrypted_entries':(I,[P]),
          'archive_entry_acl_next':(I,[P,I,C.POINTER(I),C.POINTER(I),C.POINTER(I),C.POINTER(I),C.POINTER(S)]),
          'archive_entry_xattr_next':(I,[P,C.POINTER(S),C.POINTER(P),C.POINTER(Z)]),
          'archive_entry_mac_metadata':(P,[P,C.POINTER(Z)]),
          'archive_entry_fflags':(None,[P,C.POINTER(C.c_ulong),C.POINTER(C.c_ulong)])}
        for key in ('pathname','hardlink','symlink','fflags_text'):signatures['archive_entry_'+key]=(S,[P])
        for key in ('acl_types','xattr_count','xattr_reset','sparse_count','is_encrypted','is_data_encrypted','is_metadata_encrypted'):
            signatures['archive_entry_'+key]=(I,[P])
        for key in ('acl_count','acl_reset'):signatures['archive_entry_'+key]=(I,[P,I])
        for key in ('uid','gid','size','mtime'):signatures['archive_entry_'+key]=(L,[P])
        for key in ('mode','perm','filetype'):signatures['archive_entry_'+key]=(C.c_uint,[P])
        for name,(ret,args) in signatures.items():
            f=getattr(self.lib,name);f.restype=ret;f.argtypes=args

    def call(self,name,*args):return getattr(self.lib,name)(*args)

    def string(self,name,entry,maximum=4096):
        raw=self.call('archive_entry_'+name,entry)
        if raw is None:return None
        need(len(raw)<=maximum,'native-string-bound')
        return raw.decode('utf-8','strict')

    def observe(self,entry):
        xcount=self.call('archive_entry_xattr_count',entry)
        need(0<=xcount<=32 and self.call('archive_entry_xattr_reset',entry)==xcount,'xattr-count-unknown')
        attrs={}
        for _ in range(xcount):
            name=C.c_char_p();value=C.c_void_p();length=C.c_size_t()
            need(self.call('archive_entry_xattr_next',entry,C.byref(name),C.byref(value),C.byref(length))==0,'xattr-iteration-status')
            need(name.value is not None and length.value<=4096,'xattr-observation-bound')
            key=name.value.decode('utf-8','strict');need(len(key)<=255 and key not in attrs,'duplicate-xattr-unknown')
            attrs[key]=base64.b64encode(C.string_at(value,length.value)).decode()
        if xcount:
            name=C.c_char_p();value=C.c_void_p();length=C.c_size_t()
            need(self.call('archive_entry_xattr_next',entry,C.byref(name),C.byref(value),C.byref(length))==-20,'xattr-terminal-unknown')
        types=self.call('archive_entry_acl_types',entry);acount=self.call('archive_entry_acl_count',entry,ACL_TYPES)
        need(types&~ACL_TYPES==0 and 0<=acount<=128 and self.call('archive_entry_acl_reset',entry,ACL_TYPES)==acount,'acl-count-unknown')
        acl=[]
        for _ in range(acount):
            values=[C.c_int() for _ in range(4)];name=C.c_char_p()
            need(self.call('archive_entry_acl_next',entry,ACL_TYPES,*(C.byref(v) for v in values),C.byref(name))==0,'acl-iteration-status')
            acl.append(dict(zip(('type','permset','tag','qualifier'),[v.value for v in values]),
                            name=None if name.value is None else name.value.decode('utf-8','strict')))
        if acount:
            values=[C.c_int() for _ in range(4)];name=C.c_char_p()
            need(self.call('archive_entry_acl_next',entry,ACL_TYPES,*(C.byref(v) for v in values),C.byref(name))==1,'acl-terminal-unknown')
        flags_set=C.c_ulong();flags_clear=C.c_ulong();mac_size=C.c_size_t()
        self.call('archive_entry_fflags',entry,C.byref(flags_set),C.byref(flags_clear))
        mac=self.call('archive_entry_mac_metadata',entry,C.byref(mac_size));need(mac_size.value<=4096,'mac-metadata-bound')
        return dict(acl_types=types,acl_count=acount,acl=acl,xattr_count=xcount,xattrs=dict(sorted(attrs.items())),
            capability_b64=attrs.get('security.capability'),file_flags_set=flags_set.value,file_flags_clear=flags_clear.value,
            file_flags_text=self.string('fflags_text',entry),mac_metadata_bytes=mac_size.value,
            mac_metadata_sha256=sha(C.string_at(mac,mac_size.value)) if mac_size.value else None,
            sparse_count=self.call('archive_entry_sparse_count',entry),
            encrypted=self.call('archive_entry_is_encrypted',entry),data_encrypted=self.call('archive_entry_is_data_encrypted',entry),
            metadata_encrypted=self.call('archive_entry_is_metadata_encrypted',entry))


def identity(st):return [st.st_dev,st.st_ino,st.st_mode,st.st_nlink,st.st_uid,st.st_gid,st.st_size,st.st_mtime_ns,st.st_ctime_ns]


def normalize(name):
    need(type(name)is str and len(name)<=4096,'member-path')
    name=name.removeprefix('./').removesuffix('/')
    need(name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')),'member-path')
    return name


def native_scan(reference,expected):
    native=Native(expected);path=Path(reference['path']);need(path==path.resolve(),'archive-symlink')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    a=None;before=os.fstat(fd);rows=[];deadline=time.monotonic()+60;decoded=0
    try:
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and identity(before)==reference['identity'] and before.st_size==reference['size'],'archive-identity')
        need(file_hash(path)==reference['sha256'],'archive-initial-hash')
        a=native.call('archive_read_new');need(a,'archive-allocation')
        for name in ('archive_read_support_filter_xz','archive_read_support_format_tar'):
            need(native.call(name,a)==0,'native-support-warning')
        need(native.call('archive_read_set_options',a,b'tar:mac-ext,tar:!read_concatenated_archives')==0,'native-option-warning')
        need(native.call('archive_read_open_fd',a,fd,65536)==0,'native-open-warning')
        seen=set();buf=C.create_string_buffer(65536)
        while True:
            need(time.monotonic()<deadline and len(rows)<100000,'native-scan-bound')
            entry=C.c_void_p();status=native.call('archive_read_next_header',a,C.byref(entry))
            if status==1:break
            need(status==0,'native-header-warning:'+str(native.call('archive_error_string',a)))
            name=normalize(native.string('pathname',entry));need(name not in seen,'duplicate-native-member');seen.add(name)
            hard=native.string('hardlink',entry);link=native.string('symlink',entry)
            mode=native.call('archive_entry_mode',entry);size=native.call('archive_entry_size',entry)
            kind='hardlink' if hard is not None else {stat.S_IFREG:'file',stat.S_IFDIR:'directory',stat.S_IFLNK:'symlink'}.get(stat.S_IFMT(mode))
            need(kind is not None and 0<=size<=LIMIT,'unsupported-native-node')
            obs=native.observe(entry);h=hashlib.sha256();count=0
            while True:
                need(time.monotonic()<deadline,'native-scan-wall-bound')
                amount=native.call('archive_read_data',a,buf,65536);need(0<=amount<=65536,'native-data-warning')
                if not amount:break
                count+=amount;decoded+=amount;need(count<=size and decoded<=LIMIT,'native-body-bound');h.update(buf.raw[:amount])
            need(count==size,'native-body-size')
            rows.append(dict(index=len(rows),path=name,header_position=native.call('archive_read_header_position',a),
                type=kind,mode=stat.S_IMODE(mode),uid=native.call('archive_entry_uid',entry),gid=native.call('archive_entry_gid',entry),
                bytes=size,body_sha256=h.hexdigest() if kind=='file' else None,
                target=normalize(hard) if hard is not None else link,metadata=obs))
        filters=[native.call('archive_filter_code',a,i) for i in range(native.call('archive_filter_count',a))]
        need(filters==[6,0],'native-filter-profile')
        need(identity(before)==identity(os.fstat(fd))==identity(path.lstat()) and file_hash(path)==reference['sha256'],'archive-final-binding')
        return dict(status='OBSERVED_NATIVE_ENTRY_METADATA_NOT_YET_ADMITTED',archive_sha256=reference['sha256'],
                    archive_bytes=reference['size'],format=native.call('archive_format_name',a).decode(),filters=filters,
                    encryption_format_state=native.call('archive_read_has_encrypted_entries',a),
                    native_pins=expected,members=rows)
    finally:
        try:
            if a:need(native.call('archive_read_free',a)==0,'native-close-warning')
        finally:os.close(fd)


class XZ:
    def __init__(self,stream):
        self.source=stream;self.codec=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=64*1024**2)
        self.count=0;self.deadline=time.monotonic()+60
    def read(self,n):
        need(0<n<=65536,'raw-read-quantum');out=bytearray()
        while len(out)<n:
            need(time.monotonic()<self.deadline,'raw-wall-bound')
            if self.codec.eof:
                need(not self.codec.unused_data and not self.source.read(1),'xz-trailing-or-concatenated')
                break
            incoming=self.source.read(65536) if self.codec.needs_input else b''
            need(incoming or not self.codec.needs_input,'xz-truncated')
            out.extend(self.codec.decompress(incoming,max_length=n-len(out)))
        self.count+=len(out);need(self.count<=LIMIT,'decoded-archive-bound')
        return bytes(out)


def raw_ustar(reference):
    """Independent exact header coverage: no ignored PAX/unknown format fields."""
    path=Path(reference['path']);need(path==path.resolve(),'raw-source-path')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);rows=[]
    try:
        before=os.fstat(fd);need(identity(before)==reference['identity'] and file_hash(path)==reference['sha256'],'raw-source-binding')
        with os.fdopen(os.dup(fd),'rb') as source:
            stream=XZ(source)
            while True:
                offset=stream.count;block=stream.read(512);need(len(block)==512,'raw-tar-truncated')
                if block==bytes(512):
                    need(stream.read(512)==bytes(512),'raw-tar-end')
                    while tail:=stream.read(65536):need(not any(tail),'raw-tar-nonzero-remainder')
                    need(stream.count%512==0,'raw-tar-tail-alignment');break
                need(len(rows)<100000,'raw-member-bound')
                need(block[257:265]==b'ustar\x0000' and not any(block[500:512]),'UNKNOWN_UNSUPPORTED_TAR_METADATA_FORMAT')
                for start,end in ((0,100),(157,257),(265,297),(297,329),(345,500)):
                    field=block[start:end]
                    if b'\0'in field:need(not any(field[field.index(b'\0')+1:]),'UNKNOWN_HEADER_STRING_TRAILER')
                for start,end in ((100,108),(108,116),(116,124),(124,136),(136,148),(148,156),(329,337),(337,345)):
                    need(all(c in b'01234567 \x00' for c in block[start:end]),'UNKNOWN_NON_USTAR_NUMERIC_FIELD')
                item=tarfile.TarInfo.frombuf(block,'utf-8','strict')
                need(item.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE,tarfile.SYMTYPE,tarfile.LNKTYPE),
                     'UNKNOWN_UNSUPPORTED_TAR_METADATA_CARRIER:'+repr(item.type))
                need(item.devmajor==item.devminor==0 and item.sparse is None and not item.pax_headers,'UNKNOWN_SPECIAL_HEADER_METADATA')
                need(not any(p.startswith('._') or p=='.AppleDouble' for p in normalize(item.name).split('/')),'UNKNOWN_APPLEDOUBLE_METADATA_CARRIER')
                size=item.size;need(type(size)is int and 0<=size<=LIMIT,'raw-member-size')
                h=hashlib.sha256();remaining=size
                while remaining:
                    part=stream.read(min(65536,remaining));need(part,'raw-body-truncated');h.update(part);remaining-=len(part)
                padding=stream.read((-size)%512) if size%512 else b'';need(not any(padding),'raw-body-padding')
                kind='file' if item.isfile() else 'directory' if item.isdir() else 'symlink' if item.issym() else 'hardlink'
                rows.append(dict(index=len(rows),path=normalize(item.name),type=kind,mode=item.mode,uid=item.uid,gid=item.gid,
                    bytes=size,body_sha256=h.hexdigest() if kind=='file' else None,
                    target=normalize(item.linkname) if kind=='hardlink' else item.linkname if kind=='symlink' else None,
                    header_position=offset,header_sha256=sha(block),mtime=item.mtime))
        need(identity(before)==identity(os.fstat(fd))==identity(path.lstat()) and file_hash(path)==reference['sha256'],'raw-final-binding')
        return rows
    finally:os.close(fd)


def complete(reference,expected):
    observed=native_scan(reference,expected)
    try:
        raw=raw_ustar(reference)
        need(len(raw)==len(observed['members']),'native-raw-member-closure')
        for left,right in zip(raw,observed['members']):
            need(all(left[k]==right[k] for k in ('index','path','type','mode','uid','gid','bytes','body_sha256','target','header_position')),'native-raw-member-disagreement')
            right['raw_header_sha256']=left['header_sha256'];right['archive_mtime']=left['mtime']
            m=right['metadata']
            need(m['sparse_count']==0 and m['encrypted']==m['data_encrypted']==m['metadata_encrypted']==0,'UNKNOWN_SPARSE_OR_ENCRYPTED_METADATA')
            need(not m['file_flags_set'] and not m['file_flags_clear'] and m['file_flags_text'] in (None,''),'UNSUPPORTED_FILE_FLAGS')
            need(m['mac_metadata_bytes']==0,'UNSUPPORTED_MAC_METADATA')
            need(m['acl_types']==m['acl_count']==0 and m['acl']==[],'UNSUPPORTED_ACL_ENCODING')
            # A native USTAR reader reporting attrs is an unexpected disagreement.
            need(m['xattr_count']==len(m['xattrs'])==0 and m['capability_b64'] is None,'UNKNOWN_USTAR_ATTRIBUTE_DISAGREEMENT')
        need(observed['encryption_format_state']==-2,'UNKNOWN_TAR_ENCRYPTION_STATE')
        observed['status']='COMPLETE_PINNED_NATIVE_AND_RAW_USTAR_METADATA'
        observed['coverage']='EXACT_USTAR_ENTRIES_ONLY_NO_PAX_UNKNOWN_CARRIERS_INSTALLED_OR_RUNTIME_STATE'
        return observed
    except BaseException as exc:
        # Caller can retain genuine native nonempty/unknown observations on refusal.
        exc.metadata_observations=observed
        raise


def join_metadata(manifest,reports,root_policy):
    """Join direct native/header observations to every authenticated payload node."""
    packages=manifest['pristine']['packages'];need(set(packages)==set(reports),'metadata-package-closure')
    need(root_policy==dict(mode=0o755,uid=0,gid=0,acl=None,xattrs={}) and
         all(type(root_policy[k])is int for k in ('mode','uid','gid')), 'unsupported-new-root-policy')
    metadata=dict(schema_version=1,complete=True,root=dict(root_policy),nodes={})
    bindings={};groups={}
    for package,report in sorted(reports.items()):
        source=packages[package];auth=manifest['archive_authentication'][package]
        need(report['status']=='COMPLETE_PINNED_NATIVE_AND_RAW_USTAR_METADATA','incomplete-native-observation')
        need(report['archive_sha256']==source['archive_sha256']==auth['archive_sha256'] and
             report['identity']==source['identity']==auth['identity'],'native-archive-tuple-join')
        need(report['signature_reference']['sha256']==auth['signature_sha256'],'native-signature-association')
        entries={row['path']:row for row in report['members']}
        need(len(entries)==len(report['members']),'native-member-duplicates')
        payload={p:r for p,r in entries.items() if p not in CONTROLS}
        expected={p for p,owners in manifest['pristine']['owners'].items() if package in owners}
        need(set(payload)==expected,'native-payload-owner-closure')
        controls=manifest['intake_metadata'][package]['controls']
        need(set(entries)-set(payload)==set(controls),'native-control-closure')
        for name,c in controls.items():
            r=entries[name];need(r['type']=='file' and r['bytes']==c['bytes'] and r['body_sha256']==c['sha256'],'native-control-hash')
        roots={}
        for path,row in payload.items():
            root=path;seen=set()
            while payload[root]['type']=='hardlink':
                need(root not in seen and len(seen)<64,'native-hardlink-cycle')
                seen.add(root);root=payload[root]['target'];need(root in payload,'native-hardlink-target')
            if row['type']=='hardlink':need(payload[root]['type']=='file','native-hardlink-file')
            roots[path]=root
        package_groups={}
        for path,row in sorted(payload.items()):
            node=manifest['output_nodes'][path]
            need(all(row[k]==node[k] for k in ('type','mode','uid','gid')),'native-node-metadata-join')
            if row['type']=='file':need(row['bytes']==node['bytes'] and row['body_sha256']==node['sha256'],'native-file-hash-join')
            if row['type']=='symlink':need(row['target']==node['target'],'native-symlink-join')
            if row['type']=='hardlink':need(roots[path]==node['target'],'native-hardlink-canonical-join')
            attrs=row['metadata'];need(attrs['acl_count']==attrs['acl_types']==0 and attrs['acl']==[],'UNSUPPORTED_ACL_ENCODING')
            need(attrs['xattr_count']==len(attrs['xattrs'])==0 and attrs['capability_b64'] is None and
                 attrs['file_flags_set']==attrs['file_flags_clear']==attrs['mac_metadata_bytes']==attrs['sparse_count']==0 and
                 attrs['encrypted']==attrs['data_encrypted']==attrs['metadata_encrypted']==0 and
                 attrs['file_flags_text'] in (None,''),'UNKNOWN_OR_UNSUPPORTED_JOIN_METADATA')
            inode=dict(acl=None,xattrs=json.loads(json.dumps(attrs['xattrs'],sort_keys=True)))
            if row['type']=='hardlink':
                target=payload[roots[path]]
                need(all(row[k]==target[k] for k in ('mode','uid','gid')) and attrs==target['metadata'],'conflicting-hardlink-inode-observations')
            if path in metadata['nodes']:need(metadata['nodes'][path]==inode,'shared-inode-attribute-conflict')
            metadata['nodes'][path]=inode
            bindings.setdefault(path,[]).append(dict(package=package,archive_sha256=report['archive_sha256'],
                signature_sha256=auth['signature_sha256'],member_index=row['index'],member_path=path,
                member_header_position=row['header_position'],member_header_sha256=row['raw_header_sha256'],
                native_observation_sha256=sha(encoded(row)),hardlink_group_root=roots[path],
                inode_metadata_sha256=sha(encoded(inode))))
            if row['type'] in ('file','hardlink'):package_groups.setdefault(roots[path],[]).append(path)
        groups[package]={root:sorted(names) for root,names in sorted(package_groups.items())}
    need(set(metadata['nodes'])==set(manifest['output_nodes'])==set(bindings),'complete-inode-metadata-closure')
    return metadata,dict(status='COMPLETE_NATIVE_MEMBER_AND_HARDLINK_GROUP_JOINS',nodes=bindings,hardlink_groups=groups,
        root_policy=root_policy,root_metadata_source='SEPARATE_PROJECT_NEW_ROOT_POLICY_REQUIRES_IMAGE_PROOF',
        installed_or_scriptlet_metadata_accepted=False)
