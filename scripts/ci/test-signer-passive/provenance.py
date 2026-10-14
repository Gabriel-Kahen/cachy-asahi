# SPDX-License-Identifier: MIT
"""Observed hosted Ubuntu ARM metadata; never preexisting execution admission."""
import hashlib
import json
import math
from pathlib import Path
import re
import stat
import time

FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
STDLIB='/usr/lib/python3.12'
BASE_PACKAGES={'gcc','binutils','python3.12','python3.12-minimal',
               'libpython3.12-stdlib','libc6','linux-libc-dev','libc6-dev'}
BASE_OPTIONAL={'binutils-aarch64-linux-gnu','libpython3.12-minimal'}
GCC_DIRECTORY=r'/usr/lib/gcc/aarch64-linux-gnu/([1-9][0-9]{0,2})(?:\.[0-9]{1,3}){0,2}'

def gcc_major(directory):
    need(type(directory) is str,'concrete-gcc-directory')
    match=re.fullmatch(GCC_DIRECTORY,directory)
    need(match is not None,'concrete-gcc-directory')
    return match.group(1)

def package_sets(major):
    need(type(major) is str and re.fullmatch('[1-9][0-9]{0,2}',major),'selected-gcc-major')
    required=BASE_PACKAGES|{'gcc-'+major}
    family={'gcc-'+major,'gcc-'+major+'-base','gcc-'+major+'-aarch64-linux-gnu',
            'cpp-'+major,'cpp-'+major+'-aarch64-linux-gnu',
            'libgcc-'+major+'-dev','libstdc++-'+major+'-dev'}
    return required,BASE_OPTIONAL|(family-required),family

class Refused(ValueError):pass

def need(value,code):
    if not value:raise Refused(code)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def text(value,maximum=4096):
    need(type(value) is str and 0<len(value)<=maximum and '\0' not in value,'metadata-text')
    return value

def ident(row):return [getattr(row,name) for name in FIELDS]


class MetadataReader:
    """Only two fixed metadata files, shared passive counters and original cutoff."""
    def __init__(self,host):self.host=host;self.cancelled=False;self.close_uncertain=False

    def read(self,name,io,endpoint,clock):
        limits={'/proc/version':8192,'/var/lib/dpkg/status':16*1024**2}
        need(name in limits,'closed-metadata-path');need(not self.close_uncertain,'metadata-close-uncertain')
        limit=limits[name];h=self.host
        def live():
            need(type(endpoint) in (int,float) and math.isfinite(endpoint) and clock()<endpoint,
                 'original-observation-deadline')
        def charged():live();io.charge(endpoint)
        def checked(row,directory=False):
            need(row.st_uid==row.st_gid==0 and not row.st_mode&0o022 and row.st_nlink>=1,
                 'metadata-owner-mode')
            if directory:need(stat.S_ISDIR(row.st_mode),'metadata-directory')
            else:
                need(stat.S_ISREG(row.st_mode) and row.st_nlink==1 and 0<=row.st_size<=limit,
                     'metadata-regular-file')
                if name!='/proc/version':need(row.st_size>0,'empty-package-status')
        handles=[];nodes=[];fd=None;first=None;result=None
        def remember(error):
            nonlocal first
            if first is None:first=error
            self.cancelled |= isinstance(error,KeyboardInterrupt)
        try:
            charged();row=h.lstat('/');checked(row,True)
            root=h.open('/',h.O_RDONLY|h.O_DIRECTORY|h.O_NOFOLLOW|h.O_NONBLOCK);handles.append(root)
            need(ident(h.fstat(root))==ident(row),'metadata-root-drift');nodes.append(('/',root,ident(row)))
            parent=root;current=Path('/')
            for part in Path(name).parts[1:-1]:
                current=current/part;charged();row=h.stat(part,dir_fd=parent,follow_symlinks=False);checked(row,True)
                made=h.open(part,h.O_RDONLY|h.O_DIRECTORY|h.O_NOFOLLOW|h.O_NONBLOCK,dir_fd=parent)
                handles.append(made);need(ident(h.fstat(made))==ident(row),'metadata-parent-open-drift')
                nodes.append((str(current),made,ident(row)));parent=made
            charged();leaf=Path(name).name;before=h.stat(leaf,dir_fd=parent,follow_symlinks=False);checked(before)
            fd=h.open(leaf,h.O_RDONLY|h.O_NOFOLLOW|h.O_NONBLOCK,dir_fd=parent);handles.append(fd)
            need(ident(h.fstat(fd))==ident(before),'metadata-file-open-drift')
            raw=bytearray()
            while True:
                charged();part=h.read(fd,min(65536,limit+1-len(raw)))
                need(type(part) is bytes,'metadata-read-type')
                if not part:break
                io.bytes_read+=len(part);need(io.bytes_read<=512*1024**2,'shared-read-work-limit')
                raw.extend(part);need(len(raw)<=limit,'metadata-file-budget')
            need(0<len(raw)<=limit,'metadata-empty')
            if name!='/proc/version':need(len(raw)==before.st_size,'metadata-size-drift')
            charged();need(ident(before)==ident(h.fstat(fd))==ident(h.stat(leaf,dir_fd=parent,follow_symlinks=False)),
                           'metadata-file-drift')
            for path,handle,expected in nodes:
                charged();need(expected==ident(h.fstat(handle))==ident(h.lstat(path)),'metadata-parent-drift')
            live();result=bytes(raw)
        except BaseException as error:remember(error)
        finally:
            for handle in reversed(handles):
                try:h.close(handle)
                except BaseException as error:self.close_uncertain=True;remember(error)
        if first is not None:raise first
        need(not self.close_uncertain,'metadata-close-uncertain');live()
        return result


def package_records(raw,*,gcc_major):
    required,additional,family=package_sets(gcc_major)
    need(type(raw) is bytes and 0<len(raw)<=16*1024**2 and b'\0' not in raw,'package-status-budget')
    records={};count=0
    for stanza in raw.split(b'\n\n'):
        if not stanza.strip():continue
        count+=1;need(count<=16384 and len(stanza)<=65536,'package-stanza-budget')
        fields={};last=None
        for line in stanza.splitlines():
            need(len(line)<=8192,'package-line-budget')
            if line.startswith((b' ',b'\t')):
                need(last is not None,'package-orphan-continuation');continue
            need(b': ' in line,'package-field-format');key,value=line.split(b': ',1)
            need(key not in fields and re.fullmatch(b'[A-Za-z][A-Za-z0-9-]{0,63}',key),'package-duplicate-field')
            fields[key]=value;last=key
        name=fields.get(b'Package',b'').decode('ascii')
        if name not in required|additional:continue
        need(name not in records,'package-duplicate-record')
        status=fields.get(b'Status',b'').decode('ascii');arch=fields.get(b'Architecture',b'').decode('ascii')
        version=fields.get(b'Version',b'').decode('ascii')
        need(status=='install ok installed' and arch in ('arm64','all') and re.fullmatch('[0-9A-Za-z.+:~_-]{1,128}',version),
             'installed-package-version-architecture')
        need(name not in required or arch=='arm64','required-native-package-architecture')
        records[name]={'version':version,'architecture':arch,'status':status,
                       'stanza_bytes':len(stanza),'stanza_sha256':sha(stanza)}
    need(required<=set(records),'missing-required-package-version')
    need(all(re.match(r'^'+re.escape(gcc_major)+r'(?:\.|-)',records[name]['version'].split(':')[-1])
             for name in family&set(records)),'selected-gcc-package-version-family')
    return dict(sorted(records.items()))


def capture(io,*,endpoint,source_rows,gcc_directory,host=None,runtime=None,modules=None,reader=None,clock=None):
    """Use the already trusted running runtime and the SAME observation IO/frame.

    sys.modules origins and dpkg records are observed metadata, not proof of
    executed Python bytecode, binary package ownership, kernel config or ABI.
    """
    if host is None:
        import os
        host=os
    if runtime is None:
        import sys
        runtime=sys
    if modules is None:modules=runtime.modules
    if reader is None:reader=MetadataReader(host)
    if clock is None:clock=time.monotonic
    def live():
        need(type(endpoint) in (int,float) and math.isfinite(endpoint) and clock()<endpoint,
             'original-observation-deadline')
    live();major=gcc_major(gcc_directory)
    need(type(io.nodes) is int and 0<=io.nodes<=65536 and type(io.bytes_read) is int
         and 0<=io.bytes_read<=512*1024**2,'shared-passive-counters')
    need(type(source_rows) is dict and 0<len(source_rows)<=32,'observer-Source-row-count')
    for name,row in source_rows.items():
        need(type(name) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',name) and name.endswith('.py')
             and type(row) is dict and set(row)=={'bytes','mode','sha256'} and type(row['bytes']) is int
             and 0<row['bytes']<=256*1024 and row['mode']==0o644 and type(row['sha256']) is str
             and re.fullmatch('[0-9a-f]{64}',row['sha256']),'observer-Source-row')
    frozen_source_rows=json.loads(json.dumps(source_rows,sort_keys=True,separators=(',',':'),allow_nan=False))
    version_text=text(runtime.version,1024)
    uname=host.uname();kernel={name:text(getattr(uname,name)) for name in ('sysname','nodename','release','version','machine')}
    need(kernel['sysname']=='Linux' and kernel['machine']=='aarch64','host-kernel-platform')
    version_info=list(runtime.version_info)
    need(len(version_info)==5 and version_info[:2]==[3,12] and type(version_info[2]) is int
         and all(type(version_info[i]) is int for i in (0,1,2,4))
         and version_info[2]>=0 and version_info[3]=='final' and version_info[4]==0,'running-python312')
    flags={name:getattr(runtime.flags,name) for name in ('isolated','ignore_environment','no_site',
             'no_user_site','dont_write_bytecode','optimize','safe_path')}
    need(all(type(v) in (int,bool) for v in flags.values()) and all(flags[name]==1 for name in (
         'isolated','ignore_environment','no_site','no_user_site','dont_write_bytecode','safe_path'))
         and flags['optimize']==0,'running-isolated-no-site-runtime')
    implementation={'name':text(runtime.implementation.name,64),'cache_tag':text(runtime.implementation.cache_tag,128),
                    'version':list(runtime.implementation.version)}
    need(implementation['name']=='cpython' and implementation['cache_tag']=='cpython-312'
         and implementation['version']==version_info,'running-implementation-version')
    executable=text(runtime.executable,1024);need(executable.startswith('/usr/bin/') and '..' not in Path(executable).parts,
                                              'running-executable-path')
    need(type(modules) is dict and len(modules)<=2048,'loaded-module-count')
    need(all(type(name) is str for name in modules),'loaded-module-name')
    table=tuple(sorted(modules.items()))
    def module_row(name,module):
        text(name,128);spec=getattr(module,'__spec__',None)
        origin=None if spec is None else getattr(spec,'origin',None)
        file=getattr(module,'__file__',None);cached=getattr(module,'__cached__',None)
        need(all(value is None or type(value) is str and len(value)<=1024 and '\0' not in value
                 for value in (origin,file,cached)),'loaded-module-origin')
        return {'name':name,'origin':origin,'file':file,'cached':cached}
    module_state=[module_row(name,module) for name,module in table]
    files={};samples={};requests={};sample_count=0
    def sample(path,required=True):
        nonlocal sample_count
        live();need(path not in requests,'provenance-request-replay');sample_count+=1
        need(sample_count<=1024,'provenance-sample-count')
        item=io.sample(path,endpoint);live()
        if item is None:
            need(not required,'missing-loaded-origin');requests[path]=None;return None
        need(type(item) is dict and type(item.get('body')) is bytes,'provenance-body')
        raw=item['body'];row=item['row'];canonical=item['canonical']
        need(0<len(raw)<=8*1024**2 and row=={'bytes':len(raw),'mode':row['mode'],'sha256':sha(raw)}
             and row['mode'] in (0o644,0o755),'provenance-body-pin')
        meta={k:v for k,v in item.items() if k!='body'}
        if canonical in files:need(files[canonical]==row and samples[canonical]['identity']==meta['identity'],'origin-canonical-drift')
        else:
            files[canonical]=row;samples[canonical]=meta
            need(len(files)<=513,'loaded-filename-count')
        requests[path]=meta;return canonical
    # Kernel/proc and dpkg observations share the same counters/cutoff as tools/headers.
    proc=reader.read('/proc/version',io,endpoint,clock)
    proc_text=proc.decode('utf-8');need(proc_text.startswith('Linux version '+kernel['release']+' '),'kernel-release-proc-version')
    status=reader.read('/var/lib/dpkg/status',io,endpoint,clock);packages=package_records(status,gcc_major=major)
    expected_python='.'.join(str(v) for v in version_info[:3])
    need(all(packages[name]['version'].split(':')[-1].startswith(expected_python+'-') for name in (
         'python3.12','python3.12-minimal','libpython3.12-stdlib')),'runtime-package-version-correspondence')
    executable_canonical=sample(executable)
    need(files[executable_canonical]['mode']==0o755,'running-executable-mode')
    loaded=[];special=[];excluded=[];origin_count=0
    for record in module_state:
        live();origin=record['origin']
        if origin in ('built-in','frozen'):
            special.append({'name':record['name'],'origin':origin});continue
        if origin is None or not (origin==STDLIB or origin.startswith(STDLIB+'/')):
            excluded.append({'name':record['name'],'origin':origin});continue
        need('..' not in Path(origin).parts and origin.startswith(STDLIB+'/'),'closed-stdlib-origin')
        origin_count+=1;need(origin_count<=512,'loaded-origin-count')
        if origin not in requests:canonical=sample(origin)
        else:canonical=requests[origin]['canonical']
        suffix=Path(origin).suffix
        basis='text-origin' if suffix=='.py' else 'bytecode-origin' if suffix=='.pyc' else 'native-extension-origin' if suffix=='.so' else None
        need(basis is not None,'unsupported-loaded-origin')
        need(canonical.startswith(STDLIB+'/'),'closed-canonical-stdlib-origin')
        canonical_cached=None
        if record['cached'] is not None:
            cache=record['cached'];need(cache.startswith(STDLIB+'/') and '..' not in Path(cache).parts
                                       and cache.endswith('.pyc'),'closed-stdlib-cache')
            if cache not in requests:canonical_cached=sample(cache,False)
            else:canonical_cached=None if requests[cache] is None else requests[cache]['canonical']
            need(canonical_cached is None or canonical_cached.startswith(STDLIB+'/'),'closed-canonical-stdlib-cache')
        loaded.append({**record,'basis':basis,'canonical':canonical,'canonical_cached':canonical_cached})
    # Recheck all physical file/alias/absence and runtime/module/version state.
    for path,before in requests.items():
        live();sample_count+=1;need(sample_count<=2048,'provenance-total-sample-count')
        item=io.sample(path,endpoint);live()
        if before is None:need(item is None,'loaded-cache-negative-drift')
        else:need(item is not None and {k:v for k,v in item.items() if k!='body'}==before
                  and sha(item['body'])==before['row']['sha256'],'loaded-origin-final-drift')
    need(reader.read('/proc/version',io,endpoint,clock)==proc,'proc-version-final-drift')
    need(reader.read('/var/lib/dpkg/status',io,endpoint,clock)==status,'package-status-final-drift')
    need({name:text(getattr(host.uname(),name)) for name in kernel}==kernel,'uname-final-drift')
    need(tuple(sorted(list(modules.items())))==table and [module_row(name,module) for name,module in table]==module_state,
         'loaded-modules-final-drift')
    need(list(runtime.version_info)==version_info and runtime.version==version_text
         and version_text.startswith(expected_python)
         and {name:getattr(runtime.flags,name) for name in flags}==flags
         and runtime.executable==executable and runtime.implementation.name==implementation['name']
         and runtime.implementation.cache_tag==implementation['cache_tag']
         and list(runtime.implementation.version)==implementation['version'],'runtime-final-drift')
    need(source_rows==frozen_source_rows,'observer-Source-row-final-drift')
    result={
      'kernel':{'uname':kernel,'proc_version':{'bytes':len(proc),'sha256':sha(proc),'text':proc_text},
                'proof_scope':'HOST_METADATA_ONLY'},
      'python':{'version':version_text,'version_info':version_info,'executable':executable,
                'executable_file':{'canonical':executable_canonical,'row':files[executable_canonical]},
                'implementation':implementation,'flags':flags,'observer_source_rows':frozen_source_rows,
                'bodies_embedded':False,'execution_admission_issued':False},
      'stdlib':{'modules':loaded,'files':{name:row for name,row in files.items() if name!=executable_canonical},
                'builtin_or_frozen':special,'excluded_loaded':excluded,
                'scope':'CURRENT_LOADED_ORIGINS_ONLY_NOT_EXECUTED_BYTE_OR_WHOLE_STDLIB_PROOF','bodies_embedded':False},
      'dpkg':{'status_file':{'bytes':len(status),'sha256':sha(status)},'packages':packages,
              'scope':'INSTALLED_RECORDS_NOT_BINARY_OWNERSHIP_BUILD_PROOF'}}
    raw=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
    need(len(raw)<=256*1024,'provenance-output-budget');live()
    return result
