# SPDX-License-Identifier: MIT
"""Root-reviewed Ubuntu24.04 ARM observation policy; import performs no actors.

Root must admit this exact Source before observe_current. JSON flags are never
inputs. CPython/stdlib/compiler, distro ELF initialization/IFUNC and Linux/linker
behavior are explicitly trusted roles after bounded current observations, not
universal kernel proofs. All effects belong to the caller's original guard.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import struct
import sys
from types import ModuleType

API = 'root-current-ubuntu-arm-selection-v1'
STDLIB = ('math','hashlib','re','dataclasses','ctypes','json')
ROOTS = ('/usr/lib/aarch64-linux-gnu','/usr/lib','/lib/aarch64-linux-gnu','/lib')
LIBRARY = {'path':'usr/lib/aarch64-linux-gnu/libzstd.so.1.5.5',
           'canonical_path':'/usr/lib/aarch64-linux-gnu/libzstd.so.1.5.5',
           'bytes':657432,'mode':0o644,
           'sha256':'fe726238b170b83aa83bf1f8a79109b8b61b9eb45234304511d093bbe5f5fb20',
           'uid':0,'gid':0}
CORE_BINDING = '7b383d3b267fad8a2891af284a055c6e8eade17f231a89f06222183b30388cd2'
ADAPTER_BINDING = 'ca21d384846e3ac1b2aa30dd655e94f91a8c730b4e03b5001754d64f8395d034'
ROLE_PINS = {'bridge': '96169422bd0e19b9b09af4c4493d6376a77619bc30aa2a10ed9e402c3e6f5139', 'capabilities': '7fd72715ff270a85039aa0de37b62f988a86d0844aa45be59040fadce36770bc', 'capacity': '3cdf93e97edee64c351712f099e0c92b16735f0d2340262d8993d83953eed2fa'}
BOOTSTRAP_PIN = 'd65104d312ccbd2c56c60f1c8c22b07418c567ee0f545b32be6344fcc98d4bd1'
ABI = {'pointer_bits':64,'size_t_bits':64,'signatures':{
    'ZSTD_createDStream':((),'ptr'),'ZSTD_initDStream':(('ptr',),'size_t'),
    'ZSTD_DCtx_setParameter':(('ptr','int','int'),'size_t'),
    'ZSTD_decompressStream':(('ptr','out*','in*'),'size_t'),
    'ZSTD_freeDStream':(('ptr',),'size_t'),'ZSTD_isError':(('size_t',),'uint')}}


def need(ok, reason):
    if not ok: raise ValueError(reason)


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def identity(row):
    return (row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink,
            row.st_size,row.st_mtime_ns,row.st_ctime_ns)


def elf(raw, *, shared=False):
    """Bounded static DT_NEEDED/PT_INTERP closure, with no ldd or dlopen."""
    need(type(raw)is bytes and len(raw)>=64 and raw[:7]==b'\x7fELF\x02\x01\x01','native-ELF64-LE')
    kind,machine,version,_,off,_,_,ehsize,phsize,count,_,_,_=struct.unpack_from('<HHIQQQIHHHHHH',raw,16)
    need(kind in (2,3) and (not shared or kind==3) and machine==183 and version==1
         and ehsize==64 and phsize==56 and 0<count<=256 and 64<=off<=len(raw)-count*56,'native-ARM-ELF-headers')
    loads=[];dynamic=None;interpreter=None
    for i in range(count):
        ptype,flags,p,v,_,size,mem,align=struct.unpack_from('<IIQQQQQQ',raw,off+56*i)
        need(p<=len(raw) and size<=len(raw)-p and size<=mem and flags&~7==0,'native-ELF-segment-bounds')
        if ptype==1:
            need(flags&3!=3 and (align in (0,1) or align&(align-1)==0 and p%align==v%align),'native-ELF-WX-alignment')
            need(v+mem<2**64,'native-ELF-load-overflow')
            loads.append((p,v,size,flags))
        elif ptype==2:
            need(dynamic is None and size%16==0 and size<=65536,'native-ELF-dynamic-bound');dynamic=(p,size)
        elif ptype==3:
            need(interpreter is None and 1<size<=4096,'native-ELF-interpreter')
            value=raw[p:p+size];need(value[-1:]==b'\0' and b'\0'not in value[:-1],'native-ELF-interpreter-string')
            interpreter=value[:-1].decode('ascii')
            need(interpreter.startswith('/') and all(p not in ('','.','..')for p in interpreter[1:].split('/'))
                 and not any(c in interpreter for c in ('\n','\r')),'native-ELF-interpreter-absolute')
        elif ptype==0x6474e551:need(flags&1==0,'native-ELF-executable-stack')
    need(loads and any(f&1 for _,_,_,f in loads),'native-ELF-executable-load')
    tags={};needed=[]
    if dynamic:
        p,size=dynamic;terminated=False
        for j in range(size//16):
            tag,value=struct.unpack_from('<qQ',raw,p+16*j)
            if tag==0:terminated=True;break
            if tag==1:needed.append(value)
            else:
                need(tag not in tags,'native-ELF-duplicate-dynamic-tag');tags[tag]=value
        need(terminated and len(needed)<=64,'native-ELF-needed-bound')
        need(not any(tag in tags for tag in (15,22,29)),'native-ELF-RPATH-TEXTREL-refused')
        need(not tags.get(30,0)&4,'native-ELF-TEXTREL-flag')
    names=[]
    if needed:
        address=tags.get(5);length=tags.get(10)
        need(type(address)is int and type(length)is int and 0<length<=1024**2,'native-ELF-string-table')
        ranges=[(p+address-v,length)for p,v,size,_ in loads if v<=address and address-v<=size and length<=size-(address-v)]
        need(len(ranges)==1,'native-ELF-string-table-load');p,length=ranges[0];table=raw[p:p+length]
        for index in needed:
            need(index<len(table),'native-ELF-needed-index');end=table.find(b'\0',index)
            need(index<end<=index+255,'native-ELF-needed-string')
            name=table[index:end].decode('ascii')
            need(re.fullmatch(r'[A-Za-z0-9._+~-]{1,255}',name) and name not in ('.','..'),'native-ELF-needed-name')
            names.append(name)
        need(len(set(names))==len(names),'native-ELF-duplicate-needed')
    return {'needed':tuple(names),'interpreter':interpreter,'kind':kind}


class OSBackend:
    """Concrete syscall roles, called only through the original guard."""
    lstat=staticmethod(os.lstat);fstat=staticmethod(os.fstat)
    open=staticmethod(os.open);pread=staticmethod(os.pread);close=staticmethod(os.close)
    realpath=staticmethod(os.path.realpath);read=staticmethod(os.read)
    getuid=staticmethod(os.getuid);getgid=staticmethod(os.getgid)
    uname=staticmethod(os.uname);readlink=staticmethod(os.readlink)
    sysconf=staticmethod(os.sysconf)
    def sha256(self,raw):return hashlib.sha256(raw).hexdigest()
    def python(self):return (sys.implementation.name,tuple(sys.version_info[:2]),sys.executable)
    def current_module(self,name):return sys.modules.get(name)
    def job_environment(self):
        return {key:os.environ.get(key)for key in ('GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_WORKFLOW_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT')}


class HeldSelection:
    """Separate observer FD ownership; never transferred to pair Runtime.files."""
    def __init__(self,guard,backend):
        self.guard,self.backend=guard,backend;self.nodes={};self.slots=[];self.tool_slots=[]
        self.calls=0;self.requested=0;self.first=None;self.closed=False;self.last=None;self.failure_at=None;self._cleanup=False
        self.value=self.native=None;self.observation={}
        self.checker=None;self.checker_nonce=None;self.checker_uid=self.checker_gid=None
    def check(self):
        need(not self.closed,'native-observer-closed')
        if self.first is not None and not self._cleanup:raise self.first
        now=self.guard.check(cleanup=self._cleanup)
        need(type(now)in(int,float) and math.isfinite(now) and (self.last is None or now>=self.last),'native-original-observation-clock')
        if self._cleanup:
            need(now<min(self.guard.J-180,self.failure_at+180 if self.failure_at is not None else self.guard.J-180),'native-original-cleanup-cutoff')
        self.last=now
    def fail(self,error):
        if self.first is None:
            self.first=error;self.failure_at=self.last if self.last is not None else self.guard.start
        try:self.guard.record_failure(error,cleanup=self._cleanup)
        except BaseException:pass
    def act(self,fn,*args,**kwargs):
        try:
            self.check();self.calls+=1;need(self.calls<=8192,'native-observation-call-cap')
            value=fn(*args,**kwargs);self.check();return value
        except BaseException as error:
            self.fail(error)
            raise
    def canonical(self,path):
        need(type(path)is str and path.startswith('/') and '..'not in Path(path).parts,'native-path')
        result=self.act(self.backend.realpath,path)
        need(type(result)is str and result.startswith('/') and len(result)<=4096,'native-canonical-path')
        return result
    def ancestors(self,path,root_owned=True):
        result=[]
        for parent in Path(path).parents:
            row=self.act(self.backend.lstat,str(parent))
            need(stat.S_ISDIR(row.st_mode) and (not root_owned or row.st_uid==0 and not row.st_mode&0o022),'native-root-ancestor')
            result.append((str(parent),identity(row)[:5]))
        return tuple(result)
    def file(self,path,*,executable=False,expected=None,root_owned=True):
        need(not self._cleanup,'native-no-cleanup-acquisition')
        path=self.canonical(path)
        if path in self.nodes:
            self.verify_node(path);node=self.nodes[path]
            if expected:need({k:node['row'][k]for k in expected}==expected,'native-fixed-library-reference-drift')
            return node
        need(len(self.nodes)<128,'native-held-file-cap')
        ancestors=self.ancestors(path,root_owned);before=self.act(self.backend.lstat,path)
        need(stat.S_ISREG(before.st_mode) and (not root_owned or before.st_uid==before.st_gid==0) and before.st_nlink==1
             and stat.S_IMODE(before.st_mode)in((0o755,)if executable else(0o644,0o755))
             and 0<before.st_size<=64*1024**2,'native-root-file')
        slot={'fd':None,'attempted':False,'closed':False,'path':path};self.slots.append(slot)
        self.check();slot['attempted']=True
        self.calls+=1;need(self.calls<=8192,'native-observation-call-cap')
        # Register the returned FD before post-check; ambiguous open is retained.
        slot['fd']=self.backend.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        self.check();need(type(slot['fd'])is int and slot['fd']>=0,'native-file-fd')
        need(identity(self.act(self.backend.fstat,slot['fd']))==identity(before),'native-open-identity')
        data=bytearray()
        while len(data)<before.st_size:
            n=min(65536,before.st_size-len(data));self.requested+=n
            need(self.requested<=256*1024**2,'native-lifetime-read-cap')
            block=self.act(self.backend.pread,slot['fd'],n,len(data))
            need(type(block)is bytes and 0<len(block)<=n,'native-short-read');data.extend(block)
        self.requested+=1;need(self.requested<=256*1024**2,'native-lifetime-read-cap');need(self.act(self.backend.pread,slot['fd'],1,len(data))==b'','native-growing-file')
        raw=bytes(data);row={'path':path,'bytes':len(raw),'mode':stat.S_IMODE(before.st_mode),
            'sha256':self.act(self.backend.sha256,raw),'uid':before.st_uid,'gid':before.st_gid}
        node={'row':row,'identity':identity(before),'ancestors':ancestors,'slot':slot,'raw':raw,'root_owned':root_owned}
        self.nodes[path]=node;self.verify_node(path)
        if expected:need({k:row[k]for k in expected}==expected,'native-fixed-library-reference-drift')
        return node
    def verify_node(self,path):
        node=self.nodes[path];slot=node['slot'];need(not slot['closed'],'native-retired-holder')
        need(identity(self.act(self.backend.fstat,slot['fd']))==node['identity'],'native-held-drift')
        need(identity(self.act(self.backend.lstat,path))==node['identity'],'native-named-drift')
        need(self.ancestors(path,node['root_owned'])==node['ancestors'],'native-ancestry-drift')

    def verify_checker(self):
        need(type(self.checker) is tuple and len(self.checker) == 5, 'native-held-checker-capability')
        path, fd, expected, parent_fd, parent_expected = self.checker
        need(type(path) is str and path == '/home/runner/cph-' + self.checker_nonce
             and type(fd) is type(parent_fd) is int and min(fd, parent_fd) >= 0 and fd != parent_fd
             and type(expected) is type(parent_expected) is tuple and len(expected) == len(parent_expected) == 5,
             'native-held-checker-binding')
        need(self.canonical('/home/runner') == '/home/runner' and self.canonical(path) == path,
             'native-checker-canonical')
        ident = lambda node: (node.st_dev, node.st_ino, node.st_mode, node.st_uid, node.st_gid)
        for ancestor in ('/', '/home'):
            row = self.act(self.backend.lstat, ancestor)
            need(stat.S_ISDIR(row.st_mode) and row.st_uid in (0, self.checker_uid)
                 and not row.st_mode & 0o022, 'native-checker-ancestor')
        for row in (self.act(self.backend.fstat, parent_fd), self.act(self.backend.lstat, '/home/runner')):
            need(ident(row) == parent_expected and stat.S_ISDIR(row.st_mode)
                 and row.st_uid in (0, self.checker_uid) and not row.st_mode & 0o022,
                 'native-held-checker-parent')
        for row in (self.act(self.backend.fstat, fd), self.act(self.backend.lstat, path)):
            need(ident(row) == expected and stat.S_ISDIR(row.st_mode)
                 and row.st_uid == self.checker_uid and row.st_gid == self.checker_gid
                 and stat.S_IMODE(row.st_mode) == 0o700, 'native-owned-shallow-checker-root')
        return path

    def verify(self,cleanup=False):
        need(type(cleanup)is bool,'native-verification-mode')
        previous=self._cleanup;self._cleanup=cleanup
        try:
            self.check()
            self.verify_checker()
            for path in self.nodes:self.verify_node(path)
            for slot in self.tool_slots:
                tool=slot['object'];need(slot['initialized'] and not slot['closed'] and type(tool.fd)is int,'native-typed-tool-holder')
                need(tool.path==slot['path'] and tool.sha256==slot['sha256'] and tuple(tool.held_identity)==slot['identity'],'native-typed-tool-binding')
                need(identity(self.act(self.backend.fstat,tool.fd))==slot['identity']
                     and identity(self.act(self.backend.lstat,tool.path))==slot['identity'],'native-typed-tool-drift')
            need(self.value is not None and digest((self.value,self.native))==self.observation['selection_binding'],'native-selection-mutated')
            self.check();return True
        except BaseException as error:
            self.fail(error)
            raise
        finally:self._cleanup=previous
    def close(self):
        # No retry or cleanup eligibility invented after cutoff/unknown close.
        need(not self.closed,'native-observer-disposal-already-attempted')
        first=self.first
        stop=False;cleanup_end=min(self.guard.J-180,self.failure_at+180 if self.failure_at is not None else self.guard.J-180)
        for slot in reversed(self.tool_slots):
            if slot['closed']:continue
            try:
                need(not stop,'native-observer-cleanup-stopped')
                need(self.guard.check(cleanup=True)<cleanup_end,'native-original-cleanup-cutoff')
                need(slot['initialized'] and type(slot['object'].fd)is int,'native-tool-construction-outcome-unproved')
                self.calls+=1;need(self.calls<=8192,'native-observation-call-cap')
                slot['object'].close();slot['closed']=True
                need(self.guard.check(cleanup=True)<cleanup_end,'native-original-cleanup-cutoff')
            except BaseException as e:
                if first is None:first=e
                stop=True;slot['uncertainty']=type(e).__name__
        for slot in reversed(self.slots):
            if slot['closed'] or not slot['attempted']:continue
            try:
                need(not stop,'native-observer-cleanup-stopped')
                need(self.guard.check(cleanup=True)<cleanup_end,'native-original-cleanup-cutoff')
                need(type(slot['fd'])is int,'native-open-outcome-unproved')
                self.calls+=1;need(self.calls<=8192,'native-observation-call-cap')
                fd=slot['fd'];slot['fd']=None;self.backend.close(fd);slot['closed']=True
                need(self.guard.check(cleanup=True)<cleanup_end,'native-original-cleanup-cutoff')
            except BaseException as e:
                if first is None:first=e
                stop=True
                slot['uncertainty']=type(e).__name__
        self.closed=True
        if first is not None:
            self.fail(first)
            try:first.retained_native_observation=self
            except BaseException:pass
            raise first
        return True
    def maps(self):
        need(not self._cleanup,'native-no-cleanup-acquisition')
        slot={'fd':None,'attempted':False,'closed':False,'path':'/proc/self/maps'};self.slots.append(slot)
        self.check();slot['attempted']=True
        self.calls+=1;need(self.calls<=8192,'native-observation-call-cap')
        slot['fd']=self.backend.open(slot['path'],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);self.check()
        need(type(slot['fd'])is int and slot['fd']>=0,'native-maps-fd')
        data=bytearray()
        for _ in range(65):
            self.requested+=65536;need(self.requested<=256*1024**2,'native-lifetime-read-cap')
            block=self.act(self.backend.read,slot['fd'],65536)
            need(type(block)is bytes,'native-maps-read-type')
            if not block:break
            data.extend(block);need(len(data)<=4*1024**2,'native-maps-byte-cap')
        else:need(False,'native-maps-read-call-cap')
        lines=bytes(data).splitlines();need(0<len(lines)<=8192,'native-maps-line-cap')
        paths=set()
        for line in lines:
            self.check();fields=line.decode('ascii').split(maxsplit=5)
            need(5<=len(fields)<=6 and re.fullmatch('[r-][w-][x-][ps]',fields[1]),'native-maps-row')
            if len(fields)==6 and 'x'in fields[1] and fields[5].startswith('/'):
                need(not fields[5].endswith(' (deleted)'),'native-deleted-executable-map');paths.add(fields[5])
        return bytes(data),paths


def _closure(owner, starts, *, cap=64):
    queue=list(starts);seen={};needed_rows={}
    while queue:
        owner.check();path,executable=queue.pop(0);path=owner.canonical(path)
        if path in seen:continue
        need(len(seen)<cap,'native-ELF-closure-cap')
        node=owner.file(path,executable=executable);info=elf(node['raw'],shared=not executable)
        seen[path]=node
        if info['interpreter']:
            queue.append((info['interpreter'],False));needed_rows[owner.canonical(info['interpreter'])]=True
        for name in info['needed']:
            choices=[]
            for directory in ROOTS:
                candidate=directory+'/'+name
                def lookup():
                    try:return owner.backend.lstat(candidate)
                    except FileNotFoundError:return None
                row=owner.act(lookup)
                if row is None:continue
                choices.append(owner.canonical(candidate))
            need(choices and len(set(choices))==1,'native-ambiguous-dependency-resolution')
            queue.append((choices[0],False));needed_rows[choices[0]]=True
    return seen,needed_rows


def _job(value,integration,stdlib,interpreter):
    caps=integration['capabilities']['sha256']
    job={k:value[k]for k in ('source_commit','workflow_commit','run_id','run_attempt','nonce','daemon_id')}
    job.update(architecture='aarch64',start=value['original_entry'],J=value['workflow_end'],E=value['workflow_end']-360,
        inventory_sha256='fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25',
        inputs_sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f',epoch=1791748800,
        source_binding=CORE_BINDING,adapter_source_binding=ADAPTER_BINDING,stdlib_binding=digest(stdlib),
        interpreter_sha256=interpreter['sha256'],observer_source_sha256=caps,mapping_inspector_source_sha256=caps,
        lease_verifier_source_sha256=caps,bootstrap_source_sha256=value['helper_bundle']['sha256'],
        holder_verifier_source_sha256=integration['adapter']['admission.py']['sha256'])
    return job


def observe_current(value,integration,*,guard,process_owner,stdlib_modules,ctypes_module,checker_node):
    """Return HeldSelection.value/.native for existing prepare_packet.make_packet.

    Root supplies exact admitted Source modules and original guard, not JSON
    authority. Caller retains this observer, verifies before launch, then retires
    only its descriptors. Pair Runtime acquires different descriptors.
    """
    return _observe(value,integration,guard,process_owner,stdlib_modules,ctypes_module,OSBackend(),checker_node)


def prepare_current_packet(packet,*,guard,process_owner,stdlib_modules,ctypes_module,checker_node):
    """Concrete existing-packet integration; returns (packet, held_observer).

    Root prepares Sources with existing make_packet and selects the capabilities
    successor row before this same-job operation. This function performs no
    unguarded artifact-preparation helper IO. The disabled native placeholder
    carries no authority; this Source produces the only enabled values.
    """
    guard.check()
    need(type(packet)is dict and set(packet)=={'value','pins'},'native-prepared-packet')
    packet=json.loads(json.dumps(packet,allow_nan=False))
    need(packet['pins']['integration']['native']=={'execution_granted':False,'dependencies':{},
         'interpreter':{},'stdlib':{},'mapping_grant':{},'checker_root':checker_node[0]},'native-disabled-placeholder-only')
    integration={k:v for k,v in packet['pins']['integration'].items()if k!='native'}
    selection=observe_current(packet['value'],integration,guard=guard,process_owner=process_owner,
        stdlib_modules=stdlib_modules,ctypes_module=ctypes_module,checker_node=checker_node)
    packet['value']=selection.value
    packet['pins']['integration']['native']=selection.native
    selection.verify();return packet,selection


def _observe(value,integration,guard,process_owner,stdlib_modules,ctypes_module,backend,checker_node):
    owner=HeldSelection(guard,backend)
    try:
        need(type(integration)is dict and set(integration)=={'core','adapter','bridge','capabilities','capacity'},'native-no-input-authority-flags')
        need(type(value)is dict and 'execution_granted'not in value and 'native'not in value,'native-no-value-grant')
        start,J,E=value['original_entry'],value['workflow_end'],value['workflow_end']-360
        need(all(type(x)in(int,float) and math.isfinite(x)for x in (start,J,E))
             and J==start+7200 and (guard.start,guard.J,guard.E)==(start,J,E),'native-original-guard-binding')
        owner.check();value=json.loads(json.dumps(value,allow_nan=False))
        environment=owner.act(backend.job_environment)
        need(environment.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'
             and value['source_commit']==value['workflow_commit']==environment.get('GITHUB_SHA')==environment.get('GITHUB_WORKFLOW_SHA')
             and value['run_id']==environment.get('GITHUB_RUN_ID') and value['run_attempt']==environment.get('GITHUB_RUN_ATTEMPT'),
             'native-current-job-binding')
        for key,pattern in (('source_commit','[0-9a-f]{40}'),('run_id','[1-9][0-9]{0,19}'),
                            ('run_attempt','[1-9][0-9]{0,9}'),('nonce','[0-9a-f]{32}')):
            need(type(value[key])is str and re.fullmatch(pattern,value[key]),'native-current-job-field')
        need(value['source_commit']!='0'*40,'native-current-Source-required')
        uid=owner.act(backend.getuid);gid=owner.act(backend.getgid)
        need(type(uid)is type(gid)is int and min(uid,gid)>0,'native-current-nonroot-identity')
        need(owner.act(backend.uname).machine=='aarch64','native-current-ARM')
        need(owner.act(backend.sysconf,'SC_PAGE_SIZE')in(4096,16384,65536),'native-page-size')
        implementation,version,executable=owner.act(backend.python)
        need(implementation=='cpython' and version==(3,12),'native-reviewed-CPython312-role')
        osrelease=owner.file('/etc/os-release')['raw'].decode('utf-8')
        metadata=dict(line.split('=',1)for line in osrelease.splitlines()if '='in line)
        need(metadata.get('ID')in('ubuntu','"ubuntu"') and metadata.get('VERSION_ID')in('24.04','"24.04"'),'native-Ubuntu2404-role')
        owner.checker=checker_node;owner.checker_nonce=value['nonce'];owner.checker_uid,owner.checker_gid=uid,gid
        checker=owner.verify_checker()
        interpreter=owner.file(executable,executable=True)['row']
        need(identity(owner.act(backend.lstat,owner.canonical('/proc/self/exe')))==owner.nodes[interpreter['path']]['identity'],'native-current-interpreter')
        need(type(stdlib_modules)is dict and set(stdlib_modules)==set(STDLIB) and stdlib_modules['ctypes']is ctypes_module,'native-current-stdlib-set')
        stdlib={}
        for name in STDLIB:
            module=stdlib_modules[name]
            need(type(module)is ModuleType and module.__name__==name and type(module.__file__)is str,'native-current-stdlib-module')
            need(owner.act(backend.current_module,name)is module,'native-existing-stdlib-object')
            node=owner.file(module.__file__)
            need(node['row']['path']==module.__file__,'native-stdlib-file-must-be-canonical')
            stdlib[name]=node['row']
        need(owner.act(ctypes_module.sizeof,ctypes_module.c_void_p)==8
             and owner.act(ctypes_module.sizeof,ctypes_module.c_size_t)==8,'native-current-typed-ABI')
        # Exact selected compiler/observer Source roles; no caller flags can admit them.
        for group in ('core','adapter'):
            rows={n:{k:r[k]for k in ('bytes','mode','sha256')}for n,r in integration[group].items()}
            need(digest(rows)==(CORE_BINDING if group=='core'else ADAPTER_BINDING),'native-selected-Source-closure')
            for row in integration[group].values():owner.file(row['path'],expected={k:row[k]for k in ('bytes','mode','sha256')},root_owned=False)
        for name in ('bridge','capabilities','capacity'):
            row=integration[name];need(row['sha256']==ROLE_PINS[name],'native-selected-compiler-observer-Source-role')
            owner.file(row['path'],expected={k:row[k]for k in ('bytes','mode','sha256')},root_owned=False)
        helper=value['helper_bundle'];need(helper['api']=='integrated-pairs-v3' and helper['sha256']==BOOTSTRAP_PIN,'native-selected-bootstrap-role')
        owner.file(helper['path'],expected={'bytes':26073,'mode':0o644,'sha256':BOOTSTRAP_PIN},root_owned=False)
        library=owner.file(LIBRARY['canonical_path'],expected={k:v for k,v in LIBRARY.items()if k not in ('path','canonical_path')})
        need(elf(library['raw'],shared=True)['interpreter']is None,'native-library-PT_INTERP-refused')
        libclosure,_=_closure(owner,[(LIBRARY['canonical_path'],False)])
        pythonclosure,_=_closure(owner,[(interpreter['path'],True)])
        need(len(libclosure)<=33,'native-mapping-closure-cap')
        deps={path[1:]:{k:node['row'][k]for k in ('bytes','mode','sha256','uid','gid')}
              for path,node in libclosure.items()if path!=LIBRARY['canonical_path']}
        # Always include current interpreter linker in admitted mapped closure.
        pyinfo=elf(owner.nodes[interpreter['path']]['raw'])
        if pyinfo['interpreter']:
            path=owner.canonical(pyinfo['interpreter']);node=pythonclosure[path]
            deps[path[1:]]={k:node['row'][k]for k in ('bytes','mode','sha256','uid','gid')}
        need(0<len(deps)<=32,'native-complete-libzstd-linker-dependencies')
        maps,mapped=owner.maps()
        need(interpreter['path']in mapped,'native-running-interpreter-map')
        for path in sorted(mapped):
            node=owner.file(path,executable=path==interpreter['path'])
            elf(node['raw'],shared=path!=interpreter['path'])
        tools={};toolclosure={}
        for kind in ('docker','gpg'):
            path='/usr/bin/'+kind;node=owner.file(path,executable=True)
            need(node['row']['path']==path,'native-tool-exact-canonical')
            tools[kind]=node['row']['sha256'];closure,_=_closure(owner,[(path,True)])
            for member,item in closure.items():
                if member!=path:toolclosure[member]=item['row']['sha256']
        need(0<len(toolclosure)<=64,'native-current-tool-closure-cap')
        socket=owner.act(backend.lstat,'/run/docker.sock')
        need(stat.S_ISSOCK(socket.st_mode) and socket.st_uid==0 and not socket.st_mode&0o002,'native-root-Docker-socket')
        # Reserve the actual caller-owned tool object before its FD constructor.
        tool=owner.act(process_owner.VerifiedTool.__new__,process_owner.VerifiedTool)
        docker_node=owner.nodes['/usr/bin/docker']
        slot={'object':tool,'initialized':False,'closed':False,'path':'/usr/bin/docker',
              'sha256':tools['docker'],'identity':docker_node['identity']};owner.tool_slots.append(slot)
        owner.requested+=docker_node['row']['bytes']+1
        need(owner.requested<=256*1024**2,'native-lifetime-read-cap')
        def initialize_tool():
            tool.__init__('/usr/bin/docker',tools['docker'],end=E,cap=docker_node['row']['bytes'])
            slot['initialized']=True
        owner.act(initialize_tool)
        result=owner.act(process_owner.run,('/usr/bin/docker','--host=unix:///run/docker.sock','info','--format','{{json .}}'),
            {'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','TZ':'UTC','HOME':checker},checker,
            tool=tool,work_end=E,cleanup_end=J-180,limit=2*1024**2)
        need(result.code==0 and type(result.stdout)is bytes and len(result.stdout)<=2*1024**2,'native-current-Docker-info')
        daemon=json.loads(result.stdout)
        need(type(daemon)is dict and daemon.get('Architecture')in('aarch64','arm64') and daemon.get('OSType')=='linux'
             and type(daemon.get('ID'))is str and re.fullmatch('[A-Za-z0-9:_-]{8,128}',daemon['ID']),'native-current-Docker-daemon')
        need(identity(owner.act(backend.lstat,'/run/docker.sock'))==identity(socket),'native-Docker-socket-drift')
        value.update(uid=uid,gid=gid,tools=tools,tool_closure=toolclosure,daemon_id=daemon['ID'],socket_identity=list(identity(socket)[:6]))
        job=_job(value,integration,stdlib,interpreter)
        native={'execution_granted':True,'dependencies':deps,'interpreter':interpreter,'stdlib':stdlib,'checker_root':checker,
            'mapping_grant':{'job_binding':digest(job),'inspector_source_sha256':integration['capabilities']['sha256'],
                'library_sha256':LIBRARY['sha256'],'dependencies_binding':digest(deps),'interpreter_sha256':interpreter['sha256'],
                'abi_binding':digest(ABI),'enabled':True,'initialization_admitted':True,'confinement_admitted':True}}
        owner.value,owner.native=value,native
        owner.observation={'policy':API,'selection_binding':digest((value,native)),'job':job,
            'trusted_roles':'Root-reviewed Ubuntu CPython312/stdlib/compiler; exact libzstd ABI and initialization; root-controlled glibc dependencies/IFUNC; native Linux held-FD mapping assumptions',
            'current_maps_sha256':digest(maps.hex()),'current_executable_map_count':len(mapped),
            'checker_root_observation':{'path':checker,'identity5':list(checker_node[2]),
                'parent_identity5':list(checker_node[4]),'Root_retains_and_retires_borrowed_FDs':True},
            'hard_wall_or_unmapping_proven':False}
        owner.verify();return owner
    except BaseException as error:
        owner.fail(error)
        try:error.retained_native_observation=owner
        except BaseException:pass
        raise
