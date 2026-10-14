# SPDX-License-Identifier: MIT
"""Root-selected native observations and finished owned leases; no default grant.

Constructors are Source capabilities, not JSON policy. Root supplies the exact
Runtime, held nodes and authenticated selection. These synchronous guards refuse
late success; they cannot preempt an entered OS, linker or Python operation.
"""
from dataclasses import dataclass
import hashlib
import math
import os
import re
import stat
import struct
from types import BuiltinFunctionType, ModuleType
from importlib.machinery import BuiltinImporter, ModuleSpec


def need(ok, code):
    if not ok: raise ValueError(code)


def identity(row):
    return (row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid,row.st_nlink,
            row.st_size,row.st_mtime_ns,row.st_ctime_ns)


def record(authority,error,cleanup=False):
    try: authority.record_failure(error,cleanup=cleanup)
    except BaseException: pass


def _stdlib_role(name,module,builtin_spec=None):
    """File provenance or narrowly recognized math built into selected CPython."""
    need(type(module)is ModuleType and module.__name__==name,'native-current-stdlib-module')
    attrs=vars(module)
    if type(attrs.get('__file__'))is str:
        need(name!='math' or builtin_spec is None and attrs.get('__loader__')is not BuiltinImporter,
             'native-builtin-math-file-refused')
        return 'regular-file',attrs['__file__']
    need(name=='math' and module is math and '__file__'not in attrs,'native-builtin-math-only')
    selected=attrs.get('__spec__')
    need(type(selected)is ModuleSpec and type(builtin_spec)is ModuleSpec
         and all(type(s.name)is str and type(s.origin)is str and s.name=='math' and s.loader is BuiltinImporter and s.origin=='built-in'
                 and s.has_location is False and s.submodule_search_locations is None
                 for s in (selected,builtin_spec))
         and attrs.get('__loader__')is BuiltinImporter,'native-builtin-math-loader')
    need(all(type(attrs.get(n))is BuiltinFunctionType and attrs[n].__self__ is module
             for n in ('sqrt','isfinite')),'native-builtin-math-functions')
    return 'builtin-interpreter',None

class RuntimeObserver:
    """Nonrecursive observer using original Runtime custody and selected holders.

    Initial bounded hash authentication happens once. Every subsequent capture
    freshly verifies original full-nine held/named identities and selections.
    Mutable outputs are not immutable capability Source nodes.
    """
    def __init__(self,authority,runtime,selection,admission_module):
        self.authority,self.runtime,self.selection,self.api=authority,runtime,selection,admission_module
        self.nodes=runtime.capability_nodes;self.pins=runtime.capability_pins
        self.files=runtime.files;self.tools=dict(runtime.tools)
        self._snapshot=admission_module.digest(self._data())
        self._registered=[];self._stdlib=dict(selection['stdlib'])
        try:
            authority.check();self._binding();self._native(False)
            groups=self._groups()
            need(0<len(groups)<=128,'capability-node-cap')
            for node,row in groups:
                self._node(node,row,False)
                raw=self._read(node,False)
                need(hashlib.sha256(raw).hexdigest()==row['sha256'],'capability-initial-held-sha')
                self._node(node,row,False)
                self._registered.append((node,dict(row),tuple(node[2]),node[1]))
            authority.check()
        except BaseException as error:record(authority,error);raise

    def _data(self):
        return {k:self.selection[k] for k in ('job','uid','gid','source_rows','source_binding',
                'library_row','dependencies','ABI','interpreter','loader_policy')} | {'capability_pins':self.pins,
                'runtime':{k:self.runtime.value[k] for k in ('source_commit','workflow_commit','run_id','run_attempt',
                            'nonce','daemon_id','original_entry','workflow_end','uid','gid','socket_identity','tools','tool_closure')}}

    def _action(self,cleanup,callback,*args):
        self.authority.check(cleanup=cleanup)
        result=callback(*args)
        self.authority.check(cleanup=cleanup)
        return result

    def _native(self,cleanup):
        need(self._action(cleanup,os.getuid)==self.selection['uid']
             and self._action(cleanup,os.getgid)==self.selection['gid']
             and self._action(cleanup,os.uname).machine=='aarch64','observer-native-identity')
        need(self.runtime.value['uid']==self.selection['uid'] and self.runtime.value['gid']==self.selection['gid']
             and self.runtime.value['nonce']==self.selection['job']['nonce']
             and self.runtime.value['daemon_id']==self.selection['job']['daemon_id']
             and all(self.runtime.value[k]==self.selection['job'][k] for k in ('source_commit','workflow_commit','run_id','run_attempt'))
             and self.runtime.value['original_entry']==self.authority.start
             and self.runtime.value['workflow_end']==self.authority.J,'observer-runtime-job')
        executable=self._action(cleanup,os.stat,'/proc/self/exe')
        need(identity(executable)==tuple(self.nodes['interpreter'][2]),'observer-running-interpreter')

    def _binding(self):
        api=self.api;s=self.selection;j=s['job'];a=self.authority
        need(type(a) is api.ROOT_AUTHORITY_TYPE and a.execution_granted is True,'observer-original-execution-grant')
        need(j['start']==a.start and j['J']==a.J and j['E']==a.E
             and self.runtime.deadlines['work_end']==a.E,'observer-original-clock')
        need(s['source_rows']==api.ROOT_SOURCE_ROWS and s['source_binding']==j['source_binding']==api.ROOT_SOURCE_BINDING
             and api.digest(s['source_rows'])==j['source_binding'],'observer-selected-source')
        need(s['interpreter']['sha256']==j['interpreter_sha256']
             and api.digest(self.pins['stdlib'])==j['stdlib_binding']
             and api.digest({name:{key:row[key] for key in ('bytes','mode','sha256')}
                             for name,row in self.pins['adapter'].items()})==j['adapter_source_binding'],'observer-current-root-pins')
        fields={'observer_source_sha256','mapping_inspector_source_sha256','lease_verifier_source_sha256',
                'bootstrap_source_sha256','holder_verifier_source_sha256'}
        need(set(self.pins['bootstrap'])==fields,'observer-bootstrap-membership')
        need(all(self.pins['bootstrap'][key]['sha256']==j[key] for key in fields),'observer-bootstrap-source')
        need(set(self.nodes)=={'source','library','dependencies','interpreter','bootstrap','stdlib','adapter'}
             and set(self.nodes['source'])==set(s['source_rows'])
             and set(self.nodes['dependencies'])==set(s['dependencies'])
             and set(self.nodes['bootstrap'])==fields
             and set(self.nodes['stdlib'])==set(self.pins['stdlib'])==set(s['stdlib'])==api.STDLIB
             and set(self.nodes['adapter'])==set(self.pins['adapter']),'observer-closed-node-membership')
        need(s['loader_policy']['exclusive_fd_owner'] is True,'observer-exclusive-fd-owner')

    def _groups(self):
        s=self.selection;n=self.nodes
        return ([(n['source'][k],r) for k,r in sorted(s['source_rows'].items())]
                +[(n['library'],s['library_row'])]
                +[(n['dependencies'][k],dict(r,path='/'+k)) for k,r in sorted(s['dependencies'].items())]
                +[(n['interpreter'],s['interpreter'])]
                +[(n[group][k],r) for group in ('bootstrap','stdlib','adapter') for k,r in sorted(self.pins[group].items())])

    def _node(self,node,row,cleanup):
        files=self.runtime.files
        need(type(node) is list and len(node)==4 and node[3] is False
             and any(item is node for item in files.nodes)
             and files.paths.get(str(node[0])) is node,'observer-original-held-node')
        need(type(node[1]) is int and node[1]>=0 and type(node[2]) is tuple and len(node[2])==9,'observer-held-shape')
        before=node[2]
        held=identity(self._action(cleanup,os.fstat,node[1]))
        named=identity(self._action(cleanup,os.lstat,node[0]))
        need(held==named==before and stat.S_ISREG(held[2]) and held[5]==1,'observer-held-identity-drift')
        need(held[6]==row['bytes'] and stat.S_IMODE(held[2])==row['mode'],'observer-held-size-mode')
        if 'uid' in row:need(held[3]==row['uid'] and held[4]==row['gid'],'observer-held-owner')
        if 'path' in row:need(str(node[0])==row.get('canonical_path',row['path']),'observer-held-path')
        return held

    def _read(self,node,cleanup):
        size=node[2][6];need(0<size<=64*1024**2,'capability-read-cap')
        data=bytearray()
        while len(data)<size:
            chunk=self._action(cleanup,os.pread,node[1],min(65536,size-len(data)),len(data))
            need(type(chunk) is bytes and 0<len(chunk)<=size-len(data),'capability-short-read')
            data.extend(chunk)
        return bytes(data)

    def capture(self,kind):
        cleanup=kind=='cleanup'
        try:
            need(type(kind) is str and kind in ('descriptor','source','library','cleanup','lease'),'observer-kind')
            self.authority.check(cleanup=cleanup)
            need(self.runtime.files is self.files and set(self.runtime.tools)==set(self.tools)
                 and all(self.runtime.tools[k] is v for k,v in self.tools.items())
                 and self.runtime.capability_nodes is self.nodes and self.runtime.capability_pins is self.pins
                 and self.api.digest(self._data())==self._snapshot,'observer-selection-drift')
            self._binding();self._native(cleanup)
            end=self.authority.J if cleanup else self.authority.E
            self._action(cleanup,self.runtime.gate,end)
            groups=self._groups()
            need(len(groups)==len(self._registered),'observer-registered-membership')
            for (node,row),(original,pin,before,descriptor) in zip(groups,self._registered):
                need(node is original and row==pin and tuple(node[2])==before and node[1]==descriptor,'observer-selected-holder-drift')
                self._node(node,row,cleanup)
            for name,module in self._stdlib.items():
                need(self.selection['stdlib'][name] is module,'observer-selected-stdlib')
                builtin_spec=self._action(cleanup,BuiltinImporter.find_spec,name) if name=='math' else None
                role,path=_stdlib_role(name,module,builtin_spec)
                if role=='builtin-interpreter':
                    path=self.selection['interpreter']['path']
                    need(self.pins['stdlib'][name]==self.selection['interpreter'],
                         'observer-builtin-interpreter-provenance')
                need(path==str(self.nodes['stdlib'][name][0]),'observer-selected-stdlib')
            now=self.authority.check(cleanup=cleanup)
            s=self.selection
            evidence={'job':s['job'],'source_binding':s['source_binding'],'stdlib_binding':s['job']['stdlib_binding'],
                      'library_row':s['library_row'],'dependencies':s['dependencies'],'ABI':s['ABI'],
                      'interpreter':s['interpreter'],'exclusive_fd_owner':True}
            frozen=self.api.frozen(evidence)
            self.authority.check(cleanup=cleanup)
            return self.api.Observation(self.authority,self.api.digest(s['job']),now,frozen)
        except BaseException as error:record(self.authority,error,cleanup);raise


@dataclass(frozen=True)
class LeaseReservation:
    label: str
    ticket: int
    row: object
    completed_at: float
    source_sha256: str


class FinishedLeaseVerifier:
    """Fresh full-CID broker inspection of Root's first observed successful waits."""
    ROLES={'topmem-current-1':'topmem-1','topmem-current-2':'topmem-2',
           'fish-current-1':'fish-1','fish-current-2':'fish-2','zsh-current-1':'zsh-1','zsh-current-2':'zsh-2'}
    def __init__(self,authority,runtime,admission_module,job,reservations,*,selection=None):
        self.authority,self.runtime,self.api,self.job=authority,runtime,admission_module,job
        self.selection=runtime.capability_selection if selection is None else selection
        self.owner=runtime.owner;self.reservations=dict(reservations)
        try:
            authority.check()
            need(set(reservations)==set(self.ROLES),'lease-four-reservations')
            self.binding=admission_module.digest(job);self.snapshots={}
            self.routes=dict(self.selection['routes']);self.output_bindings=dict(self.selection['output_bindings'])
            self.rows={}
            for label,reservation in self.reservations.items():
                need(type(reservation) is LeaseReservation and reservation.label==label,'lease-reservation-type')
                row=self.owner._ticket(reservation.ticket)
                need(row is reservation.row and row['role']==self.ROLES[label],'lease-original-ticket')
                self.rows[label]=row
                self.snapshots[label]=admission_module.digest(row)
            authority.check()
        except BaseException as error:record(authority,error);raise

    def verify(self,name):
        a=self.authority;r=self.runtime;s=self.selection
        try:
            now=a.check();need(self.api.digest(self.job)==self.binding and s['job']==self.job
                 and s['routes']==self.routes and s['output_bindings']==self.output_bindings,'lease-job-drift')
            route=s['routes'].get(name);binding=s['output_bindings'].get(name)
            need(type(route) is self.api.Route and route.output and type(binding) is self.api.LeaseBinding,'lease-selected-route')
            reservation=self.reservations[binding.label];row=self.rows[binding.label];owner=self.owner
            need(r.owner is owner and not owner.cleaned and owner.first_cause is None
                 and owner.work_end==a.E and owner.daemon_id==self.job['daemon_id']
                 and owner.nonce==self.job['nonce'] and owner.context_sha==binding.context_sha256
                 and owner.source_sha==reservation.source_sha256 and owner.uid==s['uid'] and owner.gid==s['gid'],'lease-owner-binding')
            need(owner._ticket(reservation.ticket) is row and reservation.row is row
                 and self.api.digest(row)==self.snapshots[binding.label]
                 and row['role']==self.ROLES[binding.label] and row['id']==binding.container_id
                 and row['image']==binding.image_id and row['waited'] is True and type(row.get('exit_code')) is int and row['exit_code']==0
                 and row.get('confirmed') is True and row.get('start_attempted') is True and row['removed'] is False,'lease-waited-original-ticket')
            need(type(reservation.completed_at) in (int,float) and math.isfinite(reservation.completed_at)
                 and a.start<=reservation.completed_at<=now<a.E,'lease-first-completion-clock')
            a.check();item=owner._container(binding.container_id,row);a.check()
            state=item['State']
            need(state.get('Status')=='exited' and type(state.get('ExitCode')) is int and state['ExitCode']==0
                 and state.get('OOMKilled') is False and not state.get('Error'),'lease-fresh-successful-exit')
            need(item['Config']['Labels']==owner._labels(row['role']) and item['Image']==binding.image_id,'lease-fresh-label-image')
            outputs=[m for m in row['mounts'] if m['target']=='/out']
            need(len(outputs)==1 and outputs[0]['source']==route.root and outputs[0]['readonly'] is False,'lease-output-mount')
            node=r.files.paths.get(route.root)
            need(node is not None and any(n is node for n in r.files.nodes),'lease-root-held')
            a.check();held=os.fstat(node[1]);a.check();named=os.lstat(route.root);a.check()
            root=route.root_identity
            actual=lambda x:(x.st_dev,x.st_ino,x.st_uid,x.st_gid,stat.S_IMODE(x.st_mode),'directory' if stat.S_ISDIR(x.st_mode) else 'other')
            expected=(root.device,root.inode,root.uid,root.gid,root.mode,root.kind)
            need(actual(held)==actual(named)==expected and root==binding.output_root,'lease-fresh-root-identity')
            need((held.st_dev,held.st_ino,held.st_mode,held.st_uid,held.st_gid)==tuple(node[2][:5]),'lease-original-root-node')
            for callback,expected in ((os.getuid,s['uid']),(os.getgid,s['gid']),(lambda:os.uname().machine,'aarch64')):
                a.check();actual=callback();a.check();need(actual==expected,'lease-native-identity')
            a.check();r.gate(a.E);a.check()
            return self.api.FinishedLease(a,self.binding,binding.label,binding.container_id,binding.image_id,
                        binding.context_sha256,root,reservation.completed_at,0,True)
        except BaseException as error:record(a,error);raise


@dataclass(frozen=True)
class NativeMappingGrant:
    """Issued only by freshly admitted Root Source; disabled unless explicit.

    ELF structure and maps cannot prove constructor confinement or ABI behavior.
    Root's reviewed current native Source must explicitly grant those assumptions.
    """
    job_binding: str
    inspector_source_sha256: str
    library_sha256: str
    dependencies_binding: str
    interpreter_sha256: str
    abi_binding: str
    enabled: bool = False
    initialization_admitted: bool = False
    confinement_admitted: bool = False


class ELFMappingInspector:
    """Finite held-ELF/maps checks under an explicit original-job Source grant.

    No universal kernel/stdlib proof is inferred. No dlopen/dlclose occurs here.
    Map snapshots are bounded /proc reads. Failed or late disposal is retained;
    an already-entered primitive can still overrun E.
    """
    def __init__(self,authority,native_source_grant,runtime):
        self.authority,self.grant,self.runtime=authority,native_source_grant,runtime
        self.observer=runtime.capability_observer
        self._before=None;self._loads={};self.retained_maps=[]

    def _act(self,callback,*args):
        self.authority.check();value=callback(*args);self.authority.check();return value

    def _grant(self,job):
        a=self.authority;g=self.grant;s=self.runtime.capability_selection
        a.check()
        need(type(g) is NativeMappingGrant and g.enabled is True and g.initialization_admitted is True
             and g.confinement_admitted is True,'native-mapping-source-grant-pending')
        need(type(self.observer) is RuntimeObserver and self.observer.authority is a
             and self.observer.runtime is self.runtime,'mapping-original-observer')
        need(job==s['job'] and g.job_binding==self.observer.api.digest(job)
             and g.inspector_source_sha256==job['mapping_inspector_source_sha256']
             and g.library_sha256==s['library_row']['sha256']
             and g.dependencies_binding==self.observer.api.digest(s['dependencies'])
             and g.interpreter_sha256==s['interpreter']['sha256']
             and g.abi_binding==self.observer.api.digest(s['ABI']),'mapping-original-source-selection')
        self.observer.capture('library');a.check()

    def _holders(self,library,dependencies):
        s=self.runtime.capability_selection;n=self.runtime.capability_nodes
        need(type(dependencies) is dict and set(dependencies)==set(n['dependencies']),'mapping-dependency-membership')
        pairs=[(library,n['library'],s['library_row']['path'])]+[(dependencies[k],n['dependencies'][k],k) for k in sorted(dependencies)]
        for item,node,path in pairs:
            need(item._owner.authority is self.authority and item.path==path,'mapping-original-artifact')
            descriptor=self._act(getattr,item,'fd')
            need(type(descriptor) is int and descriptor>=0,'mapping-artifact-fd')
            need(identity(self._act(os.fstat,descriptor))==tuple(node[2]),'mapping-artifact-original-node')
        # The already-running Python executable is Observer-pinned. This ELF
        # closure is the explicitly selected shared library and its linker/deps.
        return [n['library'],*map(n['dependencies'].get,sorted(dependencies))]

    def _elf(self,node):
        raw=self.observer._read(node,False)
        need(len(raw)>=64 and raw[:7]==b'\x7fELF\x02\x01\x01','mapping-elf64-le')
        header=struct.unpack_from('<HHIQQQIHHHHHH',raw,16)
        kind,machine,version,_,phoff,_,_,ehsize,phsize,phnum,_,_,_=header
        need(kind==3 and machine==183 and version==1 and ehsize==64 and phsize==56
             and 0<phnum<=256 and 64<=phoff<=len(raw)-phnum*56,'mapping-arm-dyn-headers')
        loads=[];interpreter_seen=False
        for index in range(phnum):
            self.authority.check()
            ptype,flags,offset,vaddr,_,filesz,memsz,align=struct.unpack_from('<IIQQQQQQ',raw,phoff+index*56)
            need(offset<=len(raw) and filesz<=len(raw)-offset and filesz<=memsz
                 and flags&~7==0,'mapping-elf-segment-bound')
            if ptype==3:
                # Executable ET_DYN libc may name its already-selected linker.
                need(not interpreter_seen and node is not self.runtime.capability_nodes['library'] and
                     any(node is original for original in self.runtime.capability_nodes['dependencies'].values()) and 1<filesz<=4096,
                     'mapping-library-or-unbounded-PT_INTERP')
                interpreter_seen=True
                text=raw[offset:offset+filesz]
                need(text[-1:]==b'\0' and b'\0' not in text[:-1],'mapping-interpreter-string')
                interpreter=text[:-1].decode('ascii')
                need(interpreter.startswith('/') and len(interpreter)<=4096 and
                     all(p not in ('','.','..') for p in interpreter[1:].split('/')),
                     'mapping-interpreter-absolute')
                canonical=self._act(os.path.realpath,interpreter)
                dependencies=self.runtime.capability_nodes['dependencies']
                selected=dependencies.get(canonical[1:] if canonical.startswith('/') else '')
                need(selected is not None and selected is not node and
                     str(selected[0])==canonical,'mapping-selected-interpreter-required')
                self.observer._node(selected,self._pin(selected),False)
                need(identity(self._act(os.stat,interpreter))==tuple(selected[2]),
                     'mapping-interpreter-held-identity')
            if ptype==0x6474e551:need(flags&1==0,'mapping-executable-stack')
            if ptype==1:
                need(flags&3!=3 and (align in (0,1) or align>1 and align&(align-1)==0
                     and offset%align==vaddr%align),'mapping-WX-load-or-alignment')
                need(vaddr+memsz<2**64,'mapping-load-address-overflow')
                loads.append((offset,filesz,flags))
        need(loads and any(flags&1 for _,_,flags in loads),'mapping-executable-load-required')
        self.observer._node(node,self._pin(node),False)
        return tuple(loads)

    def _pin(self,node):
        return next(row for original,row in self.observer._groups() if original is node)

    def _maps(self):
        a=self.authority;slot={'fd':None,'closed':False,'uncertainty':None};self.retained_maps.append(slot)
        first=None;raw=None
        try:
            a.check();slot['fd']=os.open('/proc/self/maps',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)
            a.check();need(type(slot['fd']) is int and slot['fd']>=0,'mapping-maps-fd')
            data=bytearray()
            for _ in range(65):
                block=self._act(os.read,slot['fd'],65536)
                need(type(block) is bytes,'mapping-maps-read-type')
                if not block:break
                data.extend(block);need(len(data)<=4*1024**2,'mapping-maps-byte-cap')
            else:need(False,'mapping-maps-read-cap')
            raw=bytes(data);a.check()
        except BaseException as error:first=error;record(a,error)
        if type(slot['fd']) is int and slot['fd']>=0:
            try:
                a.check();os.close(slot['fd']);slot['fd']=None;slot['closed']=True;a.check()
            except BaseException as error:
                slot['uncertainty']=error
                if first is None:first=error;record(a,error)
        elif not slot['closed']:slot['uncertainty']='maps-open-outcome-unproved'
        if slot['closed']:
            try:self.retained_maps.remove(slot)
            except BaseException as error:
                slot['uncertainty']=error
                if first is None:first=error;record(a,error)
        if first is not None:
            try:first.retained_mapping_resources=tuple(self.retained_maps)
            except BaseException:pass
            raise first
        lines=raw.splitlines();need(0<len(lines)<=8192,'mapping-maps-line-cap')
        result=[]
        for line in lines:
            a.check();fields=line.decode('ascii').split(maxsplit=5)
            need(5<=len(fields)<=6 and re.fullmatch('[r-][w-][x-][ps]',fields[1]),'mapping-maps-row')
            addresses=fields[0].split('-');device=fields[3].split(':')
            need(len(addresses)==len(device)==2 and re.fullmatch('[0-9a-f]+',fields[2])
                 and re.fullmatch('[0-9]+',fields[4]),'mapping-maps-fields')
            start,end=map(lambda v:int(v,16),addresses);major,minor=map(lambda v:int(v,16),device)
            need(0<=start<end<2**64,'mapping-maps-address')
            result.append((start,end,fields[1],int(fields[2],16),major,minor,int(fields[4]),fields[5] if len(fields)==6 else ''))
        a.check();return tuple(result)

    def preflight(self,library,dependencies,job):
        try:
            self._grant(job);need(self._before is None and not self.retained_maps,'mapping-single-premap')
            nodes=self._holders(library,dependencies)
            self._loads={id(node):self._elf(node) for node in nodes}
            self._before=self._maps();self._grant(job);return True
        except BaseException as error:record(self.authority,error);raise

    def verify(self,mapping,library,dependencies,job):
        try:
            self._grant(job);need(mapping is not None and self._before is not None and not self.retained_maps,'mapping-premap-required')
            nodes=self._holders(library,dependencies);current=self._maps()
            need(len(nodes)<=34,'mapping-node-cap');page=self._act(os.sysconf,'SC_PAGE_SIZE')
            need(type(page) is int and page in (4096,16384,65536),'mapping-native-page-size')
            expected={(os.major(n[2][0]),os.minor(n[2][0]),n[2][1]):n for n in nodes}
            need(len(expected)==len(nodes),'mapping-aliased-closure')
            seen=set();before_exec={entry for entry in self._before if 'x' in entry[2]}
            for entry in current:
                self.authority.check();start,end,permissions,offset,major,minor,inode,path=entry
                key=(major,minor,inode)
                if key in expected:
                    node=expected[key];need(path==str(node[0]) and permissions[3]=='p'
                         and not ('w' in permissions and 'x' in permissions),'mapping-held-path-permissions')
                    loads=self._loads[id(node)]
                    requested=(4 if 'r' in permissions else 0)|(2 if 'w' in permissions else 0)|(1 if 'x' in permissions else 0)
                    need(any(requested&~flags==0 and offset>=off//page*page
                             and offset+(end-start)<=((off+size+page-1)//page)*page
                             for off,size,flags in loads),'mapping-declared-load-range-permissions')
                    if 'x' in permissions:seen.add(id(node))
                elif 'x' in permissions:need(entry in before_exec,'mapping-unexpected-new-executable')
            need(id(nodes[0]) in seen and all(id(n) in seen for n in nodes[1:]),'mapping-exact-library-linked-closure')
            self._grant(job);return True
        except BaseException as error:record(self.authority,error);raise
