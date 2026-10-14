# SPDX-License-Identifier: MIT
"""Root-selected integrated pair bootstrap. Import alone has no actors.

Root supplies the current native Source selection and admits this exact closure.
No default platform, dependency row, interpreter or execution grant is invented.
"""
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time
from types import MappingProxyType

API='integrated-pairs-v2'
CORE_BINDING='e436b9c3d3046db3b05b1731400c9f8cbe06197ba39109ce62b595ccd29c3fca'
ADAPTER_BINDING='15d7f1c67988b24d9479f0045440f5091c37254450f0e054825d06a302d4a201'
CORE=('authority.py','artifact_custody.py','zstd_owner.py','pair_archive.py','pair_compare.py','checker.py')
ADAPTER=('admission.py','descriptor_ops.py','source_library_loader.py')
LABEL_MAP={'topmem-1':'topmem-current-1','topmem-2':'topmem-current-2',
           'fish-1':'fish-current-1','fish-2':'fish-current-2'}

def need(ok,code):
    if not ok:raise ValueError(code)

def digest(value):return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()

def rows(value):return {name:{k:row[k] for k in ('bytes','mode','sha256')} for name,row in value.items()}

def bind_api(admission_module,descriptor_module,loader_module):
    """Narrow successor for the selected loader's missing public type property."""
    base=admission_module.Admission
    class BoundAdmission(base):
        __pair_base__=base
        @property
        def mapping_inspector_type(self):return self._mapping_inspector_type
    admission_module.Admission=BoundAdmission
    descriptor_module.ROOT_ADMISSION_TYPE=loader_module.ROOT_ADMISSION_TYPE=BoundAdmission
    return BoundAdmission

def counted_inspector(base):
    """Count actual selected mapping observations in the same original job."""
    class CountedInspector(base):
        __pair_base__=base
        def __init__(self,*args):
            super().__init__(*args);self.preflight_calls=self.proof_calls=0
        def preflight(self,*args):
            self.authority.check();self.preflight_calls+=1
            result=super().preflight(*args);self.authority.check();return result
        def verify(self,*args):
            self.authority.check();self.proof_calls+=1
            result=super().verify(*args);self.authority.check();return result
    return CountedInspector

class OriginalClock:
    """One clock domain; a failure can only shorten the existing recovery end."""
    def __init__(self,start,J,clock):
        self.start,self.J,self.clock=start,J,clock
        self.recovery_end=J-180;self.last=start;self.first_at=None
    def __call__(self):
        now=self.clock()
        need(type(now) in (int,float) and math.isfinite(now) and now>=self.last,'integrated-clock-regression')
        self.last=now
        need(now<self.recovery_end,'integrated-recovery-cutoff')
        return now
    def fail(self,at):
        need(type(at) in (int,float) and math.isfinite(at) and self.start<=at<=self.last,'integrated-first-clock')
        self.first_at=at if self.first_at is None else min(at,self.first_at)
        self.recovery_end=min(self.recovery_end,self.first_at+180)
    def cleanup(self):
        now=self();need(now<self.recovery_end,'integrated-original-cleanup-cutoff');return now

class BufferOwner:
    """Immutable pinned Source buffers; owns no numeric descriptors."""
    def __init__(self,authority):self.authority=authority;self.items=[];self.requested=0

class BufferArtifact:
    def __init__(self,owner,path,raw,row):
        self._owner=owner;self.path=path;self.raw=raw;self.row=dict(row);self.position=0
        self.size=len(raw);self.mode=row['mode'];self.sha256=row['sha256'];owner.items.append(self)
        self.verify()
    def verify(self):
        self._owner.authority.check()
        need(self in self._owner.items and type(self.raw) is bytes and
             {'bytes':len(self.raw),'mode':self.mode,'sha256':hashlib.sha256(self.raw).hexdigest()}==self.row,
             'bootstrap-immutable-buffer-pin')
        self._owner.authority.check();return True
    def rewind(self):self.verify();self.position=0;self.verify()
    def read(self,n):
        self.verify();need(type(n)is int and 0<n<=65536,'bootstrap-buffer-read-bound')
        self._owner.requested+=n;need(self._owner.requested<=16*1024**2,'bootstrap-buffer-lifetime-read-bound')
        result=self.raw[self.position:self.position+n];self.position+=len(result);self.verify();return result

class Session:
    """Actual bridge setup under one original Authority, pending Root admission."""
    def __init__(self,driver,value,pins,*,clock=time.monotonic):
        self.driver,self.value,self.pins=driver,value,pins;self.runtime=None;self.bridge=None
        plan=pins['integration']
        need(type(plan)is dict and set(plan)=={'core','adapter','bridge','capabilities','capacity','native'},'closed-integration-pins')
        native=plan['native']
        need(type(native)is dict and set(native)=={'execution_granted','dependencies','interpreter','stdlib','mapping_grant','checker_root'},'closed-native-selection')
        need(native['execution_granted'] is True,'root-native-execution-admission-pending')
        need(type(plan['core'])is dict and set(plan['core'])==set(CORE) and digest(rows(plan['core']))==CORE_BINDING,'integrated-core-selection')
        need(type(plan['adapter'])is dict and set(plan['adapter'])==set(ADAPTER) and digest(rows(plan['adapter']))==ADAPTER_BINDING,'integrated-adapter-selection')
        self.core_rows=rows(plan['core']);self.adapter_rows=rows(plan['adapter'])
        E=value['workflow_end']-360;self.clock=OriginalClock(value['original_entry'],value['workflow_end'],clock)
        self.raw={}
        def captured(row):
            raw=driver.load_pin({k:row[k] for k in ('path','sha256')},E)
            need(len(raw)==row['bytes'] and row['mode']==0o644,'integration-source-size-mode')
            return raw
        for name in CORE:self.raw[name]=captured(plan['core'][name])
        authority_module=driver.module(self.raw['authority.py'],'pair_bootstrap_authority',end=E)
        # The second private graph's Authority class is never instantiated.
        self.authority=authority_module.Authority(value['original_entry'],value['workflow_end'],E,
            clock=self.clock,cancelled=lambda:False,execution_granted=plan['native']['execution_granted'] is True,
            cancel_types=(authority_module.Cancelled,KeyboardInterrupt,SystemExit,TimeoutError))
        original_record=self.authority.record_failure
        def record(error,cleanup=False):
            # Inner custody loops observe this same clipped clock immediately.
            original_record(error,cleanup=cleanup)
            self._clip_failure(error)
        self.authority.record_failure=record
        self.authority.check()
        self.adapters={name[:-3]:driver.module(captured(plan['adapter'][name]),'pair_adapter_'+name[:-3],end=E) for name in ADAPTER}
        self.bridge_module=driver.module(captured(plan['bridge']),'pair_integrated_bridge',end=E)
        self.capabilities=driver.module(captured(plan['capabilities']),'pair_integrated_capabilities',end=E)
        self.capacity=driver.module(captured(plan['capacity']),'pair_integrated_capacity',end=E)
        a=self.adapters['admission'];a.ROOT_AUTHORITY_TYPE=type(self.authority)
        a.ROOT_SOURCE_ROWS=self.core_rows;a.ROOT_SOURCE_BINDING=CORE_BINDING
        bind_api(a,self.adapters['descriptor_ops'],self.adapters['source_library_loader'])
        loader=self.adapters['source_library_loader']
        loader.ROOT_SOURCE_ROWS=MappingProxyType({k:MappingProxyType(dict(v)) for k,v in self.core_rows.items()})
        loader.ROOT_SOURCE_BINDING=CORE_BINDING
        self.buffer_owner=BufferOwner(self.authority)
        self.buffers={n:BufferArtifact(self.buffer_owner,n,self.raw[n],self.core_rows[n]) for n in CORE}
        self.authority.check()

    def fail(self,error):
        try:self.authority.record_failure(error)
        except BaseException:pass
        self._clip_failure(error)

    def _clip_failure(self,error):
        try:
            observed=self.clock.last
            now=self.clock.clock();self.clock.last=max(self.clock.last,now)
            # Conservatively charge from the last observed guard if the core
            # records an exception without a process failure timestamp.
            at=getattr(error,'first_failure_at',None)
            if at is None:at=observed
            self.clock.fail(at)
        except BaseException:
            self.clock.first_at=self.value['original_entry']
            self.clock.recovery_end=min(self.clock.recovery_end,self.value['original_entry']+180)

    def stage(self,runtime,recipes):
        """Keep Runtime FD ownership separate; flatten selected checker inputs."""
        self.runtime=runtime;self.authority.check();p=self.pins['integration'];native=p['native']
        need(type(native)is dict and set(native)=={'execution_granted','dependencies','interpreter','stdlib','mapping_grant','checker_root'},'closed-native-selection')
        need(native['execution_granted'] is True,'root-native-execution-admission-pending')
        files=runtime.files;E=self.authority.E
        root=Path(native['checker_root'])
        need(root.is_absolute() and '..' not in root.parts,'checker-root-canonical')
        files.directory(root,E,uid=self.value['uid'])
        d=files.paths[str(root)][2]
        need(d[4]==self.value['gid'] and stat.S_IMODE(d[2]) in (0o700,0o755),'checker-root-owner-mode')
        # Root selects a path that passes the full capacity tape; no cap increases.
        self.staged_root=root;self.staged={};self.source_nodes={};self.recipe_nodes={}
        def capture(row,*,target=None,uid=None):
            node,_=files.file(row['path'],E,sha=row['sha256'],size=row['bytes'],mode=row['mode'],uid=uid,cap=64*1024**2)
            if target is not None:
                path=files.copy(node,root/(self.value['nonce']+'-'+target),E,mode=row['mode'])
                node,_=files.file(path,E,sha=row['sha256'],size=row['bytes'],mode=row['mode'],uid=self.value['uid'],cap=64*1024**2)
            return node
        for i,(name,row) in enumerate(p['core'].items()):self.source_nodes[name]=capture(row,target='c'+str(i))
        for i,(name,row) in enumerate(recipes.items()):
            family='topmem' if '/cachy-asahi-topmem/' in name else 'fish'
            self.recipe_nodes[name]=capture({'path':str(Path(self.value['source_root'])/name),**row},target='r'+str(i))
        inv={'path':self.value['inventory_path'],'bytes':6674,'mode':0o644,'sha256':'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'}
        self.inventory_node=capture(inv,target='inventory.lock')
        loader=self.adapters['source_library_loader'];self.library_row=dict(loader.LIBRARY_REFERENCE)
        self.library_node=capture({'path':self.library_row['canonical_path'],**{k:self.library_row[k] for k in ('bytes','mode','sha256')}},uid=0)
        self.dependency_nodes={name:capture({'path':'/'+name,**row},uid=0) for name,row in native['dependencies'].items()}
        self.interpreter_node=capture(native['interpreter'],uid=0)
        bootstrap={
            'observer_source_sha256':p['capabilities'],'mapping_inspector_source_sha256':p['capabilities'],
            'lease_verifier_source_sha256':p['capabilities'],'holder_verifier_source_sha256':p['adapter']['admission.py'],
            'bootstrap_source_sha256':{'path':self.value['helper_bundle']['path'],'sha256':self.value['helper_bundle']['sha256'],
                'bytes':self.pins['bootstrap_bytes'],'mode':0o644}}
        def full(row,node):return {'path':str(node[0]),'bytes':row['bytes'],'mode':row['mode'],'sha256':row['sha256'],'uid':node[2][3],'gid':node[2][4]}
        runtime.capability_nodes={'source':self.source_nodes,'library':self.library_node,'dependencies':self.dependency_nodes,
            'interpreter':self.interpreter_node,'bootstrap':{},'adapter':{},'stdlib':{}}
        runtime.capability_pins={'bootstrap':{},'adapter':{},'stdlib':{}}
        for kind,data in (('bootstrap',bootstrap),('adapter',p['adapter']),('stdlib',native['stdlib'])):
            for name,row in data.items():
                node=capture(row);runtime.capability_nodes[kind][name]=node;runtime.capability_pins[kind][name]=full(row,node)
        self.authority.check()

    def load_graph(self):
        """Real twenty-reread loader; immutable buffers have a separate budget."""
        a=self.adapters['admission'];r=self.runtime;native=self.pins['integration']['native'];job={
            'source_commit':self.value['source_commit'],'workflow_commit':self.value['workflow_commit'],
            'run_id':self.value['run_id'],'run_attempt':self.value['run_attempt'],'nonce':self.value['nonce'],
            'daemon_id':self.value['daemon_id'],'architecture':'aarch64','start':self.authority.start,'J':self.authority.J,'E':self.authority.E,
            'inventory_sha256':a.INVENTORY,'inputs_sha256':a.INPUTS,'epoch':1791748800,'source_binding':CORE_BINDING,
            'adapter_source_binding':ADAPTER_BINDING,'stdlib_binding':a.digest(r.capability_pins['stdlib']),
            'interpreter_sha256':native['interpreter']['sha256']}
        job.update({name:row['sha256'] for name,row in r.capability_pins['bootstrap'].items()})
        self.job=job
        # Root admits these exact current interpreter modules; no project import.
        import math,hashlib,re,dataclasses,ctypes,json
        stdlib=dict(math=math,hashlib=hashlib,re=re,dataclasses=dataclasses,ctypes=ctypes,json=json)
        selection={'job':job,'uid':self.value['uid'],'gid':self.value['gid'],'routes':{},'source_rows':self.core_rows,
            'source_binding':CORE_BINDING,'library_row':self.library_row,'dependencies':native['dependencies'],
            'ABI':a.ABI,'interpreter':native['interpreter'],'loader_policy':{'mapping_policy':'held-fd-exact-mapped-closure',
            'latency':'observe-late-refuse','exclusive_fd_owner':True},'stdlib':stdlib,'output_bindings':{},
            'allocation_plan':dict.fromkeys(a.PLAN_KEYS,0)}
        self.selection=selection
        observer=self.capabilities.RuntimeObserver(self.authority,r,selection,a)
        binding=a.digest(a.frozen(job,authority=self.authority))
        verifier=a.HolderVerifier(self.authority,binding,tuple(a.HolderBinding('source',v,self.buffer_owner,BufferArtifact,BufferOwner) for v in self.buffers.values()))
        self.source_admission=a.Admission(self.authority,selection,enabled=True,observer=observer,observer_type=type(observer),
            holder_verifier=verifier,holder_verifier_type=a.HolderVerifier)
        loader=self.adapters['source_library_loader']
        self.modules=load_graph_buffers(self.buffers,self.core_rows,self.authority,self.source_admission,loader)
        self.authority.check();return self.modules

    def prepare_checker(self,reservations,evidence,image,context):
        a=self.adapters['admission'];c=self.modules['artifact_custody'];r=self.runtime
        def directory(node):
            v=node[2];return c.DirectoryIdentity(v[0],v[1],v[3],v[4],stat.S_IMODE(v[2]),'directory')
        def route(node,*,output=False,root=None,relative=None):
            path=Path(node[0]);parent=Path(root) if root is not None else path.parent
            r.files.directory(parent,self.authority.E)
            root_node=r.files.paths[str(parent)]
            return a.Route(str(parent),str(relative) if relative is not None else path.name,
                node[2][3],node[2][4],stat.S_IMODE(node[2][2]),node[2][6],False,output,directory(root_node))
        selected={};roles={'sources':{},'recipes':{},'inventory':'inventory.lock','library':self.library_row['path'],
            'dependencies':{},'packages':{},'locks':{}}
        for kind,nodes in (('sources',self.source_nodes),('recipes',self.recipe_nodes),('dependencies',self.dependency_nodes)):
            for name,node in nodes.items():
                virtual=name if kind!='dependencies' else name
                need(virtual not in selected,'integration-route-collision');selected[virtual]=route(node);roles[kind][name]=virtual
        selected['inventory.lock']=route(self.inventory_node);selected[self.library_row['path']]=route(self.library_node)
        bindings={};bounds={}
        for old,canonical in LABEL_MAP.items():
            spec=evidence[old];package='cachy-asahi-'+('topmem' if old.startswith('topmem') else 'fish-bang-bang')+'-0.1.0-1-any.pkg.tar.zst'
            output=spec['root'];rootnode=r.files.paths[str(output)];rootidentity=directory(rootnode)
            binding=a.LeaseBinding(canonical,reservations[canonical].row['id'],image,context,rootidentity)
            for name in (package,'packages.lock'):
                virtual=canonical+'/'+name;selected[virtual]=route(spec['nodes'][name],output=True);bindings[virtual]=binding
                roles['packages' if name==package else 'locks'][canonical]=virtual
            selected[canonical]=a.Route(str(output),'',self.value['uid'],self.value['gid'],rootidentity.mode,0,False,True,rootidentity)
            bindings[canonical]=binding;bounds[canonical]={n:spec['evidence'][n] for n in spec['evidence']}
        selection=dict(self.selection,routes=selected,output_bindings=bindings)
        # Concrete planner refuses missing rows, deep routes or excess lifetime work.
        planned=self.capacity.make_plan_for_routes(self.pins['integration']['native']['dependencies'],selected,bounds,
            selected={'core':self.core_rows,'adapter':self.adapter_rows,'recipes19':dict(c.SOURCE19),
                'inventory':{'bytes':6674,'mode':0o644,'sha256':a.INVENTORY},'library_reference':self.library_row},optimized=True)
        selection['allocation_plan']=planned['allocation_plan'];self.capacity_tape=planned
        r.capability_selection=selection
        observer=self.capabilities.RuntimeObserver(self.authority,r,selection,a)
        r.capability_observer=observer
        leases=self.capabilities.FinishedLeaseVerifier(self.authority,r,a,self.job,reservations,selection=selection)
        grant=self.pins['integration']['native']['mapping_grant']
        need(type(grant)is dict,'root-native-mapping-grant-shape')
        inspector=counted_inspector(self.capabilities.ELFMappingInspector)(self.authority,self.capabilities.NativeMappingGrant(**grant),r)
        self.inspector=inspector
        admission=a.Admission(self.authority,selection,enabled=True,observer=observer,observer_type=type(observer),
            lease_verifier=leases,lease_verifier_type=type(leases),identity_type=c.Identity,directory_identity_type=c.DirectoryIdentity,
            mapping_inspector=inspector,mapping_inspector_type=type(inspector),holder_verifier=None,holder_verifier_type=a.HolderVerifier)
        pair=self.modules['pair_compare']
        common={'nonce':self.value['nonce'],'source_commit':self.value['source_commit'],'context_sha256':context,
            'daemon':{'id':self.value['daemon_id'],'architecture':'aarch64'},'image_id':image,
            'entry_script_sha256':self.driver.ENTRY_SHA,'toolchain':dict(pair.TOOLCHAIN),'inventory_sha256':a.INVENTORY,
            'inventory_count':341,'epoch':1791748800,'source19_sha256':pair.digest(pair.SELECTED_INPUTS),
            'checker_source_sha256':CORE_BINDING,'decoded_metadata_source_sha256':self.core_rows['pair_archive.py']['sha256']}
        expected=dict(common,schema_version=1,reservations={k:v.row['id'] for k,v in reservations.items()},packages={
            name:{'artifact':'cachy-asahi-'+('topmem' if name=='topmem' else 'fish-bang-bang')+'-0.1.0-1-any.pkg.tar.zst',
                  'recipe_inputs':pair.SELECTED_INPUTS[name],'recipe_metadata':pair.SELECTED_METADATA[name]} for name in ('topmem','fish')})
        self.bridge=self.bridge_module.CheckerBridge.from_loaded(self.authority,self.modules,self.adapters,admission,expected,roles,
            recovery_check=self.clock.cleanup,failure_callback=r.fail,
            descriptor_type=self.capacity.bind_descriptor_type(self.adapters['descriptor_ops'].DescriptorOps),
            output_membership={LABEL_MAP[k]:sorted(v['evidence']) for k,v in evidence.items()})
        self.authority.check();return self.bridge

    def cleanup(self):
        self.clock.cleanup()
        if self.bridge is None:return {'status':'NO_CHECKER_ALLOCATIONS','mapping_retirement':'NO_MAPPING_ATTEMPT'}
        result=self.bridge.close();self.clock.cleanup()
        ops=self.bridge.ops;tokens=ops._tokens;backend=ops.backend
        need(result['status']=='CONTAINMENT_REQUIRED' and len(self.bridge.builds)==4 and self.bridge._result is not None,
             'complete-native-checker-path-required')
        measured={'files':len(self.bridge.owner._artifacts),'directories':len(ops._dirs),
            'mkdir_reservations':sum(t.kind=='mkdir' for t in tokens),
            'noacquisition_attempts':sum(t.kind=='fd' and t.fd is None and t.identity is None and t.state=='RETIRED' for t in tokens),
            'scanners':sum(t.kind=='scanner' for t in tokens),'mask_reservations':backend.mask_allocations,
            'backend_calls':ops.backend_calls,'read_requests':ops.read_bytes,'write_requests':ops.write_bytes,
            'grant_checks':self.authority._live_admission_checks,'cleanup_calls':ops.cleanup_calls,
            'mapping_preflight':self.inspector.preflight_calls,'mapping_proofs':self.inspector.proof_calls,
            'fd_mapping':len(self.bridge.loader.mappings),'check_artifact':len(self.bridge.builds),'finalize_pairs':1}
        self.capacity.verify_whole_counters(self.capacity_tape,measured);self.clock.cleanup()
        self.capacity_tape['observed_whole_counters']=measured
        self.capacity_tape['source_buffer_requested_bytes']=self.buffer_owner.requested
        self.capacity_tape['current_successful_path_within_declared_caps']=True
        return result


def load_graph_buffers(buffers,expected,authority,admission,loader,*,compiler=None):
    """Twenty complete held-buffer rereads without repeated pure-getter grants.

    This explicit integration successor retains the selected compiler/import
    graph. Source buffers have exact trusted types and immutable bytes, rather
    than external descriptor getters. Every compiler lookup and call remains a
    separately guarded admission boundary. One Authority retains all spending.
    """
    from types import ModuleType
    def gate():loader.authenticate(admission,authority,'source')
    gate();mapping_type=getattr(loader,'SourceModuleMapping');gate()
    gate();mapping=mapping_type();gate()
    mapping.authority=authority;mapping.source_artifacts=buffers
    def closure():
        gate();need(type(buffers)is dict and set(buffers)==set(CORE) and expected==rows({n:dict(admission.source_rows[n]) for n in CORE}),
            'buffer-graph-six-selection')
        result={};total=0
        for name in CORE:
            authority.check();item=buffers[name]
            need(type(item)is BufferArtifact and type(item._owner)is BufferOwner and item._owner.authority is authority,
                 'buffer-graph-exact-holder')
            need(admission.verify_holder(item,'source') is True,'buffer-graph-positive-holder')
            item.rewind();raw=bytearray()
            for _ in range(128):
                authority.check()
                if len(raw)==expected[name]['bytes']:break
                block=item.read(min(65536,expected[name]['bytes']-len(raw)))
                authority.check();need(type(block)is bytes and block,'buffer-graph-short-read');raw.extend(block)
            authority.check();need(item.read(1)==b'' and len(raw)==expected[name]['bytes'] and
                item.mode==expected[name]['mode'] and hashlib.sha256(raw).hexdigest()==expected[name]['sha256'],'buffer-graph-body-pin')
            authority.check();result[name]=bytes(raw);total+=len(raw)
        need(total<=loader.SOURCE_TOTAL,'buffer-graph-total');gate();return result
    try:
        gate();need(loader._rows(expected)==expected and admission.source_binding==CORE_BINDING,'buffer-graph-authoritative-selection')
        admission.retain('integrated-source-load',CORE_BINDING,mapping);gate()
        backend=loader.SourceCompiler() if compiler is None else compiler
        def call(method,*args):
            gate();callback=getattr(backend,method);gate()
            gate();value=callback(*args);gate();return value
        closure()
        for name in CORE:
            stem=name[:-3];private='_pair_'+CORE_BINDING+'.'+stem;adopted=[]
            def adopt(module):
                need(not adopted and type(module)is ModuleType and module.__name__==private,'buffer-graph-module-adoption')
                mapping.modules[stem]=module;adopted.append(module)
            module=call('allocate',private,adopt)
            need(len(adopted)==1 and module is adopted[0],'buffer-graph-unadopted-module')
            bodies=closure();code=call('compile',bodies[name],private);closure()
            def importer(request,globals=None,locals=None,fromlist=(),level=0,_stem=stem):
                gate();need(type(request)is str and level==0 and request in loader.GRAPH[_stem] and
                    type(fromlist)in(tuple,list) and '*' not in fromlist,'buffer-graph-closed-import')
                if request in loader.STDLIB:value=admission.stdlib[request]
                else:
                    need(request in mapping.executed,'buffer-graph-import-order');value=mapping.modules[request]
                gate();return value
            call('execute',code,module,importer,admission.stdlib);closure();mapping.executed.add(stem)
        closure();gate();mapping.complete=True;return MappingProxyType(dict(mapping.modules))
    except BaseException as error:
        try:authority.record_failure(error)
        except BaseException:pass
        mapping.uncertainties.append('partial-or-unknown-module-initialization')
        try:admission.uncertain('integrated-source-load',CORE_BINDING)
        except BaseException:pass
        raise authority.primary if authority.primary is not None else error
