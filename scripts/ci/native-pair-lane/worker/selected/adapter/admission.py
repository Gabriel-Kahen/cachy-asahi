# SPDX-License-Identifier: MIT
"""Explicit Root bootstrap capabilities; observations are not issued here.

There is no native observer, lease issuer, selection, or enabled default. Root
must admit these bootstrap objects from its held Source policy. Exact Python
types prevent accidental duck-typed PASS grants; this is not a Python sandbox.
"""
from dataclasses import dataclass
import hashlib
import math
import re
from types import MappingProxyType, ModuleType

ROOT_AUTHORITY_TYPE = None
ROOT_SOURCE_ROWS = ROOT_SOURCE_BINDING = None
SOURCE_BINDING = '8fbbcb8f5a4365e4f1a46dda6e05d03eb31b3edd76ea0dbf7f28a55633424612'
INVENTORY = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
INPUTS = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
LIBRARY_SHA = 'fe726238b170b83aa83bf1f8a79109b8b61b9eb45234304511d093bbe5f5fb20'
LABELS = ('topmem-current-1','topmem-current-2','fish-current-1','fish-current-2')
SIGNATURES = {
    'ZSTD_createDStream': ((), 'ptr'),
    'ZSTD_initDStream': (('ptr',), 'size_t'),
    'ZSTD_DCtx_setParameter': (('ptr','int','int'), 'size_t'),
    'ZSTD_decompressStream': (('ptr','out*','in*'), 'size_t'),
    'ZSTD_freeDStream': (('ptr',), 'size_t'),
    'ZSTD_isError': (('size_t',), 'uint')}
ABI = {'pointer_bits':64,'size_t_bits':64,'signatures':SIGNATURES}
STDLIB = {'math','hashlib','re','dataclasses','ctypes','json'}
JOB_KEYS = {'source_commit','workflow_commit','run_id','run_attempt','nonce','daemon_id',
            'architecture','start','J','E','inventory_sha256','inputs_sha256','epoch',
            'source_binding','observer_source_sha256','stdlib_binding','interpreter_sha256',
            'mapping_inspector_source_sha256','lease_verifier_source_sha256',
            'adapter_source_binding','bootstrap_source_sha256','holder_verifier_source_sha256'}
PLAN_KEYS={'files','directories','mkdir_reservations','noacquisition_attempts','scanners',
           'mask_reservations','backend_calls','read_requests','write_requests'}


def need(ok, code):
    if not ok: raise ValueError(code)


def record(authority,error,cleanup=False):
    try:authority.record_failure(error,cleanup=cleanup)
    except BaseException:pass


def sha(value): return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None and value != '0'*64


def relative(value):
    return (type(value) is str and 0 < len(value.encode()) <= 256
            and len(value.split('/')) <= 8
            and all(re.fullmatch('[A-Za-z0-9_.-]{1,64}',p) and p not in ('.','..') for p in value.split('/')))


def absolute(value):
    if type(value) is not str or len(value.encode())>4096 or not value.startswith('/'):return False
    if value=='/':return True
    parts=value[1:].split('/')
    return len(parts)<=32 and all(0<len(p.encode())<=255 and p not in ('.','..')
                                 and all(32<ord(c)<127 for c in p) for p in parts)


def frozen(value, depth=0, _spent=None, authority=None):
    if _spent is None:_spent=[0,0]
    _spent[0]+=1;need(_spent[0]<=2048,'grant-node-cap')
    if authority is not None:authority.check()
    need(depth<=8,'grant-depth')
    if type(value) is dict:
        need(len(value)<=128 and all(type(k) is str for k in value),'grant-map')
        for key in value:
            _spent[0]+=1;_spent[1]+=len(key.encode())
            need(_spent[0]<=2048 and len(key)<=4096 and _spent[1]<=65536,'grant-map-key-cap')
        return MappingProxyType({k:frozen(v,depth+1,_spent,authority) for k,v in value.items()})
    if type(value) in (tuple,list):
        need(len(value)<=128,'grant-sequence');return tuple(frozen(v,depth+1,_spent,authority) for v in value)
    need(type(value) in (str,int,float,bool,type(None)),'grant-data-type')
    if type(value) is float: need(math.isfinite(value),'grant-finite')
    if type(value) is str:
        _spent[1]+=len(value.encode());need(len(value)<=4096 and _spent[1]<=65536,'grant-text')
    return value


def thaw(value):
    if type(value) is MappingProxyType: return {k:thaw(v) for k,v in value.items()}
    if type(value) is tuple: return [thaw(v) for v in value]
    return value


def digest(value):
    # JSON is supplied in the admitted stdlib at execution, no input selection.
    import json
    return hashlib.sha256(json.dumps(thaw(value),sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class Route:
    root: str
    relative: str
    uid: int
    gid: int
    mode: int
    max_bytes: int
    writable: bool
    output: bool
    root_identity: object


@dataclass(frozen=True)
class Observation:
    authority: object
    job_binding: str
    observed_at: float
    evidence: object


@dataclass(frozen=True)
class FinishedLease:
    authority: object
    job_binding: str
    label: str
    container_id: str
    image_id: str
    context_sha256: str
    output_root: object
    completed_at: float
    exit_code: int
    native: bool


@dataclass(frozen=True)
class LeaseBinding:
    label: str
    container_id: str
    image_id: str
    context_sha256: str
    output_root: object


@dataclass(frozen=True)
class HolderBinding:
    kind: str
    item: object
    owner: object
    item_type: type
    owner_type: type


class HolderVerifier:
    """Root-selected exact holder objects/types, not a caller's protocol claims.

    Bootstrap holders and final core Artifacts both expose their original
    `_owner`. Root admits their class/owner Source and registers these bindings
    before the loader may call them. No resource acquisition happens here.
    """
    def __init__(self,authority,job_binding,bindings):
        need(sha(job_binding) and type(bindings) is tuple and 0<len(bindings)<=128,'holder-registration')
        self.authority,self.job_binding,self.bindings=authority,job_binding,bindings
        for binding in bindings:
            need(type(binding) is HolderBinding and binding.kind in ('source','library','dependency')
                 and type(binding.item) is binding.item_type and type(binding.owner) is binding.owner_type
                 and binding.item._owner is binding.owner and binding.owner.authority is authority,'same-job-holder-registration')

    def verify(self,item,kind,authority,job_binding):
        need(authority is self.authority and job_binding==self.job_binding,'holder-original-job')
        authority.check()
        selected=next((b for b in self.bindings if b.kind==kind and b.item is item),None)
        need(selected is not None and type(item) is selected.item_type
             and type(selected.owner) is selected.owner_type and item._owner is selected.owner
             and selected.owner.authority is authority,'same-job-selected-holder')
        need(item.verify() is True,'positive-held-verification')
        authority.check();return True


class Admission:
    """Immutable selected fields and lifetime journals, pending by default.

    The observer and lease verifier are Root-admitted Source capabilities. Their
    exact types and objects are supplied at bootstrap, never selected from data.
    They must re-observe owned current-job evidence; these dataclasses cannot
    themselves prove ARM execution, ownership or linkage behavior.
    """
    def __init__(self, authority, selection=None, *, enabled=False, observer=None,
                 observer_type=None, lease_verifier=None, lease_verifier_type=None,
                 identity_type=None, directory_identity_type=None,
                 mapping_inspector=None, mapping_inspector_type=None,
                 holder_verifier=None, holder_verifier_type=None):
        self._authority=authority; self._enabled=enabled is True
        self._observer,self._observer_type=observer,observer_type
        self._lease_verifier,self._lease_verifier_type=lease_verifier,lease_verifier_type
        self._identity_type,self._directory_identity_type=identity_type,directory_identity_type
        self._mapping_inspector,self._mapping_inspector_type=mapping_inspector,mapping_inspector_type
        self._holder_verifier,self._holder_verifier_type=holder_verifier,holder_verifier_type
        self._retained=[];self._uncertainties=[]
        self._fields=None;self._routes=MappingProxyType({});self._stdlib=MappingProxyType({})
        self._output_bindings=MappingProxyType({});self._descriptor_owner=None
        if not self._enabled: return
        try:
            need(ROOT_AUTHORITY_TYPE is not None and type(authority) is ROOT_AUTHORITY_TYPE,'original-authority-type')
            authority.check();need(authority.execution_granted is True,'original-actor-grant-pending')
            if not hasattr(authority,'_live_retained'):
                authority._live_retained=[];authority._live_uncertainties=[]
            need(type(authority._live_retained) is list and type(authority._live_uncertainties) is list,
                 'original-job-journal-type')
            self._retained=authority._live_retained;self._uncertainties=authority._live_uncertainties
            keys={'job','uid','gid','routes','source_rows','source_binding','library_row','dependencies',
                  'ABI','interpreter','loader_policy','stdlib','output_bindings','allocation_plan'}
            need(type(selection) is dict and set(selection)==keys,'closed-root-selection')
            job=selection['job'];need(type(job) is dict and set(job)==JOB_KEYS,'closed-current-job')
            need(job['start']==authority.start and job['J']==authority.J and job['E']==authority.E,'original-endpoints')
            need(all(type(job[k]) in (int,float) and math.isfinite(job[k]) for k in ('start','J','E')),'job-clock-types')
            need(type(job['source_commit']) is str and re.fullmatch('[0-9a-f]{40}',job['source_commit'])
                 and job['source_commit']==job['workflow_commit'] and job['source_commit']!='0'*40,'same-job-source')
            need(all(type(job[k]) is str and re.fullmatch('[1-9][0-9]{0,19}',job[k]) for k in ('run_id','run_attempt')),'job-run')
            need(type(job['nonce']) is str and re.fullmatch('[0-9a-f]{32}',job['nonce'])
                 and type(job['daemon_id']) is str and re.fullmatch('[A-Za-z0-9:_-]{8,128}',job['daemon_id'])
                 and job['architecture'] in ('arm64','aarch64'),'native-job')
            need(job['inventory_sha256']==INVENTORY and job['inputs_sha256']==INPUTS
                 and type(job['epoch']) is int and job['epoch']==1791748800
                 and ROOT_SOURCE_BINDING is not None
                 and job['source_binding']==selection['source_binding']==ROOT_SOURCE_BINDING,'selected-pins')
            need(all(sha(job[k]) for k in ('observer_source_sha256','stdlib_binding','interpreter_sha256',
                     'mapping_inspector_source_sha256','lease_verifier_source_sha256',
                     'adapter_source_binding','bootstrap_source_sha256','holder_verifier_source_sha256')),'root-observer-pins')
            need(type(selection['uid']) is int and type(selection['gid']) is int
                 and 0<selection['uid']<2**31 and 0<selection['gid']<2**31,'caller-uid-gid')
            routes=selection['routes'];need(type(routes) is dict and len(routes)<=128,'route-count')
            if routes:need(identity_type is not None and directory_identity_type is not None,'loaded-custody-types')
            plan=selection['allocation_plan']
            need(type(plan) is dict and set(plan)==PLAN_KEYS
                 and all(type(v) is int and v>=0 for v in plan.values()),'closed-allocation-plan')
            need(plan['files']<=128 and sum(plan[k] for k in ('files','directories','mkdir_reservations','noacquisition_attempts','scanners'))<=256
                 and plan['mask_reservations']<=1024 and plan['backend_calls']<=262144
                 and plan['read_requests']<=1024**3 and plan['write_requests']<=1024**3,'allocation-plan-capacity')
            for name,route in routes.items():
                need(relative(name) and type(route) is Route and absolute(route.root)
                     and (route.relative=='' or relative(route.relative)) and type(route.uid) is int and type(route.gid) is int
                     and min(route.uid,route.gid)>=0 and type(route.mode) is int
                     and route.mode in (0o600,0o644,0o700,0o755) and type(route.max_bytes) is int
                     and 0<=route.max_bytes<=64*1024**2 and type(route.writable) is bool and type(route.output) is bool
                     and type(route.root_identity) is directory_identity_type,'route-shape')
            need(len({(r.root,r.relative) for r in routes.values()})==len(routes),'route-alias')
            need(plan['files']>=sum(bool(r.relative) and r.mode in (0o600,0o644) for r in routes.values()),'allocation-plan-route-minimum')
            library=selection['library_row']
            need(type(library) is dict and set(library)=={'path','canonical_path','bytes','mode','sha256','uid','gid'}
                 and library['path']=='usr/lib/aarch64-linux-gnu/libzstd.so.1.5.5'
                 and library['canonical_path']=='/'+library['path'] and library['bytes']==657432
                 and type(library['bytes']) is int and library['mode']==0o644 and type(library['mode']) is int
                 and library['sha256']==LIBRARY_SHA and library['uid']==library['gid']==0
                 and type(library['uid']) is type(library['gid']) is int,'exact-library-reference')
            bindings=selection['output_bindings']
            need(type(bindings) is dict and set(bindings)=={n for n,r in routes.items() if r.output},'output-binding-membership')
            bylabel={}
            for name,binding in bindings.items():
                need(type(binding) is LeaseBinding and binding.label in LABELS and sha(binding.container_id)
                     and type(binding.image_id) is str and re.fullmatch('sha256:[0-9a-f]{64}',binding.image_id)
                     and sha(binding.image_id[7:])
                     and sha(binding.context_sha256) and binding.output_root==routes[name].root_identity,'output-binding-row')
                need(binding.label not in bylabel or bylabel[binding.label][:3]==(binding.container_id,binding.image_id,binding.context_sha256),'same-label-binding')
                bylabel[binding.label]=(binding.container_id,binding.image_id,binding.context_sha256,binding.output_root)
            if bindings:
                need(set(bylabel)==set(LABELS) and len({b[0] for b in bylabel.values()})==4
                     and len({b[1] for b in bylabel.values()})==1 and len({b[2] for b in bylabel.values()})==1,'four-distinct-selected-containers')
            rows=selection['source_rows'];need(ROOT_SOURCE_ROWS is not None and type(rows) is dict
                 and set(rows)=={'authority.py','artifact_custody.py','zstd_owner.py','pair_archive.py','pair_compare.py','checker.py'},'source6-membership')
            total=0
            for name,row in rows.items():
                need(type(row) is dict and set(row)=={'bytes','mode','sha256'}
                     and type(row['bytes']) is int and 0<row['bytes']<=4*1024**2
                     and type(row['mode']) is int and row['mode']==0o644 and sha(row['sha256']),'source6-row')
                total+=row['bytes']
            need(total<=4*1024**2 and rows==ROOT_SOURCE_ROWS
                 and digest(frozen(rows,authority=authority))==ROOT_SOURCE_BINDING,'exact-source6')
            abi=selection['ABI'];need(type(abi) is dict and set(abi)==set(ABI)
                 and type(abi['pointer_bits']) is type(abi['size_t_bits']) is int
                 and abi==ABI,'typed-arm-ABI')
            policy=selection['loader_policy'];need(type(policy) is dict and set(policy)=={'mapping_policy','latency','exclusive_fd_owner'}
                 and type(policy['exclusive_fd_owner']) is bool
                 and policy=={'mapping_policy':'held-fd-exact-mapped-closure','latency':'observe-late-refuse','exclusive_fd_owner':True},'loader-policy')
            dependencies=selection['dependencies'];need(type(dependencies) is dict and 0<len(dependencies)<=64,'linked-closure-required')
            for name,row in dependencies.items():
                need(relative(name) and type(row) is dict and set(row)=={'bytes','mode','sha256','uid','gid'}
                     and type(row['bytes']) is int and 0<row['bytes']<=64*1024**2 and sha(row['sha256'])
                     and type(row['mode']) is int and row['mode'] in (0o644,0o755)
                     and type(row['uid']) is int and type(row['gid']) is int and row['uid']==row['gid']==0,'linked-row')
            interpreter=selection['interpreter'];need(type(interpreter) is dict and set(interpreter)=={'path','bytes','mode','sha256','uid','gid'}
                 and absolute(interpreter['path']) and sha(interpreter['sha256'])
                 and interpreter['sha256']==job['interpreter_sha256'] and type(interpreter['bytes']) is int
                 and 0<interpreter['bytes']<=64*1024**2 and type(interpreter['mode']) is int and interpreter['mode']==0o755
                 and type(interpreter['uid']) is int and type(interpreter['gid']) is int
                 and interpreter['uid']==interpreter['gid']==0,'interpreter-row')
            stdlib=selection['stdlib'];need(type(stdlib) is dict and set(stdlib)==STDLIB
                 and all(type(m) is ModuleType and m.__name__==name for name,m in stdlib.items()),'stdlib-module-selection')
            data={k:v for k,v in selection.items() if k not in ('routes','stdlib','output_bindings')}
            self._fields=frozen(data,authority=authority);self._routes=MappingProxyType(dict(routes));self._stdlib=MappingProxyType(dict(stdlib))
            self._output_bindings=MappingProxyType(dict(bindings))
            self.check('descriptor' if routes else 'source')
        except BaseException as error:
            record(authority,error);raise

    @property
    def authority(self):return self._authority
    @property
    def enabled(self):return self._enabled
    @property
    def routes(self):return self._routes
    @property
    def stdlib(self):return self._stdlib
    @property
    def identity_type(self):return self._identity_type
    @property
    def directory_identity_type(self):return self._directory_identity_type
    @property
    def route_type(self):return Route
    @property
    def exclusive_fd_owner(self):return self.enabled and self.loader_policy['exclusive_fd_owner'] is True
    @property
    def mapping_inspector(self):
        need(self._mapping_inspector_type is not None and type(self._mapping_inspector) is self._mapping_inspector_type,'mapping-inspector-type')
        return self._mapping_inspector
    @property
    def output_bindings(self):return self._output_bindings
    @property
    def retained(self):return tuple(self._retained)
    @property
    def uncertainties(self):return tuple(self._uncertainties)

    def __getattr__(self,name):
        if self._fields is not None and name in self._fields:return self._fields[name]
        raise AttributeError(name)

    def authenticate(self,kind,authority):
        need(authority is self.authority,'same-original-authority');return self.check(kind)

    def verify_holder(self,item,kind):
        try:
            need(type(kind) is str and kind in ('source','library','dependency'),'holder-kind')
            self.check('source' if kind=='source' else 'library')
            need(self._holder_verifier_type is not None
                 and type(self._holder_verifier) is self._holder_verifier_type,'holder-verifier-type')
            need(self._holder_verifier.verify(item,kind,self.authority,digest(self.job)) is True,'positive-holder-proof')
            self.authority.check();return True
        except BaseException as error:
            record(self.authority,error);raise

    def check(self,kind):
        try:
            need(type(kind) is str and kind in ('descriptor','source','library','cleanup','lease'),'grant-kind')
            need(self.enabled and self._fields is not None,'root-current-job-grant-pending')
            now=self.authority.check(cleanup=kind=='cleanup')
            spent=getattr(self.authority,'_live_admission_checks',0)
            need(type(spent) is int and spent<786432,'original-job-grant-check-cap')
            self.authority._live_admission_checks=spent+1
            need(type(self._observer) is self._observer_type and self._observer_type is not None,'root-observer-type')
            observed=self._observer.capture(kind)
            after=self.authority.check(cleanup=kind=='cleanup')
            need(type(observed) is Observation and observed.authority is self.authority
                 and observed.job_binding==digest(self.job) and type(observed.observed_at) in (int,float)
                 and math.isfinite(observed.observed_at) and now<=observed.observed_at<=after,'fresh-current-job-observation')
            expected={'job':self.job,'source_binding':self.source_binding,'stdlib_binding':self.job['stdlib_binding'],
                      'library_row':self.library_row,'dependencies':self.dependencies,'ABI':self.ABI,
                      'interpreter':self.interpreter,'exclusive_fd_owner':True}
            need(type(observed.evidence) is MappingProxyType and observed.evidence==frozen({k:thaw(v) for k,v in expected.items()}),'current-selected-evidence')
            self.authority.check(cleanup=kind=='cleanup')
            return True
        except BaseException as error:
            record(self.authority,error,cleanup=kind=='cleanup');raise

    def output_owned(self,name):
        try:return self._output_owned(name)
        except BaseException as error:
            record(self.authority,error);raise

    def _output_owned(self,name):
        self.check('lease');route=self.routes.get(name)
        need(route is not None and route.output,'selected-output-route')
        need(type(self._lease_verifier) is self._lease_verifier_type and self._lease_verifier_type is not None,'root-lease-verifier-type')
        lease=self._lease_verifier.verify(name)
        observed_now=self.authority.check()
        expected=self.output_bindings[name]
        need(type(lease) is FinishedLease and lease.authority is self.authority and lease.job_binding==digest(self.job)
             and lease.label==expected.label and lease.container_id==expected.container_id
             and lease.image_id==expected.image_id and lease.context_sha256==expected.context_sha256
             and lease.output_root==expected.output_root==route.root_identity and type(lease.exit_code) is int and lease.exit_code==0
             and lease.native is True and type(lease.completed_at) in (int,float) and math.isfinite(lease.completed_at)
             and self.authority.start<=lease.completed_at<=observed_now<self.authority.E,'positive-finished-owned-lease')
        self.authority.check();return True

    def claim_descriptor_ops(self,owner):
        try:
            self.check('descriptor')
            need(owner is not None and self._descriptor_owner is None
                 and getattr(self.authority,'_live_descriptor_owner',None) is None,'one-descriptor-adapter-lifetime')
            self._descriptor_owner=owner
            self.authority._live_descriptor_owner=owner
            self.retain('descriptor-owner','original-job',owner)
        except BaseException as error:
            record(self.authority,error);raise

    def retain(self,kind,key,resource):
        need(type(kind) is str and type(key) is str and len(kind)<=64 and len(key)<=256 and resource is not None,'retained-shape')
        self._retained.append((kind,key,resource))  # Adopt before the fallible cap check.
        need(len(self._retained)<=128,'retained-resource-cap')

    def uncertain(self,kind,key):
        if len(self._uncertainties)<128:self._uncertainties.append((kind,key))
        record(self.authority,RuntimeError('uncertain-'+str(kind)))
