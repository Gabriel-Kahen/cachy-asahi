# SPDX-License-Identifier: MIT
"""Explicit original574 Apps-only data closure. Never execute or refresh ldconfig."""
import hashlib,io,json,os,re,stat,sys,tarfile
from pathlib import Path
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
sys.path.insert(0,str(ROOT/'scripts/update'))
import aux_checkpoint as aux
import aux_copy
import full_root as roots
import root_link_selection as links
# Dedicated Apps helper; shared observers and copiers remain unchanged.
import importlib.util
_spec=importlib.util.spec_from_file_location("_apps574_file_capabilities",Path(__file__).with_name("file_capabilities.py"))
caps=importlib.util.module_from_spec(_spec);sys.modules[_spec.name]=caps;_spec.loader.exec_module(caps)

_copy_spec=importlib.util.spec_from_file_location("_apps574_copy_scope",Path(__file__).with_name("full574_copy.py"))
copy_scope=importlib.util.module_from_spec(_copy_spec);sys.modules[_copy_spec.name]=copy_scope;_copy_spec.loader.exec_module(copy_scope)

PURPOSE='APPS_ORIGINAL574_READONLY_CLOSURE'
EXECUTION_BUDGET=dict(backend_seconds=600,caller_seconds=610)
LOCK_SHA256='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
VERSIONS={'cachy-asahi-apps':'0.1.0-6','cachy-asahi-repository-runtime':'0.1.0-1',
          'cachy-asahi-cache':'0.2.0-1','cachy-asahi-orphans':'0.1.0-2'}
SCAN_DATA='usr/lib/cachy-asahi-apps'
need=aux.need
sha=lambda raw:hashlib.sha256(raw).hexdigest()
encoded=lambda obj:(json.dumps(obj,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
digest=lambda obj:sha(encoded(obj))

def source_bytes(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
    try:
        info=os.fstat(fd);need(stat.S_ISREG(info.st_mode) and info.st_size<=128*1024,'candidate-source-shape')
        with os.fdopen(os.dup(fd),'rb') as stream:raw=stream.read(128*1024+1)
        need(len(raw)==info.st_size and roots._identity(info)==roots._identity(os.fstat(fd))==roots._identity(path.lstat()),'candidate-source-drift')
        return raw
    finally:os.close(fd)

_fast_spec=importlib.util.spec_from_file_location("_apps574_statx_binding",Path(__file__).with_name("full574_statx.py"))
fast=importlib.util.module_from_spec(_fast_spec);sys.modules[_fast_spec.name]=fast;_fast_spec.loader.exec_module(fast)
scoped=fast.bind(ROOT,roots,caps,copy_scope,aux_copy,source_bytes)
roots,caps,copy_scope,aux=scoped.roots,scoped.caps,scoped.copy_scope,scoped.aux

def current_payloads():
    """Exact current recipe outputs, including archive directories; no ELF input."""
    result={}
    for package in VERSIONS:
        files={};recipe=ROOT/'packages/tools'/package
        def add(source,target,mode=0o644):
            raw=source_bytes(recipe/source);need(not raw.startswith(b'\x7fELF'),'candidate-source-shape')
            files[target]=dict(type='file',mode=mode,uid=0,gid=0,bytes=len(raw),sha256=sha(raw))
        for name in ('README.md','NOTICE','LICENSE'):
            add(name,('usr/share/doc/' if name=='README.md' else 'usr/share/licenses/')+package+'/'+name)
        if package=='cachy-asahi-apps':
            add(package,'usr/bin/'+package,0o755)
            for name in ('apps.py','inventory.py','helper-pins.json'):add(name,SCAN_DATA+'/'+name)
            add('source-provenance.json','usr/share/doc/'+package+'/source-provenance.json')
        elif package=='cachy-asahi-repository-runtime':
            for name,sub in (('client.py','client'),('release.py','release'),('source_delivery.py','release')):
                add(name,'usr/share/cachy-asahi/repository-runtime/scripts/'+sub+'/'+name)
            for name in ('source-provenance.json','helper-pins.json'):add(name,'usr/share/doc/'+package+'/'+name)
        else:
            add(package,'usr/bin/'+package,0o755)
            if package=='cachy-asahi-orphans':add('protection-floor.json','usr/share/'+package+'/protection-floor.json')
        for name in tuple(files):
            for parent in Path(name).parents:
                if str(parent)!='.':files.setdefault(str(parent),dict(type='directory',mode=0o755,uid=0,gid=0))
        result[package]=files
    return result

def candidate_metadata(raw):
    """Current four archives are script/data only, including their PAX metadata."""
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r|*') as stream:
        count=0
        for member in stream:
            count+=1
            need(count<=128 and set(member.pax_headers)<={'path','linkpath','mtime','atime','ctime'},'candidate-xattrs-or-unknown-pax-refused')
    return 'NO_CAPABILITIES_OR_OTHER_XATTRS'

@fast.traced('tree-and-aux-observation')
def _measure(root,limits):
    value=roots.observe(root,limits=limits,hardlinks='generic-development-internal')
    links.check(value,limits);return value,aux.checkpoint(root,value,limits)

def measure(root,limits):
    """Read-only raw observation; measured ineligible flags are not rewritten."""
    return _measure(root,limits)[0]

@fast.traced('complete-capability-map')
def capability_map(root,observation,limits,expected=None):
    mapping=caps.observe(root,observation['nodes'],limits)
    need(expected is None or mapping==expected,'original574-security-capabilities-changed')
    return mapping

def canonical_state(state):
    """Content closure across data copies; inode identities stay in live comparisons."""
    return {key:({name:row['node'] for name,row in state[key].items()} if key in
        ('helper','configs','aliases','scan','targets','caches') else sha(state[key]) if type(state[key]) is bytes else state[key])
        for key in state}

def scan_view(state):
    # glibc scans usr/lib nonrecursively. Only this exact non-DSO data directory
    # is a candidate output; all files below it are independently source-pinned.
    value=dict(state);value['scan']=dict(state['scan']);row=value['scan'].pop(SCAN_DATA,None)
    if row is not None:need(row['node']==dict(type='directory',mode=0o755,uid=0,gid=0),'candidate-scan-directory')
    value['closure']=tuple(name for name in state['closure'] if name!=SCAN_DATA)
    return value

def unchanged(before,after,comparator):
    """No committed=True waiver: main AND auxiliary cache must remain raw equal."""
    result=aux.compare(scan_view(before),scan_view(after),comparator,committed=False)
    result.update(auxiliary_inode_liveness='NOT_ESTABLISHED_SOURCE_SNAPSHOT_KEYS',helper_execution='NOT_RUN')
    return result

def inventory_check(inventory,*,source=False):
    rows=inventory['packages'];need(type(rows) is list and 574<=len(rows)<=578,'original574-package-count')
    versions={r['name']:r['version'] for r in rows};need(len(versions)==len(rows),'duplicate-package')
    selected=versions.keys()&VERSIONS.keys()
    need(not source or not selected,'source-must-be-original574')
    need(all(versions[n]==VERSIONS[n] for n in selected),'candidate-version')
    raw=''.join(n+' '+versions[n]+'\n' for n in sorted(versions.keys()-VERSIONS.keys())).encode()
    need(len(versions.keys()-VERSIONS.keys())==574 and sha(raw)==LOCK_SHA256,'original574-lock')

def baseline_nodes(source,current,payloads):
    """Keep the full original tree, including every base DB and user-state byte."""
    allowed={n:row for payload in payloads.values() for n,row in payload.items()}
    need(all(current.get(n)==row for n,row in source.items()),'original574-baseline-node-changed')
    for name in current.keys()-source.keys():
        node=current[name]
        if name in allowed:
            need(node==allowed[name],'candidate-node-shape');continue
        if name=='var/lib/pacman/db.lck':
            need(node['type']=='file' and node['bytes']==0,'own-alpm-lock-shape');continue
        # Normal ALPM9 local entries only. Collector/replanning independently
        # validate the complete signed package metadata before any transaction.
        matched=False
        for package,version in VERSIONS.items():
            prefix='var/lib/pacman/local/'+package+'-'+version
            if name==prefix:
                need(node['type']=='directory' and node['uid']==node['gid']==0 and node['mode']==0o755,'candidate-db-directory');matched=True;break
            if name in {prefix+'/'+part for part in ('desc','files','mtree')}:
                need(node['type']=='file' and node['uid']==node['gid']==0 and node['mode']==0o644 and node['bytes']<=4*1024**2 and 'hardlink_group' not in node,'candidate-db-file');matched=True;break
        need(matched,'unselected-new-node')

def reinstall_nodes(source,current,payloads,selected,installed):
    """Only authenticated selected file bytes/missing leaves differ, never the map."""
    need(selected and selected<=installed<=payloads.keys(),'repair-installed-selection')
    effective={name:dict(nodes) for name,nodes in payloads.items()};damaged={}
    for package in installed:
        for name,wanted in payloads[package].items():
            actual=current.get(name)
            if package not in selected or wanted['type']=='directory':
                need(actual==wanted,'repair-unselected-or-directory-changed');continue
            need(name not in source and wanted['type']=='file','repair-original574-or-nonfile-target')
            for parent in Path(name).parents:
                key=parent.as_posix()
                if key=='.':continue
                row=payloads[package].get(key,source.get(key))
                need(row is not None and row['type']=='directory' and current.get(key)==row,'repair-parent-metadata-or-type')
            if actual is not None:
                need(set(actual)=={'type','mode','uid','gid','bytes','sha256'} and actual['type']=='file' and all(actual[k]==wanted[k] for k in ('mode','uid','gid')) and type(actual['bytes']) is int and 0<=actual['bytes']<=128*1024 and re.fullmatch('[0-9a-f]{64}',actual['sha256']),'repair-ordinary-single-link-exact-metadata-leaf')
                effective[package][name]=actual
            if actual!=wanted:damaged[name]=actual
    baseline_nodes(source,current,effective)
    return damaged

def pinned_json(path,pin,read):
    raw=read(Path(path).absolute(),65536);need(re.fullmatch('[0-9a-f]{64}',pin or '') and sha(raw)==pin,'policy-or-lease-pin')
    def unique(pairs):
        result={}
        for key,value in pairs:need(key not in result,'duplicate-policy-or-lease-key');result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=unique);need(type(value) is dict,'policy-or-lease-object');return value

def policy_pair(args,backend):
    values=[getattr(args,n,None) for n in ('full574_policy','full574_policy_sha256','full574_lease','full574_lease_sha256')]
    need(all(values),'explicit-policy-and-lease-required')
    read=backend.B.client.read_path
    p=pinned_json(args.full574_policy,args.full574_policy_sha256,read)
    l=pinned_json(args.full574_lease,args.full574_lease_sha256,read)
    common={'schema_version','purpose','snapshot_sha256','extraction_receipt_sha256','source_tree_sha256','source_packages_sha256','source_closure_sha256','source_capabilities_sha256','execution_budget'}
    need(set(p)==common|{'baseline_lock_sha256','candidates','source_capabilities'} and set(l)==common|{'token','source','source_identity'},'policy-or-lease-fields')
    need(type(p['schema_version']) is type(l['schema_version']) is int and p['schema_version']==l['schema_version']==1 and p['purpose']==l['purpose']==PURPOSE,'policy-or-lease-purpose')
    need(all(type(v) is dict and set(v)==set(EXECUTION_BUDGET) and all(type(n) is int for n in v.values())
             for v in (p['execution_budget'],l['execution_budget'])) and
         p['execution_budget']==l['execution_budget']==EXECUTION_BUDGET,'full574-exact-execution-budget')
    for key in common-{'schema_version','purpose','execution_budget'}:
        need(type(p[key]) is str and re.fullmatch('[0-9a-f]{64}',p[key]) and l[key]==p[key],'policy-lease-'+key)
    return p,l

def execution_seconds(args,backend):
    return policy_pair(args,backend)[0]['execution_budget']['backend_seconds']

class Adapter:
    def __init__(self,args,backend,budget):
        self.t,self.limits=backend,budget
        self.policy,self.lease=policy_pair(args,backend)
        p,l=self.policy,self.lease
        need(p['baseline_lock_sha256']==LOCK_SHA256 and type(p['candidates']) is dict and set(p['candidates'])==set(VERSIONS),'finite-original574-selection')
        need(type(p['source_capabilities']) is dict and digest(p['source_capabilities'])==p['source_capabilities_sha256'],'source-capability-map-pin')
        self.payloads=current_payloads()
        for name,row in p['candidates'].items():
            need(set(row)=={'version','archive_sha256','payload_sha256'} and row['version']==VERSIONS[name] and
                re.fullmatch('[0-9a-f]{64}',row['archive_sha256']) and row['payload_sha256']==digest(self.payloads[name]),'candidate-binding')
        self.source=Path(l['source']);need(self.source.is_absolute() and self.source!=Path('/') and
            self.source.resolve(strict=True)==self.source and not any(x.is_symlink() for x in (self.source,*self.source.parents)), 'lease-source-path')
        need(type(l['token']) is str and re.fullmatch('[0-9a-f]{32}',l['token']) and l['token']==os.environ.get('CACHY_ASAHI_APPS_TRANSACTION') and
            type(l['source_identity']) is list and len(l['source_identity'])==2 and all(type(n) is int and n>=0 for n in l['source_identity']) and
            l['source_identity']==backend.inode(self.source),'source-native-lease')
        self.binding=dict(policy_sha256=args.full574_policy_sha256,lease_sha256=args.full574_lease_sha256,
            snapshot_sha256=p['snapshot_sha256'],extraction_receipt_sha256=p['extraction_receipt_sha256'],source_capabilities_sha256=p['source_capabilities_sha256'],execution_budget=dict(EXECUTION_BUDGET))
        self.comparator=aux.load_comparator(ROOT/'scripts/ci/full-development-composition/audio_aux.py',budget)
        self.source_check()

    @fast.traced('source-revalidation')
    def source_check(self):
        need(self.t.inode(self.source)==self.lease['source_identity'],'source-lease-inode')
        fd=roots._open_root(self.source)
        try:need(os.fstatvfs(fd).f_flag&os.ST_RDONLY,'leased-source-must-be-readonly')
        finally:os.close(fd)
        observation,state=_measure(self.source,self.limits)
        capability_map(self.source,observation,self.limits,self.policy['source_capabilities'])
        aux.need(len(self.comparator.parse(state['aux_bytes']))>0,'source-aux-parse')
        need(digest(observation['nodes'])==self.policy['source_tree_sha256'] and
            digest(canonical_state(state))==self.policy['source_closure_sha256'],'native-source-snapshot-or-closure')
        return observation,state

    def authorize_reinstall(self,plan,inventory,context,plan_sha256):
        """Called only inside the original authenticated, byte-equal replan context."""
        need(not hasattr(self,'repair_names') and re.fullmatch('[0-9a-f]{64}',plan_sha256),'single-authenticated-repair-plan')
        inventory_check(inventory)
        need(plan['operation']=='reinstall' and not any(plan[k] for k in ('additions','upgrades','removals','dependencies','conflicts','unchanged_selected')) and plan['before_inventory_sha256']==plan['after_inventory_sha256'] and plan['repair_policy']=='EXPLICIT_SELECTED_SAME_VERSION_AND_METADATA_ONLY_NO_DEPENDENCY_EXPANSION','repair-only-same-metadata-no-expansion')
        rows=plan['reinstalls'];need(type(rows) is list and 0<len(rows)<=4,'finite-explicit-reinstalls')
        names=[r['after']['name'] for r in rows];need(names==sorted(set(names)) and names==plan['requested_packages'] and set(names)<=VERSIONS.keys(),'exact-requested-current-reinstall-selection')
        installed={r['name']:r['version'] for r in inventory['packages']};archives={}
        for row in rows:
            name=row['after']['name'];metadata=context['available'][name];archive=[r for r in context['release']['packages'] if r['name']==name]
            need(metadata['name']==name and metadata['version']==installed.get(name)==VERSIONS[name] and len(archive)==1 and archive[0]['version']==VERSIONS[name] and archive[0]['sha256']==self.policy['candidates'][name]['archive_sha256'],'repair-signed-current-version-and-archive')
            for role,source_kind in (('before','caller-installed-inventory'),('after','signed-release')):
                item=row[role];extra={'source','metadata_sha256'}|({'release_archive_sha256'} if role=='after' else {'declared_archive_sha256'} if 'declared_archive_sha256' in item else set())
                need(set(item)==set(metadata)|extra and all(item[k]==v for k,v in metadata.items()) and item['source']==source_kind and item['metadata_sha256']==digest(metadata),'repair-exact-installed-and-signed-metadata')
            need(row['after']['release_archive_sha256']==archive[0]['sha256'] and row['before'].get('declared_archive_sha256',archive[0]['sha256'])==archive[0]['sha256'],'repair-archive-selection-drift')
            archives[name]=archive[0]['sha256']
        self.repair_names=set(names);self.repair_installed=set(installed)&VERSIONS.keys()
        self.repair_authorization=dict(plan_sha256=plan_sha256,selected=names,archives=archives,scope='AUTHENTICATED_SAME_VERSION_ORDINARY_FILE_BYTES_OR_MISSING_LEAF_ONLY')

    def observe(self,root,budget):
        value,state=_measure(root,budget)
        original,source_state=self.source_check()
        if hasattr(self,'repair_names'):reinstall_nodes(original['nodes'],value['nodes'],self.payloads,self.repair_names,self.repair_installed)
        else:baseline_nodes(original['nodes'],value['nodes'],self.payloads)
        capability_map(root,value,budget,self.policy['source_capabilities'])
        need(digest(canonical_state(scan_view(state)))==digest(canonical_state(scan_view(source_state))),'copy-baseline-closure')
        self.comparator.parse(state['aux_bytes'])
        return value

    def source_inventory(self,inventory):
        inventory_check(inventory,source=True)
        need(digest(inventory['packages'])==self.policy['source_packages_sha256'],'source-inventory-pin')

    def owner(self,owner):
        need(owner['source']==str(self.source) and owner['source_tree_sha256']==self.policy['source_tree_sha256'] and
            owner['copy'].get('apps_full574_binding')==self.binding,'copy-policy-lease-binding')

    @fast.traced('copy-with-capability-restoration')
    def copy(self,source,target,**kwargs):
        need(Path(source)==self.source,'copy-source-lease')
        self.source_check()
        value=copy_scope.copy_data(source,target,**kwargs)
        observation=measure(target,kwargs['limits'])
        baseline_nodes(self.source_check()[0]['nodes'],observation['nodes'],self.payloads)
        restored=caps.restore(target,observation['nodes'],self.policy['source_capabilities'],kwargs['limits'])
        need(restored==self.policy['source_capabilities'],'copied-capability-map')
        value.update(mount_query_binding=scoped.receipt,apps_full574_binding=self.binding,security_capabilities='EXACT_SOURCE_MAP_RESTORED_AND_VERIFIED',source_capabilities_sha256=digest(restored))
        return value

    def selection(self,add,remove,inventory,before):
        inventory_check(inventory)
        need((set(add)|set(remove))<=VERSIONS.keys() and all(v==VERSIONS[n] for n,v in (add|remove).items()),'Apps-only-current-four-selection')
        installed={r['name'] for r in inventory['packages']}
        if hasattr(self,'repair_names'):
            need(set(add)==self.repair_names and not remove,'repair-selection-differs-from-authenticated-plan')
            reinstall_nodes(self.source_check()[0]['nodes'],before,self.payloads,self.repair_names,installed&VERSIONS.keys())
        else:
            for name in installed&VERSIONS.keys():
                need(all(before.get(n)==v for n,v in self.payloads[name].items()),'installed-current-candidate-payload')

    def archive(self,name,path,nodes):
        raw=self.t.B.client.read_path(path,self.t.I.MAX_ARCHIVE)
        need(name in VERSIONS and nodes==self.payloads[name] and sha(raw)==self.policy['candidates'][name]['archive_sha256'],'exact-current-candidate-archive-payload')
        candidate_metadata(raw)

    def old_payload(self,nodes):
        allowed={n:row for payload in self.payloads.values() for n,row in payload.items()}
        if hasattr(self,'repair_names'):
            need(hasattr(self,'repair_before'),'repair-before-map-not-captured')
            allowed.update(self.repair_before)
        need(all(n in allowed and row==allowed[n] for n,row in nodes.items()),'installed-current-candidate-payload')

    def project(self,before,payload,**kwargs):
        projected=roots.projected_internal_hardlinks(links.view(before,self.limits),payload,**kwargs)
        return links.restore_literals(projected,before['nodes'])

    def preserve(self,root,before,after,**kwargs):
        roots.check_hardlink_preservation(links.view(before,self.limits),links.view(after,self.limits),**kwargs)
        state=aux.checkpoint(root,after,self.limits)
        need(hasattr(self,'baseline'),'missing-before-closure')
        capability_map(root,after,self.limits,self.baseline_caps)
        result=unchanged(self.baseline,state,self.comparator)
        result.update(security_capabilities='EXACT_SOURCE_MAP_PRESERVED',source_capabilities_sha256=digest(self.baseline_caps))
        if hasattr(self,'repair_names'):
            need(all(after['nodes'].get(n)==row for name in self.repair_names for n,row in self.payloads[name].items()),'repaired-signed-payload-not-exact')
            result['repair']=dict(self.repair_authorization,status='SELECTED_SIGNED_ORDINARY_LEAVES_RESTORED',before_damage=self.repair_damage)
        return result

    def capture(self,root,observation):
        self.baseline=aux.checkpoint(root,observation,self.limits)
        self.baseline_caps=capability_map(root,observation,self.limits,self.policy['source_capabilities'])
        if hasattr(self,'repair_names'):
            self.repair_damage=reinstall_nodes(self.source_check()[0]['nodes'],observation['nodes'],self.payloads,self.repair_names,self.repair_installed)
            self.repair_before={n:row for name in self.repair_names for n in self.payloads[name] if (row:=observation['nodes'].get(n)) is not None}

def connect(args,backend,budget):
    values=[getattr(args,n,None) for n in ('full574_policy','full574_policy_sha256','full574_lease','full574_lease_sha256')]
    if not any(values):return None
    need(all(values),'explicit-policy-and-lease-required')
    return Adapter(args,backend,budget)
