# SPDX-License-Identifier: MIT
"""Explicit original574 Apps-only data closure. Never execute or refresh ldconfig."""
import hashlib,json,os,re,stat,sys
from pathlib import Path
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
sys.path.insert(0,str(ROOT/'scripts/update'))
import aux_checkpoint as aux
import aux_copy
import full_root as roots
import root_link_selection as links

PURPOSE='APPS_ORIGINAL574_READONLY_CLOSURE'
LOCK_SHA256='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
VERSIONS={'cachy-asahi-apps':'0.1.0-5','cachy-asahi-repository-runtime':'0.1.0-1',
          'cachy-asahi-cache':'0.2.0-1','cachy-asahi-orphans':'0.1.0-1'}
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

def _measure(root,limits):
    value=roots.observe(root,limits=limits,hardlinks='generic-development-internal')
    links.check(value,limits);return value,aux.checkpoint(root,value,limits)

def measure(root,limits):
    """Read-only raw observation; measured ineligible flags are not rewritten."""
    return _measure(root,limits)[0]

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

def pinned_json(path,pin,read):
    raw=read(Path(path).absolute(),65536);need(re.fullmatch('[0-9a-f]{64}',pin or '') and sha(raw)==pin,'policy-or-lease-pin')
    def unique(pairs):
        result={}
        for key,value in pairs:need(key not in result,'duplicate-policy-or-lease-key');result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=unique);need(type(value) is dict,'policy-or-lease-object');return value

class Adapter:
    def __init__(self,args,backend,budget):
        self.t,self.limits=backend,budget
        read=backend.B.client.read_path
        self.policy=pinned_json(args.full574_policy,args.full574_policy_sha256,read)
        self.lease=pinned_json(args.full574_lease,args.full574_lease_sha256,read)
        p,l=self.policy,self.lease
        common={'schema_version','purpose','snapshot_sha256','extraction_receipt_sha256','source_tree_sha256','source_packages_sha256','source_closure_sha256'}
        need(set(p)==common|{'baseline_lock_sha256','candidates'} and set(l)==common|{'token','source','source_identity'},'policy-or-lease-fields')
        need(type(p['schema_version']) is type(l['schema_version']) is int and p['schema_version']==l['schema_version']==1 and p['purpose']==l['purpose']==PURPOSE,'policy-or-lease-purpose')
        for key in common-{'schema_version','purpose'}:
            need(type(p[key]) is str and re.fullmatch('[0-9a-f]{64}',p[key]) and l[key]==p[key],'policy-lease-'+key)
        need(p['baseline_lock_sha256']==LOCK_SHA256 and type(p['candidates']) is dict and set(p['candidates'])==set(VERSIONS),'finite-original574-selection')
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
            snapshot_sha256=p['snapshot_sha256'],extraction_receipt_sha256=p['extraction_receipt_sha256'])
        self.comparator=aux.load_comparator(ROOT/'scripts/ci/full-development-composition/audio_aux.py',budget)
        self.source_check()

    def source_check(self):
        need(self.t.inode(self.source)==self.lease['source_identity'],'source-lease-inode')
        fd=roots._open_root(self.source)
        try:need(os.fstatvfs(fd).f_flag&os.ST_RDONLY,'leased-source-must-be-readonly')
        finally:os.close(fd)
        observation,state=_measure(self.source,self.limits)
        aux.need(len(self.comparator.parse(state['aux_bytes']))>0,'source-aux-parse')
        need(digest(observation['nodes'])==self.policy['source_tree_sha256'] and
            digest(canonical_state(state))==self.policy['source_closure_sha256'],'native-source-snapshot-or-closure')
        return observation,state

    def observe(self,root,budget):
        value,state=_measure(root,budget)
        original,source_state=self.source_check()
        baseline_nodes(original['nodes'],value['nodes'],self.payloads)
        need(digest(canonical_state(scan_view(state)))==digest(canonical_state(scan_view(source_state))),'copy-baseline-closure')
        self.comparator.parse(state['aux_bytes'])
        return value

    def source_inventory(self,inventory):
        inventory_check(inventory,source=True)
        need(digest(inventory['packages'])==self.policy['source_packages_sha256'],'source-inventory-pin')

    def owner(self,owner):
        need(owner['source']==str(self.source) and owner['source_tree_sha256']==self.policy['source_tree_sha256'] and
            owner['copy'].get('apps_full574_binding')==self.binding,'copy-policy-lease-binding')

    def copy(self,source,target,**kwargs):
        need(Path(source)==self.source,'copy-source-lease')
        value=aux_copy.copy_data(source,target,**kwargs);value['apps_full574_binding']=self.binding;return value

    def selection(self,add,remove,inventory,before):
        inventory_check(inventory)
        need((set(add)|set(remove))<=VERSIONS.keys() and all(v==VERSIONS[n] for n,v in (add|remove).items()),'Apps-only-current-four-selection')
        installed={r['name'] for r in inventory['packages']}
        for name in installed&VERSIONS.keys():
            need(all(before.get(n)==v for n,v in self.payloads[name].items()),'installed-current-candidate-payload')

    def archive(self,name,path,nodes):
        need(name in VERSIONS and nodes==self.payloads[name] and sha(self.t.B.client.read_path(path,self.t.I.MAX_ARCHIVE))==self.policy['candidates'][name]['archive_sha256'],'exact-current-candidate-archive-payload')

    def old_payload(self,nodes):
        allowed={n:row for payload in self.payloads.values() for n,row in payload.items()}
        need(all(n in allowed and row==allowed[n] for n,row in nodes.items()),'installed-current-candidate-payload')

    def project(self,before,payload,**kwargs):
        projected=roots.projected_internal_hardlinks(links.view(before,self.limits),payload,**kwargs)
        return links.restore_literals(projected,before['nodes'])

    def preserve(self,root,before,after,**kwargs):
        roots.check_hardlink_preservation(links.view(before,self.limits),links.view(after,self.limits),**kwargs)
        state=aux.checkpoint(root,after,self.limits)
        need(hasattr(self,'baseline'),'missing-before-closure')
        return unchanged(self.baseline,state,self.comparator)

    def capture(self,root,observation):
        self.baseline=aux.checkpoint(root,observation,self.limits)

def connect(args,backend,budget):
    values=[getattr(args,n,None) for n in ('full574_policy','full574_policy_sha256','full574_lease','full574_lease_sha256')]
    if not any(values):return None
    need(all(values),'explicit-policy-and-lease-required')
    return Adapter(args,backend,budget)
