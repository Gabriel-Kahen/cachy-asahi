#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Signed Apps transactions in an explicitly owned, offline disposable copy only."""
import argparse,ctypes,fcntl,hashlib,importlib.util,json,os,re,shutil,stat,sys,tempfile,time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
sys.dont_write_bytecode=True
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
sys.path.insert(0,str(ROOT/'scripts/update'))

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
B=load('apps_bound',ROOT/'scripts/update/bound_update.py');I=B.install
F=load('apps_full_root',ROOT/'scripts/update/full_root.py')
COPY=load('apps_safe_copy',ROOT/'scripts/update/measure_copy.py')
LIFETIME=load('apps_copy_lifetime',ROOT/'scripts/update/disposable_copy.py')
SUP=load('apps_supervision',ROOT/'scripts/update/supervision.py')
PURPOSE='OWNED_OFFLINE_DISPOSABLE_APPS_COPY'
MARKER='apps-copy.json';LOCK='apps-copy.lock';DB='var/lib/pacman'
MAX_PLAN=16*1024**2;SECONDS=300
need=I.need
sha=lambda raw:hashlib.sha256(raw).hexdigest()
encoded=lambda value:(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def execution_seconds(args=None):
 if args is None or not any(getattr(args,n,None) for n in ('full574_policy','full574_policy_sha256','full574_lease','full574_lease_sha256')):return SECONDS
 module=load('apps_full574_budget',Path(__file__).with_name('full574_closure.py'))
 return module.execution_seconds(args,sys.modules[__name__])
def limits(args=None):return F.Limits(deadline=time.monotonic()+execution_seconds(args))
def inode(path):
 info=path.lstat();return [info.st_dev,info.st_ino]
def environment_guard():
 need(os.getuid()==os.geteuid()==0,'mapped disposable root required; live host invocation refused')
 token=os.environ.get('CACHY_ASAHI_APPS_TRANSACTION','');need(re.fullmatch('[0-9a-f]{32}',token),'explicit disposable Apps owner token required')
 mapping=Path('/proc/self/uid_map').read_text().split()
 mapped=len(mapping)==3 and mapping[0]=='0' and mapping[1].isdigit() and int(mapping[1])>0 and mapping[2]=='1'
 need(mapped or Path('/.dockerenv').is_file(),'mapped namespace or explicit disposable container required')
 interfaces={line.split(':',1)[0].strip() for line in Path('/proc/net/dev').read_text().splitlines() if ':' in line}
 need(interfaces=={'lo'},'offline namespace required')
 need(os.environ.get('PATH')=='/usr/bin:/bin' and not any(k.startswith(('LD_','GPG_','ALPM_','PACMAN_')) for k in os.environ),'clean command environment required')
 return token

def observe(root,budget,closure=None):
 if closure is not None:return closure.observe(root,budget)
 value=F.observe(root,limits=budget,hardlinks='generic-development-internal');F.require_eligible(value);return value

def closure_for(args,budget):
 module=load('apps_full574_closure',Path(__file__).with_name('full574_closure.py')) if any(getattr(args,n,None) for n in ('full574_policy','full574_policy_sha256','full574_lease','full574_lease_sha256')) else None
 return module.connect(args,sys.modules[__name__],budget) if module else None

def pins(observation,inventory):
 nodes=observation['nodes'];database={n:r for n,r in nodes.items() if n==DB or n.startswith(DB+'/')}
 return dict(tree_sha256=sha(encoded(nodes)),database_sha256=sha(encoded(database)),
             packages_sha256=sha(encoded(inventory['packages'])),inventory_sha256=sha(encoded(inventory)))

def app_source(args):
 directory=Path(args.apps_source).absolute();raw=B.client.read_path(directory/'source-provenance.json',1024**2)
 need(sha(raw)==args.apps_provenance_sha256,'Apps provenance/source closure pin differs');provenance=I.decode(raw)
 expected={'apps.py','inventory.py','helper-pins.json','cachy-asahi-apps'}
 need(set(provenance['runtime_sources'])==expected,'exact Apps runtime source closure required')
 for name,row in provenance['runtime_sources'].items():
  blob=B.client.read_path(directory/name,128*1024);need(row==dict(bytes=len(blob),sha256=sha(blob)),'Apps source bytes differ: '+name)
 app=load('transaction_exact_apps',directory/'apps.py');c,r,_=app.helpers(Path(args.repository_source))
 return app,c,r

def root_guard(args):
 token=environment_guard();workspace=I.private(Path(args.workspace).absolute(),0)
 root=workspace/'root';need(root!=Path('/') and root.is_dir() and root.resolve(strict=True)==root,'canonical copied target required')
 raw=B.client.read_path(workspace/MARKER,65536);need(sha(raw)==args.ownership_sha256,'copy ownership pin differs');owner=I.decode(raw)
 need(set(owner)=={'schema_version','purpose','token','workspace','root','source','source_tree_sha256','copy'} and owner['schema_version']==1 and owner['purpose']==PURPOSE and owner['token']==token and owner['workspace']==inode(workspace) and owner['root']==inode(root),'owned copy identity differs')
 need(not any(p.is_symlink() for p in (root,*root.parents)) and (root/DB/'local').is_dir(),'copied local database required')
 return workspace,root,owner

@contextmanager
def locked(workspace):
 fd=os.open(workspace/LOCK,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  info=os.fstat(fd);need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600,'owned workspace lock required')
  fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
 finally:os.close(fd)

def dispose(workspace,identity):
 budget=F.Limits(deadline=time.monotonic()+60,max_nodes=510001)
 parent=F._open_root(workspace.parent);fd=None
 try:
  fd=F._open_root(workspace);mount=F._mount_id(parent,budget)
  LIFETIME._same(parent,workspace.name,fd,tuple(identity),mount,budget)
  LIFETIME._empty(fd,mount,budget,[0],depth=-1)
  LIFETIME._same(parent,workspace.name,fd,tuple(identity),mount,budget)
  os.rmdir(workspace.name,dir_fd=parent)
 finally:
  if fd is not None:os.close(fd)
  os.close(parent)

def prepare_copy(args):
 token=environment_guard();app,c,r=app_source(args);source=Path(args.source).absolute();workspace=Path(args.workspace).absolute()
 need(source!=Path('/') and not source.is_relative_to(workspace) and not workspace.is_relative_to(source),'disjoint explicit seed/copy required')
 I.private(workspace.parent,0);need(not workspace.exists(),'fresh copied workspace required')
 budget=limits(args);closure=closure_for(args,budget)
 inventory=app.inventory_reader().collect(source/DB,c,lambda row:app.package(row,r))
 if closure is not None:
  need(source==closure.source,'explicit leased original574 source required');closure.source_inventory(inventory)
 before=observe(source,budget,closure);workspace.mkdir(mode=0o700);identity=inode(workspace)
 try:
  # The copier reserves its declared maxima. Tighten that reservation to the
  # measured seed plus the existing bounded archive/ALPM-metadata headroom.
  copy_bytes=min(budget.max_bytes,before['footprint']['bytes']+I.MAX_TREE+64*1024**2)
  copy_budget=F.Limits(deadline=budget.deadline,max_packages=budget.max_packages,max_nodes=min(budget.max_nodes,len(before['nodes'])+30000),max_bytes=copy_bytes,max_file_bytes=min(budget.max_file_bytes,copy_bytes))
  report=(closure.copy if closure else COPY.copy_data)(source,workspace/'root',limits=copy_budget,hardlinks='generic-development-internal')
  root=workspace/'root';observation=observe(root,budget,closure);need(observation['nodes']==before['nodes'],'complete copy differs')
  inventory=app.inventory_reader().collect(root/DB,c,lambda row:app.package(row,r))
  need(len(inventory['packages'])<=budget.max_packages,'full-root package bound')
  owner=dict(schema_version=1,purpose=PURPOSE,token=token,workspace=identity,root=inode(root),source=str(source),source_tree_sha256=sha(encoded(before['nodes'])),copy=report)
  raw=encoded(owner)
  for name,data in ((MARKER,raw),(LOCK,b'')):
   fd=os.open(workspace/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
  return dict(status='OWNED_COPY_PREPARED',root=str(root),workspace=str(workspace),ownership_sha256=sha(raw),before=pins(observation,inventory),source_preserved=True,transaction='NOT_RUN',hardware='NOT_RUN')
 except BaseException:
  dispose(workspace,identity);raise

def snapshot_inputs(args,work,c):
 """Copy a finite release before authentication; every consumed byte is then authenticated."""
 original=Path(args.release).absolute();bundle=work/'bundle';bundle.mkdir();fd=c.directory(original);total=0
 try:
  raw=c.read_member(fd,'release.json');need(sha(raw)==args.release_sha256,'release caller pin differs');release=c.decode(raw)
  need(type(release.get('files')) is dict and 0<len(release['files'])<=c.MAX_FILES,'bounded signed file map required')
  (bundle/'release.json').write_bytes(raw);(bundle/'release.json.sig').write_bytes(c.read_member(fd,'release.json.sig',c.MAX_SIGNATURE))
  for name,pin in release['files'].items():
   c.relative(name)
   with c.member(fd,name) as source:
    info=os.fstat(source);need(info.st_size<=I.MAX_INPUTS-total,'aggregate private signed input limit')
   target=bundle/name;target.parent.mkdir(parents=True,exist_ok=True);actual,count=c.hash_member(fd,name,snapshot=target);total+=count
   need(actual==pin and total<=I.MAX_INPUTS,'private release snapshot differs')
  for name,target in release.get('symlinks',{}).items():
   c.relative(name);need(type(target) is str and '/' not in target and target not in ('.','..') and str(Path(name).parent/target) in release['files'],'safe repository alias required')
   (bundle/name).symlink_to(target)
 finally:os.close(fd)
 copied=SimpleNamespace(**vars(args));copied.release=str(bundle)
 for field,cap in (('catalog',c.MAX_JSON),('catalog_signature',c.MAX_SIGNATURE),('keyring',c.MAX_KEYRING)):
  raw=c.read_path(Path(getattr(args,field)).absolute(),cap);path=work/field;path.write_bytes(raw);setattr(copied,field,str(path))
 return copied

def expected_packages(app,inventory,plan,r):
 result=app.indexed(inventory['packages'],r)
 for row in plan['removals']:need(result.pop(row['name'])==app.package(row,r),'remove metadata drift')
 for row in plan['additions']+[x['after'] for x in plan['upgrades']+plan.get('reinstalls',[])]:result[row['name']]=app.package(row,r)
 need(sha(app.encoded([result[n] for n in sorted(result)]))==plan['after_inventory_sha256'],'planner after map differs')
 return result

def payload_guard(nodes,seed):
 units=load('apps_asahi_units',ROOT/'packages/tools/cachy-asahi-update/asahi-policy.py').REQUIRED_UNITS
 B.protected_payload(nodes,dict(protected_units=units),seed)
 for name,row in nodes.items():
  I.relative(name);need(name=='usr' or name.startswith('usr/'),'Apps writes outside usr refused')
  need(row['type'] in ('file','directory') and not row['mode']&0o6000,'ordinary non-setid Apps payload required')
  need(not name.endswith('.hook'),'Apps hook payload refused')
  for parent in Path(name).parents:
   if parent.as_posix() in seed:need(seed[parent.as_posix()]['type']=='directory','payload symlink ancestor refused')

def reinstall_old(paths,nodes,payload):
 old={n:nodes[n] for n in paths if n in nodes}
 for name in paths:
  target=payload.get(name)
  if name not in nodes:
   need(target is not None and target['type']=='file' and nodes.get(str(Path(name).parent),{}).get('type')=='directory','only missing selected ordinary leaf repair permitted')
  else:need(target is not None and nodes[name]['type']==target['type'] and 'hardlink_group' not in nodes[name],'selected repair type or hardlink differs')
 return old

def check_preservation(before,after,old,payload,database_changes):
 def held(nodes):return {n:v for n,v in nodes.items() if n not in old and n not in payload and not any(n==p or n.startswith(p+'/') for p in database_changes)}
 need(held(before)==held(after),'unselected payload/database/trust/user state changed')
 for name,node in payload.items():need(after.get(name)==node,'installed signed payload differs: '+name)
 for name in old.keys()-payload.keys():
  if old[name]['type']=='directory':
   need(name not in after or after[name]==old[name],'removed directory metadata changed')
  else:need(name not in after,'removed owned file remains')
 need(B.trust_rows(before)==B.trust_rows(after),'base trust changed')

def commit(alpm,add,remove,archives,architecture,result):
 """Ordinary dependency/signature checks; no sync DB, fetch, orphan or force flags."""
 for name,version in add.items():
  pointer=ctypes.c_void_p();alpm.ok(alpm.alpm_pkg_load(alpm.handle,os.fsencode(archives[name]),1,1,ctypes.byref(pointer)),'signed package load')
  need(alpm.alpm_pkg_get_name(pointer).decode()==name and alpm.alpm_pkg_get_version(pointer).decode()==version and alpm.alpm_pkg_get_arch(pointer) in (b'any',architecture.encode()),'loaded package identity differs')
  alpm.ok(alpm.alpm_add_pkg(alpm.handle,pointer),'exact package add')
 db=alpm.alpm_get_localdb(alpm.handle)
 for name,version in remove.items():
  pointer=alpm.alpm_db_get_pkg(db,name.encode());need(pointer and alpm.alpm_pkg_get_version(pointer).decode()==version,'exact removal identity differs');alpm.ok(alpm.alpm_remove_pkg(alpm.handle,pointer),'exact package remove')
 details=F.installer.Ptr();alpm.ok(alpm.alpm_trans_prepare(alpm.handle,ctypes.byref(details)),'ordinary ALPM prepare')
 need(alpm.packages(alpm.alpm_trans_get_add(alpm.handle))==add and alpm.packages(alpm.alpm_trans_get_remove(alpm.handle))==remove,'ALPM prepared a different selection')
 if add or remove:
  result.update(phase='commit',commit_started=True,packages_committed='UNKNOWN')
  details=F.installer.Ptr();alpm.ok(alpm.alpm_trans_commit(alpm.handle,ctypes.byref(details)),'ordinary ALPM commit');result['packages_committed']=True

def apply(args):
 result=dict(status='FAIL',phase='guard',commit_started=False,packages_committed=False,rollback='NOT_ATTEMPTED_DISPOSABLE_COPY_ONLY',hardware='NOT_RUN',release='NOT_ADMITTED',cleanup='NOT_ESTABLISHED')
 try:
  need(args.confirm_disposable_transaction is True,'explicit disposable transaction confirmation required')
  need(getattr(args,'operation',None) in ('install','remove','reinstall'),'explicit supported Apps operation required')
  workspace,root,owner=root_guard(args);app,c,r=app_source(args);budget=limits(args);closure=closure_for(args,budget)
  need(closure is not None or 'apps_full574_binding' not in owner['copy'],'full574 copy requires original explicit policy/lease')
  if closure is not None:closure.owner(owner)
  with locked(workspace),tempfile.TemporaryDirectory(prefix='apps-tx-',dir=workspace) as temp:
   work=Path(temp);result['phase']='observe-before'
   inventory=app.inventory_reader().collect(root/DB,c,lambda row:app.package(row,r));repair=closure is not None and args.operation=='reinstall'
   if not repair:
    before=observe(root,budget,closure);actual=pins(before,inventory)
    need(actual==dict(tree_sha256=args.before_tree_sha256,database_sha256=args.before_database_sha256,packages_sha256=args.before_packages_sha256,inventory_sha256=args.before_inventory_sha256),'complete before snapshot differs')
    need(len(inventory['packages'])<=budget.max_packages,'full-root package bound')
    if closure is not None:closure.capture(root,before)
   else:need(len(inventory['packages'])<=budget.max_packages,'full-root package bound')
   plan_raw=c.read_path(Path(args.plan).absolute(),MAX_PLAN);need(sha(plan_raw)==args.plan_sha256,'caller plan SHA256 differs')
   copied=snapshot_inputs(args,work,c);iv=work/'installed.json';iv.write_bytes(app.encoded(inventory));copied.installed=str(iv);copied.installed_sha256=sha(iv.read_bytes());copied.command='plan'
   result['phase']='authenticate-and-replan';fresh=app.execute(copied);need(app.encoded(fresh)==plan_raw,'authenticated plan differs from actual copied root')
   plan=fresh['plan'];expected=expected_packages(app,inventory,plan,r)
   need(len(expected)<=budget.max_packages,'after package bound')
   architecture=os.uname().machine
   need(fresh['synthetic'] or architecture=='aarch64','actual ARM release needs native ARM execution')
   with app.authenticated(copied,c,r) as context:
    protected=set(context['base'])|set(context['spec']['policy']['protected_packages'])
    add={row['name']:row['version'] for row in plan['additions']+[x['after'] for x in plan['upgrades']+plan.get('reinstalls',[])]};remove={row['name']:row['version'] for row in plan['removals']}
    changed=set(add)|set(remove);need(not changed&protected,'base/platform selection refused')
    if repair:
     closure.authorize_reinstall(plan,inventory,context,args.plan_sha256)
     current_inventory=app.inventory_reader().collect(root/DB,c,lambda row:app.package(row,r))
     need(app.indexed(current_inventory['packages'],r)==app.indexed(inventory['packages'],r),'repair-authentication-inventory-drift')
     before=observe(root,budget,closure);actual=pins(before,inventory)
     need(actual==dict(tree_sha256=args.before_tree_sha256,database_sha256=args.before_database_sha256,packages_sha256=args.before_packages_sha256,inventory_sha256=args.before_inventory_sha256),'complete before snapshot differs')
     closure.capture(root,before)
    if closure is not None:closure.selection(add,remove,inventory,before['nodes'])
    payload={};archives={};accounting=dict(bytes=0,nodes=0)
    for row in context['release']['packages']:
     if row['name'] not in add:continue
     path=Path(copied.release)/'repo'/row['filename'];nodes=I.archive_payload(path,accounting)
     # Reject control scriptlets even though ALPM execution flags remain disabled.
     members=r.archive_members(path);need('.INSTALL' not in members,'package scriptlet refused')
     pkginfo=r.run(['bsdtar','-xOf',path,members['.PKGINFO']]).decode()
     need(not any(line.startswith('backup = ') for line in pkginfo.splitlines()),'backup/pacsave semantics outside Apps copy scope')
     payload_guard(nodes,before['nodes'])
     if closure is not None:closure.archive(row['name'],path,nodes)
     for name,node in nodes.items():need(name not in payload or node==payload[name] and node['type']=='directory','signed payload overlap');payload[name]=node
     archives[row['name']]=path
    for name in payload:
     for parent in Path(name).parents:
      key=parent.as_posix()
      if key!='.':need(key in before['nodes'] or payload.get(key,{}).get('type')=='directory','implicit archive parent outside exact payload refused')
    keys=B.public_keys(dict(keyring=Path(copied.keyring)),work,c.fingerprint(args.signer))
    factory=lambda *a,**k:F.Alpm(*a,**k,limits=budget)
    pending=workspace/'apps-pending.json'
    fd=os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
     pending_identity=inode(pending);stream.write(encoded(dict(status='ATTEMPT_STARTED_COMMIT_OUTCOME_NOT_RECORDED',plan_sha256=args.plan_sha256,before=actual)));stream.flush();os.fsync(stream.fileno())
    parent=c.directory(workspace)
    try:os.fsync(parent)
    finally:os.close(parent)
    result['phase']='locked-recheck'
    with B.transaction(root,keys,work,factory) as alpm:
     versions={row['name']:row['version'] for row in inventory['packages']};need(alpm.inventory()==versions,'ALPM before inventory differs')
     old_names=changed&set(versions);old_paths=alpm.owned_files(old_names);others=alpm.owned_files(set(versions)-changed)
     for name in old_names:
      package=root/DB/'local'/(name+'-'+versions[name])
      need(not (package/'install').exists(),'installed scriptlet outside Apps copy scope')
      files=app.inventory_reader().sections(c.read_path(package/'files',4*1024**2),{'FILES','BACKUP'})
      need(not files.get('BACKUP'),'installed backup/pacsave semantics outside Apps copy scope')
     old=reinstall_old(old_paths-others,before['nodes'],payload) if args.operation=='reinstall' else {n:before['nodes'][n] for n in old_paths-others}
     if closure is not None:closure.old_payload(old)
     payload_guard(old,before['nodes']);need(not any('hardlink_group' in n for n in old.values()),'selected hardlink mutation refused')
     for n,node in payload.items():
      need(n not in before['nodes'] or n in old or node['type']=='directory' and node==before['nodes'][n],'unowned or unselected payload collision')
     removed={n for n,node in old.items() if node['type']!='directory' and n not in payload}
     projected=(closure.project if closure else F.projected_internal_hardlinks)(before,payload,selected_old_paths=set(old),removed_paths=removed,protected_paths=set(before['nodes'])-set(old),limits=budget)
     need(len(projected)+4*len(add)<=budget.max_nodes and sum(n.get('bytes',0) for n in projected.values())+64*1024**2<=budget.max_bytes,'projected payload plus bounded ALPM metadata exceeds root budget')
     result['capacity_precommit']=COPY.check_capacity([dict(path=str(workspace),bytes=sum(n.get('bytes',0) for n in payload.values())+80*1024**2,inodes=len(payload)+4*len(add)+1024)])
     checkpoint=observe(root,budget,closure)['nodes'];lock=checkpoint.pop(DB+'/db.lck',None);need(lock is not None and lock['type']=='file' and lock['bytes']==0 and checkpoint==before['nodes'],'root changed before prepare')
     need(sha(c.read_path(Path(args.plan).absolute(),MAX_PLAN))==args.plan_sha256,'caller plan changed')
     # Private authenticated inputs and complete root bytes are rechecked before commit.
     source=c.directory(copied.release)
     try:
      for name,pin in context['release']['files'].items():need(c.hash_member(source,name)[0]==pin,'authenticated input drift')
     finally:os.close(source)
     commit(alpm,add,remove,archives,architecture,result)
     need(alpm.inventory()=={n:p['version'] for n,p in expected.items()},'actual after ALPM inventory differs')
    result['phase']='verify-after'
    after_inventory=app.inventory_reader().collect(root/DB,c,lambda row:app.package(row,r));after=observe(root,budget,closure)
    need(app.indexed(after_inventory['packages'],r)==expected,'actual normalized after inventory differs')
    db_changes={DB+'/local/'+name+'-'+version for name in changed for version in {versions.get(name),expected.get(name,{}).get('version')} if version is not None}
    check_preservation(before['nodes'],after['nodes'],old,payload,db_changes)
    if closure is not None:
     result['full574_closure']=closure.preserve(root,before,after,protected_paths=set(before['nodes'])-set(old),limits=budget)
     result['full574_binding']=closure.binding
    else:F.check_hardlink_preservation(before,after,protected_paths=set(before['nodes'])-set(old),limits=budget)
    result.update(status='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION',phase='completed',scope='DEVELOPMENT_OWNED_OFFLINE_COPIED_ROOT_ONLY',synthetic=fresh['synthetic'],stable_accepted=False,freshness='NOT_ESTABLISHED',architecture=architecture,apps_provenance_sha256=args.apps_provenance_sha256,helper_pins=fresh['helper_pins'],operation=args.operation,prepared_add=add,prepared_remove=remove,before=actual,after=pins(after,after_inventory),plan_sha256=args.plan_sha256,binding=fresh['binding'],hooks='DISABLED_AND_NO_CANDIDATE_HOOKS',scriptlets='DISABLED_AND_NO_CANDIDATE_SCRIPTLETS',dependency_checks='ORDINARY_LIBALPM',copy_retained='EXPLICIT_OWNER_MUST_DISPOSE')
  result['cleanup']='OWNED_WORKSPACE_TEMP_AND_ALPM_HANDLE_LOCK_RELEASED'
  need(not (root/DB/'db.lck').exists(),'ALPM lock remains; no deletion attempted')
  root_guard(args)
  need(inode(pending)==pending_identity,'owned pending marker replaced')
  pending.unlink()
 except BaseException as error:
  result.update(status='FAIL',error_type=type(error).__name__,error=str(error)[:1024],recovery='DISPOSE_OWNED_COPY_ON_COMMIT_OR_CLEANUP_UNCERTAINTY_NO_ROLLBACK_CLAIM')
 return result

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('prepare-copy','inspect','apply','dispose-copy'))
 p.add_argument('--workspace',required=True);p.add_argument('--source');p.add_argument('--ownership-sha256')
 p.add_argument('--apps-source',required=True);p.add_argument('--apps-provenance-sha256',required=True);p.add_argument('--repository-source',required=True)
 for name in ('full574-policy','full574-policy-sha256','full574-lease','full574-lease-sha256'):p.add_argument('--'+name)
 for name in ('release','release-sha256','catalog','catalog-sha256','catalog-signature','keyring','signer','plan','plan-sha256','before-tree-sha256','before-database-sha256','before-packages-sha256','before-inventory-sha256'):p.add_argument('--'+name)
 p.add_argument('--operation',choices=('install','remove','reinstall'));p.add_argument('--applications',nargs='+');p.add_argument('--confirm-disposable-transaction',action='store_true');p.add_argument('--worker',action='store_true',help=argparse.SUPPRESS)
 a=p.parse_args()
 try:
  if a.action=='prepare-copy':result=prepare_copy(a)
  elif a.action=='inspect':
   workspace,root,owner=root_guard(a);app,c,r=app_source(a);budget=limits(a);closure=closure_for(a,budget)
   need(closure is not None or 'apps_full574_binding' not in owner['copy'],'full574 copy requires original explicit policy/lease')
   with locked(workspace):
    inventory=app.inventory_reader().collect(root/DB,c,lambda row:app.package(row,r))
    if closure is not None:closure.owner(owner);closure.selection({},{},inventory,observe(root,budget,closure)['nodes'])
    result=dict(status='OBSERVED_OWNED_COPY',before=pins(observe(root,budget,closure),inventory))
  elif a.action=='dispose-copy':
   workspace,root,owner=root_guard(a)
   with locked(workspace):
    need(not (root/DB/'db.lck').exists(),'ALPM lock present; no deletion or stale-lock waiver, dispose outer container')
    dispose(workspace,owner['workspace'])
   result=dict(status='OWNED_COPY_DISPOSED',rollback='NOT_CLAIMED')
  elif a.worker:result=apply(a)
  else:
   root_guard(a);need(a.confirm_disposable_transaction,'explicit confirmation required')
   row=SUP.run([sys.executable,'-I','-B',str(Path(__file__).resolve()),*sys.argv[1:],'--worker'],env=dict(os.environ),cwd=str(Path(a.workspace).absolute()),timeout=execution_seconds(a),output_limit=1024**2)
   need(row['termination'] is None and row['direct_child_reaped'] and row['returncode'] in (0,1),'transaction worker failed or interrupted; dispose owned copy, commit outcome unknown')
   result=I.decode(row['stdout']);need(result.get('status')=='FAIL' if row['returncode'] else result.get('status')=='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION','worker outcome differs');result['worker']={k:row[k] for k in ('returncode','termination','direct_child_reaped','group_kill_sent')}
  print(encoded(result).decode(),end='');return int(result['status']=='FAIL')
 except BaseException as error:
  print(encoded(dict(status='FAIL',error_type=type(error).__name__,error=str(error)[:1024],packages_committed='UNKNOWN' if a.action=='apply' else False,commit_started='UNKNOWN' if a.action=='apply' else False,recovery='DISPOSE_OWNED_COPY_IF_COMMIT_OR_CLEANUP_UNCERTAIN',rollback='NOT_CLAIMED')).decode(),end='');return 1
if __name__=='__main__':raise SystemExit(main())
