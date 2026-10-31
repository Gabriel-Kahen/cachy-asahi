#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite persistent606 staging; never a live-root update or acceptance gate."""
import ast,base64,hashlib,importlib.util,json,os,re,stat,sys,types
from pathlib import Path

HERE=Path(__file__).resolve().parent
PURPOSE='CURRENT606_SETUP6_OWNED_ORDINARY_SOURCE'
EXPECTED='3a586c1e3400391f56bd281ac9c16aba85d94d0fca002770e77ee1802c5d9fd1'
STAGE=Path('/measurement/source606');PRIVATE=Path('/measurement/private');OUTPUT=Path('/out')
INFRA=frozenset(('original','target','plan','runner','tools606','code','combined','out','measurement'))
MASKS={'capture':0xdb,'bridge':0x8000001b,'worker':0x800400db}
MAP_LIMIT=64*1024**2;TOTAL_LIMIT=128*1024**2

def need(value,why):
 if not value:raise ValueError(why)
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return dict(bytes=len(raw),sha256=sha(raw))
def read(path,maximum=MAP_LIMIT):
 path=Path(path);need(path.is_absolute() and not any(p.is_symlink() for p in(path,*path.parents)),'ordinary absolute path')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=maximum,'bounded single-link input')
  raw=bytearray()
  while len(raw)<=before.st_size:
   block=os.read(fd,min(1024**2,before.st_size-len(raw)+1))
   if not block:break
   raw.extend(block)
  identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'input drift');return bytes(raw)
 finally:os.close(fd)
def decode(raw):
 def pairs(rows):
  result={}
  for k,v in rows:need(k not in result,'duplicate JSON key');result[k]=v
  return result
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def authority(selection,role=None,nonce=None):
 need(type(selection)is dict and selection.get('status')=='ROOT_BOUND_CURRENT606_SETUP6_INPUTS','UNBOUND606: closed current606 selection')
 need(role in ('capture','finalizer','dispose'),'explicit finite bridge actor role')
 api=decode(read(HERE/'owner-api.json'));need(api['path']=='/runner/owner/selection.py','fixed trusted owner API path')
 raw=read(api['path'],65536);need(pin(raw)==api['pin'],'whole source-pinned owner API differs')
 namespace={'__name__':'_606_bridge_pinned_owner_selection'}
 exec(compile(raw,'<source-pinned606-owner-selection>','exec'),namespace)
 context=namespace['verify_actor'](selection,role,nonce)
 need(re.fullmatch('[0-9a-f]{40}',context['source_native']or'') and type(context['source_run'])is int and context['source_run']>0 and context['expected606_sha256']==EXPECTED and context['mask']==MASKS['capture' if role=='capture' else 'bridge'],'exact selected source/capability context')
 return context
def actor_guard(role,nonce):
 need(role in ('capture','bridge') and re.fullmatch('[0-9a-f]{32}',nonce or ''),'explicit bridge role/nonce')
 need(os.getuid()==os.geteuid()==0 and os.getpid()==1 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file(),'dedicated native root PID1 only')
 need(os.environ.get('CAA_CURRENT606_BRIDGE')==nonce and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned network-none nonce')
 status={r.split(':',1)[0]:r.split(':',1)[1].strip() for r in Path('/proc/self/status').read_text().splitlines() if ':'in r}
 need(int(status['CapEff'],16)==int(status['CapPrm'],16)==int(status['CapBnd'],16)==MASKS[role] and int(status['CapInh'],16)==int(status['CapAmb'],16)==0 and status['NoNewPrivs']=='1','exact dedicated capability/NNP profile')
 return dict({k:status[k] for k in ('CapEff','CapPrm','CapBnd','CapInh','CapAmb','NoNewPrivs')},pid=os.getpid(),ppid=os.getppid(),namespaces={n:os.stat('/proc/self/ns/'+n).st_ino for n in('pid','mnt','net')})
def load_apis(root):
 root=Path(root);pins=decode(read(HERE/'source-pins.json'))['files']
 for n,row in pins.items():need(pin(read(root/n,16*1024**2))==row,'trusted whole source differs: '+n)
 def load(name,path):
  spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
 original=read(root/'scripts/ci/full-root-upgrade-caller/persistent_scope.py').decode()
 before="need('upgrade-signing' in selected, 'separate TEST signer mount required')"
 need(original.count(before)==1,'exact original signer-mount scope seam')
 original=original.replace(before,"need(INFRASTRUCTURE<=set(selected), 'all exact606 infrastructure mounts required')")
 scope=types.ModuleType('_606_persistent_scope');exec(compile(original,'<pinned606-persistent-scope>','exec'),scope.__dict__)
 roots,copier,resolver,driver=scope._apis(root)
 # Per-call private facade: no mutation of the shared original module/global.
 scope.INFRASTRUCTURE=INFRA
 prior=sys.modules.get('full_root');sys.modules['full_root']=roots
 try:
  aux=load('_606_held_aux_checkpoint',root/'scripts/update/aux_checkpoint.py');disposal=load('_606_held_disposable_copy',root/'scripts/update/disposable_copy.py')
  sys.path.insert(0,str(root/'scripts/update'))
  try:
   import root_link_selection as links
   need(Path(links.__file__).absolute()==root/'scripts/update/root_link_selection.py','selected link API origin differs')
  finally:sys.path.pop(0)
 finally:
  if prior is None:sys.modules.pop('full_root',None)
  else:sys.modules['full_root']=prior
 caps=load('_606_complete_file_capabilities',root/'scripts/apps/file_capabilities.py')
 return types.SimpleNamespace(scope=scope,roots=roots,copier=copier,resolver=resolver,driver=driver,caps=caps,aux=aux,links=links,disposal=disposal)
def owned_measurement(context,nonce):
 row=context.get('measurement')
 need(type(row)is dict and set(row)=={'identity','uid','gid','mode'} and type(row['identity'])is list and len(row['identity'])==2 and all(type(x)is int and x>=0 for x in row['identity']) and all(type(row[k])is int and row[k]>=0 for k in('uid','gid')) and row['mode']==0o700,'closed owner measurement lease UNSUPPLIED')
 root=STAGE.parent;need(not any(p.is_symlink()for p in(root,*root.parents)),'ordinary measurement root')
 info=root.lstat();need(stat.S_ISDIR(info.st_mode)and[info.st_dev,info.st_ino]==row['identity']and info.st_uid==row['uid']and info.st_gid==row['gid']and stat.S_IMODE(info.st_mode)==0o700 and not any(root.iterdir()),'fresh leased measurement identity')
 os.chown(root,0,0)
 marker=dict(nonce=nonce,measurement=row,source_native=context['source_native'],source_run=context['source_run'])
 with (root/'measurement-owner.json').open('xb')as stream:stream.write(encoded(marker))
 return marker
def export_small_receipt(name,value,context):
 schemas={'bridge-capture.json':{'status','nonce','source_native','source_run','stage_identity','maps','native_acceptance'},'bridge-handoff.json':{'schema_version','purpose','nonce','source_native','source_run','expected606_sha256','source_root','work_root','maps'}}
 need(name in schemas and type(value)is dict and set(value)==schemas[name],'fixed small receipt schema')
 need(value['nonce']==context['nonce']and value['source_native']==context['source_native']and value['source_run']==context['source_run'],'same selected receipt owner')
 if name=='bridge-capture.json':need(value['status']=='CAPTURED_NOT_FINALIZED'and value['native_acceptance']=='NOT_GRANTED'and type(value['stage_identity'])is list and len(value['stage_identity'])==9 and all(type(v)is int and v>=0 for v in value['stage_identity']),'bounded capture metadata only')
 else:need(value['schema_version']==1 and value['purpose']==PURPOSE and value['expected606_sha256']==EXPECTED and value['source_root']=='/seed'and value['work_root']=='/work','fixed small handoff metadata')
 roles={'observation','packages','capabilities','projection'}if name=='bridge-capture.json'else{'ordinary_observation','packages','capabilities','bridge_proof'}
 need(type(value['maps'])is dict and set(value['maps'])==roles,'only four small map references')
 for role,row in value['maps'].items():
  need(type(row)is dict and set(row)==({'bytes','sha256'}if name=='bridge-capture.json'else{'path','bytes','sha256'})and type(row['bytes'])is int and 0<=row['bytes']<=MAP_LIMIT and re.fullmatch('[0-9a-f]{64}',row['sha256']or''),'map pins only; no raw map export')
  if name=='bridge-handoff.json':need(row['path']=='/bridge-proof/'+role.replace('_','-')+'.json','fixed private map reference')
 raw=encoded(value);need(len(raw)<=65536,'small receipt cap');lease=context.get('output')
 need(type(lease)is dict and set(lease)=={'identity','uid','gid','mode'}and lease['mode']==0o700,'closed owner output lease UNSUPPLIED')
 path=OUTPUT;need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary output directory')
 directory=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fd=None
 try:
  info=os.fstat(directory);need([info.st_dev,info.st_ino]==lease['identity']and info.st_uid==lease['uid']and info.st_gid==lease['gid']and stat.S_IMODE(info.st_mode)==0o700,'exact host-owned output identity')
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644,dir_fd=directory);view=memoryview(raw)
  while view:
   written=os.write(fd,view);need(written>0,'receipt write no progress');view=view[written:]
  os.fchmod(fd,0o644);os.fsync(fd);info=os.fstat(fd);need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_size==len(raw),'ordinary exact receipt output');os.fsync(directory)
 finally:
  if fd is not None:os.close(fd)
  os.close(directory)
 return pin(raw)
def recording_copier(apis,created):
 raw=read(Path(apis.copier.__file__),512*1024);text=raw.decode();anchor='        target.mkdir(mode=0o700)'
 need(text.count(anchor)==1,'exact stage creation marker seam')
 text=text.replace(anchor,anchor+'\n        _stage_created(target)')
 module=types.ModuleType('_606_recorded_stage_copy');module.__file__=apis.copier.__file__;module._stage_created=created
 exec(compile(text,'<pinned606-recorded-copy>','exec'),module.__dict__);module.roots=apis.roots
 return module
def capability_omissions(apis,omitted,limits):
 """Project only existing runtime submounts onto already excluded root names."""
 need(type(omitted)is set and len(omitted)<=limits.max_nodes and all(type(n)is str for n in omitted),'bounded mount omission set')
 result=set()
 for name in sorted(omitted):
  limits.tick();apis.roots.installer.relative(name);parts=name.split('/')
  need(len(name.encode('utf-8','surrogateescape'))<=4096 and len(parts)<=limits.max_depth+1 and '\\'not in name and not any(ord(c)<32 or ord(c)==127 for c in name),'canonical bounded mount omission')
  first=parts[0]
  need(first in apis.scope.RUNTIME or name in INFRA or name in apis.scope.MOUNT_FILES,'only literal606 infrastructure or existing runtime roots')
  result.add(first if first in apis.scope.RUNTIME else name)
 return result

def scoped_caps(apis,omitted,limits):
 omitted=capability_omissions(apis,omitted,limits)
 need(set(omitted)<=INFRA|apis.scope.RUNTIME|apis.scope.MOUNT_FILES,'only literal606 mount boundaries')
 raw=read(Path(apis.caps.__file__),512*1024);text=raw.decode()
 for before,after in (("   need(actual==set(children[prefix]),'actual node graph differs')","   if not prefix:actual-=OMITTED\n   need(actual==set(children[prefix]),'actual node graph differs')"),("need(_identity(os.fstat(fd))==identity and _mount(fd,limits)==mount,'node identity/mount drift')","need(_identity(os.fstat(fd))==identity and (_mount(fd,limits)==mount or relative in MOUNT_FILES),'node identity/mount drift')")):
  need(text.count(before)==1,'whole pinned capability observer seam');text=text.replace(before,after)
 module=types.ModuleType('_606_scoped_caps');module.OMITTED=set(omitted)-apis.scope.MOUNT_FILES;module.MOUNT_FILES=apis.scope.MOUNT_FILES
 exec(compile(text,'<source-pinned606-caps>','exec'),module.__dict__);return module
def _materialize(source,target,apis,limits,expected,policy,raw_mounts,created=None):
 """Internal source-static API; actor callers must gate authority/profile first."""
 source,target=Path(source),Path(target)
 need(not target.exists() and not target.is_symlink() and not limits.allow_cross_device,'fresh single-mount stage')
 need(target.parent.stat().st_uid==os.geteuid() and stat.S_IMODE(target.parent.stat().st_mode)==0o700,'owned private disk stage parent')
 scope,roots=apis.scope,apis.roots
 before,excluded=scope.source_manifest(source,limits,roots,policy)
 packages=apis.driver.database(source,max_packages=limits.max_packages,max_files=limits.max_package_files,max_nodes=limits.max_nodes,observed=before)
 need({r['name']:r['version'] for r in packages}==expected,'complete expected installed inventory')
 owned=scope.owned_coverage(packages,before,apis.resolver,limits)
 scoped=scoped_caps(apis,set(policy['observed_mounts'])|scope.RUNTIME,limits)
 capnodes={n:r for n,r in before.items() if n.split('/')[0]not in scope.RUNTIME}
 capabilities,identities=scoped._scan(source,capnodes,limits)
 copier=recording_copier(apis,created)if created is not None else apis.copier
 report=copier.copy_data(source,target,limits=limits,excluded=scope.RUNTIME|(INFRA&set(policy['observed_mounts']))|scope.MOUNT_FILES,absolute_paths=True)
 need(not report['unsupported_counts'],'unrecognized persistent node skipped')
 scope._restore_boundaries(source,target,before,roots,apis.copier,limits)
 staged=roots.observe(target,limits=limits,hardlinks='generic-development-internal',absolute_paths=True)
 need(staged['complete']is True and staged['nodes']==before,'complete staged nodes differ')
 need(apis.driver.database(target,max_packages=limits.max_packages,max_files=limits.max_package_files,max_nodes=limits.max_nodes,observed=staged['nodes'])==packages,'raw staged DB/package record mismatch')
 need(scope.owned_coverage(packages,staged['nodes'],apis.resolver,limits)==owned,'package-owned coverage changed')
 after,omitted=scope.source_manifest(source,limits,roots,policy)
 final_caps,final_identities=scoped._scan(source,capnodes,limits)
 need(after==before and omitted==excluded and final_caps==capabilities and final_identities==identities,'source data/capabilities/inodes changed')
 need(scope._mount_table()==raw_mounts,'source mount table changed')
 return dict(observation=staged,packages=packages,capabilities=capabilities,projection=dict(status='CAPTURED_PERSISTENT_DATA_NOT_READONLY_OR_TRANSACTION_AUTHORITY',source_preserved=True,excluded=excluded,owned_paths=owned,mount_policy=policy,copy=report,root_identity=list(roots._identity(target.stat())),source_root_identity=list(roots._identity(source.stat())),source_node_identities=identities,root_mode=stat.S_IMODE(source.stat().st_mode),root_uid=source.stat().st_uid,root_gid=source.stat().st_gid,capabilities_restored=False,consistency='per-file identity plus before/after equality; not atomic snapshot',timestamps='NOT_PRESERVED_NOT_IN_ORIGINAL_COPY_CONTRACT'))
def capture(selection,nonce,code,limits):
 context=authority(selection,'capture',nonce);profile=actor_guard('capture',nonce);apis=load_apis(code)
 owned_measurement(context,nonce)
 need(not PRIVATE.exists() and not PRIVATE.is_symlink(),'fresh private maps directory')
 raw=apis.scope._mount_table();policy=apis.scope.mount_policy(Path('/'),STAGE,apis.scope.mounts(raw))
 need(INFRA<=set(policy['observed_mounts']),'all finite606 infrastructure mounts observed')
 rawlock=read(HERE/'expected606.lock',262144);need(sha(rawlock)==EXPECTED,'exact606 lock');expected=dict(line.split() for line in rawlock.decode().splitlines());need(len(expected)==606,'606 distinct expected packages')
 def created(path):
  need(path==STAGE,'exact stage marker path');info=path.lstat()
  with (STAGE.parent/'stage-owner.json').open('xb')as stream:stream.write(encoded(dict(nonce=nonce,identity=[info.st_dev,info.st_ino])))
 result=_materialize(Path('/'),STAGE,apis,limits,expected,policy,raw,created=created)
 result['projection'].update(nonce=nonce,source_native=context['source_native'],source_run=context['source_run'],capture_profile=profile)
 PRIVATE.mkdir(mode=0o700)
 with (STAGE.parent/'private-owner.json').open('xb')as stream:stream.write(encoded(dict(nonce=nonce,identity=[PRIVATE.stat().st_dev,PRIVATE.stat().st_ino])))
 rows={}
 for n,v in result.items():
  data=encoded(v);need(len(data)<=MAP_LIMIT,'private map byte cap')
  with (PRIVATE/(n+'.json')).open('xb')as stream:stream.write(data)
  rows[n]=pin(data)
 need(sum(p.stat().st_size for p in PRIVATE.iterdir())<=TOTAL_LIMIT,'private aggregate cap')
 receipt=dict(status='CAPTURED_NOT_FINALIZED',nonce=nonce,source_native=context['source_native'],source_run=context['source_run'],stage_identity=result['projection']['root_identity'],maps=rows,native_acceptance='NOT_GRANTED')
 export_small_receipt('bridge-capture.json',receipt,context);return receipt
def _restore_and_observe(stage,captured,apis,limits):
 stage=Path(stage);projection=captured['projection']
 need(list(apis.roots._identity(stage.stat()))==projection['root_identity'],'recorded stage inode drift')
 observation=apis.roots.observe(stage,limits=limits,hardlinks='generic-development-internal',absolute_paths=True)
 need(observation['complete']is True and observation['nodes']==captured['observation']['nodes'],'stage drift before capability restoration')
 apis.caps.restore(stage,observation['nodes'],captured['capabilities'],limits)
 actual=apis.caps.observe(stage,observation['nodes'],limits)
 need(actual==captured['capabilities'],'complete restored capability map')
 after=apis.roots.observe(stage,limits=limits,hardlinks='generic-development-internal',absolute_paths=True)
 need(after['complete']is True and after['nodes']==observation['nodes'],'stage bytes changed during capability restoration')
 need(apis.driver.database(stage,max_packages=606,max_files=limits.max_package_files,max_nodes=limits.max_nodes,observed=after['nodes'])==captured['packages'],'raw DB drift during finalization')
 return after,actual
def private_bytes(value):
 if isinstance(value,bytes):return {'base64':base64.b64encode(value).decode(),'bytes':len(value),'sha256':sha(value)}
 if isinstance(value,dict):return {k:private_bytes(v)for k,v in value.items()}
 if isinstance(value,(list,tuple)):return [private_bytes(v)for v in value]
 return value
def capture_join(receipt,nonce,context):
 need(type(receipt)is dict and receipt.get('status')=='CAPTURED_NOT_FINALIZED' and receipt.get('nonce')==nonce and receipt.get('source_native')==context['source_native'] and receipt.get('source_run')==context['source_run'],'exact capture receipt nonce/source')
 need(set(receipt['maps'])=={'observation','packages','capabilities','projection'},'exact capture map roles')
 captured={};total=0
 for n,row in receipt['maps'].items():
  raw=read(PRIVATE/(n+'.json'));total+=len(raw);need(pin(raw)==row and total<=TOTAL_LIMIT,'capture map pin/aggregate differs');captured[n]=decode(raw)
 need(receipt['stage_identity']==captured['projection']['root_identity'],'capture/stage identity join')
 return captured
def prior_retirement(context,nonce):
 retirement=context.get('retirement')
 need(type(retirement)is dict and retirement.get('nonce')==nonce and retirement.get('prior_consumers_absent')is True,'closed owner prior-consumer retirement UNSUPPLIED')
 return retirement
def finalize(selection,nonce,code,limits):
 context=authority(selection,'finalizer',nonce);profile=actor_guard('bridge',nonce);prior_retirement(context,nonce);apis=load_apis(code)
 # The closed owner pins the exact small capture receipt in the separately
 # readonly actor selection before this phase starts; maps are never code.
 captured=capture_join(context['capture_receipt'],nonce,context)
 projection=captured['projection'];need(projection['nonce']==nonce and projection['source_native']==context['source_native'] and projection['source_run']==context['source_run'],'same captured owner nonce/source')
 need({p['name']:p['version'] for p in captured['packages']}==dict(line.split()for line in read(HERE/'expected606.lock').decode().splitlines()),'same606 inventory')
 observation,capabilities=_restore_and_observe(STAGE,captured,apis,limits)
 os.chown(STAGE,projection['root_uid'],projection['root_gid']);os.chmod(STAGE,projection['root_mode'])
 # Exact selected-link and ldconfig checkpoint: failure remains ineligible.
 apis.links.check(observation,limits);aux=apis.aux.checkpoint(STAGE,observation,limits)
 work=STAGE.parent/'work';need(not work.exists()and not work.is_symlink(),'fresh owned worker staging directory');work.mkdir(mode=0o700);info=work.stat();need(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o700,'exact root-owned worker staging')
 with (STAGE.parent/'work-owner.json').open('xb')as stream:stream.write(encoded(dict(nonce=nonce,identity=[info.st_dev,info.st_ino])))
 proof=dict(projection,root_identity=list(apis.roots._identity(STAGE.stat())),source_identity=list(apis.roots._identity(STAGE.stat())),staging_source_root=str(STAGE),work_identity=list(apis.roots._identity(info)),work_root='/work',work_staging_root=str(work),bridge_profile=profile,status='READY_FOR_READONLY_BIND_NOT_WORKER_AUTHORITY',capabilities_restored=True,auxiliary_checkpoint=private_bytes(aux),source_root_mode=projection['root_mode'],ordinary_root_mode=stat.S_IMODE(STAGE.stat().st_mode),read_only='WORKER_MUST_PROVE_ACTUAL_BIND',consumer_retirement='CLOSED_OWNER_MUST_JOIN_BEFORE_WORKER')
 maps={'ordinary-observation':observation,'packages':captured['packages'],'capabilities':capabilities,'bridge-proof':proof}
 dest=PRIVATE/'final';dest.mkdir(mode=0o700);rows={};total=0
 for name,value in maps.items():
  raw=encoded(value);need(len(raw)<=MAP_LIMIT,'final private map cap');total+=len(raw);need(total+sum(p.stat().st_size for p in PRIVATE.iterdir() if p.is_file())<=TOTAL_LIMIT,'all private maps aggregate cap')
  with (dest/(name+'.json')).open('xb')as stream:stream.write(raw)
  rows[name.replace('-','_')]=dict(path='/bridge-proof/'+name+'.json',**pin(raw))
 handoff=dict(schema_version=1,purpose=PURPOSE,nonce=nonce,source_native=context['source_native'],source_run=context['source_run'],expected606_sha256=EXPECTED,source_root='/seed',work_root='/work',maps=rows)
 export_small_receipt('bridge-handoff.json',handoff,context);return handoff

def remove_owned_tree(path,identity,apis,limits):
 """Exact original descriptor-only cleanup, after an owned-tree shape audit."""
 path=Path(path);parent=apis.roots._open_root(path.parent);fd=None
 try:
  fd=os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
  mount=apis.roots._mount_id(parent,limits);need(apis.roots._mount_id(fd,limits)==mount,'owned stage cleanup mount crossing')
  apis.disposal._same(parent,path.name,fd,tuple(identity),mount,limits)
  def audit(directory,depth=0,spent=None):
   spent=[0]if spent is None else spent;need(depth<=limits.max_depth,'cleanup depth bound')
   with os.scandir(directory)as entries:
    for entry in entries:
     limits.tick();spent[0]+=1;need(spent[0]<=limits.max_nodes,'cleanup node bound');info=os.stat(entry.name,dir_fd=directory,follow_symlinks=False)
     need(stat.S_ISREG(info.st_mode)or stat.S_ISLNK(info.st_mode)or stat.S_ISDIR(info.st_mode),'unrecognized cleanup node type')
     if stat.S_ISDIR(info.st_mode):
      child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
      try:need(apis.roots._mount_id(child,limits)==mount,'cleanup submount refused');audit(child,depth+1,spent)
      finally:os.close(child)
  audit(fd);apis.disposal._empty(fd,mount,limits,[0]);apis.disposal._same(parent,path.name,fd,tuple(identity),mount,limits);os.rmdir(path.name,dir_fd=parent)
 finally:
  if fd is not None:os.close(fd)
  os.close(parent)
def dispose(selection,nonce,code,limits):
 context=authority(selection,'dispose',nonce);profile=actor_guard('bridge',nonce)
 # This context must be returned only by the future source-pinned closed owner
 # after its exact live Docker/group retirement checks, not exported PASS data.
 prior_retirement(context,nonce)
 apis=load_apis(code);root=STAGE.parent;marker=decode(read(root/'measurement-owner.json',65536));lease=context.get('measurement')
 need(marker==dict(nonce=nonce,measurement=lease,source_native=context['source_native'],source_run=context['source_run']),'exact measurement owner receipt')
 info=root.lstat();need(stat.S_ISDIR(info.st_mode)and not root.is_symlink()and[info.st_dev,info.st_ino]==lease['identity']and info.st_uid==0,'owned measurement root drift')
 allowed={'source606','private','work','stage-owner.json','private-owner.json','work-owner.json','measurement-owner.json','capture-receipt.json','handoff.json'}
 need({p.name for p in root.iterdir()}<=allowed,'unknown measurement entries retained')
 trees=[]
 for path,name in ((STAGE,'stage-owner.json'),(PRIVATE,'private-owner.json'),(root/'work','work-owner.json')):
  if path.exists()or path.is_symlink():
   owner=decode(read(root/name,65536));need(owner['nonce']==nonce,'same recorded tree nonce');info=path.lstat()
   need(stat.S_ISDIR(info.st_mode)and[info.st_dev,info.st_ino]==owner['identity'],'recorded bridge tree identity');trees.append((path,owner['identity']))
 for name in allowed-{'source606','private','work'}:
  path=root/name
  if path.exists()or path.is_symlink():read(path,65536)
 for path,identity in reversed(trees):remove_owned_tree(path,identity,apis,limits)
 for name in allowed-{'source606','private','work','measurement-owner.json'}:
  path=root/name
  if path.exists():read(path,65536);path.unlink()
 read(root/'measurement-owner.json',65536);(root/'measurement-owner.json').unlink();need(not any(root.iterdir()),'measurement remains')
 os.chown(root,lease['uid'],lease['gid']);os.chmod(root,lease['mode'])
 return dict(status='REMOVED_RECORDED_OWNED_BRIDGE_DATA',nonce=nonce,profile=profile,Docker_absence='CLOSED_OWNER_MUST_REAP_THIS_DISPOSER',native_acceptance='NOT_GRANTED')

def main(argv=None):
 import argparse,time
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('capture','finalize','dispose'));parser.add_argument('--selection',type=Path,required=True);parser.add_argument('--code',type=Path,required=True);parser.add_argument('--nonce',required=True);args=parser.parse_args(argv)
 need(args.code==Path('/runner/bridge-code'),'fixed readonly bridge code root')
 need(args.selection==Path('/plan/bridge-selection.json')if args.mode=='capture'else args.selection==Path('/bridge-input/selection.json'),'fixed readonly phase selection data')
 selected=decode(read(args.selection,262144));context=authority(selected,'capture'if args.mode=='capture'else'dispose'if args.mode=='dispose'else'finalizer',args.nonce)
 # Exact resource policy comes from the source-pinned closed-owner validator,
 # never arbitrary CLI numbers or aggregate runtime success fields.
 values=context.get('limits');need(type(values)is dict and set(values)=={'seconds','max_packages','max_nodes','max_bytes','max_file_bytes','max_package_files','max_depth'} and values['max_packages']==606,'closed owner source limits required')
 apis=load_apis(args.code);limits=apis.roots.Limits(deadline=time.monotonic()+values['seconds'],**{k:v for k,v in values.items()if k!='seconds'})
 result={'capture':capture,'finalize':finalize,'dispose':dispose}[args.mode](selected,args.nonce,args.code,limits)
 if args.mode=='dispose':print(encoded(result).decode(),end='');return 0
 name='capture-receipt.json'if args.mode=='capture'else'handoff.json'
 with (Path('/measurement')/name).open('xb')as stream:stream.write(encoded(result))
 print(encoded(result).decode(),end='');return 0
if __name__=='__main__':raise SystemExit(main())
