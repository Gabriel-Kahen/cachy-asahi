# SPDX-License-Identifier: MIT
"""TEST-only owned filesystem rollback and signed forward recovery, never downgrade."""
import ast,ctypes,hashlib,importlib.util,json,os,stat,time
from pathlib import Path
_spec=importlib.util.spec_from_file_location('_normal_lifecycle_ci',Path(__file__).with_name('lifecycle_ci.py'));ci=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(ci)
need,encoded,pin=ci.need,ci.encoded,ci.pin
DB='var/lib/pacman/local';CACHES=('etc/ld.so.cache','var/cache/ldconfig/aux-cache')
def digest(v):return hashlib.sha256(encoded(v)).hexdigest()
def checkpoint(api,args):
 with api.scale.bound.client.state_directory(args.state_dir,False)as fd:return api.scale.bound.client.checkpoint(fd)
def observation(api,root,config):
 v=config['limits'];return api.scale.roots.observe(root,limits=api.scale.roots.Limits(deadline=ci.deadline(v['seconds']),max_nodes=v['root_nodes'],max_bytes=v['root_bytes'],max_file_bytes=v['file_bytes'],max_package_files=v['package_files']),hardlinks='generic-development-internal')
def summary(value,driver,root):
 nodes=value['nodes'];packages=driver.database(root,max_files=1000000,max_nodes=4000000,observed=nodes);inventory={p['name']:p['version']for p in packages};need(len(inventory)==607,'whole607 actual lifecycle database')
 return dict(nodes=len(nodes),nodes_sha256=digest(nodes),hardlink_groups_sha256=digest(value.get('hardlink_groups')),database_sha256=digest({n:r for n,r in nodes.items()if n==DB or n.startswith(DB+'/')}),inventory_sha256=driver.inventory_sha(inventory),package_count=len(inventory),caches={n:nodes[n]['sha256']for n in CACHES},payload_sha256=digest({n:r for n,r in nodes.items()if not(n==DB or n.startswith(DB+'/'))}))
def begin(args,config):return dict(lease=ci.Lease(args,config),config=config,snapshot=None,snapshot_report=None,receipt=None)
def prepare(state,args,api,copy_module,driver,nodes,protected,before):
 state['lease'].check()
 if ci.CASE!='normal':return
 root=Path(args.root);config=state['config'];base=observation(api,root,config);need(base['nodes']==nodes,'same initialized normal baseline before rollback snapshot')
 v=config['limits'];workspace=Path(args.workspace).with_name(Path(args.workspace).name+'-rollback-snapshot')
 cm=copy_module.copied_root(root,workspace,limits=api.scale.roots.Limits(deadline=ci.deadline(ci.BUDGETS['copy'],ci.BUDGETS['cleanup']),max_nodes=v['root_nodes'],max_bytes=v['root_bytes'],max_file_bytes=v['file_bytes'],max_package_files=v['package_files']))
 backup,report=cm.__enter__();state['snapshot']=cm;state['snapshot_report']=report;state['backup']=backup;state['backup_workspace']=workspace
 copied=observation(api,backup,config);need(base['nodes']==copied['nodes']and base.get('hardlink_groups')==copied.get('hardlink_groups'),'whole initialized baseline snapshot bytes/metadata/hardlinks')
 state.update(baseline=base,baseline_summary=summary(base,driver,root),snapshot_summary=summary(copied,driver,backup),protected_sha256=digest({n:nodes[n]for n in sorted(protected)}),source_before=observation(api,Path(args.source),config));state['lease'].check()
def _identity(s):return dict(dev=s.st_dev,ino=s.st_ino,uid=s.st_uid,gid=s.st_gid,mode=stat.S_IMODE(s.st_mode))
def _same(fd,path,wanted):
 a=os.fstat(fd);b=path.lstat();need(stat.S_ISDIR(a.st_mode)and stat.S_ISDIR(b.st_mode)and _identity(a)==_identity(b)==wanted,'reserved ordinary root/parent identity');return a

def swap_roots(root,backup,limits,roots):
 """Only two owned FD-bound workspaces and no-replace names may be exchanged."""
 root,backup=Path(root),Path(backup);need(root.name==backup.name=='root'and root.parent!=backup.parent,'distinct owned root slots');paths=(root.parent,backup.parent,root,backup);fds=[]
 try:
  for p in paths:
   need(p==p.resolve()and not any(x.is_symlink()for x in(p,*p.parents)),'canonical rollback slots');fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fds.append(fd)
  identities=[_identity(os.fstat(fd))for fd in fds]
  for fd,p,w in zip(fds,paths,identities):_same(fd,p,w)
  need(all(w['uid']==os.geteuid()for w in identities)and all(w['mode']==0o700 for w in identities[:2]),'private owned rollback parents')
  mount=roots._mount_id(fds[0],limits);need(all(roots._mount_id(fd,limits)==mount for fd in fds)and len({w['dev']for w in identities})==1,'one retained rollback mount')
  rename=getattr(ctypes.CDLL(None,use_errno=True),'renameat2',None);need(rename is not None,'atomic no-replace rename API required');rename.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint);rename.restype=ctypes.c_int
  def move(a,old,b,new):need(rename(a,old.encode(),b,new.encode(),1)==0,'no-replace owned rollback move failed')
  need(not os.path.lexists(backup.parent/'initial-committed-root'),'fresh committed-root retirement slot');move(fds[0],'root',fds[1],'initial-committed-root');_same(fds[2],backup.parent/'initial-committed-root',identities[2])
  need(not os.path.lexists(root),'rollback target absent after retained move');move(fds[1],'root',fds[0],'root');_same(fds[3],root,identities[3])
  for fd,p,w in zip(fds[:2],paths[:2],identities[:2]):_same(fd,p,w);os.fsync(fd)
  return dict(status='PASS_FD_BOUND_NOREPLACE_OWNED_FILESYSTEM_RESTORE',parents=identities[:2],initial_committed_root=identities[2],restored_root=identities[3],mount_id=mount,package_downgrade_attempted=False)
 finally:
  for fd in reversed(fds):os.close(fd)
def recovery_initialize(args,driver):
 path=Path(args.initializer);raw=path.read_bytes();need(hashlib.sha256(raw).hexdigest()==args.initializer_sha256,'same whole initializer before recovery')
 module=driver.load('_lifecycle_original_initializer',path);text=raw.decode();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='initialize');body=ast.get_source_segment(text,node);old="'aux-initialization-started'";new="'aux-recovery-initialization-started'";need(body.count(old)==1,'one held initialization marker seam');changed=body.replace(old,new,1);need(changed.replace(new,old,1)==body,'whole recovery initializer inverse')
 space=dict(vars(module));exec(compile(changed,'<exact-one-shot-recovery-initializer>','exec'),space);v=space['initialize'](args,Path(args.source),comparator_path=Path(args.comparator));need(v.get('status')=='PASS'and v.get('root_initialized')is True and v.get('source_preserved')is True,'actual second one-shot cache initialization')
 return dict(result=v,held_source=pin(raw),marker='aux-recovery-initialization-started',whole_body_inverse=True)
def complete(state,args,api,driver,constructor,initial_update,release,protected):
 state['lease'].check()
 if ci.CASE!='normal':return dict(status='NOT_APPLICABLE_FAULT_CASE',case=ci.CASE,rollback_attempted=False,recovery_attempted=False)
 config=state['config'];root=Path(args.root);before,after=driver.selection(args.source_root);one=checkpoint(api,args);need(type(one)is dict and one['sequence']==1 and one['signer']==args.signer and one['namespace']==args.namespace,'actual durable seq1 checkpoint before restore')
 cert=pin(Path(release['public_keyring']).read_bytes());initial_signed=dict(metadata_sha256=driver.sha(Path(args.metadata).read_bytes()),release_sha256=driver.sha((Path(args.bundle)/'release.json').read_bytes()),signature=pin(Path(args.signature).read_bytes()),certificate=cert);need(one['metadata_sha256']==initial_signed['metadata_sha256']and one['release_sha256']==initial_signed['release_sha256']==initial_update['release_sha256'],'initial checkpoint joins actual first signed release');v=config['limits'];bounds=api.scale.roots.Limits(deadline=ci.deadline(ci.BUDGETS['cleanup']),max_nodes=v['root_nodes']);restore=swap_roots(root,state['backup'],bounds,api.scale.roots)
 raw=observation(api,root,config);need(raw['nodes']==state['baseline']['nodes']and raw.get('hardlink_groups')==state['baseline'].get('hardlink_groups'),'actual restored complete baseline before inode-cache reinitialization')
 restored=summary(raw,driver,root);need(restored==state['baseline_summary'],'complete607 DB/cache/payload/hardlink baseline restore');need(checkpoint(api,args)==one,'external antirollback seq1 survives filesystem rollback')
 init=recovery_initialize(args,driver);baseline=api.Runtime(args,config).tree(root);need({p['name']:p['version']for p in driver.database(root,observed=baseline)}==before,'actual607 baseline before signed recovery')
 args.sequence=2;args.release_id=args.release_id+'-recovery2';recovery=constructor.construct(args,base=Path(args.data)/'base.json',protected=sorted(set(before)-{driver.NAME}),output=Path(args.data)/'recovery-release-inputs');need(recovery.get('status')not in('FAIL','REFUSED_API_CONTRACT'),'actual fresh signed recovery repository')
 for name in('bundle','metadata','signature','public_keyring'):setattr(args,name,str(recovery[name]))
 need(pin(Path(args.public_keyring).read_bytes())==cert and recovery['signer']==one['signer'],'same external TEST certificate and signer')
 policy=json.loads(Path(args.policy).read_bytes());policy['release_id']=recovery['release_id'];args.policy=str(Path(args.data)/'recovery-policy.json');driver.write(args.policy,policy);args.policy_sha256=driver.sha(Path(args.policy).read_bytes())
 settings=json.loads(Path(args.settings).read_bytes());settings.update(minimum_sequence=2,release_id=recovery['release_id'],metadata_sha256=driver.sha(Path(args.metadata).read_bytes()),release_sha256=driver.sha((Path(args.bundle)/'release.json').read_bytes()),public_keyring_sha256=driver.sha(Path(args.public_keyring).read_bytes()),base_trust_sha256=api.scale.bound.trust_digest(baseline));args.settings=str(Path(args.data)/'recovery-settings.json');driver.write(args.settings,settings);args.settings_sha256=driver.sha(Path(args.settings).read_bytes())
 need(checkpoint(api,args)==one,'seq1 unchanged during signed recovery construction');two=api.apply(args);driver.committed(two,before,after);final=api.Runtime(args,config).tree(root);preserved=driver.preserved(baseline,final,protected);inventory={p['name']:p['version']for p in driver.database(root,observed=final)};need(inventory==after,'actual607 recovered signed database')
 end=checkpoint(api,args);recovery_signed=dict(metadata_sha256=driver.sha(Path(args.metadata).read_bytes()),release_sha256=driver.sha((Path(args.bundle)/'release.json').read_bytes()),signature=pin(Path(args.signature).read_bytes()),certificate=pin(Path(args.public_keyring).read_bytes()));need(end['metadata_sha256']==recovery_signed['metadata_sha256']and end['release_sha256']==recovery_signed['release_sha256']==two['release_sha256'],'recovery checkpoint joins fresh signed release');need(end['sequence']==2 and end['signer']==one['signer']and end['namespace']==one['namespace'],'actual durable seq2 antirollback checkpoint')
 source_after=observation(api,Path(args.source),config);need(source_after['nodes']==state['source_before']['nodes']and source_after.get('hardlink_groups')==state['source_before'].get('hardlink_groups'),'whole persistent source preserved through restore/recovery')
 receipt=dict(status='PASS_OWNED_FILESYSTEM_ROLLBACK_AND_SIGNED_FORWARD_RECOVERY',case='normal',scope='OWNED_GENERIC16K_COPIED_ROOT_ONLY',normal_report_scope='INITIAL_SIGNED_UPDATE_ONLY',committed_transactions_total=2,package_downgrade_attempted=False,identity=state['lease'].identity,certificate=cert,initial_signed_release=initial_signed,recovery_signed_release=recovery_signed,initial_checkpoint=one,checkpoint_after_filesystem_restore=one,recovery_checkpoint=end,snapshot=state['snapshot_summary'],baseline=state['baseline_summary'],restored=restored,rollback=restore,recovery=dict(status='PASS',committed_transactions=1,sequence=2,commit_started=two['commit_started'],packages_committed=two['packages_committed'],checkpoint_changed=two['checkpoint_changed'],checkpoint_directory_synced=two['checkpoint_directory_synced'],initialization=init,inventory_sha256=driver.inventory_sha(inventory),preservation=preserved,certificate=cert),source_preserved=True,protected_payload_sha256=state['protected_sha256'],cleanup=dict(main='PENDING',snapshot='PENDING'),lease=dict(fd_closed=False))
 state['receipt']=receipt;state['lease'].check();return receipt

def finish(state,result,copy_report):
 if state is None:return
 error=None
 try:
  if state['snapshot']is not None:state['snapshot'].__exit__(None,None,None)
 except BaseException as e:error=e
 try:lease=state['lease'].close()
 except BaseException as e:
  lease=dict(fd_closed=False,error_type=type(e).__name__)
  if error is None:error=e
 result['emulated16k_lease']=lease
 if state['receipt']is not None:
  state['receipt']['cleanup']=dict(main=copy_report.get('cleanup'),snapshot=state['snapshot_report'].get('cleanup'));state['receipt']['lease']=lease
  if result.get('status')=='PASS'and error is None:verify_lifecycle_result(state['receipt'],state['lease'].identity)
 if error is not None:raise error

def verify_lifecycle_result(v,identity):
 """Pure closed DATA predicate; passive reader compiles this exact whole body."""
 import re
 def require(ok,why):
  if not ok:raise ValueError(why)
 require(type(v)is dict and v.get('status')=='PASS_OWNED_FILESYSTEM_ROLLBACK_AND_SIGNED_FORWARD_RECOVERY'and v.get('case')=='normal'and v.get('scope')=='OWNED_GENERIC16K_COPIED_ROOT_ONLY'and v.get('normal_report_scope')=='INITIAL_SIGNED_UPDATE_ONLY','explicit owned lifecycle result')
 require(type(v.get('committed_transactions_total'))is int and v['committed_transactions_total']==2 and v.get('package_downgrade_attempted')is False and v.get('source_preserved')is True,'two signed forward commits and no downgrade')
 require(v['identity']==identity and re.fullmatch('[a-f0-9]{40}',identity['source'])and re.fullmatch('[a-f0-9]{32}',identity['nonce'])and re.fullmatch('[A-F0-9]{40}',identity['signer']),'whole lifecycle source/nonce/signer')
 require(v['baseline']==v['snapshot']==v['restored']and type(v['baseline']['package_count'])is int and v['baseline']['package_count']==607,'actual complete607 snapshot/rollback equality')
 for k in('nodes_sha256','hardlink_groups_sha256','database_sha256','inventory_sha256','payload_sha256'):require(re.fullmatch('[a-f0-9]{64}',v['baseline'][k]),'whole rollback observation pin')
 require(set(v['baseline']['caches'])=={'etc/ld.so.cache','var/cache/ldconfig/aux-cache'}and all(re.fullmatch('[a-f0-9]{64}',x)for x in v['baseline']['caches'].values()),'both restored original cache pins')
 one=v['initial_checkpoint'];two=v['recovery_checkpoint'];require(v['checkpoint_after_filesystem_restore']==one and type(one['sequence'])is int and one['sequence']==1 and type(two['sequence'])is int and two['sequence']==2,'checkpoint1 preserved thencheckpoint2')
 require(one['signer']==two['signer']==identity['signer']and one['namespace']==two['namespace'],'same signed namespace')
 for record,signed in((one,v['initial_signed_release']),(two,v['recovery_signed_release'])):require(record['metadata_sha256']==signed['metadata_sha256']and record['release_sha256']==signed['release_sha256']and signed['certificate']==v['certificate'],'actual checkpoint and signed release/certificate joins')
 require(v['baseline']['inventory_sha256']=='72818a8a2ae488281b08486b92c435ec244ef3b5313f23b97473d1684ecb68b4'and v['recovery']['inventory_sha256']=='be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5','fixed before/after607 selected inventory identities')
 r=v['recovery'];require(r['status']=='PASS'and type(r['committed_transactions'])is int and r['committed_transactions']==1 and r['sequence']==2 and all(r.get(k)is True for k in('commit_started','packages_committed','checkpoint_changed','checkpoint_directory_synced')),'actual signed recovery and durable checkpoint')
 require(r['initialization']['result']['status']=='PASS'and r['initialization']['result']['source_preserved']is True and r['certificate']==v['certificate'],'held initializer and same certificate')
 require(v['rollback']['status']=='PASS_FD_BOUND_NOREPLACE_OWNED_FILESYSTEM_RESTORE'and v['rollback']['package_downgrade_attempted']is False,'guarded filesystem restore')
 require(v['cleanup']==dict(main='PASS-owned-workspace-removed',snapshot='PASS-owned-workspace-removed'),'both workspaces retired')
 lease=v['lease'];require(lease['fd_closed']is True and lease['release']=='CLOSE_ONLY_OWNED_RECEIPT_PRESERVED'and lease['kind']=='NEW_PRIVATE_CI_LEASE_NOT_PRODUCTION_TTL'and lease['held_from']=='BEFORE_FIRST_COPY'and lease['held_through']=='ORDERED_COPY_SNAPSHOT_RETIREMENT'and lease['clock_scope']=='SAME_OWNED_GUEST_KERNEL_MONOTONIC_ONLY'and lease['acquired_monotonic_ns']<lease['ended_monotonic_ns']<lease['effective_deadline_monotonic_ns'],'finite owned CI lease throughcleanup')
 require(len(str(v))<=65536,'bounded lifecycle receipt')
 return dict(status='PASS_LIFECYCLE_DATA_NOT_ROOT_ADMISSION',committed_transactions_total=2,hardware='NOT_RUN',release='NOT_ADMITTED')
