# SPDX-License-Identifier: MIT
"""Five-cap copied574→607 provisioner and exact owned-root retirement."""
import gzip,hashlib,json,os,stat,sys,time,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import case as C,desktop622 as X,formation622 as F,media
ROLES={'current607-inputs','fresh607-source','current607-code','baseline-cache'}
ROOT=Path('/measurement/current607')

def profile():return C.decode(C.read(Path(__file__).with_name('composition.json'),4*1024**2))
def private_scope(original):return X.clone(original,INFRASTRUCTURE=original.INFRASTRUCTURE|ROLES)
def capabilities(helper,raw,omitted):
 import inspect
 body=inspect.getsource(helper.derive);old="'etc/hosts','etc/hostname','etc/resolv.conf'},'only existing persistent-scope boundaries')";new="'etc/hosts','etc/hostname','etc/resolv.conf','current607-inputs','fresh607-source','current607-code','baseline-cache'},'only existing persistent-scope boundaries')"
 C.need(body.count(old)==1,'finite exact original capability boundary allowlist');changed=body.replace(old,new);C.need(changed.replace(new,old)==body,'whole original capability derivation inverse')
 namespace=dict(vars(helper));exec(compile(changed,'core622-fixed-infrastructure-caps','exec'),namespace);return namespace['derive'](raw,omitted)

def readonly(root,identity=None):
 root=Path(root);C.need(root.is_absolute()and not any(p.is_symlink()for p in(root,*root.parents)),'literal ordinary read-only bind role');fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);C.need(stat.S_ISDIR(st.st_mode)and os.fstatvfs(fd).f_flag&os.ST_RDONLY,'fresh actual read-only bind readback');C.need(identity is None or [st.st_dev,st.st_ino]==identity,'exact actual provisioned root inode');C.need(C.identity(st)==C.identity(os.fstat(fd))==C.identity(root.stat()),'stable actual root descriptor/path')
 finally:os.close(fd)

def proof_output(uid,gid):
 """Refuse an unwritable proof bind before formation or destructive retirement."""
 root=Path('/out');C.need(type(uid)is type(gid)is int and uid>=0 and gid>=0 and root.is_absolute()and not any(p.is_symlink()for p in(root,*root.parents)),'ordinary fixed owned proof-output directory');fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  st=os.fstat(fd);C.need(stat.S_ISDIR(st.st_mode)and stat.S_IMODE(st.st_mode)==0o700 and(st.st_uid,st.st_gid)==(uid,gid)and not(os.fstatvfs(fd).f_flag&os.ST_RDONLY),'actual writable owned0700 proof-output bind');C.need(C.identity(st)==C.identity(os.fstat(fd))==C.identity(root.lstat()),'stable actual proof-output descriptor/path')
 finally:os.close(fd)

def owned(selected,*,initialization=False,worker=False):
 C.selection(selected);C.need(type(initialization)is type(worker)is bool and(not worker or initialization),'finite owned initialization role');pid_ok=(os.getpid()!=1 and os.getppid()==1)if worker else os.getpid()==1
 C.need(pid_ok and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and Path('/.dockerenv').is_file()and os.environ.get('CAA_CORE7_PREPARE')==selected['nonce']and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned offline original preparer or its direct initialization worker')
 fields=dict(v.split(':',1)for v in Path('/proc/self/status').read_text().splitlines()if ':'in v);mask=0x8000001b|(1<<18 if initialization else 0)
 C.need(all(int(fields[k],16)==mask for k in('CapEff','CapPrm','CapBnd'))and int(fields['CapInh'],16)==int(fields['CapAmb'],16)==0 and fields['NoNewPrivs'].strip()=='1','exact scoped five caps plus SYS_CHROOT only for owned607 initialization and NNP');return selected

def write(name,value,uid,gid,compressed=False):
 raw=C.encoded(value);C.need(len(raw)<=256*1024**2,'original full graph raw cap');raw=gzip.compress(raw,mtime=0)if compressed else raw;C.need(len(raw)<=64*1024**2 and sum(p.stat().st_size for p in Path('/out').iterdir()if p.is_file())+len(raw)<=512*1024**2,'original aggregate export cap');path=Path('/out')/name;C.need(not path.exists(),'fresh fixed complete proof leaf');path.write_bytes(raw);os.chown(path,uid,gid);return C.pin(raw)

def payload(P,ready,rows,code,end):
 """Keep original archive parser limits; clamp its clock to this same phase."""
 old_load=P.load
 def load(name,path):
  module=old_load(name,path)
  if str(path).endswith('/scripts/update/archive_stream.py'):
   original=module.Limits;module=X.clone(module)
   def limits(*args,**kw):
    values=list(args);C.need(len(values)==7 and not kw,'held seven-field payload parser limits');values[-1]=min(values[-1],end);return original(*values)
   module.Limits=limits
  return module
 out=X.clone(P,load=load);result=out.payload(ready,rows,code);C.need(time.monotonic()<end,'whole payload before original phase expiry');return result

def keys(api,record,end):
 path=Path('/tmp/current607-public-gpg');C.need(not path.exists(),'fresh public-only provisioning key home');path.mkdir(mode=0o700);(path/'gpg.conf').write_text('no-auto-key-retrieve\nauto-key-locate clear\nno-autostart\n');argv=['/usr/bin/gpg','--batch','--no-options','--homedir',str(path),'--no-auto-key-retrieve','--auto-key-locate','clear','--no-autostart']
 def command(args,seconds=30):
  remaining=end-time.monotonic();C.need(remaining>0,'same provisioning phase clock');row,out,err,error=api['runtime'].run_command(args,Path('/tmp'),dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',HOME='/tmp',TMPDIR='/tmp'),min(seconds,remaining),1024**2);C.need(error is None and row['exit_code']==0 and row['group_absence_verified'],'original public-key command exit/group absence');return out
 for k in record['keyrings']:
  C.need(k['path'].startswith('keys/')and '/'not in k['path'][5:],'flat exact fresh public key role');C.need(C.pin(C.read(Path('/current607-inputs')/k['path']))==dict(bytes=k['size'],sha256=k['sha256']),'every fresh public key byte')
 command(argv+['--import',*[str(Path('/current607-inputs')/k['path'])for k in record['keyrings']]]);C.need(not command(argv+['--with-colons','--list-secret-keys']),'no secret key mounted into provisioner')
 trust=path/'ownertrust';trust.write_text(''.join(s+':6:\n'for s in sorted(record['preparation']['signer_roles'].values())));command(argv+['--import-ownertrust',str(trust)]);return path,command

def auxiliary_diagnostic(core,root,graph,limits,raw,before):
 """Failure DATA only. Never repair a cache or grant live-key acceptance."""
 import base64,aux_checkpoint
 A=core.F.A;records=A.parse(raw);wanted={key for key,_ in records}
 def emit(kind,value,cap):
  text=json.dumps(dict(kind=kind,acceptance=False,hardware='NOT_RUN',**value),sort_keys=True,separators=(',',':'),allow_nan=False)+'\n'
  C.need(len(text.encode())<=cap,'bounded auxiliary failure DATA');sys.stderr.write(text);sys.stderr.flush()
 # Emit whole raw DATA first, so later deadline/read failures cannot hide it.
 previous={k:before['nodes'][core.F.AUX][k]for k in('bytes','sha256')}
 emit('CORE622_LIVE_AUX_RAW',dict(raw=C.pin(raw),data=base64.b64encode(raw).decode(),copied_before=previous,raw_equal_to_copied_before=C.pin(raw)==previous,records=len(records),key_fields=['ino','ctime_seconds','size','dev'],observation='AFTER_ORIGINAL_CAPTURE_REFUSAL'),384*1024)
 nodes=graph['nodes'];roots=core.api['roots'];copy=core.api['copy'].measure_copy;rows=[];reader=aux_checkpoint.Reader(root,graph,limits)
 with copy._descriptors()as held:
  descriptor=roots._open_root(root);held.append(descriptor);rootid=roots._identity(os.fstat(descriptor));mount=roots._mount_id(descriptor,limits)
  for name,node in sorted(nodes.items()):
   limits.tick()
   if not(name.startswith('usr/lib/')and node.get('type')=='file'):continue
   with copy._parent(descriptor,name,mount,{},limits,nodes)as(parent,leaf):
    info=os.stat(leaf,dir_fd=parent,follow_symlinks=False);copy._metadata_equal(info,node)
    C.need(stat.S_ISREG(info.st_mode)and info.st_size==node['bytes'],'diagnostic observed regular file size/type')
    C.need(roots._identity(info)==roots._identity(os.stat(leaf,dir_fd=parent,follow_symlinks=False)),'stable diagnostic library stat')
    rows.append((name,(info.st_ino,info.st_ctime_ns//10**9,info.st_size,info.st_dev)))
  copy._root_check(root,descriptor,rootid,mount,limits)
 observed={key for _,key in rows};missing=[i for i,(key,_)in enumerate(records)if key not in observed];samples=[];hashed=0;budget=64*1024**2
 for index in missing[:16]:
  limits.tick();key,payload=records[index];soname=payload[1];choices=[]
  for name,live in rows:
   limits.tick()
   same_object=(live[0],live[3])==(key[0],key[3]);same_size=live[2]==key[2];same_name=soname is not None and os.fsencode(name.rsplit('/',1)[-1])==soname
   if same_object or same_size or same_name:choices.append(((not same_object,not same_name,not same_size,name),name,live))
  candidates=[]
  for _,name,live in sorted(choices)[:4]:
   size=nodes[name]['bytes']
   if size>budget-hashed:
    candidates.append(dict(path=name,verification='NOT_READ_DIAGNOSTIC_BYTE_CAP'));continue
   limits.tick();row=reader.literal(name);identity=row['identity'];actual=(identity[1],identity[8]//10**9,identity[6],identity[0]);C.need(actual==live,'diagnostic candidate did not race');hashed+=size
   candidates.append(dict(path=name,key=list(actual),identity=list(identity),node=row['node'],verification='FULL_HASH_DESCRIPTOR_OBSERVATION_ONLY',different_fields=[n for n,a,b in zip(('ino','ctime_seconds','size','dev'),key,actual)if a!=b]))
  samples.append(dict(cache_index=index,candidates=candidates))
 emit('CORE622_LIVE_AUX_KEYS',dict(scope='usr/lib/ regular files, same as original capture',stat_only=True,stat_files=len(rows),stat_matching_keys=len(wanted&observed),missing_cache_indices=missing,samples=samples,sample_limit=16,candidates_per_sample=4,hashed_bytes=hashed,hash_byte_cap=budget,cause='NOT_ESTABLISHED'),256*1024)

def capture_auxiliary(core,root,graph,limits,before):
 raw=core.F.read_aux(root)
 try:return core.F.capture(core.api,root,graph,limits,raw)
 except ValueError as original:
  if str(original)=='every auxiliary record has an actual observed live library key':
   try:auxiliary_diagnostic(core,root,graph,limits,raw,before)
   except Exception as error:
    # The original refusal wins even if the same phase deadline has expired.
    try:
     sys.stderr.write(json.dumps(dict(kind='CORE622_LIVE_AUX_DIAGNOSTIC_INCOMPLETE',error_type=type(error).__name__,acceptance=False),separators=(',',':'))+'\n');sys.stderr.flush()
    except Exception:pass
  raise

def cleanup_preserving_primary(command,keyhome):
 """Attempt the original cleanup; preserve the first failure if both fail."""
 primary=sys.exception()
 try:command(['/usr/bin/gpgconf','--homedir',str(keyhome),'--kill','all'],15)
 except Exception as error:
  if primary is None:raise
  primary.add_note('provisioning public-key cleanup also failed: '+type(error).__name__+': '+str(error)[:256])


def initialization_lease(selected,root):
 C.need(root==ROOT and root.is_absolute()and not any(p.is_symlink()for p in(root,*root.parents))and stat.S_ISDIR(root.lstat().st_mode),'only fixed ordinary owned607 initialization target');lease=C.decode(C.read(root.parent/'current607-lease.json'));C.need(lease['nonce']==selected['nonce']and lease['status']=='OWNED_CURRENT607_ROOT_LIVE'and lease['root']==[root.lstat().st_dev,root.lstat().st_ino]and lease['parent']==[root.parent.stat().st_dev,root.parent.stat().st_ino],'same source-owned607 lease/root/parent/nonce');return lease

def exec_owned_auxiliary(core,root,graph,limits,lease):
 """Pin helper by FD, enter only the owned copy, close root FD, exec by FD."""
 import aux_checkpoint
 roots=core.api['roots'];copy=core.api['copy'].measure_copy;rootfd=roots._open_root(root);helper=None
 try:
  info=os.fstat(rootfd);C.need([info.st_dev,info.st_ino]==lease['root'],'exact leased root descriptor before chroot');identity=roots._identity(info);mount=roots._mount_id(rootfd,limits)
  with copy._parent(rootfd,aux_checkpoint.HELPER_NODE,mount,{},limits,graph['nodes'])as(parent,leaf):
   helper=os.open(leaf,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);info=os.fstat(helper);copy._metadata_equal(info,graph['nodes'][aux_checkpoint.HELPER_NODE]);C.need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and info.st_size==aux_checkpoint.HELPER[1]and roots._file_hash(helper,info,limits)==aux_checkpoint.HELPER[0],'whole pinned original auxiliary helper descriptor');C.need(roots._mount_id(helper,limits)==mount,'same owned helper mount')
   C.need(roots._identity(info)==roots._identity(os.stat(leaf,dir_fd=parent,follow_symlinks=False)),'helper descriptor/path stable before execution')
  copy._root_check(root,rootfd,identity,mount,limits);limits.tick();C.need(os.execve in os.supports_fd,'required original FD exec support')
  os.fchdir(rootfd);os.chroot('.');os.chdir('/');os.close(rootfd);rootfd=None
  os.execve(helper,['/usr/bin/ldconfig'],dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',HOME='/',TMPDIR='/tmp'))
 finally:
  if helper is not None:os.close(helper)
  if rootfd is not None:os.close(rootfd)

def initialize_worker():
 selected=owned(C.decode(C.read('/workspace/selection.json')),initialization=True,worker=True);lease=initialization_lease(selected,ROOT);end=float(os.environ['CAA_CORE622_PHASE_END']);C.need(0<end-time.monotonic()<=1900,'same original provisioning phase in initialization child')
 import adapter
 core=adapter.core(Path('/workspace/core-source'));roots=core.api['roots'];limits=roots.Limits(deadline=min(end,time.monotonic()+150),max_packages=622,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3);limits.tick();sys.path.insert(0,str(core.root/'runtime/runtime-vm/scripts/update'));import aux_checkpoint,root_link_selection
 graph=roots.observe(ROOT,limits=limits,hardlinks='generic-development-internal',absolute_paths=True);root_link_selection.check(graph,limits);aux_checkpoint.checkpoint(ROOT,graph,limits);exec_owned_auxiliary(core,ROOT,graph,limits,lease)

def initialization_change(before,after,old,new):
 import aux_checkpoint
 caches={aux_checkpoint.MAIN_CACHE,aux_checkpoint.AUX_CACHE};C.need(before['complete']is after['complete']is True and set(before['unsupported_counts'])<={'absolute-symlink','auxiliary-present'}and set(after['unsupported_counts'])<={'absolute-symlink','auxiliary-present'},'both complete initialization graphs')
 C.need({n:v for n,v in before['nodes'].items()if n not in caches}=={n:v for n,v in after['nodes'].items()if n not in caches}and before['hardlink_groups']==after['hardlink_groups'],'only two generated cache nodes may change during initialization')
 for name,mode in((aux_checkpoint.MAIN_CACHE,0o644),(aux_checkpoint.AUX_CACHE,0o600)):
  node=new['caches'][name]['node'];C.need(node['type']=='file'and(node['uid'],node['gid'],node['mode'])==(0,0,mode),'ordinary root-owned initialized cache metadata')
 for field in('helper','configs','aliases','scan','targets','closure','scan_directories'):C.need(old[field]==new[field],'initialization held helper/config/library closure: '+field)
 C.need({n:v for n,v in old['caches'].items()if n not in caches}=={n:v for n,v in new['caches'].items()if n not in caches},'cache parent inode/metadata and temporary absences held');return dict(unrelated_nodes_preserved=True,library_closure_preserved=True,cache_parent_and_temps_preserved=True)

def initialize_auxiliary(core,root,graph,limits,selected):
 """One declared preparation step; original live-key acceptance follows it."""
 import base64,aux_checkpoint
 lease=initialization_lease(selected,root);old=aux_checkpoint.checkpoint(root,graph,limits);intent=dict(nonce=selected['nonce'],root=lease['root'],phase_deadline=limits.deadline,status='ONE_OWNED_ROOT_AUX_INITIALIZATION_STARTED')
 marker=Path('/tmp/current607-aux-initialization-started');fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb')as stream:stream.write(C.encoded(intent))
 limits.tick();remaining=limits.deadline-time.monotonic();C.need(remaining>0,'same remaining provisioning clock before helper');argv=[sys.executable,'-I','-B','/workspace/provision622.py','initialize607'];env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',HOME='/tmp',TMPDIR='/tmp',PYTHONDONTWRITEBYTECODE='1',CAA_CORE7_PREPARE=selected['nonce'],CAA_CORE622_PHASE_END=str(limits.deadline))
 row,out,err,error=core.api['runtime'].run_command(argv,Path('/tmp'),env,min(180,remaining),65536);receipt=dict(command=row,stdout=C.pin(out),stderr=C.pin(err));sys.stderr.write(json.dumps(dict(kind='CORE622_OWNED_AUX_INITIALIZATION_WORKER',acceptance=False,**receipt,stdout_data=base64.b64encode(out).decode(),stderr_data=base64.b64encode(err).decode()),sort_keys=True,separators=(',',':'))+'\n');sys.stderr.flush()
 if error is not None:raise error
 C.need(row['exit_code']==0 and row['group_absence_verified'],'one pinned helper foreground exit and group retirement');limits.tick();after=core.api['roots'].observe(root,limits=limits,hardlinks='generic-development-internal',absolute_paths=True);new=aux_checkpoint.checkpoint(root,after,limits);preservation=initialization_change(graph,after,old,new);live=aux_checkpoint.live_keys(new,core.F.A)
 proof=dict(status='PASS_ONE_OWNED_ROOT_AUX_INITIALIZATION',helper=receipt,preservation=preservation,live_cache_keys=live,phase_deadline=limits.deadline,cache_hashes={name:dict(before=old['caches'][name]['node']['sha256'],after=new['caches'][name]['node']['sha256'])for name in sorted((aux_checkpoint.MAIN_CACHE,aux_checkpoint.AUX_CACHE))},hardware='NOT_RUN',normal_hook_installation=False)
 return after,new,proof


def prepare():
 selected=owned(C.decode(C.read('/workspace/selection.json')),initialization=True);ms=C.decode(C.read('/workspace/media-selection.json'));proof_output(ms['uid'],ms['gid']);value=profile();end=float(os.environ['CAA_CORE622_PHASE_END']);C.need(0<end-time.monotonic()<=1900 and not ROOT.exists(),'fresh owned607 root inside unchanged1900 media phase')
 for role in ROLES:readonly(Path('/')/role)
 out=Path('/measurement');st=out.stat();lease=dict(schema=1,nonce=selected['nonce'],parent=[st.st_dev,st.st_ino],root=None,status='INTENT_FRESH_OWNED607_PROVISION',phase_deadline=end);(out/'current607-lease.json').write_bytes(C.encoded(lease));os.chown(out/'current607-lease.json',ms['uid'],ms['gid'])
 D=media.module('/source');scope,roots,copier,_=D.apis();scope=private_scope(scope);limits=roots.Limits(deadline=end,max_packages=622,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3)
 policy=scope.mount_policy(Path('/'),ROOT,scope.mounts(scope._mount_table()));before,_=scope.source_manifest(Path('/'),limits,roots,policy);caps=capabilities(D.cap_scope,C.read('/source/media-source/scripts/apps/file_capabilities.py'),set(policy['observed_mounts'])|scope.RUNTIME);mapping=caps.observe(Path('/'),D.cap_scope.nodes(before),limits)
 copy=copier.copy_data(Path('/'),ROOT,limits=limits,excluded=scope.RUNTIME|(scope.INFRASTRUCTURE&set(policy['observed_mounts']))|scope.MOUNT_FILES,absolute_paths=True);C.need(not copy['unsupported_counts'],'whole original five-cap copy without omissions');scope._restore_boundaries(Path('/'),ROOT,before,roots,copier,limits)
 measured=roots.observe(ROOT,limits=limits,hardlinks='generic-development-internal',absolute_paths=True);C.need(measured['complete']and measured['nodes']==before,'complete actual574 copied nodes/hardlinks');caps.restore(ROOT,D.cap_scope.nodes(measured['nodes']),mapping,limits)
 st=ROOT.stat();lease.update(root=[st.st_dev,st.st_ino],status='OWNED_CURRENT607_ROOT_LIVE');(out/'current607-lease.json').write_bytes(C.encoded(lease));os.chown(out/'current607-lease.json',ms['uid'],ms['gid'])
 import adapter
 core=adapter.core(Path('/workspace/core-source'));api=core.api;initial=api['db'].database(ROOT,max_packages=622,max_files=100000,max_nodes=500000,observed=measured['nodes']);C.need({r['name']:r['version']for r in initial}==value['before574'],'actual574 copied database')
 ready=Path('/current607-inputs');record=C.decode(C.read(ready/'manifest.json',4*1024**2));rows=X.manifest(value,record);P=C.load('_core622_original_full607_archive_parser',Path('/fresh607-source/parent604/profile.py'))
 for r in rows:
  for rel,pin in((r['archive'],dict(bytes=r['size'],sha256=r['sha256'])),(r['signature'],dict(bytes=r['signature_size'],sha256=r['signature_sha256']))):P.checked(ready,rel,pin,maximum=256*1024**2)
 signed=payload(P,ready,rows,Path('/current607-code'),end);C.need(signed['packages']==value['before607'],'complete authenticated607 payload projection')
 rawlock=C.decode(C.read('/workspace/core-source/scripts/ci/core-native-lifecycle/retained/desktop574-inputs.lock.json',4*1024**2));retired=next(r for r in rawlock['packages']if r['name']=='libfdk-aac');oldpath=Path('/baseline-cache')/retired['filename'];C.need(C.pin(C.read(oldpath,128*1024**2))==dict(bytes=retired['size'],sha256=retired['sha256']),'exact original upstream codec archive');removed=core.C.P.archive(oldpath)
 keyhome,command=keys(api,record,end)
 try:
  operands=[dict(r,archive=ready/r['archive'],signature=ready/r['signature'])for r in rows];transaction=X.provision(api,ROOT,keyhome,Path('/out/current607-provision.log'),operands,value,end)
  graph=roots.observe(ROOT,limits=limits,hardlinks='generic-development-internal',absolute_paths=True);actual_caps=caps.observe(ROOT,D.cap_scope.nodes(graph['nodes']),limits);final=api['db'].database(ROOT,max_packages=622,max_files=100000,max_nodes=500000,observed=graph['nodes'])
  sys.path.insert(0,str(core.root/'runtime/runtime-vm/scripts/update'));import aux_checkpoint,root_link_selection
  root_link_selection.check(graph,limits);graph,checkpoint,initialization=initialize_auxiliary(core,ROOT,graph,limits,selected);aux=capture_auxiliary(core,ROOT,graph,limits,measured);core.F.check_record(aux,graph['nodes']);auxiliary=dict(status='FULL_FD_CHECKPOINT_AND_LIVE_AUXILIARY_LIBRARY_KEYS',checkpoint=api['capabilities'].digest({k:v for k,v in checkpoint.items()if k not in('main_bytes','aux_bytes')}),live_auxiliary=aux,initialization=initialization)
  raw_database=retain_database_evidence(api,ROOT,graph,final,selected,lease,ms['uid'],ms['gid'])
  validation=F.check(value,measured,graph,mapping,actual_caps,signed,removed,initial,final,auxiliary);source_after,_=scope.source_manifest(Path('/'),limits,roots,policy);C.need(source_after==before and caps.observe(Path('/'),D.cap_scope.nodes(source_after),limits)==mapping,'complete original image source nodes/caps unchanged')
  files={};files['current607-database-raw.json.gz']=raw_database['compressed'];files['current607-root.json.gz']=write('current607-root.json.gz',graph,ms['uid'],ms['gid'],True);files['current607-capabilities.json']=write('current607-capabilities.json',actual_caps,ms['uid'],ms['gid']);files['current607-database.json']=write('current607-database.json',final,ms['uid'],ms['gid']);files['current607-auxiliary.json']=write('current607-auxiliary.json',auxiliary,ms['uid'],ms['gid'])
  report=dict(schema=1,status=validation['status'],nonce=selected['nonce'],scope=X.PROVISIONING,normal_hook_installation=False,root_identity=lease['root'],parent_identity=lease['parent'],copy=copy,transaction=transaction,validation=validation,files=files,graph_nodes_sha256=hashlib.sha256(json.dumps(graph['nodes'],sort_keys=True).encode()).hexdigest(),capabilities_sha256=api['capabilities'].digest(actual_caps),database_sha256=value['fresh607']['sha256'],packages=607,phase_deadline=end,fit='NOT_ESTABLISHED',hardware='NOT_RUN');write('current607-formation.json',report,ms['uid'],ms['gid']);return report
 finally:cleanup_preserving_primary(command,keyhome)

def retire():
 selected=owned(C.decode(C.read('/workspace/selection.json')));ms=C.decode(C.read('/workspace/media-selection.json'));proof_output(ms['uid'],ms['gid']);lease=C.decode(C.read('/measurement/current607-lease.json'));C.need(lease['nonce']==selected['nonce']and lease['root']is not None and [ROOT.parent.stat().st_dev,ROOT.parent.stat().st_ino]==lease['parent'],'exact owned parent/nonce before retirement')
 import adapter
 api=adapter.core('/workspace/core-source').api;limits=api['roots'].Limits(deadline=float(os.environ['CAA_CORE622_PHASE_END']),max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3);limits.tick();sys.path.insert(0,str(Path('/workspace/core-source/runtime/runtime-vm/scripts/update')));import disposable_copy
 parent=api['roots']._open_root(ROOT.parent);fd=None
 try:
  fd=os.open(ROOT.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);mount=api['roots']._mount_id(fd,limits);C.need([os.fstat(fd).st_dev,os.fstat(fd).st_ino]==lease['root'],'same actual provisioned607 root identity');disposable_copy._same(parent,ROOT.name,fd,tuple(lease['root']),mount,limits);disposable_copy._empty(fd,mount,limits,[0]);disposable_copy._same(parent,ROOT.name,fd,tuple(lease['root']),mount,limits);os.rmdir(ROOT.name,dir_fd=parent);C.need(not ROOT.exists(),'actual owned607 root removed before original cleanup')
 finally:
  if fd is not None:os.close(fd)
  os.close(parent)
 return write('current607-retirement.json',dict(status='PASS_EXACT607_ROOT_REMOVED_BEFORE_ORIGINAL_CLEANUP',nonce=selected['nonce'],root=lease['root'],parent=lease['parent']),ms['uid'],ms['gid'])


# Original-byte607 input/database evidence; no actor or budget authority.
CURRENT_EXPORT_CAPS=dict(archive=128*1024**2,export_archives=647070676,signatures=1024**2,signature=1024,keys=8192,key=4096,verification=2*1024**2,verification_stream=16384,input_raw=4*1024**2,input_gzip=2*1024**2,db_files=2048,db_file=512*1024,db_bytes=16*1024**2,db_raw=24*1024**2,db_gzip=8*1024**2)
CURRENT_DB='var/lib/pacman/local/'

def export_blob(raw,cap):
 import base64
 C.need(type(raw)is bytes and len(raw)<=cap,'bounded complete original607 raw evidence');return dict(pin=C.pin(raw),data_base64=base64.b64encode(raw).decode('ascii'))

def export_encoded(value,raw_cap,gzip_cap):
 raw=C.encoded(value);C.need(len(raw)<=raw_cap,'bounded complete original607 JSON before compression');packed=gzip.compress(raw,mtime=0);C.need(len(packed)<=gzip_cap,'bounded complete original607 gzip');return raw,packed

def export_selection(proof):
 selected=proof['selection'];C.selection(selected);actual=selected['actual'];C.need(actual['source']==proof['source_sha']and type(proof['run_id'])is str and str(actual['run'])==proof['run_id']and actual['attempt']==proof['attempt']==1 and proof['consumer_token']==selected['nonce']and selected['nonce']==hashlib.sha256(('current607-core622:'+actual['source']+':'+str(actual['run'])).encode()).hexdigest()[:32],'whole current607 source/run/nonce export join');C.need(type(proof['producer_token'])is str and __import__('re').fullmatch('[0-9a-f]{16,32}',proof['producer_token']),'actual original producer token');return selected

def input_evidence(ready,record,proof,verification,references):
 """All607 signatures/keys plus exact exported/referenced original archives."""
 ready=Path(ready);selected=export_selection(proof);rows=X.manifest(profile(),record);caps=CURRENT_EXPORT_CAPS;C.need(type(verification)is list and len(verification)==607,'all607 original verifier invocations required');by_archive={};spent=0
 import base64
 for item in verification:
  C.need(type(item)is dict and set(item)=={'argv','returncode','stdout_base64','stderr_base64','time_limit'}and type(item['argv'])is list and all(type(v)is str for v in item['argv'])and item['returncode']==0 and type(item['returncode'])is int and item['time_limit']==30,'original successful bounded verification DATA')
  argv=item['argv'];C.need(len(argv)==12 and argv[:4]==['gpg','--batch','--no-options','--homedir']and argv[5:10]==['--no-auto-key-retrieve','--auto-key-locate','clear','--status-fd=1','--verify']and Path(argv[4]).name=='latest607-verifier'and Path(argv[4]).parent.name=='private'and Path(argv[4]).parent.parent.parent==Path('/tmp'),'entire original public verifier argv/home');C.need(Path(argv[-1]).parent==ready/'packages'and argv[-2]==argv[-1]+'.sig'and argv[-1]not in by_archive,'unique original archive verification operands');by_archive[argv[-1]]=item
  for field in('stdout_base64','stderr_base64'):
   raw=base64.b64decode(item[field],validate=True);C.need(len(raw)<=caps['verification_stream'],'bounded original verification stream');spent+=len(raw)
 C.need(spent<=caps['verification'],'bounded whole607 verification DATA aggregate');packages={};totals=dict(archives=0,signatures=0,keys=0);test=record['preparation']['signer_roles']['ephemeral_TEST'];upstream=record['preparation']['signer_roles']['upstream_ALARM'];counts=dict(TEST=0,upstream=0,reference=0)
 C.need(type(references)is dict and len(references)==337,'fixed337 existing archive DATA references')
 for row in rows:
  C.need(row['archive']=='packages/'+Path(row['archive']).name and row['signature']==row['archive']+'.sig','flat exact607 raw archive/signature paths');verification_row=by_archive.get(str(ready/row['archive']));C.need(verification_row is not None,'actual607 verification to manifest byte role');status=base64.b64decode(verification_row['stdout_base64'],validate=True).decode('utf-8');valid=[v.split()for v in status.splitlines()if v.startswith('[GNUPG:] VALIDSIG ')];C.need(len(valid)==1 and len(valid[0])>=12 and row['signer']in(valid[0][2],valid[0][-1])and not any('[GNUPG:] '+v+' 'in status for v in('BADSIG','ERRSIG','REVKEYSIG','EXPKEYSIG','EXPSIG','KEYREVOKED','KEYEXPIRED','SIGEXPIRED')),'original complete607 exact signer and no expired/revoked signature status');sig=C.read(ready/row['signature'],caps['signature']);C.need(C.pin(sig)==dict(bytes=row['signature_size'],sha256=row['signature_sha256']),'whole original607 detached signature');totals['signatures']+=len(sig)
  ref=dict(bytes=row['size'],sha256=row['sha256'])
  if row['archive']in references:C.need(row['signer']==upstream and ref==references[row['archive']],'only exact fixed upstream archive may reference retained DATA');archive=dict(kind='EXACT_UPSTREAM_REFERENCE',pin=ref);counts['reference']+=1
  else:
   C.need(row['signer']in(test,upstream),'only declared607 signer role');kind='EXPORTED_CURRENT_TEST'if row['signer']==test else'EXPORTED_CURRENT_UPSTREAM';archive=dict(kind=kind,pin=ref,file='current607-inputs/'+row['archive']);totals['archives']+=row['size'];C.need(row['size']<=caps['archive'],'held128MiB per-input archive cap');counts['TEST'if row['signer']==test else'upstream']+=1
  C.need(totals['archives']<=caps['export_archives']and totals['signatures']<=caps['signatures'],'measured exact archive export and smaller signature aggregate');packages[row['name']]=dict(row=row,archive=archive,signature=export_blob(sig,caps['signature']),verification=verification_row)
 C.need(counts==dict(TEST=29,upstream=241,reference=337)and set(by_archive)=={str(ready/r['archive'])for r in rows},'exact29 run TEST/241 upstream exports/337 existing DATA refs');keys={}
 for row in record['keyrings']:
  name=row['path'];C.need(name=='keys/'+Path(name).name and name not in keys,'flat exact607 public key role');raw=C.read(ready/name,caps['key']);C.need(C.pin(raw)==dict(bytes=row['size'],sha256=row['sha256']),'whole actual607 public key');keys[name]=export_blob(raw,caps['key']);totals['keys']+=len(raw)
 C.need(len(keys)==2 and totals['keys']<=caps['keys'],'two bounded original public keys');return dict(schema=1,status='CURRENT607_ORIGINAL_SIGNED_INPUTS_DATA_ONLY',selection=selected,producer_token=proof['producer_token'],manifest=C.pin(C.read(ready/'manifest.json',4*1024**2)),packages=packages,keyrings=keys)

def retain_input_evidence(parent,ready,record,proof,verification):
 """Retain partial original bytes before any failure is propagated."""
 parent,ready=Path(parent),Path(ready);C.need(parent.is_absolute()and not any(p.is_symlink()for p in(parent,*parent.parents))and parent.is_dir(),'ordinary fixed current context evidence parent');target=parent/'current607-inputs';C.need(not os.path.lexists(target),'fresh current607 input evidence directory');target.mkdir(mode=0o700);(target/'packages').mkdir(mode=0o700);progress=dict(schema=1,status='INCOMPLETE_CURRENT607_ORIGINAL_INPUTS_DATA_ONLY',selection=export_selection(proof),producer_token=proof['producer_token'],manifest=C.pin(C.read(ready/'manifest.json',4*1024**2)),files={},error_type=None);primary=None
 try:
  references=C.decode(C.read(Path(__file__).with_name('composition-parent.json'),4*1024**2))['current_root_export']['reference_archives'];value=input_evidence(ready,record,proof,verification,references)
  for package in value['packages'].values():
   if package['archive']['kind']=='EXACT_UPSTREAM_REFERENCE':continue
   C.need(time.monotonic()<proof['export_phase_end'],'same current source owner clock during archive retention');relative=package['row']['archive'];raw=C.read(ready/relative,CURRENT_EXPORT_CAPS['archive']);C.need(C.pin(raw)==package['archive']['pin'],'whole stable raw607 archive before retention');destination=target/relative;C.need(not os.path.lexists(destination),'fresh literal raw607 archive output');destination.write_bytes(raw);C.need(C.pin(C.read(destination,CURRENT_EXPORT_CAPS['archive']))==package['archive']['pin'],'whole retained607 raw archive readback');progress['files'][package['archive']['file']]=package['archive']['pin']
  raw,packed=export_encoded(value,CURRENT_EXPORT_CAPS['input_raw'],CURRENT_EXPORT_CAPS['input_gzip']);(target/'current607-inputs.json.gz').write_bytes(packed);progress['files']['current607-inputs/current607-inputs.json.gz']=C.pin(packed);progress['status']='COMPLETE_CURRENT607_ORIGINAL_INPUTS_DATA_ONLY';return dict(file='current607-inputs/current607-inputs.json.gz',raw=C.pin(raw),compressed=C.pin(packed))
 except BaseException as error:primary=error;progress['error_type']=type(error).__name__;raise
 finally:
  try:
   raw=C.encoded(progress);C.need(len(raw)<=1024**2,'bounded actual607 capture index');(target/'capture.json').write_bytes(raw)
  except BaseException as error:
   if primary is None:raise
   primary.add_note('current607 input evidence finalization failed: '+type(error).__name__)

def database_evidence(api,root,graph,parsed,selected,lease,progress):
 """Read every graph-observed local DB original before the Core transaction."""
 root=Path(root);C.selection(selected);C.need(root==ROOT and [root.stat().st_dev,root.stat().st_ino]==lease['root']and selected['nonce']==lease['nonce'],'exact source-owned pre-Core607 database root');nodes={n:r for n,r in graph['nodes'].items()if n.startswith(CURRENT_DB)};files={n:r for n,r in nodes.items()if r['type']=='file'};progress.update(schema=1,status='INCOMPLETE_CURRENT607_ORIGINAL_ALPM_DATABASE_DATA_ONLY',selection=selected,root_identity=lease['root'],graph_nodes_sha256=hashlib.sha256(json.dumps(graph['nodes'],sort_keys=True).encode()).hexdigest(),parsed_database=C.pin(C.encoded(parsed)),nodes=nodes,records={},error_type=None);C.need(nodes and all(r['type']in('file','directory')for r in nodes.values())and 0<len(files)<=CURRENT_EXPORT_CAPS['db_files'],'complete bounded ordinary607 local DB graph');records=progress['records'];total=0;db=api['db']
 for name,node in sorted(files.items()):
  C.need(time.monotonic()<lease['phase_deadline'],'same provisioning phase clock during raw DB capture');relative=name[len(CURRENT_DB):];parts=relative.split('/');C.need(relative=='ALPM_DB_VERSION'or len(parts)==2 and parts[-1]in('desc','files','install','mtree'),'exact original ALPM local DB record role')
  with db.directory(root,name.rpartition('/')[0])as parent:
   before=os.stat(parts[-1],dir_fd=parent,follow_symlinks=False);raw=db.read_record(parent,parts[-1],maximum=CURRENT_EXPORT_CAPS['db_file'],expected=node);C.need(db.identity(before)==db.identity(os.stat(parts[-1],dir_fd=parent,follow_symlinks=False)),'original607 DB record stable through evidence capture')
  C.need(total+len(raw)<=CURRENT_EXPORT_CAPS['db_bytes'],'bounded complete607 raw DB aggregate');total+=len(raw);records[name]=dict(node=node,identity=list(db.identity(before)),**export_blob(raw,CURRENT_EXPORT_CAPS['db_file']))
 actual=api['db'].database(root,max_packages=622,max_files=100000,max_nodes=500000,observed=graph['nodes']);C.need(actual==parsed and {r['name']:r['version']for r in actual}==profile()['before607'],'whole original raw607 parser replay before evidence write');progress['status']='CURRENT607_ORIGINAL_ALPM_DATABASE_DATA_ONLY';progress.pop('error_type');return progress

def retain_database_evidence(api,root,graph,parsed,selected,lease,uid,gid):
 progress={};primary=None;result=None
 try:result=database_evidence(api,root,graph,parsed,selected,lease,progress)
 except BaseException as error:primary=error;progress['error_type']=type(error).__name__;raise
 finally:
  try:
   raw,packed=export_encoded(progress,CURRENT_EXPORT_CAPS['db_raw'],CURRENT_EXPORT_CAPS['db_gzip']);name='current607-database-raw.json.gz';path=Path('/out')/name;C.need(not os.path.lexists(path)and sum(p.stat().st_size for p in path.parent.iterdir()if p.is_file())+len(packed)<=512*1024**2,'fresh original607 DB evidence within unchanged512MiB aggregate');path.write_bytes(packed);os.chown(path,uid,gid)
  except BaseException as error:
   if primary is None:raise
   primary.add_note('current607 raw database evidence finalization failed: '+type(error).__name__)
 if result is not None:return dict(file=name,raw=C.pin(raw),compressed=C.pin(packed))

def retain_input_failure(parent,target,failure=None):
 """Publish actual partial DATA and a typed context state even on copy error."""
 parent,target=Path(parent),Path(target);C.need(not os.path.lexists(target)and parent.is_dir()and(parent/'current607-inputs').is_dir(),'fresh fixed early input-failure public destination');target.mkdir(mode=0o700);rows={};total=0;primary=None;errors=[dict(file='current607-inputs',error='INCOMPLETE_ORIGINAL607_INPUTS_BEFORE_CORE_ACTOR')]
 try:
  for source,name,cap in[(parent/'source-proof.json','source-proof.json',4*1024**2),(parent/'fresh607-manifest.json','retained/fresh607-manifest.json',4*1024**2)]+[(p,'current607-inputs/'+p.relative_to(parent/'current607-inputs').as_posix(),128*1024**2 if p.parent.name=='packages'else 4*1024**2)for p in sorted((parent/'current607-inputs').rglob('*'))if p.is_file()]:
   raw=C.read(source,cap);C.need(total+len(raw)<=768*1024**2,'unchanged public cap during early607 failure retention');q=target/name;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(raw);rows[name]=C.pin(raw);total+=len(raw)
 except BaseException as error:
  primary=error;errors.append(dict(file='current607-inputs',error='PARTIAL_CONTEXT_COPY_'+type(error).__name__))
  if failure is not None:failure['retention_error_type']=type(error).__name__
  raise
 finally:
  try:
   export=dict(schema=1,status='FAIL_OR_INCOMPLETE',files=rows,bytes=total,errors=errors,hardware='NOT_RUN',Asahi='NOT_RUN',release='NOT_ADMITTED')
   if failure is not None:export['current607_input_context_failure_data']=failure
   (target/'export.json').write_bytes(C.encoded(export))
  except BaseException as error:
   if primary is None:raise
   primary.add_note('pre-Core failure export finalization failed: '+type(error).__name__)

def claim_input_context(parent,selected):
 """Track only the fresh pre-Core context, independently of every Core lease."""
 parent=Path(parent);C.selection(selected);C.need(parent.parent==Path('/tmp')and parent.name.endswith('-context')and parent==parent.resolve()and not any(p.is_symlink()for p in(parent,*parent.parents)),'fixed literal pre-Core context sibling');s=parent.stat();C.need(stat.S_ISDIR(s.st_mode)and stat.S_IMODE(s.st_mode)==0o700 and s.st_uid==os.getuid()and s.st_gid==os.getgid(),'fresh owned0700 pre-Core context');return dict(schema=1,status='OWNED_PRE_CORE_INPUT_CONTEXT_NO_CORE_ACTOR',path=str(parent),root=[s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid],parent=[parent.parent.stat().st_dev,parent.parent.stat().st_ino],nonce=selected['nonce'],actual=selected['actual'],Core_actor='NOT_STARTED')

def record_input_context(claim):
 path=Path(claim['path'])/'context-owner.json';C.need(not os.path.lexists(path),'fresh pre-Core context identity record');raw=C.encoded(claim);C.need(len(raw)<=16384,'bounded pre-Core context identity');fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:C.need(os.write(fd,raw)==len(raw),'whole pre-Core identity write')
 finally:os.close(fd)

def context_failure(claim,primary,retention=None):return dict(schema=1,status='SOURCE_OWNED_PRE_CORE_CONTEXT_FAILURE_DATA_ONLY',context=claim,primary_error_type=primary,retention_error_type=retention,retirement='PENDING_ORIGINAL_PRODUCER_CLEANUP',Core_actor='NOT_STARTED',acceptance=False)

def current_context_rows(claim,selected,end):
 parent=Path(claim['path']);C.selection(selected);C.need(type(end)in(int,float)and __import__('math').isfinite(end)and time.monotonic()<end,'unchanged remaining pre-Core context retirement clock');s=parent.stat();C.need(claim['schema']==1 and claim['status']=='OWNED_PRE_CORE_INPUT_CONTEXT_NO_CORE_ACTOR'and claim['Core_actor']=='NOT_STARTED'and claim['nonce']==selected['nonce']and claim['actual']==selected['actual']and claim['root']==[s.st_dev,s.st_ino,stat.S_IMODE(s.st_mode),s.st_uid,s.st_gid]and claim['parent']==[parent.parent.stat().st_dev,parent.parent.stat().st_ino]and parent.parent==Path('/tmp')and parent.name.endswith('-context'),'same tracked pre-Core identity/source/run/nonce, no Core lease');C.need(not any(p.is_symlink()for p in(parent,*parent.parents))and s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o700,'ordinary caller-owned tracked context')
 fixed={'context-owner.json','source-proof.json','fresh607-manifest.json','fresh607-producer.json','fresh607-base-build.json','fresh607-owner.json','fresh607-tooling-seed.json'};archives=set()
 if(parent/'current607-inputs').exists():
  record=C.decode(C.read(parent/'fresh607-manifest.json',4*1024**2));rows=X.manifest(profile(),record);references=C.decode(C.read(Path(__file__).with_name('composition-parent.json'),4*1024**2))['current_root_export']['reference_archives'];archives={r['archive']for r in rows if r['archive']not in references}
 allowed=fixed|{'current607-inputs/'+n for n in archives|{'capture.json','current607-inputs.json.gz'}};files={};dirs={''};total=0
 for p in sorted(parent.rglob('*')):
  C.need(time.monotonic()<end,'same pre-Core context retirement deadline');n=p.relative_to(parent).as_posix();st=p.lstat();C.need(st.st_dev==s.st_dev and st.st_uid==os.getuid()and not p.is_symlink()and(stat.S_ISDIR(st.st_mode)or stat.S_ISREG(st.st_mode)and st.st_nlink==1),'only same-device owned ordinary pre-Core context nodes')
  if p.is_dir():C.need(n in('current607-inputs','current607-inputs/packages'),'closed pre-Core directory namespace');dirs.add(n);continue
  C.need(n in allowed,'closed source-selected pre-Core file namespace');cap=128*1024**2 if n.startswith('current607-inputs/packages/')else 4*1024**2;raw=C.read(p,cap);total+=len(raw);C.need(len(files)<2048 and total<=768*1024**2,'unchanged bounded pre-Core context files/bytes');files[n]=dict(pin=C.pin(raw),identity=list(C.identity(st)))
 expected={''}
 for n in files:expected.update(''if str(q)=='.'else q.as_posix()for q in Path(n).parents)
 C.need(expected<=dirs<=expected|{'current607-inputs','current607-inputs/packages'},'closed complete pre-Core context directories');return parent,files

def retain_context_before_retirement(claim,selected,public,end,failure):
 """Reuse exact retained bytes; copy any remaining original context DATA."""
 parent,files=current_context_rows(claim,selected,end);public=Path(public);C.need(public.is_absolute()and not any(p.is_symlink()for p in(public,*public.parents)),'literal actual pre-Core public destination');public.mkdir(mode=0o700,exist_ok=True);export_path=public/'export.json';export=C.decode(C.read(export_path,4*1024**2))if export_path.exists()else dict(schema=1,status='FAIL_OR_INCOMPLETE',files={},bytes=0,errors=[dict(file='current607-inputs',error='PRE_CORE_CONTEXT_FAILURE_DATA_ONLY')],hardware='NOT_RUN',Asahi='NOT_RUN',release='NOT_ADMITTED');mapping={}
 for name in files:
  if name.startswith('current607-inputs/'):target=name
  elif name=='source-proof.json':target=name
  elif name=='context-owner.json':target='current607-inputs/context-owner.json'
  else:target='retained/'+name
  C.need(target not in mapping,'unique closed context public role');mapping[target]=name
 existing={p.relative_to(public).as_posix()for p in public.rglob('*')if p.is_file()};C.need(existing<=set(mapping)|{'export.json'}and set(export['files'])==existing-{'export.json'},'only actual closed earlier pre-Core public files')
 total=sum(w['bytes']for w in export['files'].values())
 for target,name in mapping.items():
  C.need(time.monotonic()<end,'same remaining pre-Core context retention clock');source=parent/name;row=files[name];cap=128*1024**2 if name.startswith('current607-inputs/packages/')else 4*1024**2;raw=C.read(source,cap);C.need(C.pin(raw)==row['pin']and list(C.identity(source.stat()))==row['identity'],'whole unchanged original context byte/identity before retirement');dest=public/target
  if dest.exists():C.need(C.pin(C.read(dest,cap))==row['pin']==export['files'][target],'exact earlier public context bytes reused, never replaced')
  else:C.need(total+len(raw)<=768*1024**2,'unchanged full public cap during context retention');dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(raw);export['files'][target]=row['pin'];total+=len(raw)
 export['bytes']=total;export['status']='FAIL_OR_INCOMPLETE';export['current607_input_context_failure_data']=failure;(public/'export.json').write_bytes(C.encoded(export));C.need(current_context_rows(claim,selected,end)==(parent,files),'whole tracked context unchanged after exact public retention');return parent,files

def retire_input_context(claim,selected,core_source,public,end,failure):
 """Original FD cleanup, only after exact original partial DATA retention."""
 parent,files=retain_context_before_retirement(claim,selected,public,end,failure)
 import adapter
 core=adapter.core(core_source);roots=core.api['roots'];limits=roots.Limits(deadline=end,max_nodes=2048,max_bytes=768*1024**2,max_file_bytes=128*1024**2);sys.path.insert(0,str(core.root/'runtime/runtime-vm/scripts/update'));import disposable_copy
 grand=roots._open_root(parent.parent);fd=None
 try:
  C.need([os.fstat(grand).st_dev,os.fstat(grand).st_ino]==claim['parent'],'same original context parent descriptor');fd=os.open(parent.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=grand);st=os.fstat(fd);C.need([st.st_dev,st.st_ino,stat.S_IMODE(st.st_mode),st.st_uid,st.st_gid]==claim['root'],'same initial pre-Core context descriptor identity');mount=roots._mount_id(fd,limits);disposable_copy._same(grand,parent.name,fd,tuple(claim['root'][:2]),mount,limits);C.need(current_context_rows(claim,selected,end)==(parent,files),'whole exact context immediately before original FD retirement');disposable_copy._empty(fd,mount,limits,[0]);disposable_copy._same(grand,parent.name,fd,tuple(claim['root'][:2]),mount,limits);os.rmdir(parent.name,dir_fd=grand);C.need(not os.path.lexists(parent),'actual owned pre-Core context removed')
 finally:
  if fd is not None:os.close(fd)
  os.close(grand)
 failure['retirement']='PASS_OWNED_PRE_CORE_CONTEXT_REMOVED_AFTER_ORIGINAL_PRODUCER_CLEANUP';export_path=Path(public)/'export.json';export=C.decode(C.read(export_path,4*1024**2));export['current607_input_context_failure_data']=failure;export_path.write_bytes(C.encoded(export));return dict(status=failure['retirement'],context=claim,files=len(files),bytes=sum(v['pin']['bytes']for v in files.values()),Core_actor='NOT_STARTED')

def publish_context_failure(public,failure):
 """Bounded structured failure survives callers that discard exception notes."""
 public=Path(public);C.need(not any(p.is_symlink()for p in(public,*public.parents)),'ordinary fixed failure public destination');public.mkdir(mode=0o700,exist_ok=True);path=public/'export.json';export=C.decode(C.read(path,4*1024**2))if path.exists()else dict(schema=1,status='FAIL_OR_INCOMPLETE',files={},bytes=0,errors=[dict(file='current607-inputs',error='IDENTIFIED_PRE_CORE_CONTEXT_RETAINED')],hardware='NOT_RUN',Asahi='NOT_RUN',release='NOT_ADMITTED');export['status']='FAIL_OR_INCOMPLETE';export['current607_input_context_failure_data']=failure;path.write_bytes(C.encoded(export))

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('role',choices=('provision607','retire607','initialize607'));a=p.parse_args();initialize_worker()if a.role=='initialize607'else prepare()if a.role=='provision607'else retire()
