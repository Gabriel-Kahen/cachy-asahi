# SPDX-License-Identifier: MIT
"""Explicit disposable-clone candidate extraction repair; no automatic rollback."""
import ctypes,json,os,signal,stat,types
from pathlib import Path
# C and R are injected by the exact source-owned worker loader. R is the
# unchanged REMOVE checkpoint module, with its original ownership/retirement code.
ADD_PROGRESS=0
PHASE='ALPM_COMMIT_CANDIDATE_EXTRACTION_BEFORE_LOCAL_DB_COMMIT'
OPERATION='candidate-extraction-interruption'

def owned(lane,root,case):
 C.need(case in ('pristine','modified')and root==lane.WORK/case/'root'and root==root.resolve()and not any(p.is_symlink()for p in(root,*root.parents)),'exact existing disposable clone only')
 for p,mode in((root,0o755),(root.parent,0o700)):
  s=p.lstat();C.need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==mode,'owned clone/private parent')

def node(path):
 C.need(not any(p.is_symlink()for p in path.parents),'ordinary node ancestors');a=path.lstat();r=dict(type='directory'if stat.S_ISDIR(a.st_mode)else'symlink'if stat.S_ISLNK(a.st_mode)else'file',mode=stat.S_IMODE(a.st_mode),uid=a.st_uid,gid=a.st_gid)
 if stat.S_ISLNK(a.st_mode):r['target']=os.readlink(path)
 elif stat.S_ISREG(a.st_mode):
  C.need(a.st_size<=64*1024**2 and not os.listxattr(path,follow_symlinks=False),'bounded plain package/config file');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   C.need(R.identity(a)==R.identity(os.fstat(fd)),'same package FD before read');raw=bytearray()
   while part:=os.read(fd,min(65536,a.st_size+1-len(raw))):raw.extend(part);C.need(len(raw)<=a.st_size,'bounded stable package extent')
   C.need(len(raw)==a.st_size and R.identity(a)==R.identity(os.fstat(fd)),'whole stable package FD');r.update(bytes=len(raw),sha256=C.sha(bytes(raw)))
  finally:os.close(fd)
 else:C.need(stat.S_ISDIR(a.st_mode),'ordinary package node only')
 C.need(R.identity(a)==R.identity(path.lstat()),'stable package/config node');return r,R.identity(a)

def plain(row):return{k:v for k,v in row.items()if k!='hardlink_group'}

def choose(before,old,new):
 candidates=[n for n,r in new['nodes'].items()if n.startswith('usr/')and r['type']=='file'and n not in C.CACHES and 'hardlink_group'not in r and before['nodes'].get(n,{}).get('sha256')!=r['sha256']]
 C.need(len(candidates)>=2,'two ordered distinct candidate payload witnesses')
 a,b=candidates[0],candidates[-1]
 return dict(extracted=a,pending=b,extracted_row=plain(new['nodes'][a]),pending_before=plain(before['nodes'][b])if b in before['nodes']else None)

def partial(root,point):
 C.need(node(root/point['extracted'])[0]==point['extracted_row'],'complete real candidate bytes already extracted')
 p=root/point['pending']
 C.need(not os.path.lexists(p)or point['pending_before']is not None and node(p)[0]==point['pending_before'],'later candidate payload is still absent or exact held bytes')

class Checkpoint:
 def __init__(self,root,point,fd):self.root,self.point,self.fd=root,point,fd;self.armed=False;self.prepared=None;self.hit=False
 def bind(self,alpm):
  def progress(ctx,event,package,percent,howmany,current):
   if not(self.armed and event==ADD_PROGRESS and package==C.NAME.encode()and 0<=percent<=100 and howmany==current==1):return
   p=self.root/self.point['extracted']
   if not os.path.lexists(p):return
   try:
    if node(p)[0]!=self.point['extracted_row']:return
    C.need(not self.hit,'single extraction checkpoint');partial(self.root,self.point);self.hit=True
    R.send(self.fd,dict(type='CHECKPOINT',pid=os.getpid(),pgid=os.getpgrp(),phase=PHASE,event=event,package=C.NAME,percent=percent,howmany=howmany,current=current,point=self.point,lock=R.lock_identity(self.root),prepared=self.prepared))
    os.kill(os.getpid(),signal.SIGSTOP);os._exit(72)
   except BaseException as error:R.send(self.fd,dict(type='ERROR',message=str(error)[:512]));os._exit(71)
  self.callback=R.CALLBACK(progress);setter=alpm.lib.alpm_option_set_progresscb;setter.restype=ctypes.c_int;setter.argtypes=[ctypes.c_void_p,R.CALLBACK,ctypes.c_void_p];alpm.ok(setter(alpm.handle,self.callback,None),'install owned extraction observer')

def validate_checkpoint(row,pid,root,point):
 C.need(set(row)=={'type','pid','pgid','phase','event','package','percent','howmany','current','point','lock','prepared'}and row['type']=='CHECKPOINT'and type(row['pid'])is type(row['pgid'])is int and row['pid']==row['pgid']==pid and row['phase']==PHASE and type(row['event'])is int and row['event']==ADD_PROGRESS and row['package']==C.NAME and type(row['percent'])is int and 0<=row['percent']<=100 and type(row['howmany'])is type(row['current'])is int and row['howmany']==row['current']==1 and row['point']==point,'exact real candidate extraction checkpoint')
 p=row['prepared'];C.need(type(p)is dict and set(p)=={'prepared_add','prepared_remove','dependencies','commit_started','observer_root','hooks','scriptlets'}and p['prepared_add']=={C.NAME:C.VERSION}and set(p['prepared_remove'])=={'glibc'}and p['dependencies']=='PASS_ALPM_PREPARE'and p['commit_started']is True and p['observer_root']=='INTACT_OUTER_HELD574'and p['hooks']=='DISABLED'and p['scriptlets']=='DISABLED_EXPLICIT_HELD_POST_UPGRADE_LATER','actual dependency-checked combined replacement')
 C.need(row['lock']==R.lock_identity(root),'same original owned lock');partial(root,point)

def stop_and_kill(api,lane,root,index,point,case,report):
 # A private function namespace holds both unchanged ownership/kill/reap bodies.
 f=R.stop_and_kill;namespace=dict(f.__globals__,Checkpoint=Checkpoint,validate_checkpoint=validate_checkpoint)
 return types.FunctionType(f.__code__,namespace,f.__name__,f.__defaults__,f.__closure__)(api,lane,root,index,point,case,report)

def unrelated_db(nodes,base):
 prefix=R.LOCAL+'/glibc-'+base['glibc'];return{n:r for n,r in nodes.items()if(n==R.LOCAL or n.startswith(R.LOCAL+'/'))and n!=prefix and not n.startswith(prefix+'/')}

def classify(lane,before,interrupted,base,new,old):
 nodes=interrupted['nodes'];candidate=R.LOCAL+'/'+C.NAME+'-'+C.VERSION;oldprefix=R.LOCAL+'/glibc-'+base['glibc']
 C.need(not any(n==oldprefix or n.startswith(oldprefix+'/')for n in nodes),'held local DB removed before candidate extraction')
 candidate_nodes={n:r for n,r in nodes.items()if n==candidate or n.startswith(candidate+'/')}
 C.need(candidate in candidate_nodes and plain(candidate_nodes[candidate])==dict(type='directory',mode=0o755,uid=0,gid=0),'source-owned prepared candidate DB directory')
 allowed_meta={candidate+'/'+dest:new['data'][src]for src,dest in(('.MTREE','mtree'),('.CHANGELOG','changelog'))if src in new['data']}
 C.need(set(candidate_nodes)<={candidate,*allowed_meta},'candidate desc/files/install must not be committed')
 for n,r in candidate_nodes.items():
  if n!=candidate:C.need(plain(r)==dict(type='file',mode=0o644,uid=0,gid=0,bytes=len(allowed_meta[n]),sha256=C.sha(allowed_meta[n])),'exact archive-derived partial candidate DB metadata')
 observed={n:r for n,r in unrelated_db(nodes,base).items()if n not in candidate_nodes}
 C.need(observed==unrelated_db(before['nodes'],base),'every unrelated573 DB node byte/metadata preserved')
 user=lane.USER+'/';C.need({n:r for n,r in nodes.items()if n==lane.USER or n.startswith(user)}=={n:r for n,r in before['nodes'].items()if n==lane.USER or n.startswith(user)},'all seeded user nodes exact before repair')
 compare=dict(interrupted,nodes={n:r for n,r in nodes.items()if n!=R.LOCK});preserved=lane.unchanged(before,compare,old,new,base['glibc'])
 permitted=set(old['nodes'])|set(new['nodes'])|set(lane.CONFIGS)|C.CACHES
 for n in permitted&set(nodes):
  if nodes[n]['type']=='directory':C.need(any(plain(nodes[n])==plain(option)for option in([before['nodes'][n]]if n in before['nodes']else[])+([new['nodes'][n]]if n in new['nodes']else[])),'known package directory metadata before repair')
 moves={n:r for n,r in nodes.items()if n in permitted and r['type']!='directory'}
 for n,r in moves.items():
  options=[archive['nodes'][n]for archive in(old,new)if n in archive['nodes']]
  if n in before['nodes']:options.append(before['nodes'][n])
  if n in lane.CONFIGS:
   origin=n.removesuffix('.pacnew').removesuffix('.pacsave')
   options.extend(archive['nodes'][origin]for archive in(old,new)if origin in archive['nodes'])
   if origin in before['nodes']:options.append(before['nodes'][origin])
  C.need(any(plain(r)==plain(option)for option in options),'unknown partial package/config bytes refused: '+n)
 moves.update({n:r for n,r in candidate_nodes.items()if r['type']!='directory'})
 groups={}
 for n,r in nodes.items():
  if 'hardlink_group'in r:groups.setdefault(r['hardlink_group'],set()).add(n)
 for members in groups.values():
  if members&set(moves):
   C.need(members<=set(moves),'no hardlink from partial payload into unrelated state')
   C.need(any(members<={n for n,r in archive['nodes'].items()if r.get('hardlink_group')==archive['nodes'].get(next(iter(members)),{}).get('hardlink_group')and 'hardlink_group'in r}for archive in(old,new)),'partial hardlinks are declared archive groups')
 return moves,candidate,preserved

def quarantine(lane,root,moves,candidate):
 q=root/lane.FIXTURE/'candidate-extraction-quarantine';C.need(not os.path.lexists(q),'fresh explicit repair quarantine');identities={};directory=root/candidate;directory_id=R.identity(directory.lstat())
 # All contents are classified before any payload/DB repair starts.
 for n,r in moves.items():
  actual,ident=node(root/n);C.need(actual==plain(r),'late exact classified repair node')
  if actual['type']=='file':C.need(ident[5]==sum(v.get('hardlink_group')==r['hardlink_group']for v in moves.values())if'hardlink_group'in r else ident[5]==1,'all package hardlinks confined to classified quarantine')
  identities[n]=ident
 q.mkdir(mode=0o700);renamed_inodes=set()
 for n,r in sorted(moves.items()):
  source=root/n;dest=q/n;dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True);actual,now=node(source);previous=identities[n];same=now[:-1]==previous[:-1]if tuple(previous[:2])in renamed_inodes else now==previous;C.need(not os.path.lexists(dest)and actual==plain(r)and same,'unchanged classified node before quarantine move');os.rename(source,dest);actual,ident=node(dest);C.need(actual==plain(r)and ident[:-1]==now[:-1]and not os.path.lexists(source),'exact same inode/data quarantined');renamed_inodes.add(tuple(ident[:2]))
 C.need(R.identity(directory.lstat())[:5]==directory_id[:5]and not any(directory.iterdir()),'same empty classified candidate DB fragment only');directory.rmdir()
 return q,dict(status='PASS_EXPLICIT_SOURCE_CLASSIFIED_PARTIAL_STATE_QUARANTINED',nodes=len(moves),map_sha256=C.sha((json.dumps(moves,sort_keys=True)+'\n').encode()),automatic_rollback='NOT_CLAIMED')

def held_add(api,lane,root,archive,base,log):
 expected=dict(base);del expected['glibc'];C.need(lane.inventory(lane.database(api,root))==expected,'exact573 inventory before ordinary held add')
 alpm=api['roots'].Alpm(root,lane.WORK,log,'aarch64',limits=lane.limits(api,120))
 try:
  C.need(alpm.inventory()==expected,'intact outer ALPM sees exact573');alpm.ok(alpm.alpm_trans_init(alpm.handle,(1<<7)|(1<<10)),'ordinary NOHOOKS/NOSCRIPTLET repair');alpm.started=True
  package=ctypes.c_void_p();alpm.ok(alpm.alpm_pkg_load(alpm.handle,os.fsencode(archive),1,0,ctypes.byref(package)),'load exact pinned held archive');alpm.ok(alpm.alpm_add_pkg(alpm.handle,package),'add held provider; no remove or overwrite')
  error=api['roots'].installer.Ptr();alpm.ok(alpm.alpm_trans_prepare(alpm.handle,ctypes.byref(error)),'full ordinary recovery dependency/conflict prepare');add=alpm.packages(alpm.alpm_trans_get_add(alpm.handle));remove=alpm.packages(alpm.alpm_trans_get_remove(alpm.handle));C.need(add=={'glibc':base['glibc']}and remove=={},'exact add-only held recovery sets')
  alpm.ok(alpm.alpm_trans_commit(alpm.handle,ctypes.byref(error)),'ordinary dependency-checked held recovery commit');return dict(status='PASS_COMMITTED_REPLACEMENT',prepared_add=add,prepared_remove=remove,dependencies='PASS_ALPM_PREPARE',commit_started=True,flags=(1<<7)|(1<<10),recovery='EXPLICIT_ADD_ONLY_FROM_573_NO_DB_FORGING_NO_OVERWRITE')
 finally:alpm.close()

def restore_configs(lane,root,captured,old):
 operations=[]
 for n in lane.CONFIGS:
  if n not in captured:C.need(not os.path.lexists(root/n),'no new configuration sidecar after recovery');continue
  row,raw=captured[n];C.need(n in old['nodes']and node(root/n)[0]==plain(old['nodes'][n]),'exact reinstalled held default before explicit configuration restoration')
  fd=os.open(root/n,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   s=os.fstat(fd);C.need(s.st_nlink==1 and R.identity(s)==R.identity((root/n).lstat()),'owned singlelink configuration before restoration');view=memoryview(raw);offset=0
   while view:size=os.pwrite(fd,view,offset);C.need(size>0,'complete explicit config write');offset+=size;view=view[size:]
   os.ftruncate(fd,len(raw));os.fchmod(fd,row['mode']);C.need((s.st_uid,s.st_gid)==(row['uid'],row['gid']),'held configuration owner preserved');os.fsync(fd)
  finally:os.close(fd)
  C.need(node(root/n)[0]==plain(row),'exact captured configuration restored');operations.append(dict(path=n,sha256=C.sha(raw),operation='RESTORE_CAPTURED_OWNED_CLONE_CONFIGURATION'))
 return dict(status='PASS_EXPLICIT_EXTRACTION_RECOVERY_CONFIG_RESTORE',ALPM_active_configuration_preservation='NOT_CLAIMED',operations=operations)

def retire_quarantine(q,moves):
 seen={p.relative_to(q).as_posix()for p in q.rglob('*')if not p.is_dir()or p.is_symlink()};C.need(seen==set(moves),'closed exact repair quarantine before retirement')
 C.need({p.relative_to(q).as_posix()for p in q.rglob('*')if p.is_dir()}=={p.as_posix()for n in moves for p in Path(n).parents if p.as_posix()!='.'},'only declared quarantine directories')
 for n,r in moves.items():C.need(node(q/n)[0]==plain(r),'quarantine bytes preserved until successful recovery')
 for n in moves:os.unlink(q/n)
 for p in sorted(q.rglob('*'),key=lambda p:len(p.parts),reverse=True):C.need(p.is_dir()and not p.is_symlink(),'only owned empty quarantine directories');p.rmdir()
 q.rmdir()

def exercise(api,lane,root,index,base,new,old,before,case,report):
 owned(lane,root,case);rows=lane.database(api,root);C.need(lane.inventory(rows)==base,'exact574 before extraction operation');owners=lane.ownership(rows)
 for n,r in old['nodes'].items():
  if r['type']!='directory'and n not in C.CACHES:C.need(owners.get(n)=='glibc','held payload exclusively owned by glibc')
 for n,r in new['nodes'].items():
  if r['type']!='directory'and n not in old['nodes']:C.need(n not in before['nodes'],'candidate-only path absent in original clone')
 captured={n:(before['nodes'][n],C.read(root/n,2*1024**2))for n in lane.CONFIGS if n in before['nodes']}
 for n,(r,raw)in captured.items():C.need(node(root/n)[0]==plain(r)and C.sha(raw)==r['sha256'],'exact before574 configuration capture')
 desc=R.LOCAL+'/glibc-'+base['glibc']+'/desc';old_desc=C.read(root/desc,2*1024**2)
 point=choose(before,old,new);report.update(operation=OPERATION,point=point,outer_runtime_before=R.outer_identity(api,lane,old));checkpoint=stop_and_kill(api,lane,root,index,point,case,report);C.need(checkpoint['prepared']['prepared_remove']=={'glibc':base['glibc']},'exact held removal version')
 interrupted=lane.snapshot(api,root,case+'-interrupted-before-unlock');partial(root,point);moves,candidate,preservation=classify(lane,before,interrupted,base,new,old);report['partial_preservation']=preservation;report['partial_state']='573_UNRELATED_DB_RECORDS_WITH_PREPARED_CANDIDATE_DB_AND_PARTIAL_EXTRACTION'
 report['lock_recovery']=R.clear_owned_lock(root,checkpoint['lock'],report['writer']);q,report['quarantine']=quarantine(lane,root,moves,candidate)
 report['external_recovery']=held_add(api,lane,root,lane.INPUTS/index['held']['path'],base,lane.OUT/(case+'-extraction-held-recovery.log'));report['configuration_recovery']=restore_configs(lane,root,captured,old)
 # Candidate-only empty directories are explicit repair state, not held payload.
 for n,r in sorted(new['nodes'].items(),key=lambda item:len(item[0].split('/')),reverse=True):
  if r['type']=='directory'and n not in before['nodes']and os.path.lexists(root/n):C.need(node(root/n)[0]==plain(r),'source-owned candidate-only directory');(root/n).rmdir()
 C.need(lane.database(api,root)==rows,'complete574 ordinary DB identity/dependencies/ownership restored');new_desc=C.read(root/desc,2*1024**2);a,b=api['db'].fields(old_desc),api['db'].fields(new_desc)
 C.need({k:v for k,v in a.items()if k!='INSTALLDATE'}=={k:v for k,v in b.items()if k!='INSTALLDATE'}and len(b.get('INSTALLDATE',[]))==1 and b['INSTALLDATE'][0].isdigit(),'held DB description differs only by genuine ALPM install date');report['held_database']=dict(status='PASS_COMPLETE_574_ROWS_AND_UNRELATED_573_RECORDS',old_desc_sha256=C.sha(old_desc),new_desc_sha256=C.sha(new_desc),install_date=b['INSTALLDATE'][0],byte_identical_held_desc=old_desc==new_desc,forged_records=False)
 retire_quarantine(q,moves);recovered=lane.snapshot(api,root,case+'-recovered-held574');C.need(unrelated_db(recovered['nodes'],base)==unrelated_db(before['nodes'],base),'all573 unrelated DB nodes preserved through repair');lane.payload(recovered['nodes'],old['nodes'],C.CACHES|set(lane.CONFIGS))
 heldprefix=R.LOCAL+'/glibc-'+base['glibc'];C.need({n:r for n,r in recovered['nodes'].items()if(n==heldprefix or n.startswith(heldprefix+'/'))and n!=desc}=={n:r for n,r in before['nodes'].items()if(n==heldprefix or n.startswith(heldprefix+'/'))and n!=desc},'complete held DB subtree except genuine install-date description unchanged')
 for n,r in before['nodes'].items():
  if r['type']=='directory'and n in set(old['nodes'])|set(new['nodes']):C.need(recovered['nodes'].get(n)==r,'original shared package directory metadata preserved')
 C.need({n:r for n,r in recovered['nodes'].items()if n in lane.CONFIGS}=={n:r for n,r in before['nodes'].items()if n in lane.CONFIGS},'all captured configurations and sidecars exact')
 for n,r in new['nodes'].items():
  if n not in before['nodes']:C.need(n not in recovered['nodes'],'no candidate-only payload or directory after repair')
 C.need({n:r for n,r in recovered['nodes'].items()if n==lane.USER or n.startswith(lane.USER+'/')}=={n:r for n,r in before['nodes'].items()if n==lane.USER or n.startswith(lane.USER+'/')},'all seeded user state preserved after repair');report['recovered_preservation']=lane.unchanged(before,recovered,old,new,base['glibc']);report['outer_runtime_after']=R.outer_identity(api,lane,old);C.need(report['outer_runtime_before']==report['outer_runtime_after'],'intact outer libc/ALPM identities preserved')
 report.update(status='PASS_ACTUAL_CANDIDATE_EXTRACTION_KILL_AND_EXPLICIT_HELD_RECOVERY',automatic_rollback='NOT_CLAIMED',automatic_configuration_preservation='NOT_CLAIMED',power_loss_durability='NOT_TESTED')
