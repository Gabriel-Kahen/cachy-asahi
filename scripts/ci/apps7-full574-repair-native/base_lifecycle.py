#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Actual backend transactions in owned copies of a readonly original574 export."""
import os,signal,stat,subprocess,sys,time,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
SOURCE=Path('/source');SEED=Path('/seed');WORK=Path('/work');OUT=Path('/out');INPUTS=Path('/inputs')

class Calls:
 def __init__(self):
  self.api=C.load('original_group_runner',SOURCE/'scripts/ci/glibc-owned-runtime/runner.py');self.rows=[]
 def call(self,argv,*,seconds=610,expected=0):
  n=len(self.rows);C.need(n<64,'closed command count');row,out,err,error=self.api.run_command(list(map(str,argv)),WORK,dict(C.ENV,HOME='/tmp',CACHY_ASAHI_APPS_TRANSACTION=os.environ['OWNER_TOKEN']),seconds,1024**2)
  self.rows.append(row);C.save(OUT/'commands.json',self.rows);(OUT/('command-%02d.stdout'%n)).write_bytes(out);(OUT/('command-%02d.stderr'%n)).write_bytes(err)
  C.need(error is None and row['group_absence_verified'] and row['exit_code']==expected,'bounded actual command failed: '+str(argv[0]));return C.decode(out)

def common(workspace,owner=None):
 args=['--workspace',str(workspace),'--apps-source','/inputs/apps-source','--apps-provenance-sha256',C.sha(C.read(INPUTS/'apps-source/source-provenance.json')),
  '--repository-source','/inputs/candidate/usr/share/cachy-asahi/repository-runtime']
 for key in ('policy','lease'):args+=['--full574-'+key,'/inputs/full574-'+key+'.json','--full574-'+key+'-sha256',C.sha(C.read(INPUTS/('full574-'+key+'.json')))]
 if owner:args+=['--ownership-sha256',owner]
 return args

def backend(action,workspace,owner=None):return ['/usr/bin/python3','-I','-B','/source/scripts/ci/apps7-full574-repair-native/transaction.py',action,*common(workspace,owner)]
def credentials():
 value=C.decode(C.read(INPUTS/'release/control.json'));return [part for key in ('release','release-sha256','catalog','catalog-sha256','catalog-signature','keyring','signer') for part in
  ('--'+key,{'release':'/inputs/release/bundle','release-sha256':value['release_sha256'],'catalog':'/inputs/release/catalog.json','catalog-sha256':value['catalog_sha256'],'catalog-signature':'/inputs/release/catalog.json.sig','keyring':'/inputs/release/public.gpg','signer':value['signer']}[key])]
def inventory_identity(info):
 # A read may update atime. Bind every security/content identity field, using
 # nanoseconds for mutation times, exactly as the existing bounded C.read does.
 return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

def retain_inventory(path,summary):
 C.safe(path);before=path.lstat();raw=C.read(path,16*1024**2)
 C.need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.geteuid() and
        stat.S_IMODE(before.st_mode)==0o600 and inventory_identity(before)==inventory_identity(path.lstat()),'exact private caller-owned inventory required')
 C.need(summary['output']==str(path) and summary['bytes']==len(raw) and summary['sha256']==C.sha(raw),'original inventory command bytes differ')
 # Keep the original bytes at the existing flat export name; never republish through a weaker product path.
 fd=os.open(OUT/path.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 return raw

def planned(calls,workspace,label,operation,names):
 C.need(label in ('install','remove-selected','remove-runtime','interrupted-install') and
        workspace in (WORK/'main',WORK/'interrupted'),'fixed owned inventory scope required')
 C.safe(WORK);info=WORK.lstat();C.need(stat.S_ISDIR(info.st_mode) and info.st_uid==os.geteuid() and
        stat.S_IMODE(info.st_mode)==0o700,'private caller-owned inventory directory required')
 inventory=WORK/(label+'-inventory.json');summary=calls.call(['/inputs/candidate/usr/bin/cachy-asahi-apps','inventory','--dbpath',str(workspace/'root/var/lib/pacman'),'--output',str(inventory)],seconds=45)
 C.need(summary['status']=='OBSERVED_LOCAL_DB_METADATA','actual private inventory snapshot required');raw=retain_inventory(inventory,summary)
 plan=calls.call(['/inputs/candidate/usr/bin/cachy-asahi-apps',*credentials(),'--installed',str(inventory),'--installed-sha256',C.sha(raw),'plan',operation,*names],seconds=120)
 C.need(plan['status']=='PLANNED' and plan['applied']=='NOT_APPLIED' and plan['installer_authority'] is False and plan['plan']['installed_inventory']=='OBSERVED_LOCAL_DB_METADATA_NOT_PAYLOAD_OR_HARDWARE_ATTESTATION' and plan['synthetic'] is True,'true signed synthetic plan from actual copied database required')
 C.need(C.read(inventory,16*1024**2)==raw,'private inventory changed during planning')
 path=OUT/(label+'-plan.json');path.write_bytes(C.encoded(plan));inventory.unlink();return path,plan

def apply_args(calls,workspace,owner,path,plan):
 before=calls.call(backend('inspect',workspace,owner))['before']
 return [*backend('apply',workspace,owner),*credentials(),'--operation',plan['plan']['operation'],'--applications',*plan['plan']['requested_applications'],'--plan',str(path),'--plan-sha256',C.sha(C.read(path)),
  *[part for key,value in before.items() for part in ('--before-'+key.replace('_','-'),value)],'--confirm-disposable-transaction']
def retain_copy(workspace,owner):
 raw=C.read(workspace/'apps-copy.json',65536);C.need(C.sha(raw)==owner,'original copy marker hash differs')
 value=C.decode(raw);scope=value['copy']['apps_bind_scope']
 C.need(scope['proof']['status']=='PROVED_DISJOINT_READONLY_SOURCE_AND_OWNED_WORK_BIND_ROOTS' and scope['proof']['source']=='/seed' and scope['proof']['destination_parent']==str(workspace) and type(scope['checkpoints']) is int and scope['checkpoints']==7 and value['copy']['security_capabilities']=='EXACT_SOURCE_MAP_RESTORED_AND_VERIFIED','actual scoped complete capability copy proof required')
 (OUT/(workspace.name+'-copy.json')).write_bytes(raw)

def count(workspace):
 app=C.load('inventory_apps',INPUTS/'apps-source/apps.py');c,r,_=app.helpers(INPUTS/'candidate/usr/share/cachy-asahi/repository-runtime')
 return {p['name']:p['version'] for p in app.inventory_reader().collect(workspace/'root/var/lib/pacman',c,lambda row:app.package(row,r))['packages']}
def zero(value):
 C.need(value['status']=='FAIL' and value['commit_started'] is False and value['packages_committed'] is False,'expected explicit zero-commit refusal');return value

def interrupted(calls,workspace,owner,argv):
 # The original --worker body is directly supervised here: one private process
 # group, dedicated full574600s budget and1MiB output cap. No synthetic commit result.
 streams=[(OUT/('interrupted-'+side)).open('w+b') for side in ('stdout','stderr')];process=None;absent=False;seen=None;started=time.monotonic()
 try:
  process=subprocess.Popen([*argv,'--worker'],cwd=WORK,env=dict(C.ENV,HOME='/tmp',CACHY_ASAHI_APPS_TRANSACTION=os.environ['OWNER_TOKEN']),stdin=subprocess.DEVNULL,stdout=streams[0],stderr=streams[1],start_new_session=True)
  end=time.monotonic()+600;pending=workspace/'apps-pending.json'
  while True:
   C.need(time.monotonic()<end and sum(os.fstat(f.fileno()).st_size for f in streams)<=1024**2,'bounded interrupted attempt')
   C.need(os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None,'attempt ended before interruption point')
   if pending.exists() and (workspace/'root/var/lib/pacman/db.lck').exists():
    # A real ALPM lock is created only after the pending intent was fsynced.
    # Inspect metadata only; never read, chmod or unlink that lock.
    try:
     candidate=C.decode(C.read(pending,65536));lock=(workspace/'root/var/lib/pacman/db.lck').lstat()
    except (ValueError,OSError):continue
    C.need(stat.S_ISREG(lock.st_mode) and lock.st_nlink==1 and lock.st_uid==0 and lock.st_size==0,'uncertain real transaction lock')
    os.killpg(process.pid,signal.SIGSTOP);seen=C.decode(C.read(pending,65536));C.need(seen==candidate,'pending intent changed');break
   time.sleep(.001)
  C.need(seen['status']=='ATTEMPT_STARTED_COMMIT_OUTCOME_NOT_RECORDED','real durable pending point required')
 finally:
  if process is not None:
   # Keep leader unreaped until every signal has been sent.
   try:os.killpg(process.pid,signal.SIGKILL)
   except ProcessLookupError:pass
   process.wait(timeout=5)
   try:os.killpg(process.pid,0)
   except ProcessLookupError:absent=True
  output_bytes=sum(os.fstat(f.fileno()).st_size for f in streams)
  for stream in streams:stream.close()
 C.need(output_bytes<=1024**2,'interrupted worker final output cap')
 C.need(absent and process.returncode==-signal.SIGKILL and (workspace/'apps-pending.json').is_file() and workspace.is_dir(),'interrupted owned copy must remain pending and retained')
 value=dict(status='FAIL_INTERRUPTED_OWNED_COPY_RETAINED',time_limit=600,reap_limit=5,seconds=round(time.monotonic()-started,6),outputs={side:C.ref(OUT,OUT/('interrupted-'+side)) for side in ('stdout','stderr')},commit_started='UNKNOWN',packages_committed='UNKNOWN',rollback='NOT_CLAIMED',pending=seen,worker_group_absent=True,direct_child_reaped=True,workspace=str(workspace),ownership_sha256=owner,disposal='ONLY_OUTER_OWNER_AFTER_CONSUMER_ABSENCE',raw_lock='NOT_READ_OR_DELETED',real_lock_observed=dict(device=lock.st_dev,inode=lock.st_ino,mode=stat.S_IMODE(lock.st_mode),bytes=lock.st_size))
 C.save(OUT/'interruption.json',value);return value

def main():
 C.need(os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_APPS574_LIFECYCLE')=='1' and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'dedicated owned native offline transaction actor required')
 C.source(SOURCE);C.need(SEED.is_mount() and WORK.is_mount(),'separate readonly source and disk workspace required');os.chown(WORK,0,0);WORK.chmod(0o700)
 adapter=C.adapter(SOURCE);T=C.load('source_transaction',SOURCE/'scripts/ci/apps7-full574-repair-native/transaction.py');before=adapter.measure(SEED,T.limits());before_hash=T.sha(T.encoded(before['nodes']));source_caps=adapter.capability_map(SEED,before,T.limits());source_caps_sha=adapter.digest(source_caps);calls=Calls();report=dict(status='FAIL',hardware='NOT_RUN',source_preserved=False,workspaces_disposed=False,rollback='NOT_CLAIMED')
 try:
  workspace=WORK/('interrupted' if '--interrupt' in sys.argv else 'main');prepared=calls.call([*backend('prepare-copy',workspace),'--source','/seed']);C.need(prepared['status']=='OWNED_COPY_PREPARED' and prepared['source_preserved'] is True,'actual original copy required');owner=prepared['ownership_sha256']
  retain_copy(workspace,owner)
  if '--interrupt' in sys.argv:
   path,plan=planned(calls,workspace,'interrupted-install','install',['cache']);argv=apply_args(calls,workspace,owner,path,plan);interruption=interrupted(calls,workspace,owner,argv)
   # Original outcome stays UNKNOWN; independently inspect only immutable baseline xattrs.
   interrupted_nodes=adapter.measure(workspace/'root',T.limits())
   adapter.capability_map(workspace/'root',interrupted_nodes,T.limits(),source_caps)
   interruption.update(security_capabilities='EXACT_SOURCE_MAP_PRESERVED_AFTER_GROUP_ABSENCE',source_capabilities_sha256=source_caps_sha)
   C.save(OUT/'interruption.json',interruption);return
  user_nodes={n:v for n,v in before['nodes'].items() if n.startswith('home/') and v['type'] in ('file','symlink')}
  C.need(user_nodes,'actual original574 user-owned data coverage required')
  path,plan=planned(calls,workspace,'install','install',['apps','cache','orphans']);argv=apply_args(calls,workspace,owner,path,plan);refusals={}
  wrong=list(argv);wrong[wrong.index('--plan-sha256')+1]='0'*64;refusals['wrong-plan-sha']=zero(calls.call(wrong,expected=1))
  # Change only our disposable copy, then restore its exact bytes/mode/owner/mtime.
  desc=next(iter(sorted((workspace/'root/var/lib/pacman/local').glob('*/desc'))));raw=C.read(desc,4*1024**2);info=desc.stat()
  try:desc.write_bytes(raw+b'\n');refusals['precommit-db-drift']=zero(calls.call(argv,expected=1))
  finally:desc.write_bytes(raw);os.utime(desc,ns=(info.st_atime_ns,info.st_mtime_ns))
  cache=types.ModuleType('actual_cache_lock');cache.__file__='/inputs/candidate/usr/bin/cachy-asahi-cache';exec(compile(C.read(Path(cache.__file__)),cache.__file__,'exec'),cache.__dict__)
  held=cache.AlpmLock(str(workspace/'root'),workspace/'root/var/lib/pacman');held.acquire()
  try:refusals['foreign-alpm-lock']=zero(calls.call(argv,expected=1));held.check()
  finally:held.release()
  C.need(not (workspace/'root/var/lib/pacman/db.lck').exists(),'holder alone must release own actual lock')
  transactions=[calls.call(argv)];counts=[len(count(workspace))];C.need(counts==[578],'actual install count differs')
  for label,names,expected in [('remove-selected',['apps','cache','orphans'],575),('remove-runtime',['runtime'],574)]:
   path,plan=planned(calls,workspace,label,'remove',names);args=apply_args(calls,workspace,owner,path,plan);transactions.append(calls.call(args));rows=count(workspace);counts.append(len(rows));C.need(len(rows)==expected,'actual explicit removal count differs')
   if expected==575:C.need(rows['cachy-asahi-repository-runtime']=='0.1.0-1' and all(n not in rows for n in C.VERSIONS if n!='cachy-asahi-repository-runtime'),'Runtime dependency must remain without explicit selection')
  disposed=calls.call(backend('dispose-copy',workspace,owner),seconds=75);C.need(disposed['status']=='OWNED_COPY_DISPOSED' and not workspace.exists(),'normal owned workspace disposal required')
  after=adapter.measure(SEED,T.limits());adapter.capability_map(SEED,after,T.limits(),source_caps);C.need(T.sha(T.encoded(after['nodes']))==before_hash,'readonly source full bytes changed')
  report.update(status='PASS_NATIVE574_APPS_ACTUAL_TRANSACTIONS',base_count=574,counts=counts,transactions=transactions,refusals=refusals,source_preserved=True,user_trust_protected_preserved=True,workspaces_disposed=True,interrupted_copy='NOT_RUN_SEPARATE_ACTOR_REQUIRED',source_tree_sha256=before_hash,source_capabilities_sha256=source_caps_sha,security_capabilities='EXACT_SOURCE_MAP_PRESERVED',package_selection='FOUR_CURRENT_SCRIPT_DATA_ONLY',original_user_nodes=len(user_nodes),original_user_nodes_sha256=C.sha(C.encoded(user_nodes)),aux_inode_liveness='NOT_ESTABLISHED_NEVER_EXECUTED_OR_CONSUMED')
  C.result(report)
 except BaseException as error:report.update(error=str(error)[:1024],error_type=type(error).__name__);raise
 finally:
  C.save(OUT/'lifecycle.json',report)
  for p in OUT.iterdir():
   if p.is_file() and not p.is_symlink():os.chown(p,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))
if __name__=='__main__':main()
