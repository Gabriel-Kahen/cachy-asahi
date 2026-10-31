# SPDX-License-Identifier: MIT
"""One genuine signed selected-Welcome transaction on the owned copy only.

The closed owner supervises this primitive for90s (same per-transaction limit
as the accepted Welcome lifecycle), then proves retirement before observation.
No hooks/scriptlets, architecture/source/library/signature/dependency bypass.
"""
import ctypes,os,re,stat,time
from pathlib import Path
import contract as C
import full_root as roots
from supervised import run
from no_transaction_exec import deny_exec
NAME='cachy-asahi-apps'

def apply(root,*,before,after,archive,keys,log):
 C.need(Path(root)==Path('/work/main/root')and Path(keys)==Path('/work/test-verification')and Path(log).parent==Path('/out'),'fixed owned copy/ephemeral TEST verification scope')
 # Both handles share the original90s transaction window and exact606 bounds.
 # The unchanged parent supervisor also enforces its smaller remaining budget.
 limits=roots.Limits(deadline=time.monotonic()+90,**C.BOUNDS)
 C.need(len(before)in(605,606)and len(after)in(605,606)and {k:v for k,v in before.items()if k!=NAME}=={k:v for k,v in after.items()if k!=NAME}and len({k:v for k,v in before.items()if k!=NAME})==605,'exact other605 versions held')
 C.need(before.get(NAME)in(None,'0.1.0-6','0.1.0-7','0.1.0-16')and after.get(NAME)in(None,'0.1.0-6','0.1.0-7','0.1.0-16'),'only Welcome4/5 selection')
 if archive is not None:
  C.need(type(archive)is dict and set(archive)=={'path','bytes','sha256','signature','signer','version'},'closed exact signed archive operand')
  path=Path(archive['path']);C.need(path.parent==Path('/runner/inputs/archives')and path.name not in('.','..')and archive['version']==after.get(NAME),'exact selected archive/version')
  C.need(C.pin(C.ordinary(path,64*1024**2))=={k:archive[k]for k in('bytes','sha256')},'whole selected archive pin')
  sig=archive['signature'];C.need(set(sig)=={'path','bytes','sha256'}and sig['path']==str(path)+'.sig'and C.pin(C.ordinary(Path(sig['path']),65536))=={k:sig[k]for k in('bytes','sha256')},'exact adjacent TEST signature')
  C.need(type(archive['signer'])is str and re.fullmatch('[A-F0-9]{40}',archive['signer']),'exact TEST signer')
  result=run(['/usr/bin/gpg','--batch','--no-options','--no-autostart','--homedir',str(keys),'--no-auto-key-retrieve','--status-fd','1','--verify',sig['path'],str(path)],env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},cwd='/',timeout=20,output_limit=65536)
  status=result['stdout'].decode();C.need(result['returncode']==0 and result['termination']is None and result['direct_child_reaped']and result['group_retired']and re.search(r'^\[GNUPG:\] VALIDSIG '+archive['signer']+r' ',status,re.M)and not re.search(r'\[GNUPG:\] (BADSIG|ERRSIG|EXPSIG|EXPKEYSIG|REVKEYSIG|KEYEXPIRED|KEYREVOKED|NO_PUBKEY)',status),'TEST signer/signature/expiry refusal')
  signature_receipt=dict(signer=archive['signer'],status_stdout=C.pin(result['stdout']),status_stderr=C.pin(result['stderr']),returncode=result['returncode'],group_retired=result['group_retired'])
 else:C.need(after.get(NAME)is None and before.get(NAME)is not None,'only explicit selected removal')
 parent=Path(root)/'var/lib/pacman';parent_before=roots._identity(parent.stat());names_before=sorted(os.listdir(parent));C.need('db.lck'not in names_before,'preexisting transaction lock refused')
 lock_seen=False
 engine=roots.Alpm(Path(root),Path(keys),Path(log),'aarch64',limits=limits)
 try:
  C.need(engine.inventory()==before,'exact complete precommit606/605 inventory')
  engine.ok(engine.alpm_trans_init(engine.handle,roots.installer.FLAGS),'transaction lock/NOHOOKS/NOSCRIPTLET');engine.started=True
  lock=(parent/'db.lck').lstat();C.need(stat.S_ISREG(lock.st_mode)and lock.st_uid==lock.st_gid==0 and lock.st_nlink==1,'actual original ALPM lock lifetime');lock_seen=True
  if archive is not None:
   package=ctypes.c_void_p();engine.ok(engine.alpm_pkg_load(engine.handle,os.fsencode(archive['path']),1,1,ctypes.byref(package)),'required signed local package load')
   C.need(engine.alpm_pkg_get_name(package)==NAME.encode()and engine.alpm_pkg_get_version(package)==archive['version'].encode()and engine.alpm_pkg_get_arch(package)in(b'aarch64',b'any'),'actual same-name package identity/version/architecture')
   engine.ok(engine.alpm_add_pkg(engine.handle,package),'selected add')
  else:
   package=engine.alpm_db_get_pkg(engine.alpm_get_localdb(engine.handle),NAME.encode());C.need(package and engine.alpm_pkg_get_version(package).decode()==before[NAME],'actual selected remove version');engine.ok(engine.alpm_remove_pkg(engine.handle,package),'selected remove')
  details=roots.installer.Ptr();engine.ok(engine.alpm_trans_prepare(engine.handle,ctypes.byref(details)),'dependency/conflict prepare')
  added={NAME:after[NAME]}if archive is not None else{};removed={NAME:before[NAME]}if archive is None else{}
  roots.installer.check_prepared(engine.packages(engine.alpm_trans_get_add(engine.handle)),engine.packages(engine.alpm_trans_get_remove(engine.handle)),added,removed)
  deny_exec() # Signed load and exact prepare completed; no commit helper may mutate protected605.
  details=roots.installer.Ptr();engine.ok(engine.alpm_trans_commit(engine.handle,ctypes.byref(details)),'signed selected commit')
 finally:engine.close()
 engine=roots.Alpm(Path(root),Path(keys),Path(log),'aarch64',limits=limits)
 try:C.need(engine.inventory()==after,'independent complete postcommit inventory')
 finally:engine.close()
 parent_after=roots._identity(parent.stat());C.need(lock_seen and not os.path.lexists(parent/'db.lck')and sorted(os.listdir(parent))==names_before and parent_before[:6]==parent_after[:6],'exact transient lock removed; parent structural identity/names held')
 return dict(lock_parent=dict(path='var/lib/pacman',lock_created=True,lock_removed=True,names=names_before,before=list(parent_before),after=list(parent_after)),status='COMMITTED_SELECTED_APPS_REQUIRES_FULL_READBACK',before_count=len(before),after_count=len(after),signature='REQUIRED_TEST_ONLY',signature_receipt=signature_receipt if archive is not None else None,hooks='DISABLED',scriptlets='DISABLED',preservation='NOT_YET_CHECKED')
