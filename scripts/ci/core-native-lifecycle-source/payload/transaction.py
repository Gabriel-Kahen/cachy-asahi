# SPDX-License-Identifier: MIT
"""Signed local Core7 transactions through intact OUTER original libalpm."""
import ctypes,os,time
from pathlib import Path
import contract as C
FLAGS=(1<<7)|(1<<10)  # Original NOHOOKS / NOSCRIPTLET copied-root boundary.

def apply(api,root,keys,log,add,remove,before,after,deadline,*,prepare_only=False):
 C.need(root in(Path('/work/pristine/root'),Path('/work/modified/root'))and keys==Path('/tmp/core-public-gpg'),'only owned copied roots and isolated public-only keyring')
 C.need(time.monotonic()<deadline and type(prepare_only)is bool and len(add)<=20 and len(remove)<=15,'original caller deadline and exact finite transaction bounds')
 expected_add={r['name']:r['version']for r in add};C.need(len(expected_add)==len(add)and len(before)in(574,589)and len(after)in(574,589),'unique fixed transaction inventories')
 base,_,installed=C.states();C.need((before,after)in((base,installed),(installed,installed),(installed,base)),'only574→589/reinstall589/rollback574')
 if after==base:C.need(set(expected_add)==C.REPLACED and set(remove)==set(installed)-set(base),'restore five originals and remove exactly15 added packages')
 elif before==base:C.need(set(expected_add)==C.NAMES|set(C.profile()['support'])and not remove,'all seven and13 original dependencies installed together')
 else:C.need(set(expected_add)==C.NAMES and not remove,'all seven byte-identical accepted archives reinstalled')
 C.need({**{n:v for n,v in before.items()if n not in remove},**expected_add}==after and all(before.get(n)==v for n,v in remove.items()),'whole declared after inventory and exact removals')
 for row in add:
  C.need(set(row)=={'name','version','archive','signature','signer'}and row['archive'].is_relative_to(Path('/inputs/packages'))and row['signature']==Path(str(row['archive'])+'.sig')and re_fpr(row['signer']),'exact bound signed local archive references')
 alpm=api['roots'].Alpm(root,keys,log,'aarch64',limits=api['roots'].Limits(deadline=min(deadline,time.monotonic()+120),max_packages=589,max_nodes=500000,max_bytes=8*1024**3,max_file_bytes=1024**3))
 try:
  C.need(alpm.inventory()==before,'actual complete before DB')
  alpm.ok(alpm.alpm_trans_init(alpm.handle,FLAGS),'original NOHOOKS/NOSCRIPTLET initialize');alpm.started=True
  for row in add:
   package=ctypes.c_void_p();alpm.ok(alpm.alpm_pkg_load(alpm.handle,os.fsencode(row['archive']),1,1,ctypes.byref(package)),'strict SIGNATURE_REQUIRED local package load')
   C.need(alpm.alpm_pkg_get_name(package).decode()==row['name']and alpm.alpm_pkg_get_version(package).decode()==row['version']and alpm.alpm_pkg_get_arch(package)in(b'aarch64',b'any'),'loaded exact package identity')
   alpm.ok(alpm.alpm_add_pkg(alpm.handle,package),'add exact signed package')
  for name,version in remove.items():
   package=alpm.alpm_db_get_pkg(alpm.alpm_get_localdb(alpm.handle),name.encode());C.need(package and alpm.alpm_pkg_get_version(package).decode()==version,'exact remove version');alpm.ok(alpm.alpm_remove_pkg(alpm.handle,package),'remove exact added package')
  error=api['roots'].installer.Ptr();alpm.ok(alpm.alpm_trans_prepare(alpm.handle,ctypes.byref(error)),'original full dependency/conflict prepare')
  actual_add=alpm.packages(alpm.alpm_trans_get_add(alpm.handle));actual_remove=alpm.packages(alpm.alpm_trans_get_remove(alpm.handle));C.need((actual_add,actual_remove)==(expected_add,remove),'full prepared add/remove equality')
  report=dict(status='PRECOMMIT_RELEASE_WITHOUT_COMMIT',before=before,after=before,prepared_add=actual_add,prepared_remove=actual_remove,commit_started=False,hooks='ORIGINAL_DISABLED',scriptlets='ORIGINAL_DISABLED_EXPLICIT_COMPLETE_SYSTEMD_POST_UPGRADE_REQUIRED',signature='REQUIRED_STRICT_LOCAL_LOAD',outer_alpm='INTACT_ORIGINAL574')
  if not prepare_only:
   report['commit_started']=True;alpm.ok(alpm.alpm_trans_commit(alpm.handle,ctypes.byref(error)),'actual complete signed transaction commit');report.update(status='COMMITTED_FULL_EXACT_INVENTORY',after=alpm.inventory());C.need(report['after']==after,'actual complete after DB')
  return report
 finally:alpm.close()

def re_fpr(value):return type(value)is str and len(value)==40 and all(c in'0123456789ABCDEF'for c in value)
