#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Selected catalog-orphan removal in the existing owned offline Apps copy only."""
import argparse,hashlib,importlib.util,importlib.machinery,json,os,stat,sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path,loader=importlib.machinery.SourceFileLoader(name,str(path)));value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
def source_check():
 rows=json.loads(Path(__file__).with_name('selected-source-pins.json').read_bytes())['files']
 if set(rows)!={'scripts/apps/transaction.py','packages/tools/cachy-asahi-orphans/cachy-asahi-orphans','packages/tools/cachy-asahi-orphans/protection-floor.json'}:raise ValueError('finite original cleanup source closure required')
 for name,row in rows.items():
  path=ROOT/name
  if any(p.is_symlink() for p in (path,*path.parents)) or path.stat().st_nlink!=1 or path.stat().st_size>128*1024:raise ValueError('ordinary pinned source required')
  raw=path.read_bytes()
  if row!=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()):raise ValueError('cleanup source differs: '+name)
 return rows
source_check()
T=load('_orphan_owned_apps_transaction',ROOT/'scripts/apps/transaction.py')
O=load('_orphan_exact_readonly_rules',ROOT/'packages/tools/cachy-asahi-orphans/cachy-asahi-orphans')
SUPPORTED={'cachy-asahi-'+name for name in ('apps','repository-runtime','cache','orphans')}
need=T.need
class Cancelled(ValueError):pass

def selected_names(value):
 need(type(value) is list and len(value)<=4 and len(value)==len(set(value)) and all(type(n) is str and O.NAME.fullmatch(n) for n in value),'explicit unique selected names required; no all/recursive selectors')
 need(set(value)<=SUPPORTED,'unsupported cleanup scope: only existing full574 four-app catalog boundary')
 return sorted(value)

class _OwnedLock:
 """Constructed only after the original ALPM transaction initialization succeeds."""
 def __init__(self,root,alpm):
  need(alpm.started is True and alpm.handle,'proved live ALPM transaction required')
  self.alpm=alpm;self.handle=alpm.handle;self.db=root/T.DB
  self.fd=os.open(self.db/'db.lck',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
  self.original=self.identity(os.fstat(self.fd))
  try:self.check(self.db)
  except BaseException:os.close(self.fd);raise
 @staticmethod
 def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 def check(self,db):
  need(db==self.db and self.alpm.started is True and self.alpm.handle==self.handle and self.handle,'original live handle/root binding changed')
  held=os.fstat(self.fd);named=(db/'db.lck').lstat()
  need(stat.S_ISREG(held.st_mode) and held.st_uid==0 and held.st_nlink==1 and held.st_size==0 and not held.st_mode&0o022 and self.identity(held)==self.identity(named)==self.original,'original owned ALPM lock identity changed')
 def close(self):os.close(self.fd)

def _facts(report):
 return {key:report[key] for key in ('schema_version','scope','root','dbpath','libalpm','protection_floor_sha256','extra_protected','packages','candidates','broken_dependencies','apply_supported')}

def _recheck(root,alpm,proof,saved,selected,cancel):
 need(alpm is proof.alpm,'different ALPM handle refused');proof.check(root/T.DB)
 prior=O.unlocked
 try:
  # Private module instance only, never a product CLI ignore-lock option.
  O.unlocked=proof.check
  current,lost=O.inspect(root,root/T.DB,saved['extra_protected'],selected)
 finally:O.unlocked=prior
 proof.check(root/T.DB)
 need(_facts(current)==_facts(saved),'stale orphan graph/version/reason/protection facts')
 need(not current['broken_dependencies'] and not lost,'required or previously satisfied optional relation would be lost')
 need(all(current['packages'][n]['candidate'] and current['packages'][n]['reason']=='dependency' and not current['packages'][n]['protected'] and not current['packages'][n]['required_by'] and not current['packages'][n]['optional_required_by'] for n in selected),'selected package no longer an unprotected dependency leaf')
 if cancel():raise Cancelled('cancelled before original ALPM prepare/commit')
 return current

def _cached_archive(client,release,row,files):
 # Release package metadata has no size field. Re-read the same outside cache
 # using the original bounded single-link/no-follow streaming verifier.
 filename=row.get('filename');need(type(filename) is str and filename not in ('','.','..') and Path(filename).name==filename and '/' not in filename and '\\' not in filename,'ordinary authenticated archive basename required')
 member='repo/'+filename;client.reference(member,row['sha256'])
 need(files.get(member)==row['sha256'],'authenticated package and release-file archive hashes differ')
 fd=client.directory(release)
 try:actual,size=client.hash_member(fd,member)
 finally:os.close(fd)
 need(actual==row['sha256']==files[member],'outside authenticated rollback cache bytes changed')
 return dict(path=str(release/member),bytes=size,sha256=actual)

def apply(args,*,cancel=lambda:False):
 """Original Apps apply Namespace plus selected/orphan_plan/orphan_plan_sha256."""
 need(args.confirm_disposable_transaction is True,'explicit disposable transaction confirmation required')
 workspace,root,owner=T.root_guard(args) # Never / or a live host; original guard unchanged.
 need(all(getattr(args,n,None) for n in ('full574_policy','full574_policy_sha256','full574_lease','full574_lease_sha256')),'original full574 lease/policy required')
 selected=selected_names(args.selected)
 if not selected:return dict(status='NOT_APPLIED_NO_SELECTION',applied=False,authenticated=False,transaction='NOT_STARTED')
 if cancel():return dict(status='CANCELLED_NOT_APPLIED',applied=False,transaction='NOT_STARTED')
 need(args.operation=='remove','selected cleanup is remove-only')
 raw=T.B.client.read_path(Path(args.orphan_plan).absolute(),T.MAX_PLAN);need(T.sha(raw)==args.orphan_plan_sha256,'caller orphan plan SHA256 differs');plan=T.I.decode(raw)
 need(plan.get('operation')=='EXPLICIT_ORPHAN_REMOVAL_PLAN' and set(plan.get('selected',{}))==set(selected),'exact saved explicit readonly selection required')
 regenerated=O.plan(Path(plan['assessment']),selected);need(regenerated==plan,'saved readonly plan is stale, never authority')
 saved,_=O.json_file(Path(plan['assessment']));need(saved['root']==str(root) and saved['dbpath']==str(root/T.DB),'assessment must name this exact owned copied root')
 need(not saved['broken_dependencies'],'baseline broken dependencies refused')
 # Source/lease and complete snapshots, signed release/catalog authentication,
 # exact replanning, full574 four-app selection, payload/caps/aux preservation,
 # pending marker and ordinary ALPM exclusion remain in original T.apply.
 original_transaction=T.B.transaction;original_commit=T.commit;original_source=T.app_source;live={};cache={}
 def app_source(value):
  app,c,r=original_source(value);authenticated=app.authenticated
  @contextmanager
  def checked_auth(*a,**kw):
   with authenticated(*a,**kw) as context:
    release=Path(args.release).absolute();need(not release.is_relative_to(workspace) and not workspace.is_relative_to(release),'known-good signed cache must remain outside mutable/disposed workspace')
    rows={row['name']:row for row in context['release']['packages']}
    known={}
    for name in selected:
     need(name in context['available'] and name in rows and rows[name]['version']==plan['selected'][name]['version'],'authenticated matching rollback archive/version required')
     row=rows[name];known[name]=_cached_archive(c,release,row,context['release']['files'])
    need(not cache or known==cache,'authenticated rollback cache changed');cache.update(known)
    yield context
  app.authenticated=checked_auth;return app,c,r
 @contextmanager
 def transaction(target,keys,work,factory):
  need(target==root and not live,'single exact copied-root ALPM transaction required')
  with original_transaction(target,keys,work,factory) as alpm:
   proof=_OwnedLock(root,alpm);live.update(alpm=alpm,proof=proof)
   try:yield alpm
   finally:
    try:proof.check(root/T.DB)
    finally:proof.close();live.clear()
 def commit(alpm,add,remove,archives,architecture,result):
  need(set(cache)==set(selected),'authenticated rollback cache absent')
  need(live.get('alpm') is alpm and not add and not archives and remove=={n:plan['selected'][n]['version'] for n in selected},'authenticated Apps removal differs from explicit orphan selection')
  need(T.sha(T.B.client.read_path(Path(args.orphan_plan).absolute(),T.MAX_PLAN))==args.orphan_plan_sha256,'orphan plan changed')
  _recheck(root,alpm,live['proof'],saved,selected,cancel)
  return original_commit(alpm,add,remove,archives,architecture,result)
 T.B.transaction=transaction;T.commit=commit;T.app_source=app_source
 try:result=T.apply(args)
 finally:
  need(T.B.transaction is transaction and T.commit is commit and T.app_source is app_source,'private transaction adapter replaced')
  T.B.transaction=original_transaction;T.commit=original_commit;T.app_source=original_source
 if result.get('status')=='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION':
  result.update(status='PASS_SELECTED_CATALOG_ORPHAN_REMOVAL_IN_OWNED_COPY',selected=selected,retained_matching_signed_cache=cache,orphan_plan_sha256=args.orphan_plan_sha256,orphan_rules='ORIGINAL_REASON_REQUIRED_OPTIONAL_FLOOR_RECHECK_UNDER_OWNED_ALPM_EXCLUSION')
 elif result.get('error_type')=='Cancelled' and result.get('commit_started') is False:result.update(status='CANCELLED_NOT_APPLIED',applied=False)
 return result

REQUEST_KEYS={'workspace','ownership_sha256','apps_source','apps_provenance_sha256','repository_source',
 'release','release_sha256','catalog','catalog_sha256','catalog_signature','keyring','signer','plan','plan_sha256',
 'before_tree_sha256','before_database_sha256','before_packages_sha256','before_inventory_sha256','operation','applications',
 'full574_policy','full574_policy_sha256','full574_lease','full574_lease_sha256','confirm_disposable_transaction',
 'selected','orphan_plan','orphan_plan_sha256'}
def request(path,digest):
 raw=T.B.client.read_path(path.absolute(),65536);need(T.sha(raw)==digest,'explicit request SHA256 differs');value=T.I.decode(raw)
 need(type(value) is dict and set(value)==REQUEST_KEYS,'closed original Apps plus selected-cleanup request required')
 need(value['confirm_disposable_transaction'] is True,'explicit confirmation required')
 for name in REQUEST_KEYS-{'confirm_disposable_transaction','selected','applications'}:need(type(value[name]) is str and 0<len(value[name])<=4096,'bounded explicit request operand required')
 need(type(value['applications']) is list and 0<len(value['applications'])<=4 and all(type(n) is str and 0<len(n)<=128 for n in value['applications']),'bounded exact catalog IDs required')
 selected_names(value['selected']);return SimpleNamespace(**value)
def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--request',type=Path,required=True);parser.add_argument('--request-sha256',required=True);parser.add_argument('--worker',action='store_true',help=argparse.SUPPRESS);cli=parser.parse_args(argv)
 try:
  args=request(cli.request,cli.request_sha256);T.root_guard(args)
  if cli.worker:result=apply(args)
  else:
   row=T.SUP.run([sys.executable,'-I','-B',str(Path(__file__).resolve()),'--request',str(cli.request.absolute()),'--request-sha256',cli.request_sha256,'--worker'],env=dict(os.environ),cwd=str(Path(args.workspace).absolute()),timeout=T.execution_seconds(args),output_limit=1024**2)
   need(row['termination'] is None and row['direct_child_reaped'] and row['returncode'] in (0,1),'worker interrupted or incomplete: commit outcome UNKNOWN; dispose owned copy')
   result=T.I.decode(row['stdout']);need(result.get('status') in ('PASS_SELECTED_CATALOG_ORPHAN_REMOVAL_IN_OWNED_COPY','FAIL','CANCELLED_NOT_APPLIED','NOT_APPLIED_NO_SELECTION'),'bounded worker outcome required')
   result['worker']={k:row[k] for k in ('termination','returncode','direct_child_reaped','group_kill_sent')}
 except BaseException as error:result=dict(status='FAIL',error_type=type(error).__name__,error=str(error)[:1024],commit_started='UNKNOWN',packages_committed='UNKNOWN',rollback='NOT_CLAIMED',recovery='DISPOSE_OWNED_COPY_ON_UNKNOWN_OUTCOME')
 print(T.encoded(result).decode(),end='');return int(result.get('status')=='FAIL')
if __name__=='__main__':raise SystemExit(main())
