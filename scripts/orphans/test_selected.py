# SPDX-License-Identifier: MIT
"""Bounded pure adapter/temp lock controls. No ALPM/native transaction actor."""
import copy,importlib.util,os,stat,subprocess,sys,tempfile,unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
p=Path(__file__).with_name('selected.py');spec=importlib.util.spec_from_file_location('orphan_cleanup_controls',p);M=importlib.util.module_from_spec(spec);sys.modules[spec.name]=M;spec.loader.exec_module(M)
def report(root):
 return dict(schema_version=1,scope='readonly',root=str(root),dbpath=str(root/M.T.DB),database=dict(sha256='old'),libalpm='16.0.0',protection_floor_sha256='floor',extra_protected=[],packages={'cachy-asahi-cache':dict(version='0.2.0-1',reason='dependency',candidate=True,protected=False,required_by=[],optional_required_by=[],depends=[],optdepends=[],provides=[],satisfiers={'depends':{},'optdepends':{}})},candidates=['cachy-asahi-cache'],broken_dependencies=[],apply_supported=False)
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
  self.block=patch.object(subprocess,'Popen',side_effect=AssertionError('all actors forbidden'));self.block.start();self.addCleanup(self.block.stop)
 def test_held_backend_and_readonly_rules_byte_pins(self):self.assertEqual(len(M.source_check()),3)
 def test_only_explicit_unique_supported_catalog_names(self):
  self.assertEqual(M.selected_names(['cachy-asahi-cache']),['cachy-asahi-cache'])
  for value in (['all'],['*'],['glibc'],['cachy-asahi-cache']*2,'cachy-asahi-cache',[None]):
   with self.assertRaises((ValueError,TypeError)):M.selected_names(value)
 def test_live_host_guard_precedes_noop_or_saved_plan(self):
  args=NS(confirm_disposable_transaction=True)
  with patch.object(M.T,'root_guard',side_effect=ValueError('live host refused')),patch.object(M.O,'plan',side_effect=AssertionError('too early')):
   with self.assertRaisesRegex(ValueError,'live host'):M.apply(args)
 def test_noop_cancel_and_full574_lease_are_not_transactions(self):
  args=NS(confirm_disposable_transaction=True,selected=[],**{k:'held' for k in ('full574_policy','full574_policy_sha256','full574_lease','full574_lease_sha256')})
  with patch.object(M.T,'root_guard',return_value=(self.root,self.root,{})),patch.object(M.T,'apply',side_effect=AssertionError('no transaction')):
   self.assertEqual(M.apply(args)['status'],'NOT_APPLIED_NO_SELECTION')
   args.selected=['cachy-asahi-cache'];self.assertEqual(M.apply(args,cancel=lambda:True)['status'],'CANCELLED_NOT_APPLIED')
   args.full574_lease=None
   with self.assertRaisesRegex(ValueError,'lease'):M.apply(args)
 def proof(self):
  actor=NS(started=True,handle=123);return actor,NS(alpm=actor,check=lambda db:None)
 def test_actual_graph_under_owned_lock_reuses_product_inspector_and_restores_guard(self):
  actor,proof=self.proof();saved=report(self.root);original=M.O.unlocked;seen=[]
  def inspect(root,db,extra,selected):
   self.assertIsNot(M.O.unlocked,original);M.O.unlocked(db);seen.append((root,db,extra,selected));current=copy.deepcopy(saved);current['database']={'sha256':'owned-lock-full-snapshot'};return current,[]
  with patch.object(M.O,'inspect',side_effect=inspect):M._recheck(self.root,actor,proof,saved,['cachy-asahi-cache'],lambda:False)
  self.assertIs(M.O.unlocked,original);self.assertEqual(seen,[(self.root,self.root/M.T.DB,[],['cachy-asahi-cache'])])
 def test_changed_reason_relations_floor_version_and_lost_optional_refuse(self):
  actor,proof=self.proof();saved=report(self.root)
  for field,value in [('reason','explicit'),('version','changed'),('required_by',['needed']),('optional_required_by',['uses']),('protected',True)]:
   current=copy.deepcopy(saved);current['packages']['cachy-asahi-cache'][field]=value
   with patch.object(M.O,'inspect',return_value=(current,[])),self.assertRaisesRegex(ValueError,'stale'):M._recheck(self.root,actor,proof,saved,['cachy-asahi-cache'],lambda:False)
  for key,value in [('protection_floor_sha256','changed'),('libalpm','changed')]:
   current=copy.deepcopy(saved);current[key]=value
   with patch.object(M.O,'inspect',return_value=(current,[])),self.assertRaises(ValueError):M._recheck(self.root,actor,proof,saved,['cachy-asahi-cache'],lambda:False)
  with patch.object(M.O,'inspect',return_value=(saved,[{'kind':'optdepends'}])),self.assertRaisesRegex(ValueError,'optional'):M._recheck(self.root,actor,proof,saved,['cachy-asahi-cache'],lambda:False)
 def test_cancel_at_final_recheck_and_foreign_handle_never_commit(self):
  actor,proof=self.proof();saved=report(self.root)
  with patch.object(M.O,'inspect',return_value=(saved,[])),self.assertRaises(M.Cancelled):M._recheck(self.root,actor,proof,saved,['cachy-asahi-cache'],lambda:True)
  with self.assertRaisesRegex(ValueError,'different ALPM'):M._recheck(self.root,NS(handle=124),proof,saved,['cachy-asahi-cache'],lambda:False)
 def test_failed_inspection_restores_original_lock_guard(self):
  actor,proof=self.proof();original=M.O.unlocked
  with patch.object(M.O,'inspect',side_effect=ValueError('actual refusal')),self.assertRaisesRegex(ValueError,'actual refusal'):M._recheck(self.root,actor,proof,report(self.root),['cachy-asahi-cache'],lambda:False)
  self.assertIs(M.O.unlocked,original)
 def test_owned_lock_requires_live_handle_and_exact_regular_identity(self):
  db=self.root/M.T.DB;db.mkdir(parents=True);lock=db/'db.lck';lock.touch(mode=0o600)
  with self.assertRaisesRegex(ValueError,'live'):M._OwnedLock(self.root,NS(started=False,handle=0))
  # Simulate only mapped UID0 metadata; real temp inode/name/replacement remain tested.
  real_fstat=os.fstat;real_lstat=Path.lstat
  def mapped(s):return NS(**{k:(0 if k=='st_uid' else getattr(s,k)) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')})
  with patch.object(os,'fstat',side_effect=lambda fd:mapped(real_fstat(fd))),patch.object(Path,'lstat',lambda path:mapped(real_lstat(path))):
   actor=NS(started=True,handle=123);proof=M._OwnedLock(self.root,actor)
   try:
    proof.check(db);actor.handle=124
    with self.assertRaisesRegex(ValueError,'handle'):proof.check(db)
    actor.handle=123;lock.rename(db/'old-lock');lock.touch(mode=0o600)
    with self.assertRaisesRegex(ValueError,'identity'):proof.check(db)
   finally:proof.close()
 def test_current_uid_lock_is_not_adopted_as_root_actor_lock(self):
  db=self.root/M.T.DB;db.mkdir(parents=True);(db/'db.lck').touch(mode=0o600)
  if os.getuid()!=0:
   with self.assertRaisesRegex(ValueError,'identity'):M._OwnedLock(self.root,NS(started=True,handle=123))
 def delegated(self,*,version='0.2.0-1',remove=None):
  from unittest.mock import Mock
  selected=['cachy-asahi-cache'];saved=report(self.root);plan=dict(operation='EXPLICIT_ORPHAN_REMOVAL_PLAN',assessment=str(self.root/'assessment.json'),selected={n:saved['packages'][n] for n in selected})
  path=self.root/'plan.json';raw=M.T.encoded(plan);path.write_bytes(raw)
  args=NS(confirm_disposable_transaction=True,selected=selected,operation='remove',release=str(self.root/'outside-cache'),orphan_plan=str(path),orphan_plan_sha256=M.T.sha(raw),**{k:'held' for k in ('full574_policy','full574_policy_sha256','full574_lease','full574_lease_sha256')})
  workspace=self.root/'workspace';actor=NS(started=True,handle=123);events=[]
  archive=Path(args.release)/'repo/cache.pkg.tar.xz';archive.parent.mkdir(parents=True,exist_ok=True);archive.write_bytes(b'INERT SIGNED-CONTEXT ARCHIVE BYTES');digest=M.T.sha(archive.read_bytes())
  proof=NS(alpm=actor,check=lambda db:events.append('lock-check'),close=lambda:events.append('lock-close'))
  @contextmanager
  def authenticated(*a):
   events.append('original-authenticate');yield dict(available={'cachy-asahi-cache':{}},release=dict(files={'repo/cache.pkg.tar.xz':digest},packages=[dict(name='cachy-asahi-cache',version=version,filename='cache.pkg.tar.xz',sha256=digest)]))
  @contextmanager
  def transaction(*a):events.append('original-alpm-exclusion');yield actor
  def committed(*a):events.append('original-commit');a[-1].update(commit_started=True,packages_committed=True)
  def backend(value):
   app,c,r=M.T.app_source(value)
   with app.authenticated(value,None,None),M.T.B.transaction(self.root,None,self.root,None) as handle:
    result=dict(status='PASS_OWNED_DISPOSABLE_APPS_TRANSACTION',commit_started=False,packages_committed=False)
    M.T.commit(handle,{},remove or {'cachy-asahi-cache':'0.2.0-1'},{},'aarch64',result)
   return result
  with patch.object(M.T,'root_guard',return_value=(workspace,self.root,{})),patch.object(M.O,'plan',return_value=plan),patch.object(M.O,'json_file',return_value=(saved,{})),patch.object(M.O,'inspect',return_value=(saved,[])),patch.object(M.T,'app_source',return_value=(NS(authenticated=authenticated),M.T.B.client,None)) as original_source,patch.object(M.T.B,'transaction',transaction),patch.object(M.T,'commit',committed),patch.object(M,'_OwnedLock',return_value=proof),patch.object(M.T,'apply',side_effect=backend):
   try:return M.apply(args),events
   finally:
    self.assertIs(M.T.app_source,original_source);self.assertIs(M.T.B.transaction,transaction);self.assertIs(M.T.commit,committed)
 def test_delegates_existing_auth_exclusion_exact_remove_commit_and_retains_cache(self):
  result,events=self.delegated();self.assertEqual(result['status'],'PASS_SELECTED_CATALOG_ORPHAN_REMOVAL_IN_OWNED_COPY')
  self.assertLess(events.index('original-authenticate'),events.index('original-alpm-exclusion'));self.assertLess(events.index('original-alpm-exclusion'),events.index('original-commit'));self.assertEqual(events[-1],'lock-close')
  self.assertEqual(result['retained_matching_signed_cache']['cachy-asahi-cache'],dict(path=str(self.root/'outside-cache/repo/cache.pkg.tar.xz'),bytes=len(b'INERT SIGNED-CONTEXT ARCHIVE BYTES'),sha256=M.T.sha(b'INERT SIGNED-CONTEXT ARCHIVE BYTES')))
 def test_mismatching_rollback_archive_and_extra_removal_refuse_and_restore(self):
  with self.assertRaisesRegex(ValueError,'rollback archive'):self.delegated(version='changed')
  with self.assertRaisesRegex(ValueError,'explicit orphan selection'):self.delegated(remove={'cachy-asahi-cache':'0.2.0-1','extra':'1'})
 def archive_fixture(self):
  release=self.root/'known-good';archive=release/'repo/apps.pkg.tar.xz';archive.parent.mkdir(parents=True);archive.write_bytes(b'actual inert bytes no size declared')
  row=dict(name='cachy-asahi-apps',version='0.1.0-5',arch='any',filename=archive.name,sha256=M.T.sha(archive.read_bytes()),provenance='provenance/cachy-asahi-apps.json',depend=['cachy-asahi-repository-runtime=0.1.0-1'],files=['usr/bin/cachy-asahi-apps'],provides=[],conflict=[],replaces=[],license=['MIT'])
  return release,archive,row,{'repo/'+archive.name:row['sha256']}
 def test_real_release_row_schema_without_size_uses_measured_original_cache_bytes(self):
  release,archive,row,files=self.archive_fixture();self.assertNotIn('size',row)
  result=M._cached_archive(M.T.B.client,release,row,files)
  self.assertEqual(result,dict(path=str(archive),bytes=archive.stat().st_size,sha256=M.T.sha(archive.read_bytes())))
 def test_changed_cache_or_signed_row_file_map_hashes_refuse(self):
  release,archive,row,files=self.archive_fixture()
  for changed in ({},dict(files,**{'repo/'+archive.name:'0'*64})):
   with self.assertRaisesRegex(ValueError,'release-file'):M._cached_archive(M.T.B.client,release,row,changed)
  archive.write_bytes(b'changed cache payload')
  with self.assertRaisesRegex(ValueError,'cache bytes changed'):M._cached_archive(M.T.B.client,release,row,files)
 def test_cache_aliases_escaping_names_and_original_finite_bound_refuse(self):
  release,archive,row,files=self.archive_fixture();original=archive.read_bytes();outside=self.root/'outside';outside.write_bytes(original)
  archive.unlink();archive.symlink_to(outside)
  with self.assertRaises(OSError):M._cached_archive(M.T.B.client,release,row,files)
  archive.unlink();os.link(outside,archive)
  with self.assertRaisesRegex(M.T.B.client.Error,'non-hardlinked'):M._cached_archive(M.T.B.client,release,row,files)
  archive.unlink();archive.write_bytes(original)
  for name in ('../escape','/absolute','subdir/archive','',None,'file\\name'):
   with self.subTest(name=name),self.assertRaises(ValueError):M._cached_archive(M.T.B.client,release,dict(row,filename=name),files)
  with archive.open('r+b') as stream:stream.truncate(M.T.B.client.MAX_FILE+1)
  with self.assertRaisesRegex(M.T.B.client.Error,'bounded size'):M._cached_archive(M.T.B.client,release,row,files)
if __name__=='__main__':unittest.main(verbosity=2)
