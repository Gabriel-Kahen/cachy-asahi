# SPDX-License-Identifier: MIT
"""Source/temp-data controls only; actual namespace fixtures are separately labelled."""
import copy,importlib.util,json,os,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('apps_transaction',Path(__file__).with_name('transaction.py'));T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
FILE=dict(type='file',mode=0o644,uid=0,gid=0,bytes=1,sha256='a'*64)
DIR=dict(type='directory',mode=0o755,uid=0,gid=0)

def seed():return {'etc/pacman.conf':FILE,'etc/pacman.d':DIR,'home/user/note':FILE,'usr':DIR,'usr/share':DIR,'usr/share/unselected':FILE,'usr/share/old':FILE}

class Guards(unittest.TestCase):
 def test_normal_host_refuses_before_loading_libalpm(self):
  with patch.object(T.os,'getuid',return_value=1000),patch.object(T.F,'Alpm',side_effect=AssertionError('host mutation forbidden')):
   value=T.apply(SimpleNamespace(confirm_disposable_transaction=True))
  self.assertEqual(value['status'],'FAIL');self.assertFalse(value['commit_started']);self.assertFalse(value['packages_committed'])
 def test_confirmation_required_before_any_root_access(self):
  with patch.object(T,'root_guard',side_effect=AssertionError('root access before consent')):
   value=T.apply(SimpleNamespace(confirm_disposable_transaction=False))
  self.assertFalse(value['commit_started']);self.assertIn('confirmation',value['error'])
 def test_mapped_scope_requires_explicit_owner_and_offline_network(self):
  with patch.object(T.os,'getuid',return_value=0),patch.object(T.os,'geteuid',return_value=0),patch.dict(T.os.environ,{'PATH':'/usr/bin:/bin'},clear=True):
   with self.assertRaisesRegex(ValueError,'owner token'):T.environment_guard()
 def test_nonloopback_network_refuses_even_mapped_root(self):
  def read(path,*a,**k):
   if str(path)=='/proc/self/uid_map':return '0 1000 1\n'
   if str(path)=='/proc/net/dev':return ' lo: 0\n eth0: 0\n'
   raise AssertionError(path)
  with patch.object(T.os,'getuid',return_value=0),patch.object(T.os,'geteuid',return_value=0),patch.dict(T.os.environ,{'PATH':'/usr/bin:/bin','CACHY_ASAHI_APPS_TRANSACTION':'a'*32},clear=True),patch.object(Path,'read_text',read):
   with self.assertRaisesRegex(ValueError,'offline'):T.environment_guard()
 def test_actual_temp_auxiliary_and_absolute_link_shapes_refuse(self):
  for shape in ('ldconfig','absolute-link'):
   with self.subTest(shape=shape),tempfile.TemporaryDirectory() as temporary:
    root=Path(temporary)
    if shape=='ldconfig':(root/'usr/bin').mkdir(parents=True);(root/'usr/bin/ldconfig').write_bytes(b'inert fixture only')
    else:(root/'absolute').symlink_to('/etc/passwd')
    with self.assertRaises(ValueError):T.observe(root,T.limits())
 def test_full_snapshot_pins_bind_db_and_unowned_user_bytes(self):
  observation=dict(nodes={k:dict(v) for k,v in (seed()|{'var/lib/pacman/local/a-1/desc':FILE}).items()});inventory=dict(packages=[dict(name='a',version='1')])
  original=T.pins(observation,inventory)
  changed=copy.deepcopy(observation);changed['nodes']['home/user/note']['sha256']='b'*64
  actual=T.pins(changed,inventory);self.assertNotEqual(original['tree_sha256'],actual['tree_sha256']);self.assertEqual(original['database_sha256'],actual['database_sha256'])
  changed=copy.deepcopy(observation);changed['nodes']['var/lib/pacman/local/a-1/desc']['sha256']='b'*64
  self.assertNotEqual(original['database_sha256'],T.pins(changed,inventory)['database_sha256'])
 def test_finite_existing_full_root_bounds(self):
  value=T.limits();self.assertEqual((value.max_packages,value.max_nodes,value.max_bytes),(587,500000,8*1024**3));self.assertLessEqual(value.deadline-time.monotonic(),300)
 def test_payload_rejects_trust_hook_setid_alias_and_nonusr(self):
  before=seed()|{'usr/alias':dict(type='symlink',mode=511,uid=0,gid=0,target='share')}
  for name,node in [('etc/pacman.conf',FILE),('home/user/note',FILE),('usr/share/libalpm/hooks/evil.hook',FILE),('usr/bin/setid',FILE|dict(mode=0o4755)),('usr/alias/file',FILE),('usr/lib/modules/x',FILE)]:
   with self.subTest(name=name),self.assertRaises(ValueError):T.payload_guard({name:node},before)
  T.payload_guard({'usr/share/app':FILE},before)
 def test_unselected_db_trust_and_user_state_are_exact(self):
  before=seed()|{'var/lib/pacman/local/untouched-1/desc':FILE};old={'usr/share/old':FILE};payload={'usr/share/app':FILE}
  after={n:v for n,v in before.items() if n not in old}|payload
  T.check_preservation(before,after,old,payload,{'var/lib/pacman/local/app-1'})
  for key in ('home/user/note','etc/pacman.conf','usr/share/unselected','var/lib/pacman/local/untouched-1/desc'):
   with self.subTest(key=key),self.assertRaises(ValueError):T.check_preservation(before,after|{key:FILE|dict(sha256='b'*64)},old,payload,set())
  with self.assertRaises(ValueError):T.check_preservation(before,after|{'usr/share/extra':FILE},old,payload,set())
 def test_missing_removed_or_wrong_installed_payload_refuses(self):
  before=seed();old={'usr/share/old':FILE};payload={'usr/share/app':FILE};after={n:v for n,v in before.items() if n not in old}|payload
  for state in (after|old,after|{'usr/share/app':FILE|dict(mode=0o600)}):
   with self.assertRaises(ValueError):T.check_preservation(before,state,old,payload,set())
 def test_prepare_keeps_dependencies_conflicts_lock_and_signatures(self):
  self.assertEqual(T.I.FLAGS,(1<<7)|(1<<10))
  text=Path(T.__file__).read_text();self.assertNotIn('alpm_register_syncdb',text);self.assertNotIn('db.lck\').unlink',text)
 def test_reinstall_rows_are_exact_after_metadata_not_removal_or_expansion(self):
  app=SimpleNamespace(indexed=lambda rows,r:{p['name']:dict(p) for p in rows},package=lambda p,r:{k:v for k,v in p.items() if k in ('name','version')},encoded=T.encoded)
  inventory={'packages':[{'name':'base','version':'1'},{'name':'app','version':'1'}]};after=inventory['packages'];plan={'additions':[],'upgrades':[],'removals':[],'reinstalls':[{'before':after[1],'after':after[1]}],'after_inventory_sha256':T.sha(T.encoded(sorted(after,key=lambda row:row['name'])))}
  self.assertEqual(T.expected_packages(app,inventory,plan,None),{'base':after[0],'app':after[1]})
  plan['reinstalls'][0]['after']={'name':'app','version':'2'}
  with self.assertRaisesRegex(ValueError,'after map'):T.expected_packages(app,inventory,plan,None)
 def test_repair_allows_only_missing_selected_ordinary_leaf(self):
  nodes={'usr':DIR,'usr/share':DIR};payload={'usr/share/app':FILE}
  self.assertEqual(T.reinstall_old({'usr/share/app'},nodes,payload),{})
  self.assertEqual(T.reinstall_old({'usr/share/app'},nodes|payload,payload),payload)
  for state,target in ((nodes,{'usr/share/app':DIR}),({'usr':DIR},payload),(nodes|{'usr/share/app':DIR},payload),(nodes|{'usr/share/app':dict(type='symlink',target='elsewhere')},payload),(nodes|{'usr/share/app':FILE|{'hardlink_group':'held'}},payload)):
   with self.subTest(state=state),self.assertRaises(ValueError):T.reinstall_old({'usr/share/app'},state,target)
 def test_commit_prepare_failure_is_not_commit(self):
  class Bad:
   handle=None
   def alpm_get_localdb(self,*a):return None
   def alpm_trans_prepare(self,*a):return -1
   def ok(self,code,where):
    if code:raise ValueError(where)
  result=dict(commit_started=False,packages_committed=False)
  with self.assertRaises(ValueError):T.commit(Bad(),{},{},{},'x86_64',result)
  self.assertEqual(result,dict(commit_started=False,packages_committed=False))
 def test_commit_error_retains_unknown_not_rollback(self):
  class Bad:
   handle=None
   def alpm_get_localdb(self,*a):return None
   def alpm_db_get_pkg(self,*a):return 1
   def alpm_pkg_get_version(self,*a):return b'1'
   def alpm_remove_pkg(self,*a):return 0
   def alpm_trans_prepare(self,*a):return 0
   def alpm_trans_get_add(self,*a):return 'add'
   def alpm_trans_get_remove(self,*a):return 'remove'
   def packages(self,value):return {} if value=='add' else {'app':'1'}
   def alpm_trans_commit(self,*a):raise KeyboardInterrupt()
   def ok(self,*a):pass
  result=dict(commit_started=False,packages_committed=False)
  with self.assertRaises(KeyboardInterrupt):T.commit(Bad(),{}, {'app':'1'}, {},'x86_64',result)
  self.assertTrue(result['commit_started']);self.assertEqual(result['packages_committed'],'UNKNOWN')

if __name__=='__main__':unittest.main(verbosity=2)
