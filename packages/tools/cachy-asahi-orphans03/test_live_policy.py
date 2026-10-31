#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private file/policy controls only; no ALPM transaction or helper execution."""
import importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('live_policy_under_test',HERE/'live_policy.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
spec=importlib.util.spec_from_file_location('live_policy_remove',HERE/'remove.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R);O=R.O

def hook(kind='Package',target='test-leaf',operation='Remove'):
 return '[Trigger]\nOperation = '+operation+'\nType = '+kind+'\nTarget = '+target+'\n\n[Action]\nWhen = PostTransaction\nExec = /usr/bin/never-executed\n'

class Policy(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.home=Path(self.tmp.name);self.root=self.home/'root';self.root.mkdir(mode=0o700);self.db=self.root/'var/lib/pacman';self.db.mkdir(parents=True)
  self.policy=dict(schema_version=1,profile='private-fixture',root=str(self.root),dbpath=str(self.db),supported_base={'test-base':'1-1'},platform={},transaction_flags=1152,hooks='refuse-matching',scriptlets='refuse',configuration='refuse-selected',ldconfig={'mode':'forbid'})
 def write(self,path,text,mode=0o644):
  p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text);p.chmod(mode);return p
 def effect(self,selected=('test-leaf',),files=('usr/share/test-leaf',)):
  return P.effects(self.root,self.policy,selected,files,O)
 def reviewed(self):
  binary=self.write('usr/bin/ldconfig','INERT FIXTURE; NEVER EXECUTE\n',0o755);config=self.write('etc/ld.so.conf','include /etc/ld.so.conf.d/*.conf\ninclude /usr/lib/ld.so.conf.d/*.conf\n')
  runtime=Path('/usr/lib/libalpm.so.16').resolve(strict=True)
  self.policy['ldconfig']=dict(mode='reviewed',executable_sha256=O.digest(binary.read_bytes()),config_sha256=O.digest(config.read_bytes()),libalpm_sha256=O.digest(runtime.read_bytes()))
 def test_double_slash_root_cannot_bypass_exact_root_profile(self):
  self.policy.update(root='//',dbpath='//var/lib/pacman')
  with self.assertRaises(O.Refused):P.validate_target(Path('//'),Path('//var/lib/pacman'),self.policy,O)
 def test_exact_hash_bound_policy_read(self):
  p=self.home/'policy.json';p.write_bytes(O.encoded(self.policy));p.chmod(0o600);value,record=P.read_policy(p,O.digest(p.read_bytes()),O);self.assertEqual(value,self.policy);self.assertEqual(record['mode'],0o600)
  with self.assertRaises(O.Refused):P.read_policy(p,'0'*64,O)
 def test_unknown_policy_fields_and_relaxed_flags_refuse(self):
  for key,value in [('extra',True),('transaction_flags',0),('configuration','allow'),('hooks','allow'),('scriptlets','allow')]:
   policy=dict(self.policy);policy[key]=value
   with self.subTest(key=key),self.assertRaises(O.Refused):P.validate_target(self.root,self.db,policy,O)
 def test_fixture_profile_never_authorizes_live_root(self):
  policy=dict(self.policy,root='/',dbpath='/var/lib/pacman')
  with self.assertRaisesRegex(O.Refused,'fixture'):P.validate_target(Path('/'),Path('/var/lib/pacman'),policy,O)
 def test_real_profile_requires_full_core_and_platform_map(self):
  policy=dict(self.policy,profile='asahi-alarm-m2')
  with self.assertRaisesRegex(O.Refused,'complete'):P.validate_inventory(policy,{},O)
  policy.update(supported_base={n:'1-1' for n in P.BASE},platform={n:'1-1' for n in P.PLATFORM})
  P.validate_inventory(policy,{n:{'version':'1-1'} for n in (*P.BASE,*P.PLATFORM)},O)
 def test_explicit_target_and_conventional_db_binding(self):
  value=P.validate_target(self.root,self.db,self.policy,O);self.assertEqual(value['root'],str(self.root));self.assertIn('ino',value['dbpath_identity'])
  with self.assertRaises(O.Refused):P.validate_target(self.home,self.db,self.policy,O)
  policy=dict(self.policy,dbpath=str(self.root/'other'))
  with self.assertRaises(O.Refused):P.validate_target(self.root,self.root/'other',policy,O)
  policy=dict(self.policy,root='//',dbpath='//var/lib/pacman')
  with self.assertRaises(O.Refused):P.validate_target(Path('//'),Path('//var/lib/pacman'),policy,O)
 def test_target_identity_survives_own_db_lock_creation(self):
  before=P.validate_target(self.root,self.db,self.policy,O);(self.db/'db.lck').write_text('own fixture lock');after=P.validate_target(self.root,self.db,self.policy,O);self.assertEqual(before,after)
 def test_target_alias_and_writable_directory_refuse(self):
  alias=self.home/'alias';alias.symlink_to(self.root,target_is_directory=True);policy=dict(self.policy,root=str(alias),dbpath=str(alias/'var/lib/pacman'))
  with self.assertRaises(OSError):P.validate_target(alias,alias/'var/lib/pacman',policy,O)
  for mode in (0o777,0o755):
   self.root.chmod(mode)
   with self.assertRaises(O.Refused):P.validate_target(self.root,self.db,self.policy,O)
 def test_supported_versions_and_namespace_protection(self):
  P.validate_inventory(self.policy,{'test-base':{'version':'1-1'}},O)
  with self.assertRaises(O.Refused):P.validate_inventory(self.policy,{'test-base':{'version':'2-1'}},O)
  with self.assertRaises(O.Refused):P.validate_inventory(self.policy,{},O)
  self.assertTrue({'test-base','m1n1','pacman'}<=P.protect(self.policy,O))
  for name in ('linux-asahi-edge','asahi-firmware','mesa-git','linux-firmware-apple','u-boot-asahi','vulkan-asahi'):self.assertTrue(P.is_platform_name(name),name)
  self.assertFalse(P.is_platform_name('test-leaf'))
 def test_empty_effects_are_json_safe_and_stable(self):
  value=self.effect();self.assertEqual(value,self.effect());json.dumps(value);self.assertEqual(value['ldconfig']['mode'],'forbid')
 def test_unrelated_and_nonremoval_hooks_are_preserved(self):
  self.write('usr/share/libalpm/hooks/one.hook',hook(target='other'));self.write('usr/share/libalpm/hooks/two.hook',hook(target='*',operation='Install'));value=self.effect();self.assertEqual(len(value['hooks']),2)
 def test_matching_package_path_and_second_trigger_refuse(self):
  path=self.write('usr/share/libalpm/hooks/test.hook',hook())
  with self.assertRaisesRegex(O.Refused,'requires unsupported hook'):self.effect()
  path.write_text(hook('Path','usr/share/*'))
  with self.assertRaises(O.Refused):self.effect()
  path.write_text(hook(target='other').replace('[Action]','[Trigger]\nOperation = Remove\nType = Package\nTarget = test-*\n\n[Action]'))
  with self.assertRaises(O.Refused):self.effect()
 def test_negation_brackets_escapes_inline_comments_refuse(self):
  path=self.write('usr/share/libalpm/hooks/test.hook',hook())
  for target in ('!test-leaf','test-[ab]','test\\*','test-leaf # comment'):
   path.write_text(hook(target=target))
   with self.subTest(target=target),self.assertRaises(O.Refused):self.effect()
 def test_hook_symlink_dummy_and_duplicate_overrides_refuse(self):
  path=self.root/'usr/share/libalpm/hooks/test.hook';path.parent.mkdir(parents=True);path.symlink_to('/dev/null')
  with self.assertRaises(OSError):self.effect()
  path.unlink();path.write_text('# disabled dummy hook\n')
  with self.assertRaises(O.Refused):self.effect()
  path.write_text(hook(target='other'));self.write('etc/pacman.d/hooks/test.hook',hook(target='other'))
  with self.assertRaisesRegex(O.Refused,'duplicate'):self.effect()
 def test_custom_or_indirect_hook_configuration_refuses(self):
  p=self.write('etc/pacman.conf','[options]\nHookDir = /unreviewed/hooks\n')
  with self.assertRaises(O.Refused):self.effect()
  p.write_text('[options]\nInclude = /unreviewed/options\n')
  with self.assertRaises(O.Refused):self.effect()
  self.write('etc/pacman.d/mirrorlist','Server = https://invalid.example/$repo/os/$arch\n')
  p.write_text('[options]\n# HookDir = /commented\n[core]\nInclude = /etc/pacman.d/mirrorlist\n');self.assertEqual(self.effect()['pacman_configuration']['kind'],'file')
 def test_frontend_hold_and_ignore_patterns_are_enforced_and_recorded(self):
  p=self.write('etc/pacman.conf','[options]\nHoldPkg = pacman glibc\nIgnorePkg = test-other*\nHoldPkg = unrelated\n')
  snapshot=self.effect()['frontend_protection'];self.assertEqual(snapshot['HoldPkg'],['glibc','pacman','unrelated']);self.assertEqual(snapshot['IgnorePkg'],['test-other*'])
  for key in ('HoldPkg','IgnorePkg'):
   p.write_text('[options]\n'+key+' = test-*\n')
   with self.subTest(key=key),self.assertRaisesRegex(O.Refused,key):self.effect()
 def test_ambiguous_frontend_patterns_and_uninspected_groups_refuse(self):
  p=self.write('etc/pacman.conf','[options]\n')
  for option in ('HoldPkg = !test-leaf','IgnorePkg = test-[ab]','HoldPkg = "test-leaf"','IgnoreGroup = unreviewed-group','HoldPkg'):
   p.write_text('[options]\n'+option+'\n')
   with self.subTest(option=option),self.assertRaises(O.Refused):self.effect()
  p.write_text('[options]\nHoldPkg =\nIgnorePkg =\nIgnoreGroup =\n');self.assertEqual(self.effect()['frontend_protection'],dict(HoldPkg=[],IgnorePkg=[]))
 def test_repository_includes_pin_plain_mirrors_and_refuse_indirect_options(self):
  self.write('etc/pacman.conf','[options]\n[core]\nInclude = /etc/pacman.d/mirrorlist\n');p=self.write('etc/pacman.d/mirrorlist','Server = https://invalid.example/$repo/os/$arch\n')
  before=self.effect();self.assertIn('etc/pacman.d/mirrorlist',before['repository_include_inputs']);p.write_text('Server = https://changed.invalid/$repo/os/$arch\n');self.assertNotEqual(before,self.effect())
  for content in ('[options]\nHoldPkg = test-leaf\n','Include = /unreviewed/file\n'):
   p.write_text(content)
   with self.subTest(content=content),self.assertRaisesRegex(O.Refused,'indirect frontend'):self.effect()
 def test_helper_forbid_never_waives_existing_helper(self):
  self.write('usr/bin/ldconfig','INERT FIXTURE',0o755)
  with self.assertRaisesRegex(O.Refused,'separately reviewed'):self.effect()
 def test_reviewed_helper_binds_binary_config_runtime_and_effects(self):
  self.reviewed();value=self.effect();effect=value['ldconfig'];self.assertEqual(effect['mode'],'reviewed');self.assertEqual(effect['runtime']['sha256'],self.policy['ldconfig']['libalpm_sha256']);self.assertEqual(len(effect['authorized_effects']),3)
  self.assertEqual((self.root/'usr/bin/ldconfig').read_text(),'INERT FIXTURE; NEVER EXECUTE\n')
 def test_reviewed_binary_config_and_runtime_tamper_refuse(self):
  self.reviewed()
  for key in ('executable_sha256','config_sha256','libalpm_sha256'):
   old=self.policy['ldconfig'][key];self.policy['ldconfig'][key]='0'*64
   with self.subTest(key=key),self.assertRaises(O.Refused):self.effect()
   self.policy['ldconfig'][key]=old
 def test_included_helper_configuration_is_pinned_and_unbounded_include_refuses(self):
  self.reviewed();p=self.write('etc/ld.so.conf.d/test.conf','/usr/lib\n');before=self.effect();p.write_text('/usr/lib64\n');self.assertNotEqual(before,self.effect())
  p.write_text('include /unreviewed/location/*.conf\n')
  with self.assertRaisesRegex(O.Refused,'unreviewed indirect'):self.effect()
 def test_changed_hook_and_effect_file_identity_changes_snapshot(self):
  path=self.write('usr/share/libalpm/hooks/test.hook',hook(target='other'));before=self.effect();path.write_text(hook(target='unrelated'));self.assertNotEqual(before,self.effect())
 def test_effects_refuse_alias_unsafe_inputs_and_count_overflow(self):
  for name in ('../outside','/absolute','usr/../etc/file','usr//bad'):
   with self.subTest(name=name),self.assertRaises(O.Refused):self.effect(files=[name])
  self.write('usr/share/libalpm/hooks/one.hook',hook(target='other'));self.write('usr/share/libalpm/hooks/two.hook',hook(target='other'))
  with patch.object(P,'MAX_HOOKS',1),self.assertRaises(O.Refused):self.effect()

if __name__=='__main__':unittest.main()
