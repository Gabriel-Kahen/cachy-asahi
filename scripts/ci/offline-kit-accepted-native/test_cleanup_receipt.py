#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual Docker inspection DATA controls; no Docker or other child actors."""
import ast,copy,hashlib,json,socket,subprocess,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
OWNER=HERE/'owner.py'
if not OWNER.is_file():OWNER=HERE/'source/scripts/ci/offline-kit-accepted-native/owner.py'
PINS={'receive-created-inspection.json':'6e199ce206038571a32bc480b11a39a62f1d7adbe85cae3730912360561c3aa1',
      'cleanup-current-inspection.json':'b66e80d02ed953d9933ba2fd18144f07b0167aab44bc9627eb1549b5d03bd92c'}
node=next(n for n in ast.parse(OWNER.read_bytes()).body if isinstance(n,ast.FunctionDef)and n.name=='same_consumer_inspection')
ns={'json':json};exec(compile(ast.Module(body=[node],type_ignores=[]),'trusted-cleanup-receipt-helper','exec'),ns)
same=ns['same_consumer_inspection']
class CleanupReceiptControls(unittest.TestCase):
 def setUp(self):
  values={}
  for name,pin in PINS.items():
   raw=(HERE/'fixtures'/name).read_bytes();self.assertEqual(hashlib.sha256(raw).hexdigest(),pin);values[name]=json.loads(raw)
  self.before=values['receive-created-inspection.json'];rows=values['cleanup-current-inspection.json'];self.assertEqual(len(rows),1);self.after=rows[0]
  for obj,name in ((subprocess,'Popen'),(socket,'socket')):
   guard=patch.object(obj,name,side_effect=AssertionError('NO_CHILD_OR_NETWORK_ACTOR'));guard.start();self.addCleanup(guard.stop)
 def test_actual_pair_reproduces_old_refusal_and_new_narrow_match(self):
  self.assertEqual(self.before['Id'],self.after['Id']);self.assertEqual(self.before['Config'],self.after['Config'])
  changes={k:(self.before['HostConfig'].get(k),self.after['HostConfig'].get(k))for k in set(self.before['HostConfig'])|set(self.after['HostConfig'])if self.before['HostConfig'].get(k)!=self.after['HostConfig'].get(k)}
  self.assertEqual(changes,{'OomKillDisable':(False,None)})
  self.assertFalse(self.before['Config']==self.after['Config']and self.before['HostConfig']==self.after['HostConfig'])
  self.assertTrue(same(self.before,self.after));self.assertEqual(self.after['State']['ExitCode'],1)
 def test_normalization_is_nonmutating(self):
  before,after=copy.deepcopy(self.before),copy.deepcopy(self.after)
  self.assertTrue(same(before,after));self.assertEqual(before,self.before);self.assertEqual(after,self.after)
 def test_exact_false_default_matches(self):self.assertTrue(same(self.before,self.before))
 def test_exact_null_default_matches(self):self.assertTrue(same(self.after,self.after))
 def test_reverse_null_false_representation_matches(self):self.assertTrue(same(self.after,self.before))
 def test_only_explicit_false_or_null_allowed(self):
  for key in (True,0,1,'false','',[],{}):
   for side in ('before','after'):
    a,b=copy.deepcopy(self.before),copy.deepcopy(self.after);(a if side=='before'else b)['HostConfig']['OomKillDisable']=key
    with self.subTest(value=repr(key),side=side):self.assertFalse(same(a,b))
 def test_missing_oom_field_is_not_a_default(self):
  for side in ('before','after'):
   a,b=copy.deepcopy(self.before),copy.deepcopy(self.after);del(a if side=='before'else b)['HostConfig']['OomKillDisable']
   with self.subTest(side=side):self.assertFalse(same(a,b))
 def test_identity_name_and_image_cannot_change(self):
  for key in ('Id','Name','Image'):
   after=copy.deepcopy(self.after);after[key]='unrelated'
   with self.subTest(key=key):self.assertFalse(same(self.before,after))
 def test_identity_fields_must_exist(self):
  for key in ('Id','Name','Image'):
   a,b=copy.deepcopy(self.before),copy.deepcopy(self.after);del a[key];del b[key]
   with self.subTest(key=key):self.assertFalse(same(a,b))
 def test_full_config_stays_exact(self):
  mutations={'User':'0:0','Env':[],'Labels':{},'Cmd':['changed'],'Entrypoint':['changed'],'Image':'changed'}
  for key,value in mutations.items():
   after=copy.deepcopy(self.after);after['Config'][key]=value
   with self.subTest(key=key):self.assertFalse(same(self.before,after))
 def test_host_security_and_resource_gates_stay_exact(self):
  mutations={'NetworkMode':'bridge','ReadonlyRootfs':False,'Privileged':True,'AutoRemove':True,
   'CapDrop':[],'CapAdd':['SYS_ADMIN'],'SecurityOpt':[],'PidsLimit':129,'Memory':536870912,
   'NanoCpus':1000000000,'Devices':[{'PathOnHost':'/dev/null'}],'DeviceRequests':[{}],'VolumesFrom':['foreign'],'Tmpfs':{}}
  for key,value in mutations.items():
   after=copy.deepcopy(self.after);after['HostConfig'][key]=value
   with self.subTest(key=key):self.assertFalse(same(self.before,after))
 def test_full_mount_source_and_permissions_stay_exact(self):
  for key,value in (('Source','/foreign'),('Target','/foreign'),('ReadOnly',False)):
   after=copy.deepcopy(self.after);after['HostConfig']['Mounts'][0][key]=value
   with self.subTest(key=key):self.assertFalse(same(self.before,after))
 def test_unknown_keys_cannot_be_dropped_from_comparison(self):
  for group in ('Config','HostConfig'):
   for side in ('before','after'):
    a,b=copy.deepcopy(self.before),copy.deepcopy(self.after);(a if side=='before'else b)[group]['unreviewed-extra']=True
    with self.subTest(group=group,side=side):self.assertFalse(same(a,b))
 def test_other_boolean_number_type_changes_refuse(self):
  after=copy.deepcopy(self.after);after['HostConfig']['Privileged']=0
  self.assertFalse(same(self.before,after))
 def test_bad_structures_fail_closed(self):
  for value in (None,[],0,'row'):
   self.assertFalse(same(value,self.after));self.assertFalse(same(self.before,value))
  for group in ('Config','HostConfig'):
   for value in (None,[],0):
    after=copy.deepcopy(self.after);after[group]=value
    with self.subTest(group=group,value=value):self.assertFalse(same(self.before,after))
 def test_cleanup_still_requires_unique_receipt_before_removal(self):
  tree=ast.parse(OWNER.read_bytes());cleanup=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='cleanup');text=ast.unparse(cleanup)
  self.assertIn('len(matches) == 1 and same_consumer_inspection(matches[0], row)',text)
  self.assertLess(text.index('same_consumer_inspection'),text.index("actor.docker('rm', '-f', cid)"))
  self.assertLess(text.index('all kit consumers absent before574 image retirement'),text.index("'cleanup', '--inputs'"))
if __name__=='__main__':unittest.main(verbosity=2)
