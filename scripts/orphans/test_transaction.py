#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Adapter controls; real signed ALPM execution is a separately labelled harness."""
import hashlib,importlib.util,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
sys.dont_write_bytecode=True
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'manifests/packages.toml').is_file())
spec=importlib.util.spec_from_file_location('orphans_transaction',Path(__file__).with_name('transaction.py'))
W=importlib.util.module_from_spec(spec);sys.modules[spec.name]=W;spec.loader.exec_module(W)
sha=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest()
BACKEND=ROOT/'scripts/apps/transaction.py';ORPHANS=ROOT/'packages/tools/cachy-asahi-orphans'

class Guards(unittest.TestCase):
 def test_exact_backend_pin_loads_current_backend(self):
  T=W.load_backend(sha(BACKEND));self.assertEqual(Path(T.__file__),BACKEND)
 def test_bad_backend_pin_refuses(self):
  with self.assertRaises(ValueError):W.load_backend('0'*64)
 def test_exact_orphans_source_pin_loads_current_reader(self):
  O=W.load_orphans(ORPHANS,sha(ORPHANS/'cachy-asahi-orphans'))
  self.assertEqual(O.floor(),set(O.floor()));self.assertFalse(hasattr(O.Installed,'commit'))
 def test_bad_orphans_pin_refuses(self):
  with self.assertRaises(ValueError):W.load_orphans(ORPHANS,'0'*64)
 def test_changed_private_orphans_source_refuses(self):
  with tempfile.TemporaryDirectory() as temp:
   directory=Path(temp)
   for name in ('cachy-asahi-orphans','protection-floor.json'):(directory/name).write_bytes((ORPHANS/name).read_bytes())
   expected=sha(directory/'cachy-asahi-orphans')
   with (directory/'cachy-asahi-orphans').open('ab') as stream:stream.write(b'\n# changed source\n')
   with self.assertRaises(ValueError):W.load_orphans(directory,expected)
 def test_missing_orphan_confirmation_never_delegates(self):
  with patch.object(W,'load_backend',side_effect=AssertionError('backend loaded without confirmation')):
   value=W.apply(SimpleNamespace(confirm_orphan_removal=False))
  self.assertEqual(value['status'],'FAIL');self.assertIs(value['commit_started'],False);self.assertIs(value['packages_committed'],False)
 def test_host_scope_refusal_is_not_a_commit(self):
  a=SimpleNamespace(confirm_orphan_removal=True,confirm_disposable_transaction=True,apps_backend_sha256=sha(BACKEND),orphans_source=str(ORPHANS),orphans_source_sha256=sha(ORPHANS/'cachy-asahi-orphans'),operation='remove',selected_names=['fixture'])
  value=W.apply(a)
  self.assertEqual(value['status'],'FAIL');self.assertIs(value['commit_started'],False);self.assertIs(value['packages_committed'],False)
 def test_changed_protection_floor_refuses(self):
  with tempfile.TemporaryDirectory() as temp:
   directory=Path(temp)
   for name in ('cachy-asahi-orphans','protection-floor.json'):(directory/name).write_bytes((ORPHANS/name).read_bytes())
   O=W.load_orphans(directory,sha(directory/'cachy-asahi-orphans'))
   (directory/'protection-floor.json').write_bytes(b'{}\n')
   with self.assertRaisesRegex(ValueError,'protection floor'):O.floor()
 def test_full574_policy_and_lease_flags_are_preserved(self):
  names=('workspace','ownership-sha256','apps-source','apps-provenance-sha256','repository-source','apps-backend-sha256','orphans-source','orphans-source-sha256','orphan-plan','orphan-plan-sha256','release','release-sha256','catalog','catalog-sha256','catalog-signature','keyring','signer','plan','plan-sha256','before-tree-sha256','before-database-sha256','before-packages-sha256','before-inventory-sha256','full574-policy','full574-policy-sha256','full574-lease','full574-lease-sha256')
  argv=['apply']
  for name in names:argv+=['--'+name,'exact-'+name]
  a=W.arguments(argv+['--applications','signed-fixture','--selected-names','fixture','--confirm-orphan-removal','--confirm-disposable-transaction'])
  for name in ('full574_policy','full574_policy_sha256','full574_lease','full574_lease_sha256'):
   self.assertEqual(getattr(a,name),'exact-'+name.replace('_','-'))
  self.assertEqual(a.operation,'remove')
 def test_uncertain_delegation_is_unknown_and_never_retried(self):
  backend=SimpleNamespace(root_guard=Mock(),apply=Mock(side_effect=RuntimeError('interrupted delegated call')))
  a=SimpleNamespace(confirm_orphan_removal=True,confirm_disposable_transaction=True,apps_backend_sha256='a'*64,orphans_source=str(ORPHANS),orphans_source_sha256='b'*64)
  with patch.object(W,'load_backend',return_value=backend),patch.object(W,'load_orphans',return_value=object()),patch.object(W,'preflight',return_value=dict(selected={'fixture':'1-1'})):
   result=W.apply(a)
  self.assertEqual(result['status'],'FAIL');self.assertEqual(result['commit_started'],'UNKNOWN');self.assertEqual(result['packages_committed'],'UNKNOWN');backend.apply.assert_called_once_with(a)

if __name__=='__main__':unittest.main(verbosity=2)
