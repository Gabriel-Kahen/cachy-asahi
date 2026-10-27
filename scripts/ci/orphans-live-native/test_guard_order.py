#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure UID/input guard controls. No ALPM, workers, sudo or host-root queries."""
import contextlib,importlib.util,io,json,os,stat,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent;SOURCE=HERE.parents[2]
spec=importlib.util.spec_from_file_location('guard_order_candidate',SOURCE/'packages/tools/cachy-asahi-orphans03/live.py');L=importlib.util.module_from_spec(spec);spec.loader.exec_module(L);O=L.O
class GuardOrder(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.path=self.root/'plan.json';self.path.write_text('{}\n');self.path.chmod(0o600)
  self.args=SimpleNamespace(select=['test-leaf'],authorize_live_removal=True,plan=self.path,plan_sha256='a'*64,target_root=Path('/'),target_dbpath=Path('/var/lib/pacman'),policy=self.root/'unused-policy',policy_sha256='b'*64)
 def call(self):
  factory=Mock(side_effect=AssertionError('transaction forbidden'));result=L.execute(self.args,lambda value:None,factory=factory);factory.assert_not_called();self.assertFalse(result['commit_started']);self.assertFalse(result['packages_committed']);return result
 def test_uid_matrix_root_refuses_before_any_input_or_plan_query(self):
  for uid in (1000,1001,65534):
   with self.subTest(uid=uid),patch.object(L.os,'geteuid',return_value=uid),patch.object(O,'json_file',side_effect=AssertionError('input forbidden')) as inputs,patch.object(L,'plan',side_effect=AssertionError('plan/ALPM forbidden')) as plan:
    value=self.call();self.assertEqual(value['status'],'REFUSED');self.assertEqual(value['error_type'],'Refused');self.assertIn('no auto-sudo',value['reason']);inputs.assert_not_called();plan.assert_not_called()
 def test_privileged_root_still_reaches_strict_input_guard(self):
  with patch.object(L.os,'geteuid',return_value=0),patch.object(O,'json_file',side_effect=O.Refused('strict input sentinel')) as inputs,patch.object(L,'plan',side_effect=AssertionError('no plan query')) as plan:
   value=self.call();self.assertEqual(value['reason'],'strict input sentinel');inputs.assert_called_once_with(self.path);plan.assert_not_called()
 def test_private_target_still_reaches_strict_input_guard(self):
  self.args.target_root=self.root;self.args.target_dbpath=self.root/'var/lib/pacman'
  with patch.object(L.os,'geteuid',return_value=1001),patch.object(O,'json_file',side_effect=O.Refused('private input sentinel')) as inputs:
   self.assertEqual(self.call()['reason'],'private input sentinel');inputs.assert_called_once_with(self.path)
 def test_real_hardlink_input_remains_refused(self):
  alias=self.root/'alias';os.link(self.path,alias);self.assertEqual(self.path.stat().st_nlink,2)
  with self.assertRaisesRegex(O.Refused,'ordinary bounded single-link'):O.json_file(self.path)
 def test_foreign_owner_with_one_link_refuses_before_reading_bytes(self):
  fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
  try:
   metadata=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_nlink=1,st_uid=1001,st_size=3)
   with patch.object(O.os,'fstat',return_value=metadata),patch.object(O.os,'geteuid',return_value=1000),patch.object(O.os,'read',side_effect=AssertionError('foreign bytes must not be read')) as read:
    with self.assertRaisesRegex(O.Refused,'ordinary bounded single-link'):O.read(fd,self.path.name,O.limits(),O.MAX_JSON,True)
    read.assert_not_called()
  finally:os.close(fd)
 def test_real_owned_single_link_private_input_remains_readable(self):
  value,record=O.json_file(self.path);self.assertEqual(value,{});self.assertEqual(record['uid'],os.geteuid());self.assertEqual(record['mode'],0o600);self.assertEqual(record['links'],1)
 def test_cli_unprivileged_root_creates_no_receipt_or_worker(self):
  output=io.StringIO();argv=['remove',str(self.path),'--target-root','/','--target-dbpath','/var/lib/pacman','--policy',str(self.args.policy),'--policy-sha256','b'*64,'--plan-sha256','a'*64,'--select','test-leaf','--authorize-live-removal','--result',str(self.root/'must-not-exist')]
  with patch.object(L.os,'geteuid',return_value=1001),patch.object(O,'json_file',side_effect=AssertionError('input forbidden')) as inputs,patch.object(L.R,'Receipt',side_effect=AssertionError('receipt forbidden')) as receipt,patch.object(L,'supervise',side_effect=AssertionError('worker forbidden')) as worker,contextlib.redirect_stdout(output):code=L.main(argv)
  self.assertEqual(code,1);self.assertIn('no auto-sudo',json.loads(output.getvalue())['reason']);inputs.assert_not_called();receipt.assert_not_called();worker.assert_not_called();self.assertFalse((self.root/'must-not-exist').exists())
 def test_explicit_authorization_still_precedes_input_read(self):
  self.args.authorize_live_removal=False
  with patch.object(L.os,'geteuid',return_value=1001),patch.object(O,'json_file',side_effect=AssertionError('input forbidden')) as inputs:
   self.assertIn('--authorize-live-removal',self.call()['reason']);inputs.assert_not_called()
if __name__=='__main__':unittest.main()
