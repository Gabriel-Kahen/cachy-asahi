#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure gates: no containers, signing, install or real removal."""
import copy,hashlib,importlib.util,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import contract as C
spec=importlib.util.spec_from_file_location('orphans3_producer_controls',HERE/'producer.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class Gates(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def test_pair_requires_four_equalities_and_no_errors(self):
  good=dict(status='contents-reproduced',errors=[],packages={'candidate':dict(installed_contents_equal=True,pkginfo_equal=True,bytes_equal=True,buildinfo_equal=True)});C.pair_gate(good)
  for key in good['packages']['candidate']:
   bad=copy.deepcopy(good);bad['packages']['candidate'][key]=False
   with self.subTest(key=key),self.assertRaises(ValueError):C.pair_gate(bad)
  bad=copy.deepcopy(good);bad['errors']=['not independent']
  with self.assertRaises(ValueError):C.pair_gate(bad)
 def test_log_requires_exact53_without_skips(self):
  p=self.root/'log';good='==> Starting check()\nRan 20 tests in 0.2s\nOK\nRan 25 tests in 2.1s\nOK\nRan 8 tests in 2.0s\nOK\n';p.write_text(good);self.assertEqual(C.check_log(p,C.PRODUCT)['count'],53)
  for text in (good.replace('25','24'),good.replace('Ran 8 tests in 2.0s\nOK\n',''),good.replace('20','18'),good+'OK (skipped=1)\n',good+'FAILED\n',good.replace('OK\n','',1),good.replace('Starting check()','old')):
   p.write_text(text)
   with self.assertRaises(ValueError):C.check_log(p,C.PRODUCT)
 def test_no_download_refuses_missing_and_race_fallback(self):
  item={'target':self.root/'input'};original=Mock()
  with self.assertRaisesRegex(ValueError,'downloads forbidden'):P.fetch_existing(original,item)
  original.assert_not_called();item['target'].write_bytes(b'x')
  def attempt(item,opener):return opener('https://not-allowed.invalid')
  with self.assertRaisesRegex(ValueError,'network acquisition forbidden'):P.fetch_existing(attempt,item)
 def test_inventory_records_exact_missing_type_and_hash(self):
  context=self.root/'retained';context.mkdir();(context/'good').write_bytes(b'a');(context/'bad').write_bytes(b'b');(context/'link').symlink_to(context/'good')
  def item(n,raw):return dict(target=context/n,size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
  items=[item('good',b'a'),item('bad',b'a'),item('missing',b'a'),item('link',b'a')]
  class M:
   @staticmethod
   def plan(inputs,context):return items
  with patch.object(C,'load',return_value=M),patch.object(C,'read',return_value={}):_,rows,problems=P.inventory(self.root,context)
  self.assertEqual(rows,items);self.assertEqual({r['path']:r['reason'] for r in problems},{'bad':'SHA256','missing':'MISSING_OR_UNSAFE','link':'MISSING_OR_UNSAFE'})
 def test_result_requires_real_backend_and_scope(self):
  # Full actor result is checked separately; false real-backend cannot pass.
  for value in ({},dict(status='MODEL_PASS',real_backend=True,hardware='NOT_RUN'),dict(status='PASS_ORPHANS3_REAL_NATIVE_OFFLINE_REMOVAL',real_backend=False,hardware='NOT_RUN')):
   with self.assertRaises(ValueError):C.validate_lifecycle(value)
 def test_source_refuses_hardlinked_input(self):
  p=self.root/'source';p.write_bytes(b'data');row=dict(bytes=4,sha256=hashlib.sha256(b'data').hexdigest());C.checked(self.root,'source',row);(self.root/'alias').hardlink_to(p)
  with self.assertRaises(ValueError):C.checked(self.root,'source',row)
 def test_duplicate_and_nonfinite_json_refused(self):
  p=self.root/'bad'
  for text in ('{"x":1,"x":2}','{"x":NaN}'):
   p.write_text(text)
   with self.assertRaises(ValueError):C.read(p)
 def test_complete_result_gate_rejects_unknown_commit_or_cleanup(self):
  before={n:'1-1' for n in C.FIXTURES};after={n:v for n,v in before.items() if n!='caa-orphans3-leaf-a'}
  cases=('different-selection','duplicate-selection','same-bytes-assessment','foreign-lock','positive','stale-after-removal','helper-alias','unsafe-payload')
  positive=dict(status='APPLIED',commit_started=True,packages_committed=True,prepared_add={},prepared_remove={'caa-orphans3-leaf-a':'1-1'},transaction_released=True,handle_released=True,lock_state='ABSENT',cleanup_errors=[],worker=dict(reaped=True,exitcode=0))
  events=[dict(case=n,result=positive if n=='positive' else dict(status='REFUSED',commit_started=False,packages_committed=False),durable_result='reports/positive/result.json' if n=='positive' else None) for n in cases]
  good=dict(status='PASS_ORPHANS3_REAL_NATIVE_OFFLINE_REMOVAL',real_backend=True,version='0.2.0-1',architecture='aarch64',page_size=4096,hardware='NOT_RUN',before_count=8,after_count=7,before=before,after=after,base574_preserved=True,final_lock='ABSENT',events=events,commands=[dict(exitcode=0,expected_exit=0,stdout='',stderr='')],cleanup=dict(outer_candidate='REMOVED',foreign_lock='RELEASED_BY_OWN_HANDLE',TEST_agents='STOPPED',outer_container='PARENT_MUST_VERIFY_ABSENCE_AFTER_ACTOR_EXIT'))
  C.validate_lifecycle(good)
  for field,value in (('packages_committed','UNKNOWN'),('handle_released',False),('prepared_remove',{})):
   bad=copy.deepcopy(good);bad['events'][4]['result'][field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):C.validate_lifecycle(bad)
  bad=copy.deepcopy(good);bad['events'].pop()
  with self.assertRaises(ValueError):C.validate_lifecycle(bad)
  bad=copy.deepcopy(good);bad['cleanup']['outer_candidate']='INSTALLED'
  with self.assertRaises(ValueError):C.validate_lifecycle(bad)
if __name__=='__main__':unittest.main()
