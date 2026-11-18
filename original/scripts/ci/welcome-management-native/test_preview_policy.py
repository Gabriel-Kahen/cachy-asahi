# SPDX-License-Identifier: MIT
"""Finite per-tool complete preview guards; no native or GUI actors."""
import base64,importlib.util,json,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('preview_contract',HERE/'management_contract.py');C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
UI=dict(labels=dict(management='Management',doctor='Run Doctor',orphans='Assess orphan packages'),strings=dict(running='Running',complete='Complete',failure='Failed',unavailable='Unavailable'),raw_preview_suffix='\n[Raw preview truncated at 64 KiB.]',max_output_bytes=1048576,orphan_preview_bytes=8192,orphan_preview_suffix='\n[Raw preview truncated at 8 KiB.]')
def snapshot(text,pid=91):
 rows=[]
 for value in ('Complete','summary',text):
  raw=value.encode();rows.append(dict(name_base64='',role=61,showing=True,selected=False,checked=False,enabled=True,sensitive=True,body_base64=base64.b64encode(raw).decode(),text_sha256=C.sha(raw),text_bytes=len(raw)))
 return dict(status='PASS',pid=pid,nodes=rows)
class Preview(unittest.TestCase):
 def test_full_validation_includes_candidate_after_visible_prefix(self):
  value=dict(schema_version=1,scope=C.SCOPE,apply_supported=False,root='/',dbpath='/var/lib/pacman',padding='x'*9000,packages={'after-preview':dict(version='1',candidate=True)},candidates=['after-preview'],broken_dependencies=[])
  raw=json.dumps(value).encode();self.assertGreater(raw.index(b'after-preview'),8192)
  _,summary=C.report(raw,'orphans',{'after-preview':'1'});self.assertIn('1 possible orphan',summary)
  shown=C.preview(raw,UI,'orphans');self.assertEqual(shown,raw[:8192].decode()+UI['orphan_preview_suffix']);self.assertLess(len(shown.encode()),8300)
  value['candidates']=[]
  with self.assertRaises(ValueError):C.report(json.dumps(value).encode(),'orphans',{'after-preview':'1'})
 def test_entire_preview_not_just_subset_or_notice(self):
  shown=C.preview(b'x'*9000,UI,'orphans');expected=dict(text=['Complete','summary',shown],buttons={})
  C.snapshot(snapshot(shown),91,'management-orphans',expected)
  for bad in (shown[:-1],shown+'extra',shown[1:],'x'*8192):
   with self.subTest(change=len(bad)),self.assertRaisesRegex(ValueError,'raw preview|not showing'):C.snapshot(snapshot(bad),91,'management-orphans',expected)
  with self.assertRaises(ValueError):C.snapshot(snapshot(shown,pid=92),91,'management-orphans',expected)
 def test_doctor_keeps64k_and_orphan_failure_uses8k(self):
  raw=b'x'*70000
  self.assertEqual(C.preview(raw,UI,'doctor'),'x'*65536+UI['raw_preview_suffix'])
  for kind in ('orphans','failure'):self.assertEqual(C.preview(raw,UI,kind),'x'*8192+UI['orphan_preview_suffix'])
 def test_explicit_bound_source_policy_refuses_missing_changed_limit_or_notice(self):
  C.interface(dict(ui=UI))
  for key,value in (('orphan_preview_bytes',4096),('orphan_preview_bytes',None),('orphan_preview_suffix','wrong')):
   altered=dict(UI);altered[key]=value
   with self.assertRaises(ValueError):C.interface(dict(ui=altered))
if __name__=='__main__':unittest.main(verbosity=2)
