# SPDX-License-Identifier: MIT
import copy,json,os,socket,subprocess,tempfile,unittest
from datetime import datetime,timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import security_advisories as M
HERE=Path(__file__).resolve().parent
NOW=datetime(2026,10,19,20,tzinfo=timezone.utc)

def group(name='AVG-1',package='demo',fixed='2.0-2',affected='2.0-1'):
 return dict(name=name,packages=[package],status='Fixed',severity='High',type='arbitrary code execution',affected=affected,fixed=fixed,ticket=None,issues=['CVE-2026-12345'],advisories=['ASA-202610-1'])
def item(version='2.0-1',**kw):return dict(name='demo',version=version,arch='aarch64',**kw)
def meta(raw,stamp='2026-10-19T19:00:00Z'):return dict(url=M.URL,retrieved_at=stamp,**M.pin(raw))
def report(items=None,groups=None):return M.report([item()]if items is None else items,[group()]if groups is None else groups,{},'2026-10-19T20:00:00Z')
class Controls(unittest.TestCase):
 def test_actual_arch_epoch_pkgrel_and_prerelease_order(self):
  self.assertGreater(M.compare('1:1.0-1','2.0-9'),0);self.assertLess(M.compare('2.0-1','2.0-2'),0);self.assertLess(M.compare('1.0rc1-1','1.0-1'),0);self.assertEqual(M.compare('2.0-2','2.0-2'),0)
 def test_concrete_review_cves_versions_and_arm_unknown(self):
  v=report();r=v['packages'][0];f=r['findings'][0];self.assertEqual(r['status'],'REVIEW_REQUIRED');self.assertEqual(f['version_relation'],'BELOW_ARCH_FIXED_REFERENCE');self.assertEqual(f['issues'],['CVE-2026-12345']);self.assertEqual(f['arch_fixed_version'],'2.0-2');self.assertEqual(f['arm_fixed_version'],'UNKNOWN');self.assertIn('authenticated ARM package',f['action']);self.assertEqual(v['arm_security_status'],'UNKNOWN')
 def test_met_arch_reference_never_claims_arm_mitigation(self):
  v=report([item('1:1.0-1',origin='explicit selected ARM snapshot')]);r=v['packages'][0];self.assertEqual(r['status'],'ARCH_REFERENCES_MET_ARM_UNVERIFIED');self.assertEqual(r['arm_security_status'],'UNKNOWN');self.assertEqual(r['origin'],'explicit selected ARM snapshot');self.assertNotIn('unaffected',r['status'].lower())
 def test_source_pkgbase_virtual_provides_and_case_are_not_aliases(self):
  v=report([dict(name='renamed-demo',version='2.0-1',arch='any',pkgbase='demo',provides=['demo']),dict(name='Demo',version='2.0-1',arch='aarch64')]);self.assertTrue(all(r['status']=='UNKNOWN_NO_TRACKER_MATCH'and r['findings']==[]for r in v['packages']))
 def test_missing_fix_unknown_status_and_duplicate_asa_preserved(self):
  g=group(fixed=None);g['status']='Unknown';g['severity']='Unknown';g['advisories']*=2;v=report(groups=[g]);f=v['packages'][0]['findings'][0];self.assertEqual(f['arch_status'],'Unknown');self.assertEqual(f['advisories'],g['advisories']);self.assertEqual(f['version_relation'],'UNKNOWN_NO_ARCH_FIXED_VERSION')
 def test_incomplete_pkgrel_never_uses_vercmp_equality_as_fix(self):
  with patch.object(M,'compare',side_effect=AssertionError('no incomplete tuple ordering')):v=report([item('2.0')])
  self.assertEqual(v['packages'][0]['findings'][0]['version_relation'],'UNKNOWN_INCOMPLETE_PACKAGE_VERSION')
 def test_fresh_stale_future_wrong_hash_and_wrong_url(self):
  raw=M.encoded([group()]);m=meta(raw);v=M.provenance(m,raw,NOW,24);self.assertFalse(v['cache_stale']);self.assertEqual(v['tracker_completeness'],'UNKNOWN');self.assertTrue(M.provenance(meta(raw,'2026-10-01T00:00:00Z'),raw,NOW,24)['cache_stale'])
  for wrong in(meta(raw,'2026-10-20T00:00:00Z'),dict(m,sha256='a'*64),dict(m,url='https://example.invalid/all.json')):
   with self.assertRaises(M.Error):M.provenance(wrong,raw,NOW,24)
 def test_invalid_json_inventory_and_feed_refuse(self):
  for raw in(b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":1.2}',b'X'*(M.CAP+1)):
   with self.assertRaises(ValueError):M.decode(raw)
  for inv in([], [item(),item()], [dict(item(),arch='x86_64')],[dict(item(),version='--help')]):
   with self.assertRaises(M.Error):M.inventory(inv)
  for data in([], [group(),group()],[dict(group(),packages=['demo','demo'])],[dict(group(),issues=['not-a-CVE'])],[dict(group(),fixed='2.0;command')]):
   with self.assertRaises(M.Error):M.advisories(data)
 def test_missing_vercmp_and_bad_result_have_no_sorting_fallback(self):
  with patch.object(M.subprocess,'run',side_effect=FileNotFoundError),self.assertRaisesRegex(M.Error,'no replacement'):M.compare('1-1','2-1')
  with patch.object(M.subprocess,'run',return_value=SimpleNamespace(stdout='help')),self.assertRaises(M.Error):M.compare('1-1','2-1')
 def test_cli_offline_preserves_original_inputs_and_never_overwrites(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);raws={'inventory.json':M.encoded([item()]),'advisories.json':M.encoded([group()])};raws['provenance.json']=M.encoded(meta(raws['advisories.json']))
   for name,raw in raws.items():(root/name).write_bytes(raw)
   argv=['--inventory',str(root/'inventory.json'),'--advisories',str(root/'advisories.json'),'--provenance',str(root/'provenance.json'),'--output',str(root/'report'),'--as-of','2026-10-19T20:00:00Z'];original_run=subprocess.run;calls=[]
   def comparator(args,**kw):self.assertEqual(args[0],'/usr/bin/vercmp');self.assertEqual(len(args),3);self.assertNotIn('shell',kw);calls.append(args);return original_run(args,**kw)
   with patch.object(socket,'create_connection',side_effect=AssertionError('no network')),patch.object(M.subprocess,'run',side_effect=comparator):self.assertEqual(M.main(argv),0)
   self.assertTrue(calls)
   for name,raw in raws.items():self.assertEqual((root/name).read_bytes(),raw);self.assertEqual((root/'report'/name).read_bytes(),raw)
   result=json.loads((root/'report/report.json').read_bytes());self.assertEqual(result['inputs'],{n:M.pin(r)for n,r in raws.items()});self.assertIn('CVE-2026-12345',(root/'report/report.txt').read_text());before=(root/'report/report.json').read_bytes();self.assertEqual(M.main(argv),2);self.assertEqual((root/'report/report.json').read_bytes(),before)
 def test_bad_inputs_and_unsafe_paths_fail_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);p=root/'input';p.symlink_to(root/'absent')
   with self.assertRaises(M.Error):M.read(p)
   p.unlink();os.mkfifo(p)
   with self.assertRaises(M.Error):M.read(p)
   p.unlink();p.write_bytes(b'{}');os.link(p,root/'alias')
   with self.assertRaises(M.Error):M.read(p)
if __name__=='__main__':unittest.main()
