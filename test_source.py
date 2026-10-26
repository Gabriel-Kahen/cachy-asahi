#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite emitted source checks only: no native, VM, package or actual replay."""
import ast,json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import custody as Q,kernel_data

class SourceControls(unittest.TestCase):
 def test_complete_child_and_parent360(self):
  fact=Q.verify();self.assertEqual(fact['status'],'SOURCE_ONLY_COMPLETE_PARENT360_INVERSE')
 def test_complete_owner_inverse_and_clocks(self):
  import selected
  raw=Q.read(Q.ROOT/'emissions/owner16k.py').decode()
  for before,after in reversed(selected.OWNER_EDITS):
   self.assertEqual(raw.count(after),1);raw=raw.replace(after,before,1)
  self.assertEqual(Q.pin(raw.encode()),Q.profile()['owner_parent_inverse']['before'])
  self.assertEqual(Q.profile()['clocks'],json.loads(Q.read(Q.ROOT/'parent360/implementation/profile.json'))['clocks'])
 def test_all_three_case_code_policy_and_installer_inverses(self):
  import selected
  p=Q.profile()
  for case,rows in p['emitted_cases'].items():
   root=Q.ROOT/'emissions/cases'/case;self.assertEqual(Q.rows(root),rows)
   config=json.loads(Q.read(root/'upgrade-config.json'));receipt=json.loads(Q.read(root/'adapter.json'))['explicit_generic16k'];before=json.loads(receipt['original_config'])
   restored=json.loads(json.dumps(config));restored['code_pins']=before['code_pins'];self.assertEqual(restored,before)
   for name,proof in receipt['ledger'].items():
    raw=Q.read(root/name).decode()
    for old,new in reversed(proof['edits']):self.assertEqual(raw.count(new),1);raw=raw.replace(new,old,1)
    self.assertEqual(Q.pin(raw.encode()),proof['before']);self.assertEqual(config['code_pins'][name],proof['after']['sha256'])
   self.assertEqual(receipt['kernel_input'],p['kernel_descriptor']);self.assertEqual(receipt['clocks'],'UNCHANGED')
 def test_whole_vm_transport_inverses(self):
  for name,row in Q.profile()['vm_derivation'].items():
   raw=Q.read(Q.ROOT/'vm'/name).decode()
   for old,new in reversed(row['edits']):self.assertEqual(raw.count(new),1);raw=raw.replace(new,old,1)
   self.assertEqual(Q.pin(raw.encode()),row['before'])
 def test_kernel_data_cannot_grant_boot_and_actual_page_is_independent(self):
  descriptor=kernel_data.profile(Q.profile()['kernel_descriptor']);self.assertEqual(descriptor['boot'],'NOT_RUN')
  facts=dict(sysname='Linux',architecture='aarch64',page_size=16384,kernel=kernel_data.RELEASE)
  self.assertEqual(kernel_data.actual(facts,descriptor),facts)
  for field,value in [('page_size',4096),('page_size',True),('architecture','x86_64'),('kernel','foreign')]:
   with self.assertRaises(ValueError):kernel_data.actual(dict(facts,**{field:value}),descriptor)
 def test_no_actual_or_authority_projection_from4k(self):
  p=Q.profile();self.assertTrue(all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')))
  self.assertEqual(p['fresh_materializer_source'],'b9976eea34eaed4b6e56af3be21d4d652fa971d6')
  self.assertEqual(p['dependencies']['fresh16k']['source'],'0db9341521b5cb5d9022715b5ba638b3e4018462')

if __name__=='__main__':unittest.main()
