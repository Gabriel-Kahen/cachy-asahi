# SPDX-License-Identifier: MIT
"""Actual frozen lock/archive selection and refusal checks; no mocked cache success."""
import ast,copy,hashlib,importlib.util,json,os,sys,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('PUBLIC_PAIR_UPDATER_SOURCE',HERE.parents[2]))
s=importlib.util.spec_from_file_location('apps_aux_selection',HERE/'aux_transition.py');H=importlib.util.module_from_spec(s);s.loader.exec_module(H)
def inventory_sha(rows):return hashlib.sha256(''.join(n+' '+v+'\n' for n,v in sorted(rows.items())).encode()).hexdigest()
class Controls(unittest.TestCase):
 def setUp(self):
  self.before=dict(line.split() for line in (HERE/'before604.lock').read_text().splitlines());self.after=dict(line.split() for line in (HERE/'after604.lock').read_text().splitlines());self.config=dict(before_lock_sha256=H.BEFORE,after_lock_sha256=H.AFTER);self.snapshot=dict(release=dict(packages=[dict(name='cachy-asahi-apps',version='0.1.0-6',sha256=H.ARCHIVE)]))
 def guard(self,before=None,desired=None,snapshot=None,config=None):return H.apps6_selection_guard(snapshot or self.snapshot,before or self.before,desired or {'cachy-asahi-apps':'0.1.0-6'},config or self.config,need=H.need,inventory_sha=inventory_sha)
 def test_exact_real604_locks_and_eight_product_paths(self):
  self.assertEqual(inventory_sha(self.before),H.BEFORE);self.assertEqual(inventory_sha(self.after),H.AFTER);self.assertEqual(len(self.before),604);self.assertEqual(self.after,self.before|{'cachy-asahi-apps':'0.1.0-6'});self.assertEqual(self.before['cachy-asahi-setup'],self.after['cachy-asahi-setup']);self.guard();self.assertEqual(set(json.loads((HERE/'apps6-product.json').read_bytes())['payload']),H.FILES)
 def test_other603_setup_missing_added_or_wrong_version_refuse(self):
  for key,value in [('cachy-asahi-setup','0.1.0-4'),('cachy-asahi-apps','0.1.0-4'),('glibc','forged')]:
   b=self.before|{key:value}
   with self.subTest(key=key),self.assertRaises(ValueError):self.guard(before=b)
  for b in ({k:v for k,v in self.before.items() if k!='cachy-asahi-setup'},self.before|{'extra-package':'1'}):
   with self.assertRaises(ValueError):self.guard(before=b)
 def test_wrong_archive_extra_release_row_or_other_selection_refuse(self):
  for key,value in [('name','cachy-asahi-setup'),('version','0.1.0-5'),('sha256','a'*64)]:
   snap=copy.deepcopy(self.snapshot);snap['release']['packages'][0][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.guard(snapshot=snap)
  snap=copy.deepcopy(self.snapshot);snap['release']['packages']*=2
  with self.assertRaises(ValueError):self.guard(snapshot=snap)
  for desired in ({'cachy-asahi-setup':'0.1.0-6'},{'cachy-asahi-apps':'0.1.0-6','cachy-asahi-setup':'0.1.0-6'}):
   with self.assertRaises(ValueError):self.guard(desired=desired)
  with self.assertRaises(ValueError):self.guard(config=self.config|{'after_lock_sha256':'b'*64})
 def test_unknown_source_is_refused_before_derivation(self):
  with self.assertRaises(ValueError):H.derive((ROOT/'scripts/update/aux_runtime.py').read_bytes()+b'\n')
 def test_original_setup_only_caller_is_untouched(self):
  text=(ROOT/'scripts/update/aux_runtime.py').read_text();self.assertIn("before.get(SETUP)=='0.1.0-3'",text);self.assertIn("desired=={SETUP:'0.1.0-4'}",text)
if __name__=='__main__':unittest.main(verbosity=2)
