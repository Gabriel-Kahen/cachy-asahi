#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure versioned source, mode/tree and log-gate controls; no native actors."""
import ast,hashlib,importlib.util,json,os,shutil,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];sys.path.insert(0,str(HERE));import contract as C,custody
class Binding(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def recipe_copy(self):
  product=self.root/C.RECIPE;product.parent.mkdir(parents=True);shutil.copytree(ROOT/C.RECIPE,product)
  checks=self.root/'scripts/checks';checks.mkdir(parents=True);shutil.copyfile(ROOT/'scripts/checks/package_checks.py',checks/'package_checks.py')
  release=self.root/'scripts/release';release.mkdir(parents=True);shutil.copyfile(ROOT/'scripts/release/source_delivery.py',release/'source_delivery.py');shutil.copyfile(ROOT/'scripts/release/recipe_source_delivery.py',release/'recipe_source_delivery.py')
  profile=self.root/C.LANE;profile.mkdir(parents=True);shutil.copyfile(HERE/'product-profile.json',profile/'product-profile.json');shutil.copyfile(HERE/'candidate.SRCINFO',profile/'candidate.SRCINFO');return product
 def test_real_isolated20_file_recipe03_and_no_old_directory(self):
  self.assertEqual(C.version(ROOT,C.PRODUCT),'0.3.0-1');row=C.recipe(ROOT,C.PRODUCT);self.assertEqual(len(row['input_sha256']),20);self.assertEqual(len(row['metadata']['source']),18);self.assertFalse((ROOT/'packages/tools/cachy-asahi-orphans').exists())
 def test_legacy_recipe_or_replaced_source_never_admitted(self):
  product=self.recipe_copy();(product/'.SRCINFO').write_text((product/'.SRCINFO').read_text().replace('0.3.0','0.1.0'))
  with self.assertRaises(ValueError):C.recipe(self.root,C.PRODUCT)
  shutil.copyfile(ROOT/C.RECIPE/'.SRCINFO',product/'.SRCINFO');(product/'live.py').write_text('inert changed source')
  with self.assertRaises(ValueError):C.recipe(self.root,C.PRODUCT)
 def test_legacy53_profile_never_proves109(self):
  self.recipe_copy();p=self.root/C.LANE/'product-profile.json';value=json.loads(p.read_bytes());value.update(tests=53,test_counts=[20,25,8]);p.write_bytes(C.encoded(value))
  with self.assertRaises(ValueError):C.recipe(self.root,C.PRODUCT)
 def test_log_requires_all_six_exact_counts_and_six_natural_oks(self):
  p=self.root/'build.log';text='==> Starting check()\n'+''.join('Ran '+str(n)+' tests in 0.1s\nOK\n' for n in (20,25,8,24,25,7));p.write_text(text);self.assertEqual(C.check_log(p,C.PRODUCT)['count'],109)
  for bad in (text.split('Ran 24')[0],text.replace('Ran 24','Ran 23'),text+'OK (skipped=1)\n',text+'FAILED\n',text.replace('OK\n','',1)):
   p.write_text(bad)
   with self.assertRaises(ValueError):C.check_log(p,C.PRODUCT)
 def test_build_algorithm_selects_explicit_recipe_path(self):
  tree=ast.parse((HERE/'build_candidate.py').read_text());copy=next(n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='copytree')
  self.assertEqual(ast.dump(copy.args[0]),ast.dump(ast.parse('source/C.RECIPE',mode='eval').body));self.assertNotIn("source/'packages/tools'/name",(HERE/'build_candidate.py').read_text())
 def test_additive03_source_delivery_preserves01_default(self):
  delivery=C.load('test03_delivery',ROOT/'scripts/release/recipe_source_delivery.py');bodies,info=delivery.source_set(C.PRODUCT,lambda n:(ROOT/C.RECIPE/n).read_bytes());self.assertEqual(len(bodies),20);self.assertEqual(delivery.profile(C.PRODUCT)['version'],'0.1.0-2');self.assertEqual(delivery.source_profile(C.PRODUCT,bodies)['version'],'0.3.0-1');checker=C.load('test03_payload',ROOT/C.RECIPE/'check_source.py');self.assertEqual(delivery.payload(C.PRODUCT,'0.3.0-1'),checker.PAYLOAD)
 def test_tree_hash_known_empty_and_blob_mode_changes(self):
  files,modes,tree=custody.state(self.root,[]);self.assertEqual(tree['tree'],'4b825dc642cb6eb9a060e54bf8d69288fbee4904');p=self.root/'one';p.write_text('inert');before=custody.state(self.root,['one']);p.chmod(0o755);after=custody.state(self.root,['one']);self.assertNotEqual(before[2]['tree'],after[2]['tree']);self.assertEqual(after[1],{'one':'100755'})
 def test_custody_rejects_alias_unexpected_mode_and_escape(self):
  p=self.root/'one';p.write_text('inert');(self.root/'link').symlink_to(p)
  with self.assertRaises(ValueError):custody.state(self.root,['link'])
  p.chmod(0o600)
  with self.assertRaises(ValueError):custody.state(self.root,['one'])
  with self.assertRaises(ValueError):custody.state(self.root,['../outside'])
 def test_tree_count_and_map_hash_bind_complete_modes(self):
  (self.root/'dir').mkdir();(self.root/'dir/a').write_text('a');(self.root/'b').write_text('b');files,modes,tree=custody.state(self.root,['dir/a','b']);self.assertEqual(tree['files'],2);self.assertEqual(tree['source_map_sha256'],hashlib.sha256(custody.encoded(files)).hexdigest());self.assertEqual(set(modes),set(files))
if __name__=='__main__':unittest.main()
