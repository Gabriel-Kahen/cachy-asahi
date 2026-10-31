#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable finite data/source controls. No acceptance or build actors."""
import hashlib,importlib.util,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import materialize as M
import authority as G
import bundle as B
class Candidate(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def test_explicit_unbound_policy_refuses_before_helpers_crypto_output_or_actors(self):
  output=self.root/'bundle';value=json.loads((HERE/'authority.json').read_bytes())
  value.update(status='UNBOUND_DEBIAN_MAINTAINED_SOURCE_AUTHORITY',decision=None);policy=self.root/'unbound.json';policy.write_text(json.dumps(value))
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor forbidden')),patch.object(M,'helper',side_effect=AssertionError('helper forbidden')):
   with self.assertRaisesRegex(ValueError,'UNBOUND'):B.materialize(self.root/'absent',self.root/'absent.tar',output,policy)
  self.assertFalse(output.exists())
 def test_wrong_caa2_candidate_or_duplicate_policy_cannot_reuse_authority(self):
  value=json.loads((HERE/'authority.json').read_bytes());value['status']='ROOT_BOUND_DEBIAN_MAINTAINED_SOURCE_AUTHORITY';value['candidate']['version']='2.43.caa2-1';path=self.root/'authority.json';path.write_text(json.dumps(value))
  with self.assertRaisesRegex(ValueError,'distinct exact'):G.check(path,self.root)
  path.write_text('{"schema_version":1,"schema_version":1}')
  with self.assertRaisesRegex(ValueError,'duplicate'):G.check(path,self.root)
 def test_closed84_patch_identity40_offsets_and85th_project_patch(self):
  value=M.lock();self.assertEqual(len(value['series']['patches']),84);self.assertEqual(len(value['patch_outputs']),85)
  self.assertEqual(sum('offset ' in row['stdout'] for row in value['patch_outputs'][:84]),40)
  self.assertTrue(all(row['exit']==0 and 'fuzz' not in row['stdout']+row['stderr'] for row in value['patch_outputs']))
  self.assertEqual(value['prepared_tree'],G.EXPECTED['prepared_tree']);self.assertEqual(value['complete_patched_tree'],G.EXPECTED['quilt_tree'])
  self.assertEqual(M.pin((HERE/value['project_patch']['path']).read_bytes()),value['project_patch']['pin'])
 def test_modified_lock_and_helper_cannot_import_or_relabel_patches(self):
  clone=self.root/'source';clone.mkdir();shutil.copyfile(HERE/'source-lock.json',clone/'source-lock.json');path=clone/'source-lock.json';path.write_bytes(path.read_bytes()+b'\n')
  with patch.object(M,'HERE',clone),self.assertRaisesRegex(ValueError,'source lock'):M.lock()
  evil=self.root/'helper.py';evil.write_text("raise RuntimeError('must never execute')\n")
  with self.assertRaisesRegex(ValueError,'exact original helper'):M.helper('untrusted',evil,'0'*64)
 def test_source_policy_pins_full_bytes_and_refuses_manual_reinsertion(self):
  (self.root/'manual').mkdir();p=self.root/'manual/Makefile';p.write_bytes(b'authentic replacement\n')
  policy=dict(source_policy_files={'manual/Makefile':M.pin(p.read_bytes())},documentation={'omitted_files':['manual/intro.texi']})
  M.source_policy(self.root,policy);(self.root/'manual/intro.texi').write_bytes(b'forbidden')
  with self.assertRaisesRegex(ValueError,'manual'):M.source_policy(self.root,policy)
  (self.root/'manual/intro.texi').unlink();p.write_bytes(b'changed')
  with self.assertRaisesRegex(ValueError,'policy differs'):M.source_policy(self.root,policy)
 def test_recipe_has_real_prepare_and_fatal_checks_with_documented_manual_delta(self):
  recipe=(HERE/'PKGBUILD.in').read_text();self.assertIn('pkgver=2.43.caa3\n',recipe);self.assertNotIn('0001-mount-macro',recipe);self.assertNotIn('0003-debian-manual',recipe)
  self.assertIn('--authority "$startdir/authority.json"',recipe);self.assertNotIn('--inspection-only',recipe)
  self.assertIn('noextract=("${source[@]}")',recipe);self.assertIn('--chain-inputs "$startdir"',recipe);self.assertNotIn('--chain-inputs "$srcdir"',recipe);self.assertNotIn('make -s info',recipe);self.assertIn('MAKEINFO=: "$srcdir/$_upstream/configure"',recipe)
  commands=[line.strip() for line in recipe.splitlines() if line.strip().startswith('make ')]
  self.assertEqual(len(commands),4);self.assertTrue(all(line.startswith('make MAKEINFO=: ') for line in commands));self.assertTrue(any('check > /work/evidence/upstream-check.log' in line for line in commands));self.assertTrue(any('check-abi > /work/evidence/upstream-abi.log' in line for line in commands));self.assertIn('(( check_status == 0 && abi_status == 0 ))',recipe);self.assertIn('/runner/collect_tests.py',recipe)
  for option in ('--disable-multi-arch','--enable-bind-now','--enable-stack-protector=strong','--enable-fortify-source','--disable-systemtap','--disable-nscd','--disable-profile'):self.assertEqual(recipe.count(option),1)
  self.assertIn('debian-copyright',recipe);self.assertIn('LICENSE.cachy-asahi',recipe)
 def test_rendered_recipe_is_plain_bounded_bash_with_all_source_hashes(self):
  files={'input.xz':dict(bytes=1,sha256='a'*64),'metadata.json':dict(bytes=2,sha256='b'*64)};raw=B.render(files);path=self.root/'PKGBUILD';path.write_bytes(raw)
  self.assertNotIn(b'@SOURCE_ARRAYS@',raw);self.assertIn(b"'"+b'a'*64+b"'",raw);result=subprocess.run(['/usr/bin/bash','-n',str(path)],capture_output=True,timeout=5);self.assertEqual(result.returncode,0,result.stderr)
  for name in ('../escape','name\'unsafe','$(exec)'):
   with self.subTest(name=name),self.assertRaises(ValueError):B.render({name:dict(sha256='a'*64)})
 def test_makepkg_key_data_copies_preserve_original_authentication_inputs(self):
  row=dict(bytes=3,sha256='a'*64);files={'input.xz':dict(bytes=1,sha256='b'*64)}
  for original,copy in B.KEY_COPIES.items():files[original]=dict(row);files[copy]=dict(row)
  recipe=B.render(files).decode();self.assertNotIn("'archive-key-12.asc'",recipe);self.assertNotIn("'archive-key-13.asc'",recipe)
  for copy in B.KEY_COPIES.values():self.assertIn("'"+copy+"'",recipe)
  self.assertEqual(recipe.count("'"+'a'*64+"'"),2)
  for original,copy in B.KEY_COPIES.items():
   for missing in (original,copy):
    bad=dict(files);del bad[missing]
    with self.subTest(missing=missing),self.assertRaisesRegex(ValueError,'exact public key data copy'):B.render(bad)
   bad=dict(files);bad[copy]=dict(bytes=3,sha256='c'*64)
   with self.assertRaisesRegex(ValueError,'exact public key data copy'):B.render(bad)
 def test_portable_without_git_or_private_source_paths(self):
  for name in ('materialize.py','authority.py','bundle.py','PKGBUILD.in'):
   raw=(HERE/name).read_text();self.assertNotIn('/home/',raw);self.assertNotIn('artifacts/development/',raw);self.assertNotIn('manifests/packages.toml',raw)
  with tempfile.TemporaryDirectory() as tmp:
   clone=Path(tmp)/'portable';shutil.copytree(HERE,clone,ignore=shutil.ignore_patterns('__pycache__'))
   result=subprocess.run([sys.executable,'-I','-B',str(clone/'test_materialize.py')],cwd=tmp,capture_output=True,timeout=10);self.assertEqual(result.returncode,0,result.stderr)
if __name__=='__main__':unittest.main(verbosity=2)
