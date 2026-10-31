# SPDX-License-Identifier: MIT
"""Bounded source-only grammar and containment controls; no package/build execution."""
import importlib.util,tempfile,unittest
from pathlib import Path
s=importlib.util.spec_from_file_location('candidate',Path(__file__).with_name('materialize.py'));M=importlib.util.module_from_spec(s);s.loader.exec_module(M)
class Controls(unittest.TestCase):
 def test_series_order_and_comments(self):
  self.assertEqual(M.series(b'# comment\na.patch\n\nb/c.patch # note\n'),['a.patch','b/c.patch'])
 def test_series_options_duplicates_and_traversal_refuse(self):
  for raw in (b'a.patch -p0\n',b'a.patch\na.patch\n',b'../a.patch\n',b'/a.patch\n',b'a//b.patch\n'):
   with self.subTest(raw=raw),self.assertRaises(ValueError):M.series(raw)
 def test_actual_filename_and_null_creation(self):
  self.assertEqual(M.safe('localedata/locales/eu_FR@euro'),'localedata/locales/eu_FR@euro')
  self.assertEqual(M.paths(b'--- /dev/null\n+++ b/normal\n@@ -0,0 +1 @@\n+text\n')[0]['operation'],'create')
 def test_extended_git_empty_file_target_is_accounted(self):
  rows=M.paths(b'diff --git a/new/empty b/new/empty\nnew file mode 100644\nindex 000..e69\ndiff --git a/file b/file\n--- a/file\n+++ b/file\n@@ -1 +1 @@\n-a\n+b\n')
  self.assertIn({'path':'new/empty','operation':'git-header-declared-target'},rows)
 def test_every_header_refuses_escape_and_nonordinary_formats(self):
  for raw in (b'diff --git a/../escape b/../escape\n',b'diff --git a/old b/new\n',b'GIT binary patch\n',b'new file mode 120000\n',b'--- a/file\n+++ b/../escape\n@@ -1 +1 @@\n-a\n+b\n',b'1c1\n<a\n---\n>b\n'):
   with self.subTest(raw=raw),self.assertRaises(ValueError):M.paths(raw)
 def test_backup_label_requires_exact_new_name(self):
  self.assertEqual(M.paths(b'--- b/file.original2\n+++ b/file\n@@ -1 +1 @@\n-a\n+b\n')[0]['operation'],'absent-old-backup-label')
  with self.assertRaises(ValueError):M.paths(b'--- a/other\n+++ b/file\n@@ -1 +1 @@\n-a\n+b\n')
 def test_symlink_parent_and_leaf_refuse(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'real').mkdir();(root/'link').symlink_to('real');(root/'leaf').symlink_to('real/file')
   for name in ('link/file','leaf'):
    with self.subTest(name=name),self.assertRaises(ValueError):M.target(root,name)
   self.assertEqual(M.target(root,'real/new'),root/'real/new')
if __name__=='__main__':unittest.main()
