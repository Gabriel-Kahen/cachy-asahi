#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fenced synthetic archive DATA controls; no package program or crypto actor."""
import ctypes,hashlib,importlib.util,io,json,lzma,os,socket,subprocess,sys,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def denied(*a,**kw):raise AssertionError('external/package actor forbidden')
for n in ('Popen','run','call','check_call','check_output'):setattr(subprocess,n,denied)
for n in ('system','fork','forkpty','execv','execve','posix_spawn','posix_spawnp'):
 if hasattr(os,n):setattr(os,n,denied)
socket.socket=denied;ctypes.CDLL=denied
s=importlib.util.spec_from_file_location('old_perl_review',HERE/'review.py');R=importlib.util.module_from_spec(s);s.loader.exec_module(R)
class Data(unittest.TestCase):
 def setUp(self):self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.archive=self.root/'input.pkg.tar.xz'
 def tearDown(self):self.tmp.cleanup()
 def make(self,entries=None):
  if entries is None:entries=[('.PKGINFO','file',b'pkgname = perl\npkgver = 5.42.3-1\narch = aarch64\ndepend = glibc\n'),('usr/bin/perl','file',b'DATA_NOT_A_PROGRAM'),('usr/bin/alias','hardlink','usr/bin/perl'),('etc/profile.d/perlbin.sh','file',b'export PATH\n')]
  with tarfile.open(self.archive,'w:xz',format=tarfile.GNU_FORMAT) as tar:
   for name,kind,value in entries:
    t=tarfile.TarInfo(name);t.uid=t.gid=0;t.mode=0o755
    if kind=='file':t.size=len(value);tar.addfile(t,io.BytesIO(value))
    else:t.type={'hardlink':tarfile.LNKTYPE,'symlink':tarfile.SYMTYPE,'fifo':tarfile.FIFOTYPE}[kind];t.linkname=value;tar.addfile(t)
  return self.archive
 def test_complete_map_and_hardlink(self):
  rows,texts,meta,review,links,backups=R.analyze(self.make());self.assertEqual(len(rows),4);self.assertEqual(links['usr/bin/alias']['sha256'],rows['usr/bin/perl']['sha256']);self.assertEqual(meta['depend'],['glibc']);self.assertEqual(backups,[]);self.assertIn('etc/profile.d/perlbin.sh',review)
 def test_install_text_is_never_executed(self):
  marker=self.root/'forbidden';raw=('#!/bin/bash\ntouch '+str(marker)+'\n').encode();self.make([('.PKGINFO','file',b'pkgname = perl\n'),('.INSTALL','file',raw)]);rows,texts,*_=R.analyze(self.archive);self.assertEqual(texts['.INSTALL'],raw);self.assertFalse(marker.exists())
 def test_absent_install_explicit(self):rows,texts,*_=R.analyze(self.make());self.assertNotIn('.INSTALL',rows);self.assertNotIn('.INSTALL',texts)
 def test_backup_field_bound_to_payload(self):
  self.make([('.PKGINFO','file',b'pkgname = perl\nbackup = etc/perl.conf\n'),('etc/perl.conf','file',b'data\n')]);self.assertEqual(R.analyze(self.archive)[-1],['etc/perl.conf'])
 def test_missing_backup_refused(self):
  self.make([('.PKGINFO','file',b'backup = etc/absent\n')])
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_duplicate_path_refused(self):
  self.make([('.PKGINFO','file',b'pkgname = perl\n'),('.PKGINFO','file',b'pkgname = fake\n')])
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_traversal_refused(self):
  self.make([('../escape','file',b'x')])
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_absolute_path_refused(self):
  self.make([('/escape','file',b'x')])
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_forward_hardlink_refused(self):
  self.make([('usr/alias','hardlink','usr/target'),('usr/target','file',b'x')])
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_missing_hardlink_target_refused(self):
  self.make([('usr/alias','hardlink','usr/missing')])
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_fifo_refused(self):
  self.make([('usr/fifo','fifo','')])
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_absolute_symlink_refused(self):
  self.make([('usr/target','file',b'x'),('usr/alias','symlink','/usr/target')])
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_dangling_symlink_refused(self):
  self.make([('usr/alias','symlink','missing')])
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_missing_pkginfo_refused(self):
  self.make([('usr/a','file',b'x')])
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_binary_install_refused(self):
  self.make([('.PKGINFO','file',b'pkgname = perl\n'),('.INSTALL','file',b'\0x')])
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_oversize_control_refused(self):
  self.make([('.PKGINFO','file',b'pkgname = perl\n'),('.INSTALL','file',b'x'*(65536+1))])
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_concatenated_frame_refused(self):
  self.make();self.archive.write_bytes(self.archive.read_bytes()+lzma.compress(b'x'))
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_truncated_frame_refused(self):
  self.make();self.archive.write_bytes(self.archive.read_bytes()[:-10])
  with self.assertRaises(ValueError):R.analyze(self.archive)
 def test_wrong_exact_archive_no_output(self):
  self.make();sig=self.root/'sig';sig.write_bytes(b'fake');out=self.root/'new'
  with self.assertRaises(ValueError):R.review_exact(self.archive,sig,out)
  self.assertFalse(out.exists())
 def test_symlink_input_refused(self):
  self.make();p=self.root/'alias';p.symlink_to(self.archive)
  with self.assertRaises(OSError):R.input_pin(p)
 def test_helper_hash_tamper_refused(self):
  with patch.object(R,'input_pin',return_value={'bytes':1,'sha256':'0'*64}),self.assertRaises(ValueError):R.helper()
class ActualReceipt(unittest.TestCase):
 def test_recorded_actual_counts_and_holds(self):
  d=json.loads((HERE/'actual/review.json').read_text());self.assertEqual(d['counts'],{'nodes':3234,'types':{'file':2868,'directory':364,'hardlink':2},'ELF_headers':54,'hardlinks':2});self.assertEqual(d['authentication'],'NOT RUN; signature pin equality is not signature authentication');self.assertIsNone(d['Root_authority']);self.assertFalse(d['INSTALL_present'])
 def test_complete_actual_output_hashes(self):
  d=json.loads((HERE/'actual/review.json').read_text())
  for n,ref in d['files'].items():self.assertEqual(R.input_pin(HERE/'actual'/n),ref)
 def test_core_baseline_review_interface_exact(self):
  packet=json.loads((HERE/'actual/baseline-review.json').read_text());rows=json.loads((HERE/'actual/payload.json').read_text());expected={n:r for n,r in rows.items() if n.startswith(('.', 'etc/', 'usr/share/libalpm/'))}
  self.assertEqual(set(packet),{'status','archive','signature','metadata_config_hook_paths','note'});self.assertEqual(packet['status'],'ROOT_ARCHIVE_REVIEW_REQUIRED_BEFORE_ADMISSION');self.assertEqual(packet['metadata_config_hook_paths'],expected);self.assertEqual(packet['archive'],R.ARCHIVE);self.assertEqual(packet['signature'],R.SIGNATURE)
 def test_actual_hardlink_identity(self):
  rows=json.loads((HERE/'actual/payload.json').read_text())
  for n,r in rows.items():
   if r['type']=='hardlink':self.assertEqual((r['sha256'],r['bytes']),(rows[r['target']]['sha256'],rows[r['target']]['bytes']))
 def test_raw_controls_and_hook_hashes(self):
  d=json.loads((HERE/'actual/review.json').read_text());self.assertEqual(len(d['raw_texts']),6)
  for n,r in d['raw_texts'].items():self.assertEqual(R.input_pin(HERE/'actual'/r['file']),{k:r[k] for k in ('bytes','sha256')})
if __name__=='__main__':
 if not (__debug__ and sys.flags.isolated):raise RuntimeError('isolated assertions required')
 unittest.main()
