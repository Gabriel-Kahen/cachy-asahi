#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Mocked archive/HTTP DATA controls only: no acquisition or native actors."""
import copy,gzip,hashlib,io,json,os,stat,sys,tarfile,tempfile,time,unittest
from pathlib import Path
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import data_carrier as D


def pins(values):return {n:dict(bytes=len(v),sha256=hashlib.sha256(v).hexdigest()) for n,v in values.items()}
def archive(values,extra=(),*,pax=None,root=None):
 raw=io.BytesIO();prefix=D.PREFIX if root is None else root
 with tarfile.open(fileobj=raw,mode='w',format=tarfile.PAX_FORMAT,pax_headers={'comment':D.SOURCE} if pax is None else pax) as tar:
  for name in ('','packages'):
   item=tarfile.TarInfo(prefix+name);item.type=tarfile.DIRTYPE;item.mode=0o775;tar.addfile(item)
  for name,value in values.items():
   item=tarfile.TarInfo(prefix+name);item.size=len(value);item.mode=0o664;tar.addfile(item,io.BytesIO(value))
  for item,value in extra:tar.addfile(item,io.BytesIO(value) if value is not None else None)
 return gzip.compress(raw.getvalue())

class Response(io.BytesIO):
 status=200
 def geturl(self):return D.URL

class DataCarrier(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.home=Path(self.tmp.name);self.values={'LICENSE':b'grant','packages/a.pkg.tar.xz':b'inert DATA'};self.files=pins(self.values);self.destination=self.home/'carrier';self.until=time.monotonic()+10
 def unpack(self,raw=None,files=None):return D.unpack(io.BytesIO(archive(self.values) if raw is None else raw),self.destination,self.files if files is None else files,self.until)
 def test_complete_stream_hash_closure_and_normalized_modes(self):
  receipt=self.unpack();self.assertEqual(receipt['file_map'],self.files);self.assertEqual(receipt['files'],2);self.assertFalse(receipt['native_authority']);self.assertFalse(receipt['git_authority']);self.assertEqual(receipt['requests'],1)
  for name,value in self.values.items():self.assertEqual((self.destination/name).read_bytes(),value);self.assertEqual(stat.S_IMODE((self.destination/name).stat().st_mode),0o600)
  self.assertEqual(stat.S_IMODE((self.destination/'packages').stat().st_mode),0o700)
 def test_long_pax_path_is_bounded_and_leaf_pinned(self):
  values={'LICENSE':b'g','packages/'+('a'*150):b'd'};receipt=self.unpack(archive(values),pins(values));self.assertEqual(receipt['files'],2)
 def test_wrong_member_bytes_or_size_refused(self):
  for values in ({**self.values,'LICENSE':b'other'},{**self.values,'LICENSE':b'x'}):
   with self.subTest(values=values),self.assertRaises(ValueError):self.unpack(archive(values))
   if self.destination.exists():__import__('shutil').rmtree(self.destination)
 def test_missing_or_extra_leaf_refused(self):
  for values in ({'packages/a.pkg.tar.xz':b'inert DATA'},{**self.values,'foreign':b'x'}):
   with self.assertRaises(ValueError):self.unpack(archive(values))
   if self.destination.exists():__import__('shutil').rmtree(self.destination)
 def test_duplicate_file_refused(self):
  item=tarfile.TarInfo(D.PREFIX+'LICENSE');item.size=5
  with self.assertRaises(ValueError):self.unpack(archive(self.values,[(item,b'grant')]))
 def test_symlink_hardlink_device_and_sparse_refused(self):
  for kind in (tarfile.SYMTYPE,tarfile.LNKTYPE,tarfile.CHRTYPE,tarfile.GNUTYPE_SPARSE):
   item=tarfile.TarInfo(D.PREFIX+'packages/link');item.type=kind;item.linkname='../../outside' if kind in (tarfile.SYMTYPE,tarfile.LNKTYPE) else ''
   with self.subTest(kind=kind),self.assertRaises((ValueError,tarfile.TarError)):self.unpack(archive(self.values,[(item,None)]))
   if self.destination.exists():__import__('shutil').rmtree(self.destination)
  self.assertFalse((self.home/'outside').exists())
 def test_absolute_traversal_and_wrong_root_refused(self):
  for root in ('/outside/','../outside/','cachy-asahi-'+'0'*40+'/'):
   with self.assertRaises(ValueError):self.unpack(archive(self.values,root=root))
   if self.destination.exists():__import__('shutil').rmtree(self.destination)
 def test_unknown_or_wrong_global_pax_refused(self):
  for pax in ({'comment':'0'*40},{'path':'outside'},{'unknown':'value'}):
   with self.assertRaises(ValueError):self.unpack(archive(self.values,pax=pax))
   if self.destination.exists():__import__('shutil').rmtree(self.destination)
 def test_oversized_pax_body_refused_before_body_read(self):
  item=tarfile.TarInfo('PaxHeader');item.type=tarfile.XHDTYPE;item.size=17000
  with self.assertRaisesRegex(ValueError,'extension'):self.unpack(archive(self.values,[(item,b'x'*17000)]))
 def test_truncated_gzip_or_tar_and_nonzero_tail_refused(self):
  good=archive(self.values);plain=gzip.decompress(good)
  for raw in (good[:-8],gzip.compress(plain[:700]),gzip.compress(plain+b'evil')):
   with self.assertRaises((ValueError,EOFError,gzip.BadGzipFile)):self.unpack(raw)
   if self.destination.exists():__import__('shutil').rmtree(self.destination)
 def test_deadline_and_stream_cap_refuse(self):
  with self.assertRaisesRegex(ValueError,'deadline'):D.unpack(io.BytesIO(archive(self.values)),self.destination,self.files,time.monotonic()-1)
  self.assertFalse(self.destination.exists())
  bound=D.Bounded(io.BytesIO(b'ab'),1,self.until)
  with self.assertRaisesRegex(ValueError,'cap'):bound.read(2)
 def test_existing_or_alias_destination_refuses_without_touching_foreign(self):
  self.destination.mkdir();(self.destination/'foreign').write_bytes(b'keep')
  with self.assertRaises(ValueError):self.unpack()
  self.assertEqual((self.destination/'foreign').read_bytes(),b'keep')
 def test_acquire_exact_one_request_no_redirect_retry_or_git(self):
  profile=dict(source=D.SOURCE,files=self.files);opener=Mock(return_value=Response(archive(self.values)));root=self.home/'source';root.mkdir()
  with patch.object(D,'expected',return_value=profile),patch.object(D.C,'digest',return_value='1'*64):receipt=D.acquire(root,self.destination,self.until,opener)
  self.assertEqual(opener.call_count,1);request=opener.call_args.args[0];self.assertEqual(request.full_url,D.URL);self.assertEqual(receipt['profile_sha256'],'1'*64)
 def test_bad_http_status_or_redirect_has_only_one_request(self):
  for status,url in ((302,D.URL),(200,'https://elsewhere.invalid')):
   response=Response(b'');response.status=status;response.geturl=lambda:url;opener=Mock(return_value=response)
   with patch.object(D,'expected',return_value=dict(source=D.SOURCE,files=self.files)),self.assertRaises(ValueError):D.acquire(self.home,self.destination,self.until,opener)
   self.assertEqual(opener.call_count,1)
  with self.assertRaisesRegex(ValueError,'redirects'):D.NoRedirect().redirect_request(None,None,None,None,None,None)
 def test_data_only_verifier_rejects_alias_or_mode_drift(self):
  self.unpack();(self.destination/'LICENSE').chmod(0o644)
  with self.assertRaisesRegex(ValueError,'modes'):D.verify(self.destination,self.files,self.until)

if __name__=='__main__':unittest.main()
