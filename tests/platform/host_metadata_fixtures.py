# SPDX-License-Identifier: MIT
#!/usr/bin/env python3
"""Independent genuine tar/PAX metadata fixtures; no extraction or package code."""
import base64
import hashlib
import io
import json
import lzma
from pathlib import Path
import struct
import tarfile
import tempfile
import types
import unittest

# Populated only by the explicit host-component runner, never default tests.
module=None
NATIVE_PINS=None
OUTPUT=None


def archive(entries,format=tarfile.PAX_FORMAT):
    stream=io.BytesIO()
    with tarfile.open(fileobj=stream,mode='w',format=format) as out:
        for name,content,pax in entries:
            member=tarfile.TarInfo(name);member.size=len(content);member.mode=0o644
            member.uid=member.gid=0;member.mtime=1700000000;member.pax_headers=pax
            out.addfile(member,io.BytesIO(content))
    return lzma.compress(stream.getvalue(),format=lzma.FORMAT_XZ)


class NativeMetadataReview(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pins=NATIVE_PINS
        cls.run_directory=OUTPUT/'metadata-fixtures';cls.run_directory.mkdir(mode=0o700)
        print('RETAINED_FIXTURES='+str(cls.run_directory))

    def setUp(self):
        self.directory=self.run_directory/self._testMethodName
        self.directory.mkdir(mode=0o700)

    def record(self,label,value):
        (self.directory/(label+'.json')).write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

    def reference(self,content):
        path=self.directory/'fixture.tar.xz';path.write_bytes(content);st=path.stat()
        return dict(path=str(path),size=st.st_size,identity=module.identity(st),sha256=hashlib.sha256(content).hexdigest())

    def observe_and_refuse(self,pax):
        ref=self.reference(archive([('file',b'body',pax)]))
        observed=module.native_scan(ref,self.pins)
        self.record('native-observation',observed)
        with self.assertRaisesRegex(ValueError,'UNKNOWN') as caught:module.complete(ref,self.pins)
        self.assertTrue(hasattr(caught.exception,'metadata_observations'))
        return observed['members'][0]['metadata']

    def test_binary_xattr_and_linux_capability_observed_exactly_then_pax_refused(self):
        binary=b'\0hello\xff';cap=struct.pack('<IIIII',0x02000001,1024,0,0,0)
        obs=self.observe_and_refuse({'LIBARCHIVE.xattr.user.binary':base64.b64encode(binary).decode(),
            'LIBARCHIVE.xattr.security.capability':base64.b64encode(cap).decode()})
        self.assertEqual(base64.b64decode(obs['xattrs']['user.binary']),binary)
        self.assertEqual(base64.b64decode(obs['capability_b64']),cap)
        self.assertEqual(obs['xattr_count'],2)

    def test_access_acl_observed_then_refused(self):
        obs=self.observe_and_refuse({'SCHILY.acl.access':'user::rw-,user:123:r--,group::r--,mask::r--,other::---'})
        self.assertEqual(obs['acl_types'],0x100)
        self.assertEqual(obs['acl_count'],5)
        self.assertTrue(any(row['qualifier']==123 for row in obs['acl']))

    def test_file_flags_text_or_masks_observed_then_refused(self):
        obs=self.observe_and_refuse({'SCHILY.fflags':'schg'})
        self.assertTrue(obs['file_flags_set'] or obs['file_flags_clear'] or obs['file_flags_text'])

    def test_unknown_pax_key_is_not_admitted_as_empty_metadata(self):
        obs=self.observe_and_refuse({'VENDOR.unrecognized.security':'value'})
        self.assertEqual(obs['xattr_count'],0)
        self.assertEqual(obs['acl_count'],0)

    def test_ordinary_ustar_positive_has_explicit_unsupported_tar_encryption_state(self):
        ref=self.reference(archive([('file',b'body',{})],tarfile.USTAR_FORMAT))
        result=module.complete(ref,self.pins)
        self.record('complete-observation',result)
        self.assertEqual(result['status'],'COMPLETE_PINNED_NATIVE_AND_RAW_USTAR_METADATA')
        self.assertEqual(result['encryption_format_state'],-2)
        self.assertEqual(result['members'][0]['metadata']['encrypted'],0)

    def test_appledouble_metadata_is_observed_or_refused_never_admitted_as_empty(self):
        # Valid AppleDouble v2 FinderInfo record attached to matching ordinary file.
        blob=struct.pack('>II16sH',0x00051607,0x00020000,bytes(16),1)+struct.pack('>III',9,38,32)+bytes(32)
        ref=self.reference(archive([('._file',blob,{}),('file',b'body',{})],tarfile.USTAR_FORMAT))
        observed=module.native_scan(ref,self.pins)
        self.record('native-observation',observed)
        self.assertTrue(any(row['metadata']['mac_metadata_bytes'] for row in observed['members']),
                        'enabled Mac reader did not expose valid AppleDouble metadata')
        try:result=module.complete(ref,self.pins)
        except ValueError as error:
            self.record('refusal',dict(error=str(error)))
            return
        self.fail('AppleDouble metadata candidate admitted with no Mac metadata observation: '+str(result['status']))

    def test_sparse_map_observed_then_refused(self):
        ref=self.reference(archive([('file',b'ab',{'GNU.sparse.map':'0,1,4096,1','GNU.sparse.size':'4097','GNU.sparse.numblocks':'2'})]))
        observed=module.native_scan(ref,self.pins)
        self.record('native-observation',observed)
        node=observed['members'][0]
        self.assertGreater(node['metadata']['sparse_count'],0)
        self.assertEqual(node['bytes'],4097)
        self.assertEqual(node['body_sha256'],hashlib.sha256(b'a'+bytes(4095)+b'b').hexdigest())
        with self.assertRaisesRegex(ValueError,'UNKNOWN'):module.complete(ref,self.pins)

    def test_appledouble_named_directory_is_unknown_even_without_decodable_blob(self):
        ref=self.reference(archive([('.AppleDouble/file',b'unknown-Mac-carrier',{})],tarfile.USTAR_FORMAT))
        with self.assertRaisesRegex(ValueError,'UNKNOWN'):module.complete(ref,self.pins)

