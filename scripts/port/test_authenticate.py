import copy
import io
import json
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import authenticate as a

HERE=Path(__file__).resolve().parent
LOCK=json.loads((HERE/'desktop-archives-proposal.json').read_text())
GOOD=f'[GNUPG:] VALIDSIG {a.SIGNER} 2026-08-05 1785933702 0 4 0 1 10 00 {a.SIGNER}\n'


class BoundaryTests(unittest.TestCase):
    def test_exact_set_signer_url_bounds_and_duplicate_rejected(self):
        a.validate(LOCK)
        for mutate in [lambda d:d.update(signer_fingerprint='A'*40),
                       lambda d:d['packages'].pop(),
                       lambda d:d['packages'][0].update(url='http://example.invalid/archive'),
                       lambda d:d['packages'][0].update(filename='../archive.pkg.tar.xz'),
                       lambda d:d['packages'][0].update(size=a.MAX_BYTES+1),
                       lambda d:d['packages'].__setitem__(1,copy.deepcopy(d['packages'][0]))]:
            data=copy.deepcopy(LOCK);mutate(data)
            with self.assertRaises(ValueError):a.validate(data)
    def test_metadata_tamper_not_accepted_by_receipt_binding(self):
        proposal=json.loads((HERE/'desktop-proposal.json').read_text())
        receipt=json.loads((HERE/'generic-desktop-receipt.json').read_text())
        builder=json.loads((HERE.parents[1]/'docs/validation/input-snapshots/7d53775b2de6136d531a7f20059088def7bbb11ad8baef58e75cd5826e3a2b41.json').read_text())
        a.bind(LOCK,proposal,receipt,builder)
        for key,value in [('depends',['invented']),('sha256','0'*64),('arch','any'),('size',1),('license',['invented'])]:
            data=copy.deepcopy(LOCK);data['packages'][0][key]=value
            with self.assertRaises(ValueError):a.bind(data,proposal,receipt,builder)
    def test_gpg_status_requires_zero_exit_exact_signer_and_no_bad_status(self):
        a.status(subprocess.CompletedProcess([],0,GOOD,''))
        for status in [GOOD.replace(a.SIGNER,'A'*40),GOOD+GOOD,'',GOOD+'[GNUPG:] EXPKEYSIG ignored\n',
                       GOOD+'[GNUPG:] REVKEYSIG ignored\n',GOOD+'[GNUPG:] FAILURE verify 1\n',
                       GOOD+'[GNUPG:] NODATA 1\n']:
            with self.assertRaises(ValueError):a.status(subprocess.CompletedProcess([],0,status,''))
        with self.assertRaises(ValueError):a.status(subprocess.CompletedProcess([],1,GOOD,''))


class DataTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.expected={'name':'fixture','version':'1-1','arch':'aarch64','license':['MIT'],
                       'depends':['virtual>=2'],'provides':[],'conflicts':[],'replaces':[]}
    def archive(self,extra=(),meta=None):
        p=self.root/'fixture.pkg.tar.xz'
        pkg=(meta or 'pkgname = fixture\npkgver = 1-1\narch = aarch64\nlicense = MIT\ndepend = virtual>=2\n').encode()
        header=bytearray(64);header[:7]=b'\x7fELF\x02\x01\x01';header[18:20]=struct.pack('<H',183)
        with tarfile.open(p,'w:xz') as t:
            for name,data,kind,target in [('.PKGINFO',pkg,tarfile.REGTYPE,''),('.INSTALL',b'echo fixture\n',tarfile.REGTYPE,''),
                      ('usr/bin/fixture',bytes(header),tarfile.REGTYPE,''),
                      ('usr/share/libalpm/hooks/fixture.hook',b'[Trigger]\n',tarfile.REGTYPE,'')]+list(extra):
                m=tarfile.TarInfo(name);m.size=len(data);m.type=kind;m.linkname=target;t.addfile(m,io.BytesIO(data) if m.isfile() else None)
        return p
    def test_scriptlet_hook_elf_and_paths_recorded_without_execution_or_extraction(self):
        archive=self.archive([('usr/lib/libfixture.so',b'',tarfile.SYMTYPE,'libfixture.so.1'),
                              ('usr/share/licenses/fixture/LICENSE',b'MIT fixture notice',tarfile.REGTYPE,'')])
        result=a.observe(archive,self.expected)
        self.assertEqual(result['ELF'][0]['machine'],183)
        self.assertEqual(result['ELF'][0]['16K_load'],'NOT RUN')
        self.assertEqual({r['kind'] for r in result['hooks_and_scriptlets']},{'install-scriptlet','ALPM-hook'})
        self.assertTrue(all(not r['executed'] for r in result['hooks_and_scriptlets']))
        self.assertEqual(result['links'][0]['target'],'libfixture.so.1')
        self.assertEqual(result['license_notice_files'][0]['sha256'],a.hashlib.sha256(b'MIT fixture notice').hexdigest())
        self.assertEqual(list(self.root.iterdir()),[archive])
    def test_archive_path_duplicate_special_and_metadata_mismatch_refused(self):
        for extra in [[('../escape',b'payload',tarfile.REGTYPE,'')],
                      [('usr/bin/fixture',b'duplicate',tarfile.REGTYPE,'')],
                      [('dev/fixture',b'',tarfile.CHRTYPE,'')],
                      [('.BUILDINFO',b'',tarfile.SYMTYPE,'elsewhere')]]:
            with self.assertRaises(ValueError):a.observe(self.archive(extra),self.expected)
        with self.assertRaises(ValueError):a.observe(self.archive(meta='pkgname = changed\n'),self.expected)
    def response(self,data,url):
        r=io.BytesIO(data);r.url=url;return r
    def test_fetch_hash_size_redirect_and_cached_symlink_boundaries(self):
        item={'filename':'fixture.pkg.tar.xz','size':7,'sha256':a.hashlib.sha256(b'payload').hexdigest(),
              'url':'https://ca.us.mirror.archlinuxarm.org/aarch64/extra/fixture.pkg.tar.xz'}
        for body,url in [(b'changed',item['url']),(b'oversized',item['url']),
                         (b'payload','http://ca.us.mirror.archlinuxarm.org/fixture'),
                         (b'payload','https://other.invalid/fixture')]:
            with patch.object(a.native.urllib.request,'urlopen',return_value=self.response(body,url)):
                with self.assertRaises(ValueError):a.fetch(item,self.root)
            self.assertEqual(list(self.root.iterdir()),[])
        with patch.object(a.native.urllib.request,'urlopen',return_value=self.response(b'payload',item['url'])):
            path=a.fetch(item,self.root)
        self.assertEqual(path.read_bytes(),b'payload')
        path.write_bytes(b'changed')
        with self.assertRaises(ValueError):a.fetch(item,self.root)
        path.unlink();path.symlink_to('/etc/pacman.conf')
        with self.assertRaises(ValueError):a.fetch(item,self.root)


if __name__=='__main__':unittest.main()
