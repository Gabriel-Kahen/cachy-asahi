#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Archive DATA refusals. Actual signed ALPM journey is the explicit run.py CLI."""
import hashlib
import importlib.util
import io
import subprocess
import sys
from pathlib import Path
import tarfile
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('nm_candidate_journey',HERE/'journey.py')
j=importlib.util.module_from_spec(spec);spec.loader.exec_module(j)


class ArchiveControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='nm-journey-DATA-');self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'SYNTHETIC.tar'

    def make(self,extra=(),arch='x86_64'):
        with tarfile.open(self.path,'w')as t:
            entries=[('.PKGINFO',f'pkgname = libnm\npkgver = 1.58.1-2.1\narch = {arch}\n'.encode(),'file',0o644),('usr/lib/libnm.so.0',b'SYNTHETIC inert DATA','file',0o755),*extra]
            for name,data,kind,mode in entries:
                m=tarfile.TarInfo(name);m.mode=mode
                if kind=='link':m.type=tarfile.SYMTYPE;m.linkname=data;t.addfile(m)
                else:m.size=len(data);t.addfile(m,io.BytesIO(data))
        return self.path

    def test_regular_and_internal_link_byte_pins(self):
        data=j.archive(self.make([('usr/lib/libnm.so','libnm.so.0','link',0o777)]))
        self.assertEqual(data['leaves']['usr/lib/libnm.so.0']['sha256'],hashlib.sha256(b'SYNTHETIC inert DATA').hexdigest())
        self.assertEqual(data['leaves']['usr/lib/libnm.so']['target'],'libnm.so.0')

    def test_wrong_arch_privileged_hook_scriptlet_duplicate_and_escape_refuse(self):
        cases=[([('.INSTALL',b'never run','file',0o644)],'x86_64'),([('usr/share/libalpm/hooks/TEST.hook',b'never run','file',0o644)],'x86_64'),([('usr/lib/escape','../../../outside','link',0o777)],'x86_64'),([('usr/lib/absolute','/etc/passwd','link',0o777)],'x86_64'),([('usr/bin/suid',b'never run','file',0o4755)],'x86_64'),([('usr/lib/libnm.so.0',b'duplicate','file',0o755)],'x86_64'),([],'aarch64')]
        for extra,arch in cases:
            with self.subTest(extra=extra,arch=arch),self.assertRaises(AssertionError):j.archive(self.make(extra,arch))

    def test_optimized_launcher_refuses_before_inputs_or_docker(self):
        p=subprocess.run([sys.executable,'-O',str(HERE/'run.py'),'--allow-disposable-x86-TEST-journey','--archives',str(self.path.parent/'missing'),'--output',str(self.path.parent/'output')],capture_output=True,text=True)
        self.assertEqual(p.returncode,2);self.assertIn('optimized Python refused',p.stderr)
        self.assertFalse((self.path.parent/'output').exists())

    def test_final_absence_rejects_even_one_remaining_leaf(self):
        records={'libnm':{'leaves':{'a':{},'b':{}}}}
        self.assertTrue(j.all_absent(records,lambda _: {'type':'missing'}))
        self.assertFalse(j.all_absent(records,lambda p:{'type':'regular'if p=='b'else'missing'}))


if __name__=='__main__':unittest.main(verbosity=2)
