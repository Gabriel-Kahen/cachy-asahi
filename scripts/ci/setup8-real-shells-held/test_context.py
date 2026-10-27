#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Adversarial context controls; native entry must refuse this actual host."""
import argparse
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C
import native


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'context'
        shutil.copytree(CONTEXT,self.root)

    def refused(self):
        with self.assertRaises((ValueError,OSError)):C.verify_context(self.root)

    def test_complete_context(self):
        self.assertEqual(len(C.verify_context(self.root)['packages']),8)

    def test_archive_tamper(self):
        p=self.root/'setup8.pkg.tar.xz';p.write_bytes(p.read_bytes()+b'bad');self.refused()

    def test_source_tamper(self):
        p=self.root/'sources/cachy-asahi-fish-config/config.fish';p.write_text('# substitute\n');self.refused()

    def test_staged_payload_tamper(self):
        p=self.root/'stage/usr/share/cachy-asahi/fish/config.fish';p.write_text('# substitute\n');self.refused()

    def test_staged_mode_tamper(self):
        (self.root/'stage/usr/bin/cachy-asahi-setup').chmod(0o777);self.refused()

    def test_extra_file(self):
        (self.root/'extra').write_text('unexpected');self.refused()

    def test_unknown_component(self):
        p=self.root/'context.json';v=json.loads(p.read_bytes());v['components'].append('arbitrary');C.save(p,v);self.refused()

    def test_symlink_source(self):
        p=self.root/'sources/cachy-asahi-fish-config/config.fish';p.unlink();p.symlink_to('/etc/passwd');self.refused()

    def test_native_refuses_actual_host_before_mutation(self):
        output=Path(self.temp.name)/'not-created'
        with self.assertRaisesRegex(ValueError,'marked disposable'):native.native(self.root,output,'invalid')
        self.assertFalse(output.exists())


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--context',type=Path,required=True);p.add_argument('--work',type=Path,required=True)
    a,remaining=p.parse_known_args();CONTEXT=a.context.absolute();WORK=a.work.absolute()
    unittest.main(argv=[sys.argv[0],*remaining])
