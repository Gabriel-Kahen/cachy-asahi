#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-free full Source reproduction and refusal controls."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('image_source_factory',HERE/'prepare.py')
F = importlib.util.module_from_spec(spec);spec.loader.exec_module(F)


def deny(event,args):
    if event in ('subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','os.kill','os.killpg','socket.__new__','socket.connect'):
        raise AssertionError('Source control actor forbidden: '+event)
sys.addaudithook(deny)


class Factory(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parent = Path(os.environ['IMAGE_TOOLS_PARENT']).resolve()
        cls.policy = F.profile()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='image-factory-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root/'source'

    def test_complete_exact_source_reproduction_and_workflow_checksums(self):
        result = F.assemble(self.parent,self.output)
        actual,bodies = F.snapshot(self.output)
        self.assertEqual(actual,self.policy['expected']['files'])
        self.assertEqual(F.tree_id(bodies,{n:r['mode'] for n,r in actual.items()}),self.policy['expected']['tree'])
        self.assertEqual(result['files'],202)
        self.assertEqual(result['actual'],dict(source=None,ref=None,run=None))
        for alias in ('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-developer-workflows.yml'):
            self.assertIn(hashlib.sha256(bodies['native/common.py']).hexdigest().encode(),bodies[alias])
        self.assertEqual(bodies['.github/workflows/native-arm-build.yml'],bodies['.github/workflows/native-arm-developer-workflows.yml'])
        self.assertIn("default='source184'",bodies['native/owner.py'].decode())
        for held in ('native/capsule.py','native/safe_diagnostic.py','native/transport_proof.py','native/retained_transport.py','native/input-profile.json'):
            self.assertEqual(bodies[held],(self.parent/held).read_bytes())

    def test_incomplete_parent_refuses_before_output(self):
        parent=self.root/'bad-parent';parent.mkdir();(parent/'README.md').write_bytes(b'NOT THE NATIVE PARENT\n')
        with self.assertRaisesRegex(ValueError,'complete exact parent'):
            F.assemble(parent,self.output)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_preserved(self):
        self.output.write_bytes(b'CALLER DATA\n')
        with self.assertRaisesRegex(ValueError,'fresh ordinary output'):
            F.assemble(self.parent,self.output)
        self.assertEqual(self.output.read_bytes(),b'CALLER DATA\n')

    def test_parent_alias_refuses_before_output(self):
        alias=self.root/'alias';alias.symlink_to(self.parent,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'ordinary source root'):
            F.assemble(alias,self.output)
        self.assertFalse(self.output.exists())

    def test_extra_or_changed_maintained_operand_refuses(self):
        local=self.root/'factory';shutil.copytree(HERE,local)
        target=local/'payload/native/image_guest_v1.py';target.write_bytes(target.read_bytes()+b'\n# changed\n')
        with patch.object(F,'HERE',local),self.assertRaisesRegex(ValueError,'complete fixed payload'):
            F.assemble(self.parent,self.output)
        self.assertFalse(self.output.exists())

    def test_profile_tamper_refuses_before_parent_read(self):
        local=self.root/'factory';local.mkdir();(local/'profile.json').write_bytes(b'{}\n')
        with patch.object(F,'HERE',local),self.assertRaisesRegex(ValueError,'whole fixed source profile'):
            F.assemble(self.root/'missing-parent',self.output)
        self.assertFalse(self.output.exists())

    def test_special_member_and_hardlink_are_never_read(self):
        path=self.root/'data';path.write_bytes(b'small source\n');os.link(path,self.root/'hardlink')
        with self.assertRaisesRegex(ValueError,'single-link'):
            F.read(path)
        fifo=self.root/'fifo';os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError,'ordinary single-link'):
            F.read(fifo)

    def test_parent_source_is_data_not_executed(self):
        # This exact selected parent contains launchers and actor code; construction
        # runs under a process/socket audit guard and only reads/copies pinned bytes.
        self.assertEqual(self.policy['parent']['commit'],'111f14d2b21b220d86912d5ead978848c7ef1cb0')
        self.assertEqual(self.policy['expected']['actual'],dict(source=None,ref=None,run=None))
        for leaf in self.policy['payload']:
            self.assertNotIn('packages/tools/',leaf)
        self.assertEqual(self.policy['target_base'],'main')


if __name__=='__main__':
    unittest.main(verbosity=2)
