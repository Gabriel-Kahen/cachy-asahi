#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-free full Source reproduction and refusal controls."""
import ast
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


    def test_component_queue_keeps_multiple_pending_and_exact_job_body(self):
        aliases = F.WORKFLOW_ALIASES
        legacy = b'name: inert\nconcurrency:\n  group: native-arm-developer-workflows\n  cancel-in-progress: false\njobs:\n  native:\n    runs-on: ubuntu-24.04-arm\n    timeout-minutes: 135\n'
        raw = {aliases[0]: legacy, aliases[1]: legacy, 'native/held.py': b'INERT DATA'}
        scheduled = F.scheduled_workflows(raw)
        self.assertEqual(raw[aliases[0]], legacy)
        self.assertEqual(scheduled['native/held.py'], raw['native/held.py'])
        self.assertEqual(scheduled[aliases[0]], scheduled[aliases[1]])
        block = ('concurrency:\n  group: ' + F.CONCURRENCY_GROUP + '\n  cancel-in-progress: false\n  queue: max\njobs:\n').encode()
        before = b'concurrency:\n  group: native-arm-developer-workflows\n  cancel-in-progress: false\njobs:\n'
        self.assertEqual(scheduled[aliases[0]].replace(block, before, 1), legacy)
        self.assertEqual(F.CONCURRENCY_GROUP, 'native-arm-image-tools')

    def test_unreviewed_existing_queue_group_and_duplicate_block_refuse(self):
        aliases = F.WORKFLOW_ALIASES
        legacy = b'name: inert\nconcurrency:\n  group: native-arm-developer-workflows\n  cancel-in-progress: false\njobs:\n'
        for bad in (legacy.replace(b'jobs:', b'  queue: max\njobs:'), legacy.replace(b'native-arm-developer-workflows', b'foreign-lane'), legacy + legacy):
            with self.subTest(raw=bad), self.assertRaisesRegex(ValueError, 'legacy concurrency'):
                F.scheduled_workflows({aliases[0]: bad, aliases[1]: bad})

    def test_mismatched_workflow_aliases_refuse_scheduling(self):
        with self.assertRaisesRegex(ValueError, 'aliases differ'):
            F.scheduled_workflows(dict(zip(F.WORKFLOW_ALIASES, (b'left', b'right'))))


    def test_producer_cleanup_exact_five_file_delta_and_observer_inverse(self):
        bodies = (F.snapshot(self.parent, checkout=True)[1] | F.snapshot(F.HERE / 'payload')[1])
        result = F.retired_producer(bodies)
        self.assertEqual({n for n in result if result[n] != bodies[n]}, set(F.PRODUCER_AFTER))
        for name, row in F.PRODUCER_AFTER.items():
            self.assertEqual(len(result[name]), row['bytes'])
            self.assertEqual(hashlib.sha256(result[name]).hexdigest(), row['sha256'])
        old = b'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898'
        new = b'8e71ba83e7d5037c6f7772401ec3b872684ccfa8472d855d8d6d3052cb1f41ba'
        self.assertEqual(result['native/failure_retention.py'].count(new), 1)
        self.assertNotIn(old, result['native/failure_retention.py'])
        self.assert_component_producer_pins(result)
        self.assertEqual(bodies, (F.snapshot(self.parent, checkout=True)[1] | F.snapshot(F.HERE / 'payload')[1]))

    def test_changed_immutable_producer_helper_refuses(self):
        bodies = (F.snapshot(self.parent, checkout=True)[1] | F.snapshot(F.HERE / 'payload')[1])
        rows, overlay = F.snapshot(F.HERE / 'producer-overlay')
        rows = dict(rows); rows['bootstrap/scripts/ci/native_arm.py'] = dict(rows['bootstrap/scripts/ci/native_arm.py'], sha256='0'*64)
        with patch.object(F, 'snapshot', return_value=(rows, overlay)), self.assertRaisesRegex(ValueError, 'retirement overlay differs'):
            F.retired_producer(bodies)

    def test_stale_strict_observer_input_refuses(self):
        bodies = dict((F.snapshot(self.parent, checkout=True)[1] | F.snapshot(F.HERE / 'payload')[1]))
        bodies['native/failure_retention.py'] += b'\n# stale observer\n'
        with self.assertRaisesRegex(ValueError, 'producer/observer inputs differ'):
            F.retired_producer(bodies)


    def test_stale_strict_observer_overlay_refuses(self):
        bodies = (F.snapshot(self.parent, checkout=True)[1] | F.snapshot(F.HERE / 'payload')[1])
        rows, overlay = F.snapshot(F.HERE / 'producer-overlay'); rows, overlay = dict(rows), dict(overlay)
        old = b'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898'
        new = b'8e71ba83e7d5037c6f7772401ec3b872684ccfa8472d855d8d6d3052cb1f41ba'
        overlay['native/failure_retention.py'] = overlay['native/failure_retention.py'].replace(new, old, 1)
        raw = overlay['native/failure_retention.py']; rows['native/failure_retention.py'] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), mode=420)
        with patch.object(F, 'snapshot', return_value=(rows, overlay)), self.assertRaisesRegex(ValueError, 'retirement overlay differs'):
            F.retired_producer(bodies)


    def assert_component_producer_pins(self, bodies):
        maps = []
        for name in ('native/image_reader_v1.py', 'native/image_projection_v1.py'):
            selected = [node.value for node in ast.parse(bodies[name]).body if isinstance(node, ast.Assign)
                        and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'PRODUCERS']
            self.assertEqual(len(selected), 1)
            maps.append(ast.literal_eval(selected[0]))
        self.assertEqual(maps[0], maps[1])
        self.assertEqual(maps[0]['native/image_alpm_v1.py'], hashlib.sha256(bodies['native/image_alpm_v1.py']).hexdigest())

    def test_combined_old_alpm_reader_pin_refuses(self):
        bodies = F.retired_producer((F.snapshot(self.parent, checkout=True)[1] | F.snapshot(F.HERE / 'payload')[1]))
        name = 'native/image_reader_v1.py'
        current = hashlib.sha256(bodies['native/image_alpm_v1.py']).hexdigest().encode()
        bodies[name] = bodies[name].replace(current, b'1f88ed10057cadfd99fe84822aa3f5e283f25baa1da948b42f9b01d6683a6cba', 1)
        with self.assertRaises(AssertionError):
            self.assert_component_producer_pins(bodies)

    def test_combined_old_alpm_projector_pin_refuses(self):
        bodies = F.retired_producer((F.snapshot(self.parent, checkout=True)[1] | F.snapshot(F.HERE / 'payload')[1]))
        name = 'native/image_projection_v1.py'
        current = hashlib.sha256(bodies['native/image_alpm_v1.py']).hexdigest().encode()
        bodies[name] = bodies[name].replace(current, b'1f88ed10057cadfd99fe84822aa3f5e283f25baa1da948b42f9b01d6683a6cba', 1)
        with self.assertRaises(AssertionError):
            self.assert_component_producer_pins(bodies)


    def test_control_checkout_excludes_non_source_git_object_metadata(self):
        checkout = self.root / 'real-checkout'
        shutil.copytree(self.parent, checkout, ignore=shutil.ignore_patterns('.git'))
        metadata = checkout / '.git/objects/pack/fixture.idx'
        metadata.parent.mkdir(parents=True)
        metadata.write_bytes(b'NON_SOURCE_GIT_METADATA\n'); metadata.chmod(0o444)
        # Raw Source validation remains strict. Only the existing checkout mode
        # excludes Git's bookkeeping, exactly as production assemble() does.
        with self.assertRaisesRegex(ValueError, 'source mode'):
            F.snapshot(checkout)
        original = self.parent
        self.parent = checkout
        try:
            for name in (
                'test_changed_immutable_producer_helper_refuses',
                'test_combined_old_alpm_projector_pin_refuses',
                'test_combined_old_alpm_reader_pin_refuses',
                'test_producer_cleanup_exact_five_file_delta_and_observer_inverse',
                'test_stale_strict_observer_input_refuses',
                'test_stale_strict_observer_overlay_refuses'):
                with self.subTest(control=name):
                    getattr(self, name)()
        finally:
            self.parent = original


if __name__=='__main__':
    unittest.main(verbosity=2)
