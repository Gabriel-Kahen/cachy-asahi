# SPDX-License-Identifier: MIT
"""Focused Source DATA controls. No build, library transaction or process actors."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('platform_source_prepare_tested', HERE / 'prepare.py')
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)


def deny(event, args):
    if event.startswith(('subprocess.', 'socket.')) or event in ('os.system', 'os.posix_spawn', 'os.fork', 'os.exec'):
        raise AssertionError('Source DATA control denied actor: ' + event)


sys.addaudithook(deny)


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Caller selects a retained local basis; this test never fetches or opens Git.
        cls.basis = Path(os.environ['PLATFORM_NATIVE_BASIS']).absolute()
        cls.value, cls.before, cls.after = P.render(cls.basis)
        cls.payload = P.tree(HERE / 'payload')

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='platform-source-data-')
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)

    def test_real_closed191_to199_and_original_runtime_caps(self):
        self.assertEqual(len(self.before), 191); self.assertEqual(len(self.after), 199)
        self.assertEqual(P.git_tree(self.after), self.value['source_tree'])
        self.assertEqual(self.after['native/common.py'], self.before['native/common.py'])
        changed = {n for n in self.after if self.after[n] != self.before.get(n)}
        self.assertEqual(changed, set(self.value['payload']))
        self.assertEqual(len(changed), 13)

    def test_complete_materialization_and_existing_output_preserved(self):
        target = self.root / 'trial'; stage = P.emit(self.basis, target)
        self.assertEqual(stage['pr_base'], 'main'); self.assertTrue(all(v is None for v in stage['actual'].values()))
        self.assertEqual(P.rows(P.tree(target / 'source')), self.value['after'])
        self.assertEqual(json.loads((target / 'source-modes.json').read_bytes()), {n: m for n, (_, m) in self.after.items()})
        self.assertEqual(len(json.loads((target / 'source-authorization.json').read_bytes())), 199)
        self.assertFalse(list(target.rglob('__pycache__')))
        marker = target / 'caller-file'; marker.write_bytes(b'caller-owned bytes')
        with self.assertRaisesRegex(ValueError, 'fresh output'):
            P.emit(self.basis, target)
        self.assertEqual(marker.read_bytes(), b'caller-owned bytes')

    def test_changed_basis_refuses_before_output(self):
        changed = dict(self.before); changed['native/common.py'] = (b'changed', 0o644)
        with patch.object(P, 'tree', return_value=changed), self.assertRaisesRegex(ValueError, 'genuine191 basis differs'):
            P.emit(self.basis, self.root / 'absent')
        self.assertFalse((self.root / 'absent').exists())

    def test_changed_native_payload_refuses(self):
        changed = dict(self.payload); name = 'native/platform_reader_v1.py'
        changed[name] = (changed[name][0] + b'\n# unbound\n', changed[name][1])
        with patch.object(P, 'tree', side_effect=[self.before, changed]), self.assertRaisesRegex(ValueError, 'finite native payload differs'):
            P.render(self.basis)

    def test_symlink_hardlink_and_empty_directory_refuse(self):
        root = self.root / 'source'; root.mkdir()
        target = root / 'file'; target.write_bytes(b'original')
        alias = root / 'alias'; alias.symlink_to('file')
        with self.assertRaises(ValueError): P.tree(root)
        alias.unlink(); os.link(target, alias)
        with self.assertRaises(ValueError): P.tree(root)
        alias.unlink(); (root / 'empty').mkdir()
        with self.assertRaisesRegex(ValueError, 'unexpected source directory'): P.tree(root)

    def test_output_overlap_and_insecure_parent_refuse(self):
        with self.assertRaisesRegex(ValueError, 'disjoint'):
            P.emit(self.basis, self.basis / 'nested-output')
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'owned0700'):
            P.emit(self.basis, self.root / 'absent')

    def test_concurrent_destination_is_never_replaced(self):
        target = self.root / 'raced'
        def race(_):
            target.mkdir(); (target / 'sentinel').write_bytes(b'foreign')
            return self.value, self.before, self.after
        with patch.object(P, 'render', side_effect=race), self.assertRaises(FileExistsError):
            P.emit(self.basis, target)
        self.assertEqual((target / 'sentinel').read_bytes(), b'foreign')
        self.assertFalse((target / 'source').exists())

    def test_whole_profile_pin_and_unsafe_names_refuse(self):
        with patch.object(P, 'PROFILE_SHA256', '0' * 64), self.assertRaisesRegex(ValueError, 'fixed Source profile'):
            P.profile()
        for name in ('../escape', '/absolute', 'a//b', '.git/config'):
            with self.assertRaises(ValueError): P.relative(name)


    def test_component_queue_keeps_multiple_pending_and_exact_job_body(self):
        aliases = P.WORKFLOW_ALIASES
        legacy = b'name: inert\nconcurrency:\n  group: native-arm-developer-workflows\n  cancel-in-progress: false\njobs:\n  native:\n    runs-on: ubuntu-24.04-arm\n    timeout-minutes: 135\n'
        raw = {aliases[0]: legacy, aliases[1]: legacy, 'native/held.py': b'INERT DATA'}
        scheduled = P.scheduled_workflows(raw)
        self.assertEqual(raw[aliases[0]], legacy)
        self.assertEqual(scheduled['native/held.py'], raw['native/held.py'])
        self.assertEqual(scheduled[aliases[0]], scheduled[aliases[1]])
        block = ('concurrency:\n  group: ' + P.CONCURRENCY_GROUP + '\n  cancel-in-progress: false\n  queue: max\njobs:\n').encode()
        before = b'concurrency:\n  group: native-arm-developer-workflows\n  cancel-in-progress: false\njobs:\n'
        self.assertEqual(scheduled[aliases[0]].replace(block, before, 1), legacy)
        self.assertEqual(P.CONCURRENCY_GROUP, 'native-arm-platform-tools')

    def test_unreviewed_existing_queue_group_and_duplicate_block_refuse(self):
        aliases = P.WORKFLOW_ALIASES
        legacy = b'name: inert\nconcurrency:\n  group: native-arm-developer-workflows\n  cancel-in-progress: false\njobs:\n'
        for bad in (legacy.replace(b'jobs:', b'  queue: max\njobs:'), legacy.replace(b'native-arm-developer-workflows', b'foreign-lane'), legacy + legacy):
            with self.subTest(raw=bad), self.assertRaisesRegex(ValueError, 'legacy concurrency'):
                P.scheduled_workflows({aliases[0]: bad, aliases[1]: bad})

    def test_mismatched_workflow_aliases_refuse_scheduling(self):
        with self.assertRaisesRegex(ValueError, 'aliases differ'):
            P.scheduled_workflows(dict(zip(P.WORKFLOW_ALIASES, (b'left', b'right'))))


if __name__ == '__main__':
    unittest.main(verbosity=2)
