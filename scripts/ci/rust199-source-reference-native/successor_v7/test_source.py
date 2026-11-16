# SPDX-License-Identifier: MIT
"""Notice constructor DATA controls; no candidate, actor, Reader or native execution."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('notice_source_proposal', HERE / 'prepare.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class SourceControls(unittest.TestCase):
    def fixture(self):
        before = {p.PREFIX + 'reference.py': (b'FENCED old package source', 0o644),
                  'actor/entry.py': (b'FENCED unchanged actor', 0o644),
                  'resource-policy.json': (b'FENCED unchanged resources', 0o644),
                  'root-admission.TEMPLATE.json': (b'FENCED unchanged authority', 0o644)}
        before['source-map.json'] = (p.encode(dict(schema=1, operation='FENCED', actual=p.ACTUAL,
                                                  files=p.fs.descriptors(before))), 0o644)
        parent = dict(files=len(before), bytes=sum(len(r) for r, m in before.values()), tree=p.fs.tree(before),
                      map_sha256=p.fs.pin(before['source-map.json'][0])['sha256'], factory_commit='FENCED')
        return before, parent
    def test_only_notice_leaves_change_and_inverse_is_complete(self):
        before, parent = self.fixture()
        with patch.object(p, 'PARENT', parent):
            after = p.render(before)
            self.assertEqual(set(after) - set(before), {p.PREFIX + 'notice_preservation.py', p.PREFIX + 'notice-catalogue.DATA.json', p.REVISION})
            for name in ('actor/entry.py', 'resource-policy.json', 'root-admission.TEMPLATE.json'):
                self.assertEqual(after[name], before[name])
            marker = json.loads(after[p.REVISION][0])
            self.assertFalse(marker['operational'])
            self.assertEqual(marker['pending'], 'COORDINATOR_SUCCESSOR_CANDIDATE_BINDING_REQUIRED')
            self.assertEqual(p.undo(after, before, marker), before)
    def test_changed_map_notice_and_protected_source_refuse_inverse(self):
        before, parent = self.fixture()
        with patch.object(p, 'PARENT', parent):
            after = p.render(before)
            marker = json.loads(after[p.REVISION][0])
            for name in ('source-map.json', p.PREFIX + 'reference.py', 'actor/entry.py', p.REVISION):
                bad = dict(after)
                bad[name] = (b'FENCED changed', 0o644)
                with self.subTest(name=name), self.assertRaises(ValueError): p.undo(bad, before, marker)
            bad = dict(after)
            bad['actor/entry.py'] = (b'FENCED changed', 0o644)
            body = json.loads(bad['source-map.json'][0])
            body['files'] = p.fs.descriptors({n: row for n, row in bad.items() if n != 'source-map.json'})
            bad['source-map.json'] = (p.encode(body), 0o644)
            with self.assertRaises(ValueError): p.undo(bad, before, marker)
    def test_wrong_parent_refuses_before_render(self):
        with self.assertRaises(ValueError): p.render({})
    def test_whole_parent_capture_and_input_alias_refusal(self):
        before, parent = self.fixture()
        with tempfile.TemporaryDirectory(prefix='FENCED-notice-parent-') as directory:
            root = Path(directory)
            for name, (raw, mode) in before.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                path.chmod(mode)
            with patch.object(p, 'PARENT', parent):
                self.assertEqual(p.capture(root), before)
                (root / 'actor/entry.py').write_bytes(b'FENCED changed')
                with self.assertRaises(ValueError): p.capture(root)
                (root / 'actor/entry.py').unlink()
                (root / 'actor/entry.py').symlink_to(root / 'resource-policy.json')
                with self.assertRaises((OSError, ValueError)): p.capture(root)
    def test_complete_constructor_and_wrong_profile_existing_output_refusals(self):
        before, parent = self.fixture()
        with tempfile.TemporaryDirectory(prefix='FENCED-notice-constructor-') as directory:
            root = Path(directory)
            parent_root, constructor = root / 'parent', root / 'constructor'
            parent_root.mkdir()
            constructor.mkdir()
            for name, (raw, mode) in before.items():
                path = parent_root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                path.chmod(mode)
            for name, (raw, mode) in p.fs.snapshot(HERE / 'payload').items():
                path = constructor / 'payload' / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
                path.chmod(mode)
            with patch.object(p, 'PARENT', parent), patch.object(p, 'HERE', constructor):
                files = p.render(before)
                profile = dict(schema=7, operational=False, actual=p.ACTUAL, parent=parent, scope=p.SCOPE,
                               constructor_files=p.inputs(), files=len(files), bytes=sum(len(raw) for raw, _ in files.values()),
                               tree=p.fs.tree(files), map_sha256=p.fs.pin(files['source-map.json'][0])['sha256'])
                raw = p.encode(profile)
                (constructor / 'constructor-profile.json').write_bytes(raw)
                expected = p.fs.pin(raw)['sha256']
                with self.assertRaises(ValueError): p.construct(parent_root, root / 'wrong-profile', '0' * 64)
                self.assertFalse((root / 'wrong-profile').exists())
                result = p.construct(parent_root, root / 'output', expected)
                self.assertFalse(result['operational'])
                self.assertEqual(p.fs.snapshot(root / 'output'), files)
                with self.assertRaises((OSError, ValueError)): p.construct(parent_root, root / 'output', expected)
                with self.assertRaises(ValueError): p.construct(parent_root, constructor / 'overlap', expected)
    def test_payload_has_no_build_actor_or_authority_changes(self):
        rows = p.fs.snapshot(HERE / 'payload')
        self.assertEqual(set(rows), p.LEAVES)
        value = json.loads(rows[p.PREFIX + 'notice-catalogue.DATA.json'][0])
        self.assertEqual(value['catalogue_basis']['seal_sha256'], p.SEAL)
        self.assertIsNone(value['Root_review'])
        self.assertIsNone(value['accepted'])
        self.assertEqual(len(value['files']), 425)


if __name__ == '__main__':
    unittest.main()
