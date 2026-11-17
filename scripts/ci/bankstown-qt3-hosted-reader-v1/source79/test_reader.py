# SPDX-License-Identifier: MIT
"""Genuine Source79 DATA and finite composition controls; no runtime authority.

Require --source79, or explicitly derive the deterministic unpublished Source79
DATA from genuine --source78 plus the exact maintained workflow. Only private
copies mutate. Archive delivery, Root grant and result identity are never faked.
"""
import argparse
from contextlib import contextmanager, redirect_stdout
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ACTORS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn',
                         'os.posix_spawn', 'os.fork')) or event in ('os.system', 'fcntl.flock'):
        ACTORS.append(event)
        raise AssertionError('SOURCE79_DATA_NO_OPERATIONAL_ROLE: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('source79_wrapper_controls', HERE / 'reader.py')
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)
SOURCE79 = SOURCE78 = None


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def snapshot(root):
    result = {}
    for path in root.rglob('*'):
        row = path.lstat()
        name = path.relative_to(root).as_posix()
        if stat.S_ISDIR(row.st_mode):
            result[name + '/'] = dict(mode=stat.S_IMODE(row.st_mode))
        else:
            if not stat.S_ISREG(row.st_mode):
                raise AssertionError('original fixture is ordinary DATA only')
            result[name] = dict(pin(path.read_bytes()), mode=stat.S_IMODE(row.st_mode), links=row.st_nlink)
    return result


def data_files(root):
    return {p.relative_to(root).as_posix(): (p.read_bytes(), stat.S_IMODE(p.lstat().st_mode))
            for p in root.rglob('*') if p.is_file()}


def independent_tree(files):
    def oid(kind, body):
        return hashlib.sha1(kind + b' ' + str(len(body)).encode() + b'\0' + body).digest()
    def directory(rows):
        leaves, children = [], {}
        for name, (raw, mode) in rows.items():
            if '/' in name:
                first, rest = name.split('/', 1)
                children.setdefault(first, {})[rest] = (raw, mode)
            else:
                prefix = b'100755' if mode == 0o755 else b'100644'
                leaves.append((name, False, prefix + b' ' + name.encode() + b'\0' + oid(b'blob', raw)))
        for name, rows in children.items():
            leaves.append((name, True, b'40000 ' + name.encode() + b'\0' + directory(rows)))
        return oid(b'tree', b''.join(row[2] for row in sorted(leaves, key=lambda r: (r[0] + ('/' if r[1] else '')).encode())))
    return directory(files).hex()


class GenuineSource79(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE79 is None and SOURCE78 is None:
            raise RuntimeError('explicit genuine --source79 or --source78 DATA required; no skipped PASS')
        cls.original = (SOURCE79 if SOURCE79 is not None else SOURCE78).resolve()
        cls.before = snapshot(cls.original)
        cls.tmp = tempfile.TemporaryDirectory(prefix='source79-reader-DATA-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = Path(cls.tmp.name) / 'source79'
        shutil.copytree(cls.original, cls.root)
        if SOURCE79 is None:
            legacy = W.legacy()
            legacy.source_readiness(cls.original)
            mapping = legacy.H.decoded((cls.root / 'source-map.json').read_bytes())
            workflow = cls.root / W.WORKFLOW
            workflow.parent.mkdir(parents=True)
            body = (W.LEGACY.parents[2] / W.WORKFLOW).read_bytes()
            if pin(body) != W.WORKFLOW_PIN:
                raise AssertionError('exact maintained workflow DATA required')
            workflow.write_bytes(body); workflow.chmod(0o644)
            mapping['files'][W.WORKFLOW] = dict(W.WORKFLOW_PIN, mode=0o644)
            raw = legacy.encoded(mapping)
            for name in W.ALIASES:
                (cls.root / name).write_bytes(raw); (cls.root / name).chmod(0o644)
        cls.files = data_files(cls.root)
        cls.mapping = json.loads(cls.files['source-map.json'][0])

    @classmethod
    def tearDownClass(cls):
        if snapshot(cls.original) != cls.before:
            raise AssertionError('original genuine DATA changed')
        if ACTORS:
            raise AssertionError('operational attempts: ' + repr(ACTORS))

    @contextmanager
    def changed(self, name, *, body=None, mode=None, symlink=False, hardlink=False):
        path = self.root / name
        before, bits = path.read_bytes(), stat.S_IMODE(path.lstat().st_mode)
        try:
            if symlink or hardlink:
                path.unlink()
                if symlink:
                    path.symlink_to(self.root / 'source-map.json')
                else:
                    import os
                    os.link(self.root / 'source-map.json', path)
            else:
                if body is not None: path.write_bytes(body)
                if mode is not None: path.chmod(mode)
            yield
        finally:
            if symlink or hardlink: path.unlink()
            path.write_bytes(before); path.chmod(bits)

    def test_exact_source79_tuple_and_actuals_remain_unissued(self):
        result = W.source_readiness(self.root)
        self.assertEqual(result['status'], 'PASS_SOURCE79_DATA_ONLY')
        self.assertEqual({k: result[k] for k in W.SOURCE79}, W.SOURCE79)
        self.assertEqual(len(self.files), 79)
        self.assertEqual(sum(len(raw) for raw, _ in self.files.values()), 35747849)
        self.assertEqual(independent_tree(self.files), W.SOURCE79['tree'])
        self.assertTrue(result['full_inverse']); self.assertTrue(result['workflow_gap_closed'])
        self.assertFalse(result['dispatch_ready'])
        self.assertTrue(all(v is None for v in result['actual'].values()))
        self.assertIsNone(result['Root_acceptance'])
        self.assertFalse(result['native_acceptance']); self.assertFalse(result['hardware_acceptance'])
        self.assertFalse(result['release_acceptance'])
        for key in ('source', 'legal', 'key_freshness', 'exact_Qt_recipe_correspondence'):
            self.assertEqual(result[key], 'HELD')
        self.assertEqual(result['original_Qt_minus2'], 'UNCHANGED')
        self.assertEqual(result['M2'], 'NOT_RUN')

    def test_exact_workflow_and_source78_inverse_only_remove_one_leaf(self):
        original = W.inverse_files(self.files)
        self.assertEqual(set(self.files) - set(original), {W.WORKFLOW})
        self.assertEqual(len(original), 78)
        self.assertEqual(pin(original['source-map.json'][0]), W.legacy().SOURCE78)
        self.assertEqual(original['source-map.json'], original['source.lock.json'])
        self.assertEqual(self.files[W.WORKFLOW], ((W.LEGACY.parents[2] / W.WORKFLOW).read_bytes(), 0o644))
        for name in set(original) - W.ALIASES:
            self.assertEqual(original[name], self.files[name])
        self.assertEqual(independent_tree(original), '5c2e5f8ea02ce1304684026bb8e2e06912b068d9')
        if SOURCE78 is not None:
            self.assertEqual(original, data_files(SOURCE78))

    def test_source72_and_prospective477_predicates_are_preserved(self):
        result = W.source_readiness(self.root)
        self.assertEqual(result['inverse_status'], 'PASS_SOURCE78_DATA_ONLY')
        self.assertEqual(result['preserved_Source72_members'], 70)
        joins = result['prospective_inventory_joins']
        self.assertEqual((joins['inventory_count'], joins['protected_count'], joins['catalog_count'], joins['addition_count']), (477, 349, 333, 128))
        self.assertIsNone(joins['Root_acceptance']); self.assertFalse(joins['native_acceptance'])

    def test_workflow_body_mode_and_alias_mutations_refuse(self):
        for name, body, mode in ((W.WORKFLOW, self.files[W.WORKFLOW][0] + b'\n', None),
                                 (W.WORKFLOW, None, 0o755), ('source.lock.json', self.files['source.lock.json'][0] + b'\n', None),
                                 ('source-map.json', None, 0o600)):
            with self.subTest(member=name), self.changed(name, body=body, mode=mode), self.assertRaises(ValueError):
                W.source_readiness(self.root)

    def test_preserved_runtime_catalog_and_old_member_mutations_refuse(self):
        for name in ('scripts/ci/bankstown-qt3-hosted-v1/hosted.py',
                     'scripts/ci/bankstown-qt3-native-source/owner.py',
                     'inputs/catalog333.DATA.json', 'inputs/prospective477.expected.DATA.lock'):
            with self.subTest(member=name), self.changed(name, body=self.files[name][0] + b'\n'), self.assertRaises(ValueError):
                W.source_readiness(self.root)

    def test_foreign_file_empty_directory_and_aliased_leaf_refuse(self):
        path = self.root / 'FOREIGN'
        path.mkdir()
        try:
            with self.assertRaises(ValueError): W.source_readiness(self.root)
        finally: path.rmdir()
        path.write_bytes(b'MODEL FOREIGN DATA')
        try:
            with self.assertRaises(ValueError): W.source_readiness(self.root)
        finally: path.unlink()
        for link in ('symlink', 'hardlink'):
            with self.subTest(link=link), self.changed(W.WORKFLOW, **{link: True}), self.assertRaises(ValueError):
                W.source_readiness(self.root)

    def test_git_metadata_exclusion_requires_explicit_checkout_mode(self):
        metadata = self.root / '.git'; metadata.mkdir()
        (metadata / 'MODEL_METADATA').write_bytes(b'MODEL_NOT_CREDENTIAL_DATA')
        try:
            with self.assertRaises(ValueError): W.source_readiness(self.root)
            self.assertTrue(W.source_readiness(self.root, allow_git_metadata=True)['full_inverse'])
        finally:
            (metadata / 'MODEL_METADATA').unlink(); metadata.rmdir()
        metadata.symlink_to(self.root / '.github', target_is_directory=True)
        try:
            with self.assertRaises(ValueError): W.source_readiness(self.root, allow_git_metadata=True)
        finally: metadata.unlink()

    def test_rehashed_model_outer_claim_cannot_change_inner_source78(self):
        # MODEL outer authenticity only: the independent old map remains fixed.
        files = dict(self.files); mapping = copy.deepcopy(self.mapping)
        name = 'scripts/ci/bankstown-qt3-native-source/owner.py'
        files[name] = (files[name][0] + b'\n', files[name][1])
        mapping['files'][name] = dict(pin(files[name][0]), mode=files[name][1])
        raw = W.legacy().encoded(mapping)
        for alias in W.ALIASES: files[alias] = (raw, 0o644)
        with self.assertRaisesRegex(ValueError, 'EXACT_CANONICAL_SOURCE78_INVERSE_MAP'):
            W.inverse_files(files)

    def test_inner_inverse_rejects_wrong_schema_nonnull_actual_and_extra_member(self):
        for mutate in (lambda m: m.update(schema=3), lambda m: m['actual'].update(source='a' * 40),
                       lambda m: m['files'].pop(W.WORKFLOW)):
            mapping = copy.deepcopy(self.mapping); mutate(mapping)
            raw = W.legacy().encoded(mapping); files = dict(self.files)
            for alias in W.ALIASES: files[alias] = (raw, 0o644)
            with self.assertRaises(ValueError): W.inverse_files(files)
        files = dict(self.files); files['FOREIGN'] = (b'foreign', 0o644)
        with self.assertRaises(ValueError): W.inverse_files(files)

    def test_frozen_reader_unchanged_and_only_private_admission_selectors_differ(self):
        original, selected = W.legacy(), W.admission_reader()
        self.assertEqual(pin((W.LEGACY / 'reader.py').read_bytes()), W.LEGACY_READER)
        self.assertEqual(pin((W.LEGACY / 'result.py').read_bytes()), W.LEGACY_RESULT)
        self.assertEqual(original.SOURCE78, dict(bytes=15363, sha256='dc3197203a91bdcd98cdd98f4f672d05abbc6865e26f2b744c3646c1b4d761eb'))
        self.assertEqual(selected.SOURCE78, W.SOURCE79['source_map'])
        for name in ('admit_inputs', 'complete_inputs', 'workflow_binding', 'selected', 'qualify_result'):
            self.assertEqual(getattr(original, name).__code__, getattr(selected, name).__code__, name)
        self.assertTrue(selected.source_readiness(self.root)['workflow_gap_closed'])

    def test_wrapper_delegates_model_kwargs_without_weakening_or_result_relabel(self):
        # MODEL dispatch boundary only; no grant/input/body acceptance is claimed.
        arguments = dict(source_root=self.root, request_path=self.root / 'MODEL-request',
                         request_sha256='0' * 64, provider={}, context={}, workflow={}, registration={}, now=1)
        callback = SimpleNamespace(admit_inputs=lambda **kw: kw)
        with patch.object(W, 'admission_reader', return_value=callback):
            self.assertEqual(W.admit_inputs(**arguments), arguments)
        with self.assertRaisesRegex(ValueError, 'EXTERNALLY_SELECTED_SOURCE79_READER'):
            W.qualify_result({}, {}, reader_pin=dict(bytes=1, sha256='0' * 64))
        with tempfile.TemporaryDirectory(prefix='source79-helper-MODEL-') as temporary:
            here = Path(temporary); (here / 'reader.py').write_bytes(b'raise AssertionError("UNREVIEWED")\n')
            (here / 'result.py').write_bytes(b'raise AssertionError("UNREVIEWED")\n')
            with patch.object(W, 'LEGACY', here), self.assertRaisesRegex(ValueError, 'FROZEN_READER_PROGRAM_PIN'):
                W.legacy()
            with patch.object(W, 'LEGACY', here), self.assertRaisesRegex(ValueError, 'FROZEN_READER_PROGRAM_PIN'):
                W.qualify_result({}, {}, reader_pin=pin(Path(W.__file__).read_bytes()))

    def test_cli_source_keeps_authority_and_native_acceptance_unissued(self):
        output = io.StringIO()
        with patch.object(sys, 'argv', [str(HERE / 'reader.py'), 'source', '--source-root', str(self.root)]), redirect_stdout(output):
            W.main()
        report = json.loads(output.getvalue())
        self.assertEqual(report['status'], 'PASS_SOURCE79_DATA_ONLY')
        self.assertFalse(report['dispatch_ready']); self.assertFalse(report['native_acceptance'])

    def test_no_actor_attempt_and_original_fixture_unchanged(self):
        self.assertEqual(ACTORS, [])
        self.assertEqual(snapshot(self.original), self.before)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument('--source79', type=Path)
    choice.add_argument('--source78', type=Path)
    options, remaining = parser.parse_known_args()
    SOURCE79, SOURCE78 = options.source79, options.source78
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
