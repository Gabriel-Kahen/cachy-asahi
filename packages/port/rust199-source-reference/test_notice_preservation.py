# SPDX-License-Identifier: MIT
"""Portable DATA controls; no native build, package installation or legal acceptance."""
import ast
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('notice_preservation', HERE / 'notice_preservation.py')
n = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(n)
PAYLOAD = HERE.parents[2] / 'scripts/ci/rust199-source-reference-native/successor_v7/payload/packages/port/rust199-source-reference'


class NoticeControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='FENCED-notices-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.body = b'// Copyright 2017 The Rust Project Developers.\n// FENCED test body, not an upstream grant.\n'
        self.names = ['rustc-1.99.0-src/vendor/fenced-1/src/a.rs', 'rustc-1.99.0-src/vendor/fenced-1/src/b.rs']
        self.archive = self.root / 'source.tar.xz'
        self.make_archive([(name, self.body, tarfile.REGTYPE) for name in self.names])
        self.value = dict(schema=1, scope=n.SCOPE, holds_preserved=True, Root_review=None, accepted=None,
                          source_archive=n.pin(self.archive.read_bytes()), components=[],
                          files={name: dict(**n.pin(self.body), contexts=[dict(lines=[1, 2], text=self.body.decode(), classification='FENCED')]) for name in self.names})
        self.catalogue = self.root / 'catalogue.json'
        self.save()
    def make_archive(self, rows):
        with tarfile.open(self.archive, 'w:xz') as tar:
            for name, body, kind in rows:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = len(body) if kind == tarfile.REGTYPE else 0
                info.linkname = '/etc/passwd' if kind == tarfile.SYMTYPE else ''
                tar.addfile(info, io.BytesIO(body) if info.size else None)
    def save(self):
        self.catalogue.write_bytes(n.encode(self.value))
        self.expected = hashlib.sha256(self.catalogue.read_bytes()).hexdigest()
    def stage(self, name='out'):
        return n.stage(self.archive, self.catalogue, self.root / name, self.expected)
    def test_authentic_bytes_dedup_and_all_provenance(self):
        result = self.stage()
        self.assertEqual(list(result['paths']), sorted(self.names))
        self.assertEqual(len(list((self.root / 'out/bodies').iterdir())), 1)
        for row in result['paths'].values():
            self.assertEqual((self.root / 'out' / row['body']).read_bytes(), self.body)
            self.assertEqual(row['sha256'], n.pin(self.body)['sha256'])
        self.assertFalse(result['manifest_authors_are_owners'])
        self.assertTrue(result['holds_preserved'])
        self.assertEqual((self.root / 'out/catalogue.DATA.json').read_bytes(), self.catalogue.read_bytes())
    def test_output_determinism(self):
        self.stage('one')
        self.stage('two')
        def tree(name):
            return {str(p.relative_to(self.root / name)): p.read_bytes() for p in (self.root / name).rglob('*') if p.is_file()}
        self.assertEqual(tree('one'), tree('two'))
    def test_changed_catalogue_or_archive_refuses_before_output(self):
        self.catalogue.write_bytes(self.catalogue.read_bytes() + b' ')
        with self.assertRaises(ValueError): self.stage()
        self.save()
        self.archive.write_bytes(self.archive.read_bytes() + b'changed')
        with self.assertRaises(ValueError): self.stage()
        self.assertFalse((self.root / 'out').exists())
    def test_unsafe_path_oversize_and_context_drift_refuse(self):
        original = copy.deepcopy(self.value)
        for mutation in ('unsafe', 'oversize', 'context', 'missing'):
            self.value = copy.deepcopy(original)
            if mutation == 'unsafe': self.value['files']['rustc-1.99.0-src/vendor/../escape'] = self.value['files'].pop(self.names[0])
            if mutation == 'oversize': self.value['files'][self.names[0]]['bytes'] = n.MAX_FILE + 1
            if mutation == 'context': self.value['files'][self.names[0]]['contexts'][0]['text'] = 'changed'
            if mutation == 'missing': self.value['files'][self.names[0].replace('a.rs', 'absent.rs')] = self.value['files'].pop(self.names[0])
            self.save()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.stage()
            self.assertFalse((self.root / 'out').exists())
    def test_duplicate_link_and_wrong_wholefile_refuse(self):
        for mutation in ('duplicate', 'link', 'hash'):
            rows = [(name, self.body, tarfile.REGTYPE) for name in self.names]
            if mutation == 'duplicate': rows.append(rows[0])
            if mutation == 'link': rows[0] = (self.names[0], b'', tarfile.SYMTYPE)
            if mutation == 'hash': rows[0] = (self.names[0], b'X' * len(self.body), tarfile.REGTYPE)
            self.make_archive(rows)
            self.value['source_archive'] = n.pin(self.archive.read_bytes())
            self.save()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.stage()
    def test_input_aliases_and_missing_refuse(self):
        for mutation in ('symlink', 'hardlink', 'missing', 'oversize'):
            path = self.root / mutation
            if mutation == 'symlink': path.symlink_to(self.catalogue)
            if mutation == 'hardlink': os.link(self.catalogue, path)
            if mutation == 'oversize': path.write_bytes(b'x' * (n.MAX_CATALOGUE + 1))
            with self.subTest(mutation=mutation), self.assertRaises((OSError, ValueError)):
                n.catalogue(path, self.expected)
            if path.exists() or path.is_symlink(): path.unlink()
    def test_existing_or_aliased_destination_refuses(self):
        (self.root / 'out').mkdir()
        with self.assertRaises(ValueError): self.stage()
        (self.root / 'alias').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): n.stage(self.archive, self.catalogue, self.root / 'alias/out2', self.expected)
    def with_grant(self):
        grant = b'Copyright 2023 FENCED retained evidence. No test legal grant.\n'
        digest = n.pin(grant)['sha256']
        self.value['retained_upstream_grant_bodies'] = {digest: dict(**n.pin(grant), text=grant.decode(), path='/FENCED/retained-original-grant')}
        self.value['components'] = [dict(component='fenced-1', retained_exact_upstream_grant_bodies=[digest])]
        self.value['grant_scope'] = 'FENCED component-scoped prior evidence, not a package-wide grant'
        self.save()
        return digest, grant
    def test_retained_grant_body_and_distinct_provenance_are_preserved(self):
        digest, grant = self.with_grant()
        result = self.stage()
        row = result['retained_grants'][digest]
        self.assertEqual((self.root / 'out' / row['body']).read_bytes(), grant)
        self.assertEqual(row['retained_evidence_path'], '/FENCED/retained-original-grant')
        self.assertEqual(row['components'], ['fenced-1'])
        self.assertEqual(row['scope'], self.value['grant_scope'])
    def test_changed_grant_body_or_component_provenance_refuses(self):
        digest, grant = self.with_grant()
        original = copy.deepcopy(self.value)
        for mutation in ('body', 'binding'):
            self.value = copy.deepcopy(original)
            if mutation == 'body': self.value['retained_upstream_grant_bodies'][digest]['text'] += 'changed'
            else: self.value['components'][0]['retained_exact_upstream_grant_bodies'] = []
            self.save()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.stage()
            self.assertFalse((self.root / 'out').exists())
    def test_overlay_changes_only_package_notice_hook(self):
        self.assertEqual((PAYLOAD / 'notice_preservation.py').read_bytes(), (HERE / 'notice_preservation.py').read_bytes())
        before = ast.parse((HERE / 'reference.py').read_bytes())
        after = ast.parse((PAYLOAD / 'reference.py').read_bytes())
        original = next(node for node in before.body if isinstance(node, ast.FunctionDef) and node.name == 'package')
        proposed = next(node for node in after.body if isinstance(node, ast.FunctionDef) and node.name == 'package')
        self.assertEqual(ast.dump(ast.Module(body=proposed.body[:len(original.body)-1], type_ignores=[])), ast.dump(ast.Module(body=original.body[:-1], type_ignores=[])))
        self.assertEqual(ast.dump(proposed.body[-1]), ast.dump(original.body[-1]))
        proposed.body = original.body
        self.assertEqual(ast.dump(before), ast.dump(after))
    def test_package_hook_stages_alongside_existing_grants(self):
        spec = importlib.util.spec_from_file_location('proposed_notice_recipe', PAYLOAD / 'reference.py')
        recipe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(recipe)
        work = self.root / 'work'
        work.mkdir()
        (work / 'dest').mkdir()
        rust = work / 'rustc-1.99.0-src'
        rust.mkdir()
        for name in ('COPYRIGHT', 'LICENSE-MIT', 'LICENSE-APACHE'): (rust / name).write_text('FENCED ' + name)
        for name in ('compiler-rt', 'libunwind'):
            p = work / 'llvm-project-23.1.1.src' / name
            p.mkdir(parents=True)
            (p / 'LICENSE.TXT').write_text('FENCED ' + name)
        receipt = dict(admission_sha256='FENCED', config_sha256=recipe.digest(PAYLOAD / 'bootstrap.toml') if (PAYLOAD / 'bootstrap.toml').exists() else recipe.digest(HERE / 'bootstrap.toml'), staged_tree_sha256=recipe.tree_digest(work / 'dest'))
        (work / 'built.json').write_text(json.dumps(receipt))
        dest = self.root / 'pkg'
        dest.mkdir()
        # Only fixture receipt/config paths are projected; execute the actual proposed package hook.
        old_digest = recipe.digest
        def digest(path):
            if path == PAYLOAD / 'bootstrap.toml': return receipt['config_sha256']
            return old_digest(path)
        old_copy = recipe.shutil.copyfile
        def copyfile(source, target):
            if source.parent == PAYLOAD and source.name in ('inputs.json', 'LICENSE.packaging'):
                source = HERE / source.name
            return old_copy(source, target)
        original_exec = importlib.machinery.SourceFileLoader.exec_module
        calls = []
        def exec_module(loader, module):
            original_exec(loader, module)
            def fixture_stage(*args):
                calls.append(args)
                return n.stage(self.archive, self.catalogue, args[2], self.expected)
            module.stage = fixture_stage
        with patch.object(recipe, 'check_stage'), patch.object(recipe, 'digest', side_effect=digest), patch.object(recipe.shutil, 'copyfile', side_effect=copyfile), patch.dict(os.environ, {'CACHY_ASAHI_RUST199_ADMISSION_SHA256': 'FENCED'}), patch.object(importlib.machinery.SourceFileLoader, 'exec_module', exec_module):
            recipe.package(work, dest)
        notices = dest / recipe.PREFIX.relative_to('/') / 'share/licenses/rust199-source-reference'
        self.assertEqual((notices / 'COPYRIGHT').read_text(), 'FENCED COPYRIGHT')
        self.assertEqual((notices / 'source-notices' / 'bodies' / (n.pin(self.body)['sha256'] + '.txt')).read_bytes(), self.body)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], work / 'verified-materials/rustc-1.99.0-src.tar.xz')
        self.assertEqual(calls[0][2], notices / 'source-notices')


if __name__ == '__main__':
    unittest.main()
