# SPDX-License-Identifier: MIT
"""Fenced synthetic Source/capsule DATA tests; no held code, package or role runs."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def data_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


p = data_module('lifecycle_source_data_test', HERE/'prepare.py')
capsule = data_module('lifecycle_capsule_data_test', HERE/'payload/hosted/capsule.py')
common = data_module('lifecycle_common_definition_test', HERE/'payload/hosted/common.py')


def put(root, name, body, mode=0o644):
    path = root/name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    path.chmod(mode)
    return path


def envelope(entries):
    """Small opaque fixtures only; never package/source publisher archives."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:', format=tarfile.PAX_FORMAT) as output:
        for name, body, mode, kind in entries:
            item = tarfile.TarInfo(name)
            item.mode, item.mtime, item.uid, item.gid = mode, 1791748800, 0, 0
            item.type = kind
            item.size = len(body) if kind == tarfile.REGTYPE else 0
            if kind == tarfile.SYMTYPE:
                item.linkname = '/dev/null'
            output.addfile(item, io.BytesIO(body) if kind == tarfile.REGTYPE else None)
    return buffer.getvalue()


def material_fixture(root, entries=None):
    source = root/'source'
    work = root/'work'
    source.mkdir()
    work.mkdir()
    bodies = {'data.txt':b'PASSIVE DATA ONLY\n', 'source-map.json':b'{"fixture":"not a Root source"}\n'}
    members = {name:dict(**p.fs.pin(body),mode=0o444) for name,body in bodies.items()}
    if entries is None:
        entries = [('capsule/'+name,body,0o444,tarfile.REGTYPE) for name,body in bodies.items()]
    raw = envelope(entries)
    contract = dict(capsule=dict(**p.fs.pin(raw),members=members,source_map_sha256=p.fs.pin(bodies['source-map.json'])['sha256']))
    put(source,'lifecycle-capsule.tar',raw)
    put(source,'contract.json',p.encode(contract))
    return source,work,contract,bodies


class SourceDataTests(unittest.TestCase):
    def test_unreviewed_refuses_before_held_code_filesystem_or_archive(self):
        review = HERE/'prerequisites.TEMPLATE.json'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(p,'held_code') as held, patch.object(p,'module') as imported, patch.object(p.fs,'snapshot') as scanned, patch.object(p,'capsule_tar') as packed:
                with self.assertRaisesRegex(ValueError,'unreviewed'):
                    p.render(root/'not-opened-frozen',root/'not-imported-held',review,hashlib.sha256(review.read_bytes()).hexdigest())
                held.assert_not_called()
                imported.assert_not_called()
                scanned.assert_not_called()
                packed.assert_not_called()

    def test_constructor_missing_review_cannot_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(p.fs,'publish') as published:
                with self.assertRaises(FileNotFoundError):
                    p.construct(root/'frozen',root/'component',root/'missing-review.json','a'*64,root/'not-created')
                published.assert_not_called()
                self.assertFalse((root/'not-created').exists())

    def test_generated_and_hosted_actual_selectors_match_and_remain_null(self):
        self.assertEqual(p.ACTUAL,common.ACTUAL)
        self.assertTrue(all(value is None for value in p.ACTUAL.values()))

    def test_root_adopted_removal_refusal_core_is_the_only_held_pin(self):
        held = json.loads((HERE/'held-source.json').read_text())
        self.assertEqual(held['commit'],'7bf0da67717ea24f0b1782f8505967c48b64b0b0')
        self.assertIn('read_result.py',held['files'])
        self.assertIn('actor.py',held['files'])

    def test_capsule_tar_is_deterministic_and_preserves_protected_file_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            put(root,'trust/public.data',b'OPAQUE PUBLIC FIXTURE\n',0o444)
            put(root,'source-map.json',b'{"fixture":true}\n',0o444)
            raw,rows = p.capsule_tar(root)
            for file in (root/'trust/public.data',root/'source-map.json'):
                os.utime(file,ns=(123456789,987654321))
            again,again_rows = p.capsule_tar(root)
            self.assertEqual((raw,rows),(again,again_rows))
            self.assertTrue(all(row['mode']==0o444 for row in rows.values()))
            with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as parsed:
                for item in parsed:
                    self.assertTrue(item.isfile())
                    self.assertEqual((item.mode,item.uid,item.gid,item.mtime),(0o444,0,0,1791748800))

    def test_capsule_tar_refuses_aliases_and_unadmitted_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = put(root,'data',b'PASSIVE DATA',0o555)
            with self.assertRaisesRegex(ValueError,'DATA mode'):
                p.capsule_tar(root)
            target.chmod(0o444)
            (root/'alias').symlink_to(target)
            with self.assertRaises(OSError):
                p.capsule_tar(root)

    def test_capsule_materialization_roundtrips_only_opaque_fixture_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            source,work,_contract,bodies = material_fixture(Path(directory))
            result = capsule.materialize(source,work)
            self.assertEqual(result,work/'lifecycle-inputs')
            for name,body in bodies.items():
                self.assertEqual((result/name).read_bytes(),body)
                self.assertEqual((result/name).stat().st_mode & 0o777,0o444)

    def test_changed_whole_capsule_refuses_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            source,work,_contract,_bodies = material_fixture(Path(directory))
            with (source/'lifecycle-capsule.tar').open('ab') as stream:
                stream.write(b'changed')
            with self.assertRaisesRegex(ValueError,'capsule bytes'):
                capsule.materialize(source,work)
            self.assertFalse((work/'lifecycle-inputs').exists())

    def test_member_modes_sizes_and_hashes_are_bound_independently(self):
        for field,value in (('mode',0o644),('bytes',999),('sha256','0'*64)):
            with self.subTest(field=field),tempfile.TemporaryDirectory() as directory:
                source,work,contract,_bodies = material_fixture(Path(directory))
                contract['capsule']['members']['data.txt'][field] = value
                (source/'contract.json').write_bytes(p.encode(contract))
                with self.assertRaises(ValueError):
                    capsule.materialize(source,work)

    def test_traversal_special_duplicate_and_unmapped_members_refuse(self):
        cases = [
            [('capsule/../escape',b'x',0o444,tarfile.REGTYPE)],
            [('capsule/link',b'',0o444,tarfile.SYMTYPE)],
            [('capsule/data.txt',b'PASSIVE DATA ONLY\n',0o444,tarfile.REGTYPE)]*2,
            [('capsule/unmapped',b'x',0o444,tarfile.REGTYPE)],
        ]
        for entries in cases:
            with self.subTest(entries=entries),tempfile.TemporaryDirectory() as directory:
                source,work,_contract,_bodies = material_fixture(Path(directory),entries)
                with self.assertRaises(ValueError):
                    capsule.materialize(source,work)
                self.assertFalse((Path(directory)/'escape').exists())

    def test_missing_member_and_wrong_inner_map_hash_refuse(self):
        for variant in ('missing','map'):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as directory:
                entries = [('capsule/data.txt',b'PASSIVE DATA ONLY\n',0o444,tarfile.REGTYPE)] if variant=='missing' else None
                source,work,contract,_bodies = material_fixture(Path(directory),entries)
                if variant=='map':
                    contract['capsule']['source_map_sha256'] = '0'*64
                    (source/'contract.json').write_bytes(p.encode(contract))
                with self.assertRaises(ValueError):
                    capsule.materialize(source,work)

    def test_materializer_refuses_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            source,work,_contract,_bodies = material_fixture(Path(directory))
            (work/'lifecycle-inputs').mkdir()
            with self.assertRaisesRegex(ValueError,'fresh'):
                capsule.materialize(source,work)

    def test_synthetic_render_has_closed_map_and_exact_original200_inverse(self):
        # Only mocked constructor DATA flows past the real refusal gate here.
        # No genuine archives, Root review or held module is supplied/imported.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home,frozen,component = root/'constructor',root/'frozen',root/'component'
            home.mkdir();frozen.mkdir();component.mkdir();(home/'work').mkdir()
            original = {'original/held%03d.data'%i:(b'PASSIVE HELD FIXTURE\n',0o644) for i in range(200)}
            for name,(body,mode) in original.items():
                put(frozen,name,body,mode)
            frozen_map = p.encode(dict(files=p.fs.descriptors(original)))
            put(frozen,'source-map.json',frozen_map)
            put(home,'held-source.json',p.encode(dict(commit='SYNTHETIC_DATA_ONLY',frozen_bootstrap_source_map_sha256=p.fs.pin(frozen_map)['sha256'])))
            for name in ('LICENSE','expected349.lock','policy.json','root-admission.TEMPLATE.json','prerequisites.TEMPLATE.json'):
                put(home,name,b'PASSIVE CONSTRUCTOR DATA\n')
            put(home,'payload/hosted/common.py',b'__LIFECYCLE_CODE_MAP_SHA__\n')
            put(home,'payload/hosted/entry.py',b'PASSIVE SOURCE DATA; NEVER IMPORTED\n')
            put(home,'workflow.yml.in',b'__COMMON_SHA__ __ENTRY_SHA__\n')
            review = put(root,'review.json',b'{"fixture":"not a qualification"}\n')
            def fake_prepare(args):
                out = Path(args.output)
                out.mkdir()
                put(out,'opaque.data',b'PASSIVE CAPSULE DATA\n',0o444)
                # Models the held maker under private umask077. The coordinator
                # seals the generated Source-map mode before preserving it.
                put(out,'source-map.json',b'{"fixture":true}\n',0o600)
            with patch.object(p,'HERE',home),patch.object(p.prereq,'validate',return_value=dict(paths={},review={})),patch.object(p.prereq,'check_capsule_review',return_value={'fixture':'DATA_ONLY'}),patch.object(p,'held_code',return_value={'definition.data':(b'PASSIVE CODE FIXTURE\n',0o644)}),patch.object(p,'module',return_value=SimpleNamespace(prepare=fake_prepare)):
                files = p.render(frozen,component,review,'a'*64)
            inverse = json.loads(files['inverse.json'][0])
            undo = {name:row for name,row in files.items() if name not in inverse['additions']}
            self.assertEqual(undo,original)
            self.assertEqual(p.fs.tree(undo),inverse['before_tree'])
            manifest = json.loads(files['source-map.json'][0])
            self.assertEqual(manifest['actual'],p.ACTUAL)
            self.assertEqual(manifest['files'],p.fs.descriptors({name:row for name,row in files.items() if name!='source-map.json'}))
            self.assertEqual(files['.github/workflows/native-arm-build.yml'],files['.github/workflows/native-arm-perl5423-installed-lifecycle-v1.yml'])
            contract = json.loads(files['contract.json'][0])
            self.assertEqual(contract['capsule']['members']['source-map.json']['mode'],0o444)


if __name__ == '__main__':
    unittest.main()
