#!/usr/bin/env -S python3 -I
# SPDX-License-Identifier: MIT
"""Negative DATA controls only: never construct an admitted operational fixture."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('rust_admission_controls', HERE / 'admission.py')
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.fork', 'os.posix_spawn'):
        raise AssertionError('actor forbidden in admission DATA controls: ' + event)


sys.addaudithook(fence)


class Controls(unittest.TestCase):
    def test_null_root_template_refuses_before_any_file_or_actor(self):
        value = json.loads((HERE / 'root-admission.TEMPLATE.json').read_bytes())
        with patch.object(a, 'read_file', side_effect=AssertionError('material read before Root gates')):
            with self.assertRaises(ValueError):
                a.validate(value)
        self.assertIsNone(value['llvm']['root_decision']['sha256'])
        self.assertIsNone(value['image']['qualification_proof']['sha256'])
        self.assertEqual(value['resources'], json.loads((HERE / 'policy.json').read_bytes()))

    def test_publication_or_wrong_source_is_not_an_accepted_native_job(self):
        source = dict(sha=a.LLVM_SOURCE, ref=None, run=None, job=None)
        with self.assertRaises(ValueError):
            a.selector(source, source=a.LLVM_SOURCE)
        source.update(sha='0'*40, ref='refs/heads/codex/MODELED', run='1', job='2')
        with self.assertRaises(ValueError):
            a.selector(source, source=a.LLVM_SOURCE)
        for missing in (None, {}, {'path': '/inputs/unsigned.pkg.tar.zst'}):
            with self.subTest(missing=missing), self.assertRaises(ValueError):
                a.descriptor(missing)

    def test_wrong_material_pin_or_https_only_intake_refuses(self):
        # These are fixed public declarations, with no acquired/qualified result.
        rows = [dict(name=k, **v, local_path=None, transport='PINNED_HTTPS_DECLARATION') for k, v in a.MATERIALS.items()]
        a.material_rows(rows, False)
        with self.assertRaisesRegex(ValueError, 'HTTPS declaration'):
            a.material_rows(rows, True)
        rows[0]['sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'pin or URL'):
            a.material_rows(rows, False)

    def test_original_must_bind_exact_llvm_source_run_job_and_artifact(self):
        source = dict(sha=a.LLVM_SOURCE, run='1', job='2')
        # Declaration joins only; no package, decision, qualification or admitted fixture.
        original = dict(source=a.LLVM_SOURCE, run='1', job='2', artifact_id='3')
        for key, value in [('source', '0'*40), ('run', '9'), ('job', '9'), ('artifact_id', '9')]:
            changed = dict(original, **{key: value})
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'exact accepted LLVM'):
                a.original_join(changed, source, dict(id='3'))

    def test_false_namespace_or_writable_stage0_alias_never_qualifies(self):
        context = dict(image=dict(id='MODELED_IMAGE'), candidate_admission=dict(sha256='MODELED_Q'),
                       stage0_tree_sha256='MODELED_TREE')
        rejected = dict(schema=1, status='ROOT_QUALIFIED_READONLY_VOLUME_SUBPATH', image_id='MODELED_IMAGE',
            candidate_admission_sha256='MODELED_Q', stage0_tree_sha256='MODELED_TREE',
            paths=['/stage0', '/work/build/stage0'], readonly=True, namespace_permissions_verified=False,
            write_attempts_denied=True, alias_write_attempts_denied=True)
        with self.assertRaises(ValueError):
            a.readonly_subpath(rejected, context)
        rejected.update(namespace_permissions_verified=True, alias_write_attempts_denied=False)
        with self.assertRaises(ValueError):
            a.readonly_subpath(rejected, context)

    def test_model_stage0_digest_is_not_native_compatibility(self):
        context = dict(image_root='/MODELED/original-tree', image=dict(rootfs_tree_sha256='1'*64),
                       stage0_tree_sha256='2'*64)
        rejected = dict(schema=1, scope='PRIVATE_SOURCE_REFERENCE_INPUT_QUALIFICATION_ONLY',
            status='QUALIFIED_FOR_PRIVATE_BUILD_ONLY', holds_preserved=True, inputs_sha256=a.INPUTS_SHA,
            environment=dict(native_target=a.TARGET, llvm_version='23.1.1',
                llvm_prefix='/opt/cachy-asahi/llvm23-source-reference', root='/MODELED/original-tree', tree_sha256='1'*64),
            stage0=dict(native_target=a.TARGET, version='1.98.0', compatibility='UNQUALIFIED', assembled_tree_sha256='2'*64),
            source_audit={})
        with self.assertRaisesRegex(ValueError, 'metadata/model stage0'):
            a.candidate_qualification(rejected, dict(cargo_metadata_version='0.99'), context)

    def test_json_pin_alias_mutability_and_duplicate_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            p = Path(temporary) / 'DATA.json'
            body = b'{"model":"DATA_ONLY"}\n'
            p.write_bytes(body)
            with self.assertRaisesRegex(ValueError, 'readonly'):
                a.read_json(str(p), hashlib.sha256(body).hexdigest())
            p.chmod(0o444)
            with self.assertRaisesRegex(ValueError, 'SHA differs'):
                a.read_json(str(p), '0'*64)
            alias = p.parent / 'alias.json'
            alias.symlink_to(p)
            with self.assertRaisesRegex(ValueError, 'aliases'):
                a.read_json(str(alias), hashlib.sha256(body).hexdigest())
            hard = p.parent / 'hard.json'
            os.link(p, hard)
            with self.assertRaisesRegex(ValueError, 'single-link'):
                a.read_json(str(p), hashlib.sha256(body).hexdigest())
            for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e999}'):
                with self.subTest(raw=raw), self.assertRaises(ValueError):
                    a.decode(raw)


if __name__ == '__main__':
    unittest.main(verbosity=2)
