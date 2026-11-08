# SPDX-License-Identifier: MIT
"""Modeled local identity/authority joins only; no Root authority or actor is issued."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C
import controller as H
import local as L

ROOT = Path(__file__).resolve().parents[3]


def hosted():
    value = C.defaults()
    value.update(status='ROOT_BOUND_GENERIC16K_NAMESPACE_PROBE_INPUTS', issuer='Root', input_reviewed=True,
                 actual_source='1' * 40, actual_ref='codex/MODELED_ONLY', actual_run=42,
                 kernel=dict(Image={}, config={}, qualification={}, release='MODELED', source='2' * 40, run=1),
                 rootfs=dict(archive={}, manifest={}, qualification={}, source='3' * 40, run=2))
    return value


def selected():
    value = L.defaults()
    value.update(status='ROOT_BOUND_LOCAL_GENERIC16K_NAMESPACE_PROBE_INPUTS', issuer='Root', input_reviewed=True,
                 actual_source='1' * 40, actual_ref='codex/MODELED_LOCAL_ONLY', actual_run=None,
                 local_id='Root-local-MODELED_NOT_ISSUED', nonce='a' * 32,
                 kernel=dict(Image={}, config={}, qualification={}, release='MODELED', source='2' * 40, run=1),
                 rootfs=dict(archive={}, manifest={}, qualification={}, source=None, run=None),
                 input_provenance=dict(kernel={}, rootfs={}, provider={}))
    return value


class LocalData(unittest.TestCase):
    def setUp(self):
        for name in ('subprocess.Popen', 'subprocess.run', 'os.execve', 'socket.socket', 'ctypes.CDLL'):
            self.enterContext(patch(name, side_effect=AssertionError('LOCAL_DATA_ACTOR_DENIED:' + name)))

    def test_separately_versioned_local_template_is_unbound(self):
        self.assertEqual(C.decode(C.read(H.HERE / 'input-policy.json')), C.defaults())
        self.assertEqual(C.decode(C.read(H.HERE / 'local-input-policy.json')), L.defaults())
        self.assertEqual(C.defaults()['schema'], 1)
        self.assertEqual(L.defaults()['schema'], 2)
        self.assertIsNone(L.defaults()['actual_run'])
        self.assertIsNone(L.defaults()['local_id'])
        with self.assertRaisesRegex(ValueError, 'UNBOUND'):
            L.selection(L.defaults())

    def test_local_positive_contract_is_not_a_github_run(self):
        value = L.selection(selected())
        self.assertIsNone(value['actual_run'])
        self.assertIsNone(value['rootfs']['run'])
        self.assertEqual(value['local_id'], 'Root-local-MODELED_NOT_ISSUED')

    def test_a9_or_any_github_id_cannot_be_reused_as_local_run(self):
        for run in (42506488789, 1, True, '42'):
            value = selected()
            value['actual_run'] = run
            with self.subTest(run=run), self.assertRaisesRegex(ValueError, 'no GitHub run'):
                L.selection(value)

    def test_hosted_branch_still_requires_genuine_run_and_rejects_local_schema(self):
        value = hosted()
        C.bound(value)
        value['actual_run'] = None
        with self.assertRaises(ValueError):
            C.bound(value)
        with self.assertRaises(ValueError):
            C.bound(selected())

    def test_local_nonce_caps_and_input_provenance_are_not_optional(self):
        for field, replacement in [('nonce', None), ('local_id', 'default'), ('actual_source', None),
                                   ('input_provenance', {}), ('bounds', dict(C.BOUNDS, VM_seconds=181))]:
            value = selected()
            value[field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                L.selection(value)

    def test_exact_git_code_tree_and_body_counterexample(self):
        with tempfile.TemporaryDirectory(prefix='MODEL_ONLY_GIT_DATA_') as temporary:
            root = Path(temporary)
            table, files = {}, {}
            for name in L.CODE:
                path = root / name
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                body = ('MODEL_ONLY_NO_CODE_EXECUTION:' + name).encode()
                path.write_bytes(body)
                oid = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
                table[name] = dict(mode='100644', oid=oid)
                files[name] = dict(C.pin(body), **table[name])
            tree = L.tree_id(table)
            raw = ('tree ' + tree + '\n\nMODEL_ONLY_NOT_A_GIT_WRITE\n').encode()
            actual = hashlib.sha1(b'commit ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
            rawpath = root / 'MODEL.raw';rawpath.write_bytes(raw)
            mappath = root / 'MODEL-map.json';mappath.write_bytes(C.encoded(table))
            value = selected();value['actual_source'] = actual
            proof = dict(source=actual, ref=value['actual_ref'], tree=tree,
                         raw_commit=dict(path=str(rawpath), **C.pin(raw)),
                         full_map=dict(path=str(mappath), **C.pin(mappath.read_bytes())), files=files)
            with patch.object(L, '__file__', str(root / L.LANE / 'local.py')):
                self.assertEqual(L.code(root, proof, value), files)
                (root / L.LANE / 'guest.py').write_bytes(b'MODELED_STALE_BODY')
                with self.assertRaisesRegex(ValueError, 'pinned input differs'):
                    L.code(root, proof, value)

    def test_unissued_authority_refuses_before_provider_or_lease(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selection_path = root / 'selection.json';selection_path.write_bytes(C.encoded(selected()))
            authority = root / 'UNISSUED_MODEL.json';authority.write_bytes(C.encoded(dict(schema=1, issuer='Root', approved=None)))
            args = type('ModeledArgs', (), dict(selection=selection_path, selection_sha256=C.pin(selection_path.read_bytes())['sha256'],
                        local_authority=authority, local_authority_sha256=C.pin(authority.read_bytes())['sha256']))()
            with self.assertRaisesRegex(ValueError, 'independent Root local'):
                L.authorize(args)

    def test_private_provider_rejects_shell_wrapper_before_any_exec(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'usr/bin/qemu-system-aarch64';binary.parent.mkdir(parents=True)
            raw = b'#!/bin/sh\nMODELED_WRAPPER_NOT_EXECUTED\n';binary.write_bytes(raw);binary.chmod(0o755)
            manifest = dict(schema=1, status='ROOT_REVIEWED_PRIVATE_QEMU_PROVIDER', host_machine=os.uname().machine,
                            binary='usr/bin/qemu-system-aarch64', files={'usr/bin/qemu-system-aarch64': dict(C.pin(raw), mode=0o755)},
                            host_libraries={})
            with self.assertRaisesRegex(ValueError, 'no implicit wrapper'):
                L.provider(root, manifest, binary, C.pin(raw),
                           {'LD_LIBRARY_PATH': str(root / 'usr/lib'), 'QEMU_MODULE_DIR': str(root / 'usr/lib/qemu')})

    def test_local_firmware_path_is_explicit_and_hosted_argv_is_held(self):
        args = (Path('/MODEL/qemu'), Path('/MODEL/work'), 'a' * 32)
        old = H.qemu_argv(*args)
        local = H.qemu_argv(*args, firmware_dir=Path('/MODEL/private/usr/share/qemu'))
        self.assertNotIn('-L', old)
        self.assertEqual(local[1:3], ['-L', '/MODEL/private/usr/share/qemu'])
        self.assertEqual([local[0], *local[3:]], old)
        self.assertEqual(C.BOUNDS['VM_seconds'], 180)
        self.assertEqual(C.BOUNDS['owner_seconds'], 240)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=ROOT)
    args, remaining = parser.parse_known_args()
    ROOT = args.root.resolve()
    unittest.main(argv=[sys.argv[0], *remaining])
