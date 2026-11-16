#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""MODEL controls for offline DATA recovery; no GPG, network or package execution."""
import base64
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('recover_qt', Path(__file__).with_name('recover_qt_signature.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def model(signature=b'MODEL_NOT_AN_AUTHENTIC_SIGNATURE', change=None):
    row = copy.deepcopy(r.frozen_record())
    row['signature'] = r.descriptor(signature)
    fields = {'FILENAME': [row['filename']], 'NAME': ['qt6-base'], 'BASE': ['qt6-base'],
        'VERSION': [row['version']], 'ARCH': [row['arch']], 'CSIZE': [str(row['archive']['bytes'])],
        'SHA256SUM': [row['archive']['sha256']], 'LICENSE': row['licenses_declared'],
        'PGPSIG': [base64.b64encode(signature).decode()]}
    if change:
        change(fields)
    desc = ('\n\n'.join('%' + k + '%\n' + '\n'.join(v) for k, v in fields.items()) + '\n').encode()
    row['source']['entry_bytes'] = len(desc)
    row['source']['entry_sha256'] = r.descriptor(desc)['sha256']
    return row, desc, signature


def database(row, desc, repeat=False, kind=tarfile.REGTYPE):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as archive:
        for _ in range(2 if repeat else 1):
            member = tarfile.TarInfo(row['source']['entry'])
            member.type = kind
            member.size = len(desc) if kind == tarfile.REGTYPE else 0
            archive.addfile(member, io.BytesIO(desc) if member.size else None)
    raw = out.getvalue()
    row['source']['database'].update(r.descriptor(raw))
    return raw


class Recovery(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qt-signature-model-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for target in ('socket.socket', 'subprocess.Popen'):
            patch = mock.patch(target, side_effect=AssertionError('NO_NETWORK_OR_PROCESS'))
            patch.start()
            self.addCleanup(patch.stop)

    def test_frozen_identity_matches_existing_catalog_without_promotion(self):
        row = r.frozen_record()
        lock = json.loads((r.HERE / 'inputs.lock.json').read_bytes())['packages']['qt6-base']
        for key in ('filename', 'version', 'arch', 'archive', 'signature'):
            self.assertEqual(row[key], lock[key])
        self.assertEqual(lock['archive_metadata'], 'NOT_ACQUIRED_OR_INSPECTED')
        self.assertEqual(row['signature']['bytes'], 566)

    def test_model_recovers_only_signature_and_held_receipt_with_private_modes(self):
        row, desc, sig = model()
        raw = database(row, desc)
        path = self.root / 'extra.db'
        path.write_bytes(raw)
        output = self.root / 'recovered'
        with mock.patch.object(r, 'frozen_record', return_value=row):
            receipt = r.recover(path, output)
        self.assertEqual(set(p.name for p in output.iterdir()), {row['filename'] + '.sig', 'recovery.json'})
        self.assertEqual((output / (row['filename'] + '.sig')).read_bytes(), sig)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in output.iterdir()))
        self.assertFalse(receipt['catalog_accepted'])
        self.assertFalse(receipt['archive_supplied_by_this_operation'])
        self.assertFalse(receipt['native_execution'])
        self.assertIsNone(receipt['root_authority'])
        self.assertEqual(receipt['signature_authentication'], 'NOT_PERFORMED')
        self.assertEqual(receipt['source'], row['source'])
        # Exercise the existing catalog's DATA intake, without its GPG/main path.
        spec = importlib.util.spec_from_file_location('qt_catalog', r.HERE / 'catalog.py')
        catalog = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(catalog)
        self.assertEqual(catalog.find_input(row['filename'] + '.sig', [output], row['signature']),
                         output / (row['filename'] + '.sig'))
        self.assertIsNone(catalog.find_input(row['filename'], [output], row['archive']))

    def test_database_and_desc_whole_pins_are_required(self):
        row, desc, _ = model()
        raw = database(row, desc)
        with self.assertRaisesRegex(ValueError, 'DATABASE_PIN'):
            r.database_signature(raw + b'changed', row)
        with self.assertRaisesRegex(ValueError, 'DESC_PIN'):
            r.signature_from_desc(desc + b'changed', row)

    def test_package_version_archive_and_license_associations_cannot_be_substituted(self):
        for key in ('FILENAME', 'VERSION', 'ARCH', 'CSIZE', 'SHA256SUM', 'LICENSE'):
            row, desc, _ = model(change=lambda fields: fields.update({key: ['DIFFERENT']}))
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.signature_from_desc(desc, row)

    def test_base64_and_signature_pin_refuse_forgery(self):
        for text in ('***', base64.b64encode(b'forged').decode()):
            row, desc, _ = model(change=lambda fields: fields.update(PGPSIG=[text]))
            with self.subTest(text=text), self.assertRaises(ValueError):
                r.signature_from_desc(desc, row)
        row, desc, _ = model(change=lambda fields: fields.update(PGPSIG=['one', 'two']))
        with self.assertRaisesRegex(ValueError, 'ONE_ENCODED'):
            r.signature_from_desc(desc, row)

    def test_duplicate_or_link_desc_cannot_supply_signature(self):
        for kwargs in ({'repeat': True}, {'kind': tarfile.SYMTYPE}):
            row, desc, _ = model()
            with self.assertRaisesRegex(ValueError, 'ONE_REGULAR_DESC'):
                r.database_signature(database(row, desc, **kwargs), row)

    def test_missing_truncated_and_expired_database_refuse(self):
        row, desc, _ = model()
        row['source']['entry'] = 'absent/desc'
        raw = database(row, desc)
        row['source']['entry'] = 'qt6-base-6.12.0-2/desc'
        with self.assertRaisesRegex(ValueError, 'EXACT_DESC'):
            r.database_signature(raw, row)
        raw = database(row, desc)[:-30]
        row['source']['database'].update(r.descriptor(raw))
        with self.assertRaises((EOFError, tarfile.TarError)):
            r.database_signature(raw, row)
        raw = database(row, desc)
        with mock.patch.object(r.time, 'monotonic', side_effect=[0, 31]):
            with self.assertRaisesRegex(ValueError, 'DATABASE_MEMBER_BOUND'):
                r.database_signature(raw, row)

    def test_aliased_hardlinked_special_and_changed_inputs_refuse(self):
        path = self.root / 'db'
        path.write_bytes(b'model')
        expected = r.descriptor(b'model')
        link = self.root / 'link'
        link.symlink_to(path)
        with self.assertRaisesRegex(ValueError, 'ALIASED'):
            r.pinned(link, expected)
        link.unlink()
        os.link(path, link)
        with self.assertRaisesRegex(ValueError, 'ORDINARY'):
            r.pinned(path, expected)
        link.unlink()
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, 'ORDINARY'):
            r.pinned(fifo, expected)
        original = os.fstat
        def changed(fd):
            before = original(fd)
            values = {k: getattr(before, k) for k in dir(before) if k.startswith('st_')}
            values['st_ino'] += 1
            return types.SimpleNamespace(**values)
        with mock.patch.object(r.os, 'fstat', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'INPUT_CHANGED'):
                r.pinned(path, expected)

    def test_existing_output_and_public_parent_refuse_without_writes(self):
        path = self.root / 'db'
        path.write_bytes(b'model')
        output = self.root / 'existing'
        output.mkdir()
        with self.assertRaisesRegex(ValueError, 'FRESH_SEPARATE'):
            r.recover(path, output)
        self.assertFalse(list(output.iterdir()))
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'OWNED_PRIVATE_PARENT'):
            r.recover(path, self.root / 'new')
        self.assertFalse((self.root / 'new').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
