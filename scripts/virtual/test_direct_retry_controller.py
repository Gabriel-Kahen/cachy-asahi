# SPDX-License-Identifier: MIT
"""Exact successor base binding; no Docker, compiler or guest execution."""
import copy
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import common
import controller as c
import test_controller as fixtures


class DirectBaseInputs(unittest.TestCase):
    setUpClass = classmethod(fixtures.InputTests.setUpClass.__func__)
    tearDownClass = classmethod(fixtures.InputTests.tearDownClass.__func__)

    def validate(self, contract):
        # Keep the proposed controller beside the held source dependencies.
        with tempfile.TemporaryDirectory() as temporary:
            owner = Path(temporary)
            for name in c.CORE:
                shutil.copyfile(Path(fixtures.__file__).with_name(name), owner/name)
            shutil.copyfile(c.__file__, owner/'controller.py')
            with patch.object(c, '__file__', str(owner/'controller.py')):
                return fixtures.InputTests.validate(self, contract)

    def test_exact_successor_accepts_but_unlisted_input_bytes_do_not(self):
        contract = copy.deepcopy(self.contract)
        paths = {name: self.root / row['path'] for name, row in contract['files'].items()}
        originals = {path: path.read_bytes() for path in paths.values()}
        self.addCleanup(lambda: [path.write_bytes(raw) for path, raw in originals.items()])
        # Same native 341-package base; only Vim and its runtime were refreshed.
        source = Path(__file__).resolve()
        while not (source / 'scripts/ci/maintained-native/locks/inputs-successor.lock.json').is_file():
            if source == source.parent:
                raise AssertionError('repository successor lock missing')
            source = source.parent
        successor = source / 'scripts/ci/maintained-native/locks/inputs-successor.lock.json'
        paths['base_inputs_lock'].write_bytes(successor.read_bytes())
        self.assertEqual(common.digest(paths['base_inputs_lock']),
                         'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f')
        upstream = common.json_load(successor)
        base = {row['name'][0]: row['version'][0] for row in upstream['rootfs_packages']}
        base.update({row['name']: row['version'] for row in upstream['packages']})
        versions = {row['name']: row['version'] for row in contract['baseline']}
        for name, rows in (('base_lock', base), ('installed_lock', base | versions)):
            paths[name].write_text(''.join(name+' '+version+'\n' for name, version in sorted(rows.items())))
        receipt = common.json_load(paths['commit_receipt'])
        receipt.update(base_packages_sha256=common.digest(paths['base_lock']),
                       installed_packages_sha256=common.digest(paths['installed_lock']))
        common.save(paths['commit_receipt'], receipt)
        image = common.json_load(paths['installed_image_receipt'])
        image.update(lock_sha256=common.digest(paths['installed_lock']),
                     commit_receipt_sha256=common.digest(paths['commit_receipt']))
        common.save(paths['installed_image_receipt'], image)
        verified = common.json_load(paths['committed_verification'])
        verified['installed_packages_sha256'] = common.digest(paths['installed_lock'])
        common.save(paths['committed_verification'], verified)
        for name, path in paths.items(): contract['files'][name]['sha256'] = common.digest(path)
        self.validate(contract)
        # Identical package maps with unlisted input bytes still fail the pin gate.
        paths['base_inputs_lock'].write_bytes(successor.read_bytes()+b'\n')
        contract['files']['base_inputs_lock']['sha256'] = common.digest(paths['base_inputs_lock'])
        with self.assertRaisesRegex(common.Refused, 'accepted native base input snapshot differs'):
            self.validate(contract)

    def test_main_accepts_explicit_argv_without_reading_caller_flags(self):
        with patch.object(c.sys, 'argv', ['foreign-caller', '--unknown']), \
             patch.object(c, 'native_guard', side_effect=ValueError('inert native guard')):
            with self.assertRaisesRegex(ValueError, 'inert native guard'):
                c.main(['--contract-sha256', 'a'*64])
