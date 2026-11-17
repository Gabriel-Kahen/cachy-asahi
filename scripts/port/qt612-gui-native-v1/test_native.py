#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""MODEL_ONLY receipt predicates, not genuine Qt/native provenance evidence.

The archive boundary and upstream source descriptor are patched ONLY in this
test process, so tiny nonsensical MODEL bytes are never offered as real inputs.
Production has no source-pin override or alternate archive-validation mode.
"""
import sys


def no_actors(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
            'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn'):
        raise ValueError('MODEL_ONLY_NO_ACTORS')


sys.addaudithook(no_actors)

import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
spec = importlib.util.spec_from_file_location('gui_native', HERE / 'native.py')
N = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N)
C = N.C


def write(root, name, raw):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    path.chmod(0o644)
    return C.pin(raw)


class ModelPairControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qt-gui-pair-MODEL_ONLY-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = self.root/'work'
        self.work.mkdir()
        self.roots = [self.root/'first', self.root/'second']
        self.comparison = self.root/'comparison.json'
        source = b'MODEL_ONLY_NOT_A_QT_SOURCE_ARCHIVE'
        archive = b'MODEL_ONLY_NOT_A_QT_BINARY_ARCHIVE'
        entry = b'# MODEL_ONLY original entry DATA, never executed\n'
        self.lock = b'gcc 16.2.1\nglibc 2.44\n'
        reviewed = C.inspect_recipe(REPO)
        self.reviewed = copy.deepcopy(reviewed)
        self.reviewed['contract']['upstream']['archive'].update(C.pin(source))
        contract = self.reviewed['contract']
        active = contract['native_recipe_files']
        upstream = contract['upstream']['archive']
        self.binding = dict(schema=1, kind='QT612_GUI_NATIVE_PAIR_EXTERNAL_BINDING_V1',
            recipe_commit=C.RECIPE_COMMIT, image='sha256:'+'a'*64, inventory_pin=C.pin(self.lock),
            entry_script_pin=C.pin(entry), entry_script_path='original-entry.sh',
            nonce='1'*32, source_date_epoch=1234567890, producer_binding_pin=C.pin(b'MODEL_ONLY producer binding'))
        self.binding['environment_ids'] = ['MODEL_ONLY-'+self.binding['nonce']+'-'+str(i) for i in (1, 2)]
        self.archive_results = {}
        for index, root in enumerate(self.roots):
            root.mkdir()
            for name in active:
                write(root, 'inputs/'+name, (REPO/C.RECIPE_PATH/name).read_bytes())
            write(root, 'inputs/'+upstream['filename'], source)
            archive_pin = write(root, 'artifacts/'+C.FILENAME, archive)
            stage = dict(status='PASS_QT612_GUI_DESTDIR_CONTRACT_ONLY', architecture='aarch64',
                evidence_scope='STAGED_AARCH64_ELF_16K_GEOMETRY_ONLY',
                files={}, symlinks={}, directories={}, elf={}, payload_bytes=0,
                native_execution='NOT_ESTABLISHED', installation='NOT_ESTABLISHED', hardware='NOT_ESTABLISHED',
                provider_transaction=None, native_acceptance=None)
            actual = dict(archive=dict(path=str(root/'artifacts'/C.FILENAME), **archive_pin),
                stage=stage, metadata=dict(original_builddate='1234567890',
                    PKGINFO=dict(raw='MODEL_ONLY_PKGINFO', fields=dict(pkgname=[C.PACKAGE])),
                    BUILDINFO=dict(raw='MODEL_ONLY_BUILDINFO', fields=dict(pkgver=[C.VERSION],
                        installed=['gcc-16.2.1-aarch64', 'glibc-2.44-aarch64']))),
                archive_inventory={'usr/lib/qt6/MODEL_ONLY': dict(type='file', mode=0o644,
                    uid=0, gid=0, mtime=1234567890, pax={}, **C.pin(b'MODEL_ONLY'))})
            self.archive_results[root] = actual
            member = actual['archive_inventory']['usr/lib/qt6/MODEL_ONLY']
            validation = dict(errors=[], artifacts=[dict(artifact=C.FILENAME, sha256=archive_pin['sha256'],
                status='artifact-static-pass', errors=[], review=[], elf={},
                members={'usr/lib/qt6/MODEL_ONLY': dict(type='0', mode=0o644, uid=0, gid=0,
                    size=member['bytes'], mtime=1234567890, link='', sha256=member['sha256'])},
                metadata={'.PKGINFO': actual['metadata']['PKGINFO']['fields'],
                          '.BUILDINFO': actual['metadata']['BUILDINFO']['fields']})])
            check_log = 'artifacts/'+C.FILENAME.removesuffix('.pkg.tar.xz')+'-check.log'
            raw = {
                'original-entry.sh': entry,
                'expected-packages.lock': self.lock, 'artifacts/packages.lock': self.lock,
                'artifacts/environment.txt': b'Linux MODEL_ONLY aarch64\n4096\n'+self.lock,
                'artifacts/generated.SRCINFO': (REPO/C.RECIPE_PATH/'.SRCINFO').read_bytes(),
                'artifacts/config.sha256': b'MODEL_ONLY config hash bytes\n',
                'artifacts/makepkg.conf': b'MODEL_ONLY makepkg config\n',
                'artifacts/pacman.conf': b'MODEL_ONLY pacman config\n',
                'artifacts/qt612-configuration.json': C.encode(dict(status='PASS_CONFIGURED_PROFILE_ONLY', settings=113, native='NOT_ESTABLISHED')),
                'artifacts/qt612-source-notices.json': C.encode(dict(status='PASS_QT612_SOURCE_NOTICES_ONLY', notices=173, bytes=636122)),
                'artifacts/qt612-stage-contract.json': C.encode(stage),
                'validation.json': C.encode(validation),
                check_log: N.MARKER+b'\n',
                'build.log': b'==> Starting check()...\n'+N.MARKER+b'\n==> Finished making: MODEL_ONLY\n',
                'artifacts/MODEL_ONLY-prepare.log': b'MODEL_ONLY extra indexed phase log\n'}
            hashes = {name: write(root, name, data)['sha256'] for name, data in raw.items()}
            hashes['artifacts/'+C.FILENAME] = archive_pin['sha256']
            record = dict(status='built-package-static-pass', exit_code=0, mode='native',
                builder_host_arch='aarch64', image=self.binding['image'], image_id=self.binding['image'],
                clean_environment_id=self.binding['environment_ids'][index], source_date_epoch=1234567890,
                expected_packages_sha256=self.binding['inventory_pin']['sha256'],
                entry_script_sha256=self.binding['entry_script_pin']['sha256'], files=hashes,
                artifacts={C.FILENAME: archive_pin['sha256']},
                recipe_metadata=N.srcinfo((REPO/C.RECIPE_PATH/'.SRCINFO').read_bytes()),
                recipe_inputs={name: row['sha256'] for name, row in active.items()} | {upstream['filename']: upstream['sha256']})
            write(root, 'provenance.json', C.encode(record))
        write(self.root, 'comparison.json', C.encode(dict(status='contents-reproduced', errors=[], packages={C.FILENAME:
            dict(installed_contents_equal=True, pkginfo_equal=True, buildinfo_equal=True, bytes_equal=True)})))
        source_seam = patch.object(C, 'inspect_recipe', return_value=self.reviewed)
        source_seam.start()
        self.addCleanup(source_seam.stop)
        archive_seam = patch.object(N.A, 'inspect_archive', side_effect=lambda path, work, recipe_root: self.archive_results[path.parent.parent])
        archive_seam.start()
        self.addCleanup(archive_seam.stop)

    def validate(self, **changes):
        args = dict(first=self.roots[0], second=self.roots[1], comparison=self.comparison,
                    recipe_root=REPO, work=self.work, binding=self.binding)
        args.update(changes)
        return N.validate_pair(**args)

    def change_record(self, index, transform):
        path = self.roots[index]/'provenance.json'
        value = C.decode(path.read_bytes())
        transform(value)
        write(self.roots[index], 'provenance.json', C.encode(value))

    def rehash(self, index, name):
        self.change_record(index, lambda value: value['files'].update({name:C.pin((self.roots[index]/name).read_bytes())['sha256']}))

    def test_MODEL_ONLY_consistency_does_not_authenticate_actor(self):
        result = self.validate()
        self.assertFalse(result['native_acceptance'])
        self.assertFalse(result['native_execution_authenticated'])
        self.assertTrue(result['strict_archive_payload_PKGINFO_BUILDINFO_equal'])
        self.assertEqual(result['builds'], 2)
        self.assertIn(str(self.roots[0]/'artifacts/MODEL_ONLY-prepare.log'), result['original_operand_pins'])
        self.assertEqual(result['producer_binding_pin'], self.binding['producer_binding_pin'])
        self.assertEqual(result['archive_pin'], C.pin(b'MODEL_ONLY_NOT_A_QT_BINARY_ARCHIVE'))

    def test_MODEL_ONLY_binding_and_environment_identity(self):
        bad = copy.deepcopy(self.binding)
        bad['environment_ids'][1] = bad['environment_ids'][0]
        with self.assertRaisesRegex(ValueError, 'distinct environment'):
            self.validate(binding=bad)
        with self.assertRaisesRegex(ValueError, 'disjoint'):
            self.validate(second=self.roots[0])
        bad = copy.deepcopy(self.binding)
        bad['recipe_commit'] = '0'*40
        with self.assertRaisesRegex(ValueError, 'binding schema'):
            self.validate(binding=bad)

    def test_MODEL_ONLY_missing_and_mutated_referenced_operands(self):
        name = 'artifacts/MODEL_ONLY-prepare.log'
        path = self.roots[0]/name
        path.write_bytes(b'changed referenced log\n')
        with self.assertRaisesRegex(ValueError, 'whole input bytes'):
            self.validate()
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'must remain indexed'):
            self.validate()

    def test_MODEL_ONLY_unindexed_log_is_not_omitted(self):
        write(self.roots[0], 'artifacts/UNINDEXED.log', b'MODEL_ONLY\n')
        with self.assertRaisesRegex(ValueError, 'must remain indexed'):
            self.validate()

    def test_MODEL_ONLY_current_source_snapshot_must_match_pin(self):
        path = self.roots[0]/'inputs'/self.reviewed['contract']['upstream']['archive']['filename']
        path.write_bytes(b'changed MODEL source')
        with self.assertRaisesRegex(ValueError, 'exact-size|whole input bytes'):
            self.validate()

    def test_MODEL_ONLY_entry_bytes_not_merely_claimed_hash(self):
        write(self.roots[0], 'original-entry.sh', b'different MODEL entry bytes\n')
        self.rehash(0, 'original-entry.sh')
        with self.assertRaisesRegex(ValueError, 'exact-size|whole input bytes'):
            self.validate()

    def test_MODEL_ONLY_complete_inventory_current_bytes(self):
        write(self.roots[1], 'artifacts/packages.lock', b'gcc 16.2.2\nglibc 2.44\n')
        self.rehash(1, 'artifacts/packages.lock')
        with self.assertRaisesRegex(ValueError, 'whole input bytes'):
            self.validate()

    def test_MODEL_ONLY_check_marker_and_stage_cannot_be_rewritten(self):
        name = 'artifacts/'+C.FILENAME.removesuffix('.pkg.tar.xz')+'-check.log'
        write(self.roots[0], name, b'MODEL no successful Qt check\n')
        self.rehash(0, name)
        with self.assertRaisesRegex(ValueError, 'actual check logs'):
            self.validate()
        write(self.roots[0], name, N.MARKER+b'\n')
        self.rehash(0, name)
        name = 'artifacts/qt612-stage-contract.json'
        stage = C.decode((self.roots[0]/name).read_bytes())
        stage['native_acceptance'] = True
        write(self.roots[0], name, C.encode(stage))
        self.rehash(0, name)
        with self.assertRaisesRegex(ValueError, 'archive whole pin/stage'):
            self.validate()

    def test_MODEL_ONLY_four_strict_original_comparisons(self):
        compared = C.decode(self.comparison.read_bytes())
        compared['packages'][C.FILENAME]['bytes_equal'] = False
        self.comparison.write_bytes(C.encode(compared))
        with self.assertRaisesRegex(ValueError, 'four-way comparison'):
            self.validate()

    def test_MODEL_ONLY_changed_validation_current_archive_join(self):
        name = 'validation.json'
        value = C.decode((self.roots[0]/name).read_bytes())
        value['artifacts'][0]['members']['usr/lib/qt6/MODEL_ONLY']['size'] += 1
        write(self.roots[0], name, C.encode(value))
        self.rehash(0, name)
        with self.assertRaisesRegex(ValueError, 'member/current archive'):
            self.validate()

    def test_MODEL_ONLY_real_sources_cannot_use_tiny_source_fixture(self):
        source_spec = importlib.util.spec_from_file_location('common_unpatched', HERE/'common.py')
        original = importlib.util.module_from_spec(source_spec)
        source_spec.loader.exec_module(original)
        with patch.object(C, 'inspect_recipe', side_effect=original.inspect_recipe):
            with self.assertRaisesRegex(ValueError, 'successful normal build record'):
                self.validate()


if __name__ == '__main__':
    unittest.main()
