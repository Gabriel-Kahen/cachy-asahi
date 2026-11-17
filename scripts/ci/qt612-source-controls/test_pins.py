# SPDX-License-Identifier: MIT
"""Bounded adversarial MODEL trees; no Qt build, execution, or native credit."""
import hashlib
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('qt612_source_pins', HERE / 'pins.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
REFUSAL = (ValueError, OSError, TypeError, KeyError)


def pin(raw, kind='file', mode=0o644, **extra):
    return {'kind': kind, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'mode': mode, **extra}


class FrozenSourceModelControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='qt612-source-pins-MODEL-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'holder/family'
        self.root.mkdir(parents=True)
        self.files = {}
        for name in ('README.txt', '.SRCINFO', '.gitattributes'):
            self.files[name] = self.put(self.root, name, b'MODEL passive source bytes\n')
        for origin in ('arch', 'alarm'):
            target = f'recipe-inputs/{origin}/LICENSE'
            self.files[target] = self.put(self.root, target, b'MODEL license bytes, no upstream claim\n')
            name = f'recipe-inputs/{origin}/LICENSES/0BSD.txt'
            path = self.root / name
            path.parent.mkdir()
            path.symlink_to('../LICENSE')
            self.files[name] = pin(b'../LICENSE', 'symlink', 0o777, target='../LICENSE')

    @staticmethod
    def put(root, name, raw):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o644)
        return pin(raw)

    def verify(self):
        return P.verify_family(self.root, self.files)

    def refuse(self):
        with self.assertRaises(REFUSAL):
            self.verify()

    def test_exact_files_hidden_metadata_and_both_passive_links(self):
        result = self.verify()
        self.assertEqual(result, {'status': 'PASS_FROZEN_SOURCE_BYTES_ONLY', 'files': 7,
                                 'bytes': sum(row['bytes'] for row in self.files.values()), 'passive_symlinks': 2})
        self.assertEqual((self.root / 'recipe-inputs/arch/LICENSES/0BSD.txt').readlink(), Path('../LICENSE'))

    def test_missing_file_extra_file_and_empty_directory_refuse(self):
        path = self.root / 'README.txt'
        raw = path.read_bytes()
        path.unlink()
        self.refuse()
        self.put(self.root, 'README.txt', raw)
        extra = self.root / 'extra.txt'
        extra.write_bytes(b'MODEL extra')
        self.refuse()
        extra.unlink()
        (self.root / 'empty-unlisted-directory').mkdir()
        self.refuse()

    def test_same_size_body_change_and_truncation_refuse(self):
        path = self.root / 'README.txt'
        raw = path.read_bytes()
        for body in (b'X' + raw[1:], raw[:-1], b''):
            with self.subTest(bytes=len(body)):
                path.write_bytes(body)
                self.refuse()

    def test_unsafe_regular_file_and_directory_modes_refuse(self):
        path = self.root / 'README.txt'
        for mode in (0o600, 0o664, 0o755, 0o4755):
            with self.subTest(mode=mode):
                path.chmod(mode)
                self.refuse()
        path.chmod(0o644)
        self.root.chmod(0o777)
        self.refuse()
        self.root.chmod(0o755)

    def test_hardlink_fifo_and_unapproved_actual_symlink_refuse(self):
        path = self.root / 'README.txt'
        raw = path.read_bytes()
        for kind in ('hardlink', 'fifo', 'symlink'):
            with self.subTest(kind=kind):
                path.unlink()
                if kind == 'hardlink':
                    alias = self.base / 'hardlink-alias'
                    alias.write_bytes(raw)
                    os.link(alias, path)
                elif kind == 'fifo':
                    os.mkfifo(path, 0o644)
                else:
                    path.symlink_to('.SRCINFO')
                with patch.object(P.os, 'read', side_effect=AssertionError('reject special node before reading')):
                    self.refuse()
                path.unlink()
                self.put(self.root, 'README.txt', raw)

    def test_passive_link_target_changes_refuse(self):
        path = self.root / 'recipe-inputs/arch/LICENSES/0BSD.txt'
        for target in ('../OTHER__', '/etc/passwd', '../../../../outside', '0BSD.txt'):
            with self.subTest(target=target):
                path.unlink()
                path.symlink_to(target)
                self.refuse()

    def test_only_whitelisted_link_names_and_literal_targets_are_accepted(self):
        name = 'other-link.txt'
        (self.root / name).symlink_to('README.txt')
        self.files[name] = pin(b'README.txt', 'symlink', 0o777, target='README.txt')
        self.refuse()
        (self.root / name).unlink()
        del self.files[name]
        name = 'recipe-inputs/arch/LICENSES/0BSD.txt'
        self.files[name] = pin(b'../OTHER__', 'symlink', 0o777, target='../OTHER__')
        self.refuse()

    def test_passive_target_must_have_its_own_ordinary_pin(self):
        target = 'recipe-inputs/arch/LICENSE'
        del self.files[target]
        with patch.object(P.os, 'open', side_effect=AssertionError('manifest must reject missing target pin before opens')):
            self.refuse()

    def test_wrong_symlink_hash_size_mode_and_descriptor_types_refuse(self):
        name = 'recipe-inputs/arch/LICENSES/0BSD.txt'
        original = self.files[name]
        for changes in ({'sha256': 'f' * 64}, {'bytes': 1}, {'mode': 0o644}, {'bytes': True}, {'target': None}):
            with self.subTest(changes=changes):
                self.files[name] = dict(original, **changes)
                self.refuse()

    def test_private_components_refuse_even_when_explicitly_pinned(self):
        for index, private in enumerate(('.git', '.GIT', '.ssh', '.GnUpG', '.aws', '.CONFIG', '.cache', '.codex')):
            with self.subTest(private=private):
                root = self.base / ('private-model-' + str(index))
                root.mkdir()
                name = f'public/{private}/MODEL.txt'
                files = {name: self.put(root, name, b'MODEL private component, explicitly pinned\n')}
                with patch.object(P.os, 'open', side_effect=AssertionError('private manifest path reached filesystem opens')):
                    with self.assertRaises(REFUSAL):
                        P.verify_family(root, files)

    def test_private_root_ancestor_refuses_before_open(self):
        root = self.base / '.SSH/family'
        root.mkdir(parents=True)
        files = {'README.txt': self.put(root, 'README.txt', b'MODEL\n')}
        with patch.object(P.os, 'open', side_effect=AssertionError('private root reached opens')):
            with self.assertRaises(REFUSAL):
                P.verify_family(root, files)

    def test_relative_traversing_absolute_and_excessive_depth_names_refuse(self):
        row = self.files['README.txt']
        for name in ('../escape', '/absolute', 'a/../escape', './README.txt', 'a//b', 'a\\b',
                     '/'.join(['nested'] * 12 + ['file'])):
            with self.subTest(name=name):
                with patch.object(P.os, 'open', side_effect=AssertionError('unsafe manifest member reached opens')):
                    with self.assertRaises(REFUSAL):
                        P.verify_family(self.root, {name: row})

    def test_regular_descriptor_booleans_and_extra_fields_refuse(self):
        original = self.files['README.txt']
        for changes in ({'bytes': True}, {'mode': True}, {'sha256': None}, {'kind': 'device'},
                        {'bytes': -1}, {'target': 'README.txt'}):
            with self.subTest(changes=changes):
                self.files['README.txt'] = dict(original, **changes)
                self.refuse()

    def test_descriptor_over_2mib_refuses_before_open(self):
        self.files['README.txt']['bytes'] = 2 * 1024**2 + 1
        with patch.object(P.os, 'open', side_effect=AssertionError('oversize descriptor reached opens')):
            self.refuse()

    def test_sparse_over_2mib_refuses_before_file_open_or_hash(self):
        path = self.root / 'README.txt'
        with path.open('r+b') as stream:
            stream.truncate(2 * 1024**2 + 1)
        original = os.open

        def directories_only(path, flags, *args, **kwargs):
            if not flags & os.O_DIRECTORY:
                raise AssertionError('oversize tree opened a payload file')
            return original(path, flags, *args, **kwargs)

        with patch.object(P.os, 'open', side_effect=directories_only):
            self.refuse()

    def test_total_byte_cap_accepts_exact_boundary_and_refuses_one_less(self):
        total = sum(row['bytes'] for row in self.files.values())
        with patch.object(P, 'MAX_TOTAL_BYTES', total):
            self.assertEqual(self.verify()['bytes'], total)
        with patch.object(P, 'MAX_TOTAL_BYTES', total - 1):
            with patch.object(P.os, 'open', side_effect=AssertionError('declared total cap reached opens')):
                self.refuse()

    def test_file_count_boundaries_and_513_descriptors_refuse(self):
        root = self.base / 'two-flat-files'
        root.mkdir()
        files = {name: self.put(root, name, b'MODEL\n') for name in ('a', 'b')}
        with patch.object(P, 'MAX_FILES', 2):
            self.assertEqual(P.verify_family(root, files)['files'], 2)
        with patch.object(P, 'MAX_FILES', 1), self.assertRaises(REFUSAL):
            P.verify_family(root, files)
        too_many = {f'file-{number}': files['a'] for number in range(513)}
        with patch.object(P.os, 'open', side_effect=AssertionError('excess descriptors reached opens')):
            with self.assertRaises(REFUSAL):
                P.verify_family(root, too_many)

    def test_relative_root_filesystem_root_and_symlink_ancestors_refuse(self):
        alias = self.base / 'root-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        parent_alias = self.base / 'parent-alias'
        parent_alias.symlink_to(self.root.parent, target_is_directory=True)
        for root in (Path('relative-family'), Path('/'), alias, parent_alias / self.root.name):
            with self.subTest(root=str(root)):
                with patch.object(P.os, 'open', side_effect=AssertionError('unsafe root reached opens')):
                    with self.assertRaises(REFUSAL):
                        P.verify_family(root, self.files)

    def test_root_replacement_during_read_refuses(self):
        self.replaced_during_read(replace_parent=False)

    def test_parent_replacement_during_read_refuses(self):
        self.replaced_during_read(replace_parent=True)

    def replaced_during_read(self, replace_parent):
        original = os.read
        changed = False

        def mutate(fd, length):
            nonlocal changed
            raw = original(fd, length)
            if raw and not changed:
                changed = True
                if replace_parent:
                    self.root.parent.rename(self.base / 'parked-parent')
                    outside = self.base / 'outside'
                    outside.mkdir()
                    self.root.parent.symlink_to(outside, target_is_directory=True)
                else:
                    self.root.rename(self.base / 'parked-root')
                    self.root.mkdir()
            return raw

        with patch.object(P.os, 'read', side_effect=mutate):
            self.refuse()
        self.assertTrue(changed, 'the replacement must happen after a real MODEL payload read')


if __name__ == '__main__':
    unittest.main(verbosity=2)
