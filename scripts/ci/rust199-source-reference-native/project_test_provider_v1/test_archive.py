# SPDX-License-Identifier: MIT
"""Synthetic XZ/ELF DATA, no real signature, native package, actor or grant."""
import copy
import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

ATTEMPTS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.fork', 'os.posix_spawn', 'fcntl.flock'):
        ATTEMPTS.append(event)
        raise AssertionError('ARCHIVE_DATA_NO_ACTOR: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


F = load('held_v18_archive_fixture', HERE.parent / 'successor_v18/test_dependencies.py')
A = load('project_archive_controls', HERE / 'archive.py')
D = F.D


class ArchiveControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='project-archive-MODEL-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.path = self.root / 'MODEL.pkg.tar.xz'
        self.row = F.package()

    def package(self, *, additions=(), missing_license=False, changed_license=False, license_alias=False):
        row = self.row
        metadata = ''.join(key + ' = ' + value + '\n' for key, values in row['metadata'].items() for value in values).encode()
        members = [('.PKGINFO', metadata, 0o644, 'file', ''), ('.BUILDINFO', F.buildinfo(row), 0o644, 'file', '')]
        for name, item in row['providers'].items():
            members.append((name, F.BODY if item['kind'] == 'file' else b'', item['mode'], item['kind'], item.get('target', '')))
        if not missing_license:
            members.append(('usr/share/licenses/libgit2/COPYING', b'SUBSTITUTED' if changed_license else F.LICENSE,
                            0o777 if license_alias else 0o644, 'symlink' if license_alias else 'file', 'other'))
        with tarfile.open(self.path, 'w:xz') as package:
            for name, raw, mode, kind, target in [*members, *additions]:
                member = tarfile.TarInfo(name); member.mode = mode
                member.type = {'file': tarfile.REGTYPE, 'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE,
                               'dir': tarfile.DIRTYPE, 'fifo': tarfile.FIFOTYPE}[kind]
                member.linkname = target
                member.size = len(raw) if kind == 'file' else 0
                package.addfile(member, io.BytesIO(raw) if kind == 'file' else None)
        row['archive'] = D.pin(self.path.read_bytes())
        return row

    def audit(self):
        return A.audit(self.path, self.row, D)

    def test_complete_synthetic_archive_and_internal_alias_chain(self):
        self.row['providers']['usr/lib/libgit2.so']['target'] = 'libgit2.so.middle'
        self.row['providers']['usr/lib/libgit2.so.middle'] = dict(kind='symlink', mode=0o777, target='libgit2.so.0')
        self.package(); result = self.audit()
        self.assertEqual(result['providers'], self.row['providers'])
        self.assertEqual(result['installed_licenses'], {'usr/share/licenses/libgit2/COPYING': D.pin(F.LICENSE)})
        self.assertTrue(result['complete_provider_inventory'])
        self.assertFalse(result['native_acceptance']); self.assertIsNone(result['Root_acceptance'])

    def test_undeclared_elf_shared_object_and_alias_refuse_after_archive_rehash(self):
        for item in (('usr/lib/hidden.so.1', F.BODY, 0o755, 'file', ''),
                     ('usr/lib/hidden.a', b'!<arch>\nMODEL', 0o644, 'file', ''),
                     ('usr/bin/hidden', F.BODY, 0o755, 'file', ''),
                     ('usr/lib/hidden.so', b'LINKER SCRIPT', 0o644, 'file', ''),
                     ('usr/lib/hidden', b'', 0o777, 'symlink', 'libgit2.so.0'),
                     ('usr/share/hidden.so', b'', 0o777, 'symlink', 'libgit2.so.0')):
            self.package(additions=[item])
            with self.subTest(member=item[0]), self.assertRaises(ValueError): self.audit()

    def test_dangling_cycle_and_escape_aliases_refuse(self):
        baseline = copy.deepcopy(self.row)
        for kind in ('dangling', 'cycle', 'escape', 'alias-only'):
            self.row = copy.deepcopy(baseline)
            alias = self.row['providers']['usr/lib/libgit2.so']
            alias['target'] = {'dangling': 'MISSING.so', 'cycle': 'libgit2.loop.so', 'escape': '../libgit2.so.0', 'alias-only': 'libgit2.so.0'}[kind]
            if kind == 'cycle': self.row['providers']['usr/lib/libgit2.loop.so'] = dict(kind='symlink', mode=0o777, target='libgit2.so')
            if kind == 'alias-only': self.row['providers'].pop('usr/lib/libgit2.so.0')
            self.package()
            with self.subTest(kind=kind), self.assertRaises(ValueError): self.audit()

    def test_hooks_install_paths_hardlinks_special_nodes_and_alias_ancestors_refuse(self):
        for item in (('.INSTALL', b'MODEL', 0o644, 'file', ''),
                     ('usr/share/libalpm/hooks/MODEL.hook', b'MODEL', 0o644, 'file', ''),
                     ('etc/pacman.d/hooks/MODEL.hook', b'MODEL', 0o644, 'file', ''),
                     ('../ESCAPE', b'MODEL', 0o644, 'file', ''),
                     ('usr/lib/HARDLINK', b'', 0o644, 'hardlink', 'usr/lib/libgit2.so.0'),
                     ('usr/lib/FIFO', b'', 0o644, 'fifo', ''),
                     ('usr/lib', b'', 0o777, 'symlink', 'OTHER'),
                     ('usr/share/escape', b'', 0o777, 'symlink', '../../../..')):
            self.package(additions=[item])
            with self.subTest(member=item[0]), self.assertRaises(ValueError): self.audit()

    def test_installed_license_must_match_exact_retained_source_bytes(self):
        for kwargs in (dict(missing_license=True), dict(changed_license=True), dict(license_alias=True),
                       dict(additions=[('usr/share/licenses/libgit2/EXTRA', F.LICENSE, 0o644, 'file', '')])):
            self.package(**kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError): self.audit()

    def test_unedited_buildinfo_archive_and_metadata_still_use_frozen_predicates(self):
        self.package()
        changed = copy.deepcopy(self.row); changed['license_provenance']['pkgbuild']['sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'recipe hash correspondence'): A.audit(self.path, changed, D)
        changed = copy.deepcopy(self.row); changed['metadata']['arch'] = ['x86_64']
        with self.assertRaises(ValueError): A.audit(self.path, changed, D)
        self.path.write_bytes(self.path.read_bytes() + b'CHANGED')
        with self.assertRaisesRegex(ValueError, 'whole original'): self.audit()

    def test_cancellation_propagates_without_native_or_signature_claim(self):
        self.package()
        def cancelled(): raise ValueError('MODEL_CANCELLED')
        with self.assertRaisesRegex(ValueError, 'MODEL_CANCELLED'): A.audit(self.path, self.row, D, cancelled)

    def test_no_actor_attempt(self):
        self.assertEqual(ATTEMPTS, [])


if __name__ == '__main__': unittest.main(verbosity=2)
