#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""MODEL_ONLY package/archive predicates; never genuine Qt package evidence."""
import sys


def no_actors(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
            'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn'):
        raise ValueError('MODEL_ONLY_NO_ACTORS')


sys.addaudithook(no_actors)

import importlib.util
import io
import lzma
import os
from pathlib import Path
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
spec = importlib.util.spec_from_file_location('qt_gui_archive', HERE / 'archive.py')
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


def pkginfo(**overrides):
    rows = dict(pkgname=[A.PACKAGE], pkgbase=[A.PACKAGE], pkgver=[A.VERSION], arch=['aarch64'],
                depend=A.DEPENDS, provides=A.PROVIDES, conflict=A.CONFLICTS,
                license=A.LICENSES, builddate=['1234567890'])
    rows.update(overrides)
    return ('# MODEL_ONLY not a genuine package\n' + ''.join(f'{key} = {value}\n' for key, values in rows.items() for value in values)).encode()


def buildinfo(**overrides):
    rows = dict(format=['2'], pkgname=[A.PACKAGE], pkgbase=[A.PACKAGE], pkgver=[A.VERSION],
                pkgarch=['aarch64'], pkgbuild_sha256sum=[A.RECIPE_FILES['PKGBUILD']['sha256']],
                builddate=['1234567890'], installed=['MODEL_ONLY-1-1-aarch64'])
    rows.update(overrides)
    return ''.join(f'{key} = {value}\n' for key, values in rows.items() for value in values).encode()


def tar_bytes(extra=(), pkg=None, build=None, missing=(), format=tarfile.PAX_FORMAT):
    members = [('.PKGINFO', pkg if pkg is not None else pkginfo(), 'file', 0o644),
               ('.BUILDINFO', build if build is not None else buildinfo(), 'file', 0o644),
               ('.MTREE', b'MODEL_ONLY opaque mtree bytes not validated', 'file', 0o644),
               ('usr', b'', 'directory', 0o755), ('usr/lib', b'', 'directory', 0o755),
               ('usr/lib/qt6', b'', 'directory', 0o755),
               ('usr/lib/qt6/MODEL_ONLY', b'not a Qt artifact', 'file', 0o644)]
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=format) as archive:
        for name, body, kind, mode in [*members, *extra]:
            if name in missing:
                continue
            info = tarfile.TarInfo(name)
            info.uid = info.gid = 0
            info.mode = mode
            info.mtime = 1234567890
            if kind == 'directory':
                info.type = tarfile.DIRTYPE
            elif kind == 'symlink':
                info.type, info.linkname = tarfile.SYMTYPE, body.decode()
            elif kind == 'hardlink':
                info.type, info.linkname = tarfile.LNKTYPE, body.decode()
            elif kind == 'fifo':
                info.type = tarfile.FIFOTYPE
            else:
                info.size = len(body)
            archive.addfile(info, io.BytesIO(body) if kind == 'file' else None)
    return output.getvalue()


class ModelArchivePredicates(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qt-gui-archive-MODEL_ONLY-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.work = self.root / 'work'
        self.work.mkdir()
        self.path = self.root / 'MODEL_ONLY.pkg.tar.xz'
        self.called = []

        def inspect_stage(root, license_manifest):
            # Deliberate MODEL_ONLY boundary seam. No fake Qt payload is offered
            # to the real stage validator and no native result is fabricated.
            self.called.append(dict(root=str(root), policy=str(license_manifest)))
            self.assertTrue((root / 'usr/lib/qt6/MODEL_ONLY').is_file())
            return dict(kind='MODEL_ONLY_STAGE_BOUNDARY_NOT_VALIDATED', native_acceptance=None)
        self.stage = patch.object(A, 'load_stage', return_value=types.SimpleNamespace(inspect=inspect_stage))
        self.stage.start()
        self.addCleanup(self.stage.stop)

    def inspect(self, raw=None):
        self.path.write_bytes(lzma.compress(tar_bytes() if raw is None else raw))
        return A.inspect_archive(self.path, self.work, REPO)

    def test_MODEL_ONLY_complete_archive_predicates_and_cleanup(self):
        result = self.inspect()
        self.assertEqual(result['archive'], dict(path=str(self.path), **A.pin(self.path.read_bytes())))
        self.assertFalse(result['native_acceptance'])
        self.assertIsNone(result['pair_receipts'])
        self.assertIsNone(result['metadata']['MTREE']['semantic_validation'])
        self.assertEqual(result['metadata']['PKGINFO']['raw'].encode(), pkginfo())
        self.assertEqual(result['metadata']['BUILDINFO']['raw'].encode(), buildinfo())
        self.assertEqual(result['metadata']['original_builddate'], '1234567890')
        self.assertEqual(result['stage']['kind'], 'MODEL_ONLY_STAGE_BOUNDARY_NOT_VALIDATED')
        self.assertEqual(list(self.work.iterdir()), [])

    def test_MODEL_ONLY_exact_name_version_arch(self):
        for field, value in (('pkgname', 'qt6-base'), ('pkgver', '6.12.0-3'), ('arch', 'x86_64')):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'exact GUI package'):
                self.inspect(tar_bytes(pkg=pkginfo(**{field: [value]})))

    def test_MODEL_ONLY_dependency_provides_conflicts(self):
        for field in ('depend', 'provides', 'conflict'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'exact GUI package'):
                self.inspect(tar_bytes(pkg=pkginfo(**{field: ['MODEL_WRONG']})))

    def test_MODEL_ONLY_no_replaces_backup_install_hook(self):
        for field in ('replaces', 'backup', 'install', 'hook'):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'no replaces'):
                self.inspect(tar_bytes(pkg=pkginfo(**{field: ['MODEL_WRONG']})))

    def test_MODEL_ONLY_BUILDINFO_exact_recipe_hash(self):
        with self.assertRaisesRegex(ValueError, 'pkgbuild_sha256sum'):
            self.inspect(tar_bytes(build=buildinfo(pkgbuild_sha256sum=['0' * 64])))

    def test_MODEL_ONLY_builddate_not_rewritten_or_normalized(self):
        with self.assertRaisesRegex(ValueError, 'unchanged matching'):
            self.inspect(tar_bytes(build=buildinfo(builddate=['1234567891'])))

    def test_MODEL_ONLY_MTree_required(self):
        with self.assertRaisesRegex(ValueError, 'three original package metadata'):
            self.inspect(tar_bytes(missing=['.MTREE']))

    def test_MODEL_ONLY_INSTALL_member_refused(self):
        with self.assertRaisesRegex(ValueError, 'only ordinary required'):
            self.inspect(tar_bytes(extra=[('.INSTALL', b'MODEL_ONLY script never execute', 'file', 0o644)]))

    def test_MODEL_ONLY_duplicate_member(self):
        with self.assertRaisesRegex(ValueError, 'duplicate/alias'):
            self.inspect(tar_bytes(extra=[('usr/lib/qt6/MODEL_ONLY', b'x', 'file', 0o644)]))

    def test_MODEL_ONLY_traversal_member(self):
        with self.assertRaisesRegex(ValueError, 'canonical ordinary tar member'):
            self.inspect(tar_bytes(extra=[('../escape', b'x', 'file', 0o644)]))
        self.assertFalse((self.root / 'escape').exists())

    def test_MODEL_ONLY_hardlink_FIFO_refused(self):
        for kind in ('hardlink', 'fifo'):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'hardlink/device/FIFO'):
                self.inspect(tar_bytes(extra=[('usr/lib/qt6/special', b'usr/lib/qt6/MODEL_ONLY', kind, 0o644)]))

    def test_MODEL_ONLY_symlink_parent_cannot_escape(self):
        for kind in ('file', 'directory'):
            extra = [('usr/lib/qt6/link', b'../../../../outside', 'symlink', 0o777),
                     ('usr/lib/qt6/link/escape', b'', kind, 0o755)]
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'symlink tar parent'):
                self.inspect(tar_bytes(extra=extra))

    def test_MODEL_ONLY_absolute_symlink_refused(self):
        with self.assertRaisesRegex(ValueError, 'relative printable symlink'):
            self.inspect(tar_bytes(extra=[('usr/lib/qt6/link', b'/etc/passwd', 'symlink', 0o777)]))

    def test_MODEL_ONLY_unsafe_mode_refused(self):
        with self.assertRaisesRegex(ValueError, 'unsafe tar mode'):
            self.inspect(tar_bytes(extra=[('usr/lib/qt6/bad', b'x', 'file', 0o4755)]))

    def test_MODEL_ONLY_xz_trailing_and_second_stream_refused(self):
        for suffix in (b'x', lzma.compress(b'')):
            self.path.write_bytes(lzma.compress(tar_bytes()) + suffix)
            with self.subTest(suffix=suffix[:8]), self.assertRaisesRegex(ValueError, 'single XZ stream'):
                A.inspect_archive(self.path, self.work, REPO)

    def test_MODEL_ONLY_xz_truncation(self):
        self.path.write_bytes(lzma.compress(tar_bytes())[:-1])
        with self.assertRaisesRegex(ValueError, 'truncated XZ'):
            A.inspect_archive(self.path, self.work, REPO)

    def test_MODEL_ONLY_nonzero_tar_trailer(self):
        with self.assertRaisesRegex(ValueError, 'nonzero tar trailing'):
            self.inspect(tar_bytes() + b'X' * 512)

    def test_MODEL_ONLY_bounded_PAX_long_path(self):
        name = 'usr/lib/qt6/' + '/'.join(['MODEL_ONLY_' + 'a' * 70] * 4) + '/data'
        result = self.inspect(tar_bytes(extra=[(name, b'MODEL_ONLY', 'file', 0o644)]))
        self.assertIn(name, result['archive_inventory'])
        self.assertEqual(result['archive_inventory'][name]['pax']['path'], name)

    def test_MODEL_ONLY_tar_header_checksum(self):
        raw = bytearray(tar_bytes())
        raw[0] ^= 1
        with self.assertRaisesRegex(ValueError, 'header checksum'):
            self.inspect(raw)

    def test_MODEL_ONLY_original_metadata_must_be_root_owned(self):
        raw = bytearray(tar_bytes())
        raw[108:116] = b'0000001\0'
        raw[148:156] = b'        '
        checksum = sum(raw[:512])
        raw[148:156] = f'{checksum:06o}\0 '.encode()
        with self.assertRaisesRegex(ValueError, 'root-owned archive metadata'):
            self.inspect(raw)

    def test_MODEL_ONLY_caps(self):
        for key, value in (('MAX_COMPRESSED', 1), ('MAX_EXPANDED', 1), ('MAX_MEMBER', 1), ('MAX_NODES', 1)):
            with self.subTest(key=key), patch.object(A, key, value), self.assertRaises(ValueError):
                self.inspect()

    def test_MODEL_ONLY_real_stage_boundary_rejects_nonsense(self):
        self.stage.stop()
        with self.assertRaisesRegex(ValueError, 'shared library/SONAME'):
            self.inspect()

    def test_MODEL_ONLY_real_helper_whole_pin_refuses_mutation(self):
        self.stage.stop()
        raw = (REPO / A.RECIPE_PATH / 'check_stage.py').read_bytes()
        self.assertEqual(A.load_stage(raw).PACKAGE, A.PACKAGE)
        with self.assertRaisesRegex(ValueError, 'whole-pinned'):
            A.load_stage(raw + b'\n')

    def test_MODEL_ONLY_bad_archive_paths(self):
        self.path.write_bytes(lzma.compress(tar_bytes()))
        link = self.root / 'alias'
        link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, 'symlink path component'):
            A.inspect_archive(link, self.work, REPO)
        os.link(self.path, self.root / 'hardlink')
        with self.assertRaisesRegex(ValueError, 'single-link'):
            A.inspect_archive(self.path, self.work, REPO)

    def test_MODEL_ONLY_actor_fence(self):
        for event in ('subprocess.Popen', 'socket.__new__', 'ctypes.dlopen', 'os.system', 'os.exec', 'os.fork'):
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, 'NO_ACTORS'):
                sys.audit(event)


if __name__ == '__main__':
    unittest.main()
