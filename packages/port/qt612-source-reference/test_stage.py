#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic MODEL controls only: these fixtures are not runnable Qt binaries."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('qt612_stage_checks', Path(__file__).with_name('check_stage.py'))
stage = importlib.util.module_from_spec(spec); spec.loader.exec_module(stage)


def model_elf(machine=183, soname=None):
    body = bytearray(512)
    body[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', body, 16, 3, machine, 1)
    struct.pack_into('<Q', body, 32, 64)
    struct.pack_into('<HHH', body, 52, 64, 56, 2)
    struct.pack_into('<IIQQQQQQ', body, 64, 1, 5, 0, 0x1000, 0x1000, 512, 512, 4096)
    struct.pack_into('<IIQQQQQQ', body, 120, 2, 6, 256, 0x1100, 0x1100, 64, 64, 8)
    if soname:
        text = b'\0' + soname.encode() + b'\0'
        body[384:384 + len(text)] = text
        for n, item in enumerate(((5, 0x1180), (10, len(text)), (14, 1), (0, 0))):
            struct.pack_into('<qQ', body, 256 + n * 16, *item)
    return bytes(body)


class ModelStageControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='qt612-stage-MODEL-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / 'stage'
        self.root.mkdir()
        self.manifest = self.base / 'source-notices.json'
        text = b'Synthetic MODEL license; no upstream source claim.\n'
        self.manifest.write_text(json.dumps({'schema_version': 1, 'source_notices': {
            'LICENSES/MODEL.txt': hashlib.sha256(text).hexdigest()}}))
        self.put(stage.NOTICE_ROOT + '/LICENSES/MODEL.txt', text)
        for module in stage.MODULES + stage.PRIVATE_MODULES:
            library = f'libQt6{module}.so'
            self.put('usr/lib/' + library + '.6.12.0', model_elf(soname=library + '.6'))
            (self.root / ('usr/lib/' + library + '.6')).symlink_to(library + '.6.12.0')
            (self.root / ('usr/lib/' + library)).symlink_to(library + '.6')
            for name in (f'usr/include/qt6/Qt{module}/Qt{module}',
                         f'usr/lib/pkgconfig/Qt6{module}.pc',
                         f'usr/lib/cmake/Qt6{module}/Qt6{module}Config.cmake'):
                self.put(name, b'Synthetic MODEL development metadata\n')
        for name in stage.TOOLS + tuple('usr/lib/qt6/plugins/' + plugin for plugin in stage.PLUGINS):
            self.put(name, model_elf())
        self.put('usr/include/qt6/QtCore/qtcoreversion.h', b'#define QTCORE_VERSION_STR "6.12.0"\n')

    def put(self, name, body):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(0o755 if body.startswith(b'\x7fELF') else 0o644)
        return path

    def inspect(self, arch='aarch64'):
        return stage.inspect(self.root, arch, self.manifest)

    def test_complete_model_inventory_and_evidence_limits(self):
        result = self.inspect()
        self.assertEqual(result['architecture'], 'aarch64')
        self.assertEqual(result['hardware'], 'NOT_RUN')
        self.assertEqual(result['native_execution'], 'NOT_ESTABLISHED')
        self.assertEqual(len(result['elf']), len(stage.MODULES + stage.PRIVATE_MODULES) + len(stage.TOOLS) + len(stage.PLUGINS))
        self.assertIn('usr/lib/libQt6Core.so', result['symlinks'])

    def test_x86_requires_explicit_host_selection(self):
        for path in self.root.rglob('*'):
            if path.is_file() and not path.is_symlink() and path.read_bytes().startswith(b'\x7fELF'):
                body = bytearray(path.read_bytes())
                struct.pack_into('<H', body, 18, 62)
                path.write_bytes(body)
        with self.assertRaisesRegex(ValueError, 'architecture'):
            self.inspect()
        self.assertEqual(self.inspect('x86_64')['evidence_scope'], 'HOST_X86_64_STAGE_ONLY')

    def test_missing_module(self):
        for module in ('Core', 'XcbQpa'):
            path = self.root / f'usr/lib/libQt6{module}.so.6.12.0'; raw = path.read_bytes(); path.unlink()
            with self.subTest(module=module), self.assertRaises(ValueError): self.inspect()
            path.write_bytes(raw); path.chmod(0o755)

    def test_wrong_soname(self):
        self.put('usr/lib/libQt6Core.so.6.12.0', model_elf(soname='libQt6Core.so.7'))
        with self.assertRaisesRegex(ValueError, 'SONAME'):
            self.inspect()

    def test_elf_bounds(self):
        self.put(stage.TOOLS[0], model_elf()[:100])
        with self.assertRaisesRegex(ValueError, 'headers'):
            self.inspect()

    def test_other_elf_cannot_hide_in_inventory(self):
        self.put('usr/lib/qt6/foreign-tool', model_elf(machine=62))
        with self.assertRaisesRegex(ValueError, 'architecture'):
            self.inspect()

    def test_missing_plugin(self):
        (self.root / ('usr/lib/qt6/plugins/' + stage.PLUGINS[0])).unlink()
        with self.assertRaisesRegex(ValueError, 'plugin required'):
            self.inspect()

    def test_wrong_header_version(self):
        self.put('usr/include/qt6/QtCore/qtcoreversion.h', b'#define QTCORE_VERSION_STR "6.11.0"\n')
        with self.assertRaisesRegex(ValueError, 'version header'):
            self.inspect()

    def test_missing_development_file(self):
        (self.root / 'usr/lib/pkgconfig/Qt6Widgets.pc').unlink()
        with self.assertRaisesRegex(ValueError, 'development file'):
            self.inspect()

    def test_disabled_plugin(self):
        for plugin in ('libqwayland.so', 'libqvnc.so'):
            with self.subTest(plugin=plugin):
                path = self.put('usr/lib/qt6/plugins/platforms/' + plugin, model_elf())
                with self.assertRaisesRegex(ValueError, 'disabled platform'):
                    self.inspect()
                path.unlink()

    def test_stage_caps_refuse_before_read(self):
        for bound, limit, message in (('MAX_ENTRIES', 1, 'entry limit'),
                                      ('MAX_FILE_BYTES', 1, 'byte limit'),
                                      ('MAX_PAYLOAD_BYTES', 1, 'byte limit')):
            with self.subTest(bound=bound), patch.object(stage, bound, limit):
                with self.assertRaisesRegex(ValueError, message):
                    self.inspect()

    def test_other_sql_driver(self):
        self.put('usr/lib/qt6/plugins/sqldrivers/libqsqlpsql.so', model_elf())
        with self.assertRaisesRegex(ValueError, 'SQLite-only'):
            self.inspect()

    def test_notice_hash(self):
        self.put(stage.NOTICE_ROOT + '/LICENSES/MODEL.txt', b'changed\n')
        with self.assertRaisesRegex(ValueError, 'notices differ'):
            self.inspect()

    def test_extra_notice(self):
        self.put(stage.NOTICE_ROOT + '/unreviewed.txt', b'extra\n')
        with self.assertRaisesRegex(ValueError, 'notices differ'):
            self.inspect()

    def test_forbidden_ownership(self):
        for name in ('etc/profile', 'boot/kernel', 'usr/lib/systemd/system/test.service',
                     'usr/share/libalpm/hooks/test.hook', 'usr/lib/libEGL.so', 'usr/share/alsa/test.conf'):
            with self.subTest(name=name):
                path = self.put(name, b'unowned\n')
                with self.assertRaisesRegex(ValueError, 'ownership'):
                    self.inspect()
                path.unlink()
                while path.parent != self.root and not any(path.parent.iterdir()):
                    path = path.parent
                    path.rmdir()

    def test_unsafe_mode(self):
        (self.root / stage.TOOLS[0]).chmod(0o4755)
        with self.assertRaisesRegex(ValueError, 'unsafe payload mode'):
            self.inspect()

    def test_links_are_relative_internal_and_resolved(self):
        path = self.root / 'usr/lib/qt6/model-link'
        for target in ('/etc/passwd', '../../../../outside', 'absent', 'model-link'):
            with self.subTest(target=target):
                path.symlink_to(target)
                with self.assertRaises(ValueError):
                    self.inspect()
                path.unlink()

    def test_live_root_refused(self):
        with self.assertRaisesRegex(ValueError, 'private staging'):
            stage.inspect(Path('/'), license_manifest=self.manifest)


if __name__ == '__main__':
    unittest.main()
