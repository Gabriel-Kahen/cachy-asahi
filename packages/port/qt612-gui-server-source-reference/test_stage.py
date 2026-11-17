#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic MODEL controls only: these fixtures are not runnable Qt binaries."""
import sys


def no_actors(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
            'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn'):
        raise ValueError('MODEL_STAGE_ONLY_NO_ACTORS')


sys.addaudithook(no_actors)

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('qt612_stage_checks', Path(__file__).with_name('check_stage.py'))
stage = importlib.util.module_from_spec(spec); spec.loader.exec_module(stage)


def model_elf(machine=183, soname=None, needed=(), gnu=False):
    """Synthetic ELF bytes, deliberately not a runnable Qt artifact."""
    body = bytearray(2048)
    body[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', body, 16, 3, machine, 1)
    struct.pack_into('<Q', body, 32, 64)
    struct.pack_into('<HHH', body, 52, 64, 56, 2)
    struct.pack_into('<IIQQQQQQ', body, 64, 1, 5, 0, 0x4000, 0x4000, len(body), len(body), 16384)
    strings = bytearray(b'\0')

    def text(value):
        start = len(strings)
        strings.extend(value.encode() + b'\0')
        return start

    entries = [(1, text(name)) for name in needed]
    if soname:
        entries.append((14, text(soname)))
    if gnu:
        filename, required, provided = text('libMODEL.so.1'), text('MODEL_REQUIRED_1'), text('MODEL_PROVIDED_1')
        struct.pack_into('<HHIII', body, 768, 1, 1, filename, 16, 0)
        struct.pack_into('<IHHII', body, 784, 0x1234, 0, 2, required, 0)
        struct.pack_into('<HHHHIII', body, 832, 1, 0, 2, 1, 0x5678, 20, 0)
        struct.pack_into('<II', body, 852, provided, 0)
        entries.extend(((0x6ffffffe, 0x4300), (0x6fffffff, 1),
                        (0x6ffffffc, 0x4340), (0x6ffffffd, 1)))
    entries.extend(((5, 0x4200), (10, len(strings)), (0, 0)))
    body[512:512 + len(strings)] = strings
    struct.pack_into('<IIQQQQQQ', body, 120, 2, 6, 256, 0x4100, 0x4100, len(entries) * 16, len(entries) * 16, 8)
    for number, item in enumerate(entries):
        struct.pack_into('<qQ', body, 256 + number * 16, *item)
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
        notice_map = {f'LICENSES/MODEL-{n}.txt': hashlib.sha256(text).hexdigest() for n in range(173)}
        self.manifest.write_text(json.dumps({'schema_version': 1, 'source_notices': notice_map}))
        # Explicit test-process seam only. Production accepts the fixed upstream
        # policy whole pin; these MODEL bytes cannot satisfy that pin.
        self.production_notice_pin = dict(stage.NOTICE_POLICY_PIN)
        raw = self.manifest.read_bytes()
        policy_seam = patch.object(stage, 'NOTICE_POLICY_PIN', dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
        policy_seam.start()
        self.addCleanup(policy_seam.stop)
        for name in notice_map:
            self.put(stage.NOTICE_ROOT + '/' + name, text)
        for module in stage.MODULES + stage.PRIVATE_MODULES:
            library = f'libQt6{module}.so'
            self.put('usr/lib/' + library + '.6.12.0', model_elf(soname=library + '.6'))
            (self.root / ('usr/lib/' + library + '.6')).symlink_to(library + '.6.12.0')
            (self.root / ('usr/lib/' + library)).symlink_to(library + '.6')
            if module in stage.MODULES:
                required = (f'usr/include/qt6/Qt{module}/Qt{module}',
                            f'usr/lib/pkgconfig/Qt6{module}.pc',
                            f'usr/lib/cmake/Qt6{module}/Qt6{module}Config.cmake')
            elif module in stage.PRIVATE_HEADERS:
                required = (f'usr/include/qt6/Qt{module}/6.12.0/Qt{module}/private/{stage.PRIVATE_HEADERS[module]}',
                            f'usr/lib/cmake/Qt6{module}Private/Qt6{module}PrivateConfig.cmake')
            else:
                required = ()
            for name in required:
                self.put(name, b'Synthetic MODEL development metadata\n')
        for name in stage.TOOLS + tuple('usr/lib/qt6/plugins/' + plugin for plugin in stage.PLUGINS):
            self.put(name, model_elf())
        self.put('usr/include/qt6/QtCore/qtcoreversion.h', b'#define QTCORE_VERSION_STR "6.12.0"\n')
        self.gui_targets = (b'add_library(Qt6::Gui SHARED IMPORTED)\n'
            b'set_target_properties(Qt6::Gui PROPERTIES\n'
            b'  QT_ENABLED_PRIVATE_FEATURES "wayland_client;wayland_server;wayland_egl"\n'
            b'  QT_DISABLED_PRIVATE_FEATURES "wayland_brcm"\n)\n')
        self.put(stage.GUI_TARGETS, self.gui_targets)
        self.put(stage.GUI_PRIVATE_CONFIG, b'#define QT_FEATURE_wayland_server 1\n')
        for name in stage.SERVER_METADATA[2:]:
            self.put(name, b'# Synthetic MODEL provider package metadata; never executed\n')


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
        self.assertEqual(result['hardware'], 'NOT_ESTABLISHED')
        self.assertEqual(result['native_execution'], 'NOT_ESTABLISHED')
        self.assertEqual(len(result['elf']), len(stage.MODULES + stage.PRIVATE_MODULES) + len(stage.TOOLS) + len(stage.PLUGINS))
        self.assertIn('usr/lib/libQt6Core.so', result['symlinks'])

    def test_MODEL_server_feature_export_and_whole_file_pins(self):
        result = self.inspect()
        self.assertEqual(result['status'], 'PASS_QT612_GUI_SERVER_DESTDIR_CONTRACT_ONLY')
        proof = result['server_feature_export']
        self.assertEqual(proof['status'], 'PASS_QT612_GUI_SERVER_FEATURE_EXPORT_BYTES_ONLY')
        self.assertEqual(proof['target'], 'Qt6::Gui')
        self.assertEqual(proof['enabled_private_feature'], 'wayland_server')
        self.assertTrue(proof['disabled_private_feature_absent'])
        self.assertEqual(proof['private_header_definition'], 1)
        self.assertIsNone(proof['native_acceptance'])
        self.assertIsNone(result['native_acceptance'])
        for name in stage.SERVER_METADATA:
            raw = (self.root / name).read_bytes()
            self.assertEqual(proof['files'][name], dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()))
            self.assertEqual(proof['files'][name], {k: result['files'][name][k] for k in ('bytes', 'sha256')})

    def test_MODEL_missing_server_provider_metadata_refused(self):
        for name in stage.SERVER_METADATA:
            path = self.root / name
            body = path.read_bytes()
            path.unlink()
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'server provider metadata'):
                self.inspect()
            self.put(name, body)

    def test_MODEL_server_feature_OFF_export_refused(self):
        for enabled, disabled in ((b'wayland_client', b'wayland_brcm'),
                                  (b'wayland_client;wayland_server', b'wayland_server')):
            raw = self.gui_targets.replace(b'wayland_client;wayland_server;wayland_egl', enabled).replace(b'wayland_brcm', disabled)
            self.put(stage.GUI_TARGETS, raw)
            with self.subTest(enabled=enabled, disabled=disabled), self.assertRaisesRegex(ValueError, 'enabled private export'):
                self.inspect()

    def test_MODEL_server_feature_header_missing_OFF_duplicate_refused(self):
        for body in (b'#define QT_FEATURE_wayland_client 1\n', b'#define QT_FEATURE_wayland_server -1\n',
                     b'#define QT_FEATURE_wayland_server 0\n',
                     b'#define QT_FEATURE_wayland_server 1\n#define QT_FEATURE_wayland_server -1\n',
                     b'#define QT_FEATURE_wayland_server 1\n#define QT_FEATURE_wayland_server 1\n'):
            self.put(stage.GUI_PRIVATE_CONFIG, body)
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, 'exact one QT_FEATURE'):
                self.inspect()

    def test_MODEL_duplicate_Gui_target_block_refused(self):
        block = self.gui_targets.split(b'set_target_properties', 1)[1]
        self.put(stage.GUI_TARGETS, self.gui_targets+b'set_target_properties'+block)
        with self.assertRaisesRegex(ValueError, 'exact one Qt6::Gui target property block'):
            self.inspect()

    def test_MODEL_duplicate_Gui_target_declaration_refused(self):
        self.put(stage.GUI_TARGETS, self.gui_targets+b'add_library(Qt6::Gui SHARED IMPORTED)\n')
        with self.assertRaisesRegex(ValueError, 'exact one imported Qt6::Gui'):
            self.inspect()

    def test_MODEL_duplicate_private_feature_property_refused(self):
        line = b'  QT_ENABLED_PRIVATE_FEATURES "wayland_server"\n'
        self.put(stage.GUI_TARGETS, self.gui_targets.replace(b'\n)\n', b'\n'+line+b')\n'))
        with self.assertRaisesRegex(ValueError, 'exact one literal'):
            self.inspect()

    def test_MODEL_server_export_wrong_target_or_nonliteral_refused(self):
        for body in (self.gui_targets.replace(b'Qt6::Gui', b'Qt6::Other'),
                     self.gui_targets.replace(b'wayland_client;wayland_server;wayland_egl', b'${MODEL_FEATURES}'),
                     self.gui_targets.replace(b'wayland_client;wayland_server;wayland_egl', b'wayland_server;wayland_server')):
            self.put(stage.GUI_TARGETS, body)
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, 'exact one|unique nonempty'):
                self.inspect()

    def test_MODEL_server_metadata_symlink_cannot_substitute_ordinary_bytes(self):
        name = stage.SERVER_METADATA[2]
        path = self.root / name
        path.unlink()
        target = self.put('usr/lib/cmake/Qt6MODEL/metadata.cmake', b'# MODEL metadata\n')
        path.symlink_to('../Qt6MODEL/metadata.cmake')
        with self.assertRaisesRegex(ValueError, 'server provider metadata'):
            self.inspect()

    def test_non_aarch64_refused(self):
        for path in self.root.rglob('*'):
            if path.is_file() and not path.is_symlink() and path.read_bytes().startswith(b'\x7fELF'):
                body = bytearray(path.read_bytes())
                struct.pack_into('<H', body, 18, 62)
                path.write_bytes(body)
        with self.assertRaisesRegex(ValueError, 'architecture'):
            self.inspect()
        with self.assertRaisesRegex(ValueError, 'architecture'):
            self.inspect('x86_64')

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
        for plugin in ('libqlinuxfb.so', 'libqvnc.so'):
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
        self.put(stage.NOTICE_ROOT + '/LICENSES/MODEL-0.txt', b'changed\n')
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

    def test_MODEL_needed_and_GNU_versions_are_byte_metadata(self):
        self.put('usr/lib/libQt6Core.so.6.12.0', model_elf(
            soname='libQt6Core.so.6', needed=('libMODEL.so.1', 'libQt6Gui.so.6'), gnu=True))
        info = self.inspect()['elf']['usr/lib/libQt6Core.so.6.12.0']
        self.assertEqual(info['needed'], ['libMODEL.so.1', 'libQt6Gui.so.6'])
        self.assertEqual(info['version_needs'], [dict(file='libMODEL.so.1', versions=[
            dict(name='MODEL_REQUIRED_1', hash=0x1234, flags=0, other=2)])])
        self.assertEqual(info['version_definitions'], [dict(flags=0, index=2, hash=0x5678,
            names=['MODEL_PROVIDED_1'])])
        self.assertEqual(info['needed_providers']['libMODEL.so.1']['availability'], 'UNAVAILABLE_IN_STAGE')
        self.assertEqual(info['needed_providers']['libQt6Gui.so.6']['staged_paths'], ['usr/lib/libQt6Gui.so.6.12.0'])
        self.assertIsNone(info['needed_providers']['libQt6Gui.so.6']['runtime_resolution'])
        self.assertEqual(info['version_provider_observations'], [dict(file='libMODEL.so.1',
            required_names=['MODEL_REQUIRED_1'], staged_providers=[], runtime_resolution=None)])

    def test_MODEL_absent_GNU_metadata_is_unavailable(self):
        info = stage.elf_info(model_elf())
        self.assertIsNone(info['interpreter'])
        self.assertIsNone(info['version_needs'])
        self.assertIsNone(info['version_definitions'])
        self.assertEqual(info['needed'], [])

    def test_MODEL_interpreter_is_exact_byte_metadata(self):
        body = bytearray(model_elf())
        interpreter = b'/lib/ld-linux-aarch64.so.1\0'
        struct.pack_into('<H', body, 56, 3)
        struct.pack_into('<IIQQQQQQ', body, 176, 3, 4, 1024, 0x4400, 0x4400,
                         len(interpreter), len(interpreter), 1)
        body[1024:1024 + len(interpreter)] = interpreter
        self.assertEqual(stage.elf_info(body)['interpreter'], '/lib/ld-linux-aarch64.so.1')
        body[1024 + len(interpreter) - 1] = 65
        with self.assertRaisesRegex(ValueError, 'interpreter string malformed'):
            stage.elf_info(body)

    def test_MODEL_4k_load_alignment_refused(self):
        body = bytearray(model_elf())
        struct.pack_into('<Q', body, 64 + 48, 4096)
        with self.assertRaisesRegex(ValueError, '16K load geometry'):
            stage.elf_info(body)

    def test_MODEL_incongruent_load_geometry_refused(self):
        body = bytearray(model_elf())
        struct.pack_into('<Q', body, 64 + 16, 0x4001)
        with self.assertRaisesRegex(ValueError, '16K load geometry'):
            stage.elf_info(body)

    def test_MODEL_file_size_exceeds_memory_refused(self):
        body = bytearray(model_elf())
        struct.pack_into('<Q', body, 64 + 40, 1)
        with self.assertRaisesRegex(ValueError, '16K load geometry'):
            stage.elf_info(body)

    def test_MODEL_GNU_record_outside_load_refused(self):
        body = bytearray(model_elf(gnu=True))
        struct.pack_into('<Q', body, 256 + 8, 0xffffffffffff0000)
        with self.assertRaisesRegex(ValueError, 'file-backed load'):
            stage.elf_info(body)

    def test_MODEL_GNU_aux_chain_count_refused(self):
        body = bytearray(model_elf(gnu=True))
        struct.pack_into('<I', body, 784 + 12, 16)
        with self.assertRaisesRegex(ValueError, 'auxiliary chain count'):
            stage.elf_info(body)

    def test_MODEL_dynamic_string_bounds_refused(self):
        body = bytearray(model_elf(needed=('libMODEL.so.1',)))
        struct.pack_into('<Q', body, 256 + 8, 999999)
        with self.assertRaisesRegex(ValueError, 'string outside table'):
            stage.elf_info(body)

    def test_MODEL_private_development_contract(self):
        module = 'EglFSDeviceIntegration'
        path = self.root / f'usr/lib/cmake/Qt6{module}Private/Qt6{module}PrivateConfig.cmake'
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'private module development'):
            self.inspect()

    def test_MODEL_hardlinked_payload_refused(self):
        os.link(self.root / stage.TOOLS[0], self.base / 'hardlink-outside-stage')
        with self.assertRaisesRegex(ValueError, 'single-link'):
            self.inspect()

    def test_MODEL_incomplete_notice_policy_refused(self):
        self.manifest.write_text(json.dumps(dict(schema_version=1, source_notices={'MODEL': '0' * 64})))
        with self.assertRaisesRegex(ValueError, 'pinned173'):
            self.inspect()

    def test_MODEL_unexpected_Qml_library_refused(self):
        self.put('usr/lib/libQt6Qml.so.6.12.0', model_elf(soname='libQt6Qml.so.6'))
        with self.assertRaisesRegex(ValueError, 'exact18 Qt shared library'):
            self.inspect()

    def test_MODEL_unexpected_Qml_SONAME_refused(self):
        self.put('usr/lib/qt6/foreign-library', model_elf(soname='libQt6Qml.so.6'))
        with self.assertRaisesRegex(ValueError, 'exact18 Qt shared SONAME'):
            self.inspect()

    def test_MODEL_static_support_is_retained(self):
        self.put('usr/lib/libQt6KmsSupport.a', b'!<arch>\nMODEL static support, never run\n')
        self.assertIn('usr/lib/libQt6KmsSupport.a', self.inspect()['files'])

    def test_MODEL_policy_does_not_satisfy_production_whole_pin(self):
        with patch.object(stage, 'NOTICE_POLICY_PIN', self.production_notice_pin):
            with self.assertRaisesRegex(ValueError, 'pinned173'):
                self.inspect()

    def test_MODEL_actor_fence_active_before_stage_import(self):
        for event in ('subprocess.Popen', 'socket.__new__', 'ctypes.dlopen', 'os.system', 'os.exec', 'os.fork'):
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, 'NO_ACTORS'):
                sys.audit(event)

    def test_MODEL_disabled_extra_GUI_backend(self):
        self.put('usr/lib/qt6/plugins/egldeviceintegrations/libqeglfs-x11-integration.so', model_elf())
        with self.assertRaisesRegex(ValueError, 'disabled GUI plugin'):
            self.inspect()

    def test_live_root_refused(self):
        with self.assertRaisesRegex(ValueError, 'private staging'):
            stage.inspect(Path('/'), license_manifest=self.manifest)


if __name__ == '__main__':
    unittest.main()
