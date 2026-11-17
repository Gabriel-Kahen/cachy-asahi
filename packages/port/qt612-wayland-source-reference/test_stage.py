#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""MODEL byte fixtures only; not built QtWayland payload/native evidence."""
import sys


def no_actors(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
            'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn'):
        raise ValueError('MODEL_STAGE_ONLY_NO_ACTORS')


sys.addaudithook(no_actors)

import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('qtwayland_stage', HERE/'check_stage.py')
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)


def model_elf(soname=None, machine=183):
    """Synthetic ELF bytes deliberately not runnable Qt artifacts."""
    raw = bytearray(1024)
    raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', raw, 16, 3, machine, 1)
    struct.pack_into('<Q', raw, 32, 64)
    struct.pack_into('<HHH', raw, 52, 64, 56, 2)
    struct.pack_into('<IIQQQQQQ', raw, 64, 1, 5, 0, 0x4000, 0x4000, len(raw), len(raw), 16384)
    strings = b'\0'+soname.encode()+b'\0' if soname else b'\0'
    raw[512:512+len(strings)] = strings
    entries = [(5, 0x4200), (10, len(strings))]
    if soname:
        entries.append((14, 1))
    entries.append((0, 0))
    struct.pack_into('<IIQQQQQQ', raw, 120, 2, 6, 256, 0x4100, 0x4100, len(entries)*16, len(entries)*16, 8)
    for index, row in enumerate(entries):
        struct.pack_into('<qQ', raw, 256+index*16, *row)
    return bytes(raw)


class ModelStage(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qtwayland-stage-MODEL-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base/'stage'
        self.root.mkdir()
        self.policy = self.base/'source-notices.json'
        notices = {}
        for index in range(16):
            name = f'LICENSES/MODEL-{index}.txt'
            body = b'MODEL synthetic notice; no upstream source claim\n'
            self.put(S.NOTICE_ROOT+'/'+name, body)
            notices[name] = hashlib.sha256(body).hexdigest()
        raw = json.dumps(dict(schema_version=1, source_notices=notices)).encode()
        self.policy.write_bytes(raw)
        self.real_policy_pin = dict(S.NOTICE_POLICY_PIN)
        seam = patch.object(S, 'NOTICE_POLICY_PIN', S.pin(raw))
        seam.start()
        self.addCleanup(seam.stop)
        self.dependency_policy = self.base/'dependency-inputs.json'
        dependency_files = {}
        for index in range(52):
            name = f'share/qt6/wayland/protocols/MODEL-{index}.txt'
            body = b'MODEL external Qtbase protocol/attribution/license bytes\n'
            self.put(S.DEPENDENCY_NOTICE_ROOT+'/'+name, body)
            dependency_files[name] = S.pin(body)
        raw = json.dumps(dict(schema=1, kind='QT612_WAYLAND_EXTERNAL_QTBASE_PROTOCOL_INPUTS_V1',
            qtbase_revision='025bdad181de241e81bf853c8a2d7bf3d19261a9', actual_native_prefix=None,
            source_legal_acceptance=None, files=dependency_files)).encode()
        self.dependency_policy.write_bytes(raw)
        self.real_dependency_pin = dict(S.DEPENDENCY_POLICY_PIN)
        dependency_seam = patch.object(S, 'DEPENDENCY_POLICY_PIN', S.pin(raw))
        dependency_seam.start()
        self.addCleanup(dependency_seam.stop)
        # MODEL seams are test-process patches only; production has no switch.
        qml_source_files = {name:S.pin(b'MODEL original source QML\n') for name in S.QML_SOURCE_FILES}
        source_seam = patch.object(S, 'QML_SOURCE_FILES', qml_source_files)
        source_seam.start()
        self.addCleanup(source_seam.stop)
        for module in S.MODULES + S.PRIVATE_MODULES:
            library = 'libQt6'+module
            self.put('usr/lib/'+library+'.so.6.12.0', model_elf(library+'.so.6'))
            (self.root/('usr/lib/'+library+'.so.6')).symlink_to(library+'.so.6.12.0')
            (self.root/('usr/lib/'+library+'.so')).symlink_to(library+'.so.6')
            if module in S.MODULES:
                required = ('usr/include/qt6/Qt'+module+'/Qt'+module,
                    'usr/lib/pkgconfig/Qt6'+module+'.pc',
                    'usr/lib/cmake/Qt6'+module+'/Qt6'+module+'Config.cmake')
            else:
                required = ('usr/include/qt6/Qt'+module+'/6.12.0/Qt'+module+'/private/waylandeglclientbufferintegration_p.h',
                    'usr/lib/cmake/Qt6'+module+'Private/Qt6'+module+'PrivateConfig.cmake')
            for name in required:
                self.put(name, b'MODEL development metadata\n')
        self.put('usr/lib/cmake/Qt6'+S.HEADER_MODULE+'/Qt6'+S.HEADER_MODULE+'Config.cmake', b'MODEL header-only target\n')
        for plugin in S.PLUGINS:
            self.put('usr/lib/qt6/plugins/'+plugin, model_elf())
        for uri, (plugin, target) in S.QML_MODULES.items():
            directory = 'usr/lib/qt6/qml/'+uri.replace('.', '/')
            typeinfo = 'WaylandCompositor.qmltypes' if uri == 'QtWayland.Compositor' else 'plugins.qmltypes'
            raw = f'module {uri}\noptional plugin {plugin}\nlinktarget Qt6::{target}\ntypeinfo {typeinfo}\n'
            self.put(directory+'/qmldir', raw.encode())
            self.put(directory+'/'+typeinfo, b'MODEL generated qmltypes\n')
            self.put(directory+'/lib'+plugin+'.so', model_elf())
        for name in S.QML_SOURCE_FILES:
            self.put('usr/lib/qt6/qml/QtWayland/Compositor/'+name, b'MODEL original source QML\n')

    def put(self, name, raw):
        path = self.root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o755 if raw.startswith(b'\x7fELF') else 0o644)
        return path

    def inspect(self):
        return S.inspect(self.root, license_manifest=self.policy, dependency_policy=self.dependency_policy)

    def test_MODEL_full_Quick_stage_has_six_shared_modules_eight_QML(self):
        report = self.inspect()
        self.assertEqual(len(S.MODULES+S.PRIVATE_MODULES), 6)
        self.assertEqual(len(report['qml']), 8)
        self.assertEqual(len(report['elf']), 6+7+8)
        self.assertEqual(report['native_execution'], 'NOT_ESTABLISHED')
        self.assertIsNone(report['native_acceptance'])
        self.assertEqual(report['hardware'], 'NOT_ESTABLISHED')
        self.assertEqual(report['dependency_notice_files'], 52)
        self.assertEqual(report['dependency_feature_gate'], 'HELD_GUI18_WAYLAND_SERVER_OFF_NO_FEATURE_WAIVER')
        self.assertIsNone(next(iter(report['elf'].values()))['version_definitions'])

    def test_MODEL_header_only_target_is_not_a_shared_library(self):
        self.assertTrue(self.inspect())
        self.put('usr/lib/libQt6WaylandClientFeatures.so.6.12.0', model_elf('libQt6WaylandClientFeatures.so.6'))
        with self.assertRaisesRegex(ValueError, 'ownership/no GUI18 overlap'):
            self.inspect()

    def test_MODEL_missing_Quick_plugin_refused(self):
        uri = 'QtWayland.Compositor.QtShell'
        name = 'usr/lib/qt6/qml/'+uri.replace('.', '/')+'/lib'+S.QML_MODULES[uri][0]+'.so'
        (self.root/name).unlink()
        with self.assertRaisesRegex(ValueError, 'full Quick QML plugin'):
            self.inspect()

    def test_MODEL_missing_backing_module_refused(self):
        path = self.root/'usr/lib/libQt6WaylandCompositorXdgShell.so.6.12.0'
        path.unlink()
        with self.assertRaises(ValueError):
            self.inspect()

    def test_MODEL_missing_typeinfo_refused(self):
        (self.root/'usr/lib/qt6/qml/QtWayland/Client/TextureSharing/plugins.qmltypes').unlink()
        with self.assertRaisesRegex(ValueError, 'typeinfo body'):
            self.inspect()

    def test_MODEL_original_Quick_source_QML_required(self):
        self.put('usr/lib/qt6/qml/QtWayland/Compositor/qmlfiles/WaylandOutputWindow.qml', b'changed\n')
        with self.assertRaisesRegex(ValueError, 'original full Quick source QML'):
            self.inspect()

    def test_MODEL_wrong_QML_URI_or_plugin_refused(self):
        path = self.root/'usr/lib/qt6/qml/QtWayland/Compositor/qmldir'
        raw = path.read_bytes()
        for changed in (raw.replace(b'module QtWayland.Compositor', b'module MODEL.WRONG'),
                        raw.replace(b'plugin qwaylandcompositorplugin', b'plugin MODEL_WRONG')):
            path.write_bytes(changed)
            with self.assertRaisesRegex(ValueError, 'QML module URI|QML plugin declaration'):
                self.inspect()

    def test_MODEL_no_GUI18_or_unselected_provider_overlap(self):
        for name in ('usr/lib/libQt6WaylandClient.so.6.12.0', 'usr/lib/qt6/plugins/platforms/libqwayland.so',
                     'usr/lib/cmake/Qt6WaylandClient/Qt6WaylandClientConfig.cmake',
                     'usr/lib/qt6/plugins/wayland-decoration-client/libbradient.so'):
            with self.subTest(name=name):
                path = self.put(name, b'MODEL forbidden duplicate')
                with self.assertRaisesRegex(ValueError, 'ownership/no GUI18 overlap'):
                    self.inspect()
                path.unlink()
                while path.parent != self.root and not any(path.parent.iterdir()):
                    path = path.parent
                    path.rmdir()

    def test_MODEL_AArch64_16K_required_for_all_ELF(self):
        path = 'usr/lib/qt6/plugins/'+S.PLUGINS[0]
        for machine in (62, 40):
            self.put(path, model_elf(machine=machine))
            with self.assertRaisesRegex(ValueError, 'AArch64 architecture'):
                self.inspect()
        body = bytearray(model_elf())
        struct.pack_into('<Q', body, 112, 4096)
        self.put(path, body)
        with self.assertRaisesRegex(ValueError, '16K load geometry'):
            self.inspect()

    def test_MODEL_notice_inventory_and_production_pin(self):
        with patch.object(S, 'NOTICE_POLICY_PIN', self.real_policy_pin):
            with self.assertRaisesRegex(ValueError, 'frozen QtWayland source notice policy'):
                self.inspect()
        self.put(S.NOTICE_ROOT+'/EXTRA.txt', b'MODEL extra\n')
        with self.assertRaisesRegex(ValueError, 'complete actual QtWayland'):
            self.inspect()

    def test_MODEL_unsafe_aliases_and_hardlinks_refused(self):
        path = self.root/'usr/lib/libQt6WaylandCompositor.so'
        path.unlink()
        path.symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError, 'escaping stage link'):
            self.inspect()
        path.unlink()
        path.symlink_to('libQt6WaylandCompositor.so.6')
        os.link(self.root/'usr/lib/libQt6WaylandCompositor.so.6.12.0', self.base/'hardlink')
        with self.assertRaisesRegex(ValueError, 'single-link'):
            self.inspect()

    def test_MODEL_external_dependency_license_bytes_and_policy_are_closed(self):
        with patch.object(S, 'DEPENDENCY_POLICY_PIN', self.real_dependency_pin):
            with self.assertRaisesRegex(ValueError, 'frozen Qtbase dependency notice policy'):
                self.inspect()
        self.put(S.DEPENDENCY_NOTICE_ROOT+'/share/qt6/wayland/protocols/MODEL-0.txt', b'changed\n')
        with self.assertRaisesRegex(ValueError, 'complete actual Qtbase dependency'):
            self.inspect()

    def test_MODEL_dependency_notices_no_symlink_or_omission(self):
        path = self.root/(S.DEPENDENCY_NOTICE_ROOT+'/share/qt6/wayland/protocols/MODEL-0.txt')
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'complete actual Qtbase dependency'):
            self.inspect()
        path.symlink_to('MODEL-1.txt')
        with self.assertRaisesRegex(ValueError, 'complete actual Qtbase dependency'):
            self.inspect()

    def test_MODEL_actor_fence_precedes_stage_import(self):
        for event in ('subprocess.Popen', 'socket.__new__', 'ctypes.dlopen', 'os.system'):
            with self.subTest(event=event), self.assertRaisesRegex(ValueError, 'NO_ACTORS'):
                sys.audit(event)

    def test_MODEL_inventory_caps_refuse(self):
        for field in ('MAX_ENTRIES', 'MAX_FILE_BYTES', 'MAX_PAYLOAD_BYTES'):
            with self.subTest(field=field), patch.object(S, field, 1), self.assertRaisesRegex(ValueError, 'cap'):
                self.inspect()


class SourceAlgorithmPins(unittest.TestCase):
    def test_verbatim_original_whole_pinned_ELF_algorithm(self):
        raw = (HERE.parent/'qt612-gui-source-reference/check_stage.py').read_bytes()
        self.assertEqual(S.pin(raw), S.ELF_ORIGIN_PIN)
        def function(source):
            tree = ast.parse(source)
            return ast.get_source_segment(source.decode(), next(node for node in tree.body
                if isinstance(node, ast.FunctionDef) and node.name == 'elf_info')).encode()
        expected, actual = function(raw), function((HERE/'check_stage.py').read_bytes())
        self.assertEqual(S.pin(actual), S.ELF_FUNCTION_PIN)
        self.assertEqual(actual, expected)

    def test_genuine_source_policy_and_exact_declarative_helpers(self):
        self.assertEqual(S.pin((HERE/'source-notices.json').read_bytes()), S.NOTICE_POLICY_PIN)
        self.assertEqual(S.pin((HERE/'dependency-inputs.json').read_bytes()), S.DEPENDENCY_POLICY_PIN)
        dependency = json.loads((HERE/'dependency-inputs.json').read_bytes())
        self.assertEqual(len(dependency['files']), 52)
        self.assertEqual(sum(row['bytes'] for row in dependency['files'].values()), 449254)
        for name, expected in S.QML_HELPER_PINS.items():
            self.assertEqual(S.pin((HERE/'upstream/declarative-build-helpers'/name).read_bytes()), expected)


if __name__ == '__main__':
    unittest.main()
