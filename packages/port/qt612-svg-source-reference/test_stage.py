# SPDX-License-Identifier: MIT
"""Synthetic MODEL ELF/layout controls only; these are not usable Qt packages."""
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('qtsvg612_stage_model', Path(__file__).with_name('check_stage.py'))
S = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(S)


def reject_actors(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.fork', 'os.posix_spawn')) or event in (
            'os.system', 'os.kill', 'os.killpg', 'os.pidfd_open', 'fcntl.flock', 'resource.setrlimit'):
        raise ValueError('QT612_SVG_MODEL_NO_ACTORS_OR_KERNEL_CUSTODY')


sys.addaudithook(reject_actors)


def model_elf(soname=None, needed=('libQt6Core.so.6', 'libQt6Gui.so.6'), machine=183):
    body = bytearray(1024)
    body[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', body, 16, 3, machine, 1)
    struct.pack_into('<Q', body, 32, 64)
    struct.pack_into('<HHH', body, 52, 64, 56, 2)
    struct.pack_into('<IIQQQQQQ', body, 64, 1, 5, 0, 0x10000, 0x10000, 1024, 1024, 16384)
    struct.pack_into('<IIQQQQQQ', body, 120, 2, 6, 256, 0x10100, 0x10100, 128, 128, 8)
    strings, entries = bytearray(b'\0'), []
    for value in needed:
        entries.append((1, len(strings)))
        strings.extend(value.encode() + b'\0')
    if soname:
        entries.append((14, len(strings)))
        strings.extend(soname.encode() + b'\0')
    entries.extend(((5, 0x10200), (10, len(strings)), (0, 0)))
    for index, item in enumerate(entries):
        struct.pack_into('<qQ', body, 256 + index * 16, *item)
    body[512:512 + len(strings)] = strings
    return bytes(body)


class SvgStageModelControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='qt612-svg-stage-MODEL-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / 'stage'
        self.root.mkdir()
        self.references = self.base / 'MODEL-references'
        self.references.mkdir()
        self.reference_patch = patch.object(S, 'REFERENCE_DIR', self.references)
        self.reference_patch.start()
        self.addCleanup(self.reference_patch.stop)
        notices = {'LICENSES/MODEL.txt': b'MODEL notice one\n', 'src/REUSE.toml': b'MODEL grant two\n'}
        self.policy = {'schema_version': 1, 'source_notices': {name: S.sha(raw) for name, raw in notices.items()}}
        self.policy_path = self.references / 'source-notices.json'
        self.policy_path.write_text(json.dumps(self.policy, sort_keys=True))
        for source, staged in (('LICENSE.packaging', 'LICENSE.packaging'),
                               ('LICENSE.third-party', 'LicenseRef-Qt-ThirdParty.txt')):
            raw = ('MODEL packaging notice ' + source + '\n').encode()
            (self.references / source).write_bytes(raw)
            self.put(S.LICENSE_ROOT + '/' + staged, raw)
        self.put(S.LICENSE_ROOT + '/source-notices.json', self.policy_path.read_bytes())
        for name, raw in notices.items():
            self.put(S.NOTICE_ROOT + '/' + name, raw)
        for module in S.MODULES:
            library = f'libQt6{module}.so'
            self.put('usr/lib/' + library + '.6.12.0', model_elf(soname=library + '.6'))
            (self.root / ('usr/lib/' + library + '.6')).symlink_to(library + '.6.12.0')
            (self.root / ('usr/lib/' + library)).symlink_to(library + '.6')
            for name in (f'usr/include/qt6/Qt{module}/Qt{module}', f'usr/lib/libQt6{module}.prl',
                         f'usr/lib/pkgconfig/Qt6{module}.pc', f'usr/lib/cmake/Qt6{module}/Qt6{module}Config.cmake',
                         f'usr/lib/qt6/modules/{module}.json',
                         f'usr/lib/qt6/metatypes/qt6{module.lower()}_metatypes.json'):
                self.put(name)
            self.put(f'usr/include/qt6/Qt{module}/qt{module.lower()}version.h',
                     f'#define QT{module.upper()}_VERSION_STR "6.12.0"\n'.encode())
        for name in ('usr/include/qt6/QtSvg/6.12.0/QtSvg/private/qsvghandler_p.h',
                     'usr/include/qt6/QtSvg/QSvgRenderer', 'usr/include/qt6/QtSvg/qsvgrenderer.h',
                     'usr/include/qt6/QtSvg/QSvgGenerator', 'usr/include/qt6/QtSvg/qsvggenerator.h',
                     'usr/include/qt6/QtSvgWidgets/QSvgWidget', 'usr/include/qt6/QtSvgWidgets/qsvgwidget.h',
                     'usr/lib/cmake/Qt6SvgPrivate/Qt6SvgPrivateConfig.cmake',
                     'usr/lib/cmake/Qt6Gui/Qt6QSvgPluginConfig.cmake',
                     'usr/lib/cmake/Qt6Gui/Qt6QSvgIconPluginConfig.cmake',
                     *('usr/lib/qt6/mkspecs/modules/' + name for name in S.PRI)):
            self.put(name)
        for name in S.PLUGINS:
            self.put('usr/lib/qt6/plugins/' + name, model_elf(needed=('libQt6Svg.so.6', 'libQt6Core.so.6')))

    def put(self, name, raw=b'Synthetic MODEL development metadata\n'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o755 if raw.startswith(b'\x7fELF') else 0o644)
        return path

    def inspect(self, arch='aarch64'):
        return S.inspect(self.root, arch, self.policy_path)

    def test_complete_model_reports_whole_inventory_needed_and_limits(self):
        value = self.inspect()
        self.assertEqual(value['status'], 'PASS_QT612_SVG_DESTDIR_CONTRACT_ONLY')
        self.assertEqual(len(value['elf']), 4)
        self.assertEqual(len(value['symlinks']), 4)
        self.assertEqual(value['elf']['usr/lib/libQt6Svg.so.6.12.0']['needed'], ['libQt6Core.so.6', 'libQt6Gui.so.6'])
        self.assertEqual(value['elf']['usr/lib/libQt6Svg.so.6.12.0']['load_geometry'], 'PASS_STATIC_16K_PT_LOAD_ONLY')
        self.assertEqual(value['elf']['usr/lib/libQt6Svg.so.6.12.0']['load_segments'][0]['alignment'], 16384)
        self.assertEqual(value['native_execution'], 'NOT_ESTABLISHED')
        self.assertEqual(value['installation'], 'NOT_RUN')
        self.assertEqual(value['hardware'], 'NOT_RUN')
        self.assertEqual(value['payload_bytes'], sum(row['bytes'] for row in value['files'].values()))

    def test_actor_audit_is_refused_without_starting_an_actor(self):
        with self.assertRaisesRegex(ValueError, 'NO_ACTORS'):
            sys.audit('socket.connect')

    def test_x86_payload_requires_explicit_host_selection(self):
        for path in self.root.rglob('*'):
            if path.is_file() and not path.is_symlink():
                raw = path.read_bytes()
                if raw.startswith(b'\x7fELF'):
                    raw = bytearray(raw); struct.pack_into('<H', raw, 18, 62); path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, 'architecture'):
            self.inspect()
        self.assertEqual(self.inspect('x86_64')['evidence_scope'], 'HOST_X86_64_STAGE_ONLY')

    def test_wrong_soname_and_missing_module_refuse(self):
        path = self.put('usr/lib/libQt6Svg.so.6.12.0', model_elf(soname='libQt6Svg.so.7'))
        with self.assertRaisesRegex(ValueError, 'SONAME'):
            self.inspect()
        path.unlink()
        with self.assertRaises(ValueError):
            self.inspect()

    def test_missing_plugin_and_private_metadata_refuse(self):
        for name in ('usr/lib/qt6/plugins/' + S.PLUGINS[0],
                     'usr/lib/cmake/Qt6SvgPrivate/Qt6SvgPrivateConfig.cmake',
                     'usr/include/qt6/QtSvg/6.12.0/QtSvg/private/qsvghandler_p.h',
                     'usr/lib/qt6/mkspecs/modules/qt_lib_svgwidgets.pri'):
            with self.subTest(name=name):
                path = self.root / name; raw = path.read_bytes(); mode = path.stat().st_mode
                path.unlink()
                with self.assertRaises(ValueError):
                    self.inspect()
                self.put(name, raw).chmod(mode & 0o777)

    def test_wrong_version_header_refuses(self):
        self.put('usr/include/qt6/QtSvg/qtsvgversion.h', b'#define QTSVG_VERSION_STR "6.11.0"\n')
        with self.assertRaisesRegex(ValueError, 'version header'):
            self.inspect()

    def test_no_qtbase_platform_or_unowned_private_module_files(self):
        for name in ('usr/lib/libQt6Core.so.6.12.0', 'usr/include/qt6/QtGui/qguiapplication.h',
                     'usr/lib/cmake/Qt6Gui/Qt6GuiConfig.cmake',
                     'usr/lib/cmake/Qt6SvgWidgetsPrivate/Qt6SvgWidgetsPrivateConfig.cmake',
                     'usr/lib/qt6/plugins/platforms/libqoffscreen.so',
                     'usr/lib/qt6/plugins/imageformats/libqjpeg.so',
                     'usr/lib/qt6/mkspecs/modules/qt_lib_core.pri', 'usr/lib/libQt6Svg.so.7',
                     S.LICENSE_ROOT + '/dependency-contract.json'):
            with self.subTest(name=name):
                path = self.put(name)
                with self.assertRaisesRegex(ValueError, 'ownership'):
                    self.inspect()
                path.unlink()
                while path.parent != self.root and not any(path.parent.iterdir()):
                    path = path.parent; path.rmdir()

    def test_hooks_services_platform_and_private_paths_refuse(self):
        for name in ('boot/kernel', 'etc/profile', 'usr/share/libalpm/hooks/qt.hook',
                     'usr/lib/systemd/system/qt.service', 'usr/share/alsa/qt.conf',
                     S.NOTICE_ROOT + '/.SSH/key'):
            with self.subTest(name=name):
                path = self.put(name)
                with self.assertRaises(ValueError):
                    self.inspect()
                path.unlink()
                while path.parent != self.root and not any(path.parent.iterdir()):
                    path = path.parent; path.rmdir()

    def test_absolute_dangling_cyclic_and_other_links_refuse(self):
        path = self.root / 'usr/lib/libQt6Svg.so'
        for target in ('/usr/lib/libQt6Svg.so.6', 'missing', 'libQt6Svg.so', '../../../../outside'):
            with self.subTest(target=target):
                path.unlink(); path.symlink_to(target)
                with self.assertRaises(ValueError):
                    self.inspect()

    def test_hardlinks_fifo_and_unsafe_modes_refuse(self):
        path = self.root / 'usr/include/qt6/QtSvg/QSvgRenderer'
        raw = path.read_bytes()
        path.chmod(0o664)
        with self.assertRaisesRegex(ValueError, 'unsafe'):
            self.inspect()
        path.chmod(0o644)
        os.link(path, self.base / 'MODEL-hardlink')
        with self.assertRaisesRegex(ValueError, 'single-link'):
            self.inspect()
        path.unlink(); os.mkfifo(path, 0o644)
        with self.assertRaisesRegex(ValueError, 'single-link'):
            self.inspect()

    def test_notice_corpus_missing_changed_extra_and_packaging_policy_refuse(self):
        path = self.root / (S.NOTICE_ROOT + '/LICENSES/MODEL.txt')
        raw = path.read_bytes()
        path.write_bytes(b'changed\n')
        with self.assertRaisesRegex(ValueError, 'notice corpus'):
            self.inspect()
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'notice corpus'):
            self.inspect()
        self.put(str(path.relative_to(self.root)), raw)
        extra = self.put(S.NOTICE_ROOT + '/unreviewed.txt')
        with self.assertRaisesRegex(ValueError, 'notice corpus'):
            self.inspect()
        extra.unlink()
        self.put(S.LICENSE_ROOT + '/source-notices.json', b'{}')
        with self.assertRaisesRegex(ValueError, 'packaging license/policy'):
            self.inspect()

    def test_notice_policy_schema_duplicate_paths_and_booleans_refuse(self):
        for policy in ({'schema_version': True, 'source_notices': self.policy['source_notices']},
                       {'schema_version': 1, 'source_notices': {'../outside': 'f' * 64}},
                       {'schema_version': 1, 'source_notices': {}, 'extra': True}):
            with self.subTest(policy=policy):
                self.policy_path.write_text(json.dumps(policy))
                with self.assertRaises(ValueError):
                    self.inspect()
        self.policy_path.write_bytes(b'{"schema_version":1,"schema_version":1,"source_notices":{}}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.inspect()

    def test_bounded_elf_strings_and_headers_refuse(self):
        for position, format_, value in ((32, '<Q', 4096), (264, '<Q', 99999), (328, '<Q', 99999)):
            with self.subTest(position=position):
                raw = bytearray(model_elf(soname='libQt6Svg.so.6'))
                struct.pack_into(format_, raw, position, value)
                with self.assertRaises(ValueError):
                    S.elf_info(raw, 183)

    def test_4k_nonpower_alignment_and_offset_vaddr_mismatch_refuse(self):
        for position, value in ((112, 4096), (112, 24576), (80, 0x10001), (112, 131072)):
            with self.subTest(position=position, value=value):
                raw = bytearray(model_elf(soname='libQt6Svg.so.6'))
                struct.pack_into('<Q', raw, position, value)
                with self.assertRaisesRegex(ValueError, 'static 16K PT_LOAD geometry'):
                    S.elf_info(raw, 183)

    def test_stage_entry_file_and_total_byte_caps(self):
        total = self.inspect()['payload_bytes']
        with patch.object(S, 'MAX_PAYLOAD_BYTES', total):
            self.assertEqual(self.inspect()['payload_bytes'], total)
        for name, value in (('MAX_ENTRIES', 1), ('MAX_FILE_BYTES', 1), ('MAX_PAYLOAD_BYTES', total - 1)):
            with self.subTest(cap=name), patch.object(S, name, value):
                with self.assertRaisesRegex(ValueError, 'cap'):
                    self.inspect()

    def test_sparse_over_64mib_refuses_before_body_read(self):
        path = self.root / 'usr/lib/libQt6Svg.so.6.12.0'
        with path.open('r+b') as stream:
            stream.truncate(64 * 1024**2 + 1)
        original = Path.read_bytes
        def guarded(selected):
            if selected == path:
                raise AssertionError('oversize payload reached body read')
            return original(selected)
        with patch.object(Path, 'read_bytes', guarded):
            with self.assertRaisesRegex(ValueError, 'byte cap'):
                self.inspect()

    def test_live_root_and_root_alias_refuse(self):
        alias = self.base / 'stage-alias'
        alias.symlink_to(self.root, target_is_directory=True)
        for root in (Path('/'), alias, Path('relative')):
            with self.subTest(root=str(root)), self.assertRaisesRegex(ValueError, 'private QtSvg staging root'):
                S.inspect(root, license_manifest=self.policy_path)


if __name__ == '__main__':
    unittest.main(verbosity=2)
