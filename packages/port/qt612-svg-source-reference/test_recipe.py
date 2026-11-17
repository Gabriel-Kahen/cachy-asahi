# SPDX-License-Identifier: MIT
"""Pinned recipe and structural dependency MODEL controls; no Qt/native result."""
import hashlib
import importlib.util
from pathlib import Path
import re
import struct
import sys
import tempfile
import unittest


def no_actors(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.fork', 'os.posix_spawn')) or event in (
            'os.system', 'fcntl.flock', 'resource.setrlimit', 'os.kill', 'os.killpg'):
        raise ValueError('SVG_RECIPE_MODEL_NO_ACTORS')


sys.addaudithook(no_actors)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('svg_recipe_source', HERE / 'source.py')
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)


class RecipeAndDependencies(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='qtsvg-dependency-MODEL-')
        self.addCleanup(temporary.cleanup); self.base = Path(temporary.name)
        self.prefix = self.base / 'qtbase'; self.prefix.mkdir()

    def put(self, name, raw=b'MODEL metadata, not evaluated CMake\n'):
        path = self.prefix / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
        return path

    def model_prefix(self):
        for module in S.BASE_MODULES:
            self.put(f'include/qt6/Qt{module}/qt{module.lower()}version.h',
                     f'#define QT{module.upper()}_VERSION_STR "6.12.0"\n'.encode())
        for module in S.BASE_CONFIGS: self.put(f'lib/cmake/{module}/{module}Config.cmake')
        for name in S.PRIVATE_HEADERS: self.put('include/qt6/' + name)
        body = bytearray(64); body[:7] = b'\x7fELF\x02\x01\x01'; struct.pack_into('<HHI', body, 16, 3, 183, 1)
        for module in S.BASE_MODULES: self.put(f'lib/libQt6{module}.so.6.12.0', body)
        for tool in ('moc', 'rcc', 'uic'): self.put('lib/qt6/' + tool, body).chmod(0o755)
        self.put('lib/qt6/plugins/platforms/libqoffscreen.so', body)

    def test_active_source_aliases_and_whole_sha256_join_srcinfo(self):
        fields = {}
        for line in (HERE / '.SRCINFO').read_text().splitlines():
            if ' = ' in line:
                key, value = line.strip().split(' = ', 1); fields.setdefault(key, []).append(value)
        self.assertEqual(len(fields['source']), len(fields['sha256sums']))
        for name, digest in zip(fields['source'], fields['sha256sums']):
            if name.startswith('https://'):
                self.assertTrue(name.endswith('/qtsvg-everywhere-src-6.12.0.tar.xz'))
                self.assertEqual(digest, 'e4ab39534ec97987b1b9b60ef7f4d3253d5912a69f8c713a01753174a4029331')
            else:
                self.assertEqual(hashlib.sha256((HERE / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(fields['depends'], ['glibc', 'libgcc', 'libstdc++', 'qt6-base=6.12.0', 'zlib'])
        self.assertEqual(fields['provides'], ['qt6-svg=6.12.0', 'libQt6Svg.so.6', 'libQt6SvgWidgets.so.6'])
        self.assertEqual(fields['conflicts'], ['qt6-svg'])
        self.assertEqual(fields['arch'], ['aarch64'])
        self.assertNotIn('replaces', fields); self.assertNotIn('install', fields)

    def test_normal_recipe_preflight_full_profile_and_owned_lifecycle(self):
        recipe = (HERE / 'PKGBUILD').read_text()
        for flag in ('--nodeps', '--nocheck', '--ignorearch', 'nproc', "'!check'"):
            self.assertNotIn(flag, recipe)
        build = recipe.split('build() {', 1)[1].split('\ncheck()', 1)[0]
        self.assertLess(build.index('dependencies --prefix /usr'), build.index('cmake -C'))
        self.assertIn('targets --build', build)
        self.assertIn('DESTDIR="$pkgdir" cmake --install', recipe)
        self.assertIn('QT612_OWN_PLUGIN_ROOT="$srcdir/build/lib/qt6/plugins"', recipe)
        profile = (HERE / 'configure.cmake').read_text()
        self.assertNotRegex(profile, r'FEATURE_(?:svg|widgets|graphicsview) OFF')
        for key in ('QT_BUILD_TESTS', 'QT_BUILD_DOCS', 'QT_BUILD_EXAMPLES', 'QT_GENERATE_SBOM'):
            self.assertIn(f'set({key} OFF CACHE BOOL "" FORCE)', profile)
        guard = (HERE / 'dependency_guard.cmake').read_text()
        self.assertIn('if(QT_NO_PACKAGE_VERSION_CHECK)', guard)
        self.assertIn('6.12.0 EXACT REQUIRED', guard)
        self.assertIn('CorePrivate GuiPrivate WidgetsPrivate CoreTools WidgetsTools', guard)
        self.assertIn('xmlstreamreader xmlstreamwriter cssparser widgets graphicsview system_zlib', guard)

    def test_positive_model_dependency_check_is_structural_only(self):
        self.model_prefix(); result = S.dependencies(self.prefix)
        self.assertEqual(result['status'], 'PASS_STRUCTURAL_QT612_PREFIX_ONLY')
        self.assertEqual(len(result['files']), 24)
        self.assertEqual(result['native_execution'], 'NOT_ESTABLISHED')
        self.assertEqual(result['source_ABI_provider'], 'ROOT_PINNED_PROVIDER_STILL_REQUIRED')

    def test_wrong_qt611_version_refuses_before_libraries(self):
        self.put('include/qt6/QtCore/qtcoreversion.h', b'#define QTCORE_VERSION_STR "6.11.2"\n')
        with self.assertRaisesRegex(ValueError, 'exactly 6.12.0'): S.dependencies(self.prefix)

    def test_missing_private_metadata_header_tool_and_platform_refuse(self):
        self.model_prefix()
        for name in ('lib/cmake/Qt6GuiPrivate/Qt6GuiPrivateConfig.cmake',
                     'include/qt6/' + S.PRIVATE_HEADERS[0], 'lib/qt6/moc',
                     'lib/qt6/plugins/platforms/libqoffscreen.so'):
            with self.subTest(name=name):
                path = self.prefix / name; raw = path.read_bytes(); path.unlink()
                with self.assertRaises((ValueError, OSError)): S.dependencies(self.prefix)
                self.put(name, raw)
                if name == 'lib/qt6/moc': (self.prefix / name).chmod(0o755)

    def test_nonexecutable_native_tool_refuses(self):
        self.model_prefix(); (self.prefix / 'lib/qt6/moc').chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'executable'): S.dependencies(self.prefix)

    def test_foreign_elf_and_aliased_private_inputs_refuse(self):
        self.model_prefix(); path = self.prefix / 'lib/libQt6Gui.so.6.12.0'; raw = path.read_bytes()
        changed = bytearray(raw); struct.pack_into('<H', changed, 18, 62); path.write_bytes(changed)
        with self.assertRaisesRegex(ValueError, 'AArch64'): S.dependencies(self.prefix)
        path.write_bytes(raw)
        header = self.prefix / ('include/qt6/' + S.PRIVATE_HEADERS[0]); header.unlink()
        header.symlink_to(self.prefix / ('include/qt6/' + S.PRIVATE_HEADERS[1]))
        with self.assertRaises(ValueError): S.dependencies(self.prefix)

    def test_partial_generated_module_or_plugin_metadata_cannot_pass(self):
        build = self.base / 'build'
        for name in S.GENERATED_CONFIGS:
            path = build / 'lib/cmake' / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(b'MODEL_CFG')
        result = S.targets(build)
        self.assertEqual(result['status'], 'PASS_GENERATED_SVG_TARGET_METADATA_ONLY')
        self.assertEqual(len(result['files']), 5)
        for name in S.GENERATED_CONFIGS:
            path = build / 'lib/cmake' / name; path.unlink()
            with self.assertRaises((ValueError, OSError)): S.targets(build)
            path.write_bytes(b'MODEL_CFG')


if __name__ == '__main__': unittest.main(verbosity=2)
