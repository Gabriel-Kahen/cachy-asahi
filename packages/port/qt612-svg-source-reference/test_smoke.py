#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SOURCE controls only: inspect smoke contracts and parse its owned SVG fixture.

No CMake evaluation, compiler discovery, Qt loading, rendering or native acceptance
is established by these tests. The real recipe check() must execute the smoke.
"""
import sys


def actor_fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.fork', 'os.posix_spawn')) or event in {
        'os.system', 'fcntl.flock', 'resource.setrlimit', 'os.kill', 'os.killpg',
    }:
        raise RuntimeError('SOURCE_SVG_SMOKE_ACTOR_FENCE:' + event)


sys.addaudithook(actor_fence)

from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
MARKER = 'PASS_QT612_SVG_OFFSCREEN_API_RENDER_ONLY'


def command(source, name, first=None):
    found = re.findall(r'(?m)^' + re.escape(name) + r'\(([^)]*)\)', source)
    if first:
        found = [value for value in found if value.split()[0] == first]
    if len(found) != 1:
        raise ValueError('one simple source command required: ' + name)
    return found[0].split()


class SourceSmokeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.smoke = (ROOT/'smoke.cpp').read_text()
        cls.cmake = (ROOT/'SmokeCMakeLists.txt').read_text()

    def test_controls_refuse_actor_events(self):
        for event in ('subprocess.Popen', 'socket.connect', 'ctypes.dlopen', 'os.system', 'resource.setrlimit'):
            with self.subTest(event=event), self.assertRaisesRegex(RuntimeError, 'SOURCE_SVG_SMOKE_ACTOR_FENCE'):
                sys.audit(event)

    def test_two_canonical_explicit_roots_and_registry_guards(self):
        for expression in ('foreach(_root IN ITEMS QT612_BUILD_TREE QT612_DEPENDENCY_PREFIX)',
                           'NOT IS_ABSOLUTE "${${_root}}"',
                           'NOT IS_DIRECTORY "${${_root}}/lib/cmake"',
                           'file(REAL_PATH "${${_root}}" _canonical)',
                           'NOT "${${_root}}" STREQUAL "${_canonical}"',
                           'if(QT612_BUILD_TREE STREQUAL QT612_DEPENDENCY_PREFIX)',
                           'set(CMAKE_FIND_USE_PACKAGE_REGISTRY OFF)',
                           'set(CMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY OFF)'):
            with self.subTest(expression=expression):
                self.assertIn(expression, self.cmake)

    def test_exact_base_discovery_has_only_base_components(self):
        self.assertEqual(command(self.cmake, 'find_package', 'Qt6'),
                         ['Qt6', '6.12.0', 'EXACT', 'REQUIRED', 'COMPONENTS', 'Core', 'Gui', 'Widgets',
                          'CONFIG', 'PATHS', '"${QT612_DEPENDENCY_PREFIX}/lib/cmake/Qt6"', 'NO_DEFAULT_PATH'])
        self.assertIn('set(Qt6_DIR "${QT612_DEPENDENCY_PREFIX}/lib/cmake/Qt6" CACHE PATH "" FORCE)', self.cmake)
        self.assertIn('NOT Qt6_DIR STREQUAL "${QT612_DEPENDENCY_PREFIX}/lib/cmake/Qt6"', self.cmake)

    def test_svg_configs_and_module_target_roots_are_distinct_from_base(self):
        self.assertIn('set(_qt612_base_modules Core Gui Widgets)', self.cmake)
        self.assertIn('set(_qt612_svg_modules Svg SvgWidgets)', self.cmake)
        for module in ('Svg', 'SvgWidgets'):
            self.assertEqual(command(self.cmake, 'find_package', 'Qt6'+module),
                             ['Qt6'+module, '6.12.0', 'EXACT', 'REQUIRED', 'CONFIG', 'PATHS',
                              '"${QT612_BUILD_TREE}/lib/cmake/Qt6'+module+'"', 'NO_DEFAULT_PATH'])
        for expression in ('NOT EXISTS "${_config}/Qt6${_module}Config.cmake"',
                           'set(Qt6${_module}_DIR "${_config}" CACHE PATH "" FORCE)',
                           'qt612_require_imported("${_module}" "${QT612_DEPENDENCY_PREFIX}")',
                           'qt612_require_imported("${_module}" "${QT612_BUILD_TREE}")'):
            self.assertIn(expression, self.cmake)

    def test_imported_targets_guard_exact_version_every_config_and_file(self):
        for expression in ('NOT TARGET Qt6::${_module}',
                           'NOT Qt6${_module}_DIR STREQUAL "${_root}/lib/cmake/Qt6${_module}"',
                           'get_target_property(_imported Qt6::${_module} IMPORTED)',
                           'get_target_property(_version Qt6::${_module} _qt_package_version)',
                           'get_target_property(_configs Qt6::${_module} IMPORTED_CONFIGURATIONS)',
                           'NOT _imported OR NOT _version STREQUAL "6.12.0" OR NOT _configs',
                           'set(_expected "${_root}/lib/libQt6${_module}.so.6.12.0")',
                           'foreach(_configuration IN LISTS _configs)',
                           'get_target_property(_location Qt6::${_module} IMPORTED_LOCATION_${_configuration})',
                           'NOT _location STREQUAL _expected OR NOT EXISTS "${_location}"',
                           'file(REAL_PATH "${_location}" _real_location)',
                           'NOT _real_location STREQUAL _expected',
                           '_generic_location AND NOT _generic_location STREQUAL _expected'):
            with self.subTest(expression=expression):
                self.assertIn(expression, self.cmake)

    def test_standard_cpp_linkage_and_no_cmake_actor_or_link_fallback(self):
        self.assertEqual(command(self.cmake, 'add_executable'), ['qt612-smoke', 'smoke.cpp'])
        self.assertEqual(command(self.cmake, 'target_link_libraries'),
                         ['qt612-smoke', 'PRIVATE', 'Qt6::Core', 'Qt6::Gui', 'Qt6::Widgets', 'Qt6::Svg', 'Qt6::SvgWidgets'])
        self.assertEqual(command(self.cmake, 'target_compile_features'), ['qt612-smoke', 'PRIVATE', 'cxx_std_17'])
        self.assertNotRegex(self.cmake.lower(), r'fetchcontent|externalproject|execute_process|add_custom_|find_library|link_directories')

    def test_inline_svg_is_valid_small_owned_geometry_without_external_content(self):
        fixtures = re.findall(r'R"SVG\((.*?)\)SVG"', self.smoke, re.S)
        self.assertEqual(len(fixtures), 1)
        self.assertLess(len(fixtures[0]), 1024)
        root = ET.fromstring(fixtures[0])
        self.assertEqual(root.tag, '{http://www.w3.org/2000/svg}svg')
        self.assertEqual(root.attrib, dict(width='32', height='32', viewBox='0 0 32 32'))
        self.assertEqual([child.attrib for child in root], [
            dict(x='4', y='4', width='12', height='24', fill='#d31f2f'),
            dict(x='16', y='4', width='12', height='24', fill='#11ad59')])
        self.assertTrue(all(child.tag == '{http://www.w3.org/2000/svg}rect' for child in root))
        self.assertNotRegex(fixtures[0], r'href|script|image|text|animate|filter|url\(')

    def test_direct_renderer_checks_actual_color_and_transparency(self):
        for expression in ('QSvgRenderer renderer;', '!renderer.load(svg)', '!renderer.isValid()',
                           'renderer.animated()', 'renderer.defaultSize() != QSize(32, 32)',
                           'renderer.render(&painter);', 'image.fill(Qt::transparent);',
                           '!pattern(raster(renderer), 32)',
                           'image.pixelColor(extent / 4, extent / 2) == QColor(211, 31, 47)',
                           'image.pixelColor(3 * extent / 4, extent / 2) == QColor(17, 173, 89)',
                           'qAlpha(image.pixel(0, 0)) == 0',
                           'qAlpha(image.pixel(extent - 1, extent - 1)) == 0'):
            self.assertIn(expression, self.smoke)

    def test_generator_paints_buffer_then_validates_roundtrip_rendering(self):
        for expression in ('QBuffer output(&generated);', 'QSvgGenerator generator;',
                           'generator.setOutputDevice(&output);', 'generator.setSize(QSize(32, 32));',
                           'generator.setViewBox(QRect(0, 0, 32, 32));', '!painter.begin(&generator)',
                           'painter.fillRect(QRect(4, 4, 24, 24), QColor(17, 31, 211));', '!painter.end()',
                           'generated.size() > 65536', '!roundtrip.load(generated)',
                           'roundtrip.viewBox() != QRect(0, 0, 32, 32)',
                           'regenerated.pixelColor(16, 16) != QColor(17, 31, 211)',
                           'qAlpha(regenerated.pixel(0, 0)) != 0'):
            self.assertIn(expression, self.smoke)
        self.assertLess(self.smoke.index('output.close();'), self.smoke.index('roundtrip.load(generated)'))

    def test_svgwidgets_uses_a_real_widget_paint(self):
        for expression in ('QSvgWidget widget;', 'widget.load(svg);', 'widget.resize(32, 32);',
                           '!widget.renderer()->isValid()', 'widget.render(&widgetImage);',
                           '!pattern(widgetImage, 32, false)'):
            self.assertIn(expression, self.smoke)

    def test_image_and_scalable_icon_factories_have_meaningful_pixel_checks(self):
        for expression in ('QImageReader::supportedImageFormats().contains(QByteArray("svg"))',
                           'QImageReader reader(&input, QByteArray("svg"));', '!reader.canRead()',
                           '!pattern(reader.read(), 32)', 'QStringLiteral("smoke.svg")',
                           'file.write(svg) != svg.size()', '!file.flush()', 'QIcon icon(svgPath);',
                           'icon.pixmap(QSize(64, 64), 1.0, QIcon::Normal, QIcon::Off).toImage()',
                           'icon.isNull() || !pattern(iconImage, 64)'):
            self.assertIn(expression, self.smoke)

    def test_own_plugin_root_is_compile_bound_and_only_runtime_search_root(self):
        self.assertIn('QT612_EXPECTED_PLUGIN_ROOT=\\"${QT612_BUILD_TREE}/lib/qt6/plugins\\"', self.cmake)
        for expression in ('qEnvironmentVariable("QT612_OWN_PLUGIN_ROOT")',
                           'ownRoot != QString::fromUtf8(QT612_EXPECTED_PLUGIN_ROOT)',
                           '!root.isAbsolute()', '!root.isDir()', 'root.canonicalFilePath() != ownRoot',
                           'file.isFile() && !file.isSymLink() && file.canonicalFilePath() == path',
                           'S_ISREG(info.st_mode) && info.st_nlink == 1',
                           'QStringLiteral("/imageformats/libqsvg.so")',
                           'QStringLiteral("/iconengines/libqsvgicon.so")',
                           'QCoreApplication::setLibraryPaths(QStringList{ownRoot});',
                           'QCoreApplication::libraryPaths() != QStringList{ownRoot}',
                           '!imageLoader.instance() || !iconLoader.instance()',
                           'org.qt-project.Qt.QImageIOHandlerFactoryInterface',
                           'org.qt-project.Qt.QIconEngineFactoryInterface'):
            self.assertIn(expression, self.smoke)
        self.assertLess(self.smoke.index('QApplication app'), self.smoke.index('setLibraryPaths'))
        self.assertLess(self.smoke.index('setLibraryPaths'), self.smoke.index('imageLoader.instance()'))
        self.assertLess(self.smoke.index('iconLoader.instance()'), self.smoke.index('QIcon icon'))

    def test_offscreen_exact_version_and_marker_only_after_all_success(self):
        self.assertIn('static_assert(QT_VERSION == QT_VERSION_CHECK(6, 12, 0));', self.smoke)
        self.assertIn('static_assert(std::string_view(QTSVG_VERSION_STR) == "6.12.0");', self.smoke)
        self.assertIn('static_assert(std::string_view(QTSVGWIDGETS_VERSION_STR) == "6.12.0");', self.smoke)
        self.assertIn('QString::fromLatin1(qVersion()) != QStringLiteral("6.12.0")', self.smoke)
        self.assertIn('app.platformName() != QStringLiteral("offscreen")', self.smoke)
        self.assertLess(self.smoke.index('qputenv("QT_QPA_PLATFORM", "offscreen")'), self.smoke.index('QApplication app'))
        self.assertEqual(self.smoke.count(MARKER), 1)
        self.assertIn('const int result = app.exec();\n    if (result == 0)\n        std::puts("'+MARKER+'");', self.smoke)
        self.assertLess(self.smoke.index('return 8;'), self.smoke.index('std::puts'))
        self.assertNotRegex(self.smoke, r'QOpenGL|QNetwork|QProcess|/dev/|wl_display|eglInitialize|gbm_create|\bsystem\s*\(')


if __name__ == '__main__':
    unittest.main()
