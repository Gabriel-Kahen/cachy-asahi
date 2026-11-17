#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SOURCE/MODEL contract controls only; no CMake, compilation or Qt execution.

These assertions inspect the proposed smoke sources. They cannot establish
CMake evaluation, library discovery, linking, runtime behavior or GPU support.
"""
import sys


def actor_fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.fork', 'os.posix_spawn')) or event in {
        'os.system', 'fcntl.flock', 'resource.setrlimit', 'os.kill', 'os.killpg',
    }:
        raise RuntimeError('SOURCE_MODEL_ACTOR_FENCE:' + event)


sys.addaudithook(actor_fence)

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parent
MODULES = ('Core', 'Gui', 'Network', 'Widgets', 'OpenGL', 'OpenGLWidgets', 'PrintSupport', 'WaylandClient')
COMPONENTS = ('Core', 'Network', 'Widgets', 'OpenGL', 'OpenGLWidgets', 'PrintSupport', 'WaylandClient')
PRIVATE_MODULES = ('EglFSDeviceIntegrationPrivate', 'EglFsKmsGbmSupportPrivate',
                   'EglFsKmsSupportPrivate', 'WlShellIntegrationPrivate')
MARKER = 'PASS_QT612_GUI_SERVER_OFFSCREEN_AND_LOCAL_DISPLAY_API_ONLY'


def command(source, name, *, first=None):
    """Read one simple source command; this is not a CMake interpreter."""
    found = re.findall(r'(?m)^' + re.escape(name) + r'\(([^)]*)\)', source)
    if first:
        found = [value for value in found if value.split()[0] == first]
    if len(found) != 1:
        raise ValueError('one source command required: ' + name)
    return found[0].split()


class SourceModelSmokeContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cmake = (ROOT / 'SmokeCMakeLists.txt').read_text()
        cls.smoke = (ROOT / 'smoke.cpp').read_text()

    def test_preimport_actor_fence(self):
        for event in ('subprocess.Popen', 'socket.connect', 'ctypes.dlopen', 'os.system', 'os.exec',
                      'os.fork', 'os.forkpty', 'os.posix_spawn', 'fcntl.flock', 'resource.setrlimit',
                      'os.kill', 'os.killpg'):
            with self.subTest(event=event), self.assertRaisesRegex(RuntimeError, 'SOURCE_MODEL_ACTOR_FENCE'):
                sys.audit(event)

    def test_finite_standard_exact_cmake_discovery(self):
        found = command(self.cmake, 'find_package', first='Qt6')
        self.assertEqual(found[:5], ['Qt6', '6.12.0', 'EXACT', 'REQUIRED', 'COMPONENTS'])
        self.assertEqual(tuple(found[5:found.index('CONFIG')]), COMPONENTS)
        self.assertEqual(found[-4:], ['CONFIG', 'PATHS', '"${QT612_BUILD_TREE}/lib/cmake/Qt6"', 'NO_DEFAULT_PATH'])
        module_list = re.search(r'set\(_qt612_modules ([^)]*)\)', self.cmake).group(1).split()
        self.assertEqual(tuple(module_list), MODULES)
        linked = command(self.cmake, 'target_link_libraries')
        self.assertEqual(linked, ['qt612-smoke', 'PRIVATE'] + ['Qt6::' + module for module in COMPONENTS] + ['PkgConfig::QT612Server'])

    def test_absolute_canonical_explicit_tree_and_no_registry_fallback(self):
        for expression in ('NOT IS_ABSOLUTE "${QT612_BUILD_TREE}"',
                           'NOT IS_DIRECTORY "${QT612_BUILD_TREE}/lib/cmake/Qt6"',
                           'file(REAL_PATH "${QT612_BUILD_TREE}" _qt612_tree)',
                           'NOT QT612_BUILD_TREE STREQUAL _qt612_tree',
                           'set(CMAKE_FIND_USE_PACKAGE_REGISTRY OFF)',
                           'set(CMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY OFF)',
                           'set(Qt6_DIR "${QT612_BUILD_TREE}/lib/cmake/Qt6" CACHE PATH "" FORCE)',
                           'NOT Qt6_DIR STREQUAL "${QT612_BUILD_TREE}/lib/cmake/Qt6"'):
            with self.subTest(expression=expression):
                self.assertIn(expression, self.cmake)

    def test_each_imported_module_has_own_tree_and_version_predicates(self):
        for expression in ('NOT EXISTS "${_config}/Qt6${_module}Config.cmake"',
                           'set(Qt6${_module}_DIR "${_config}" CACHE PATH "" FORCE)',
                           'NOT Qt6${_module}_DIR STREQUAL "${QT612_BUILD_TREE}/lib/cmake/Qt6${_module}"',
                           'NOT TARGET Qt6::${_module}',
                           'get_target_property(_imported Qt6::${_module} IMPORTED)',
                           'get_target_property(_version Qt6::${_module} _qt_package_version)',
                           'NOT _imported OR NOT _version STREQUAL "6.12.0" OR NOT _configs'):
            with self.subTest(expression=expression):
                self.assertIn(expression, self.cmake)

    def test_all_imported_configurations_refuse_foreign_missing_or_aliased_library(self):
        for expression in ('get_target_property(_configs Qt6::${_module} IMPORTED_CONFIGURATIONS)',
                           'string(REGEX REPLACE "Private$" "" _library_module "${_module}")',
                           'set(_expected "${QT612_BUILD_TREE}/lib/libQt6${_library_module}.so.6.12.0")',
                           'foreach(_configuration IN LISTS _configs)',
                           'get_target_property(_location Qt6::${_module} IMPORTED_LOCATION_${_configuration})',
                           'NOT _location STREQUAL _expected OR NOT EXISTS "${_location}"',
                           'file(REAL_PATH "${_location}" _real_location)',
                           'NOT _real_location STREQUAL _expected',
                           '_generic_location AND NOT _generic_location STREQUAL _expected'):
            with self.subTest(expression=expression):
                self.assertIn(expression, self.cmake)

    def test_five_gui_modules_have_normal_cmake_discovery(self):
        private = re.search(r'set\(_qt612_private_modules ([^)]*)\)', self.cmake).group(1).split()
        self.assertEqual(tuple(private), PRIVATE_MODULES)
        self.assertIn('set(_qt612_all_modules ${_qt612_modules} ${_qt612_private_modules})', self.cmake)
        self.assertEqual(self.cmake.count('foreach(_module IN LISTS _qt612_all_modules)'), 2)
        discovered = re.findall(r'(?m)^find_package\(([^)]*)\)', self.cmake)
        self.assertEqual(len(discovered), 8)
        for module in PRIVATE_MODULES:
            with self.subTest(module=module):
                expected = ['Qt6' + module, '6.12.0', 'EXACT', 'REQUIRED', 'CONFIG', 'PATHS',
                            '"${QT612_BUILD_TREE}/lib/cmake/Qt6' + module + '"', 'NO_DEFAULT_PATH']
                self.assertEqual(command(self.cmake, 'find_package', first='Qt6' + module), expected)
        linked = command(self.cmake, 'target_link_libraries')
        self.assertIn('Qt6::WaylandClient', linked)
        self.assertTrue(all('Qt6::' + module not in linked for module in PRIVATE_MODULES))

    def test_source_has_no_fetch_custom_actor_or_manual_link_fallback(self):
        self.assertNotRegex(self.cmake.lower(), r'fetchcontent|externalproject|execute_process|add_custom_|find_library|link_directories')
        self.assertEqual(command(self.cmake, 'add_executable'), ['qt612-smoke', 'smoke.cpp'])
        self.assertEqual(command(self.cmake, 'target_compile_features'), ['qt612-smoke', 'PRIVATE', 'cxx_std_17'])

    def test_exact_version_offscreen_before_application(self):
        self.assertIn('static_assert(QT_VERSION == QT_VERSION_CHECK(6, 12, 0))', self.smoke)
        self.assertIn('QString::fromLatin1(qVersion()) != QStringLiteral("6.12.0")', self.smoke)
        self.assertLess(self.smoke.index('qputenv("QT_QPA_PLATFORM", "offscreen")'), self.smoke.index('QApplication app'))
        self.assertIn('app.platformName() != QStringLiteral("offscreen")', self.smoke)

    def test_deterministic_raster_widget_render_and_pixel_check(self):
        for expression in ('QWidget widget;', 'widget.resize(32, 32);', 'const QColor background(17, 31, 47);',
                           'palette.setColor(QPalette::Window, background);', 'widget.setPalette(palette);',
                           'widget.setAutoFillBackground(true);', 'widget.render(&image);',
                           'image.isNull() || image.pixelColor(16, 16) != background'):
            with self.subTest(expression=expression):
                self.assertIn(expression, self.smoke)

    def test_noncontext_opengl_api_and_finite_module_symbols(self):
        for expression in ('QOpenGLVersionProfile profile;', 'profile.setVersion(3, 3);',
                           'profile.setProfile(QSurfaceFormat::CoreProfile);', '!profile.isValid()',
                           'profile.version().first != 3', 'profile.version().second != 3',
                           'profile.profile() != QSurfaceFormat::CoreProfile',
                           'QOpenGLWidget::staticMetaObject.className()', 'QPageSetupDialog::staticMetaObject.className()',
                           'QWaylandClientExtension::staticMetaObject.className()'):
            with self.subTest(expression=expression):
                self.assertIn(expression, self.smoke)
        code = re.sub(r'//[^\n]*', '', self.smoke)
        self.assertNotRegex(code, r'QOpenGLContext|QOffscreenSurface|\bQOpenGLWidget\s+\w+|\bQPageSetupDialog\s+\w+|\bQWaylandClientExtension\s+\w+')
        self.assertNotRegex(code, r'makeCurrent|glDraw|glGet|swapBuffers|(?<![A-Za-z0-9_])create\(')

    def test_core_network_objects_have_no_request_or_direct_device_actor(self):
        self.assertIn('QTemporaryFile file;', self.smoke)
        self.assertIn('QCryptographicHash::hash(payload, QCryptographicHash::Sha256)', self.smoke)
        self.assertIn('QNetworkAccessManager manager;', self.smoke)
        self.assertNotRegex(self.smoke, r'manager\.(get|post|put|deleteResource|sendCustomRequest)\s*\(')
        self.assertNotRegex(self.smoke, r'/dev/|wl_display_connect|wl_display_add_socket|wl_display_run|wl_registry|eglInitialize|gbm_create|QProcess|\bsystem\s*\(')

    def test_marker_distinguishes_gui_api_only_and_follows_event_loop_success(self):
        self.assertEqual(self.smoke.count(MARKER), 1)
        self.assertIn('const int result = app.exec();\n    if (result == 0)\n        std::puts("' + MARKER + '");', self.smoke)
        self.assertIn('QTimer::singleShot(0, &app, &QCoreApplication::quit);', self.smoke)
        self.assertNotIn('PASS_QT612_OFFSCREEN_API_SMOKE_ONLY', self.smoke)
        self.assertNotRegex(self.smoke, r'PASS_.*(HARDWARE|GPU_RENDER|M2)')

    def test_server_feature_and_normal_dependency_are_required(self):
        for expression in ('find_package(PkgConfig REQUIRED)',
                           'pkg_check_modules(QT612Server REQUIRED IMPORTED_TARGET wayland-server>=1.15)',
                           'get_target_property(_enabled_private Qt6::Gui QT_ENABLED_PRIVATE_FEATURES)',
                           'get_target_property(_disabled_private Qt6::Gui QT_DISABLED_PRIVATE_FEATURES)',
                           'NOT "wayland_server" IN_LIST _enabled_private OR "wayland_server" IN_LIST _disabled_private'):
            self.assertIn(expression,self.cmake)
        self.assertIn('wl_display *server = wl_display_create();',self.smoke)
        self.assertIn('wl_display_destroy(server);',self.smoke)
        self.assertNotRegex(self.smoke,r'wl_display_add_socket|wl_display_run|wl_display_connect')

    def test_wayland_support_configs_and_scanner_are_confined_to_own_tree(self):
        for expression in ('foreach(_support WaylandGlobalPrivate WaylandScannerTools)',
                           'set(Qt6${_support}_DIR "${QT612_BUILD_TREE}/lib/cmake/Qt6${_support}" CACHE PATH "" FORCE)',
                           'NOT Qt6${_support}_DIR STREQUAL "${QT612_BUILD_TREE}/lib/cmake/Qt6${_support}"',
                           '"${QT612_BUILD_TREE}/include/QtWaylandGlobal" IN_LIST _global_includes',
                           'get_target_property(_scanner_configs Qt6::qtwaylandscanner IMPORTED_CONFIGURATIONS)',
                           'set(_scanner_expected "${QT612_BUILD_TREE}/lib/qt6/qtwaylandscanner")',
                           'NOT _scanner_location STREQUAL _scanner_expected OR NOT _scanner_real STREQUAL _scanner_expected',
                           '_scanner_generic AND NOT _scanner_generic STREQUAL _scanner_expected'):
            self.assertIn(expression,self.cmake)


if __name__ == '__main__':
    unittest.main()
