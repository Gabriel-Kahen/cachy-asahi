#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SOURCE/MODEL contract checks; no CMake, compiler, Qt, session or signing run."""
import sys


def actor_fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.fork', 'os.posix_spawn')) or event in {
        'os.system', 'fcntl.flock', 'resource.setrlimit', 'os.kill', 'os.killpg',
    }:
        raise RuntimeError('WAYLAND_SOURCE_MODEL_ACTOR_FENCE:' + event)


sys.addaudithook(actor_fence)

import json
from pathlib import Path
import re
import unittest

HERE = Path(__file__).resolve().parent
DEPENDENCIES = ['Core', 'Gui', 'OpenGL', 'Qml', 'Quick', 'Svg', 'DBus', 'WaylandClient']
URIS = ['QtWayland.Compositor', 'QtWayland.Compositor.XdgShell', 'QtWayland.Compositor.IviApplication',
        'QtWayland.Compositor.WlShell', 'QtWayland.Compositor.QtShell',
        'QtWayland.Compositor.PresentationTime', 'QtWayland.Compositor.TextureSharingExtension']


def commands(source, name):
    """Extract simple source commands; never evaluate CMake."""
    return [value.split() for value in re.findall(r'(?m)^' + re.escape(name) + r'\(([^)]*)\)', source)]


class SourceModelContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cmake = (HERE / 'SmokeCMakeLists.txt').read_text()
        cls.cpp = (HERE / 'smoke.cpp').read_text()
        cls.qml = (HERE / 'smoke.qml').read_text()
        cls.lifecycle = json.loads((HERE / 'lifecycle.DATA.json').read_bytes())

    def test_preimport_actor_fence(self):
        for event in ('subprocess.Popen', 'socket.connect', 'ctypes.dlopen', 'os.system', 'os.exec', 'os.fork',
                      'os.forkpty', 'os.posix_spawn', 'fcntl.flock', 'resource.setrlimit', 'os.kill', 'os.killpg'):
            with self.subTest(event=event), self.assertRaisesRegex(RuntimeError, 'WAYLAND_SOURCE_MODEL_ACTOR_FENCE'):
                sys.audit(event)

    def test_normal_exact_qt612_discovery_never_disables_quick_qml_or_svg(self):
        found = commands(self.cmake, 'find_package')
        self.assertEqual(found[0][:6], ['Qt6', '6.12.0', 'EXACT', 'REQUIRED', 'CONFIG', 'COMPONENTS'])
        self.assertEqual(found[0][6:found[0].index('PATHS')], DEPENDENCIES)
        expected = ['Qt6', 'Qt6WaylandCompositor', 'Qt6WaylandEglCompositorHwIntegrationPrivate', 'Qt6WaylandScannerTools']
        self.assertEqual([row[0] for row in found], expected)
        self.assertTrue(all(row[1:4] == ['6.12.0', 'EXACT', 'REQUIRED'] and row[-1] == 'NO_DEFAULT_PATH' for row in found))
        self.assertNotRegex(self.cmake, r'QUIET|OPTIONAL_COMPONENTS|FEATURE_.*(?:qml|quick).*OFF|Qt5')

    def test_native_dependency_prefix_and_canonical_new_build_are_explicit(self):
        for expression in ('NOT IS_ABSOLUTE "${QT612_BUILD_TREE}"', 'NOT QT612_DEPENDENCY_PREFIX STREQUAL "/usr"',
                           'file(REAL_PATH "${QT612_BUILD_TREE}" _tree)', 'NOT QT612_BUILD_TREE STREQUAL _tree',
                           'set(CMAKE_FIND_USE_PACKAGE_REGISTRY OFF)', 'set(CMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY OFF)',
                           'set(Qt6_DIR "${QT612_DEPENDENCY_PREFIX}/lib/cmake/Qt6" CACHE PATH "" FORCE)',
                           'set(Qt6${_module}_DIR "${QT612_BUILD_TREE}/lib/cmake/Qt6${_module}" CACHE PATH "" FORCE)'):
            with self.subTest(expression=expression): self.assertIn(expression, self.cmake)

    def test_each_module_imported_location_version_and_realpath_are_checked(self):
        for expression in ('foreach(_module IN LISTS _dependencies _own_modules)',
                           'NOT Qt6${_module}_DIR STREQUAL "${_prefix}/lib/cmake/Qt6${_module}"',
                           'get_target_property(_version Qt6::${_module} _qt_package_version)',
                           'NOT _version STREQUAL "6.12.0"',
                           'string(REGEX REPLACE "Private$" "" _library "${_module}")',
                           'require_imported_location(Qt6::${_module} "${_prefix}/lib/libQt6${_library}.so.6.12.0")',
                           'get_target_property(_imported ${target} IMPORTED)',
                           'get_target_property(_configs ${target} IMPORTED_CONFIGURATIONS)',
                           'get_target_property(_generic ${target} IMPORTED_LOCATION)',
                           'NOT _location STREQUAL expected OR NOT EXISTS "${_location}"',
                           'file(REAL_PATH "${_location}" _real)', 'NOT _real STREQUAL expected'):
            with self.subTest(expression=expression): self.assertIn(expression, self.cmake)

    def test_source_backed_normal_server_scanner_macro_and_exact_tool_locations(self):
        for expression in ('NOT COMMAND qt6_generate_wayland_protocol_server_sources',
                           'require_imported_location(Qt6::qtwaylandscanner "${QT612_DEPENDENCY_PREFIX}/lib/qt6/qtwaylandscanner")',
                           'require_imported_location(Wayland::Scanner "${QT612_DEPENDENCY_PREFIX}/bin/wayland-scanner")',
                           'qt6_generate_wayland_protocol_server_sources(qt612-wayland-smoke PRIVATE_CODE',
                           'FILES "${CMAKE_CURRENT_BINARY_DIR}/smoke-protocol.xml"'):
            with self.subTest(expression=expression): self.assertIn(expression, self.cmake)
        self.assertNotRegex(self.cmake, r'execute_process|add_custom_command|ExternalProject|FetchContent|Qt5|find_program')
        self.assertIn('project(qt612_wayland_reference_smoke LANGUAGES C CXX)', self.cmake)

    def test_linkage_includes_all_required_dependencies_and_new_compositor(self):
        linked = commands(self.cmake, 'target_link_libraries')[0]
        self.assertEqual(linked, ['qt612-wayland-smoke', 'PRIVATE'] + ['Qt6::' + name for name in DEPENDENCIES]
                         + ['Qt6::WaylandCompositor', 'Wayland::Server'])
        self.assertIn('WaylandEglCompositorHwIntegrationPrivate', self.cmake)

    def test_qml_imports_and_type_ids_match_the_seven_source_modules(self):
        imports = re.findall(r'(?m)^import ([A-Za-z0-9_.]+) 6\.12$', self.qml)
        self.assertEqual(imports, ['QtQml', 'QtQuick'] + URIS)
        types = re.findall(r'\{"(QtWayland\.[^"]+)", "([A-Za-z]+)"\}', self.cpp)
        self.assertEqual([uri for uri, name in types], URIS)
        self.assertEqual([name for uri, name in types], ['WaylandCompositor', 'XdgShell', 'IviApplication', 'WlShell',
                                                        'QtShell', 'PresentationTime', 'TextureSharingExtension'])
        self.assertIn('qmlTypeId(type.uri, 6, 12, type.type) < 0', self.cpp)

    def test_client_texture_sharing_not_initialized_under_offscreen(self):
        self.assertNotIn('import QtWayland.Client.TextureSharing', self.qml)
        self.assertIn('QtWayland.Client.TextureSharing', self.lifecycle['qml']['packaged_URIs'])
        self.assertIn('NOT_TESTED_INITIALIZER_PROBES_QPA_NATIVE_SERVER_BUFFER', self.lifecycle['qml']['client_texture_sharing_offscreen'])
        self.assertIn('NO_QML_TYPES', self.lifecycle['qml']['client_texture_sharing_offscreen'])

    def test_component_is_compiled_locally_without_object_creation(self):
        for expression in ('QFileInfo(QString::fromLocal8Bit(argv[1])).isAbsolute()',
                           'QUrl::fromLocalFile(QString::fromLocal8Bit(argv[1]))', 'QQmlComponent::PreferSynchronous',
                           'if (!component.isReady())',
                           'engine.setImportPathList({QStringLiteral(QT612_WAYLAND_QML_DIR), QStringLiteral(QT612_DEPENDENCY_QML_DIR)})'):
            with self.subTest(expression=expression): self.assertIn(expression, self.cpp)
        code = re.sub(r'//[^\n]*', '', self.cpp)
        self.assertNotRegex(code, r'\.create\s*\(|\bQWaylandCompositor\s+\w+|app\.exec|wl_display|QOpenGLContext|makeCurrent')
        self.assertNotRegex(self.qml, r'WaylandCompositor\s*\{|Window\s*\{|Component\.onCompleted|https?://')

    def test_exact_version_offscreen_and_finite_non_session_apis(self):
        self.assertIn('static_assert(QT_VERSION == QT_VERSION_CHECK(6, 12, 0))', self.cpp)
        self.assertIn('QString::fromLatin1(qVersion()) != QStringLiteral("6.12.0")', self.cpp)
        self.assertLess(self.cpp.index('qputenv("QT_QPA_PLATFORM", "offscreen")'), self.cpp.index('QGuiApplication app'))
        self.assertIn('app.platformName() != QStringLiteral("offscreen")', self.cpp)
        for expression in ('QWaylandCompositor::staticMetaObject', 'QWaylandClientExtension::staticMetaObject',
                           'QQuickItem::staticMetaObject', 'QOpenGLVersionProfile profile;', 'QSvgRenderer svg(', 'QDBusMessage::createSignal'):
            self.assertIn(expression, self.cpp)
        self.assertNotRegex(self.cpp, r'QDBusConnection|QQuickWindow|/dev/|socketName|wl_display|QProcess')

    def test_qml_roots_match_exact_qtdeclarative_install_layout(self):
        self.assertIn('set(_qml_root "${QT612_BUILD_TREE}/lib/qt6/qml")', self.cmake)
        self.assertIn('QT612_WAYLAND_QML_DIR="${_qml_root}"', self.cmake)
        self.assertIn('QT612_DEPENDENCY_QML_DIR="${QT612_DEPENDENCY_PREFIX}/lib/qt6/qml"', self.cmake)
        self.assertNotIn('${QT612_BUILD_TREE}/qml', self.cmake)

    def test_marker_claims_only_api_qml_scope(self):
        self.assertEqual(self.cpp.count('PASS_QT612_WAYLAND_QML_API_ONLY'), 1)
        self.assertNotRegex(self.cpp, r'PASS_.*(?:GPU|NATIVE|HARDWARE|COMPOSITOR_RUNNING|HYPRLAND)')

    def test_lifecycle_package_coinstalls_gui18_without_owned_overlap(self):
        pkg = self.lifecycle['package']
        self.assertEqual(pkg['conflicts'], ['qt6-wayland'])
        self.assertEqual(pkg['replaces'], [])
        self.assertEqual(pkg['coinstall_with'], 'cachy-asahi-qt612-gui-source-reference=6.12.0-1')
        self.assertEqual(pkg['module_count'], 6)
        self.assertEqual(len(pkg['new_libraries']), 6)
        self.assertEqual(len(pkg['required_plugins_relative_to_usr_lib_qt6_plugins']), 7)
        self.assertIn('FORBIDDEN', pkg['GUI18_owned_path_overlap'])
        self.assertEqual(len(self.lifecycle['qml']['packaged_URIs']), 8)

    def test_lifecycle_required_dependencies_are_unbound_not_silently_disabled(self):
        deps = self.lifecycle['dependency_contract']
        self.assertEqual(deps['required_components'], DEPENDENCIES)
        self.assertEqual(deps['exact_Qt_version'], '6.12.0')
        self.assertIsNone(deps['QtDeclarative_signed_project_provider'])
        self.assertIsNone(deps['QtSvg_signed_project_provider'])
        self.assertIn('NO_QML_QUICK_DISABLE', deps['missing_provider_behavior'])
        self.assertIn('NOT_NATIVE_OR_SIGNED_PROJECT_PROOF', deps['foreign_host_configuration'])

    def test_lifecycle_normal_signed_commands_preserve_config_and_refuse_dependencies(self):
        normal = self.lifecycle['normal_pacman_contract']
        self.assertEqual(normal['SigLevel'], ['Required', 'TrustedOnly'])
        self.assertEqual(normal['LocalFileSigLevel'], ['Required', 'TrustedOnly'])
        self.assertNotEqual(normal['config'], normal['gpgdir'])
        self.assertTrue(normal['argv_templates_are_DATA'])
        self.assertEqual([stage['name'] for stage in normal['stages']], ['install', 'reinstall', 'upgrade', 'rollback', 'remove'])
        for stage in normal['stages']:
            self.assertEqual(stage['operation'][:2], ['-R' if stage['name'] == 'remove' else '-U', '--'])
        self.assertIn('DEPENDENCY_REFUSAL_REQUIRED', normal['stages'][-1]['expected_alpm'])
        self.assertEqual(len(normal['required_negative_controls']), 4)
        self.assertIn('PRESERVE_ALL_NO_DELETION_OR_RELABEL', self.lifecycle['preservation']['user_configuration_pacsave_pacnew'])

    def test_lifecycle_all_actual_results_and_acceptance_remain_unbound(self):
        self.assertTrue(all(value is None for value in self.lifecycle['actual'].values()))
        for field in ('native_acceptance', 'release_acceptance', 'hardware_acceptance', 'full72_claim'):
            self.assertIs(self.lifecycle[field], False)


if __name__ == '__main__':
    unittest.main()
