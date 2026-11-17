# SPDX-License-Identifier: MIT
"""Read-only real recipe/source contract checks; no Qt or package actors."""
import sys

sys.dont_write_bytecode = True


def no_actors(event, args):
    denied = event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
        'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'fcntl.flock',
        'os.remove', 'os.rename', 'os.mkdir', 'os.rmdir', 'os.chmod', 'os.chown',
        'os.link', 'os.symlink', 'os.truncate')
    if event == 'open':
        mode, flags = args[1:3]
        denied |= bool(mode and any(c in mode for c in 'wxa+')) or bool(flags & (1 | 2 | 64 | 512 | 1024))
    if denied:
        raise RuntimeError('WAYLAND_RECIPE_READ_ONLY_NO_ACTORS')


sys.addaudithook(no_actors)

import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import unittest

HERE = Path(__file__).resolve().parent
PACKAGE = 'cachy-asahi-qt612-wayland-source-reference'
REVISION = 'c4f85cd060e3e80a7d71829defac9cf5a40e8ffa'
ARCHIVE = {'bytes': 908828, 'sha256': 'ae14d9bcf1bb3c300a3ab2e6a53f50284e5c6c966a4ac4cc5aedcb1bc74e4d02'}
OWN_POLICY = {'bytes': 1748, 'sha256': 'c4e6a5bf9a58e79ec40c83c2394bf2bdfdef4ab172471e8abaca4b64b8c746d8'}
DEPENDENCY_POLICY = {'bytes': 9460, 'sha256': '21ac9d87755c0a4efaa37bde993566da910bba99393ae68a73f0be20bb38d01f'}
MODULES = {'WaylandCompositor', 'WaylandEglCompositorHwIntegration', 'WaylandCompositorXdgShell',
           'WaylandCompositorIviapplication', 'WaylandCompositorWLShell', 'WaylandCompositorPresentationTime'}
URIS = {'QtWayland.Compositor', 'QtWayland.Compositor.XdgShell', 'QtWayland.Compositor.IviApplication',
        'QtWayland.Compositor.WlShell', 'QtWayland.Compositor.QtShell', 'QtWayland.Compositor.PresentationTime',
        'QtWayland.Compositor.TextureSharingExtension', 'QtWayland.Client.TextureSharing'}
RUNTIME = ['glibc', 'libgcc', 'libstdc++', 'qt6-base=6.12.0', 'qt6-declarative=6.12.0',
           'qt6-svg=6.12.0', 'wayland>=1.15', 'libxkbcommon>=0.5.0', 'libdrm', 'libglvnd']


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def data(name):
    return json.loads((HERE / name).read_bytes())


class ActualRecipeControls(unittest.TestCase):
    def setUp(self):
        self.recipe = (HERE / 'PKGBUILD').read_text()
        self.lock = data('SOURCE-INPUTS.lock.json')

    def srcinfo(self):
        result = {}
        for line in (HERE / '.SRCINFO').read_text().splitlines():
            if not line.strip():
                continue
            row = re.fullmatch(r'\s*([a-z0-9_]+) = (.+)', line)
            self.assertIsNotNone(row, 'ordinary generated source metadata')
            result.setdefault(row[1], []).append(row[2])
        return result

    def archive_contents(self):
        path = HERE / 'upstream/qtwayland-everywhere-src-6.12.0.tar.xz'
        self.assertEqual(pin(path.read_bytes()), ARCHIVE)
        wanted = set(data('source-notices.json')['source_notices']) | {'.tag', '.cmake.conf'}
        result = {}; total = 0; count = 0
        with tarfile.open(path, 'r:xz') as archive:
            for member in archive:
                count += 1; total += member.size
                self.assertLessEqual(count, 2048)
                self.assertLessEqual(total, 4 * 1024**2)
                name = PurePosixPath(member.name)
                self.assertFalse(name.is_absolute())
                self.assertNotIn('..', name.parts)
                self.assertEqual(name.parts[0], 'qtwayland-everywhere-src-6.12.0')
                relative = '/'.join(name.parts[1:])
                if relative in wanted or (relative.startswith('src/') and relative.endswith('CMakeLists.txt')):
                    self.assertTrue(member.isfile())
                    self.assertLessEqual(member.size, 512 * 1024)
                    with archive.extractfile(member) as stream:
                        body = stream.read(member.size + 1)
                    self.assertEqual(len(body), member.size)
                    self.assertNotIn(relative, result)
                    result[relative] = body
        self.assertEqual(count, 859)
        self.assertEqual(total, 2930771)
        self.assertTrue(wanted <= result.keys())
        return result

    def test_identity_provides_and_reviewable_install_removal_boundary(self):
        info = self.srcinfo()
        for key, value in {'pkgbase': PACKAGE, 'pkgname': PACKAGE, 'pkgver': '6.12.0',
                           'pkgrel': '1', 'arch': 'aarch64'}.items():
            self.assertEqual(info[key], [value])
        self.assertEqual(set(info['provides']), {'qt6-wayland=6.12.0'} |
                         {'libQt6'+m+'.so.6' for m in MODULES})
        self.assertEqual(len(info['provides']), 7)
        self.assertEqual(info['conflicts'], ['qt6-wayland'])
        for key in ('replaces', 'install', 'backup'):
            self.assertNotIn(key, info)
        self.assertNotRegex(self.recipe, r'(?m)^install=|\b(?:pre|post)_(?:install|remove|upgrade)\s*\(|libalpm/hooks')
        self.assertNotIn('libQt6WaylandClient.so.6', info['provides'])
        self.assertNotIn('qt6-base=6.12.0', info['provides'])

    def test_normal_dependencies_real_check_and_no_abi_bypass(self):
        info = self.srcinfo()
        self.assertEqual(info['depends'], RUNTIME)
        self.assertEqual(info['makedepends'], ['gcc', 'cmake>=3.25', 'ninja', 'pkgconf', 'python', 'perl'])
        self.assertNotIn('!check', info.get('options', []))
        self.assertNotRegex(self.recipe, r'--(?:nodeps|nocheck|skipchecks)\b|\b(?:pacman|sudo|systemctl|modprobe)\s')
        self.assertIn('QT_QPA_PLATFORM=offscreen', self.recipe)
        self.assertIn('timeout 60 "$srcdir/smoke-build/qt612-wayland-smoke"', self.recipe)
        self.assertIn('install-dependency-notices --prefix /usr', self.recipe)
        self.assertIn('--dependency-policy "$srcdir/dependency-inputs.json"', self.recipe)
        guard = (HERE / 'dependency_guard.cmake').read_text()
        bypass = r'(?:QT_NO_PACKAGE_VERSION_CHECK|QT_NO_PACKAGE_VERSION_INCOMPATIBLE_WARNING|QT_FORCE_FIND_TOOLS|CMAKE_DISABLE_FIND_PACKAGE\w*)'
        self.assertNotRegex(guard + self.recipe, r'(?:set\(\s*'+bypass+r'\s+|'+bypass+r'(?:\s*[:\w]*=|=))(?:ON|TRUE|1)\b')
        self.assertRegex(guard, r'if\(QT_NO_PACKAGE_VERSION_CHECK\)\s+message\(FATAL_ERROR')
        self.assertNotRegex(guard, r'unset\(QT_FEATURE_|set\(QT_FEATURE_')
        self.assertIn('Qt6 6.12.0 EXACT REQUIRED CONFIG', guard)
        self.assertIn('COMPONENTS BuildInternals Core Gui DBus OpenGL Qml Quick Svg WaylandClient', guard)
        for package in ('Qt6QmlBuildInternals', 'Qt6WaylandScannerTools'):
            self.assertIn('find_package('+package+' 6.12.0 EXACT REQUIRED CONFIG', guard)
        self.assertIn('_qt_package_version', guard)
        self.assertIn('if(NOT _version STREQUAL "6.12.0")', guard)
        for target in ('CorePrivate','GuiPrivate','QmlPrivate','QuickPrivate','WaylandClientPrivate','WaylandGlobalPrivate','qtwaylandscanner'):
            self.assertIn('Qt6::'+target, guard)
        self.assertIn('foreach(_feature wayland waylandscanner wayland_client wayland_egl opengl egl wayland_server)', guard)
        self.assertIn('CMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY OFF', guard)

    def test_all12_real_source_roles_and_frozen_checksums(self):
        info = self.srcinfo(); sources, hashes = info['source'], info['sha256sums']
        self.assertEqual(len(sources), 12)
        self.assertEqual(len(sources), len(set(sources)))
        self.assertEqual(len(hashes), 12)
        self.assertEqual(sources[0], 'https://download.qt.io/archive/qt/6.12/6.12.0/submodules/qtwayland-everywhere-src-6.12.0.tar.xz')
        self.assertEqual(hashes[0], ARCHIVE['sha256'])
        for source, digest in zip(sources[1:], hashes[1:]):
            self.assertEqual(Path(source).name, source)
            self.assertRegex(digest, r'^[0-9a-f]{64}$')
            self.assertEqual(pin((HERE / source).read_bytes())['sha256'], digest)
        self.assertEqual({k:self.lock['archive'][k] for k in ARCHIVE}, ARCHIVE)
        self.assertEqual(self.lock['upstream_revision'], REVISION)
        self.assertEqual(self.lock['tag_object'], '0ece37e8d6e6a8cb41dfa82dc433c67a77385e89')
        self.assertEqual(self.lock['patches'], [])
        self.assertEqual(self.lock['Qtbase_security_patches'], 'REMAIN_REQUIRED_ON_COMPATIBLE_GUI_DEPENDENCY')

    def test_real_archive_own16_notices_and_official_tag_reference(self):
        contents = self.archive_contents()
        self.assertEqual(contents['.tag'].decode().strip(), REVISION)
        self.assertIn(b'set(QT_REPO_MODULE_VERSION "6.12.0")', contents['.cmake.conf'])
        self.assertEqual(pin((HERE / 'source-notices.json').read_bytes()), OWN_POLICY)
        policy = data('source-notices.json')['source_notices']
        self.assertEqual(len(policy), 16)
        self.assertEqual(sum(len(contents[n]) for n in policy), 128430)
        for name, digest in policy.items():
            self.assertEqual(pin(contents[name])['sha256'], digest)
        remote = data('upstream/git-v6.12.0-ls-remote.DATA.json')
        stdout = (HERE / 'upstream/git-v6.12.0-ls-remote.txt').read_bytes()
        self.assertEqual(pin(stdout), remote['stdout'])
        self.assertIn((REVISION+'\trefs/tags/v6.12.0^{}').encode(), stdout)
        self.assertEqual(remote['exit'], 0)
        self.assertEqual(remote['stderr'], '')
        self.assertIsNone(data('upstream/acquisition.DATA.json')['Root_grants'])

    def test_exact52_external_prefix_operands_remain_unbound(self):
        raw = (HERE / 'dependency-inputs.json').read_bytes()
        self.assertEqual(pin(raw), DEPENDENCY_POLICY)
        policy = json.loads(raw)
        self.assertEqual(len(policy['files']), 52)
        self.assertEqual(policy['qtbase_revision'], '025bdad181de241e81bf853c8a2d7bf3d19261a9')
        self.assertIsNone(policy['actual_native_prefix'])
        self.assertIsNone(policy['source_legal_acceptance'])
        for name, row in policy['files'].items():
            self.assertTrue(name.startswith('share/qt6/wayland/'))
            self.assertNotIn('..', PurePosixPath(name).parts)
            self.assertGreater(row['bytes'], 0)
            self.assertRegex(row['sha256'], r'^[0-9a-f]{64}$')
        self.assertIn('share/qt6/wayland/protocols/MIT_LICENSE.txt', policy['files'])

    def test_full23_setting_profile_and_serial_builds(self):
        settings = {}
        for line in (HERE / 'configure.cmake').read_text().splitlines():
            if not line or line.startswith('#'):
                continue
            row = re.fullmatch(r'set\((\w+) (\S+) CACHE (?:BOOL|STRING) "" FORCE\)', line)
            self.assertIsNotNone(row)
            self.assertNotIn(row[1], settings)
            settings[row[1]] = row[2]
        self.assertEqual(len(settings), 23)
        for feature in ('wayland_server','wayland_compositor_quick','wayland_dmabuf_client_buffer',
                        'wayland_client_ivi_shell','wayland_client_qt_shell','wayland_decoration_adwaita'):
            self.assertEqual(settings['FEATURE_'+feature], 'ON')
        self.assertEqual(settings['FEATURE_wayland_layer_integration_vsp2'], 'OFF')
        self.assertEqual(settings['CMAKE_AUTOGEN_PARALLEL'], '1')
        for key in ('CMAKE_SHARED_LINKER_FLAGS_INIT', 'CMAKE_MODULE_LINKER_FLAGS_INIT'):
            self.assertEqual(settings[key], '-Wl,-z,max-page-size=16384')
        self.assertIn('export MAX_JOBS=1 CMAKE_BUILD_PARALLEL_LEVEL=1', self.recipe)
        for phase in ('build','check'):
            body = re.search(r'(?ms)^'+phase+r'\(\) \{(.*?)^\}', self.recipe)[1]
            self.assertLess(body.index('_qt_single_job || return'), body.index('cmake '))
            self.assertIn('--parallel "$MAX_JOBS"', body)

    def test_six_shared_eight_qml_and_exact612_helper_source(self):
        contents = self.archive_contents()
        tree = ast.parse((HERE / 'check_stage.py').read_text())
        names = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name):
                if node.targets[0].id in ('MODULES','PRIVATE_MODULES','QML_MODULES','HEADER_MODULE'):
                    names[node.targets[0].id] = ast.literal_eval(node.value)
        self.assertEqual(set(names['MODULES']) | set(names['PRIVATE_MODULES']), MODULES)
        self.assertEqual(set(names['QML_MODULES']), URIS)
        self.assertEqual(names['HEADER_MODULE'], 'WaylandClientFeaturesPrivate')
        source_cmake = b'\n'.join(b for n,b in contents.items() if n.endswith('CMakeLists.txt'))
        for module in MODULES:
            declared = module+'Private' if module=='WaylandEglCompositorHwIntegration' else module
            self.assertRegex(source_cmake, rb'qt_internal_add_(?:module|qml_module)\('+declared.encode()+rb'\b')
        for uri in URIS:
            self.assertIn(uri.encode(), source_cmake)
        proof = data('upstream/declarative-build-helper-provenance.DATA.json')
        self.assertEqual(len(proof['files']), 2)
        for member, row in proof['files'].items():
            self.assertEqual(row['revision'], '4332fbbb4c340463dc8cee36dda0c85d932122d8')
            self.assertEqual(pin((HERE / 'upstream/declarative-build-helpers' / member).read_bytes()),
                             {k:row[k] for k in ('bytes','sha256')})
        self.assertIs(proof['imported_or_executed'], False)
        self.assertIs(proof['native_acceptance'], False)

    def test_final_build_contract_and_lifecycle_hold_actual_native(self):
        contract = data('BUILD-CONTRACT.json'); info = self.srcinfo()
        self.assertEqual(contract['package']['name'], PACKAGE)
        self.assertEqual(contract['package']['version'], '6.12.0-1')
        self.assertEqual(contract['package']['conflicts'], ['qt6-wayland'])
        self.assertEqual(contract['package']['replaces'], [])
        self.assertEqual(contract['package']['hooks'], [])
        self.assertIsNone(contract['package']['install_script'])
        self.assertIs(contract['package']['selected_for_release'], False)
        self.assertEqual(contract['dependencies']['runtime'], info['depends'])
        self.assertEqual(contract['dependencies']['build'], info['makedepends'])
        self.assertIs(contract['dependencies']['normal_makepkg_checks'], True)
        actual_settings = dict(re.findall(r'^set\((\w+) (\S+) CACHE (?:BOOL|STRING) "" FORCE\)$',
                                          (HERE / 'configure.cmake').read_text(), re.MULTILINE))
        self.assertEqual(contract['configuration']['settings'], actual_settings)
        self.assertEqual(contract['source_notices']['count'], 16)
        host = contract['actual_host']
        self.assertEqual(host['scope'], 'HOST_X86_64_CONFIGURE_ONLY')
        self.assertEqual(host['configure_status'], 'REFUSED_QT6112_FOR_REQUIRED_QT6120')
        self.assertIsNone(host['configured_targets'])
        report = host['configure_refusal']
        self.assertEqual(set(report), {'path','bytes','sha256'})
        member = PurePosixPath(report['path'])
        self.assertFalse(member.is_absolute())
        self.assertNotIn('..', member.parts)
        log = HERE / report['path']
        self.assertEqual(log, log.resolve())
        self.assertGreater(log.stat().st_size, 0)
        self.assertLessEqual(log.stat().st_size, 1024**2)
        raw = log.read_bytes()
        self.assertEqual(pin(raw), {k:report[k] for k in ('bytes','sha256')})
        self.assertIn(b'6.11.2', raw)
        self.assertIn(b'6.12.0', raw)
        self.assertIs(contract['actual_native']['native_acceptance'], False)
        for key in ('Root_selection','archive','build_pair','comparison','image','inventory','signature'):
            self.assertIsNone(contract['actual_native'][key])
        lifecycle = data('lifecycle.DATA.json')
        self.assertEqual(lifecycle['package']['module_count'], 6)
        self.assertTrue(all(value is None for value in lifecycle['actual'].values()))
        for key in ('native_acceptance','hardware_acceptance','release_acceptance','full72_claim'):
            self.assertIs(lifecycle[key], False)

    def test_permanent_actor_and_write_fence(self):
        for event,args in [('subprocess.Popen',()),('socket.__new__',()),('ctypes.dlopen',()),
                           ('os.system',()),('fcntl.flock',()),('open',('MODEL','w',0))]:
            with self.assertRaisesRegex(RuntimeError,'WAYLAND_RECIPE_READ_ONLY'):sys.audit(event,*args)


if __name__ == '__main__':
    unittest.main()
