# SPDX-License-Identifier: MIT
"""Check real GUI recipe DATA and source reuse; never run package/build actors."""
import sys

sys.dont_write_bytecode = True


def no_actors(event, args):
    denied = event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
        'os.system', 'os.exec', 'os.fork', 'os.posix_spawn', 'fcntl.flock',
        'os.remove', 'os.rename', 'os.mkdir', 'os.rmdir', 'os.chmod', 'os.chown',
        'os.link', 'os.symlink', 'os.truncate')
    if event == 'open':
        mode, flags = args[1:3]
        denied |= bool(mode and any(c in mode for c in 'wxa+'))
        denied |= bool(flags & (1 | 2 | 64 | 512 | 1024))
    if denied:
        raise RuntimeError('ACTOR_FREE_READ_ONLY_RECIPE_CONTROLS')


sys.addaudithook(no_actors)  # Installed before other imports or recipe reads.

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = HERE.with_name('qt612-source-reference')
PACKAGE = 'cachy-asahi-qt612-gui-source-reference'
MODULES = ('Concurrent Core DBus EglFSDeviceIntegration EglFsKmsGbmSupport '
           'EglFsKmsSupport Gui Network OpenGL OpenGLWidgets PrintSupport Sql '
           'Test WaylandClient Widgets WlShellIntegration XcbQpa Xml').split()
PATCHES = ['CVE-2026-116337-qtbase-6.12-0002.diff', 'CVE-2026-116337-qtbase-6.12-0001.diff',
           'CVE-2026-105924-qtbase-6.12.diff', 'CVE-2026-105943-qtbase-6.12.diff']
ARCHIVE = {'filename': 'qtbase-everywhere-src-6.12.0.tar.xz', 'bytes': 51220268,
           'sha256': 'a951bd163c7b80fc6b8c88d7668fb56abf91c152373e13c10666763238131307',
           'url': 'https://download.qt.io/archive/qt/6.12/6.12.0/submodules/qtbase-everywhere-src-6.12.0.tar.xz'}


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


class RecipeContract(unittest.TestCase):
    def setUp(self):
        self.recipe = (HERE / 'PKGBUILD').read_text()
        self.lock = json.loads((HERE / 'SOURCE-INPUTS.lock.json').read_bytes())

    def srcinfo(self):
        result = {}
        for line in (HERE / '.SRCINFO').read_text().splitlines():
            if not line.strip():
                continue
            match = re.fullmatch(r'\s*([a-z0-9_]+) = (.+)', line)
            self.assertIsNotNone(match, 'ordinary generated .SRCINFO row')
            result.setdefault(match[1], []).append(match[2])
        return result

    def test_real_package_identity_and_install_removal_metadata(self):
        info = self.srcinfo()
        for key, value in {'pkgbase': PACKAGE, 'pkgname': PACKAGE, 'pkgver': '6.12.0',
                           'pkgrel': '1', 'arch': 'aarch64'}.items():
            self.assertEqual(info.get(key), [value])
        self.assertEqual(sorted(info['provides']), sorted(['qt6-base=6.12.0'] +
                         ['libQt6' + module + '.so.6' for module in MODULES]))
        self.assertEqual(sorted(info['conflicts']), ['cachy-asahi-qt612-base-source-reference', 'qt6-base'])
        for key in ('replaces', 'install', 'backup'):
            self.assertNotIn(key, info)
        self.assertNotIn('install=', self.recipe)
        self.assertNotRegex(self.recipe, r'/usr/share/libalpm/hooks|\b(?:pre|post)_(?:install|upgrade|remove)\s*\(')

    def test_normal_dependency_checks_and_genuine_check_phase(self):
        info = self.srcinfo()
        self.assertTrue({'libdrm', 'libglvnd', 'mesa', 'wayland>=1.15', 'libgl',
                         'md4c>=0.5.3', 'md4c<0.6'} <= set(info['depends']))
        self.assertEqual(set(info['makedepends']), {'gcc', 'cmake>=3.25', 'ninja', 'pkgconf', 'python', 'perl', 'patch'})
        self.assertNotIn('!check', info.get('options', []))
        self.assertNotRegex(self.recipe, r'--(?:nodeps|nocheck|skipchecks)\b|\b(?:SKIP_CHECK|NOCHECK)\s*=')
        self.assertRegex(self.recipe, r'(?m)^check\(\) \{')
        self.assertIn('timeout 60 "$srcdir/smoke-build/qt612-smoke"', self.recipe)
        self.assertIn('QT_QPA_PLATFORM=offscreen', self.recipe)
        self.assertIn('python "$srcdir/check_stage.py" --root "$pkgdir"', self.recipe)
        self.assertNotRegex(self.recipe, r'QT_QPA_PLATFORM=(?:eglfs|wayland)\b|\b(?:pacman|sudo|modprobe)\s')

    def test_all13_actual_source_checksum_roles_and_archive_pin(self):
        info = self.srcinfo()
        sources, checksums = info['source'], info['sha256sums']
        self.assertEqual(len(sources), 13)
        self.assertEqual(len(set(sources)), 13)
        self.assertEqual(len(checksums), 13)
        self.assertEqual(self.lock['archive'], ARCHIVE)
        self.assertEqual(sources[0], ARCHIVE['url'])
        self.assertEqual(checksums[0], ARCHIVE['sha256'])
        for source, digest in zip(sources[1:], checksums[1:]):
            self.assertEqual(Path(source).name, source)
            self.assertRegex(digest, r'^[0-9a-f]{64}$')
            self.assertEqual(pin((HERE / source).read_bytes())['sha256'], digest)
        self.assertEqual(sources[-4:], PATCHES)
        self.assertNotIn('SKIP', checksums)

    def test_exact69a_material_reuse_and_one_package_literal_inverse(self):
        self.assertEqual(self.lock['basis_commit'], '69a02851b87ca29daf2e197101b66bf75ff61889')
        self.assertIsNone(self.lock['Root_selection'])
        self.assertIsNone(self.lock['native_pair'])
        self.assertEqual(self.lock['official_0bd04f_correspondence'], 'HOLD_UNCHANGED')
        for name, row in self.lock['reused'].items():
            original = (ROOT / row['path']).read_bytes()
            current = (HERE / name).read_bytes()
            if name == 'configure.cmake':
                self.assertEqual(pin(original), row['original'])
            elif name == 'source.py':
                self.assertEqual(pin(original), row['original'])
                self.assertEqual(pin(current), row['projected'])
                old = b"PACKAGE = 'cachy-asahi-qt612-base-source-reference'"
                new = b"PACKAGE = 'cachy-asahi-qt612-gui-source-reference'"
                self.assertEqual(original.count(old), 1)
                self.assertEqual(current.count(new), 1)
                self.assertEqual(current.replace(new, old), original)
            else:
                self.assertEqual(pin(original), {k: row[k] for k in ('bytes', 'sha256')})
                self.assertEqual(current, original)
        policy = json.loads((HERE / 'source-notices.json').read_bytes())
        self.assertEqual(len(policy['source_notices']), 173)
        self.assertEqual(set(PATCHES), {n for n in self.lock['reused'] if n.endswith('.diff')})
        self.assertIn('--forward --fuzz=0', self.recipe)
        self.assertEqual(re.findall(r'\b(CVE-[\w.-]+\.diff)', self.recipe.split('prepare()')[1].split('build()')[0]), PATCHES)

    def test_finite_gui_profile_and_serial_source_policy(self):
        settings = {}
        for line in (HERE / 'configure.cmake').read_text().splitlines():
            if not line.strip() or line.startswith('#'):
                continue
            match = re.fullmatch(r'set\((\w+) (\S+) CACHE (?:BOOL|STRING) "" FORCE\)', line)
            self.assertIsNotNone(match)
            self.assertNotIn(match[1], settings)
            settings[match[1]] = match[2]
        self.assertEqual(len(settings), 113)
        for feature in ('egl eglfs kms gbm eglfs_gbm wayland waylandscanner qtwaylandscanner '
                        'wayland_client wayland_client_wl_shell wayland_client_xdg_shell wayland_egl').split():
            self.assertEqual(settings['FEATURE_' + feature], 'ON')
        for feature in ('wayland_server eglfs_brcm eglfs_vsp2 eglfs_mali eglfs_viv eglfs_rcar '
                        'eglfs_viv_wl eglfs_openwfd wayland_brcm').split():
            self.assertEqual(settings['FEATURE_' + feature], 'OFF')
        self.assertEqual(settings['CMAKE_AUTOGEN_PARALLEL'], '1')
        helper = lambda text: re.search(r'(?ms)^_qt_single_job\(\) \{.*?^\}', text)[0]
        self.assertEqual(helper(self.recipe), helper((BASE / 'PKGBUILD').read_text()))
        for phase in ('build', 'check'):
            body = re.search(r'(?ms)^' + phase + r'\(\) \{(.*?)^\}', self.recipe)[1]
            self.assertLess(body.index('_qt_single_job || return'), body.index('cmake '))
            self.assertIn('--parallel "$MAX_JOBS"', body)

    def test_whole_source_audit_data_and_unbound_actual_limits(self):
        raw = (HERE / 'module-source-contract.DATA.json').read_bytes()
        audit = json.loads(raw)
        self.assertEqual(raw, encoded(audit))
        self.assertEqual(pin(raw), {'bytes': 35643, 'sha256': 'ba1b0b516247b62b8bffd7b2aad85f3c4603d2f6e86ee54f0f4626bd50aa888e'})
        self.assertEqual(len(audit['source_files']), 39)
        self.assertEqual(len(audit['protocol_xml_contract']['bundled_inputs']), 28)
        self.assertEqual(set(audit['modules']), {'EglFSDeviceIntegration', 'EglFsKmsGbmSupport',
                                               'EglFsKmsSupport', 'WaylandClient', 'WlShellIntegration'})
        for member, row in (audit['source_files'] | audit['protocol_xml_contract']['bundled_inputs']).items():
            self.assertFalse(PurePosixPath(member).is_absolute())
            self.assertNotIn('..', PurePosixPath(member).parts)
            self.assertGreater(row['bytes'], 0)
            self.assertRegex(row['sha256'], r'^[0-9a-f]{64}$')
        self.assertEqual(audit['scope']['other_frozen_catalog_modules_outside_candidate_scope'], 54)
        for key in ('actual_configure', 'actual_build', 'actual_stage', 'actual_runtime', 'Root_acceptance'):
            self.assertIsNone(audit[key])
        for key in ('native_acceptance', 'hardware_acceptance', 'release_acceptance'):
            self.assertIs(audit[key], False)
        resource = json.loads((HERE / 'SERIAL-POLICY.DATA.json').read_bytes())
        for key in ('Root_acceptance', 'actual_peak_memory_bytes', 'actual_peak_storage_bytes', 'capacity_sufficient'):
            self.assertIsNone(resource[key])
        self.assertEqual(resource['inner_builder']['memory_bytes'], 4 * 1024**3)
        self.assertEqual(resource['inner_builder']['MAX_JOBS'], 1)

    def test_final_build_contract_joins_real_recipe_without_new_native_credit(self):
        contract = json.loads((HERE / 'BUILD-CONTRACT.json').read_bytes())
        info = self.srcinfo()
        self.assertEqual(contract['package']['name'], PACKAGE)
        self.assertEqual(contract['package']['version'], '6.12.0-1')
        self.assertIs(contract['package']['selected_for_release'], False)
        self.assertEqual(contract['package']['hooks'], [])
        self.assertIsNone(contract['package']['install_script'])
        self.assertEqual(contract['package']['replaces'], [])
        for field in ('runtime', 'build'):
            self.assertEqual(contract['dependencies'][field], info['depends' if field == 'runtime' else 'makedepends'])
        self.assertIs(contract['dependencies']['normal_makepkg_checks'], True)
        profile = dict(re.findall(r'^set\((\w+) (\S+) CACHE (?:BOOL|STRING) "" FORCE\)$',
                                 (HERE / 'configure.cmake').read_text(), re.MULTILINE))
        self.assertEqual(contract['configuration']['settings'], profile)
        self.assertEqual(contract['source_notices']['count'], 173)
        self.assertEqual(contract['patch_order'], PATCHES)
        self.assertEqual(contract['patch_fuzz'], 0)
        native = contract['actual_native']
        for key in ('Root_selection', 'archive', 'build_pair', 'comparison', 'image',
                    'inventory', 'public_TEST_key', 'signature'):
            self.assertIsNone(native[key])
        self.assertIs(native['native_acceptance'], False)
        self.assertEqual(native['M2'], 'NOT RUN')
        self.assertEqual(native['installation'], 'NOT RUN')
        self.assertEqual(native['removal'], 'NOT RUN')
        self.assertTrue(contract['foreign_official_correspondence']['status'].startswith('HOLD'))

    def test_actor_and_write_fence_is_active_during_own_controls(self):
        for event, args in [('subprocess.Popen', ()), ('socket.__new__', ()), ('ctypes.dlopen', ()),
                            ('os.system', ()), ('fcntl.flock', ()), ('open', ('MODEL', 'w', 0))]:
            with self.assertRaisesRegex(RuntimeError, 'ACTOR_FREE_READ_ONLY'):
                sys.audit(event, *args)


# Run this file separately from sibling controls that intentionally execute stub Bash.
if __name__ == '__main__':
    unittest.main()
