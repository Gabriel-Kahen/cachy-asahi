# SPDX-License-Identifier: MIT
"""MODEL source/configuration refusal controls; no Qt/native result credit."""
import sys

def actor_fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn', 'fcntl.flock', 'resource.setrlimit', 'os.kill', 'os.killpg'):
        raise ValueError('GUI_SOURCE_DATA_ONLY_NO_ACTORS')

sys.addaudithook(actor_fence)
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('qt612_source_checks', HERE / 'source.py')
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)


class Source(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='qt612-source-MODEL-')
        self.addCleanup(temporary.cleanup); self.base = Path(temporary.name)
        self.root = self.base / 'source'; self.root.mkdir()
        (self.root / '.tag').write_text(S.REVISION + '\n')
        (self.root / '.cmake.conf').write_text('set(QT_REPO_MODULE_VERSION "6.12.0")\n')
        (self.root / 'LICENSES').mkdir(); self.body = b'MODEL_NOTICE_NOT_A_LICENSE_GRANT\n'
        (self.root / 'LICENSES/MODEL.txt').write_bytes(self.body)
        self.policy = self.base / 'policy.json'
        self.policy.write_text(json.dumps(dict(schema_version=1, source_notices={
            'LICENSES/MODEL.txt': hashlib.sha256(self.body).hexdigest()})))

    def test_exact_model_source_notice_selection(self):
        self.assertEqual(S.notices(self.root, self.policy), {'LICENSES/MODEL.txt': self.body})

    def test_changed_revision_notice_and_escaping_policy_refuse(self):
        tag = self.root / '.tag'; tag.write_text('wrong\n')
        with self.assertRaises(ValueError): S.notices(self.root, self.policy)
        tag.write_text(S.REVISION + '\n'); (self.root / 'LICENSES/MODEL.txt').write_bytes(b'CHANGED')
        with self.assertRaises(ValueError): S.notices(self.root, self.policy)
        self.policy.write_text(json.dumps(dict(schema_version=1, source_notices={'../escape': '0' * 64})))
        with self.assertRaises(ValueError): S.notices(self.root, self.policy)

    def test_notice_copy_is_confined_to_named_fresh_destdir(self):
        stage = self.base / S.PACKAGE; stage.mkdir()
        result = S.install_notices(self.root, self.policy, stage)
        path = stage / 'usr/share/licenses' / S.PACKAGE / 'source/LICENSES/MODEL.txt'
        self.assertEqual(path.read_bytes(), self.body); self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        self.assertEqual(result['notices'], 1)
        with self.assertRaises(ValueError): S.install_notices(self.root, self.policy, stage)

    def test_unnamed_or_aliased_notice_destdir_refuses(self):
        with self.assertRaises(ValueError): S.install_notices(self.root, self.policy, self.base)
        stage = self.base / S.PACKAGE; stage.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): S.install_notices(self.root, self.policy, stage)

    def config(self):
        profile = self.base / 'profile.cmake'; build = self.base / 'build'; build.mkdir()
        settings = {f'FEATURE_test_{n}': 'OFF' for n in range(40)}
        settings['CMAKE_INSTALL_PREFIX'] = '/usr'
        profile.write_text(''.join(f'set({k} {v} CACHE {"BOOL" if k.startswith("FEATURE_") else "STRING"} "" FORCE)\n'
                                   for k, v in settings.items()))
        cache = ''.join(f'{"QT_" if k.startswith("FEATURE_") else ""}{k}:INTERNAL={v}\n' for k, v in settings.items())
        cache += '"QT_QMAKE_LIB_OF_TARGET_GLIB2::GLIB2":INTERNAL=glib\n"QT_QMAKE_LIB_OF_TARGET_GLIB2::FLAGS":INTERNAL=-lglib\n'
        (build / 'CMakeCache.txt').write_text(cache)
        return profile, build

    def test_configuration_accepts_real_qt_quoted_internal_key_shape(self):
        profile, build = self.config()
        self.assertEqual(S.configuration(build, profile)['settings'], 41)

    def test_configuration_feature_or_prefix_drift_refuses(self):
        profile, build = self.config(); path = build / 'CMakeCache.txt'; raw = path.read_text()
        for changed in (raw.replace('QT_FEATURE_test_0:INTERNAL=OFF', 'QT_FEATURE_test_0:INTERNAL=ON'),
                        raw.replace('CMAKE_INSTALL_PREFIX:INTERNAL=/usr', 'CMAKE_INSTALL_PREFIX:INTERNAL=/opt')):
            path.write_text(changed)
            with self.assertRaises(ValueError): S.configuration(build, profile)

    def server_config(self):
        profile,build = self.config()
        profile.write_text(profile.read_text()+'set(FEATURE_wayland_server ON CACHE BOOL "" FORCE)\n')
        cache = build/'CMakeCache.txt'
        cache.write_text(cache.read_text()+'FEATURE_wayland_server:BOOL=ON\nQT_FEATURE_wayland_server:INTERNAL=ON\n'
                         'QT612_SERVER_PC_VERSION:INTERNAL=1.26.0\nQT612_SERVER_API_LINKS:INTERNAL=1\n')
        targets = build/'lib/cmake/Qt6Gui/Qt6GuiTargets.cmake';targets.parent.mkdir(parents=True)
        targets.write_text('set_target_properties(Qt6::Gui PROPERTIES\n'
                           ' QT_ENABLED_PRIVATE_FEATURES "wayland_client;wayland_server;wayland_egl"\n'
                           ' QT_DISABLED_PRIVATE_FEATURES "wayland_brcm"\n)\n')
        header = build/'src/gui/qtgui-config_p.h';header.parent.mkdir(parents=True)
        header.write_text('#define QT_FEATURE_wayland_server 1\n')
        return profile,build,targets,header

    def test_server_model_joins_cache_export_header_and_prerequisite(self):
        profile,build,_,_ = self.server_config()
        self.assertEqual(S.configuration(build,profile)['settings'],42)

    def test_server_cache_or_prerequisite_drift_refuses(self):
        profile,build,_,_ = self.server_config();cache=build/'CMakeCache.txt';raw=cache.read_text()
        for before,after in (('FEATURE_wayland_server:BOOL=ON','FEATURE_wayland_server:BOOL=OFF'),
                             ('QT612_SERVER_API_LINKS:INTERNAL=1','QT612_SERVER_API_LINKS:INTERNAL=0'),
                             ('QT612_SERVER_PC_VERSION:INTERNAL=1.26.0','QT612_SERVER_PC_VERSION:INTERNAL=1.14.9')):
            cache.write_text(raw.replace(before,after))
            with self.assertRaises(ValueError): S.configuration(build,profile)

    def test_server_off_export_or_header_refuses(self):
        profile,build,targets,header = self.server_config();raw=targets.read_text()
        targets.write_text(raw.replace('wayland_client;wayland_server;wayland_egl','wayland_client;wayland_egl'))
        with self.assertRaises(ValueError): S.configuration(build,profile)
        targets.write_text(raw);header.write_text('#define QT_FEATURE_wayland_server -1\n')
        with self.assertRaises(ValueError): S.configuration(build,profile)


if __name__ == '__main__': unittest.main(verbosity=2)
