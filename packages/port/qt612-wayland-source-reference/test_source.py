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
        libraries = ('WaylandCompositor','WaylandEglCompositorHwIntegration','WaylandCompositorXdgShell',
                     'WaylandCompositorIviapplication','WaylandCompositorWLShell','WaylandCompositorPresentationTime')
        lines = ['build lib/libQt6'+m+'.so.6.12.0: MODEL_DECLARATION' for m in libraries]
        uris = ('QtWayland.Compositor','QtWayland.Compositor.XdgShell','QtWayland.Compositor.IviApplication',
                'QtWayland.Compositor.WlShell','QtWayland.Compositor.QtShell','QtWayland.Compositor.PresentationTime',
                'QtWayland.Compositor.TextureSharingExtension','QtWayland.Client.TextureSharing')
        lines += ['build lib/qt6/qml/'+u.replace('.','/')+'/libMODEL.so: MODEL_DECLARATION' for u in uris]
        lines += ['build lib/qt6/plugins/'+n+': MODEL_DECLARATION' for n in
                  ('wayland-shell-integration/libivi-shell.so','wayland-shell-integration/libqt-shell.so',
                   'wayland-decoration-client/libadwaita.so')]
        (build/'build.ninja').write_text('\n'.join(lines)+'\n')
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


    def test_empty_or_partial_configure_never_passes(self):
        profile,build = self.config()
        original = (build/'build.ninja').read_text()
        for raw in ('',original.replace('libQt6WaylandCompositorXdgShell','libQt6MODEL_MISSING'),
                    original.replace('QtWayland/Client/TextureSharing','MODEL_MISSING')):
            (build/'build.ninja').write_text(raw)
            with self.assertRaises(ValueError):S.configuration(build,profile)

    def test_dependency_notice_bytes_and_private_copy(self):
        prefix = self.base/'MODEL_PREFIX';prefix.mkdir()
        rows = {}
        for n in range(52):
            name = 'share/qt6/wayland/MODEL_'+str(n)
            path=prefix/name;path.parent.mkdir(parents=True,exist_ok=True);body=('MODEL_DEP_'+str(n)).encode()
            path.write_bytes(body);rows[name]=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
        policy=self.base/'dependency-policy.json'
        policy.write_text(json.dumps(dict(schema=1,kind='QT612_WAYLAND_EXTERNAL_QTBASE_PROTOCOL_INPUTS_V1',
            qtbase_revision='025bdad181de241e81bf853c8a2d7bf3d19261a9',files=rows,
            actual_native_prefix=None,source_legal_acceptance=None)))
        self.assertEqual(len(S.dependency_inputs(prefix,policy)),52)
        stage=self.base/S.PACKAGE;stage.mkdir()
        self.assertEqual(S.install_dependency_notices(prefix,policy,stage)['files'],52)
        with self.assertRaises(ValueError):S.install_dependency_notices(prefix,policy,stage)
        (prefix/next(iter(rows))).write_bytes(b'MUTATED_MODEL')
        with self.assertRaises(ValueError):S.dependency_inputs(prefix,policy)


if __name__ == '__main__': unittest.main(verbosity=2)
