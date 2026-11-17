# SPDX-License-Identifier: MIT
"""MODEL source/configuration refusal controls; no Qt/native result credit."""
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


if __name__ == '__main__': unittest.main(verbosity=2)
