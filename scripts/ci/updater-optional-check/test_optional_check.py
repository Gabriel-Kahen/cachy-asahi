# SPDX-License-Identifier: MIT
"""Source controls only. No Docker, signature transaction or host Check."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('prepare', HERE / 'prepare.py')
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class SourceTests(unittest.TestCase):
    def test_versioned_preflight_keeps_exact_dependencies_and_signature_cases(self):
        sources, dependencies = prepare.preflight()
        installed = prepare.inventory(sources['expected-installed-packages.lock'])
        self.assertEqual(len(installed), 360)
        self.assertEqual(installed['cachy-asahi-update'], '4.4.2-3')
        self.assertEqual(len(dependencies['packages']), 5)
        check = sources['real-check/real-check.py']
        self.assertIn(b'invalid-signature-preserves-pending', check)
        self.assertIn(b'missing-signature-preserves-no-version', check)
        self.assertIn(b'optional_cases(home, config_file,', check)
        self.assertNotIn(b'4.4.2-2', check)

    def test_missing_or_ambiguous_fixture_transform_refuses(self):
        for raw in (b'unrelated', b'old old'):
            with self.subTest(raw=raw), self.assertRaisesRegex(ValueError, 'exact historical'):
                prepare.replace(raw, b'old', b'new')

    def test_historical_blob_substitution_refuses(self):
        with patch.object(prepare.subprocess, 'check_output', return_value=b'substitution'):
            with self.assertRaisesRegex(ValueError, 'historical blob changed'):
                prepare.historical('inside.py')

    @unittest.skipUnless(os.environ.get('UPDATER_OPTIONAL_PATCHED_SOURCE'), 'requires exact local patched source')
    def test_optional_fixture_against_actual_patched_check_entry(self):
        source = Path(os.environ['UPDATER_OPTIONAL_PATCHED_SOURCE']).resolve(strict=True)
        verifier = prepare.ROOT / prepare.PACKAGE / 'verify-updater.py'
        subprocess.run(['/usr/bin/python3', '-I', '-B', str(verifier), '--source', str(source)],
                       check=True, capture_output=True, timeout=35)
        files, _ = prepare.preflight()
        scopes = []
        for name in ('real-check.py', 'optional_cases.py'):
            scope = {'__file__': name}
            exec(compile(files['real-check/' + name], name, 'exec'), scope)
            scopes.append(scope)
        historical, optional = scopes
        with tempfile.TemporaryDirectory(prefix='optional-check-source-') as work:
            home = Path(work)
            for name in ('config/arch-update', 'state/arch-update', 'data', 'runtime', 'test-bin'):
                (home / name).mkdir(parents=True)
            config = home / 'config/arch-update/arch-update.conf'
            fake = home / 'test-bin'
            for name in ('awk', 'cat', 'cut', 'date', 'grep', 'mkdir', 'mktemp', 'mv', 'rm', 'sed', 'tr', 'wc'):
                (fake / name).symlink_to(shutil.which(name))
            (fake / 'gettext.sh').write_text('eval_gettext() { printf "%s" "$1"; }\n')
            checkupdates = fake / 'checkupdates'
            checkupdates.write_text('#!/usr/bin/bash\nexit 2\n')
            checkupdates.chmod(0o755)

            def run(argv, *, expected):
                self.assertIsNone(expected)
                self.assertEqual(argv[-2:], ['/usr/bin/arch-update', '--check'])
                env = dict(word.split('=', 1) for word in argv[argv.index('-i') + 1:-2])
                env['PATH'] = f'{home / "optional-bin"}:{fake}'
                env['ARCH_UPDATE_LIBDIR'] = str(source / 'src/lib')
                result = subprocess.run(['/usr/bin/bash', str(source / 'src/arch-update.sh'), '--check'],
                                        cwd=home, env=env, capture_output=True, timeout=10)
                return result

            result = {'cases': {}}
            optional['exercise'](home, config, result, run, historical['user_command'],
                                 historical['snapshot'], historical['need'])
            self.assertEqual(len(result['cases']), 8)
            self.assertEqual(result['cases']['optional-system-discovery-failure']['exit'], 20)
            self.assertEqual((home / 'state/arch-update/last_updates_check_flatpak').read_bytes(), b'')


if __name__ == '__main__':
    unittest.main()
