# SPDX-License-Identifier: MIT
"""Source controls only. No Docker, signature transaction or host Check."""
import ast
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout
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
        with tempfile.TemporaryDirectory(prefix='optional-historical-') as work:
            historical = Path(work)
            (historical / 'inside.py').write_bytes(b'substitution')
            with patch.object(prepare, 'HISTORICAL', historical):
                with self.assertRaisesRegex(ValueError, 'input digest differs'):
                    prepare.historical('inside.py')

    def test_capsule_emits_one_bounded_json_line(self):
        files, _ = prepare.preflight()
        inside = files['inside.py']
        self.assertNotIn(b'/out/', inside)
        scope = {'__name__': 'installed_fixture'}
        exec(compile(inside, 'inside.py', 'exec'), scope)
        output = io.StringIO()
        value = {'status': 'PASS', 'type': 'fixture'}
        with redirect_stdout(output):
            scope['emit_result'](value)
            with self.assertRaisesRegex(ValueError, 'receipt exceeds bound'):
                scope['emit_result']({'overlong': 'x' * prepare.RESULT_LIMIT})
        self.assertEqual(output.getvalue().count('\n'), 1)
        self.assertEqual(json.loads(output.getvalue()), value)

    def test_frozen_real_check_records_expected_case_names(self):
        files, _ = prepare.preflight()
        tree = ast.parse(files['real-check/real-check.py'])
        recorded = {
            node.args[0].value for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id == 'check' and isinstance(node.args[0], ast.Constant)
        }
        for node in ast.walk(tree):
            if (isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Store)
                    and ast.unparse(node.value) == "result['cases']"
                    and isinstance(node.slice, ast.Constant)):
                recorded.add(node.slice.value)
        expected = {name for name in prepare.EXPECTED_CASE_EXITS if not name.startswith('optional-')}
        self.assertEqual(recorded, expected)

    def test_capsule_success_requires_exact_case_exits(self):
        files, _ = prepare.preflight()
        scope = {'__name__': 'installed_fixture'}
        exec(compile(files['inside.py'], 'inside.py', 'exec'), scope)
        check = {'status': 'PASS', 'cases': {
            name: {'exit': code} for name, code in prepare.EXPECTED_CASE_EXITS.items()
        }}
        self.assertEqual(len(check['cases']), 15)
        self.assertTrue(scope['complete_cases'](check))
        check['cases']['optional-empty']['exit'] = False
        self.assertFalse(scope['complete_cases'](check))
        del check['cases']['optional-empty']
        self.assertFalse(scope['complete_cases'](check))

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
            optional_exits = {name: row['exit'] for name, row in result['cases'].items()}
            self.assertEqual(optional_exits, {
                name: code for name, code in prepare.EXPECTED_CASE_EXITS.items()
                if name.startswith('optional-')
            })
            self.assertEqual((home / 'state/arch-update/last_updates_check_flatpak').read_bytes(), b'')


class StageTests(unittest.TestCase):
    def stage_capsule(self, suffix, retained_files=0):
        files, _ = prepare.preflight()
        checks = prepare.load('stage_test_checks', prepare.ROOT / prepare.CHECKER, prepare.CHECKER_SHA)
        recipe = (prepare.ROOT / prepare.PACKAGE / 'PKGBUILD').read_bytes()
        srcinfo = checks.metadata((prepare.ROOT / prepare.PACKAGE / '.SRCINFO').read_text())
        with tempfile.TemporaryDirectory(prefix='updater-capsule-stage-') as work:
            work = Path(work)
            native = work / 'native'; native.mkdir()
            cache = work / 'cache'; cache.mkdir()
            image = 'sha256:' + 'd' * 64
            (native / 'image-id').write_text(image + '\n')
            (native / 'packages.lock').write_bytes(files['compiler-packages.lock'])
            (native / 'result.json').write_text(json.dumps({
                'native_pair': 'PASS', 'image_id': image, 'inventory_sha256': prepare.BUILDER_SHA}))

            def pin(name, body):
                (cache / name).write_bytes(body)
                return {'filename': name, 'size': len(body), 'sha256': prepare.digest(body)}

            dep = pin('fixture.pkg.tar.xz', b'inert runtime archive')
            sig = pin('fixture.pkg.tar.xz.sig', b'inert runtime signature')
            dep.update(signature_size=sig['size'], signature_sha256=sig['sha256'])
            key = pin('archlinuxarm.gpg', b'inert keyring')
            dependencies = {'packages': [dep], 'keyring_files': [key], 'signer_fingerprint': 'e' * 40}
            archive = work / 'fixture.tar'
            pkginfo = 'pkgname = cachy-asahi-update\npkgver = 4.4.2-3\narch = aarch64\nlicense = GPL-3.0-or-later\n'
            pkginfo += ''.join('depend = ' + name + '\n' for name in srcinfo['depends'])
            buildinfo = ('format = 2\npkgname = cachy-asahi-update\npkgver = 4.4.2-3\npkgarch = aarch64\n'
                         f'pkgbuild_sha256sum = {prepare.PKGBUILD_SHA}\n')
            with tarfile.open(archive, 'w:xz' if suffix == '.xz' else 'w') as tar:
                for name, text in (('.PKGINFO', pkginfo), ('.BUILDINFO', buildinfo), ('.MTREE', 'inert')):
                    data = text.encode()
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    tar.addfile(member, io.BytesIO(data))
            body = (archive.read_bytes() if suffix == '.xz' else
                    subprocess.check_output(['zstd', '-q', '-c', str(archive)], timeout=10))
            name = 'cachy-asahi-update-4.4.2-3-aarch64.pkg.tar' + suffix
            package_sha = prepare.digest(body)
            for index in (1, 2):
                build = native / f'build-{index}'
                artifacts = build / 'artifacts'; artifacts.mkdir(parents=True)
                recipe_dir = build / 'inputs/recipe'; recipe_dir.mkdir(parents=True)
                (artifacts / name).write_bytes(body)
                retained = artifacts / 'linux-source-closure/vendor/fixture-1.0.0'
                if retained_files:
                    retained.mkdir(parents=True)
                    for index_file in range(retained_files):
                        (retained / f'module-{index_file}.rs').write_text('// Inert retained source\n')
                (recipe_dir / 'PKGBUILD').write_bytes(recipe)
                controller = {'image_id': image, 'builder_inventory_sha256': prepare.BUILDER_SHA,
                              'tool_pins': {}, 'entry_script_sha256': 'a' * 64, 'nonce': str(index) * 32,
                              'recipe_input_sha256': {'PKGBUILD': prepare.PKGBUILD_SHA}}
                controller_raw = json.dumps(controller).encode()
                (recipe_dir.parent / 'controller-input.json').write_bytes(controller_raw)
                outputs = {path.relative_to(artifacts).as_posix(): prepare.digest(path.read_bytes())
                           for path in artifacts.rglob('*') if path.is_file()}
                provenance = build / 'provenance.json'
                provenance.write_text(json.dumps({
                    'native_compilation': 'PASS-private-native-package-static-checks',
                    'outputs_sha256': outputs, 'package_sha256': package_sha,
                    'controller_sha256': prepare.digest(controller_raw)}))
                if retained_files:
                    self.assertGreater(provenance.stat().st_size, 64 * 1024)
            output = work / 'inputs'
            with patch.object(prepare, 'preflight', return_value=(files, dependencies)):
                result = prepare.stage(native, cache, output)
            self.assertEqual(result['package_sha256'], package_sha)
            self.assertEqual((output / 'updater.pkg.tar.xz').read_bytes(), body)
            self.assertEqual(result['installation'], 'NOT RUN')

    def test_real_stage_path_with_xz_pair(self):
        self.stage_capsule('.xz')

    def test_real_stage_path_with_retained_source_provenance(self):
        self.stage_capsule('.xz', retained_files=700)

    @unittest.skipUnless(shutil.which('zstd'), 'zstd is required for the zstd case')
    def test_real_stage_path_with_zstd_pair(self):
        self.stage_capsule('.zst')

    def test_cli_emits_only_bounded_preparation_problem(self):
        def fail(_native, _cache, _output, progress):
            progress('runtime-inputs')
            raise FileNotFoundError('/private/path/fixture')

        stdout = io.StringIO()
        args = ['--native-output','/unused','--cache','/unused','--output','/unused']
        with patch.object(prepare,'stage',side_effect=fail), redirect_stdout(stdout):
            self.assertEqual(prepare.main(args),1)
        self.assertEqual(json.loads(stdout.getvalue()),
                         {'status':'FAIL','phase':'runtime-inputs','problem':'missing-input'})


if __name__ == '__main__':
    unittest.main()
