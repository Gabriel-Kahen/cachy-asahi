"""Installed/moved CLI controls with real retained sources and hostile DATA roots."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

PARSER = argparse.ArgumentParser()
PARSER.add_argument('--recipe-root', type=Path, default=Path(__file__).resolve().parent)
ARGS, REST = PARSER.parse_known_args()
PKG = ARGS.recipe_root.resolve()
PROVENANCE = json.loads((PKG / 'source-provenance.json').read_bytes())


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def snapshot(path):
    return {str(p.relative_to(path)): (p.stat().st_mode, p.read_bytes() if p.is_file() else None)
            for p in (path, *sorted(path.rglob('*')))}


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.workspace = self.root / 'user-workspace'; self.workspace.mkdir()
        self.data = self.workspace / 'data'; self.data.mkdir()
        archive = (PKG / 'check-inputs.tar.gz').read_bytes()
        self.assertEqual((len(archive), digest(archive)), tuple(PROVENANCE['check_data']['archive'][k] for k in ('bytes', 'sha256')))
        expected = PROVENANCE['check_data']['files']; seen = set()
        with tarfile.open(PKG / 'check-inputs.tar.gz', 'r:gz') as tar:
            members = tar.getmembers(); self.assertEqual(len(members), len(expected) + 1)
            for member in members:
                name = member.name.removeprefix('check-inputs/')
                self.assertTrue(member.name.startswith('check-inputs/') and member.isfile() and name not in seen)
                seen.add(name); self.assertIn(name, {*expected, 'files.json'})
                with tar.extractfile(member) as stream: raw = stream.read(2 * 1024**2)
                self.assertEqual(len(raw), member.size)
                if name == 'files.json': self.assertEqual(json.loads(raw), expected)
                else: self.assertEqual((len(raw), digest(raw)), tuple(expected[name][k] for k in ('bytes', 'sha256')))
                target = self.data / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
        # Use the actual reviewed package() function, not a second install map.
        self.prefix = self.root / 'stage'
        command = ['bash', '-e', '-c', 'source "$1/PKGBUILD"; srcdir="$1"; pkgdir="$2"; package', 'package-check', str(PKG), str(self.prefix)]
        result = subprocess.run(command, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        moved = self.root / 'moved-stage'; self.prefix.rename(moved); self.prefix = moved
        self.cli = self.prefix / 'usr/bin/cachy-asahi-build-tools'
        self.cache = self.workspace / 'cache'
        self.env = dict(os.environ, PYTHONPATH=str(self.workspace), PYTHONHOME=str(self.workspace))
        self.invoke('cache-init', '--cache', self.cache)

    def invoke(self, *args, expected=0, system_shebang=False):
        command = [str(self.cli)] if system_shebang else [sys.executable, '-I', '-B', str(self.cli)]
        result = subprocess.run(command + [str(x) for x in args], cwd=self.workspace,
                                env=self.env, capture_output=True, timeout=130)
        self.assertEqual(result.returncode, expected, result.stderr.decode())
        return json.loads(result.stdout) if result.stdout.startswith(b'{') else result

    def import_real(self, archive=None, expected=0):
        catalog = self.data / 'inputs/source-inputs.json'
        return self.invoke('import-local', '--cache', self.cache, '--inputs', catalog,
            '--inputs-sha256', digest(catalog.read_bytes()), '--id', 'zlib-1.3.2',
            '--local-archive', archive or self.data / 'zlib-1.3.2.tar.gz', expected=expected)

    def preflight(self, variant='baseline', expected=0):
        plan = self.data / (variant + '-source-plan.json')
        return self.invoke('source-preflight', '--recipe', self.data / 'recipes' / variant,
            '--source-plan', plan, '--source-plan-sha256', digest(plan.read_bytes()),
            '--source-catalog', self.data / 'inputs/source-inputs.json',
            '--source-cache', self.cache, expected=expected)

    def test_moved_package_import_verify_and_both_real_recipe_preflights(self):
        result = self.import_real(); self.assertEqual(result['network_fetches'], 0)
        self.assertEqual(result['source_kind'], 'local_archive')
        catalog = self.data / 'inputs/source-inputs.json'
        verified = self.invoke('cache-verify', '--cache', self.cache, '--inputs', catalog,
            '--inputs-sha256', digest(catalog.read_bytes()), '--id', 'zlib-1.3.2', system_shebang=True)
        self.assertEqual(verified['sources'][0]['status'], 'verified')
        before = snapshot(self.cache)
        for variant in ('baseline', 'lto'):
            result = self.preflight(variant); self.assertEqual(result['status'], 'VERIFIED_OFFLINE_SOURCE_BINDING_ONLY')
            self.assertFalse(result['builder_started']); self.assertFalse(result['legal_acceptance'])
        self.assertEqual(before, snapshot(self.cache))
        self.invoke('--help', system_shebang=True)

    def test_missing_and_tampered_local_archive_refuse_without_objects(self):
        for archive in (self.data / 'absent', self.data / 'zlib-1.3.2.tar.gz'):
            if archive.exists(): archive.write_bytes(b'changed')
            before = snapshot(self.cache); self.import_real(archive, expected=1)
            self.assertEqual(before, snapshot(self.cache))

    def test_poisoned_object_is_preserved_without_network_repair(self):
        self.import_real(); next((self.cache / 'objects').iterdir()).write_bytes(b'changed')
        before = snapshot(self.cache)
        self.preflight(expected=1); self.import_real(expected=1)
        self.assertEqual(before, snapshot(self.cache))

    def test_user_workspace_python_and_environment_cannot_select_trusted_code(self):
        poison = "from pathlib import Path\nPath('IMPORTED_USER_CODE').write_text('bad')\nraise RuntimeError('untrusted workspace code')\n"
        for name in ('sitecustomize.py', 'source_cache.py', 'source_delivery.py', 'package_checks.py', 'source_materials.py'):
            (self.workspace / name).write_text(poison)
        for path in ('scripts/maintenance/source_cache.py', 'scripts/build/source_materials.py', 'scripts/checks/package_checks.py'):
            target = self.workspace / path; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(poison)
        self.import_real(); self.preflight()
        self.assertFalse((self.workspace / 'IMPORTED_USER_CODE').exists())
        plan = self.data / 'baseline-source-plan.json'
        self.invoke('source-preflight', '--recipe', self.data / 'recipes/baseline',
            '--source-plan', plan, '--source-plan-sha256', digest(plan.read_bytes()),
            '--source-catalog', self.data / 'inputs/source-inputs.json', '--source-cache', self.cache,
            '--repo-root', self.workspace, expected=2)

    def test_recipe_shell_code_is_read_only_data_and_drift_refuses(self):
        self.import_real()
        recipe = self.data / 'recipes/baseline/PKGBUILD'
        recipe.write_text(recipe.read_text() + '\nprintf bad > EXECUTED_RECIPE\n')
        self.preflight(expected=1)
        self.assertFalse((self.workspace / 'EXECUTED_RECIPE').exists())

    def test_only_six_offline_commands_and_isolated_invocation_are_supported(self):
        self.invoke('cache-acquire', expected=2)
        self.invoke('build', expected=2)
        result = subprocess.run([sys.executable, '-S', str(self.cli)], cwd=self.root,
                                env={k:v for k,v in os.environ.items() if not k.startswith('PYTHON')},
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1); self.assertIn(b'python3 -I', result.stderr)

    def test_versioned_recipe_check_and_preflight_use_the_packaged_parser_without_srcinfo(self):
        self.import_real()
        recipe = self.data / 'recipes/baseline/PKGBUILD'
        recipe.write_text(recipe.read_text() + "\ndepends=('python>=3.12')\n")
        plan_path = self.data / 'baseline-source-plan.json'
        plan = json.loads(plan_path.read_bytes())
        plan['recipe_inputs']['PKGBUILD'] = digest(recipe.read_bytes())
        plan_path.write_text(json.dumps(plan))
        checked = self.invoke('recipe-check', recipe)
        self.assertFalse(checked['recipes'][0]['errors'])
        self.assertEqual(checked['recipes'][0]['metadata']['depends'], ['python>=3.12'])
        self.assertEqual(self.preflight()['status'], 'VERIFIED_OFFLINE_SOURCE_BINDING_ONLY')
        self.assertFalse((recipe.parent / '.SRCINFO').exists())
        recipe.write_text(recipe.read_text() + "\nconflicts=('linux-asahi>=1')\n")
        refused = self.invoke('recipe-check', recipe, expected=1)
        self.assertTrue(any('protected platform' in e for e in refused['recipes'][0]['errors']))

    def consistency_inputs(self):
        recipe = self.workspace / 'literal/PKGBUILD'
        recipe.parent.mkdir()
        recipe.write_text("pkgname=sample\npkgver=1.0\npkgrel=1\narch=('any')\ndepends=('python>=3.12')\npackage() {\n    touch SHOULD_NOT_RUN\n}\n")
        info = recipe.parent / '.SRCINFO'
        info.write_text('pkgbase = sample\n    pkgver = 1.0\n    pkgrel = 1\n    arch = any\n    depends = python>=3.12\npkgname = sample\n')
        return recipe, info

    def test_installed_consistency_match_stale_mismatch_and_explicit_metadata(self):
        recipe, info = self.consistency_inputs()
        before = snapshot(self.workspace)
        result = self.invoke('recipe-consistency', recipe)
        self.assertEqual(result['status'], 'MATCH_MODELED_LITERAL_DECLARATIONS')
        self.assertFalse(result['shell_evaluation'])
        self.assertEqual(result['opaque_stage_functions'], ['package'])
        self.assertEqual(result['inputs']['PKGBUILD']['sha256'], digest(recipe.read_bytes()))
        self.assertEqual(before, snapshot(self.workspace))
        info.rename(info.with_name('retained-metadata'))
        info = info.with_name('retained-metadata')
        info.write_text(info.read_text().replace('pkgver = 1.0', 'pkgver = 0.9'))
        result = self.invoke('recipe-consistency', recipe, '--srcinfo', info, expected=1)
        self.assertEqual(result['status'], 'MISMATCH')
        self.assertEqual([row['field'] for row in result['mismatches']], ['pkgver'])
        self.assertEqual(result['inputs']['SRCINFO']['sha256'], digest(info.read_bytes()))
        self.assertFalse((self.workspace / 'SHOULD_NOT_RUN').exists())

    def test_installed_consistency_unsupported_shell_and_missing_metadata_never_match(self):
        recipe, info = self.consistency_inputs()
        recipe.write_text(recipe.read_text().replace('pkgver=1.0', 'pkgver="$(touch SHOULD_NOT_RUN)"'))
        before = snapshot(self.workspace)
        result = self.invoke('recipe-consistency', recipe, expected=2)
        self.assertEqual(result['status'], 'UNSUPPORTED')
        self.assertFalse(result['shell_evaluation'])
        self.assertEqual(before, snapshot(self.workspace))
        info.unlink()
        result = self.invoke('recipe-consistency', recipe, expected=2)
        self.assertEqual(result['status'], 'INPUT_ERROR')
        self.assertFalse((self.workspace / 'SHOULD_NOT_RUN').exists())

    def test_consistency_imports_adjacent_checker_and_freezes_legacy_modules(self):
        recipe, _ = self.consistency_inputs()
        poison = "from pathlib import Path\nPath('IMPORTED_USER_CODE').write_text('bad')\nraise RuntimeError('workspace code')\n"
        (self.workspace / 'recipe_metadata_consistency.py').write_text(poison)
        nested = self.workspace / 'scripts/checks/recipe_metadata_consistency.py'
        nested.parent.mkdir(parents=True); nested.write_text(poison)
        result = self.invoke('recipe-consistency', recipe)
        self.assertEqual(result['status'], 'MATCH_MODELED_LITERAL_DECLARATIONS')
        self.assertFalse((self.workspace / 'IMPORTED_USER_CODE').exists())
        self.assertEqual(PROVENANCE['frozen_build_tools_basis']['version'], '0.1.1-1')
        self.assertTrue(PROVENANCE['frozen_build_tools_basis']['six_modules_byte_held'])
        self.assertEqual(len(PROVENANCE['trusted_code']), 7)

    def test_exact_installed_code_paths_pins_modes_and_no_hooks(self):
        installed = {str(p.relative_to(self.prefix)) for p in self.prefix.rglob('*') if p.is_file()}
        expected = {'usr/bin/cachy-asahi-build-tools',
                    'usr/share/doc/cachy-asahi-build-tools/README.md',
                    'usr/share/doc/cachy-asahi-build-tools/source-provenance.json',
                    'usr/share/licenses/cachy-asahi-build-tools/LICENSE',
                    'usr/share/licenses/cachy-asahi-build-tools/NOTICE'}
        for row in PROVENANCE['trusted_code'].values():
            name = row['installed_path'].lstrip('/'); expected.add(name)
            body = (self.prefix / name).read_bytes()
            self.assertEqual((len(body), digest(body)), (row['bytes'], row['sha256']))
            self.assertEqual((self.prefix / name).stat().st_mode & 0o777, 0o644)
        self.assertEqual(installed, expected)
        self.assertEqual(self.cli.stat().st_mode & 0o777, 0o755)
        self.assertEqual(PROVENANCE['install_hooks'], [])
        self.assertNotIn('install=', (PKG / 'PKGBUILD').read_text())


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *REST], verbosity=2)
