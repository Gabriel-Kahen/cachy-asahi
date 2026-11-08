"""Literal dependency DATA controls; never source a PKGBUILD or start actors."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'scripts/checks/package_checks.py').is_file())
HERE = Path(__file__).resolve().parent
V2 = HERE.parent / 'scripts/checks/package_checks_v2.py'
if not V2.is_file():
    V2 = ROOT / 'scripts/checks/package_checks_v2.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


OLD = load('literal_before', ROOT / 'scripts/checks/package_checks.py')
NEW = load('literal_v2', V2)
ACTORS = []
AUDIT_ACTIVE = False


def deny(event, args):
    if AUDIT_ACTIVE and (event.startswith(('socket.', 'subprocess.', 'os.exec', 'os.fork', 'os.spawn', 'os.posix_spawn')) or event == 'os.system'):
        ACTORS.append(event)
        raise AssertionError('literal metadata controls forbid actors')


sys.addaudithook(deny)


class LiteralTests(unittest.TestCase):
    def setUp(self):
        global AUDIT_ACTIVE
        AUDIT_ACTIVE = True
        self.addCleanup(self.stop_audit)

    @staticmethod
    def stop_audit():
        global AUDIT_ACTIVE
        AUDIT_ACTIVE = False

    def test_actual_build_tools_and_source_tools_versioned_dependency_reproduction(self):
        for name, version in [('cachy-asahi-build-tools', '3.12'), ('cachy-asahi-source-tools', '3.14')]:
            path = ROOT / 'packages/tools' / name / 'PKGBUILD'
            if not path.is_file():
                # Artifact-only run before Root has merged the prior package.
                path = ROOT / 'artifacts/development/build-tools-package-development-20261108/canonical-ready/packages/tools' / name / 'PKGBUILD'
            text = path.read_text()
            with self.assertRaisesRegex(ValueError, 'dynamic depends'): OLD.literal_metadata(text)
            self.assertIn('python>=' + version, NEW.literal_metadata(text)['depends'])

    def test_five_operators_architecture_fields_and_literal_epoch_release(self):
        for field in ('depends', 'makedepends', 'checkdepends', 'conflicts', 'replaces'):
            for suffix in ('', '_aarch64'):
                for operator in ('>=', '<=', '=', '>', '<'):
                    item = 'libfoo.so' + operator + '2:1.5~rc1+git-3.1'
                    self.assertEqual(NEW.literal_metadata(field + suffix + "=('" + item + "')")[field + suffix], [item])
        self.assertEqual(NEW.literal_metadata('depends=(python=3.12 xz zstd)')['depends'], ['python=3.12', 'xz', 'zstd'])

    def test_provides_exact_version_only_and_invalid_comparisons_refuse(self):
        self.assertEqual(NEW.literal_metadata("provides=('library.so=1-64')")['provides'], ['library.so=1-64'])
        for value in ('python>=', 'python==1', 'python!=1', 'python=>1', 'python<<1', 'python>>1', 'python><1', 'python > 1', 'python>=1/2'):
            with self.assertRaises(ValueError): NEW.literal_metadata("depends=('" + value + "')")
        for operator in ('>=', '<=', '>', '<'):
            with self.assertRaises(ValueError): NEW.literal_metadata("provides=('python" + operator + "3.12')")

    def test_redirection_compound_words_and_assignment_tails_refuse(self):
        for text in ("depends=(python>=3.12)", "depends=(python <input)",
                     "depends=('python'>='3.12')", "depends=(python'>=3.12')",
                     "depends=('python>=3.12') > output", "depends=('python>=3.12'); touch marker",
                     "depends=((python))", "depends=('python>=3.12' '')"):
            with self.assertRaises(ValueError): NEW.literal_metadata(text)

    def test_original_expansion_and_script_marker_filter_is_retained(self):
        for value in ('$VERSION', '${VERSION}', '$(touch marker)', '`touch marker`', 'python; touch marker', 'python\\>=3'):
            for quote in ("'", '"'):
                with self.assertRaises(ValueError): NEW.literal_metadata('depends=(' + quote + value + quote + ')')

    def test_comparison_signs_remain_refused_in_nonrelation_fields(self):
        for field in ('source', 'license', 'pkgname', 'pkgver', 'install', 'sha256sums'):
            for value in ('data>output', 'data<input'):
                with self.assertRaisesRegex(ValueError, 'dynamic'): NEW.literal_metadata(field + "=('" + value + "')")

    def test_optional_dependency_description_and_epoch_stay_distinct(self):
        item = 'python>=2:3.12-1: optional bindings'
        self.assertEqual(NEW.literal_metadata("optdepends=('" + item + "')")['optdepends'], [item])
        for item in ('python: ', 'python: write > file', 'python>=3.12: reason\nsecond line'):
            with self.assertRaises(ValueError): NEW.literal_metadata("optdepends=('" + item + "')")

    def test_protected_platform_relations_remain_rejected(self):
        for package in OLD.PROTECTED_PACKAGES:
            for field, operator in [('provides', '='), ('conflicts', '>='), ('replaces', '<')]:
                data = NEW.literal_metadata(field + "=('" + package + operator + "1')")
                self.assertEqual(NEW.platform_relations(data), OLD.platform_relations(data))
                self.assertTrue(NEW.platform_relations(data))

    def make_recipe(self, base, depends="'python>=3.12'", relation=''):
        (base / 'payload').write_bytes(b'opaque source data\n')
        checksum = hashlib.sha256((base / 'payload').read_bytes()).hexdigest()
        (base / 'PKGBUILD').write_text("pkgname=literal-probe\npkgver=1\npkgrel=1\narch=(any)\nlicense=(MIT)\nsource=(payload)\nsha256sums=('" + checksum + "')\ndepends=(" + depends + ")\n" + relation + "\npackage() {\n  touch EXECUTED_RECIPE\n}\n")

    def test_real_recipe_inspection_without_srcinfo_or_shell_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp); self.make_recipe(base)
            with self.assertRaisesRegex(ValueError, 'dynamic depends'): OLD.recipe(base / 'PKGBUILD')
            result = NEW.recipe(base / 'PKGBUILD')
            self.assertEqual(result['status'], 'static-pass'); self.assertFalse(result['errors'])
            self.assertEqual(result['metadata']['depends'], ['python>=3.12'])
            self.assertFalse((base / '.SRCINFO').exists()); self.assertFalse((base / 'EXECUTED_RECIPE').exists())

    def test_single_recipe_cli_reports_success_and_protected_failure_as_data(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            for relation, expected in [('', 0), ("conflicts=('linux-asahi>=1')", 1)]:
                self.make_recipe(base, relation=relation); output = io.StringIO()
                with patch.object(sys, 'argv', ['package_checks_v2.py', 'recipe', str(base / 'PKGBUILD')]), contextlib.redirect_stdout(output):
                    self.assertEqual(NEW.main(), expected)
                self.assertEqual(bool(json.loads(output.getvalue())['recipes'][0]['errors']), bool(expected))
            self.assertEqual(ACTORS, [])

    def test_all_other_owner_functions_and_protected_constants_are_exactly_held(self):
        before = (ROOT / 'scripts/checks/package_checks.py').read_text(); after = V2.read_text()
        a = {n.name: ast.get_source_segment(before, n) for n in ast.parse(before).body if isinstance(n, ast.FunctionDef)}
        b = {n.name: ast.get_source_segment(after, n) for n in ast.parse(after).body if isinstance(n, ast.FunctionDef)}
        self.assertEqual(set(b) - set(a), {'relation_literals'})
        for name in set(a) - {'literal_metadata', 'main'}: self.assertEqual(a[name], b[name], name)
        for name in ('FIELDS', 'PROTECTED', 'PROTECTED_PACKAGES', 'ARCH_FIELDS', 'PACKAGE_METADATA', 'MAX_MEMBER', 'MAX_TOTAL'):
            self.assertEqual(getattr(OLD, name), getattr(NEW, name))


class AuditIsolationTests(unittest.TestCase):
    def test_import_and_owned_test_cleanup_do_not_block_other_python_fixtures(self):
        # A fresh process reproduces shared unittest discovery, including import
        # before our tests and other fixture processes after our cleanup.
        script = '''import importlib.util, subprocess, sys, unittest
spec=importlib.util.spec_from_file_location('audit_fixture',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert not m.AUDIT_ACTIVE
subprocess.run([sys.executable,'-I','-c','pass'],check=True,timeout=5)
case=m.LiteralTests('test_single_recipe_cli_reports_success_and_protected_failure_as_data')
result=unittest.TextTestRunner().run(unittest.TestSuite([case]))
assert result.wasSuccessful() and not m.AUDIT_ACTIVE
case.setUp()
try:
    try: subprocess.run([sys.executable,'-I','-c','pass'],check=True,timeout=5)
    except AssertionError: pass
    else: raise AssertionError('owned DATA guard was not active')
finally: case.doCleanups()
assert not m.AUDIT_ACTIVE
subprocess.run([sys.executable,'-I','-c','pass'],check=True,timeout=5)
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script, str(Path(__file__).resolve())],
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == '__main__':
    unittest.main(verbosity=2)
