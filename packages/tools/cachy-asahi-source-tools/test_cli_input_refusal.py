#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Maintained pure-data CLI controls; no mirror, native actors or network."""
import argparse
import ast
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import re
from pathlib import Path
import sys
import tarfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
PACKAGE = HERE
# Historical launcher and payload are inert fixtures from main 7c2c47382ce5.
# Only launcher code is evaluated; packed helper schemas are parsed with AST.
BASELINE_LAUNCHER = '''#!/usr/bin/python3 -IB
# SPDX-License-Identifier: MIT
"""Offline exact source mirrors and inert rebuild contexts."""
import argparse
import importlib.util
from pathlib import Path
import sys

RUNTIME = Path(__file__).resolve().parents[1] / 'lib/cachy-asahi/source-tools/scripts'
COMMANDS = {
    'mirror-export': ('release/release_source_mirror.py', 'export'),
    'mirror-successor': ('release/release_source_mirror.py', 'update'),
    'mirror-verify': ('release/release_source_mirror.py', 'verify'),
    'build-context': ('build/mirror_consumer.py', 'materialize'),
    'verify-context': ('build/mirror_consumer.py', 'verify-context'),
}

def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__, epilog='Each command accepts --help for its exact caller-pinned inputs.')
    parser.add_argument('--version', action='version', version='cachy-asahi-source-tools 0.1.0')
    parser.add_argument('command', choices=COMMANDS)
    if not argv or argv[0] not in COMMANDS:
        parser.parse_args(argv)
        return 2
    path, command = COMMANDS[argv[0]]
    spec = importlib.util.spec_from_file_location('installed_source_tools', RUNTIME / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.main([command, *argv[1:]])

if __name__ == '__main__':
    sys.dont_write_bytecode = True
    raise SystemExit(main())
'''
BASELINE_LAUNCHER_SHA256 = 'b7ccbb013b5479b80cfde65444454a3d22a4078e03ffd816a808ae12d983ac2a'
BASELINE_PAYLOAD = {'files': {'usr/bin/cachy-asahi-source-tools': {'bytes': 1483,
                                                'mode': 493,
                                                'sha256': 'b7ccbb013b5479b80cfde65444454a3d22a4078e03ffd816a808ae12d983ac2a'},
           'usr/lib/cachy-asahi/source-tools/scripts/build/build_v2.py': {'bytes': 13242,
                                                                          'mode': 420,
                                                                          'sha256': '37242a5680c0cb587087042455782478dac0f574f977a5f696c97d29eac39b43'},
           'usr/lib/cachy-asahi/source-tools/scripts/build/container-entry-v2.sh': {'bytes': 2447,
                                                                                    'mode': 420,
                                                                                    'sha256': '9be3db97efde70536a81d1c97f9ac69893a6004ab403566f8453704a2a189d2a'},
           'usr/lib/cachy-asahi/source-tools/scripts/build/mirror_consumer.py': {'bytes': 23156,
                                                                                 'mode': 420,
                                                                                 'sha256': 'dadde9d1c13f66b7295b86bf585ccad1801a130ed85e8bbe1f51fbd07c976b81'},
           'usr/lib/cachy-asahi/source-tools/scripts/build/source_materials.py': {'bytes': 7877,
                                                                                  'mode': 420,
                                                                                  'sha256': '9b0d95d2604ae4689f081283fc671281ce13879fcb146ddf4188873b05c89e5a'},
           'usr/lib/cachy-asahi/source-tools/scripts/checks/package_checks.py': {'bytes': 17706,
                                                                                 'mode': 420,
                                                                                 'sha256': 'e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8'},
           'usr/lib/cachy-asahi/source-tools/scripts/maintenance/source_cache.py': {'bytes': 14253,
                                                                                    'mode': 420,
                                                                                    'sha256': '3c922b1c5ea737605d7fd39aa986fa281c50bcf6926660390032e677706e28f3'},
           'usr/lib/cachy-asahi/source-tools/scripts/release/recipe_source_delivery.py': {'bytes': 24188,
                                                                                          'mode': 420,
                                                                                          'sha256': '779f8147a13d3f90d11b9e5610f2d7d74fce28d0732797331fc832f0e87323be'},
           'usr/lib/cachy-asahi/source-tools/scripts/release/release_sbom.py': {'bytes': 31044,
                                                                                'mode': 420,
                                                                                'sha256': '1a53831128858c6c629f2449a7276a52846e52ebf426baa6f1c010aa209af486'},
           'usr/lib/cachy-asahi/source-tools/scripts/release/release_source_mirror.py': {'bytes': 42982,
                                                                                         'mode': 420,
                                                                                         'sha256': '9c944d009f7035aa35862eea9d9990a52190136ad735d9460ca1ea4f4e34215c'},
           'usr/lib/cachy-asahi/source-tools/scripts/release/source_delivery.py': {'bytes': 16456,
                                                                                   'mode': 420,
                                                                                   'sha256': '8fc7757579bb0e97ccee1f3e1634ad3f827899c8ace6823cfda9f226214df36e'},
           'usr/lib/cachy-asahi/source-tools/scripts/update/archive_stream.py': {'bytes': 11938,
                                                                                 'mode': 420,
                                                                                 'sha256': '10f1a4c0ac5b98852d9ebb150af28f9ce345c800935a64fa463bc90f72fcb838'},
           'usr/share/doc/cachy-asahi-source-tools/README.md': {'bytes': 4159,
                                                                'mode': 420,
                                                                'sha256': 'c6fa9875b2dab616e6a9b39e58df53d1b287084e8c09a2f2c1ae55bd6a6ff3bb'},
           'usr/share/doc/cachy-asahi-source-tools/source-provenance.json': {'bytes': 2442,
                                                                             'mode': 420,
                                                                             'sha256': '28b2b8a2708bc3fece91d5560b17da358b59937d4afcebf5a42be28a1802b042'},
           'usr/share/licenses/cachy-asahi-source-tools/LICENSE': {'bytes': 1081,
                                                                   'mode': 420,
                                                                   'sha256': '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'},
           'usr/share/licenses/cachy-asahi-source-tools/NOTICE': {'bytes': 370,
                                                                  'mode': 420,
                                                                  'sha256': '650d77ba3fddc940807b827b88a4f8f274a2cce5048c0e3e2a785337ca6b6bfb'}},
 'package': 'cachy-asahi-source-tools',
 'schema_version': 1,
 'self': 'usr/share/doc/cachy-asahi-source-tools/payload-map.json'}
CURRENT_PINS = {'cachy-asahi-source-tools': 'df7b7d7168800c888412b05a955aa70a69491ad788cf320fffe893770b2cc9dc', 'README.md': '339574fe5d1b7fc61ad80fb36439e7acfcd87eb18cc6c813a76305943c139f08', 'payload-map.json': '480110e26ef1c1976ef09f835617d32e9eb4ca02dfa70c2e28393bf252279f61'}
HELD_PINS = {'private_runtime': 'fa9db2ee4a6f16fee53b79494d437901570c80798de9219d2cc637b9f430575a',
 'provenance': '28b2b8a2708bc3fece91d5560b17da358b59937d4afcebf5a42be28a1802b042'}
PIN = '1' * 64
OTHER = '2' * 64


def load_launcher(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def helper_source(path):
    if path == 'release/source_mirror_catalog.py':
        return (PACKAGE / 'source_mirror_catalog.py').read_bytes()
    with tarfile.open(PACKAGE / 'private-source.tar.gz', 'r:gz') as archive:
        return archive.extractfile('private/scripts/' + path).read()


def parse_options(raw):
    """Extract the actual installed scalar parser schema without invoking it."""
    tree = ast.parse(raw)
    parsers = {}
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'add_parser'):
            parsers[node.targets[0].id] = (node.value.args[0].value, {})
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == 'add_argument' and isinstance(node.func.value, ast.Name)
                and node.func.value.id in parsers):
            assert not any(kw.arg == 'nargs' or (kw.arg == 'action' and
                not (isinstance(kw.value, ast.Name) and kw.value.id == 'SingleValue'))
                for kw in node.keywords), 'non-scalar schema changed'
            kwargs = {kw.arg: ast.literal_eval(kw.value) for kw in node.keywords if kw.arg in ('required', 'choices')}
            for arg in node.args:
                if arg.value.startswith('--'):
                    parsers[node.func.value.id][1][arg.value] = kwargs
    return dict(parsers.values())


class CliInputRefusal(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert hashlib.sha256(BASELINE_LAUNCHER.encode()).hexdigest() == BASELINE_LAUNCHER_SHA256
        cls.before = types.ModuleType('source_tools_before')
        cls.before.__file__ = str(PACKAGE / 'legacy-launcher-fixture')
        exec(compile(BASELINE_LAUNCHER, cls.before.__file__, 'exec'), cls.before.__dict__)
        cls.after = load_launcher(PACKAGE / 'cachy-asahi-source-tools', 'source_tools_after')

    def refused_before_import(self, argv):
        err = io.StringIO()
        with mock.patch.object(self.after.importlib.util, 'spec_from_file_location') as loader:
            with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as caught:
                self.after.main(argv)
            self.assertEqual(caught.exception.code, 2)
            loader.assert_not_called()
        return err.getvalue()

    def forwarded(self, launcher, argv, main=None):
        target = types.SimpleNamespace(main=main or mock.Mock(return_value=0))
        spec = types.SimpleNamespace(name='installed_source_tools', loader=mock.Mock())
        with mock.patch.object(launcher.importlib.util, 'spec_from_file_location', return_value=spec):
            with mock.patch.object(launcher.importlib.util, 'module_from_spec', return_value=target):
                with mock.patch.dict(sys.modules):
                    result = launcher.main(argv)
        return result, target.main

    def test_installed_schema_exactly_matches_preflight(self):
        for command, (path, operation) in self.after.COMMANDS.items():
            with self.subTest(command=command):
                actual = parse_options(helper_source(path))[operation]
                self.assertEqual(set(self.after.OPTIONS[command]), set(actual))
        self.assertEqual(self.before.COMMANDS, {key: value for key, value in self.after.COMMANDS.items() if key != 'mirror-list'})
        self.assertEqual(self.after.COMMANDS['mirror-list'], ('release/source_mirror_catalog.py', 'list'))

    def test_baseline_conflicting_successor_pin_reaches_inert_runtime(self):
        schema = parse_options(helper_source('release/release_source_mirror.py'))['update']
        parser = argparse.ArgumentParser()
        for option, kwargs in schema.items():
            parser.add_argument(option, **kwargs)
        captured = []
        def inert_runtime(argv):
            self.assertEqual(argv[0], 'update')
            captured.append(parser.parse_args(argv[1:]))
            return 0
        argv = ['mirror-successor', '--previous-bundle', 'old.tar', '--previous-sha256', PIN,
                '--previous-release-sha256', PIN, '--release-dir', 'next', '--release-sha256', PIN,
                '--output', 'inert-output', '--previous-sha256=' + OTHER]
        status, _ = self.forwarded(self.before, argv, inert_runtime)
        self.assertEqual(status, 0)
        self.assertEqual(captured[0].previous_sha256, OTHER)
        self.assertIn('repeated option refused', self.refused_before_import(argv))

    def test_every_scalar_option_refuses_repeat_and_mixed_equals(self):
        for command, options in self.after.OPTIONS.items():
            for option in options:
                for pair in ((option, PIN, option, OTHER),
                             (option + '=' + PIN, option, OTHER),
                             (option, PIN, option + '=' + OTHER),
                             (option + '=' + PIN, option + '=' + PIN)):
                    with self.subTest(command=command, option=option, pair=pair):
                        error = self.refused_before_import([command, *pair])
                        self.assertIn('repeated option refused: ' + option, error)

    def test_abbreviation_cannot_bypass_conflicting_pin_refusal(self):
        for spelling in ('--previous-sha', '--previous-sha256x'):
            with self.subTest(spelling=spelling):
                error = self.refused_before_import(['mirror-successor', '--previous-sha256', PIN, spelling, OTHER])
                self.assertIn('unrecognized arguments', error)

    def test_single_inputs_forward_byte_for_byte_for_all_commands(self):
        for command, options in self.after.OPTIONS.items():
            # Values containing '=' or beginning '--' remain ordinary scalar data
            # when represented with argparse's standard equals spelling.
            values = [option + '=--inert=value' for option in options]
            with self.subTest(command=command):
                status, target = self.forwarded(self.after, [command, *values])
                self.assertEqual(status, 0)
                target.assert_called_once_with([self.after.COMMANDS[command][1], *values])

    def test_help_remains_delegated_to_actual_helper(self):
        for command in self.after.COMMANDS:
            for flag in ('-h', '--help'):
                with self.subTest(command=command, flag=flag):
                    status, target = self.forwarded(self.after, [command, flag])
                    self.assertEqual(status, 0)
                    target.assert_called_once_with([self.after.COMMANDS[command][1], flag])

    def test_incomplete_values_and_unknown_options_refuse_before_import(self):
        for argv in (['mirror-successor', '--previous-sha256'], ['mirror-export', '--dry-run'],
                     ['mirror-verify', 'surprise-positional'], ['build-context', '--out=/tmp/inert']):
            with self.subTest(argv=argv):
                self.refused_before_import(argv)

    def test_proposed_recipe_checksums_and_payload_match_exact_overlay(self):
        def body(name):
            # The executing test may be makepkg's staged copy outside the recipe.
            path = Path(__file__) if name == 'test_cli_input_refusal.py' else PACKAGE / name
            return path.read_bytes()
        info = body('.SRCINFO').decode()
        sources = re.findall(r'^\s+source = (.+)$', info, re.M)
        sums = re.findall(r'^\s+sha256sums = (.+)$', info, re.M)
        self.assertEqual(len(sources), len(sums))
        self.assertEqual(len(sources), 14)
        self.assertIn('test_cli_input_refusal.py', sources)
        recipe = body('PKGBUILD').decode()
        recipe_sums = re.search(r'^sha256sums=\((.+)\)$', recipe, re.M).group(1).split()
        self.assertEqual(recipe_sums, sums)
        recipe_sources = re.search(r'^source=\((.+)\)$', recipe, re.M).group(1).split()
        self.assertEqual(recipe_sources, sources)
        self.assertIn('pkgver=0.2.0\n', recipe)
        self.assertIn('pkgrel=1\n', recipe)
        self.assertIn('\tpkgver = 0.2.0\n', info)
        self.assertIn('\tpkgrel = 1\n', info)
        for name, checksum in zip(sources, sums):
            with self.subTest(source=name):
                self.assertEqual(hashlib.sha256(body(name)).hexdigest(), checksum)
        before = BASELINE_PAYLOAD
        after = json.loads(body('payload-map.json'))
        extension = 'usr/lib/cachy-asahi/source-tools/scripts/release/source_mirror_catalog.py'
        self.assertEqual(set(before['files']) | {extension}, set(after['files']))
        changed = {'usr/bin/cachy-asahi-source-tools': 'cachy-asahi-source-tools',
                   'usr/share/doc/cachy-asahi-source-tools/README.md': 'README.md'}
        for key, row in after['files'].items():
            if key == extension:
                raw = body('source_mirror_catalog.py')
                self.assertEqual(row, dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), mode=0o644))
            elif key in changed:
                raw = body(changed[key])
                self.assertEqual(row, dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                                           mode=before['files'][key]['mode']))
            else:
                self.assertEqual(row, before['files'][key])
        for name, checksum in CURRENT_PINS.items():
            self.assertEqual(hashlib.sha256(body(name)).hexdigest(), checksum)
        for name, checksum in (('private-source.tar.gz', HELD_PINS['private_runtime']),
                               ('source-provenance.json', HELD_PINS['provenance'])):
            self.assertEqual(hashlib.sha256(body(name)).hexdigest(), checksum)

    def test_global_version_and_unknown_command_keep_status(self):
        with contextlib.redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as caught:
            self.after.main(['--version'])
        self.assertEqual(caught.exception.code, 0)
        self.assertEqual(output.getvalue().strip(), 'cachy-asahi-source-tools 0.2.0')
        self.refused_before_import(['unrecognized-command'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, default=HERE)
    PACKAGE = parser.parse_args().recipe_root.resolve()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CliInputRefusal)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = dict(status='PASS' if result.wasSuccessful() else 'FAIL', tests=result.testsRun,
                  failures=len(result.failures), errors=len(result.errors),
                  evidence='PURE_DATA_FOCUSED_CLI_CONTROLS',
                  baseline_revision='7c2c47382ce5346d18f1de9952051faab4189f40',
                  baseline_launcher_sha256=BASELINE_LAUNCHER_SHA256,
                  packed_private_source_sha256=hashlib.sha256((PACKAGE / 'private-source.tar.gz').read_bytes()).hexdigest(),
                  current_launcher_sha256=hashlib.sha256((PACKAGE / 'cachy-asahi-source-tools').read_bytes()).hexdigest(),
                  native_build='NOT_RUN', alpm_installation='NOT_RUN', namespace_probe='NOT_RUN',
                  hardware='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED')
    print(json.dumps(report, sort_keys=True, indent=2))
    raise SystemExit(not result.wasSuccessful())
