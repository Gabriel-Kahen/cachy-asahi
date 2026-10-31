# SPDX-License-Identifier: MIT
"""Portable fixed-profile/refusal and complete original TEST-signer routing controls."""
import ast
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import prepare as F


class Controls(unittest.TestCase):
    def test_complete_fixed_profile_and_payload(self):
        value = F.profile()
        self.assertEqual(F.files(HERE / 'payload'), value['payload'])
        self.assertEqual((len(value['parent']['files']), len(value['payload']),
                          len(value['expected']['files'])), (745, 49, 796))
        self.assertEqual(value['bounds'], {'acquire64': 890, 'cleanup': 240, 'command': 90,
                         'lifecycle': 3600, 'observation': 600, 'owner': 4800,
                         'producer': 2300, 'transaction': 120})
        self.assertIsNone(value['actual'])
        self.assertEqual(value['default_mode'], 'baseline-scriptlet')

    def test_parent_payload_and_output_refuse_before_emitter(self):
        value = F.profile()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / 'runtime'
            runtime.mkdir()
            output = root / 'output'
            for problem in ('payload', 'parent', 'existing-output', 'nested-output'):
                def files(path, **kwargs):
                    rows = dict(value['payload'] if Path(path) == HERE / 'payload'
                                else value['parent']['files'])
                    if (problem == 'payload' and Path(path) == HERE / 'payload'
                            or problem == 'parent' and Path(path) == runtime):
                        rows.pop(next(iter(rows)))
                    return rows
                candidate = runtime / 'nested' if problem == 'nested-output' else output
                if problem == 'existing-output':
                    output.mkdir()
                with self.subTest(problem=problem), patch.object(F, 'files', side_effect=files), \
                     patch.object(F, 'load', side_effect=AssertionError('EMITTER_MUST_NOT_START')):
                    with self.assertRaises(ValueError):
                        F.assemble(runtime, candidate)
                if output.exists():
                    output.rmdir()
                self.assertFalse(candidate.exists())

    def test_stable_read_ordinary_path_and_link_refusal(self):
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / 'ordinary'
            path.write_bytes(b'stable bytes with deliberately stale atime')
            os.utime(path, ns=(1, path.stat().st_mtime_ns))
            self.assertEqual(F.read(path), path.read_bytes())
            alias = root / 'alias'
            alias.symlink_to(path.name)
            with self.assertRaisesRegex(ValueError, 'ordinary'):
                F.read(alias)
            os.link(path, root / 'hardlink')
            with self.assertRaisesRegex(ValueError, 'single-link'):
                F.read(path)

    def test_explicit_launch_template_is_exact_single_literal_successor(self):
        value = F.profile()
        launch = value['workflow_launch']
        template = F.read(HERE / launch['template']['path'])
        self.assertEqual(F.pin(template), {key: launch['template'][key]
                                         for key in ('bytes', 'sha256')})
        self.assertEqual(template.replace(launch['proposed'].encode(),
                                         launch['before'].encode(), 1),
                         F.read(HERE / 'payload/workflow.yml.in'))
        self.assertEqual({name for name in value['expected']['files']
                          if value['expected']['files'][name] != launch['files'][name]},
                         {'scripts/ci/core-native-lifecycle/workflow.yml.in',
                          'scripts/ci/core-native-lifecycle/source-manifest.json',
                          '.github/workflows/native-arm-build.yml',
                          '.github/workflows/native-arm-core-lifecycle.yml'})
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'mode'):
                F.assemble(Path(temporary), Path(temporary) / 'out', 'unknown')

    def test_transport_replacements_and_real_failed_public_packing(self):
        import json
        import zipfile
        value = F.profile()
        record = value['evidence_transport']
        self.assertEqual(set(record['replacements']), {'entry.py', 'owner.py', 'workflow.yml.in'})
        for name, row in record['replacements'].items():
            self.assertEqual(F.pin(F.read(HERE / row['path'])),
                             {key: row[key] for key in ('bytes', 'sha256')})
            self.assertEqual(F.pin(F.read(HERE / 'payload' / name)), row['before'])
        self.assertEqual(len(record['files']), 796)
        self.assertIsNone(record['actual'])
        with F.modules(HERE / 'payload'):
            owner = F.load(HERE / 'templates/transport-owner.py', '_source_transport_control')
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                public = root / 'public'
                public.mkdir()
                name = 'inputs/packages/python-pytest-1:9.1.1-1-any.pkg.tar.xz'
                path = public / name
                path.parent.mkdir(parents=True)
                path.write_bytes(b'INERT_CONTROL_ONLY_NO_PACKAGE_AUTHORITY')
                owner.save(public / 'owner.json', {'status': 'FAIL', 'error': 'retained failure bytes'})
                wanted = {n: F.pin(F.read(public / n)) for n in (name, 'owner.json')}
                owner.save(public / 'export.json', {'status': 'FAIL_OR_INCOMPLETE', 'files': wanted})
                args = types.SimpleNamespace(public=public, output=root / 'transport')
                self.assertEqual(owner.transport(args), 0)
                self.assertEqual({p.name for p in args.output.iterdir()}, {'public.zip', 'transport.json'})
                with zipfile.ZipFile(args.output / 'public.zip') as archive:
                    self.assertIsNone(archive.testzip())
                    self.assertEqual(archive.read(name), path.read_bytes())
                    self.assertEqual(archive.read('owner.json'), (public / 'owner.json').read_bytes())
                self.assertFalse(json.loads((args.output / 'transport.json').read_bytes())['acceptance'])
                path.write_bytes(b'drift')
                with self.assertRaisesRegex(ValueError, 'whole original export membership'):
                    owner.transport(types.SimpleNamespace(public=public, output=root / 'never'))
                self.assertFalse((root / 'never').exists())

    def test_auth_import_exact_body_inverse_dependency_and_preoutput_drift_refusal(self):
        value = F.profile()
        record = value['auth_import']
        self.assertEqual(set(record['replacements']), {'entry.py', 'owner.py', 'workflow.yml.in', 'assemble.py'})
        self.assertEqual(set(record['additions']), {'core-tools/package_checks.py'})
        self.assertEqual(len(record['files']), 797)
        self.assertIsNone(record['actual'])
        for name, row in record['replacements'].items():
            self.assertEqual(F.pin(F.read(HERE / row['path'])), {k: row[k] for k in ('bytes', 'sha256')})
            self.assertEqual(F.pin(F.read(HERE / 'payload' / name)), row['before'])
        row = record['additions']['core-tools/package_checks.py']
        self.assertEqual(F.pin(F.read(HERE / row['path'])), {k: row[k] for k in ('bytes', 'sha256')})
        self.assertEqual(row['origin'], {'source': '3dbd3180c74045786ba6ab1a444367a0aaf8f0d9',
                                        'path': 'scripts/checks/package_checks.py'})
        text = F.read(HERE / record['replacements']['assemble.py']['path']).decode()
        helper = "def authentication_module():\n sys.path.insert(0,str(Path(__file__).resolve().parent/'core-tools'));import authenticate as A\n return A\n\n"
        self.assertEqual(text.count(helper), 1)
        text = text.replace(helper, '', 1)
        text = text.replace(" A=authentication_module()", " sys.path.insert(0,str(SOURCE/'core-tools'));import authenticate as A", 1)
        text = text.replace('if args.source_only:authentication_module();signer_module();print(',
                            'if args.source_only:signer_module();print(', 1)
        self.assertEqual(text.encode(), F.read(HERE / 'payload/assemble.py'))
        workflow = F.read(HERE / record['replacements']['workflow.yml.in']['path'])
        addition = b'          python3 -I -B "$OWN/assemble.py" --source-only\n'
        self.assertEqual(workflow.count(addition), 1)
        self.assertEqual(workflow.replace(addition, b'', 1), F.read(HERE / 'templates/transport-workflow.yml.in'))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / 'runtime'
            runtime.mkdir()
            original = F.read
            def read(path, *args):
                return b'drift' if Path(path) == HERE / row['path'] else original(path, *args)
            def files(path, **kwargs):
                return value['payload'] if Path(path) == HERE / 'payload' else value['parent']['files']
            with patch.object(F, 'files', side_effect=files), patch.object(F, 'read', side_effect=read), \
                 patch.object(F, 'load', side_effect=AssertionError('EMITTER_MUST_NOT_START')):
                with self.assertRaisesRegex(ValueError, 'added dependency'):
                    F.assemble(runtime, root / 'must-not-exist')
            self.assertFalse((root / 'must-not-exist').exists())

    def test_whole_original_sign_body_and_all_seven_inert_calls(self):
        """Only the GPG subprocess boundary is fake; the complete sign() body runs."""
        value = F.profile()
        signer = F.load(HERE / 'payload/test_signer.py', '_core796_test_signer_control')
        source = F.read(Path(signer.__file__)).decode()
        function = next(node for node in ast.parse(source).body
                        if isinstance(node, ast.FunctionDef) and node.name == 'sign')
        self.assertEqual(F.pin(ast.get_source_segment(source, function).encode()),
                         value['original_signer']['function'])
        fingerprint, calls = 'A' * 40, []
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs, authority = root / 'inputs', root / 'authority'
            inputs.mkdir()
            authority.mkdir(mode=0o700)
            names = ('pacman', 'systemd', 'systemd-libs', 'systemd-resolvconf',
                     'systemd-sysvcompat', 'systemd-tests', 'systemd-ukify')
            packages = [inputs / name for name in names]
            for package in packages:
                package.write_bytes(b'EXPLICIT_INERT_FIXTURE_NO_SIGNATURE_AUTHORITY')
            prefix = ['gpg', '--batch', '--no-options', '--homedir',
                      str(authority / 'test-signing'), '--no-auto-key-retrieve',
                      '--pinentry-mode', 'loopback', '--passphrase', '']

            def run(argv, **kwargs):
                calls.append(argv)
                self.assertEqual(argv[:len(prefix)], prefix)
                self.assertEqual(kwargs, {'check': True, 'capture_output': True, 'timeout': 30})
                if '--quick-generate-key' in argv:
                    self.assertEqual(argv[len(prefix):], ['--quick-generate-key',
                                     'TEST ONLY composition <composition@test.invalid>',
                                     'ed25519', 'sign', '1d'])
                else:
                    self.assertEqual(argv[-4], '--output')
                    self.assertEqual(argv[-2], '--detach-sign')
                    self.assertEqual(argv[-3], argv[-1] + '.sig')
                return types.SimpleNamespace(returncode=0)

            def output(argv, **kwargs):
                calls.append(argv)
                self.assertEqual(argv[:len(prefix)], prefix)
                if argv[-1] == '--list-keys':
                    self.assertEqual(argv[len(prefix):], ['--with-colons', '--list-keys'])
                    self.assertEqual(kwargs, {'text': True, 'timeout': 30})
                    return 'fpr:::::::::' + fingerprint + ':\n'
                self.assertEqual(argv[len(prefix):], ['--armor', '--export', fingerprint])
                self.assertEqual(kwargs, {'timeout': 30})
                return b'EXPLICIT_INERT_PUBLIC_DATA_NOT_A_KEY'

            with patch.object(subprocess, 'run', side_effect=run), \
                 patch.object(subprocess, 'check_output', side_effect=output), \
                 patch.object(subprocess, 'Popen', side_effect=AssertionError('NO_PROCESS')):
                self.assertEqual(signer.sign(inputs, authority, packages), fingerprint)
            self.assertEqual(len(calls), 10)
            self.assertEqual([argv[-1] for argv in calls if '--detach-sign' in argv],
                             [str(package) for package in packages])
            self.assertEqual((inputs / 'TEST-public.asc').read_bytes(),
                             b'EXPLICIT_INERT_PUBLIC_DATA_NOT_A_KEY')
            self.assertEqual((authority / 'test-signing').stat().st_mode & 0o777, 0o700)


if __name__ == '__main__':
    unittest.main(verbosity=2)
