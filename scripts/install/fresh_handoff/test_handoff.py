#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Local software tests; predecessor authentication is a labeled TEST seam.

The signed candidate test uses genuine fresh disposable TEST signatures. Other
custody tests use the existing recovery suite's UNSIGNED synthetic fixtures.
No native actor, ALPM transaction, installed session or M2 is exercised.
"""
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


H = load('fresh_handoff', Path(__file__).with_name('handoff.py'))
F = load('fresh_recovery_fixtures', ROOT / 'scripts/release/test_recovery_bundle.py')
# Reuse the original tiny fixture and its explicitly mocked predecessor auth.
# All custody/parsing/reinspection/copy operations remain the production code.
F.B, F.C, F.P, F.K = H.R, H.C, H.R.P, H.K
REAL_INSPECT = H.K.inspect
FIRST = load('fresh_first_login', ROOT / 'scripts/install/first_login.py')
SETUP = load('fresh_setup8', ROOT / 'packages/tools/cachy-asahi-setup8/setup.py')


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.f = F.BundleTests(methodName='runTest')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.root = self.f.root
        self.candidate = self.root / 'candidate'
        shutil.copytree(self.f.kit, self.candidate, symlinks=True)
        self.f.build()
        self.original_inspect = self.f.authenticated_seam
        def test_auth(args):
            if Path(args.kit).name == 'candidate':
                H.need(args.signer == 'B' * 40 and args.namespace == 'dev.TEST-candidate', 'TEST candidate authority mismatch')
                H.need(args.kit_sha256 == H.C.digest((Path(args.kit) / 'kit.json').read_bytes()), 'TEST candidate kit pin differs')
                return dict(release_sha256=H.C.digest((Path(args.kit) / 'release/release.json').read_bytes()))
            return self.original_inspect(args)
        H.K.inspect.side_effect = test_auth
        self.commit = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
        self.chosen = dict(schema_version=1, purpose='development-fresh-install-handoff', source_commit=self.commit,
            candidate=dict(kit_sha256=H.C.digest((self.candidate/'kit.json').read_bytes()),
                release_sha256=self.f.chosen['release_sha256'], signer='B'*40,
                namespace='dev.TEST-candidate', minimum_sequence=1),
            recovery=dict(receipt_sha256=self.f.result['receipt_sha256'], selection_sha256=self.f.selection_pin,
                release_sha256=self.f.chosen['release_sha256'], signer=self.f.signer,
                namespace='dev.original', minimum_sequence=1))
        self.selection_path = self.root / 'handoff-selection.json'
        self.output = self.root / 'handoff'
        self.args = argparse.Namespace(output=self.output, candidate=self.candidate, recovery=self.f.output,
                                       selection=self.selection_path, state_dir=self.f.state)
        self.save()

    def save(self):
        self.selection_path.write_bytes(H.C.encoded(self.chosen))
        self.args.selection_sha256 = H.C.digest(self.selection_path.read_bytes())

    def build(self):
        result = H.prepare(self.args)
        self.check = argparse.Namespace(workspace=self.output, state_dir=self.f.state,
            selection_sha256=self.args.selection_sha256, receipt_sha256=result['receipt_sha256'])
        return result

    def test_portable_data_after_originals_deleted_and_no_receiver_state_writes(self):
        before = H.K.inventory(self.f.state)
        result = self.build()
        shutil.rmtree(self.candidate)
        shutil.rmtree(self.f.output)
        shutil.rmtree(self.f.kit)
        shutil.rmtree(self.f.inputs)
        relocated = self.root / 'moved handoff'
        self.output.rename(relocated)
        self.check.workspace = relocated
        checked = H.verify(self.check)
        self.assertEqual(result['receipt_sha256'], checked['receipt_sha256'])
        self.assertEqual(before, H.K.inventory(self.f.state))
        self.assertEqual(checked['status'], 'HELD_DEVELOPMENT_HANDOFF')
        self.assertFalse(checked['packages_installed'])
        self.assertFalse(checked['release_accepted'])
        self.assertEqual(checked['m2_air_13'], 'NOT RUN')
        self.assertEqual(len(checked['actions']), 8)
        self.assertTrue((relocated/'recovery/recovery/packages/original-00/archive').is_file())
        self.assertIn('boot/session restoration', (relocated/'ACTIONS.txt').read_text())

    def test_genuine_TEST_signed_candidate_and_signature_refusal(self):
        kit_tests = load('fresh_signed_candidate_fixtures', ROOT / 'scripts/release/test_offline_kit.py')
        kit_tests.KitTests.setUpClass()
        self.addCleanup(kit_tests.KitTests.tearDownClass)
        signed = kit_tests.KitTests(methodName='runTest')
        setup = kit_tests.t.ReleaseTests.setUp
        def platform_fixture(case):
            setup(case)
            base = kit_tests.t.r.load(case.inputs / 'base.json')
            base['packages'].append(dict(name='original-00', version='1-1', arch='aarch64',
                                         depend=[], provides=[], conflict=[], files=[]))
            case.put('base.json', base)
            case.release_spec['base'].update(case.ref('base.json'))
            case.release_spec['policy']['protected_packages'] = ['original-00']
        with mock.patch.object(kit_tests.t.ReleaseTests, 'setUp', platform_fixture):
            signed.setUp()
        self.addCleanup(signed.doCleanups)
        result = signed.assemble()
        shutil.rmtree(self.candidate)
        shutil.move(signed.output, self.candidate)
        self.chosen['candidate'].update(kit_sha256=result['kit_sha256'],
            release_sha256=result['release_sha256'], signer=signed.f.key,
            namespace=signed.args.namespace)
        self.save()
        def independent_auth(args):
            return REAL_INSPECT(args) if Path(args.kit).name == 'candidate' else self.original_inspect(args)
        H.K.inspect.side_effect = independent_auth
        # Candidate kit signatures are actually verified. Only the predecessor
        # uses the explicitly unsigned TEST actor seam from recovery fixtures.
        self.build()
        checked = H.verify(self.check)
        self.assertEqual(checked['candidate_release_sha256'], result['release_sha256'])
        self.assertFalse(checked['trust_enrolled'])
        signature = self.candidate / 'development.json.sig'
        signature.chmod(0o600)
        signature.write_bytes(b'TEST invalid signature')
        receipt_path = self.candidate / 'kit.json'
        receipt = H.C.decode(receipt_path.read_bytes())
        receipt['files']['development.json.sig'] = H.C.digest(signature.read_bytes())
        receipt_path.chmod(0o600)
        receipt_path.write_bytes(H.C.encoded(receipt))
        self.chosen['candidate']['kit_sha256'] = H.C.digest(receipt_path.read_bytes())
        self.save()
        self.args.output = self.root / 'refused-signature'
        with self.assertRaises(H.C.Error):
            H.prepare(self.args)
        self.assertFalse(self.args.output.exists())

    def test_changed_candidate_or_recovery_or_operator_instructions_refused(self):
        self.build()
        for name in ('candidate/release/base.json', 'recovery/recovery/packages/original-00/archive', 'ACTIONS.txt'):
            with self.subTest(name=name):
                path = self.output/name
                raw = path.read_bytes()
                path.chmod(0o600)
                path.write_bytes(raw + b'TEST tamper')
                with self.assertRaises(H.C.Error):
                    H.verify(self.check)
                path.write_bytes(raw)
        H.verify(self.check)

    def test_foreign_file_and_escaping_alias_refused(self):
        self.build()
        path = self.output / 'foreign'
        path.write_text('TEST')
        with self.assertRaises(H.C.Error): H.verify(self.check)
        path.unlink()
        path.symlink_to('/etc/passwd')
        with self.assertRaises(H.C.Error): H.verify(self.check)

    def test_wrong_external_pins_and_signer_refused_before_publication(self):
        for role, field, value in (('candidate', 'release_sha256', 'f'*64),
                                   ('candidate', 'signer', 'C'*40),
                                   ('recovery', 'receipt_sha256', 'f'*64),
                                   ('recovery', 'signer', 'C'*40)):
            with self.subTest(role=role, field=field):
                original = self.chosen[role][field]
                self.chosen[role][field] = value
                self.save()
                with self.assertRaises(H.C.Error): H.prepare(self.args)
                self.assertFalse(self.output.exists())
                self.chosen[role][field] = original
        self.save()

    def test_missing_recovery_asset_refused_without_publishing(self):
        (self.f.output / 'recovery/packages/original-00/archive').unlink()
        with self.assertRaises(H.C.Error): H.prepare(self.args)
        self.assertFalse(self.output.exists())

    def test_platform_change_is_not_a_valid_preserving_handoff(self):
        path = self.candidate/'release/base.json'
        base = H.C.decode(path.read_bytes())
        base['packages'][0]['version'] = 'TEST-incompatible-platform'
        path.write_bytes(H.C.encoded(base))
        with self.assertRaisesRegex(H.C.Error, 'protected platform differs'):
            H.prepare(self.args)
        self.assertFalse(self.output.exists())

    def test_failure_during_copy_is_atomic_and_existing_output_is_preserved(self):
        original = H.copy_data
        def interrupt(source, target):
            original(source, target)
            raise InterruptedError('TEST interruption')
        with mock.patch.object(H, 'copy_data', side_effect=interrupt):
            with self.assertRaises(InterruptedError): H.prepare(self.args)
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.root.glob('.fresh-handoff-*')))
        self.output.mkdir()
        marker = self.output/'user-owned'
        marker.write_text('preserve')
        with self.assertRaises(H.C.Error): H.prepare(self.args)
        self.assertEqual(marker.read_text(), 'preserve')

    def test_unsafe_or_overlapping_output_refused(self):
        for target in (self.candidate/'out', self.f.output/'out', self.f.state/'out'):
            with self.subTest(target=target):
                self.args.output = target
                with self.assertRaises(H.C.Error): H.prepare(self.args)
        self.args.output = self.output
        alias = self.root/'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        self.args.output = alias/'new-handoff'
        with self.assertRaises(OSError): H.prepare(self.args)
        self.assertFalse(self.output.exists())

    def test_closed_selection_rejects_promotion_and_duplicate_keys(self):
        value = copy.deepcopy(self.chosen)
        value['release_accepted'] = True
        with self.assertRaises(H.C.Error): H.selection(H.C.encoded(value))
        with self.assertRaises(H.C.Error): H.selection(b'{"schema_version":1,"schema_version":1}')
        value = copy.deepcopy(self.chosen)
        value['candidate']['minimum_sequence'] = True
        with self.assertRaises(H.C.Error): H.selection(H.C.encoded(value))

    def test_exact_owning_sources_are_bound_and_drift_refuses(self):
        refs = H.source_refs(self.commit)
        self.assertEqual(set(refs), set(H.SOURCES))
        reader = H.C.read_path
        def changed(path, maximum):
            raw = reader(path, maximum)
            return raw + b'TEST drift' if path == ROOT / H.SOURCES[0] else raw
        with mock.patch.object(H.C, 'read_path', side_effect=changed):
            with self.assertRaisesRegex(H.C.Error, 'source differs'):
                H.prepare(self.args)
        self.assertFalse(self.output.exists())


class RealHelperJourneyTests(unittest.TestCase):
    def test_real_templates_activate_recover_and_remove_without_losing_user_bytes(self):
        if not all(os.access(FIRST.PROGRAMS[name], os.X_OK) for name in ('fish', 'zsh')):
            self.skipTest('existing fish/zsh programs unavailable; no dependencies installed')
        with tempfile.TemporaryDirectory(prefix='fresh-handoff-TEST-home-') as temporary:
            root = Path(temporary)
            home = root/'ordinary home'
            home.mkdir(mode=0o700)
            templates = root/'usr/share/cachy-asahi'
            for name, source in (('fish/config.fish', 'packages/shells/cachy-asahi-fish-config/config.fish'),
                                 ('zsh/config.zsh', 'packages/shells/cachy-asahi-zsh-config/config.zsh')):
                path = templates/name
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT/source, path)
            helper = root/'usr/bin/cachy-asahi-setup'
            helper.parent.mkdir(parents=True)
            shutil.copyfile(ROOT/'packages/tools/cachy-asahi-setup8/cachy-asahi-setup', helper)
            helper.chmod(0o700)
            fish = home/'.config/fish/config.fish'
            fish.parent.mkdir(parents=True)
            original = b'# retained user configuration without final newline'
            fish.write_bytes(original)
            paths = ['--setup-helper', str(helper), '--home', str(home), '--template-root', str(templates)]
            def first(*argv):
                return FIRST.execute(FIRST.parser().parse_args([*argv, *paths]))
            report, code = first('activate', '--components', 'fish', 'zsh')
            self.assertEqual((code, report['status']), (0, 'activation-preview'))
            self.assertEqual(fish.read_bytes(), original)
            # Genuine interrupted helper write in an owned temp home. Actor
            # boundary only: deliberately injected exception, not power loss.
            engine = SETUP.Setup(home, templates)
            atomic = engine.fs.atomic
            def interrupted(path, *args, **kwargs):
                result = atomic(path, *args, **kwargs)
                if path == engine.targets['fish']:
                    raise InterruptedError('TEST interrupted setup')
                return result
            try:
                with mock.patch.object(engine.fs, 'atomic', side_effect=interrupted):
                    with self.assertRaises(InterruptedError):
                        engine.run('activate', ('fish', 'zsh'), True)
            finally:
                engine.close()
            report, code = first('inspect')
            self.assertEqual((code, report['status']), (2, 'recovery-required'))
            report, code = first('recover')
            self.assertEqual(report['status'], 'recovery-preview')
            report, code = first('recover', '--apply')
            self.assertEqual((code, report['status']), (0, 'recovery-applied'))
            self.assertIn(original, fish.read_bytes())
            report, code = first('activate', '--components', 'fish', 'zsh', '--apply')
            self.assertEqual((code, report['status']), (0, 'activation-applied'))
            args = FIRST.freeze_paths(FIRST.parser().parse_args(paths))
            report, code = FIRST.invoke(FIRST.helper_command(args, 'remove', ('fish', 'zsh'), True))
            self.assertEqual(code, 0)
            self.assertEqual(fish.read_bytes(), original)
            self.assertFalse((home/'.zshrc').exists())


if __name__ == '__main__':
    unittest.main()
