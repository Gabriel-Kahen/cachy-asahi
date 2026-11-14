#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Genuine TEST candidate/predecessor/archive signatures; no verifier mocks.

The fixed production ALARM anchor is replaced only inside this TEST process by
an explicit disposable TEST anchor. No production identity/trust is claimed.
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

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


H = load('genuine_signed_handoff', HERE / 'handoff.py')
F = load('genuine_handoff_fixture', HERE / 'signed_fixture.py')


class SignedHandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        F.T.ReleaseTests.setUpClass()
        cls.owner = unittest.TestCase(methodName='runTest')
        cls.original_keys = H.R.P.auth.KEYS
        try:
            cls.fixture = F.SignedFixture(cls.owner, H)
            H.R.P.auth.KEYS = {**cls.original_keys, 'alarm': cls.fixture.anchor}
            cls.fixture.materialize()
            F.T.r.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                       'Other TEST signer <other-test@invalid>', 'ed25519', 'sign', '1d'], env=cls.fixture.env)
            listing = F.T.r.run(['gpg', '--batch', '--with-colons', '--list-keys'], env=cls.fixture.env).decode()
            cls.other_key = next(line.split(':')[9] for line in listing.splitlines()
                                 if line.startswith('fpr:') and line.split(':')[9] != cls.fixture.key)
        except BaseException:
            H.R.P.auth.KEYS = cls.original_keys
            cls.owner.doCleanups()
            F.T.ReleaseTests.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        H.R.P.auth.KEYS = cls.original_keys
        cls.owner.doCleanups()
        F.T.ReleaseTests.tearDownClass()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fresh-TEST-genuine-case-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.candidate, self.recovery = self.root/'candidate', self.root/'recovery'
        shutil.copytree(self.fixture.candidate, self.candidate, symlinks=True)
        shutil.copytree(self.fixture.recovery, self.recovery, symlinks=True)
        self.state = self.root/'state'
        self.state.mkdir(mode=0o700)
        self.chosen = copy.deepcopy(self.fixture.chosen)
        self.selection = self.root/'selection.json'
        self.output = self.root/'handoff'
        self.args = argparse.Namespace(selection=self.selection, candidate=self.candidate,
                                       recovery=self.recovery, output=self.output, state_dir=self.state)
        self.save()

    def save(self):
        self.selection.write_bytes(H.C.encoded(self.chosen))
        self.args.selection_sha256 = H.C.digest(self.selection.read_bytes())

    def build(self):
        result = H.prepare(self.args)
        self.check = argparse.Namespace(workspace=self.output, receipt_sha256=result['receipt_sha256'],
                                       selection_sha256=self.args.selection_sha256, state_dir=self.state)
        return result

    def repin_recovery(self):
        # TEST operator repins all transport layers. Semantic/signature rejection
        # must still happen; checksums alone cannot authorize different bytes.
        prior_path = self.recovery/'recovery/receipt.json'
        prior = H.C.decode(prior_path.read_bytes())
        for row in prior['packages']:
            for field in ('archive', 'signature'):
                data = (self.recovery/'recovery/packages'/row['name']/field).read_bytes()
                row[field].update(size=len(data), sha256=H.C.digest(data))
        prior_path.chmod(0o600)
        prior_path.write_bytes(H.C.encoded(prior))
        selection_path = self.recovery/'selection.json'
        selected = H.C.decode(selection_path.read_bytes())
        selected['recovery_receipt'].update(size=prior_path.stat().st_size, sha256=H.C.digest(prior_path.read_bytes()))
        selection_path.chmod(0o600)
        selection_path.write_bytes(H.C.encoded(selected))
        self.chosen['recovery']['selection_sha256'] = H.C.digest(selection_path.read_bytes())
        receipt_path = self.recovery/'recovery-bundle.json'
        receipt = H.C.decode(receipt_path.read_bytes())
        files, links = H.K.inventory(self.recovery)
        files.pop('recovery-bundle.json')
        receipt.update(files=files, symlinks=links, selection_sha256=self.chosen['recovery']['selection_sha256'])
        receipt_path.chmod(0o600)
        receipt_path.write_bytes(H.C.encoded(receipt))
        self.chosen['recovery']['receipt_sha256'] = H.C.digest(receipt_path.read_bytes())
        self.save()

    def test_real_signed_pair_and_all16_recovery_archives_survive_relocation(self):
        before = H.K.inventory(self.state)
        result = self.build()
        moved = self.root/'moved operator media'
        self.output.rename(moved)
        shutil.rmtree(self.candidate)
        shutil.rmtree(self.recovery)
        self.check.workspace = moved
        checked = H.verify(self.check)
        self.assertTrue(checked['fresh_recovery_signature_verification'])
        self.assertEqual(checked['status'], 'HELD_DEVELOPMENT_HANDOFF')
        self.assertEqual(checked['receipt_sha256'], result['receipt_sha256'])
        self.assertFalse(checked['trust_enrolled'])
        self.assertFalse(checked['packages_installed'])
        self.assertEqual(H.K.inventory(self.state), before)
        self.assertEqual(len(list((moved/'recovery/recovery/packages').iterdir())), 16)

    def test_unknown_predecessor_identity_and_wrong_release_are_named_refusals(self):
        for field, value, message in (('signer', 'C'*40, 'PREDECESSOR_AUTH_REFUSED'),
                                      ('release_sha256', 'f'*64, 'predecessor release differs')):
            with self.subTest(field=field):
                original = self.chosen['recovery'][field]
                self.chosen['recovery'][field] = value
                self.save()
                with self.assertRaisesRegex(H.C.Error, message): H.prepare(self.args)
                self.assertFalse(self.output.exists())
                self.chosen['recovery'][field] = original
        self.save()

    def test_unknown_candidate_keyring_cannot_replace_signed_identity(self):
        # A different valid public key is repinned as transport data. The actual
        # crypto path must still reject the unavailable pinned signing identity.
        path = self.candidate/'public.gpg'
        path.chmod(0o600)
        path.write_bytes(F.T.r.run(['gpg', '--batch', '--export', self.other_key], env=self.fixture.env))
        receipt_path = self.candidate/'kit.json'
        receipt = H.C.decode(receipt_path.read_bytes())
        receipt['files']['public.gpg'] = H.C.digest(path.read_bytes())
        receipt_path.chmod(0o600)
        receipt_path.write_bytes(H.C.encoded(receipt))
        self.chosen['candidate']['kit_sha256'] = H.C.digest(receipt_path.read_bytes())
        self.save()
        with self.assertRaisesRegex(H.C.Error, 'CANDIDATE_AUTH_REFUSED'): H.prepare(self.args)
        self.assertFalse(self.output.exists())

    def test_unknown_predecessor_keyring_is_a_cryptographic_refusal(self):
        kit = self.recovery/'predecessor'
        path = kit/'public.gpg'
        path.chmod(0o600)
        path.write_bytes(F.T.r.run(['gpg', '--batch', '--export', self.other_key], env=self.fixture.env))
        receipt_path = kit/'kit.json'
        receipt = H.C.decode(receipt_path.read_bytes())
        receipt['files']['public.gpg'] = H.C.digest(path.read_bytes())
        receipt_path.chmod(0o600)
        receipt_path.write_bytes(H.C.encoded(receipt))
        selected_path = self.recovery/'selection.json'
        selected = H.C.decode(selected_path.read_bytes())
        selected['kit_sha256'] = H.C.digest(receipt_path.read_bytes())
        selected_path.chmod(0o600)
        selected_path.write_bytes(H.C.encoded(selected))
        self.repin_recovery()
        with self.assertRaisesRegex(H.C.Error, 'PREDECESSOR_AUTH_REFUSED.*GPG rejected'):
            H.prepare(self.args)
        self.assertFalse(self.output.exists())

    def test_missing_and_tampered_recovery_bytes_refused(self):
        path = self.recovery/'recovery/packages/test-old-00/archive'
        original = path.read_bytes()
        path.unlink()
        with self.assertRaisesRegex(H.C.Error, 'PREDECESSOR_AUTH_REFUSED'): H.prepare(self.args)
        path.write_bytes(original + b'TEST corrupt archive')
        with self.assertRaisesRegex(H.C.Error, 'PREDECESSOR_AUTH_REFUSED'): H.prepare(self.args)
        self.assertFalse(self.output.exists())

    def test_invalid_recovery_signature_is_rejected_after_all_hashes_are_repinned(self):
        path = self.recovery/'recovery/packages/test-old-00/signature'
        path.chmod(0o600)
        path.write_bytes(b'TEST invalid detached signature')
        self.repin_recovery()
        with self.assertRaisesRegex(H.C.Error, 'RECOVERY_SIGNATURE_REFUSED: test-old-00'):
            H.prepare(self.args)
        self.assertFalse(self.output.exists())

    def test_genuinely_signed_wrong_recovery_version_is_not_the_selected_predecessor(self):
        archive = self.recovery/'recovery/packages/test-old-00/archive'
        archive.chmod(0o600)
        import io
        import tarfile
        with tarfile.open(archive, 'w:xz') as tar:
            raw = b'pkgname = test-old-00\npkgver = 99-1\narch = aarch64\nlicense = MIT\n'
            entry = tarfile.TarInfo('.PKGINFO')
            entry.size = len(raw)
            tar.addfile(entry, io.BytesIO(raw))
        signature = Path(str(archive)+'.sig')
        F.T.r.sign(archive, self.fixture.key, self.fixture.env)
        target = archive.with_name('signature')
        target.chmod(0o600)
        target.write_bytes(signature.read_bytes())
        signature.unlink()
        self.repin_recovery()
        with self.assertRaisesRegex(H.C.Error, 'PREDECESSOR_AUTH_REFUSED'):
            H.prepare(self.args)
        self.assertFalse(self.output.exists())

    def test_signed_key_transition_is_held_without_separate_transition_admission(self):
        other = self.other_key
        role = 'transition-candidate'
        replacement, checked = self.fixture.kit(self, role, other)
        shutil.rmtree(self.candidate)
        shutil.move(replacement, self.candidate)
        self.chosen['candidate'].update(kit_sha256=checked['kit_sha256'], release_sha256=checked['release_sha256'],
                                        signer=other, namespace='dev.test-'+role)
        self.save()
        with self.assertRaisesRegex(H.C.Error, 'SIGNER_TRANSITION_HELD'): H.prepare(self.args)
        self.assertFalse(self.output.exists())

    def test_source_hidden_relocated_cli_and_explicit_TEST_anchor_journey(self):
        if not shutil.which('bwrap'):
            self.skipTest('bwrap unavailable; no dependencies installed')
        result = self.build()
        moved = self.root/'moved handoff'
        self.output.rename(moved)
        shutil.rmtree(self.candidate)
        shutil.rmtree(self.recovery)
        operator = moved/'operator'
        arguments = ['verify', '--workspace', str(moved), '--receipt-sha256', result['receipt_sha256'],
                     '--selection-sha256', self.args.selection_sha256, '--state-dir', str(self.state)]
        # Only this owned case root survives /tmp hiding. The producer fixtures,
        # private TEST signing home, original checkout and network are hidden.
        prefix = ['bwrap', '--unshare-net', '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev',
                  '--tmpfs', '/tmp', '--bind', str(self.root), str(self.root),
                  '--tmpfs', str(F.ROOT), '--chdir', str(self.root)]
        environment = dict(os.environ, PYTHONPATH='/TEST-poison', PYTHONHOME='/TEST-poison', HOME='/TEST-no-home')
        product = subprocess.run([*prefix, sys.executable, '-I', '-B',
            str(operator/'scripts/install/fresh_handoff/runtime.py'), '--runtime-sha256', result['runtime_sha256'],
            '--', *arguments], capture_output=True, timeout=60, env=environment)
        # Production policy is fixed ALARM, so these TEST recovery certificates
        # stay refused by the actual CLI. No product trust bypass is introduced.
        self.assertEqual(product.returncode, 1, product.stdout.decode())
        self.assertIn(b'PREDECESSOR_AUTH_REFUSED', product.stderr)
        self.assertIn(b'pinned ALARM certificate required', product.stderr)
        driver = self.root/'TEST-explicit-anchor-driver.py'
        driver.write_text('''import importlib.util,pathlib,socket,sys
operator=pathlib.Path(sys.argv[1])
assert not list(pathlib.Path(sys.argv[5]).iterdir())
assert not pathlib.Path(sys.argv[6]).exists()
assert [name for _,name in socket.if_nameindex()]==['lo']
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
runtime=load('TEST_operator_runtime',operator/'scripts/install/fresh_handoff/runtime.py')
lock=runtime.verify(operator,sys.argv[2])
handoff=load('TEST_operator_handoff',operator/'scripts/install/fresh_handoff/handoff.py')
handoff.DELIVERED_SOURCE_LOCK=lock
# TEST-ONLY external anchor substitution. Every verifier remains unchanged.
handoff.R.P.auth.KEYS={**handoff.R.P.auth.KEYS,'alarm':(sys.argv[3],sys.argv[4])}
raise SystemExit(handoff.main(sys.argv[7:]))
''')
        before = H.K.inventory(self.state)
        process = subprocess.run([*prefix, sys.executable, '-I', '-B', str(driver), str(operator),
            result['runtime_sha256'], self.fixture.key, self.fixture.anchor[1], str(F.ROOT),
            str(self.fixture.home), *arguments], capture_output=True, timeout=60, env=environment)
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        observed = json.loads(process.stdout)
        self.assertTrue(observed['fresh_recovery_signature_verification'])
        self.assertEqual(observed['status'], 'HELD_DEVELOPMENT_HANDOFF')
        self.assertEqual(observed['runtime_sha256'], result['runtime_sha256'])
        self.assertFalse(observed['trust_enrolled'])
        self.assertEqual(H.K.inventory(self.state), before)
        self.assertFalse(list(operator.rglob('__pycache__')))


if __name__ == '__main__':
    unittest.main()
