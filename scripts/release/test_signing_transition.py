#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real disposable TEST keys and signed synthetic releases; no system trust changes."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
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

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


t = module('signing_transition', 'signing_transition.py')
fixture = module('transition_fixture', 'test_compare_releases.py')
fixture.c = t.c
fixture.fixture.r = t.r


class TransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.ComparisonTests.setUpClass.__func__(cls)
        cls.next_temp = tempfile.TemporaryDirectory(prefix='synthetic-next-key-')
        cls.next_home = Path(cls.next_temp.name)
        cls.next_home.chmod(0o700)
        env = dict(os.environ, GNUPGHOME=str(cls.next_home))
        t.r.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                 'Synthetic next key <next@invalid>', 'ed25519', 'sign', '1d'], env=env)
        listing = t.r.run(['gpg', '--batch', '--with-colons', '--list-keys'], env=env).decode()
        cls.next_key = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        cls.next_env = env

    @classmethod
    def tearDownClass(cls):
        subprocess.run(['gpgconf', '--homedir', str(cls.next_home), '--kill', 'all'], capture_output=True)
        cls.next_temp.cleanup()
        fixture.ComparisonTests.tearDownClass.__func__(cls)

    put = fixture.ComparisonTests.put
    ref = fixture.ComparisonTests.ref
    save_spec = fixture.ComparisonTests.save_spec
    bundle = fixture.ComparisonTests.bundle
    snapshot = fixture.ComparisonTests.snapshot

    def setUp(self):
        fixture.ComparisonTests.setUp(self)
        now = datetime.now(timezone.utc).replace(microsecond=0)
        stamp = lambda value: value.isoformat().replace('+00:00', 'Z')
        self.as_of, self.start, self.end = map(stamp, (now, now - timedelta(minutes=1), now + timedelta(hours=1)))
        self.before = self.bundle('before', [('fixture', '1-1', b'before')])
        self.old_key, self.old_env = self.key, self.env
        self.key, self.env = self.next_key, self.next_env
        self.after = self.bundle('after', [('fixture', '2-1', b'after')])
        self.key, self.env = self.old_key, self.old_env
        for side, key, env in (('old', self.old_key, self.old_env), ('new', self.next_key, self.next_env)):
            (self.base / (side + '.asc')).write_bytes(t.r.run(['gpg', '--batch', '--armor', '--export', key], env=env))
        self.output = self.base / 'transition'
        self.args = argparse.Namespace(before=self.before, after=self.after, old_key=self.old_key, new_key=self.next_key,
            old_certificate=self.base / 'old.asc', new_certificate=self.base / 'new.asc', old_gpg_home=self.home,
            new_gpg_home=self.next_home, output=self.output, not_before=self.start, not_after=self.end, as_of=self.as_of)

    def verify(self, **kwargs):
        values = dict(bundle=self.output, before=self.before, after=self.after,
                      old_key=self.old_key, new_key=self.next_key, as_of=self.as_of, compare=True)
        values.update(kwargs)
        return t.verify(**values)

    def resign(self, record):
        (self.output / 'transition.json').write_text(json.dumps(record))
        for side, key, home in (('old', self.old_key, self.home), ('new', self.next_key, self.next_home)):
            (self.output / (side + '.sig')).unlink()
            t.gpg(home, ['--local-user', key, '--digest-algo', 'SHA256', '--detach-sign', '--output',
                        self.output / (side + '.sig'), self.output / 'transition.json'], signing=True)

    def test_dual_signed_create_and_independent_public_only_comparison(self):
        before = self.snapshot()
        created = t.create(self.args)
        value = self.verify()
        self.assertEqual(value, created)
        self.assertEqual(value['comparison']['packages'][0]['change'], 'upgraded')
        self.assertEqual(value['comparison']['signers'], dict(before=self.old_key, after=self.next_key))
        self.assertIsNone(value['comparison']['signer'])
        self.assertFalse(value['stable_eligibility_checked'])
        self.assertFalse(value['client_trust_changed'])
        self.assertEqual(value['current_revocation'], 'UNKNOWN_OFFLINE_EXPORT')
        self.assertFalse(value['freshness_established'])
        self.assertEqual(self.snapshot(), before)
        with t.verifier((self.base / 'new.asc').read_bytes(), self.next_key) as env:
            self.assertEqual(t.gpg(env['GNUPGHOME'], ['--with-colons', '--list-secret-keys']), b'')

    def test_existing_same_signer_comparison_refuses_cross_key_bundle(self):
        # Old native-role source maps pin this exact legacy file. New transition
        # APIs belong only in the versioned sibling, never a retargeted pin.
        self.assertEqual(t.digest((HERE / 'compare_releases.py').read_bytes()),
                         '27086c7b0af74a1226deae7a6a71245882b82608a1fa9d33b68e657979c7d83c')
        self.assertEqual(Path(t.c.__file__).name, 'compare_releases_v2.py')
        with self.assertRaises(t.r.Error):
            t.c.compare_releases(self.before, self.after, self.old_key, self.old_env)

    def test_missing_or_wrong_old_or_new_signature_refused(self):
        t.create(self.args)
        for side in ('old', 'new'):
            path = self.output / (side + '.sig')
            saved = path.read_bytes()
            path.unlink()
            with self.assertRaises(t.r.Error):self.verify()
            path.write_bytes((self.output / ('new.sig' if side == 'old' else 'old.sig')).read_bytes())
            with self.assertRaises(t.r.Error):self.verify()
            path.write_bytes(saved)

    def test_appended_duplicate_signatures_refused(self):
        t.create(self.args)
        path = self.output / 'old.sig'
        path.write_bytes(path.read_bytes() * 2)
        with self.assertRaisesRegex(t.r.Error, 'exactly one'):self.verify()

    def test_certificate_replacement_and_private_material_refused(self):
        t.create(self.args)
        path = self.output / 'new-public.asc'
        saved = path.read_bytes()
        path.write_bytes((self.base / 'old.asc').read_bytes())
        with self.assertRaisesRegex(t.r.Error, 'public certificate changed'):self.verify()
        path.write_bytes(saved)
        secret = t.r.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
                          '--export-secret-keys', self.next_key], env=self.next_env)
        with self.assertRaises((t.r.Error, t.expiry.Error)):
            with t.verifier(secret, self.next_key):self.fail('secret certificate accepted')

    def test_revoked_and_multiple_primary_public_exports_refused(self):
        old = (self.base / 'old.asc').read_bytes()
        new = (self.base / 'new.asc').read_bytes()
        with self.assertRaises(t.expiry.Error):
            with t.verifier(old + new, self.old_key):self.fail('multiple primaries accepted')
        with tempfile.TemporaryDirectory(prefix='synthetic-revoked-public-') as temporary:
            home = Path(temporary)
            certificate = home / 'public.asc';certificate.write_bytes(new)
            t.gpg(home, ['--import', certificate])
            revocation = home / 'revocation.asc'
            automatic = self.next_home / 'openpgp-revocs.d' / (self.next_key + '.rev')
            revocation.write_text(automatic.read_text().replace('\n:-----BEGIN', '\n-----BEGIN'))
            t.gpg(home, ['--import', revocation])
            revoked = t.gpg(home, ['--armor', '--export', self.next_key])
        with self.assertRaisesRegex(t.r.Error, 'no current signing window'):
            with t.verifier(revoked, self.next_key):self.fail('revoked certificate accepted')

    def test_expired_public_export_and_sha1_signature_refused(self):
        with tempfile.TemporaryDirectory(prefix='synthetic-expired-key-') as temporary:
            home = Path(temporary)
            env = dict(os.environ, GNUPGHOME=temporary)
            try:
                t.r.run(['gpg', '--batch', '--faked-system-time', '1600000000!', '--pinentry-mode', 'loopback',
                         '--passphrase', '', '--quick-generate-key', 'Expired TEST <expired@invalid>',
                         'ed25519', 'sign', '1d'], env=env)
                listing = t.r.run(['gpg', '--batch', '--with-colons', '--list-keys'], env=env).decode()
                key = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
                raw = t.r.run(['gpg', '--batch', '--armor', '--export', key], env=env)
                with self.assertRaisesRegex(t.r.Error, 'no current signing window'):
                    with t.verifier(raw, key):self.fail('expired certificate accepted')
            finally:
                subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'all'], capture_output=True)
        t.create(self.args)
        (self.output / 'old.sig').unlink()
        t.gpg(self.home, ['--local-user', self.old_key, '--digest-algo', 'SHA1', '--detach-sign', '--output',
                         self.output / 'old.sig', self.output / 'transition.json'], signing=True)
        with self.assertRaises(t.r.Error):self.verify()

    def test_release_replay_reversal_and_wrong_fingerprint_refused(self):
        t.create(self.args)
        for overrides in (dict(before=self.after, after=self.before), dict(old_key=self.next_key),
                          dict(new_key=self.old_key), dict(after=self.before)):
            with self.assertRaises((t.r.Error, t.expiry.Error)):self.verify(**overrides)

    def test_even_resigned_different_release_hash_or_repository_refused(self):
        t.create(self.args)
        saved = json.loads((self.output / 'transition.json').read_bytes())
        for field, value in (('release_sha256', '0' * 64), ('repo_name', 'different')):
            record = copy.deepcopy(saved)
            record['after'][field] = value
            self.resign(record)
            with self.assertRaises(t.r.Error):self.verify()

    def test_signed_payload_tampering_and_observed_mid_comparison_changes_refused(self):
        t.create(self.args)
        base = self.after / 'base.json'
        raw = base.read_bytes()
        base.write_bytes(raw + b' ')
        with self.assertRaises(t.r.Error):self.verify()
        base.write_bytes(raw)
        original = t.c.compare_releases
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            (self.output / 'new.sig').write_bytes(b'changed')
            return result
        with mock.patch.object(t.c, 'compare_releases', side_effect=changed):
            with self.assertRaisesRegex(t.r.Error, 'transition changed'):self.verify()

    def test_time_window_bounds_and_bad_schema_refused_even_when_resigned(self):
        t.create(self.args)
        for when in (self.end, '2000-01-01T00:00:00Z'):
            with self.assertRaisesRegex(t.r.Error, 'overlap window'):self.verify(as_of=when)
        record = json.loads((self.output / 'transition.json').read_bytes())
        record['not_after'] = '2099-01-01T00:00:00Z'
        self.resign(record)
        with self.assertRaisesRegex(t.r.Error, 'overlap window'):self.verify()
        record['schema_version'] = True
        self.resign(record)
        with self.assertRaisesRegex(t.r.Error, 'schema/purpose'):self.verify()

    def test_alias_hardlink_extra_and_duplicate_json_refused(self):
        t.create(self.args)
        extra = self.output / 'unexpected'
        extra.write_text('extra')
        with self.assertRaises(t.r.Error):self.verify()
        extra.unlink()
        alias = self.base / 'alias'
        alias.symlink_to(self.output, target_is_directory=True)
        with self.assertRaises(t.r.Error):self.verify(bundle=alias)
        os.link(self.output / 'new.sig', self.base / 'linked.sig')
        with self.assertRaises(t.expiry.Error):self.verify()
        (self.base / 'linked.sig').unlink()
        path = self.output / 'transition.json'
        path.write_bytes(path.read_bytes().replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1'))
        with self.assertRaisesRegex(t.r.Error, 'duplicate'):self.verify()

    def test_existing_output_and_signer_failure_preserve_previous_and_cleanup_new(self):
        t.create(self.args)
        saved = {p.name:p.read_bytes() for p in self.output.iterdir()}
        with self.assertRaises(FileExistsError):t.create(self.args)
        self.assertEqual({p.name:p.read_bytes() for p in self.output.iterdir()}, saved)
        shutil.rmtree(self.output)
        original = t.gpg
        def refuse(home, args, **kwargs):
            if kwargs.get('signing'):raise t.r.Error('signer unavailable')
            return original(home, args, **kwargs)
        with mock.patch.object(t, 'gpg', side_effect=refuse):
            with self.assertRaisesRegex(t.r.Error, 'signer unavailable'):t.create(self.args)
        self.assertFalse(self.output.exists())

    def test_cli_compare_and_failure_emit_no_partial_json(self):
        t.create(self.args)
        command = [sys.executable, '-B', str(HERE / 'signing_transition.py'), 'compare', '--bundle', str(self.output),
                   '--before', str(self.before), '--after', str(self.after), '--old-key', self.old_key,
                   '--new-key', self.next_key, '--as-of', self.as_of]
        value = subprocess.run(command, capture_output=True)
        self.assertEqual(value.returncode, 0, value.stderr.decode())
        self.assertEqual(json.loads(value.stdout)['status'], 'VERIFIED_FINITE_PLANNED_KEY_TRANSITION_ONLY')
        (self.output / 'old.sig').write_bytes(b'bad')
        value = subprocess.run(command, capture_output=True)
        self.assertEqual(value.returncode, 1)
        self.assertEqual(value.stdout, b'')


if __name__ == '__main__':
    unittest.main()
