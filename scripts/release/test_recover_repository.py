#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real temporary archives/signatures/operations. Stable gates modeled only in tests."""
import argparse
import contextlib
import fcntl
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


H = module('recovery', 'recover_repository.py')
F = module('recovery_fixture', 'test_release.py')
F.r = H.R


class Recovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        F.ReleaseTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        F.ReleaseTests.tearDownClass.__func__(cls)

    def setUp(self):
        F.ReleaseTests.setUp(self)
        (self.root / '.release.lock').touch()
        self.endpoint = self.base / 'endpoint'
        self.endpoint.mkdir()

    put = F.ReleaseTests.put
    ref = F.ReleaseTests.ref
    save_spec = F.ReleaseTests.save_spec
    stage = F.ReleaseTests.stage

    @contextlib.contextmanager
    def gates(self):
        # Only physical/native gate attestations are modeled. All signatures,
        # promotion binding, payload, metadata and dependency checks remain real.
        with mock.patch.object(H.R, 'gates_check', side_effect=lambda *args: H.R.load(args[-1])):
            yield

    def promote(self, rid, version):
        with tarfile.open(self.archive) as archive:
            files = {entry.name: archive.extractfile(entry).read() for entry in archive.getmembers()}
        previous_version = H.R.pkginfo(self.archive)['version']
        files['.PKGINFO'] = files['.PKGINFO'].replace(('pkgver = ' + previous_version).encode(), ('pkgver = ' + version).encode())
        files['usr/share/fixture/config'] = ('synthetic-version=' + version + '\n').encode()
        self.archive = self.inputs / ('fixture-' + version + '-any.pkg.tar.gz')
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name, raw in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(raw)
                archive.addfile(entry, io.BytesIO(raw))
        self.digest = H.R.sha(self.archive)
        provenance = H.R.load(self.inputs / 'provenance.json')
        provenance.update(artifact_sha256=self.digest)
        provenance['package']['version'] = version
        self.put('provenance.json', provenance)
        self.release_spec.update(release_id=rid, packages=[dict(artifact=self.ref(self.archive.name),
                                                             provenance=self.ref('provenance.json'))])
        self.stage()
        gates = self.inputs / (rid + '-gates.json')
        H.R.write(gates, dict(schema_version=1, synthetic=True, release_id=rid,
                             release_sha256=H.R.sha(self.directory / 'release.json')))
        with self.gates():
            H.R.promote(argparse.Namespace(release_id=rid, gates=str(gates)), self.root, self.key, self.env)

    def export(self):
        with self.gates():
            return H.E.export(self.root, self.endpoint, self.home, self.key, True)

    def pair(self, successor_change=None):
        self.promote('previous', '1.0-1')
        self.first = self.export()
        if successor_change:
            successor_change()
        self.promote('successor', '2.0-1')
        self.second = self.export()

    def proposal(self):
        with self.gates():
            return H.prepare(self.root, self.endpoint, self.home, self.key,
                             os.readlink(self.endpoint / 'current'), 'previous', 'Synthetic endpoint regression drill')

    def sign(self, proposal=None):
        self.plan_path = self.inputs / 'recovery.json'
        H.R.write(self.plan_path, proposal if proposal is not None else self.proposal())
        Path(str(self.plan_path) + '.sig').unlink(missing_ok=True)
        H.R.sign(self.plan_path, self.key, self.env)

    def recover(self, apply=True):
        with self.gates():
            return H.recover(self.root, self.endpoint, self.home, self.key, self.plan_path, apply)

    def resign(self, path):
        path.with_name(path.name + '.sig').unlink()
        H.R.sign(path, self.key, self.env)

    def mismatched_lineage(self, rid):
        directory = self.root / 'stable' / rid
        release = directory / 'release.json'
        manifest = H.R.load(release)
        package, = manifest['packages']
        archive = directory / 'repo' / package['filename']
        archive_pin = H.R.sha(archive)
        self.assertEqual(package['sha256'], archive_pin)
        wrong = '0' * 64
        package['sha256'] = wrong
        provenance = directory / package['provenance']
        data = H.R.load(provenance)
        data['artifact_sha256'] = wrong
        H.R.write(provenance, data)
        spec = directory / 'spec.json'
        selected = H.R.load(spec)
        selected['packages'][0]['artifact']['sha256'] = wrong
        selected['packages'][0]['provenance']['sha256'] = H.R.sha(provenance)
        H.R.write(spec, selected)
        for kind in ('db', 'files'):
            path = directory / 'repo' / f"{selected['repo_name']}.{kind}.tar.gz"
            raw = io.BytesIO(path.read_bytes())
            with tarfile.open(fileobj=raw) as before, tarfile.open(path, 'w:gz') as after:
                for member in before.getmembers():
                    if member.isfile():
                        body = before.extractfile(member).read()
                        if member.name.endswith('/desc'):
                            field = b'%SHA256SUM%\n'
                            self.assertEqual(body.count(field + archive_pin.encode()), 1)
                            body = body.replace(field + archive_pin.encode(), field + wrong.encode())
                        after.addfile(member, io.BytesIO(body))
                    else:
                        after.addfile(member)
            self.resign(path)
        manifest['files'] = H.R.payload_files(directory)
        H.R.write(release, manifest)
        self.resign(release)
        promotion = self.root / 'promotions' / (rid + '.json')
        record = H.R.load(promotion)
        record['release_sha256'] = H.R.sha(release)
        record['gates']['release_sha256'] = record['release_sha256']
        H.R.write(promotion, record)
        self.resign(promotion)
        # The file map still matches the observed archive, but the claimed
        # build digest differs. Refuse it in the shared verifier as well.
        with self.assertRaisesRegex(H.R.Error, 'artifact digest differs from signed file map'):
            H.R.verify_release(directory, self.key, self.env)
        self.assertEqual(H.R.sha(archive), manifest['files']['repo/' + package['filename']])
        return H.R.sha(release), H.R.sha(promotion)

    def snapshot(self, directory):
        return {p.relative_to(directory).as_posix(): ('link', os.readlink(p)) if p.is_symlink()
                else ('file', p.read_bytes()) for p in directory.rglob('*') if p.is_file() or p.is_symlink()}

    def failure_preserves_endpoint(self, action, reason=None):
        before = self.snapshot(self.endpoint)
        error = self.assertRaisesRegex((H.R.Error, OSError), reason) if reason else self.assertRaises((H.R.Error, OSError))
        with error:
            action()
        self.assertEqual(self.snapshot(self.endpoint), before)

    def withdraw(self, rid):
        reason = self.inputs / 'incident.txt'
        reason.write_text('Synthetic incident.\n')
        H.R.withdraw(argparse.Namespace(release_id=rid, reason=str(reason)), self.root, self.key, self.env)

    def test_plan_and_preview_are_read_only(self):
        self.pair()
        before = self.snapshot(self.root), self.snapshot(self.endpoint)
        plan = self.proposal()
        self.assertEqual(plan['target_release_id'], 'previous')
        self.assertEqual((self.snapshot(self.root), self.snapshot(self.endpoint)), before)
        self.sign(plan)
        result = self.recover(False)
        self.assertEqual(result['status'], 'planned-local-endpoint')
        self.assertEqual((self.snapshot(self.root), self.snapshot(self.endpoint)), before)

    def test_signed_target_lineage_mismatch_refuses_plan_preview_and_apply(self):
        self.pair()
        plan = self.proposal()
        plan['target_release_sha256'], plan['target_promotion_sha256'] = self.mismatched_lineage('previous')
        self.sign(plan)
        reason = 'artifact digest differs from signed file map'
        self.failure_preserves_endpoint(self.proposal, reason)
        self.failure_preserves_endpoint(lambda: self.recover(False), reason)
        self.failure_preserves_endpoint(self.recover, reason)

    def test_signed_current_lineage_mismatch_refuses_export(self):
        self.pair()
        self.mismatched_lineage('successor')
        self.failure_preserves_endpoint(self.export, 'artifact digest differs from signed file map')

    def test_recovery_retains_signed_authorization_and_ordinary_export_is_explicitly_independent(self):
        self.pair()
        self.sign()
        source = self.snapshot(self.root)
        result = self.recover()
        self.assertEqual(result['selected_release'], 'previous')
        self.assertEqual(self.snapshot(self.root), source)
        self.assertFalse(result['source_selection_changed'])
        self.assertFalse(result['installed_system_recovered'])
        generation = self.endpoint / result['selection']
        self.assertEqual((generation / 'recovery-plan.json').read_bytes(), self.plan_path.read_bytes())
        H.R.verify_signature(generation / 'recovery-plan.json', self.key, self.env)
        self.assertTrue((self.endpoint / self.second['selection']).is_dir())
        self.assertTrue((self.endpoint / self.first['selection']).is_dir())
        self.assertEqual(self.export()['selected_release'], 'successor')
        self.assertTrue(generation.is_dir())

    def test_withdrawn_successor_recovers_with_latest_withdrawal_retained(self):
        self.pair()
        self.withdraw('successor')
        self.sign()
        source = self.snapshot(self.root)
        result = self.recover()
        self.assertEqual(result['selected_release'], 'previous')
        for suffix in ('', '.sig'):
            name = 'withdrawals/successor.json' + suffix
            self.assertEqual((self.endpoint / 'current' / name).read_bytes(), (self.root / name).read_bytes())
        self.assertEqual(self.snapshot(self.root), source)

    def test_real_stable_gate_is_never_bypassed_by_cli_or_api(self):
        self.pair()
        self.sign()
        self.failure_preserves_endpoint(lambda: H.recover(self.root, self.endpoint, self.home, self.key,
                                                          self.plan_path, True), 'synthetic fixtures cannot enter stable')
        command = [sys.executable, '-I', '-B', str(HERE / 'recover_repository.py'), '--root', self.root,
                   '--endpoint', self.endpoint, '--gpg-home', self.home, '--key', self.key,
                   'recover', '--plan', self.plan_path, '--apply']
        before = self.snapshot(self.endpoint)
        result = subprocess.run(command, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b'synthetic fixtures cannot enter stable', result.stderr)
        self.assertEqual(self.snapshot(self.endpoint), before)

    def test_stale_expected_selection_and_replay_are_refused(self):
        self.pair()
        with self.gates():
            self.failure_preserves_endpoint(lambda: H.prepare(self.root, self.endpoint, self.home, self.key,
                                             self.first['selection'], 'previous', 'stale'), 'expected endpoint selection differs')
        self.sign()
        self.recover()
        self.failure_preserves_endpoint(self.recover, 'expected endpoint selection differs')

    def test_late_withdrawal_requires_new_signed_plan(self):
        self.pair()
        self.sign()
        self.withdraw('successor')
        self.failure_preserves_endpoint(self.recover, 'signed recovery plan no longer matches')
        self.sign()
        self.assertEqual(self.recover()['selected_release'], 'previous')

    def test_target_withdrawal_and_partial_target_promotion_are_refused(self):
        self.pair()
        self.sign()
        signature = self.root / 'promotions/previous.json.sig'
        original = signature.read_bytes()
        signature.unlink()
        self.failure_preserves_endpoint(self.recover)
        signature.write_bytes(original)
        self.withdraw('previous')
        self.failure_preserves_endpoint(self.recover, 'selected release is withdrawn')

    def test_disappeared_advertised_withdrawal_is_refused(self):
        self.pair()
        self.release_spec['release_id'] = 'abandoned'
        self.stage()
        self.withdraw('abandoned')
        self.export()
        for suffix in ('', '.sig'):
            (self.root / ('withdrawals/abandoned.json' + suffix)).unlink()
        with self.gates():
            self.failure_preserves_endpoint(self.proposal, 'previously advertised withdrawal disappeared')

    def test_wrong_signer_tampered_plan_and_signed_wrong_digest_are_refused(self):
        self.pair()
        self.sign()
        self.failure_preserves_endpoint(lambda: H.recover(self.root, self.endpoint, self.home, 'F' * 40,
                                                         self.plan_path, True))
        self.plan_path.write_bytes(self.plan_path.read_bytes() + b'changed')
        self.failure_preserves_endpoint(self.recover)
        plan = self.proposal()
        plan['target_release_sha256'] = '0' * 64
        self.sign(plan)
        self.failure_preserves_endpoint(self.recover, 'signed recovery plan no longer matches')

    def test_corrupt_target_and_current_are_refused_without_endpoint_changes(self):
        self.pair()
        self.sign()
        target = self.root / 'stable/previous/repo/fixture-1.0-1-any.pkg.tar.gz'
        original = target.read_bytes()
        target.write_bytes(original + b'corrupt')
        self.failure_preserves_endpoint(self.recover)
        target.write_bytes(original)
        current = self.endpoint / 'current/release/release.json'
        current.chmod(0o644)
        current.write_bytes(current.read_bytes() + b'corrupt')
        self.failure_preserves_endpoint(self.recover)

    def test_compatible_base_and_policy_are_required(self):
        def base_change():
            base = H.R.load(self.inputs / 'base.json')
            base['packages'][0]['version'] = 'changed-platform'
            self.put('base.json', base)
            self.release_spec['base'].update(self.ref('base.json'))
        self.pair(base_change)
        self.failure_preserves_endpoint(self.proposal, 'identical complete base inventory')

    def test_supported_model_policy_cannot_change_during_recovery(self):
        self.pair(lambda: self.release_spec['policy'].update(supported_models=['m2-air-15']))
        self.failure_preserves_endpoint(self.proposal, 'package/platform policy differs')

    def test_promotion_order_is_timezone_aware_and_required(self):
        self.pair()
        promotion = self.root / 'promotions/previous.json'
        saved = H.R.load(promotion)
        saved['promoted_utc'] = '9999-01-01T00:00:00+00:00'
        H.R.write(promotion, saved)
        Path(str(promotion) + '.sig').unlink()
        H.R.sign(promotion, self.key, self.env)
        self.failure_preserves_endpoint(self.proposal, 'earlier authenticated promotion')

    def test_copy_interruption_preserves_current_and_cleans_partial_generation(self):
        self.pair()
        self.sign()
        original, calls = H.E.copy_file, 0
        def interrupted(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('injected interrupted copy')
            return original(*args)
        with mock.patch.object(H.E, 'copy_file', side_effect=interrupted):
            self.failure_preserves_endpoint(self.recover, 'injected interrupted copy')
        self.assertFalse(any(path.name.startswith('.') for path in self.endpoint.iterdir()))

    def test_commit_failure_retains_verified_inactive_generation_and_retry(self):
        self.pair()
        self.sign()
        with mock.patch.object(H.E.os, 'replace', side_effect=OSError('injected commit failure')):
            with self.assertRaisesRegex(OSError, 'injected commit failure'):
                self.recover()
        self.assertEqual(os.readlink(self.endpoint / 'current'), self.second['selection'])
        self.assertEqual(len(list((self.endpoint / 'generations').iterdir())), 3)
        self.assertEqual(self.recover()['selected_release'], 'previous')

    def test_post_commit_sync_failure_reports_uncertainty(self):
        self.pair()
        self.sign()
        original = H.E.sync_directory
        def fail(path):
            if path == self.endpoint:
                raise OSError('injected endpoint fsync failure')
            original(path)
        with mock.patch.object(H.E, 'sync_directory', side_effect=fail):
            result = self.recover()
        self.assertTrue(result['durability_uncertain'])
        self.assertEqual(H.R.load(self.endpoint / 'current/release/release.json')['release_id'], 'previous')

    def test_release_and_endpoint_writer_locks_are_shared_with_export(self):
        self.pair()
        self.sign()
        with (self.root / '.release.lock').open('rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.failure_preserves_endpoint(self.recover)
        descriptor = os.open(self.endpoint, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.failure_preserves_endpoint(self.recover)
        finally:
            os.close(descriptor)

    def test_plan_ownership_aliases_and_generation_bounds_are_required(self):
        self.pair()
        self.sign()
        self.plan_path.chmod(0o666)
        self.failure_preserves_endpoint(self.recover)
        self.plan_path.chmod(0o644)
        alias = self.inputs / 'alias'
        alias.symlink_to(self.plan_path)
        self.failure_preserves_endpoint(lambda: H.recover(self.root, self.endpoint, self.home, self.key, alias, True))
        with mock.patch.object(H.E, 'MAX_FILES', 1):
            self.failure_preserves_endpoint(self.recover)

    def test_authorization_change_during_copy_stops_selection(self):
        self.pair()
        self.sign()
        original, changed = H.E.copy_file, False
        def drift(*args):
            nonlocal changed
            original(*args)
            if not changed:
                changed = True
                document = H.R.load(self.plan_path)
                document['reason'] += ' concurrently changed'
                self.sign(document)
        with mock.patch.object(H.E, 'copy_file', side_effect=drift):
            self.failure_preserves_endpoint(self.recover)

    def test_target_lineage_changes_after_staging_before_retention(self):
        self.pair()
        self.sign()
        original = H.E.generation_check

        def drift(directory, plan):
            original(directory, plan)
            if directory.parent.name.startswith('.export-'):
                self.mismatched_lineage('previous')

        with mock.patch.object(H.E, 'generation_check', side_effect=drift):
            self.failure_preserves_endpoint(self.recover, 'artifact digest differs from signed file map')
        self.assertFalse(any(path.name.startswith('.') for path in self.endpoint.iterdir()))

    def test_target_gate_is_rechecked_independently_of_current_gate(self):
        self.pair()
        self.sign()
        def validate(directory, manifest, release_spec, gates):
            if manifest['release_id'] == 'previous':
                raise H.R.Error('injected target acceptance refusal')
            return H.R.load(gates)
        with mock.patch.object(H.R, 'gates_check', side_effect=validate):
            self.failure_preserves_endpoint(lambda: H.recover(self.root, self.endpoint, self.home, self.key,
                                                             self.plan_path, True), 'injected target acceptance refusal')

    def test_target_manifest_and_promotion_rereads_remain_bound_to_verified_maps(self):
        self.pair()
        original = H.describe_retained
        for relative in ('stable/previous/release.json', 'promotions/previous.json'):
            path = self.root / relative
            raw = path.read_bytes()
            def drift(*args, **kwargs):
                result = original(*args, **kwargs)
                path.write_bytes(raw + b'\n')
                return result
            try:
                with self.subTest(relative=relative), mock.patch.object(H, 'describe_retained', side_effect=drift):
                    self.failure_preserves_endpoint(self.proposal, 'authenticated metadata changed')
            finally:
                path.write_bytes(raw)

    def test_reused_inactive_generation_rechecks_target_withdrawal_before_selection(self):
        self.pair()
        self.sign()
        with mock.patch.object(H.E.os, 'replace', side_effect=OSError('injected commit failure')):
            with self.assertRaises(OSError):
                self.recover()
        original, withdrawn = H.E.generation_check, False
        def drift(directory, plan):
            nonlocal withdrawn
            original(directory, plan)
            if directory.name not in (self.first['generation'], self.second['generation']) and not withdrawn:
                withdrawn = True
                self.withdraw('previous')
        with mock.patch.object(H.E, 'generation_check', side_effect=drift):
            self.failure_preserves_endpoint(self.recover, 'selected release is withdrawn')
        self.assertTrue(withdrawn)

    def test_earlier_promotion_cannot_hide_newer_target_package(self):
        self.promote('previous', '2.0-1')
        self.first = self.export()
        # Deliberate fixture-only bypass of normal source selection ordering;
        # recovery must still reject this authenticated mismatch.
        (self.root / 'stable/current').unlink()
        self.promote('successor', '1.0-1')
        self.second = self.export()
        self.failure_preserves_endpoint(self.proposal, 'predecessor contains a newer package')


if __name__ == '__main__':
    unittest.main(verbosity=2)
