#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Data-only SYNTHETIC acceptance authorities; no native/crypto acceptance.

Fixture.authority is the complete readable schema example. Its externally
trusted crypto assertions are deliberately simulated, not GPG verification.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import gate as g

REPO = Path(__file__).resolve().parents[3]


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


class Fixture:
    def __init__(self, root):
        self.root, self.data = root, {}
        self.commit, self.recipe_commit = 'a' * 40, 'b' * 40
        self.nonce, self.image = 'c' * 32, 'sha256:' + 'd' * 64
        self.refs = {name: 'control/' + name + '.json' for name in g.REFS}
        self.refs.update(repository='raw/result.json', public_manifest='public/public-artifact-manifest.json',
                         packages='control/packages.lock', reset='raw/revoked-A-sync-cache-reset.json')
        self.put(self.refs['packages'], (REPO / 'scripts/port/refreshed-desktop/proposed-builder-inventory.lock').read_bytes())
        self.base = g.inventory(self.data[self.refs['packages']])
        self.put(self.refs['current_inputs'], (REPO / 'scripts/ci/inputs.lock.json').read_bytes())
        self.rows, self.payloads = {}, {}
        for phase, version in (('baseline', '0.1.0-1'), ('upgrade', '0.1.1-1')):
            self.rows[phase] = []
            self.payloads[phase] = {}
            for name in sorted(g.ORIGINALS):
                filename = name + '-' + version + '-any.pkg.tar.xz'
                data = ('SYNTHETIC archive ' + phase + name).encode()
                payload = 'usr/share/' + name + '/fixture.txt'
                pin = g.digest(('SYNTHETIC payload ' + phase + name).encode())
                self.payloads[phase][payload] = pin
                self.rows[phase].append({'name': name, 'version': version, 'archive': phase + '/' + filename,
                                        'sha256': g.digest(data), 'payload_sha256': {payload: pin}})
                self.put('public/TEST-repositories/' + ('baseline-A' if phase == 'baseline' else 'updated-B') + '/' + filename, data)
        public = {}
        aliases = {'active': {'target': 'updated-B', 'kind': 'directory'}}
        for label in g.LABELS:
            phase = 'baseline' if label == 'baseline-A' else 'upgrade'
            folder = 'public/TEST-repositories/' + label + '/'
            for row in self.rows[phase]:
                filename = Path(row['archive']).name
                data = ('SYNTHETIC archive ' + phase + row['name']).encode()
                self.put(folder + filename, data)
                self.put(folder + filename + '.sig', b'SYNTHETIC external signature ' + label.encode() + filename.encode())
            filename = g.PROBE + ('-1-1-any.pkg.tar.xz' if phase == 'baseline' else '-2-1-any.pkg.tar.xz')
            self.put(folder + filename, b'SYNTHETIC probe ' + label.encode())
            if label != 'missing-package-signature-B': self.put(folder + filename + '.sig', b'SYNTHETIC probe signature ' + label.encode())
            for kind in ('db', 'files'):
                data = b'SYNTHETIC database ' + label.encode() + kind.encode()
                self.put(folder + 'integration.' + kind + '.tar.gz', data)
                if not (label == 'missing-database-signature-B' and kind == 'db'):
                    self.put(folder + 'integration.' + kind + '.tar.gz.sig', b'SYNTHETIC DB signature ' + label.encode() + kind.encode())
                for suffix in ('', '.sig'):
                    target = 'integration.' + kind + '.tar.gz' + suffix
                    if folder + target not in self.data: continue
                    alias = 'integration.' + kind + suffix
                    self.put(folder + alias, self.data[folder + target])
                    aliases[label + '/' + alias] = {'target': label + '/' + target, 'kind': 'file',
                                                   'regular_copy_sha256': g.digest(self.data[folder + target])}
        for name in ('TEST-signer-A-public.asc', 'TEST-signer-B-public.asc', 'TEST-verifier-public.asc', 'TEST-signer-A-revoked-public.asc'):
            self.put('public/' + name, b'SYNTHETIC externally accepted public certificate ' + name.encode())
        self.put('public/TEST-pacman.conf', g.STRICT_CONFIG)
        self.put('public/TEST-repository-aliases.json', encode(aliases))
        self.put('public/TEST-repository-aliases.json.sig', b'SYNTHETIC external alias signature')
        self.cases = [{'name': name, 'result': 'PASS', 'expected_signature_rejection': negative} for name, negative in g.CASES]
        self.cases[8]['rejection_contract'] = {'kind': 'missing-required-local-database-signature',
                                              'missing': ['integration.db.sig', 'integration.db.tar.gz.sig']}
        public = {name.removeprefix('public/'): {'sha256': g.digest(data), 'bytes': len(data)}
                  for name, data in self.data.items() if name.startswith('public/')}
        self.put(self.refs['public_manifest'], encode({'development_only': True, 'selected_for_release': False,
            'production_credentials_used': False, 'source_commit': self.commit,
            'purpose': 'TEST-ONLY-offline-repository-case-verification', 'cases': self.cases,
            'expected_negative_cases_retained': True, 'files': public}))
        fingerprints = {'signer-A': 'A' * 40, 'signer-B': 'B' * 40, 'verifier': 'C' * 40}
        identities = {role: {'fingerprint': fp, 'public_sha256': public['TEST-' + role + '-public.asc']['sha256']}
                      for role, fp in fingerprints.items()}
        expected = {'nonce': self.nonce, 'image_id': self.image, 'daemon_arch': 'aarch64',
                    'script_sha256': 'e' * 64, 'upgrade_kind': 'synthetic-changed-package-fixtures'}
        self.put(self.refs['repository_contract'], encode({**expected, 'source_commit': self.commit,
             'execution': 'native-aarch64-disposable-docker', 'allow_system_mutation': True, **self.rows}))
        commands = []
        def add_command(label, data, *, expected=0, exit_code=0, positive=False, stderr=False):
            log = f'{len(commands):03d}-{label}.txt'
            self.put('raw/' + log, data)
            row = {'label': label, 'log': log, 'sha256': g.digest(data), 'expected': expected,
                   'exit_code': exit_code, 'argv': ['SYNTHETIC source fixture']}
            if positive: row['positive_diagnostics'] = 'PASS'
            if stderr:
                row['stderr_log'], row['stderr_sha256'] = log[:-4] + '-stderr.txt', g.digest(b'')
                self.put('raw/' + row['stderr_log'], b'')
            commands.append(row)
            return row
        state = None
        previous = {'inventory': self.inventory(None), 'files': {path: {'type': 'missing'} for path in self.owned()}}
        for index, (name, negative) in enumerate(g.CASES):
            if index == 9:
                for label in g.LEGACY_LOGS:
                    if label != 'gpg-revoked-A-status': add_command(label, b'SYNTHETIC captured legacy status\n')
                proof = add_command('gpg-revoked-A-status', ('[GNUPG:] REVKEYSIG ' + 'A' * 16 + ' TEST\n[GNUPG:] VALIDSIG ' + 'A' * 40 + ' TEST\n').encode(), expected=None)
            if index == 10:
                for phase in ('before', 'after'):
                    add_command('inventory-revoked-A-sync-cache-reset-' + phase, self.inventory('baseline').encode(), positive=True, stderr=True)
            before = copy.deepcopy(previous)
            if not negative: state = 'baseline' if name in ('trusted-baseline-full-install', 'full-rollback-to-retained-A') else 'upgrade'
            hashes = {} if state is None else self.payloads[state] | {self.probe_path(): g.digest(f'SYNTHETIC TEST fixture version {1 if state == "baseline" else 2}\n'.encode())}
            after = {'inventory': self.inventory(state), 'files': {path: {'type': 'regular', 'sha256': hashes[path], 'uid': 0, 'gid': 0, 'mode': 0o644}
                     if path in hashes else {'type': 'missing'} for path in self.owned()}}
            self.put('raw/' + name + '-before-snapshot.json', encode(before))
            self.put('raw/' + name + '-after-snapshot.json', encode(after))
            data = b'SYNTHETIC signature/trust rejection\n' if negative else b'SYNTHETIC transaction success\n'
            if index == 8: data = self.missing_database_diagnostic()
            if index == 9: data = b'error: signature from "TEST ONLY disposable repository signer-A <signer-A@test.invalid>" is invalid\n'
            row = add_command(name, data, exit_code=1 if negative else 0, expected='nonzero' if negative else 0, positive=not negative)
            if index == 8: row['signature_rejection_kind'] = 'missing-required-local-database-signature'
            previous = after
        add_command('dependency-consistency', b'No database errors have been found!\n', positive=True, stderr=True)
        rejected = next(row for row in commands if row['label'] == 'revoked-A-repository-rejected')
        reset = {'status': 'PASS', 'absence': 'PASS', 'installed_state_unchanged': True,
                 'scope': 'two private copied-root sync files after revoked-A rejection',
                 'prior_rejection_log_sha256': rejected['sha256'],
                 'removed': {name: public['TEST-repositories/baseline-A/' + target]['sha256'] for name, target in
                 (('integration.db', 'integration.db.tar.gz'), ('integration.db.sig', 'integration.db.tar.gz.sig'))}}
        reset['revocation_status_log_sha256'] = proof['sha256']
        snapshot = self.data['raw/revoked-A-repository-rejected-after-snapshot.json']
        for suffix in ('before', 'after'): self.put('raw/revoked-A-sync-cache-reset-' + suffix + '-snapshot.json', snapshot)
        self.put(self.refs['reset'], encode(reset))
        self.put('raw/TEST-repository-aliases.json', self.data['public/TEST-repository-aliases.json'])
        self.repository = {'status': 'PASS', 'purpose': 'disposable-generic-repository-test', 'source_commit': self.commit,
            'schema_version': 1, 'original_inputs': {phase: {r['name']: {key: r[key] for key in ('sha256', 'version')} for r in rows} for phase, rows in self.rows.items()},
            'test_private_state_removed': True, 'published': False, 'hardware_validation': 'NOT RUN', 'stable_promotion': 'NOT RUN',
            'cases': self.cases, 'base_versions': self.base, 'input_contract': expected, 'public_TEST_identities': identities,
            'guard': {'privileges': {'CapEff': 0x400cb, 'CapPrm': 0x400cb, 'CapBnd': 0x400cb,
                      'CapInh': 0, 'CapAmb': 0, 'NoNewPrivs': 1}, 'interfaces': ['lo'], 'docker_marker': True},
            'environment': {'architecture': 'aarch64', 'execution': 'native-disposable-container', 'uid': 0},
            'commands': commands, 'evidence_sha256': {name.removeprefix('raw/'): g.digest(data) for name, data in self.data.items() if name.startswith('raw/')},
            'sync_cache_reset': {'receipt': Path(self.refs['reset']).name, 'sha256': g.digest(self.data[self.refs['reset']])},
            'final_sync_cache': {name: public['TEST-repositories/updated-B/' + target]['sha256'] for name, target in
                (('integration.db', 'integration.db.tar.gz'), ('integration.db.sig', 'integration.db.tar.gz.sig'))}}
        self.put(self.refs['repository'], encode(self.repository))
        self.project()
        self.put(self.refs['aggregate'], encode({'schema_version': 1, 'purpose': 'frozen-development-only-native-integration',
             'status': 'PASS', 'source_commit': self.commit, 'base_image': self.image, 'development_only': True,
             'cancelled': False, 'hardware_validation': 'NOT RUN', 'production_trust': 'NOT RUN',
             'owned_image_cleanup': {'status': 'PASS', 'absence_verified': True, 'cleanup_uncertain': False},
             'selected_for_release': False, 'stages': {name: {'status': 'PASS'} for name in
                 ('fixtures', 'signer', 'lifecycle', 'repository', 'onboarding', 'desktop', 'source-suites')}}))
        self.put(self.refs['runner'], encode({'commit': self.commit, 'run_id': '123', 'kernel': {'machine': 'aarch64'}, 'docker_server_arch': 'aarch64'}))
        self.put(self.refs['bootstrap'], encode({'status': 'image-provisioned', 'image_id': self.image,
             'inputs_sha256': g.INPUTS_SHA, 'packages_lock_sha256': g.PACKAGES_SHA}))
        self.put(self.refs['cleanup'], encode({'status': 'PASS', 'absence_verified': True, 'container_id': 'f' * 64,
             'name_absence_verified': True, 'id_absence_verified': True, 'container': 'cachy-asahi-repository-' + self.nonce}))
        self.put(self.refs['recipes_lock'], encode({'SYNTHETIC': 'source pins'}))
        self.put(self.refs['fixture_manifest'], encode({'source_commit': self.recipe_commit, 'development_only': True,
             'selected_for_release': False, 'frozen_lock_sha256': g.digest(self.data[self.refs['recipes_lock']]),
             'packages': {name: {'base_version': '0.1.0-1', 'upgrade_version': '0.1.1-1'} for name in g.ORIGINALS}}))
        self.put(self.refs['integration_lock'], encode({'recipe_source_commit': self.recipe_commit,
             'recipes_sha256': g.digest(self.data[self.refs['recipes_lock']]),
             'source_files': {'scripts/integration/repository.py': {'sha256': 'e' * 64}},
             'generated_fixture_files': {'fixture-manifest.json': {'sha256': g.digest(self.data[self.refs['fixture_manifest']])}}}))
        self.put(self.refs['public_acceptance'], encode({'status': 'PASS', 'purpose': 'accepted-repository-public-artifacts',
             'source_commit': self.commit, 'run_id': '123', 'nonce': self.nonce, 'manifest_sha256': g.digest(self.data[self.refs['public_manifest']])}))
        signers = {role: {'fingerprint': fp, 'certificate': 'public/TEST-' + role + '-public.asc'} for role, fp in fingerprints.items()}
        pairs = []
        for label, role in (('baseline-A', 'signer-A'), ('updated-B', 'signer-B')):
            for name in public:
                if name.startswith('TEST-repositories/' + label + '/') and (name.endswith('.pkg.tar.xz') or name.endswith(('.db.tar.gz', '.files.tar.gz'))):
                    pairs.append({'path': 'public/' + name, 'signature': 'public/' + name + '.sig', 'signer': role, 'status': 'VALID'})
        pairs.append({'path': 'public/TEST-repository-aliases.json', 'signature': 'public/TEST-repository-aliases.json.sig', 'signer': 'signer-B', 'status': 'VALID'})
        self.authority = {'schema_version': 1, 'purpose': 'accepted-repository-client-inputs', 'status': 'PASS',
             'development_only': True, 'selected_for_release': False, 'run_id': '123', 'source_commit': self.commit,
             'recipe_source_commit': self.recipe_commit, 'nonce': self.nonce, 'image_id': self.image,
             'repository_source_sha256': 'e' * 64, 'archive_role': 'updated', 'refs': self.refs,
             'archives': [{'name': row['name'], 'path': 'public/TEST-repositories/updated-B/' + Path(row['archive']).name,
                           'version': row['version'], 'sha256': row['sha256'], 'bytes': len(self.data['public/TEST-repositories/updated-B/' + Path(row['archive']).name])}
                          for row in self.rows['upgrade']],
             'crypto': {'purpose': 'external-repository-cryptographic-acceptance', 'status': 'PASS',
                   'boundary': 'external-attestation-only', 'source_commit': self.commit, 'run_id': '123', 'nonce': self.nonce,
                   'image_id': self.image, 'artifact_map_sha256': g.digest(g.canonical(public)), 'signers': signers,
                   'cases': [{'name': n, 'status': 'PASS', 'expected_signature_rejection': negative} for n, negative in g.CASES],
                   'signed_objects': sorted(pairs, key=lambda r: r['path']), 'original_local_certification': 'native-receipts-only',
                   'revocation': {'signer': 'signer-A', 'fingerprint': fingerprints['signer-A'], 'status': 'REVOKED', 'certificate': 'public/TEST-signer-A-revoked-public.asc'}}}
        self.refresh()

    @staticmethod
    def probe_path(): return 'usr/share/cachy-asahi-repository-TEST/fixture.txt'
    @staticmethod
    def missing_database_diagnostic():
        return (b':: Synchronizing package databases...\n integration downloading...\n'
                b"error: failed retrieving file 'integration.db.sig' from disk: Could not open file /scratch/repos/active/integration.db.sig\n"
                b'error: failed to synchronize all databases (download library error)\n')
    def owned(self): return set(self.payloads['baseline']) | set(self.payloads['upgrade']) | {self.probe_path()}
    def inventory(self, state):
        rows = dict(self.base)
        if state:
            rows.update({r['name']: r['version'] for r in self.rows[state]})
            rows[g.PROBE] = '1-1' if state == 'baseline' else '2-1'
        return ''.join(f'{name} {rows[name]}\n' for name in sorted(rows))
    def put(self, name, data):
        self.data[name] = data
        path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
    def change(self, role, change):
        value = json.loads(self.data[self.refs[role]]); change(value); self.put(self.refs[role], encode(value)); self.refresh()
    def bind_native(self):
        self.change('repository', lambda r: r.update(evidence_sha256={name.removeprefix('raw/'): g.digest(data)
                    for name, data in self.data.items() if name.startswith('raw/') and name != self.refs['repository']}))
    def project(self):
        raw = json.loads(self.data[self.refs['repository']]); projected = copy.deepcopy(raw)
        projected['base_versions'] = [{'name': name, 'version': self.base[name]} for name in sorted(self.base)]
        captures, operations = {}, {}
        for row in raw['commands']:
            if row['label'] in g.LEGACY_LOGS:
                alias = row['log'].split('-', 1)[0] + '-' + g.LEGACY_LOGS[row['label']] + '.txt'
                captures[row['log']] = (alias, self.data['raw/' + row['log']])
            for phase in ('before', 'after'):
                if row['label'] == 'inventory-revoked-A-sync-cache-reset-' + phase:
                    prefix = row['log'].split('-', 1)[0] + '-inventory-revoked-A-sync-reset-' + phase
                    operations[row['log']] = (prefix + '.txt', self.data['raw/' + row['log']])
                    operations[row['stderr_log']] = (prefix + '-stderr.txt', self.data['raw/' + row['stderr_log']])
            if row['label'] == 'dependency-consistency':
                prefix = row['log'].split('-', 1)[0] + '-installed-relation-check'
                operations[row['log']] = (prefix + '.txt', self.data['raw/' + row['log']])
                operations[row['stderr_log']] = (prefix + '-stderr.txt', self.data['raw/' + row['stderr_log']])
        for phase in ('before', 'after'):
            name = 'revoked-A-sync-cache-reset-' + phase + '-snapshot.json'
            operations[name] = ('revoked-A-sync-reset-' + phase + '-snapshot.json', self.data['raw/' + name])
        operations['revoked-A-sync-cache-reset.json'] = ('revoked-A-sync-reset.json', self.data[self.refs['reset']])
        index = {'schema_version': 1, 'purpose': 'validated-repository-operation-aliases', 'generic_content_guard': 'UNCHANGED',
            'original_bytes_preserved': True, 'files': {name: {'public_path': alias, 'original_sha256': g.digest(data),
            'public_sha256': g.digest(data), 'bytes': len(data)} for name, (alias, data) in operations.items()}}
        captures.update(operations)
        folder = str(Path(self.refs['projected_repository']).parent) + '/'
        self.put(folder + 'repository-operation-aliases.json', encode(index))
        for alias, data in captures.values(): self.put(folder + alias, data)
        for row in projected['commands']:
            if row['log'] in captures: row['public_log'] = captures[row['log']][0]
            if row.get('stderr_log') in operations: row['public_stderr_log'] = captures[row['stderr_log']][0]
            row['argv_sha256'] = g.digest(json.dumps(row.pop('argv'), sort_keys=True).encode())
        projected['sync_cache_reset']['public_receipt'] = 'revoked-A-sync-reset.json'
        projected['public_operation_index'] = 'repository-operation-aliases.json'
        self.put(self.refs['projected_repository'], encode(projected))
        self.put(self.refs['projection'], encode({'purpose': 'validated-repository-inventory-projection',
            'status_preserved': 'PASS', 'package_count': 341, 'generic_content_guard': 'UNCHANGED',
            'original_sha256': g.digest(self.data[self.refs['repository']]), 'original_bytes': len(self.data[self.refs['repository']]),
            'projected_sha256': g.digest(self.data[self.refs['projected_repository']]), 'projected_bytes': len(self.data[self.refs['projected_repository']])}))
    def refresh(self):
        if not hasattr(self, 'authority'): return
        self.authority['files'] = {name: {'sha256': g.digest(data), 'bytes': len(data)} for name, data in self.data.items()}
        for role, key in (('bootstrap', 'bootstrap_sha256'), ('packages', 'packages_sha256'), ('current_inputs', 'current_inputs_sha256'),
                          ('fixture_manifest', 'fixture_manifest_sha256'), ('integration_lock', 'integration_lock_sha256'), ('recipes_lock', 'recipes_lock_sha256')):
            self.authority[key] = g.digest(self.data[self.refs[role]])
    def accept(self):
        raw = encode(self.authority)
        return g.accept(self.root, raw, g.digest(raw))


class GateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='repository-gate-synthetic-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fixture = Fixture(self.root)

    def test_complete_external_attestation_is_explicit_not_crypto_execution(self):
        value = self.fixture.accept()
        self.assertEqual(value['crypto_verification'], 'external-attestation-only')
        self.assertEqual(value['base_versions'], [{'name': name, 'version': self.fixture.base[name]} for name in sorted(self.fixture.base)])
        self.assertEqual({r['name'] for r in value['archives']}, g.ORIGINALS)
        self.assertEqual(len(value['lineage']), 15)
        self.assertTrue(value['consumers_recheck_required'])

    def test_authority_must_be_externally_pinned(self):
        with self.assertRaises(g.Refused): g.accept(self.root, encode(self.fixture.authority), '0' * 64)

    def test_aggregate_fail_rejects_before_archive_reads(self):
        self.fixture.change('aggregate', lambda r: r.update(status='FAIL'))
        original = g.read
        def monitored(path, *args):
            self.assertNotIn('.pkg.tar.', str(path)); return original(path, *args)
        with mock.patch.object(g, 'read', side_effect=monitored), self.assertRaisesRegex(g.Refused, 'aggregate PASS'):
            self.fixture.accept()

    def test_actual_initial_purpose_and_all_stages_required(self):
        self.fixture.change('aggregate', lambda r: r.update(purpose='broader-producer-summary'))
        with self.assertRaises(g.Refused): self.fixture.accept()

    def test_cancelled_uncertain_or_unobserved_cleanup_aggregate_refused(self):
        for change in (lambda r: r.update(cancelled=True), lambda r: r.update(cancelled=0),
                       lambda r: r['owned_image_cleanup'].update(cleanup_uncertain=True), lambda r: r.update(production_trust='PASS'),
                       lambda r: r['owned_image_cleanup'].update(absence_verified=False),
                       lambda r: r['stages']['repository'].update(status='FAIL')):
            saved = self.fixture.data[self.fixture.refs['aggregate']]
            self.fixture.change('aggregate', change)
            with self.subTest(change=change), self.assertRaisesRegex(g.Refused, 'aggregate PASS'): self.fixture.accept()
            self.fixture.put(self.fixture.refs['aggregate'], saved); self.fixture.refresh()

    def test_native_guard_exact_caps_privileges_and_scalar_types(self):
        for change in (lambda r: r['guard']['privileges'].update(CapEff=0x400cb | (1 << 21)),
                       lambda r: r['guard']['privileges'].update(CapBnd=0xcb),
                       lambda r: r['guard']['privileges'].update(CapInh=False),
                       lambda r: r['guard']['privileges'].update(NoNewPrivs=True),
                       lambda r: r['environment'].update(uid=False),
                       lambda r: r['guard'].update(interfaces=['lo', 'eth0']),
                       lambda r: r['environment'].update(architecture='x86_64')):
            saved = self.fixture.data[self.fixture.refs['repository']]
            self.fixture.change('repository', change)
            with self.subTest(change=change), self.assertRaisesRegex(g.Refused, 'native repository guard'): self.fixture.accept()
            self.fixture.put(self.fixture.refs['repository'], saved); self.fixture.refresh()

    def test_exact_eleven_case_set(self):
        for change in (lambda r: r['cases'].pop(), lambda r: r['cases'].reverse(),
                       lambda r: r['cases'][0].update(expected_signature_rejection=1),
                       lambda r: r['cases'][5].update(result='FAIL')):
            original = self.fixture.data[self.fixture.refs['repository']]
            self.fixture.change('repository', change)
            with self.assertRaises(g.Refused): self.fixture.accept()
            self.fixture.put(self.fixture.refs['repository'], original); self.fixture.refresh()

    def test_input_drift_refused(self):
        path = self.root / self.fixture.authority['archives'][0]['path']; path.write_bytes(b'changed')
        with self.assertRaises(g.Refused): self.fixture.accept()

    def test_map_size_boolean_unknown_fields_or_paths_refused(self):
        for key, value in (('bytes', True), ('extra', 'unknown')):
            row = self.fixture.authority['files'][self.fixture.refs['aggregate']]
            original = dict(row); row[key] = value
            with self.assertRaises(g.Refused): self.fixture.accept()
            row.clear(); row.update(original)
        self.fixture.authority['files']['../escape'] = {'sha256': '0' * 64, 'bytes': 0}
        with self.assertRaises(g.Refused): self.fixture.accept()

    def test_extra_file_symlink_fifo_and_hardlink_refused(self):
        target = self.root / 'undeclared'
        for kind in ('file', 'symlink', 'fifo', 'hardlink'):
            if kind == 'file': target.write_bytes(b'unknown')
            elif kind == 'symlink': target.symlink_to(self.root / self.fixture.refs['aggregate'])
            elif kind == 'fifo': os.mkfifo(target)
            else: os.link(self.root / self.fixture.refs['aggregate'], target)
            with self.subTest(kind=kind), self.assertRaises(g.Refused): self.fixture.accept()
            target.unlink()

    def test_parent_symlink_refused(self):
        link = self.root.parent / (self.root.name + '-alias'); link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(link.unlink)
        raw = encode(self.fixture.authority)
        with self.assertRaises(g.Refused): g.accept(link, raw, g.digest(raw))

    def test_run_source_and_bootstrap_identity_mismatch(self):
        for role, change in (('runner', lambda r: r.update(run_id='456')),
                             ('bootstrap', lambda r: r.update(image_id='sha256:' + '1' * 64)),
                             ('integration_lock', lambda r: r.update(recipe_source_commit='1' * 40))):
            saved = self.fixture.data[self.fixture.refs[role]]
            self.fixture.change(role, change)
            with self.assertRaises(g.Refused): self.fixture.accept()
            self.fixture.put(self.fixture.refs[role], saved); self.fixture.refresh()

    def test_projection_cannot_change_an_unknown_field(self):
        self.fixture.change('projected_repository', lambda r: r.update(published=True))
        self.fixture.change('projection', lambda r: r.update(projected_sha256=g.digest(self.fixture.data[self.fixture.refs['projected_repository']]),
                                                             projected_bytes=len(self.fixture.data[self.fixture.refs['projected_repository']])))
        with self.assertRaisesRegex(g.Refused, 'projection change'): self.fixture.accept()

    def test_raw_projection_hash_binding(self):
        self.fixture.change('projection', lambda r: r.update(original_sha256='0' * 64))
        with self.assertRaises(g.Refused): self.fixture.accept()

    def test_negative_snapshot_or_transaction_drift(self):
        name = 'raw/untrusted-A-rejected-after-snapshot.json'
        value = json.loads(self.fixture.data[name]); value['files'][self.fixture.probe_path()] = {'type': 'regular', 'sha256': '0' * 64}
        self.fixture.put(name, encode(value)); self.fixture.refresh()
        with self.assertRaisesRegex(g.Refused, 'negative transaction'): self.fixture.accept()

    def test_positive_before_snapshot_must_continue_previous_case(self):
        name = 'raw/trusted-baseline-full-install-before-snapshot.json'
        value = json.loads(self.fixture.data[name]); value['inventory'] += 'invented-package 1-1\n'
        self.fixture.put(name, encode(value)); self.fixture.refresh()
        with self.assertRaisesRegex(g.Refused, 'snapshot chain'): self.fixture.accept()

    def test_initial_payload_absence_and_missing_parent_semantics(self):
        before = 'raw/untrusted-A-rejected-before-snapshot.json'
        after = before.replace('-before-', '-after-')
        value = json.loads(self.fixture.data[before]); value['files'][self.fixture.probe_path()]['missing_parent'] = 'usr/share/cachy-asahi-repository-TEST'
        following = 'raw/trusted-baseline-full-install-before-snapshot.json'
        for name in (before, after, following): self.fixture.put(name, encode(value))
        self.fixture.refresh(); self.fixture.accept()
        value['files'][self.fixture.probe_path()]['missing_parent'] = 'unrelated'
        for name in (before, after, following): self.fixture.put(name, encode(value))
        self.fixture.refresh()
        with self.assertRaisesRegex(g.Refused, 'initial copied root'): self.fixture.accept()

    def test_reset_requires_bound_rejection_and_full_revocation_fingerprint(self):
        saved = self.fixture.data[self.fixture.refs['reset']]
        self.fixture.change('reset', lambda r: r.update(prior_rejection_log_sha256='0' * 64))
        self.fixture.change('repository', lambda r: r['sync_cache_reset'].update(sha256=g.digest(self.fixture.data[self.fixture.refs['reset']])))
        self.fixture.project(); self.fixture.refresh()
        with self.assertRaises(g.Refused): self.fixture.accept()
        self.fixture.put(self.fixture.refs['reset'], saved)
        self.fixture.change('repository', lambda r: r['sync_cache_reset'].update(sha256=g.digest(saved)))
        row = next(r for r in self.fixture.repository['commands'] if r['label'] == 'gpg-revoked-A-status')
        log = 'raw/' + row['log']
        self.fixture.put(log, b'[GNUPG:] REVKEYSIG AAAAAAAAAAAAAAAA TEST\n[GNUPG:] VALIDSIG BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB TEST\n')
        pin = g.digest(self.fixture.data[log])
        self.fixture.change('reset', lambda r: r.update(revocation_status_log_sha256=pin))
        def update(row):
            next(r for r in row['commands'] if r['label'] == 'gpg-revoked-A-status')['sha256'] = pin
            row['sync_cache_reset']['sha256'] = g.digest(self.fixture.data[self.fixture.refs['reset']])
        self.fixture.change('repository', update); self.fixture.bind_native(); self.fixture.project(); self.fixture.refresh()
        with self.assertRaisesRegex(g.Refused, 'fingerprint evidence'): self.fixture.accept()

    def test_reset_snapshots_must_match_actual_revoked_case(self):
        name = 'raw/revoked-A-sync-cache-reset-after-snapshot.json'
        value = json.loads(self.fixture.data[name]); value['inventory'] += 'unrelated 1-1\n'
        self.fixture.put(name, encode(value)); self.fixture.bind_native(); self.fixture.project(); self.fixture.refresh()
        with self.assertRaisesRegex(g.Refused, 'operation reset snapshot'): self.fixture.accept()

    def test_reset_command_label_must_be_unique(self):
        duplicate = copy.deepcopy(next(r for r in self.fixture.repository['commands'] if r['label'] == 'gpg-revoked-A-status'))
        self.fixture.change('repository', lambda r: r['commands'].append(duplicate))
        self.fixture.project(); self.fixture.refresh()
        with self.assertRaisesRegex(g.Refused, 'unique complete projection'): self.fixture.accept()

    def test_missing_positive_diagnostics_and_raw_log_binding(self):
        self.fixture.change('repository', lambda r: r['commands'][1].pop('positive_diagnostics'))
        self.fixture.project(); self.fixture.refresh()
        with self.assertRaisesRegex(g.Refused, 'diagnostic acceptance'): self.fixture.accept()

    def test_raw_command_logs_and_paired_stderr_binding(self):
        for change in (lambda r: r['commands'][-1].update(sha256='0' * 64),
                       lambda r: r['commands'][0].update(stderr_log='unbound-stderr.txt'),
                       lambda r: r['commands'][0].update(stderr_log='000-untrusted-A-rejected.txt', stderr_sha256='0' * 64)):
            saved = self.fixture.data[self.fixture.refs['repository']]
            self.fixture.change('repository', change); self.fixture.project(); self.fixture.refresh()
            with self.assertRaises(g.Refused): self.fixture.accept()
            self.fixture.put(self.fixture.refs['repository'], saved); self.fixture.project(); self.fixture.refresh()

    def test_positive_expected_false_is_not_integer_zero(self):
        self.fixture.change('repository', lambda r: r['commands'][1].update(expected=False))
        self.fixture.project(); self.fixture.refresh()
        with self.assertRaisesRegex(g.Refused, 'positive diagnostic command policy'): self.fixture.accept()

    def test_current_ci_operation_protocol_is_accepted_with_identical_copies(self):
        spec = importlib.util.spec_from_file_location('readonly_repository_projection', REPO / 'scripts/ci/repository_projection.py')
        producer = importlib.util.module_from_spec(spec); spec.loader.exec_module(producer)
        raw = json.loads(self.fixture.data[self.fixture.refs['repository']])
        contract = json.loads(self.fixture.data[self.fixture.refs['repository_contract']])
        operations, expected_index = producer.operation_files(self.root / 'raw', raw, contract)
        self.assertEqual(len(operations), 9)
        self.assertEqual(json.loads(self.fixture.data['control/repository-operation-aliases.json']), expected_index)
        for original, (public, data) in operations.items():
            self.assertEqual(self.fixture.data['raw/' + original], data)
            self.assertEqual(self.fixture.data['control/' + public], data)
        projected = json.loads(self.fixture.data[self.fixture.refs['projected_repository']])
        self.assertEqual(projected['sync_cache_reset']['public_receipt'], 'revoked-A-sync-reset.json')
        self.assertEqual(projected['public_operation_index'], 'repository-operation-aliases.json')
        self.assertEqual(sum('public_log' in row for row in projected['commands']), 9)
        self.assertEqual(sum('public_stderr_log' in row for row in projected['commands']), 3)
        self.fixture.accept()

    def test_operation_index_requires_exact_fields_map_and_scalar_types(self):
        name = 'control/repository-operation-aliases.json'
        saved = self.fixture.data[name]
        for change in (lambda r: r.update(schema_version=True), lambda r: r.update(purpose='generic-aliases'),
                       lambda r: r.update(original_bytes_preserved=1), lambda r: r.update(extra='unknown'),
                       lambda r: r['files'].pop(next(iter(r['files']))),
                       lambda r: r['files'].update(unknown={'public_path': 'unknown', 'original_sha256': '0' * 64, 'public_sha256': '0' * 64, 'bytes': 0}),
                       lambda r: next(row for row in r['files'].values() if row['bytes'] == 0).update(bytes=False),
                       lambda r: next(iter(r['files'].values())).update(public_path='different.txt'),
                       lambda r: next(iter(r['files'].values())).update(public_sha256='0' * 64)):
            value = json.loads(saved); change(value); self.fixture.put(name, encode(value)); self.fixture.refresh()
            with self.subTest(change=change), self.assertRaisesRegex(g.Refused, 'operation index'): self.fixture.accept()
            self.fixture.put(name, saved); self.fixture.refresh()

    def test_operation_public_copies_must_preserve_raw_bytes(self):
        index = json.loads(self.fixture.data['control/repository-operation-aliases.json'])
        name = 'control/' + next(iter(index['files'].values()))['public_path']
        self.fixture.put(name, b'coherently pinned but changed public bytes'); self.fixture.refresh()
        with self.assertRaisesRegex(g.Refused, 'projected operation bytes'): self.fixture.accept()

    def test_projection_refs_and_unknown_fields_cannot_be_whitelisted(self):
        for change in (lambda r: r.update(public_operation_index='different.json'),
                       lambda r: r['sync_cache_reset'].update(public_receipt='different.json'),
                       lambda r: r['commands'][0].update(public_log='invented.txt'),
                       lambda r: r.update(unknown_projection_field='unknown')):
            saved = self.fixture.data[self.fixture.refs['projected_repository']]
            self.fixture.change('projected_repository', change)
            self.fixture.change('projection', lambda r: r.update(projected_sha256=g.digest(self.fixture.data[self.fixture.refs['projected_repository']]),
                                                        projected_bytes=len(self.fixture.data[self.fixture.refs['projected_repository']])))
            with self.assertRaisesRegex(g.Refused, 'unknown repository projection change'): self.fixture.accept()
            self.fixture.put(self.fixture.refs['projected_repository'], saved); self.fixture.project(); self.fixture.refresh()

    def test_operations_require_native_source_pins_and_order(self):
        saved = self.fixture.data[self.fixture.refs['repository']]
        for change in (lambda r: r['evidence_sha256'].pop('revoked-A-sync-cache-reset.json'),
                       lambda r: r['evidence_sha256'].update({'revoked-A-sync-cache-reset.json': '0' * 64}),
                       lambda r: r['commands'].reverse(),
                       lambda r: r['original_inputs']['baseline'].pop(next(iter(r['original_inputs']['baseline'])))):
            self.fixture.change('repository', change); self.fixture.project(); self.fixture.refresh()
            with self.assertRaises(g.Refused): self.fixture.accept()
            self.fixture.put(self.fixture.refs['repository'], saved); self.fixture.project(); self.fixture.refresh()

    def poison_command(self, label, data, stderr=False):
        raw = json.loads(self.fixture.data[self.fixture.refs['repository']])
        row = next(row for row in raw['commands'] if row['label'] == label)
        if stderr and 'stderr_log' not in row:
            row['stderr_log'] = row['log'][:-4] + '-stderr.txt'
        name, pin = ('stderr_log', 'stderr_sha256') if stderr else ('log', 'sha256')
        self.fixture.put('raw/' + row[name], data); row[pin] = g.digest(data)
        self.fixture.put(self.fixture.refs['repository'], encode(raw))
        self.fixture.bind_native(); self.fixture.project(); self.fixture.refresh()

    def test_positive_raw_errors_reject_after_all_hashes_and_projection_rebound(self):
        for data, stderr in ((b'error: command failed\n', False), (b'CoUlD NoT ChAnGe the root directory: Operation not permitted\n', True)):
            if stderr: self.poison_command('trusted-baseline-full-install', b'normal stdout without terminal LF')
            self.poison_command('trusted-baseline-full-install', data, stderr)
            with self.assertRaisesRegex(g.Refused, 'positive raw diagnostics'): self.fixture.accept()

    def test_positive_inventory_stderr_and_relation_diagnostics_are_exact(self):
        self.poison_command('inventory-revoked-A-sync-cache-reset-before', b'error: hidden ancillary failure\n', stderr=True)
        with self.assertRaisesRegex(g.Refused, 'inventory or stderr'): self.fixture.accept()

    def test_negative_raw_diagnostics_require_signature_or_trust_rejection(self):
        self.poison_command('tampered-package-signature-rejected', b'error: network unavailable\n')
        with self.assertRaisesRegex(g.Refused, 'lacks signature or trust'): self.fixture.accept()

    def test_missing_database_diagnostic_rejects_generic_near_miss(self):
        self.poison_command('missing-database-signature-rejected', self.fixture.missing_database_diagnostic().replace(b'/scratch/repos/active/', b'/scratch/repos/unselected/'))
        with self.assertRaisesRegex(g.Refused, 'exact local missing database'): self.fixture.accept()

    def test_missing_operation_index_is_refused_even_with_projected_fields(self):
        name = 'control/repository-operation-aliases.json'
        del self.fixture.data[name]; (self.root / name).unlink(); self.fixture.refresh()
        with self.assertRaisesRegex(g.Refused, 'operation index required'): self.fixture.accept()

    def test_finite_payload_lock_and_base_versions_identity(self):
        self.fixture.change('repository', lambda r: r['base_versions'].pop(next(iter(r['base_versions']))))
        self.fixture.project(); self.fixture.refresh()
        with self.assertRaisesRegex(g.Refused, 'complete base'): self.fixture.accept()

    def test_fixture_source_pin_cannot_be_changed_without_lock_binding(self):
        self.fixture.change('fixture_manifest', lambda r: r.update(source_commit='0' * 40))
        with self.assertRaisesRegex(g.Refused, 'fixture source'): self.fixture.accept()

    def test_tree_does_not_follow_directory_swap_after_stat(self):
        real_open = os.open
        swapped = [False]
        target = self.root / 'public'
        other = self.root.parent / (self.root.name + '-outside')
        other.mkdir(); self.addCleanup(other.rmdir)
        def replacing(path, flags, *args, **kwargs):
            if path == 'public' and flags & os.O_DIRECTORY and not swapped[0]:
                swapped[0] = True
                target.rename(self.root / 'held-public')
                target.symlink_to(other, target_is_directory=True)
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(g.os, 'open', side_effect=replacing), self.assertRaises(g.Refused):
            self.fixture.accept()
        self.assertTrue(swapped[0])

    def test_tree_scan_stops_at_first_excess_entry(self):
        class Entry:
            name = 'declared'
            def stat(self, **_): return (self.root / 'declared').lstat()
        entry = Entry(); entry.root = self.root
        (self.root / 'declared').write_bytes(b'fixture')
        class Scanner:
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def __iter__(self):
                for _ in range(4097): yield entry
                raise AssertionError('unbounded iteration past limit+1')
        with mock.patch.object(g.os, 'scandir', return_value=Scanner()), self.assertRaisesRegex(g.Refused, 'tree bound'):
            g.tree(self.root, {'declared': {}})

    def test_incomplete_public_export_even_if_resigned_authority(self):
        self.fixture.change('public_manifest', lambda r: r['files'].pop('TEST-repositories/updated-B/integration.files.sig'))
        self.fixture.change('public_acceptance', lambda r: r.update(manifest_sha256=g.digest(self.fixture.data[self.fixture.refs['public_manifest']])))
        with self.assertRaises(g.Refused): self.fixture.accept()

    def test_all_three_signer_roles_distinct_and_bound(self):
        self.fixture.change('repository', lambda r: r['public_TEST_identities']['signer-B'].update(fingerprint='A' * 40))
        self.fixture.project(); self.fixture.refresh()
        with self.assertRaisesRegex(g.Refused, 'distinct signer'): self.fixture.accept()

    def test_external_crypto_attestation_is_mandatory_and_exact(self):
        for change in (lambda c: c.update(status='NOT RUN'), lambda c: c['cases'].pop(),
                       lambda c: c['signed_objects'].pop(), lambda c: c['revocation'].update(status='VALID'),
                       lambda c: c['cases'][0].update(expected_signature_rejection=1)):
            saved = copy.deepcopy(self.fixture.authority['crypto']); change(self.fixture.authority['crypto'])
            with self.assertRaises(g.Refused): self.fixture.accept()
            self.fixture.authority['crypto'] = saved

    def test_probe_cannot_be_returned_as_original(self):
        self.fixture.authority['archives'][0]['name'] = g.PROBE
        with self.assertRaises(g.Refused): self.fixture.accept()

    def test_historical_baseline_role_is_explicit(self):
        self.fixture.authority['archive_role'] = 'baseline'
        self.fixture.authority['archives'] = [{'name': r['name'], 'version': r['version'], 'sha256': r['sha256'],
            'path': 'public/TEST-repositories/baseline-A/' + Path(r['archive']).name,
            'bytes': len(self.fixture.data['public/TEST-repositories/baseline-A/' + Path(r['archive']).name])} for r in self.fixture.rows['baseline']]
        result = self.fixture.accept()
        self.assertEqual(result['archive_role'], 'baseline')
        self.assertTrue(all(r['original_signer'] == 'A' * 40 for r in result['archives']))

    def test_complete_base_and_owned_absence_required(self):
        self.fixture.change('cleanup', lambda r: r.pop('id_absence_verified'))
        with self.assertRaisesRegex(g.Refused, 'name and ID absence'): self.fixture.accept()

    def test_duplicate_and_nonfinite_json_authority_refused(self):
        for data in (b'{"purpose":1,"purpose":2}', b'{"value":NaN}'):
            with self.assertRaises(g.Refused): g.accept(self.root, data, g.digest(data))

    def test_file_change_after_validation_refused(self):
        original = g.tree; count = [0]
        def changed(root, files):
            original(root, files); count[0] += 1
            if count[0] == 2:
                path = root / self.fixture.authority['archives'][0]['path']
                data = path.read_bytes(); path.write_bytes(b'X' * len(data))
        with mock.patch.object(g, 'tree', side_effect=changed), self.assertRaisesRegex(g.Refused, 'changed before acceptance'):
            self.fixture.accept()


if __name__ == '__main__':
    unittest.main()
