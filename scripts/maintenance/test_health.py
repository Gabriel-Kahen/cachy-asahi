#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite offline health controls; signatures are covered by retained-DATA replay."""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('health.py')
spec = importlib.util.spec_from_file_location('health_test_subject', SCRIPT)
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
NOW = '2026-10-27T12:00:00Z'
KEY = 'A' * 40


def fixture(root, match=True):
    packages = [dict(name='demo', version='1-1', arch='aarch64', depend=[], provides=[])]
    source = dict(package={k: packages[0][k] for k in ('name', 'version', 'arch')},
                  recipe_sha256='b' * 64, sources=[dict(url='fixture://demo', sha256='c' * 64)])
    ctx = dict(binding=dict(release_id='fixture', release_sha256='a' * 64, source_commit='d' * 40,
                           snapshot_id='fixture-base', synthetic=True,
                           package_inventory_sha256=h.pins.digest(h.a.encoded(h.identities(packages))),
                           project_sources_sha256=h.pins.digest(h.a.encoded({'demo': source}))),
               packages=packages, sources={'demo': source}, created_utc='2026-10-27T10:00:00+00:00', path=root)
    graph = dict(schema_version=1, metadata_role='pre-change-release', release_id='fixture', snapshot_id='fixture-base',
                 packages=packages, sources=[dict(id='demo-src', **{k: source[k] for k in ('recipe_sha256', 'sources')})],
                 build_dependencies=[dict(package='demo', source_id='demo-src', makedepend=[], checkdepend=[], toolchain=[],
                                          owner='FIXTURE-maintainer', disposition='build', hold_reason=None)],
                 changed=dict(sources=[], toolchains=[], advisories=[]),
                 capacity=dict(native_aarch64_slots=1, owner='FIXTURE-builder', reference='fixture, not measured'))
    inventory = [{k: packages[0][k] for k in ('name', 'version', 'arch', 'provides')}]
    advisories = [dict(name='AVG-1', packages=['demo' if match else 'different-binary'],
                       status='Fixed', severity='High', type='FICTIONAL test only', affected='0-1', fixed='1-1',
                       issues=[], advisories=[])]
    raws = dict(inventory=h.a.encoded(inventory), advisories=h.a.encoded(advisories), graph=h.a.encoded(graph))
    provenance = dict(url=h.a.URL, retrieved_at=NOW, **h.a.pin(raws['advisories']))
    raws['provenance'] = h.a.encoded(provenance)
    report = h.a.report(inventory, advisories, h.a.provenance(provenance, raws['advisories'], h.a.utc(NOW), 24), NOW)
    report['inputs'] = {key + '.json': h.a.pin(raws[key]) for key in ('inventory', 'advisories', 'provenance')}
    raws['advisory_report'] = h.a.encoded(report)
    raws['report'] = h.a.encoded(h.update.plan(raws, NOW))

    def save(name, raw):
        path = root / (name + '.json')
        path.write_bytes(raw)
        return dict(path=path.name, sha256=h.pins.digest(raw))

    entries = {'maintenance': dict(binding=copy.deepcopy(ctx['binding']), observed_at=NOW,
                                   inputs={key: save(key, raw) for key, raw in raws.items()})}
    ops = dict(roles={role: 'FIXTURE-' + role for role in h.ROLES}, package_owners={'demo': 'FIXTURE-owner'},
               capacity=dict(native_aarch64_slots=1, builder_owner='FIXTURE-builder', builder_reference='unmeasured fixture',
                             repository_owner='FIXTURE-repo', repository_reference='fixture://repo'))
    entries['operations'] = dict(binding=copy.deepcopy(ctx['binding']), observed_at=NOW,
                                 inputs={'record': save('operations', h.a.encoded(ops))})
    return ctx, dict(schema_version=1, observations=entries)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='maintenance-health-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ctx, self.obs = fixture(self.root)

    def assess(self, as_of=NOW):
        before = {p: p.read_bytes() for p in self.root.iterdir() if p.is_file()}
        reader = h.Reader(self.root)
        with patch.object(socket, 'create_connection', side_effect=AssertionError('offline only')):
            value = h.assess(self.ctx, self.obs, reader, KEY, {}, as_of)
        reader.finish()
        self.assertEqual(before, {p: p.read_bytes() for p in before})
        return value

    def codes(self, value, kind=None):
        return {f['code'] for f in value['findings'] if kind is None or f['kind'] == kind}

    def rewrite(self, name, change, replan=True):
        entry = self.obs['observations']['maintenance']
        path = self.root / entry['inputs'][name]['path']
        value = h.a.decode(path.read_bytes())
        change(value)
        raw = h.a.encoded(value)
        path.write_bytes(raw)
        entry['inputs'][name]['sha256'] = h.pins.digest(raw)
        if replan:
            raws = {k: (self.root / entry['inputs'][k]['path']).read_bytes() for k in h.update.INPUTS}
            raw = h.a.encoded(h.update.plan(raws, NOW))
            (self.root / entry['inputs']['report']['path']).write_bytes(raw)
            entry['inputs']['report']['sha256'] = h.pins.digest(raw)

    def test_matching_arch_fixed_reference_still_unknown_arm_and_held(self):
        value = self.assess()
        self.assertEqual(value['checks']['maintenance']['coverage_packages'], 1)
        self.assertEqual(value['checks']['maintenance']['held_rebuild_groups'], 1)
        self.assertTrue({'ARM_AFFECTEDNESS_UNKNOWN', 'ARM_FIX_EVIDENCE_MISSING', 'REBUILD_HELD'} <= self.codes(value))
        self.assertEqual(value['arm_security_status'], 'UNKNOWN')
        self.assertEqual(value['maintenance_acceptance'], 'NOT_ESTABLISHED')

    def test_clean_finite_no_drift_or_owner_gap_never_becomes_security_acceptance(self):
        self.ctx, self.obs = fixture(self.root, match=False)
        value = self.assess()
        self.assertEqual(self.codes(value, 'maintenance'), {'ADVISORY_COVERAGE_UNKNOWN'})
        self.assertEqual(value['checks']['operations']['status'], 'REPLAYED_FINITE')
        self.assertEqual(value['checks']['maintenance']['held_rebuild_groups'], 0)
        self.assertEqual(value['status'], 'OFFLINE_HEALTH_REVIEW_REQUIRED')
        self.assertEqual(value['native_build'], 'NOT_RUN')

    def test_each_generation_and_identity_binding_component_refused(self):
        for field in self.ctx['binding']:
            with self.subTest(field=field):
                original = self.obs['observations']['maintenance']['binding'][field]
                self.obs['observations']['maintenance']['binding'][field] = 'wrong'
                with self.assertRaisesRegex(h.ERRORS, 'binding mismatch'):
                    self.assess()
                self.obs['observations']['maintenance']['binding'][field] = original

    def test_graph_release_or_base_snapshot_mismatch_refused(self):
        for field in ('release_id', 'snapshot_id'):
            with self.subTest(field=field):
                self.ctx, self.obs = fixture(self.root)
                self.rewrite('graph', lambda v: v.update({field: 'different-generation'}))
                with self.assertRaisesRegex(h.ERRORS, 'graph generation mismatch'):
                    self.assess()

    def test_signed_source_recipe_and_full_source_descriptor_mismatch_refused(self):
        for field in ('recipe_sha256', 'sources'):
            with self.subTest(field=field):
                self.ctx, self.obs = fixture(self.root)
                self.rewrite('graph', lambda v: v['sources'][0].update({field: 'e' * 64 if field == 'recipe_sha256'
                                                                       else [dict(url='fixture://other', sha256='f' * 64)]}))
                with self.assertRaisesRegex(h.ERRORS, 'signed recipe/source pins'):
                    self.assess()

    def test_inventory_omission_from_signed_base_is_refused(self):
        self.ctx['packages'].append(dict(name='base', version='2-1', arch='aarch64', depend=[], provides=[]))
        with self.assertRaisesRegex(h.ERRORS, 'effective release/base inventory'):
            self.assess()

    def test_graph_runtime_metadata_differs_from_signed_release(self):
        self.rewrite('graph', lambda v: v['packages'][0].update(depend=['extra']))
        with self.assertRaisesRegex(h.ERRORS, 'signed runtime metadata'):
            self.assess()

    def test_stale_observation_report_and_cache_are_actionable(self):
        value = self.assess('2026-10-29T12:00:00Z')
        self.assertTrue({'STALE_OBSERVATION', 'STALE_MAINTENANCE_REPORT', 'STALE_ADVISORY_REPORT',
                         'STALE_ADVISORY_CACHE'} <= self.codes(value))
        self.assertEqual(value['checks']['operations']['status'], 'REVIEW_REQUIRED')
        self.assertTrue(all(f['action'] for f in value['findings']))

    def test_missing_inputs_and_absent_categories_are_unavailable(self):
        (self.root / 'report.json').unlink()
        value = self.assess()
        self.assertEqual(value['checks']['maintenance']['status'], 'UNAVAILABLE')
        self.assertEqual(self.codes(value, 'signing'), {'EVIDENCE_UNAVAILABLE'})

    def test_unknown_owner_and_capacity_do_not_disappear_in_unaffected_package(self):
        self.ctx, self.obs = fixture(self.root, match=False)
        self.rewrite('graph', lambda v: (v['build_dependencies'][0].update(owner=None),
                                         v['capacity'].update(native_aarch64_slots=None, owner=None)))
        value = self.assess()
        self.assertIn('UNKNOWN_PACKAGE_OWNER', self.codes(value, 'maintenance'))
        self.assertIn('CAPACITY_OR_CAPACITY_OWNER_UNAVAILABLE', self.codes(value, 'maintenance'))

    def test_missing_operations_role_package_owner_and_repository_capacity(self):
        entry = self.obs['observations']['operations']['inputs']['record']
        path = self.root / entry['path']
        record = h.a.decode(path.read_bytes())
        record['roles']['support'] = None
        record['package_owners']['demo'] = None
        record['capacity'].update(native_aarch64_slots=0, repository_owner=None)
        raw = h.a.encoded(record)
        path.write_bytes(raw)
        entry['sha256'] = h.pins.digest(raw)
        value = self.assess()
        self.assertTrue({'MAINTENANCE_ROLE_MISSING', 'MAINTENANCE_PACKAGE_MISSING',
                         'MAINTENANCE_CAPACITY_MISSING', 'NATIVE_CAPACITY_UNAVAILABLE'} <= self.codes(value, 'operations'))

    def test_tampered_rehashed_retained_report_does_not_replay(self):
        self.rewrite('report', lambda v: v.update(maintenance_review_held=False), replan=False)
        with self.assertRaisesRegex(h.ERRORS, 'does not replay'):
            self.assess()

    def test_future_report_and_future_observation_refused(self):
        self.obs['observations']['maintenance']['observed_at'] = '2026-10-28T12:00:00Z'
        with self.assertRaisesRegex(h.ERRORS, 'future'):
            self.assess()
        self.obs['observations']['maintenance']['observed_at'] = '2026-10-27T11:00:00Z'
        with self.assertRaisesRegex(h.ERRORS, 'postdates observation'):
            self.assess()

    def test_observation_binding_predates_signed_generation(self):
        self.obs['observations']['maintenance']['observed_at'] = '2026-10-27T09:00:00Z'
        with self.assertRaisesRegex(h.ERRORS, 'predates release generation'):
            self.assess()

    def test_all_missing_is_review_required(self):
        self.obs['observations'] = {}
        value = self.assess()
        self.assertEqual(len(value['findings']), len(h.KINDS))
        self.assertTrue(all(v['status'] == 'UNAVAILABLE' for v in value['checks'].values()))

    def test_reader_wrong_hash_symlink_duplicate_keys_and_change_refused(self):
        reader = h.Reader(self.root)
        ref = self.obs['observations']['maintenance']['inputs']['inventory']
        with self.assertRaisesRegex(h.ERRORS, 'checksum'):
            reader.read(dict(ref, sha256='0' * 64))
        (self.root / 'alias').symlink_to(ref['path'])
        with self.assertRaisesRegex(h.ERRORS, 'symlink'):
            reader.read(dict(ref, path='alias'))
        with self.assertRaisesRegex(h.ERRORS, 'duplicate'):
            h.a.decode(b'{"a":1,"a":2}')
        reader.read(ref)
        (self.root / ref['path']).write_bytes(b'[]')
        with self.assertRaisesRegex(h.ERRORS, 'changed'):
            reader.finish()

    def test_text_contains_actionable_holds_and_coverage(self):
        text = h.text_report(self.assess())
        self.assertIn('Packages reviewed=1; held rebuild groups=1', text)
        self.assertIn('ARM_AFFECTEDNESS_UNKNOWN [demo]', text)
        self.assertIn('maintenance acceptance NOT_ESTABLISHED', text)

    def attach(self, kind, values):
        refs = {}
        for name, value in values.items():
            raw = value if type(value) is bytes else h.a.encoded(value)
            path = self.root / (kind + '-' + name + '.json')
            path.write_bytes(raw)
            refs[name] = dict(path=path.name, sha256=h.pins.digest(raw))
        self.obs['observations'][kind] = dict(binding=copy.deepcopy(self.ctx['binding']), observed_at=NOW, inputs=refs)

    def test_complete_clean_finite_case_replays_all_observations_without_false_health(self):
        self.ctx, self.obs = fixture(self.root, match=False)
        epoch = h.expiry.timestamp(NOW)
        row = ['pub', '-', '255', '22', 'AAAA', str(epoch - 100), str(epoch + 86400 * 365), '', '', '', '', 'scSC']
        colons = ':'.join(row) + '\n' + ':'.join(['fpr', '', '', '', '', '', '', '', '', KEY]) + '\n'
        signing = h.expiry.report(colons, KEY, epoch, 30)
        self.attach('signing', dict(certificate=b'FIXTURE PUBLIC CERTIFICATE TRANSPORT', report=signing))
        candidate = dict(schema_version=1, packages=list(self.ctx['sources'].values()))
        source = h.pins.comparison(self.ctx['sources'], self.ctx['sources'])
        self.attach('sources', dict(candidate=candidate, report=source))
        prior_ctx = copy.deepcopy(self.ctx)
        prior_ctx['binding']['release_sha256'] = 'e' * 64
        prior_ctx['created_utc'] = '2026-10-26T10:00:00+00:00'
        comparison = dict(before=prior_ctx['binding'], after=self.ctx['binding'], packages=[],
                          dependency_impact=dict(unchanged_dependents=[]), policy=[], coordinated_sets=[])
        self.attach('comparison', dict(report=comparison))
        self.obs['observations']['comparison']['inputs']['predecessor'] = dict(path=str(self.root), sha256='e' * 64)
        with patch.object(h.expiry, 'inspect', return_value=colons), patch.object(h.pins, 'check_source_pins', return_value=source), \
             patch.object(h, 'context', return_value=prior_ctx), patch.object(h.comparison, 'compare_releases', return_value=comparison):
            value = self.assess()
        self.assertTrue(all(c['status'] != 'UNAVAILABLE' for c in value['checks'].values()))
        self.assertEqual(self.codes(value), {'REVOCATION_UNAVAILABLE_OFFLINE', 'UPSTREAM_FRESHNESS_UNAVAILABLE_OFFLINE', 'ADVISORY_COVERAGE_UNKNOWN'})
        self.assertEqual(value['checks']['sources']['changed_packages'], 0)
        self.assertEqual(value['checks']['maintenance']['held_rebuild_groups'], 0)
        self.assertEqual(value['checks']['operations']['status'], 'REPLAYED_FINITE')
        self.assertEqual(value['maintenance_acceptance'], 'NOT_ESTABLISHED')

    def test_missing_runtime_fields_on_unaffected_package_are_reported(self):
        self.ctx, self.obs = fixture(self.root, match=False)
        self.rewrite('graph', lambda v: (v['packages'][0].pop('depend'), v['packages'][0].pop('provides')))
        value = self.assess()
        gaps = [f for f in value['findings'] if f['code'] == 'UNKNOWN_RUNTIME_METADATA']
        self.assertEqual({f['field'] for f in gaps}, {'depend', 'provides'})
        self.assertEqual(value['checks']['maintenance']['held_rebuild_groups'], 0)

    def test_missing_signed_source_mapping_is_actionable(self):
        self.rewrite('graph', lambda v: (v['sources'].clear(), v['build_dependencies'][0].update(source_id=None)))
        self.assertIn('SIGNED_SOURCE_MAPPING_UNAVAILABLE', self.codes(self.assess()))

    def test_signing_expiry_replay_and_expired_at_evaluation_time(self):
        epoch = h.expiry.timestamp(NOW)
        expires = epoch + 3600
        def colons(as_of):
            # Real producer parser; GPG transport is isolated in this unit test.
            row = ['pub', 'e' if as_of >= expires else '-', '255', '22', 'AAAA', str(epoch - 100), str(expires), '', '', '', '', 'scSC']
            fpr = ['fpr', '', '', '', '', '', '', '', '', KEY]
            return ':'.join(row) + '\n' + ':'.join(fpr) + '\n'
        report = h.expiry.report(colons(epoch), KEY, epoch, 30)
        self.attach('signing', dict(certificate=b'SYNTHETIC PUBLIC CERTIFICATE UNIT TRANSPORT', report=report))
        with patch.object(h.expiry, 'inspect', side_effect=lambda raw, as_of: colons(as_of)):
            current = self.assess()
            later = self.assess('2026-10-27T14:00:00Z')
        self.assertIn('EXPIRES_SOON', self.codes(current, 'signing'))
        self.assertTrue({'EXPIRED', 'NO_SIGNING_WINDOW', 'REVOCATION_UNAVAILABLE_OFFLINE'} <= self.codes(later, 'signing'))
        self.assertIn('expiry epoch=', h.text_report(current))

    def test_source_drift_names_fields_and_coverage_visible_in_text(self):
        changed = copy.deepcopy(self.ctx['sources']['demo'])
        changed['recipe_sha256'] = 'f' * 64
        candidate = dict(schema_version=1, packages=[changed])
        report = h.pins.comparison(self.ctx['sources'], h.pins.indexed(candidate['packages']))
        self.attach('sources', dict(candidate=candidate, report=report))
        with patch.object(h.pins, 'check_source_pins', return_value=report):
            value = self.assess()
        self.assertIn('SOURCE_DRIFT', self.codes(value, 'sources'))
        self.assertIn('demo: recipe_sha256', h.text_report(value))
        self.assertIn('UPSTREAM_FRESHNESS_UNAVAILABLE_OFFLINE', self.codes(value, 'sources'))

    def test_same_version_byte_transition_and_downgrade_require_review(self):
        prior_ctx = copy.deepcopy(self.ctx)
        prior_ctx['binding']['release_sha256'] = 'e' * 64
        prior_ctx['created_utc'] = '2026-10-26T10:00:00+00:00'
        before = dict(self.ctx['packages'][0], filename='demo.pkg.tar.gz', sha256='a' * 64)
        for version in ('1-1', '0-1'):
            with self.subTest(version=version):
                after = dict(before, version=version, sha256='b' * 64)
                report = dict(before=prior_ctx['binding'], after=self.ctx['binding'],
                              packages=h.comparison.package_changes({'demo': before}, {'demo': after}, artifacts=True),
                              dependency_impact=dict(unchanged_dependents=[]), policy=[], coordinated_sets=[])
                self.attach('comparison', dict(report=report))
                self.obs['observations']['comparison']['inputs']['predecessor'] = dict(path=str(self.root), sha256='e' * 64)
                with patch.object(h, 'context', return_value=prior_ctx), patch.object(h.comparison, 'compare_releases', return_value=report):
                    value = self.assess()
                self.assertIn('PACKAGE_TRANSITION_REVIEW', self.codes(value, 'comparison'))
                expected = 'same-version-byte-change' if version == '1-1' else 'downgraded'
                self.assertIn(expected, h.text_report(value))

    def test_public_verifier_does_not_copy_user_config_trustdb_or_secrets(self):
        home = self.root / 'verification-home'
        home.mkdir()
        (home / 'pubring.gpg').write_bytes(b'PUBLIC KEYRING BYTES')
        (home / 'gpg.conf').write_text('auto-key-retrieve\nkeyserver malicious.invalid\n')
        (home / 'trustdb.gpg').write_bytes(b'USER TRUST DATA')
        (home / 'private-keys-v1.d').mkdir()
        before = {p: p.read_bytes() for p in home.iterdir() if p.is_file()}
        with h.verification_env(home, self.root / 'release') as env:
            isolated = Path(env['GNUPGHOME'])
            self.assertEqual((isolated / 'pubring.gpg').read_bytes(), b'PUBLIC KEYRING BYTES')
            self.assertFalse((isolated / 'trustdb.gpg').exists())
            self.assertFalse((isolated / 'private-keys-v1.d').exists())
            self.assertIn('no-auto-key-retrieve', (isolated / 'gpg.conf').read_text())
            self.assertNotIn('malicious.invalid', (isolated / 'gpg.conf').read_text())
            self.assertNotIn('SSH_AUTH_SOCK', env)
        self.assertFalse(isolated.exists())
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_helper_error_is_clean_cli_refusal(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), patch.object(h.comparison, 'directory', side_effect=h.comparison.r.Error('helper refusal')):
            status = h.main(['--release', str(self.root), '--release-sha256', 'a' * 64, '--key', KEY,
                             '--gpg-home', str(self.root), '--as-of', NOW])
        self.assertEqual(status, 2)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('helper refusal', err.getvalue())

    def test_cli_bad_release_digest_clean_refusal(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = h.main(['--release', str(self.root), '--release-sha256', 'wrong', '--key', KEY,
                             '--gpg-home', str(self.root), '--as-of', NOW])
        self.assertEqual(status, 2)
        self.assertEqual(out.getvalue(), '')
        self.assertIn('SHA-256', err.getvalue())


if __name__ == '__main__':
    unittest.main()
