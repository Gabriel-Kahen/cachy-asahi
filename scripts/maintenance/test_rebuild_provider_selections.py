#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline typed-binding controls. Evidence records here are synthetic, never native."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import unittest
from test_rebuild_plan import m


def fixture():
    packages=[dict(name=n,version='1-1',arch='aarch64',depend=[],provides=[])for n in ('base-a','base-b','base-consumer','app')]
    packages[0]['provides']=['shared=2'];packages[1]['provides']=['shared=3'];packages[2]['depend']=['shared>=2'];packages[3]['depend']=['base-consumer']
    sources=[dict(id=p['name'],recipe_sha256='a'*64,sources=[dict(url='https://example.invalid/SYNTHETIC/'+p['name'],sha256='b'*64)])for p in packages]
    builds=[dict(package=p['name'],source_id=p['name'],makedepend=[],checkdepend=[],toolchain=[],disposition='build'if p['name']=='app'else'external',owner='synthetic-owner',hold_reason=None)for p in packages]
    return dict(schema_version=1,metadata_role='pre-change-release',release_id='SYNTHETIC_BINDING_CONTROL',snapshot_id='SYNTHETIC_BASE',packages=packages,sources=sources,build_dependencies=builds,changed=dict(sources=['app'],toolchains=[],advisories=[]),capacity=dict(native_aarch64_slots=1,owner='synthetic-owner',reference='synthetic-control-only'))


def selection(value,provider='base-a',consumer='base-consumer',dependency='shared>=2'):
    packages={p['name']:p for p in value['packages']};builds={p['package']:p for p in value['build_dependencies']}
    offers=[p['name']for p in value['packages']if m.r.relation(dependency)[0]in [p['name'],*[m.r.relation(v)[0]for v in p['provides']]]]
    context=m.provider_context(consumer,'depend',dependency,offers,packages)
    inventory=''.join(n+' '+p['version']+'\n'for n,p in sorted(packages.items())if builds[n]['disposition']=='external')
    return dict(package=consumer,field='depend',dependency=dependency,provider=provider,evidence=dict(kind='INSTALLED_ALPM_CACHE_QUERY_V1',image='sha256:'+'c'*64,inventory_sha256=hashlib.sha256(inventory.encode()).hexdigest(),capture_sha256='d'*64,metadata_sha256=hashlib.sha256(m.pins.encoded(context)).hexdigest()))


class SelectionTests(unittest.TestCase):
    def setUp(self):self.value=fixture()
    def bound(self):self.value['provider_selections']=[selection(self.value)];return m.plan(self.value)
    def app(self,report):return next(g for g in report['groups']if'app'in g['packages'])
    def reject(self,fragment):
        with self.assertRaisesRegex((m.r.Error,m.s.Error,ValueError),fragment):m.plan(self.value)

    def test_without_selection_preserves_canonical_result_exactly(self):
        self.assertEqual(hashlib.sha256(m.pins.encoded(m.plan(self.value))).hexdigest(),'244c1ac9737ee76e89e1044ec3275d4d0fdfcb035ecb0dea6c78e927a8a71431')
        self.assertTrue(self.app(m.plan(self.value))['held'])

    def test_explicit_selection_resolves_only_matching_baseline_ambiguity(self):
        before=copy.deepcopy(self.value);report=self.bound()
        self.assertFalse(self.app(report)['held'])
        issue=report['dependency_issues'][0];self.assertEqual(issue['status'],'AMBIGUOUS_PROVIDER_BOUND_TO_INSTALLED_QUERY')
        self.assertEqual(issue['matching_providers'],['base-a','base-b'])
        row=next(p for p in report['baseline_inputs']if p['name']=='base-consumer')
        self.assertEqual(row['prerequisites'],['base-a','base-b'])
        self.assertEqual(self.value['packages'],before['packages'])
        self.assertEqual(self.value['build_dependencies'],before['build_dependencies'])

    def test_other_actual_satisfier_can_be_explicitly_bound(self):
        self.value['provider_selections']=[selection(self.value,'base-b')]
        self.assertFalse(self.app(m.plan(self.value))['held'])

    def test_wrong_provider_does_not_become_a_satisfier(self):
        self.value['provider_selections']=[selection(self.value,'app')];self.reject('actually ambiguous satisfying')

    def test_unsatisfied_version_cannot_be_overridden(self):
        self.value['packages'][2]['depend']=['shared>2'];self.value['provider_selections']=[selection(self.value,dependency='shared>2')]
        self.reject('actually ambiguous')

    def test_constraint_change_makes_the_binding_stale(self):
        self.value['provider_selections']=[selection(self.value)];self.value['packages'][2]['depend']=['shared>=3'];self.reject('unused/stale')

    def test_changed_provider_metadata_refused(self):
        self.value['provider_selections']=[selection(self.value)];self.value['packages'][1]['provides']=['shared=4'];self.reject('metadata differs')

    def test_changed_inventory_refused(self):
        self.value['provider_selections']=[selection(self.value)];self.value['packages'][0]['version']='2-1';self.reject('inventory differs')

    def test_changed_consumer_metadata_refused(self):
        self.value['provider_selections']=[selection(self.value)];self.value['packages'][2]['provides']=['new-offer'];self.reject('metadata differs')

    def test_non_runtime_field_refused(self):
        row=selection(self.value);row['field']='makedepend';self.value['provider_selections']=[row];self.reject('runtime depend')

    def test_duplicate_selection_refused(self):
        row=selection(self.value);self.value['provider_selections']=[row,row];self.reject('duplicate provider')

    def test_incomplete_evidence_refused(self):
        row=selection(self.value);del row['evidence']['capture_sha256'];self.value['provider_selections']=[row]
        self.reject('fields')

    def test_bad_digest_refused(self):
        row=selection(self.value);row['evidence']['capture_sha256']=True;self.value['provider_selections']=[row];self.reject('checksum')

    def test_unknown_provider_refused(self):
        row=selection(self.value,'absent');self.value['provider_selections']=[row];self.reject('outside finite')

    def test_affected_baseline_change_cannot_reuse_installed_selection(self):
        self.value['provider_selections']=[selection(self.value)];self.value['changed']['sources']=['base-a'];self.reject('affected-package review')

    def test_project_build_cannot_claim_baseline_selection(self):
        self.value['build_dependencies'][2]['disposition']='build';self.value['provider_selections']=[selection(self.value)];self.reject('external baseline only')

    def test_missing_source_pin_still_holds(self):
        self.value['build_dependencies'][0]['source_id']=None;self.value['sources']=[p for p in self.value['sources']if p['id']!='base-a']
        self.assertTrue(self.app(self.bound())['held'])

    def test_missing_owner_on_unselected_provider_still_holds(self):
        self.value['build_dependencies'][1]['owner']=None
        self.assertTrue(self.app(self.bound())['held'])

    def test_cycle_hold_is_preserved(self):
        self.value['packages'][3]['depend'].append('app');report=self.bound()
        self.assertTrue(self.app(report)['held']);self.assertIn('CYCLE_BOOTSTRAP_REVIEW_REQUIRED',self.app(report)['holds'])

    def test_unrelated_ambiguity_remains_held(self):
        self.value['packages'].append(dict(name='base-other',version='1-1',arch='any',depend=['shared>=2'],provides=[]))
        self.value['sources'].append(dict(id='base-other',recipe_sha256='a'*64,sources=[dict(url='https://example.invalid/SYNTHETIC/other',sha256='b'*64)]))
        self.value['build_dependencies'].append(dict(package='base-other',source_id='base-other',makedepend=[],checkdepend=[],toolchain=[],disposition='external',owner='synthetic-owner',hold_reason=None))
        self.value['packages'][3]['depend'].append('base-other');report=self.bound()
        self.assertTrue(self.app(report)['held']);self.assertEqual([p['status']for p in report['dependency_issues']].count('AMBIGUOUS_PROVIDER'),1)

    def two_selections(self):
        self.value['packages'].append(dict(name='base-other',version='1-1',arch='any',depend=['shared>=2'],provides=[]))
        self.value['sources'].append(dict(id='base-other',recipe_sha256='a'*64,sources=[dict(url='https://example.invalid/SYNTHETIC/other',sha256='b'*64)]))
        self.value['build_dependencies'].append(dict(package='base-other',source_id='base-other',makedepend=[],checkdepend=[],toolchain=[],disposition='external',owner='synthetic-owner',hold_reason=None))
        self.value['packages'][3]['depend'].append('base-other')
        self.value['provider_selections']=[selection(self.value),selection(self.value,consumer='base-other')]

    def test_two_explicit_selections_can_share_one_capture(self):
        self.two_selections();self.assertFalse(self.app(m.plan(self.value))['held'])

    def test_mixed_image_bindings_refused(self):
        self.two_selections();self.value['provider_selections'][1]['evidence']['image']='sha256:'+'e'*64;self.reject('one installed-image capture')

    def test_mixed_capture_bindings_refused(self):
        self.two_selections();self.value['provider_selections'][1]['evidence']['capture_sha256']='e'*64;self.reject('one installed-image capture')

    def test_unavailable_dependency_hold_is_preserved(self):
        self.value['packages'][3]['depend'].append('missing>=9');report=self.bound()
        self.assertTrue(self.app(report)['held']);self.assertIn('UNAVAILABLE_DEPENDENCY',[p['status']for p in report['dependency_issues']])

    def test_version_rejected_named_candidate_remains_visible(self):
        self.value['packages'].append(dict(name='shared',version='1-1',arch='aarch64',depend=[],provides=[]))
        self.value['sources'].append(dict(id='shared',recipe_sha256='a'*64,sources=[dict(url='https://example.invalid/SYNTHETIC/shared',sha256='b'*64)]))
        self.value['build_dependencies'].append(dict(package='shared',source_id='shared',makedepend=[],checkdepend=[],toolchain=[],disposition='external',owner='synthetic-owner',hold_reason=None))
        report=self.bound();issue=report['dependency_issues'][0]
        self.assertEqual(issue['candidates'],['base-a','base-b','shared']);self.assertEqual(issue['matching_providers'],['base-a','base-b'])
        row=next(p for p in report['baseline_inputs']if p['name']=='base-consumer')
        self.assertEqual(row['prerequisites'],['base-a','base-b','shared'])

    def test_deterministic_and_input_preserving(self):
        self.value['provider_selections']=[selection(self.value)];before=copy.deepcopy(self.value)
        self.assertEqual(m.pins.encoded(m.plan(self.value)),m.pins.encoded(m.plan(self.value)));self.assertEqual(self.value,before)


if __name__=='__main__':unittest.main()
