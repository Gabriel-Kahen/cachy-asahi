#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real offline planner/admission composition over explicitly synthetic receipts."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'scripts/build/build_v2.py').is_file())
SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/maintenance/campaign.py'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


m = load('campaign_under_test', SCRIPT)
output_fixture = load('campaign_output_fixture', ROOT / 'tests/test_build_outputs_v2.py')
update_fixture = load('campaign_update_fixture', ROOT / 'scripts/maintenance/test_update_plan.py')


class CampaignFixture:
    """Use existing retained-output fixture; no package build is represented as real."""
    def __init__(self, root):
        self.root = root
        self.originals = root / 'original-planning-inputs'
        self.originals.mkdir()
        self.batches = root / 'synthetic-batches'
        self.batches.mkdir()
        self.f = output_fixture.Fixture(self.batches)
        graph = copy.deepcopy(self.f.source)
        graph.update(metadata_role='pre-change-release', release_id='SYNTHETIC-CAMPAIGN',
                     snapshot_id='SYNTHETIC-base', changed=dict(sources=['alpha-src'], toolchains=[], advisories=[]),
                     capacity=dict(native_aarch64_slots=1, owner='SYNTHETIC-owner', reference='Unmeasured fixture'))
        graph['packages'].append(dict(name='fixture-base', version='1-1', arch='aarch64', depend=[], provides=[]))
        graph['sources'].append(dict(id='fixture-base-src', recipe_sha256='c' * 64,
            sources=[dict(url='https://example.invalid/FIXTURE-base.tar', sha256='d' * 64)]))
        graph['build_dependencies'].append(dict(package='fixture-base', source_id='fixture-base-src',
            makedepend=[], checkdepend=[]))
        graph['packages'].append(dict(name='linux-asahi', version='1-1', arch='aarch64', depend=[], provides=[]))
        graph['sources'].append(dict(id='linux-asahi-src', recipe_sha256='e' * 64,
            sources=[dict(url='https://example.invalid/FIXTURE-linux-asahi.tar', sha256='f' * 64)]))
        graph['build_dependencies'].append(dict(package='linux-asahi', source_id='linux-asahi-src',
            makedepend=[], checkdepend=[]))
        for row in graph['build_dependencies']:
            row.update(toolchain=[], owner='SYNTHETIC-owner', disposition='build' if row['package'] == 'alpha' else 'external',
                       hold_reason=None)
        self.graph = graph
        self.f.source = copy.deepcopy(graph)
        self.f.write()
        items = [dict(name=p['name'], version=p['version'], arch=p['arch'], provides=p['provides'], pkgbase=p['name'])
                 for p in graph['packages']]
        advisory = dict(name='AVG-1', packages=['alpha'], status='Fixed', severity='High', type='SYNTHETIC issue',
            affected='1-1', fixed='1-2', issues=['CVE-2026-12345'], advisories=['ASA-202610-1'])
        raws = update_fixture.originals(items=items, groups=[advisory], graph=graph)
        inputs = {}
        for name, raw in raws.items():
            path = self.originals / (name + '.json')
            path.write_bytes(raw)
            inputs[name] = self.ref(path)
        self.selection = dict(schema_version=1, campaign_id='SYNTHETIC-CAMPAIGN', as_of=update_fixture.NOW,
            max_age_hours=24, inputs=inputs, build_graph=self.ref(self.batches / 'input.json'))
        self.selection_path = self.originals / 'selection.json'
        self.put(self.selection_path, self.selection)
        self.store = m.Store(root / 'campaign')

    @staticmethod
    def put(path, value):
        path.write_bytes(m.encoded(value))
        return path

    @staticmethod
    def ref(path):
        return dict(path=str(path), sha256=m.digest(path))

    def prepare(self):
        return m.prepare(self.store, self.ref(self.selection_path))

    def bind(self):
        with self.store.lock():
            return m.bind(self.store, self.ref(self.f.spec_path))

    def verify(self, retry=False):
        with self.store.lock():
            return m.verify(self.store, retry=retry)

    def handoff(self, path=None):
        path = self.release() if path is None else path
        with self.store.lock():
            return m.handoff(self.store, self.ref(path))

    def release(self):
        directory = self.root / 'release-inputs'
        directory.mkdir(exist_ok=True)
        first = self.f.batches['first']
        name = next(iter(first['record']['artifacts']))
        archive = directory / name
        shutil.copyfile(first['output'] / 'artifacts' / name, archive)
        record = dict(schema_version=1, artifact_sha256=m.digest(archive),
            package=dict(name='alpha', version='1-1', arch='aarch64'), source_commit='a' * 40,
            recipe_sha256=first['record']['recipe_inputs']['PKGBUILD'], licenses=['MIT'],
            sources=self.graph['sources'][0]['sources'],
            build=dict(execution='synthetic', architecture='aarch64', environment='SYNTHETIC-fixture',
                       snapshot_id='SYNTHETIC-base'))
        self.put(directory / 'provenance.json', record)
        base = dict(schema_version=1, snapshot_id='SYNTHETIC-base', target_arch='aarch64',
            kind='complete-target-transaction', packages=[
                dict(name='linux-asahi', version='1-1', arch='aarch64', depend=[], provides=[], conflict=[], files=[]),
                dict(name='fixture-base', version='1-1', arch='aarch64', depend=[], provides=[], conflict=[], files=[])])
        self.put(directory / 'base.json', base)
        def local(name):
            return dict(path=name, sha256=m.digest(directory / name))
        spec = dict(schema_version=1, release_id='SYNTHETIC-CAMPAIGN', synthetic=True,
            target_arch='aarch64', repo_name='SYNTHETIC', source_commit='a' * 40,
            base=dict(local('base.json'), snapshot_id='SYNTHETIC-base'),
            packages=[dict(artifact=local(name), provenance=local('provenance.json'))],
            policy=dict(supported_models=['m2-air-13'], selected_packages=['alpha'], protected_packages=['linux-asahi'],
                coordinated_sets=[dict(name='SYNTHETIC-runtime', versions={'fixture-base': '1-1'})]), evidence=[])
        return self.put(directory / 'spec.json', spec)


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='campaign-offline-')
        self.addCleanup(self.temp.cleanup)
        self.f = CampaignFixture(Path(self.temp.name))

    def ready(self):
        self.f.prepare()
        self.f.bind()
        return self.f.verify()

    def test_declared_source_delivery_actual_associations_and_drift(self):
        self.ready()
        path = self.f.release()
        directory = path.parent
        first = self.f.f.batches['first']
        def material(name, raw):
            target = directory / name
            target.write_bytes(raw)
            return dict(id=name, path=name, sha256=m.sha(raw), bytes=len(raw))
        record = dict(package=dict(name='alpha', version='1-1', arch='aarch64',
            sha256=next(iter(first['record']['artifacts'].values()))),
            recipe_key='PKGBUILD', review_status='INCOMPLETE synthetic review; no legal approval',
            bundle=material('source-bundle', self.f.f.body),
            notices=[material('notice', self.f.f.notice)],
            recipe=material('recipe', (first['output'] / 'inputs/PKGBUILD').read_bytes()),
            source_map=material('source-map', m.encoded(first['record']['recipe_inputs'])),
            authorization=material('review', b'SYNTHETIC retained review; gaps remain\n'))
        index = self.f.put(directory / 'index.json', dict(schema_version=1,
            purpose='release-source-delivery', synthetic=True, packages=[record]))
        spec = m.decode(m.read(path))
        spec['source_delivery'] = dict(schema_version=1,
            index=dict(id='index.json', path='index.json', sha256=m.digest(index)))
        self.f.put(path, spec)
        state = self.f.handoff(path)
        receipt = self.f.store.value(state['handoff'])
        self.assertEqual(receipt['source_delivery'], 'CHECKED_DECLARED_ASSOCIATIONS')
        self.assertEqual(receipt['status'], 'SYNTHETIC_HANDOFF_NOT_STAGEABLE')
        for name in ('source-bundle', 'notice', 'recipe', 'source-map', 'review', 'index.json'):
            self.assertIn(str(directory / name), receipt['closure'])
        (directory / 'source-bundle').write_bytes(b'drift')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            self.f.handoff(path)
        self.assertEqual(self.f.store.state()['phases']['handoff'], 'FAILED')
        self.assertIsNone(self.f.store.state()['handoff'])

    def test_release_license_and_build_architecture_projections_cannot_drift(self):
        self.ready()
        for field, value, message in (('licenses', ['UNRELATED'], 'license projection'),
                                       ('architecture', 'x86_64', 'build architecture')):
            path = self.f.release()
            provenance = path.parent / 'provenance.json'
            record = m.decode(m.read(provenance))
            if field == 'licenses':
                record[field] = value
            else:
                record['build'][field] = value
            self.f.put(provenance, record)
            spec = m.decode(m.read(path))
            spec['packages'][0]['provenance']['sha256'] = m.digest(provenance)
            self.f.put(path, spec)
            with self.assertRaisesRegex(ValueError, message):
                self.f.handoff(path)
            self.assertEqual(self.f.store.state()['phases']['handoff'], 'FAILED')

    def test_real_planners_pair_admission_and_release_preflight(self):
        initial = self.f.prepare()
        self.assertEqual(initial['required_packages'], ['alpha'])
        self.assertEqual(initial['build_holds'], [])
        self.assertEqual(initial['phases']['outputs'], 'NOT_RUN')
        self.assertEqual(initial['phases']['security_review'], 'BLOCKED')
        self.f.bind()
        verified = self.f.verify()
        self.assertEqual(verified['phases']['outputs'], 'COMPLETE')
        admitted = self.f.store.value(verified['candidate'])
        self.assertEqual(admitted['status'], 'SYNTHETIC_LOCAL_CANDIDATE')
        self.assertTrue(admitted['packages'][0]['bytes_equal'])
        final = self.f.handoff()
        receipt = self.f.store.value(final['handoff'])
        self.assertEqual(receipt['status'], 'SYNTHETIC_HANDOFF_NOT_STAGEABLE')
        self.assertIsNone(receipt['command'])
        self.assertEqual(receipt['security_review'], 'BLOCKED')
        self.assertEqual(receipt['source_delivery'], 'NOT_DECLARED')
        for phase in ('staging', 'publication', 'installed', 'hardware'):
            self.assertEqual(final['phases'][phase], 'NOT_RUN')
        self.assertFalse(receipt['authenticated'])

    def test_original_planning_bytes_can_be_removed_after_durable_prepare(self):
        self.f.prepare()
        shutil.rmtree(self.f.originals)
        self.f.bind()
        verified = self.f.verify()
        self.assertEqual(verified['phases']['outputs'], 'COMPLETE')
        reopened = m.Store(self.f.store.path)
        with reopened.lock():
            self.assertEqual(reopened.checked(), verified)

    def test_exact_pair_coverage_and_binding_checksum_are_required(self):
        self.f.prepare()
        spec = copy.deepcopy(self.f.f.spec)
        spec['pairs'][0]['package'] = 'fixture-base'
        self.f.put(self.f.f.spec_path, spec)
        with self.assertRaisesRegex(ValueError, 'exact full rebuild pair coverage'):
            self.f.bind()
        self.f.f.write()
        with self.f.store.lock(), self.assertRaisesRegex(ValueError, 'checksum mismatch'):
            m.bind(self.f.store, dict(path=str(self.f.f.spec_path), sha256='0' * 64))
        self.assertIsNone(self.f.store.state()['binding'])

    def test_candidate_semantic_changes_outside_declared_roots_refuse_prepare(self):
        for change in ('version', 'source'):
            with self.subTest(change=change), tempfile.TemporaryDirectory(prefix='campaign-undeclared-change-') as td:
                fixture = CampaignFixture(Path(td))
                if change == 'version':
                    fixture.f.source['packages'][1]['version'] = '2-1'
                else:
                    fixture.f.source['sources'][1]['recipe_sha256'] = '0' * 64
                fixture.f.write()
                fixture.selection['build_graph'] = fixture.ref(fixture.batches / 'input.json')
                fixture.put(fixture.selection_path, fixture.selection)
                with self.assertRaisesRegex(ValueError, 'changed|root|difference|coverage'):
                    fixture.prepare()
                self.assertFalse(fixture.store.path.exists())

    def test_failed_verification_is_journaled_requires_explicit_retry(self):
        self.f.prepare()
        self.f.f.batches['second']['state']['status'] = 'INCOMPLETE'
        self.f.f.batches['second']['state']['packages']['alpha']['status'] = 'FAILED'
        self.f.f.write()
        self.f.bind()
        with self.assertRaisesRegex(ValueError, 'incomplete batch'):
            self.f.verify()
        failed = self.f.store.state()
        self.assertEqual(failed['phases']['outputs'], 'FAILED')
        self.assertEqual(failed['attempts'], 1)
        self.assertIsNone(failed['candidate'])
        self.assertTrue(any(row['state']['phases']['outputs'] == 'RUNNING' for row in self.f.store.history()))
        with self.assertRaisesRegex(ValueError, 'explicit --retry'):
            self.f.verify()
        # The same binding cannot silently reset the bounded retry budget.
        self.assertEqual(self.f.bind()['attempts'], 1)
        for count in (2, 3):
            with self.assertRaisesRegex(ValueError, 'incomplete batch'):
                self.f.verify(retry=True)
            self.assertEqual(self.f.store.state()['attempts'], count)
        with self.assertRaisesRegex(ValueError, 'three verification attempts exhausted'):
            self.f.verify(retry=True)

    def test_new_explicit_receipts_resume_after_failure(self):
        self.f.prepare()
        second = self.f.f.batches['second']['state']
        original = copy.deepcopy(second)
        second['status'] = 'INCOMPLETE'
        second['packages']['alpha']['status'] = 'FAILED'
        self.f.f.write()
        self.f.bind()
        with self.assertRaisesRegex(ValueError, 'incomplete batch'):
            self.f.verify()
        self.f.f.batches['second']['state'] = original
        self.f.f.write()
        rebound = self.f.bind()
        self.assertEqual(rebound['attempts'], 0)
        self.assertEqual(self.f.verify()['phases']['outputs'], 'COMPLETE')

    def test_retry_requires_prior_failure(self):
        self.f.prepare()
        self.f.bind()
        with self.assertRaisesRegex(ValueError, '--retry requires a failed'):
            self.f.verify(retry=True)
        self.assertEqual(self.f.store.state()['attempts'], 0)

    def test_completed_verify_resume_is_idempotent(self):
        verified = self.ready()
        count = len(self.f.store.history())
        self.assertEqual(self.f.verify(), verified)
        self.assertEqual(self.f.verify(), verified)
        self.assertEqual(len(self.f.store.history()), count)
        self.assertEqual(self.f.store.state()['attempts'], 1)

    def test_planner_capacity_hold_remains_blocked_without_output_admission(self):
        self.f.f.source['capacity'] = dict(native_aarch64_slots=None, owner=None, reference=None)
        self.f.f.write()
        self.f.selection['build_graph'] = self.f.ref(self.f.batches / 'input.json')
        self.f.put(self.f.selection_path, self.f.selection)
        state = self.f.prepare()
        self.assertTrue(state['build_holds'])
        self.f.bind()
        with self.assertRaisesRegex(ValueError, 'build plan blocked'):
            self.f.verify()
        final = self.f.store.state()
        self.assertEqual(final['phases']['outputs'], 'BLOCKED')
        self.assertEqual(final['phases']['handoff'], 'NOT_RUN')
        self.assertIsNone(final['candidate'])

    def test_interrupted_running_checkpoint_requires_explicit_retry(self):
        self.f.prepare()
        self.f.bind()
        state = self.f.store.state()
        state['phases']['outputs'] = 'RUNNING'
        state['attempts'] = 1
        with self.f.store.lock():
            self.f.store.commit(state)
        with self.assertRaisesRegex(ValueError, 'explicit --retry'):
            self.f.verify()
        final = self.f.verify(retry=True)
        self.assertEqual(final['phases']['outputs'], 'COMPLETE')
        self.assertEqual(final['attempts'], 2)

    def test_retained_output_drift_cannot_reuse_completed_candidate(self):
        self.ready()
        (self.f.f.batches['second']['output'] / 'build.log').write_text('CHANGED\n')
        with self.assertRaisesRegex(ValueError, 'snapshot changed'):
            self.f.handoff()
        final = self.f.store.state()
        self.assertEqual(final['phases']['handoff'], 'FAILED')
        self.assertIsNone(final['handoff'])

    def test_batch_checkpoint_drift_cannot_reuse_binding(self):
        self.f.prepare()
        self.f.bind()
        path = self.f.f.batches['second']['path'] / 'state.json'
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaisesRegex(ValueError, 'selected input checksum mismatch'):
            self.f.verify()
        self.assertEqual(self.f.store.state()['phases']['outputs'], 'FAILED')

    def test_concurrent_command_refuses_without_journal_mutation(self):
        self.f.prepare()
        count = len(self.f.store.history())
        with self.f.store.lock():
            result = subprocess.run([sys.executable, '-B', str(SCRIPT), 'status',
                '--campaign', str(self.f.store.path)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 2)
        self.assertIn('owned by another command', result.stderr)
        self.assertEqual(len(self.f.store.history()), count)

    def test_retained_object_drift_refused_before_new_event(self):
        state = self.f.prepare()
        self.f.store.object_path(state['build_graph']).write_bytes(b'{}\n')
        with self.f.store.lock(), self.assertRaisesRegex(ValueError, 'campaign object drift'):
            self.f.store.checked()
        self.assertEqual(len(self.f.store.history()), 1)

    def test_implementation_binding_mismatch_refuses_resume(self):
        state = self.f.prepare()
        state['implementation']['scripts/release/release.py'] = '0' * 64
        with self.f.store.lock():
            self.f.store.commit(state)
        with self.f.store.lock(), self.assertRaisesRegex(ValueError, 'implementation drift'):
            self.f.store.checked()

    def test_journal_link_drift_refuses_resume(self):
        self.f.prepare()
        self.f.bind()
        event = self.f.store.path / 'events/000002.json'
        value = m.decode(event.read_bytes())
        value['previous'] = '0' * 64
        event.write_bytes(m.encoded(value))
        with self.assertRaisesRegex(ValueError, 'journal chain mismatch'):
            self.f.store.state()

    def test_release_source_projection_mismatch_stays_failed(self):
        self.ready()
        path = self.f.release()
        spec = m.decode(path.read_bytes())
        provenance = path.parent / 'provenance.json'
        row = m.decode(provenance.read_bytes())
        row['sources'][0]['sha256'] = '0' * 64
        self.f.put(provenance, row)
        spec['packages'][0]['provenance']['sha256'] = m.digest(provenance)
        self.f.put(path, spec)
        with self.assertRaisesRegex(ValueError, 'release source projection differs'):
            self.f.handoff(path)
        self.assertEqual(self.f.store.state()['phases']['handoff'], 'FAILED')

    def test_release_dependency_failure_stays_failed(self):
        self.ready()
        path = self.f.release()
        spec = m.decode(path.read_bytes())
        base_path = path.parent / 'base.json'
        base = m.decode(base_path.read_bytes())
        base['packages'][1]['version'] = '0-1'
        self.f.put(base_path, base)
        spec['base']['sha256'] = m.digest(base_path)
        self.f.put(path, spec)
        with self.assertRaisesRegex(Exception, 'unsatisfied dependency'):
            self.f.handoff(path)
        self.assertEqual(self.f.store.state()['phases']['handoff'], 'FAILED')

    def test_release_snapshot_must_match_pinned_campaign_graph(self):
        self.ready()
        path = self.f.release()
        spec = m.decode(path.read_bytes())
        base_path = path.parent / 'base.json'
        base = m.decode(base_path.read_bytes())
        base['snapshot_id'] = 'DIFFERENT-snapshot'
        self.f.put(base_path, base)
        spec['base'].update(snapshot_id=base['snapshot_id'], sha256=m.digest(base_path))
        self.f.put(path, spec)
        with self.assertRaisesRegex(ValueError, 'snapshot'):
            self.f.handoff(path)
        self.assertIsNone(self.f.store.state()['handoff'])

    def test_release_baseline_drift_cannot_be_hidden_by_fresh_checksums(self):
        self.ready()
        path = self.f.release()
        spec = m.decode(path.read_bytes())
        base_path = path.parent / 'base.json'
        base = m.decode(base_path.read_bytes())
        # This does not break alpha's dependency or the declared fixture-base
        # coordinated set; only the new campaign graph/transaction join catches it.
        base['packages'][0]['version'] = '2-1'
        self.f.put(base_path, base)
        spec['base']['sha256'] = m.digest(base_path)
        self.f.put(path, spec)
        with self.assertRaisesRegex(ValueError, 'transaction|graph'):
            self.f.handoff(path)
        self.assertIsNone(self.f.store.state()['handoff'])

    def test_synthetic_label_cannot_be_cleared_in_release_handoff(self):
        self.ready()
        path = self.f.release()
        spec = m.decode(path.read_bytes())
        spec['synthetic'] = False
        self.f.put(path, spec)
        with self.assertRaisesRegex(ValueError, 'synthetic labels differ'):
            self.f.handoff(path)


if __name__ == '__main__':
    unittest.main()
