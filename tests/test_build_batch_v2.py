# SPDX-License-Identifier: MIT
"""Offline batch controls; no Docker, acquisition, builds, or native credit."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from test_batch_v2_fixture import Fixture, FakeBuilder, INTERFACE, NAMES, ROOT

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/maintenance/build_batch_v2.py'
spec = importlib.util.spec_from_file_location('batch_v2_under_test', SCRIPT)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class OfflineBatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='batch-v2-', dir=Path(__file__).parent)
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.fixture = Fixture(m, self.path)
        transport = patch.object(m.SM.cache, 'transport', side_effect=AssertionError('source acquisition forbidden'))
        self.transport = transport.start(); self.addCleanup(transport.stop)

    def run_batch(self, admitted, output, **kwargs):
        return m.run(admitted, output, builder_interface=INTERFACE, **kwargs)

    def stage(self, task, out):
        out.mkdir(mode=0o700)
        binding = task['offline_sources']
        prepared = m.SM.prepare(self.fixture.reports[task['package']], binding['source_plan'],
            binding['source_plan_sha256'], binding['source_catalog'], binding['source_cache'])
        selection = m.SM.stage(prepared, out / 'source-material')
        pins = {'source-material/' + str(p.relative_to(out / 'source-material')):m.B.digest(p)
                for p in (out / 'source-material').rglob('*') if p.is_file()}
        (out / 'provenance.json').write_bytes(m.encoded(dict(source_material=selection, files=pins)))
        return selection

    def test_deterministic_c01_admission_is_offline_and_preserves_cache(self):
        before = self.fixture.cache_pin()
        with patch.object(m.SM.cache, 'run', wraps=m.SM.cache.run) as run:
            admitted, again = self.fixture.admit(), self.fixture.admit()
        self.assertEqual(m.encoded(admitted), m.encoded(again))
        self.assertEqual(admitted['builder_interface'], INTERFACE)
        self.assertEqual(admitted['sources_sha256'], m.B.digest(self.fixture.sources))
        self.assertEqual(admitted['planned_packages'], list(NAMES))
        self.assertTrue(all(not g['held'] for g in admitted['groups']))
        self.assertTrue(all(t['prerequisites'] == [] for t in admitted['tasks'].values()))
        self.assertGreaterEqual(run.call_count, 4)
        self.assertTrue(all(c.kwargs.get('offline') is True for c in run.call_args_list))
        self.assertEqual(before, self.fixture.cache_pin()); self.transport.assert_not_called()
        tasks = admitted['tasks']
        self.assertNotEqual(tasks[NAMES[0]]['recipe_inputs']['PKGBUILD'], tasks[NAMES[1]]['recipe_inputs']['PKGBUILD'])
        for name in NAMES:
            with self.subTest(package=name):
                task = tasks[name]
                self.assertEqual(task['mode'], 'emulated')
                self.assertEqual(task['offline_sources']['catalog_sha256'], m.B.digest(self.fixture.catalog))
                out = self.path / ('material-' + name)
                self.assertEqual(task['source_material'], self.stage(task, out))
                self.assertFalse(task['source_material']['legal_acceptance'])
                self.assertFalse(task['source_material']['source_completeness_accepted'])
                self.assertEqual(m.B.digest(out / 'source-material/srcdest/zlib-1.3.2.tar.gz'), self.fixture.row['material']['sha256'])
                self.assertEqual(task['source_material_files'], m.B.snapshot(out / 'source-material'))
                m.verify_material(task, out)

    def test_explicit_interface_required_and_wrong_interface_refused(self):
        args = self.fixture.arguments()
        with self.assertRaises(TypeError): m.admission(*args)
        with self.assertRaises(ValueError): m.admission(*args, builder_interface='legacy')

    def test_bindings_interface_is_independent(self):
        self.fixture.sources_value['builder_interface'] = 'legacy'
        with self.assertRaises(ValueError): self.fixture.admit()

    def test_selected_binding_hash(self):
        args = list(self.fixture.arguments()); args[-1] = '0' * 64
        with self.assertRaises(ValueError): m.admission(*args, builder_interface=INTERFACE)

    def test_every_task_needs_binding(self):
        del self.fixture.sources_value['tasks'][NAMES[1]]
        with self.assertRaises(ValueError): self.fixture.admit()

    def test_extra_binding_refused(self):
        self.fixture.sources_value['tasks']['unplanned'] = copy.deepcopy(self.fixture.sources_value['tasks'][NAMES[0]])
        with self.assertRaises(ValueError): self.fixture.admit()

    def test_plan_must_bind_its_own_recipe(self):
        other = self.fixture.sources_value['tasks'][NAMES[1]]
        self.fixture.sources_value['tasks'][NAMES[0]].update(source_plan=other['source_plan'], source_plan_sha256=other['source_plan_sha256'])
        with self.assertRaises(ValueError): self.fixture.admit()

    def test_plan_pin_mismatch(self):
        self.fixture.sources_value['tasks'][NAMES[0]]['source_plan_sha256'] = '0' * 64
        with self.assertRaises(ValueError): self.fixture.admit()

    def test_missing_object_is_not_acquired(self):
        (self.fixture.cache / 'objects' / self.fixture.row['material']['sha256']).unlink()
        with self.assertRaises(ValueError): self.fixture.admit()
        self.transport.assert_not_called()

    def test_changed_object_is_not_repaired(self):
        (self.fixture.cache / 'objects' / self.fixture.row['material']['sha256']).write_bytes(b'wrong source')
        with self.assertRaises(ValueError): self.fixture.admit()
        self.transport.assert_not_called()

    def test_missing_receipt_is_not_repaired(self):
        receipt = next((self.fixture.cache / 'receipts').iterdir()); receipt.unlink()
        with self.assertRaises(ValueError): self.fixture.admit()
        self.assertFalse(receipt.exists()); self.transport.assert_not_called()

    def test_catalog_pin_independently_checked(self):
        catalog = json.loads(self.fixture.catalog.read_bytes()); catalog['sources'][0]['revision'] = 'changed'
        self.fixture.catalog.write_bytes(m.encoded(catalog))
        with self.assertRaises(ValueError): self.fixture.admit()

    def test_unavailable_build_dependency_stays_refused(self):
        self.fixture.remove_external('gcc')
        with self.assertRaises(ValueError): self.fixture.admit()

    def test_ambiguous_compiler_provider_stays_refused(self):
        self.fixture.add_competing_gcc()
        with self.assertRaises(ValueError): self.fixture.admit()

    def test_production_command_is_only_versioned_offline_builder(self):
        admitted = self.fixture.admit(); task = admitted['tasks'][NAMES[0]]
        with patch.object(m.subprocess, 'Popen') as popen:
            m.Builder(admitted).start(task, self.path / 'owned-build', None, 17)
        command = popen.call_args.args[0]
        self.assertIn(str(ROOT / 'scripts/build/build_v2.py'), command)
        self.assertNotIn(str(ROOT / 'scripts/build/build.py'), command)
        self.assertEqual(command[command.index('--network') + 1], 'none')
        for option,key in (('--source-plan','source_plan'), ('--source-plan-sha256','source_plan_sha256'),
                ('--source-catalog','source_catalog'), ('--source-cache','source_cache')):
            self.assertEqual(command[command.index(option) + 1], task['offline_sources'][key])
        self.assertEqual(popen.call_args.kwargs['pass_fds'], (17,))
        self.assertEqual(m.Builder.kind, 'PINNED_OCI_BUILD_V2_OFFLINE_SOURCES')

    def test_material_verifier_checks_actual_retained_bytes(self):
        task = self.fixture.admit()['tasks'][NAMES[0]]; out = self.path / 'material'
        self.stage(task, out); m.verify_material(task, out)
        archive = out / 'source-material/srcdest/zlib-1.3.2.tar.gz'
        archive.chmod(0o600); archive.write_bytes(b'changed source')
        with self.assertRaises(ValueError): m.verify_material(task, out)

    def test_material_verifier_rejects_extra_file(self):
        task = self.fixture.admit()['tasks'][NAMES[0]]; out = self.path / 'material'
        self.stage(task, out); (out / 'source-material/extra').write_text('stale')
        with self.assertRaises(ValueError): m.verify_material(task, out)

    def test_two_finite_batches_complete_with_independent_real_c01_inputs(self):
        admitted = self.fixture.admit(); before = self.fixture.cache_pin()
        for index in range(2):
            builder = FakeBuilder(m)
            state = self.run_batch(admitted, self.path / f'batch-{index}', builder=builder)
            self.assertEqual(state['status'], 'COMPLETE')
            self.assertEqual(state['kind'], builder.kind)
            self.assertEqual(state['hardware_status'], 'NOT RUN')
            self.assertEqual(sorted(builder.started), list(NAMES))
            self.assertTrue(all(len(r['attempts']) == 1 for r in state['packages'].values()))
        self.assertEqual(before, self.fixture.cache_pin()); self.transport.assert_not_called()

    def test_failed_baseline_preserves_lto_and_named_retry_is_isolated(self):
        admitted = self.fixture.admit(); builder = FakeBuilder(m, fail=[NAMES[0]])
        output = self.path / 'failure-resume'; failed = self.run_batch(admitted, output, builder=builder)
        self.assertEqual({p:r['status'] for p,r in failed['packages'].items()}, {NAMES[0]:'FAILED',NAMES[1]:'SUCCESS'})
        lto = copy.deepcopy(failed['packages'][NAMES[1]]); builder.fail.clear()
        final = self.run_batch(admitted, output, resume=True, retry=[NAMES[0]], builder=builder)
        self.assertEqual(final['status'], 'COMPLETE'); self.assertEqual(final['packages'][NAMES[1]], lto)
        self.assertEqual([len(final['packages'][p]['attempts']) for p in NAMES], [2,1])
        self.assertEqual(builder.started.count(NAMES[1]), 1); self.assertEqual(builder.started.count(NAMES[0]), 2)

    def test_failed_resume_refuses_plan_drift_before_spawn(self):
        admitted = self.fixture.admit(); builder = FakeBuilder(m, fail=[NAMES[0]])
        output = self.path / 'plan-drift'; self.run_batch(admitted, output, builder=builder)
        Path(self.fixture.sources_value['tasks'][NAMES[0]]['source_plan']).write_bytes(b'{}\n')
        before = list(builder.started)
        with self.assertRaises(ValueError): self.run_batch(admitted, output, resume=True, retry=[NAMES[0]], builder=builder)
        self.assertEqual(builder.started, before)

    def test_failed_resume_refuses_cache_drift_before_spawn(self):
        admitted = self.fixture.admit(); builder = FakeBuilder(m, fail=[NAMES[0]])
        output = self.path / 'cache-drift'; self.run_batch(admitted, output, builder=builder)
        (self.fixture.cache / 'objects' / self.fixture.row['material']['sha256']).write_bytes(b'changed source')
        before = list(builder.started)
        with self.assertRaises(ValueError): self.run_batch(admitted, output, resume=True, retry=[NAMES[0]], builder=builder)
        self.assertEqual(builder.started, before)

    def test_wrong_run_interface_cannot_dispatch_even_fake(self):
        admitted = self.fixture.admit(); builder = FakeBuilder(m)
        with self.assertRaises(ValueError): m.run(admitted, self.path / 'refused', builder=builder, builder_interface='legacy')
        self.assertFalse(builder.started); self.assertFalse((self.path / 'refused').exists())

    def test_derived_lto_starts_after_baseline_success_is_verified(self):
        self.fixture.add_reviewed_baseline_prerequisite()
        admitted = self.fixture.admit(); builder = FakeBuilder(m)
        self.assertEqual(admitted['tasks'][NAMES[1]]['prerequisites'], [NAMES[0]])
        state = self.run_batch(admitted, self.path / 'ordered', builder=builder)
        self.assertEqual(state['status'], 'COMPLETE')
        self.assertEqual(builder.events, [('start', NAMES[0]), ('verified', NAMES[0]),
                                         ('start', NAMES[1]), ('verified', NAMES[1])])
        self.assertEqual(state['packages'][NAMES[0]]['attempts'][0]['artifact_sha256'],
                         admitted['tasks'][NAMES[1]]['prerequisite_artifacts'][NAMES[0]])

    def test_derived_lto_wrong_image_artifact_pin_blocks_before_spawn(self):
        self.fixture.add_reviewed_baseline_prerequisite(artifact_sha='0' * 64)
        admitted = self.fixture.admit(); builder = FakeBuilder(m)
        state = self.run_batch(admitted, self.path / 'wrong-pin', builder=builder)
        self.assertEqual(state['status'], 'INCOMPLETE')
        self.assertEqual(state['packages'][NAMES[0]]['status'], 'SUCCESS')
        self.assertEqual(state['packages'][NAMES[1]]['status'], 'BLOCKED')
        self.assertEqual(builder.started, [NAMES[0]])

    def test_derived_lto_is_not_started_after_failed_baseline(self):
        self.fixture.add_reviewed_baseline_prerequisite()
        admitted = self.fixture.admit(); builder = FakeBuilder(m, fail=[NAMES[0]])
        state = self.run_batch(admitted, self.path / 'failed-dependency', builder=builder)
        self.assertEqual(state['status'], 'INCOMPLETE')
        self.assertEqual(state['packages'][NAMES[0]]['status'], 'FAILED')
        self.assertEqual(state['packages'][NAMES[1]]['status'], 'BLOCKED')
        self.assertEqual(builder.started, [NAMES[0]])


if __name__ == '__main__': unittest.main()
