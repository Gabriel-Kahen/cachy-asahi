"""Synthetic pinned-artifact and mocked workload checks; no benchmark execution."""
import gzip
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import zlib_workload as w


class ZlibWorkloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='zlib-adapter-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.process = patch.object(w.subprocess, 'run', side_effect=AssertionError('No real subprocess or native binary'))
        self.addCleanup(self.process.stop); self.process.start()

    def pin_manifest(self, args):
        variant, source, _ = w.EXPERIMENTS[args.experiment]
        update = patch.dict(w.EXPERIMENTS, {args.experiment: (variant, source, w.sha(args.archive_manifest.read_bytes()))})
        self.addCleanup(update.stop); update.start()

    def fixture(self, experiment='ARM-C04'):
        base = self.root / experiment; base.mkdir()
        root = base / 'compiled'; root.mkdir()
        variant, source, _ = w.EXPERIMENTS[experiment]
        for name in ('baseline', variant):
            directory = root / (name + '-1'); directory.mkdir()
            binary = directory / 'minigzip'; binary.write_bytes(('synthetic non-binary ' + name).encode()); binary.chmod(0o755)
        corpus = root / 'corpus'; corpus.mkdir()
        heldout = b'explicit public held-out fixture\n'
        (corpus / 'heldout-source.bin').write_bytes(heldout)
        (corpus / 'manifest.json').write_text(json.dumps({'files': [
            {'path': 'heldout-source.bin', 'role': 'heldout', 'kind': 'input', 'bytes': len(heldout), 'sha256': w.sha(heldout)}]}))
        files = {str(path.relative_to(root)): w.sha(path.read_bytes()) for path in root.rglob('*') if path.is_file()}
        archive = base / 'archive-manifest.json'
        archive.write_text(json.dumps({'purpose': experiment + '-same-job-followup', 'source_commit': source,
                                      'source_sha256': w.SOURCE_SHA, 'development_only': True,
                                      'selected_for_release': False, 'files': files}))
        operator = {'experiment_id': 'synthetic-fixture-' + experiment, 'machine_id': 'synthetic-M2-id', 'base_id': 'synthetic-base',
                    'execution_context': 'physical', 'hardware_gate_evidence': str(base / 'operator-gate.json'),
                    'order': ['baseline', 'candidate', 'candidate', 'baseline'] * 3, 'minimum_trials': 6,
                    'timeout_seconds': 300, 'sample_seconds': .5,
                    'controls': {'power_source': 'synthetic AC', 'display_config': 'synthetic fixed', 'brightness': 'synthetic fixed',
                                 'cache_mode': 'synthetic warm', 'background_load': 'synthetic none', 'warmup': 'synthetic procedure',
                                 'ambient_C': [20, 25], 'thermal_start_C': [30, 40], 'battery_soc_percent': [40, 60]},
                    'thresholds': {'minimum_elapsed_improvement_pct': 5, 'maximum_elapsed_range_pct': 10}}
        operator_path = base / 'operator.json'; operator_path.write_text(json.dumps(operator))
        args = SimpleNamespace(experiment=experiment, artifact_root=root, archive_manifest=archive, operator_config=operator_path,
                               output=base / 'config.json', corpus_manifest=corpus / 'manifest.json', input=corpus / 'heldout-source.bin',
                               payload_bytes=256, iterations=2)
        self.pin_manifest(args)
        return args, operator

    def prepare_run(self, args):
        cwd = args.artifact_root.parent / 'work'; cwd.mkdir()
        paths = patch.object(w.Path, 'cwd', return_value=cwd)
        self.addCleanup(paths.stop); paths.start()
        env = patch.dict(w.os.environ, {'ZLIB_MINIGZIP': str(args.artifact_root / 'baseline-1/minigzip')})
        self.addCleanup(env.stop); env.start()
        return cwd

    def child(self, calls, fault=None):
        def run(argv, **kwargs):
            calls.append((argv, kwargs))
            self.assertEqual(kwargs['timeout'], 60)
            self.assertNotIn('start_new_session', kwargs)
            self.assertNotIn('shell', kwargs)
            data = kwargs['stdin'].read()
            if fault == 'timeout':
                raise subprocess.TimeoutExpired(argv, 60)
            if fault == 'exit':
                return SimpleNamespace(returncode=1)
            output = gzip.compress(data, mtime=0) if argv[-1] == '-6' else gzip.decompress(data)
            if fault == 'corrupt-decode' and argv[-1] == '-d':
                output = b'bad decoded bytes'
            kwargs['stdout'].write(output)
            return SimpleNamespace(returncode=0)
        return run

    def test_all_four_configs_reuse_existing_harness_and_exact_artifact_selection(self):
        for experiment in w.EXPERIMENTS.copy():
            with self.subTest(experiment=experiment):
                args, operator = self.fixture(experiment)
                config = w.prepare_config(args)
                self.assertEqual(config['controls'], operator['controls'])
                self.assertEqual(config['thresholds'], operator['thresholds'])
                self.assertEqual(config['hardware_gate_evidence'], operator['hardware_gate_evidence'])
                self.assertEqual(config['allowed_state_changes'], [])
                self.assertEqual(config['env'], {'LC_ALL': 'C'})
                self.assertIn(config['argv'][0], config['inputs'])
                self.assertEqual(config['argv'][1:3], ['-B', str(Path(w.__file__).resolve())])
                self.assertIn(str(Path(w.benchmark.__file__).resolve()), config['inputs'])
                for variant in ('baseline', 'candidate'):
                    self.assertEqual(config['variant_env'][variant], {'ZLIB_MINIGZIP': config['change'][variant]})
                    self.assertEqual(config['variant_inputs'][variant], [config['change'][variant]])
                self.assertEqual(json.loads(args.output.read_text()), config)

    def test_changed_manifest_source_binary_or_heldout_pin_is_refused_without_output(self):
        args, _ = self.fixture()
        original = args.archive_manifest.read_bytes()
        args.archive_manifest.write_bytes(original + b' ')
        with self.assertRaisesRegex(ValueError, 'manifest hash'):
            w.prepare_config(args)
        args.archive_manifest.write_bytes(original)
        receipt = json.loads(original); receipt['source_commit'] = '0' * 40
        args.archive_manifest.write_text(json.dumps(receipt)); self.pin_manifest(args)
        with self.assertRaisesRegex(ValueError, 'source'):
            w.prepare_config(args)
        args.archive_manifest.write_bytes(original); self.pin_manifest(args)
        binary = args.artifact_root / 'baseline-1/minigzip'; binary.write_bytes(b'replaced')
        with self.assertRaisesRegex(ValueError, 'file hash'):
            w.prepare_config(args)
        self.assertFalse(args.output.exists())

    def test_training_data_and_wrong_experiment_are_refused(self):
        args, _ = self.fixture()
        args.experiment = 'ARM-C02'
        with self.assertRaisesRegex(ValueError, 'experiment'):
            w.prepare_config(args)
        args.experiment = 'ARM-C04'
        corpus = json.loads(args.corpus_manifest.read_text()); corpus['files'][0]['role'] = 'train'
        args.corpus_manifest.write_text(json.dumps(corpus))
        receipt = json.loads(args.archive_manifest.read_text())
        receipt['files']['corpus/manifest.json'] = w.sha(args.corpus_manifest.read_bytes())
        args.archive_manifest.write_text(json.dumps(receipt)); self.pin_manifest(args)
        with self.assertRaisesRegex(ValueError, 'never training'):
            w.prepare_config(args)

    def test_heldout_bytes_and_manifest_row_drift_are_refused(self):
        args, _ = self.fixture()
        before = args.input.read_bytes(); args.input.write_bytes(before + b'changed')
        with self.assertRaisesRegex(ValueError, 'file hash'):
            w.prepare_config(args)
        args.input.write_bytes(before)
        corpus = json.loads(args.corpus_manifest.read_text()); corpus['files'][0]['bytes'] += 1
        args.corpus_manifest.write_text(json.dumps(corpus))
        receipt = json.loads(args.archive_manifest.read_text())
        receipt['files']['corpus/manifest.json'] = w.sha(args.corpus_manifest.read_bytes())
        args.archive_manifest.write_text(json.dumps(receipt)); self.pin_manifest(args)
        with self.assertRaisesRegex(ValueError, 'corpus bytes'):
            w.prepare_config(args)

    def test_missing_operator_fields_bad_budgets_and_adapter_overrides_are_refused(self):
        args, operator = self.fixture()
        altered = [{k: v for k, v in operator.items() if k != 'thresholds'},
                   {**operator, 'execution_context': 'unknown'},
                   {**operator, 'thresholds': {}}, {**operator, 'variant_env': {}},
                   {**operator, 'allowed_state_changes': ['kernel']}]
        for config in altered:
            args.operator_config.write_text(json.dumps(config))
            with self.subTest(config=config), self.assertRaises(ValueError):
                w.prepare_config(args)
        self.assertFalse(args.output.exists())

    def test_successful_bounded_roundtrip_uses_only_selected_binary_and_cwd_outputs(self):
        args, _ = self.fixture(); cwd = self.prepare_run(args); calls = []
        with patch.object(w.subprocess, 'run', side_effect=self.child(calls)), patch.object(w.sys, 'stdout', io.StringIO()):
            report = w.run_workload(args)
        self.assertEqual(len(calls), 4)
        self.assertEqual([argv[-1] for argv, _ in calls], ['-6', '-d', '-6', '-d'])
        self.assertEqual(report['payload_bytes'], 256)
        self.assertEqual(len(report['checks']), 2)
        self.assertEqual(report['optimization_acceptance'], 'NOT RUN')
        self.assertIn('process startup', report['timing_scope'])
        self.assertTrue(all(Path(kwargs['stdout'].name).parent == cwd for _, kwargs in calls))
        self.assertFalse((cwd / 'encoded.gz').exists())

    def test_child_nonzero_timeout_or_wrong_decoded_bytes_cannot_pass(self):
        for index, fault in enumerate(('exit', 'timeout', 'corrupt-decode')):
            args, _ = self.fixture(('ARM-C01', 'ARM-C02', 'ARM-C03')[index]); self.prepare_run(args)
            with self.subTest(fault=fault), patch.object(w.subprocess, 'run', side_effect=self.child([], fault)), \
                 self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                w.run_workload(args)

    def test_independent_gzip_check_rejects_truncated_stream_even_after_zero_child_exits(self):
        args, _ = self.fixture(); self.prepare_run(args)
        def invalid(argv, **kwargs):
            data = kwargs['stdin'].read()
            if argv[-1] == '-6':
                kwargs['stdout'].write(gzip.compress(data, mtime=0)[:-8])
            else:
                heldout = args.input.read_bytes()
                kwargs['stdout'].write((heldout * 100)[:args.payload_bytes])
            return SimpleNamespace(returncode=0)
        with patch.object(w.subprocess, 'run', side_effect=invalid), self.assertRaisesRegex(ValueError, 'roundtrip differs'):
            w.run_workload(args)

    def test_excess_encoded_output_is_rejected_before_decoder_runs(self):
        args, _ = self.fixture(); self.prepare_run(args); calls = []
        def too_large(argv, **kwargs):
            calls.append(argv)
            kwargs['stdout'].truncate(256 + 1024**2 + 1)
            return SimpleNamespace(returncode=0)
        with patch.object(w, 'MAX_PAYLOAD', 256), patch.object(w.subprocess, 'run', side_effect=too_large), \
             self.assertRaisesRegex(ValueError, 'bounded regular'):
            w.run_workload(args)
        self.assertEqual(len(calls), 1)

    def test_runtime_rechecks_manifest_and_requires_empty_cwd_and_closed_binary(self):
        args, _ = self.fixture(); cwd = self.prepare_run(args)
        args.archive_manifest.write_text(args.archive_manifest.read_text() + '\n')
        with self.assertRaisesRegex(ValueError, 'manifest hash'):
            w.run_workload(args)
        self.pin_manifest(args)
        with patch.dict(w.os.environ, {'ZLIB_MINIGZIP': '/usr/bin/gzip'}), self.assertRaisesRegex(ValueError, 'pinned experiment'):
            w.run_workload(args)
        (cwd / 'preexisting').write_text('preserve')
        with self.assertRaisesRegex(ValueError, 'empty isolated'):
            w.run_workload(args)

    def test_payload_and_iteration_bounds_refuse_before_artifact_access(self):
        for size, count in ((0, 1), (w.MAX_PAYLOAD + 1, 1), (1, 0), (1, 33), (True, 1)):
            with self.subTest(size=size, count=count), self.assertRaises(ValueError):
                w.bounds(size, count)


if __name__ == '__main__':
    unittest.main()
