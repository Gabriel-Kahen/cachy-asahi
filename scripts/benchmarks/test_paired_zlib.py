# SPDX-License-Identifier: MIT
"""Real host subprocess controls; fixture programs never represent ARM artifacts."""
import copy
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch
import benchmark as B
import paired_zlib as P
import paired_zlib_v2 as P2

HERE = Path(__file__).resolve().parent
BASE = HERE.parents[3]


def fixture(root):
    root.mkdir(parents=True)
    artifacts = root / 'artifacts'
    artifacts.mkdir()
    for name in ('baseline-1', 'lto-1'):
        folder = artifacts / name
        folder.mkdir()
        binary = folder / 'minigzip'
        binary.write_text('#!' + sys.executable + '\nimport gzip,sys\ndata=sys.stdin.buffer.read()\n'
                          'sys.stdout.buffer.write(gzip.decompress(data) if sys.argv[-1]=="-d" else gzip.compress(data,mtime=0))\n# ' + name + '\n')
        binary.chmod(0o755)
    corpus = artifacts / 'corpus'
    corpus.mkdir()
    heldout = b'Control-only public fixture: no ARM or M2 measurement.\n' * 128
    (corpus / 'heldout-source.bin').write_bytes(heldout)
    (corpus / 'manifest.json').write_text(json.dumps({'control_only': True, 'heldout_sha256': B.digest(corpus / 'heldout-source.bin')}))
    manifest = root / 'fixture.json'
    manifest.write_text(json.dumps({'files': {str(p.relative_to(artifacts)): B.digest(p) for p in artifacts.rglob('*') if p.is_file()}}))
    driver = root / 'control_driver.py'
    driver.write_text('''import contextlib,io,json,os,sys
from pathlib import Path
from types import SimpleNamespace as NS
sys.path.insert(0,sys.argv[1])
import zlib_workload as Z
root=Path(sys.argv[2]);manifest=Path(sys.argv[3]);pins=json.loads(manifest.read_text())['files']
for name,digest in pins.items():
 assert Z.sha((root/name).read_bytes())==digest
heldout=(root/'corpus/heldout-source.bin').read_bytes()
# Test-only input seam: real production materials() and original pins stay intact.
Z.materials=lambda *args: ('ARM-C01',root,heldout)
a=NS(payload_bytes=32768,iterations=1,corpus_manifest=root/'corpus/manifest.json',input=root/'corpus/heldout-source.bin',archive_manifest=manifest)
with contextlib.redirect_stdout(io.StringIO()):r=Z.run_workload(a)
r.update(control_only=True,experiment='CONTROL_FIXTURE')
print(json.dumps(r))
''')
    baseline, candidate = (str(artifacts / n / 'minigzip') for n in ('baseline-1', 'lto-1'))
    controls = dict(power_source='control unqualified', display_config='uncontrolled host', brightness='unmeasured',
                    cache_mode='warm fixture', background_load='uncontrolled host', warmup='one excluded ABBA block',
                    ambient_C=[0, 100], thermal_start_C=[0, 100], battery_soc_percent=[0, 100])
    config = dict(experiment_id='paired-control', machine_id='host-control-only', base_id='live-host-control',
                  workload_id='gzip-fixture', execution_context='unknown',
                  change=dict(variable='fixture artifact path', environment_key='ZLIB_MINIGZIP', baseline=baseline,
                              candidate=candidate, rationale='identical algorithm controls only; no gain claim'),
                  argv=[str(Path(sys.executable).resolve()), str(driver), str(HERE), str(artifacts), str(manifest)],
                  inputs=[str(Path(sys.executable).resolve()), str(driver), str(manifest),
                          str(HERE / 'paired_zlib.py'), str(HERE / 'zlib_workload.py'), str(corpus / 'heldout-source.bin')],
                  variant_inputs=dict(baseline=[baseline], candidate=[candidate]),
                  variant_env=dict(baseline={'ZLIB_MINIGZIP': baseline}, candidate={'ZLIB_MINIGZIP': candidate}),
                  order=P.ORDER, minimum_trials=6, timeout_seconds=5, sample_seconds=.1,
                  controls=controls, thresholds=dict(minimum_elapsed_improvement_pct=5, maximum_elapsed_range_pct=100),
                  allowed_state_changes=[])
    identity = B.live_identity('unknown')
    record = {k: v for k, v in identity.items() if k not in ('packages', 'repositories')}
    record.update(packages=dict(returncode=0, stdout=identity['packages']) if identity['packages'] is not None else dict(returncode=1),
                  repositories=dict(sync_databases=identity['repositories']))
    state = root / 'state.json'
    B.write_json(state, record)
    cfg = root / 'config.json'
    B.write_json(cfg, config)
    plan = root / 'plan.json'
    B.freeze(cfg, state, state, plan)
    conditions = root / 'conditions'
    conditions.mkdir()
    condition = controls | dict(ambient_C=20, thermal_start_C=20, battery_soc_percent=50,
                               operator='automated control fixture', notes='Values are synthetic; sensor data is raw host-only.')
    for row in P.schedule(config, 1):
        B.write_json(conditions / (row['name'] + '.json'), condition)
    return NS(plan=plan, conditions_root=conditions, output=root / 'session', warmup_blocks=1,
              session_seconds=180, control_only=True)


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_real_end_to_end_correctness_warmup_and_twelve_measured_slots(self):
        args = fixture(self.root / 'complete')
        r = P.run(args)
        self.assertEqual(r['status'], 'COMPLETE_CONTROL_ONLY', r.get('error'))
        self.assertEqual(len(r['completed']), 18)
        comparison = B.read_json(args.output / 'comparison.json')
        self.assertEqual(len(comparison['trial_bindings']), 12)
        self.assertEqual(comparison['summary_seconds']['baseline']['n'], 6)
        self.assertEqual(comparison['summary_seconds']['candidate']['n'], 6)
        self.assertEqual([x['variant'] for x in r['completed'][6:]], P.ORDER)
        self.assertEqual(r['optimization_acceptance'], 'NOT RUN')
        self.assertTrue(all(x['workload']['control_only'] for x in r['completed']))
        self.assertEqual(len({B.read_json(Path(x['trial']['path']))['cwd'] for x in r['completed']}), 18)
        # Retain this one real bounded run outside temporary paths when requested.
        target = os.environ.get('PAIRED_CONTROL_EVIDENCE')
        if target:
            import shutil
            shutil.copytree(args.output.parent, target)

    def test_prepare_composes_original_config_and_freeze_with_wrapper_pin(self):
        from test_zlib_workload import ZlibWorkloadTests
        # Reuse exact source-adapter fixture controls, with only its manifest pin mocked.
        case = ZlibWorkloadTests()
        case.setUp()
        try:
            a, operator = case.fixture()
            operator['order'] = P.ORDER
            a.operator_config.write_text(json.dumps(operator))
            a.baseline_state = a.artifact_root.parent / 'baseline.json'
            a.candidate_state = a.baseline_state
            a.output = a.artifact_root.parent / 'paired-plan'
            # Actual freeze hardware-state gates are separately covered by unchanged harness tests.
            with patch.object(B, 'freeze') as freeze:
                result = P.prepare(a)
            self.assertEqual(result['status'], 'PREPARED_NOT_EXECUTED')
            c = B.read_json(a.output / 'config.json')
            self.assertIn(str(HERE / 'paired_zlib.py'), c['inputs'])
            self.assertEqual(c['argv'][2], str(HERE / 'zlib_workload.py'))
            freeze.assert_called_once_with(a.output / 'config.json', a.baseline_state, a.candidate_state, a.output / 'plan.json')
        finally:
            case.doCleanups()

    def test_semantic_report_rejects_wrong_binary_or_decoded_hash(self):
        args = fixture(self.root / 'report')
        r = P.run(args)
        self.assertEqual(r['status'], 'COMPLETE_CONTROL_ONLY', r.get('error'))
        report = r['completed'][0]['workload']
        target = self.root / 'report.json'
        for kind in ('binary', 'decoded', 'level', 'scope'):
            bad = copy.deepcopy(report)
            if kind == 'binary': bad['minigzip_sha256'] = '0' * 64
            elif kind == 'decoded': bad['checks'][0]['decoded_sha256'] = '0' * 64
            elif kind == 'level': bad['compression_level'] = 9
            else: bad['control_only'] = False
            target.write_text(json.dumps(bad))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                P.workload_report(target, report['minigzip'], True)

    def test_bad_order_and_unfrozen_wrapper_refuse_before_actors(self):
        args = fixture(self.root / 'refuse')
        plan = B.load_plan(args.plan)
        for order in (['baseline'] * 6 + ['candidate'] * 6, P.ABBA * 3, P.ORDER[:8]):
            with self.subTest(order=order), self.assertRaises(ValueError):
                P.balanced(order)
        plan['config']['inputs'].remove(str(HERE / 'paired_zlib.py'))
        with patch.object(B, 'run', side_effect=AssertionError('no actor')), self.assertRaisesRegex(ValueError, 'runner source'):
            P.validate(plan, True)

    def test_config_cannot_claim_unpinned_wrapper(self):
        args = fixture(self.root / 'unpinned')
        plan = B.load_plan(args.plan)
        plan['inputs'] = [r for r in plan['inputs'] if r['path'] != str(HERE / 'paired_zlib.py')]
        with self.assertRaisesRegex(ValueError, 'actual frozen pin'):
            P.validate(plan, True)

    def test_session_deadline_interrupt_preserves_failure_and_restores_timer(self):
        args = fixture(self.root / 'deadline')
        prior = signal.getsignal(signal.SIGALRM)
        def expire(*a):
            signal.getsignal(signal.SIGALRM)(signal.SIGALRM, None)
        with patch.object(B, 'run', side_effect=expire):
            r = P.run(args)
        self.assertEqual(r['status'], 'FAIL')
        self.assertIn('session deadline', r['error'])
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), prior)
        self.assertFalse((args.output / 'comparison.json').exists())

    def test_default_target_mode_refuses_control_plan_before_output(self):
        args = fixture(self.root / 'native-refuse')
        args.control_only = False
        with patch.object(B, 'run', side_effect=AssertionError('no actor')), self.assertRaisesRegex(ValueError, 'physical native ARM'):
            P.run(args)
        self.assertFalse(args.output.exists())

    def test_failed_slot_stops_without_retry_or_comparison(self):
        args = fixture(self.root / 'failure')
        original = B.run
        calls = []
        def fail(plan, slot, state, condition, work, raw):
            calls.append(raw.name)
            if raw.name == 'warmup-01':
                raw.mkdir()
                (raw / 'stderr.txt').write_text('explicit failure fixture')
                return 2
            return original(plan, slot, state, condition, work, raw)
        with patch.object(B, 'run', side_effect=fail):
            result = P.run(args)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(calls, ['correctness-00', 'correctness-01', 'warmup-00', 'warmup-01'])
        self.assertTrue((args.output / 'warmup-01/stderr.txt').is_file())
        self.assertFalse((args.output / 'comparison.json').exists())

    def test_semantic_correctness_fails_before_warmups(self):
        args = fixture(self.root / 'semantic')
        original = P.workload_report
        def corrupted(path, expected, control):
            if 'correctness-01' in str(path):
                raise ValueError('independent decoder mismatch fixture')
            return original(path, expected, control)
        with patch.object(P, 'workload_report', side_effect=corrupted):
            result = P.run(args)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(len(result['completed']), 1)
        self.assertFalse((args.output / 'warmup-00').exists())

    def test_condition_and_artifact_drift_cannot_reach_next_slot(self):
        for kind in ('condition', 'artifact'):
            with self.subTest(kind=kind):
                args = fixture(self.root / kind)
                original = B.run
                def mutate(*a):
                    result = original(*a)
                    if a[-1].name == 'correctness-00':
                        path = args.conditions_root / 'correctness-01.json' if kind == 'condition' else Path(B.load_plan(args.plan)['config']['change']['candidate'])
                        path.write_bytes(path.read_bytes() + b'\n')
                    return result
                with patch.object(B, 'run', side_effect=mutate):
                    result = P.run(args)
                self.assertEqual(result['status'], 'FAIL')
                self.assertEqual(len(result['completed']), 1)
                self.assertFalse((args.output / 'comparison.json').exists())


class V2SourceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_interrupted_checkpoint_can_publish_failure(self):
        running = {'status': 'RUNNING', 'completed': []}
        P2.save_session(self.root, running)

        def interrupt(value, stream, **kwargs):
            stream.write('{"status":')
            raise KeyboardInterrupt('modeled session deadline')

        with patch.object(P2.json, 'dump', side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            P2.save_session(self.root, {'status': 'RUNNING', 'completed': ['correctness-00']})

        session_file = self.root / 'session.json'
        self.assertEqual(json.loads(session_file.read_bytes()), running)
        failure = {'status': 'FAIL', 'completed': ['correctness-00']}
        P2.save_session(self.root, failure)
        self.assertEqual(json.loads(session_file.read_bytes()), failure)
        self.assertEqual(list(self.root.iterdir()), [session_file])

    def test_expanded_payload_hash_is_reused_with_per_slot_validation(self):
        heldout = b'modeled held-out data'
        payload = (heldout * 2)[:len(heldout) + 3]
        corpus_manifest = self.root / 'corpus' / 'manifest.json'
        archive = self.root / 'archive-manifest.json'
        config = {'order': P2.ORDER, 'timeout_seconds': 1, 'paired_zlib': 'exact-arm',
                  'change': {'baseline': 'baseline-tool', 'candidate': 'candidate-tool'},
                  'argv': ['python', '-B', 'zlib_workload.py', 'run',
                           '--archive-manifest', str(archive), '--corpus-manifest', str(corpus_manifest),
                           '--input', str(corpus_manifest.with_name('heldout-source.bin')),
                           '--payload-bytes', str(len(payload)), '--iterations', '1']}
        plan = {'config': config, 'baseline_binding': {'path': 'baseline-state'},
                'candidate_binding': {'path': 'candidate-state'}}
        args = NS(plan=self.root / 'plan.json', conditions_root=self.root / 'conditions', output=self.root / 'session',
                  warmup_blocks=1, session_seconds=30, control_only=False)
        args.plan.write_text('{}')
        args.conditions_root.mkdir()
        for slot in P2.schedule(config, args.warmup_blocks):
            (args.conditions_root / (slot['name'] + '.json')).write_text('{}')
        report = {'experiment': 'ARM-C01', 'heldout_sha256': P2.Z.sha(heldout),
                  'payload_sha256': P2.Z.sha(payload), 'payload_bytes': len(payload), 'iterations': 1}
        bad_report = report | {'payload_sha256': '0' * 64}

        def slot_runner(plan, slot, state, condition, work, raw, *, paired, check_workload):
            raw.mkdir()
            try:
                checked = check_workload(b'modeled stdout', config['order'][slot])
            except ValueError as error:
                P2.B.write_json(raw / 'trial.json', {'error': str(error)})
                return 2
            P2.B.write_json(raw / 'trial.json', {'paired_zlib': {'step': paired, 'report': checked}})
            return 0

        with (
            patch.object(P2.os, 'getuid', return_value=1000),
            patch.object(P2.os, 'geteuid', return_value=1000),
            patch.object(P2.B, 'load_plan', return_value=plan),
            patch.object(P2, 'validate'),
            patch.object(P2.B, 'validate_conditions'),
            patch.object(P2.B, 'run', side_effect=slot_runner) as run,
            patch.object(P2, 'workload_report', side_effect=[report, report, bad_report]),
            patch.object(P2.Z, 'materials', return_value=('ARM-C01', self.root, heldout)) as materials,
            patch.object(P2.Z, 'sha', wraps=P2.Z.sha) as digest,
        ):
            session = P2.run(args)

        self.assertEqual(session['status'], 'FAIL')
        self.assertIn('original workload output joins differ', session['error'])
        self.assertEqual([slot['name'] for slot in session['completed']], ['correctness-00', 'correctness-01'])
        self.assertEqual(run.call_count, 3)
        self.assertEqual(materials.call_count, 3)
        self.assertEqual(sum(call.args == (payload,) for call in digest.call_args_list), 1)


class V2AdmissionTests(unittest.TestCase):
    """Use frozen inputs and raw record fixtures without launching workloads."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.runner = P2.B
        self.driver = self.root / 'driver'
        self.driver.write_bytes(b'modeled interpreter')
        self.artifacts = {}
        for variant in ('baseline', 'candidate'):
            artifact = self.root / variant
            artifact.write_text(variant)
            artifact.chmod(0o700)
            self.artifacts[variant] = str(artifact)
        controls = dict.fromkeys(('power_source', 'display_config', 'brightness', 'cache_mode',
                                  'background_load', 'warmup'), 'fixture')
        controls.update(ambient_C=[0, 100], thermal_start_C=[0, 100], battery_soc_percent=[0, 100])
        self.config = dict(experiment_id='paired-check', machine_id='fixture', base_id='fixture',
                           workload_id='receipt-check', execution_context='unknown',
                           argv=[str(self.driver)], inputs=[str(self.driver), str(HERE / 'paired_zlib_v2.py')],
                           change=self.artifacts | dict(variable='fixture', environment_key='ZLIB_MINIGZIP',
                                                        rationale='modeled evidence'),
                           variant_inputs={variant: [path] for variant, path in self.artifacts.items()},
                           variant_env={variant: {'ZLIB_MINIGZIP': path} for variant, path in self.artifacts.items()},
                           order=P2.ORDER, minimum_trials=6, timeout_seconds=1, sample_seconds=.1,
                           controls=controls, thresholds=dict(minimum_elapsed_improvement_pct=0,
                                                              maximum_elapsed_range_pct=10),
                           paired_zlib='control-only')
        self.config_path = self.root / 'config.json'
        self.runner.write_json(self.config_path, self.config)
        self.state = self.root / 'state.json'
        self.runner.write_json(self.state, {'execution_context': 'unknown', 'packages': {'returncode': 1}})
        self.identity = self.runner.state_identity(self.runner.read_json(self.state))
        self.plan = self.root / 'plan.json'
        self.runner.freeze(self.config_path, self.state, self.state, self.plan)
        self.args = NS(plan=self.plan, conditions_root=self.root / 'conditions', output=self.root / 'session',
                       warmup_blocks=1, session_seconds=30, control_only=True)
        self.args.conditions_root.mkdir()
        condition = controls | dict(ambient_C=20, thermal_start_C=20, battery_soc_percent=50,
                                   operator='fixture', notes='Modeled conditions.')
        for step in P2.schedule(self.config, self.args.warmup_blocks):
            self.runner.write_json(self.args.conditions_root / (step['name'] + '.json'), condition)
        self.output = self.root / 'comparison.json'
        self.bad_report_at = None
        self.measurements = [self.args.output / f'measured-{i:02d}' for i in range(len(P2.ORDER))]
        for target, name, kwargs in (
            (P2.os, 'getuid', {'return_value': 1000}),
            (P2.os, 'geteuid', {'return_value': 1000}),
            (self.runner, 'live_identity', {'return_value': self.identity}),
            (self.runner, 'execute', {'side_effect': self.modeled_execute}),
            (self.runner.retirement_adapter(), 'verify', {'side_effect': self.modeled_verify}),
        ):
            fixture_patch = patch.object(target, name, **kwargs)
            fixture_patch.start()
            self.addCleanup(fixture_patch.stop)

    def modeled_execute(self, argv, cwd, env, output, timeout, interval):
        artifact = env['ZLIB_MINIGZIP']
        payload = '1' * 64
        report = dict(status='PASS', control_only=True, minigzip=artifact,
                      minigzip_sha256=self.runner.digest(artifact), heldout_sha256='2' * 64,
                      payload_sha256=payload, payload_bytes=32, iterations=1, compression_level=6,
                      checks=[dict(iteration=0, decoded_sha256=payload, encoded_sha256='3' * 64)],
                      hardware_validation='NOT RUN', optimization_acceptance='NOT RUN')
        if output.name == self.bad_report_at:
            report['checks'][0]['decoded_sha256'] = '4' * 64
        row = dict(monotonic_ns=10, memory={'lifecycle': 'unknown'}, thermal=[], power=[])
        self.runner.write_json(output / 'stdout.txt', report)
        (output / 'telemetry.jsonl').write_text(json.dumps(row) + '\n')
        (output / 'stderr.txt').touch()
        (output / 'owned-retirement.json').touch()
        return dict(elapsed_ns=10, monotonic_start_ns=10, monotonic_end_ns=20,
                    returncode=0, error=None, sample_count=1, metrics=self.runner.metrics([row]),
                    sampling_status=dict(worker_stopped=True, workload_reaped=True, error=None, dropped_samples=0))

    def modeled_verify(self, directory, trial, interval, samples, summarize, rss_metrics):
        return summarize(samples)

    def replace_trial(self, directory, trial):
        (directory / 'trial.json').write_text(json.dumps(trial))

    def test_last_slot_report_refusal_cannot_be_compared(self):
        self.bad_report_at = self.measurements[-1].name
        result = P2.run(self.args)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('complete per-iteration correctness report required', result['error'])
        last = self.runner.read_json(self.measurements[-1] / 'trial.json')
        self.assertIs(last['valid'], False)
        self.assertNotIn('report', last['paired_zlib'])
        with self.assertRaisesRegex(self.runner.Invalid, 'failed/interrupted workload'):
            self.runner.compare(self.plan, self.measurements, self.output)
        self.assertFalse(self.output.exists())

    def test_complete_session_replays_and_refuses_changed_raw_or_cached_report(self):
        result = P2.run(self.args)
        self.assertEqual(result['status'], 'COMPLETE_CONTROL_ONLY', result.get('error'))
        self.assertEqual(self.runner.compare(self.plan, self.measurements, self.output), 0)
        complete = self.runner.read_json(self.output)
        self.assertEqual(len(complete['trial_bindings']), 12)

        last_dir = self.measurements[-1]
        original = self.runner.read_json(last_dir / 'trial.json')
        edited = copy.deepcopy(original)
        edited['paired_zlib']['report']['checks'][0]['encoded_sha256'] = '0' * 64
        self.replace_trial(last_dir, edited)
        with self.assertRaisesRegex(self.runner.Invalid, 'report differs from verified stdout'):
            self.runner.compare(self.plan, self.measurements, self.root / 'cached.json')

        edited = copy.deepcopy(original)
        raw = last_dir / 'stdout.txt'
        changed = self.runner.read_json(raw)
        changed['checks'] = []
        raw.write_text(json.dumps(changed))
        edited['raw_sha256']['stdout.txt'] = self.runner.digest(raw)
        edited['paired_zlib']['report'] = changed
        self.replace_trial(last_dir, edited)
        with self.assertRaisesRegex(ValueError, 'complete per-iteration correctness report required'):
            self.runner.compare(self.plan, self.measurements, self.root / 'rebound.json')

    def test_comparison_refuses_warmup_and_other_session(self):
        result = P2.run(self.args)
        self.assertEqual(result['status'], 'COMPLETE_CONTROL_ONLY', result.get('error'))
        warmup = self.args.output / 'warmup-00'
        with self.assertRaisesRegex(self.runner.Invalid, 'session, phase or slot'):
            self.runner.compare(self.plan, [warmup, *self.measurements[1:]], self.output)

        first = self.measurements[0]
        edited = self.runner.read_json(first / 'trial.json')
        edited['paired_zlib']['step']['session_id'] = '0' * 32
        self.replace_trial(first, edited)
        with self.assertRaisesRegex(self.runner.Invalid, 'different sessions'):
            self.runner.compare(self.plan, self.measurements, self.output)

    def test_interrupted_trial_publication_leaves_raw_but_no_admission(self):
        initial_write = self.runner.write_json

        def interrupted(path, data):
            initial_write(path, data)
            if path.name == 'trial.json':
                self.assertTrue(data['valid'])
                self.assertIn('report', data['paired_zlib'])
                raise KeyboardInterrupt('modeled publication interruption')

        cwd = self.root / 'work'
        cwd.mkdir()
        raw = self.root / 'raw'
        condition = self.args.conditions_root / 'measured-00.json'
        paired = dict(session_id='f' * 32, phase='measured', index=0)
        verifier = P2.workload_check(self.runner.load_plan(self.plan))
        with patch.object(self.runner, 'write_json', side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            self.runner.run(self.plan, 0, self.state, condition, cwd, raw,
                            paired=paired, check_workload=verifier)
        self.assertTrue((raw / 'stdout.txt').is_file())
        self.assertFalse((raw / 'trial.json').exists())
        with self.assertRaises(FileNotFoundError):
            self.runner.compare(self.plan, [raw], self.output)

    def test_generic_run_refuses_paired_plan_before_execution(self):
        with self.assertRaisesRegex(self.runner.Invalid, 'must run through paired_zlib_v2'):
            self.runner.run(self.plan, 0, self.state, self.args.conditions_root / 'measured-00.json',
                            self.root, self.root / 'raw')
        self.runner.execute.assert_not_called()

    def test_ordinary_plan_retains_generic_run_and_compare(self):
        generic = dict(self.config)
        del generic['paired_zlib']
        config_path, plan = self.root / 'generic-config.json', self.root / 'generic-plan.json'
        self.runner.write_json(config_path, generic)
        self.runner.freeze(config_path, self.state, self.state, plan)
        cwd = self.root / 'work'
        cwd.mkdir()
        outputs = []
        for index in range(len(generic['order'])):
            name = f'measured-{index:02d}'
            output = self.root / name
            status = self.runner.run(plan, index, self.state, self.args.conditions_root / (name + '.json'),
                                     cwd, output)
            self.assertEqual(status, 0)
            self.assertNotIn('paired_zlib', self.runner.read_json(output / 'trial.json'))
            outputs.append(output)
        self.assertEqual(self.runner.compare(plan, outputs, self.output), 0)


if __name__ == '__main__':
    unittest.main()
