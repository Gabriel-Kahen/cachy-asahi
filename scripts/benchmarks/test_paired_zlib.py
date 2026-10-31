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


if __name__ == '__main__':
    unittest.main()
