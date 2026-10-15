"""Closed C02 controls and full receiver fixtures; no native actors or replay."""
import io
import importlib.util
import json
from pathlib import Path
import tarfile
import sys
from types import SimpleNamespace
from unittest.mock import patch

import test_arm_c01 as fixtures

a = fixtures.a


def load(name, filename, imports):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, imports):
        spec.loader.exec_module(module)
    return module


stage = load('c02_export_fixture', 'stage.py', {'arm_c01': a})
helper = load('c02_helper_fixture', 'native_trial.py', {'arm_c01': a, 'stage': stage})


class C02Tests(fixtures.IsolatedTests):
    def setUp(self):
        super().setUp()
        self.addCleanup(a.select_experiment, 'ARM-C01')
        a.select_experiment('ARM-C02')

    def receipt(self):
        return fixtures.ReceiverTests.receipt(self)

    def test_only_optimization_changes_and_lto_is_disabled_in_both(self):
        baseline = a.build_flags('baseline')
        candidate = a.build_flags('o3')
        self.assertEqual(candidate, (baseline[0].replace('-O2 ', '-O3 ', 1), baseline[1]))
        self.assertTrue(all('-fno-lto' in flags for flags in (*baseline, *candidate)))
        self.assertNotIn('-flto=', ' '.join(candidate))
        self.assertEqual(a.build_names(), ('baseline-1', 'baseline-2', 'o3-1', 'o3-2'))
        for variant in ('lto', 'native', 'unknown'):
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                a.build_flags(variant)
        with self.assertRaises(ValueError):
            a.select_experiment('ARM-C99')
        self.assertEqual(a.EXPERIMENT, 'ARM-C02')

    def test_c01_default_controls_and_labels_remain_exact(self):
        a.select_experiment('ARM-C01')
        self.assertEqual((a.CANDIDATE, a.PURPOSE, a.MARKER, a.container_prefix()),
            ('lto', 'ARM-C01-native-correctness-only', 'CACHY_ASAHI_ARM_C01', 'cachy-asahi-arm-c01-'))
        self.assertEqual(a.build_flags('baseline'), (a.BASE_FLAGS + ' -fno-lto', a.LINK_FLAGS + ' -fno-lto'))
        self.assertEqual(a.build_flags('lto'), (a.BASE_FLAGS + ' -flto=2 -Werror=lto-type-mismatch', a.LINK_FLAGS + ' -flto=2'))
        self.assertEqual(a.build_names(), ('baseline-1', 'baseline-2', 'lto-1', 'lto-2'))

    def test_full_c02_graph_and_bounded_outputs_have_honest_labels(self):
        raw, contract, report, manifest, commands = self.receipt()
        verified = a.verify_result(raw, contract)
        self.assertEqual(verified['purpose'], 'ARM-C02-native-correctness-only')
        self.assertEqual(verified['reproducibility'], {'baseline': 'PASS', 'o3': 'PASS'})
        self.assertEqual(verified['receiver_verification']['command_count'], 505)
        self.assertFalse(any('lto-' in row['name'] for row in commands))
        exported = stage.export_artifacts(raw, self.root / 'artifacts', verified)
        self.assertEqual(exported['purpose'], 'ARM-C02-same-job-followup')
        bundle = self.root / 'artifacts/development-ARM-C02-outputs.tar.gz'
        with tarfile.open(bundle, 'r:gz') as archive:
            self.assertEqual(len(archive.getmembers()), 79)
            self.assertTrue(any(n.startswith('o3-') for n in archive.getnames()))
            self.assertFalse(any(n.startswith('lto-') for n in archive.getnames()))
        stage.project_evidence(self.root, self.root / 'selected')
        projection = json.loads((self.root / 'selected/projection.json').read_text())
        self.assertEqual(projection['purpose'], 'ARM-C02-same-job-followup')
        self.assertTrue((self.root / 'selected/o3-1/Makefile.txt').is_file())

    def test_wrong_experiment_identity_is_refused(self):
        raw, contract, report, _, _ = self.receipt()
        bad = {**contract, 'purpose': 'ARM-C01-native-correctness-only'}
        with self.assertRaisesRegex(ValueError, 'source contract'):
            a.verify_result(raw, bad)
        report['purpose'] = 'ARM-C01-native-correctness-only'
        a.save(raw / 'result.json', report)
        with self.assertRaisesRegex(ValueError, 'software-only'):
            a.verify_result(raw, contract)

    def test_o2_config_cannot_be_accepted_as_o3(self):
        raw, contract, report, _, _ = self.receipt()
        for name in ('Makefile', 'configure.log'):
            path = raw / 'o3-1' / (name + '.txt')
            path.write_bytes(path.read_bytes().replace(b'-O3 ', b'-O2 ', 1))
            report['builds'][2]['generated_configuration_sha256'][name] = a.sha(path)
        a.save(raw / 'result.json', report)
        with self.assertRaisesRegex(ValueError, 'compiler flags'):
            a.verify_result(raw, contract)

    def test_lto_sections_cannot_leak_into_c02(self):
        raw, contract, _, _, commands = self.receipt()
        row = next(r for r in commands if r['name'] == 'o3-1-archive-sections')
        log = raw / row['log']; log.write_bytes(b'.gnu.lto_unexpected\n')
        row.update(log_sha256=a.sha(log), log_bytes=log.stat().st_size)
        a.save(raw / 'commands.json', commands)
        with self.assertRaisesRegex(ValueError, 'LTO evidence'):
            a.verify_result(raw, contract)

    def test_helper_selects_c02_before_preflight_and_uses_its_owned_name(self):
        a.select_experiment('ARM-C01')
        with patch.object(helper, 'preflight', side_effect=ValueError('stop before actors')), self.assertRaises(ValueError):
            helper.run(SimpleNamespace(experiment='ARM-C02'))
        self.assertEqual(a.EXPERIMENT, 'ARM-C02')
        inputs = self.root / 'trial/inputs'; inputs.mkdir(parents=True)
        (inputs / 'contract.json').write_text(json.dumps({'nonce': 'c' * 32}))
        with patch.object(helper.native, 'run', return_value='') as run:
            result = helper.cleanup(self.root, ['docker'])
        self.assertTrue(result['container']['name'].startswith('cachy-asahi-arm-c02-'))
        self.assertTrue(all('arm-c01' not in str(call) for call in run.call_args_list))

    def test_host_transports_closed_selection_to_inside_process(self):
        args = fixtures.ControllerTests.args(self)
        calls = []
        def command(runner, name, argv, **kwargs):
            calls.append((name, argv))
            if name == 'context':
                return json.dumps([{'Endpoints': {'docker': {'Host': 'unix:///var/run/docker.sock'}}}]).encode()
            if name == 'daemon':
                return json.dumps({'Architecture': 'aarch64', 'OSType': 'linux'}).encode()
            if name == 'image':
                return json.dumps([{'Id': args.image, 'Architecture': 'arm64', 'Config': {}}]).encode()
            if name == 'container':
                return b''
            raise AssertionError(name)
        with patch.object(a.platform, 'machine', return_value='aarch64'), \
             patch.object(a, 'SOURCE_SHA', a.sha(args.source)), \
             patch.object(a.Commands, 'run', autospec=True, side_effect=command), \
             patch.object(a.Commands, 'stop', return_value=True), \
             patch.object(a.subprocess, 'run', return_value=SimpleNamespace(returncode=0)), \
             patch.object(a, 'verify_result', return_value={'receiver_verification': {}}), \
             patch.object(a.sys, 'stdout', io.StringIO()):
            self.assertEqual(a.host(args), 0)
        report = json.loads((args.output / 'result.json').read_text())
        self.assertEqual(report['purpose'], 'ARM-C02-native-correctness-only')
        argv = next(argv for name, argv in calls if name == 'container')
        self.assertEqual(argv[-2:], ['--experiment', 'ARM-C02'])
        self.assertIn('CACHY_ASAHI_ARM_C02=', ' '.join(argv))
        self.assertNotIn('CACHY_ASAHI_ARM_C01=', ' '.join(argv))
        self.assertTrue(argv[argv.index('--name') + 1].startswith('cachy-asahi-arm-c02-'))
