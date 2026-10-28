"""Synthetic C04 controls/receiver regressions; compiler support is not established."""
import copy
import io
import json
from pathlib import Path
import sys
import tarfile
from types import SimpleNamespace
from unittest.mock import patch

import test_arm_c01 as fixtures
from test_arm_c02 import load

a = fixtures.a
stage = load('c04_export_fixture', 'stage.py', {'arm_c01': a})
helper = load('c04_helper_fixture', 'native_trial.py', {'arm_c01': a, 'stage': stage})


class C04Tests(fixtures.IsolatedTests):
    def setUp(self):
        super().setUp()
        self.addCleanup(a.select_experiment, 'ARM-C01')
        a.select_experiment('ARM-C04')
        self.enterContext(patch.dict(sys.modules, {a.__name__: a}))

    def receipt(self):
        return fixtures.ReceiverTests.receipt(self)

    def test_only_tuning_changes_with_o2_generic_isa_and_no_lto(self):
        baseline, candidate = a.build_flags('baseline'), a.build_flags('m2')
        self.assertEqual(candidate, (baseline[0].replace('-mtune=generic', '-mtune=apple-m2', 1), baseline[1]))
        self.assertIn('-O2 -g -march=armv8-a -mtune=apple-m2', candidate[0])
        self.assertTrue(all('-fno-lto' in value for value in (*baseline, *candidate)))
        self.assertEqual(a.configure_flags('m2'), candidate)
        self.assertEqual(a.strict_flags('m2-1'), candidate)
        self.assertEqual(a.build_names(), ('baseline-1', 'baseline-2', 'm2-1', 'm2-2'))
        self.assertIsNone(a.profile_adapter())
        self.assertEqual(a.tool_names(), a.TOOLS)
        for variant in ('lto', 'o3', 'pgo', 'native', 'unknown'):
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                a.build_flags(variant)
        with self.assertRaises(ValueError):
            a.select_experiment('ARM-C99')
        self.assertEqual(a.EXPERIMENT, 'ARM-C04')

    def test_complete_receiver_and_export_have_exact_c04_labels_and_scope(self):
        raw, contract, report, manifest, commands = self.receipt()
        verified = a.verify_result(raw, contract)
        self.assertEqual(verified['purpose'], 'ARM-C04-native-correctness-only')
        self.assertEqual(verified['reproducibility'], {'baseline': 'PASS', 'm2': 'PASS'})
        self.assertEqual(verified['receiver_verification']['command_count'], 505)
        self.assertEqual((verified['hardware_validation'], verified['performance_acceptance']), ('NOT RUN', 'NOT RUN'))
        self.assertNotIn('profile_verification', verified)
        self.assertFalse(any('profile' in str(row) or 'lto-' in row['name'] for row in commands))
        self.assertEqual(a.command_plan(manifest)[5]['name'], 'baseline-1-configure')
        exported = stage.export_artifacts(raw, self.root / 'export', verified)
        self.assertEqual(exported['purpose'], 'ARM-C04-same-job-followup')
        with tarfile.open(self.root / 'export/development-ARM-C04-outputs.tar.gz') as archive:
            names = archive.getnames()
            self.assertEqual(len(names), 79)
            self.assertIn('m2-1/Makefile.txt', names)
            self.assertFalse(any('pgo' in name or name.endswith('.gcda') for name in names))

    def test_masked_generic_o3_isa_lto_or_profile_flags_are_refused(self):
        raw, contract, original, _, _ = self.receipt()
        directory = raw / 'm2-1'
        before = {name: (directory / (name + '.txt')).read_bytes() for name in ('Makefile', 'configure.log')}
        changes = [
            (b'-mtune=apple-m2', b'-mtune=generic'),
            (b'-O2 ', b'-O3 '),
            (b'-march=armv8-a', b'-march=apple-m2'),
            (b'-fno-lto', b'-flto=2'),
            (b'-fno-lto', b'-fno-lto -fprofile-use=/tmp/profile'),
            (b'-fno-lto', b'-fno-lto -fprofile-generate=/tmp/profile')]
        for old, new in changes:
            report = copy.deepcopy(original)
            for name, data in before.items():
                path = directory / (name + '.txt'); path.write_bytes(data.replace(old, new))
                report['builds'][2]['generated_configuration_sha256'][name] = a.sha(path)
            a.save(raw / 'result.json', report)
            with self.subTest(flags=new), self.assertRaisesRegex(ValueError, 'compiler flags'):
                a.verify_result(raw, contract)

    def test_hidden_lto_sections_fail_despite_no_lto_declaration(self):
        raw, contract, _, _, commands = self.receipt()
        row = next(row for row in commands if row['name'] == 'm2-1-archive-sections')
        path = raw / row['log']; path.write_bytes(b'.gnu.lto_unexpected\n')
        row.update(log_sha256=a.sha(path), log_bytes=path.stat().st_size)
        a.save(raw / 'commands.json', commands)
        with self.assertRaisesRegex(ValueError, 'LTO evidence'):
            a.verify_result(raw, contract)

    def test_wrong_experiment_contract_or_report_cannot_claim_c04(self):
        raw, contract, report, _, _ = self.receipt()
        with self.assertRaisesRegex(ValueError, 'source contract'):
            a.verify_result(raw, {**contract, 'purpose': 'ARM-C03-native-correctness-only'})
        report['purpose'] = 'ARM-C02-native-correctness-only'; a.save(raw / 'result.json', report)
        with self.assertRaisesRegex(ValueError, 'software-only'):
            a.verify_result(raw, contract)

    def test_host_propagates_c04_without_profile_adapter_transport(self):
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
        self.assertEqual(report['purpose'], 'ARM-C04-native-correctness-only')
        self.assertNotIn('pgo_sha256', report['contract'])
        self.assertFalse((args.output / 'inputs/pgo.py').exists())
        argv = next(argv for name, argv in calls if name == 'container')
        self.assertEqual(argv[-2:], ['--experiment', 'ARM-C04'])
        self.assertIn('CACHY_ASAHI_ARM_C04=', ' '.join(argv))
        self.assertNotIn('CACHY_ASAHI_ARM_C03=', ' '.join(argv))
        self.assertTrue(argv[argv.index('--name') + 1].startswith('cachy-asahi-arm-c04-'))

    def test_helper_selects_c04_before_preflight_and_owns_its_cleanup_name(self):
        a.select_experiment('ARM-C01')
        with patch.object(helper, 'preflight', side_effect=ValueError('stop before actors')), self.assertRaises(ValueError):
            helper.run(SimpleNamespace(experiment='ARM-C04'))
        self.assertEqual(a.EXPERIMENT, 'ARM-C04')
        inputs = self.root / 'trial/inputs'; inputs.mkdir(parents=True)
        (inputs / 'contract.json').write_text(json.dumps({'nonce': 'c' * 32}))
        with patch.object(helper.native, 'run', return_value='') as run:
            result = helper.cleanup(self.root, ['docker'])
        self.assertTrue(result['container']['name'].startswith('cachy-asahi-arm-c04-'))
        self.assertTrue(all('arm-c01' not in str(call) for call in run.call_args_list))
