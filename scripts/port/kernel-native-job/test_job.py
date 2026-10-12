# SPDX-License-Identifier: MIT
from contextlib import contextmanager
import ast
import importlib.util
import copy
import json
import os
import signal
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import job

spec = importlib.util.spec_from_file_location('kernel_child_evidence_fixture',
    Path(__file__).resolve().parents[1] / 'kernel-native-stage/evidence.py')
child_evidence = importlib.util.module_from_spec(spec); spec.loader.exec_module(child_evidence)


class JobContracts(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name); (self.root / 'artifacts/kernel-native-job').mkdir(parents=True)
        self.args = SimpleNamespace(source_root=self.root, source_commit='a' * 40, packet_sha256='b' * 64,
            packet=self.root / 'packet', output=self.root / 'artifacts/kernel-native-job/job-1-1',
            docker_binary=Path('/usr/bin/docker'), docker_sha256='c' * 64,
            docker_endpoint='unix:///run/docker.sock', execute_native=True, deadline=20760)
        self.image = 'sha256:' + 'd' * 64

    def test_fixed_aggregate_reserves_fit_hosted_ceiling(self):
        self.assertEqual(job.DEADLINE, 20760)
        self.assertEqual(job.DEADLINE + 600 + 180 + 60, 21600)
        self.assertEqual(job.KERNEL_ENVELOPE, 18000 + 240)

    def test_isolated_cli_loads_owned_modules(self):
        result = subprocess.run([sys.executable, '-I', '-B', job.__file__, '--help'], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'--execute-native', result.stdout)

    def test_producer_is_original_cli_build_without_override_or_integration(self):
        command = job.producer_command(self.root, self.root / 'private')
        self.assertEqual(command[:5], ['/usr/bin/python3', '-I', '-B', str(self.root / 'scripts/ci/native_arm.py'), 'build'])
        self.assertIn(job.packet.INPUTS_SHA, command); self.assertIn(job.packet.RECIPES_SHA, command)
        self.assertNotIn('integration', command)
        self.assertFalse(any('fdk-native-job' in arg for arg in command))

    def test_non_native_or_budget_changed_refuses(self):
        with patch.object(job.platform, 'machine', return_value='x86_64'):
            with self.assertRaises(ValueError): job.ordinary(self.args)
        self.args.deadline = 21600
        with self.assertRaises(ValueError): job.ordinary(self.args)

    def test_daemon_actual_range_must_include_fixed_kernel_API_148(self):
        info = {'ID': 'fixture-daemon-id', 'Architecture': 'aarch64', 'OSType': 'linux',
            'CgroupVersion': '2', 'SecurityOptions': ['name=seccomp']}
        docker = job.Docker(self.args)
        for raw, accepted in ((b'1.51 1.24', True), (b'1.48 1.24', True), (b'1.48 1.48', True),
                              (b'1.47 1.24', False), (b'1.52 1.49', False), (b'1.48 1.49', False),
                              (b'unknown', False), (b'1.48', False), (b'1.48 1.24 extra', False),
                              (b'1.48.0 1.24', False)):
            responses = [SimpleNamespace(returncode=0, stdout=json.dumps(info).encode()), SimpleNamespace(returncode=0, stdout=raw)]
            with patch.object(docker, 'call', side_effect=responses):
                if accepted: self.assertEqual(docker.info(Mock())['id'], info['ID'])
                else:
                    with self.assertRaises(ValueError): docker.info(Mock())

    def test_job_guard_and_kernel_wire_pin_the_same_fixed_API(self):
        path = Path(job.__file__).resolve().parents[1] / 'kernel-native-stage/image.py'
        source = ast.parse(path.read_text())
        values = [ast.literal_eval(node.value) for node in source.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == 'API_VERSION' for target in node.targets)]
        self.assertEqual(values, [job.KERNEL_API_VERSION])
        self.assertEqual(job.KERNEL_API_VERSION, '1.48')

    def test_acquisition_uses_actual_held_receipt_and_exact_seven_paths(self):
        out = self.root / 'acquire'; out.mkdir()
        arguments = {'archive': str(out / 'asahi.tar.gz'), 'config': str(out / 'embedded-config'),
            'patch': str(out / 'candidate.patch'), 'bio_baseline': str(out / 'artifacts/kernel-candidates/baseline/source-slice/block/bio.c'),
            'bio_candidate': str(out / 'artifacts/kernel-candidates/candidate/source-slice/block/bio.c'),
            'package_cache': str(out / 'packages'), 'key_dir': str(out / 'keys')}
        job.save(out / 'acquisition.json', {'status': 'PASS-acquired-source-data', 'arguments': arguments})
        self.assertEqual(set(job.acquired_paths(out)), {'archive', 'config', 'patch', 'bio-baseline', 'bio-candidate', 'package-cache', 'key-dir'})
        arguments['archive'] = str(self.root / 'escape')
        job.save(out / 'acquisition.json', {'status': 'PASS-acquired-source-data', 'arguments': arguments})
        with self.assertRaises(ValueError): job.acquired_paths(out)

    def producer_fixture(self):
        private = self.root / 'private'; private.mkdir(); producer = private / 'producer'; producer.mkdir()
        # Exact pinned real inputs/inventory are injected below. These are
        # receiver source fixtures, never a native execution assertion.
        inputs, packages = b'input snapshot\n', b'complete inventory\n'
        result = {'mode': 'build', 'status': 'native-builds-and-byte-comparison-pass', 'native_build': 'PASS',
            'hardware_validation': 'NOT RUN', 'verified_signed_packages': 248,
            'reviewed_inputs_sha256': job.packet.INPUTS_SHA, 'reviewed_recipes_sha256': job.packet.RECIPES_SHA,
            'bootstrap_script_sha256': job.packet.HELPERS['scripts/ci/native_arm.py'][0]}
        bootstrap = {'status': 'image-provisioned', 'image_id': self.image,
            'inputs_sha256': job.packet.INPUTS_SHA, 'packages_lock_sha256': job.BASE_SHA}
        runner = {'commit': self.args.source_commit, 'runner_arch': 'ARM64', 'uid': os.getuid(),
            'bootstrap_script_sha256': job.packet.HELPERS['scripts/ci/native_arm.py'][0]}
        for name, record in (('result.json', result), ('bootstrap.json', bootstrap), ('runner.json', runner)):
            job.save(producer / name, record)
        (producer / 'image-id').write_text(self.image + '\n')
        (producer / 'inputs.lock.json').write_bytes(inputs); (producer / 'packages.lock').write_bytes(packages)
        return private, result, bootstrap, inputs, packages

    def test_producer_receiver_checks_native_success_and_captures_bound_receipts(self):
        private, result, _, inputs, packages = self.producer_fixture()
        original = job.packet.sha
        def sha(data): return job.packet.INPUTS_SHA if data == inputs else job.BASE_SHA if data == packages else original(data)
        with patch.object(job.packet, 'sha', side_effect=sha):
            image, accepted = job.accepted_producer(private, self.args.source_commit)
        self.assertEqual(image, self.image)
        self.assertEqual(job.packet.load(accepted / 'result.json'), result)
        self.assertEqual((accepted / 'packages.lock').read_bytes(), packages)

    def test_invalid_producer_receipt_cannot_launch_kernel(self):
        private, result, _, _, _ = self.producer_fixture()
        result['native_build'] = 'NOT RUN'; job.save(private / 'producer/result.json', result)
        with self.assertRaisesRegex(ValueError, 'original-producer-receipt'):
            job.accepted_producer(private, self.args.source_commit)
        self.assertFalse((private / 'accepted').exists())

    def test_verified_package_counter_matches_exact_original_producer_contract(self):
        source_root = Path(job.__file__).resolve().parents[3]
        inputs = job.packet.load(source_root / 'scripts/ci/inputs.lock.json', job.packet.INPUTS_SHA)
        self.assertEqual(len(inputs['packages']), 248)
        original = job.packet.read(source_root / 'scripts/ci/native_arm.py')
        self.assertEqual(job.packet.sha(original), job.packet.HELPERS['scripts/ci/native_arm.py'][0])
        self.assertIn(b"return len(inputs['packages'])", original)
        private, result, _, _, _ = self.producer_fixture()
        result['verified_signed_packages'] = 249; job.save(private / 'producer/result.json', result)
        with self.assertRaisesRegex(ValueError, 'original-producer-receipt'):
            job.accepted_producer(private, self.args.source_commit)

    def test_kernel_command_uses_actual_git_root_and_frozen_stage_contract(self):
        accepted = self.root / 'accepted'; accepted.mkdir()
        job.save(accepted / 'bootstrap.json', {'status': 'fixture'}); job.save(accepted / 'result.json', {'status': 'fixture'})
        paths = {name: self.root / name for name in ('archive', 'config', 'patch', 'bio-baseline', 'bio-candidate', 'package-cache', 'key-dir')}
        command = job.kernel_command(self.args, self.root, self.image, accepted, paths, self.root / 'kernel-out')
        self.assertIn(job.packet.KERNEL_SHA, command)
        self.assertEqual(command[command.index('--root') + 1], str(self.root))
        self.assertEqual(command[3], str(self.root / 'source' / (job.packet.KERNEL + 'stage.py')))
        self.assertEqual(command[command.index('--image') + 1], self.image)
        self.assertEqual(command[command.index('--source-commit') + 1], self.args.source_commit)

    def test_kernel_receiver_requires_both_full_variants_probe_and_cleanup(self):
        out = self.root / 'kernel'; (out / 'private').mkdir(parents=True)
        record = {'status': 'PASS', 'source_commit': self.args.source_commit, 'phase': 'complete', 'cancelled': False,
            'native_kernel_compilation': 'PASS', 'kernel_execution': 'NOT RUN', 'hardware_validation': 'NOT RUN',
            'performance': 'NOT MEASURED', 'cleanup': {'status': 'PASS'},
            **{name: {'status': 'PASS', 'action': name, 'cancelled': False} for name in ('probe', 'baseline', 'candidate')}}
        job.save(out / 'private/result.json', record); self.assertEqual(job.kernel_status(out, self.args.source_commit), record)
        for field in ('probe', 'baseline', 'candidate', 'cleanup'):
            changed = json.loads(json.dumps(record)); changed[field]['status'] = 'FAIL'
            job.save(out / 'private/result.json', changed)
            with self.assertRaises(ValueError): job.kernel_status(out, self.args.source_commit)

    def test_source_bound_partial_baseline_survives_candidate_failure(self):
        out = self.root / 'kernel'; (out / 'private').mkdir(parents=True)
        record = {'status': 'FAIL', 'source_commit': self.args.source_commit, 'phase': 'candidate', 'cancelled': False,
            'kernel_execution': 'NOT RUN', 'hardware_validation': 'NOT RUN', 'performance': 'NOT MEASURED',
            **{name: {'status': 'PASS', 'action': name, 'nonce': 'e' * 32, 'cancelled': False} for name in ('probe', 'baseline')}}
        job.save(out / 'private/result.json', record)
        self.assertEqual(job.kernel_progress(out, self.args.source_commit),
            {'kernel_probe': 'PASS', 'baseline': 'PASS', 'candidate': 'FAIL', 'native_compilation': 'NOT ACCEPTED'})
        for changed in (dict(record, source_commit='f' * 40), dict(record, phase='invented')):
            job.save(out / 'private/result.json', changed)
            with self.assertRaises(ValueError): job.kernel_progress(out, self.args.source_commit)
        record['baseline']['nonce'] = 'f' * 32; job.save(out / 'private/result.json', record)
        with self.assertRaises(ValueError): job.kernel_progress(out, self.args.source_commit)

    def test_unknown_producer_mutation_empty_inventory_is_not_cleanup_pass(self):
        docker = Mock(); docker.inventory.return_value = set()
        result = job.cleanup_base(docker, Mock(), self.root, None, False, Mock())
        self.assertEqual(result['status'], 'FAIL'); self.assertTrue(result['producer_mutation_uncertain'])
        docker.call.assert_not_called()

    def test_only_journaled_base_id_can_be_removed_and_absence_is_required(self):
        docker = Mock(daemon={'id': 'daemon'}); docker.inventory.return_value = set()
        baseline = Mock(record={'source_commit': self.args.source_commit, 'identity_sha256': 'b' * 64, 'nonce': 'e' * 32})
        baseline.protected.return_value = set()
        job.save(self.root / 'base-ownership.json', {'image_id': self.image, 'daemon': docker.daemon,
            'producer_finished': True, 'source_commit': self.args.source_commit,
            'producer_sha256': job.packet.HELPERS['scripts/ci/native_arm.py'][0],
            'baseline_identity_sha256': 'b' * 64, 'nonce': 'e' * 32})
        row = {'Id': self.image, 'Architecture': 'arm64', 'Os': 'linux'}
        docker.call.side_effect = [SimpleNamespace(returncode=0, stdout=json.dumps([row]).encode()),
            SimpleNamespace(returncode=0, stdout=b''), SimpleNamespace(returncode=1, stdout=b'No such image')]
        self.assertEqual(job.cleanup_base(docker, Mock(), self.root, self.image, True, baseline)['status'], 'PASS')
        self.assertEqual(docker.call.call_args_list[1].args[1], ['image', 'rm', '--no-prune', self.image])
        docker.call.side_effect = [SimpleNamespace(returncode=0, stdout=json.dumps([row]).encode()),
            SimpleNamespace(returncode=1, stdout=b'image in use')]
        with self.assertRaises(ValueError): job.cleanup_base(docker, Mock(), self.root, self.image, True, baseline)

    def test_finish_public_is_allowlist_and_late_cancel_preserves_fail(self):
        out = self.args.output; (out / 'private').mkdir(parents=True); (out / 'public').mkdir()
        status = job.initial(self.args); private = {'status': dict(status), 'secret_log': 'never public'}
        @contextmanager
        def defer(): yield [15]
        with patch.object(job.runtime, 'defer_signals', defer):
            with self.assertRaises(job.runtime.Cancelled): job.finish(out, status, private)
        value = job.packet.load(out / 'public/status.json')
        self.assertEqual((value['status'], value['cancelled']), ('FAIL', True))
        self.assertNotIn('secret_log', value)

    def test_failed_final_publication_does_not_leave_stale_pass(self):
        out = self.args.output; (out / 'private').mkdir(parents=True); (out / 'public').mkdir()
        status = job.initial(self.args)
        for path in (out / 'private/result.json', out / 'public/status.json'): job.save(path, {'status': 'PASS'})
        with patch.object(job, 'save', side_effect=OSError('injected publication failure')):
            with self.assertRaises(OSError): job.finish(out, status, {'status': status})
        self.assertFalse((out / 'public/status.json').exists()); self.assertFalse((out / 'private/result.json').exists())

    def controller_fixture(self):
        accepted = self.root / 'accepted'; accepted.mkdir()
        job.save(accepted / 'bootstrap.json', {'status': 'fixture'}); job.save(accepted / 'result.json', {'status': 'fixture'})
        fake = Mock(); fake.info.return_value = {'id': 'fixture-daemon', 'architecture': 'aarch64'}; fake.daemon = fake.info.return_value
        fake.inventory.return_value = set()
        fake.pins = [(1, 2, 0, 0, 0o100755), (1, 3, 0, 0, 0o140660)]
        fake.image.return_value = {'id': self.image, 'architecture': 'arm64', 'os': 'linux', 'config': {},
            'rootfs': {'type': 'layers', 'layers': []}, 'size': 1, 'parent': None, 'repo_tags': [], 'repo_digests': []}
        row = {'Id': self.image, 'Architecture': 'arm64', 'Os': 'linux'}
        fake.call.side_effect = [SimpleNamespace(returncode=0, stdout=json.dumps([row]).encode()),
            SimpleNamespace(returncode=0, stdout=b''), SimpleNamespace(returncode=1, stdout=b'No such image')]
        phases = []; self.parallel_override = None
        self.child_receipt_change = None; self.child_exit = 0
        def runner(seconds, env, logs):
            instance = Mock(deadline=job.snapshot_clock() + seconds); instance.run_many.return_value = [SimpleNamespace(returncode=0), SimpleNamespace(returncode=0)]
            if seconds == job.PARALLEL and self.parallel_override is not None:
                if isinstance(self.parallel_override, BaseException): instance.run_many.side_effect = self.parallel_override
                else: instance.run_many.return_value = self.parallel_override
            instance.run.return_value = SimpleNamespace(returncode=0, stdout=b'')
            if seconds == job.KERNEL_ENVELOPE:
                def child(command, **kwargs):
                    out = Path(command[command.index('--output') + 1]); (out / 'private').mkdir(parents=True)
                    bind = {'source_commit': self.args.source_commit, 'stage_lock_sha256': job.packet.KERNEL_SHA,
                        'output_name_sha256': job.packet.sha(out.name.encode()), 'run_id': '1', 'run_attempt': '1',
                        'nonce': '9' * 32, 'accepted_result_sha256': job.packet.sha(job.packet.read(accepted / 'result.json')),
                        'bootstrap_sha256': job.packet.sha(job.packet.read(accepted / 'bootstrap.json')),
                        'inputs_sha256': job.packet.INPUTS_SHA, 'base_inventory_sha256': job.BASE_SHA}
                    diagnostic = child_evidence.initial(bind, child_evidence.Trace())
                    diagnostic.update(current_predicate='COMPLETE',
                        commands={name: child_evidence.exit_record(0) for name in child_evidence.ACTIONS},
                        cleanup={'status': 'PASS', 'category': 'NONE'})
                    record = {'source_commit': self.args.source_commit, 'stage_lock_sha256': job.packet.KERNEL_SHA,
                        'nonce': bind['nonce'], 'status': 'PASS', 'phase': 'complete', 'cancelled': False,
                        'native_kernel_compilation': 'PASS', 'kernel_execution': 'NOT RUN',
                        'hardware_validation': 'NOT RUN', 'performance': 'NOT MEASURED',
                        'cleanup': {'status': 'PASS'}, 'diagnostics': diagnostic}
                    for name in ('probe', 'baseline', 'candidate'):
                        record[name] = {'status': 'PASS', 'action': name, 'cancelled': False, 'nonce': bind['nonce']}
                    if callable(self.child_receipt_change): self.child_receipt_change(record)
                    if self.child_receipt_change is not False: job.save(out / 'private/result.json', record)
                    return SimpleNamespace(returncode=self.child_exit, stdout=b'')
                instance.run.side_effect = child
            phases.append((seconds, instance)); return instance
        def source(*args, **kwargs): args[5].mkdir(parents=True); return {'status': 'PASS'}
        self.patches = [patch.object(job, '__file__', str(self.root / 'scripts/port/kernel-native-job/job.py')),
            patch.dict(job.os.environ, {'GITHUB_WORKSPACE': str(self.root), 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}),
            patch.object(job, 'ordinary'), patch.object(job.packet, 'verify', side_effect=source),
            patch.object(job, 'Docker', return_value=fake), patch.object(job.runtime, 'Runner', side_effect=runner),
            patch.object(job, 'accepted_producer', return_value=(self.image, accepted)),
            patch.object(job, 'acquired_paths', return_value={key: self.root / key for key in
                ('archive', 'config', 'patch', 'bio-baseline', 'bio-candidate', 'package-cache', 'key-dir')}),
            patch.object(job, 'kernel_status', return_value={'status': 'PASS'}),
            patch.object(job, 'kernel_owned_absence', return_value=True),
            patch.object(job.shutil, 'disk_usage', return_value=SimpleNamespace(free=30 * 1024**3))]
        for item in self.patches: item.start(); self.addCleanup(item.stop)
        return fake, phases

    def failure_receipts(self, phase, reason, cancelled=False):
        public_record = job.packet.load(self.args.output / 'public/status.json')
        private_record = job.packet.load(self.args.output / 'private/result.json')
        self.assertEqual(public_record, private_record['status'])
        self.assertEqual((public_record['status'], public_record['first_failed_phase'], public_record['failure_reason'],
            public_record['cancelled']), ('FAIL', phase, reason, cancelled))
        self.assertEqual((private_record['failure_phase'], private_record['failure_reason']), (phase, reason))
        self.assertEqual(job.public.project(json.dumps(public_record).encode(), self.args.source_commit,
            self.args.packet_sha256, 'success'), public_record)
        return public_record, private_record

    def test_actual_child_nonzero_retains_inner_predicate_and_outer_first_failure(self):
        self.controller_fixture(); self.child_exit = 1
        def failed(record):
            record.update(status='FAIL', phase='provision', native_kernel_compilation='NOT RUN',
                          cleanup={'status': 'FAIL'})
            for name in ('probe', 'baseline', 'candidate'): record.pop(name)
            row = record['diagnostics']; row['current_predicate'] = 'PROVISION_COMMAND'
            row['commands'] = {name: {'kind': 'NOT_RUN', 'code': None} for name in child_evidence.ACTIONS}
            row['commands']['provision'] = child_evidence.exit_record(125)
            row['cleanup'] = {'status': 'FAIL', 'category': 'UNCERTAIN_MUTATION'}
            child_evidence.failure(row, 'COMMAND_NONZERO')
        self.child_receipt_change = failed
        with patch.object(job, 'kernel_owned_absence', side_effect=ValueError('owned-absence-unverified')):
            self.assertEqual(job.execute(self.args), 1)
        status, _ = self.failure_receipts('kernel', 'KERNEL_EXIT')
        self.assertEqual(status['kernel_child']['availability'], 'VERIFIED')
        self.assertEqual(status['kernel_child']['exit'], job.public.exit_record(1))
        self.assertEqual(status['kernel_child']['diagnostics']['commands']['provision'], job.public.exit_record(125))
        self.assertEqual(status['kernel_child']['diagnostics']['first_failed_predicate'], 'PROVISION_COMMAND')
        self.assertEqual(status['kernel_probe'], 'NOT RUN'); self.assertEqual(status['native_compilation'], 'NOT RUN')
        self.assertEqual(status['cleanup'], 'FAIL')
        self.assertEqual(status['daemon_baseline']['owned_absence'], 'UNVERIFIED')

    def test_returned_child_failure_without_receipt_does_not_invent_child_predicate(self):
        self.controller_fixture(); self.child_exit = 1; self.child_receipt_change = False
        self.assertEqual(job.execute(self.args), 1)
        status, _ = self.failure_receipts('kernel', 'KERNEL_EXIT')
        self.assertEqual(status['kernel_child'], {'availability': 'UNAVAILABLE',
            'exit': job.public.exit_record(1), 'diagnostics': None})

    def test_zero_child_without_bound_diagnostics_cannot_accept_terminal_pair(self):
        self.controller_fixture(); self.child_receipt_change = lambda row: row.pop('diagnostics')
        self.assertEqual(job.execute(self.args), 1)
        status, _ = self.failure_receipts('kernel', 'KERNEL_RECEIPT_REJECTED')
        self.assertEqual(status['kernel_child'], {'availability': 'UNVERIFIED',
            'exit': job.public.exit_record(0), 'diagnostics': None})
        self.assertNotEqual(status['native_compilation'], 'PASS')
        self.assertEqual((status['kernel_probe'], status['baseline'], status['candidate']), ('NOT RUN',) * 3)
        self.assertEqual(status['cleanup'], 'FAIL')

    def test_missing_capture_cannot_be_promoted_by_later_file_creation(self):
        self.controller_fixture(); self.child_exit = 1; self.child_receipt_change = False
        actual = job.child_observation; captures = []
        def capture(args, output, invocation, row):
            captures.append(output)
            result = actual(args, output, invocation, row)
            job.save(output / 'private/result.json', {'diagnostics': 'later secret receipt'})
            return result
        with patch.object(job, 'child_observation', side_effect=capture):
            self.assertEqual(job.execute(self.args), 1)
        status, _ = self.failure_receipts('kernel', 'KERNEL_EXIT')
        self.assertEqual(len(captures), 1)
        self.assertEqual((status['kernel_child']['availability'], status['kernel_child']['diagnostics']), ('UNAVAILABLE', None))

    def next_output(self, index):
        self.args.output = self.args.output.with_name('job-case-' + str(index))

    def test_initial_schema_has_no_invented_resource_or_exit_observations(self):
        status = job.initial(self.args)
        self.assertEqual(set(status), job.public.KEYS); self.assertEqual(len(status), 26)
        self.assertEqual(status['schema_version'], 4)
        self.assertEqual(status['kernel_child'], {'availability': 'NOT_RUN',
            'exit': {'kind': 'NOT_RUN', 'code': None}, 'diagnostics': None})
        self.assertEqual(status['resources'], {name: None for name in job.public.RESOURCE_KEYS})
        for name in ('producer_exit', 'acquisition_exit'):
            self.assertEqual(status[name], {'kind': 'NOT_RUN', 'code': None})

    @contextmanager
    def native_profile(self, memory, free):
        original = Path.read_text
        def read(path, *args, **kwargs):
            if str(path) == '/proc/self/status': return 'CapEff:\t0000000000000000\nCapPrm:\t0000000000000000\n'
            if str(path) == '/proc/meminfo': return memory
            return original(path, *args, **kwargs)
        with patch.object(job.platform, 'system', return_value='Linux'), patch.object(job.platform, 'machine', return_value='aarch64'), \
             patch.object(job.os, 'getuid', return_value=1001), patch.object(job.os, 'geteuid', return_value=1001), \
             patch.object(job.os, 'getgid', return_value=1001), patch.object(job.os, 'getegid', return_value=1001), \
             patch.dict(job.os.environ, {'GITHUB_REPOSITORY': 'Gabriel-Kahen/cachy-asahi', 'RUNNER_ARCH': 'ARM64', 'RUNNER_OS': 'Linux'}), \
             patch.object(Path, 'read_text', read), patch.object(Path, 'is_file', return_value=True), \
             patch.object(job.os, 'access', return_value=True), patch.object(job.shutil, 'disk_usage', return_value=SimpleNamespace(free=free)):
            yield

    def test_ordinary_records_actual_resource_scalars_before_memory_or_disk_refusal(self):
        gib = 1024**3
        cases = ((15 * gib, 14 * gib, 30 * gib, None),
                 (15 * gib - 1024, 14 * gib, 30 * gib, 'host-memory-reserve'),
                 (15 * gib, 14 * gib - 1024, 30 * gib, 'host-memory-reserve'),
                 (None, 14 * gib, 30 * gib, 'host-memory-reserve'),
                 (15 * gib, None, 30 * gib, 'host-memory-reserve'),
                 (15 * gib, 14 * gib, 30 * gib - 1, 'host-disk-reserve'))
        for total, available, free, error in cases:
            with self.subTest(total=total, available=available, free=free):
                memory = ''.join(name + ': ' + str(value // 1024) + ' kB\n' for name, value in
                    (('MemTotal', total), ('MemAvailable', available)) if value is not None)
                resources = job.initial(self.args)['resources']
                with self.native_profile(memory, free):
                    if error:
                        with self.assertRaisesRegex(ValueError, error): job.ordinary(self.args, resources)
                    else: job.ordinary(self.args, resources)
                self.assertEqual(resources, {'mem_total_bytes': total, 'mem_available_bytes': available,
                    'initial_free_disk_bytes': free if error != 'host-memory-reserve' else None,
                    'pre_kernel_free_disk_bytes': None})

    def test_preflight_resource_refusal_has_bounded_public_and_private_cause(self):
        actual_ordinary = job.ordinary; self.controller_fixture(); gib = 1024**3
        for index, (memory, free, reason) in enumerate((('MemTotal: 1 kB\nMemAvailable: 2 kB\n', 30 * gib, 'HOST_MEMORY_RESERVE'),
                ('MemTotal: 15728640 kB\nMemAvailable: 14680064 kB\n', 30 * gib - 1, 'HOST_DISK_RESERVE'))):
            with self.subTest(reason=reason):
                self.next_output(index)
                with self.native_profile(memory, free), patch.object(job, 'ordinary', side_effect=actual_ordinary):
                    self.assertEqual(job.execute(self.args), 1)
                status, _ = self.failure_receipts('preflight', reason)
                self.assertEqual(status['resources']['pre_kernel_free_disk_bytes'], None)
                self.assertEqual(status['resources']['initial_free_disk_bytes'], free if index else None)
                self.assertEqual(status['resources']['mem_total_bytes'], 15 * gib if index else 1024)
                self.assertEqual(status['resources']['mem_available_bytes'], 14 * gib if index else 2048)

    def test_parallel_observed_exits_distinguish_first_failure_and_survive_cleanup_failure(self):
        _, phases = self.controller_fixture()
        for index, (codes, reason) in enumerate((([1, 0], 'PRODUCER_EXIT'), ([0, 1], 'ACQUISITION_EXIT'),
                                                ([1, -15], 'BOTH_CHILDREN_EXIT'))):
            with self.subTest(codes=codes):
                self.next_output(index)
                self.parallel_override = [SimpleNamespace(returncode=code) for code in codes]
                self.assertEqual(job.execute(self.args), 1)
                status, _ = self.failure_receipts('parallel', reason)
                self.assertEqual(status['producer_exit'], job.public.exit_record(codes[0]))
                self.assertEqual(status['acquisition_exit'], job.public.exit_record(codes[1]))
                self.assertEqual(status['cleanup'], 'FAIL')
                self.assertEqual(status['producer'], 'FAIL' if codes[0] else 'NOT RUN')
                self.assertEqual(status['baseline'], 'NOT RUN')
        self.assertFalse(any(seconds == job.KERNEL_ENVELOPE for seconds, _ in phases))

    def test_parallel_exceptions_are_finite_unobserved_and_do_not_export_secret_text(self):
        self.controller_fixture()
        secret = '/private/secret-token-12345'
        cases = ((job.runtime.Cancelled(15), 'CANCELLED', True),
            (ValueError('command-timeout'), 'PARALLEL_TIMEOUT', False),
            (ValueError('deadline-exhausted'), 'PARALLEL_TIMEOUT', False),
            (ValueError('output-bound'), 'PARALLEL_OUTPUT_BOUND', False),
            (ValueError(secret), 'PARALLEL_RUN_FAILED', False),
            (RuntimeError('command-timeout ' + secret), 'PARALLEL_RUN_FAILED', False))
        for index, (error, reason, cancelled) in enumerate(cases):
            with self.subTest(reason=reason, error=type(error).__name__):
                self.next_output(index); self.parallel_override = error
                self.assertEqual(job.execute(self.args), 1)
                status, private = self.failure_receipts('parallel', reason, cancelled)
                for name in ('producer_exit', 'acquisition_exit'):
                    self.assertEqual(status[name], {'kind': 'UNOBSERVED', 'code': None})
                self.assertEqual(status['cleanup'], 'FAIL')
                self.assertNotIn(secret, json.dumps(status)); self.assertNotIn(secret, json.dumps(private))

    def test_malformed_parallel_results_fail_closed_without_partial_exit_or_secret_leak(self):
        self.controller_fixture(); secret = '/private/secret-malformed-result'
        cases = ([], [SimpleNamespace(returncode=0)], [SimpleNamespace(returncode=0)] * 3,
                 secret, [SimpleNamespace(returncode=0), SimpleNamespace(returncode=True)],
                 [SimpleNamespace(returncode=False), SimpleNamespace(returncode=0)],
                 [SimpleNamespace(returncode=secret), SimpleNamespace(returncode=0)],
                 [SimpleNamespace(returncode=0), SimpleNamespace(returncode=2**100)],
                 [SimpleNamespace(returncode=-65), SimpleNamespace(returncode=0)])
        for index, result in enumerate(cases):
            with self.subTest(index=index):
                self.next_output(index); self.parallel_override = result
                self.assertEqual(job.execute(self.args), 1)
                status, private = self.failure_receipts('parallel', 'PARALLEL_RUN_FAILED')
                for name in ('producer_exit', 'acquisition_exit'):
                    self.assertEqual(status[name], {'kind': 'UNOBSERVED', 'code': None})
                self.assertNotIn(secret, json.dumps(status)); self.assertNotIn(secret, json.dumps(private))

    def test_zero_child_exits_do_not_accept_rejected_producer_or_acquisition_receipts(self):
        self.controller_fixture()
        for index, (target, phase, reason) in enumerate((('accepted_producer', 'producer', 'PRODUCER_RECEIPT_REJECTED'),
                ('acquired_paths', 'acquisition', 'ACQUISITION_RECEIPT_REJECTED'))):
            with self.subTest(target=target):
                self.next_output(index)
                with patch.object(job, target, side_effect=ValueError('/private/secret-receipt')):
                    self.assertEqual(job.execute(self.args), 1)
                status, private = self.failure_receipts(phase, reason)
                self.assertEqual(status['producer_exit'], job.public.exit_record(0))
                self.assertEqual(status['acquisition_exit'], job.public.exit_record(0))
                self.assertEqual(status['baseline'], 'NOT RUN')
                self.assertNotIn('secret-receipt', json.dumps(private))

    def test_guard_causes_survive_cleanup_and_capture_measured_pre_kernel_disk(self):
        self.controller_fixture()
        cases = (([0, 301], 30 * 1024**3, 'source', 'PRODUCER_TIME_RESERVE'),
                 ([0, 0, 2351], 30 * 1024**3, 'kernel', 'KERNEL_TIME_RESERVE'),
                 ([0, 0, 0], 8 * 1024**3 - 1, 'kernel', 'KERNEL_DISK_RESERVE'))
        for index, (clock, free, phase, reason) in enumerate(cases):
            with self.subTest(reason=reason):
                self.next_output(index)
                with patch.object(job.time, 'monotonic', side_effect=clock), patch.object(job.shutil, 'disk_usage', return_value=SimpleNamespace(free=free)):
                    self.assertEqual(job.execute(self.args), 1)
                status, _ = self.failure_receipts(phase, reason)
                expected = {name: None for name in job.public.RESOURCE_KEYS}
                if reason == 'KERNEL_DISK_RESERVE': expected['pre_kernel_free_disk_bytes'] = free
                self.assertEqual(status['resources'], expected)

    def test_mocked_ordinary_does_not_invent_initial_resource_measures(self):
        self.controller_fixture(); self.assertEqual(job.execute(self.args), 0)
        status = job.packet.load(self.args.output / 'public/status.json')
        self.assertEqual(status['resources'], {name: 30 * 1024**3 if name == 'pre_kernel_free_disk_bytes' else None
            for name in job.public.RESOURCE_KEYS})

    def test_controller_only_accepts_complete_native_and_cleanup_receipts(self):
        fake, phases = self.controller_fixture()
        self.assertEqual(job.execute(self.args), 0)
        status = job.packet.load(self.args.output / 'public/status.json')
        self.assertEqual(status['status'], 'PASS'); self.assertEqual(status['phase'], 'complete')
        self.assertEqual([seconds for seconds, _ in phases], [300, 2050, 18240, 150])
        command = phases[2][1].run.call_args.args[0]
        self.assertEqual(command[command.index('--image') + 1], self.image)
        self.assertNotIn('secret', status)

    def test_budget_refusal_after_producer_never_starts_kernel(self):
        _, phases = self.controller_fixture()
        with patch.object(job.time, 'monotonic', side_effect=[0, 0, 2351]):
            self.assertEqual(job.execute(self.args), 1)
        self.assertEqual([seconds for seconds, _ in phases], [300, 2050, 150])
        status = job.packet.load(self.args.output / 'public/status.json')
        self.assertEqual((status['status'], status['producer'], status['baseline']), ('FAIL', 'PASS', 'NOT RUN'))

    def test_interrupted_producer_never_launches_kernel_or_infers_absence(self):
        _, phases = self.controller_fixture()
        original = job.runtime.Runner.side_effect
        def runner(seconds, env, logs):
            instance = original(seconds, env, logs)
            if seconds == job.PARALLEL: instance.run_many.side_effect = job.runtime.Cancelled(15)
            return instance
        job.runtime.Runner.side_effect = runner
        self.assertEqual(job.execute(self.args), 1)
        status = job.packet.load(self.args.output / 'public/status.json')
        self.assertTrue(status['cancelled']); self.assertEqual(status['cleanup'], 'FAIL')
        self.assertEqual([seconds for seconds, _ in phases], [300, 2050, 150])
        self.assertEqual(status['candidate'], 'NOT RUN')

    def test_outer_cleanup_failure_revokes_completed_kernel_acceptance(self):
        fake, _ = self.controller_fixture(); fake.call.side_effect = OSError('injected daemon loss')
        self.assertEqual(job.execute(self.args), 1)
        status = job.packet.load(self.args.output / 'public/status.json')
        self.assertEqual((status['status'], status['baseline'], status['candidate'], status['native_compilation']),
            ('FAIL', 'PASS', 'PASS', 'NOT ACCEPTED'))
        self.failure_receipts('cleanup', 'OWNED_ABSENCE_UNVERIFIED')

    def main_argv(self):
        return ['--execute-native', '--source-root', str(self.args.source_root), '--source-commit', self.args.source_commit,
            '--packet', str(self.args.packet), '--packet-sha256', self.args.packet_sha256, '--output', str(self.args.output),
            '--docker-binary', str(self.args.docker_binary), '--docker-sha256', self.args.docker_sha256,
            '--docker-endpoint', self.args.docker_endpoint]

    def test_real_sigterm_during_final_restoration_keeps_fail_and_restores_pair(self):
        self.controller_fixture()
        previous = {number: signal.getsignal(number) for number in job.runtime.SIGNALS}
        actual = signal.signal; original_finish = job.finish; armed = False; injected = False
        def finish(*args):
            nonlocal armed
            result = original_finish(*args)
            if args[1]['phase'] == 'complete': armed = True
            return result
        def restore(number, handler):
            nonlocal injected
            result = actual(number, handler)
            if armed and not injected and number == signal.SIGINT and handler == previous[number]:
                injected = True; os.kill(os.getpid(), signal.SIGTERM)
            return result
        try:
            with patch.object(job, 'finish', side_effect=finish), patch.object(signal, 'signal', side_effect=restore):
                self.assertEqual(job.main(self.main_argv()), 1)
            self.assertTrue(injected)
            public_record = job.packet.load(self.args.output / 'public/status.json')
            self.failure_receipts('finalization', 'CANCELLED', cancelled=True)
            self.assertEqual((public_record['status'], public_record['cancelled'], public_record['native_compilation']),
                ('FAIL', True, 'NOT ACCEPTED'))
            self.assertEqual({number: signal.getsignal(number) for number in job.runtime.SIGNALS}, previous)
        finally:
            for number, handler in previous.items(): actual(number, handler)

    def test_parallel_failure_survives_real_sigterm_during_final_guard_restoration(self):
        self.controller_fixture()
        self.parallel_override = [SimpleNamespace(returncode=1), SimpleNamespace(returncode=0)]
        previous = {number: signal.getsignal(number) for number in job.runtime.SIGNALS}
        actual = signal.signal; original_finish = job.finish; armed = False; injected = False
        def finish(*args):
            nonlocal armed
            result = original_finish(*args)
            if args[1]['phase'] == 'cleanup': armed = True
            return result
        def restore(number, handler):
            nonlocal injected
            result = actual(number, handler)
            if armed and not injected and number == signal.SIGINT and handler == previous[number]:
                injected = True; os.kill(os.getpid(), signal.SIGTERM)
            return result
        try:
            with patch.object(job, 'finish', side_effect=finish), patch.object(signal, 'signal', side_effect=restore):
                self.assertEqual(job.main(self.main_argv()), 1)
            self.assertTrue(injected)
            status, _ = self.failure_receipts('parallel', 'PRODUCER_EXIT', cancelled=True)
            self.assertEqual(status['producer_exit'], job.public.exit_record(1))
            self.assertEqual(status['acquisition_exit'], job.public.exit_record(0))
            self.assertEqual({number: signal.getsignal(number) for number in job.runtime.SIGNALS}, previous)
        finally:
            for number, handler in previous.items(): actual(number, handler)

    def test_final_pass_publication_follows_handler_restoration(self):
        self.controller_fixture()
        previous = {number: signal.getsignal(number) for number in job.runtime.SIGNALS}
        original = job.publish; published = []
        def publish(out, status, private):
            if status['status'] == 'PASS':
                self.assertEqual({number: signal.getsignal(number) for number in previous}, previous)
                self.assertEqual(job.packet.load(out / 'public/status.json')['status'], 'FAIL')
                published.append(status)
            return original(out, status, private)
        with patch.object(job, 'publish', side_effect=publish):
            self.assertEqual(job.main(self.main_argv()), 0)
        self.assertEqual(len(published), 1)
        self.assertEqual(job.packet.load(self.args.output / 'public/status.json')['status'], 'PASS')

    def test_real_cleanup_restoration_cancel_discards_pending_pass(self):
        self.controller_fixture()
        actual = signal.signal; original = job.finish; armed = False; injected = False
        def finish(*args):
            nonlocal armed
            result = original(*args)
            if args[1]['phase'] == 'complete': armed = True
            return result
        def restore(number, handler):
            nonlocal injected
            result = actual(number, handler)
            if armed and not injected and number == signal.SIGINT and getattr(handler, '__name__', '') == 'cancel':
                injected = True; os.kill(os.getpid(), signal.SIGTERM)
            return result
        with patch.object(job, 'finish', side_effect=finish), patch.object(signal, 'signal', side_effect=restore):
            self.assertEqual(job.main(self.main_argv()), 1)
        self.assertTrue(injected)
        record = job.packet.load(self.args.output / 'public/status.json')
        self.assertEqual((record['status'], record['cancelled'], record['native_compilation']),
            ('FAIL', True, 'NOT ACCEPTED'))
        self.assertEqual(record, job.packet.load(self.args.output / 'private/result.json')['status'])

    def test_actual_sigterm_at_final_unmask_leaves_bound_fail(self):
        script = r'''
import json, os, signal, sys, tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, sys.argv[1])
import job
from test_job import JobContracts
parent = Path(sys.argv[2]); temporary = tempfile.TemporaryDirectory
with patch.object(tempfile, 'TemporaryDirectory', side_effect=lambda *a, **kw: temporary(*a, dir=parent, **kw)):
    case = JobContracts(); case.setUp()
case.controller_fixture()
signal.signal(signal.SIGTERM, signal.SIG_DFL)
old = {s: signal.getsignal(s) for s in job.runtime.SIGNALS}
(parent / 'child-output.json').write_text(json.dumps(str(case.args.output)))
armed = False; actual_finish = job.finish; actual_mask = signal.pthread_sigmask
def finish(*args):
    global armed
    result = actual_finish(*args)
    if args[1]['phase'] == 'complete': armed = True
    return result
def unmask(how, mask):
    if armed and how == signal.SIG_SETMASK and signal.SIGTERM not in mask and all(signal.getsignal(s) == old[s] for s in old):
        (parent / 'term-injected').write_text('actual TERM after pending scan')
        os.kill(os.getpid(), signal.SIGTERM)
    return actual_mask(how, mask)
with patch.object(job, 'finish', side_effect=finish), patch.object(signal, 'pthread_sigmask', side_effect=unmask):
    job.main(case.main_argv())
'''
        result = subprocess.run([sys.executable, '-I', '-B', '-c', script,
            str(Path(job.__file__).parent), str(self.root)], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, -signal.SIGTERM, result.stderr)
        self.assertTrue((self.root / 'term-injected').is_file())
        out = Path(json.loads((self.root / 'child-output.json').read_text()))
        raw = job.packet.load(out / 'public/status.json')
        self.assertEqual(raw, job.packet.load(out / 'private/result.json')['status'])
        self.assertEqual((raw['status'], raw['native_compilation']), ('FAIL', 'NOT ACCEPTED'))
        self.assertEqual(job.public.project((out / 'public/status.json').read_bytes(),
            self.args.source_commit, self.args.packet_sha256, 'failure')['status'], 'FAIL')

    def test_slow_initial_receipt_consumes_budget_before_producer_launch(self):
        _, phases = self.controller_fixture(); clock = 0; original = job.finish
        def finish(out, status, private):
            nonlocal clock
            value = original(out, status, private)
            if status['phase'] == 'preflight': clock += 600
            return value
        with patch.object(job, 'finish', side_effect=finish), patch.object(job.time, 'monotonic', side_effect=lambda: clock):
            self.assertEqual(job.execute(self.args), 1)
        self.assertEqual([seconds for seconds, _ in phases], [job.SETUP, job.CLEANUP])
        record = job.packet.load(self.args.output / 'public/status.json')
        self.assertEqual((record['status'], record['producer'], record['baseline']), ('FAIL', 'NOT RUN', 'NOT RUN'))

    def test_startup_exact_remaining_budget_boundary_is_enforced(self):
        _, phases = self.controller_fixture(); original = job.finish; clock = 0
        def finish(out, status, private):
            nonlocal clock
            value = original(out, status, private)
            if status['phase'] == 'preflight': clock += job.SETUP
            return value
        with patch.object(job, 'finish', side_effect=finish), patch.object(job.time, 'monotonic', side_effect=lambda: clock):
            self.assertEqual(job.execute(self.args), 0)
        self.assertEqual([seconds for seconds, _ in phases], [job.SETUP, job.PARALLEL, job.KERNEL_ENVELOPE, job.CLEANUP])



    def populated_controller(self, borrowed=None):
        fake, phases = self.controller_fixture()
        baseline_id = borrowed or 'sha256:' + 'e' * 64
        rows = {baseline_id: {'id': baseline_id, 'architecture': 'amd64', 'os': 'linux',
            'config': {'Env': ['TOKEN=private-baseline']}, 'rootfs': {'type': 'layers', 'layers': []},
            'size': 5, 'parent': None, 'repo_tags': ['borrowed:a', 'borrowed:b'], 'repo_digests': []}}
        new = json.loads(json.dumps(fake.image.return_value))
        fake.image.side_effect = lambda runner, image: json.loads(json.dumps(rows[image]))
        fake.inventory.side_effect = lambda runner, kind: set(rows) if kind == 'image' else set()
        accepted = job.accepted_producer.return_value
        def accept(*args):
            if self.image not in rows: rows[self.image] = new
            return accepted
        job.accepted_producer.side_effect = accept
        def call(runner, argv):
            if argv[:2] == ['image', 'rm']:
                del rows[argv[-1]]; return SimpleNamespace(returncode=0, stdout=b'')
            if argv[:2] == ['image', 'inspect']:
                if argv[-1] in rows:
                    return SimpleNamespace(returncode=0, stdout=json.dumps([{'Id': argv[-1], 'Architecture': 'arm64', 'Os': 'linux'}]).encode())
                return SimpleNamespace(returncode=1, stdout=b'No such image')
            raise AssertionError(argv)
        fake.call.side_effect = call
        return fake, phases, rows, baseline_id

    def test_controller_accepts_preserved_populated_baseline_without_exporting_metadata(self):
        fake, _, rows, baseline_id = self.populated_controller()
        self.assertEqual(job.execute(self.args), 0)
        status = job.packet.load(self.args.output / 'public/status.json'); summary = status['daemon_baseline']
        self.assertEqual(summary['initial_image_id_count'], 1)
        self.assertEqual((summary['preservation'], summary['owned_absence'], summary['producer_mutation']),
            ('PASS', 'PASS', 'COMPLETE_ACCEPTED'))
        self.assertEqual(summary['pre_identity_sha256'], summary['post_identity_sha256'])
        self.assertEqual(set(rows), {baseline_id})
        self.assertNotIn('private-baseline', json.dumps(status)); self.assertNotIn('borrowed:a', json.dumps(status))
        removals = [row.args[1] for row in fake.call.call_args_list if row.args[1][:2] == ['image', 'rm']]
        self.assertEqual(removals, [['image', 'rm', '--no-prune', self.image]])

    def test_controller_borrowed_producer_IID_refuses_kernel_and_all_image_removal(self):
        fake, phases, rows, baseline_id = self.populated_controller(self.image)
        self.assertEqual(job.execute(self.args), 1)
        status, _ = self.failure_receipts('producer', 'PRODUCER_BASELINE_ID_COLLISION')
        self.assertEqual(status['producer'], 'FAIL')
        self.assertEqual(status['daemon_baseline']['producer_mutation'], 'COMPLETE_REJECTED')
        self.assertEqual(status['daemon_baseline']['preservation'], 'PASS')
        self.assertEqual([seconds for seconds, _ in phases], [job.SETUP, job.PARALLEL, job.CLEANUP])
        self.assertIn(baseline_id, rows); fake.call.assert_not_called()
        self.assertFalse((self.args.output / 'private/base-ownership.json').exists())

    def test_controller_known_new_base_does_not_delete_unexplained_image_ids(self):
        fake, _, rows, baseline_id = self.populated_controller()
        original = job.accepted_producer.side_effect; foreign = 'sha256:' + 'f' * 64
        def accept(*args):
            accepted = original(*args); row = json.loads(json.dumps(rows[baseline_id])); row['id'] = foreign
            row['repo_tags'] = []; rows[foreign] = row; return accepted
        job.accepted_producer.side_effect = accept
        self.assertEqual(job.execute(self.args), 0)
        self.assertEqual(set(rows), {baseline_id, foreign})
        summary = job.packet.load(self.args.output / 'public/status.json')['daemon_baseline']
        self.assertEqual(summary['legacy_build_cache'], 'NOT_ESTABLISHED')
        self.assertFalse(any(call.args[1][-1] == foreign for call in fake.call.call_args_list))

    def test_controller_postproducer_retag_refuses_kernel_and_preservation(self):
        _, phases, rows, baseline_id = self.populated_controller()
        original = job.accepted_producer.side_effect
        def accept(*args):
            result = original(*args); rows[baseline_id]['repo_tags'] = ['changed:a']; return result
        job.accepted_producer.side_effect = accept
        self.assertEqual(job.execute(self.args), 1)
        status, _ = self.failure_receipts('producer', 'DAEMON_BASELINE_CHANGED')
        self.assertEqual(status['daemon_baseline']['preservation'], 'FAIL')
        self.assertEqual(status['daemon_baseline']['producer_mutation'], 'COMPLETE_REJECTED')
        self.assertEqual(status['cleanup'], 'FAIL'); self.assertEqual(status['baseline'], 'NOT RUN')
        self.assertEqual([seconds for seconds, _ in phases], [job.SETUP, job.PARALLEL, job.CLEANUP])

    def test_initial_nonempty_containers_and_image_failure_have_distinct_typed_counts(self):
        fake, phases = self.controller_fixture()
        fake.inventory.side_effect = lambda runner, kind: {'a' * 64} if kind == 'container' else set()
        self.assertEqual(job.execute(self.args), 1)
        status, _ = self.failure_receipts('source', 'DAEMON_CONTAINERS_PRESENT')
        self.assertEqual(status['daemon_baseline']['initial_container_count'], 1)
        self.assertEqual(status['daemon_baseline']['initial_image_id_count'], 0)
        self.assertEqual(status['daemon_baseline']['producer_mutation'], 'NOT_STARTED')
        self.assertFalse(any(seconds == job.PARALLEL for seconds, _ in phases))
        self.next_output(2)
        def inventory(runner, kind):
            if kind == 'image': raise ValueError('malformed-query')
            return set()
        fake.inventory.side_effect = inventory
        self.assertEqual(job.execute(self.args), 1)
        status, _ = self.failure_receipts('source', 'DAEMON_BASELINE_UNVERIFIED')
        self.assertEqual(status['daemon_baseline']['initial_container_count'], 0)
        self.assertIsNone(status['daemon_baseline']['initial_image_id_count'])

    def test_baseline_journal_is_durable_before_either_child_launch(self):
        _, phases = self.controller_fixture(); factory = job.runtime.Runner.side_effect
        def runner(seconds, env, logs):
            instance = factory(seconds, env, logs)
            if seconds == job.PARALLEL:
                def children(*args, **kwargs):
                    path = self.args.output / 'private/daemon-baseline.json'
                    record = job.packet.load(path)
                    self.assertEqual(record['observations'][0]['stage'], 'before_producer')
                    self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(record['source_commit'], self.args.source_commit)
                    return [SimpleNamespace(returncode=0), SimpleNamespace(returncode=0)]
                instance.run_many.side_effect = children
            return instance
        job.runtime.Runner.side_effect = runner
        self.assertEqual(job.execute(self.args), 0)
        self.assertEqual([seconds for seconds, _ in phases], [job.SETUP, job.PARALLEL, job.KERNEL_ENVELOPE, job.CLEANUP])

    def test_kernel_owned_absence_failure_cannot_publish_base_only_cleanup_PASS(self):
        self.controller_fixture()
        with patch.object(job, 'kernel_owned_absence', side_effect=ValueError('kernel-owned-absence-unverified')):
            self.assertEqual(job.execute(self.args), 1)
        status, _ = self.failure_receipts('cleanup', 'OWNED_ABSENCE_UNVERIFIED')
        self.assertEqual(status['native_compilation'], 'NOT ACCEPTED')
        self.assertEqual(status['daemon_baseline']['preservation'], 'PASS')
        self.assertEqual(status['daemon_baseline']['owned_absence'], 'UNVERIFIED')

    def test_final_baseline_query_failure_cannot_publish_preservation_or_cleanup_PASS(self):
        fake, _, _, _ = self.populated_controller(); original = fake.call.side_effect; removed = False
        def call(runner, argv):
            nonlocal removed
            result = original(runner, argv)
            if argv[:2] == ['image', 'rm']: removed = True
            return result
        fake.call.side_effect = call; original_image = fake.image.side_effect
        def image(runner, identifier):
            if removed: raise ValueError('inventory-disconnected')
            return original_image(runner, identifier)
        fake.image.side_effect = image
        self.assertEqual(job.execute(self.args), 1)
        status, _ = self.failure_receipts('cleanup', 'DAEMON_BASELINE_UNVERIFIED')
        self.assertEqual(status['daemon_baseline']['owned_absence'], 'PASS')
        self.assertEqual(status['daemon_baseline']['preservation'], 'UNVERIFIED')
        self.assertIsNone(status['daemon_baseline']['post_identity_sha256'])

    def test_unknown_async_producer_is_not_repaired_by_final_preservation_PASS(self):
        _, _ = self.controller_fixture(); self.parallel_override = job.runtime.Cancelled(15)
        self.assertEqual(job.execute(self.args), 1)
        status, _ = self.failure_receipts('parallel', 'CANCELLED', True)
        self.assertEqual(status['daemon_baseline']['preservation'], 'PASS')
        self.assertEqual(status['daemon_baseline']['producer_mutation'], 'UNCERTAIN')
        self.assertEqual(status['daemon_baseline']['owned_absence'], 'UNVERIFIED')
        self.assertEqual(status['cleanup'], 'FAIL')

    def test_kernel_scoped_absence_receiver_requires_bound_positive_records(self):
        out = self.root / 'kernel-clean'; (out / 'private').mkdir(parents=True)
        daemon = {'id': 'fixture-daemon', 'architecture': 'aarch64'}
        clean = {'status': 'PASS', 'records': [
            {'status': 'PASS', 'absence_verified': True, 'cancelled': False, 'errors': []},
            {'status': 'PASS', 'absence_verified': True, 'commit_attempted': True}]}
        record = {'source_commit': self.args.source_commit, 'status': 'FAIL', 'kernel_execution': 'NOT RUN',
            'hardware_validation': 'NOT RUN', 'performance': 'NOT MEASURED', 'daemon': daemon,
            'accepted_base': {'image_id': self.image}, 'cleanup': clean}
        job.save(out / 'private/result.json', record)
        self.assertTrue(job.kernel_owned_absence(out, self.args.source_commit, self.image, daemon))
        with patch.object(job.packet, 'load', side_effect=AssertionError('second receipt read')):
            self.assertTrue(job.kernel_owned_absence(out, self.args.source_commit, self.image, daemon, record))
        changes = (lambda r: r['cleanup'].update(status='FAIL'), lambda r: r['cleanup'].update(records=[]),
            lambda r: r['cleanup']['records'][0].update(absence_verified=False),
            lambda r: r['cleanup']['records'][0].update(uncertain_commit=True),
            lambda r: r['cleanup']['records'][0].update(cancelled=True), lambda r: r.update(source_commit='f' * 40),
            lambda r: r['accepted_base'].update(image_id='sha256:' + 'f' * 64), lambda r: r.update(daemon={}),
            lambda r: r['cleanup'].update(records=r['cleanup']['records'][:1]),
            lambda r: r['cleanup'].update(records=r['cleanup']['records'][:1] * 2),
            lambda r: r['cleanup']['records'][0].update(errors=['failed-absence']),
            lambda r: r['cleanup']['records'][1].update(commit_attempted=1))
        for change in changes:
            altered = json.loads(json.dumps(record)); change(altered); job.save(out / 'private/result.json', altered)
            with self.assertRaisesRegex(ValueError, 'kernel-owned-absence-unverified'):
                job.kernel_owned_absence(out, self.args.source_commit, self.image, daemon)


    def test_actual_TERM_during_producer_receipt_acceptance_retains_bound_uncertain_FAIL(self):
        _, phases = self.controller_fixture()
        def receipt(*args): os.kill(os.getpid(), signal.SIGTERM)
        job.accepted_producer.side_effect = receipt
        self.assertEqual(job.execute(self.args), 1)
        status, _ = self.failure_receipts('producer', 'CANCELLED', True)
        self.assertEqual(status['producer'], 'FAIL')
        self.assertEqual(status['daemon_baseline']['producer_mutation'], 'UNCERTAIN')
        self.assertEqual(status['producer_exit'], {'kind': 'EXIT_ZERO', 'code': 0})
        self.assertEqual(status['cleanup'], 'FAIL')
        self.assertFalse(any(seconds == job.KERNEL_ENVELOPE for seconds, _ in phases))

    def test_actual_TERM_after_owned_base_acceptance_retains_closed_rejected_state(self):
        self.controller_fixture(); original = job.Baseline.observe
        def observe(baseline, runner, stage):
            if stage == 'before_kernel': os.kill(os.getpid(), signal.SIGTERM)
            return original(baseline, runner, stage)
        with patch.object(job.Baseline, 'observe', observe): self.assertEqual(job.execute(self.args), 1)
        status, _ = self.failure_receipts('producer', 'CANCELLED', True)
        self.assertEqual(status['producer'], 'FAIL')
        self.assertEqual(status['daemon_baseline']['producer_mutation'], 'COMPLETE_REJECTED')
        self.assertEqual(status['cleanup'], 'FAIL')


    def test_actual_TERM_at_state_transition_boundaries_always_retains_bound_FAIL(self):
        fake, _, _, _ = self.populated_controller()
        targets = ((job.Baseline.start.__code__, 'self.ready = True'),
            (job.work.__code__, "status.update(producer_exit={'kind': 'UNOBSERVED'"),
            (job.work.__code__, "status['daemon_baseline']['producer_mutation'] = 'COMPLETE_ACCEPTED'"))
        import inspect
        for index, (code, fragment) in enumerate(targets):
            with self.subTest(boundary=fragment):
                self.next_output('transition-' + str(index)); injected = False
                lines, offset = inspect.getsourcelines(code)
                target = next(offset + i for i, line in enumerate(lines) if fragment in line)
                previous = sys.gettrace()
                def trace(frame, event, arg):
                    nonlocal injected
                    if frame.f_code is code and event == 'line' and frame.f_lineno == target and not injected:
                        injected = True; os.kill(os.getpid(), signal.SIGTERM)
                    return trace
                try:
                    sys.settrace(trace); self.assertEqual(job.execute(self.args), 1)
                finally: sys.settrace(previous)
                self.assertTrue(injected)
                status = job.packet.load(self.args.output / 'public/status.json')
                private = job.packet.load(self.args.output / 'private/result.json')
                self.assertTrue(status['cancelled']); self.assertEqual(status['status'], 'FAIL')
                self.assertEqual(private['status'], status)
                self.assertEqual(job.public.project(json.dumps(status).encode(), self.args.source_commit,
                    self.args.packet_sha256, 'success'), status)


class BaselineContracts(unittest.TestCase):
    setUp = JobContracts.setUp

    def metadata(self, identifier, tags=None, arch='arm64', parent=''):
        return {'Id': identifier, 'Architecture': arch, 'Os': 'linux', 'Config': {'Env': ['SAMPLE=private'],
            'Labels': {'fixture': 'preserve'}, 'UnknownFutureKey': [1, True, None]},
            'RootFS': {'Type': 'layers', 'Layers': ['sha256:' + '1' * 64]}, 'Size': 123,
            'Parent': parent, 'RepoTags': tags or [], 'RepoDigests': []}

    def fixture(self, images=None):
        self.images = images or {}; self.containers = set(); self.removals = []; self.query_failure = {}
        self.daemon = job.Docker(self.args)
        self.daemon.daemon = {'id': 'fixture-daemon', 'architecture': 'aarch64'}
        self.daemon.pins = [(1, 2, 0, 0, 0o100755), (1, 3, 0, 0, 0o140660)]
        self.daemon.local = Mock(); self.daemon.info = Mock(return_value=self.daemon.daemon)
        def call(runner, argv):
            code, output = 0, b''
            if argv[0] in ('container', 'image') and argv[1] == 'ls':
                kind = argv[0]
                if kind in self.query_failure: return self.query_failure[kind]
                values = self.containers if kind == 'container' else self.images
                output = ('\n'.join(sorted(values)) + ('\n' if values else '')).encode()
            elif argv[:2] == ['image', 'inspect']:
                if argv[2] in self.images: output = json.dumps([self.images[argv[2]]]).encode()
                else: code, output = 1, b'No such image'
            elif argv[:2] == ['image', 'rm']:
                self.removals.append(argv)
                row = self.images.pop(argv[-1])
                # Model the documented ancestor deletion default; the test must
                # preserve an untagged ancestor through explicit no-prune.
                if '--no-prune' not in argv and row['Parent'] in self.images: del self.images[row['Parent']]
            else: raise AssertionError(argv)
            return SimpleNamespace(returncode=code, stdout=output)
        self.daemon.call = Mock(side_effect=call)
        self.summary = job.initial(self.args)['daemon_baseline']
        self.baseline = job.Baseline(self.args, self.daemon, self.root, self.summary)
        self.runner = Mock(deadline=job.snapshot_clock() + 60)
        self.env = patch.dict(job.os.environ, {'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '2'})
        self.env.start(); self.addCleanup(self.env.stop)
        return self.baseline

    def journal_base(self, identifier):
        job.save(self.root / 'base-ownership.json', {'image_id': identifier, 'daemon': self.daemon.daemon,
            'producer_finished': True, 'source_commit': self.args.source_commit,
            'producer_sha256': job.packet.HELPERS['scripts/ci/native_arm.py'][0],
            'baseline_identity_sha256': self.baseline.record['identity_sha256'],
            'nonce': self.baseline.record['nonce']})

    def test_full_borrowed_metadata_and_foreign_dangling_images_are_preserved(self):
        foreign, dangling = 'sha256:' + 'f' * 64, 'sha256:' + 'e' * 64
        baseline = self.fixture({foreign: self.metadata(foreign, ['fixture:a', 'fixture:b'], 'amd64'),
            dangling: self.metadata(dangling)})
        baseline.start(self.runner)
        self.assertEqual(baseline.protected(), {foreign, dangling})
        self.assertEqual(self.summary['initial_container_count'], 0)
        self.assertEqual(self.summary['initial_image_id_count'], 2)
        self.assertEqual(baseline.record['images'][1]['config']['UnknownFutureKey'], [1, True, None])
        record = job.packet.load(baseline.path)
        self.assertEqual(record, baseline.record); self.assertEqual(record['run_id'], '123')
        self.assertEqual(baseline.path.stat().st_mode & 0o777, 0o600)
        self.images[self.image] = self.metadata(self.image)
        baseline.observe(self.runner, 'before_kernel')
        del self.images[self.image]
        baseline.observe(self.runner, 'after_cleanup')
        self.assertEqual(self.summary['preservation'], 'PASS')
        self.assertEqual(self.summary['pre_identity_sha256'], self.summary['post_identity_sha256'])
        self.assertFalse(self.removals)

    def test_empty_baseline_is_positive_and_unowned_new_ids_are_never_removed(self):
        baseline = self.fixture(); baseline.start(self.runner)
        self.images[self.image] = self.metadata(self.image)
        baseline.observe(self.runner, 'before_kernel'); baseline.observe(self.runner, 'after_cleanup')
        self.assertEqual(self.summary['preservation'], 'PASS'); self.assertFalse(self.removals)
        self.assertEqual(self.summary['legacy_build_cache'], 'NOT_ESTABLISHED')
        self.assertEqual(baseline.record['observations'][-1]['image_id_count'], 1)

    def test_container_presence_does_not_short_circuit_the_image_query(self):
        baseline = self.fixture(); self.containers.add('a' * 64)
        with self.assertRaisesRegex(ValueError, 'baseline-containers-present'): baseline.start(self.runner)
        self.assertEqual(self.summary['initial_container_count'], 1)
        self.assertEqual(self.summary['initial_image_id_count'], 0)
        self.assertEqual([call.args[1][0] for call in self.daemon.call.call_args_list], ['container', 'image'])
        self.assertFalse(baseline.path.exists())

    def test_inventory_query_parse_and_bounds_keep_null_distinct_from_zero(self):
        for index, result in enumerate((SimpleNamespace(returncode=1, stdout=b'query-failed'),
            SimpleNamespace(returncode=0, stdout=b'bad-ID'), SimpleNamespace(returncode=0, stdout=b'a' * (128 * 1024 + 1)),
            SimpleNamespace(returncode=0, stdout=(('sha256:' + 'e' * 64 + '\n') * 257).encode()))):
            with self.subTest(index=index):
                baseline = self.fixture(); self.query_failure['image'] = result
                with self.assertRaises(ValueError): baseline.start(self.runner)
                self.assertEqual(self.summary['initial_container_count'], 0)
                self.assertIsNone(self.summary['initial_image_id_count'])
                self.assertIsNone(self.summary['pre_identity_sha256'])
                self.assertFalse(baseline.ready)
                self.env.stop()

    def test_failed_container_query_still_observes_valid_image_count(self):
        baseline = self.fixture(); self.query_failure['container'] = SimpleNamespace(returncode=1, stdout=b'failure')
        with self.assertRaises(ValueError): baseline.start(self.runner)
        self.assertIsNone(self.summary['initial_container_count'])
        self.assertEqual(self.summary['initial_image_id_count'], 0)

    def test_duplicate_image_rows_deduplicate_ids_without_losing_references(self):
        baseline = self.fixture({self.image: self.metadata(self.image, ['sample:a', 'sample:b'])})
        original = self.daemon.call.side_effect
        def call(runner, argv):
            result = original(runner, argv)
            if argv[:2] == ['image', 'ls']: result.stdout *= 2
            return result
        self.daemon.call.side_effect = call; baseline.start(self.runner)
        self.assertEqual(self.summary['initial_image_id_count'], 1)
        self.assertEqual(baseline.record['images'][0]['repo_tags'], ['sample:a', 'sample:b'])

    def test_same_id_retag_config_layer_and_size_drift_refuse_preservation(self):
        changes = (lambda row: row.update(RepoTags=['retagged:latest']),
            lambda row: row['Config'].update(Env=['CHANGED=yes']),
            lambda row: row['RootFS'].update(Layers=['sha256:' + '2' * 64]), lambda row: row.update(Size=124))
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                baseline = self.fixture({self.image: self.metadata(self.image, ['original:a'])})
                baseline.start(self.runner); change(self.images[self.image])
                with self.assertRaisesRegex(ValueError, 'baseline-changed'): baseline.observe(self.runner, 'after_cleanup')
                self.assertEqual(self.summary['preservation'], 'FAIL')
                self.assertNotEqual(self.summary['pre_identity_sha256'], self.summary['post_identity_sha256'])
                baseline.path.unlink(); self.env.stop()

    def test_positive_missing_baseline_id_is_changed_not_an_absence_success(self):
        baseline = self.fixture({self.image: self.metadata(self.image)})
        baseline.start(self.runner); del self.images[self.image]
        with self.assertRaisesRegex(ValueError, 'baseline-changed'): baseline.observe(self.runner, 'after_cleanup')
        self.assertEqual(self.summary['preservation'], 'FAIL')

    def test_capture_repeats_full_metadata_and_refuses_same_id_reference_churn(self):
        baseline = self.fixture({self.image: self.metadata(self.image, ['original:a'])})
        original = self.daemon.image; calls = 0
        def image(runner, identifier):
            nonlocal calls
            row = original(runner, identifier); calls += 1
            if calls == 1: self.images[identifier]['RepoTags'] = ['changed:a']
            return row
        self.daemon.image = image
        with self.assertRaisesRegex(ValueError, 'baseline-capture-drift'): baseline.start(self.runner)
        self.assertFalse(baseline.path.exists()); self.assertIsNone(self.summary['pre_identity_sha256'])

    def test_journal_tamper_owner_mode_and_daemon_identity_cannot_authorize_cleanup(self):
        baseline = self.fixture(); baseline.start(self.runner)
        record = job.packet.load(baseline.path); record['nonce'] = 'e' * 32; job.save(baseline.path, record)
        with self.assertRaisesRegex(ValueError, 'baseline-journal-binding'): baseline.protected()
        job.save(baseline.path, baseline.record); baseline.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'baseline-journal-binding'): baseline.protected()
        baseline.path.chmod(0o600); self.daemon.daemon = {'id': 'another-daemon', 'architecture': 'arm64'}
        with self.assertRaisesRegex(ValueError, 'baseline-daemon-binding'): baseline.protected()

    def test_metadata_overflow_bad_types_duplicate_refs_and_JSON_keys_are_refused(self):
        variants = (lambda r: r.update(Size=True), lambda r: r.update(Parent=False),
            lambda r: r.update(RepoTags=['a'] * 257), lambda r: r.update(RepoTags=['a', 'a']),
            lambda r: r['Config'].update(Value='a' * 65537), lambda r: r.update(Config={'Value': float('nan')}))
        for change in variants:
            with self.subTest(change=change):
                baseline = self.fixture({self.image: self.metadata(self.image)}); change(self.images[self.image])
                with self.assertRaises(ValueError): baseline.start(self.runner)
                self.assertFalse(baseline.path.exists()); self.env.stop()
        self.fixture()
        self.daemon.call.return_value = SimpleNamespace(returncode=0,
            stdout=b'[{"Id":"x","Id":"y"}]'); self.daemon.call.side_effect = None
        with self.assertRaisesRegex(ValueError, 'packet-json-duplicate'): self.daemon.image(self.runner, self.image)

    def test_bounded_JSON_depth_nodes_and_aggregate_canonical_bytes(self):
        nested = {}; current = nested
        for _ in range(17): current['next'] = {}; current = current['next']
        for value in (nested, {'many': [None] * 8192}):
            with self.assertRaisesRegex(ValueError, 'baseline-JSON-bound'): job.bounded_json(value)
        images = {}
        for index in range(70):
            identifier = 'sha256:' + format(index, '064x'); images[identifier] = self.metadata(identifier)
            images[identifier]['Config']['Large'] = 'x' * 65000
        baseline = self.fixture(images)
        with self.assertRaisesRegex(ValueError, 'baseline-aggregate-bound'): baseline.start(self.runner)
        self.assertFalse(baseline.path.exists())

    def test_empty_rootfs_omitted_layers_is_supported_without_dropping_Config(self):
        row = self.metadata(self.image); row['RootFS'] = {'Type': 'layers'}; row['Config'] = None
        baseline = self.fixture({self.image: row}); baseline.start(self.runner)
        self.assertEqual(baseline.record['images'][0]['rootfs']['layers'], [])
        self.assertIsNone(baseline.record['images'][0]['config'])

    def test_reference_bound_is_combined_across_tags_and_digests(self):
        row = self.metadata(self.image, ['tag:' + str(i) for i in range(128)])
        row['RepoDigests'] = ['repo@sha256:' + format(i, '064x') for i in range(128)]
        baseline = self.fixture({self.image: row}); baseline.start(self.runner)
        baseline.path.unlink(); row['RepoDigests'].append('extra@sha256:' + 'f' * 64)
        baseline = self.fixture({self.image: row})
        with self.assertRaisesRegex(ValueError, 'baseline-image-references'): baseline.start(self.runner)
        self.assertFalse(baseline.path.exists())

    def test_duplicate_reference_bound_to_different_ids_refuses_capture(self):
        foreign = 'sha256:' + 'e' * 64
        baseline = self.fixture({self.image: self.metadata(self.image, ['same:tag']), foreign: self.metadata(foreign, ['same:tag'])})
        with self.assertRaisesRegex(ValueError, 'baseline-reference-binding'): baseline.start(self.runner)

    def test_ancestor_survives_no_prune_and_only_new_journaled_id_is_removed(self):
        parent = 'sha256:' + 'e' * 64
        baseline = self.fixture({parent: self.metadata(parent)}); baseline.start(self.runner)
        self.images[self.image] = self.metadata(self.image, parent=parent); self.journal_base(self.image)
        result = job.cleanup_base(self.daemon, self.runner, self.root, self.image, True, baseline)
        baseline.observe(self.runner, 'after_cleanup')
        self.assertEqual(result['status'], 'PASS'); self.assertIn(parent, self.images)
        self.assertEqual(self.removals, [['image', 'rm', '--no-prune', self.image]])
        self.assertEqual(self.summary['preservation'], 'PASS')

    def test_borrowed_id_cannot_be_deleted_even_with_fabricated_base_ownership(self):
        baseline = self.fixture({self.image: self.metadata(self.image)}); baseline.start(self.runner)
        self.journal_base(self.image)
        with self.assertRaisesRegex(ValueError, 'baseline-ID-collision'):
            job.cleanup_base(self.daemon, self.runner, self.root, self.image, True, baseline)
        self.assertFalse(self.removals); self.assertIn(self.image, self.images)

    def test_uncertain_producer_cannot_turn_empty_inventory_into_cleanup_pass(self):
        baseline = self.fixture(); baseline.start(self.runner)
        result = job.cleanup_base(self.daemon, self.runner, self.root, None, False, baseline)
        baseline.observe(self.runner, 'after_cleanup')
        self.assertEqual(result['status'], 'FAIL'); self.assertTrue(result['producer_mutation_uncertain'])
        self.assertEqual(self.summary['preservation'], 'PASS'); self.assertFalse(self.removals)

    def test_actual_TERM_during_capture_keeps_image_query_unstarted_and_no_journal(self):
        baseline = self.fixture(); original = self.daemon.call.side_effect
        def call(runner, argv):
            if argv[0] == 'container': os.kill(os.getpid(), signal.SIGTERM)
            return original(runner, argv)
        self.daemon.call.side_effect = call
        with job.runtime.cancellation_handlers(), self.assertRaises(job.runtime.Cancelled): baseline.start(self.runner)
        self.assertFalse(baseline.path.exists()); self.assertFalse(self.removals)
        self.assertIsNone(self.summary['initial_image_id_count'])

    def test_snapshot_deadline_cannot_be_extended_by_observation_or_receipt_save(self):
        baseline = self.fixture(); self.runner.deadline = job.snapshot_clock() - 1
        with self.assertRaisesRegex(ValueError, 'deadline-exhausted'): baseline.start(self.runner)
        self.assertFalse(baseline.path.exists())
        self.runner.deadline = job.snapshot_clock() + 60
        original = job.save
        def save(path, record):
            original(path, record); self.runner.deadline = job.snapshot_clock() - 1
        with patch.object(job, 'save', side_effect=save):
            with self.assertRaisesRegex(ValueError, 'deadline-exhausted'): baseline.start(self.runner)
        self.assertFalse(baseline.ready); self.assertIsNone(self.summary['pre_identity_sha256'])


class ChildObservationTests(unittest.TestCase):
    def setUp(self):
        JobContracts.setUp(self)
        self.accepted = self.root / 'accepted'; self.accepted.mkdir()
        for name in ('result.json', 'bootstrap.json'): job.save(self.accepted / name, {'fixture': name})
        self.output = self.root / 'artifacts/kernel-native-stage' / ('hosted-job-' + '1' * 32)
        (self.output / 'private').mkdir(parents=True)
        self.path = self.output / 'private/result.json'
        bind = {'source_commit': self.args.source_commit, 'stage_lock_sha256': job.packet.KERNEL_SHA,
            'output_name_sha256': job.packet.sha(self.output.name.encode()), 'run_id': '1', 'run_attempt': '2',
            'nonce': '9' * 32, 'accepted_result_sha256': job.packet.sha(job.packet.read(self.accepted / 'result.json')),
            'bootstrap_sha256': job.packet.sha(job.packet.read(self.accepted / 'bootstrap.json')),
            'inputs_sha256': job.packet.INPUTS_SHA, 'base_inventory_sha256': job.BASE_SHA}
        diagnostic = child_evidence.initial(bind)
        self.invocation = {key: value for key, value in bind.items() if key != 'nonce'}
        diagnostic['current_predicate'] = 'PROVISION_COMMAND'
        diagnostic['commands']['provision'] = child_evidence.exit_record(125)
        child_evidence.failure(diagnostic, 'COMMAND_NONZERO')
        diagnostic['cleanup'] = {'status': 'FAIL', 'category': 'UNCERTAIN_MUTATION'}
        self.record = {'source_commit': self.args.source_commit, 'stage_lock_sha256': job.packet.KERNEL_SHA,
            'nonce': bind['nonce'], 'status': 'FAIL', 'phase': 'provision', 'cancelled': False,
            'native_kernel_compilation': 'NOT RUN', 'kernel_execution': 'NOT RUN', 'hardware_validation': 'NOT RUN',
            'performance': 'NOT MEASURED', 'cleanup': {'status': 'FAIL'}, 'diagnostics': diagnostic}
        self.env = patch.dict(job.os.environ, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '2'})
        self.env.start(); self.addCleanup(self.env.stop)

    def observe(self, code=1):
        row = {'availability': 'UNAVAILABLE', 'exit': job.public.exit_record(code), 'diagnostics': None}
        result = job.child_observation(self.args, self.output, self.invocation, row)
        return result, row

    def test_actual_child_exit_and_worker_exit_remain_separate_with_bound_first_predicate(self):
        job.save(self.path, self.record); record, row = self.observe()
        self.assertEqual(record, self.record)
        self.assertEqual(row['exit'], job.public.exit_record(1))
        self.assertEqual(row['diagnostics']['commands']['provision'], job.public.exit_record(125))
        self.assertEqual(row['diagnostics']['first_failed_predicate'], 'PROVISION_COMMAND')
        self.assertEqual(row['diagnostics']['cleanup']['category'], 'UNCERTAIN_MUTATION')
        self.assertNotIn('binding', row['diagnostics']); self.assertNotIn('nonce', row['diagnostics'])
        job.public.kernel_child(row)

    def test_inputs_bind_frozen_actual_invocation_not_mutable_post_return_files(self):
        command = job.kernel_command(self.args, self.root, self.image, self.accepted, {}, self.output)
        frozen = job.child_binding(command, {'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '2'})
        self.assertEqual(frozen, self.invocation)
        job.save(self.accepted / 'result.json', {'later': 'unaccepted result'})
        job.save(self.path, self.record)
        self.assertEqual(self.observe()[1]['availability'], 'VERIFIED')
        self.record['diagnostics']['binding']['accepted_result_sha256'] = job.packet.sha(job.packet.read(self.accepted / 'result.json'))
        job.save(self.path, self.record)
        self.assertEqual(self.observe()[1]['availability'], 'UNVERIFIED')
        command += ['--accepted-result-sha256', 'f' * 64]
        with self.assertRaises(ValueError): job.child_binding(command, {})

    def test_missing_and_unbound_receipts_are_unavailable_or_unverified(self):
        result, row = self.observe(); self.assertIsNone(result); self.assertEqual(row['availability'], 'UNAVAILABLE')
        variants = (lambda r: r.pop('diagnostics'), lambda r: r['diagnostics']['binding'].update(source_commit='f' * 40),
            lambda r: r['diagnostics']['binding'].update(stage_lock_sha256='f' * 64),
            lambda r: r['diagnostics']['binding'].update(run_id='3'),
            lambda r: r['diagnostics']['binding'].update(run_attempt='3'),
            lambda r: r['diagnostics']['binding'].update(output_name_sha256='f' * 64),
            lambda r: r['diagnostics']['binding'].update(accepted_result_sha256='f' * 64),
            lambda r: r['diagnostics']['binding'].update(bootstrap_sha256='f' * 64),
            lambda r: r['diagnostics']['binding'].update(inputs_sha256='f' * 64),
            lambda r: r['diagnostics']['binding'].update(base_inventory_sha256='f' * 64),
            lambda r: r.update(nonce='f' * 32), lambda r: r.update(stage_lock_sha256='f' * 64),
            lambda r: r['cleanup'].update(status='PASS'), lambda r: r['diagnostics'].update(raw_error='secret/path'))
        for change in variants:
            record = json.loads(json.dumps(self.record)); change(record); job.save(self.path, record)
            with self.subTest(change=change):
                result, row = self.observe(); self.assertIsNone(result)
                self.assertEqual((row['availability'], row['diagnostics']), ('UNVERIFIED', None))
                self.assertEqual(row['exit'], job.public.exit_record(1))

    def test_file_type_mode_owner_and_links_are_not_receipt_authority(self):
        job.save(self.path, self.record); self.path.chmod(0o644)
        self.assertEqual(self.observe()[1]['availability'], 'UNVERIFIED')
        self.path.chmod(0o600)
        with patch.object(job.os, 'getuid', return_value=job.os.getuid() + 1):
            self.assertEqual(self.observe()[1]['availability'], 'UNVERIFIED')
        link = self.path.with_name('hardlink'); link.hardlink_to(self.path)
        self.assertEqual(self.observe()[1]['availability'], 'UNVERIFIED'); link.unlink()
        self.path.unlink(); self.path.symlink_to(self.accepted / 'result.json')
        self.assertEqual(self.observe()[1]['availability'], 'UNVERIFIED')

    def test_receipt_changed_after_capture_is_refused_not_republished(self):
        job.save(self.path, self.record); original = job.packet.read; changed = False
        def read(path, *args):
            nonlocal changed
            data = original(path, *args)
            if path == self.path and not changed:
                changed = True; self.path.write_bytes(data + b' ')
            return data
        with patch.object(job.packet, 'read', side_effect=read):
            result, row = self.observe()
        self.assertIsNone(result); self.assertEqual(row['availability'], 'UNVERIFIED')

    def test_verified_projection_reuses_captured_bytes_without_reading_receipt_again(self):
        job.save(self.path, self.record); original = job.packet.read; reads = []
        def read(path, *args):
            reads.append(path); return original(path, *args)
        with patch.object(job.packet, 'read', side_effect=read):
            result, row = self.observe()
        self.assertEqual(reads.count(self.path), 1)
        self.path.write_text('{"unvalidated":"secret"}')
        self.assertEqual(row['diagnostics']['first_failed_predicate'], 'PROVISION_COMMAND')
        self.assertEqual(result['diagnostics'], self.record['diagnostics'])

    def test_pending_receipt_can_attest_no_first_failure_without_inventing_completion(self):
        row = json.loads(json.dumps(self.record)); row['cleanup'] = {'status': 'NOT RUN'}
        row['diagnostics'] = child_evidence.initial(row['diagnostics']['binding'])
        job.save(self.path, row); record, observed = self.observe(-15)
        self.assertIsNotNone(record); self.assertEqual(observed['exit'], job.public.exit_record(-15))
        self.assertEqual(observed['diagnostics']['first_failed_predicate'], 'NONE')
        self.assertEqual(observed['diagnostics']['commands']['baseline'], {'kind': 'NOT_RUN', 'code': None})

    def test_false_complete_status_or_missing_variant_nonce_cannot_be_verified(self):
        row = json.loads(json.dumps(self.record)); row.update(status='PASS', phase='complete', cleanup={'status': 'PASS'})
        d = child_evidence.initial(row['diagnostics']['binding'], child_evidence.Trace()); d.update(current_predicate='COMPLETE',
            commands={name: child_evidence.exit_record(0) for name in child_evidence.ACTIONS}, cleanup={'status': 'PASS', 'category': 'NONE'})
        row['diagnostics'] = d; job.save(self.path, row)
        self.assertEqual(self.observe(0)[1]['availability'], 'UNVERIFIED')


class OperationChildObservationTests(unittest.TestCase):
    setUp = ChildObservationTests.setUp
    observe = ChildObservationTests.observe

    def test_bound_new_diagnostic_capture_is_frozen_separate_from_actual_child_exit(self):
        trace=child_evidence.Trace();trace.current['action']='provision';trace.begin('CREATE');trace.returned(125)
        with trace.scope('QUERY_RETURN'):trace.fail(ValueError('kernel worker exit failed'),'COMMAND_NONZERO')
        with trace.scope('CLEANUP_ABSENCE','cleanup'):trace.fail(ValueError('unknown'),'UNCERTAIN_MUTATION')
        self.record['diagnostics'].update(schema_version=3,operation=trace.snapshot())
        job.save(self.path,self.record)
        result,row=self.observe(1)
        self.assertEqual(row['availability'],'VERIFIED')
        self.assertEqual(row['exit'],job.public.exit_record(1))
        self.assertEqual(row['diagnostics']['operation']['first_failure']['query_return'],job.public.exit_record(125))
        snapshot=copy.deepcopy(row['diagnostics'])
        self.record['diagnostics']['operation']['first_failure']['query_return']['code']=0
        job.save(self.path,self.record)
        result['diagnostics']['operation']['first_failure']['query_return']['code']=0
        self.assertEqual(row['diagnostics'],snapshot)
        with patch.object(job.packet,'read',side_effect=AssertionError('must not reread')):
            job.public.child_validate_public(row['diagnostics'])



class ModernResourceChildTests(unittest.TestCase):
    setUp = ChildObservationTests.setUp
    observe = ChildObservationTests.observe
    def complete(self):
        row=copy.deepcopy(self.record);d=child_evidence.initial(row['diagnostics']['binding'],child_evidence.Trace())
        d.update(current_predicate='COMPLETE',commands={name:child_evidence.exit_record(0) for name in child_evidence.ACTIONS},cleanup={'status':'PASS','category':'NONE'})
        row.update(status='PASS',phase='complete',cancelled=False,native_kernel_compilation='PASS',cleanup={'status':'PASS'},diagnostics=d)
        for name in ('probe','baseline','candidate'):row[name]={'status':'PASS','action':name,'cancelled':False,'nonce':row['nonce']}
        return row
    def test_bound_complete_requires_three_and_missing_resource_field_never_verifies(self):
        original=self.complete();job.save(self.path,original)
        self.assertEqual(self.observe(0)[1]['availability'],'VERIFIED')
        for version in (1,2,3):
            row=copy.deepcopy(original);d=row['diagnostics'];d['schema_version']=version
            if version==1:d.pop('operation')
            elif version==2:
                for slot in d['operation'].values():
                    if slot is not None:slot.pop('resource_mismatch')
            else:d['operation']['current'].pop('resource_mismatch')
            job.save(self.path,row);self.assertEqual(self.observe(0)[1]['availability'],'UNVERIFIED')

    def test_resource_diagnostic_capture_stays_bound_and_immutable_after_file_drift(self):
        trace=child_evidence.Trace();trace.current['action']='provision'
        with trace.scope('INSPECT_RESOURCES'):
            trace.resources_refused({'Memory':'private-secret'},{'Memory':14},())
            trace.fail(ValueError('docker-container-resources'))
        row=copy.deepcopy(self.record);d=child_evidence.initial(row['diagnostics']['binding'],trace)
        d.update(current_predicate='PROVISION_COMMAND');child_evidence.failure(d,'INVALID_DATA')
        d['cleanup']={'status':'FAIL','category':'ABSENCE_UNVERIFIED'};row['diagnostics']=d
        job.save(self.path,row);record,observed=self.observe(1);self.assertIsNotNone(record)
        frozen=copy.deepcopy(observed['diagnostics']);self.path.write_text('{"raw":"private-secret"}')
        record['diagnostics']['operation']['first_failure']['resource_mismatch']['field']='NanoCpus'
        self.assertEqual(observed['diagnostics'],frozen)
        with patch.object(job.packet,'read',side_effect=AssertionError('no second capture')):job.public.child_validate_public(frozen)
        self.assertEqual(frozen['operation']['first_failure']['resource_mismatch'],{'field':'Memory','kind':'TYPE'})


if __name__ == '__main__': unittest.main()
