# SPDX-License-Identifier: MIT
from contextlib import contextmanager
import ast
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
        result = job.cleanup_base(docker, Mock(), self.root, None, False)
        self.assertEqual(result['status'], 'FAIL'); self.assertTrue(result['producer_mutation_uncertain'])
        docker.call.assert_not_called()

    def test_only_journaled_base_id_can_be_removed_and_absence_is_required(self):
        docker = Mock(daemon={'id': 'daemon'}); docker.inventory.return_value = set()
        job.save(self.root / 'base-ownership.json', {'image_id': self.image, 'daemon': docker.daemon, 'producer_finished': True})
        row = {'Id': self.image, 'Architecture': 'arm64', 'Os': 'linux'}
        docker.call.side_effect = [SimpleNamespace(returncode=0, stdout=json.dumps([row]).encode()),
            SimpleNamespace(returncode=0, stdout=b''), SimpleNamespace(returncode=1, stdout=b'No such image')]
        self.assertEqual(job.cleanup_base(docker, Mock(), self.root, self.image, True)['status'], 'PASS')
        self.assertEqual(docker.call.call_args_list[1].args[1], ['image', 'rm', self.image])
        docker.call.side_effect = [SimpleNamespace(returncode=0, stdout=json.dumps([row]).encode()),
            SimpleNamespace(returncode=1, stdout=b'image in use')]
        with self.assertRaises(ValueError): job.cleanup_base(docker, Mock(), self.root, self.image, True)

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
        fake = Mock(); fake.info.return_value = {'id': 'fixture-daemon'}; fake.daemon = fake.info.return_value
        fake.inventory.return_value = set()
        row = {'Id': self.image, 'Architecture': 'arm64', 'Os': 'linux'}
        fake.call.side_effect = [SimpleNamespace(returncode=0, stdout=json.dumps([row]).encode()),
            SimpleNamespace(returncode=0, stdout=b''), SimpleNamespace(returncode=1, stdout=b'No such image')]
        phases = []
        def runner(seconds, env, logs):
            instance = Mock(); instance.run_many.return_value = [SimpleNamespace(returncode=0), SimpleNamespace(returncode=0)]
            instance.run.return_value = SimpleNamespace(returncode=0, stdout=b'')
            phases.append((seconds, instance)); return instance
        def source(*args, **kwargs): args[5].mkdir(parents=True); return {'status': 'PASS'}
        self.patches = [patch.object(job, '__file__', str(self.root / 'scripts/port/kernel-native-job/job.py')),
            patch.dict(job.os.environ, {'GITHUB_WORKSPACE': str(self.root)}),
            patch.object(job, 'ordinary'), patch.object(job.packet, 'verify', side_effect=source),
            patch.object(job, 'Docker', return_value=fake), patch.object(job.runtime, 'Runner', side_effect=runner),
            patch.object(job, 'accepted_producer', return_value=(self.image, accepted)),
            patch.object(job, 'acquired_paths', return_value={key: self.root / key for key in
                ('archive', 'config', 'patch', 'bio-baseline', 'bio-candidate', 'package-cache', 'key-dir')}),
            patch.object(job, 'kernel_status', return_value={'status': 'PASS'}),
            patch.object(job.shutil, 'disk_usage', return_value=SimpleNamespace(free=30 * 1024**3))]
        for item in self.patches: item.start(); self.addCleanup(item.stop)
        return fake, phases

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
            private_record = job.packet.load(self.args.output / 'private/result.json')['status']
            self.assertEqual(public_record, private_record)
            self.assertEqual((public_record['status'], public_record['cancelled'], public_record['native_compilation']),
                ('FAIL', True, 'NOT ACCEPTED'))
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


if __name__ == '__main__': unittest.main()
