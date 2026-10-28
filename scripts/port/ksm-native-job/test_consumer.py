# SPDX-License-Identifier: MIT
import copy
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ksm_consumer_tested', HERE / 'consumer.py')
c = importlib.util.module_from_spec(spec)
exec(compile((HERE / 'consumer.py').read_bytes(), str(HERE / 'consumer.py'), 'exec'), c.__dict__)
IMAGE = 'sha256:' + 'a' * 64


class ConsumerTests(unittest.TestCase):
    def test_original_producer_cli_command_without_override(self):
        command = c.producer_command('/checkout', '/private', inputs_sha='a' * 64, recipes_sha='b' * 64)
        self.assertEqual(command[:4], ['/usr/bin/python3', '-B', '/checkout/scripts/ci/native_arm.py', 'build'])
        self.assertNotIn('integration', command)
        self.assertNotIn('producer.py', ' '.join(command))

    def test_exact_two_fresh_offline_native_builds(self):
        a, b = c.build_commands('/checkout', '/private', IMAGE)
        self.assertNotEqual(a, b)
        self.assertEqual(a[-1], '/private/build-1')
        self.assertEqual(b[-1], '/private/build-2')
        self.assertEqual(a[a.index('--network') + 1], 'none')
        self.assertEqual(a[a.index('--mode') + 1], 'native')
        self.assertEqual(a[a.index('--source-date-epoch') + 1], '1791748800')
        self.assertEqual(a[a.index('--expected-packages') + 1], '/private/producer/packages.lock')

    def test_compare_requires_bytes(self):
        self.assertEqual(c.compare_command('/checkout', '/private')[-1], '--require-bytes')

    def test_lifecycle_command_binds_all_accepted_sources_and_same_job_inputs(self):
        pins = {'scripts/port/ksm-lifecycle/' + name: letter * 64 for name, letter in
                [('stage.py', 'a'), ('worker.py', 'b'), ('contract.py', 'c')]}
        binding = {'image': IMAGE, 'daemon-id': 'daemon-id', 'docker-endpoint': 'unix:///run/docker.sock',
                   'docker-sha256': 'd' * 64, 'docker-socket-device': '1', 'docker-socket-inode': '2',
                   'source-commit': 'e' * 40, 'run-id': '1', 'runner-sha256': 'f' * 64,
                   'bootstrap-sha256': 'a' * 64, 'stage-sha256': 'a' * 64, 'worker-sha256': 'b' * 64,
                   'contract-source-sha256': 'c' * 64, 'build-1-provenance-sha256': 'd' * 64,
                   'build-2-provenance-sha256': 'e' * 64}
        command = c.lifecycle_command('/checkout', '/private', binding, pins)
        pairs = dict(zip(command[3::2], command[4::2]))
        self.assertEqual(pairs['--source'], '/checkout')
        self.assertEqual(pairs['--current-inputs'], '/checkout/scripts/ci/inputs.lock.json')
        self.assertEqual(pairs['--build-1'], '/private/build-1')
        self.assertEqual(pairs['--build-2'], '/private/build-2')
        self.assertEqual(pairs['--build-1-provenance-sha256'], 'd' * 64)
        for key, wrong in [('worker-sha256', 'a' * 64), ('image', 'latest'),
                           ('docker-endpoint', 'tcp://remote'), ('run-id', 'not-a-job')]:
            with self.assertRaises(ValueError):
                c.lifecycle_command('/checkout', '/private', {**binding, key: wrong}, pins)

    def test_output_path_escape_checkout_overlap_and_mutable_image_refused(self):
        for root, private, image in [('/checkout', '/checkout/output', IMAGE),
                                     ('checkout', '/private', IMAGE),
                                     ('/checkout', '/private/../outside', IMAGE),
                                     ('/checkout', '/private,other', IMAGE),
                                     ('/checkout', '/private', 'latest')]:
            with self.assertRaises(ValueError):
                c.build_commands(root, private, image)

    def test_empty_or_partial_or_buildinfo_unequal_comparison_refused(self):
        good = {'status': 'contents-reproduced', 'errors': [], 'hardware_status': 'NOT RUN',
                'independence_limit': 'Distinct recorded container runs', 'packages': {'ksm.pkg':
                dict.fromkeys(('installed_contents_equal', 'pkginfo_equal', 'bytes_equal', 'buildinfo_equal'), True)}}
        self.assertEqual(c.validate_comparison(good, 'ksm.pkg')['status'], 'PASS')
        for key in good['packages']['ksm.pkg']:
            bad = copy.deepcopy(good)
            bad['packages']['ksm.pkg'][key] = False
            with self.assertRaises(ValueError):
                c.validate_comparison(bad, 'ksm.pkg')
        good['packages'] = {}
        with self.assertRaises(ValueError):
            c.validate_comparison(good, 'ksm.pkg')

    def test_unowned_original_receipt_is_insufficient(self):
        with self.assertRaises(ValueError):
            c.validate_ownership({'status': 'image-provisioned', 'image_id': IMAGE}, nonce='b' * 32,
                                 commit='c' * 40, run_id='1', image=IMAGE, daemon='daemon-id')

    def test_ownership_requires_every_same_job_binding_and_absence(self):
        args = {'nonce': 'b' * 32, 'commit': 'c' * 40, 'run_id': '1', 'image': IMAGE, 'daemon': 'daemon-id'}
        good = {'schema_version': 1, 'status': 'PASS', 'nonce': args['nonce'], 'source_commit': args['commit'],
                'run_id': '1', 'image_id': IMAGE, 'daemon_id': args['daemon'], 'owns_image': True,
                'containers_absent': True, 'journal_sha256': 'd' * 64}
        c.validate_ownership(good, **args)
        with self.assertRaises(ValueError):
            c.validate_ownership({**good, 'schema_version': True}, **args)
        for key in good:
            bad = copy.deepcopy(good)
            bad[key] = False
            with self.assertRaises((ValueError, TypeError)):
                c.validate_ownership(bad, **args)

    def test_lifecycle_cleanup_and_cancellation_cannot_be_hidden(self):
        binding = {'source_commit': 'c' * 40, 'run_id': '1', 'image_id': IMAGE,
                   'daemon_id': 'daemon-id', 'docker_endpoint': 'unix:///run/docker.sock'}
        good = {**binding, 'status': 'PASS', 'source_sha256': {'source': 'a' * 64}, 'package': {'sha256': 'b' * 64},
                'hardware': 'NOT RUN', 'management': 'NOT RUN', 'published': False,
                'private_artifacts_retained': False, 'controller_tmp_removed': 'PASS', 'docker_boundary_closed': 'PASS',
                'phases': [{'phase': phase, 'status': 'PASS', 'container_cleanup': 'PASS',
                            'container_state': {'status': 'exited', 'exit_code': 0, 'oom_killed': False}}
                           for phase in ('sign', 'lifecycle')]}
        self.assertEqual(c.validate_lifecycle(good, binding, good['source_sha256'], good['package'], controller_exit=0)['status'], 'PASS')
        for exit_code in (1, -15, False):
            with self.assertRaises(ValueError):
                c.validate_lifecycle(good, binding, good['source_sha256'], good['package'], controller_exit=exit_code)
        for state in ({}, {'status': 'exited', 'exit_code': False, 'oom_killed': False},
                      {'status': 'exited', 'exit_code': 0, 'oom_killed': True},
                      {'status': 'exited', 'exit_code': -15, 'oom_killed': False}):
            bad = copy.deepcopy(good)
            bad['phases'][0]['container_state'] = state
            with self.assertRaises(ValueError):
                c.validate_lifecycle(bad, binding, good['source_sha256'], good['package'], controller_exit=0)
        for update in [{'cancelled': True}, {'private_artifacts_retained': True}, {'controller_tmp_removed': 'FAIL'},
                       {'docker_boundary_closed': 'FAIL'}, {'run_id': '2'}, {'phases': []}]:
            with self.assertRaises(ValueError):
                c.validate_lifecycle({**good, **update}, binding, good['source_sha256'], good['package'], controller_exit=0)

    def test_aggregate_deadline_reserve_and_phase_replay(self):
        now = [0]
        deadline = c.Deadline(500, clock=lambda: now[0])
        self.assertEqual(deadline.phase('producer', 6600), 290)
        with self.assertRaises(ValueError):
            deadline.phase('producer', 6600)
        now[0] = 291
        with self.assertRaises(ValueError):
            deadline.phase('build-1', 360)
        self.assertEqual(deadline.phase('cleanup', 180, reserve=30), 179)
        now[0] = 501
        with self.assertRaises(ValueError):
            deadline.phase('public', 30, reserve=0)

    def test_phase_limits_and_cleanup_reserves_cannot_be_borrowed(self):
        for name, maximum, reserve in [('build-1', 361, 210), ('lifecycle', 601, 210),
                                       ('producer', 6600, 0), ('cleanup', 180, 0)]:
            with self.assertRaises(ValueError):
                c.Deadline().phase(name, maximum, reserve)


if __name__ == '__main__':
    unittest.main()
