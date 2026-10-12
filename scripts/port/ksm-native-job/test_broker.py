# SPDX-License-Identifier: MIT
"""Fake Docker fixtures only; no daemon, builds, package execution or network."""
import importlib.util
import json
import os
import signal
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('ksm_broker_fixture', Path(__file__).with_name('broker.py'))
broker = importlib.util.module_from_spec(spec); spec.loader.exec_module(broker)


class FakeDocker:
    endpoint, expected = 'unix:///run/docker.sock', 'fixture-daemon-123'
    cli_sha256, socket_identity = 'f' * 64, (3, 4)
    def __init__(self, private):
        self.private, self.calls, self.containers = private, [], {}
        self.image = 'sha256:' + 'a' * 64
        self.image_exists, self.next_id, self.action, self.after = False, 1, None, None
        self.labels = {}
        self.owner = None

    def call(self, argv, timeout):
        assert argv[:2] == ['docker', '--host=' + self.endpoint]
        assert 0 < timeout <= 1800
        self.calls.append(argv)
        args = argv[2:]
        if self.action: self.action(args)
        def result(code=0, data=b''):
            if self.after: self.after(args)
            return subprocess.CompletedProcess(argv, code, data)
        if args[0] == 'build':
            rows = [json.loads(line) for line in self.owner.journal_path.read_text().splitlines()]
            assert any(row['event'] == 'image-reserved' for row in rows)
            assert rows[-1] == {'event': 'docker-operation-reserved', 'nonce': self.owner.nonce, 'phase': self.owner.phase, 'argv': argv}
            self.image_exists = True
            self.labels = dict(args[index + 1].split('=', 1) for index, value in enumerate(args) if value == '--label')
            (self.private / 'producer/image-id').write_text(self.image + '\n')
            return result(data=b'bootstrap log\n')
        if args[:2] == ['image', 'inspect']:
            if not self.image_exists:
                return result(1, ('Error response from daemon: No such image: ' + self.image).encode())
            return result(data=json.dumps([{'Id': self.image, 'Architecture': 'arm64', 'Os': 'linux', 'Config': {'Labels': self.labels}}]).encode())
        if args[:2] == ['image', 'rm']:
            self.image_exists = False
            return result()
        if args[:2] == ['image', 'ls']:
            return result(data=self.image.encode() if self.image_exists else b'')
        if args[0] == 'create':
            rows = [json.loads(line) for line in self.owner.journal_path.read_text().splitlines()]
            assert any(row['event'] == 'container-reserved' and row['name'] == args[args.index('--name') + 1] for row in rows)
            assert rows[-1]['event'] == 'docker-operation-reserved'
            name = args[args.index('--name') + 1]
            cid = f'{self.next_id:064x}'; self.next_id += 1
            labels = dict(args[index + 1].split('=', 1) for index, value in enumerate(args) if value == '--label')
            self.containers[name] = {'Id': cid, 'Name': '/' + name, 'Image': self.image,
                                     'Config': {'Labels': labels}, 'State': {'Status': 'created', 'ExitCode': 0, 'OOMKilled': False}}
            return result(data=(cid + '\n').encode())
        if args[:2] == ['container', 'inspect']:
            row = next((row for name, row in self.containers.items() if args[2] in {name, row['Id']}), None)
            return result(0, json.dumps([row]).encode()) if row else result(1, b'not found')
        if args[0] == 'start':
            row = next(row for row in self.containers.values() if row['Id'] == args[-1])
            row['State']['Status'] = 'exited'
            return result(data=b'fixture stdout\n')
        if args[0] == 'rm':
            name = next(name for name, row in self.containers.items() if row['Id'] == args[-1])
            del self.containers[name]
            return result()
        if args[:2] == ['container', 'ls']:
            selected = args[-1]
            matches = [row['Id'] for name, row in self.containers.items()
                       if selected in {'name=^/' + name + '$', 'id=' + row['Id']}]
            return result(data='\n'.join(matches).encode())
        if args[:2] == ['info', '--format']:
            return result(data=(b'arm64\n' if args[-1] == '{{.Architecture}}' else self.expected.encode()))
        if args == ['context', 'inspect']:
            return result(data=json.dumps([{'Name': 'default', 'Endpoints': {'docker': {'Host': self.endpoint}}}], indent=2).encode() + b'\n')
        if args == ['version']: return result(data=b'fixture Docker version\n')
        raise AssertionError(args)


class BaselineDocker(FakeDocker):
    def __init__(self, private):
        super().__init__(private)
        self.protected = 'sha256:' + 'e' * 64
        self.images = {self.protected: {'Id': self.protected, 'Architecture': 'arm64', 'Os': 'linux',
            'Config': {'Labels': {'existing': 'untouched'}}, 'RootFS': {'Type': 'layers', 'Layers': []},
            'Size': 123, 'Parent': '', 'RepoTags': ['fixture/base:1'], 'RepoDigests': []}}
        self.references = {'fixture/base:1': self.protected}
        self.duplicate_inventory, self.baseline_action = False, None

    def call(self, argv, timeout):
        args = argv[2:]
        if self.baseline_action: self.baseline_action(args)
        if args in (['image', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}'],
                    ['container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}']):
            self.calls.append(argv)
            values = sorted(self.images) + ([self.image] if self.image_exists else []) if args[0] == 'image' else [r['Id'] for r in self.containers.values()]
            if self.duplicate_inventory: values *= 2
            return subprocess.CompletedProcess(argv, 0, ('\n'.join(values) + ('\n' if values else '')).encode())
        if args[:2] == ['image', 'inspect']:
            image = self.references.get(args[2], args[2])
            if image in self.images:
                self.calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, json.dumps([self.images[image]]).encode())
        return super().call(argv, timeout)


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.private, self.source = root / 'private', root / 'source'
        self.private.mkdir(mode=0o700); self.source.mkdir(mode=0o700)
        (self.private / 'producer/context').mkdir(parents=True)
        self.backend = BaselineDocker(self.private)
        self.binding = {'source_commit': 'c' * 40, 'packet_sha256': 'd' * 64,
                        'run_id': '123', 'run_attempt': '1', 'uid': os.getuid(), 'gid': os.getgid()}
        self.nonce = '1' * 32
        self.baseline = broker.Baseline(self.backend, self.private, self.binding, self.nonce)
        self.addCleanup(self.baseline.close)

    def owner(self):
        owner = broker.Broker(self.backend, self.private / 'journal.jsonl', self.nonce, self.private, self.source,
            context_digest=lambda _: 'b' * 64, binding={k: v for k, v in self.binding.items() if k != 'run_attempt'},
            baseline=self.baseline)
        self.backend.owner = owner; self.addCleanup(owner.close)
        return owner

    def build(self, owner):
        return owner.request(['docker', 'build', '--network=none', '--pull=false', '--platform=linux/arm64',
            '--iidfile', str(self.private / 'producer/image-id'), str(self.private / 'producer/context')])

    def test_bound_durable_baseline_deduplicates_ids_and_protects_references(self):
        self.backend.duplicate_inventory = True
        summary = self.baseline.start()
        self.assertEqual(self.baseline.protected(), frozenset({self.backend.protected}))
        self.assertEqual(summary['initial_image_id_count'], 1)
        self.assertEqual(summary['preservation'], 'UNVERIFIED')
        row = json.loads(self.baseline.path.read_bytes().splitlines()[0])
        for key, value in self.binding.items(): self.assertEqual(row[key], value)
        self.assertEqual(row['docker_sha256'], self.backend.cli_sha256)
        self.assertEqual(row['docker_socket_identity'], list(self.backend.socket_identity))
        self.assertEqual(self.baseline.path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(any(call[2:] == ['image', 'inspect', 'fixture/base:1'] for call in self.backend.calls))

    def test_protected_drift_is_sticky_and_cannot_be_promoted_by_later_restore(self):
        self.baseline.start()
        self.backend.images[self.backend.protected]['Config']['Labels']['existing'] = 'changed'
        with self.assertRaisesRegex(ValueError, 'baseline-changed'): self.baseline.observe('after_producer')
        self.backend.images[self.backend.protected]['Config']['Labels']['existing'] = 'untouched'
        self.baseline.observe('after_cleanup')
        self.assertEqual(self.baseline.summary()['preservation'], 'FAIL')

    def test_positive_reference_binding_refuses_retarget_and_tag_loss(self):
        self.baseline.start()
        self.backend.references['fixture/base:1'] = self.backend.image
        with self.assertRaises(ValueError): self.baseline.observe('after_producer')
        self.backend.references['fixture/base:1'] = self.backend.protected
        self.backend.images[self.backend.protected]['RepoTags'] = []
        with self.assertRaisesRegex(ValueError, 'baseline-changed'): self.baseline.observe('after_producer')

    def test_initial_collision_and_foreign_container_refuse_without_mutation(self):
        other = 'sha256:' + '9' * 64
        self.backend.images[other] = {**self.backend.images[self.backend.protected], 'Id': other}
        with self.assertRaisesRegex(ValueError, 'reference-collision'): self.baseline.start()
        self.assertFalse(any(call[2] in ('rm', 'build') for call in self.backend.calls))

    def test_foreign_container_and_missing_baseline_refuse(self):
        self.backend.containers['foreign'] = {'Id': '9' * 64}
        with self.assertRaisesRegex(ValueError, 'containers-present'): self.baseline.start()
        self.backend.containers.clear()
        self.baseline = broker.Baseline(self.backend, self.private, self.binding, self.nonce)
        self.addCleanup(self.baseline.close)
        self.baseline.start(); self.backend.images.clear()
        with self.assertRaisesRegex(ValueError, 'image-missing'): self.baseline.observe('after_producer')

    def test_valid_foreign_container_refuses_at_first_inventory_gate_without_image_query(self):
        observed = []
        self.baseline.on_inventory = lambda kind, result: observed.append((kind, result.returncode))
        self.backend.containers['foreign'] = {'Id': '9' * 64}
        with self.assertRaisesRegex(ValueError, 'baseline-containers-present'): self.baseline.start()
        self.assertEqual(observed, [('container', 0)])
        self.assertEqual(self.baseline.summary()['initial_container_count'], 1)
        self.assertIsNone(self.baseline.summary()['initial_image_id_count'])
        self.assertEqual([call[2:] for call in self.backend.calls],
                         [['container', 'ls', '--all', '--no-trunc', '--format', '{{.ID}}']])
        self.assertFalse(self.baseline.path.exists())

    def test_option_like_reference_metadata_refuses_before_reference_inspection(self):
        for field in ('RepoTags', 'RepoDigests'):
            with self.subTest(field=field):
                self.backend.calls.clear()
                self.backend.images[self.backend.protected]['RepoTags'] = []
                self.backend.images[self.backend.protected]['RepoDigests'] = []
                self.backend.images[self.backend.protected][field] = ['--help']
                baseline = broker.Baseline(self.backend, self.private, self.binding, self.nonce)
                try:
                    with self.assertRaisesRegex(ValueError, 'baseline-reference-bound'): baseline.start()
                    self.assertFalse(any(call[2:] == ['image', 'inspect', '--help'] for call in self.backend.calls))
                    self.assertFalse(baseline.path.exists())
                finally: baseline.close()

    def test_actual_broker_preserves_baseline_and_unknown_images_with_nonpruning_cleanup(self):
        self.baseline.start(); owner = self.owner(); self.build(owner)
        other = 'sha256:' + '9' * 64
        self.backend.images[other] = {**self.backend.images[self.backend.protected], 'Id': other,
                                     'RepoTags': [], 'RepoDigests': []}
        self.assertEqual(owner.cleanup()['status'], 'PASS')
        self.assertEqual(self.baseline.summary()['preservation'], 'UNVERIFIED')
        summary = self.baseline.observe('after_cleanup')
        self.assertEqual(summary['preservation'], 'PASS')
        self.assertEqual(summary['unowned_image_id_count'], 1)
        self.assertEqual(set(self.backend.images), {self.backend.protected, other})
        removals = [call[2:] for call in self.backend.calls if call[2:4] == ['image', 'rm']]
        self.assertEqual(removals, [['image', 'rm', '--no-prune', self.backend.image]])

    def test_baseline_iid_collision_never_inspects_owned_labels_or_removes_protected_image(self):
        self.baseline.start(); owner = self.owner(); self.backend.image = self.backend.protected
        with self.assertRaisesRegex(ValueError, 'baseline-ID-collision'): self.build(owner)
        self.assertIsNone(owner.image)
        self.assertEqual(owner.cleanup()['status'], 'FAIL')
        self.assertFalse(any(call[2:4] == ['image', 'rm'] for call in self.backend.calls))

    def test_cleanup_observation_uses_only_protected_ids_and_cannot_grant_final_preservation(self):
        self.baseline.start(); index = len(self.backend.calls)
        self.baseline.observe('after_cleanup', cleanup=True)
        self.assertTrue(all(call[2:] == ['image', 'inspect', self.backend.protected] for call in self.backend.calls[index:]))
        self.assertEqual(self.baseline.summary()['observation_mode'], 'protected-image-metadata-only')
        self.assertEqual(self.baseline.summary()['preservation'], 'UNVERIFIED')

    def test_receipt_and_backend_binding_drift_refuse(self):
        self.baseline.start()
        self.baseline.path.write_bytes(b'forged\n')
        with self.assertRaisesRegex(ValueError, 'receipt-drift'): self.baseline.protected()
        self.backend.expected = 'foreign-daemon-123'
        with self.assertRaisesRegex(ValueError, 'backend-binding-drift'): self.baseline.protected()

    def test_broker_baseline_phase_deadline_is_not_borrowed(self):
        self.baseline.start(); owner = self.owner()
        owner.operation_deadline = owner.clock() - 1
        with self.assertRaisesRegex(ValueError, 'phase-deadline'): self.build(owner)
        self.assertFalse(any(call[2] == 'build' for call in self.backend.calls))

    def test_real_signal_during_baseline_observation_refuses_and_keeps_private_receipt(self):
        self.baseline.start()
        def interrupt(*_): raise broker.Cancelled('fixture-real-signal')
        previous = signal.signal(signal.SIGTERM, interrupt)
        try:
            self.backend.baseline_action = lambda args: os.kill(os.getpid(), signal.SIGTERM)
            with self.assertRaises(broker.Cancelled): self.baseline.observe('after_producer')
        finally: signal.signal(signal.SIGTERM, previous)
        self.assertEqual(self.baseline.summary()['preservation'], 'FAIL')
        self.assertTrue(self.baseline.path.is_file())

    def test_bounded_parser_rejects_duplicate_nonfinite_depth_and_excess_inventory(self):
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'[' * 18 + b'0' + b']' * 18):
            with self.subTest(data=data), self.assertRaises(ValueError): broker.baseline_json(data)
        original = self.backend.call
        def oversized(argv, timeout):
            if argv[2] == 'image' and argv[3] == 'ls':
                return subprocess.CompletedProcess(argv, 0, ((self.backend.protected + '\n') * 257).encode())
            return original(argv, timeout)
        self.backend.call = oversized
        with self.assertRaisesRegex(ValueError, 'inventory-bound'): self.baseline.start()
        self.assertFalse(self.baseline.path.exists())

    def test_unstable_initial_projection_never_becomes_a_protection_grant(self):
        calls = 0
        def mutate(args):
            nonlocal calls
            if args[:2] == ['image', 'inspect']:
                calls += 1
                if calls == 3: self.backend.images[self.backend.protected]['Size'] += 1
        self.backend.baseline_action = mutate
        with self.assertRaisesRegex(ValueError, 'capture-drift'): self.baseline.start()
        self.assertFalse(self.baseline.ready)
        self.assertFalse(self.baseline.path.exists())

    def test_baseline_nonce_or_same_job_binding_mismatch_refuses_broker(self):
        self.baseline.start(); self.baseline.binding['run_id'] = '999'
        with self.assertRaisesRegex(ValueError, 'same-job-baseline'): self.owner()
        self.assertFalse((self.private / 'journal.jsonl').exists())

    def test_immediate_predelete_exclusion_refuses_protected_iid_even_after_other_build(self):
        self.baseline.start(); owner = self.owner(); self.build(owner)
        owner.image = self.backend.protected
        self.assertEqual(owner.cleanup()['status'], 'FAIL')
        self.assertFalse(any(call[2:4] == ['image', 'rm'] for call in self.backend.calls))
        self.assertIn(self.backend.protected, self.backend.images)
        self.assertTrue(self.backend.image_exists)

    def test_retained_runtime_cancellation_allows_owned_disposal_but_refuses_late_preservation_pass(self):
        spec = importlib.util.spec_from_file_location('ksm_baseline_runtime_fixture', Path(__file__).with_name('runtime.py'))
        runtime = importlib.util.module_from_spec(spec); spec.loader.exec_module(runtime)
        with self.assertRaises(runtime.Cancelled):
            with runtime.cancellation_handlers() as state:
                self.baseline.cancelled = lambda: state.signum is not None
                self.baseline.start(); owner = self.owner(); self.build(owner)
                owner.cancelled = lambda: state.signum is not None
                owner.failed = True  # Executor never admits a cancelled producer.
                def cancel_at_removal(args):
                    if args == ['image', 'rm', '--no-prune', self.backend.image]:
                        os.kill(os.getpid(), signal.SIGTERM)
                self.backend.baseline_action = cancel_at_removal
                with runtime.defer_signals() as events:
                    result = owner.cleanup()
                self.assertEqual(events, [signal.SIGTERM])
                self.assertEqual(state.signum, signal.SIGTERM)
                self.assertEqual(result['status'], 'FAIL')
                self.assertTrue(result['owned_image_absent'])
                self.assertFalse(self.backend.image_exists)
                self.assertIn(self.backend.protected, self.backend.images)
                count = len(self.backend.calls)
                with self.assertRaises(broker.Cancelled): self.baseline.observe('after_cleanup')
                self.assertEqual(len(self.backend.calls), count)
                self.assertEqual(self.baseline.summary()['preservation'], 'FAIL')
                self.assertEqual([call[2:] for call in self.backend.calls if call[2:4] == ['image', 'rm']],
                                 [['image', 'rm', '--no-prune', self.backend.image]])


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.private, self.source = root / 'private', root / 'source'
        self.private.mkdir(mode=0o700); self.source.mkdir(mode=0o700)
        (self.private / 'producer/context').mkdir(parents=True)
        entry = self.source / 'scripts/build/container-entry.sh'; entry.parent.mkdir(parents=True); entry.write_bytes(b'fixture')
        self.backend = FakeDocker(self.private)
        self.nonce = '1' * 32
        self.owner = broker.Broker(self.backend, self.private / 'journal.jsonl', self.nonce, self.private, self.source,
                                   context_digest=lambda _: 'b' * 64,
                                   binding={'source_commit': 'c' * 40, 'run_id': '123', 'packet_sha256': 'd' * 64,
                                            'uid': os.getuid(), 'gid': os.getgid()})
        self.backend.owner = self.owner; self.addCleanup(self.owner.close)

    def build(self):
        return self.owner.request(['docker', 'build', '--network=none', '--pull=false', '--platform=linux/arm64',
                                   '--iidfile', str(self.private / 'producer/image-id'), str(self.private / 'producer/context')])

    def inventory(self):
        return ['docker', 'run', '--rm', '--pull=never', '--network=none', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--read-only', '--entrypoint=/bin/cat', self.backend.image,
                '/builder-packages.lock']

    def builder(self, name='cachy-asahi-' + '2' * 16, output=None):
        output = output or self.private / 'build-1'
        output.mkdir(exist_ok=True)
        for directory in ('inputs', 'artifacts'): (output / directory).mkdir(exist_ok=True)
        (output / 'expected-packages.lock').write_text('fixture 1\n')
        return ['docker', 'run', '--rm', '--name', name, '--pull=never', '--platform', 'linux/arm64',
                '--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
                '--pids-limit', '512', '--memory', '4g', '--cpus', '4', '--network', 'none',
                '--tmpfs', '/tmp:rw,nosuid,nodev,exec,size=4g', '--env', 'CACHY_ASAHI_CONTAINER=1',
                '--env', 'SOURCE_DATE_EPOCH=1791748800',
                '--mount', f'type=bind,src={output}/inputs,dst=/inputs,readonly',
                '--mount', f'type=bind,src={output}/artifacts,dst=/out',
                '--mount', f'type=bind,src={self.source}/scripts/build/container-entry.sh,dst=/builder-entry.sh,readonly',
                '--mount', f'type=bind,src={output}/expected-packages.lock,dst=/expected-packages.lock,readonly',
                '--entrypoint', '/bin/bash', self.backend.image, '/builder-entry.sh']

    def rows(self):
        return [json.loads(line) for line in self.owner.journal_path.read_text().splitlines()]

    def test_probe_commands_use_bound_backend_and_context_endpoint(self):
        for argv in (['info', '--format', '{{.Architecture}}'], ['version'], ['context', 'inspect']):
            self.assertEqual(self.owner.request(['docker', *argv]).returncode, 0)
        self.assertEqual(json.loads(self.owner.request(['docker', 'context', 'inspect']).stdout)[0]['Endpoints']['docker']['Host'], self.backend.endpoint)
        self.assertEqual(self.rows()[0]['daemon_id'], self.backend.expected)
        self.assertEqual(self.rows()[0]['packet_sha256'], 'd' * 64)

    def test_build_reserved_before_backend_labels_limits_and_immutable_binding(self):
        self.assertEqual(self.build().stdout, b'bootstrap log\n')
        command = next(argv for argv in self.backend.calls if argv[2] == 'build')
        for flag in ('--memory=4g', '--memory-swap=4g', '--network=none', '--pull=false', '--platform=linux/arm64'):
            self.assertIn(flag, command)
        self.assertIn(broker.LABEL + '=' + self.nonce, command)
        self.assertIn(broker.CONTEXT_LABEL + '=' + 'b' * 64, command)
        self.assertEqual(self.owner.image, self.backend.image)
        self.assertEqual(self.rows()[-1]['event'], 'image-bound')
        with self.assertRaises(ValueError): self.build()

    def test_inventory_run_preserves_stdout_and_confirms_owned_id_cleanup(self):
        self.build()
        self.assertEqual(self.owner.request(self.inventory()).stdout, b'fixture stdout\n')
        events = [row['event'] for row in self.rows()]
        self.assertLess(events.index('container-reserved'), events.index('container-bound'))
        for event in ('container-start-reserved', 'container-exited', 'container-removal-reserved', 'container-absent'):
            self.assertIn(event, events)
        self.assertFalse(self.backend.containers)
        removal = next(args for args in self.backend.calls if args[2] == 'rm')
        self.assertRegex(removal[-1], r'^[0-9a-f]{64}$')
        selectors = [args[-1] for args in self.backend.calls if args[2:4] == ['container', 'ls']]
        self.assertEqual(len(selectors), 2)
        self.assertTrue(selectors[0].startswith('name=^/')); self.assertTrue(selectors[1].startswith('id='))

    def test_builder_original_random_name_and_mounts_are_preserved(self):
        self.build(); self.owner.phase = 'ksm-1'
        argv = self.builder()
        self.assertEqual(self.owner.request(argv).returncode, 0)
        creation = next(args for args in self.backend.calls if args[2] == 'create')
        self.assertIn('cachy-asahi-' + '2' * 16, creation)
        self.assertEqual(self.rows()[-1]['phase'], 'ksm-1')
        self.assertIn(broker.IMAGE_LABEL + '=' + self.backend.image, creation)
        self.assertNotIn('--rm', creation)

    def test_eight_original_and_two_ksm_builds_have_distinct_journaled_environments(self):
        self.build(); self.owner.request(self.inventory())
        number = 2
        for recipe in sorted(broker.ORIGINALS):
            for attempt in (1, 2):
                self.owner.request(self.builder(f'cachy-asahi-{number:016x}', self.private / 'producer' / f'{recipe}-{attempt}'))
                number += 1
        for attempt in (1, 2):
            self.owner.phase = f'ksm-{attempt}'
            self.owner.request(self.builder(f'cachy-asahi-{number:016x}', self.private / f'build-{attempt}'))
            number += 1
        exits = [row for row in self.rows() if row['event'] == 'container-exited']
        self.assertEqual(len(exits), 11)
        self.assertEqual(len({row['id'] for row in exits}), 11)
        self.assertEqual([row['phase'] for row in exits].count('producer'), 9)
        self.assertEqual(self.owner.cleanup()['status'], 'PASS')
        self.assertFalse(self.backend.image_exists)
        self.assertEqual(self.rows()[-1]['legacy_build_cache_absence'], 'NOT ESTABLISHED')

    def test_arbitrary_privileged_network_mount_and_remote_commands_refused_before_backend(self):
        self.build(); self.owner.phase = 'ksm-1'
        argv = self.builder()
        for candidate in (['docker', '--host=tcp://remote', 'info'], ['docker', 'system', 'prune'],
                          ['docker', 'rm', '-f', 'unowned'], argv[:2] + ['--privileged'] + argv[2:],
                          [arg.replace('type=bind,src=' + str(self.private / 'build-1/inputs'), 'type=bind,src=/') for arg in argv],
                          [arg if arg != 'none' else 'bridge' for arg in argv]):
            self.owner.failed = False  # Independent policy branch fixtures.
            count = len(self.backend.calls)
            with self.subTest(argv=candidate[:4]), self.assertRaises(ValueError): self.owner.request(candidate)
            self.assertEqual(len(self.backend.calls), count)

    def test_wrong_container_nonce_refuses_start_and_removal(self):
        self.build()
        def tamper(args):
            if args[:2] == ['container', 'inspect']:
                next(iter(self.backend.containers.values()))['Config']['Labels'][broker.LABEL] = 'f' * 32
        self.backend.action = tamper
        with self.assertRaisesRegex(ValueError, 'ownership'): self.owner.request(self.inventory())
        self.assertFalse(any(args[2] in {'start', 'rm'} for args in self.backend.calls))
        self.assertEqual(self.owner.cleanup()['status'], 'FAIL')
        self.assertTrue(self.backend.containers)

    def test_wrong_id_after_start_refuses_removal(self):
        self.build()
        inspections = 0
        def tamper(args):
            nonlocal inspections
            if args[:2] == ['container', 'inspect']:
                inspections += 1
                if inspections == 2: next(iter(self.backend.containers.values()))['Id'] = 'e' * 64
        self.backend.action = tamper
        with self.assertRaises(ValueError): self.owner.request(self.inventory())
        self.assertFalse(any(args[2] == 'rm' for args in self.backend.calls))
        self.assertTrue(any(row['event'] == 'request-failed' for row in self.rows()))

    def test_unknown_creation_commit_keeps_reservation_failed_and_cleanup_explicit(self):
        self.build()
        def lose_response(args):
            if args[0] == 'create': raise OSError('fixture daemon loss before binding')
        self.backend.action = lose_response
        with self.assertRaises(OSError): self.owner.request(self.inventory())
        self.assertIsNone(next(iter(self.owner.containers.values()))['id'])
        self.assertEqual(self.rows()[-1]['classification'], 'uncertain')
        self.backend.action = None
        self.assertEqual(self.owner.cleanup()['status'], 'FAIL')

    def test_cancellation_after_creation_commit_does_not_start_or_claim_pass(self):
        self.build(); state = {'cancelled': False}
        self.owner.cancelled = lambda: state['cancelled']
        def cancel(args):
            if args[0] == 'create': state['cancelled'] = True
        self.backend.action = cancel
        with self.assertRaises(broker.Cancelled): self.owner.request(self.inventory())
        self.assertFalse(any(args[2] == 'start' for args in self.backend.calls))
        self.backend.action = None
        self.assertEqual(self.owner.cleanup()['status'], 'FAIL')
        self.assertFalse(self.backend.containers)

    def test_backend_socket_daemon_or_cli_drift_after_commit_never_binds_success(self):
        for boundary in ('socket', 'daemon', 'cli'):
            backend = FakeDocker(self.private)
            owner = broker.Broker(backend, self.private / ('journal-' + boundary), self.nonce, self.private, self.source,
                                  context_digest=lambda _: 'b' * 64,
                                  binding={'source_commit': 'c' * 40, 'run_id': '123', 'packet_sha256': 'd' * 64,
                                           'uid': os.getuid(), 'gid': os.getgid()})
            backend.owner = owner; self.addCleanup(owner.close)
            def drift(args):
                if args[0] == 'build': raise ValueError(boundary + '-postoperation-drift')
            backend.after = drift
            with self.subTest(boundary=boundary), self.assertRaises(ValueError):
                owner.request(['docker', 'build', '--network=none', '--pull=false', '--platform=linux/arm64',
                               '--iidfile', str(self.private / 'producer/image-id'), str(self.private / 'producer/context')])
            self.assertTrue(backend.image_exists)  # Commit occurred; response binding failed.
            self.assertIsNone(owner.image)
            self.assertTrue(owner.failed)
            self.assertEqual(owner.cleanup()['status'], 'FAIL')
            self.assertFalse(any(args[2:4] == ['image', 'rm'] for args in backend.calls))

    def test_pre_cancel_and_deadline_refuse_mutation(self):
        self.owner.cancelled = lambda: True
        with self.assertRaises(broker.Cancelled): self.build()
        self.assertEqual(self.backend.calls, [])
        self.owner.cancelled = lambda: False; self.owner.deadline = self.owner.clock() - 1
        with self.assertRaises(ValueError): self.owner.request(['docker', 'version'])
        self.assertEqual(self.backend.calls, [])

    def test_duplicate_name_and_phase_inventory_replay_refused(self):
        self.build(); self.owner.request(self.inventory())
        with self.assertRaises(ValueError): self.owner.request(self.inventory())
        self.owner.phase = 'ksm-1'
        with self.assertRaises(ValueError): self.owner.request(self.inventory())

    def test_failed_image_build_keeps_unknown_commit_and_no_image_disposal(self):
        original = self.backend.call
        def failed(argv, timeout):
            if argv[2] == 'build': return subprocess.CompletedProcess(argv, 1, b'failed')
            return original(argv, timeout)
        self.backend.call = failed
        with self.assertRaises(ValueError): self.build()
        self.assertEqual(self.owner.cleanup()['status'], 'FAIL')
        self.assertFalse(any(args[2:4] == ['image', 'rm'] for args in self.backend.calls))

    def test_nonpruning_owned_image_cleanup_preserves_untagged_ancestor(self):
        # Model Moby28's recursive parent deletion when prune=True. This is a
        # causal backend fixture, not a real daemon/ancestor cleanup result.
        class AncestorDocker(FakeDocker):
            ancestor='sha256:'+'9'*64
            ancestor_exists=True
            def call(self,argv,timeout):
                result=super().call(argv,timeout)
                if argv[2:4]==['image','rm'] and '--no-prune' not in argv:
                    self.ancestor_exists=False
                return result
        old=AncestorDocker(self.private);old.image_exists=True
        old.call(['docker','--host='+old.endpoint,'image','rm',old.image],30)
        self.assertFalse(old.ancestor_exists,'old immutable-ID removal can prune an unowned ancestor')
        protected=AncestorDocker(self.private);self.owner.backend=protected;protected.owner=self.owner
        self.build();self.assertEqual(self.owner.cleanup()['status'],'PASS')
        self.assertTrue(protected.ancestor_exists);self.assertFalse(protected.image_exists)
        removed=[argv for argv in protected.calls if argv[2:4]==['image','rm']]
        self.assertEqual(removed,[['docker','--host='+protected.endpoint,'image','rm','--no-prune',protected.image]])
        self.assertNotIn('--force',removed[0]);self.assertNotIn(protected.ancestor,removed[0])
        reserved=[row['argv'] for row in self.rows() if row['event']=='docker-operation-reserved' and row['argv'][2:4]==['image','rm']]
        self.assertEqual(reserved,removed)

    def test_cleanup_image_nonce_and_context_labels_must_match(self):
        self.build(); self.backend.labels[broker.CONTEXT_LABEL] = 'e' * 64
        with self.assertRaises(ValueError): self.owner.cleanup_image()
        self.assertFalse(any(args[2:4] == ['image', 'rm'] for args in self.backend.calls))

    def test_journal_path_swap_refuses_request_without_overwriting_foreign_file(self):
        saved = self.private / 'saved-journal'
        self.owner.journal_path.rename(saved); self.owner.journal_path.write_bytes(b'foreign')
        with self.assertRaisesRegex(ValueError, 'journal-namespace'): self.owner.request(['docker', 'version'])
        self.assertEqual(self.owner.journal_path.read_bytes(), b'foreign')
        self.assertEqual(self.backend.calls, [])

    def test_wire_bounds_reject_huge_argv(self):
        with self.assertRaises(ValueError): self.owner.request(['docker', 'version', 'x' * 8193])
        self.assertEqual(self.backend.calls, [])

    def test_failed_request_permanently_refuses_new_mutation(self):
        with self.assertRaises(ValueError): self.owner.request(['docker', 'system', 'prune'])
        with self.assertRaisesRegex(ValueError, 'failed-broker'): self.build()
        self.assertEqual(self.backend.calls, [])

    def test_container_budget_refuses_fifteenth_reservation(self):
        self.build()
        self.owner.containers = {f'fixture-{i}': {'id': f'{i:064x}', 'absent': True} for i in range(14)}
        count = len(self.backend.calls)
        with self.assertRaisesRegex(ValueError, 'reservation-budget'): self.owner.request(self.inventory())
        self.assertEqual(len(self.backend.calls), count)

    def test_wrong_image_labels_refused_before_new_container_commit(self):
        self.build(); self.backend.labels[broker.LABEL] = 'e' * 32
        with self.assertRaisesRegex(ValueError, 'image-ownership'): self.owner.request(self.inventory())
        self.assertFalse(any(args[2] == 'create' for args in self.backend.calls))

    def test_ambiguous_absence_does_not_claim_cleanup_pass(self):
        self.build(); original = self.backend.call
        def failed(argv, timeout):
            if argv[2:4] == ['image', 'inspect'] and not self.backend.image_exists:
                return subprocess.CompletedProcess(argv, 1, b'cannot connect to Docker daemon')
            return original(argv, timeout)
        self.backend.call = failed
        self.assertEqual(self.owner.cleanup()['status'], 'FAIL')
        self.assertFalse(self.owner.image_removed)

    def test_nonzero_and_oom_exit_cannot_supply_clean_environment(self):
        self.build(); original = self.backend.call
        def oom(argv, timeout):
            result = original(argv, timeout)
            if argv[2] == 'start': next(iter(self.backend.containers.values()))['State']['OOMKilled'] = True
            return result
        self.backend.call = oom
        with self.assertRaisesRegex(ValueError, 'exit-state'): self.owner.request(self.inventory())
        self.assertFalse(any(row['event'] == 'container-exited' for row in self.rows()))
        self.assertEqual(self.owner.cleanup()['status'], 'FAIL')

    def test_oversized_backend_output_refused_with_durable_failure(self):
        self.backend.call = lambda argv, timeout: subprocess.CompletedProcess(argv, 0, b'x' * (broker.RESPONSE_LIMIT + 1))
        with self.assertRaisesRegex(ValueError, 'bounded-folded'): self.owner.request(['docker', 'version'])
        self.assertEqual(self.rows()[-1]['event'], 'request-failed')

    def test_individual_image_absence_allows_empty_inspect_json_with_exact_error_only(self):
        self.build(); original = self.backend.call
        def empty_json(argv, timeout):
            result = original(argv, timeout)
            if argv[2:4] == ['image', 'inspect'] and not self.backend.image_exists:
                result.stdout = b'[]\n' + result.stdout
            return result
        self.backend.call = empty_json
        self.assertEqual(self.owner.cleanup()['status'], 'PASS')

    def test_unknown_actual_create_commit_is_owned_recovered_but_still_fail(self):
        self.build()
        def drift(args):
            if args[0] == 'create': raise OSError('fixture lost response after actual commit')
        self.backend.after = drift
        with self.assertRaises(OSError): self.owner.request(self.inventory())
        self.assertTrue(self.backend.containers)
        self.assertIsNone(next(iter(self.owner.containers.values()))['id'])
        self.backend.after = None
        self.assertEqual(self.owner.cleanup()['status'], 'FAIL')
        self.assertFalse(self.backend.containers)

    def test_phase_deadline_clamps_backend_timeout_without_borrowing_reserve(self):
        observed = []
        self.owner.clock = lambda: 100
        self.owner.deadline = 1000
        self.owner.operation_deadline = 130
        original = self.backend.call
        def timed(argv, timeout):
            observed.append(timeout)
            return original(argv, timeout)
        self.backend.call = timed
        self.owner.request(['docker', 'version'])
        self.assertEqual(observed, [30])
        self.owner.operation_deadline = 99
        with self.assertRaisesRegex(ValueError, 'phase-deadline'): self.owner.request(['docker', 'version'])
        self.assertEqual(observed, [30])

    def test_backend_overrunning_phase_deadline_never_completes_successful_operation(self):
        tick = [100]
        self.owner.clock = lambda: tick[0]
        self.owner.deadline, self.owner.operation_deadline = 1000, 130
        self.backend.after = lambda _: tick.__setitem__(0, 131)
        with self.assertRaisesRegex(ValueError, 'operation-phase'): self.owner.request(['docker', 'version'])
        self.assertFalse(any(row['event'] == 'docker-operation-completed' for row in self.rows()))
        self.assertTrue(self.owner.failed)

    def test_cleanup_uses_global_reserve_after_local_phase_expired(self):
        self.build(); self.owner.operation_deadline = self.owner.clock() - 1
        self.assertEqual(self.owner.cleanup()['status'], 'PASS')
        self.assertFalse(self.backend.image_exists)

    def test_exact_absence_forms_refuse_whitespace_and_unbound_object_diagnostic(self):
        outputs = broker.image_absence_outputs(self.backend.image)
        self.assertEqual(len(outputs), 12)
        diagnostic = ('Error response from daemon: No such image: ' + self.backend.image).encode()
        self.assertIn(b'[]\n' + diagnostic + b'\n', outputs)
        for data in (b' ' + diagnostic, diagnostic + b' ', diagnostic + b'\n\n',
                     diagnostic.replace(self.backend.image.encode(), ('sha256:' + 'f' * 64).encode())):
            self.assertNotIn(data, outputs)

    def test_actual_context_response_bytes_forwarded_unchanged_with_alias(self):
        data = b'[ {"Name":"actual-default","Endpoints":{"docker":{"Host":"unix:///var/run/docker.sock"}},"Metadata":{"Description":"actual"}} ]\n'
        original = self.backend.call
        def actual(argv, timeout):
            if argv[2:] == ['context', 'inspect']:
                self.backend.calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, data)
            return original(argv, timeout)
        self.backend.call = actual
        result = self.owner.request(['docker', 'context', 'inspect'])
        self.assertEqual(result.stdout, data)
        self.assertEqual(self.backend.calls, [['docker', '--host=' + self.backend.endpoint, 'context', 'inspect']])
        completion = self.rows()[-1]
        self.assertEqual(completion['stdout_sha256'], broker.hashlib.sha256(data).hexdigest())

    def test_actual_context_remote_duplicate_or_malformed_response_refused(self):
        responses = (b'[]', b'[{},{}]', b'{}', b'[{"Endpoints":{"docker":{"Host":"tcp://remote"}}}]',
                     b'[{"Endpoints":{"docker":{"Host":"unix:///run/docker.sock","Host":"tcp://remote"}}}]',
                     b'[{"Endpoints":{"docker":{"Host":"unix:///run/docker.sock"}},"value":NaN}]',
                     b'[{"Endpoints":[]}]')
        for data in responses:
            self.owner.failed = False  # Independent malformed-backend fixtures.
            self.backend.call = lambda argv, timeout: subprocess.CompletedProcess(argv, 0, data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.owner.request(['docker', 'context', 'inspect'])
            self.assertTrue(self.owner.failed)
        self.owner.failed = False
        self.backend.call = lambda argv, timeout: subprocess.CompletedProcess(argv, 1, b'context unavailable')
        with self.assertRaisesRegex(ValueError, 'context-inspection-failed'):
            self.owner.request(['docker', 'context', 'inspect'])



class RPCDiagnosticsTests(unittest.TestCase):
    def handle(self, *, refused=False, broken=False, partial=False, cancelled=False, diagnostics=True):
        from unittest.mock import patch
        import struct
        import socket
        from types import SimpleNamespace
        token='1'*64; observed=broker.Diagnostics() if diagnostics else None
        owner=SimpleNamespace(diagnostics=observed,failed=False,events=[],calls=[])
        def request(argv):
            owner.calls.append(argv)
            if refused: raise ValueError('private-secret-refusal/path/token')
            return subprocess.CompletedProcess(argv,0,b'private-output-and-id')
        owner.request=request;owner.record=lambda kind,**fields:owner.events.append((kind,fields))
        class Connection:
            writes=[];closed=False
            def __enter__(self):return self
            def __exit__(self,*args):self.closed=True
            def settimeout(self,value):pass
            def getsockopt(self,*args):return struct.pack('3i',77,os.geteuid(),os.getegid())
            def sendall(self,data):
                if partial:self.writes.append(data[:3])
                if cancelled:raise broker.Cancelled('private cancellation detail')
                if broken:
                    read,write=os.pipe();os.close(read)
                    try:os.write(write,data)
                    finally:os.close(write)
                self.writes.append(data)
        connection=Connection();subject=object.__new__(broker.Service);subject.broker=owner;subject.token=token
        wire=json.dumps({'token':token,'argv':['version']}).encode()
        error=None
        with patch.object(broker,'receive',return_value=wire):
            try:subject.handle(connection)
            except (BrokenPipeError,broker.Cancelled) as raised:error=type(raised).__name__
        return owner,connection,error

    def test_completed_or_refused_request_real_broken_pipe_preserves_first_failure(self):
        for refused in (False,True):
            with self.subTest(refused=refused):
                owner,connection,error=self.handle(refused=refused,broken=True)
                self.assertEqual(error,'BrokenPipeError');self.assertTrue(connection.closed)
                row=owner.diagnostics.snapshot()['rpc']
                self.assertEqual(row['first_failure']['category'],'ValueError' if refused else 'BrokenPipeError')
                self.assertEqual(row['last_failure']['category'],'BrokenPipeError')
                self.assertEqual(row['current']['step'],'REPLY_FAILED')
                self.assertEqual(owner.failed,refused)  # Same original Service semantics.
                self.assertEqual(len(owner.calls),1)
                encoded=json.dumps(owner.diagnostics.snapshot())
                self.assertNotIn('private',encoded);self.assertNotIn('token',encoded)
                self.assertIsNone(row['request_return'] if refused else None)
                if not refused:self.assertEqual(row['request_return']['code'],0)

    def test_partial_reply_and_cancellation_refuse_without_retry(self):
        for cancelled in (False,True):
            owner,connection,error=self.handle(broken=not cancelled,partial=True,cancelled=cancelled)
            self.assertEqual(error,'Cancelled' if cancelled else 'BrokenPipeError')
            self.assertEqual(len(connection.writes),1);self.assertEqual(len(connection.writes[0]),3)
            self.assertEqual(len(owner.calls),1)
            self.assertEqual(owner.diagnostics.snapshot()['rpc']['current']['step'],'REPLY_FAILED')

    def test_diagnostics_do_not_change_request_result_or_exception(self):
        for refused in (False,True):
            for broken in (False,True):
                with self.subTest(refused=refused,broken=broken):
                    a,c,e=self.handle(refused=refused,broken=broken)
                    b,d,f=self.handle(refused=refused,broken=broken,diagnostics=False)
                    self.assertEqual((a.calls,a.events,a.failed,e,c.writes),(b.calls,b.events,b.failed,f,d.writes))

    def test_closed_labels_counts_hashes_and_unknown_types_have_finite_projection(self):
        class SecretError(Exception):pass
        diagnostic=broker.Diagnostics()
        for _ in range(4100):diagnostic.begin()
        diagnostic.kind(['credential-secret-command','/private/secret'])
        diagnostic.returned(subprocess.CompletedProcess([],True,b'private\0credential'),argv=['info'])
        diagnostic.failure('private-stage',SecretError('raw-secret-error'))
        diagnostic.cleaned({'status':'FAIL','containers_absent':True,'owned_image_absent':True,'error_type':'SecretError'},True)
        row=diagnostic.snapshot();encoded=json.dumps(row).encode()
        self.assertLessEqual(len(encoded),4096);self.assertNotIn(b'private',encoded);self.assertNotIn(b'credential',encoded)
        self.assertEqual(row['rpc']['requests'],4096);self.assertTrue(row['rpc']['saturated'])
        self.assertEqual(row['rpc']['current']['kind'],'UNKNOWN')
        self.assertIsNone(row['rpc']['cli_return']['code'])
        self.assertEqual(row['rpc']['first_failure']['category'],'UNKNOWN')
        self.assertEqual(row['cleanup']['error_category'],'UNKNOWN')
        row=diagnostic.snapshot({'started':'raw-secret', 'runner_return_code':True,
            'natural_poll_code':-129,'reaped_code':256,'reaping':'private','extra':'credential'})
        self.assertNotIn('private',json.dumps(row));self.assertNotIn('credential',json.dumps(row))
        self.assertIsNone(row['producer']['runner_return_code']);self.assertIsNone(row['producer']['started'])
        self.assertEqual(row['producer']['reaping'],'UNKNOWN')
        class ForeignResult:
            @property
            def stdout(self):raise AssertionError('observer must not read rejected foreign result')
        self.assertEqual(broker.diagnostic_result(ForeignResult()),
            {'code':None,'stdout_bytes':None,'stdout_sha256':None})
        first=row['rpc']['first_failure'];diagnostic.begin();diagnostic.failure('CLEANUP',OSError('later private'))
        self.assertEqual(diagnostic.snapshot()['rpc']['first_failure'],first)
        self.assertEqual(diagnostic.snapshot()['rpc']['last_failure']['category'],'OSError')
        diagnostic.cleaned({'status':['private'],'error_type':['private']},False)
        self.assertEqual(diagnostic.snapshot({'reaping':['private']})['producer']['reaping'],'UNKNOWN')
        self.assertEqual(diagnostic.snapshot()['cleanup']['status'],'UNKNOWN')



class BrokerReturnDiagnosticsTests(unittest.TestCase):
    setUp = BrokerTests.setUp
    def test_actual_cleanup_success_reports_only_existing_returned_flags(self):
        self.owner.diagnostics=broker.Diagnostics()
        result=self.owner.cleanup();row=self.owner.diagnostics.snapshot()['cleanup']
        self.assertEqual(result['status'],'PASS');self.assertEqual(row['status'],'PASS')
        self.assertFalse(row['owner_failed']);self.assertTrue(row['containers_absent'])
        self.assertTrue(row['owned_image_absent']);self.assertIsNone(row['error_category'])

    def test_cli_return_captured_before_original_postcheck_refusal(self):
        self.owner.diagnostics=broker.Diagnostics();self.owner.diagnostics.begin()
        self.backend.action=lambda args:setattr(self.owner,'failed',True)
        with self.assertRaisesRegex(ValueError,'failed-broker'):
            self.owner.call(['version'])
        row=self.owner.diagnostics.snapshot()['rpc']['cli_return']
        self.assertEqual(row['code'],0);self.assertEqual(row['kind'],'VERSION')
        self.assertEqual(row['stdout_bytes'],len(b'fixture Docker version\n'))

    def test_cleanup_sticky_fail_does_not_erase_actual_returned_absence_flags(self):
        self.owner.diagnostics=broker.Diagnostics();self.owner.failed=True
        result=self.owner.cleanup();row=self.owner.diagnostics.snapshot()['cleanup']
        self.assertEqual(result['status'],'FAIL');self.assertEqual(row['status'],'FAIL')
        self.assertTrue(row['containers_absent']);self.assertTrue(row['owned_image_absent'])
        self.assertTrue(row['owner_failed']);self.assertIsNone(row['error_category'])

    def test_cleanup_exception_and_success_separate_observed_result_flags(self):
        self.owner.diagnostics=broker.Diagnostics()
        with __import__('unittest.mock',fromlist=['patch']).patch.object(self.owner,'check',side_effect=OSError('raw/private')):
            self.assertEqual(self.owner.cleanup()['status'],'FAIL')
        row=self.owner.diagnostics.snapshot()['cleanup']
        self.assertFalse(row['containers_absent']);self.assertFalse(row['owned_image_absent'])
        self.assertEqual(row['error_category'],'OSError')
        self.assertEqual(self.owner.diagnostics.snapshot()['rpc']['first_failure']['stage'],'CLEANUP')



if __name__ == '__main__': unittest.main()
