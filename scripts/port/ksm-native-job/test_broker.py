# SPDX-License-Identifier: MIT
"""Fake Docker fixtures only; no daemon, builds, package execution or network."""
import importlib.util
import json
import os
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


if __name__ == '__main__': unittest.main()
