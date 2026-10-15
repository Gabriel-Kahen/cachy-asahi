#!/usr/bin/env python3
"""Controller fixtures: no Docker daemon, native build, install, or host mutation."""
import copy
from contextlib import ExitStack, contextmanager
import json
import os
import signal
from pathlib import Path
import socket
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import stage as s

ENDPOINT = 'unix:///var/run/docker.sock'
IMAGE = 'sha256:' + 'a' * 64
CID = 'c' * 64
COMMIT = 'd' * 40
SIGNING = {'fingerprint': 'A' * 40, 'signature_sha256': 'b' * 64, 'public_key_sha256': 'e' * 64}


def contract(phase='sign'):
    return {'schema_version': 1, 'purpose': s.PURPOSE, 'scope': s.SCOPE, 'nonce': 'f' * 32,
            'source_commit': COMMIT, 'run_id': '123', 'daemon_id': 'local-daemon', 'image_id': IMAGE,
            'uid': 1000, 'package': {'sha256': '1' * 64}, 'approved_inputs_sha256': '2' * 64,
            'bootstrap_sha256': '3' * 64, 'packages_sha256': s.base.PACKAGES_SHA,
            'current_inputs_sha256': s.base.INPUTS_SHA, 'source_sha256': {'fixture': '4' * 64},
            'signing': SIGNING if phase == 'lifecycle' else None, 'phase': phase}


def receipt(c, status='PASS'):
    result = {key: c[key] for key in ('schema_version', 'purpose', 'scope', 'phase', 'nonce', 'image_id',
                                     'source_commit', 'packages_sha256', 'source_sha256')}
    return {**result, 'package_sha256': c['package']['sha256'], 'status': status,
            'checks': [{'name': name, 'status': 'PASS'} for name in sorted(s.CHECKS[c['phase']])],
            'signing': SIGNING, 'cleanup': {'processes': 'PASS', 'tmpfs': 'PASS'},
            'hardware': 'NOT RUN', 'management': 'NOT RUN'}


def inspected(c, source, output):
    root = c['phase'] == 'lifecycle'
    owner = 0 if root else c['uid']
    memory, pids = (2 * 1024**3, 96) if root else (1024**3, 64)
    digest = s.sha(json.dumps(c, sort_keys=True).encode())
    return {'Id': CID, 'Image': IMAGE,
            'Config': {'User': f'{owner}:{owner}', 'Labels': {'cachy-asahi.ksm.nonce': c['nonce'],
                        'cachy-asahi.ksm.contract': digest}, 'Entrypoint': ['/usr/bin/python'],
                       'Cmd': ['-I', '-B', '/source/scripts/port/ksm-lifecycle/worker.py', '--phase', c['phase'],
                               '--contract-sha256', digest],
                       'Env': ['HOME=/tmp/ksm-stage', 'PATH=/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE=1',
                               'CACHY_ASAHI_IMAGE_ID=' + IMAGE, 'CACHY_ASAHI_CLIENT_UID=1000']},
            'HostConfig': {'ReadonlyRootfs': not root, 'NetworkMode': 'none', 'IpcMode': 'private',
                           'PidMode': '', 'UTSMode': '', 'Privileged': False, 'CapDrop': ['ALL'],
                           'CapAdd': ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID'] if root else None,
                           'SecurityOpt': ['no-new-privileges'], 'Memory': memory, 'MemorySwap': memory,
                           'NanoCpus': 2 * 10**9, 'PidsLimit': pids,
                           'Ulimits': [{'Name': 'nofile', 'Soft': 256, 'Hard': 256}],
                           'Tmpfs': {'/tmp': f'rw,nosuid,nodev,exec,size=256m,mode={"1777" if root else "0700"},uid={owner},gid={owner}'}},
            'Mounts': [{'Type': 'bind', 'Destination': '/source', 'Source': str(source), 'RW': False},
                       {'Type': 'bind', 'Destination': '/out', 'Source': str(output), 'RW': True}],
            'State': {'Status': 'exited', 'Running': False, 'Paused': False, 'Restarting': False,
                      'ExitCode': 0, 'OOMKilled': False, 'Dead': False, 'Error': ''}}


class DockerBoundaryTests(unittest.TestCase):
    """Real sealed ELF and Unix-socket fixtures; daemon responses are mocked."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ksm-docker-boundary-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cli = self.root / 'docker-fixture'
        self.cli.write_bytes(Path('/usr/bin/true').read_bytes())
        self.cli.chmod(0o755)
        self.socket_path = self.root / 'docker.sock'
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.bind(str(self.socket_path))
        self.socket_path.chmod(0o600)
        self.addCleanup(self.socket.close)
        self.endpoint = 'unix://' + str(self.socket_path)
        original_command = s.base.docker_command
        def command(endpoint, *args):
            if endpoint == self.endpoint:
                return ['docker', '--host=' + endpoint, *args]
            return original_command(endpoint, *args)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(s.base, 'docker_command', side_effect=command).start()
        mock.patch.object(s, 'DOCKER_CLI', self.cli).start()
        mock.patch.object(s, 'coordinator_identity', return_value=(1000, 1000)).start()
        info = self.socket_path.stat()
        self.docker = s.Docker(self.endpoint, 'local-daemon', s.sha(self.cli.read_bytes()), info.st_dev, info.st_ino)
        self.addCleanup(self.docker.close)
        s.base.CANCELLED = False
        self.addCleanup(setattr, s.base, 'CANCELLED', False)

    def command(self, *args):
        return s.base.docker_command(self.endpoint, *args)

    def transport(self, argv, **kwargs):
        self.assertEqual(argv[:2], [self.docker.executable, '--host=' + self.endpoint])
        return (0, b'local-daemon\n') if argv[2:] == ['info', '--format', '{{.ID}}'] else (0, b'')

    def test_executes_sealed_checked_bytes_and_refuses_modification(self):
        result = subprocess.run([self.docker.executable], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0)  # /usr/bin/true fixture, never Docker.
        with self.assertRaises(OSError):os.write(self.docker.exec_fd, b'changed')

    def test_every_operation_including_removal_and_absence_checks_has_identity_checks(self):
        with mock.patch.object(s.base, 'bounded', side_effect=self.transport) as transport:
            for args in (('create', '--name', 'fixture'), ('inspect', CID), ('start', '--attach', CID)):
                self.docker.successful(self.command(*args))
            self.docker.remove('fixture', CID)
        operations = [call.args[0][2:] for call in transport.call_args_list]
        self.assertEqual(len(operations), 18)  # Six real operation requests, each checked twice.
        for n in range(0, len(operations), 3):
            self.assertEqual(operations[n], ['info', '--format', '{{.ID}}'])
            self.assertEqual(operations[n + 2], ['info', '--format', '{{.ID}}'])

    def test_wrong_daemon_refused_before_create_start_and_cleanup_queries(self):
        for args in (('create',), ('start', CID), ('rm', CID), ('container', 'ls')):
            with self.subTest(args=args), mock.patch.object(s.base, 'bounded', return_value=(0, b'wrong-daemon\n')) as transport:
                with self.assertRaisesRegex(ValueError, 'daemon-identity-drift'):
                    self.docker.successful(self.command(*args))
                self.assertEqual(transport.call_count, 1)
                self.assertEqual(transport.call_args.args[0][2:], ['info', '--format', '{{.ID}}'])

    def test_A_B_A_phase_counterexample_never_launches_on_B(self):
        source, output = self.root / 'source', self.root / 'out'
        source.mkdir(); output.mkdir()
        c = contract()
        current, launched = ['local-daemon'], []
        def transport(argv, **kwargs):
            if argv[2:] == ['info', '--format', '{{.ID}}']:
                return 0, current[0].encode()
            if argv[2:4] == ['container', 'ls']:
                current[0] = 'wrong-daemon'  # Exact original reproduction's change.
                return 0, b''
            if argv[2] in {'create', 'start'}:
                launched.append((argv[2], current[0]))
                current[0] = 'local-daemon'
                return 0, CID.encode()
            raise AssertionError(argv)
        report = {'phases': []}
        with mock.patch.object(s.base, 'bounded', side_effect=transport):
            with self.assertRaises(ValueError):
                s.phase_run(self.endpoint, 'local-daemon', IMAGE, source, output, c, report, docker=self.docker)
        self.assertEqual(launched, [])
        self.assertEqual(report['phases'][0]['status'], 'FAIL')

    def test_daemon_drift_between_inspect_and_start_refuses_start(self):
        current, launched = ['local-daemon'], []
        def transport(argv, **kwargs):
            if argv[2:] == ['info', '--format', '{{.ID}}']:
                return 0, current[0].encode()
            if argv[2] == 'inspect':
                current[0] = 'wrong-daemon'
                return 0, b'[]'
            launched.append(argv[2])
            return 0, b''
        with mock.patch.object(s.base, 'bounded', side_effect=transport):
            with self.assertRaisesRegex(ValueError, 'daemon-identity-drift'):
                self.docker.successful(self.command('inspect', CID))
            with self.assertRaisesRegex(ValueError, 'daemon-identity-drift'):
                self.docker.successful(self.command('start', CID))
        self.assertEqual(launched, [])

    def test_daemon_drift_between_cleanup_queries_cannot_claim_absence(self):
        current, queries = ['local-daemon'], []
        def transport(argv, **kwargs):
            if argv[2:] == ['info', '--format', '{{.ID}}']:
                return 0, current[0].encode()
            queries.append(argv[2:])
            if argv[2:4] == ['container', 'ls']:
                current[0] = 'wrong-daemon'
            return 0, b''
        with mock.patch.object(s.base, 'bounded', side_effect=transport):
            with self.assertRaisesRegex(ValueError, 'daemon-identity-drift'):
                self.docker.remove('fixture', CID)
        self.assertEqual(len(queries), 2)  # rm then name query; ID query cannot cross to B.

    def test_cli_path_or_bytes_drift_refused_without_any_daemon_call(self):
        original = self.cli.read_bytes()
        self.cli.write_bytes(original + b'changed')
        with mock.patch.object(s.base, 'bounded') as transport:
            with self.assertRaises(ValueError):self.docker.successful(self.command('create'))
            transport.assert_not_called()

    def test_cli_inode_replacement_refused_even_with_same_bytes(self):
        other = self.root / 'replacement'
        other.write_bytes(self.cli.read_bytes()); other.chmod(0o755)
        other.replace(self.cli)
        with mock.patch.object(s.base, 'bounded') as transport:
            with self.assertRaisesRegex(ValueError, 'cli-path-drift'):
                self.docker.successful(self.command('start', CID))
            transport.assert_not_called()

    def test_socket_replacement_refused_even_with_same_endpoint_and_daemon_id(self):
        self.socket_path.unlink()
        replacement = socket.socket(socket.AF_UNIX)
        self.addCleanup(replacement.close)
        replacement.bind(str(self.socket_path)); self.socket_path.chmod(0o600)
        with mock.patch.object(s.base, 'bounded') as transport:
            with self.assertRaisesRegex(ValueError, 'socket-identity-drift'):
                self.docker.successful(self.command('create'))
            transport.assert_not_called()

    def test_cli_checksum_and_socket_pin_required_at_capture(self):
        info = self.socket_path.stat()
        for checksum, inode in (('f' * 64, info.st_ino), (s.sha(self.cli.read_bytes()), info.st_ino + 1)):
            with self.subTest(checksum=checksum, inode=inode), self.assertRaises(ValueError):
                s.Docker(self.endpoint, 'local-daemon', checksum, info.st_dev, inode)

    def test_nonregular_cli_refused_before_open(self):
        self.cli.unlink(); os.mkfifo(self.cli)
        info = self.socket_path.stat()
        with mock.patch.object(s.os, 'open') as opened:
            with self.assertRaisesRegex(ValueError, 'unsafe-docker-cli'):
                s.Docker(self.endpoint, 'local-daemon', 'a' * 64, info.st_dev, info.st_ino)
            opened.assert_not_called()

    def test_identity_change_to_another_matching_pair_is_refused(self):
        with mock.patch.object(s, 'coordinator_identity', return_value=(1001, 1001)), \
                mock.patch.object(s.base, 'bounded') as transport:
            with self.assertRaisesRegex(ValueError, 'coordinator-identity-drift'):
                self.docker.successful(self.command('create'))
            transport.assert_not_called()

    def test_transport_failure_still_checks_files_and_daemon_afterwards(self):
        def transport(argv, **kwargs):
            if argv[2:] == ['info', '--format', '{{.ID}}']:
                return 0, b'local-daemon'
            raise ValueError('transport failure')
        with mock.patch.object(s.base, 'bounded', side_effect=transport) as transport:
            with self.assertRaisesRegex(ValueError, 'transport failure'):
                self.docker.successful(self.command('create'))
            self.assertEqual(transport.call_count, 3)

    def test_cli_drift_during_operation_fails_at_post_execution_boundary(self):
        def transport(argv, **kwargs):
            if argv[2:] == ['info', '--format', '{{.ID}}']:
                return 0, b'local-daemon'
            data = self.cli.read_bytes()
            self.cli.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
            return 0, b'operation succeeded'
        with mock.patch.object(s.base, 'bounded', side_effect=transport) as called:
            with self.assertRaisesRegex(ValueError, 'docker-cli-.*drift'):
                self.docker.successful(self.command('create'))
        self.assertEqual(called.call_count, 2)

    def test_socket_drift_during_transport_error_still_fails_at_boundary(self):
        def transport(argv, **kwargs):
            if argv[2:] == ['info', '--format', '{{.ID}}']:
                return 0, b'local-daemon'
            self.socket_path.unlink()
            replacement = socket.socket(socket.AF_UNIX)
            self.addCleanup(replacement.close)
            replacement.bind(str(self.socket_path)); self.socket_path.chmod(0o600)
            raise ValueError('transport failure')
        with mock.patch.object(s.base, 'bounded', side_effect=transport) as called:
            with self.assertRaisesRegex(ValueError, 'local-socket-identity-drift'):
                self.docker.successful(self.command('inspect', CID))
        self.assertEqual(called.call_count, 2)

    def test_close_attempts_all_descriptors_after_one_close_error(self):
        close = os.close
        original = list(self.docker.fds)
        seen = []
        def fail_once(fd):
            seen.append(fd)
            close(fd)
            if len(seen) == 1:raise OSError('fixture close boundary error')
        with mock.patch.object(s.os, 'close', side_effect=fail_once):
            with self.assertRaises(OSError):self.docker.close()
        self.assertEqual(set(seen), set(original))
        self.assertEqual(self.docker.fds, [])


class StageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ksm-stage-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.source, self.out = [Path(self.tmp.name) / name for name in ('source', 'out')]
        self.source.mkdir()
        self.out.mkdir()
        s.base.CANCELLED = False
        self.addCleanup(setattr, s.base, 'CANCELLED', False)

    def test_phase_flags_and_endpoint(self):
        for phase in ('sign', 'lifecycle'):
            c = contract(phase)
            argv = s.container_command(ENDPOINT, IMAGE, 'fixture', self.source, self.out, 1000, phase, c['nonce'], '5' * 64)
            self.assertEqual(argv[:3], ['docker', '--host=' + ENDPOINT, 'create'])
            self.assertIn('--network=none', argv)
            self.assertIn('--cap-drop=ALL', argv)
            self.assertEqual('--read-only' in argv, phase == 'sign')
            self.assertEqual(argv[argv.index('--user') + 1], '0:0' if phase == 'lifecycle' else '1000:1000')
            self.assertEqual([x for x in argv if x.startswith('--cap-add=')],
                             ['--cap-add=' + x for x in ('CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID')]
                             if phase == 'lifecycle' else [])

    def test_remote_endpoint_refused(self):
        with self.assertRaises(ValueError):
            s.container_command('tcp://fixture:2375', IMAGE, 'fixture', self.source, self.out, 1000, 'sign', 'n', 'h')

    def test_isolation_accepts_both_phases(self):
        for phase in ('sign', 'lifecycle'):
            c = contract(phase)
            s.inspect_isolation(inspected(c, self.source, self.out), c, self.source, self.out)

    def test_isolation_drift_refused(self):
        edits = [('Config', 'Cmd', ['/bin/sh']), ('Config', 'Entrypoint', ['/bin/sh']),
                 ('Config', 'Env', ['PATH=/usr/bin:/bin', 'LD_PRELOAD=/source/inject.so']),
                 ('HostConfig', 'SecurityOpt', ['no-new-privileges', 'seccomp=unconfined']),
                 ('HostConfig', 'CapAdd', ['SYS_ADMIN']), ('HostConfig', 'NetworkMode', 'host'),
                 ('HostConfig', 'Privileged', True), ('HostConfig', 'ReadonlyRootfs', False),
                 ('HostConfig', 'DeviceCgroupRules', ['a *:* rwm']), ('HostConfig', 'Ulimits', [])]
        c = contract()
        for section, key, value in edits:
            with self.subTest(key=key):
                record = inspected(c, self.source, self.out)
                record[section][key] = value
                with self.assertRaises(ValueError):
                    s.inspect_isolation(record, c, self.source, self.out)

    def test_unowned_container_refused(self):
        c = contract()
        record = inspected(c, self.source, self.out)
        record['Config']['Labels']['cachy-asahi.ksm.nonce'] = 'other'
        with self.assertRaisesRegex(ValueError, 'unowned'):
            s.inspect_owned(record, s.sha(json.dumps(c, sort_keys=True).encode()), c['nonce'], IMAGE)

    def test_extra_mount_refused(self):
        c = contract()
        record = inspected(c, self.source, self.out)
        record['Mounts'].append({'Type': 'bind', 'Destination': '/host', 'Source': '/', 'RW': True})
        with self.assertRaisesRegex(ValueError, 'mount'):
            s.inspect_isolation(record, c, self.source, self.out)

    def test_receipt_pass_and_cancelled_fail(self):
        for phase in ('sign', 'lifecycle'):
            c = contract(phase)
            s.validate_receipt(receipt(c), c)
            failed = receipt(c, 'FAIL')
            failed.update(checks=[], cleanup={'processes': 'FAIL', 'tmpfs': 'PASS'}, cancelled=True)
            s.validate_receipt(failed, c)

    def test_receipt_unknown_data_or_false_pass_refused(self):
        c = contract()
        for change in ({'raw_log': 'private'}, {'hardware': 'PASS'}, {'checks': []},
                       {'cleanup': {'processes': 'FAIL', 'tmpfs': 'PASS'}}, {'signing': None},
                       {'cancelled': True}, {'package_sha256': '9' * 64},
                       {'checks': [{'name': 'signature', 'status': 'PASS'}] * 2}):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    s.validate_receipt({**receipt(c), **change}, c)

    def test_lifecycle_operational_failure_keeps_public_signing_binding(self):
        c = contract('lifecycle')
        failed = receipt(c, 'FAIL')
        failed['checks'] = [{'name': 'install', 'status': 'FAIL'}]
        s.validate_receipt(failed, c)
        failed['signing'] = None
        with self.assertRaisesRegex(ValueError, 'signing-binding'):
            s.validate_receipt(failed, c)

    def phase(self, fault=None, absent=False, remaining=b''):
        c = contract()
        obj = inspected(c, self.source, self.out)
        report = {'phases': []}
        commands = []
        removals = []
        def success(argv, **kwargs):
            commands.append(argv)
            self.assertEqual(argv[:2], ['docker', '--host=' + ENDPOINT])
            if argv[2] == 'create':
                if fault == 'ambiguous-create':
                    raise ValueError('transport failure after daemon created object')
                return CID.encode()
            if argv[2] == 'inspect':
                return json.dumps([obj]).encode()
            if argv[2:4] == ['container', 'ls']:
                return remaining if '--filter' in argv and ('id=' + CID) in argv else b''
            raise AssertionError(argv)
        def bounded(argv, **kwargs):
            commands.append(argv)
            self.assertEqual(argv[:2], ['docker', '--host=' + ENDPOINT])
            if argv[2] == 'start':
                if fault == 'cancel':
                    s.base.CANCELLED = True
                    raise KeyboardInterrupt()
                worker = receipt(c, 'FAIL' if fault == 'worker' else 'PASS')
                if fault == 'unbound':
                    worker['nonce'] = 'another'
                (self.out / 'worker-receipt.json').write_text(json.dumps(worker))
                return (1 if fault == 'worker' else 0), b'private signing output discarded'
            if argv[2] == 'inspect':
                if absent:
                    return 1, b'not found or transport failure'
                owned = copy.deepcopy(obj)
                if fault == 'ownership':
                    owned['Config']['Labels'] = {}
                return 0, json.dumps([owned]).encode()
            raise AssertionError(argv)
        def remove(name, cid):
            removals.append((name, cid, ENDPOINT))
            if fault == 'cleanup':
                raise ValueError('daemon removal not confirmed')
        def check_absent(selected):
            data = success(s.base.docker_command(ENDPOINT, 'container', 'ls', '--all', '--quiet', '--no-trunc', '--filter', selected))
            s.need(not data.strip(), 'fixture absence failed')
        docker = SimpleNamespace(endpoint=ENDPOINT, expected='local-daemon', successful=success,
                                 bounded=bounded, remove=remove, absent=check_absent)
        with mock.patch.object(s.base, 'CANCELLED', False):
            if fault or remaining:
                with self.assertRaises((ValueError, KeyboardInterrupt)):
                    s.phase_run(ENDPOINT, 'local-daemon', IMAGE, self.source, self.out, c, report, docker=docker)
            else:
                s.phase_run(ENDPOINT, 'local-daemon', IMAGE, self.source, self.out, c, report, docker=docker)
        return report['phases'][0], commands, removals

    def test_contract_mode_is_exact_under_restrictive_umask(self):
        for mask in (0o022, 0o027, 0o077):
            with self.subTest(umask=oct(mask)):
                path = self.source / 'inputs.json'
                path.unlink(missing_ok=True)
                previous = os.umask(mask)
                try:
                    row, _, _ = self.phase()
                finally:
                    os.umask(previous)
                self.assertEqual(row['status'], 'PASS')
                self.assertEqual(path.stat().st_mode & 0o777, 0o644)
                self.assertEqual(json.loads(path.read_bytes()), contract())

    def test_phase_pass_only_after_cleanup(self):
        row, _, removals = self.phase()
        self.assertEqual((row['status'], row['container_cleanup']), ('PASS', 'PASS'))
        self.assertEqual(len(removals), 1)
        self.assertNotIn('private signing output discarded', json.dumps(row))

    def test_ambiguous_create_removes_owned_named_container(self):
        row, _, removals = self.phase('ambiguous-create')
        self.assertEqual((row['status'], row['container_cleanup']), ('FAIL', 'PASS'))
        self.assertEqual(len(removals), 1)

    def test_cancellation_still_confirms_container_removal(self):
        row, _, removals = self.phase('cancel')
        self.assertEqual((row['status'], row['container_cleanup']), ('FAIL', 'PASS'))
        self.assertEqual(len(removals), 1)

    def test_cleanup_failure_blocks_pass(self):
        row, _, _ = self.phase('cleanup')
        self.assertEqual((row['status'], row['container_cleanup']), ('FAIL', 'FAIL'))

    def test_cleanup_never_deletes_unowned_name(self):
        row, _, removals = self.phase('ownership')
        self.assertEqual(row['container_cleanup'], 'FAIL')
        self.assertEqual(removals, [])

    def test_known_id_absence_checked_when_name_is_absent(self):
        row, commands, _ = self.phase(absent=True)
        self.assertEqual(row['container_cleanup'], 'PASS')
        self.assertTrue(any('id=' + CID in argv for argv in commands))

    def test_renamed_live_id_blocks_cleanup_pass(self):
        row, _, _ = self.phase(absent=True, remaining=CID.encode())
        self.assertEqual((row['status'], row['container_cleanup']), ('FAIL', 'FAIL'))

    def test_worker_fail_is_retained_but_unbound_receipt_is_discarded(self):
        row, _, _ = self.phase('worker')
        self.assertEqual(row['worker']['status'], 'FAIL')
        row, _, _ = self.phase('unbound')
        self.assertNotIn('worker', row)

    def test_daemon_drift_prevents_cleanup_claim(self):
        docker = SimpleNamespace(endpoint=ENDPOINT, expected='changed-daemon',
                                 successful=mock.Mock(side_effect=ValueError('identity drift')))
        with mock.patch.object(s.base, 'CANCELLED', False):
            report = {'phases': []}
            with self.assertRaises(ValueError):
                s.phase_run(ENDPOINT, 'changed-daemon', IMAGE, self.source, self.out, contract(), report, docker=docker)
            self.assertEqual(report['phases'][0]['status'], 'FAIL')
            self.assertEqual(report['phases'][0]['container_cleanup'], 'NOT RUN')

    def test_native_boundary_refuses_without_docker(self):
        with mock.patch.object(s.platform, 'machine', return_value='x86_64'), mock.patch.object(s.base, 'successful') as command:
            with self.assertRaisesRegex(ValueError, 'native-nonroot'):
                s.controller(SimpleNamespace())
            command.assert_not_called()

    def test_contract_loader_executes_exact_checked_snapshot(self):
        with mock.patch.object(s.base, 'checked', return_value=b'marker = "checked bytes"\n'):
            self.assertEqual(s.load_contract('fixture').marker, 'checked bytes')

    def controller_fixture(self, fault=None, *, run_wrapper=False):
        public = Path(self.tmp.name) / 'public'
        args = SimpleNamespace(image=IMAGE, daemon_id='local-daemon', source_commit=COMMIT, run_id='123',
                               docker_endpoint=ENDPOINT, docker_sha256='a' * 64,
                               docker_socket_device='1', docker_socket_inode='2',
                               runner='runner', runner_sha256='5' * 64, bootstrap='bootstrap',
                               bootstrap_sha256='6' * 64, packages='packages', current_inputs='current',
                               contract_source_sha256='7' * 64, approved_inputs='approved', build_1='one',
                               build_2='two', build_1_provenance_sha256='8' * 64,
                               build_2_provenance_sha256='9' * 64, output=str(public))
        package = {'filename': 'fixture.pkg.tar.xz', 'sha256': s.sha(b'archive'),
                   'provenance_sha256': ['8' * 64, '9' * 64]}
        if fault == 'provenance-drift':
            package['provenance_sha256'][1] = 'a' * 64
        module = SimpleNamespace(APPROVED_MAP_SHA256='b' * 64,
                                 validate_build_pair=mock.Mock(return_value=(package, b'archive')))
        runner = {'commit': COMMIT, 'run_id': '123', 'uid': 1000, 'kernel': {'machine': 'aarch64'},
                  'docker_server_arch': 'aarch64', 'docker_endpoint': ENDPOINT}
        data = {'runner': json.dumps(runner).encode(), 'bootstrap': b'fixture bootstrap',
                'packages': b'fixture inventory', 'current': b'fixture current inputs', 'approved': b'fixture map',
                'one/provenance.json': b'first', 'two/provenance.json': b'second'}
        private = []
        created = []
        original_temporary = s.tempfile.TemporaryDirectory
        original_finalize = s.base.finalize_receipt
        def late_cancel(path, report):
            original_finalize(path, report)
            s.base.CANCELLED = True
        class CleanupFailure:
            def __init__(self, **kwargs):
                self.actual = original_temporary(**kwargs)
                self.name = self.actual.name
                created.append(self.actual)
            def cleanup(self):
                raise OSError('fixture private cleanup failure')
        def checked(path, expected):
            if str(path) in data:
                return data[str(path)]
            blob = Path(path).read_bytes()
            self.assertEqual(s.sha(blob), expected)
            return blob
        def docker(argv, **kwargs):
            if argv == ['docker', 'context', 'inspect']:
                return json.dumps([{'Endpoints': {'docker': {'Host': ENDPOINT}}}]).encode()
            self.assertEqual(argv[:2], ['docker', '--host=' + ENDPOINT])
            if argv[2] == 'info':
                return b'aarch64\n'
            if argv[2:4] == ['image', 'inspect']:
                return json.dumps([{'Id': IMAGE, 'Architecture': 'arm64', 'Os': 'linux'}]).encode()
            raise AssertionError(argv)
        def phase(endpoint, daemon, image, source, output, c, report, *, docker):
            private.append(source.parent)
            self.assertEqual(endpoint, ENDPOINT)
            self.assertEqual(daemon, 'local-daemon')
            self.assertEqual((source / package['filename']).read_bytes(), b'archive')
            report['phases'].append({'phase': c['phase'], 'status': 'PASS', 'container_cleanup': 'PASS'})
            result = receipt(c)
            if c['phase'] == 'sign':
                (output / 'package.sig').write_bytes(b'signature')
                (output / 'public.gpg').write_bytes(b'public key')
                result['signing'] = {'fingerprint': 'A' * 40, 'signature_sha256': s.sha(b'signature'),
                                     'public_key_sha256': s.sha(b'public key')}
                if fault == 'extra-output':
                    (output / 'secret.key').write_bytes(b'private material')
            else:
                self.assertEqual((source / 'package.sig').read_bytes(), b'signature')
                if fault == 'lifecycle':
                    raise ValueError('fixture lifecycle failure')
                if fault == 'cancel':
                    s.base.CANCELLED = True
            (output / 'worker-receipt.json').write_text(json.dumps(result))
            return result
        boundary = SimpleNamespace(endpoint=ENDPOINT, expected='local-daemon', cli_sha256='a' * 64,
                                   closed=False, successful=docker)
        def close():
            boundary.closed = True
            if fault == 'close-cancel':
                s.base.CANCELLED = True
        boundary.close = close
        with ExitStack() as stack:
            for target, name, kwargs in (
                (s.platform, 'system', {'return_value': 'Linux'}),
                (s.platform, 'machine', {'return_value': 'aarch64'}),
                (s.os, 'getuid', {'return_value': 1000}), (s.os, 'geteuid', {'return_value': 1000}),
                (s.os, 'getgid', {'return_value': 1000}), (s.os, 'getegid', {'return_value': 1000}),
                (s, 'Docker', {'return_value': boundary}), (s.base, 'checked', {'side_effect': checked}),
                (s.base, 'bootstrap', {}), (s, 'load_contract', {'return_value': module}),
                (s, 'sources', {'return_value': ({'scripts/fixture.py': b'fixture'}, {'scripts/fixture.py': s.sha(b'fixture')})}),
                (s, 'phase_run', {'side_effect': phase})):
                stack.enter_context(mock.patch.object(target, name, **kwargs))
            stack.enter_context(mock.patch.dict(s.os.environ, {'GITHUB_SHA': COMMIT, 'GITHUB_RUN_ID': '123'}))
            if fault == 'cleanup':
                stack.enter_context(mock.patch.object(s.tempfile, 'TemporaryDirectory', CleanupFailure))
            if fault == 'receipt-cancel':
                stack.enter_context(mock.patch.object(s.base, 'finalize_receipt', side_effect=late_cancel))
            if fault == 'provenance-drift':
                with self.assertRaisesRegex(ValueError, 'provenance-read-drift'):
                    s.controller(args)
                self.assertFalse(public.exists())
                return None
            report = s.run(args) if run_wrapper else s.controller(args)
        self.assertEqual({p.name for p in public.iterdir()}, {'receipt.json'})
        if fault == 'cleanup':
            self.assertTrue(private and all(p.exists() for p in private))
            self.assertEqual(report['controller_tmp_removed'], 'FAIL')
            self.assertTrue(report['private_artifacts_retained'])
            self.assertTrue(json.loads((public / 'receipt.json').read_bytes())['private_artifacts_retained'])
            for actual in created:
                actual.cleanup()
        else:
            self.assertTrue(private and all(not p.exists() for p in private))
            self.assertEqual(report['controller_tmp_removed'], 'PASS')
            self.assertFalse(report['private_artifacts_retained'])
        self.assertFalse(report['published'])
        self.assertTrue(boundary.closed)
        self.assertEqual(report['docker_boundary_closed'], 'PASS')
        encoded = (public / 'receipt.json').read_text()
        self.assertNotIn('private material', encoded)
        self.assertNotIn('fixture lifecycle failure', encoded)
        return report

    def test_controller_retains_only_curated_receipt(self):
        self.assertEqual(self.controller_fixture()['status'], 'PASS')

    def test_controller_failure_removes_private_signing_artifacts(self):
        self.assertEqual(self.controller_fixture('lifecycle')['status'], 'FAIL')

    def test_controller_rejects_unexpected_signing_output(self):
        self.assertEqual(self.controller_fixture('extra-output')['status'], 'FAIL')

    def test_controller_cancellation_cannot_publish_pass(self):
        self.assertEqual(self.controller_fixture('cancel')['status'], 'FAIL')

    def test_controller_rechecks_consumed_provenance_hashes(self):
        self.controller_fixture('provenance-drift')

    def test_controller_cleanup_failure_reports_private_artifacts_retained(self):
        self.assertEqual(self.controller_fixture('cleanup')['status'], 'FAIL')

    def test_controller_fd_disposal_cancellation_cannot_persist_pass(self):
        report = self.controller_fixture('close-cancel')
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(json.loads((Path(self.tmp.name) / 'public/receipt.json').read_bytes())['status'], 'FAIL')

    def test_controller_cancellation_after_real_receipt_writer_rewrites_durable_pass(self):
        report = self.controller_fixture('receipt-cancel')
        saved = json.loads((Path(self.tmp.name) / 'public/receipt.json').read_bytes())
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(saved['status'], 'FAIL')
        self.assertTrue(saved['cancelled'])

    def final_cancellation(self, sig, *, restoration):
        original_public = s.public_receipt
        original_defer = s.base.defer_signals
        original_signal = signal.signal
        state = {'public_returned': False, 'injected': False}
        def public(*args, **kwargs):
            result = original_public(*args, **kwargs)
            state['public_returned'] = True
            return result
        @contextmanager
        def defer():
            with original_defer():
                yield
                if not restoration and state['public_returned'] and not state['injected']:
                    state['injected'] = True
                    os.kill(os.getpid(), sig)  # Real remembered signal after the real fsync.
        def restoring(signal_number, handler):
            result = original_signal(signal_number, handler)
            if restoration and state['public_returned'] and not state['injected'] \
                    and signal_number == sig and handler is s.base.interrupt:
                state['injected'] = True
                os.kill(os.getpid(), sig)  # Real raised Cancelled at final handler restoration.
            return result
        with s.base.cancellation_handlers(), ExitStack() as stack:
            stack.enter_context(mock.patch.object(s, 'public_receipt', side_effect=public))
            stack.enter_context(mock.patch.object(s.base, 'defer_signals', side_effect=defer))
            stack.enter_context(mock.patch.object(s.base.signal, 'signal', side_effect=restoring))
            report = self.controller_fixture()
        saved = json.loads((Path(self.tmp.name) / 'public/receipt.json').read_bytes())
        self.assertTrue(state['injected'])
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(saved['status'], 'FAIL')
        self.assertTrue(saved['cancelled'])
        self.assertEqual(saved['controller_tmp_removed'], 'PASS')
        self.assertEqual(saved['docker_boundary_closed'], 'PASS')
        self.assertFalse(saved['private_artifacts_retained'])

    def test_final_outer_deferral_remembered_sigterm_rewrites_durable_pass(self):
        self.final_cancellation(signal.SIGTERM, restoration=False)

    def test_final_outer_deferral_remembered_sigint_rewrites_durable_pass(self):
        self.final_cancellation(signal.SIGINT, restoration=False)

    def test_final_outer_handler_restore_sigterm_rewrites_durable_pass(self):
        self.final_cancellation(signal.SIGTERM, restoration=True)

    def test_final_outer_handler_restore_sigint_rewrites_durable_pass(self):
        self.final_cancellation(signal.SIGINT, restoration=True)

    def test_run_caller_default_sigint_restoration_rewrites_completed_receipt(self):
        original_signal = signal.signal
        previous = {sig: signal.getsignal(sig) for sig in s.base.SIGNALS}
        original_public = s.public_receipt
        state = {'public_returned': False, 'injected': False}
        def public(*args, **kwargs):
            result = original_public(*args, **kwargs)
            state['public_returned'] = True
            return result
        def restore(sig, handler):
            result = original_signal(sig, handler)
            if state['public_returned'] and not state['injected'] and sig == signal.SIGINT \
                    and handler is signal.default_int_handler:
                state['injected'] = True
                os.kill(os.getpid(), signal.SIGINT)  # Actual caller handler raises KeyboardInterrupt.
            return result
        original_signal(signal.SIGINT, signal.default_int_handler)
        try:
            with mock.patch.object(s, 'public_receipt', side_effect=public), \
                    mock.patch.object(s.base.signal, 'signal', side_effect=restore):
                report = self.controller_fixture(run_wrapper=True)
        finally:
            for sig, handler in previous.items():
                original_signal(sig, handler)
        saved = json.loads((Path(self.tmp.name) / 'public/receipt.json').read_bytes())
        self.assertTrue(state['injected'])
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(saved['status'], 'FAIL')
        self.assertTrue(saved['cancelled'])
        self.assertEqual([row['phase'] for row in saved['phases']], ['sign', 'lifecycle'])
        self.assertEqual(saved['controller_tmp_removed'], 'PASS')
        self.assertEqual(saved['docker_boundary_closed'], 'PASS')
        self.assertFalse(saved['private_artifacts_retained'])

    def test_privileged_or_mismatched_identity_refuses_before_docker_or_inputs(self):
        for uid, euid, gid, egid in ((1000, 0, 1000, 0), (0, 0, 1000, 1000), (1000, 1001, 1000, 1000),
                                    (1000, 1000, 0, 0), (1000, 1000, 1000, 0), (1000, 1000, 1000, 1001)):
            with self.subTest(ids=(uid, euid, gid, egid)), ExitStack() as stack:
                for name, value in (('getuid', uid), ('geteuid', euid), ('getgid', gid), ('getegid', egid)):
                    stack.enter_context(mock.patch.object(s.os, name, return_value=value))
                docker = stack.enter_context(mock.patch.object(s, 'Docker'))
                checked = stack.enter_context(mock.patch.object(s.base, 'checked'))
                with self.assertRaisesRegex(ValueError, 'matching-positive'):
                    s.controller(SimpleNamespace())
                docker.assert_not_called()
                checked.assert_not_called()


if __name__ == '__main__':
    unittest.main()
