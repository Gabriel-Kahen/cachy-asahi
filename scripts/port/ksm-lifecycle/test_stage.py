#!/usr/bin/env python3
"""Controller fixtures: no Docker daemon, native build, install, or host mutation."""
import ast
import copy
from contextlib import ExitStack, contextmanager
import io
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



class StageDiagnosticTests(unittest.TestCase):
    """Closed observations with inert phase collaborators; no daemon or worker."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ksmd-')
        self.addCleanup(self.tmp.cleanup)
        self.source, self.out = [Path(self.tmp.name) / name for name in ('source', 'out')]
        self.source.mkdir(); self.out.mkdir()
        s.diagnostic_start(SimpleNamespace(source_commit=COMMIT, run_id='123'))
        self.addCleanup(setattr, s, '_DIAGNOSTIC', None)
        s.base.CANCELLED = False
        self.addCleanup(setattr, s.base, 'CANCELLED', False)

    def phase(self, *, phase='sign', code=0, worker=True, invalid_id=False,
              cleanup=False, cancel=False, attach_error=None, contract_error=False, cleanup_cancel=False):
        c = contract(phase)
        obj = inspected(c, self.source, self.out)
        report = {'phases': []}
        def success(argv, **kwargs):
            if argv[2:4] == ['container', 'ls']:
                return b''
            if argv[2] == 'create':
                return b'invalid' if invalid_id else CID.encode()
            if argv[2] == 'inspect':
                return json.dumps([obj]).encode()
            raise AssertionError(argv)
        def bounded(argv, **kwargs):
            if argv[2] == 'start':
                if cancel:
                    s.base.CANCELLED = True
                    raise KeyboardInterrupt('PRIVATE_CANCEL_SENTINEL')
                if attach_error is not None:
                    raise attach_error
                if worker:
                    (self.out / 'worker-receipt.json').write_text(json.dumps(receipt(c)))
                return code, b'PRIVATE_ATTACH_SENTINEL'
            if argv[2] == 'inspect':
                return 0, json.dumps([obj]).encode()
            raise AssertionError(argv)
        def remove(*args):
            if cleanup_cancel:
                raise KeyboardInterrupt('PRIVATE_CLEANUP_CANCEL_SENTINEL')
            if cleanup:
                s.need(False, 'owned-container-absence-unconfirmed')
        docker = SimpleNamespace(endpoint=ENDPOINT, expected='local-daemon', successful=success,
                                 bounded=bounded, remove=remove, absent=mock.Mock())
        with ExitStack() as stack:
            if contract_error:
                stack.enter_context(mock.patch.object(s.os, 'open', side_effect=PermissionError('PRIVATE_PATH_SENTINEL')))
            try:
                s.phase_run(ENDPOINT, 'local-daemon', IMAGE, self.source, self.out, c, report, docker=docker)
            except (ValueError, OSError, KeyboardInterrupt) as error:
                return report, error
        return report, None

    def record(self):
        stream = io.StringIO()
        with mock.patch.object(s.sys, 'stdout', stream):
            s.diagnostic_emit()
            s.diagnostic_emit()
        lines = stream.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith(s.DIAGNOSTIC_PREFIX))
        self.assertLessEqual(len(stream.getvalue().encode()), s.DIAGNOSTIC_MAX_BYTES)
        for sentinel in ('PRIVATE_', 'worker-receipt.json', 'Traceback'):
            self.assertNotIn(sentinel, stream.getvalue())
        record = json.loads(lines[0][len(s.DIAGNOSTIC_PREFIX):])
        self.assertEqual(set(record), {'schema_version', 'source_commit', 'run_id', 'first_failure',
                                      'cleanup_failure', 'cancelled', 'attach_return'})
        self.assertEqual((record['source_commit'], record['run_id']), (COMMIT, '123'))
        return record

    def test_source_check_provenance_and_foreign_messages(self):
        for factory, expected in ((lambda: ValueError('worker-phase-failed'), 'UNKNOWN'),
                                  (lambda: KeyError('PRIVATE_PATH_SENTINEL'), 'UNKNOWN')):
            with self.subTest(expected=expected):
                s.diagnostic_start(SimpleNamespace(source_commit=COMMIT, run_id='123'))
                s.diagnostic_site('WORKER_RESULT', 'SIGN')
                s.diagnostic_failure(factory())
                self.assertEqual(s._DIAGNOSTIC['first_failure']['check'], expected)
        s.diagnostic_start(SimpleNamespace(source_commit=COMMIT, run_id='123'))
        try:
            s.need(False, 'worker-phase-failed')
        except ValueError as error:
            self.assertIs(type(error), ValueError)
            self.assertEqual(error.args, ('worker-phase-failed',))
            s.diagnostic_failure(error)
        self.assertEqual(self.record()['first_failure']['check'], 'worker-phase-failed')

    def test_forged_provenance_subclass_and_unknown_check_are_not_exported(self):
        class Foreign(ValueError):
            pass
        for error in (ValueError('PRIVATE_ERROR_SENTINEL'), Foreign('worker-phase-failed')):
            error._ksm_check = (object(), 'worker-phase-failed')
            s.diagnostic_start(SimpleNamespace(source_commit=COMMIT, run_id='123'))
            s.diagnostic_failure(error)
            self.assertEqual(s._DIAGNOSTIC['first_failure']['check'], 'UNKNOWN')
        s.diagnostic_start(SimpleNamespace(source_commit=COMMIT, run_id='123'))
        try:
            s.need(False, 'PRIVATE_UNKNOWN_CHECK_SENTINEL')
        except ValueError as error:
            s.diagnostic_failure(error)
        self.assertEqual(self.record()['first_failure']['check'], 'UNKNOWN')

    def test_first_source_failure_survives_cleanup_and_generic_mask(self):
        report, error = self.phase(invalid_id=True, cleanup=True)
        self.assertEqual(str(error), 'phase-or-cleanup-failed')  # Existing exception policy holds.
        self.assertEqual(report['phases'][0]['container_cleanup'], 'FAIL')
        record = self.record()
        self.assertEqual(record['first_failure'], {'selector': 'SIGN', 'site': 'CREATED_ID',
                         'check': 'invalid-created-container-id', 'category': 'VALUE_ERROR'})
        self.assertEqual(record['cleanup_failure'], {'selector': 'SIGN', 'site': 'CLEANUP_REMOVE',
                         'check': 'owned-container-absence-unconfirmed', 'category': 'VALUE_ERROR'})
        self.assertEqual(record['attach_return'], {'SIGN': None, 'LIFECYCLE': None})

    def test_return_zero_with_missing_receipt_is_observed_without_acceptance(self):
        report, error = self.phase(worker=False)
        self.assertEqual(str(error), 'phase-or-cleanup-failed')
        self.assertNotIn('worker', report['phases'][0])
        self.assertEqual(report['phases'][0]['status'], 'FAIL')
        record = self.record()
        self.assertEqual(record['attach_return']['SIGN'], 0)
        self.assertEqual(record['first_failure'], {'selector': 'SIGN', 'site': 'RECEIPT_READ',
                                                  'check': 'UNKNOWN', 'category': 'OS_ERROR'})
        self.assertIsNone(record['cleanup_failure'])

    def test_nonzero_return_with_missing_receipt_is_not_worker_result(self):
        _, error = self.phase(phase='lifecycle', code=17, worker=False)
        self.assertIsInstance(error, ValueError)
        record = self.record()
        self.assertEqual(record['attach_return'], {'SIGN': None, 'LIFECYCLE': 17})
        self.assertEqual(record['first_failure']['site'], 'RECEIPT_READ')
        self.assertEqual(record['first_failure']['check'], 'UNKNOWN')

    def test_nonzero_observed_return_keeps_bound_worker_guard_distinct(self):
        report, error = self.phase(code=17)
        self.assertEqual(str(error), 'phase-or-cleanup-failed')
        self.assertEqual(report['phases'][0]['worker']['status'], 'PASS')
        record = self.record()
        self.assertEqual(record['attach_return']['SIGN'], 17)
        self.assertEqual(record['first_failure']['check'], 'worker-phase-failed')
        self.assertEqual(record['first_failure']['site'], 'WORKER_RESULT')

    def test_attach_exception_has_no_return_or_invented_check(self):
        self.phase(attach_error=ValueError('PRIVATE_ATTACH_ERROR_SENTINEL'))
        record = self.record()
        self.assertEqual(record['attach_return'], {'SIGN': None, 'LIFECYCLE': None})
        self.assertEqual(record['first_failure']['site'], 'ATTACH')
        self.assertEqual(record['first_failure']['check'], 'UNKNOWN')

    def test_cancellation_is_sticky_separate_and_preserves_cleanup(self):
        report, error = self.phase(cancel=True, cleanup=True)
        self.assertEqual(str(error), 'phase-or-cleanup-failed')
        self.assertEqual(report['phases'][0]['status'], 'FAIL')
        s.base.CANCELLED = False  # Observation cannot be erased by subsequent state.
        record = self.record()
        self.assertTrue(record['cancelled'])
        self.assertEqual(record['first_failure']['category'], 'KEYBOARD_INTERRUPT')
        self.assertEqual(record['first_failure']['site'], 'ATTACH')
        self.assertEqual(record['cleanup_failure']['site'], 'CLEANUP_REMOVE')
        self.assertIsNone(record['attach_return']['SIGN'])

    def test_success_and_contract_mode_remain_unchanged(self):
        report, error = self.phase(phase='lifecycle')
        self.assertIsNone(error)
        self.assertEqual(report['phases'][0]['status'], 'PASS')
        self.assertEqual((self.source / 'inputs.json').stat().st_mode & 0o777, 0o644)
        self.assertEqual(set(report), {'phases'})
        self.assertEqual(set(report['phases'][0]), {'phase', 'status', 'container_cleanup',
                         'attach_bytes', 'attach_sha256', 'worker', 'container_state'})
        record = self.record()
        self.assertIsNone(record['first_failure'])
        self.assertIsNone(record['cleanup_failure'])
        self.assertFalse(record['cancelled'])
        self.assertEqual(record['attach_return'], {'SIGN': None, 'LIFECYCLE': 0})

    def test_contract_write_site_precedes_phase_cleanup_try(self):
        report, error = self.phase(contract_error=True)
        self.assertIsInstance(error, PermissionError)
        self.assertEqual(report['phases'], [])
        # Outer handler observes the escaping exception at the retained phase site.
        s.diagnostic_failure(error)
        record = self.record()
        self.assertEqual(record['first_failure']['selector'], 'SIGN')
        self.assertEqual(record['first_failure']['site'], 'CONTRACT_WRITE')
        self.assertIsNone(record['cleanup_failure'])

    def test_transport_first_error_survives_existing_identity_finally_mask(self):
        s.diagnostic_site('ATTACH', 'SIGN')
        calls = []
        def files():
            calls.append('checked')
            if len(calls) == 2:
                s.need(False, 'docker-cli-read-drift')
        boundary = SimpleNamespace(endpoint=ENDPOINT, executable='inert-fixture', check_files=files)
        with mock.patch.object(s.base, 'bounded', side_effect=ValueError('PRIVATE_TRANSPORT_SENTINEL')):
            with self.assertRaisesRegex(ValueError, 'docker-cli-read-drift'):
                s.Docker.raw(boundary, s.base.docker_command(ENDPOINT, 'start', '--attach', CID))
        record = self.record()
        self.assertEqual(record['first_failure'], {'selector': 'SIGN', 'site': 'ATTACH',
                                                  'check': 'UNKNOWN', 'category': 'VALUE_ERROR'})
        self.assertIsNone(record['cleanup_failure'])
        self.assertIsNone(record['attach_return']['SIGN'])

    def test_command_first_error_survives_existing_daemon_identity_finally_mask(self):
        s.diagnostic_site('ATTACH', 'LIFECYCLE')
        calls = []
        def identity():
            calls.append('identity')
            if len(calls) == 2:
                s.need(False, 'local-daemon-identity-drift')
        boundary = SimpleNamespace(identity=identity, raw=mock.Mock(side_effect=OSError('PRIVATE_COMMAND_SENTINEL')))
        with self.assertRaisesRegex(ValueError, 'local-daemon-identity-drift'):
            s.Docker.bounded(boundary, ['inert-fixture'])
        record = self.record()
        self.assertEqual(record['first_failure'], {'selector': 'LIFECYCLE', 'site': 'ATTACH',
                                                  'check': 'UNKNOWN', 'category': 'OS_ERROR'})
        self.assertIsNone(record['cleanup_failure'])
        self.assertIsNone(record['attach_return']['LIFECYCLE'])

    def test_return_type_and_bounds_are_closed(self):
        for code in (True, False, -129, 256, '17', None):
            s.diagnostic_site('ATTACH', 'SIGN')
            s.diagnostic_attach_return(code)
            self.assertIsNone(s._DIAGNOSTIC['attach_return']['SIGN'])
        for code in (-128, 0, 255):
            s.diagnostic_attach_return(code)
            self.assertIs(type(s._DIAGNOSTIC['attach_return']['SIGN']), int)
            self.assertEqual(s._DIAGNOSTIC['attach_return']['SIGN'], code)

    def test_inactive_and_invalid_binding_emit_nothing(self):
        for commit, run in ((COMMIT, '../private'), ('PRIVATE_SOURCE_SENTINEL', '123'),
                            (COMMIT, '1' * 21), (COMMIT, 123)):
            s.diagnostic_start(SimpleNamespace(source_commit=commit, run_id=run))
            s.diagnostic_site('ATTACH', 'SIGN')
            s.diagnostic_failure(ValueError('PRIVATE_ERROR_SENTINEL'))
            s.diagnostic_attach_return(0)
            with mock.patch.object(s.sys, 'stdout', io.StringIO()) as stream:
                s.diagnostic_emit()
            self.assertEqual(stream.getvalue(), '')
        self.assertIsNone(s._DIAGNOSTIC)

    def cli_argv(self):
        options = ('image', 'daemon-id', 'docker-endpoint', 'docker-sha256', 'docker-socket-device',
                   'docker-socket-inode', 'source-commit', 'run-id', 'runner', 'runner-sha256', 'bootstrap',
                   'bootstrap-sha256', 'packages', 'current-inputs', 'source', 'stage-sha256', 'worker-sha256',
                   'contract-source-sha256', 'approved-inputs', 'build-1', 'build-1-provenance-sha256',
                   'build-2', 'build-2-provenance-sha256', 'output')
        argv = ['stage.py']
        for option in options:
            argv += ['--' + option, COMMIT if option == 'source-commit' else '123' if option == 'run-id' else 'fixture']
        return argv

    def test_main_emits_once_for_success_and_caught_refusal(self):
        argv = self.cli_argv()
        for refused in (False, True):
            with self.subTest(refused=refused), ExitStack() as stack:
                stack.enter_context(mock.patch.object(s.sys, 'argv', argv))
                out = stack.enter_context(mock.patch.object(s.sys, 'stdout', io.StringIO()))
                err = stack.enter_context(mock.patch.object(s.sys, 'stderr', io.StringIO()))
                def run(args):
                    s.diagnostic_site('PLATFORM', 'CONTROLLER')
                    if refused:
                        s.need(False, 'native-nonroot-coordinator-required')
                    return {'status': 'PASS', 'phases': []}
                stack.enter_context(mock.patch.object(s, 'run', side_effect=run))
                self.assertEqual(s.main(), int(refused))
                lines = [line for line in out.getvalue().splitlines() if line.startswith(s.DIAGNOSTIC_PREFIX)]
                self.assertEqual(len(lines), 1)
                record = json.loads(lines[0][len(s.DIAGNOSTIC_PREFIX):])
                self.assertEqual(record['source_commit'], COMMIT)
                self.assertEqual(record['first_failure'] is not None, refused)
                self.assertNotIn('PRIVATE_', out.getvalue() + err.getvalue())

    def test_main_best_effort_emission_preserves_success_or_primary_refusal(self):
        original_dumps = s.json.dumps
        for refused in (False, True):
            for broken in ('stream', 'encoder'):
                with self.subTest(refused=refused, broken=broken), ExitStack() as stack:
                    stack.enter_context(mock.patch.object(s.sys, 'argv', self.cli_argv()))
                    out = io.StringIO()
                    class BrokenDiagnosticStream:
                        def write(self, data):
                            if data.startswith(s.DIAGNOSTIC_PREFIX):
                                raise OSError('PRIVATE_STREAM_SENTINEL')
                            return out.write(data)
                        def flush(self):
                            return None
                    stack.enter_context(mock.patch.object(s.sys, 'stdout', BrokenDiagnosticStream()))
                    stack.enter_context(mock.patch.object(s.sys, 'stderr', io.StringIO()))
                    def encode(value, *args, **kwargs):
                        if broken == 'encoder' and 'attach_return' in value:
                            raise ValueError('PRIVATE_JSON_SENTINEL')
                        return original_dumps(value, *args, **kwargs)
                    stack.enter_context(mock.patch.object(s.json, 'dumps', side_effect=encode))
                    def run(args):
                        s.diagnostic_site('PLATFORM', 'CONTROLLER')
                        if refused:
                            s.need(False, 'native-nonroot-coordinator-required')
                        return {'status': 'PASS', 'phases': []}
                    stack.enter_context(mock.patch.object(s, 'run', side_effect=run))
                    self.assertEqual(s.main(), int(refused))
                    if refused:
                        self.assertEqual(s._DIAGNOSTIC['first_failure']['check'],
                                         'native-nonroot-coordinator-required')
                    else:
                        self.assertIsNone(s._DIAGNOSTIC['first_failure'])
                    self.assertNotIn('PRIVATE_', out.getvalue())

    def test_emit_ordinary_write_error_preserves_primary_and_never_retries(self):
        s.diagnostic_site('ATTACH', 'SIGN')
        s.diagnostic_failure(ValueError('PRIVATE_ORIGINAL_SENTINEL'))
        first = s._DIAGNOSTIC['first_failure'].copy()
        with mock.patch('builtins.print', side_effect=OSError('PRIVATE_STREAM_SENTINEL')) as writer:
            s.diagnostic_emit()
            s.diagnostic_emit()
        self.assertEqual(writer.call_count, 1)
        self.assertEqual(s._DIAGNOSTIC['first_failure'], first)

    def test_emit_serialization_error_preserves_primary_and_never_retries(self):
        s.diagnostic_site('ATTACH', 'LIFECYCLE')
        s.diagnostic_failure(ValueError('PRIVATE_ORIGINAL_SENTINEL'))
        first = s._DIAGNOSTIC['first_failure'].copy()
        with mock.patch.object(s.json, 'dumps', side_effect=ValueError('PRIVATE_JSON_SENTINEL')) as encoder, \
                mock.patch('builtins.print') as writer:
            s.diagnostic_emit()
            s.diagnostic_emit()
        self.assertEqual(encoder.call_count, 1)
        writer.assert_not_called()
        self.assertEqual(s._DIAGNOSTIC['first_failure'], first)

    def test_emit_cancellation_is_never_swallowed_or_retried(self):
        with mock.patch('builtins.print', side_effect=KeyboardInterrupt()) as writer:
            with self.assertRaises(KeyboardInterrupt):
                s.diagnostic_emit()
            s.diagnostic_emit()
        self.assertEqual(writer.call_count, 1)

    def test_cleanup_cancellation_preserves_first_error_and_propagates(self):
        report, error = self.phase(invalid_id=True, cleanup_cancel=True)
        self.assertIsInstance(error, KeyboardInterrupt)
        self.assertEqual(report['phases'][0]['container_cleanup'], 'FAIL')
        record = self.record()
        self.assertEqual(record['first_failure']['check'], 'invalid-created-container-id')
        self.assertEqual(record['cleanup_failure']['category'], 'KEYBOARD_INTERRUPT')
        self.assertEqual(record['cleanup_failure']['site'], 'CLEANUP_REMOVE')
        self.assertTrue(record['cancelled'])

    def test_cleanup_only_failure_remains_separate_from_worker_pass(self):
        report, error = self.phase(cleanup=True)
        self.assertEqual(str(error), 'phase-or-cleanup-failed')
        self.assertEqual(report['phases'][0]['worker']['status'], 'PASS')
        self.assertEqual(report['phases'][0]['status'], 'FAIL')
        record = self.record()
        self.assertEqual(record['first_failure'], record['cleanup_failure'])
        self.assertEqual(record['cleanup_failure']['check'], 'owned-container-absence-unconfirmed')
        self.assertEqual(record['attach_return']['SIGN'], 0)



_BASE_CONTROLLER_SOURCE = "def controller(args):\n    uid, gid = coordinator_identity()\n    need(platform.system() == 'Linux' and platform.machine() in {'aarch64', 'arm64'},\n         'native-nonroot-coordinator-required')\n    need(re.fullmatch(r'[0-9a-f]{40}', args.source_commit) and re.fullmatch(r'[0-9]{1,20}', args.run_id)\n         and os.environ.get('GITHUB_SHA') == args.source_commit and os.environ.get('GITHUB_RUN_ID') == args.run_id,\n         'genuine-same-job-source-required')\n    need(re.fullmatch(r'sha256:[0-9a-f]{64}', args.image), 'immutable-image-required')\n    docker = Docker(args.docker_endpoint, args.daemon_id, args.docker_sha256,\n                    args.docker_socket_device, args.docker_socket_inode)\n    try:\n        return controller_inputs(args, docker, uid, gid)\n    finally:\n        if not docker.closed:\n            with base.defer_signals():\n                docker.close()"
_BLOCKED_DIAGNOSTIC_FAILURE_SOURCE = 'def diagnostic_failure(error, *, cleanup=False):\n    """Never serialize an exception message, operands, or foreign check text."""\n    if _DIAGNOSTIC is None:\n        return\n    kind = type(error)\n    category = \'UNKNOWN\'\n    if isinstance(error, base.Cancelled):\n        category = \'CANCELLED\'\n    elif isinstance(error, KeyboardInterrupt):\n        category = \'KEYBOARD_INTERRUPT\'\n    elif kind is ValueError:\n        category = \'VALUE_ERROR\'\n    elif isinstance(error, OSError):\n        category = \'OS_ERROR\'\n    elif kind is KeyError:\n        category = \'KEY_ERROR\'\n    elif kind is TypeError:\n        category = \'TYPE_ERROR\'\n    elif isinstance(error, subprocess.SubprocessError):\n        category = \'SUBPROCESS_ERROR\'\n    if category in {\'CANCELLED\', \'KEYBOARD_INTERRUPT\'} or base.CANCELLED:\n        _DIAGNOSTIC[\'cancelled\'] = True\n    check = \'UNKNOWN\'\n    if kind is ValueError:\n        provenance = error.__dict__.get(\'_ksm_check\')\n        if type(provenance) is tuple and len(provenance) == 2 and provenance[0] is _CHECK_PROVENANCE \\\n                and type(provenance[1]) is str and provenance[1] in DIAGNOSTIC_CHECKS:\n            check = provenance[1]\n    row = {\'selector\': _DIAGNOSTIC[\'_selector\'], \'site\': _DIAGNOSTIC[\'_site\'],\n           \'check\': check, \'category\': category}\n    if _DIAGNOSTIC[\'first_failure\'] is None:\n        _DIAGNOSTIC[\'first_failure\'] = row\n    cleanup = cleanup or _DIAGNOSTIC[\'_site\'] in {\n        \'CLEANUP_INSPECT\', \'CLEANUP_OWNERSHIP\', \'CLEANUP_REMOVE\', \'CLEANUP_ABSENCE\',\n        \'PRIVATE_CLEANUP\', \'DOCKER_CLOSE\'}\n    if cleanup and _DIAGNOSTIC[\'cleanup_failure\'] is None:\n        _DIAGNOSTIC[\'cleanup_failure\'] = row.copy()'

class StageDiagnosticPreservationTests(unittest.TestCase):
    """Complete-controller AST pairs with inert constructor/body/close callbacks."""
    def original(self, error):
        try:
            raise error
        except BaseException:
            pass
        for name, value in (('__cause__', RuntimeError('PRIVATE_CAUSE_SENTINEL')),
                            ('__context__', RuntimeError('PRIVATE_CONTEXT_SENTINEL')),
                            ('__suppress_context__', True)):
            BaseException.__dict__[name].__set__(error, value)
        return error

    def fields(self, error):
        return {name: BaseException.__dict__[name].__get__(error) for name in
                ('args', '__cause__', '__context__', '__traceback__', '__suppress_context__')}

    def controller_pair(self, primary, *, variant='corrected', setup=None, close_error=None):
        tree = ast.parse(Path(s.__file__).read_bytes())
        names = {'need', 'coordinator_identity', 'controller', 'diagnostic_start', 'diagnostic_site', 'diagnostic_failure'}
        assignments = {'DIAGNOSTIC_SELECTORS', 'DIAGNOSTIC_SITES', 'DIAGNOSTIC_CHECKS', '_CHECK_PROVENANCE', '_DIAGNOSTIC'}
        selected = [node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name in names
                    or isinstance(node, ast.Assign) and len(node.targets) == 1
                    and isinstance(node.targets[0], ast.Name) and node.targets[0].id in assignments]
        if variant in {'base', 'blocked'}:
            replacement = ast.parse(_BASE_CONTROLLER_SOURCE if variant == 'base' else
                                    _BLOCKED_DIAGNOSTIC_FAILURE_SOURCE).body[0]
            selected = [replacement if isinstance(node, ast.FunctionDef) and node.name == replacement.name else node
                        for node in selected]
        events = []
        @contextmanager
        def deferred():
            events.append('defer-enter')
            try:
                yield
            finally:
                events.append('defer-exit')
        base = SimpleNamespace(Cancelled=s.base.Cancelled, CANCELLED=False, defer_signals=deferred)
        ns = {'base': base, 're': s.re, 'subprocess': subprocess,
              'platform': SimpleNamespace(system=lambda: 'Linux', machine=lambda: 'aarch64'),
              'os': SimpleNamespace(getuid=lambda: 1000, geteuid=lambda: 1000,
                                    getgid=lambda: 1000, getegid=lambda: 1000,
                                    environ={'GITHUB_SHA': COMMIT, 'GITHUB_RUN_ID': '123'})}
        exec(compile(ast.Module(body=selected, type_ignores=[]), 'inert-complete-stage-controller', 'exec'), ns)
        observed = {}
        class InertDocker:
            closed = False
            def close(self):
                events.append('close')
                self.closed = True
                if close_error is not None:
                    raise close_error
        docker = InertDocker()
        def constructor(*args):
            events.append('constructor')
            return docker
        def body(*args):
            events.append('body')
            try:
                raise primary
            except BaseException:
                observed.update(self.fields(primary))
                raise
        ns.update(Docker=constructor, controller_inputs=body)
        args = SimpleNamespace(source_commit=COMMIT, run_id='123', image=IMAGE, docker_endpoint='fixture',
                               daemon_id='fixture', docker_sha256='fixture', docker_socket_device=1,
                               docker_socket_inode=1)
        ns['diagnostic_start'](args)
        if setup is not None:
            setup(ns, primary)
        escaped = None
        try:
            ns['controller'](args)
        except BaseException as error:
            escaped = error
        self.assertEqual(events, ['constructor', 'body', 'defer-enter', 'close', 'defer-exit'])
        self.assertTrue(docker.closed)
        self.assertIs(base.CANCELLED, False)  # Optional collection cannot alter operative signal state.
        return ns, escaped, observed

    def preserved(self, primary, escaped, before):
        self.assertIs(escaped, primary)
        after = self.fields(primary)
        for name in ('args', '__cause__', '__context__', '__suppress_context__'):
            self.assertIs(after[name], before[name])
        chain = []
        trace = after['__traceback__']
        while trace is not None:
            chain.append(trace)
            trace = trace.tb_next
        self.assertTrue(any(trace is before['__traceback__'] for trace in chain))
        self.assertEqual([trace.tb_frame.f_code.co_name for trace in chain[:3]],
                         ['controller_pair', 'controller', 'body'])
        self.assertIs(chain[2], before['__traceback__'])

    def test_two_sealed_countermodels_reproduce_and_correct_in_complete_controller(self):
        class HostileOSError(OSError):
            @property
            def __class__(self):
                raise LookupError('PRIVATE_CLASS_SENTINEL')
        class HostileDict(dict):
            def get(self, *args):
                raise LookupError('PRIVATE_DICT_SENTINEL')
        for kind in ('class', 'dictionary'):
            for variant in ('base', 'blocked', 'corrected'):
                with self.subTest(kind=kind, variant=variant):
                    primary = self.original(HostileOSError('PRIMARY') if kind == 'class' else ValueError('PRIMARY'))
                    if kind == 'dictionary':
                        primary.__dict__ = HostileDict()
                    ns, escaped, before = self.controller_pair(primary, variant=variant)
                    if variant == 'blocked':
                        self.assertIs(type(escaped), LookupError)
                        self.assertIsNot(escaped, primary)
                    else:
                        self.preserved(primary, escaped, before)
                    if variant == 'corrected':
                        self.assertEqual(ns['_DIAGNOSTIC']['first_failure']['check'], 'UNKNOWN')
                        self.assertEqual(ns['_DIAGNOSTIC']['first_failure']['category'],
                                         'OS_ERROR' if kind == 'class' else 'VALUE_ERROR')

    def test_exact_dictionary_foreign_collision_key_is_never_compared(self):
        events = []
        class Collision:
            def __hash__(self):
                return hash('_ksm_check')
            def __eq__(self, other):
                events.append('foreign-equality')
                raise LookupError('PRIVATE_COLLISION_SENTINEL')
        primary = self.original(ValueError('PRIMARY'))
        primary.__dict__[Collision()] = 'PRIVATE_VALUE_SENTINEL'
        ns, escaped, before = self.controller_pair(primary)
        self.preserved(primary, escaped, before)
        self.assertEqual(events, [])
        self.assertEqual(ns['_DIAGNOSTIC']['first_failure']['check'], 'UNKNOWN')

    def test_actual_lineage_bypasses_class_spoof_and_all_metaclass_hooks(self):
        events = []
        class HostileMeta(type):
            def __getattribute__(cls, name):
                if name == '__mro__':
                    events.append('meta-attribute')
                    raise LookupError('PRIVATE_META_ATTRIBUTE')
                return super().__getattribute__(name)
            @property
            def __mro__(cls):
                events.append('meta-property')
                raise LookupError('PRIVATE_META_PROPERTY')
            def __eq__(cls, other):
                events.append('meta-equality')
                raise LookupError('PRIVATE_META_EQUALITY')
        class Foreign(OSError, metaclass=HostileMeta):
            @property
            def __class__(self):
                events.append('class-spoof')
                return KeyboardInterrupt
        primary = self.original(Foreign('PRIMARY'))
        events.clear()
        with self.assertRaises(LookupError):
            type.__getattribute__(type(primary), '__mro__')
        self.assertEqual(events, ['meta-property'])
        events.clear()
        ns, escaped, before = self.controller_pair(primary)
        self.preserved(primary, escaped, before)
        self.assertEqual(events, [])
        self.assertEqual(ns['_DIAGNOSTIC']['first_failure']['category'], 'OS_ERROR')
        self.assertIs(ns['_DIAGNOSTIC']['cancelled'], False)

    def test_collector_does_not_call_foreign_metaclass_subclasscheck(self):
        events = []
        class HostileMeta(type):
            def __subclasscheck__(cls, child):
                events.append('meta-subclass')
                raise LookupError('PRIVATE_META_SUBCLASS')
        class Foreign(OSError, metaclass=HostileMeta):
            pass
        primary = Foreign('PRIMARY')  # Raising it itself invokes interpreter subclass normalization.
        with mock.patch.object(s, '_DIAGNOSTIC', None):
            s.diagnostic_start(SimpleNamespace(source_commit=COMMIT, run_id='123'))
            s.diagnostic_failure(primary)
            self.assertEqual(s._DIAGNOSTIC['first_failure']['category'], 'OS_ERROR')
        self.assertEqual(events, [])

    def test_genuine_original_cancellation_subclasses_are_sticky_without_class_lookup(self):
        events = []
        class Genuine(s.base.Cancelled):
            @property
            def __class__(self):
                events.append('class-property')
                raise LookupError('PRIVATE_CANCELLATION_CLASS')
        primary = self.original(Genuine('PRIMARY'))
        ns, escaped, before = self.controller_pair(primary)
        self.preserved(primary, escaped, before)
        self.assertEqual(events, [])
        self.assertEqual(ns['_DIAGNOSTIC']['first_failure']['category'], 'CANCELLED')
        self.assertIs(ns['_DIAGNOSTIC']['cancelled'], True)

    def test_secondary_baseexceptions_are_contained_with_independent_sticky_observation(self):
        class Secondary(BaseException):
            @property
            def __class__(self):
                raise LookupError('PRIVATE_SECONDARY_CLASS')
        class CancelledSecondary(KeyboardInterrupt):
            @property
            def __class__(self):
                raise LookupError('PRIVATE_SECONDARY_CANCEL_CLASS')
        for secondary in (LookupError('PRIVATE_SECONDARY'), Secondary('PRIVATE_SECONDARY'),
                          CancelledSecondary('PRIVATE_SECONDARY'), s.base.Cancelled('PRIVATE_SECONDARY')):
            with self.subTest(kind=type.__dict__['__name__'].__get__(type(secondary))):
                primary = self.original(ValueError('PRIMARY'))
                def setup(ns, original):
                    original.__dict__['_ksm_check'] = (ns['_CHECK_PROVENANCE'], 'worker-phase-failed')
                    class ThrowingChecks:
                        def __contains__(self, value):
                            raise secondary
                    ns['DIAGNOSTIC_CHECKS'] = ThrowingChecks()
                ns, escaped, before = self.controller_pair(primary, setup=setup)
                self.preserved(primary, escaped, before)
                self.assertIsNone(ns['_DIAGNOSTIC']['first_failure'])
                self.assertIs(ns['_DIAGNOSTIC']['cancelled'], any(parent is KeyboardInterrupt
                              for parent in type.__dict__['__mro__'].__get__(type(secondary))))

    def test_same_primary_collection_fault_restores_traceback_args_cause_context(self):
        primary = self.original(ValueError('PRIMARY'))
        def setup(ns, original):
            original.__dict__['_ksm_check'] = (ns['_CHECK_PROVENANCE'], 'worker-phase-failed')
            class ThrowingChecks:
                def __contains__(self, value):
                    original.args = ('PRIVATE_MUTATION_SENTINEL',)
                    original.__cause__ = RuntimeError('PRIVATE_MUTATED_CAUSE')
                    original.__context__ = RuntimeError('PRIVATE_MUTATED_CONTEXT')
                    original.__suppress_context__ = False
                    raise original
            ns['DIAGNOSTIC_CHECKS'] = ThrowingChecks()
        ns, escaped, before = self.controller_pair(primary, setup=setup)
        self.preserved(primary, escaped, before)
        self.assertIsNone(ns['_DIAGNOSTIC']['first_failure'])

    def test_source_provenance_still_accepts_only_exact_dictionary_and_tuple(self):
        def valid(ns, original):
            original.__dict__['_ksm_check'] = (ns['_CHECK_PROVENANCE'], 'worker-phase-failed')
        primary = self.original(ValueError('PRIMARY'))
        ns, escaped, before = self.controller_pair(primary, setup=valid)
        self.preserved(primary, escaped, before)
        self.assertEqual(ns['_DIAGNOSTIC']['first_failure']['check'], 'worker-phase-failed')
        class ForeignTuple(tuple):
            def __len__(self):
                raise LookupError('PRIVATE_TUPLE_LEN')
        def foreign(ns, original):
            original.__dict__['_ksm_check'] = ForeignTuple((ns['_CHECK_PROVENANCE'], 'worker-phase-failed'))
        primary = self.original(ValueError('PRIMARY'))
        ns, escaped, before = self.controller_pair(primary, setup=foreign)
        self.preserved(primary, escaped, before)
        self.assertEqual(ns['_DIAGNOSTIC']['first_failure']['check'], 'UNKNOWN')

    def test_existing_cleanup_error_precedence_and_first_diagnostic_remain_separate(self):
        for variant in ('base', 'corrected'):
            primary = self.original(OSError('PRIMARY'))
            cleanup = RuntimeError('PRIVATE_CLEANUP_SENTINEL')
            ns, escaped, before = self.controller_pair(primary, variant=variant, close_error=cleanup)
            self.assertIs(escaped, cleanup)
            self.assertIs(self.fields(cleanup)['__context__'], primary)
            if variant == 'corrected':
                self.assertEqual(ns['_DIAGNOSTIC']['first_failure']['category'], 'OS_ERROR')
                self.assertEqual(ns['_DIAGNOSTIC']['cleanup_failure']['site'], 'DOCKER_CLOSE')

    def test_foreign_exact_dictionary_keys_are_rejected_before_lookup_or_write(self):
        events = []
        class Collision:
            def __hash__(self):
                return hash('_selector')
            def __eq__(self, other):
                events.append('foreign-state-equality')
                raise LookupError('PRIVATE_STATE_COLLISION')
        primary = self.original(OSError('PRIMARY'))
        before = self.fields(primary)
        with mock.patch.object(s, '_DIAGNOSTIC', {Collision(): 'PRIVATE_VALUE_SENTINEL'}):
            s.diagnostic_failure(primary)
        after = self.fields(primary)
        self.assertTrue(all(after[name] is before[name] for name in before))
        self.assertEqual(events, [])

    def test_foreign_diagnostic_dictionary_is_not_called(self):
        events = []
        class ForeignState(dict):
            def __getitem__(self, key):
                events.append('get')
                raise LookupError('PRIVATE_STATE_SENTINEL')
            def __setitem__(self, key, value):
                events.append('set')
                raise LookupError('PRIVATE_STATE_SENTINEL')
        primary = self.original(OSError('PRIMARY'))
        before = self.fields(primary)
        with mock.patch.object(s, '_DIAGNOSTIC', ForeignState()):
            s.diagnostic_failure(primary)
        after = self.fields(primary)
        self.assertTrue(all(after[name] is before[name] for name in before))
        self.assertEqual(events, [])


class IsolationSelectorTests(unittest.TestCase):
    """Memory-only isolation predicates; no constructor, process or daemon call."""
    CASES = (
        ('Config', 'User', 'other', 'user'),
        ('HostConfig', 'ReadonlyRootfs', None, 'readonly-rootfs'),
        ('HostConfig', 'NetworkMode', 'host', 'network-mode'),
        ('HostConfig', 'IpcMode', 'host', 'ipc-mode'),
        ('HostConfig', 'PidMode', 'host', 'pid-mode'),
        ('HostConfig', 'UTSMode', 'host', 'uts-mode'),
        ('HostConfig', 'Privileged', True, 'privileged'),
        ('HostConfig', 'CapDrop', [], 'cap-drop'),
        ('HostConfig', 'CapAdd', ['SYS_ADMIN'], 'cap-add'),
        ('HostConfig', 'SecurityOpt', ['seccomp=unconfined'], 'security-opt'),
        ('HostConfig', 'Memory', 1, 'memory-and-swap'),
        ('HostConfig', 'NanoCpus', 1, 'nano-cpus'),
        ('HostConfig', 'PidsLimit', 1, 'pids-limit'),
        ('HostConfig', 'Devices', [{}], 'devices'),
        ('HostConfig', 'DeviceRequests', [{}], 'device-requests'),
        ('HostConfig', 'VolumesFrom', ['foreign'], 'volumes-from'),
        ('HostConfig', 'PortBindings', {'80/tcp': []}, 'port-bindings'),
        ('HostConfig', 'DeviceCgroupRules', ['a *:* rwm'], 'device-cgroup-rules'),
        ('HostConfig', 'Ulimits', [], 'ulimits'),
    )

    def record(self, phase):
        c = contract(phase)
        return c, inspected(c, Path('/fixture-source'), Path('/fixture-out'))

    def run_record(self, c, record):
        return s.inspect_isolation(record, c, Path('/fixture-source'), Path('/fixture-out'))

    def test_both_phases_accept_and_each_false_predicate_has_closed_provenance(self):
        for phase in ('sign', 'lifecycle'):
            c, record = self.record(phase)
            self.run_record(c, record)
            for section, field, value, suffix in self.CASES:
                with self.subTest(phase=phase, field=field):
                    bad = copy.deepcopy(record)
                    bad[section][field] = value
                    with self.assertRaises(ValueError) as caught:
                        self.run_record(c, bad)
                    code = 'sandbox-isolation-' + suffix + '-drift'
                    self.assertEqual(caught.exception.args, (code,))
                    provenance = caught.exception.__dict__['_ksm_check']
                    self.assertIs(provenance[0], s._CHECK_PROVENANCE)
                    self.assertEqual(provenance[1], code)
                    self.assertIn(code, s.DIAGNOSTIC_CHECKS)

    def test_every_two_false_predicate_pair_reports_first_in_original_order(self):
        for phase in ('sign', 'lifecycle'):
            c, record = self.record(phase)
            for first, left in enumerate(self.CASES):
                for second, right in enumerate(self.CASES):
                    with self.subTest(phase=phase, first=first, second=second):
                        bad = copy.deepcopy(record)
                        for section, field, value, _ in (left, right):
                            bad[section][field] = value
                        with self.assertRaises(ValueError) as caught:
                            self.run_record(c, bad)
                        self.assertEqual(caught.exception.args,
                            ('sandbox-isolation-' + self.CASES[min(first, second)][3] + '-drift',))

    def test_later_missing_or_malformed_values_are_not_read_after_false_predicate(self):
        for phase in ('sign', 'lifecycle'):
            c, record = self.record(phase)
            for section, field, value, suffix in self.CASES[:-1]:
                bad = copy.deepcopy(record)
                bad[section][field] = value
                del bad['HostConfig']['Ulimits']
                with self.subTest(phase=phase, field=field), self.assertRaises(ValueError) as caught:
                    self.run_record(c, bad)
                self.assertEqual(caught.exception.args, ('sandbox-isolation-' + suffix + '-drift',))
            bad = copy.deepcopy(record)
            bad['Config']['User'] = 'other'
            bad['HostConfig']['CapAdd'] = [['not-hashable']]
            with self.assertRaisesRegex(ValueError, '^sandbox-isolation-user-drift$'):
                self.run_record(c, bad)

    def test_memory_and_swap_remain_one_chained_predicate_and_no_normalization_added(self):
        for phase in ('sign', 'lifecycle'):
            c, record = self.record(phase)
            for field in ('Memory', 'MemorySwap'):
                bad = copy.deepcopy(record)
                bad['HostConfig'][field] = 1
                with self.assertRaisesRegex(ValueError, '^sandbox-isolation-memory-and-swap-drift$'):
                    self.run_record(c, bad)
            for field, value, suffix in (
                    ('CapAdd', ['CAP_CHOWN'], 'cap-add'),
                    ('Ulimits', record['HostConfig']['Ulimits'] + [{'Name': 'nproc', 'Soft': 1, 'Hard': 1}], 'ulimits')):
                bad = copy.deepcopy(record)
                bad['HostConfig'][field] = value
                with self.assertRaisesRegex(ValueError, '^sandbox-isolation-' + suffix + '-drift$'):
                    self.run_record(c, bad)

    def test_missing_and_malformed_fields_preserve_exception_category(self):
        for phase in ('sign', 'lifecycle'):
            c, record = self.record(phase)
            for section, field in (('Config', 'User'), ('HostConfig', 'NetworkMode'),
                                   ('HostConfig', 'CapDrop'), ('HostConfig', 'Ulimits')):
                bad = copy.deepcopy(record)
                del bad[section][field]
                with self.assertRaises(KeyError) as caught:
                    self.run_record(c, bad)
                self.assertEqual(caught.exception.args, (field,))
            bad = copy.deepcopy(record)
            bad['HostConfig']['CapAdd'] = [['not-hashable']]
            with self.assertRaises(TypeError):
                self.run_record(c, bad)


if __name__ == '__main__':
    unittest.main()
