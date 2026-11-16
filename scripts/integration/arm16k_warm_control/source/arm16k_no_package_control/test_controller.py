# SPDX-License-Identifier: MIT
"""MODEL controller boundaries: no Docker, sockets, credentials or images read."""
import copy
from contextlib import ExitStack
import importlib.util
import json
import os
import re
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('no_package_controller_model', HERE/'controller.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
K, M, P = (C.S.local(name) for name in ('contracts', 'metadata', 'plan'))
NONCE, BASE = 'a'*32, 'b'*32


def proof(**changes):
    fields = dict(UID='1000', USERNAME='builder', PID1='systemd', ARCH='aarch64',
        PAGESIZE='16384', XDG_SESSION_ID='c1', Id='c1', Name='builder', User='1000',
        Active='yes', State='active', Class='user', Remote='no', Type='tty',
        Service='login', Leader='123', LOGIND='active', DBUS='active')
    fields.update(changes)
    return ('\nTCG_LOGIN_BEGIN '+BASE+'\n'+''.join(key+'='+value+'\n' for key, value in fields.items())+
            'TCG_LOGIN_END '+BASE+'\n').encode()


def frame(stage):
    return (M.BEGIN+(NONCE+' '+stage+'\n').encode()+
        b''.join(path.encode()+b'|ABSENT\n' for path in M.PATHS)+
        M.END+(NONCE+' '+stage+'\n').encode())


class Clock:
    def __init__(self):
        self.now = 10.
        self.sleeps = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        if not 0 < seconds <= .05:
            raise AssertionError('finite short idle polling')
        self.sleeps.append(seconds)
        self.now += seconds


class Serial:
    """Only scheduled in-memory bytes; no stream or socket implementation."""
    def __init__(self, chunks=None):
        self.deadline = 100.
        self.data = bytearray()
        self.sent, self.deadlines = [], []
        self.chunks = list(chunks or [b'login: ', b'Password: ',
            ('ARM16K_SHELL_READY '+BASE).encode(), proof(),
            frame('after_login'), frame('before_logout'), b'login: '])

    def send(self, value):
        self.sent.append(value)

    def until(self, pattern):
        self.deadlines.append(self.deadline)
        if not self.chunks:
            raise EOFError('MODEL serial closed')
        chunk = self.chunks.pop(0)
        if isinstance(chunk, BaseException):
            raise chunk
        self.data.extend(chunk)
        match = re.search(pattern, chunk)
        if not match:
            raise TimeoutError('MODEL expected protocol absent')
        return match


class Journey(unittest.TestCase):
    def setUp(self):
        self.packet = dict(nonce=NONCE, baseline_nonce=BASE, idle_seconds=2,
            timing=dict(login_seconds=5, proof_seconds=6, probe_seconds=7, logout_seconds=8))
        self.clock = Clock()
        self.guards = 0

    def guard(self):
        self.guards += 1

    def run_model(self, serial):
        return C.journey(serial, 'MODEL_NOT_A_REAL_SECRET', self.packet,
            self.guard, self.clock, self.clock.sleep)

    def test_normal_pam_two_probe_idle_and_logout_order(self):
        serial = Serial()
        result = self.run_model(serial)
        self.assertEqual(serial.sent, [b'builder\n', b'MODEL_NOT_A_REAL_SECRET\n',
            b'/usr/local/libexec/arm16k-login-proof\n',
            P.guest_command('after_login', NONCE).encode(),
            P.guest_command('before_logout', NONCE).encode(), b'exit\n'])
        self.assertEqual(serial.deadlines[:5], [15., 15., 15., 16., 17.])
        self.assertAlmostEqual(serial.deadlines[5], 19.)
        self.assertAlmostEqual(serial.deadlines[6], 20.)
        self.assertEqual(serial.deadline, 100.)
        self.assertEqual(len(result['session']), 18)
        self.assertEqual(set(result['metadata']), {'after_login', 'before_logout'})
        self.assertTrue(all(result['metadata'][stage] == dict.fromkeys(M.PATHS)
            for stage in result['metadata']))
        self.assertTrue(result['normal_PAM_logout_observed'])
        self.assertGreaterEqual(result['observed_idle_ns'], 2_000_000_000)
        self.assertLessEqual(result['observed_idle_ns'], 2_050_000_000)
        self.assertGreater(self.guards, 7)
        self.assertTrue(self.clock.sleeps)
        self.assertNotIn('MODEL_NOT_A_REAL_SECRET', json.dumps(result))
        self.assertNotIn('TCG_LOGIN_BEGIN', json.dumps(result))

    def test_zero_idle_still_has_two_separate_probe_slices(self):
        self.packet['idle_seconds'] = 0
        result = self.run_model(Serial())
        self.assertEqual(result['observed_idle_ns'], 0)
        self.assertEqual(self.clock.sleeps, [])
        self.assertEqual(len(result['metadata']), 2)

    def test_waits_never_extend_original_serial_deadline(self):
        serial = Serial()
        serial.deadline = 12.5
        self.run_model(serial)
        self.assertTrue(all(deadline <= 12.5 for deadline in serial.deadlines))
        self.assertEqual(serial.deadline, 12.5)

    def test_guard_failure_stops_before_password_or_probes(self):
        serial = Serial()
        def guard():
            raise ValueError('MODEL exhausted')
        with self.assertRaises(ValueError):
            C.journey(serial, 'MODEL', self.packet, guard, self.clock, self.clock.sleep)
        self.assertEqual(serial.sent, [])

    def test_eof_during_login_stops_before_proof(self):
        serial = Serial([b'login: ', EOFError('MODEL EOF')])
        with self.assertRaises(EOFError):
            self.run_model(serial)
        self.assertEqual(serial.sent, [b'builder\n'])

    def test_idle_deadline_failure_prevents_second_probe_and_logout(self):
        serial = Serial()
        serial.deadline = 11.
        with self.assertRaises(ValueError):
            self.run_model(serial)
        self.assertEqual(len(serial.sent), 4)
        self.assertNotIn(b'exit\n', serial.sent)

    def test_wrong_metadata_nonce_or_path_cannot_reach_logout(self):
        for replacement in (frame('before_logout'),
                frame('after_login').replace(b'root|ABSENT', b'private|ABSENT'),
                frame('after_login').replace(NONCE.encode(), b'c'*32)):
            with self.subTest(replacement=replacement[:40]):
                serial = Serial()
                serial.chunks[4] = replacement
                with self.assertRaises((ValueError, TimeoutError)):
                    self.run_model(serial)
                self.assertNotIn(b'exit\n', serial.sent)

    def test_logout_prompt_is_required(self):
        serial = Serial()
        serial.chunks[-1] = EOFError('MODEL missing PAM logout')
        with self.assertRaises(EOFError):
            self.run_model(serial)
        self.assertEqual(serial.sent[-1], b'exit\n')

    def test_exact_eighteen_field_normal_pam_proof(self):
        self.assertEqual(len(C.login_fields(proof(), BASE)), 18)
        for changes in (dict(UID='0'), dict(Service='sshd'), dict(Type='unspecified'),
                dict(Remote='yes'), dict(LOGIND='inactive'), dict(DBUS='inactive'),
                dict(ARCH='x86_64'), dict(PAGESIZE='4096'), dict(Active='no'),
                dict(Id='other'), dict(Extra='MODEL_UNTRUSTED_TEXT')):
            with self.subTest(changes=changes), self.assertRaises((ValueError, AssertionError)):
                C.login_fields(proof(**changes), BASE)
        for raw in (proof()+proof(), proof().replace(b'DBUS=active\n', b''),
                proof().replace(b'UID=1000\n', b'UID=1000\nUID=1000\n')):
            with self.assertRaises((ValueError, AssertionError)):
                C.login_fields(raw, BASE)


def container():
    mounts = {('bind', '/PUBLIC_MODEL/code', '/code', False),
              ('bind', '/PUBLIC_MODEL/raw', '/base/guest.raw', False),
              ('bind', '/PUBLIC_MODEL/out', '/work', True)}
    r = dict(owner_memory_bytes=256*1024**2, cpus=2, pids=128)
    labels = {'org.cachy-asahi.no-package-nonce': NONCE}
    row = dict(Id='d'*64, Name='/MODEL', Image='sha256:'+'e'*64,
        Config=dict(Labels=labels.copy(), Entrypoint=['/usr/bin/python3'],
            Cmd=['-I', '-B', '/code/actor.py', '--execute-root-bound-actor']),
        Mounts=[dict(Type=kind, Source=source, Destination=target, RW=rw)
                for kind, source, target, rw in sorted(mounts)],
        HostConfig=dict(ReadonlyRootfs=True, NetworkMode='none', CapDrop=['ALL'],
            CapAdd=[], Privileged=False, Devices=[], Init=False,
            SecurityOpt=['no-new-privileges'], Memory=r['owner_memory_bytes'],
            MemorySwap=r['owner_memory_bytes'], NanoCpus=2*10**9, PidsLimit=128),
        State=dict(Running=False, ExitCode=0, OOMKilled=False))
    return row, labels, mounts, r


class ContainerCustody(unittest.TestCase):
    def validate(self, row, labels, mounts, resources):
        return C.validate_container(row, 'MODEL', 'sha256:'+'e'*64, labels, mounts, resources)

    def test_exact_owned_identity_and_mounts_pass(self):
        row, labels, mounts, resources = container()
        self.validate(row, labels, mounts, resources)

    def test_foreign_identity_entrypoint_and_mounts_are_refused(self):
        for change in ('id', 'name', 'image', 'labels', 'entrypoint', 'cmd',
                'extra-credential', 'rw-input', 'ro-output', 'duplicate-mount', 'source'):
            row, labels, mounts, resources = container()
            if change == 'id': row['Id'] = 'bad'
            elif change == 'name': row['Name'] = '/FOREIGN'
            elif change == 'image': row['Image'] = 'sha256:'+'f'*64
            elif change == 'labels': row['Config']['Labels'] = {}
            elif change == 'entrypoint': row['Config']['Entrypoint'] = ['/bin/sh']
            elif change == 'cmd': row['Config']['Cmd'] += ['--foreign']
            elif change == 'extra-credential': row['Mounts'].append(dict(Type='bind', Source='/MODEL_CREDENTIAL_NEVER_OPEN', Destination='/secret', RW=False))
            elif change == 'rw-input': next(m for m in row['Mounts'] if m['Destination'] == '/code')['RW'] = True
            elif change == 'ro-output': next(m for m in row['Mounts'] if m['Destination'] == '/work')['RW'] = False
            elif change == 'duplicate-mount': row['Mounts'].append(copy.deepcopy(row['Mounts'][0]))
            elif change == 'source': row['Mounts'][0]['Source'] = '/FOREIGN'
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(row, labels, mounts, resources)

    def test_resource_and_privilege_relaxations_are_refused(self):
        changes = dict(ReadonlyRootfs=False, NetworkMode='host', CapDrop=[],
            CapAdd=['SYS_ADMIN'], Privileged=True, Devices=[{'PathOnHost': '/dev/MODEL'}],
            Init=True, SecurityOpt=[], Memory=1, MemorySwap=-1, NanoCpus=1, PidsLimit=-1)
        for key, value in changes.items():
            row, labels, mounts, resources = container()
            row['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.validate(row, labels, mounts, resources)


class Removal(unittest.TestCase):
    def scope(self, row, *, result=0, listing=None, recover_error=None):
        calls = []
        def recover(deadline):
            calls.append(('recover', deadline))
            if recover_error:
                raise recover_error
            return row
        def call(argv, deadline):
            calls.append((argv, deadline))
            return SimpleNamespace(returncode=result)
        def listed(deadline):
            calls.append(('listing', deadline))
            return listing
        return SimpleNamespace(cid='d'*64, recover=recover, call=call, listing=listed), calls

    def test_stopped_owned_container_only_normal_rm_and_absence(self):
        scope, calls = self.scope({'State': {'Running': False}})
        report = {}
        C.normal_remove(scope, report, 123.)
        commands = [call[0] for call in calls if isinstance(call[0], list)]
        self.assertEqual(commands, [['docker', 'container', 'rm', 'd'*64]])
        self.assertTrue(report['normal_owned_cleanup'])
        self.assertTrue(report['owned_container_absence_verified'])
        self.assertTrue(all(deadline <= 123. for _, deadline in calls))

    def test_running_or_foreign_container_cannot_be_removed(self):
        for row, error in (({'State': {'Running': True}}, None),
                (None, AssertionError('MODEL foreign identity refusal'))):
            scope, calls = self.scope(row, recover_error=error)
            with self.subTest(error=error), self.assertRaises((ValueError, AssertionError)):
                C.normal_remove(scope, {}, 123.)
            self.assertFalse(any(isinstance(call[0], list) for call in calls))

    def test_absent_container_is_not_removed(self):
        scope, calls = self.scope(None)
        report = {}
        C.normal_remove(scope, report, 123.)
        self.assertEqual(report, {'owned_container_absence_verified': True})
        self.assertEqual(len(calls), 1)

    def test_removal_error_or_remaining_name_cannot_claim_cleanup(self):
        for result, listing in ((1, None), (0, 'd'*64)):
            scope, calls = self.scope({'State': {'Running': False}}, result=result, listing=listing)
            report = {}
            with self.subTest(result=result), self.assertRaises(ValueError):
                C.normal_remove(scope, report, 123.)
            self.assertNotIn('normal_owned_cleanup', report)
            self.assertFalse(any('--force' in call[0] for call in calls if isinstance(call[0], list)))


class PeerReuse(unittest.TestCase):
    def test_source65_qmp_peer_checks_original_parent_argv_and_pidfds(self):
        """Exercise the unchanged peer primitive with process/socket DATA fakes."""
        legacy = C.S.legacy('controller')
        row = {'State': dict(Running=True, OOMKilled=False, Pid=654)}
        argv = ['/MODEL/qemu', '-nic', 'none']
        identities = {321: dict(pid=321, parent=654, start=1, argv=[s.encode() for s in argv]),
                      654: dict(pid=654, parent=1, start=2, argv=[b'/MODEL/actor'])}
        stream = SimpleNamespace(fileno=lambda: 42, getsockopt=lambda *a: struct.pack('3i', 321, os.getuid(), os.getgid()))
        dead = []
        poll = SimpleNamespace(register=lambda *a: None, poll=lambda *a: dead.copy())
        with patch.object(legacy, 'module', return_value=K), \
                patch.object(legacy.os, 'pidfd_open', side_effect=[10, 11], create=True), \
                patch.object(legacy.os, 'close') as close, \
                patch.object(legacy, 'proc_identity', side_effect=lambda pid: copy.deepcopy(identities[pid])), \
                patch.object(legacy.select, 'poll', return_value=poll):
            peer = legacy.QMPPeer(stream, row, argv)
            evidence = peer.evidence()
            self.assertTrue(evidence['original_connection'])
            self.assertTrue(evidence['pidfds_live_checked'])
            identities[321]['parent'] = 999
            with self.assertRaises(ValueError): peer.check(row)
            identities[321]['parent'] = 654
            identities[321]['argv'] = [b'/MODEL/foreign']
            with self.assertRaises(ValueError): peer.check(row)
            identities[321]['argv'] = [s.encode() for s in argv]
            dead.append((10, 1))
            with self.assertRaises(ValueError): peer.check(row)
            peer.close()
            self.assertEqual([call.args[0] for call in close.call_args_list], [10, 11])


class LaunchEpoch(unittest.TestCase):
    def test_post_scan_epoch_is_fresh_bounded_and_returns_whole_seconds(self):
        now = 1_800_000_100*10**9+123
        for utc_ns in (now, now-30*10**9):
            self.assertEqual(C.launch_epoch(dict(nonce=NONCE, utc_ns=utc_ns), NONCE,
                now-120*10**9, now), utc_ns//10**9)

    def test_wrong_nonce_shape_types_or_pre_admission_epoch_are_refused(self):
        now = 1_800_000_100*10**9
        for value in ({}, dict(nonce=NONCE, utc_ns=now, extra='MODEL_UNTRUSTED'),
                dict(nonce='c'*32, utc_ns=now), dict(nonce=NONCE, utc_ns=True),
                dict(nonce=NONCE, utc_ns=str(now)), dict(nonce=NONCE, utc_ns=now+1),
                dict(nonce=NONCE, utc_ns=now-30*10**9-1),
                dict(nonce=NONCE, utc_ns=now-10*10**9-1)):
            with self.subTest(value=value), self.assertRaises(ValueError) as caught:
                C.launch_epoch(value, NONCE, now-10*10**9, now)
            self.assertNotIn('MODEL_UNTRUSTED', str(caught.exception))
        for admission, current in ((True, now), (now-1, True), (str(now), now)):
            with self.subTest(admission=admission, current=current), self.assertRaises(ValueError):
                C.launch_epoch(dict(nonce=NONCE, utc_ns=now), NONCE, admission, current)


class ObservationBindings(unittest.TestCase):
    def setUp(self):
        self.pin = K.bytes_pin(b'PUBLIC_MODEL_PIN')
        self.source = K.bytes_pin(b'PUBLIC_MODEL_SOURCE')
        self.argv = ['/MODEL/qemu', '-nic', 'none']
        self.packet = dict(nonce=NONCE, baseline_nonce=BASE, reader=self.pin,
            baseline=dict.fromkeys(('raw', 'prepared', 'certificate'), self.pin),
            kernel=dict.fromkeys(('Image', 'config'), self.pin))
        self.data = dict(schema=1, status='PASS_NO_PACKAGE_ACTOR_OFFLINE_METADATA_ONLY',
            operation=K.OP, nonce=NONCE, baseline_nonce=BASE, source_lock=self.source,
            baseline=self.packet['baseline'], kernel=self.packet['kernel'], reader=self.pin,
            metadata=dict(offline_before=dict.fromkeys(M.PATHS), offline_after=dict.fromkeys(M.PATHS)),
            qemu_receipt=self.pin, qemu_argv=self.pin, qemu_epoch=self.pin, qemu_naturally_retired=True,
            original_raw_identity_unchanged=True, VM_acceptance=None, Root_acceptance=None,
            preservation=None, ALPM=None)

    def validate(self, data, *, receipt=None, vector=None):
        runtime = C.S.legacy('runtime')
        with patch.object(K, 'pin', return_value=self.pin), \
                patch.object(K, 'load', return_value=dict(argv=self.argv if vector is None else vector)), \
                patch.object(runtime, 'receipt', return_value=receipt or dict(passed=True, argv=self.argv)), \
                patch.object(runtime, 'natural', side_effect=lambda row: row['passed'] is True):
            return C.validate_observations(data, self.packet, self.source, Path('/PUBLIC_MODEL/out'), self.argv)

    def test_exact_observation_receipt_and_original_peer_vector_pass(self):
        self.assertEqual(self.validate(self.data), self.data['metadata'])

    def test_substituted_case_source_input_or_receipt_is_refused(self):
        replacements = dict(schema=True, status='PASS', operation='FOREIGN', nonce='c'*32,
            baseline_nonce='c'*32, source_lock=K.bytes_pin(b'other'), baseline={}, kernel={},
            reader=K.bytes_pin(b'other'), qemu_receipt=K.bytes_pin(b'other'), qemu_argv=K.bytes_pin(b'other'),
            qemu_epoch=K.bytes_pin(b'other'))
        for field, value in replacements.items():
            data = copy.deepcopy(self.data); data[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(data)
        for field in ('VM_acceptance', 'Root_acceptance', 'preservation', 'ALPM'):
            data = copy.deepcopy(self.data); data[field] = 'CLAIMED'
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(data)

    def test_unknown_fields_missing_phases_and_truthy_claims_are_refused(self):
        for field in ('qemu_naturally_retired', 'original_raw_identity_unchanged'):
            data = copy.deepcopy(self.data); data[field] = 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(data)
        for change in ('extra', 'missing-phase', 'extra-phase'):
            data = copy.deepcopy(self.data)
            if change == 'extra': data['raw_serial'] = 'MODEL_UNTRUSTED'
            elif change == 'missing-phase': del data['metadata']['offline_after']
            else: data['metadata']['before_logout'] = {}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(data)

    def test_nonnatural_receipt_or_vector_mismatch_is_refused(self):
        for kwargs in (dict(receipt=dict(passed=False, argv=self.argv)),
                dict(receipt=dict(passed=True, argv=['/MODEL/foreign'])), dict(vector=['/MODEL/foreign'])):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.validate(self.data, **kwargs)


class ExecuteModel(unittest.TestCase):
    """Full adapter execution over synthetic DATA and fake process boundaries."""
    def run_model(self, failure=None):
        with tempfile.TemporaryDirectory(prefix='control-execute-model-') as tmp:
            root = Path(tmp)
            packetdir, output, kernel = root/'packet', root/'out', root/'kernel'
            packetdir.mkdir(); kernel.mkdir()
            for name in ('control-packet.json', 'raw_metadata.py'):
                (packetdir/name).touch()
            required = dict(CONFIG_ARM64='y', CONFIG_ARM64_16K_PAGES='y', CONFIG_RTC_CLASS='y',
                CONFIG_RTC_DRV_PL031='y', CONFIG_RTC_HCTOSYS='y',
                CONFIG_RTC_HCTOSYS_DEVICE='"rtc0"', CONFIG_RTC_SYSTOHC='n',
                CONFIG_VIRTIO_BLK='y', CONFIG_EXT4_FS='y')
            (kernel/'config').write_text(''.join(key+'='+value+'\n' for key, value in required.items()))
            baseline, credentials = root/'BASELINE_NEVER_OPEN', root/'CREDENTIAL_NEVER_OPEN'
            authority, admission = root/'authority', root/'admission'
            pin, source = dict(bytes=1, sha256='a'*64), dict(bytes=2, sha256='b'*64)
            resources = dict(boot_seconds=400, cleanup_seconds=60, cpus=2, pids=128, owner_memory_bytes=256*1024**2)
            packet = dict(nonce=NONCE, baseline_nonce=BASE, idle_seconds=0, reader=pin,
                source_lock=source, resources=resources, tool_image='sha256:'+'e'*64,
                baseline=dict(raw=pin, prepared=pin, certificate=pin), kernel=dict(Image=pin, config=pin),
                timing=dict(login_seconds=5, proof_seconds=5, probe_seconds=5, logout_seconds=5))
            auth = dict(external_admission=pin, quota_device=None, credentials=pin)
            events, commands, handles, scopes, peers = [], [], [], [], []
            admission_ns = 1_800_000_000*10**9
            model_utc = [admission_ns]
            launch = dict(nonce=NONCE, utc_ns=admission_ns)
            def launched_argv(): return ['/MODEL/qemu', '--epoch', str(launch['utc_ns']//10**9)]
            metadata = dict.fromkeys(M.PATHS)
            observations = dict(schema=1, status='PASS_NO_PACKAGE_ACTOR_OFFLINE_METADATA_ONLY',
                operation='MODEL_CONTROL', nonce=NONCE, baseline_nonce=BASE, source_lock=source,
                baseline=packet['baseline'], kernel=packet['kernel'], reader=pin,
                metadata=dict(offline_before=metadata, offline_after=metadata),
                qemu_receipt=pin, qemu_argv=pin, qemu_epoch=pin, qemu_naturally_retired=True,
                original_raw_identity_unchanged=True, VM_acceptance=None, Root_acceptance=None,
                preservation=None, ALPM=None)
            def load(path, *args):
                events.append(('load', Path(path).name))
                if Path(path) == output/'qemu-epoch.json' and failure == 'missing-launch':
                    raise FileNotFoundError('MODEL launch epoch absent')
                return {packetdir/'control-packet.json': packet, authority: auth, admission: {},
                    baseline/'prepared.json': dict(nonce=BASE, files={'guest.raw': pin}),
                    credentials: dict(username='builder', password='MODEL_SYNTHETIC_PASSWORD_1234'),
                    output/'observations.json': observations,
                    output/'qemu-argv.json': dict(argv=['/MODEL/qemu', '--epoch', str(admission_ns//10**9)]
                        if failure == 'old-recorded-vector' else launched_argv()),
                    output/'qemu-epoch.json': launch}[Path(path)]
            def pinned(path, *args):
                events.append(('pin', Path(path).name)); return pin
            fakeK = SimpleNamespace(need=K.need, keys=K.keys, ordinary=Path, load=load, pin=pinned,
                inputs=lambda *a, **kw: None, authority=lambda *a, **kw: events.append('authority'),
                admission=lambda *a, **kw: events.append('admission'), canonical=K.canonical,
                OP='MODEL_CONTROL', END=None)
            class Guard:
                def __init__(self, *args, **kwargs): self.samples = []
                def __call__(self, *args): self.samples.append({'MODEL_budget_only': True})
            class State:
                pending = []
                cleaning = False
                def __enter__(self): events.append('cancellation-enter'); return self
                def __exit__(self, *args): events.append('cancellation-exit')
            class Route:
                def __enter__(self): events.append('transport-enter')
                def __exit__(self, *args): events.append('transport-exit')
            class Owned:
                def __init__(self, name, cidfile, image, labels, base, out):
                    self.name, self.cidfile, self.image, self.labels = name, cidfile, image, labels
                    self.cid, self.submitted, self.present = 'd'*64, False, False
                    self.row = None
                    scopes.append(self)
                def listing(self, deadline): return self.cid if self.present else None
                def recover(self, deadline):
                    if not self.present: return None
                    self.validate(self.row)
                    return self.row
                def cleanup(self, report):
                    events.append('forced-owned-fallback')
                    report['cleanup_errors'].append(dict(step='ownership-recovery', category='ValueError',
                        message='MODEL_ARBITRARY_PRIVATE_DIAGNOSTIC'))
                    self.present = False
                    report['owned_container_absence_verified'] = True
            def serial_factory(stream, deadline):
                serial = Serial(); serial.deadline = deadline; serial.stream = stream
                serial.data.extend(b'MODEL_ARBITRARY_RAW_SERIAL\n')
                return serial
            class Peer:
                def __init__(self, stream, row, argv):
                    self.assert_launch(argv)
                    self.closed = False; self.argv = argv
                    peers.append(self); events.append('peer-created')
                @staticmethod
                def assert_launch(argv):
                    if argv != launched_argv() or str(admission_ns//10**9) in argv:
                        raise AssertionError('MODEL QMP peer must bind post-scan launch epoch')
                def evidence(self): return dict(MODEL_peer=True)
                def check(self, row):
                    K.need(row['State']['Running'], 'MODEL current running peer')
                    events.append('peer-checked')
                def close(self): self.closed = True
            class Wire:
                def __init__(self):
                    self.closed = False; self.target = None; self.method = None; self.greeted = False
                    handles.append(self)
                def settimeout(self, timeout): pass
                def connect(self, target):
                    self.target = target
                    if failure == 'serial-connect' and target.endswith('serial.sock'):
                        raise OSError('MODEL_ARBITRARY_PRIVATE_DIAGNOSTIC')
                def makefile(self, *args, **kwargs): return self
                def write(self, raw):
                    self.method = json.loads(raw)['execute']
                    events.append('QMP-'+self.method)
                    return len(raw)
                def readline(self, count):
                    if not self.greeted:
                        self.greeted = True; return b'{"QMP":{}}\n'
                    if failure == 'qmp': return b'{"id":"qmp_capabilities","error":{}}\n'
                    if self.method == 'quit': scopes[0].row['State']['Running'] = False
                    return json.dumps({'return': {}, 'id': self.method}).encode()+b'\n'
                def close(self): self.closed = True
            def command(argv, *args, **kwargs):
                commands.append(argv)
                if argv[:2] == ['docker', 'info']: return '["name=rootless"]'
                if argv[:3] == ['docker', 'image', 'inspect']:
                    return json.dumps([{'Id': packet['tool_image'], 'Config': {'Labels': {}}}])
                if argv[:2] == ['docker', 'create']:
                    scope = scopes[0]
                    row, _, _, _ = container()
                    row.update(Name='/'+scope.name, Image=scope.image)
                    row['Config']['Labels'] = scope.labels
                    row['Mounts'] = []
                    for index, arg in enumerate(argv):
                        if arg == '--mount':
                            parts = argv[index+1].split(',')
                            values = dict(p.split('=', 1) for p in parts if '=' in p)
                            row['Mounts'].append(dict(Type=values['type'], Source=values['source'],
                                Destination=values['target'], RW='readonly' not in parts))
                    scope.present, scope.row = True, row
                    if failure == 'create':
                        row['State']['Running'] = True
                        raise TimeoutError('MODEL_ARBITRARY_PRIVATE_DIAGNOSTIC')
                    return ''
                if argv[:2] == ['docker', 'start']:
                    scopes[0].row['State']['Running'] = True
                    # Simulate a long preboot observation. The admitted host
                    # epoch is deliberately stale when QEMU actually launches.
                    model_utc[0] += 100*10**9
                    launch['utc_ns'] = model_utc[0]
                    if failure == 'stale-launch': launch['utc_ns'] -= 30*10**9+1
                    elif failure == 'future-launch': launch['utc_ns'] += 1
                    elif failure == 'wrong-launch-nonce': launch['nonce'] = 'c'*32
                    elif failure == 'old-admission-epoch': launch['utc_ns'] = admission_ns
                    for node in ('serial.sock', 'qmp.sock'): (output/node).touch()
                    return ''
                if argv[:2] == ['docker', 'wait']: return '0'
                raise AssertionError('MODEL unexpected command')
            def docker_call(argv, *args, **kwargs):
                commands.append(argv)
                if argv[:3] == ['docker', 'container', 'rm']:
                    self.assertFalse(scopes[0].row['State']['Running'])
                    self.assertNotIn('--force', argv)
                    scopes[0].present = False
                elif argv[:2] != ['docker', 'wait']:
                    raise AssertionError('MODEL unexpected custody command')
                return SimpleNamespace(returncode=0, stdout=b'0')
            fakeR = SimpleNamespace(transport=lambda auth: Route(), allocated=lambda *a: 0, GUARD=None,
                command=command, docker_call=docker_call,
                receipt=lambda path: {'MODEL': True, 'argv': ['/MODEL/qemu', '--epoch', str(admission_ns//10**9)]
                    if failure == 'old-receipt-vector' else launched_argv()}, natural=lambda row: True)
            realLC = C.S.legacy('contracts')
            original_parse = realLC.helper('reference_controller.py').parse_frame
            fakeLC = SimpleNamespace(helper=lambda name: SimpleNamespace(Cancellation=State, OwnedContainer=Owned,
                Serial=serial_factory, parse_frame=original_parse) if name == 'reference_controller.py' else realLC.helper(name), END=None)
            fakeS = SimpleNamespace(LEGACY=C.S.LEGACY, source=lambda expected: source,
                local=lambda name: {'contracts': fakeK, 'metadata': M, 'plan': P,
                    'actor': SimpleNamespace(qemu_argv=lambda packet, epoch: ['/MODEL/qemu', '--epoch', str(epoch)])}[name],
                legacy=lambda name: {'runtime': fakeR, 'controller': SimpleNamespace(QMPPeer=Peer),
                    'contracts': fakeLC, 'budget': SimpleNamespace(Guard=Guard)}[name])
            original_lstat = Path.lstat
            def lstat(path, *args, **kwargs):
                if path == credentials:
                    return SimpleNamespace(st_mode=stat.S_IFREG|0o600, st_nlink=1, st_uid=os.getuid())
                if path in (output/'serial.sock', output/'qmp.sock'):
                    return SimpleNamespace(st_mode=stat.S_IFSOCK|0o600, st_uid=os.getuid())
                return original_lstat(path, *args, **kwargs)
            args = SimpleNamespace(source_lock_sha256=source['sha256'], packet=packetdir, output=output,
                baseline=baseline, kernel=kernel, credentials=credentials, authority=authority,
                authority_sha256=pin['sha256'], external_admission=admission)
            with ExitStack() as stack:
                stack.enter_context(patch.object(C, 'S', fakeS))
                stack.enter_context(patch.object(C.os, 'umask', return_value=0))
                # MODEL capability only: this does not establish interpreter
                # support for actual Linux process custody.
                stack.enter_context(patch.object(C.os, 'pidfd_open',
                    side_effect=AssertionError('MODEL no real pidfd operation'), create=True))
                stack.enter_context(patch.object(C.time, 'time_ns', side_effect=lambda: model_utc[0]))
                stack.enter_context(patch.object(C.socket, 'socket', side_effect=lambda *a: Wire()))
                stack.enter_context(patch.object(Path, 'lstat', lstat))
                result = C.execute(args)
            report = json.loads((output/'report.json').read_bytes())
            self.assertNotIn('MODEL_ARBITRARY_RAW_SERIAL', json.dumps(report))
            self.assertNotIn('MODEL_ARBITRARY_PRIVATE_DIAGNOSTIC', json.dumps(report))
            self.assertNotIn('MODEL_SYNTHETIC_PASSWORD_1234', json.dumps(report))
            self.assertEqual(events[-2:], ['transport-exit', 'cancellation-exit'])
            self.assertTrue(all(handle.closed for handle in handles))
            self.assertTrue(all(peer.closed for peer in peers))
            self.assertTrue(report['owned_container_absence_verified'])
            self.assertIsNone(report['Root_acceptance'])
            self.assertIsNone(report['VM_acceptance'])
            self.assertIsNone(report['preservation'])
            self.assertIsNone(report['ALPM'])
            self.assertIsNone(fakeR.GUARD)
            self.assertIsNone(fakeK.END)
            self.assertIsNone(fakeLC.END)
            return result, report, events, commands

    def test_complete_model_journey_and_normal_retirement(self):
        result, report, events, commands = self.run_model()
        self.assertEqual(result, 0)
        self.assertEqual(report['status'], 'COMPLETE_NO_PACKAGE_METADATA_OBSERVATION_ONLY')
        self.assertTrue(report['normal_PAM_logout_observed'])
        self.assertTrue(report['normal_owned_cleanup'])
        self.assertNotIn('forced-owned-fallback', events)
        self.assertIn('peer-created', events)
        self.assertIn('peer-checked', events)
        self.assertIn('QMP-quit', events)
        self.assertLess(events.index('transport-enter'), events.index(('pin', 'guest.raw')))
        self.assertFalse(any('--force' in command for command in commands))
        self.assertEqual(set(report['comparison']['phases']), set(M.PHASES))
        self.assertLess(events.index(('load', 'qemu-epoch.json')), events.index('peer-created'))
        self.assertIn(('pin', 'qemu-epoch.json'), events)

    def test_serial_connect_failure_closes_socket_and_normally_retires_peer(self):
        result, report, events, _ = self.run_model('serial-connect')
        self.assertEqual(result, 1)
        self.assertEqual(report['failure_category'], 'OSError')
        self.assertEqual(report['status'], 'HOLD_NO_PACKAGE_CONTROL')
        self.assertTrue(report['normal_owned_cleanup'])
        self.assertNotIn('forced-owned-fallback', events)

    def test_ambiguous_create_or_qmp_failure_is_owned_fallback_hold(self):
        for failure in ('create', 'qmp'):
            with self.subTest(failure=failure):
                result, report, events, _ = self.run_model(failure)
                self.assertEqual(result, 1)
                self.assertEqual(report['status'], 'HOLD_NO_PACKAGE_CONTROL')
                self.assertTrue(report['forced_owned_cleanup_fallback'])
                self.assertIn('forced-owned-fallback', events)
                self.assertEqual(report['cleanup_errors'], [dict(step='ownership-recovery', category='ValueError')])

    def test_missing_stale_future_wrong_case_or_admission_epoch_never_authenticates_peer(self):
        for failure in ('missing-launch', 'stale-launch', 'future-launch',
                'wrong-launch-nonce', 'old-admission-epoch'):
            with self.subTest(failure=failure):
                result, report, events, _ = self.run_model(failure)
                self.assertEqual(result, 1)
                self.assertEqual(report['status'], 'HOLD_NO_PACKAGE_CONTROL')
                self.assertNotIn('peer-created', events)
                self.assertTrue(report['forced_owned_cleanup_fallback'])

    def test_receipt_and_recorded_argv_cannot_revert_to_admission_epoch(self):
        for failure in ('old-receipt-vector', 'old-recorded-vector'):
            with self.subTest(failure=failure):
                result, report, events, _ = self.run_model(failure)
                self.assertEqual(result, 1)
                self.assertEqual(report['status'], 'HOLD_NO_PACKAGE_CONTROL')
                self.assertIn('peer-created', events)
                self.assertTrue(report['normal_owned_cleanup'])
                self.assertNotIn('forced-owned-fallback', events)


class TransportOrder(unittest.TestCase):
    def run_model(self, native_api=True):
        """Execute only to an in-memory rejected transport; all input APIs fake."""
        with tempfile.TemporaryDirectory(prefix='control-model-') as tmp:
            root = Path(tmp)
            packetdir, output = root/'packet', root/'out'
            packetdir.mkdir()
            for name in ('control-packet.json', 'raw_metadata.py'):
                (packetdir/name).touch()
            baseline, kernel, credentials = root/'BASELINE_NEVER_OPEN', root/'KERNEL_NEVER_OPEN', root/'CREDENTIAL_NEVER_OPEN'
            authority, admission = root/'authority', root/'admission'
            pin = dict(bytes=1, sha256='a'*64)
            source = dict(bytes=2, sha256='b'*64)
            packet = dict(nonce=NONCE, reader=pin, resources=dict(boot_seconds=400, cleanup_seconds=60),
                baseline={'raw': pin, 'prepared': pin}, kernel={'Image': pin, 'config': pin})
            auth = dict(external_admission=pin, quota_device=None, credentials=pin)
            events = []
            private = (baseline, kernel, credentials)
            def checked(path):
                path = Path(path)
                if any(path == p or p in path.parents for p in private):
                    events.append('PRIVATE_INPUT_READ')
                    raise AssertionError('MODEL private input reached before rejected transport')
                return path
            def load(path, *args):
                path = checked(path)
                return {packetdir/'control-packet.json': packet, authority: auth, admission: {}}[path]
            def pinned(path, *args):
                checked(path)
                return pin
            fakeK = SimpleNamespace(need=K.need, ordinary=Path, load=load, pin=pinned,
                inputs=lambda *a, **kw: None,
                authority=lambda *a, **kw: events.append('AUTHORITY_VALIDATED'),
                admission=lambda *a, **kw: events.append('ADMISSION_VALIDATED'),
                canonical=K.canonical, OP='MODEL_CONTROL', END=None)
            class Route:
                def __enter__(self):
                    events.append('TRANSPORT_VALIDATED_AND_REJECTED')
                    raise ValueError('MODEL invalid reviewed CLI')
                def __exit__(self, *args):
                    events.append('UNENTERED_TRANSPORT_EXIT')
            class State:
                pending = []
                cleaning = False
                def __enter__(self): return self
                def __exit__(self, *args): pass
            class Guard:
                samples = []
                def __init__(self, *args, **kwargs): pass
                def __call__(self, *args): pass
            fakeR = SimpleNamespace(transport=lambda auth: events.append('TRANSPORT_CREATED') or Route(),
                allocated=lambda *a: 0, GUARD=None)
            fakeB = SimpleNamespace(Cancellation=State)
            fakeLC = SimpleNamespace(helper=lambda name: fakeB)
            fakeS = SimpleNamespace(LEGACY=C.S.LEGACY, source=lambda expected: source,
                local=lambda name: {'contracts': fakeK, 'metadata': M}[name],
                legacy=lambda name: {'runtime': fakeR, 'controller': object(),
                    'contracts': fakeLC, 'budget': SimpleNamespace(Guard=Guard)}[name])
            args = SimpleNamespace(source_lock_sha256=source['sha256'], packet=packetdir,
                output=output, baseline=baseline, kernel=kernel, credentials=credentials,
                authority=authority, authority_sha256=pin['sha256'], external_admission=admission)
            with ExitStack() as stack:
                stack.enter_context(patch.object(C, 'S', fakeS))
                stack.enter_context(patch.object(C.socket, 'socket', side_effect=AssertionError('MODEL no real sockets')))
                if not native_api:
                    # Actual absence, including on hosts whose os normally has
                    # the API; only public grant validation needs getuid here.
                    stack.enter_context(patch.object(C, 'os', SimpleNamespace(getuid=os.getuid)))
                    with self.assertRaisesRegex(ValueError, '^native Linux pidfd_open required$'):
                        C.execute(args)
                    self.assertFalse(output.exists())
                    self.assertEqual(events, ['AUTHORITY_VALIDATED', 'ADMISSION_VALIDATED'])
                    return
                stack.enter_context(patch.object(C.os, 'umask', return_value=0))
                stack.enter_context(patch.object(C.os, 'pidfd_open',
                    side_effect=AssertionError('MODEL no real pidfd operation'), create=True))
                self.assertEqual(C.execute(args), 1)
            self.assertEqual(events, ['AUTHORITY_VALIDATED', 'ADMISSION_VALIDATED',
                'TRANSPORT_CREATED', 'TRANSPORT_VALIDATED_AND_REJECTED'])
            report = json.loads((output/'report.json').read_bytes())
            self.assertEqual(report['status'], 'HOLD_NO_PACKAGE_CONTROL')
            self.assertEqual(report['failure_category'], 'ValueError')
            self.assertIsNone(report['Root_acceptance'])
            self.assertIsNone(report['VM_acceptance'])
            self.assertNotIn('MODEL invalid reviewed CLI', json.dumps(report))
            self.assertNotIn('CREDENTIAL_NEVER_OPEN', json.dumps(report))

    def test_rejected_transport_never_hashes_or_loads_private_inputs(self):
        self.run_model()

    def test_missing_native_pidfd_api_refuses_after_grants_before_private_io_or_output(self):
        self.run_model(native_api=False)


if __name__ == '__main__':
    unittest.main(verbosity=2)
