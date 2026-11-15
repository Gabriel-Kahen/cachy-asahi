# SPDX-License-Identifier: MIT
"""Synthetic controller/actor controls; no Docker, socket, VM or host mutation."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


def load(name):
    spec = importlib.util.spec_from_file_location('llvm23_control_' + name, Path(__file__).parent / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


B, V = load('boot'), load('vm_actor')


def fence(event, args):
    if event == 'open' or event.startswith(('subprocess.', 'os.system', 'os.exec', 'os.spawn',
            'os.posix_spawn', 'os.fork', 'os.kill', 'socket.', 'ctypes.')):
        raise RuntimeError('operational/filesystem event forbidden: ' + event)


sys.addaudithook(fence)


def limits():
    # Modeled resource fields, never a proposed/issued resource certificate.
    return dict(cpus=3, pids=48, guest_memory_bytes=768 * 1024**2,
                owner_memory_bytes=1024**3, boot_seconds=100, cleanup_seconds=30,
                overlay_cap_bytes=64 * 1024**2, readback_allocated_cap_bytes=128 * 1024**2,
                logs_cap_bytes=1024**2, reserve_bytes=1024**2, clone_allocated_cap_bytes=256 * 1024**2)


class Wire:
    def __init__(self, rows):
        self.rows = iter(rows)
        self.writes = []

    def readline(self, size):
        return next(self.rows)

    def write(self, data):
        self.writes.append(data)
        return len(data)


def encoded(value):
    return json.dumps(value).encode() + b'\n'


class Scope:
    submitted = True
    cid = 'c' * 64

    def __init__(self, wait_fails=False, ambiguous=False):
        self.calls = []
        self.wait_fails = wait_fails
        self.ambiguous = ambiguous

    def recover(self, deadline):
        if self.ambiguous:
            raise ValueError('modeled custody ambiguity')
        return {'Id': self.cid}

    def call(self, argv, deadline):
        self.calls.append(argv)
        if self.wait_fails and argv[1] == 'wait':
            raise TimeoutError('modeled wait timeout')
        return SimpleNamespace(returncode=0)

    def listing(self, deadline):
        return None


class MemoryPath:
    """Only synthetic in-memory files; implements the actor's finite path API."""
    def __init__(self, state, name='work'):
        self.state, self.name = state, name

    def __truediv__(self, name):
        return MemoryPath(self.state, self.name + '/' + name)

    def exists(self):
        return self.name in self.state

    def is_file(self):
        return self.exists()

    def is_symlink(self):
        return False

    def open(self, mode):
        if mode != 'x' or self.exists():
            raise FileExistsError(self.name)
        self.state[self.name] = b''
        return io.StringIO()

    def write_text(self, value):
        self.state[self.name] = value.encode()

    def write_bytes(self, value):
        self.state[self.name] = value


class BootTests(unittest.TestCase):
    def test_prepared_root_selection_refuses_before_data_or_actor_access(self):
        pin = dict(bytes=4, sha256='a' * 64)
        args = SimpleNamespace(prepared=Path('/SYNTHETIC/prepared'), output=Path('/SYNTHETIC/output'),
                               prepared_sha256=pin['sha256'])
        K = SimpleNamespace(ordinary=lambda p: p, pin=lambda *args: pin,
                            load=lambda *args: self.fail('must refuse before further DATA reads'))
        for authority in (dict(allow_boot=False, prepared=pin),
                          dict(allow_boot=True, prepared=pin | dict(sha256='b' * 64))):
            with self.subTest(authority=authority), self.assertRaises(ValueError):
                B.prepared_binding(args, dict(authority=authority), K,
                                   lambda *args: self.fail('host credentials must remain unread'))

    def test_changed_complete_prepared_raw_pin_refused(self):
        pin = dict(bytes=4, sha256='a' * 64)
        ctx = dict(authority=dict(allow_boot=True, prepared=pin), source_lock=pin,
                   case={}, certs={}, limits=dict(prepared_raw_bytes=4), kernel={}, tool={},
                   base=dict(files={}, nonce='1' * 32), nonce='2' * 32,
                   paths=dict(packet='/SYNTHETIC/packet'))
        manifest = dict(status='PREPARED_LLVM23_IMAGE_NOT_BOOTED', operation='SYNTHETIC',
            source_lock=pin, case={}, certs={}, limits=ctx['limits'], kernel={}, tool={}, packet=pin,
            base_files={}, baseline_nonce='1' * 32, nonce='2' * 32,
            files={n: pin for n in ('guest.raw', 'Image', 'kernel.config')})
        def observed(path, *args):
            return pin | dict(sha256='b' * 64) if path.name == 'guest.raw' else pin
        K = SimpleNamespace(OP='SYNTHETIC', ordinary=lambda p: p, pin=observed,
                            load=lambda *args: manifest)
        args = SimpleNamespace(prepared=Path('/SYNTHETIC/prepared'), output=Path('/SYNTHETIC/output'),
                               prepared_sha256=pin['sha256'])
        with self.assertRaisesRegex(ValueError, 'complete prepared input bytes changed'):
            B.prepared_binding(args, ctx, K, lambda *args: self.fail('no credentials read on tampered input'))

    def test_resources_actual_values(self):
        self.assertEqual(B.resources(limits()), limits())

    def test_resources_refuse_missing_bool_fractional_memory_and_overlay_overflow(self):
        for row in (limits() | dict(cpus=True), limits() | dict(guest_memory_bytes=1025),
                    limits() | dict(overlay_cap_bytes=1024**3 + 1), {'cpus': 1}):
            with self.subTest(row=row), self.assertRaises(ValueError):
                B.resources(row)

    def test_qmp_capabilities_then_quit(self):
        incoming = bytearray(b''.join([encoded({'QMP': {}}), encoded({'return': {}, 'id': 'llvm23-1'}),
                     encoded({'event': 'STOP'}), encoded({'return': {}, 'id': 'llvm23-2'})]))
        writes, polls, timeouts = [], [], []
        first = [True]
        def recv(size):
            if first.pop() if first else False: raise B.socket.timeout('modeled local timeout')
            part = bytes(incoming[:size]); del incoming[:size]; return part
        def send(data):
            part = bytes(data[:3]); writes.append(part); return len(part)
        raw = SimpleNamespace(recv=recv, send=send, settimeout=timeouts.append)
        stream = B.LineStream(B.GuardedSocket(raw, 20, lambda: polls.append(True), clock=lambda: 10))
        qmp = B.QMP(stream, 20, lambda: None, clock=lambda: 10)
        qmp.greeting(); qmp.rpc('qmp_capabilities'); qmp.rpc('quit')
        self.assertEqual([json.loads(row)['execute'] for row in b''.join(writes).splitlines()], ['qmp_capabilities', 'quit'])
        self.assertTrue(polls)
        self.assertTrue(all(0 < value <= .5 for value in timeouts))

    def test_qmp_no_quit_before_capabilities_or_other_method(self):
        for method in ('quit', 'stop', 'query-status'):
            wire = Wire([])
            with self.subTest(method=method), self.assertRaises(ValueError):
                B.QMP(wire, 20, lambda: None, clock=lambda: 10).rpc(method)
            self.assertEqual(wire.writes, [])

    def test_qmp_never_retries_completed_request(self):
        wire = Wire([encoded({'return': {}, 'id': 'llvm23-1'})])
        qmp = B.QMP(wire, 20, lambda: None, clock=lambda: 10)
        qmp.rpc('qmp_capabilities')
        with self.assertRaises(ValueError):
            qmp.rpc('qmp_capabilities')
        self.assertEqual(len(wire.writes), 1)

    def test_qmp_deadline_refuses_before_write(self):
        wire = Wire([])
        with self.assertRaises(ValueError):
            B.QMP(wire, 10, lambda: None, clock=lambda: 10).rpc('qmp_capabilities')
        self.assertEqual(wire.writes, [])

    def test_qmp_wrong_duplicate_or_error_response_refused(self):
        for row in (encoded({'return': {}, 'id': 'other'}),
                    encoded({'error': {}, 'id': 'llvm23-1'}),
                    b'{"return":{},"id":"llvm23-1","id":"llvm23-1"}\n'):
            with self.subTest(row=row), self.assertRaises(ValueError):
                B.QMP(Wire([row]), 20, lambda: None, clock=lambda: 10).rpc('qmp_capabilities')

    def test_qmp_bounded_events_and_partial_request_are_no_retry(self):
        wire = Wire([encoded({'event': 'STOP'})] * 64)
        qmp = B.QMP(wire, 20, lambda: None, clock=lambda: 10)
        with self.assertRaises(ValueError): qmp.rpc('qmp_capabilities')
        with self.assertRaises(ValueError): qmp.rpc('qmp_capabilities')
        self.assertEqual(len(wire.writes), 1)
        wire = Wire([])
        wire.write = lambda data: 1
        with self.assertRaises(ValueError):
            B.QMP(wire, 20, lambda: None, clock=lambda: 10).rpc('qmp_capabilities')

    def test_cleanup_wait_failure_still_removes_but_cannot_pass(self):
        scope = Scope(wait_fails=True)
        report = dict(status=B.PASS)
        B.cleanup_owned(scope, report, B.time.monotonic() + 30)
        self.assertEqual([row[1:3] for row in scope.calls], [['wait', scope.cid], ['container', 'rm']])
        self.assertTrue(report['owned_container_absence_verified'])
        self.assertEqual(B.finish_status(report, []), 'HOLD_CLEANUP_OR_CANCELLED')

    def test_ambiguous_custody_refuses_cleanup_mutation(self):
        scope = Scope(ambiguous=True)
        report = dict(status=B.PASS)
        B.cleanup_owned(scope, report, B.time.monotonic() + 30)
        self.assertEqual(scope.calls, [])
        self.assertNotIn('owned_container_absence_verified', report)
        self.assertEqual(B.finish_status(report, []), 'HOLD_CLEANUP_OR_CANCELLED')

    def test_quota_failure_is_sticky_and_cleanup_keeps_observing(self):
        reads = []
        def refusal():
            reads.append(True)
            raise ValueError('modeled unknown/exhausted quota')
        watcher = B.LiveGuard(refusal)
        with self.assertRaises(ValueError): watcher.check()
        watcher.poll(cleanup=True)
        watcher.poll(cleanup=True)
        self.assertEqual(reads, [True, True, True])
        self.assertEqual(len(watcher.errors), 1)

    def test_initial_quota_refusal_prevents_monitor_or_daemon_start(self):
        def refusal(): raise ValueError('modeled initial resource refusal')
        watcher = B.LiveGuard(refusal)
        with self.assertRaises(ValueError): watcher.__enter__()
        self.assertEqual(len(watcher.errors), 1)

    def test_cancelled_or_missing_absence_cannot_pass(self):
        self.assertEqual(B.finish_status(dict(status=B.PASS, owned_container_absence_verified=True), [15]),
                         'HOLD_CLEANUP_OR_CANCELLED')
        self.assertEqual(B.finish_status(dict(status=B.PASS), []), 'HOLD_CLEANUP_OR_CANCELLED')

    def test_exact_container_policy_and_host_credentials_never_mounted(self):
        image, name, labels = 'sha256:' + 'a' * 64, 'SYNTHETIC', {'nonce': '2' * 32}
        mounts = {('bind', '/modeled/' + n, '/inputs/' + n, False) for n in
                  ('guest.raw', 'Image', 'kernel.config', 'prepared.json', 'ownership.json', 'input-manifest.json')}
        mounts.update({('bind', '/modeled/code', '/code', False), ('bind', '/modeled/out', '/work', True)})
        row = dict(Id='c' * 64, Name='/' + name, Image=image,
            Config=dict(Labels=labels.copy(), User='0:0', Entrypoint=['/usr/bin/python3'], Cmd=['-I', '-B', '/code/vm_actor.py']),
            Mounts=[dict(Type=t, Source=s, Destination=d, RW=rw) for t, s, d, rw in mounts],
            HostConfig=dict(ReadonlyRootfs=True, NetworkMode='none', CapDrop=['ALL'], CapAdd=[],
                Privileged=False, Devices=[], Init=False, SecurityOpt=['no-new-privileges'],
                Memory=limits()['owner_memory_bytes'], MemorySwap=limits()['owner_memory_bytes'],
                NanoCpus=limits()['cpus'] * 1000000000, PidsLimit=limits()['pids']))
        B.container_policy(row, name, image, labels, mounts, limits())
        for kind in ('credentials', 'user', 'cap', 'memory', 'label'):
            changed = copy.deepcopy(row)
            if kind == 'credentials': changed['Mounts'].append(dict(Type='bind', Source='/secret/credentials.json', Destination='/inputs/credentials.json', RW=False))
            elif kind == 'user': changed['Config']['User'] = '1000:1000'
            elif kind == 'cap': changed['HostConfig']['CapAdd'] = ['CAP_CHOWN']
            elif kind == 'memory': changed['HostConfig']['Memory'] += 1
            else: changed['Config']['Labels']['nonce'] = '3' * 32
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                B.container_policy(changed, name, image, labels, mounts, limits())

    def test_qemu_dynamic_resources_and_fixed_no_network_tcg(self):
        argv = V.qemu_argv(dict(baseline_nonce='1' * 32, nonce='2' * 32), 1800000000, limits())
        self.assertEqual(argv[argv.index('-smp') + 1], '3')
        self.assertEqual(argv[argv.index('-m') + 1], '768')
        self.assertEqual(argv[argv.index('-nic') + 1], 'none')
        self.assertEqual(argv[argv.index('-accel') + 1], 'tcg,thread=multi')
        self.assertIn('arm16k_llvm23_vm_nonce=' + '2' * 32, argv[argv.index('-append') + 1])
        self.assertNotIn('/dev/kvm', repr(argv))

    def test_actual_domain_uid_mapping_capabilities_and_interface_refusals(self):
        status = dict.fromkeys(('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb'), '0')
        status['NoNewPrivs'] = '1'
        V.domain(status, {'lo'}, '0 1000 1\n', 1000)
        V.domain(status, {'lo'}, '0 1000 1\n1 100000 65536\n', 1000)
        for s, interfaces, uid_map, kvm in (
                (status | dict(CapBnd='1'), {'lo'}, '0 1000 1', False),
                (status, {'lo', 'eth0'}, '0 1000 1', False),
                (status, {'lo'}, '0 1001 1', False),
                (status, {'lo'}, '0 1000 65536', False),
                (status, {'lo'}, '0 1000 1', True)):
            with self.subTest(uid_map=uid_map, kvm=kvm), self.assertRaises(ValueError):
                V.domain(s, interfaces, uid_map, 1000, kvm)

    def actor(self, natural):
        state, commands, postboot = {}, [], []
        work = MemoryPath(state)
        row = dict(passed=True, signals=[] if natural else ['SIGKILL'])
        K = SimpleNamespace(OP='SYNTHETIC', canonical=lambda value: (json.dumps(value, sort_keys=True, indent=2) + '\n').encode())
        def command(argv, out, label, **options):
            commands.append((label, argv, options))
            if label == 'qemu': state['work/qemu.json'] = b'SYNTHETIC'
        R = SimpleNamespace(command=command, natural=lambda value: value['passed'] and not value['signals'])
        def proof(*args):
            postboot.append(True)
            return dict(status='PASS_COMPLETE_LLVM23_POSTBOOT_PRESERVATION')
        ops = SimpleNamespace(modules=lambda: (K, R, None, None, None),
                              guard=lambda *args: lambda: None, receipt=lambda path: row.copy(), postboot=proof)
        ctx = dict(limits=limits(), deadline=100, nonce='2' * 32, source_lock={'SYNTHETIC': True})
        epoch = dict(deadline_monotonic=100, nonce=ctx['nonce'], utc_ns=1800000000 * 10**9)
        previous_time, previous_resource = V.time, V.resource
        V.time = SimpleNamespace(monotonic=lambda: 10, time_ns=lambda: epoch['utc_ns'])
        V.resource = SimpleNamespace(RLIMIT_CORE=4, setrlimit=lambda *args: None)
        try:
            result = V.run(ctx, dict(nonce=ctx['nonce'], baseline_nonce='1' * 32), epoch, work, ops)
            with self.assertRaises(ValueError):
                V.run(ctx, dict(nonce=ctx['nonce'], baseline_nonce='1' * 32), epoch, work, ops)
        finally:
            V.time, V.resource = previous_time, previous_resource
        self.assertEqual([item[0] for item in commands], ['overlay-create', 'qemu'])
        self.assertEqual(commands[1][2]['child_file_size_cap'], limits()['overlay_cap_bytes'])
        return result, postboot

    def test_actor_forced_retirement_is_hold_without_postboot_or_retry(self):
        result, postboot = self.actor(False)
        self.assertEqual(result, 1)
        self.assertEqual(postboot, [])

    def test_actor_natural_retirement_can_reach_passive_postboot_once(self):
        result, postboot = self.actor(True)
        self.assertEqual(result, 0)
        self.assertEqual(postboot, [True])


if __name__ == '__main__':
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(BootTests))
    raise SystemExit(not result.wasSuccessful())
