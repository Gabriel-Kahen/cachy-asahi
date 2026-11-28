#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Explicit Root-gated LLVM23 software VM controller; inert on import."""
import argparse
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
PASS = 'PASS_EMULATED_ARM16K_LLVM23_LIFECYCLE_ONLY'


def load(name):
    spec = importlib.util.spec_from_file_location('llvm23_boot_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def need(value, message):
    if not value:
        raise ValueError(message)


def resources(limits):
    names = ('cpus', 'pids', 'guest_memory_bytes', 'owner_memory_bytes', 'boot_seconds',
             'cleanup_seconds', 'overlay_cap_bytes', 'readback_allocated_cap_bytes',
             'logs_cap_bytes', 'reserve_bytes', 'clone_allocated_cap_bytes')
    need(all(type(limits.get(k)) is int and limits[k] > 0 for k in names),
         'complete positive actual Root VM resource limits required')
    need(limits['guest_memory_bytes'] % 1024**2 == 0 and
         limits['owner_memory_bytes'] >= limits['guest_memory_bytes'] and
         limits['overlay_cap_bytes'] <= 1024**3,
         'exact MiB guest memory and runtime overlay hard ceiling required')
    return limits


class LiveGuard:
    """Cooperative guard: no thread may coexist with preexec_fn child setup."""
    def __init__(self, guard):
        self.guard = guard
        self.errors = []

    def poll(self, cleanup=False):
        try:
            self.guard()
        except BaseException as error:
            if not self.errors:
                self.errors.append(error)
        if self.errors and not cleanup:
            raise ValueError('live Root resource guard failed') from self.errors[0]

    def check(self):
        self.poll()

    def __enter__(self):
        self.check()
        return self

    def __exit__(self, *_):
        return None


class GuardedSocket:
    """Deadline/quota polling around each partial local socket read or write."""
    def __init__(self, raw, deadline, guard, clock=time.monotonic):
        self.raw, self.deadline, self.guard, self.clock = raw, deadline, guard, clock

    def tick(self):
        self.guard()
        left = self.deadline - self.clock()
        need(left > 0, 'finite owned socket deadline')
        self.raw.settimeout(min(.5, left))

    def settimeout(self, _):
        self.tick()

    def recv(self, size):
        while True:
            self.tick()
            try:
                return self.raw.recv(size)
            except socket.timeout:
                pass

    def sendall(self, data):
        view = memoryview(data)
        while view:
            self.tick()
            try:
                sent = self.raw.send(view)
            except socket.timeout:
                continue
            need(sent > 0, 'owned socket closed during partial write')
            view = view[sent:]

    def close(self):
        self.raw.close()


class LineStream:
    """Bounded QMP lines; cooperative reads avoid makefile timeout buffering."""
    def __init__(self, stream):
        self.stream, self.buffer = stream, b''

    def readline(self, cap):
        while b'\n' not in self.buffer and len(self.buffer) < cap:
            part = self.stream.recv(min(4096, cap - len(self.buffer)))
            if not part:
                break
            self.buffer += part
        end = self.buffer.find(b'\n')
        count = min(cap, end + 1 if end >= 0 else len(self.buffer))
        result, self.buffer = self.buffer[:count], self.buffer[count:]
        return result

    def write(self, data):
        self.stream.sendall(data)
        return len(data)

    def close(self):
        self.stream.close()


def unique(rows):
    value = {}
    for key, item in rows:
        need(key not in value, 'duplicate QMP JSON key')
        value[key] = item
    return value


class QMP:
    """Exactly one capabilities call and one quit; no retry or other commands."""
    def __init__(self, stream, deadline, guard, clock=time.monotonic):
        self.stream, self.deadline, self.guard, self.clock = stream, deadline, guard, clock
        self.calls = []

    def receive(self):
        self.guard()
        need(self.clock() < self.deadline, 'finite QMP reply deadline')
        line = self.stream.readline(65537)
        need(0 < len(line) <= 65536 and line.endswith(b'\n'), 'bounded complete QMP reply required')
        row = json.loads(line, object_pairs_hook=unique)
        need(type(row) is dict, 'QMP object required')
        self.guard()
        return row

    def greeting(self):
        need(set(self.receive()) == {'QMP'}, 'actual QMP greeting required')

    def rpc(self, method):
        self.guard()
        need(self.clock() < self.deadline, 'finite QMP request deadline')
        need((method == 'qmp_capabilities' and not self.calls) or
             (method == 'quit' and self.calls == ['qmp_capabilities']),
             'fixed once-only QMP capabilities then quit required')
        self.calls.append(method)
        identity = 'llvm23-' + str(len(self.calls))
        payload = json.dumps(dict(execute=method, id=identity)).encode() + b'\n'
        need(self.stream.write(payload) == len(payload), 'partial QMP request refused without retry')
        for _ in range(64):
            row = self.receive()
            if row.get('id') == identity:
                need(set(row) == {'return', 'id'} and row['return'] == {},
                     'exact successful matching QMP reply required')
                return
            need('event' in row and 'id' not in row and 'error' not in row,
                 'unmatched or ambiguous QMP response refused')
        raise ValueError('bounded matching QMP response absent')


def container_policy(row, name, image, labels, mounts, limits):
    need(re.fullmatch('[0-9a-f]{64}', row.get('Id', '')) and row['Name'] == '/' + name and
         row['Image'] == image and row['Config']['Labels'] == labels and
         row['Config']['Entrypoint'] == ['/usr/bin/python3'] and
         row['Config']['User'] == '0:0' and
         row['Config']['Cmd'] == ['-I', '-B', '/code/vm_actor.py'], 'exact owned VM actor identity')
    need(len(row['Mounts']) == len(mounts) and {(m['Type'], m['Source'], m['Destination'], m['RW'])
         for m in row['Mounts']} == mounts, 'exact public readonly files/code and owned work mounts')
    h = row['HostConfig']
    need(h['ReadonlyRootfs'] is True and h['NetworkMode'] == 'none' and h['CapDrop'] == ['ALL']
         and not h.get('CapAdd') and h['Privileged'] is False and not h['Devices']
         and h['Init'] is False and h['SecurityOpt'] == ['no-new-privileges']
         and h['Memory'] == h['MemorySwap'] == limits['owner_memory_bytes']
         and h['NanoCpus'] == limits['cpus'] * 1000000000 and h['PidsLimit'] == limits['pids'],
         'actual Root resource/cap0/NNP/no-network container policy required')


def finish_status(report, pending):
    if pending or report.get('cleanup_errors') or not report.get('owned_container_absence_verified'):
        report['status'] = 'HOLD_CLEANUP_OR_CANCELLED'
    return report['status']


def publish_report(out, report, state):
    with ExitStack() as files:
        try:
            stage = Path(files.enter_context(tempfile.TemporaryDirectory(dir=out))) / 'report.json'
            finish_status(report, [])
            stage.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        finally:
            state.__exit__()
        # The deferred handler covered staging. Publish only the settled verdict.
        if state.pending:
            report['cancelled_signals'] = list(state.pending)
            finish_status(report, state.pending)
            stage.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        stage.replace(out / 'report.json')


def cleanup_owned(scope, report, deadline):
    """A custody failure refuses destruction; a wait failure cannot skip cleanup."""
    if not scope.submitted:
        report['owned_container_absence_verified'] = True
        return
    errors = report.setdefault('cleanup_errors', [])
    try:
        row = scope.recover(deadline)
    except BaseException as error:
        errors.append(dict(step='ownership-recovery', category=type(error).__name__))
        return
    if row is None:
        report['owned_container_absence_verified'] = True
        return
    report['cleanup_ownership_verified'] = True
    for step, argv in (
            ('owned-wait', ['docker', 'wait', scope.cid]),
            ('owned-remove', ['docker', 'container', 'rm', '--force', scope.cid])):
        try:
            # Divide only the remaining Root-issued cleanup envelope. A failed
            # wait retains time for ownership-checked disposal and absence proof.
            until = time.monotonic() + (deadline - time.monotonic()) / (3 if step == 'owned-wait' else 2)
            result = scope.call(argv, until)
            need(result.returncode == 0, 'owned cleanup command failed')
        except BaseException as error:
            errors.append(dict(step=step, category=type(error).__name__))
    try:
        need(scope.listing(deadline) is None, 'owned container remains after removal')
        report['owned_container_absence_verified'] = True
    except BaseException as error:
        errors.append(dict(step='absence-check', category=type(error).__name__))


def prepared_binding(args, ctx, K, receipt):
    source = K.ordinary(args.prepared)
    out = K.ordinary(args.output)
    need(source != out and source not in out.parents and out not in source.parents,
         'disjoint immutable prepared input and fresh output required')
    pin = K.pin(source / 'prepared.json')
    need(pin['sha256'] == args.prepared_sha256 and ctx['authority']['allow_boot'] is True
         and ctx['authority']['prepared'] == pin, 'Root must select exact prepared clone and boot')
    m = K.load(source / 'prepared.json')
    need(m['status'] == 'PREPARED_LLVM23_IMAGE_NOT_BOOTED' and m['operation'] == K.OP
         and m['source_lock'] == ctx['source_lock'] and m['case'] == ctx['case']
         and m['certs'] == ctx['certs'] and m['limits'] == ctx['limits']
         and m['kernel'] == ctx['kernel'] and m['tool'] == ctx['tool']
         and m['packet'] == K.pin(Path(ctx['paths']['packet']) / 'case-packet.json')
         and m['base_files'] == ctx['base']['files']
         and m['baseline_nonce'] == ctx['base']['nonce'] and m['nonce'] == ctx['nonce']
         and re.fullmatch('[0-9a-f]{32}', m['nonce']) and m['nonce'] != m['baseline_nonce'],
         'exact Root prepared LLVM image lineage required')
    need(set(m['files']) == {'guest.raw', 'Image', 'kernel.config'}, 'closed prepared file membership')
    for name, expected in m['files'].items():
        need(K.pin(source / name, ctx['limits']['prepared_raw_bytes']) == expected,
             'complete prepared input bytes changed')
    need(m['files']['Image'] == ctx['kernel']['files']['Image'] and
         m['files']['kernel.config'] == ctx['kernel']['files']['config'] and
         m['files']['guest.raw']['bytes'] == ctx['limits']['prepared_raw_bytes'],
         'exact Root RTC kernel and prepared raw geometry')
    need(K.pin(source / 'ownership.json', 64 * 1024**2) == m['ownership'],
         'immutable Source111 ownership baseline required')
    need(K.pin(source / 'credentials.json', 4096) == ctx['authority']['credentials'],
         'exact Root-selected original PAM credentials required')
    info = (source / 'credentials.json').lstat()
    need(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
         'private owner-only baseline PAM credentials')
    secret = receipt(source / 'credentials.json', 4096)
    need(secret['username'] == 'builder' and
         re.fullmatch('[A-Za-z0-9_-]{24,128}', secret['password']), 'literal private baseline login')
    return source, out, m, secret, pin


def run(args, ctx, ops):
    K, R, B, O, D = ops.modules()
    limits = resources(ctx['limits'])
    source, out, prepared, secret, prepared_pin = prepared_binding(args, ctx, K, ops.receipt)
    need(not out.exists() and not out.is_symlink(), 'fresh output required')
    os.umask(0o077)
    out.mkdir(mode=0o700)
    deadline = int(ctx['deadline'])
    ctx['deadline'] = deadline
    ctx['final_deadline'] = int(ctx['final_deadline'])
    ctx['prepared_pin'] = prepared_pin
    ctx['active_deadline'] = deadline
    ops.END = deadline
    # Both files use exclusive creation. An ambiguous earlier attempt is HOLD,
    # never grounds for another create/start or rewriting its actor authority.
    with (source / 'llvm23-attempt.json').open('x') as stream:
        stream.write(K.canonical(dict(operation=K.OP, nonce=prepared['nonce'], prepared=prepared_pin,
                                     authority=ctx['authority'])).decode())
    with (source / 'input-manifest.json').open('x') as stream:
        stream.write(K.canonical(dict(ctx=ctx, phase='boot', deadline=deadline,
                                     prepared_pin=prepared_pin)).decode())
    report = dict(status='HOLD', operation=K.OP, native16K='UNQUALIFIED', M2='UNQUALIFIED',
                  performance='NOT_MEASURED', release='UNQUALIFIED', Root_acceptance=None,
                  guest_shutdown='NOT_QUALIFIED_QMP_QUIT_ONLY', nonce=prepared['nonce'])
    scope = serial = qmp_socket = qfile = stream = None
    state = B.Cancellation()
    route = R.transport(ctx['authority'], deadline=ctx['deadline'])
    entered = False
    sequence = 0
    watcher = LiveGuard(ops.guard(ctx, out))
    previous_live_guard = getattr(R, 'LIVE_GUARD', None)
    R.LIVE_GUARD = lambda: watcher.poll(cleanup=state.cleaning)

    def command(label, argv, *, completed=False, check=True, until=None, cleanup=False):
        if not cleanup:
            watcher.check()
        end = ctx['active_deadline'] if until is None else min(until, ctx['active_deadline'])
        watched = {} if cleanup else dict(
                           watched_tree=(out, sum(limits[n] for n in
                               ('overlay_cap_bytes', 'readback_allocated_cap_bytes', 'logs_cap_bytes')),
                               limits['reserve_bytes']),
                           watched_paths=((out / 'overlay.qcow2', limits['overlay_cap_bytes']),
                                          (out / 'verification.raw', limits['readback_allocated_cap_bytes'])))
        result = R.command(argv, out, label, seconds=end - time.monotonic(), deadline=end,
                           completed=completed, check=check, defer_cancel=cleanup, **watched)
        if not cleanup:
            watcher.check()
        return result

    state.__enter__()
    try:
        watcher.__enter__()  # Initial actual readonly quota check precedes daemon access.
        route.__enter__()
        entered = True
        need('name=rootless' in json.loads(command('rootless', ['docker', 'info', '--format', '{{json .SecurityOptions}}'])),
             'qualified actual local rootless daemon required')
        image = ctx['tool']['image_id']
        need(re.fullmatch('sha256:[0-9a-f]{64}', image), 'actual exact tool image ID required')
        images = json.loads(command('image', ['docker', 'image', 'inspect', image]))
        need(len(images) == 1 and images[0]['Id'] == image, 'selected immutable tool image required')
        name = 'cachy-llvm23-16k-' + secrets.token_hex(12)
        labels = dict(images[0]['Config'].get('Labels') or {})
        labels.update({'org.cachy-asahi.llvm23-owner': str(os.getuid()),
                       'org.cachy-asahi.llvm23-nonce': prepared['nonce'],
                       'org.cachy-asahi.llvm23-prepared': args.prepared_sha256})
        # Host-only PAM credentials are never mounted into the VM owner. The
        # exact public DATA file membership excludes credentials.json entirely.
        mounts = {('bind', str(source / filename), '/inputs/' + filename, False)
                  for filename in ('guest.raw', 'Image', 'kernel.config', 'prepared.json',
                                   'ownership.json', 'input-manifest.json')}
        mounts.update({('bind', str(HERE), '/code', False), ('bind', str(out), '/work', True)})

        class Scope(B.OwnedContainer):
            def call(self, argv, until):
                nonlocal sequence
                sequence += 1
                return command('owned-docker-' + str(sequence), argv, completed=True, check=False,
                               until=until, cleanup=state.cleaning)

            def validate(self, row):
                container_policy(row, name, image, labels, mounts, limits)

        scope = Scope(name, out / 'container.cid', image, labels, source, out)
        need(scope.listing(deadline) is None, 'fresh owned name required')
        epoch = dict(nonce=prepared['nonce'], utc_ns=time.time_ns(),
                     monotonic_ns=time.monotonic_ns(), deadline_monotonic=deadline)
        (out / 'host-epoch.json').write_bytes(K.canonical(epoch))
        argv = ['docker', 'create', '--cidfile', str(scope.cidfile), '--name', name, '--init=false',
                '--pull=never', '--read-only', '--network=none', '--user=0:0', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--cpus=' + str(limits['cpus']),
                '--memory=' + str(limits['owner_memory_bytes']), '--memory-swap=' + str(limits['owner_memory_bytes']),
                '--pids-limit=' + str(limits['pids']), '--tmpfs',
                '/tmp:rw,nodev,nosuid,noexec,size=' + str(limits['logs_cap_bytes'])]
        for key, value in sorted(labels.items()):
            argv += ['--label', key + '=' + value]
        for kind, src, target, rw in sorted(mounts):
            argv += ['--mount', 'type=' + kind + ',source=' + src + ',target=' + target + ('' if rw else ',readonly')]
        argv += ['--env', 'CACHY_LLVM23_VM_BOOT=1', '--entrypoint', '/usr/bin/python3',
                 image, '-I', '-B', '/code/vm_actor.py']
        scope.submitted = True
        command('create', argv)
        observed = scope.recover(deadline)
        report['container_id'] = observed['Id']
        report['runtime'] = observed['HostConfig']
        command('start', ['docker', 'start', name])
        with tempfile.TemporaryDirectory(prefix='llvm23-sockets-') as short:
            link = Path(short) / 'out'
            link.symlink_to(out, target_is_directory=True)
            for node in ('serial.sock', 'qmp.sock'):
                while not (out / node).exists():
                    watcher.check()
                    need(time.monotonic() < deadline, 'finite owned socket startup')
                    time.sleep(.05)
                info = (out / node).lstat()
                need(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid(), 'owned VM Unix socket required')
            qmp_socket = socket.socket(socket.AF_UNIX)
            qmp_socket.settimeout(min(.5, deadline - time.monotonic()))
            qmp_socket.connect(str(link / 'qmp.sock'))
            qfile = LineStream(GuardedSocket(qmp_socket, deadline, watcher.check))
            qmp = QMP(qfile, deadline, watcher.check)
            qmp.greeting()
            qmp.rpc('qmp_capabilities')
            stream = socket.socket(socket.AF_UNIX)
            stream.settimeout(min(.5, deadline - time.monotonic()))
            stream.connect(str(link / 'serial.sock'))
            stream = GuardedSocket(stream, deadline, watcher.check)
            serial = B.Serial(stream, deadline)
            P = ops.load('protocol')
            report.update(P.journey(serial, secret['password'], prepared['baseline_nonce'],
                                    prepared['nonce'], B.parse_frame))
            watcher.check()
            qmp.rpc('quit')
            report['QMP_quit_requested'] = True
        command('normal-container-wait', ['docker', 'wait', name])
        finished = scope.recover(deadline)
        need(finished['State']['ExitCode'] == 0 and finished['State']['OOMKilled'] is False
             and finished['State']['Running'] is False, 'natural zero-exit owner completion')
        retirement = ops.receipt(out / 'qemu-retirement.json')
        need(R.natural(retirement) and not retirement.get('actor_cancelled'), 'natural signal-free QEMU reap required')
        report['QEMU_retirement'] = retirement
        preservation = ops.receipt(out / 'postboot-preservation.json')
        need(preservation['status'] == 'PASS_COMPLETE_LLVM23_POSTBOOT_PRESERVATION'
             and preservation['nonce'] == prepared['nonce'] and preservation['source_lock'] == ctx['source_lock']
             and preservation['ownership'] == prepared['ownership']
             and all(preservation.get(k) is True for k in ('all111_unchanged', 'PAM_boot_unchanged', 'fixture_unchanged', 'prefix_absent')),
             'complete baseline111/PAM/fixture/removal preservation required')
        results = out / 'guest-results'
        baseline_sha = hashlib.sha256(''.join(name + ' ' + version + '\n' for name, version in
            sorted(ctx['certs']['baseline_certificate']['inventory'].items())).encode()).hexdigest()
        report['outputs'] = ops.load('proof').outputs(results, report['restored'],
            baseline_sha, epoch['utc_ns'] // 10**9,
            int(time.time()), limits['guest_output_cap_bytes'], prepared['nonce'])
        report['postboot_preservation'] = preservation
        need(K.pin(source / 'prepared.json') == prepared_pin, 'prepared manifest changed during boot')
        for filename, expected in prepared['files'].items():
            need(K.pin(source / filename, limits['prepared_raw_bytes']) == expected, 'readonly prepared bytes changed')
        ops.recheck(ctx)
        watcher.check()
        report['status'] = PASS
    except BaseException as error:
        report['failure'] = dict(category=type(error).__name__, message=str(error)[:1024])
    finally:
        state.cleaning = True
        ctx['active_deadline'] = ctx['final_deadline']
        ops.END = ctx['active_deadline']
        for label, handle in (('serial', stream), ('qmp-file', qfile), ('qmp-socket', qmp_socket)):
            try:
                if handle is not None:
                    handle.close()
            except BaseException as error:
                report.setdefault('cleanup_errors', []).append(dict(step=label, category=type(error).__name__))
        try:
            if scope is not None:
                cleanup_owned(scope, report, ctx['active_deadline'])
            else:
                report['owned_container_absence_verified'] = True
            if serial is not None:
                (out / 'serial.redacted.log').write_bytes(bytes(serial.data).replace(
                    secret['password'].encode(), b'[REDACTED TEST PASSWORD]'))
            watcher.check()
        except BaseException as error:
            report.setdefault('cleanup_errors', []).append(dict(step='guard-or-receipt', category=type(error).__name__))
        finally:
            try:
                watcher.__exit__()
            except BaseException as error:
                report.setdefault('cleanup_errors', []).append(dict(step='quota-observer-retirement', category=type(error).__name__))
            R.LIVE_GUARD = previous_live_guard
            try:
                if entered:
                    route.__exit__(None, None, None)
            except BaseException as error:
                report.setdefault('cleanup_errors', []).append(dict(step='transport', category=type(error).__name__))
            publish_report(out, report, state)
    return 0 if report['status'] == PASS else 1


def main():
    ops = load('ops')
    parser = argparse.ArgumentParser(description=__doc__)
    ops.arguments(parser)
    parser.add_argument('--prepared', type=Path, required=True)
    parser.add_argument('--prepared-sha256', required=True)
    parser.add_argument('--allow-boot', action='store_true')
    args = parser.parse_args()
    if not (args.allow_boot and sys.flags.isolated and sys.dont_write_bytecode and __debug__):
        parser.error('explicit Root boot with python -I -B required')
    ctx = ops.preflight(args, 'boot')
    return run(args, ctx, ops)


if __name__ == '__main__':
    raise SystemExit(main())
