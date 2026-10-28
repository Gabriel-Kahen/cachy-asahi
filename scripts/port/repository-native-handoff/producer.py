#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Authenticated frozen-worker observer. Checkpoints are observations, not admission.

Only the frozen worker may write /out. This module reads finite original logs,
public certificates and hashes; it never exports a key home, private revocation
certificate or agent. The host must reject every nonzero/cancelled worker even
if its private original terminal receipt was written before cancellation.
"""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import sys
import threading
import time
import types

SOURCE_SHA256 = '49c87f41bbb2fe1288251f16019f12aaeabb98d81ff5339387873e88e903b940'
FRAME_MARKER, ACK_MARKER = b'\x1eRCNH1 ', b'\x1eRCNH1-ACK '
DECODED_LIMIT, WIRE_LIMIT, READ_LIMIT = 4 * 1024**2, 6 * 1024**2, 16 * 1024**2
PHASE_SECONDS = 30
PHASES = {1: 'pre-A-revocation', 2: 'post-public-export'}
FRAME_KEYS = {'schema_version', 'purpose', 'nonce', 'sequence', 'phase', 'payload', 'payload_sha256', 'previous_frame_sha256'}
ACK_KEYS = {'schema_version', 'purpose', 'nonce', 'sequence', 'phase', 'frame_sha256', 'durable_host_digest'}
SIGNALS = {signal.SIGINT, signal.SIGTERM}
PENDING = []
PRIVATE = re.compile(rb'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY|\((?:protected-)?private-key')


class Refused(ValueError):
    pass


class Cancelled(Refused):
    pass


def need(condition, reason):
    if not condition:
        raise Refused(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
    except (TypeError, ValueError, RecursionError):
        raise Refused('checkpoint-json-invalid') from None


def decode(raw):
    need(isinstance(raw, bytes) and 0 < len(raw) <= WIRE_LIMIT, 'checkpoint-json-bound')
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'checkpoint-duplicate-field')
            value[key] = item
        return value
    def invalid(_):
        raise Refused('checkpoint-noninteger-number')
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    except (ValueError, UnicodeError, RecursionError):
        raise Refused('checkpoint-json-invalid') from None
    need(isinstance(value, dict), 'checkpoint-object-required')
    return value


def pin(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def identity(info):
    return tuple(getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path, limit=READ_LIMIT):
    """Bounded stable no-follow read of every ancestor and the final regular file."""
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and type(limit) is int and 0 <= limit <= READ_LIMIT,
         'checkpoint-safe-read-required')
    descriptors, ancestors = [], []
    try:
        descriptors.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        current = Path('/')
        ancestors.append((current, os.fstat(descriptors[-1])))
        for part in path.parts[1:-1]:
            descriptors.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptors[-1]))
            current /= part
            ancestors.append((current, os.fstat(descriptors[-1])))
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=descriptors[-1])
        with os.fdopen(fd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
                 'checkpoint-regular-file-bound')
            raw = stream.read(limit + 1)
            need(len(raw) == before.st_size and identity(before) == identity(os.fstat(stream.fileno()))
                 == identity(os.stat(path.name, dir_fd=descriptors[-1], follow_symlinks=False)), 'checkpoint-read-drift')
        for ancestor, before in ancestors:
            after = ancestor.lstat()
            need((before.st_dev, before.st_ino, before.st_mode) == (after.st_dev, after.st_ino, after.st_mode),
                 'checkpoint-ancestor-drift')
        return raw
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def _line(wire, marker):
    need(isinstance(wire, bytes) and 0 < len(wire) <= WIRE_LIMIT and wire.startswith(marker)
         and wire.endswith(b'\n') and wire.count(b'\n') == 1, 'checkpoint-wire-refused')
    body = wire[len(marker):-1]
    value = decode(body)
    need(canonical(value) == body, 'checkpoint-wire-not-canonical')
    return value, body


def encode_frame(payload, nonce, sequence, previous_frame_sha256='0' * 64):
    need(isinstance(payload, dict) and isinstance(nonce, str) and re.fullmatch('[0-9a-f]{32}', nonce)
         and type(sequence) is int and sequence in PHASES and pin(previous_frame_sha256), 'checkpoint-identity-invalid')
    need(sequence != 1 or previous_frame_sha256 == '0' * 64, 'checkpoint-initial-chain-invalid')
    raw = canonical(payload)
    need(0 < len(raw) <= DECODED_LIMIT and not PRIVATE.search(raw), 'checkpoint-decoded-bound-or-private')
    frame = {'schema_version': 1, 'purpose': 'repository-native-checkpoint', 'nonce': nonce,
             'sequence': sequence, 'phase': PHASES[sequence], 'payload': base64.b64encode(raw).decode(),
             'payload_sha256': digest(raw), 'previous_frame_sha256': previous_frame_sha256}
    wire = FRAME_MARKER + canonical(frame) + b'\n'
    need(len(wire) <= WIRE_LIMIT, 'checkpoint-wire-bound')
    return wire


def parse_frame(wire, *, nonce, sequence, previous_frame_sha256):
    need(isinstance(nonce, str) and re.fullmatch('[0-9a-f]{32}', nonce) and type(sequence) is int
         and sequence in PHASES and pin(previous_frame_sha256), 'checkpoint-identity-invalid')
    frame, body = _line(wire, FRAME_MARKER)
    need(set(frame) == FRAME_KEYS and type(frame['schema_version']) is int and frame['schema_version'] == 1
         and frame['purpose'] == 'repository-native-checkpoint' and frame['nonce'] == nonce
         and type(frame['sequence']) is int and frame['sequence'] == sequence and sequence in PHASES
         and frame['phase'] == PHASES[sequence] and pin(frame['previous_frame_sha256'])
         and frame['previous_frame_sha256'] == previous_frame_sha256 and pin(frame['payload_sha256']),
         'checkpoint-frame-binding-refused')
    need(sequence != 1 or previous_frame_sha256 == '0' * 64, 'checkpoint-initial-chain-invalid')
    try:
        raw = base64.b64decode(frame['payload'], validate=True)
    except (ValueError, TypeError):
        raise Refused('checkpoint-payload-base64-refused') from None
    need(0 < len(raw) <= DECODED_LIMIT and base64.b64encode(raw).decode() == frame['payload']
         and digest(raw) == frame['payload_sha256'] and not PRIVATE.search(raw), 'checkpoint-payload-binding-refused')
    payload = decode(raw)
    need(canonical(payload) == raw, 'checkpoint-payload-not-canonical')
    return {'frame': frame, 'payload': payload, 'frame_sha256': digest(body)}


def frame_digest(wire):
    _, body = _line(wire, FRAME_MARKER)
    return digest(body)


def encode_ack(frame):
    need(isinstance(frame, dict), 'checkpoint-ack-frame-required')
    if 'frame' in frame:
        need(isinstance(frame['frame'], dict) and pin(frame.get('frame_sha256')), 'checkpoint-ack-frame-required')
        frame = {**frame['frame'], 'frame_sha256': frame['frame_sha256']}
    # Host callers supply a verified parsed frame and its durable canonical digest.
    need({'nonce', 'sequence', 'phase', 'frame_sha256'} <= set(frame)
         and isinstance(frame['nonce'], str) and re.fullmatch('[0-9a-f]{32}', frame['nonce'])
         and type(frame['sequence']) is int and frame['sequence'] in PHASES
         and frame['phase'] == PHASES[frame['sequence']] and pin(frame['frame_sha256']),
         'checkpoint-ack-frame-required')
    ack = {'schema_version': 1, 'purpose': 'repository-native-checkpoint-ack', 'nonce': frame['nonce'],
           'sequence': frame['sequence'], 'phase': frame['phase'], 'frame_sha256': frame['frame_sha256'],
           'durable_host_digest': True}
    return ACK_MARKER + canonical(ack) + b'\n'


def validate_ack(wire, parsed):
    ack, _ = _line(wire, ACK_MARKER)
    frame = parsed['frame']
    need(set(ack) == ACK_KEYS and type(ack['schema_version']) is int and ack['schema_version'] == 1
         and ack['purpose'] == 'repository-native-checkpoint-ack' and ack['durable_host_digest'] is True
         and all(ack[key] == frame[key] for key in ('nonce', 'sequence', 'phase'))
         and type(ack['sequence']) is int and ack['frame_sha256'] == parsed['frame_sha256'], 'checkpoint-ack-binding-refused')
    return ack


@contextmanager
def _handlers(handler):
    """Install and restore both handlers while kernel delivery is blocked."""
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    originals = {number: signal.getsignal(number) for number in SIGNALS}
    error = None
    try:
        for number in SIGNALS:
            signal.signal(number, handler)
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
        try:
            for number, original in originals.items():
                for _ in range(2):
                    try:
                        signal.signal(number, original)
                    except BaseException as failure:
                        error = error or failure
                    if signal.getsignal(number) == original:
                        break
                else:
                    error = error or Refused('checkpoint-handler-restoration-refused')
            # Consume transitions before restoring unblocked default dispositions.
            for number in SIGNALS - set(mask):
                while number in signal.sigpending():
                    signal.sigtimedwait({number}, 0)
                    try:
                        handler(number, None)
                    except BaseException as failure:
                        error = error or failure
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        if error is not None:
            raise error


@contextmanager
def cancellation_handlers():
    def stop(number, _):
        raise Cancelled('checkpoint-cancelled-' + str(number))
    with _handlers(stop):
        yield


@contextmanager
def defer_cancellation():
    pending = []
    PENDING.append(pending)
    def remember(number, _):
        pending.append(number)
    try:
        with _handlers(remember):
            yield
    finally:
        PENDING.pop()
        if pending:
            if PENDING:
                PENDING[-1].extend(pending)
            else:
                raise Cancelled('checkpoint-cancelled-after-cleanup')


@contextmanager
def acknowledgement_deadline(deadline):
    need(isinstance(deadline, (int, float)) and not isinstance(deadline, bool) and math.isfinite(deadline)
         and deadline > time.monotonic(), 'checkpoint-deadline-expired')
    mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
    original = signal.getsignal(signal.SIGALRM)
    installed, queued = False, False
    def expired(*_):
        raise Refused('checkpoint-ack-timeout')
    try:
        need(signal.SIGALRM not in mask and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0),
             'checkpoint-caller-alarm-active-or-blocked')
        installed = True
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, max(0.000001, deadline - time.monotonic()))
        signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        yield
        need(time.monotonic() < deadline, 'checkpoint-ack-deadline-exceeded')
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
        try:
            if installed:
                signal.setitimer(signal.ITIMER_REAL, 0)
                failure = None
                try:
                    for _ in range(2):
                        try:
                            signal.signal(signal.SIGALRM, original)
                        except BaseException as error:
                            failure = failure or error
                        if signal.getsignal(signal.SIGALRM) == original:
                            break
                    else:
                        failure = failure or Refused('checkpoint-alarm-restoration-refused')
                    if failure is not None:
                        raise failure
                finally:
                    while signal.SIGALRM in signal.sigpending():
                        signal.sigtimedwait({signal.SIGALRM}, 0)
                        queued = True
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        if queued:
            raise Refused('checkpoint-ack-timeout')


def _blob(raw):
    return {'bytes': len(raw), 'sha256': digest(raw), 'base64': base64.b64encode(raw).decode()}


def _snapshots(integration):
    """Finite top-level original snapshots: hashes only, no copied system bytes."""
    root = integration.out
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        entries = os.listdir(fd)
        need(len(entries) <= 512, 'checkpoint-output-directory-bound')
        result = {}
        for name in entries:
            if name.endswith('-snapshot.json'):
                need(re.fullmatch('[A-Za-z0-9-]+-snapshot.json', name), 'checkpoint-snapshot-name-invalid')
                raw = read(root / name)
                result[name] = {'bytes': len(raw), 'sha256': digest(raw)}
        return result
    finally:
        os.close(fd)


def _original_record(integration, path, role, label, module):
    argv = [str(value) for value in integration.gpg(integration.keys[role]['home']) +
            ['--status-fd', '1', '--verify', str(path) + '.sig', path]]
    matches = [(index, row) for index, row in enumerate(integration.receipts)
               if row.get('label') == label and row.get('argv') == argv]
    need(len(matches) == 1, 'checkpoint-original-verification-not-unique')
    index, row = matches[0]
    need(type(row.get('expected')) is int and row['expected'] == 0 and type(row.get('exit_code')) is int
         and row['exit_code'] == 0 and row.get('log') == f'{index:03d}-{label}.txt'
         and 'stderr_log' not in row and pin(row.get('sha256')), 'checkpoint-original-merged-command-required')
    status = read(integration.out / row['log'], 1024**2)
    need(digest(status) == row['sha256'], 'checkpoint-original-status-drift')
    module.signature_status(status.decode('utf-8', errors='strict'), integration.keys[role]['fingerprint'])
    data, signature = read(path), read(Path(str(path) + '.sig'))
    return {'path': str(path), 'signature': str(path) + '.sig', 'signer': role, 'fingerprint': integration.keys[role]['fingerprint'],
            'data_sha256': digest(data), 'data_bytes': len(data), 'signature_sha256': digest(signature),
            'signature_bytes': len(signature), 'command_index': index, 'receipt': decode(canonical(row)),
            'stream_layout': 'merged-stdout-stderr', 'original_stdout': _blob(status)}


def pre_revocation(integration, module):
    objects = []
    for field, label, role, probe in (('baseline', 'baseline-A', 'signer-A', '1-1'), ('upgrade', 'updated-B', 'signer-B', '2-1')):
        rows = integration.spec[field]
        need(isinstance(rows, list) and len(rows) == 4 and {row.get('name') for row in rows} == module.ORIGINALS,
             'checkpoint-exact-original-inputs-required')
        names = [Path(row.get('archive', row.get('path'))).name for row in rows]
        names += [module.FIXTURE + '-' + probe + '-any.pkg.tar.xz', 'integration.db.tar.gz', 'integration.files.tar.gz']
        need(len(set(names)) == 7 and all(re.fullmatch('[A-Za-z0-9][A-Za-z0-9._+:-]+', name) for name in names),
             'checkpoint-positive-subjects-required')
        for name in sorted(names):
            path = integration.scratch / 'repos' / label / name
            command_label = 'verify-database-' + label if name.startswith('integration.') else 'verify-' + role
            objects.append(_original_record(integration, path, role, command_label, module))
    certificates = {}
    for role in ('signer-A', 'signer-B', 'verifier'):
        raw = read(integration.out / ('TEST-' + role + '-public.asc'), 256 * 1024)
        need(raw.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----') and not PRIVATE.search(raw)
             and digest(raw) == integration.keys[role]['public_sha256'], 'checkpoint-original-public-certificate-refused')
        certificates[role] = {'fingerprint': integration.keys[role]['fingerprint'], 'certificate': _blob(raw)}
    return {'purpose': 'original-pre-revocation-observation', 'source_sha256': SOURCE_SHA256,
            'parsed_spec_sha256': digest(canonical(integration.spec)), 'source_commit': integration.spec['source_commit'],
            'image_id': integration.spec['image_id'], 'objects': sorted(objects, key=lambda row: row['path']),
            'public_certificates': certificates, 'snapshot_sha256': _snapshots(integration),
            'private_key_custody': 'NOT OBSERVED', 'native_admission': 'NOT CLAIMED'}


def post_export(integration, module):
    alias = integration.out / 'TEST-repository-aliases.json'
    observed = _original_record(integration, alias, 'signer-B', 'verify-signer-B', module)
    receipt = decode(canonical(integration.result))
    need(receipt.get('status') == 'RUNNING', 'checkpoint-before-original-terminal-required')
    alias_raw, signature_raw = read(alias), read(Path(str(alias) + '.sig'))
    need(digest(alias_raw) == observed['data_sha256'] and digest(signature_raw) == observed['signature_sha256'],
         'checkpoint-alias-changed-during-capture')
    return {'purpose': 'original-post-public-export-observation', 'source_sha256': SOURCE_SHA256,
            'source_commit': integration.spec['source_commit'], 'image_id': integration.spec['image_id'],
            'alias': {**observed, 'data': _blob(alias_raw), 'signature_data': _blob(signature_raw)},
            'original_precleanup_receipt': receipt, 'snapshot_sha256': _snapshots(integration),
            'private_cleanup': 'NOT YET OBSERVED', 'native_admission': 'NOT CLAIMED'}


class Checkpoints:
    def __init__(self, protocol, nonce, deadline, phase_seconds=PHASE_SECONDS):
        need(isinstance(nonce, str) and re.fullmatch('[0-9a-f]{32}', nonce) and callable(getattr(protocol, 'exchange', None)),
             'checkpoint-protocol-and-nonce-required')
        need(isinstance(deadline, (int, float)) and not isinstance(deadline, bool) and math.isfinite(deadline)
             and deadline > time.monotonic() and isinstance(phase_seconds, (int, float)) and not isinstance(phase_seconds, bool)
             and math.isfinite(phase_seconds) and 0 < phase_seconds <= PHASE_SECONDS, 'checkpoint-finite-deadline-required')
        self.protocol, self.nonce, self.deadline, self.phase_seconds = protocol, nonce, deadline, phase_seconds
        self.sequence, self.previous, self.records = 0, '0' * 64, []

    def emit(self, payload):
        sequence = self.sequence + 1
        need(sequence in PHASES, 'checkpoint-count-exceeded')
        wire = encode_frame(payload, self.nonce, sequence, self.previous)
        parsed = parse_frame(wire, nonce=self.nonce, sequence=sequence, previous_frame_sha256=self.previous)
        deadline = min(self.deadline, time.monotonic() + self.phase_seconds)
        with acknowledgement_deadline(deadline):
            ack = validate_ack(self.protocol.exchange(wire, deadline=deadline), parsed)
        self.sequence, self.previous = sequence, parsed['frame_sha256']
        self.records.append({'nonce': self.nonce, 'sequence': sequence, 'phase': PHASES[sequence],
                             'frame_sha256': self.previous, 'payload_sha256': parsed['frame']['payload_sha256'],
                             'durable_host_digest': ack['durable_host_digest']})


def observer_class(module, checkpoints):
    class ObservedIntegration(module.Integration):
        def __init__(self, spec, observed=None):
            super().__init__(spec, observed)
            need(spec.get('nonce') == checkpoints.nonce and spec.get('script_sha256') == SOURCE_SHA256,
                 'checkpoint-original-spec-binding-refused')

        def command(self, label, argv, **kwargs):
            if label == 'revoke-A-signing-home':
                expected = [str(value) for value in self.gpg(self.keys['signer-A']['home']) +
                            ['--import', self.home / 'TEST-revocation.asc']]
                need(checkpoints.sequence == 0 and [str(value) for value in argv] == expected,
                     'checkpoint-first-revocation-command-required')
                checkpoints.emit(pre_revocation(self, module))
            return super().command(label, argv, **kwargs)

        def export_public_repositories(self):
            need(checkpoints.sequence == 1, 'checkpoint-pre-revocation-ack-required')
            result = super().export_public_repositories()
            checkpoints.emit(post_export(self, module))
            return result

        def cleanup(self):
            with defer_cancellation():
                return super().cleanup()
    return ObservedIntegration


def observe(source_path, protocol, *, nonce, deadline, argv=None, phase_seconds=PHASE_SECONDS):
    """Authenticated original main; controlled caller transports the two frames."""
    need(threading.current_thread() is threading.main_thread(), 'checkpoint-main-thread-required')
    source_path = Path(source_path).absolute()
    raw = read(source_path, 1024**2)
    need(digest(raw) == SOURCE_SHA256, 'checkpoint-frozen-source-pin-refused')
    module = types.ModuleType('authenticated_repository_native_observed')
    module.__file__ = str(source_path)
    exec(compile(raw, str(source_path), 'exec'), module.__dict__)
    checkpoints = Checkpoints(protocol, nonce, deadline, phase_seconds)
    module.Integration = observer_class(module, checkpoints)
    original_argv = sys.argv
    try:
        with cancellation_handlers():
            if argv is not None:
                need(isinstance(argv, (list, tuple)) and all(isinstance(value, str) for value in argv), 'checkpoint-original-argv-required')
                sys.argv = [str(source_path), *argv]
            result = module.main()  # Original guard runs before all worker actions.
            need(checkpoints.sequence == 2 and read(source_path, 1024**2) == raw, 'checkpoint-incomplete-or-source-drift')
        return {'status': 'PASS-observation-only', 'source_sha256': SOURCE_SHA256,
                'checkpoints': checkpoints.records, 'original_return': result, 'native_admission': 'NOT CLAIMED'}
    finally:
        sys.argv = original_argv


class StdioProtocol:
    """Finite byte transport only; the host owns durable checkpoint acceptance."""
    def __init__(self, input_fd=0, output_fd=1):
        need(type(input_fd) is int and type(output_fd) is int and input_fd >= 0 and output_fd >= 0
             and input_fd != output_fd, 'checkpoint-distinct-stdio-fds-required')
        self.input_fd, self.output_fd = input_fd, output_fd

    def exchange(self, wire, *, deadline):
        need(isinstance(wire, bytes) and 0 < len(wire) <= WIRE_LIMIT and deadline > time.monotonic(),
             'checkpoint-stdio-bound-or-deadline')
        originals = {fd: os.get_blocking(fd) for fd in (self.input_fd, self.output_fd)}
        offset, ack = 0, bytearray()
        try:
            with defer_cancellation():
                for fd in originals:
                    os.set_blocking(fd, False)
            with selectors.DefaultSelector() as selector:
                selector.register(self.input_fd, selectors.EVENT_READ, 'input')
                selector.register(self.output_fd, selectors.EVENT_WRITE, 'output')
                while selector.get_map():
                    need(time.monotonic() < deadline, 'checkpoint-stdio-timeout')
                    for key, _ in selector.select(min(0.05, max(0, deadline - time.monotonic()))):
                        if key.data == 'output':
                            try:
                                count = os.write(key.fd, wire[offset:offset + 65536])
                            except BlockingIOError:
                                continue
                            need(count > 0, 'checkpoint-stdio-write-stalled')
                            offset += count
                            if offset == len(wire):
                                selector.unregister(key.fd)
                        else:
                            try:
                                data = os.read(key.fd, min(65536, WIRE_LIMIT + 1 - len(ack)))
                            except BlockingIOError:
                                continue
                            need(data, 'checkpoint-stdio-eof')
                            ack.extend(data)
                            need(len(ack) <= WIRE_LIMIT and ack.count(b'\n') <= 1, 'checkpoint-stdio-ack-bound')
                            if b'\n' in ack:
                                need(ack.endswith(b'\n'), 'checkpoint-stdio-ack-trailing-bytes')
                                selector.unregister(key.fd)
            return bytes(ack)
        finally:
            with defer_cancellation():
                for fd, blocking in originals.items():
                    os.set_blocking(fd, blocking)


def main(argv=None, *, protocol=None):
    """Wrapper-only options are stripped; the original CLI is otherwise intact."""
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--handoff-deadline', required=True, type=float)
    parser.add_argument('--handoff-source', type=Path, default=Path('/runner/repository.py'))
    parser.add_argument('--handoff-phase-seconds', type=float, default=PHASE_SECONDS)
    args, original_args = parser.parse_known_args(argv)
    return observe(args.handoff_source, protocol if protocol is not None else StdioProtocol(),
                   nonce=os.environ.get('CACHY_ASAHI_DISPOSABLE_REPOSITORY', ''), deadline=args.handoff_deadline,
                   argv=original_args, phase_seconds=args.handoff_phase_seconds)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('repository-native observer refused: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
