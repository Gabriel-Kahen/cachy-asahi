# SPDX-License-Identifier: MIT
import base64
import json
import os
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch

import capture as c


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.end = time.monotonic() + 20
    def frame(self, sequence, previous):
        data = c.encoded({'modeled': True, 'objects': 14 if sequence == 1 else 1})
        return {'schema_version': 1, 'purpose': 'repository-native-checkpoint', 'nonce': 'a' * 32,
                'sequence': sequence, 'phase': c.PHASES[sequence - 1], 'payload': base64.b64encode(data).decode(),
                'payload_sha256': c.digest(data), 'previous_frame_sha256': previous}
    def test_durable_ack_two_frames_and_chain(self):
        state = c.Checkpoints(self.root, 'a' * 32, deadline=self.end)
        calls = []; real = c.os.fsync
        with patch.object(c.os, 'fsync', side_effect=lambda fd: (calls.append(fd), real(fd))[-1]):
            ack = state.receive(self.frame(1, '0' * 64), self.end)
        self.assertEqual(len(calls), 2)
        value = json.loads(ack[len(c.ACK_MARKER):]); self.assertTrue(value['durable_host_digest'])
        self.assertEqual(value['frame_sha256'], c.digest(c.read(self.root / 'checkpoint-1.json').rstrip(b'\n')))
        state.receive(self.frame(2, state.previous), self.end)
        self.assertEqual(len(state.records), 2)
        with self.assertRaises(c.Refused):
            state.receive(self.frame(2, state.previous), self.end)
    def test_directory_fsync_failure_never_acks(self):
        state = c.Checkpoints(self.root, 'a' * 32, deadline=self.end)
        with patch.object(c.os, 'fsync', side_effect=OSError('fault')):
            with self.assertRaises(OSError):
                state.receive(self.frame(1, '0' * 64), self.end)
        self.assertTrue(state.failed); self.assertEqual(state.records, [])
    def test_bad_nonce_chain_or_payload_refuses(self):
        for field, value in [('nonce', 'b' * 32), ('previous_frame_sha256', 'b' * 64),
                             ('payload_sha256', 'c' * 64), ('sequence', True)]:
            with self.subTest(field=field):
                frame = self.frame(1, '0' * 64); frame[field] = value
                state = c.Checkpoints(self.root, 'a' * 32, deadline=self.end)
                with self.assertRaises(c.Refused):
                    state.receive(frame, self.end)
    def test_symlink_hardlink_and_parent_swap_refuse(self):
        source = self.root / 'source'; source.write_bytes(b'fixed')
        link = self.root / 'link'; link.symlink_to(source)
        with self.assertRaises(OSError): c.read(link)
        os.link(source, self.root / 'hard')
        with self.assertRaises(c.Refused): c.read(source)
        with self.assertRaises(c.Refused): c.write_atomic(self.root / 'new', b'x', (0, 0))
    def test_unbuffered_short_write_and_expiry_during_write(self):
        real = c.os.write; calls = []
        def short(fd, data):
            calls.append(len(data)); return real(fd, data[:1])
        with patch.object(c.os, 'write', side_effect=short): c.write_atomic(self.root / 'short', b'abc')
        self.assertEqual(c.read(self.root / 'short'), b'abc'); self.assertEqual(calls, [3, 2, 1])
        now = [1.0]; writes = []
        def cross(fd, data):
            writes.append(now[0]); result = real(fd, data[:1]); now[0] = 3.0; return result
        with patch.object(c.time, 'monotonic', side_effect=lambda: now[0]), patch.object(c.os, 'write', side_effect=cross):
            with self.assertRaises(c.Refused): c.write_atomic(self.root / 'expired', b'abc', deadline=2.0)
        self.assertEqual(writes, [1.0]); self.assertEqual((self.root / 'expired').read_bytes(), b'a')
    def test_explicit_capture_pending_and_private_material_refusal(self):
        source = self.root / 'source'; source.write_bytes(b'actual bytes')
        value = c.capture_files({'raw/source.txt': source}, self.root / 'out', deadline=self.end)
        self.assertEqual(value['status'], 'PENDING'); self.assertEqual(value['native_admission'], 'NOT RUN')
        source.write_bytes(b'-----BEGIN PGP PRIVATE KEY BLOCK-----\n')
        with self.assertRaises(c.Refused): c.capture_files({'raw/source.txt': source}, self.root / 'bad', deadline=self.end)
        with self.assertRaises(c.Refused): c.relative('TEST-revocation.asc')
    def test_real_signal_records_cancel_and_restores_pair(self):
        old = {s: signal.getsignal(s) for s in c.SIGNALS}
        with self.assertRaises(c.Cancelled):
            with c.cancellation() as state:
                os.kill(os.getpid(), signal.SIGTERM)
                with state.defer(): state.check()
                state.check()
        self.assertEqual({s: signal.getsignal(s) for s in c.SIGNALS}, old)
    def test_expired_or_poisoned_deadline_does_no_write(self):
        for deadline in (True, float('nan'), float('inf'), -1.0):
            with self.subTest(deadline=deadline), self.assertRaises(c.Refused):
                c.write_atomic(self.root / 'absent', b'x', deadline=deadline)
            self.assertFalse((self.root / 'absent').exists())
    def test_root_replacement_stops_before_next_capture_write(self):
        first, second = self.root / 'one', self.root / 'two'
        first.write_bytes(b'first'); second.write_bytes(b'second')
        output = self.root / 'out'; real = c.write_atomic
        def replace(path, data, *args, **kwargs):
            result = real(path, data, *args, **kwargs)
            if Path(path).name == 'a':
                output.rename(self.root / 'original')
                output.mkdir(mode=0o700); (output / 'a').write_bytes(data)
            return result
        with patch.object(c, 'write_atomic', side_effect=replace), self.assertRaises(c.Refused):
            c.capture_files({'a': first, 'b': second}, output, deadline=self.end)
        self.assertFalse((output / 'b').exists()); self.assertFalse((output / 'capture.json').exists())
    def test_real_term_during_restoration_is_refusal(self):
        original = signal.getsignal(signal.SIGTERM); calls = []
        old = lambda *args: calls.append(args)
        signal.signal(signal.SIGTERM, old)
        real = signal.signal; sent = []
        def setter(sig, handler):
            result = real(sig, handler)
            if sig == signal.SIGTERM and handler is old and not sent:
                sent.append(True); os.kill(os.getpid(), signal.SIGTERM)
            return result
        try:
            with patch.object(c.signal, 'signal', side_effect=setter), self.assertRaises(c.Cancelled):
                with c.cancellation(): pass
            self.assertEqual(calls, []); self.assertIs(signal.getsignal(signal.SIGTERM), old)
        finally: signal.signal(signal.SIGTERM, original)
    def test_cross_module_host_ack_is_durable_and_not_public(self):
        import producer as p
        import launch as launch
        state = c.Checkpoints(self.root, 'a' * 32, deadline=self.end)
        host = launch.Protocol('a' * 32, state.receive, self.end)
        previous = '0' * 64
        for sequence in (1, 2):
            wire = p.encode_frame({'modeled': True}, 'a' * 32, sequence, previous)
            host.feed(wire[:5]); host.feed(wire[5:])
            parsed = p.parse_frame(wire, nonce='a' * 32, sequence=sequence, previous_frame_sha256=previous)
            p.validate_ack(host.stdin(), parsed)
            previous = parsed['frame_sha256']
        host.feed(b'original public text\n'); host.finish()
        self.assertEqual(bytes(host.plain), b'original public text\n')
        self.assertEqual(len(state.records), 2)


if __name__ == '__main__': unittest.main()
