#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Explicit Source310 DATA and real local socketpairs; no QEMU or guest simulation claim."""
import argparse
import ast
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ARGS = None


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


P = module('qmp_observation_proposal', HERE / 'proposal.py')
OBS = module('qmp_observation_functions', HERE / 'observations.py')


class K:
    @staticmethod
    def need(ok, why):
        if not ok: raise ValueError(why)
    @staticmethod
    def canonical(value): return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    @staticmethod
    def ordinary(path):
        path = Path(path)
        K.need(path.is_absolute() and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary path')
        return path


class ProposalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.controller = (ARGS.source / 'controller.py').read_bytes()
        cls.original = (ARGS.source / 'hold_cleanup.py').read_bytes()
        cls.result = P.transform(cls.controller, cls.original)
        cls.temporary = tempfile.TemporaryDirectory(prefix='qmp-public-DATA-')
        cls.addClassCleanup(cls.temporary.cleanup)
        root = Path(cls.temporary.name)
        for name, body in cls.result.items(): (root / name).write_bytes(body)
        cls.new = module('qmp_public_new_helper', root / 'hold_cleanup.py')
        cls.old = module('qmp_public_old_helper', ARGS.source / 'hold_cleanup.py')

    def wires(self, helper, payload, *, answer=True, fragments=False):
        client, server = socket.socketpair()
        self.addCleanup(server.close); self.addCleanup(client.close)
        client.settimeout(2); stream = client.makefile('rwb', buffering=0); self.addCleanup(stream.close)
        peer = types.SimpleNamespace(stream=client, fd=client.fileno())
        captured = []
        def respond():
            server.settimeout(.5); request = bytearray()
            while not request.endswith(b'\n'):
                request.extend(server.recv(128))
            captured.append(bytes(request))
            if answer:
                if fragments:
                    for part in payload: server.sendall(bytes([part]))
                else: server.sendall(payload)
        worker = threading.Thread(target=respond)
        worker.start()
        progress = {}
        try:
            helper.quit_hold_qmp(K, peer, stream, lambda: None, time.monotonic() + .12, progress)
        finally:
            worker.join(.6); self.assertFalse(worker.is_alive())
        self.assertEqual(client.gettimeout(), 2)
        return captured, progress

    def test_source_inverse_and_only_three_proposed_leaves(self):
        self.assertEqual(P.inverse(self.controller, self.original, self.result), (self.controller, self.original))
        self.assertEqual(set(self.result), {'controller.py', 'hold_cleanup.py', 'qmp_observations.py'})
        for name, raw in self.result.items(): compile(raw, name, 'exec')
        wrong = dict(self.result, **{'controller.py': b'wrong'})
        with self.assertRaises(ValueError): P.inverse(self.controller, self.original, wrong)

    def test_changed_input_refused(self):
        with self.assertRaises(ValueError): P.transform(self.controller + b' ', self.original)
        with self.assertRaises(ValueError): P.transform(self.controller, self.original + b' ')

    def test_actual44_byte_request_is_identical_valid_json_real_lf(self):
        requests = []
        for raw in (self.original, self.result['hold_cleanup.py']):
            for node in ast.walk(ast.parse(raw)):
                if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'request' for t in node.targets):
                    requests.append(ast.literal_eval(node.value))
        self.assertEqual(requests[0], requests[1]); self.assertEqual(len(requests[0]), 44)
        self.assertEqual(requests[0][-1:], b'\n')
        self.assertEqual(json.loads(requests[0]), {'execute': 'quit', 'id': 'guest-HOLD-retire'})

    def test_real_socketpair_valid_ack_fragmentation_unchanged(self):
        payload = b'{"event":"STOP"}\r\n{"return":{},"id":"guest-HOLD-retire"}\r\n'
        for helper in (self.old, self.new):
            captured, progress = self.wires(helper, payload, fragments=True)
            self.assertEqual(len(captured[0]), 44); self.assertEqual(progress['stage'], 'ACKNOWLEDGED')

    def test_no_ack_still_times_out_no_deadline_extension(self):
        for helper in (self.old, self.new):
            started = time.monotonic()
            with self.assertRaises(TimeoutError): self.wires(helper, b'', answer=False)
            self.assertLess(time.monotonic() - started, .8)

    def test_error_and_unmatched_ack_still_refuse(self):
        for helper in (self.old, self.new):
            with self.assertRaises(ValueError): self.wires(helper, b'{"error":{},"id":"guest-HOLD-retire"}\n')
            with self.assertRaises(TimeoutError): self.wires(helper, b'{"return":{},"id":"wrong"}\n')

    def test_queue_observation_is_nonconsuming_and_not_exact_delivery_claim(self):
        left, right = socket.socketpair(); self.addCleanup(left.close); self.addCleanup(right.close)
        peer = types.SimpleNamespace(stream=left, fd=left.fileno())
        right.sendall(b'pending')
        before = OBS.transport_observation(peer)
        self.assertEqual(before['input_queued_bytes'], 7)
        self.assertEqual(left.recv(7), b'pending')
        left.sendall(b'x' * 44)
        after = OBS.transport_observation(peer)
        self.assertGreater(after['output_kernel_accounted_bytes'], 0)
        self.assertEqual(right.recv(44), b'x' * 44)
        self.assertIsNone(after['Root_acceptance'])

    def test_observer_failure_cannot_waive_or_mask_transport(self):
        with patch.object(self.new, 'observe_transport', return_value={'status': 'UNAVAILABLE'}):
            _, progress = self.wires(self.new, b'{"return":{},"id":"guest-HOLD-retire"}\n')
            self.assertEqual(progress['stage'], 'ACKNOWLEDGED')
        with patch.object(OBS.fcntl, 'ioctl', side_effect=OSError('model refusal')):
            left, right = socket.socketpair(); self.addCleanup(left.close); self.addCleanup(right.close)
            self.assertEqual(OBS.transport_observation(types.SimpleNamespace(stream=left, fd=left.fileno()))['status'], 'UNAVAILABLE')

    def receipt(self, row):
        owned = tempfile.TemporaryDirectory(prefix='qmp-retirement-DATA-'); self.addCleanup(owned.cleanup)
        root = Path(owned.name); path = root / 'qemu.json'; path.write_bytes(K.canonical(row)); path.chmod(0o600)
        return root, path

    def test_real_wait_status_negative_exit_pin_loss_reproduced_and_fixed(self):
        row = dict(exit=os.waitstatus_to_exitcode(15), passed=False, reaped=True,
                   ownership='REAPED', group_census='EMPTY_TWICE', signals=['SIGTERM'], timeout=True)
        self.assertEqual(row['exit'], -15)
        root, path = self.receipt(row)
        old = self.old.retirement_observation(K, root, 'guest-HOLD-retired.json')['qemu']
        new = self.new.retirement_observation(K, root, 'guest-HOLD-retired.json')['qemu']
        self.assertEqual(old, {'status': 'REFUSED_UNSAFE_OR_INVALID'})
        self.assertEqual(new['file'], P.pin(path.read_bytes())); self.assertEqual(new['observed']['exit'], -15)
        self.assertFalse(new['observed']['passed'])

    def test_group_ownership_failure_states_and_partial_pin_retention(self):
        for ownership, group in (('UNKNOWN', 'UNKNOWN'), ('REAPED', 'RESERVED_MEMBERS_REMAIN')):
            root, path = self.receipt(dict(exit=-9, ownership=ownership, group_census=group, signals=['SIGKILL']))
            old = self.old.retirement_observation(K, root, 'guest-HOLD-retired.json')['qemu']
            new = self.new.retirement_observation(K, root, 'guest-HOLD-retired.json')['qemu']
            self.assertEqual(old['status'], 'REFUSED_UNSAFE_OR_INVALID')
            self.assertEqual(new['observed']['group_census'], group)
            self.assertEqual(new['file'], P.pin(path.read_bytes()))
        root, path = self.receipt(dict(exit='invalid-not-exported'))
        partial = self.new.retirement_observation(K, root, 'guest-HOLD-retired.json')['qemu']
        self.assertEqual(partial['status'], 'REFUSED_UNSAFE_OR_INVALID')
        self.assertEqual(partial['file'], P.pin(path.read_bytes()))
        self.assertNotIn('invalid-not-exported', json.dumps(partial))

    def test_before_after_journal_retains_prior_pin_if_file_disappears(self):
        root, path = self.receipt(dict(exit=-15, ownership='REAPED', group_census='EMPTY_TWICE'))
        report = {'status': 'HOLD', 'failure': {'category': 'GuestHold'}}
        OBS.retirement_journal(K, root, 'guest-HOLD-retired.json', 'BEFORE_FORCED_FALLBACK', report, self.new.retirement_observation)
        expected = P.pin(path.read_bytes()); path.unlink()
        OBS.retirement_journal(K, root, 'guest-HOLD-retired.json', 'AFTER_OWNED_CLEANUP', report, self.new.retirement_observation)
        journal = report['retirement_observation_journal']
        self.assertEqual(journal[0]['observation']['qemu']['file'], expected)
        self.assertEqual(journal[1]['observation']['qemu']['status'], 'ABSENT')
        self.assertEqual(report['status'], 'HOLD')
        self.assertEqual(report['failure'], {'category': 'GuestHold'})
        OBS.retirement_journal(K, root, 'guest-HOLD-retired.json', 'AFTER_OWNED_CLEANUP', report, self.new.retirement_observation)
        self.assertEqual(len(journal), 2)

    def test_absence_or_unsafe_receipt_never_fabricates_retirement(self):
        owned = tempfile.TemporaryDirectory(); self.addCleanup(owned.cleanup); root = Path(owned.name)
        absent = self.new.retirement_observation(K, root, 'guest-HOLD-retired.json')
        self.assertEqual(absent['qemu']['status'], 'ABSENT'); self.assertIsNone(absent['VM_acceptance'])
        (root / 'qemu.json').symlink_to('/proc/self/stat')
        self.assertEqual(self.new.retirement_observation(K, root, 'guest-HOLD-retired.json')['qemu']['status'], 'REFUSED_UNSAFE_OR_INVALID')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--source', type=Path, required=True)
    ARGS, remaining = parser.parse_known_args()
    unittest.main(argv=[__file__, *remaining])
