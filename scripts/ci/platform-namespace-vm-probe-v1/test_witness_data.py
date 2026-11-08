# SPDX-License-Identifier: MIT
"""Actor-denied kernel-witness protocol models, not actual socket/namespace observations."""
import base64
import copy
from pathlib import Path
import socket
import stat
import struct
import sys
import types
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C
import guest as G
import inside as I
import owned_command as O
import witness as W
from test_data import model_report, model_witness, NONCE, RELEASE


def packet(value=None, credentials=(31, 23001, 23001), flags=0):
    value = model_report() if value is None else value
    raw = C.encoded(value['inner_observation']['payload'])
    return raw, [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack('iII', *credentials))], flags, None


class WitnessData(unittest.TestCase):
    def setUp(self):
        for name in ('subprocess.Popen', 'subprocess.run', 'os.execve', 'os.dup2',
                     'socket.socket', 'socket.socketpair', 'ctypes.CDLL'):
            self.enterContext(patch(name, side_effect=AssertionError('WITNESS_DATA_ACTOR_DENIED:' + name)))

    def test_one_and_two_level_parent_maps_need_same_kernel_outer_witness(self):
        for uid, parent in [(0, 23001), (23001, 0)]:
            value = model_report()
            value['inside'].update(uid=uid, euid=uid, gid=uid, egid=uid,
                                   uid_map=[[uid, parent, 1]], gid_map=[[uid, parent, 1]])
            value['inner_observation'] = model_witness(value['inside'], value['before'])
            with self.subTest(uid=uid, parent=parent):
                C.validate_report(value, NONCE, RELEASE)

    def test_immediate_parent_map_alone_never_proves_outer_identity(self):
        value = model_report()
        value['inner_observation'] = None
        with self.assertRaises(ValueError):
            C.validate_report(value, NONCE, RELEASE)

    def test_wrong_uid_gid_or_sender_pid_refuses_even_with_plausible_parent_map(self):
        for field, changed in [('uid', 0), ('gid', 0), ('uid', 65534), ('pid', 33), ('pid', True)]:
            value = model_report()
            value['inner_observation']['credentials'][field] = changed
            with self.subTest(field=field, changed=changed), self.assertRaises(ValueError):
                C.validate_report(value, NONCE, RELEASE)

    def test_forged_nonce_release_context_or_packet_pin_refuses(self):
        for field, changed in [('nonce', 'c' * 32), ('release', 'OTHER'),
                               ('context', dict(model_report()['inside'], pid=999))]:
            value = model_report()
            value['inner_observation']['payload'][field] = changed
            value['inner_observation']['packet'] = C.pin(C.encoded(value['inner_observation']['payload']))
            with self.subTest(field=field), self.assertRaises(ValueError):
                C.validate_report(value, NONCE, RELEASE)
        value = model_report(); value['inner_observation']['packet']['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            C.validate_report(value, NONCE, RELEASE)

    def test_wrong_observer_namespace_or_new_pid_namespace_refuses(self):
        value = model_report(); value['inner_observation']['observer']['user_namespace'] = 'user:[999]'
        with self.assertRaises(ValueError):
            C.validate_report(value, NONCE, RELEASE)
        value = model_report(); value['inside']['namespaces']['pid'] = 'pid:[999]'
        value['inner_observation'] = model_witness(value['inside'], value['before'])
        with self.assertRaises(ValueError):
            C.validate_report(value, NONCE, RELEASE)

    def test_outer_caps_nnp_namespace_and_retirement_predicates_stay_required(self):
        for mutate in (lambda v: v['before']['capabilities'].update(CapEff=1),
                       lambda v: v['inside'].update(NoNewPrivs=0),
                       lambda v: v['inside']['namespaces'].update(net=v['before']['namespaces']['net']),
                       lambda v: v['command'].update(group_absence_verified=False)):
            value = model_report(); mutate(value)
            value['inner_observation'] = model_witness(value['inside'], value['before'])
            with self.assertRaises(ValueError):
                C.validate_report(value, NONCE, RELEASE)

    def test_empty_or_ambiguous_local_identity_map_refuses(self):
        for rows in ([], [[999, 0, 1]], [[23001, 0, 1], [23001, 1, 1]]):
            value = model_report(); value['inside']['uid_map'] = rows
            value['inner_observation'] = model_witness(value['inside'], value['before'])
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                C.validate_report(value, NONCE, RELEASE)

    def test_receive_uses_ancillary_credentials_and_rejects_missing_duplicate_or_truncated(self):
        valid = packet()
        for first in [(valid[0], [], 0, None), (valid[0], valid[1] * 2, 0, None),
                      (valid[0], valid[1], socket.MSG_TRUNC, None),
                      (valid[0], valid[1], socket.MSG_CTRUNC, None),
                      (b'x' * (W.PACKET_BYTES + 1), valid[1], 0, None)]:
            receiver = Mock(); receiver.recvmsg.return_value = first
            with self.subTest(flags=first[2]), self.assertRaises(ValueError):
                W.receive(receiver)
        receiver = Mock(); receiver.recvmsg.side_effect = [valid, BlockingIOError()]
        with patch.object(W.os, 'getuid', return_value=23001), patch.object(W.os, 'geteuid', return_value=23001), \
             patch.object(W.os, 'getgid', return_value=23001), patch.object(W.os, 'getegid', return_value=23001), \
             patch.object(W.os, 'readlink', side_effect=['user:[100]', 'pid:[100]']):
            observed = W.receive(receiver)
        self.assertEqual(observed['credentials'], dict(pid=31, uid=23001, gid=23001))
        receiver.getsockopt.assert_not_called()  # SO_PEERCRED would report creator credentials, not send-time identity.

    def test_extra_packet_and_noncanonical_or_duplicate_json_refuse(self):
        receiver = Mock(); receiver.recvmsg.side_effect = [packet(), packet()]
        with self.assertRaisesRegex(ValueError, 'extra'):
            W.receive(receiver)
        valid = packet()
        for raw in (b'{"schema":1,"schema":1}', valid[0] + b' '):
            receiver = Mock(); receiver.recvmsg.return_value = (raw, valid[1], 0, None)
            with self.assertRaises(ValueError):
                W.receive(receiver)

    def test_unexpected_scm_rights_are_closed_before_refusal(self):
        receiver = Mock()
        receiver.recvmsg.return_value = (b'{}', [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('2i', 80, 81))], 0, None)
        with patch.object(W.os, 'close') as close, self.assertRaises(ValueError):
            W.receive(receiver)
        self.assertEqual([c.args for c in close.call_args_list], [(80,), (81,)])

    def test_channel_refuses_unknown_fd3_without_replacing_any_descriptor(self):
        sender, receiver = Mock(), Mock(); sender.fileno.return_value = 9
        with patch.object(W.socket, 'socketpair', return_value=(sender, receiver)), self.assertRaises(ValueError):
            W.channel()
        sender.close.assert_called_once(); receiver.close.assert_called_once()

    def test_owned_command_passes_only_fd3_and_keeps_close_fds(self):
        with patch.object(O.os, 'fstat', return_value=types.SimpleNamespace(st_mode=stat.S_IFSOCK)), \
             patch.object(O.subprocess, 'Popen', side_effect=RuntimeError('DENIED_BEFORE_CHILD')) as popen:
            with self.assertRaisesRegex(RuntimeError, 'DENIED_BEFORE_CHILD'):
                O.run_command(['MODELED'], Path('/MODELED'), C.ENV, 20, 65536)
        self.assertEqual(popen.call_args.kwargs['pass_fds'], (3,))
        self.assertIs(popen.call_args.kwargs['close_fds'], True)
        self.assertIs(popen.call_args.kwargs['start_new_session'], True)
        with patch.object(O.os, 'fstat', return_value=types.SimpleNamespace(st_mode=stat.S_IFREG)):
            with self.assertRaisesRegex(ValueError, 'socket FD3'):
                O.run_command(['MODELED'], Path('/MODELED'), C.ENV, 20, 65536)

    def test_raw_inside_context_sent_before_any_local_validation(self):
        raw = dict(model_report()['inside'], NoNewPrivs=0)
        with patch.object(I.G, 'guard'), patch.object(I.G, 'observe', return_value=raw), \
             patch.object(I.W, 'send') as send, patch.object(I.G, 'emit') as emit:
            with self.assertRaises(ValueError):
                I.main(NONCE, RELEASE)
        send.assert_called_once_with(raw, NONCE, RELEASE); emit.assert_not_called()

    def test_sender_emits_one_bounded_packet_without_explicit_ancillary_credentials(self):
        context = model_report()['inside']
        raw = C.encoded(dict(schema=1, nonce=NONCE, release=RELEASE, context=context))
        endpoint = Mock(family=socket.AF_UNIX, type=socket.SOCK_SEQPACKET)
        endpoint.send.return_value = len(raw)
        manager = Mock(); manager.__enter__ = Mock(return_value=endpoint); manager.__exit__ = Mock(return_value=False)
        with patch.object(W.socket, 'socket', return_value=manager) as opened:
            W.send(context, NONCE, RELEASE)
        opened.assert_called_once_with(fileno=3)
        endpoint.send.assert_called_once_with(raw, socket.MSG_DONTWAIT)
        endpoint.sendmsg.assert_not_called()
        with self.assertRaisesRegex(ValueError, 'finite raw inner context'):
            W.send(dict(oversize='x' * W.PACKET_BYTES), NONCE, RELEASE)

    def test_largest_source_bounded_packet_and_stderr_fit_unchanged_report_cap(self):
        value = model_report()
        value['inside']['MODELED_EXTRA_DATA_NOT_REAL_CONTEXT'] = 'x' * 9000
        value['inner_observation'] = model_witness(value['inside'], value['before'])
        self.assertLessEqual(len(C.encoded(value['inner_observation']['payload'])), W.PACKET_BYTES)
        value['stderr'] = C.pin(b'x' * 65536); value['stderr_preview'] = C.stderr_preview(b'x' * 65536)
        value['command'].update(stderr_bytes=65536, stderr_sha256=value['stderr']['sha256'])
        C.validate_report(value, NONCE, RELEASE)
        self.assertLess(len(C.encoded(value)), C.BOUNDS['report_bytes'])

    def test_parent_keeps_raw_context_when_kernel_projection_refuses(self):
        value = model_report(); evidence = copy.deepcopy(value['inner_observation']); evidence['credentials']['uid'] = 0
        out = b'NSVM_EXEC_V1 ' + NONCE.encode() + b' ' + base64.b64encode(C.encoded(value['exec_context'])) + b'\n'
        out += b'NSVM_INSIDE_V1 ' + NONCE.encode() + b' ' + base64.b64encode(C.encoded(value['inside'])) + b'\n'
        work = Mock(); work.iterdir.return_value = iter(())
        actual_path = Path
        def path(name):
            return work if str(name) == '/tmp/namespace-vm-probe' else actual_path(name)
        shared = b'MODELED_BOUND_SHARED_RUNNER_DATA'
        selected = C.encoded(dict(runner=C.pin(shared), bwrap=value['bwrap']))
        sender, receiver = Mock(), Mock()
        with patch.object(G, 'guard'), patch.object(G, 'Path', side_effect=path), \
             patch.object(G.C, 'read', side_effect=lambda p: shared if str(p) == '/probe/runner.py' else selected), \
             patch.object(G, 'drop_identity'), patch.object(G, 'observe', side_effect=[value['before'], value['after']]), \
             patch.object(G.W, 'channel', return_value=(sender, receiver)), patch.object(G.W, 'receive', return_value=evidence), \
             patch.object(G.O, 'run_command', return_value=(value['command'], out, b'', None)), patch.object(G, 'emit') as emit:
            self.assertEqual(G.main(NONCE, RELEASE), 1)
        retained = emit.call_args.args[2]
        self.assertEqual(retained['inner_observation']['payload']['context'], value['inside'])
        self.assertIsNone(retained['inside'])
        self.assertEqual(retained['status'], 'PROBE_EXECUTION_OR_RETIREMENT_FAILED')
        self.assertTrue(retained['cleanup']['work_removed'])
        self.assertTrue(receiver.close.called and sender.close.called)


if __name__ == '__main__':
    unittest.main()
