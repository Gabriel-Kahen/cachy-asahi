# SPDX-License-Identifier: MIT
"""Synthetic serial DATA controls; never enter guest/VM/compiler/ALPM/GPG roles.

Only the reviewed local protocol definitions are loaded before the permanent
process/network/ctypes/filesystem fence. All fixture identities are modeled.
"""
import ast
import pathlib
import re
import sys
import unittest


def load_protocol():
    source = (pathlib.Path(__file__).parent / 'protocol.py').read_bytes()
    tree = ast.parse(source, filename='protocol.py')
    allowed = (ast.Import, ast.Assign, ast.FunctionDef, ast.Expr)
    if any(not isinstance(node, allowed) for node in tree.body):
        raise ValueError('protocol must remain finite definitions and constants')
    if any(isinstance(node, ast.Expr) and not (
            isinstance(node.value, ast.Constant) and isinstance(node.value.value, str))
            for node in tree.body):
        raise ValueError('top-level protocol expressions must be docstrings')
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            raise ValueError('protocol DATA may import only re')
        if isinstance(node, ast.Import) and any(
                item.name != 're' or item.asname for item in node.names):
            raise ValueError('protocol DATA may import only re')
    namespace = {}
    exec(compile(tree, 'protocol.py', 'exec'), namespace)
    return namespace


P = load_protocol()
NONCE = '1' * 32
BASELINE_NONCE = '2' * 32
EPOCH = 1800000000
PIN = 'a' * 64


def fence(event, args):
    if event == 'open' or event.startswith((
            'subprocess.', 'os.system', 'os.exec', 'os.spawn', 'os.posix_spawn',
            'os.fork', 'socket.', 'ctypes.')):
        raise RuntimeError('operational or filesystem event forbidden: ' + event)


sys.addaudithook(fence)


def restored_fields():
    return P['RESTORED'] | dict(
        BASE_SHA256=PIN, FINAL_SHA256=PIN, C_SHA256='b' * 64,
        CXX_SHA256='c' * 64, HOST_BOOT_UTC=str(EPOCH),
        GUEST_BEFORE_CRYPTO_UTC=str(EPOCH + 2),
        RTC_BEFORE_CRYPTO_UTC=str(EPOCH + 2))


def framed(kind, values):
    return ('LLVM23_' + kind + '_BEGIN ' + NONCE + '\n'
            + ''.join(key + '=' + value + '\n' for key, value in values.items())
            + 'LLVM23_' + kind + '_END ' + NONCE + '\n').encode()


def session_fields():
    return dict(ARCH='aarch64', PAGESIZE='16384', UID='1000',
                USERNAME='builder', PID1='systemd', Name='builder', User='1000',
                Class='user', Type='tty', Service='login', Remote='no',
                LOGIND='active', DBUS='active', Id='c1', XDG_SESSION_ID='c1',
                Leader='100', State='active')


class Serial:
    """Modeled serial bytes and command recording, without a transport."""

    def __init__(self):
        self.sent = []
        self.data = (b'login: Password: ARM16K_SHELL_READY '
                     + BASELINE_NONCE.encode() + b'\nTCG_LOGIN_END '
                     + BASELINE_NONCE.encode() + b'\n'
                     + framed('INSTALLED', P['INSTALLED'])
                     + framed('PROBE', P['PROBE'])
                     + framed('RESTORED', restored_fields()))

    def until(self, pattern):
        if not re.search(pattern, self.data):
            raise AssertionError('missing modeled serial observation')

    def send(self, data):
        self.sent.append(data)


class ProtocolTests(unittest.TestCase):
    def test_valid_restoration(self):
        fields = restored_fields()
        self.assertEqual(P['validate'](fields, PIN, EPOCH, EPOCH + 10), fields)

    def test_valid_probe(self):
        self.assertEqual(P['validate_probe'](P['PROBE'].copy()), P['PROBE'])

    def test_valid_frame(self):
        self.assertEqual(P['frame'](framed('PROBE', P['PROBE']), NONCE), P['PROBE'])

    def test_terminal_crlf(self):
        data = framed('PROBE', P['PROBE']).replace(b'\n', b'\r\n')
        self.assertEqual(P['frame'](data, NONCE), P['PROBE'])

    def test_embedded_carriage_return_refused(self):
        data = framed('PROBE', P['PROBE']).replace(b'STATUS', b'STA\rTUS')
        with self.assertRaises(ValueError):
            P['frame'](data, NONCE)

    def test_duplicate_frame_refused(self):
        with self.assertRaises(ValueError):
            P['frame'](framed('PROBE', P['PROBE']) * 2, NONCE)

    def test_duplicate_field_refused(self):
        data = framed('PROBE', P['PROBE']).replace(
            b'STATUS=PASS', b'STATUS=PASS\nSTATUS=PASS')
        with self.assertRaises(ValueError):
            P['frame'](data, NONCE)

    def test_overlong_value_refused(self):
        with self.assertRaises(ValueError):
            P['frame'](framed('PROBE', P['PROBE'] | dict(STATUS='x' * 257)), NONCE)

    def test_wrong_nonce_refused(self):
        with self.assertRaises(ValueError):
            P['frame'](framed('PROBE', P['PROBE']), BASELINE_NONCE)

    def test_unlisted_phase_refused(self):
        with self.assertRaises(ValueError):
            P['frame'](framed('PROBE', P['PROBE']), NONCE, '../../')

    def test_hold_refused(self):
        with self.assertRaises(ValueError):
            P['validate'](restored_fields() | dict(STATUS='HOLD'), PIN, EPOCH, EPOCH + 10)

    def test_changed_final_inventory_refused(self):
        with self.assertRaises(ValueError):
            P['validate'](restored_fields() | dict(FINAL_SHA256='d' * 64),
                          PIN, EPOCH, EPOCH + 10)

    def test_unexpected_authority_field_refused(self):
        with self.assertRaises(ValueError):
            P['validate'](restored_fields() | dict(EXTRA='authority'),
                          PIN, EPOCH, EPOCH + 10)

    def test_rtc_disagreement_refused(self):
        with self.assertRaises(ValueError):
            P['validate'](restored_fields() | dict(RTC_BEFORE_CRYPTO_UTC=str(EPOCH + 100)),
                          PIN, EPOCH, EPOCH + 10)

    def test_root_group_probe_refused(self):
        with self.assertRaises(ValueError):
            P['validate_probe'](P['PROBE'] | dict(GID='0'))

    def test_valid_pam_session(self):
        P['_session'](session_fields())

    def test_runuser_session_refused(self):
        with self.assertRaises(ValueError):
            P['_session'](session_fields() | dict(Service='runuser'))

    def test_journey_command_order(self):
        serial = Serial()
        result = P['journey'](serial, 'SYNTHETIC-PASSWORD', BASELINE_NONCE, NONCE,
                              lambda data, nonce: session_fields())
        self.assertEqual(result['session'], session_fields())
        self.assertEqual(result['installed'], P['INSTALLED'])
        self.assertEqual(result['probe'], P['PROBE'])
        self.assertEqual(result['restored'], restored_fields())
        self.assertTrue(result['normal_PAM_logout_observed'])
        self.assertEqual(serial.sent[:3], [b'builder\n', b'SYNTHETIC-PASSWORD\n',
                                          b'unset HISTFILE; /usr/local/libexec/arm16k-login-proof\n'])
        prefix = (b'/usr/bin/env -i HOME=/home/builder USER=builder LOGNAME=builder '
                  b'PATH=/usr/bin:/bin LC_ALL=C TZ=UTC /usr/bin/bash --noprofile --norc '
                  b'/var/lib/arm16k-llvm23-vm/probe.sh ' + NONCE.encode())
        self.assertEqual(serial.sent[3:], [prefix + b'\n', prefix + b' restored\n', b'exit\n'])


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ProtocolTests)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    raise SystemExit(not result.wasSuccessful())
