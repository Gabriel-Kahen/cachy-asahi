# SPDX-License-Identifier: MIT
"""Modeled child stderr only; cannot recover the prior hash-only 577 actual bytes."""
import base64
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C
from test_data import model_report, NONCE, RELEASE


def report(raw):
    value = model_report()
    value['stderr'] = C.pin(raw)
    value['stderr_preview'] = C.stderr_preview(raw)
    value['command'].update(stderr_bytes=len(raw), stderr_sha256=C.pin(raw)['sha256'])
    return value


class StderrData(unittest.TestCase):
    def setUp(self):
        for name in ('subprocess.Popen', 'subprocess.run', 'os.execve', 'socket.socket', 'ctypes.CDLL'):
            self.enterContext(patch(name, side_effect=AssertionError('STDERR_DATA_ACTOR_DENIED:' + name)))

    def test_empty_stderr_is_exact_complete_diagnostic(self):
        value = report(b'')
        self.assertEqual(C.validate_stderr(value), b'')
        self.assertEqual(value['stderr_preview']['prefix_b64'], '')
        self.assertFalse(value['stderr_preview']['truncated'])

    def test_modeled_577_bytes_roundtrip_without_text_or_cause_inference(self):
        raw = (b'MODELED_NOT_ACTUAL_STDERR\x00\xff\x1b[31m\n' * 24)[:577]
        self.assertEqual(len(raw), 577)
        value = report(raw)
        self.assertEqual(C.validate_stderr(value), raw)
        self.assertEqual(value['stderr'], C.pin(raw))
        self.assertIsNone(value['numeric_unshare_errno'])

    def test_prefix_boundary_and_explicit_truncation(self):
        for length in (16384, 16385, 65536):
            raw = b'x' * length
            value = report(raw)
            self.assertEqual(C.validate_stderr(value), raw[:16384])
            self.assertEqual(value['stderr_preview']['truncated'], length > 16384)
            self.assertEqual(value['stderr_preview']['bytes'], length)
            self.assertEqual(value['stderr_preview']['sha256'], C.pin(raw)['sha256'])

    def test_producer_rejects_overbudget_or_nonbytes(self):
        for raw in (b'x' * 65537, bytearray(b'x'), 'text'):
            with self.subTest(kind=type(raw).__name__), self.assertRaises(ValueError):
                C.stderr_preview(raw)

    def test_complete_preview_content_forgery_refuses(self):
        value = report(b'actual modeled child error')
        value['stderr_preview']['prefix_b64'] = base64.b64encode(b'forged modeled child text').decode('ascii')
        with self.assertRaises(ValueError):
            C.validate_stderr(value)

    def test_whole_pin_must_join_actual_command_and_preview(self):
        for container, key, changed in [('stderr', 'sha256', '0' * 64),
                                        ('stderr_preview', 'sha256', '0' * 64),
                                        ('command', 'stderr_bytes', 1),
                                        ('command', 'stderr_sha256', '0' * 64)]:
            value = report(b'error')
            value[container][key] = changed
            with self.subTest(container=container, key=key), self.assertRaises(ValueError):
                C.validate_stderr(value)

    def test_wrong_lengths_booleans_truncation_schema_or_extra_keys_refuse(self):
        for key, changed in [('bytes', True), ('truncated', 0), ('truncated', True),
                             ('schema', True), ('encoding', 'utf-8'), ('extra', 'unbound'),
                             ('prefix_b64', base64.b64encode(b'err').decode('ascii'))]:
            value = report(b'error')
            value['stderr_preview'][key] = changed
            with self.subTest(key=key, changed=changed), self.assertRaises(ValueError):
                C.validate_stderr(value)

    def test_invalid_and_noncanonical_base64_refuses(self):
        for encoded in ('!!!!', 'Zg==\n', 'Zh==', '\u00ff'):
            value = report(b'f')
            value['stderr_preview']['prefix_b64'] = encoded
            with self.subTest(encoded=encoded), self.assertRaises(ValueError):
                C.validate_stderr(value)

    def test_maximum_preview_stays_within_existing_report_frame(self):
        value = report(b'x' * 65536)
        C.validate_report(value, NONCE, RELEASE)
        self.assertLess(len(C.encoded(value)), C.BOUNDS['report_bytes'])
        self.assertEqual(C.BOUNDS['command_output_bytes'], 65536)
        self.assertEqual(C.STDERR_PREVIEW_BYTES, 16384)

    def test_observed_nonzero_keeps_inside_null_and_errno_unknown(self):
        value = report(b'MODELED diagnostic, not an errno observation')
        value.update(status='OBSERVED_BWRAP_NONZERO', inside=None)
        value['command']['exit_code'] = 1
        C.validate_report(value, NONCE, RELEASE)
        for key, changed in [('inside', value['exec_context']), ('numeric_unshare_errno', 1)]:
            forged = copy.deepcopy(value)
            forged[key] = changed
            with self.subTest(key=key), self.assertRaises(ValueError):
                C.validate_report(forged, NONCE, RELEASE)

    def test_diagnostic_never_bypasses_success_identity_or_namespace_checks(self):
        value = report(b'TEXT CLAIMS SUCCESS BUT IS ONLY DATA')
        value['inside']['namespaces']['net'] = value['before']['namespaces']['net']
        with self.assertRaises(ValueError):
            C.validate_report(value, NONCE, RELEASE)
        value = report(b'')
        value['before']['capabilities']['CapEff'] = 1
        with self.assertRaises(ValueError):
            C.validate_report(value, NONCE, RELEASE)


if __name__ == '__main__':
    unittest.main()
