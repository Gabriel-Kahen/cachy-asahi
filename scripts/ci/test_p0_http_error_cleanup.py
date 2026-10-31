"""P0 HTTP error retirement; local files and mocked HTTP only."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import time
import types
import unittest
import urllib.error
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location(
    'p0_http_error_test', Path(__file__).resolve().parent / 'development/p0_ci.py')
p0 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p0)


class FalseyHTTPError(urllib.error.HTTPError):
    def __bool__(self):
        return False


class HTTPErrorCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.target = Path(temporary.name) / 'controlled-input'
        self.item = {'filename': self.target.name, 'size': 1,
                     'sha256': hashlib.sha256(b'x').hexdigest(),
                     'url': 'https://example.invalid/pinned'}
        self.owner = types.SimpleNamespace(
            plan={'nonce': 'owned-test', 'url_overrides': {}}, deadline=time.monotonic() + 30,
            source_interval_selected=False, source_interval_active=None, retained=[],
            download_guard=Mock(), capture_download=Mock())
        p0.PREPARATION_QUARANTINE.clear()
        self.addCleanup(p0.PREPARATION_QUARANTINE.clear)

    def http_error(self, kind=urllib.error.HTTPError):
        body = io.BytesIO(b'controlled response body')
        self.addCleanup(body.close)
        error = kind(self.item['url'], 404, 'controlled', {}, body)
        self.addCleanup(error.close)
        return error, body

    def failed_open(self, error):
        self.owner.capture_download.reset_mock()
        opener = Mock()
        opener.open.side_effect = error
        deadline = self.owner.deadline
        with patch.dict(p0.sys.modules, {spec.name: p0}), \
                patch.object(p0.urllib.request, 'build_opener', return_value=opener):
            try:
                p0.Preparation.fetch(self.owner, self.item, self.target, ordinal=0)
            except BaseException as actual:
                self.assertIs(actual, error)
            else:
                self.fail('expected the original open error')
        self.assertEqual(self.owner.deadline, deadline)
        self.assertGreater(opener.open.call_args.kwargs['timeout'], 0)
        self.assertLessEqual(opener.open.call_args.kwargs['timeout'], 30)
        self.assertFalse(self.target.exists())
        self.assertIn(error, self.owner.retained)
        self.assertTrue(error.native_preflight_cleanup_uncertain)
        self.assertTrue(all(call.args[0] is error for call in self.owner.capture_download.call_args_list))
        partial = self.target.with_name(self.target.name + '.owned-test.partial')
        self.assertTrue(partial.is_file())
        partial.unlink()

    def test_http_error_body_closed_and_primary_preserved(self):
        for selected in (False, True):
            with self.subTest(interval_selected=selected):
                error, body = self.http_error()
                self.owner.source_interval_selected = selected
                self.failed_open(error)
                self.assertTrue(body.closed)
                self.assertEqual(error.code, 404)
                self.assertEqual(error.nativeci_pipeline_operation, 'download-http-error')
                self.assertFalse(getattr(error, 'native_preflight_cancelled', False))

    def test_body_close_failure_keeps_http_error_and_uncertainty(self):
        error, body = self.http_error()
        with patch.object(error, 'close', side_effect=OSError('controlled close failure')) as close:
            self.failed_open(error)
            close.assert_called_once_with()
        self.assertFalse(body.closed)
        self.assertFalse(getattr(error, 'native_preflight_cancelled', False))

    def test_body_close_cancellation_is_sticky_on_original_error(self):
        error, body = self.http_error()
        with patch.object(error, 'close', side_effect=KeyboardInterrupt()) as close:
            self.failed_open(error)
            close.assert_called_once_with()
        self.assertFalse(body.closed)
        self.assertTrue(error.native_preflight_cancelled)

    def test_existing_cancellation_is_not_cleared_by_successful_close(self):
        error, body = self.http_error()
        error.native_preflight_cancelled = True
        self.failed_open(error)
        self.assertTrue(body.closed)
        self.assertTrue(error.native_preflight_cancelled)

    def test_falsey_http_error_is_still_the_primary(self):
        error, body = self.http_error(FalseyHTTPError)
        self.failed_open(error)
        self.assertTrue(body.closed)

    def test_other_connection_errors_keep_existing_cleanup_accounting(self):
        for error in (urllib.error.URLError('controlled'), TimeoutError('controlled'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                error.close = Mock()
                self.failed_open(error)
                error.close.assert_not_called()
                self.assertEqual(bool(getattr(error, 'native_preflight_cancelled', False)),
                                 isinstance(error, KeyboardInterrupt))


if __name__ == '__main__':
    unittest.main()
