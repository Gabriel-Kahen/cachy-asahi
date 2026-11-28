# SPDX-License-Identifier: MIT
"""Local controls for the installed-Check runtime archive intake."""
import hashlib
import io
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import runtime_intake as intake


def pin(body):
    return len(body), hashlib.sha256(body).hexdigest()


class Response(io.BytesIO):
    status = 200

    def __init__(self, url, body):
        super().__init__(body)
        self.url = url

    def geturl(self):
        return self.url


class RuntimeIntake(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='updater-runtime-intake-test-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.output = self.root / 'runtime-cache'
        self.keyring = self.root / intake.KEYRING
        self.keyring.write_bytes(b'inert public keyring')
        patch = mock.patch.object(intake, 'KEYRING_PIN', pin(self.keyring.read_bytes()))
        patch.start()
        self.addCleanup(patch.stop)

    def test_hits_exact_immutable_paths_and_total(self):
        rows = list(intake.runtime_files())
        self.assertEqual(len(rows), 10)
        self.assertEqual(sum(size for _, _, (size, _) in rows), 800646)
        self.assertEqual(len({url for _, url, _ in rows}), 10)
        for name, url, _ in rows:
            xdg = name.startswith('xdg-utils-')
            carrier = intake.XDG_CARRIER if xdg else intake.RUNTIME_CARRIER
            lane = 'upstream-signatures' if name.endswith('.sig') and not xdg else 'packages'
            self.assertEqual(url, f'{intake.BASE_URL}{carrier}/{lane}/{name}')

    def stage_fixture(self, received):
        name = 'inert.pkg.tar.xz'
        url = intake.BASE_URL + 'fixture'
        with mock.patch.object(intake, 'runtime_files', return_value=[(name, url, pin(b'expected'))]):
            opener = mock.Mock()
            opener.open.return_value = Response(url, received)
            with mock.patch.object(intake, 'build_opener', return_value=opener):
                return intake.stage(self.output, self.keyring)

    def test_atomic_private_cache_from_checked_bytes(self):
        body = b'expected'
        count, size = self.stage_fixture(body)
        self.assertEqual((count, size), (2, len(body) + self.keyring.stat().st_size))
        self.assertEqual((self.output / 'inert.pkg.tar.xz').read_bytes(), body)
        self.assertEqual((self.output / intake.KEYRING).read_bytes(), self.keyring.read_bytes())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(p.stat().st_mode & 0o777 == 0o600 for p in self.output.iterdir()))

    def test_wrong_bytes_never_publish_cache(self):
        for body in (b'changed!', b'', b'expected extra'):
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, 'runtime-input-pin'):
                self.stage_fixture(body)
        self.assertEqual(list(self.root.iterdir()), [self.keyring])

    def test_refuses_changed_url_and_expired_deadline(self):
        url = intake.BASE_URL + 'fixture'
        opener = mock.Mock()
        opener.open.return_value = Response('https://example.com/other', b'expected')
        with self.assertRaisesRegex(ValueError, 'runtime-input-transport'):
            intake.download(opener, url, pin(b'expected'), time.monotonic() + 5)
        self.assertTrue(opener.open.return_value.closed)
        opener.reset_mock()
        with self.assertRaisesRegex(ValueError, 'runtime-input-deadline'):
            intake.download(opener, url, pin(b'expected'), time.monotonic() - 1)
        opener.open.assert_not_called()

    def test_refuses_keyring_alias_and_existing_cache(self):
        alternate = self.root / 'alternate'
        self.keyring.rename(alternate)
        self.keyring.symlink_to(alternate)
        with self.assertRaisesRegex(ValueError, 'runtime-keyring-path'):
            self.stage_fixture(b'expected')
        self.assertFalse(self.output.exists())
        self.keyring.unlink()
        os.link(alternate, self.keyring)
        with self.assertRaisesRegex(ValueError, 'runtime-keyring-file'):
            self.stage_fixture(b'expected')
        self.output.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, 'runtime-output-path'):
            self.stage_fixture(b'expected')
