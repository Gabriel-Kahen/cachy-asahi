# SPDX-License-Identifier: MIT
from contextlib import redirect_stderr, redirect_stdout
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

import intake

ROOT = Path(__file__).resolve().parents[3]
URL = 'https://intake.invalid/packet.tar?authorization=protected'


def fixture_member(name, body, **metadata):
    member = tarfile.TarInfo(name)
    member.mode = 0o600
    member.size = len(body)
    for key, value in metadata.items():
        setattr(member, key, value)
    return member, body


def fixture_archive(*members):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:', format=tarfile.USTAR_FORMAT) as archive:
        for member, body in members:
            archive.addfile(member, io.BytesIO(body))
    return stream.getvalue()


class IntakeTests(unittest.TestCase):
    def test_all_twenty_two_members_match_the_original_signed_locks(self):
        sources = (
            ('alarm-cache', 'scripts/ci/inputs.lock.json', {'bubblewrap', 'jbigkit', 'libtiff'}),
            ('extension', 'scripts/port/kernel-native-stage/dependencies.json',
             {'clang', 'compiler-rt', 'libgit2', 'libxslt', 'lld', 'llvm', 'rust', 'rust-src'}),
        )
        expected = {}
        for lane, filename, names in sources:
            lock = json.loads((ROOT / filename).read_bytes())
            self.assertEqual(lock['signer_fingerprint'], '68B3537F39A313B3E574D06777193F152BDBE6A6')
            for row in lock['packages']:
                if row['name'] in names:
                    name = row['filename']
                    expected[name] = lane, row['size'], row['sha256']
                    expected[name + '.sig'] = lane, row['signature_size'], row['signature_sha256']
        self.assertEqual(len(expected), 22)
        self.assertEqual(intake.MEMBERS, expected)

    def test_rejects_non_https_userinfo_fragments_and_controls(self):
        for value in ('', '//intake.invalid/packet', 'http://intake.invalid/packet',
                      'https:///packet', 'https://user@intake.invalid/packet',
                      'https://intake.invalid/packet#fragment', 'https://intake.invalid/has space',
                      'https://intake.invalid/has\nnewline', 'https://intake.invalid:0/packet',
                      'https://intake.invalid:65536/packet'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                intake.endpoint(value)
        self.assertEqual(intake.endpoint(URL), ('intake.invalid', None, '/packet.tar?authorization=protected'))

    def test_only_direct_get_with_the_exact_pinned_response_is_accepted(self):
        body = b'archive'
        cases = (
            (200, [('Content-Length', '7')], body, True),
            (200, [('Transfer-Encoding', 'chunked')], body, True),
            (302, [('Location', 'https://different.invalid')], body, False),
            (206, [], body, False),
            (200, [('Content-Length', '7'), ('Content-Length', '7')], body, False),
            (200, [('Content-Length', '8')], body, False),
            (200, [('Content-Length', '7'), ('Transfer-Encoding', 'chunked')], body, False),
            (200, [('Content-Encoding', 'gzip')], body, False),
            (200, [], body[:-1], False),
            (200, [], body + b'!', False),
            (200, [], b'changed', False),
        )
        for status, headers, content, accepted in cases:
            with self.subTest(status=status, headers=headers, content=content):
                with io.BytesIO(content) as response, patch.object(intake.http.client, 'HTTPSConnection') as https:
                    response.status = status
                    response.headers = Message()
                    for key, value in headers:
                        response.headers[key] = value
                    connection = https.return_value
                    connection.getresponse.return_value = response
                    destination = io.BytesIO()
                    with patch.multiple(intake, ARCHIVE_BYTES=len(body), ARCHIVE_SHA256=hashlib.sha256(body).hexdigest()):
                        if accepted:
                            intake.download(URL, destination)
                            self.assertEqual(destination.getvalue(), body)
                        else:
                            with self.assertRaises(ValueError):
                                intake.download(URL, destination)
                    https.assert_called_once_with('intake.invalid', None, timeout=20)
                    connection.request.assert_called_once_with('GET', '/packet.tar?authorization=protected')
                    connection.close.assert_called_once()

    def test_exact_flat_ustar_only_and_both_lanes_are_private(self):
        first = fixture_member('a', b'producer')
        second = fixture_member('b', b'extension')
        good = fixture_archive(first, second)
        pins = {'a': ('alarm-cache', 8, hashlib.sha256(b'producer').hexdigest()),
                'b': ('extension', 9, hashlib.sha256(b'extension').hexdigest())}
        cases = (
            fixture_archive(second, first),
            fixture_archive(first),
            fixture_archive(first, second, second),
            fixture_archive(fixture_member('../a', b'producer'), second),
            fixture_archive(fixture_member('a', b'producer', uid=1), second),
            fixture_archive(fixture_member('a', b'producer', mode=0o644), second),
            fixture_archive(fixture_member('a', b'', type=tarfile.SYMTYPE, linkname='b'), second),
            fixture_archive(fixture_member('a', b'', type=tarfile.LNKTYPE, linkname='b'), second),
            fixture_archive(first, fixture_member('b', b'EXTENSION')),
            good[:520] + b'!' + good[521:],
            good[:-1],
            good + b'!',
        )
        with tempfile.TemporaryDirectory() as name, patch.multiple(intake, MEMBERS=pins, ARCHIVE_BYTES=len(good)):
            root = Path(name)
            valid = root / 'valid'
            valid.mkdir()
            intake.stage(io.BytesIO(good), valid)
            for filename, (lane, _, _) in pins.items():
                directory = valid / lane
                file = directory / filename
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o600)
                self.assertEqual([part.name for part in directory.iterdir()], [filename])
            for index, content in enumerate(cases):
                with self.subTest(index=index), self.assertRaises(ValueError):
                    target = root / str(index)
                    target.mkdir()
                    intake.stage(io.BytesIO(content), target)
            self.assertFalse((root / 'a').exists())

    def test_worker_exit_does_not_print_endpoint_or_exception(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as name, patch.dict(os.environ, {intake.URL_ENV: URL}), \
                patch.object(sys, 'argv', ['intake.py', name]), redirect_stdout(output), redirect_stderr(output):
            download = Mock(side_effect=ValueError(URL))
            with patch.object(intake, 'download', download):
                self.assertEqual(intake.main(), 1)
            self.assertNotIn(intake.URL_ENV, os.environ)
            self.assertEqual(list(Path(name).iterdir()), [])
        self.assertEqual(output.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
