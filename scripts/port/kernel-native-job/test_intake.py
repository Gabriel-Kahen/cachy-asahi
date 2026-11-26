# SPDX-License-Identifier: MIT
from contextlib import redirect_stderr, redirect_stdout
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
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

    def test_ssh_closes_both_pinned_lanes_without_overwriting_base_files(self):
        kernel, added, historical = intake.carrier_profiles()
        self.assertEqual([len(profile[3]) for profile in (kernel, added, historical)], [22, 26, 183])
        lock = json.loads((ROOT / 'scripts/ci/inputs.lock.json').read_bytes())
        for row in lock['packages']:
            if row['name'] in {'gtk-update-icon-cache', 'libinput'}:
                path = 'alarm-cache/' + row['filename']
                self.assertEqual(added[3][path], (row['size'], row['sha256']))
                self.assertEqual(added[3][path + '.sig'], (row['signature_size'], row['signature_sha256']))
        files = intake.retained_files('ssh')
        self.assertEqual(sum(path.startswith('alarm-cache/') for path in files), 214)
        self.assertEqual(sum(path.startswith('extension/') for path in files), 16)
        self.assertEqual({key: files[key] for key in intake.retained_files('https')}, intake.kernel_files())
        self.assertNotIn('manifest.json', files)

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
        with tempfile.TemporaryDirectory() as name, patch.dict(os.environ, {
                intake.URL_ENV: URL, intake.TRANSPORT_ENV: 'https', 'RUNNER_TEMP': name,
                'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}), redirect_stdout(output), redirect_stderr(output):
            download = Mock(side_effect=ValueError(URL))
            with patch.object(intake, 'download', download):
                with patch.object(intake.os, 'umask'):
                    self.assertEqual(intake.main(), 1)
            self.assertNotIn(intake.URL_ENV, os.environ)
            self.assertEqual(list(Path(name).iterdir()), [])
        self.assertEqual(output.getvalue(), '')

    def test_real_git_round_trip_and_pin_refusals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / 'repo'
            repository.mkdir()

            def git(*args):
                return subprocess.check_output(['/usr/bin/git', '-C', str(repository), *args]).decode().strip()

            git('init', '-q', '--template=', '--object-format=sha1', '-b', 'native623-r1')
            bodies = {'alarm-cache/base.sig': b'base', 'extension/lib-1:2.pkg.tar.xz': b'extended'}
            members = {}
            for relative, body in bodies.items():
                lane, name = relative.split('/')
                members[relative] = len(body), hashlib.sha256(body).hexdigest()
                (repository / lane).mkdir()
                (repository / relative).write_bytes(body)
            git('add', '--', 'alarm-cache', 'extension')
            git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', 'parentless')
            commit, tree = git('rev-parse', 'HEAD'), git('rev-parse', 'HEAD^{tree}')
            identity = root / 'test-key'
            subprocess.run(['/usr/bin/ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(identity)],
                           check=True, capture_output=True)
            fingerprint = subprocess.check_output(['/usr/bin/ssh-keygen', '-lf', str(identity), '-E', 'sha256'])
            deploy_key = b' '.join(fingerprint.split()[:2])
            def profiles():
                return ((intake.SSH_REF, intake.SSH_COMMIT, intake.SSH_TREE, members),)

            with patch.multiple(intake, SSH_COMMIT=commit, SSH_TREE=tree, carrier_profiles=profiles,
                                SSH_REMOTE=repository.as_uri(), DEPLOY_KEY=deploy_key,
                                GIT=intake.GIT + ['-c', 'protocol.file.allow=always']):
                values = {intake.SSH_ENV: identity.read_text(), intake.TRANSPORT_ENV: 'ssh',
                          'RUNNER_TEMP': directory, 'GITHUB_RUN_ID': '23', 'GITHUB_RUN_ATTEMPT': '1'}
                with patch.dict(os.environ, values), patch.object(intake.os, 'umask'):
                    self.assertEqual(intake.main(), 0)
                    self.assertNotIn(intake.SSH_ENV, os.environ)
                staged = intake.runner_output(values)
                self.assertEqual({str(p.relative_to(staged)): p.read_bytes()
                                  for p in staged.glob('*/*')}, bodies)
                self.assertEqual(list(root.glob('kernel623-fetch-*')), [])
                for index, change in enumerate(({'SSH_COMMIT': '0' * 40}, {'SSH_TREE': '0' * 40},
                                                {'DEPLOY_KEY': b'256 SHA256:wrong'}), start=2):
                    values['GITHUB_RUN_ATTEMPT'] = str(index)
                    with patch.multiple(intake, **change), patch.dict(os.environ, values), patch.object(intake.os, 'umask'):
                        self.assertEqual(intake.main(), 1)
                        self.assertNotIn(intake.SSH_ENV, os.environ)
                    self.assertFalse(intake.runner_output(values).exists())
                    self.assertEqual(list(root.glob('kernel623-fetch-*')), [])

    def test_runner_copy_refuses_tampering_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'staged'
            source.mkdir()
            for lane in ('alarm-cache', 'extension'):
                (source / lane).mkdir()
            output = root / 'copy'
            output.mkdir()
            content = b'expected'
            files = {'alarm-cache/body': (len(content), hashlib.sha256(content).hexdigest())}
            pinned = source / 'alarm-cache' / 'body'
            for case in ('extra', 'changed', 'symlink'):
                with self.subTest(case=case), self.assertRaises(ValueError if case != 'symlink' else OSError):
                    if case == 'extra':
                        (source / 'extra').touch()
                    elif case == 'changed':
                        pinned.write_bytes(b'tampered')
                    else:
                        pinned.symlink_to(root / 'unlisted')
                    try:
                        intake.materialize(source, output, files)
                    finally:
                        (source / 'extra').unlink(missing_ok=True)
                        pinned.unlink(missing_ok=True)
                        for path in output.glob('*/*'):
                            path.unlink()
                        for path in output.iterdir():
                            path.rmdir()


if __name__ == '__main__':
    unittest.main()
