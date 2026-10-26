#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Original synthetic boundary checks; never compile or execute upstream code."""
import sys
sys.dont_write_bytecode = True

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
PACKET = Path('/tmp/fdk-aac-3.0.0-selected-source.tar')
ROOT = 'fdk-aac-3.0.0'


def load(name, directory=HERE, filename=None):
    spec = importlib.util.spec_from_file_location(name, directory / (filename or f'{name}.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


source_check = load('source_check')
materializer = load('materialize')
selector = load('select_source', filename='select-source.py')
PRIVATE_PACKET = Path('/tmp/cachy-fdk-redistributable-source-3.0.0.tar.gz')
if (HERE / source_check.PACKET).is_file():
    PACKET = HERE / source_check.PACKET


def records(files):
    return {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
            for name, data in files.items()}


def archive(entries):
    """Entries are (name, bytes) or (name, tar type, link target)."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w') as handle:
        for entry in entries:
            info = tarfile.TarInfo(entry[0])
            if len(entry) == 2:
                info.size = len(entry[1])
                handle.addfile(info, io.BytesIO(entry[1]))
            else:
                info.type, info.linkname = entry[1:]
                handle.addfile(info)
    stream.seek(0)
    return tarfile.open(fileobj=stream, mode='r:')


class MemberTests(unittest.TestCase):
    def setUp(self):
        self.files = {'codec/source.c': b'original synthetic source\n',
                      'NOTICE': b'original synthetic notice\n', '.hidden': b'ok\n'}
        self.expected = records(self.files)
        self.entries = [(ROOT, tarfile.DIRTYPE, ''),
                        (ROOT + '/codec', tarfile.DIRTYPE, '')]
        self.entries += [(ROOT + '/' + name, data) for name, data in self.files.items()]

    def audit(self, entries=None, expected=None):
        with archive(self.entries if entries is None else entries) as handle:
            return source_check.audit_members(handle, self.expected if expected is None else expected)

    def reject(self, entries=None, expected=None):
        with self.assertRaises(ValueError):
            self.audit(entries, expected)

    def test_complete_packet_counts_bytes_without_extraction(self):
        self.assertEqual(self.audit(), {'files': 3, 'bytes': sum(map(len, self.files.values()))})

    def test_explicit_directory_entries_are_optional(self):
        self.assertEqual(self.audit(self.entries[2:])['files'], 3)

    def test_empty_regular_file_is_valid(self):
        self.files['codec/empty.c'] = b''
        entries = self.entries + [(ROOT + '/codec/empty.c', b'')]
        self.assertEqual(self.audit(entries, records(self.files))['files'], 4)

    def test_unsafe_and_noncanonical_member_paths_fail(self):
        for name in ('/fdk-aac-3.0.0/NOTICE', '../NOTICE', ROOT + '/../NOTICE',
                     ROOT + '/codec/../../NOTICE', ROOT + '/./NOTICE',
                     ROOT + '//NOTICE', '', '.', ROOT + '/codec/../NOTICE'):
            with self.subTest(name=name):
                self.reject(self.entries + [(name, b'bad')])

    def test_wrong_root_and_prefix_lookalike_fail(self):
        for name in ('other/NOTICE', ROOT + '-other/NOTICE', 'NOTICE'):
            with self.subTest(name=name):
                self.reject(self.entries + [(name, b'bad')])

    def test_symlink_and_hardlink_fail_even_for_expected_names(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                entries = [row for row in self.entries if row[0] != ROOT + '/NOTICE']
                self.reject(entries + [(ROOT + '/NOTICE', kind, ROOT + '/codec/source.c')])

    def test_fifo_devices_and_other_special_types_fail(self):
        for kind in (tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.CONTTYPE):
            with self.subTest(kind=kind):
                self.reject(self.entries + [(ROOT + '/special', kind, '')])

    def test_duplicate_files_and_directories_fail(self):
        for row in (self.entries[0], self.entries[1], self.entries[-1]):
            with self.subTest(name=row[0]):
                self.reject(self.entries + [row])

    def test_unexpected_regular_file_fails(self):
        self.reject(self.entries + [(ROOT + '/unreviewed.c', b'new source')])

    def test_missing_expected_file_fails(self):
        self.reject(self.entries[:-1])

    def test_stray_directory_or_directory_replacing_file_fails(self):
        for name in (ROOT + '/stray', ROOT + '/NOTICE', ROOT + '/codec/stray'):
            with self.subTest(name=name):
                self.reject(self.entries + [(name, tarfile.DIRTYPE, '')])

    def test_size_mismatch_fails(self):
        expected = {name: dict(row) for name, row in self.expected.items()}
        expected['NOTICE']['bytes'] += 1
        self.reject(expected=expected)

    def test_same_size_digest_mismatch_fails(self):
        entries = [(row[0], b'X' * len(row[1])) if row[0] == ROOT + '/NOTICE'
                   else row for row in self.entries]
        self.reject(entries)


class RegularReadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root / 'input'
        self.file.write_bytes(b'fixture\n')

    def test_regular_file_is_read_exactly(self):
        self.assertEqual(source_check.read_regular(self.file, 8), b'fixture\n')

    def test_oversized_and_missing_files_fail(self):
        with self.assertRaises((ValueError, OSError)):
            source_check.read_regular(self.file, 7)
        with self.assertRaises((ValueError, OSError)):
            source_check.read_regular(self.root / 'absent', 8)

    def test_final_symlink_fails(self):
        link = self.root / 'link'
        link.symlink_to(self.file)
        with self.assertRaises((ValueError, OSError)):
            source_check.read_regular(link, 8)

    def test_directory_fails(self):
        with self.assertRaises((ValueError, OSError)):
            source_check.read_regular(self.root, 8)

    def test_fifo_is_opened_nonblocking_and_rejected(self):
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        real_open = os.open
        def checked_open(path, flags, *args, **kwargs):
            self.assertTrue(flags & os.O_NONBLOCK)
            self.assertTrue(flags & os.O_NOFOLLOW)
            return real_open(path, flags, *args, **kwargs)
        with mock.patch.object(source_check.os, 'open', side_effect=checked_open):
            with self.assertRaises((ValueError, OSError)):
                source_check.read_regular(fifo, 8)

    def test_changed_manifest_fails_before_packet_use(self):
        manifest = self.root / 'manifest.json'
        manifest.write_bytes(b'{}')
        with self.assertRaises(ValueError):
            source_check.verify_packet(self.root / 'absent.tar.gz', manifest)

    def test_wrong_packet_hash_fails_before_archive_use(self):
        self.file.write_bytes(b'not the reviewed source packet')
        with self.assertRaises(ValueError):
            source_check.verify_packet(self.file)

    def test_selected_raw_packet_must_match_exact_bytes_before_tar_parser(self):
        for data in (b'not tar', gzip.compress(b'fixture', mtime=0), b'x' * 129):
            with self.subTest(length=len(data)):
                self.file.write_bytes(data)
                with mock.patch.object(source_check, 'SELECTED_LIMIT', 128), \
                     mock.patch.object(source_check.tarfile, 'open', side_effect=AssertionError('parser reached')):
                    with self.assertRaises(ValueError):
                        source_check.verify_packet(self.file)

    def test_original_input_over_8MiB_is_not_read_as_large_unpinned_source(self):
        with self.file.open('wb') as stream:
            stream.truncate(8 * 1024 * 1024 + 1)
        with mock.patch.object(selector, 'read_regular', side_effect=AssertionError('source read')):
            with self.assertRaisesRegex(ValueError, 'original source packet exceeds'):
                selector.source_input(self.file)

    def test_large_selected_candidate_requires_its_exact_digest_before_parsing(self):
        with self.file.open('wb') as stream:
            stream.truncate(source_check.PACKET_BYTES)
        with mock.patch.object(source_check, 'read_regular', return_value=b'wrong'), \
             mock.patch.object(selector.tarfile, 'open', side_effect=AssertionError('parser reached')):
            with self.assertRaisesRegex(ValueError, 'selected packet differs'):
                selector.selected_bytes(self.file)



class MaterializeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'build-recipe'
        self.review = self.root / 'reviewed-inputs.json'
        approved = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in HERE.iterdir() if path.is_file()}
        self.review.write_text(json.dumps(approved, sort_keys=True))
        self.review_sha = hashlib.sha256(self.review.read_bytes()).hexdigest()

    def materialize(self, packet=PACKET):
        return materializer.materialize(packet, self.output, self.review, self.review_sha)

    def test_missing_packet_leaves_no_output(self):
        with self.assertRaises((ValueError, OSError)):
            self.materialize(self.root / 'missing.tar.gz')
        self.assertFalse(self.output.exists())

    def test_wrong_packet_leaves_no_output(self):
        packet = self.root / 'wrong.tar.gz'
        packet.write_bytes(b'not upstream')
        with self.assertRaises(ValueError):
            self.materialize(packet)
        self.assertFalse(self.output.exists())

    def test_existing_output_is_never_overwritten(self):
        self.output.mkdir()
        marker = self.output / 'keep'
        marker.write_bytes(b'unchanged')
        with self.assertRaises((ValueError, OSError)):
            self.materialize()
        self.assertEqual(marker.read_bytes(), b'unchanged')
        self.assertEqual(list(self.output.iterdir()), [marker])

    def test_output_symlink_is_never_followed(self):
        target = self.root / 'keep'
        target.mkdir()
        self.output.symlink_to(target, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.materialize()
        self.assertTrue(self.output.is_symlink())
        self.assertEqual(list(target.iterdir()), [])

    def test_reviewed_map_is_required_and_digest_bound(self):
        for reviewed, checksum in ((None, None), (self.review, None),
                                   (None, self.review_sha), (self.review, '0' * 64)):
            with self.subTest(reviewed=reviewed, checksum=checksum):
                with self.assertRaises(ValueError):
                    materializer.materialize(PACKET, self.output, reviewed, checksum)
                self.assertFalse(self.output.exists())

    def test_reviewed_map_with_incomplete_set_fails(self):
        self.review.write_text('{}')
        self.review_sha = hashlib.sha256(self.review.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):
            self.materialize()
        self.assertFalse(self.output.exists())

    def test_repository_output_and_symlink_parent_are_rejected(self):
        inside = HERE / ('new-output-' + self.root.name)
        with self.assertRaises(ValueError):
            materializer.materialize(PACKET, inside, self.review, self.review_sha)
        self.assertFalse(inside.exists())
        link = self.root / 'repo-link'
        link.symlink_to(HERE, target_is_directory=True)
        with self.assertRaises(ValueError):
            materializer.materialize(PACKET, link / inside.name, self.review, self.review_sha)
        self.assertFalse(inside.exists())

    def test_changed_recipe_metadata_cannot_use_old_review(self):
        clone = self.clone_template()
        recipe = clone / 'PKGBUILD'
        recipe.write_bytes(recipe.read_bytes() + b'\n# changed reviewed recipe\n')
        with mock.patch.object(materializer, 'template_files',
                               side_effect=lambda: source_check.template_files(clone)):
            with self.assertRaisesRegex(ValueError, 'independently reviewed'):
                self.materialize()
        self.assertFalse(self.output.exists())

    def clone_template(self, name='template'):
        clone = self.root / name
        clone.mkdir()
        for path in HERE.iterdir():
            if path.is_file():
                shutil.copyfile(path, clone / path.name)
        return clone

    def test_changed_local_grant_leaves_no_output(self):
        clone = self.clone_template()
        (clone / 'NOTICE.classic').write_bytes(b'altered grant')
        with mock.patch.object(materializer, 'template_files',
                               side_effect=lambda: source_check.template_files(clone)):
            with self.assertRaises(ValueError):
                self.materialize()
        self.assertFalse(self.output.exists())

    def test_changed_source_pin_leaves_no_output(self):
        clone = self.clone_template()
        metadata = clone / '.SRCINFO'
        metadata.write_text(metadata.read_text().replace(source_check.PACKET_SHA, '0' * 64))
        with mock.patch.object(materializer, 'template_files',
                               side_effect=lambda: source_check.template_files(clone)):
            with self.assertRaises(ValueError):
                self.materialize()
        self.assertFalse(self.output.exists())

    def test_extra_or_missing_template_file_leaves_no_output(self):
        clone = self.clone_template()
        (clone / 'unreviewed').write_bytes(b'extra')
        with mock.patch.object(materializer, 'template_files',
                               side_effect=lambda: source_check.template_files(clone)):
            with self.assertRaises(ValueError):
                self.materialize()
        self.assertFalse(self.output.exists())
        (clone / 'unreviewed').unlink()
        (clone / 'NOTICE.xhe-aac').unlink()
        with mock.patch.object(materializer, 'template_files',
                               side_effect=lambda: source_check.template_files(clone)):
            with self.assertRaises(ValueError):
                self.materialize()
        self.assertFalse(self.output.exists())

    @unittest.skipUnless(PACKET.is_file(), 'selected source packet is unavailable')
    def test_relocated_pristine_inputs_ignore_polluted_build_directory(self):
        inputs = self.clone_template('inputs')
        packet = inputs / source_check.PACKET
        if not packet.exists():
            shutil.copyfile(PACKET, packet)
        approved = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in inputs.iterdir()}
        self.review.write_text(json.dumps(approved, sort_keys=True))
        digest = hashlib.sha256(self.review.read_bytes()).hexdigest()
        work = self.root / 'work'
        work.mkdir()
        (work / 'src').mkdir()
        (work / 'pkg').mkdir()
        (work / 'build.log').write_text('original synthetic build log\n')
        script = ('import json, sys; sys.path.insert(0, sys.argv[1]); '
                  'import materialize; '
                  'print(json.dumps(materialize.materialize(*sys.argv[2:])))')
        result = subprocess.run([sys.executable, '-B', '-c', script, str(inputs),
                                 str(packet), str(self.output), str(self.review), digest],
                                cwd=work, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'materialized-source-only')
        self.assertEqual(report['files'], 900)
        self.assertEqual(report['input_sha256'], approved)
        self.assertEqual({path.name for path in self.output.iterdir()}, set(approved))
        self.assertEqual({path.name for path in work.iterdir()}, {'src', 'pkg', 'build.log'})

    @unittest.skipUnless(PACKET.is_file(), 'selected source packet is unavailable')
    def test_retained_packet_materializes_exact_flat_template_once(self):
        report = self.materialize()
        self.assertEqual(report['status'], 'materialized-source-only')
        self.assertEqual(report['files'], 900)
        self.assertGreater(report['bytes'], 0)
        self.assertEqual(report['native_build'], 'NOT RUN')
        self.assertEqual(report['host_build_install'], 'NOT RUN')
        expected = {path.name: path.read_bytes() for path in HERE.iterdir()
                    if path.is_file() and path.name != source_check.PACKET}
        expected[source_check.PACKET] = PACKET.read_bytes()
        self.assertEqual({path.name for path in self.output.iterdir()}, set(expected))
        self.assertEqual(report['input_sha256'],
                         {name: hashlib.sha256(data).hexdigest()
                          for name, data in expected.items()})
        for name, data in expected.items():
            with self.subTest(name=name):
                path = self.output / name
                self.assertFalse(path.is_symlink())
                self.assertTrue(path.is_file())
                self.assertEqual(path.read_bytes(), data)


class SelectorFixtureTests(unittest.TestCase):
    def test_sorted_archive_is_deterministic_with_fixed_metadata(self):
        files = {'z/file.c': b'original synthetic source\n', 'a.h': b'original header\n'}
        first = selector.build_archive(files)
        self.assertEqual(first, selector.build_archive(dict(reversed(list(files.items())))))
        self.assertEqual(first[257:263], b'ustar\0')
        with tarfile.open(fileobj=io.BytesIO(first), mode='r:') as archive:
            members = list(archive)
            self.assertEqual([member.name for member in members],
                             [source_check.PREFIX + name for name in sorted(files)])
            for member in members:
                self.assertEqual(member.type, tarfile.REGTYPE)
                self.assertEqual((member.mode, member.uid, member.gid, member.mtime),
                                 (0o644, 0, 0, 1791748800))
                self.assertEqual((member.uname, member.gname), ('', ''))
                with archive.extractfile(member) as stream:
                    self.assertEqual(stream.read(), files[member.name[len(source_check.PREFIX):]])

    def test_unsafe_output_member_names_fail(self):
        for name in ('../source.c', '/source.c', 'a/../source.c', 'a//source.c',
                     'a/./source.c', '.', '', 'a\\source.c'):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    selector.build_archive({name: b'original synthetic source'})

    def test_upstream_member_outside_fixed_archive_root_is_rejected(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            member = tarfile.TarInfo('outside/source.c')
            data = b'original synthetic source'
            member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
        data = buffer.getvalue()
        with mock.patch.object(selector, 'UPSTREAM_SHA', hashlib.sha256(data).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'invalid source member'):
                selector.selected_data(data)

    def test_wrong_input_digest_and_existing_output_fail_without_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wrong, output = root / 'wrong.tar.gz', root / 'selected.tar.gz'
            wrong.write_bytes(b'not a pinned source packet')
            with self.assertRaises(ValueError):
                selector.create_codec_packet(wrong, output)
            self.assertFalse(output.exists())
            output.write_bytes(b'keep existing bytes')
            with self.assertRaises(ValueError):
                selector.create_codec_packet(wrong, output)
            self.assertEqual(output.read_bytes(), b'keep existing bytes')


class TransportTests(unittest.TestCase):
    class Response(io.BytesIO):
        def __init__(self, data, url=selector.UPSTREAM_URL):
            super().__init__(data)
            self.url, self.read_sizes = url, []

        def geturl(self):
            return self.url

        def read(self, size=-1):
            self.read_sizes.append(size)
            return super().read(size)

    def test_transport_uses_fixed_commit_timeout_and_bounded_read(self):
        data = b'F' * 4707099
        response = self.Response(data)
        with mock.patch.object(selector, 'UPSTREAM_SHA', hashlib.sha256(data).hexdigest()), \
             mock.patch.object(selector.urllib.request, 'urlopen', return_value=response) as opened:
            self.assertEqual(selector.fetch_upstream(), data)
        request = opened.call_args.args[0]
        self.assertEqual(request.full_url, selector.UPSTREAM_URL)
        self.assertTrue(request.full_url.endswith(source_check.COMMIT))
        self.assertEqual(opened.call_args.kwargs, {'timeout': 30})
        self.assertEqual(response.read_sizes, [8 * 1024 * 1024 + 1])

    def test_bad_digest_and_short_body_are_rejected(self):
        for data in (b'F' * 4707099, b'truncated fixture'):
            with self.subTest(length=len(data)):
                response = self.Response(data)
                with mock.patch.object(selector.urllib.request, 'urlopen', return_value=response):
                    with self.assertRaisesRegex(ValueError, 'fixed commit archive'):
                        selector.fetch_upstream()

    def test_oversized_response_is_bounded_and_rejected(self):
        response = self.Response(b'F' * (8 * 1024 * 1024 + 2))
        with mock.patch.object(selector.urllib.request, 'urlopen', return_value=response):
            with self.assertRaisesRegex(ValueError, 'fixed commit archive'):
                selector.fetch_upstream()
        self.assertEqual(response.read_sizes, [8 * 1024 * 1024 + 1])

    def test_redirects_to_http_or_other_host_fail_before_body_read(self):
        for url in ('http://codeload.github.com/source', 'https://untrusted.invalid/source',
                    'https://codeload.github.com.untrusted.invalid/source'):
            with self.subTest(url=url):
                response = self.Response(b'never read this fixture', url)
                with mock.patch.object(selector.urllib.request, 'urlopen', return_value=response):
                    with self.assertRaisesRegex(ValueError, 'redirected'):
                        selector.fetch_upstream()
                self.assertEqual(response.read_sizes, [])

    def test_transport_failure_leaves_no_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'selected.tar.gz'
            with mock.patch.object(selector.urllib.request, 'urlopen', side_effect=OSError('fixture offline')):
                with self.assertRaises(OSError):
                    selector.create_codec_packet(None, output)
            self.assertFalse(output.exists())


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'checkout'
        self.base = self.repo / 'packages' / 'codec'
        self.base.mkdir(parents=True)
        shutil.copyfile(HERE / 'build-layout.json', self.base / 'build-layout.json')

    def regular_gitdir(self, head):
        gitdir = self.repo / '.git'
        gitdir.mkdir()
        (gitdir / 'objects').mkdir()
        (gitdir / 'refs').mkdir()
        (gitdir / 'HEAD').write_text(head + '\n')
        return gitdir

    def test_detached_and_symbolic_heads_recognize_actual_repository_structure(self):
        gitdir = self.regular_gitdir('a' * 40)
        for head in ('a' * 40, 'b' * 64, 'ref: refs/heads/fixture'):
            with self.subTest(head=head):
                (gitdir / 'HEAD').write_text(head + '\n')
                with mock.patch('subprocess.run', side_effect=AssertionError('Git command forbidden')):
                    self.assertEqual(source_check.repository_roots(self.base), [self.base, self.repo])
        for head in ('not a HEAD', 'ref: refs/heads/../unsafe', 'ref: refs/heads/two words'):
            with self.subTest(head=head):
                (gitdir / 'HEAD').write_text(head + '\n')
                self.assertEqual(source_check.repository_roots(self.base), [self.base])
        (gitdir / 'HEAD').write_text('a' * 40)
        (gitdir / 'refs').rmdir()
        self.assertEqual(source_check.repository_roots(self.base), [self.base])

    def test_valid_repository_output_is_refused_before_source_access(self):
        self.regular_gitdir('ref: refs/heads/fixture')
        output = self.repo / 'selected.tar.gz'
        with mock.patch.object(selector, 'HERE', self.base), \
             mock.patch.object(selector, 'fetch_upstream', side_effect=AssertionError('source access forbidden')):
            with self.assertRaisesRegex(ValueError, 'outside the repository'):
                selector.create_codec_packet(None, output)
        self.assertFalse(output.exists())

    def test_worktree_gitfile_and_commondir_are_recognized_without_git(self):
        common = self.root / 'metadata'
        gitdir = common / 'worktrees' / 'fixture'
        gitdir.mkdir(parents=True)
        (common / 'objects').mkdir()
        (common / 'refs').mkdir()
        (gitdir / 'HEAD').write_text('ref: refs/heads/fixture\n')
        (gitdir / 'commondir').write_text('../..\n')
        (self.repo / '.git').write_text('gitdir: ../metadata/worktrees/fixture\n')
        before = {path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}
        with mock.patch('subprocess.run', side_effect=AssertionError('Git command forbidden')):
            self.assertEqual(source_check.repository_roots(self.base), [self.base, self.repo])
        with mock.patch.object(selector, 'HERE', self.base):
            with self.assertRaisesRegex(ValueError, 'outside the repository'):
                selector.create_codec_packet(None, self.repo / 'blocked.tar.gz')
        self.assertEqual({path: path.read_bytes() for path in self.root.rglob('*') if path.is_file()}, before)

    @unittest.skipUnless(PACKET.is_file(), 'selected source packet is unavailable')
    def test_invalid_stray_marker_does_not_block_external_source_output(self):
        marker = self.repo / '.git'
        marker.write_text('not a gitdir pointer\n')
        before = marker.read_bytes()
        output = self.repo / 'selected.tar.gz'
        self.assertEqual(source_check.repository_roots(self.base), [self.base])
        with mock.patch.object(selector, 'HERE', self.base):
            report = selector.create_codec_packet(PACKET, output)
        self.assertEqual(report['packet_sha256'], source_check.PACKET_SHA)
        self.assertEqual(marker.read_bytes(), before)

    @unittest.skipUnless(PACKET.is_file(), 'selected source packet is unavailable')
    def test_valid_repository_allows_output_beyond_its_boundary(self):
        self.regular_gitdir('a' * 40)
        output = self.root / 'selected.tar.gz'
        with mock.patch.object(selector, 'HERE', self.base):
            report = selector.create_codec_packet(PACKET, output)
        self.assertEqual(report['packet_sha256'], source_check.PACKET_SHA)
        self.assertFalse((self.repo / 'selected.tar.gz').exists())


class SelectorPacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.input = PACKET if PACKET.is_file() else PRIVATE_PACKET
        if not cls.input.is_file():
            raise unittest.SkipTest('selected and private source packets are unavailable')
        cls.files = selector.selected_bytes(cls.input)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def fixture_packet(self, files):
        packet = self.root / 'fixture.tar.gz'
        packet.write_bytes(gzip.compress(selector.build_archive(files), mtime=0))
        return packet, hashlib.sha256(packet.read_bytes()).hexdigest()

    def test_exact_900_file_scope_omits_ungranted_scaffold_and_assets(self):
        layout = json.loads(source_check.read_regular(HERE / 'build-layout.json', 1024 * 1024))
        expected = set(layout['selected_implementation_files']) | {'NOTICE', 'xhe-aac/NOTICE'}
        self.assertEqual(set(self.files), expected)
        self.assertEqual(len(self.files), 900)
        excluded = {'CMakeLists.txt', 'Makefile.am', 'configure.ac', 'README.md',
                    'Android.bp', 'rust/bitstreams/input.rawpkts',
                    'cpp/documentation/aacEncoder.pdf', 'cpp/documentation/aacDecoder.pdf',
                    'Apache-2.0.txt', 'rust/build.rs'}
        self.assertFalse(excluded & set(self.files))
        for name, record in layout['selected_implementation_files'].items():
            raw = self.files[name]
            self.assertEqual(len(raw), record['bytes'], name)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), record['sha256'], name)
            self.assertIn(b'Fraunhofer', raw, name)
            self.assertIn(b'Redistribution and use in source and binary forms', raw, name)
        for notice, (name, digest) in source_check.NOTICES.items():
            if name:
                self.assertEqual(hashlib.sha256(self.files[name]).hexdigest(), digest, notice)

    @unittest.skipUnless(PRIVATE_PACKET.is_file(), 'historical private packet is unavailable')
    def test_private_packet_selection_matches_only_clean_codec_bytes(self):
        self.assertEqual(selector.selected_bytes(PRIVATE_PACKET), self.files)

    def test_two_clean_packets_have_identical_pinned_bytes(self):
        first, second = self.root / 'first.tar.gz', self.root / 'second.tar.gz'
        report = selector.create_codec_packet(self.input, first)
        selector.create_codec_packet(self.input, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(report['files'], 900)
        self.assertEqual(report['packet_sha256'], source_check.PACKET_SHA)
        self.assertFalse(report['upstream_scaffold_copied'])
        self.assertEqual(report['codec_source_modifications'], [])
        self.assertEqual(report['native_build'], 'NOT RUN')
        self.assertEqual(report['publication'], 'NOT RUN')
        self.assertEqual(report['input_sha256'], records(self.files))

    def test_real_raw_packet_rejects_trailing_truncated_changed_and_gzip_bytes_before_parser(self):
        raw = selector.build_archive(self.files)
        self.assertEqual(len(raw), source_check.PACKET_BYTES)
        self.assertEqual(sha := hashlib.sha256(raw).hexdigest(), source_check.PACKET_SHA)
        for altered in (raw[:-1], raw + b'\0', b'X' + raw[1:], gzip.compress(raw, mtime=0)):
            with self.subTest(length=len(altered)):
                path = self.root / 'altered.tar'; path.write_bytes(altered)
                with mock.patch.object(source_check.tarfile, 'open', side_effect=AssertionError('parser reached')):
                    with self.assertRaises(ValueError):source_check.verify_packet(path)
        path = self.root / source_check.PACKET; path.write_bytes(raw)
        self.assertEqual(source_check.verify_packet(path)['files'], 900)


    def test_fetched_upstream_selection_omits_five_ungranted_assets(self):
        buffer = io.BytesIO()
        files = {**self.files, 'CMakeLists.txt': b'original ungranted scaffold fixture',
                 'README.md': b'original ungranted wrapper fixture',
                 'cpp/documentation/aacDecoder.pdf': b'original restricted document fixture',
                 'rust/bitstreams/input.rawpkts': b'original ungranted test asset fixture',
                 'rust/build.rs': b'original ungranted build wrapper fixture'}
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            for name, data in files.items():
                member = tarfile.TarInfo(selector.UPSTREAM_PREFIX + name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        original = buffer.getvalue()
        digest = hashlib.sha256(original).hexdigest()
        output = self.root / 'fetched-selected.tar.gz'
        with mock.patch.object(selector, 'UPSTREAM_SHA', digest), \
             mock.patch.object(selector, 'fetch_upstream', return_value=original) as fetched:
            self.assertEqual(selector.selected_data(original), self.files)
            report = selector.create_codec_packet(None, output)
        fetched.assert_called_once_with()
        self.assertEqual(report['packet_sha256'], source_check.PACKET_SHA)
        self.assertEqual(report['producer_input_sha256'], digest)
        self.assertEqual(report['files'], 900)
        self.assertEqual(report['input_sha256'], records(self.files))
        self.assertEqual(set(self.root.iterdir()), {output})

    def test_missing_implementation_fails_after_fixture_digest_gate(self):
        files = dict(self.files)
        missing = next(name for name in files if name.endswith(('.c', '.cpp')))
        del files[missing]
        packet, digest = self.fixture_packet(files)
        with mock.patch.object(selector, 'PRIVATE_SHA', digest):
            with self.assertRaisesRegex(ValueError, 'inventory incomplete'):
                selector.selected_bytes(packet)

    def test_changed_grant_fails_after_fixture_digest_gate(self):
        files = dict(self.files)
        files['NOTICE'] = b'X' + files['NOTICE'][1:]
        packet, digest = self.fixture_packet(files)
        with mock.patch.object(selector, 'PRIVATE_SHA', digest):
            with self.assertRaisesRegex(ValueError, 'source bytes changed'):
                selector.selected_bytes(packet)

    def test_grant_marker_is_required_even_with_fixture_byte_pin(self):
        files = dict(self.files)
        name = next(name for name in files if name.endswith(('.c', '.cpp')))
        files[name] = files[name].replace(b'Fraunhofer', b'Unauthored')
        packet, digest = self.fixture_packet(files)
        layout = json.loads(source_check.read_regular(HERE / 'build-layout.json', 1024 * 1024))
        layout['selected_implementation_files'][name] = records({name: files[name]})[name]
        layout_bytes = json.dumps(layout).encode()
        original_read = selector.read_regular
        def fixture_read(path, limit):
            return layout_bytes if Path(path).name == 'build-layout.json' else original_read(path, limit)
        with mock.patch.object(selector, 'PRIVATE_SHA', digest), \
             mock.patch.object(selector, 'read_regular', side_effect=fixture_read):
            with self.assertRaisesRegex(ValueError, 'source grant absent'):
                selector.selected_bytes(packet)


if __name__ == '__main__':
    unittest.main()
