#!/usr/bin/env python3
"""Inert retrieval corruption/bounds/credential and public-retention checks."""
import base64
import hashlib
import importlib.util
import io
import contextlib
import json
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import urllib.error
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'scripts/checks/package_checks.py').is_file())


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


trial = load('audio_retrieval', HERE / 'retrieve_audio.py')
composition = load('audio_public_retention', ROOT / 'scripts/ci/full-development-composition/run.py')


class Response(io.BytesIO):
    status = 200
    headers = {}


class Retrieval(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.output = self.root / 'output'; self.output.mkdir()
        self.row = {'filename': 'fixture.pkg.tar.xz', 'size': 7, 'sha256': hashlib.sha256(b'package').hexdigest()}

    def frame(self, extra=None, extra_type=tarfile.REGTYPE):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w:gz') as archive:
            for path, data in (('fixture/inputs/private-source.tar.gz', b'private source'),
                               ('fixture/artifacts/' + self.row['filename'], b'package')):
                member = tarfile.TarInfo(path); member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            if extra:
                member = tarfile.TarInfo(extra); member.size = 1; member.type = extra_type
                archive.addfile(member, io.BytesIO(b'x'))
        return output.getvalue()

    def bundle(self, data=None, *, corrupt=False, zip_extra=None):
        data = self.frame() if data is None else data
        digest = hashlib.sha256(data).hexdigest()
        body = base64.encodebytes(data)
        if corrupt: body = body.replace(body[:1], b'A' if body[:1] != b'A' else b'B', 1)
        lines = [f'CACHY_ASAHI_EVIDENCE_BEGIN fixture sha256={digest} bytes={len(data)}'.encode(), *body.splitlines(), b'CACHY_ASAHI_EVIDENCE_END fixture']
        log = b''.join(b'2026-10-15T18:59:01.123Z ' + line + b'\n' for line in lines)
        path = self.root / 'logs.zip'
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('native/retention.txt', log); z.writestr('0_native.txt', b'ignored aggregate')
            if zip_extra: z.writestr(zip_extra, b'ignored')
        return path, {'fixture': ('fixture-package', len(data), digest)}

    def decode(self, path, wanted):
        trial.decode(path, 'native/retention.txt', {'fixture'}, wanted, {'fixture-package': self.row}, self.output)

    def test_only_exact_package_member_is_written(self):
        self.assertEqual(hashlib.sha256((HERE / 'audio-inputs.json').read_bytes()).hexdigest(), trial.POLICY)
        path, wanted = self.bundle(); self.decode(path, wanted)
        self.assertEqual([p.name for p in self.output.iterdir()], [self.row['filename']])
        self.assertEqual((self.output / self.row['filename']).read_bytes(), b'package')
        self.assertEqual((self.output / self.row['filename']).stat().st_mode & 0o777, 0o600)

    def test_frame_and_package_pin_corruption_refused(self):
        path, wanted = self.bundle(corrupt=True)
        with self.assertRaisesRegex(trial.Refused, 'compressed-pin'): self.decode(path, wanted)
        path, wanted = self.bundle(); self.row['sha256'] = '0' * 64
        with self.assertRaisesRegex(trial.Refused, 'package-byte-pin'): self.decode(path, wanted)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_tar_paths_duplicates_and_zip_paths_refused(self):
        for extra in ('fixture/../escape', 'fixture/artifacts/' + self.row['filename']):
            path, wanted = self.bundle(self.frame(extra))
            with self.subTest(path=extra), self.assertRaisesRegex(trial.Refused, 'frame-member'):
                self.decode(path, wanted)
        path, wanted = self.bundle(self.frame('fixture/special', tarfile.CONTTYPE))
        with self.assertRaisesRegex(trial.Refused, 'frame-member'): self.decode(path, wanted)
        path, wanted = self.bundle(zip_extra='../escape')
        with self.assertRaisesRegex(trial.Refused, 'zip-entry'): self.decode(path, wanted)

    def test_zip_central_budget_precedes_zipfile_allocation(self):
        path = self.root / 'oversized-directory.zip'
        with zipfile.ZipFile(path, 'w') as z:
            for number in range(65): z.writestr(str(number), b'')
        with patch.object(trial.zipfile, 'ZipFile') as parser, self.assertRaisesRegex(trial.Refused, 'directory-budget'):
            trial.decode(path, 'unused', set(), {}, {}, self.output)
        parser.assert_not_called()

    def test_redirect_drops_auth_and_foreign_host_refused(self):
        signed = 'https://fixture.blob.core.windows.net/private?signature=TEST'
        redirect = urllib.error.HTTPError('https://api.github.com/fixed', 302, 'redirect', {'Location': signed}, None)
        opener = Mock(); opener.open.side_effect = [redirect, Response(b'input')]
        with patch.object(trial.urllib.request, 'build_opener', return_value=opener):
            trial.fetch('https://api.github.com/fixed', self.root / 'input', 5, time.monotonic() + 10, token='TEST-token')
        first, second = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual(first.get_header('Authorization'), 'Bearer TEST-token')
        self.assertIsNone(second.get_header('Authorization'))
        self.assertFalse(trial.url_allowed('http://fixture.blob.core.windows.net/insecure', True))
        self.assertFalse(trial.url_allowed('https://fixture.invalid/private', True))
        self.assertFalse(trial.url_allowed('https://api.github.com/fixed', False))

    def test_download_budget_refuses_excess(self):
        opener = Mock(); opener.open.return_value = Response(b'exceeds-budget')
        with patch.object(trial.urllib.request, 'build_opener', return_value=opener), self.assertRaisesRegex(trial.Refused, 'download-size'):
            trial.fetch(trial.LSP, self.root / 'excess', 4, time.monotonic() + 10)

    def aggregate_fixture(self, run_row, *, duplicate=False, bad_pin=False, wrong_shape=False, primary=False):
        run, expected, frames, original_wanted = run_row
        blocks, wanted, policy = [], {}, {}
        for frame in sorted(frames):
            data = b'skipped-frame'
            if frame in original_wanted:
                row = dict(self.row, filename=frame + '.pkg.tar.xz')
                policy[frame] = row
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode='w:gz') as archive:
                    member = tarfile.TarInfo(frame + '/artifacts/' + row['filename'])
                    member.size = 7; archive.addfile(member, io.BytesIO(b'package'))
                data = stream.getvalue()
            digest = hashlib.sha256(data).hexdigest()
            if frame in original_wanted: wanted[frame] = (frame, len(data), digest)
            blocks.append((f'CACHY_ASAHI_EVIDENCE_BEGIN {frame} sha256={digest} bytes={len(data)}\n'.encode()
                + base64.encodebytes(data) + f'CACHY_ASAHI_EVIDENCE_END {frame}\n'.encode()))
        if duplicate: blocks.append(blocks[0])
        if bad_pin:
            first = next(iter(wanted)); package, size, _ = wanted[first]
            wanted[first] = (package, size, '0' * 64)
        path = self.root / (run + '.zip')
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr('0_native.txt', b'INVALID_AGGREGATE_IGNORED' if primary else b''.join(blocks))
            z.writestr('native/system.txt', b'ignored')
            if primary: z.writestr(expected, b''.join(blocks))
            if wrong_shape: z.writestr('native/1_Set up job.txt', b'ignored')
        output = self.root / ('aggregate-' + str(len(list(self.root.iterdir())))); output.mkdir()
        return path, expected, frames, wanted, policy, output

    def test_exact_two_member_aggregate_six_and_eight_frames(self):
        for run_row in trial.RUNS:
            with self.subTest(run=run_row[0]):
                args = self.aggregate_fixture(run_row)
                trial.decode(*args)
                output = args[-1]
                self.assertEqual({p.name for p in output.iterdir()}, {r['filename'] for r in args[-2].values()})
                self.assertTrue(all(p.read_bytes() == b'package' for p in output.iterdir()))
                self.assertEqual(len(args[2]), 6 if run_row is trial.RUNS[0] else 8)

    def test_frozen_per_step_member_remains_primary(self):
        trial.decode(*self.aggregate_fixture(trial.RUNS[1], primary=True))

    def test_aggregate_duplicate_frame_wrong_shape_and_pin_refused(self):
        for options, reason in (({'duplicate': True}, 'unexpected-frame'),
                                ({'wrong_shape': True}, 'fixed-retention-step-missing'),
                                ({'bad_pin': True}, 'frame-header-pin-refused')):
            with self.subTest(options=options), self.assertRaisesRegex(trial.Refused, reason):
                trial.decode(*self.aggregate_fixture(trial.RUNS[1], **options))
        args = list(self.aggregate_fixture(trial.RUNS[0])); args[1] = 'native/9_Unreviewed step.txt'
        with self.assertRaisesRegex(trial.Refused, 'fixed-retention-step-missing'):
            trial.decode(*args)

    def test_missing_step_reports_fixed_run_zip_and_bounded_public_labels(self):
        for run, expected, frames, wanted in trial.RUNS:
            path = self.root / (run + '.zip')
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('0_native.txt', b'PRIVATE_LOG_BODY')
                z.writestr('renamed-native/6_Retain public diagnostics, source snapshots and package pairs.txt', b'PRIVATE_BINARY')
                z.writestr('native/1_Set up job.txt', b'PRIVATE_TOKEN')
                z.writestr('native/private-notes-SECRET', b'PRIVATE_KEY')
            with patch.object(trial, 'extract_package') as extract, self.assertRaisesRegex(trial.Refused, 'fixed-retention-step-missing') as caught:
                trial.decode(path, expected, frames, wanted, {}, self.output)
            extract.assert_not_called()
            report = caught.exception.lookup
            self.assertEqual(report['run_id'], run)
            self.assertEqual(report['expected_step'], expected)
            self.assertEqual(report['zip_bytes'], path.stat().st_size)
            self.assertEqual(report['zip_sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(report['member_count'], 4)
            self.assertEqual(report['other_members'], 1)
            self.assertFalse(report['labels_truncated'])
            self.assertEqual(report['public_step_labels'], ['0_native.txt', 'native/1_Set up job.txt',
                'renamed-native/6_Retain public diagnostics, source snapshots and package pairs.txt'])
            out = io.StringIO()
            with patch.object(trial, 'retrieve', side_effect=caught.exception), patch('sys.argv', ['retrieve', '--output', str(self.output)]), contextlib.redirect_stdout(out):
                self.assertEqual(trial.main(), 1)
            text = out.getvalue()
            self.assertIn('AUDIO_INPUT_RETRIEVAL_LOOKUP=', text)
            self.assertIn('AUDIO_INPUT_RETRIEVAL=FAIL fixed-retention-step-missing', text)
            for private in ('SECRET', 'PRIVATE_', 'https:', 'Bearer', 'GH_TOKEN'):
                self.assertNotIn(private, text)
            self.assertEqual(list(self.output.iterdir()), [])

    def test_missing_step_labels_are_closed_and_truncated(self):
        run, expected, frames, wanted = trial.RUNS[1]
        path = self.root / (run + '.zip')
        with zipfile.ZipFile(path, 'w') as z:
            for i in range(24): z.writestr('native/' + str(i) + '_Public fixture.txt', b'ignored')
            for name in ('native/25_Unicode-é.txt', 'native/26_URL_https:fixture.txt', 'other/secret.asc'):
                z.writestr(name, b'PRIVATE')
        with self.assertRaises(trial.Refused) as caught:
            trial.decode(path, expected, frames, wanted, {}, self.output)
        report = caught.exception.lookup
        self.assertEqual(len(report['public_step_labels']), 16)
        self.assertTrue(report['labels_truncated'])
        self.assertEqual(report['other_members'], 3)
        self.assertLess(len(json.dumps(report)), 4096)
        self.assertNotIn('secret', json.dumps(report))

    def test_public_retention_excludes_private_archives_sources_and_keys(self):
        raw, public = self.root / 'private', self.root / 'public'
        (raw / 'inputs').mkdir(parents=True); public.mkdir()
        for name in ('audio.pkg.tar.xz', 'lsp.pkg.tar.xz.sig', 'source.tar.gz', 'TEST-secret'):
            (raw / 'inputs' / name).write_bytes(b'PRIVATE-BINARY-OR-SOURCE')
        (raw / 'audio-summary.json').write_text('{"transaction":"NOT RUN"}\n')
        composition.retain(raw, public)
        composition.retain_updater(self.root, raw, public)
        self.assertEqual([str(p.relative_to(public)) for p in public.rglob('*') if p.is_file()], ['diagnostics/audio-summary.json'])
        self.assertNotIn(b'PRIVATE-BINARY-OR-SOURCE', next(p for p in public.rglob('*') if p.is_file()).read_bytes())


if __name__ == '__main__': unittest.main()
