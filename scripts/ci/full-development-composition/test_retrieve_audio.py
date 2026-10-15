#!/usr/bin/env python3
"""Inert retrieval corruption/bounds/credential and public-retention checks."""
import base64
import hashlib
import importlib.util
import io
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
candidate = ROOT / 'artifacts/development/full-composition-audio-20261015/candidate/scripts/ci/full-development-composition/run.py'
composition = load('audio_public_retention', candidate if candidate.is_file() else ROOT / 'scripts/ci/full-development-composition/run.py')


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
