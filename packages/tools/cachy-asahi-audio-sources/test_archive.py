#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Require the actual package archive and real source packet; no installation."""
import argparse
import importlib.util
import io
import json
from pathlib import Path
import shutil
import sys
import tempfile
import tarfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audio_package_test_helpers', HERE / 'test_package.py')
T = importlib.util.module_from_spec(spec); spec.loader.exec_module(T)
C = T.C


class ActualArchive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.recipe, cls.hidden = Path(ARGS.recipe_root).absolute(), Path(ARGS.hide_checkout).absolute()
        cls.temp = tempfile.TemporaryDirectory(prefix='audio-tool-actual-archive-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name)
        extracted = cls.root / 'archive-extracted'
        cls.receipt = C.archive(cls.recipe, Path(ARGS.archive).absolute(), extracted)
        cls.prefix = cls.root / 'moved-package-prefix'; extracted.rename(cls.prefix)
        cls.packet = cls.root / 'moved-caller-packet'; shutil.copytree(ARGS.packet, cls.packet)
        cls.index = C.sha((cls.packet / 'delivery.json').read_bytes())
        if cls.index != ARGS.sha256:
            raise AssertionError('actual source packet caller pin differs')
        cls.materials = cls.root / 'private-original-materials'; shutil.copytree(ARGS.materials, cls.materials)
        cls.wmidi = cls.root / 'private-wmidi'; cls.wmidi.mkdir(mode=0o700)
        for name in ('source.tar.gz', 'commit.json'):
            shutil.copyfile(Path(ARGS.wmidi) / name, cls.wmidi / name)

    def invoke(self, *args):
        return T.invoke(self.root, self.prefix, self.recipe, self.hidden, *args)

    def test_actual_archive_metadata_payload_and_moved_runtime(self):
        self.assertEqual(self.receipt['status'], 'PASS_ACTUAL_ARCHIVE_PAYLOAD_AND_METADATA')
        self.assertEqual(self.receipt['payload_files'], 17)
        child = self.invoke('check'); self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout)['files'], 10)

    def test_archive_directory_and_ownership_tamper_refuse(self):
        for kind in ('extra-directory', 'directory-mode', 'file-owner', 'installation-metadata'):
            with self.subTest(kind=kind):
                buffer = io.BytesIO()
                with tarfile.open(ARGS.archive) as original, tarfile.open(fileobj=buffer, mode='w') as changed:
                    for node in original:
                        if kind == 'directory-mode' and node.name.rstrip('/') == 'usr':
                            node.mode = 0o777
                        if kind == 'file-owner' and node.name == 'usr/bin/cachy-asahi-audio-sources':
                            node.uid = 1
                        with original.extractfile(node) if node.isfile() else io.BytesIO() as body:
                            raw = body.read()
                        if kind == 'installation-metadata' and node.name == '.PKGINFO':
                            raw += b'replaces = unrelated-package\n'; node.size = len(raw)
                        changed.addfile(node, io.BytesIO(raw) if node.isfile() else None)
                    if kind == 'extra-directory':
                        node = tarfile.TarInfo('etc'); node.type = tarfile.DIRTYPE; node.mode = 0o755
                        changed.addfile(node)
                source = self.root / (kind + '.tar'); source.write_bytes(buffer.getvalue())
                output = self.root / (kind + '-must-not-extract')
                with self.assertRaises(ValueError):
                    C.archive(self.recipe, source, output)
                self.assertFalse(output.exists())

    def test_real_packet_verify_with_hidden_checkout(self):
        child = self.invoke('verify', '--packet', self.packet, '--sha256', self.index)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        report = json.loads(child.stdout)
        self.assertEqual(report['registry']['exact_crates'], 117)
        self.assertEqual(report['registry']['exact_member_files'], 4292)
        self.assertFalse(report['holds']['legal_acceptance'])
        self.assertEqual(report['holds']['release'], 'NOT_ADMITTED')

    def test_real_export_from_extracted_moved_tool_then_offline_relocation(self):
        output = self.root / 'actual-installed-tool-export'
        child = self.invoke('export', '--handoff', self.packet / 'handoff', '--materials', self.materials,
                            '--wmidi', self.wmidi, '--output', output)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        report = json.loads(child.stdout)
        self.assertEqual(report['delivery_sha256'], self.index)
        moved = self.root / 'relocated-tool-produced-packet'; output.rename(moved)
        child = self.invoke('verify', '--packet', moved, '--sha256', self.index)
        self.assertEqual(child.returncode, 0, child.stdout + child.stderr)
        # Exported metadata must not carry the private original receipt's cache paths.
        for path in moved.rglob('*.json'):
            raw = path.read_bytes()
            for token in (b'/home/gabe/', b'original_path', b'tool_probes', b'CARGO_HOME'):
                self.assertNotIn(token, raw)

    def test_missing_or_tampered_packet_refuses(self):
        path = self.packet / 'registry/crates/wmidi-3.1.0.crate'; raw = path.read_bytes()
        try:
            path.write_bytes(raw + b'altered')
            child = self.invoke('verify', '--packet', self.packet, '--sha256', self.index)
            self.assertEqual(child.returncode, 2)
            path.unlink()
            child = self.invoke('verify', '--packet', self.packet, '--sha256', self.index)
            self.assertEqual(child.returncode, 2)
        finally:
            path.write_bytes(raw); path.chmod(0o600)

    def test_actual_archive_runtime_refusals_before_import(self):
        T.runtime_refusals(self, self.root, self.prefix, self.recipe, self.hidden)

    def test_payload_removal_inverse_preserves_caller_data(self):
        copy = self.root / 'removal-copy'; shutil.copytree(self.prefix, copy)
        sentinel = copy / 'caller-owned.txt'; sentinel.write_text('caller bytes')
        before = (self.packet / 'delivery.json').read_bytes()
        for name in C.payload(self.recipe):
            (copy / name).unlink()
        self.assertEqual([p.relative_to(copy).as_posix() for p in copy.rglob('*') if p.is_file()], ['caller-owned.txt'])
        self.assertEqual(sentinel.read_text(), 'caller bytes')
        self.assertEqual((self.packet / 'delivery.json').read_bytes(), before)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('recipe-root', 'archive', 'packet', 'sha256', 'materials', 'wmidi', 'hide-checkout'):
        parser.add_argument('--' + name, required=True)
    ARGS, rest = parser.parse_known_args()
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
