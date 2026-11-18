#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Replay the retained R127 archive through the maintained Fish constructor."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('fish_prepare_r12', HERE/'prepare.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
IO = P.P
ORIGINAL_SHA = '82dacd72f1201f6478cd48620b566b3c4349e8347ed595bcaeb2d092c8029abd'
CHECK_PIN = dict(bytes=186, sha256='1d6b1629e20ffbd06508ef8a9b43e5a0c87a01a238b5dbea12410985db6f12b5')
PACKAGE_PIN = dict(bytes=5516, sha256='6dee81130f3ba3e570791cf079d2152893461ec27fa6e2e34a3d614986f9a949')


def archived_evidence(original):
    raw = IO.read(original)
    if IO.pin(raw)['sha256'] != ORIGINAL_SHA:
        raise ValueError('exact original R127 evidence archive required')
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive:
            name = member.name.partition('/evidence/')[2]
            if name and member.isfile():
                path = PurePosixPath(name)
                if path.is_absolute() or '..' in path.parts or name in files:
                    raise ValueError('unsafe archived evidence member')
                with archive.extractfile(member) as stream:
                    files[name] = stream.read()
    manifest = json.loads(files.pop('inner-public-manifest.json'))
    if {name: IO.pin(raw) for name, raw in files.items()} != manifest['files']:
        raise ValueError('original R127 inner manifest differs')
    return files, manifest


class Retention(unittest.TestCase):
    def test_exact_constructor_and_r127_export(self):
        files, manifest = archived_evidence(ARGS.original)
        with tempfile.TemporaryDirectory(prefix='fish-r12-data-') as name:
            root = Path(name)
            source = root/'source'
            construction = P.construct(ARGS.base, source)
            self.assertEqual(construction['tree'], P.R12['tree'])
            self.assertEqual(construction['source_map'], P.R12['map'])
            self.assertIsNone(construction['Root_authority'])
            exporter = IO.load_bytes((source/P.EXPORT).read_bytes(), 'constructed_exporter', source/P.EXPORT)
            old = IO.load_bytes((ARGS.base/P.EXPORT).read_bytes(), 'archived_exporter', ARGS.base/P.EXPORT)
            retention = json.loads((source/P.POLICY).read_bytes())['inner_public_retention']
            self.assertEqual(exporter.DECLARATION, retention)
            for field in ('public_leaves', 'success_required'):
                changes = [(before, after) for before, after in zip(old.DECLARATION[field], retention[field], strict=True)
                           if before != after]
                self.assertEqual(changes, [(f'build-{i}/artifacts/{P.OLD_LOG}', f'build-{i}/artifacts/{P.NEW_LOG}')
                                           for i in (1, 2)])
            inner = root/'volume/work/fish02-native'
            public = root/'evidence'
            report = json.loads(files['report.json'])
            context = {key: report[key] for key in ('source', 'ref', 'source_map_sha256', 'run', 'attempt', 'job', 'nonce')}
            original_manifest_paths = []
            for build in (1, 2):
                prefix = f'build-{build}/'
                log, = [line for line in files[prefix+'build.log'].splitlines(keepends=True) if line.startswith(b'PASS:')]
                self.assertEqual(IO.pin(log), CHECK_PIN)
                self.assertEqual(report['pair']['semantic_checks'][build-1], dict(CHECK_PIN, file=P.NEW_LOG))
                original_manifest_paths.append(prefix+'artifacts/'+P.OLD_LOG)
                self.assertEqual(IO.pin(files[prefix+'artifacts/'+exporter.PACKAGE+'.pkg.tar.xz']), PACKAGE_PIN)
                files[prefix+'artifacts/'+P.NEW_LOG] = log
            self.assertEqual(manifest['missing_required'], original_manifest_paths)
            for item, raw in files.items():
                leaf = inner/item
                leaf.parent.mkdir(parents=True, exist_ok=True)
                leaf.write_bytes(raw)
            exported = exporter.export(inner, public, context, os.getuid())
            self.assertEqual(exported['status'], 'EXPORTED')
            self.assertFalse(exported['accepting'])
            self.assertEqual(exported['missing_required'], [])
            self.assertEqual({name: IO.pin(raw) for name, raw in files.items()},
                             json.loads((public/'inner-public-manifest.json').read_bytes())['files'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--original', type=Path, required=True)
    ARGS = parser.parse_args()
    unittest.main(argv=[__file__], verbosity=2)
