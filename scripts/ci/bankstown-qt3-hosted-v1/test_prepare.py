# SPDX-License-Identifier: MIT
"""Fenced DATA controls; tiny Source72 bodies are explicit MODEL input custody."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import sys
import tempfile
import unittest
from unittest import mock

resource.setrlimit(resource.RLIMIT_AS, (128 * 1024**2,) * 2)


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
            'os.system', 'os.exec', 'os.fork', 'os.posix_spawn'):
        raise AssertionError('ROLE_FORBIDDEN: ' + event)


sys.addaudithook(fence)
spec = importlib.util.spec_from_file_location('hosted_prepare_under_test', Path(__file__).with_name('prepare.py'))
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
ACTUAL_SOURCE = None


class Data(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bankstown-hosted-prepare-model-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source, self.runtime, self.output = [self.root / x for x in ('source', 'runtime', 'output')]
        self.source.mkdir()
        self.runtime.mkdir()
        self.P = M.helper()
        rows = {}
        for i in range(70):
            name, body = 'model/f' + str(i), ('MODEL body ' + str(i)).encode()
            p = self.source / name
            p.parent.mkdir(exist_ok=True)
            p.write_bytes(body)
            p.chmod(0o755 if i == 0 else 0o644)
            rows[name] = dict(M.pin(body), mode=stat.S_IMODE(p.stat().st_mode))
        self.raw = self.P.H.encoded(dict(schema=1, kind='BANKSTOWN_QT3_CLOSED_NATIVE_SOURCE_V1',
            operation='bankstown-qt3-native-private-test-v1', files=rows,
            actual=dict(source=None, ref=None, run=None, job=None, image=None, profile=None,
                        executor=None, Root_final_acceptance=None)))
        for name in ('source-map.json', 'source.lock.json'):
            (self.source / name).write_bytes(self.raw)
        for name in M.RUNTIME:
            p = self.runtime / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(self.raw if name == 'source72-map.DATA.json' else b'MODEL runtime DATA\n')
        # Only the historical Source's authenticity/required-member closure is modeled.
        # Actual preserved-row, namespace, mode, body, helper-copy and map logic runs.
        for patch in (mock.patch.object(M, 'SOURCE72_PIN', M.pin(self.raw)),
                      mock.patch.object(M, 'helper', return_value=self.P),
                      mock.patch.object(self.P, 'REQUIRED', set()),
                      mock.patch.object(self.P, 'required_members', return_value=set())):
            patch.start()
            self.addCleanup(patch.stop)

    def run_prepare(self):
        return M.prepare_source(source72=self.source, output=self.output, runtime_root=self.runtime)

    def test_positive_preserves_all_seventy_bodies_modes_and_unissued_fields(self):
        result = self.run_prepare()
        value = json.loads((self.output / 'source-map.json').read_bytes())
        self.assertEqual(value['files'] | {}, json.loads((self.output / 'source.lock.json').read_bytes())['files'])
        self.assertEqual(len(value['files']), 76)
        for name, row in json.loads(self.raw)['files'].items():
            self.assertEqual(value['files'][name], row)
            self.assertEqual((self.output / name).read_bytes(), (self.source / name).read_bytes())
            self.assertEqual(stat.S_IMODE((self.output / name).stat().st_mode), row['mode'])
        self.assertTrue(all(v is None for v in value['actual'].values()))
        self.assertIsNone(result['actual_source'])
        self.assertFalse(result['native_credit'])
        self.assertNotIn(M.PREFIX + 'prepare.py', value['files'])

    def test_body_tamper(self):
        (self.source / 'model/f0').write_bytes(b'wrong')
        with self.assertRaises(ValueError): self.run_prepare()
        self.assertFalse(self.output.exists())

    def test_mode_tamper(self):
        (self.source / 'model/f0').chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'MODE_CHANGED'): self.run_prepare()

    def test_map_alias_tamper(self):
        (self.source / 'source.lock.json').write_bytes(self.raw + b'\n')
        with self.assertRaises(ValueError): self.run_prepare()

    def test_map_alias_mode_changed(self):
        for name in ('source-map.json', 'source.lock.json'):
            with self.subTest(alias=name):
                path = self.source / name
                path.chmod(0o600)
                with self.assertRaisesRegex(ValueError, 'SOURCE72_MAP_MODE_CHANGED'):
                    self.run_prepare()
                path.chmod(0o644)
        self.assertFalse(self.output.exists())

    def test_extra_member_and_directory_refuse(self):
        (self.source / 'unlisted').mkdir()
        with self.assertRaisesRegex(ValueError, 'FOREIGN_SOURCE_DIRECTORY'): self.run_prepare()
        (self.source / 'unlisted').rmdir()
        (self.source / 'unlisted').write_bytes(b'foreign')
        with self.assertRaisesRegex(ValueError, 'FOREIGN_OR_ALIASED'): self.run_prepare()

    def test_symlink_and_hardlink_refuse(self):
        p = self.source / 'model/f0'
        p.unlink()
        p.symlink_to('f1')
        with self.assertRaisesRegex(ValueError, 'FOREIGN_OR_ALIASED'): self.run_prepare()
        p.unlink()
        os.link(self.source / 'model/f1', p)
        with self.assertRaisesRegex(ValueError, 'FOREIGN_OR_ALIASED'): self.run_prepare()

    def test_retained_oldmap_tamper(self):
        (self.runtime / 'source72-map.DATA.json').write_bytes(b'wrong')
        with self.assertRaisesRegex(ValueError, 'RETAINED_SOURCE72_MAP'): self.run_prepare()

    def test_missing_or_aliased_runtime_refuses(self):
        p = self.runtime / 'hosted.py'
        p.unlink()
        with self.assertRaisesRegex(ValueError, 'ORDINARY_FINITE'): self.run_prepare()
        p.symlink_to('inputs.py')
        with self.assertRaisesRegex(ValueError, 'ORDINARY_FINITE'): self.run_prepare()

    def test_existing_output_unchanged(self):
        self.output.mkdir()
        (self.output / 'sentinel').write_bytes(b'keep')
        with self.assertRaisesRegex(ValueError, 'FRESH_AUDIO_SOURCE_OUTPUT'): self.run_prepare()
        self.assertEqual((self.output / 'sentinel').read_bytes(), b'keep')

    def test_output_inside_original_source_refuses_without_writes(self):
        output = self.source / 'new-output'
        with self.assertRaisesRegex(ValueError, 'SOURCE72_OUTPUT_DISJOINT'):
            M.prepare_source(source72=self.source, output=output, runtime_root=self.runtime)
        self.assertFalse(output.exists())

    def test_external_original_map_pin_refuses(self):
        with mock.patch.object(M, 'SOURCE72_PIN', dict(M.pin(self.raw), sha256='0' * 64)):
            with self.assertRaises(ValueError): self.run_prepare()


class Genuine(unittest.TestCase):
    def test_explicit_preserved_source72_data_only(self):
        if ACTUAL_SOURCE is None:
            self.skipTest('optional externally selected genuine Source72 not supplied')
        raw, rows = M.source72_rows(ACTUAL_SOURCE, M.helper())
        self.assertEqual(M.pin(raw), M.SOURCE72_PIN)
        self.assertEqual(len(rows), 70)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--source72', type=Path)
    args, remaining = parser.parse_known_args()
    ACTUAL_SOURCE = args.source72
    unittest.main(argv=[sys.argv[0], *remaining])
