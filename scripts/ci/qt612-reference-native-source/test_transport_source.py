# SPDX-License-Identifier: MIT
"""Inert cache MODEL/refusals; signed inventory and native actors are not modeled."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('source_tests',HERE/'transport_source.py')
S = importlib.util.module_from_spec(spec); spec.loader.exec_module(S)
M = S.M


class SourceControls(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix='qt612-cache-MODEL-'); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name); self.source = self.root/'source'; self.source.mkdir()
        material = self.source/'source-material'; material.mkdir()
        self.archive = b'MODEL inert archive, no tar or native Qt result\n'
        (material/S.ARCHIVE).write_bytes(self.archive)
        row = dict(material=dict(id='qtbase612',path=S.ARCHIVE,**M.pin(self.archive)),
            url='https://example.invalid/MODEL.tar.xz',revision='MODEL',license='MODEL only',license_evidence=[])
        catalog = M.encoded(dict(schema_version=1,purpose='source-cache-inputs',sources=[row]))
        (material/'catalog.json').write_bytes(catalog)
        (material/'plan.json').write_bytes(M.encoded(dict(scope='MODEL_ONLY')))
        self.cache = self.root/'cache'
        self.addCleanup(patch.stopall)
        patch.object(S.P,'verify_producer_source',return_value={'scope':'MODEL_SOURCE_ONLY'}).start()

    def create(self): return S.prepare_cache(source=self.source,source_map_sha256='0'*64,output=self.cache)

    def test_private_cache_whole_byte_roundtrip(self):
        result = self.create()
        self.assertEqual(result['status'],'PREPARED_PRIVATE_OFFLINE_CACHE_DATA_ONLY')
        self.assertEqual(S.verify_cache(source=self.source,source_map_sha256='0'*64,cache=self.cache)['status'],
                         'PASS_PRIVATE_CACHE_WHOLE_PINS_ONLY')
        self.assertEqual((self.cache/'objects'/M.pin(self.archive)['sha256']).stat().st_mode&0o777,0o600)

    def test_cache_mutation_refused(self):
        self.create(); next((self.cache/'objects').iterdir()).write_bytes(b'CHANGED')
        with self.assertRaises(ValueError): S.verify_cache(source=self.source,source_map_sha256='0'*64,cache=self.cache)

    def test_cache_receipt_mutation_refused(self):
        self.create(); next((self.cache/'receipts').iterdir()).write_bytes(b'CHANGED')
        with self.assertRaises(ValueError): S.verify_cache(source=self.source,source_map_sha256='0'*64,cache=self.cache)

    def test_nonempty_partial_cache_refused(self):
        self.create(); (self.cache/'.partial/UNSELECTED').write_bytes(b'EXTRA')
        with self.assertRaises(ValueError): S.verify_cache(source=self.source,source_map_sha256='0'*64,cache=self.cache)

    def test_linked_object_refused(self):
        self.create(); p = next((self.cache/'objects').iterdir()); p.unlink()
        p.symlink_to(self.source/'source-material'/S.ARCHIVE)
        with self.assertRaises(ValueError): S.verify_cache(source=self.source,source_map_sha256='0'*64,cache=self.cache)

    def test_public_directory_mode_refused(self):
        self.create(); (self.cache/'objects').chmod(0o755)
        with self.assertRaises(ValueError): S.verify_cache(source=self.source,source_map_sha256='0'*64,cache=self.cache)

    def test_fresh_cache_required(self):
        self.create()
        with self.assertRaises(FileExistsError): self.create()

    def test_command_plan_uses_normal_source_arguments_without_loading_source_code(self):
        self.create()
        # If source code were imported this deliberately absent runtime would fail.
        commands = S.pair_commands(self.source,self.root/'out','sha256:'+'1'*64,'2'*64,nonce='3'*32,
                                  source_map_sha256='0'*64,source_cache=self.cache)
        for row in commands['builds']:
            for flag in ('--source-plan','--source-plan-sha256','--source-catalog','--source-cache'):
                self.assertIn(flag,row['argv'])
        self.assertFalse(commands['actor_enabled'])

    def test_parent_projection_has_exact_inverse_and_no_double_projection(self):
        raw = (HERE/'producer.py').read_bytes(); projected = S.project_producer(raw)
        self.assertEqual(projected.replace(b"root/'source-material'/",b"root/'recipe'/"),raw)
        with self.assertRaises(ValueError): S.project_producer(projected)


if __name__ == '__main__': unittest.main()
