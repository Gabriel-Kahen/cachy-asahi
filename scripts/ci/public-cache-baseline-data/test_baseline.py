#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Genuine public baseline DATA checks; no phase, guest or runtime acceptance."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import resource
import stat
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2,) * 2)
resource.setrlimit(resource.RLIMIT_CPU, (60,) * 2)
resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024**2,) * 2)
resource.setrlimit(resource.RLIMIT_NOFILE, (128,) * 2)
ATTEMPTS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn')) or event in (
            'os.system', 'os.kill', 'os.killpg', 'os.pidfd_open', 'fcntl.flock', 'resource.setrlimit'):
        ATTEMPTS.append(event); raise AssertionError('PUBLIC_BASELINE_DATA_NO_ACTOR: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('public_baseline_caller_tests', HERE / 'caller.py')
A = importlib.util.module_from_spec(spec); spec.loader.exec_module(A)
C, P, T = A.helpers()
BODY = A.whole(HERE / 'baseline-cache.bin', A.BASELINE)
PROVIDERS = T.qualified_providers()
NAMES = {'libdb-5.3.so', 'libdb_cxx-5.3.so', 'libdb_stl-5.3.so'}


def derive(body=BODY, projection=PROVIDERS):
    return T.derive(body, projection['baseline_nodes'], projection['db_nodes'], projection['db_elf_sonames'])


class Controls(unittest.TestCase):
    def test_exact_fixture_and_public_provenance(self):
        self.assertEqual(A.pin(BODY), A.BASELINE)
        self.assertEqual(stat.S_IMODE((HERE / 'baseline-cache.bin').stat().st_mode), 0o644)
        proof = json.loads((HERE / 'provenance.DATA.json').read_bytes())
        self.assertEqual(proof['fixture'], dict(path='baseline-cache.bin', mode=0o644, **A.BASELINE))
        self.assertEqual(proof['source_reference']['baseline_descriptor'], 'baseline-public.DATA.json')
        A.whole(A.FAMILY / 'baseline-public.DATA.json', proof['source_reference']['baseline_descriptor_pin'])
        self.assertFalse(proof['origin']['fresh_scan_performed_here'])
        self.assertFalse(proof['origin']['private_Root_records_copied'])
        for key in ('Root_authority', 'Root_acceptance', 'lifecycle_acceptance', 'VM', 'M2', 'release'):
            self.assertIsNone(proof[key])

    def test_finite358_canonical_decode_and_roundtrip(self):
        decoded = C.decode(BODY)
        self.assertEqual(len(decoded['entries']), 358)
        self.assertEqual(C.encode(decoded['entries']), BODY)
        self.assertEqual(decoded['architecture'], 'AARCH64_LITTLE_ENDIAN')
        self.assertIsNone(decoded['Root_acceptance']); self.assertIsNone(decoded['lifecycle_acceptance'])

    def test_all_baseline_targets_join_pinned_provider_projection(self):
        rows = C.decode(BODY)['entries']; joined = P.join(rows, PROVIDERS['baseline_nodes'])
        self.assertEqual(len(joined), 358); self.assertEqual(len(PROVIDERS['baseline_nodes']), 540)
        self.assertFalse(NAMES & {row['name'] for row in rows})
        self.assertTrue(all(row['provider']['package']['name'] != 'db5.3' for row in joined))

    def test_independent_three_provider_derivation_does_not_read_sample(self):
        original = Path.read_bytes
        def guarded(path):
            if path == A.FAMILY / 'actual-r90-cache.bin': raise AssertionError('observed sample cannot be a derivation input')
            return original(path)
        with patch.object(Path, 'read_bytes', guarded): report, installed = A.analyze(BODY)
        self.assertEqual(report['baseline_entries'], 358); self.assertEqual(report['installed_entries'], 361)
        self.assertEqual(set(report['added_names']), NAMES); self.assertEqual(len(C.decode(installed)['entries']), 361)
        for key in ('Root_acceptance', 'lifecycle_acceptance', 'VM', 'M2', 'release'): self.assertIsNone(report[key])

    def test_derived_body_matches_known_pin_and_observed_sample_only_after_derivation(self):
        manifest, installed = derive()
        self.assertEqual(A.pin(installed), A.INSTALLED)
        self.assertEqual(installed, (A.FAMILY / 'actual-r90-cache.bin').read_bytes())
        self.assertEqual(manifest['restored'], A.BASELINE); self.assertEqual(A.pin(BODY), A.BASELINE)
        self.assertEqual({row['name'] for row in manifest['added_entries']}, NAMES)
        for key in ('Root_acceptance', 'lifecycle_acceptance', 'VM', 'M2', 'release'): self.assertIsNone(manifest[key])

    def test_empty_hash_only_sample_and_drift_cannot_replace_baseline(self):
        _, installed = derive()
        for raw in (b'', json.dumps(A.BASELINE).encode(), installed, BODY[:-1], BODY + b'\0', b'x' + BODY[1:]):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError): derive(raw)
            with self.subTest(caller_size=len(raw)), self.assertRaises(ValueError): A.analyze(raw)

    def test_fixture_reader_refuses_alias_mode_and_body_drift(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); path = root / 'baseline'; path.write_bytes(BODY); path.chmod(0o644)
            self.assertEqual(A.whole(path, A.BASELINE), BODY)
            alias = root / 'alias'; alias.symlink_to(path)
            with self.assertRaises(ValueError): A.whole(alias, A.BASELINE)
            hard = root / 'hard'; os.link(path, hard)
            with self.assertRaises(ValueError): A.whole(path, A.BASELINE)
            hard.unlink(); path.chmod(0o600)
            with self.assertRaises(ValueError): A.whole(path, A.BASELINE)
            path.chmod(0o644); path.write_bytes(b'x' + BODY[1:])
            with self.assertRaises(ValueError): A.whole(path, A.BASELINE)

    def test_malformed_baseline_header_entries_and_geometry_refuse(self):
        for offset, fmt, value in ((20, '<I', 4097), (28, '<B', 3), (29, '<B', 1), (36, '<I', 1),
                                   (48, '<i', 0x303), (52, '<I', 0), (64, '<Q', 1), (32, '<I', 49)):
            raw = bytearray(BODY); struct.pack_into(fmt, raw, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError): C.decode(bytes(raw))

    def test_truncation_suffix_and_cap_excess_refuse(self):
        for raw in (b'', BODY[:47], BODY[:-1], BODY + b'\0', BODY + b'\n', b'x' * (C.CAP + 1)):
            with self.subTest(size=len(raw)), self.assertRaises(ValueError): C.decode(raw)

    def test_provider_alias_and_soname_projection_substitutions_refuse(self):
        for group in ('baseline_nodes', 'db_nodes', 'db_elf_sonames'):
            value = copy.deepcopy(PROVIDERS); value[group].pop(next(iter(value[group])))
            with self.subTest(group=group), self.assertRaises(ValueError): derive(projection=value)
        self.assertEqual(T.BASELINE, A.BASELINE); self.assertEqual(A.pin(BODY), A.BASELINE)


if __name__ == '__main__':
    if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError('use unoptimized Python -I -B')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
    passed = (result.wasSuccessful() and result.testsRun == 10 and not result.skipped and not result.expectedFailures
              and not result.unexpectedSuccesses and not ATTEMPTS)
    print(json.dumps(dict(status='PASS_PUBLIC_BASELINE_DATA_ONLY' if passed else 'FAIL', tests=result.testsRun,
                         skips=len(result.skipped), actor_attempts=len(ATTEMPTS), Root_acceptance=None,
                         lifecycle_acceptance=None, VM=None, M2=None, release=None), sort_keys=True))
    sys.exit(0 if passed else 1)
