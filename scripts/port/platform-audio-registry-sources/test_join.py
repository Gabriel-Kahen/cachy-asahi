#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Synthetic registry/archive DATA controls; never native/source acceptance."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import unittest

spec = importlib.util.spec_from_file_location('audio_registry_join', Path(__file__).with_name('join.py'))
j = importlib.util.module_from_spec(spec); spec.loader.exec_module(j)


def archive(files, special=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as output:
        for path, body in files.items():
            info = tarfile.TarInfo(path); info.size = len(body); output.addfile(info, io.BytesIO(body))
        if special:
            output.addfile(special)
    return stream.getvalue()


class RegistryJoin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a = j.trusted_auditor(Path(ARGS.trusted_checkout))

    def setUp(self):
        self.files = {'Cargo.toml': b'[package]\nname="demo"\nversion="1.2.3"\nlicense="MIT"\n',
                      'LICENSE': b'Synthetic license-text observation, not a grant.\n', 'src/lib.rs': b'// inert synthetic source\n'}
        self.root = 'vendor/demo-1.2.3'
        self.vendor = {self.root + '/' + p: b for p, b in self.files.items()}
        mapping = {'files': {p: j.digest(b) for p, b in self.files.items()}, 'package': '1' * 64}
        self.vendor[self.root + '/.cargo-checksum.json'] = json.dumps(mapping).encode()

    def compare(self, files):
        raw = archive({'demo-1.2.3/' + p: b for p, b in files.items()})
        return j.correspondence(self.a, raw, 'demo', '1.2.3', self.root, self.vendor)

    def test_exact_member_bytes_and_license_remain_data_only(self):
        result = self.compare(self.files)
        self.assertEqual(result['status'], 'EXACT_MEMBER_BYTES')
        self.assertEqual(result['vendor_declared_files'], 3)
        self.assertTrue(result['raw_license_observation']['text_presence'])
        self.assertFalse(result['raw_license_observation']['legal_acceptance'])

    def test_every_missing_extra_and_changed_file_is_retained(self):
        files = dict(self.files); del files['LICENSE']; files['src/lib.rs'] += b'changed'; files['extra.rs'] = b'extra'
        result = self.compare(files)
        self.assertEqual(result['status'], 'HOLD_MEMBER_DIFFERENCES')
        self.assertEqual([r['path'] for r in result['missing']], ['LICENSE'])
        self.assertEqual([r['path'] for r in result['extra']], ['extra.rs'])
        self.assertEqual([r['path'] for r in result['different']], ['src/lib.rs'])
        self.assertFalse(result['raw_license_observation']['text_presence'])

    def test_altered_vendor_bytes_cannot_hide_behind_declared_file_map(self):
        self.vendor[self.root + '/src/lib.rs'] += b'changed'
        with self.assertRaisesRegex(ValueError, 'VENDOR_FILE_CHECKSUM_DIFFERS'):
            self.compare(self.files)

    def test_exact_registry_row_and_yanked_state_are_preserved(self):
        raw = b'raw archive bytes'
        row = {'name': 'demo', 'vers': '1.2.3', 'cksum': j.digest(raw), 'yanked': True, 'v': 2}
        selected = j.selected_index(json.dumps(row).encode(), 'demo', '1.2.3')
        self.assertTrue(selected['row']['yanked'])
        j.registry_checksum(selected, j.digest(raw), raw)
        with self.assertRaisesRegex(ValueError, 'OFFICIAL_INDEX_VENDOR'):
            j.registry_checksum(selected, '0' * 64, raw)
        with self.assertRaisesRegex(ValueError, 'RAW_CRATE_REGISTRY'):
            j.registry_checksum(selected, j.digest(raw), raw + b'changed')

    def test_index_duplicates_missing_versions_bad_checksums_and_json_refuse(self):
        row = json.dumps({'name': 'demo', 'vers': '1.2.3', 'cksum': 'a' * 64, 'yanked': False}).encode()
        for bad in (row + b'\n' + row, row.replace(b'1.2.3', b'1.2.4'), row.replace(b'a' * 64, b'not-a-checksum'), b'{"name":"demo","name":"other"}'):
            with self.subTest(data=bad[:40]), self.assertRaises(ValueError):
                j.selected_index(bad, 'demo', '1.2.3')

    def test_exact_url_syntax_and_sparse_prefix_rules(self):
        for name, suffix in [('a', '1/a'), ('ab', '2/ab'), ('ABC', '3/a/abc'), ('Abcd', 'ab/cd/abcd')]:
            self.assertEqual(j.index_url(name), 'https://index.crates.io/' + suffix)
        for name, version in [('x/y', '1.2.3'), ('demo', '../1.2.3'), ('demo', '1.2.3?query'), ('0bad', '1.2.3')]:
            with self.assertRaises(ValueError): j.archive_url(name, version)

    def test_links_duplicates_unsafe_names_and_foreign_roots_refuse(self):
        special = tarfile.TarInfo('demo-1.2.3/link'); special.type = tarfile.SYMTYPE; special.linkname = '/etc/passwd'
        valid = {'demo-1.2.3/Cargo.toml': self.files['Cargo.toml']}
        cases = [archive(valid, special), archive({'../escape': b'x'}), archive({'foreign-1.2.3/Cargo.toml': b'x'})]
        special = tarfile.TarInfo('demo-1.2.3/Cargo.toml'); special.size = 0
        cases.append(archive(valid, special))
        for raw in cases:
            with self.assertRaises(ValueError): j.raw_members(self.a, raw, 'demo', '1.2.3')

    def test_object_and_expanded_member_caps_refuse(self):
        with self.assertRaisesRegex(ValueError, 'RAW_CRATE_BYTE_LIMIT'):
            j.raw_members(self.a, b'x' * (j.MAX_OBJECT + 1), 'demo', '1.2.3')
        special = tarfile.TarInfo('demo-1.2.3/oversized'); special.type = tarfile.DIRTYPE; special.size = self.a.MAX_FILE + 1
        with self.assertRaisesRegex(ValueError, 'RAW_CRATE_EXPANDED_LIMIT'):
            j.raw_members(self.a, archive({'demo-1.2.3/small': b'x'}, special), 'demo', '1.2.3')
        with self.assertRaisesRegex(ValueError, 'AGGREGATE_PROBE'):
            j.raw_members(self.a, archive({'demo-1.2.3/data': b'bounded'}), 'demo', '1.2.3',
                          lambda size: j.need(size <= 1, 'AGGREGATE_PROBE'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--trusted-checkout', default=str(Path(__file__).resolve().parents[3]))
    ARGS, rest = parser.parse_known_args(); unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
