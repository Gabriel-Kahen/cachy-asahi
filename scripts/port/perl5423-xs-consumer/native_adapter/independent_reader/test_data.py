# SPDX-License-Identifier: MIT
"""Synthetic tamper/refusal controls; never execute a complete evidence Reader."""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('xs_reader_controls', HERE / 'reader.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
d = r.d


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.fork', 'os.posix_spawn'):
        raise AssertionError('actor forbidden in passive Reader controls: ' + event)


sys.addaudithook(fence)


def model(parent, kind=stat.S_IFREG, body=b'MODELED DATA ONLY'):
    evidence = parent / 'evidence'
    evidence.mkdir()
    (evidence / 'leaf.txt').write_bytes(body)
    archive = parent / 'MODELED.zip'
    entry = zipfile.ZipInfo('leaf.txt')
    entry.create_system = 3
    entry.external_attr = (kind | 0o644) << 16
    with zipfile.ZipFile(archive, 'w') as stream:
        stream.writestr(entry, body)
    b = dict(source=r.SOURCE, ref=r.REF, run='1', job='2', approval='3'*64,
             source_map_sha256=r.MAP, operation='perl5423-native-xs-v1')
    metadata = dict(id=7, size_in_bytes=archive.stat().st_size, expired=False,
                    name='perl5423-native-xs-v1-1-1', workflow_run=dict(id=1, head_sha=r.SOURCE,
                    head_branch=r.REF.removeprefix('refs/heads/')))
    raw = json.dumps(metadata).encode()
    a = dict(id='7', **d.pin(archive.read_bytes()), metadata_sha256=d.pin(raw)['sha256'])
    return archive, evidence, a, raw, b


class Controls(unittest.TestCase):
    def setUp(self):
        d.start()

    def test_null_actual_binding_refuses(self):
        value = d.decode((HERE / 'binding.TEMPLATE.json').read_bytes())
        with self.assertRaises(ValueError):
            r.binding(value)

    def test_duplicate_nonfinite_and_path_alias_refuse(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
            with self.assertRaises(ValueError):
                d.decode(raw)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'target').write_bytes(b'data')
            (root / 'alias').symlink_to(root / 'target')
            with self.assertRaises(OSError):
                d.read(root, 'alias')

    def test_original_substitution_and_extra_leaf_refuse(self):
        for extra in (False, True):
            with tempfile.TemporaryDirectory() as temp:
                archive, evidence, a, raw, b = model(Path(temp))
                if extra:
                    (evidence / 'extra.txt').write_bytes(b'unrecorded')
                else:
                    (evidence / 'leaf.txt').write_bytes(b'SUBSTITUTED')
                with self.assertRaises(ValueError):
                    r.original(archive, evidence, a, raw, b)

    def test_symlink_archive_member_and_wrong_metadata_refuse(self):
        with tempfile.TemporaryDirectory() as temp:
            archive, evidence, a, raw, b = model(Path(temp), stat.S_IFLNK)
            with self.assertRaises(ValueError):
                r.original(archive, evidence, a, raw, b)
            with self.assertRaises(ValueError):
                r.original(archive, evidence, a, raw.replace(b'"id": 7', b'"id": 8'), b)

    def test_forced_or_unobserved_retirement_refuses(self):
        for row in (dict(exit=0), dict(natural_exit=True, forced_cleanup=True, exit=0)):
            with self.assertRaises(ValueError):
                d.natural(row)

    def test_missing_external_input_refuses_before_any_role(self):
        args = argparse.Namespace(binding='/MISSING/Root-binding.json', binding_sha256='0'*64,
                                  source_root='/MISSING/source', evidence='/MISSING/evidence',
                                  original_artifact='/MISSING/Original.zip', artifact_metadata='/MISSING/metadata.json')
        with self.assertRaises((FileNotFoundError, ValueError)):
            r.validate(args)


if __name__ == '__main__':
    unittest.main(verbosity=2)
