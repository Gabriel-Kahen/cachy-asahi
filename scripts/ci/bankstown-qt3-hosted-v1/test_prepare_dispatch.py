# SPDX-License-Identifier: MIT
"""Fenced Source79 DATA controls; tiny old bodies are an explicit MODEL boundary.

The optional genuine case requires externally selected --source78 DATA. No Source
payload, workflow, actor or network role executes. Mutations affect fresh copies.
"""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import resource
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

# The genuine35MiB tree and unchanged held helper's joined catalog body coexist.
# This bounds the whole test process without changing any constructor predicate.
resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2,) * 2)


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.fork',
                         'os.spawn', 'os.posix_spawn')) or event in ('os.system', 'fcntl.flock'):
        raise AssertionError('SOURCE_DATA_NO_OPERATIONAL_ROLE: '+event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audio_dispatch_prepare_controls', HERE/'prepare_dispatch.py')
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
ACTUAL_SOURCE = None


def git_tree(files):
    """Independent whole name/body/mode Git tree calculation, without Git."""
    root = {}
    for name, (body, mode) in files.items():
        directory = root
        parts = name.split('/')
        for component in parts[:-1]:
            directory = directory.setdefault(component, {})
        directory[parts[-1]] = (body, mode)
    def oid(kind, body):
        digest = hashlib.sha1(kind+b' '+str(len(body)).encode()+b'\0')
        digest.update(body)
        return digest.digest()
    def directory_oid(directory):
        data = bytearray()
        for name, value in sorted(directory.items(), key=lambda item: item[0]+('/' if type(item[1]) is dict else '')):
            isdir = type(value) is dict
            mode = b'40000' if isdir else (b'100755' if value[1] == 0o755 else b'100644')
            digest = directory_oid(value) if isdir else oid(b'blob', value[0])
            data.extend(mode+b' '+name.encode()+b'\0'+digest)
        return oid(b'tree', bytes(data))
    return directory_oid(root).hex()


def identity(files):
    return dict(files=len(files), bytes=sum(len(body) for body, mode in files.values()),
                tree=git_tree(files), source_map=M.pin(files['source-map.json'][0]))


def write_files(root, files):
    root.mkdir()
    for name, (body, mode) in files.items():
        path = root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        path.chmod(mode)


def fingerprints(files):
    return {name: dict(M.pin(body), mode=mode) for name, (body, mode) in files.items()}


def stream_fingerprints(root):
    result = {}
    for name in M.snapshot(root, names_only=True):
        path = root/name
        before = path.stat()
        digest, size = hashlib.sha256(), 0
        with path.open('rb') as stream:
            while part := stream.read(1024**2):
                size += len(part)
                digest.update(part)
        after = path.stat()
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if tuple(getattr(before, n) for n in fields) != tuple(getattr(after, n) for n in fields):
            raise AssertionError('original fixture changed during fingerprint')
        result[name] = dict(bytes=size, sha256=digest.hexdigest(), mode=stat.S_IMODE(after.st_mode))
    return result


class Model(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='bankstown-dispatch-MODEL-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source, self.output = self.root/'source78', self.root/'source79'
        self.P = M.trusted_prepare()
        old = {f'model/f{i:02}': (b'MODEL old body '+str(i).encode()+b'\n', 0o755 if i == 0 else 0o644) for i in range(70)}
        rows = {name: dict(M.pin(body), mode=mode) for name, (body, mode) in old.items()}
        actual = dict(source=None, ref=None, run=None, job=None, image=None, profile=None,
                      executor=None, Root_final_acceptance=None)
        value = dict(schema=1, kind='BANKSTOWN_QT3_CLOSED_NATIVE_SOURCE_V1',
                     operation='bankstown-qt3-native-private-test-v1', actual=actual, files=rows)
        self.old_map = M.encoded(value)
        runtime = {}
        for name in M.RUNTIME_PINS:
            # Original runtime bodies remain literal; only the old Source72 DATA
            # map and its externally selected authenticity are modeled.
            body = self.old_map if name.endswith('source72-map.DATA.json') else (HERE/name).read_bytes()
            runtime[M.PREFIX+name] = (body, 0o644)
        self.files = dict(old, **runtime)
        value = dict(value, files={name: dict(M.pin(body), mode=mode) for name, (body, mode) in self.files.items()})
        raw = M.encoded(value)
        self.files.update({'source-map.json': (raw, 0o644), 'source.lock.json': (raw, 0o644)})
        write_files(self.source, self.files)
        runtime_pins = {name.removeprefix(M.PREFIX): dict(M.pin(body), mode=mode)
                        for name, (body, mode) in runtime.items()}
        # These exact historical tuple/closure boundaries are MODEL only. Full
        # constructor namespace, rows, bodies, modes, workflow and inverse run.
        for p in (patch.object(M, 'SOURCE78', identity(self.files)),
                  patch.object(M, 'SOURCE72_MAP', M.pin(self.old_map)),
                  patch.object(M, 'RUNTIME_PINS', runtime_pins),
                  patch.object(M, 'trusted_prepare', return_value=self.P),
                  patch.object(self.P, 'REQUIRED', set()),
                  patch.object(self.P, 'required_members', return_value=set())):
            p.start(); self.addCleanup(p.stop)

    def prepare(self, **kw):
        return M.prepare_source(source78=self.source, output=self.output, **kw)

    def test_only_workflow_added_two_aliases_changed_and_inverse_preserves_every_byte_mode(self):
        receipt = self.prepare()
        result = M.snapshot(self.output)
        self.assertEqual(receipt['source'], identity(result))
        self.assertTrue(all(value is None for value in receipt['actual'].values()))
        self.assertIs(receipt['native_credit'], False)
        self.assertEqual(set(result)-set(self.files), {M.WORKFLOW})
        self.assertEqual({n for n in self.files if result[n] != self.files[n]}, {'source-map.json', 'source.lock.json'})
        self.assertEqual(result[M.WORKFLOW], ((M.ROOT/M.WORKFLOW).read_bytes(), 0o644))
        self.assertEqual(result['source-map.json'], result['source.lock.json'])
        self.assertEqual(M.inverse_files(result), self.files)
        value = M.decode(result['source-map.json'][0])
        self.assertEqual(len(value['files']), 77)
        self.assertTrue(all(v is None for v in value['actual'].values()))
        self.assertEqual(M.snapshot(self.source), self.files)
        self.assertEqual(M.identity(result), identity(result))

    def test_fixed_workflow_whole_pin_and_ordinary_mode_before_output(self):
        path = self.root/'workflow.yml'
        body = (M.ROOT/M.WORKFLOW).read_bytes()
        path.write_bytes(body+b'\n'); path.chmod(0o644)
        with self.assertRaises(ValueError): self.prepare(workflow_path=path)
        self.assertFalse(self.output.exists())
        path.write_bytes(body); path.chmod(0o755)
        with self.assertRaises(ValueError): self.prepare(workflow_path=path)
        self.assertFalse(self.output.exists())
        path.chmod(0o644); self.prepare(workflow_path=path)
        self.assertEqual(M.snapshot(self.output)[M.WORKFLOW], (body, 0o644))

    def test_changed_and_missing_original_body_refuse_without_output(self):
        path = self.source/'model/f00'
        path.write_bytes(b'changed')
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.output.exists())
        path.unlink()
        with self.assertRaises((ValueError, FileNotFoundError)): self.prepare()
        self.assertFalse(self.output.exists())

    def test_original_body_and_map_modes_refuse(self):
        for name in ('model/f00', 'source-map.json', 'source.lock.json'):
            path = self.source/name
            before = stat.S_IMODE(path.stat().st_mode)
            path.chmod(0o600)
            with self.subTest(name=name), self.assertRaises(ValueError): self.prepare()
            self.assertFalse(self.output.exists()); path.chmod(before)

    def test_changed_alias_and_extra_file_or_empty_directory_refuse(self):
        alias = self.source/'source.lock.json'; raw = alias.read_bytes()
        alias.write_bytes(raw+b'\n')
        with self.assertRaises(ValueError): self.prepare()
        alias.write_bytes(raw)
        extra = self.source/'FOREIGN'; extra.write_bytes(b'extra')
        with self.assertRaises(ValueError): self.prepare()
        extra.unlink(); extra.mkdir()
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.output.exists())

    def test_source_root_alias_leaf_symlink_and_hardlink_refuse(self):
        alias = self.root/'alias'; alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ValueError): M.prepare_source(source78=alias, output=self.output)
        path = self.source/'model/f00'; path.unlink(); path.symlink_to('f01')
        with self.assertRaises(ValueError): self.prepare()
        path.unlink(); os.link(self.source/'model/f01', path)
        with self.assertRaises(ValueError): self.prepare()
        self.assertFalse(self.output.exists())

    def test_output_inside_source_and_existing_output_are_preserved(self):
        inner = self.source/'output'
        with self.assertRaises(ValueError): M.prepare_source(source78=self.source, output=inner)
        self.assertFalse(inner.exists())
        self.output.mkdir(); sentinel = self.output/'KEEP'; sentinel.write_bytes(b'keep')
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual(sentinel.read_bytes(), b'keep')
        self.assertEqual(M.snapshot(self.source), self.files)

    def test_inverse_changed_workflow_mode_body_and_map_refuse(self):
        self.prepare(); result = M.snapshot(self.output)
        for name, replacement in ((M.WORKFLOW, (result[M.WORKFLOW][0]+b'\n', 0o644)),
                                  (M.WORKFLOW, (result[M.WORKFLOW][0], 0o755)),
                                  ('source-map.json', (result['source-map.json'][0]+b'\n', 0o644)),
                                  ('source.lock.json', (result['source.lock.json'][0], 0o600))):
            files = dict(result); files[name] = replacement
            with self.subTest(name=name), self.assertRaises(ValueError): M.inverse_files(files)
        self.assertEqual(M.snapshot(self.source), self.files)

    def test_inverse_foreign_or_missing_member_and_nonnull_actual_refuse(self):
        self.prepare(); result = M.snapshot(self.output)
        files = dict(result); files['FOREIGN'] = (b'foreign', 0o644)
        with self.assertRaises(ValueError): M.inverse_files(files)
        files = dict(result); del files[M.WORKFLOW]
        with self.assertRaises(ValueError): M.inverse_files(files)
        value = M.decode(result['source-map.json'][0]); value['actual']['source'] = 'a'*40
        raw = M.encoded(value); files = dict(result)
        for name in ('source-map.json', 'source.lock.json'): files[name] = (raw, 0o644)
        with self.assertRaises(ValueError): M.inverse_files(files)


class Genuine(unittest.TestCase):
    def test_explicit_genuine_source78_full_copy_inverse_and_original_unchanged(self):
        if ACTUAL_SOURCE is None:
            self.skipTest('optional genuine Source78 not selected; immutable Source CID pending')
        # Stream the before census so the test does not retain a second full
        # catalog while the actual maintained constructor reads its own input.
        preserved = stream_fingerprints(ACTUAL_SOURCE)
        self.assertEqual(len(preserved), M.SOURCE78['files'])
        self.assertEqual(sum(row['bytes'] for row in preserved.values()), M.SOURCE78['bytes'])
        self.assertEqual({k: preserved['source-map.json'][k] for k in ('bytes', 'sha256')}, M.SOURCE78['source_map'])
        with tempfile.TemporaryDirectory(prefix='bankstown-dispatch-genuine-DATA-') as temporary:
            output = Path(temporary)/'source79'
            receipt = M.prepare_source(source78=ACTUAL_SOURCE, output=output)
            after = M.snapshot(output)
            self.assertEqual(receipt['source'], identity(after))
            self.assertTrue(all(value is None for value in receipt['actual'].values()))
            self.assertIs(receipt['native_credit'], False)
            self.assertEqual(len(after), 79)
            self.assertEqual(set(after)-set(preserved), {M.WORKFLOW})
            emitted = fingerprints(after)
            self.assertEqual({n for n in preserved if preserved[n] != emitted[n]}, {'source-map.json', 'source.lock.json'})
            inverse = M.inverse_files(after)
            self.assertEqual(identity(inverse), M.SOURCE78)
            self.assertEqual(fingerprints(inverse), preserved)
            self.assertEqual(stream_fingerprints(ACTUAL_SOURCE), preserved)
            self.assertEqual(M.identity(after), identity(after))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('--source78', type=Path)
    options, remaining = parser.parse_known_args()
    ACTUAL_SOURCE = options.source78
    unittest.main(argv=[sys.argv[0], *remaining])
