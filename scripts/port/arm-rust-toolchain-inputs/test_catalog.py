#!/usr/bin/env python3
"""Data-only negative controls; synthetic AArch64 ELF bytes are never run."""
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('catalog', Path(__file__).with_name('catalog.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def tiny_elf(machine=183, terminated=True, duplicate=False):
    data = bytearray(512)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<H', data, 18, machine)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HH', data, 54, 56, 2)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 4, 0, 0x1000, 0, 512, 512, 0x1000)
    tags = [(5, 0x1100), (10, 32), (1, 1), (14, 14)]
    if duplicate:
        tags.append((5, 0x1100))
    if terminated:
        tags.append((0, 0))
    struct.pack_into('<IIQQQQQQ', data, 120, 2, 4, 320, 0x1140, 0, len(tags) * 16, len(tags) * 16, 8)
    data[256:288] = b'\0libc.so.6\0xxxlibfake.so\0'.ljust(32, b'\0')
    for i, pair in enumerate(tags):
        struct.pack_into('<qQ', data, 320 + i * 16, *pair)
    return bytes(data)


class CatalogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, items=(), pkgname='fixture', arch='aarch64'):
        target = self.root / 'data.tar.xz'
        with tarfile.open(target, 'w:xz') as t:
            info = f'pkgname = {pkgname}\npkgver = 1-1\narch = {arch}\n'.encode()
            m = tarfile.TarInfo('.PKGINFO')
            m.size = len(info)
            t.addfile(m, io.BytesIO(info))
            for item in items:
                name, value, typ = item
                m = tarfile.TarInfo(name)
                if typ == 'file':
                    m.size = len(value)
                    t.addfile(m, io.BytesIO(value))
                else:
                    m.type = {'symlink': tarfile.SYMTYPE, 'hardlink': tarfile.LNKTYPE,
                              'directory': tarfile.DIRTYPE, 'device': tarfile.CHRTYPE}[typ]
                    m.linkname = value
                    t.addfile(m)
        return target

    def inspect(self, items=(), **kwargs):
        return c.inspect_archive(self.archive(items, **kwargs),
                                 {'name': 'fixture', 'version': '1-1', 'arch': 'aarch64',
                                  'depends': [], 'provides': []}, time.monotonic() + 10)

    def test_normal_archive_hashes_and_modes(self):
        value = self.inspect([('usr/bin/tool', tiny_elf(), 'file')])
        self.assertEqual(value['entries']['/usr/bin/tool']['sha256'], c.digest(tiny_elf())['sha256'])
        self.assertEqual(value['entries']['/usr/bin/tool']['elf']['machine'], 183)

    def test_duplicate_member_refused(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.inspect([('usr/a', b'a', 'file'), ('usr/a', b'a', 'file')])

    def test_path_traversal_and_absolute_member_refused(self):
        for path in ('../a', '/usr/a', 'usr/../a', './usr/a', 'usr//a'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.inspect([(path, b'a', 'file')])

    def test_device_refused(self):
        with self.assertRaisesRegex(ValueError, 'special archive node'):
            self.inspect([('dev/unsafe', '', 'device')])

    def test_link_ancestor_refused(self):
        with self.assertRaisesRegex(ValueError, 'ancestor'):
            self.inspect([('usr/link', '/tmp', 'symlink'), ('usr/link/a', b'a', 'file')])

    def test_escaping_link_refused(self):
        with self.assertRaisesRegex(ValueError, 'escapes'):
            self.inspect([('usr/a', '../../a', 'symlink')])

    def test_hardlink_to_regular_file(self):
        value = self.inspect([('usr/a', b'a', 'file'), ('usr/b', 'usr/a', 'hardlink')])
        self.assertEqual(c.resolve('/usr/b', value['entries']), '/usr/a')

    def test_hardlink_to_symlink_refused(self):
        with self.assertRaisesRegex(ValueError, 'regular file'):
            self.inspect([('usr/a', 'b', 'symlink'), ('usr/c', 'usr/a', 'hardlink')])

    def test_hardlink_cycle_refused(self):
        with self.assertRaisesRegex(ValueError, 'cycle'):
            self.inspect([('usr/a', 'usr/b', 'hardlink'), ('usr/b', 'usr/a', 'hardlink')])

    def test_package_identity_refused(self):
        with self.assertRaisesRegex(ValueError, 'identity'):
            self.inspect(pkgname='other')

    def test_file_count_limit(self):
        with patch.object(c, 'MAX_MEMBERS', 1), self.assertRaisesRegex(ValueError, 'count bound'):
            self.inspect([('usr/a', b'a', 'file')])

    def test_file_size_limit(self):
        with patch.object(c, 'MAX_FILE', 2), self.assertRaisesRegex(ValueError, 'size bound'):
            self.inspect()

    def test_deadline(self):
        with self.assertRaisesRegex(ValueError, 'deadline'):
            c.inspect_archive(self.archive(), {}, time.monotonic() - 1)

    def test_elf_machine_and_bounds(self):
        for data in (tiny_elf(62), tiny_elf()[:130]):
            with self.assertRaises(ValueError):
                c.elf(data)

    def test_dynamic_table(self):
        parsed = c.elf(tiny_elf())
        self.assertEqual(parsed['needed'], ['libc.so.6'])
        for data in (tiny_elf(terminated=False), tiny_elf(duplicate=True)):
            with self.assertRaises(ValueError):
                c.elf(data)

    def test_namespace_links_and_elf_joins(self):
        obj = c.elf(tiny_elf())
        entries = {'/lib': {'type': 'symlink', 'resolved': '/usr/lib'},
                   '/usr/lib/libc.so.6': {'type': 'file', 'elf': dict(obj, needed=[])},
                   '/usr/bin/tool': {'type': 'file', 'elf': dict(obj, interpreter='/lib/libc.so.6')}}
        joins, missing = c.elf_joins(entries)
        self.assertFalse(missing)
        self.assertEqual(len(joins), 2)

    def test_missing_elf_provider_is_visible(self):
        joins, missing = c.elf_joins({'/usr/bin/tool': {'type': 'file', 'elf': c.elf(tiny_elf())}})
        self.assertFalse(joins)
        self.assertEqual(missing[0]['needed'], 'libc.so.6')

    def test_symlink_cycle_refused(self):
        with self.assertRaisesRegex(ValueError, 'cycle'):
            c.resolve('/a', {'/a': {'type': 'symlink', 'resolved': '/b'}, '/b': {'type': 'symlink', 'resolved': '/a'}})

    def test_changed_duplicate_cache_refused(self):
        a, b = self.root / 'a', self.root / 'b'
        a.mkdir()
        b.mkdir()
        (a / 'input').write_bytes(b'a')
        (b / 'input').write_bytes(b'b')
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            c.find_input('input', [a, b], c.digest(b'a'))

    def test_snapshot_binds_changed_cache(self):
        source, target = self.root / 'source', self.root / 'snapshot'
        source.write_bytes(b'original')
        c.snapshot(source, target, c.digest(b'original'), time.monotonic() + 10)
        source.write_bytes(b'replaced')
        self.assertEqual(target.read_bytes(), b'original')
        with self.assertRaisesRegex(ValueError, 'changed'):
            c.snapshot(source, self.root / 'bad', c.digest(b'original'), time.monotonic() + 10)

    def test_signature_wrong_signer_refused(self):
        primary = 'A' * 40
        status = f'[GNUPG:] VALIDSIG {primary} 2026-01-01 1 0 4 0 1 10 00 {primary}\n'.encode()
        run = type('Run', (), {'stdout': status, 'stderr': b'', 'returncode': 0})()
        with patch.object(c.subprocess, 'run', return_value=run):
            result = c.signatures(Path('archive'), Path('sig'), Path('key'), primary)
            self.assertEqual(result['key_freshness'], 'NOT_ESTABLISHED')
            with self.assertRaisesRegex(ValueError, 'signer'):
                c.signatures(Path('archive'), Path('sig'), Path('key'), 'B' * 40)

    def test_signature_bad_math_refused(self):
        run = type('Run', (), {'stdout': b'', 'stderr': b'bad signature', 'returncode': 1})()
        with patch.object(c.subprocess, 'run', return_value=run), self.assertRaisesRegex(ValueError, 'mathematics'):
            c.signatures(Path('archive'), Path('sig'), Path('key'), 'A' * 40)

    def test_locked_package_dependencies_and_rust_association(self):
        lock = json.loads((c.HERE / 'inputs.lock.json').read_text())
        self.assertGreater(len(c.package_joins(lock)), 100)
        c.pin(c.HERE / 'rust-137-files.json', lock['bankstown_rust_association'])
        self.assertEqual(len(json.loads((c.HERE / 'rust-137-files.json').read_text())['files']), 137)
        lock['dependency_joins'].pop()
        with self.assertRaisesRegex(ValueError, 'unjoined'):
            c.package_joins(lock)

    def test_wrong_dependency_provider_refused(self):
        lock = json.loads((c.HERE / 'inputs.lock.json').read_text())
        lock['dependency_joins'][0]['provider'] = 'rust'
        with self.assertRaisesRegex(ValueError, 'provider name'):
            c.package_joins(lock)

    def test_missing_input_preparation_refused_before_output(self):
        cache, output = self.root / 'empty', self.root / 'output'
        cache.mkdir()
        with patch.object(sys, 'argv', ['catalog.py', '--cache', str(cache), '--output', str(output), '--prepare']):
            with self.assertRaisesRegex(ValueError, 'missing inputs'):
                c.main()
        self.assertFalse(output.exists())

    def test_source_notice_join_does_not_close_recipe_correspondence(self):
        facts = json.loads((c.HERE / 'source-facts.json').read_text())
        packages = {}
        for r in facts['recipes']:
            name = 'llvm-libs' if r['package'] == 'llvm' else r['package']
            packages[name] = {'metadata': {'/.BUILDINFO': {'pkgbuild_sha256sum': [r['retained_pkgbuild_sha256']]}}, 'entries': {}}
        for item in facts['upstream']['llvm']['licenses']:
            name = item['path'].split('/')[0]
            name = 'llvm-libs' if name == 'llvm' else name
            packages[name]['entries'][f'/usr/share/licenses/{name}/LICENSE'] = item
        result = c.source_joins(packages, facts)
        self.assertTrue(all(not r['exact_match'] for r in result['recipes']))
        self.assertTrue(all(r['exact_match'] for r in result['license_notices']))
        self.assertEqual(result['corresponding_source_acceptance'], 'NOT_ESTABLISHED')


if __name__ == '__main__':
    unittest.main()
