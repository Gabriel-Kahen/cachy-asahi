#!/usr/bin/env python3
"""Synthetic data-only controls; never scan retained packages or invoke gpgv."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('retained_ui_audit_under_test', HERE / 'audit.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)
CHECKER = 'scripts/checks/package_checks.py'
HELD_CHECKER = (audit.ROOT / 'scripts/ci/llhttp-minimal-native-source-data/fixtures/Source95/held-source'
                / 'scripts/ci/llhttp-reference-native-source/base/runtime' / CHECKER)
RESOLVER = 'scripts/port/platform-residual-closure/resolve.py'
# Verbatim resolver blob from fb862ffea at RESOLVER.
HELD_RESOLVER = HERE / 'fixtures' / 'resolve.fb862ffea.py.data'
HELD_READERS = {CHECKER: HELD_CHECKER, RESOLVER: HELD_RESOLVER}


def elf(alignment=16384):
    data = bytearray(120)
    data[:16] = b'\x7fELF\x02\x01\x01' + bytes(9)
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, 3, 183, 1, 0, 64, 0, 0,
                     64, 56, 1, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0, 0, len(data), len(data), alignment)
    return bytes(data)


class AuditControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = json.loads((HERE / 'inputs.json').read_text())
        temporary = tempfile.TemporaryDirectory(prefix='retained-ui-readers-')
        cls.addClassCleanup(temporary.cleanup)
        cls.reader_root = Path(temporary.name)
        for name, row in cls.config['reader_sources'].items():
            source = HELD_READERS.get(name, audit.ROOT / name)
            target = cls.reader_root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(audit.checked_bytes({'path': str(source), **row}))
        with patch.object(audit, 'ROOT', cls.reader_root):
            cls.modules = audit.modules(cls.config)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='retained-ui-synthetic-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.limits = copy.deepcopy(self.config['limits'])
        self.budget = {'deadline': time.monotonic() + 15, 'compressed_allowance': 0,
                       'compressed_observed_snapshot_bytes': 0, 'logical_bytes': 0, 'headers': 0}
        self.item = {'name': 'synthetic-ui', 'version': '1-1', 'arch': 'aarch64',
                     'depends': ['glibc'], 'licenses_declared': ['MIT']}
        self.pkginfo = (b'pkgname = synthetic-ui\npkgbase = synthetic-ui\npkgver = 1-1\narch = aarch64\n'
                        b'depend = glibc\nlicense = MIT\n')
        self.buildinfo = b'pkgname = synthetic-ui\npkgbase = synthetic-ui\npkgver = 1-1\npkgarch = aarch64\n'

    def archive(self, members=None):
        if members is None:
            members = [('.PKGINFO', self.pkginfo), ('.BUILDINFO', self.buildinfo)]
        path = self.root / ('fixture-%d.tar.xz' % len(list(self.root.iterdir())))
        with tarfile.open(path, 'w:xz', format=tarfile.USTAR_FORMAT, preset=0) as archive:
            for name, body in members:
                if isinstance(body, tarfile.TarInfo):
                    archive.addfile(body)
                else:
                    entry = tarfile.TarInfo(name)
                    entry.size = len(body)
                    archive.addfile(entry, io.BytesIO(body))
        return path

    def inspect(self, members=None):
        return audit.inspect(self.archive(members), self.item, self.modules, self.limits, self.budget)

    def test_geometry_reader_uses_exact_held_checker(self):
        checker = Path(self.modules['geometry'].__file__)
        self.assertEqual(checker, self.reader_root / CHECKER)
        self.assertEqual(checker.read_bytes(), HELD_CHECKER.read_bytes())

    def test_resolver_fixture_matches_historical_pins_and_loaded_reader(self):
        body = HELD_RESOLVER.read_bytes()
        pin = {'bytes': len(body), 'sha256': audit.sha(body)}
        self.assertEqual(pin, {'bytes': 36995,
                              'sha256': 'df71e3166025849785f1bdd4543f36938d7fd191dc8d407aa420a1b61968548e'})
        seat = json.loads((HERE / 'seat-inputs.json').read_text())
        for config in (self.config, seat):
            self.assertEqual(config['reader_sources'][RESOLVER], pin)
        resolver = Path(self.modules['resolver'].__file__)
        self.assertEqual(resolver, self.reader_root / RESOLVER)
        self.assertEqual(resolver.read_bytes(), body)

    def test_snapshot_full_pin_and_same_length_change(self):
        source = self.root / 'source'
        source.write_bytes(b'original')
        expected = {'bytes': 8, 'sha256': audit.sha(b'original')}
        row = audit.snapshot(source, expected, self.root / 'snapshot', self.limits, self.budget)
        self.assertEqual(row['status'], 'PASS_FULL_SIZE_SHA256')
        self.assertEqual((self.root / 'snapshot').read_bytes(), b'original')
        self.assertEqual(self.budget['compressed_allowance'], 24)
        source.write_bytes(b'changed!')
        with self.assertRaisesRegex(ValueError, 'SHA256/identity'):
            audit.snapshot(source, expected, self.root / 'changed', self.limits, self.budget)

    def test_snapshot_symlink_and_linked_parent_refused(self):
        source = self.root / 'source'
        source.write_bytes(b'x')
        expected = {'bytes': 1, 'sha256': audit.sha(b'x')}
        link = self.root / 'link'
        link.symlink_to(source)
        with self.assertRaisesRegex(ValueError, 'linked'):
            audit.snapshot(link, expected, self.root / 'output', self.limits, self.budget)
        directory = self.root / 'directory'
        directory.mkdir()
        (directory / 'source').write_bytes(b'x')
        parent_link = self.root / 'parent-link'
        parent_link.symlink_to(directory, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'linked'):
            audit.snapshot(parent_link / 'source', expected, self.root / 'output2', self.limits, self.budget)

    def test_snapshot_size_and_aggregate_allowance_refused(self):
        source = self.root / 'source'
        source.write_bytes(b'long')
        with self.assertRaisesRegex(ValueError, 'size/type'):
            audit.snapshot(source, {'bytes': 3, 'sha256': audit.sha(b'lon')}, self.root / 'size', self.limits, self.budget)
        self.limits['compressed_archive_read_allowance'] = 11
        with self.assertRaisesRegex(ValueError, 'aggregate'):
            audit.snapshot(source, {'bytes': 4, 'sha256': audit.sha(b'long')}, self.root / 'budget', self.limits, self.budget)

    def test_failed_snapshot_reserves_reads_and_blocks_second_attempt(self):
        source = self.root / 'source'
        source.write_bytes(b'changed!')
        expected = {'bytes': 8, 'sha256': audit.sha(b'original')}
        self.limits['compressed_archive_read_allowance'] = 47
        with self.assertRaisesRegex(ValueError, 'SHA256/identity'):
            audit.snapshot(source, expected, self.root / 'first', self.limits, self.budget)
        self.assertEqual(self.budget['compressed_allowance'], 24)
        self.assertEqual(self.budget['compressed_observed_snapshot_bytes'], 8)
        with self.assertRaisesRegex(ValueError, 'aggregate'):
            audit.snapshot(source, expected, self.root / 'second', self.limits, self.budget)
        self.assertEqual(self.budget['compressed_allowance'], 24)
        self.assertEqual(self.budget['compressed_observed_snapshot_bytes'], 8)
        self.assertFalse((self.root / 'second').exists())

    def test_snapshot_early_refusal_keeps_reservation(self):
        source = self.root / 'source'
        source.write_bytes(b'longer')
        expected = {'bytes': 4, 'sha256': audit.sha(b'long')}
        with self.assertRaisesRegex(ValueError, 'size/type'):
            audit.snapshot(source, expected, self.root / 'wrong-size', self.limits, self.budget)
        self.assertEqual(self.budget['compressed_allowance'], 12)
        self.assertEqual(self.budget['compressed_observed_snapshot_bytes'], 0)

    def status(self, signer=None, primary=None):
        signer = signer or self.config['official_primary']
        primary = primary or signer
        return '[GNUPG:] VALIDSIG %s 2026-11-15 1794700000 0 4 0 1 8 00 %s\n' % (signer, primary)

    def test_strict_signature_primary_roles_and_bad_status(self):
        official, project = self.config['official_primary'], self.config['project_primary']
        self.assertEqual(audit.signature_status(0, self.status(), official)['primary'], official)
        self.assertEqual(audit.signature_status(0, self.status(project), project)['freshness_external_trust_native_build'], 'HOLD')
        for code, text, expected in [
            (1, self.status(), official), (0, self.status(project), official),
            (0, self.status(official, project), official), (0, self.status(project, official), official),
            (0, self.status() * 2, official), (0, '', official),
            (0, self.status().replace(' 00 ', ' '), official),
        ]:
            with self.subTest(code=code, text=text), self.assertRaises(ValueError):
                audit.signature_status(code, text, expected)
        for bad in audit.BAD:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                audit.signature_status(0, self.status() + '[GNUPG:] ' + bad + ' detail\n', official)

    def test_candidates_only_declared_or_frozen_intake(self):
        config = {'six_pair_archive_root': '/frozen-six'}
        intake = {'pairs': [{'archive': {'filename': 'known.pkg.tar.xz'}}]}
        item = {'archive': {'filename': 'known.pkg.tar.xz'}, 'observations': [
            {'path': '/declared/archive'}, {'archive': {'path': '/paired/archive'}, 'signature': {'path': '/paired/sig'}},
            {'path': '/declared/archive'}, {'unrelated': '/ignore'}]}
        self.assertEqual(audit.candidate_paths(item, config, intake), [
            ('/declared/archive', '/declared/archive.sig'), ('/paired/archive', '/paired/sig')])
        item['observations'] = []
        self.assertEqual(audit.candidate_paths(item, config, intake), [('/frozen-six/known.pkg.tar.xz', '/frozen-six/known.pkg.tar.xz.sig')])
        item['archive']['filename'] = 'not-declared.pkg.tar.xz'
        self.assertEqual(audit.candidate_paths(item, config, intake), [])

    def test_metadata_exact_identity_and_archive_accounting(self):
        row, entries = self.inspect()
        self.assertEqual(row['PKGINFO_status'], 'PASS_EXACT_PLAN')
        self.assertEqual(row['BUILDINFO_status'], 'PASS_IDENTITY')
        self.assertEqual(row['members'], 2)
        self.assertEqual(set(entries), {'/.PKGINFO', '/.BUILDINFO'})
        self.assertEqual(row['logical_bytes'], self.budget['logical_bytes'])
        self.assertEqual(row['raw_headers'], self.budget['headers'])

    def test_many_extended_members_never_accumulate_tarinfo_cache(self):
        reader = audit.CurrentMemberTarFile
        for format in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT):
            with self.subTest(format=format):
                observed = []
                class ObservedReader(reader):
                    def next(self):
                        member = super().next()
                        observed.append(len(self.members))
                        return member
                path = self.root / ('extended-%d.tar.xz' % format)
                with tarfile.open(path, 'w:xz', format=format, preset=0) as archive:
                    members = [('.PKGINFO', self.pkginfo), ('.BUILDINFO', self.buildinfo)]
                    members += [('usr/share/' + 'long-name-' * 20 + str(i), b'x') for i in range(2048)]
                    for name, body in members:
                        member = tarfile.TarInfo(name); member.size = len(body)
                        archive.addfile(member, io.BytesIO(body))
                before = self.budget['headers']
                with patch.object(audit, 'CurrentMemberTarFile', ObservedReader):
                    row, entries = audit.inspect(path, self.item, self.modules, self.limits, self.budget)
                self.assertEqual(row['PKGINFO_status'], 'PASS_EXACT_PLAN')
                self.assertEqual(row['members'], 2050)
                self.assertEqual(self.budget['headers'] - before, 4098)
                self.assertEqual(entries['/' + members[-1][0]]['sha256'], audit.sha(b'x'))
                self.assertGreaterEqual(len(observed), 2051)
                self.assertEqual(max(observed), 0)

    def test_pkginfo_wrong_or_duplicate_identity_fails(self):
        for body in [self.pkginfo.replace(b'pkgver = 1-1', b'pkgver = 2-1'),
                     self.pkginfo + b'pkgname = synthetic-ui\n']:
            with self.subTest(body=body):
                row, _ = self.inspect([('.PKGINFO', body), ('.BUILDINFO', self.buildinfo)])
                self.assertEqual(row['PKGINFO_status'], 'FAIL')

    def test_buildinfo_absent_or_conflicting_identity_held(self):
        for body in [None, self.buildinfo.replace(b'pkgarch = aarch64', b'pkgarch = x86_64'),
                     self.buildinfo + b'pkgver = 2-1\n', self.buildinfo + b'pkgname = synthetic-ui\n']:
            members = [('.PKGINFO', self.pkginfo)]
            if body is not None:
                members.append(('.BUILDINFO', body))
            with self.subTest(body=body):
                row, _ = self.inspect(members)
                self.assertEqual(row['BUILDINFO_status'], 'HOLD')

    def test_duplicate_pkgbase_in_both_metadata_files_held(self):
        for extra in [b'pkgbase = synthetic-ui\n', b'pkgbase = contradictory\n']:
            with self.subTest(extra=extra):
                row, _ = self.inspect([('.PKGINFO', self.pkginfo + extra),
                                       ('.BUILDINFO', self.buildinfo + extra)])
                self.assertEqual(row['BUILDINFO_status'], 'HOLD')

    def test_duplicate_canonical_member_refused(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.inspect([('.PKGINFO', self.pkginfo), ('./.PKGINFO', self.pkginfo)])

    def test_path_traversal_and_non_directory_ancestor_refused(self):
        for members in [[('../escaped', b'x')], [('usr', b'x'), ('usr/bin/tool', b'x')]]:
            with self.subTest(members=members), self.assertRaises(ValueError):
                self.inspect(members)

    def test_links_are_catalog_data_and_never_followed(self):
        link = tarfile.TarInfo('usr/lib/link')
        link.type, link.linkname = tarfile.SYMTYPE, '/definitely/not/a/host/file'
        row, entries = self.inspect([('usr/lib/link', link)])
        self.assertEqual(entries['/usr/lib/link'], {'type': 'symlink', 'resolved': '/definitely/not/a/host/file'})
        self.assertEqual(row['ELF_objects'], [])
        link.linkname = '../../../../escape'
        with self.assertRaisesRegex(ValueError, 'escapes'):
            self.inspect([('usr/lib/link', link)])

    def test_metadata_and_total_decoded_caps(self):
        self.limits['metadata_object_bytes'] = len(self.pkginfo) - 1
        with self.assertRaisesRegex(ValueError, 'metadata object cap'):
            self.inspect()
        self.limits = copy.deepcopy(self.config['limits'])
        self.limits['logical_bytes'] = 1024
        with self.assertRaisesRegex(ValueError, 'logical|decoded'):
            self.inspect()

    def test_aggregate_header_cap_and_deadline(self):
        self.limits['members'] = 1
        with self.assertRaisesRegex(ValueError, 'header cap'):
            self.inspect()
        self.limits = copy.deepcopy(self.config['limits'])
        self.budget['deadline'] = time.monotonic() - 1
        with self.assertRaisesRegex(ValueError, 'deadline'):
            self.inspect()

    def test_elf_4k_vs_16k_and_object_cap(self):
        for alignment, status in [(4096, 'FAIL_GEOMETRY_OR_ARCH'), (16384, 'PASS_STATIC_ELF')]:
            with self.subTest(alignment=alignment):
                row, _ = self.inspect([('usr/bin/tool', elf(alignment))])
                obj = row['ELF_objects'][0]
                self.assertEqual(obj['status'], status)
                self.assertFalse(obj['elf']['runtime_load_verified'])
                self.assertEqual(obj['geometry']['hardware_status'], 'NOT RUN')
        self.limits['elf_object_bytes'] = 100
        row, _ = self.inspect([('usr/bin/tool', elf())])
        self.assertEqual(row['ELF_objects'][0]['status'], 'HOLD_OBJECT_CAP')
        self.assertNotIn('elf', row['ELF_objects'][0])

    def test_baseline_metadata_does_not_close_payload_or_symbol_gap(self):
        report = {'packages': [{'name': 'synthetic-ui', 'version': '1-1', 'repo': 'extra',
                   'status': 'PASS_BYTE_SIGNATURE_METADATA_SCAN', 'PKGINFO_status': 'PASS_EXACT_PLAN',
                   'signature': {'status': 'PASS_SIGNATURE_MATHEMATICS'},
                   'metadata': {'/.PKGINFO': {'fields': {'pkgname': ['synthetic-ui']}}},
                   'ELF_objects': [{'path': '/usr/bin/tool', 'status': 'PASS_STATIC_ELF',
                       'elf': {'classification': 'aarch64-loadable-elf', 'needed': ['libc.so.6']},
                       'gnu_versions': {'needs': {'libc.so.6': ['GLIBC_2.43']}}}]}]}
        plan = {'edges': [{'consumer': {'name': 'synthetic-ui'}, 'requirement': 'glibc',
                           'selected': {'name': 'glibc'}}]}
        baseline = {'packages': [{'name': 'glibc', 'version': '2.43-1', 'desc': {}}]}
        audit.finish_joins(report, plan, baseline, {}, self.modules)
        self.assertEqual(report['actual_dependency_joins'][0]['status'], 'PASS_METADATA_ONLY')
        self.assertEqual(report['static_NEEDED_joins'][0]['status'], 'HOLD_BASELINE_OR_MISSING_PAYLOAD_PROVIDER')
        self.assertEqual(report['GNU_version_name_joins'][0]['status'], 'HOLD_BASELINE_OR_PROVIDER_GEOMETRY_SYMBOLS')

    def test_unsupported_search_holds_needed_and_version_names(self):
        def package(name, obj):
            return {'name': name, 'version': '1-1', 'repo': 'extra',
                    'status': 'PASS_BYTE_SIGNATURE_METADATA_SCAN', 'ELF_objects': [obj]}
        consumer = {'path': '/usr/bin/tool', 'status': 'PASS_STATIC_ELF',
                    'elf': {'classification': 'aarch64-loadable-elf', 'needed': ['libtest.so.1']},
                    'gnu_versions': {'needs': {'libtest.so.1': ['TEST_1']}}}
        provider = {'path': '/usr/lib/libtest.so.1', 'status': 'PASS_STATIC_ELF',
                    'elf': {'classification': 'aarch64-loadable-elf', 'needed': []},
                    'gnu_versions': {'defines': ['TEST_1']}}
        namespace = {'/usr/bin/tool': {'package': 'consumer', 'type': 'file'},
                     '/usr/lib/libtest.so.1': {'package': 'provider', 'type': 'file'}}
        for search, expected in [(None, 'PASS_VERSION_NAME'), ('relative/path', 'HOLD_UNSUPPORTED_SEARCH_PATH')]:
            with self.subTest(search=search):
                obj = copy.deepcopy(consumer)
                if search is not None:
                    obj['elf']['runpath'] = search
                report = {'packages': [package('consumer', obj), package('provider', provider)]}
                audit.finish_joins(report, {'edges': []}, {'packages': []}, namespace, self.modules)
                needed, version = report['static_NEEDED_joins'][0], report['GNU_version_name_joins'][0]
                self.assertEqual(needed['provider'], '/usr/lib/libtest.so.1')
                self.assertEqual(version['status'], expected)
                self.assertEqual(needed['status'], 'PASS_ADDITION_NAMESPACE_VERSION_NAMES_ONLY'
                                 if search is None else 'HOLD_UNSUPPORTED_SEARCH_PATH')

    def test_selected_payload_projection_preserves_nodes_and_static_elf_fields(self):
        path = self.root / 'projection.tar.xz'
        tool = elf()
        with tarfile.open(path, 'w:xz', format=tarfile.USTAR_FORMAT, preset=0) as archive:
            for name, body, mode, uid, gid in [('usr/bin/tool', tool, 0o755, 0, 0),
                    ('usr/share/data', b'contents', 0o640, 10, 20), ('usr/share/unselected', b'other', 0o644, 0, 0)]:
                entry = tarfile.TarInfo(name)
                entry.size, entry.mode, entry.uid, entry.gid = len(body), mode, uid, gid
                archive.addfile(entry, io.BytesIO(body))
            for name, kind, target in [('usr/bin/link', tarfile.SYMTYPE, 'tool'),
                                       ('usr/bin/hard', tarfile.LNKTYPE, 'usr/bin/tool')]:
                entry = tarfile.TarInfo(name)
                entry.type, entry.linkname, entry.mode = kind, target, 0o777
                archive.addfile(entry)
        selected = {'/usr/bin/tool', '/usr/share/data', '/usr/bin/link', '/usr/bin/hard'}
        row, entries = audit.inspect(path, self.item, self.modules, self.limits, self.budget, selected)
        data = entries['/usr/share/data']['payload']
        self.assertEqual(data, {'type': '0', 'mode': 0o640, 'uid': 10, 'gid': 20,
                               'bytes': 8, 'sha256': audit.sha(b'contents'), 'link': ''})
        projected = entries['/usr/bin/tool']['payload']
        self.assertEqual(projected['mode'], 0o755)
        self.assertEqual(projected['sha256'], audit.sha(tool))
        self.assertEqual(projected['ELF'], {'machine': 'aarch64', 'LOAD': [
            {'offset': 0, 'vaddr': 0, 'align': 16384, 'flags': 5}], 'runtime': 'NOT RUN'})
        self.assertEqual(row['ELF_objects'][0]['status'], 'PASS_STATIC_ELF')
        for name, kind, target in [('/usr/bin/link', '2', 'tool'), ('/usr/bin/hard', '1', 'usr/bin/tool')]:
            with self.subTest(name=name):
                payload = entries[name]['payload']
                self.assertEqual(payload['type'], kind)
                self.assertEqual(payload['mode'], 0o777)
                self.assertEqual(payload['link'], target)
                self.assertIsNone(payload['sha256'])
                self.assertNotIn('ELF', payload)
                self.assertEqual(entries[name]['resolved'], '/usr/bin/tool')
        self.assertNotIn('payload', entries['/usr/share/unselected'])


if __name__ == '__main__':
    unittest.main()
