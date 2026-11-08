#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real TEST-GPG/filesystem archive controls; stable hardware admission alone is modeled."""
import argparse
import contextlib
import copy
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


t = module('endpoint_transport_under_test', HERE / 'transport.py')
fixture = module('endpoint_transport_fixture', HERE.parents[1] / 'client/test_endpoint.py')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def archive_bytes(records):
    """Independent stdlib USTAR headers, without tarfile's record-size padding."""
    chunks = []
    for header, body in records:
        header = copy.copy(header)
        header.size = len(body)
        chunks += [header.tobuf(format=tarfile.USTAR_FORMAT), body, b'\0' * (-len(body) % 512)]
    return b''.join(chunks) + b'\0' * 1024


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture.EndpointTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        fixture.EndpointTests.tearDownClass.__func__(cls)

    def setUp(self):
        fixture.EndpointTests.setUp(self)
        self.tar = self.base / 'endpoint.tar'
        self.output = self.base / 'received'

    put = fixture.EndpointTests.put
    ref = fixture.EndpointTests.ref
    save_spec = fixture.EndpointTests.save_spec
    stage = fixture.EndpointTests.stage
    promote = fixture.EndpointTests.promote
    export = fixture.EndpointTests.export
    snapshot = fixture.EndpointTests.snapshot
    add_sources = fixture.EndpointTests.add_sources
    generation = fixture.EndpointTests.generation
    edit = fixture.EndpointTests.edit
    rehash = fixture.EndpointTests.rehash
    withdraw = fixture.EndpointTests.withdraw

    def gates(self, modeled):
        # Fixture promotion and positive stable API checks model only the same
        # hardware gate used by test_endpoint.py. Actual signatures stay real.
        return (mock.patch.object(t.e.r, 'gates_check', side_effect=lambda *a: t.e.r.load(a[-1]))
                if modeled else contextlib.nullcontext())

    def pack(self, modeled=True, **changes):
        args = dict(generation=self.gen, expected_generation=self.ident, public_keyring=self.keyring,
                    signer=self.key, output=self.tar)
        args.update(changes)
        with self.gates(modeled):
            return t.pack(**args)

    def unpack(self, modeled=True, **changes):
        args = dict(archive=self.tar, archive_sha256=sha(self.tar.read_bytes()),
                    expected_generation=self.ident, public_keyring=self.keyring,
                    signer=self.key, output=self.output)
        args.update(changes)
        with self.gates(modeled):
            return t.unpack(**args)

    def withdrawal_archive(self):
        self.generation(); self.withdraw(); self.pack(modeled=False)

    def records(self):
        with tarfile.open(self.tar, 'r:') as archive:
            result = []
            for member in archive:
                self.assertTrue(member.isfile())
                with archive.extractfile(member) as stream:
                    result.append((copy.copy(member), stream.read()))
            return result

    def refused_unpack(self, raw=None, **changes):
        if raw is not None:
            bad = self.base / 'malformed.tar'; bad.write_bytes(raw)
            changes = dict(archive=bad, archive_sha256=sha(raw), **changes)
        before, children = self.snapshot(self.endpoint), set(self.base.iterdir())
        key = self.keyring.read_bytes()
        with self.assertRaises((t.c.Error, t.e.r.Error, t.k.c.Error, OSError, ValueError, tarfile.TarError)):
            self.unpack(**changes)
        self.assertEqual(self.snapshot(self.endpoint), before)
        self.assertEqual(set(self.base.iterdir()), children)
        self.assertEqual(self.keyring.read_bytes(), key)

    def refused_pack(self, **changes):
        before, children = self.snapshot(self.endpoint), set(self.base.iterdir())
        with self.assertRaises((t.c.Error, t.e.r.Error, t.k.c.Error, OSError, ValueError, tarfile.TarError)):
            self.pack(**changes)
        self.assertEqual(self.snapshot(self.endpoint), before)
        self.assertEqual(set(self.base.iterdir()), children)

    def cli(self, command, output=None, **changes):
        args = dict(expected_generation=self.ident, public_keyring=self.keyring,
                    signer=self.key, output=output or (self.tar if command == 'pack' else self.output))
        if command == 'pack':
            args['generation'] = self.gen
        else:
            args.update(archive=self.tar, archive_sha256=sha(self.tar.read_bytes()))
        args.update(changes)
        argv = [sys.executable, '-B', HERE / 'transport.py', command]
        for key, value in args.items():
            argv += ['--' + key.replace('_', '-'), str(value)]
        return subprocess.run(argv, capture_output=True, timeout=45)

    def assert_flags(self, result):
        for flag in ('freshness_established', 'installation_authorized', 'production_accepted',
                     'trust_changed', 'state_changed', 'network_used'):
            self.assertIs(result[flag], False)

    def test_deterministic_complete_source_roundtrip_aliases_and_relocation(self):
        self.generation(sources=True)
        before, key = self.snapshot(self.endpoint), self.keyring.read_bytes()
        packed = self.pack()
        second = self.base / 'same endpoint.tar'
        self.pack(output=second)
        raw = self.tar.read_bytes()
        self.assertEqual(second.read_bytes(), raw)
        self.assertEqual(packed['status'], 'packed-endpoint-archive')
        self.assertEqual(packed['archive_sha256'], sha(raw))
        self.assertTrue(packed['output_created'])
        self.assertEqual(raw[-1024:], b'\0' * 1024)
        records = self.records()
        files, aliases = t.e.tree(self.gen)
        names = ['export.json', *sorted(n for n in files if n != 'export.json')]
        self.assertEqual([header.name for header, _ in records], names)
        self.assertEqual({header.name: body for header, body in records},
                         {name: (self.gen / name).read_bytes() for name in files})
        listed = subprocess.run(['bsdtar', '-tf', self.tar], capture_output=True, timeout=15)
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertEqual(listed.stdout.decode().splitlines(), names)
        self.assertEqual(len(raw), sum(512 + (len(body) + 511) // 512 * 512 for _, body in records) + 1024)
        unpacked = self.unpack()
        self.assertEqual(unpacked['status'], 'unpacked-endpoint-archive')
        self.assertEqual(self.snapshot(self.output), self.snapshot(self.gen))
        self.assertEqual(unpacked['files'], len(files))
        self.assertEqual(unpacked['aliases'], len(aliases))
        self.assertEqual(unpacked['bytes'], sum((self.gen / name).stat().st_size for name in files))
        self.assertEqual(packed['files'], unpacked['files'])
        self.assertEqual(packed['bytes'], unpacked['bytes'])
        for path in (self.output, *self.output.rglob('*')):
            if not path.is_symlink():
                self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o444)
        moved = self.base / 'relocated'; self.output.rename(moved)
        with self.gates(True):
            verified = t.p.verify(moved, self.ident, self.keyring, self.key)
        self.assertEqual(verified['repository_relative_path'], 'release/repo/fixture.db')
        self.assertTrue(verified['stable_contract_checked'])
        self.assertEqual(self.snapshot(self.endpoint), before)
        self.assertEqual(self.keyring.read_bytes(), key)
        self.assert_flags(packed); self.assert_flags(unpacked)

    def test_real_cli_withdrawal_pack_unpack_preserves_signed_notice(self):
        self.generation(); self.withdraw()
        before = self.snapshot(self.endpoint)
        packed = self.cli('pack')
        self.assertEqual(packed.returncode, 0, packed.stderr)
        self.assertEqual(packed.stderr, b'')
        self.assertEqual(json.loads(packed.stdout)['status'], 'packed-endpoint-archive')
        imported = self.cli('unpack')
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertEqual(imported.stderr, b'')
        result = json.loads(imported.stdout)
        self.assertEqual(result['status'], 'unpacked-endpoint-archive')
        self.assertEqual(result['withdrawn_releases'], ['fixture-1'])
        self.assertIsNone(result['selected_release'])
        self.assertFalse(result['stable_contract_checked'])
        self.assertEqual(self.snapshot(self.output), self.snapshot(self.gen))
        self.assertEqual(t.p.verify(self.output, self.ident, self.keyring, self.key)['withdrawn_releases'], ['fixture-1'])
        self.assertEqual(self.snapshot(self.endpoint), before)
        self.assert_flags(result)

    def test_real_cli_stable_pack_and_unpack_refuse_without_success_stdout(self):
        self.generation()
        packed = self.cli('pack')
        self.assertEqual(packed.returncode, 1)
        self.assertEqual(packed.stdout, b'')
        self.assertEqual(json.loads(packed.stderr)['status'], 'endpoint-transport-refused')
        self.assertFalse(self.tar.exists())
        self.pack()
        imported = self.cli('unpack')
        self.assertEqual(imported.returncode, 1)
        self.assertEqual(imported.stdout, b'')
        self.assertEqual(json.loads(imported.stderr)['status'], 'endpoint-transport-refused')
        self.assertFalse(self.output.exists())

    def test_wrong_outer_digest_generation_and_signer_refused(self):
        self.withdrawal_archive()
        for changes in (dict(archive_sha256='f' * 64), dict(archive_sha256='A' * 64),
                        dict(expected_generation='f' * 64), dict(signer='F' * 40)):
            with self.subTest(changes=changes): self.refused_unpack(**changes)
        self.refused_pack(output=self.base / 'new.tar', expected_generation='f' * 64)

    def test_wrong_real_public_certificate_refused(self):
        self.withdrawal_archive()
        wrong = self.inputs / 'wrong.gpg'; uid = 'Wrong transport key <transport@invalid>'
        fixture.fixture.e.r.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
            '--quick-generate-key', uid, 'ed25519', 'sign', '1d'], env=self.env)
        fixture.fixture.e.r.run(['gpg', '--batch', '--export', '--output', wrong, uid], env=self.env)
        self.refused_unpack(public_keyring=wrong)

    def test_package_and_source_body_tamper_with_fresh_outer_hash_refused(self):
        self.generation(sources=True); self.pack()
        records = self.records()
        for name in ('release/repo/' + self.archive_package_name(), 'release/evidence/source.tar'):
            changed = [(header, body + b'tampered' if header.name == name else body) for header, body in records]
            self.assertTrue(any(h.name == name for h, _ in records))
            with self.subTest(member=name): self.refused_unpack(archive_bytes(changed))

    def archive_package_name(self):
        return next(p.name for p in (self.gen / 'release/repo').iterdir() if '.pkg.tar.' in p.name and not p.name.endswith('.sig'))

    def test_inventory_tamper_and_unknown_member_refused(self):
        self.withdrawal_archive(); records = self.records()
        changed = [(header, body + b' ' if header.name == 'export.json' else body) for header, body in records]
        self.refused_unpack(archive_bytes(changed))
        extra = tarfile.TarInfo('unknown'); extra.mode = 0o644
        self.refused_unpack(archive_bytes([*records, (extra, b'foreign bytes')]))

    def test_header_extensions_and_special_member_types_refused(self):
        self.withdrawal_archive(); records = self.records()
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                     tarfile.GNUTYPE_LONGLINK, tarfile.GNUTYPE_SPARSE,
                     tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE,
                     tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            header = copy.copy(records[0][0]); header.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE): header.linkname = 'outside'
            with self.subTest(kind=kind): self.refused_unpack(archive_bytes([(header, records[0][1]), *records[1:]]))

    def test_noncanonical_header_metadata_refused(self):
        self.withdrawal_archive(); records = self.records()
        for field, value in [('mode', 0o755), ('uid', 1), ('gid', 1), ('mtime', 1),
                             ('uname', 'owner'), ('gname', 'group'), ('linkname', 'hidden'),
                             ('type', tarfile.AREGTYPE)]:
            header = copy.copy(records[0][0]); setattr(header, field, value)
            with self.subTest(field=field): self.refused_unpack(archive_bytes([(header, records[0][1]), *records[1:]]))

    def test_rooted_traversal_ambiguous_and_hidden_member_names_refused(self):
        self.withdrawal_archive(); records = self.records()
        for name in ('/export.json', '../export.json', './export.json', 'a/../export.json',
                     'a//export.json', 'export.json\0hidden', 'prefix/export.json'):
            header = copy.copy(records[0][0]); header.name = name
            with self.subTest(name=name): self.refused_unpack(archive_bytes([(header, records[0][1]), *records[1:]]))

    def test_duplicate_and_reordered_entries_refused(self):
        self.withdrawal_archive(); records = self.records()
        for changed in ([records[1], records[0], *records[2:]],
                        [records[0], records[2], records[1]],
                        [records[0], records[1], records[1], *records[2:]]):
            with self.subTest(names=[h.name for h, _ in changed]): self.refused_unpack(archive_bytes(changed))

    def test_partial_padding_end_junk_and_concatenated_archives_refused(self):
        self.withdrawal_archive(); raw = self.tar.read_bytes()
        with tarfile.open(self.tar, 'r:') as archive:
            first = archive.next(); pad = first.offset_data + first.size
        nonzero = bytearray(raw); self.assertNotEqual(pad % 512, 0); nonzero[pad] = 1
        for changed in (raw[:100], raw[:pad - 1], raw[:-512], raw[:-1024], raw + b'\0' * 512,
                        raw + b'junk', raw + raw, raw + b'\0' * (10240 - len(raw) % 10240), bytes(nonzero)):
            with self.subTest(length=len(changed)): self.refused_unpack(changed)

    def test_checksum_and_hidden_header_padding_refused(self):
        self.withdrawal_archive(); raw = self.tar.read_bytes()
        changed = bytearray(raw); changed[0] ^= 1
        self.refused_unpack(bytes(changed))
        # Bytes outside the represented USTAR fields cannot hide extra metadata,
        # even after updating the ordinary tar checksum independently.
        changed = bytearray(raw); changed[500] = 1; changed[148:156] = b' ' * 8
        changed[148:156] = ('%06o\0 ' % sum(changed[:512])).encode()
        self.refused_unpack(bytes(changed))

    def test_valid_signed_endpoint_with_unrepresentable_ustar_name_refused(self):
        rid = 'long-release-' + 'x' * 100
        self.promote(rid)
        reason = self.inputs / 'incident.txt'; reason.write_text('Synthetic long-name withdrawal.\n')
        fixture.fixture.e.r.withdraw(argparse.Namespace(release_id=rid, reason=str(reason)),
                                    self.root, self.key, self.env)
        record = self.export(); self.ident = record['generation']
        self.gen = self.endpoint / 'generations' / self.ident
        verified = t.p.verify(self.gen, self.ident, self.keyring, self.key)
        self.assertEqual(verified['withdrawn_releases'], [rid])
        self.refused_pack(modeled=False)
        self.assertFalse(self.tar.exists())

    def test_resources_and_deadline_refuse_without_output(self):
        self.withdrawal_archive()
        for name, value in (('MAX_FILES', 1), ('MAX_BYTES', 1),
                            ('MAX_ARCHIVE', self.tar.stat().st_size - 1), ('MAX_SECONDS', 0)):
            with self.subTest(bound=name), mock.patch.object(t, name, value): self.refused_unpack()

    def test_existing_output_types_and_parent_permissions_never_overwrite(self):
        self.withdrawal_archive()
        for kind in ('file', 'directory', 'symlink'):
            if kind == 'file': self.output.write_bytes(b'operator data')
            elif kind == 'directory': self.output.mkdir(); (self.output / 'held').write_bytes(b'operator data')
            else: self.output.symlink_to(self.inputs)
            before = self.snapshot(self.base)
            self.refused_unpack(); self.refused_pack(output=self.output)
            self.assertEqual(self.snapshot(self.base), before)
            if kind == 'directory': shutil.rmtree(self.output)
            else: self.output.unlink()
        parent = self.base / 'writable'; parent.mkdir(); parent.chmod(0o777)
        self.refused_unpack(output=parent / 'out'); self.refused_pack(output=parent / 'out.tar')
        parent.chmod(0o700)

    def test_symlink_hardlink_nested_and_noncanonical_operands_refused(self):
        self.withdrawal_archive()
        alias = self.base / 'archive-link'; alias.symlink_to(self.tar)
        self.refused_unpack(archive=alias)
        hard = self.base / 'hard.tar'; os.link(self.tar, hard)
        self.refused_unpack(archive=hard)
        hard.unlink()
        source = self.base / 'source-link'; source.symlink_to(self.gen, target_is_directory=True)
        self.refused_pack(generation=source, output=self.base / 'new.tar')
        self.refused_pack(output=self.gen / 'nested.tar')
        self.refused_unpack(output=str(self.base) + '/../untrusted')
        key = self.base / 'key-link'; key.symlink_to(self.keyring)
        self.refused_unpack(public_keyring=key)

    def test_source_shared_lock_and_exclusive_writer_refusal(self):
        self.generation()
        fd = os.open(self.gen, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.refused_pack()
        finally:
            os.close(fd)
        original, calls = t.p.verify, []
        def observe(*args, **kw):
            if Path(args[0]) == self.gen:
                held = os.open(self.gen, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    with self.assertRaises(BlockingIOError): fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(held)
                calls.append(True)
            return original(*args, **kw)
        with mock.patch.object(t.p, 'verify', side_effect=observe): self.pack()
        self.assertGreaterEqual(len(calls), 2)

    def test_source_change_before_final_verification_refuses_publication(self):
        self.generation()
        original, calls = t.p.verify, []
        def change(*args, **kw):
            if Path(args[0]) == self.gen:
                calls.append(True)
                if len(calls) == 2: self.edit(self.gen / 'promotion.json.sig', b'changed after stream\n')
            return original(*args, **kw)
        children = set(self.base.iterdir())
        with mock.patch.object(t.p, 'verify', side_effect=change):
            with self.assertRaises((t.c.Error, t.e.r.Error, OSError, ValueError)): self.pack()
        self.assertEqual(len(calls), 2)
        self.assertFalse(self.tar.exists())
        self.assertEqual(set(self.base.iterdir()), children)

    def test_stream_faults_clean_partial_pack_and_unpack_outputs(self):
        self.generation()
        original = t.transfer
        calls = []
        def fail(stream, output, size, expected, deadline):
            calls.append(True)
            if len(calls) == 2:
                output.write(b'partial')
                raise OSError('injected stream write failure')
            return original(stream, output, size, expected, deadline)
        with mock.patch.object(t, 'transfer', side_effect=fail):
            self.refused_pack()
        self.assertEqual(len(calls), 2)
        self.assertFalse(self.tar.exists())
        self.pack(); calls.clear()
        with mock.patch.object(t, 'transfer', side_effect=fail):
            self.refused_unpack()
        self.assertEqual(len(calls), 2)
        self.assertFalse(self.output.exists())

    def test_atomic_publication_collisions_preserve_other_writer(self):
        self.generation()
        original, before = t.publish_file, self.snapshot(self.endpoint)
        def race_file(*args):
            self.tar.write_bytes(b'other archive writer')
            return original(*args)
        with mock.patch.object(t, 'publish_file', side_effect=race_file):
            with self.assertRaises(OSError): self.pack()
        self.assertEqual(self.tar.read_bytes(), b'other archive writer')
        self.assertFalse(list(self.base.glob('.endpoint-pack-*')))
        self.tar.unlink(); self.pack()
        original_directory = t.k.publish
        def race_directory(*args):
            self.output.mkdir(); (self.output / 'held').write_bytes(b'other directory writer')
            return original_directory(*args)
        with mock.patch.object(t.k, 'publish', side_effect=race_directory):
            with self.assertRaises(OSError): self.unpack()
        self.assertEqual(self.snapshot(self.output), {'held': ('file', b'other directory writer')})
        self.assertFalse(list(self.base.glob('.endpoint-unpack-*')))
        self.assertEqual(self.snapshot(self.endpoint), before)

    def test_archive_reads_are_incremental_and_never_whole_file(self):
        self.withdrawal_archive()
        digest = sha(self.tar.read_bytes())
        read, io_open, fdopen = os.read, io.open, os.fdopen
        requests = []
        def selected(value):
            try:
                path = os.readlink('/proc/self/fd/' + str(value)) if isinstance(value, int) else os.fspath(value)
                return Path(path) == self.tar
            except (OSError, TypeError): return False
        def bounded(fd, count):
            if selected(fd):
                self.assertGreater(count, 0); self.assertLessEqual(count, t.CHUNK); requests.append(count)
            return read(fd, count)
        class Reader:
            def __init__(self, stream): self.stream = stream
            def read(inner, count=-1):
                self.assertGreater(count, 0); self.assertLessEqual(count, t.CHUNK); requests.append(count)
                return inner.stream.read(count)
            def __getattr__(self, name): return getattr(self.stream, name)
            def __enter__(self): return self
            def __exit__(self, *args): return self.stream.__exit__(*args)
        def opened(original):
            def call(value, *args, **kw):
                result = original(value, *args, **kw)
                return Reader(result) if selected(value) else result
            return call
        with mock.patch.object(os, 'read', side_effect=bounded), \
             mock.patch.object(io, 'open', side_effect=opened(io_open)), \
             mock.patch.object(os, 'fdopen', side_effect=opened(fdopen)):
            result = t.unpack(self.tar, digest, self.ident, self.keyring, self.key, self.output)
        self.assertEqual(result['status'], 'unpacked-endpoint-archive')
        self.assertGreater(len(requests), 3)


if __name__ == '__main__':
    unittest.main()
