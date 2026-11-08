"""Producer ownership contract and isolated ordinary-input refusals; no native actor."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace
import unittest

P = Path(__file__).resolve().parents[1] / 'overlay/native'
NAME = 'cachy-asahi-security-maintenance'
ARCHIVE = NAME + '-0.1.0-2-any.pkg.tar.zst'
PRIOR = NAME + '-0.1.0-1-any.pkg.tar.zst'


def isolated(filename, names, namespace):
    tree = ast.parse((P / filename).read_bytes())
    body = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names]
    assert {n.name for n in body} == set(names)
    exec(compile(ast.Module(body=body, type_ignores=[]), '<isolated-functions>', 'exec'), namespace)
    return namespace


class ArchiveRootOwnership(unittest.TestCase):
    def test_exact_three_archive_copies_establish_root_ownership_without_other_recipe_changes(self):
        ns = isolated('security_native_v1.py', ('dockerfile',),
                      dict(re=re, ARCHIVE=ARCHIVE, PRIOR_ARCHIVE=PRIOR,
                           need=lambda ok, why: self.assertTrue(ok, why)))
        rendered = ns['dockerfile']('FROM bounded-base\nRUN true\nUSER alarm\nWORKDIR /tmp\n', 'a' * 64)
        rows = [line for line in rendered.splitlines() if line.startswith('COPY --from=')]
        archive_rows = [line for line in rows if '.pkg.tar.zst' in line]
        self.assertEqual(archive_rows, [
            f'COPY --from=security-prior-build --chown=0:0 /tmp/security-prior-build/{PRIOR} /opt/native-security-v1/prior/{PRIOR}',
            f'COPY --from=security-build-one --chown=0:0 /tmp/security-build/{ARCHIVE} /opt/native-security-v1/pair/one/{ARCHIVE}',
            f'COPY --from=security-build-two --chown=0:0 /tmp/security-build/{ARCHIVE} /opt/native-security-v1/pair/two/{ARCHIVE}',
        ])
        self.assertEqual(rendered.count('--chown=0:0'), 3)
        self.assertEqual(len(rows), 6)
        self.assertTrue(all('--chown' not in row for row in rows if row not in archive_rows))
        # This fixed synthetic-base digest covers the entire previous recipe:
        # stage ordering, commands, stage-slot copies and USER alarm boundaries.
        self.assertEqual(hashlib.sha256(rendered.replace(' --chown=0:0', '').encode()).hexdigest(),
                         '43922a27d13bb8953543efb59e96208037ae6e4e6b262dd631615aab5944317d')

    def test_profile_payload_expected_map_and_prepare_pin_agree(self):
        factory = P.parent.parent
        raw = (factory / 'profile.json').read_bytes(); profile = json.loads(raw)
        prepare = ast.parse((factory / 'prepare.py').read_bytes())
        digest = next(n.value.value for n in prepare.body if isinstance(n, ast.Assign)
                      and any(isinstance(t, ast.Name) and t.id == 'PROFILE_SHA256' for t in n.targets))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
        helper = (P / 'security_native_v1.py').read_bytes()
        row = dict(bytes=len(helper), sha256=hashlib.sha256(helper).hexdigest(), mode=0o644)
        self.assertEqual(profile['payload']['native/security_native_v1.py'], row)
        self.assertEqual(profile['expected']['files']['native/security_native_v1.py'], row)
        self.assertEqual(profile['proposed_ref'], 'codex/native-security-maintenance-recovery-v12')
        self.assertTrue(all(value is None for value in profile['actual'].values()))
        self.assertEqual(profile['parent']['source'], '850368889d6dcabdc8afbe87f64f05650c44f90a')
        mapping = dict(profile['source_map_metadata'])
        mapping['files'] = {name: row for name, row in profile['expected']['files'].items()
                            if name != 'native/source-map.json'}
        self.assertEqual(len(mapping['files']), 208)
        encoded = (json.dumps(mapping, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
        self.assertEqual(profile['expected']['files']['native/source-map.json'],
                         dict(bytes=len(encoded), sha256=hashlib.sha256(encoded).hexdigest(), mode=0o644))

    def read_fixture(self, path, maximum=1024, *, uid=0, gid=0, mutate=False):
        opened, closed = [], []
        def open_fd(*args):
            fd = os.open(*args); opened.append(fd); return fd
        def stat_fd(fd):
            value = os.fstat(fd)
            fields = {k: getattr(value, k) for k in dir(value) if k.startswith('st_')}
            fields.update(st_uid=uid, st_gid=gid)
            return SimpleNamespace(**fields)
        changed = False
        def read_fd(fd, size):
            nonlocal changed
            raw = os.read(fd, size)
            if mutate and not changed:
                changed = True
                with open(path, 'ab') as stream: stream.write(b'!')
            return raw
        def close_fd(fd):
            closed.append(fd); os.close(fd)
        fake_os = SimpleNamespace(open=open_fd, fstat=stat_fd, read=read_fd, close=close_fd,
            **{key: getattr(os, key) for key in ('O_RDONLY', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK')})
        ns = isolated('security_recovery_native.py', ('need', '_ordinary'), dict(Path=Path, os=fake_os, stat=stat))
        try:
            return ns['_ordinary'](path, maximum)
        finally:
            self.assertEqual(opened, closed)
            for fd in opened:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_ordinary_root_file_accepted_and_descriptor_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'archive'; path.write_bytes(b'archive')
            self.assertEqual(self.read_fixture(path), b'archive')

    def test_nonroot_uid_or_gid_refused_and_descriptor_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'archive'; path.write_bytes(b'archive')
            for uid, gid in ((1000, 0), (0, 1000), (1000, 1000)):
                with self.subTest(uid=uid, gid=gid), self.assertRaisesRegex(ValueError, 'root-owned'):
                    self.read_fixture(path, uid=uid, gid=gid)

    def test_hardlink_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'archive'; path.write_bytes(b'archive')
            alias = Path(directory) / 'hardlink'; os.link(path, alias)
            with self.assertRaisesRegex(ValueError, 'root-owned'): self.read_fixture(path)
            alias.unlink(); alias.symlink_to(path)
            with self.assertRaisesRegex(ValueError, 'canonical'): self.read_fixture(alias)

    def test_nonregular_empty_and_oversized_refused_and_descriptor_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'archive'
            os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, 'root-owned'): self.read_fixture(path)
            path.unlink(); path.write_bytes(b'')
            with self.assertRaisesRegex(ValueError, 'root-owned'): self.read_fixture(path)
            path.write_bytes(b'oversized')
            with self.assertRaisesRegex(ValueError, 'root-owned'): self.read_fixture(path, maximum=3)

    def test_changed_input_refused_and_descriptor_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'archive'; path.write_bytes(b'archive')
            with self.assertRaisesRegex(ValueError, 'stable'): self.read_fixture(path, mutate=True)


if __name__ == '__main__': unittest.main(verbosity=2)
