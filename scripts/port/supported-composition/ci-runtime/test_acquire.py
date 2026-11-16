#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""MODEL transfer/cache controls. Never contact archives or execute image tools."""
import base64
import hashlib
import importlib.util
import io
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('composition_input_acquisition', HERE / 'acquire.py')
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.exec', 'os.fork', 'os.posix_spawn'):
        raise AssertionError('MODEL controls forbid network/process/actor operation: ' + event)


sys.addaudithook(fence)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


class Model:
    """Tiny MODEL bodies and synthetic DB; none is an actual Arch input."""
    PACKAGES = ('mpdecimal-4.0.1-3-x86_64.pkg.tar.zst', 'python-3.14.9-1-x86_64.pkg.tar.zst')

    def __init__(self, root, mutation=None):
        self.root = root
        self.cache, self.context, self.lock = root / 'cache', root / 'context', root / 'model.lock'
        self.data = {name: ('MODEL package ' + name).encode() for name in self.PACKAGES}
        self.data.update({name + '.sig': ('MODEL signature ' + name).encode() for name in self.PACKAGES})
        self.sources = {'core.db': 'https://archive.archlinux.org/repos/2026/11/09/core/os/x86_64/core.db'}
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode='w') as archive:
            for name in self.PACKAGES:
                prefix = name.removesuffix('-x86_64.pkg.tar.zst')
                fields = {'FILENAME': name, 'CSIZE': str(len(self.data[name])),
                          'SHA256SUM': pin(self.data[name])['sha256'],
                          'PGPSIG': base64.b64encode(self.data[name + '.sig']).decode()}
                if mutation and name == self.PACKAGES[0]:
                    mutation(fields)
                raw = ''.join('%' + key + '%\n' + value + '\n\n' for key, value in fields.items()).encode()
                member = tarfile.TarInfo(prefix + '/desc')
                member.size, member.mode = len(raw), 0o644
                archive.addfile(member, io.BytesIO(raw))
                self.sources[name] = 'https://archive.archlinux.org/packages/' + name[0] + '/' + prefix.rsplit('-', 2)[0] + '/' + name
                self.sources[name + '.sig'] = 'db:' + prefix + '/desc'
        self.data['core.db'] = output.getvalue()
        self.order = ['core.db', *self.PACKAGES, *(name + '.sig' for name in self.PACKAGES)]
        self.lock.write_text(''.join(f"{len(self.data[name])} {pin(self.data[name])['sha256']} {name} {self.sources[name]}\n" for name in self.order))
        self.lock.chmod(0o644)
        self.rows = A.load_lock(self.lock)
        self.by_source = {self.sources[name]: name for name in self.order}
        self.calls = []

    def transfer(self, row, path, remaining):
        name = self.by_source[row['source']]
        self.calls.append((name, remaining))
        path.write_bytes(self.data[name])
        return dict(http_status=200, scope='MODEL_NOT_NETWORK')

    def acquire(self, **kwargs):
        return A.acquire(self.cache, self.context, lock_path=self.lock, transfer=kwargs.pop('transfer', self.transfer),
                         sleep=kwargs.pop('sleep', lambda _: None), **kwargs)

    def seed(self):
        self.cache.mkdir(mode=0o700)
        for name, raw in self.data.items():
            (self.cache / name).write_bytes(raw)
            (self.cache / name).chmod(0o644)

    def check_context(self):
        self.assertions = {str(p.relative_to(self.context)) for p in self.context.rglob('*') if p.is_file()}
        assert self.assertions == {'inputs.lock'} | {'inputs/' + name for name in self.order}
        assert (self.context / 'inputs.lock').read_bytes() == self.lock.read_bytes()
        for name in self.order:
            assert (self.context / 'inputs' / name).read_bytes() == self.data[name]


class Clock:
    def __init__(self):
        self.now = 0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Acquisition(unittest.TestCase):
    def test_cold_context_and_exact_warm_cache_need_no_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            model = Model(Path(tmp))
            model.acquire()
            model.check_context()
            self.assertEqual([name for name, _ in model.calls], ['core.db', *model.PACKAGES])
            self.assertEqual({p.name for p in model.cache.iterdir()}, set(model.order))
            model.context = model.root / 'warm-context'
            model.acquire(transfer=lambda *args: self.fail('verified warm cache must not transfer'))
            model.check_context()

    def test_corrupt_regular_cache_refetches_only_that_pinned_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            model = Model(Path(tmp)); model.seed()
            (model.cache / model.PACKAGES[1]).write_bytes(b'MODEL corrupt cache')
            model.acquire(); model.check_context()
            self.assertEqual([name for name, _ in model.calls], [model.PACKAGES[1]])

    def test_signature_is_rederived_from_pinned_db_without_extra_transfer(self):
        with tempfile.TemporaryDirectory() as tmp:
            model = Model(Path(tmp)); model.seed()
            (model.cache / (model.PACKAGES[0] + '.sig')).write_bytes(b'MODEL corrupt signature')
            model.acquire(transfer=lambda *args: self.fail('signature must come from pinned DB'))
            model.check_context()

    def test_wrong_download_size_or_digest_never_publishes_or_retries(self):
        for change in ('size', 'digest'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                model = Model(Path(tmp))
                def wrong(row, path, remaining):
                    model.calls.append(('wrong', remaining)); raw = model.data['core.db']
                    path.write_bytes(raw[:-1] if change == 'size' else bytes([raw[0] ^ 1]) + raw[1:])
                    return dict(http_status=200)
                with self.assertRaises(ValueError): model.acquire(transfer=wrong)
                self.assertEqual(len(model.calls), 1)
                self.assertFalse(model.context.exists())
                self.assertFalse((model.cache / 'core.db').exists())

    def test_transient_partial_transfer_retries_then_verifies_complete_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            model = Model(Path(tmp)); attempts = []
            def interrupted(row, path, remaining):
                attempts.append(row['source'])
                if len(attempts) == 1:
                    path.write_bytes(b'MODEL partial')
                    raise A.TransferError('MODEL connection timeout', retryable=True)
                return model.transfer(row, path, remaining)
            model.acquire(transfer=interrupted); model.check_context()
            self.assertEqual(len(attempts), 4)
            self.assertEqual(attempts[0], attempts[1])

    def test_lock_change_after_valid_transfer_refuses_before_context_creation(self):
        with tempfile.TemporaryDirectory() as tmp:
            model = Model(Path(tmp))
            def changing_lock(row, path, remaining):
                result = model.transfer(row, path, remaining)
                if len(model.calls) == 1:
                    text = model.lock.read_text()
                    model.lock.write_text(text.replace(model.rows[model.PACKAGES[0]]['sha256'], '0' * 64))
                return result
            with self.assertRaisesRegex(ValueError, 'lock changed'):
                model.acquire(transfer=changing_lock)
            self.assertEqual(len(model.calls), 3)
            self.assertFalse(model.context.exists())

    def test_retry_exhaustion_and_terminal_errors_stop_without_context(self):
        for retryable, wanted in ((True, 3), (False, 1)):
            with self.subTest(retryable=retryable), tempfile.TemporaryDirectory() as tmp:
                model = Model(Path(tmp)); attempts = []
                def fail(*args):
                    attempts.append(1)
                    raise A.TransferError('MODEL failure', retryable=retryable)
                with self.assertRaises(A.TransferError): model.acquire(transfer=fail)
                self.assertEqual(len(attempts), wanted)
                self.assertFalse(model.context.exists())

    def test_total_deadline_is_not_reset_between_attempts_or_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            model = Model(Path(tmp)); clock = Clock()
            def slow(row, path, remaining):
                model.transfer(row, path, remaining); clock.now += 11
                return dict(http_status=200)
            with self.assertRaisesRegex(ValueError, 'deadline'): model.acquire(transfer=slow, clock=clock, sleep=clock.sleep, total_seconds=10)
            self.assertEqual(len(model.calls), 1)
            self.assertFalse(model.context.exists())

    def test_alias_hardlink_and_fifo_are_not_read_as_cache_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            model = Model(Path(tmp)); leaf = model.root / 'operand'
            leaf.write_bytes(model.data['core.db']); target = model.root / 'other'
            target.symlink_to(leaf)
            with self.assertRaises(ValueError): A.verified(target, model.rows['core.db'])
            target.unlink(); os.link(leaf, target)
            with self.assertRaises(ValueError): A.verified(target, model.rows['core.db'])
            target.unlink(); os.mkfifo(target)
            with self.assertRaises(ValueError): A.verified(target, model.rows['core.db'])

    def test_cache_alias_extra_entry_and_writable_root_refuse_before_transfer(self):
        for change in ('alias', 'extra', 'writable'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                model = Model(Path(tmp)); model.seed()
                if change == 'alias':
                    original = model.cache; model.cache = model.root / 'alias'; model.cache.symlink_to(original, target_is_directory=True)
                elif change == 'extra': (model.cache / 'UNLISTED').write_bytes(b'MODEL')
                else: model.cache.chmod(0o777)
                with self.assertRaises(ValueError): model.acquire(transfer=lambda *args: self.fail('unsafe cache must refuse before transfer'))
                self.assertFalse(model.context.exists())

    def test_existing_or_overlapping_context_is_never_reused(self):
        for change in ('existing', 'nested'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                model = Model(Path(tmp))
                if change == 'existing': model.context.mkdir()
                else: model.context = model.cache / 'nested'
                with self.assertRaises(ValueError): model.acquire(transfer=lambda *args: self.fail('invalid context must refuse before transfer'))

    def test_lock_refuses_duplicate_unsafe_or_unverified_sources(self):
        for change in ('duplicate', 'http', 'moving-host', 'digest', 'path'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as tmp:
                model = Model(Path(tmp)); text = model.lock.read_text()
                if change == 'duplicate': text += text.splitlines()[0] + '\n'
                elif change == 'http': text = text.replace('https://', 'http://', 1)
                elif change == 'moving-host': text = text.replace('archive.archlinux.org', 'example.invalid', 1)
                elif change == 'digest': text = text.replace(model.rows['core.db']['sha256'], 'not-a-pin', 1)
                else: text = text.replace(' core.db ', ' ../core.db ', 1)
                model.lock.write_text(text)
                with self.assertRaises(ValueError): A.load_lock(model.lock)

    def test_db_package_fields_and_embedded_signature_must_join_lock(self):
        for field, value in (('FILENAME', 'substituted.pkg.tar.zst'), ('CSIZE', '1'), ('SHA256SUM', '0' * 64), ('PGPSIG', 'not-base64!')):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                model = Model(Path(tmp), mutation=lambda fields: fields.update({field: value}))
                with self.assertRaises((ValueError, KeyError)): A.database(model.rows, model.data['core.db'])

    def test_curl_has_explicit_https_size_and_process_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            model = Model(Path(tmp)); row = model.rows['core.db']
            with patch.object(A.subprocess, 'run', return_value=SimpleNamespace(returncode=0, stdout=b'200', stderr=b'')) as run:
                A.fetch(row, model.root / 'download', 7)
            argv = run.call_args.args[0]
            self.assertEqual(argv[:2], ['curl', '--disable'])
            for option, value in (('--proto', '=https'), ('--proto-redir', '=https'), ('--max-redirs', '2'), ('--max-filesize', str(row['bytes']))):
                self.assertEqual(argv[argv.index(option) + 1], value)
            self.assertLessEqual(float(argv[argv.index('--connect-timeout') + 1]), 7)
            self.assertLessEqual(float(argv[argv.index('--max-time') + 1]), 7)
            self.assertLessEqual(run.call_args.kwargs['timeout'], 8)
            self.assertEqual(argv[-1], row['source'])

    def test_curl_retries_only_transport_or_transient_http_failures(self):
        for code, status, retry in ((28, b'000', True), (22, b'503', True), (22, b'429', True), (22, b'404', False), (60, b'000', False), (0, b'302', False)):
            with self.subTest(code=code, status=status), patch.object(A.subprocess, 'run', return_value=SimpleNamespace(returncode=code, stdout=status, stderr=b'')):
                with self.assertRaises(A.TransferError) as error: A.fetch(dict(bytes=10, source='https://archive.archlinux.org/MODEL'), Path('/MODEL-output'), 10)
                self.assertEqual(error.exception.retryable, retry)

    def test_curl_process_timeout_stays_bounded_and_retryable(self):
        with patch.object(A.subprocess, 'run', side_effect=subprocess.TimeoutExpired('MODEL curl', 4)):
            with self.assertRaises(A.TransferError) as error:
                A.fetch(dict(bytes=10, source='https://archive.archlinux.org/MODEL'), Path('/MODEL-output'), 3)
            self.assertTrue(error.exception.retryable)

    def test_real_manifest_and_image_install_keep_original_immutable_contract(self):
        rows = A.load_lock()
        self.assertEqual(rows['core.db']['bytes'], 131666)
        self.assertEqual(rows['core.db']['sha256'], 'aec62efbfb59d300204f936a633a59d3c89d6a7e7f94852b8f621b61a253afae')
        self.assertEqual(set(rows), {'core.db', *(name for package in Model.PACKAGES for name in (package, package + '.sig'))})
        dockerfile = (HERE / 'Dockerfile').read_text()
        self.assertIn('archlinux:base@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae', dockerfile)
        self.assertIn('python=3.14.9-1 mpdecimal=4.0.1-3', dockerfile)
        self.assertIn('SigLevel = Required DatabaseOptional', dockerfile)
        self.assertIn('Server = file:///opt/composition-inputs', dockerfile)
        self.assertIn('RUN --network=none', dockerfile)
        self.assertIn(hashlib.sha256(A.LOCK.read_bytes()).hexdigest(), dockerfile)
        self.assertNotIn('curl ', dockerfile)


if __name__ == '__main__':
    unittest.main()
