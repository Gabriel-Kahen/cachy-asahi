# SPDX-License-Identifier: MIT
"""Synthetic private-root tests; actual commits never use the host package DB."""
import hashlib
import contextlib
import importlib.util
import io
import json
import os
import errno
import fcntl
import py_compile
import stat
import signal
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
WORKER = HERE / 'local_transaction.py'
ARTIFACTS = HERE.parents[1] / 'artifacts/install-local-transaction-correction-20261012/followup-03/tests'
LIBALPM_SHA256 = 'da30edd45277cf4b1000485658976042f8106fe0b97378d1e6c4e81a9d7c4888'
RUNTIME_SHA256 = '8a7cd5e73cf383b2d81ad577b8513c6fd7d49f9fd2572961c73ae9d289cab821'
# Actual executions require the coordinator's independently reviewed source pin.
REVIEWED_WORKER_SHA256 = None
FIXTURE_SELECTION_SHA256 = None  # Native receiver only; legacy actual26 remains unchanged.


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def environment(**values):
    result = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'}
    if 'HOME' in os.environ: result['HOME'] = os.environ['HOME']
    result.update(values)
    return result


def load_worker():
    data = WORKER.read_bytes()
    spec = importlib.util.spec_from_file_location('local_transaction_fixture', WORKER)
    module = importlib.util.module_from_spec(spec)
    exec(compile(data, str(WORKER), 'exec'), module.__dict__)
    module._fixture_source_sha256 = hashlib.sha256(data).hexdigest()
    return module


def capsule_fds():
    found = {}
    for name in os.listdir('/proc/self/fd'):
        try: target = os.readlink('/proc/self/fd/' + name)
        except FileNotFoundError: continue
        if 'memfd:local-transaction-' in target: found[int(name)] = target
    return found


class SignedPackages:
    """Fresh TEST signing state, unrelated to all host/system trust stores."""
    def __init__(self, root):
        self.root = root
        self.home = root / 'test-key-home'; self.home.mkdir(mode=0o700)
        try:
            self.command('--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                         'TEST ONLY private install fixture <install-test@example.invalid>',
                         'ed25519', 'sign', '0')
            listing = self.command('--with-colons', '--list-keys').stdout.decode()
            self.fingerprint = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
            self.certificate = root / 'test-public-key.asc'
            self.certificate.write_bytes(self.command('--armor', '--export', self.fingerprint).stdout)
        except BaseException:
            self.close()
            raise

    def command(self, *args):
        return subprocess.run(['/usr/bin/gpg', '--no-options', '--homedir', str(self.home), '--batch', *args],
                              capture_output=True, check=True, timeout=30,
                              env=environment())

    def close(self):
        subprocess.run(['/usr/bin/gpgconf', '--homedir', str(self.home), '--kill', 'all'],
                       capture_output=True, timeout=10, check=False)

    def package(self, directory, name, version='1.0-1', depends=(), files=None, signing_key=None):
        files = files or {f'usr/share/{name}/data': (name + '\n').encode()}
        metadata = '\n'.join((f'pkgname = {name}', f'pkgbase = {name}', f'pkgver = {version}',
                              'pkgdesc = TEST ONLY inert private-root fixture',
                              'url = https://example.invalid/private-test', 'builddate = 1700000000',
                              'packager = TEST ONLY', f'size = {sum(map(len, files.values()))}',
                              'arch = any', 'license = MIT', *(f'depend = {value}' for value in depends))) + '\n'
        archive = directory / f'{name}-{version}-any.pkg.tar.gz'
        with tarfile.open(archive, 'w:gz') as stream:
            for path, data in {'.PKGINFO': metadata.encode(), **files}.items():
                member = tarfile.TarInfo(path); member.size = len(data); member.mode = 0o644
                member.uid = member.gid = 0; member.mtime = 1700000000
                stream.addfile(member, io.BytesIO(data))
        signature = Path(str(archive) + '.sig')
        self.command('--pinentry-mode', 'loopback', '--passphrase', '', '--local-user', signing_key or self.fingerprint + '!',
                     '--output', str(signature), '--detach-sign', str(archive))
        return archive, signature, files


class Fixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not WORKER.is_file(): raise unittest.SkipTest('local transaction implementation not available')
        missing = [name for name in ('gpg', 'gpgconf') if not shutil.which(name)]
        if missing: raise unittest.SkipTest('fixture signing tools unavailable: ' + ','.join(missing))
        cls.keys_temp = tempfile.TemporaryDirectory(prefix='caa-install-test-keys-')
        cls.addClassCleanup(cls.keys_temp.cleanup)
        cls.keys = SignedPackages(Path(cls.keys_temp.name))
        cls.addClassCleanup(cls.keys.close)
        cls.module = load_worker()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='caa-install-test-case-')
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name); self.workspace.chmod(0o700)
        self.public_key = self.workspace / 'test-public-key.asc'
        self.public_key.write_bytes(self.keys.certificate.read_bytes()); self.public_key.chmod(0o600)

    def reference(self, path):
        return {'path': str(path), 'size': path.stat().st_size, 'sha256': sha(path)}

    def package(self, name='caa-install-fixture-a', version='1.0-1', **kwargs):
        archive, signature, files = self.keys.package(self.workspace, name, version, **kwargs)
        archive.chmod(0o600); signature.chmod(0o600)
        row = {'name': name, 'version': version, 'archive': self.reference(archive),
               'signature': self.reference(signature), 'signer': self.keys.fingerprint}
        return row, files

    def contract(self, rows, before=None, after=None, protected=None, remove=None, timeout=20):
        before, remove = before or {}, remove or {}
        if after is None:
            after = {name: version for name, version in before.items() if name not in remove}
            after.update({row['name']: row['version'] for row in rows})
        contract = {'schema_version': 1, 'scope': 'synthetic-fixture', 'workspace': str(self.workspace),
                'architecture': 'x86_64', 'before': before, 'after': after,
                'protected': protected or {}, 'add': rows, 'remove': remove,
                'keyring': self.reference(self.public_key), 'timeout_seconds': timeout,
                'libalpm_sha256': LIBALPM_SHA256}
        if FIXTURE_SELECTION_SHA256 is not None:
            contract.update(schema_version=2, scope='native-aarch64-fixture', architecture='aarch64',
                            input_selection_sha256=FIXTURE_SELECTION_SHA256,
                            profile_sha256=self.module.NATIVE_PROFILE_SHA)
        return contract


class ContractTests(Fixtures):
    def test_minimal_finite_fixture_contract(self):
        row, _ = self.package()
        self.module.validate_contract(self.contract([row]))

    def test_scope_real_candidate_requires_authority_and_is_not_fixture_override(self):
        row, _ = self.package(); contract = self.contract([row]); contract['scope'] = 'real-candidate'
        for pin in (None, 'a' * 64):
            with self.subTest(selection=pin), self.assertRaises(ValueError):
                self.module.validate_contract(contract, selection_sha256=pin)

    def test_closed_top_level_contract_and_required_inputs(self):
        row, _ = self.package(); original = self.contract([row])
        for field in original:
            contract = json.loads(json.dumps(original)); del contract[field]
            with self.subTest(missing=field), self.assertRaises(ValueError): self.module.validate_contract(contract)
        contract = dict(original, arbitrary='PRIVATE TOKEN')
        with self.assertRaises(ValueError): self.module.validate_contract(contract)

    def test_bounds_and_exact_types(self):
        row, _ = self.package(); original = self.contract([row])
        for field, values in (('timeout_seconds', (True, 0, 1201, 1.0, '1')),
                              ('schema_version', (True, 2, '1')),
                              ('libalpm_sha256', (True, '', 'A' * 64, 'a' * 63)),
                              ('architecture', ('aarch64', '', True))):
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.module.validate_contract(dict(original, **{field: value}))

    def test_duplicate_add_and_malformed_inventory_refused(self):
        row, _ = self.package(); original = self.contract([row])
        for changes in ({'add': [row, row]}, {'before': {'../escape': '1'}},
                        {'after': {'caa-install-fixture-a': True}}, {'remove': {'a': []}},
                        {'protected': {'a': ''}}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.module.validate_contract(dict(original, **changes))

    def test_closed_package_and_file_reference_shapes(self):
        row, _ = self.package()
        for field, value in (('name', '../escape'), ('name', 'a\nargv'), ('version', []),
                             ('signer', 'a' * 40), ('signer', True)):
            poisoned = json.loads(json.dumps(row)); poisoned[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.module.validate_contract(self.contract([poisoned]))
        for reference in ('archive', 'signature'):
            for field, value in (('size', True), ('size', 0), ('sha256', 'A' * 64),
                                 ('path', 'relative'), ('error', 'PRIVATE TOKEN')):
                poisoned = json.loads(json.dumps(row)); poisoned[reference][field] = value
                with self.subTest(reference=reference, field=field), self.assertRaises(ValueError):
                    self.module.capture(poisoned[reference])

    def test_model_postinstall_inventory_mismatch_refused(self):
        for actual in ({'a': '1'}, {'a': '2', 'extra': '1'}, {}):
            with self.subTest(actual=actual), self.assertRaises(ValueError):
                self.module.check_inventory(actual, {'a': '2'}, 'after')
        self.module.check_inventory({'a': '2'}, {'a': '2'}, 'after')

    def test_model_declared_after_exact_add_remove(self):
        self.assertEqual(self.module.declared_after({'a': '1', 'b': '1'}, {'a': '2', 'c': '1'}, {'b': '1'}),
                         {'a': '2', 'c': '1'})

    def test_model_prepared_plan_mismatch_refused(self):
        planned_add, planned_remove = {'a': '2'}, {'b': '1'}
        self.module.check_prepared(planned_add, planned_remove, planned_add, planned_remove)
        for actual_add, actual_remove in (({'a': '3'}, planned_remove),
                                          ({'a': '2', 'extra': '1'}, planned_remove),
                                          (planned_add, {}), (planned_add, {'b': '2'})):
            with self.subTest(add=actual_add, remove=actual_remove), self.assertRaises(ValueError):
                self.module.check_prepared(actual_add, actual_remove, planned_add, planned_remove)

    def test_model_projected_ldconfig_alias_is_refused(self):
        seed = {'usr': {'type': 'directory'}, 'usr/bin': {'type': 'symlink', 'target': 'aux'},
                'usr/aux': {'type': 'directory'}}
        for origin in ('existing', 'added'):
            file = {'type': 'file', 'sha256': 'a' * 64, 'bytes': 1}
            baseline, added = dict(seed), {}
            (baseline if origin == 'existing' else added)['usr/aux/ldconfig'] = file
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                self.module.projected_paths(baseline, added)

    def test_model_projected_escaping_and_cyclic_links_are_refused(self):
        for target in ('../../../outside', '/outside', 'bin'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.module.projected_paths({'usr/bin': {'type': 'symlink', 'target': target}}, {})

    def test_model_relative_internal_payload_link_is_retained(self):
        nodes = {'usr': {'type': 'directory'}, 'usr/share': {'type': 'directory'},
                 'usr/share/data': {'type': 'file', 'sha256': 'a' * 64, 'bytes': 1},
                 'usr/share/link': {'type': 'symlink', 'target': 'data'}}
        self.assertEqual(self.module.projected_paths({}, nodes), nodes)

    def test_model_public_only_keyring_allows_trust_metadata_and_no_secret_directory(self):
        root = self.workspace / 'public-only'; root.mkdir(mode=0o700)
        self.module.public_keyring_only(b'tru::1:1700000000:0:3:1:5:\ngpg: harmless fixture diagnostic\n', root)
        (root / 'private-keys-v1.d').mkdir(mode=0o700)
        self.module.public_keyring_only(b'tru::1:1700000000:0:3:1:5:\n', root)

    def test_model_public_only_keyring_rejects_secret_or_unknown_records(self):
        root = self.workspace / 'public-only'; root.mkdir(mode=0o700)
        for listing in (b'sec::255:22:TEST:\n', b'ssb::255:22:TEST:\n', b'unknown:record\n'):
            with self.subTest(listing=listing), self.assertRaises(ValueError):
                self.module.public_keyring_only(listing, root)

    def test_model_public_only_keyring_rejects_private_material_or_directory_link(self):
        root = self.workspace / 'public-only'; root.mkdir(mode=0o700)
        secret = root / 'private-keys-v1.d'; secret.mkdir(mode=0o700)
        (secret / 'TEST-ONLY.key').write_bytes(b'controlled fake private material\n')
        with self.assertRaises(ValueError): self.module.public_keyring_only(b'tru::1:0:0:\n', root)
        (secret / 'TEST-ONLY.key').unlink(); secret.rmdir()
        empty = self.workspace / 'empty'; empty.mkdir(mode=0o700); secret.symlink_to(empty, target_is_directory=True)
        with self.assertRaises(ValueError): self.module.public_keyring_only(b'tru::1:0:0:\n', root)


class ParentModelTests(Fixtures):
    """Mocked child receipts; no namespace, GPG verifier or C package commit."""
    def model(self, *, expired=False, cancelled=False, corrupt=False, replace_at=None, lose_receipt=False,
              term_promotion=False, capsule_fault=None, via_main=False):
        runtime_bytes = (HERE.parent / 'port/kernel-native-job/runtime.py').read_bytes()
        self.assertEqual(hashlib.sha256(runtime_bytes).hexdigest(), RUNTIME_SHA256)
        self.module.RUNTIME_BYTES = runtime_bytes
        real_runtime = self.module.runtime()
        row, files = self.package(); contract = self.contract([row])
        path = self.workspace / 'contract.json'; path.write_bytes(encoded(contract)); path.chmod(0o600)
        output = self.workspace / 'evidence'
        observed = {'child_completed': False, 'restoration_entered': False, 'final_lock_attempted': False}
        before_capsules = capsule_fds(); before_handlers = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
        before_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        close_fd = os.close
        def faulty_close(fd):
            target = capsule_fds().get(fd, '')
            selected = bool(capsule_fault and target and not observed.get('capsule_fault_fired'))
            if selected:
                observed['capsule_fault_fired'] = True
                if capsule_fault == 'oserror-before': raise OSError('modeled capsule close error before effect')
            close_fd(fd)
            if selected:
                observed['capsule_close_effect'] = True
                if capsule_fault == 'interrupt-after': raise KeyboardInterrupt('modeled interruption after actual capsule close')
                if capsule_fault == 'oserror-after': raise OSError('modeled capsule close error after effect')
                if capsule_fault == 'term-after':
                    handler = signal.getsignal(signal.SIGTERM)
                    observed['capsule_handler_callable'] = callable(handler)
                    self.assertTrue(callable(handler), 'capsule disposal must retain SIGTERM protection')
                    handler(signal.SIGTERM, None)
        original = self.workspace / 'original-evidence'
        def replace():
            output.rename(original); output.mkdir(mode=0o700)
            for name in ('foreign-marker', 'result.json', 'candidate-packages.lock', 'installed-packages.lock'):
                (output / name).write_bytes(('FOREIGN ' + name + '\n').encode())
            observed['foreign_before'] = {p.name: p.read_bytes() for p in output.iterdir()}
        save = self.module.Evidence.save
        write = self.module.Evidence.write
        atomic_replace = os.replace
        def replace_file(*args, **kwargs):
            result = atomic_replace(*args, **kwargs)
            if replace_at == 'atomic' and observed.get('publishing_pass') and Path(args[1]).name == 'result.json':
                replace()
                raise OSError('modeled failure after atomic PASS receipt replacement')
            return result
        def write_evidence(evidence, name, *args, **kwargs):
            if name == 'installed-packages.lock': observed['final_lock_attempted'] = True
            result = write(evidence, name, *args, **kwargs)
            if name == 'installed-packages.lock' and term_promotion:
                handler = signal.getsignal(signal.SIGTERM)
                observed['promotion_handler_callable'] = callable(handler)
                self.assertTrue(callable(handler), 'SIGTERM must be guarded during final lock promotion')
                observed['promotion_term_delivered'] = True
                handler(signal.SIGTERM, None)
            return result
        def publish(evidence, name, value, *args, **kwargs):
            observed['publishing_pass'] = value.get('status') == 'PASS-disposable-payload-transaction'
            try: result = save(evidence, name, value, *args, **kwargs)
            finally: observed['publishing_pass'] = False
            if replace_at == 'published' and value.get('status') == 'PASS-disposable-payload-transaction':
                replace()
                if lose_receipt: os.ftruncate(evidence.nodes['result.json'][0], 0)
                raise OSError('modeled failure after receipt path replacement')
            return result
        def child(*args, **kwargs):
            observed['environment'] = dict(args[2] if len(args) > 2 else kwargs['env'])
            logs = Path(args[3] if len(args) > 3 else kwargs['log_dir']); logs.mkdir(mode=0o700)
            (logs / 'command.log').write_bytes(b'')
            snapshot = output / 'system-snapshot'; snapshot.mkdir(mode=0o700)
            package_db = snapshot / ('var/lib/pacman/local/' + row['name'] + '-' + row['version'])
            package_db.mkdir(parents=True)
            (package_db / 'desc').write_text('%NAME%\n' + row['name'] + '\n\n%VERSION%\n' + row['version'] + '\n')
            (package_db / 'files').write_text('%FILES%\n' + '\n'.join(files) + '\n')
            for relative, data in files.items():
                target = snapshot / relative; target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b'corrupted model export\n' if corrupt else data); target.chmod(0o644)
            (output / 'candidate-packages.lock').write_bytes(
                ''.join(f'{name} {version}\n' for name, version in sorted(contract['after'].items())).encode())
            self.module.OWNED_OUTPUT.overwrite('result.json', encoded(
                             {'status': 'PROVISIONAL-disposable-payload-transaction', 'phase': 'complete',
                              'commit_started': True, 'committed': True, 'installed_payload_verified': True,
                              'before': contract['before'], 'after': contract['after'],
                              'worker_source_sha256': self.module._fixture_source_sha256,
                              'runtime_source_sha256': RUNTIME_SHA256,
                              'evidence_identity': list(self.module.OWNED_OUTPUT.identity)}) + b'\n')
            observed['child_completed'] = True
            if expired: self.module.TASK_DEADLINE = time.monotonic() - 1
            if replace_at == 'child-return': replace()
            return subprocess.CompletedProcess([], 0, b'', b'')
        @contextlib.contextmanager
        def cancellation():
            with real_runtime.cancellation_handlers():
                yield
                observed['restoration_entered'] = True
                observed['restoration_status'] = json.loads(self.module.OWNED_OUTPUT.read('result.json', 1024**2))['status']
                observed['final_lock_at_restoration'] = (output / 'installed-packages.lock').exists()
                if cancelled: raise KeyboardInterrupt('modeled late handler restoration cancellation')
        runtime = types.SimpleNamespace(**vars(real_runtime)); runtime.cancellation_handlers = cancellation
        with patch.object(self.module, 'supervise', side_effect=child), patch.object(self.module, 'runtime', return_value=runtime), \
             patch.object(self.module.Evidence, 'save', new=publish), \
             patch.object(self.module.Evidence, 'write', new=write_evidence), \
             patch.object(self.module.os, 'replace', side_effect=replace_file), \
             patch.object(self.module.os, 'close', side_effect=faulty_close):
            try:
                if via_main:
                    argv = ['local_transaction.py', '--contract', str(path), '--contract-sha256', sha(path),
                            '--output', str(output), '--worker-source-sha256', self.module._fixture_source_sha256,
                            '--allow-disposable-payload-commit']
                    with patch.object(self.module.sys, 'argv', argv), contextlib.redirect_stdout(io.StringIO()):
                        observed['main_return'] = self.module.main()
                    report = json.loads(self.module.OWNED_OUTPUT.read('result.json', 1024**2, checked=False))
                else:
                    report = self.module.execute(path, sha(path), output, allow=True,
                                                 worker_source_sha256=self.module._fixture_source_sha256)
            except BaseException as error:
                if capsule_fault is None: raise
                observed['escaped_exception'] = type(error).__name__
                report = json.loads(self.module.OWNED_OUTPUT.read('result.json', 1024**2, checked=False))
        observed['new_capsule_fds'] = {fd: name for fd, name in capsule_fds().items() if fd not in before_capsules}
        observed['handlers_restored'] = all(signal.getsignal(number) is handler for number, handler in before_handlers.items())
        observed['mask_restored'] = signal.pthread_sigmask(signal.SIG_BLOCK, set()) == before_mask
        if capsule_fault:
            registry = getattr(self.module, 'OWNED_CAPSULES', None)
            observed['capsule_cleanup_report'] = getattr(registry, 'last_report', None)
            observed['retained_capsule_ownership'] = len(getattr(registry, 'owned', {}))
            self.capsule_observations = getattr(self, 'capsule_observations', []) + [{
                'fault': capsule_fault, 'via_main': via_main, 'corrupt_export': corrupt,
                'observed': json.loads(json.dumps(observed)), 'receipt': json.loads(json.dumps(report))}]
            # Baseline red controls record leaked descriptors and stale authority first.
            retained_evidence = self.module.OWNED_OUTPUT
            def cleanup_red_fixture():
                if observed.get('fixture_cleanup_done'): return
                observed['fixture_cleanup_done'] = True
                for fd in observed['new_capsule_fds']:
                    if fd in capsule_fds(): close_fd(fd)
                if report['status'] == 'PASS-disposable-payload-transaction':
                    retained_evidence.revoke({'status': 'FAIL', 'commit_started': True, 'committed': True,
                                             'fixture': 'baseline model cleanup after recorded counterexample'})
            observed['cleanup_fixture'] = cleanup_red_fixture
        self.addCleanup(self.module.OWNED_OUTPUT.close)
        if capsule_fault: self.addCleanup(cleanup_red_fixture)
        if replace_at:
            observed['foreign_after'] = {p.name: p.read_bytes() for p in output.iterdir()}
            output = original
        return report, output, observed

    def assert_no_authority(self, report, output):
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(json.loads((output / 'result.json').read_bytes())['status'], 'FAIL')
        self.assertFalse((output / 'candidate-packages.lock').exists())
        self.assertFalse((output / 'installed-packages.lock').exists())

    def test_model_parent_accepts_valid_export_after_provisional_child(self):
        report, output, observed = self.model()
        self.assertTrue(observed['child_completed']); self.assertTrue(observed['restoration_entered'])
        self.assertEqual(observed['restoration_status'], 'PASS-disposable-payload-transaction')
        self.assertTrue(observed['final_lock_at_restoration'])
        self.assertEqual(report['status'], 'PASS-disposable-payload-transaction')
        self.assertTrue(report['parent_export_verified'])
        self.assertTrue((output / 'installed-packages.lock').is_file())
        self.assertFalse((output / 'candidate-packages.lock').exists())

    def test_model_expired_deadline_revokes_provisional_success_locks(self):
        report, output, observed = self.model(expired=True)
        self.assertTrue(observed['child_completed']); self.assert_no_authority(report, output)
        self.assertIn('deadline', report['parent_error'])

    def test_model_late_restoration_cancel_revokes_pass_and_final_lock(self):
        report, output, observed = self.model(cancelled=True)
        self.assertTrue(observed['child_completed']); self.assertTrue(observed['restoration_entered'])
        self.assertEqual(observed['restoration_status'], 'PASS-disposable-payload-transaction')
        self.assertTrue(observed['final_lock_at_restoration'])
        self.assert_no_authority(report, output)
        self.assertEqual(report['parent_error_type'], 'KeyboardInterrupt')
        self.assertIn('restoration cancellation', report['parent_error'])

    def test_model_parent_export_payload_mismatch_refuses_success(self):
        report, output, observed = self.model(corrupt=True)
        self.assertTrue(observed['child_completed']); self.assert_no_authority(report, output)
        self.assertIn('export payload differs', report['parent_error'])

    def test_model_wrong_or_missing_external_source_pin_refuses_child_launch(self):
        row, _ = self.package(); path = self.workspace / 'contract.json'
        path.write_bytes(encoded(self.contract([row]))); path.chmod(0o600)
        for pin in (None, '0' * 64):
            with self.subTest(pin=pin), patch.object(self.module, 'supervise') as child, self.assertRaises(ValueError):
                self.module.execute(path, sha(path), self.workspace / 'evidence', allow=True,
                                    worker_source_sha256=pin)
            child.assert_not_called()
            self.assertFalse((self.workspace / 'evidence').exists())

    def test_model_published_receipt_replacement_revokes_original_authority(self):
        report, original, observed = self.model(replace_at='published')
        self.assertTrue(observed['child_completed']); self.assert_no_authority(report, original)
        self.assertTrue(observed['final_lock_attempted'])
        self.assertIs(report['commit_started'], True); self.assertIs(report['committed'], True)
        self.assertEqual(observed['foreign_before'], observed['foreign_after'])
        self.assertIn('replacement', report['parent_error'])

    def test_model_unreadable_original_receipt_reports_unknown_without_foreign_fallback(self):
        report, original, observed = self.model(replace_at='published', lose_receipt=True)
        self.assert_no_authority(report, original)
        self.assertEqual(report['commit_started'], 'UNKNOWN'); self.assertEqual(report['committed'], 'UNKNOWN')
        self.assertEqual(observed['foreign_before'], observed['foreign_after'])

    def test_model_atomic_pass_replacement_error_revokes_pending_original_inode(self):
        report, original, observed = self.model(replace_at='atomic')
        self.assertTrue(observed['child_completed']); self.assertTrue(observed['final_lock_attempted'])
        self.assert_no_authority(report, original)
        self.assertEqual(observed['foreign_before'], observed['foreign_after'])
        self.assertIn('atomic PASS', report['parent_error'])

    def test_model_directory_replacement_refuses_promotion(self):
        report, original, observed = self.model(replace_at='child-return')
        self.assert_no_authority(report, original)
        self.assertFalse(observed['final_lock_attempted'])
        self.assertEqual(observed['foreign_before'], observed['foreign_after'])
        self.assertIn('identity', report['parent_error'])

    def test_model_retained_receipt_and_lock_aliases_revoked_without_touching_foreign_names(self):
        output = self.workspace / 'evidence'; output.mkdir(mode=0o700)
        evidence = self.module.Evidence(output); self.addCleanup(evidence.close)
        evidence.save('result.json', {'status': 'PASS-disposable-payload-transaction'})
        evidence.write('installed-packages.lock', b'fixture 1\n', exclusive=True)
        foreign = {}
        for name in ('result.json', 'installed-packages.lock'):
            (output / name).rename(output / ('original-' + name))
            (output / name).write_bytes(('FOREIGN ' + name + '\n').encode())
            foreign[name] = (output / name).read_bytes()
        evidence.revoke({'status': 'FAIL', 'commit_started': 'UNKNOWN', 'committed': 'UNKNOWN'})
        self.assertEqual(json.loads((output / 'original-result.json').read_bytes())['status'], 'FAIL')
        self.assertEqual((output / 'original-installed-packages.lock').read_bytes(), b'REVOKED\n')
        self.assertEqual({name: (output / name).read_bytes() for name in foreign}, foreign)

    def test_model_parent_child_environment_preserves_home(self):
        report, _, observed = self.model()
        self.assertEqual(report['status'], 'PASS-disposable-payload-transaction')
        self.assertEqual(observed['environment'].get('HOME'), os.environ.get('HOME'))
        self.assertEqual('HOME' in observed['environment'], 'HOME' in os.environ)

    def test_model_unreviewed_actual_classes_refuse_before_setup_or_probe(self):
        with patch.dict(globals(), {'REVIEWED_WORKER_SHA256': None}), \
             patch.object(Fixtures, 'setUpClass') as setup, \
             patch.object(subprocess, 'run') as child, patch.object(shutil, 'which') as probe:
            for cls in (ActualTransactionTests, SupervisionTests):
                with self.subTest(cls=cls.__name__), self.assertRaises(unittest.SkipTest): cls.setUpClass()
            case = BarrierTests('test_actual_isolate_keeps_host_readonly_and_only_evidence_persistent')
            with self.assertRaises(unittest.SkipTest):
                case.test_actual_isolate_keeps_host_readonly_and_only_evidence_persistent()
            setup.assert_not_called(); child.assert_not_called(); probe.assert_not_called()

    def test_model_cli_fallback_revokes_original_inodes_without_touching_replacement(self):
        output = self.workspace / 'evidence'; original = self.workspace / 'original-evidence'
        observed = {}
        def failed_execute(*args, **kwargs):
            output.mkdir(mode=0o700); evidence = self.module.Evidence(output)
            self.addCleanup(evidence.close)
            self.module.OWNED_OUTPUT = evidence; self.module.ENGINE_STARTED = True
            evidence.save('result.json', {'status': 'PASS-disposable-payload-transaction',
                                         'commit_started': True, 'committed': True})
            evidence.write('installed-packages.lock', b'fixture 1\n', exclusive=True)
            evidence.write('candidate-packages.lock', b'fixture 1\n', exclusive=True)
            (output / 'installed-packages.lock').rename(output / 'retained-final-lock')
            output.rename(original); output.mkdir(mode=0o700)
            for name in ('result.json', 'installed-packages.lock', 'candidate-packages.lock', 'foreign-marker'):
                (output / name).write_bytes(('FOREIGN ' + name + '\n').encode())
            observed['foreign'] = {p.name: p.read_bytes() for p in output.iterdir()}
            raise OSError('modeled CLI fallback after receipt replacement')
        argv = ['local_transaction.py', '--contract', str(self.workspace / 'contract.json'),
                '--contract-sha256', '0' * 64, '--output', str(output),
                '--worker-source-sha256', self.module._fixture_source_sha256,
                '--allow-disposable-payload-commit']
        printed = io.StringIO()
        with patch.object(self.module, 'execute', side_effect=failed_execute), \
             patch.object(self.module.sys, 'argv', argv), contextlib.redirect_stdout(printed):
            code = self.module.main()
        self.addCleanup(self.module.OWNED_OUTPUT.close)
        self.assertEqual(code, 2)
        record = json.loads(printed.getvalue()); self.assertEqual(record['status'], 'FAIL')
        self.assertIs(record['commit_started'], True); self.assertIs(record['committed'], True)
        self.assertEqual(json.loads((original / 'result.json').read_bytes())['status'], 'FAIL')
        self.assertFalse((original / 'installed-packages.lock').exists())
        self.assertFalse((original / 'candidate-packages.lock').exists())
        self.assertEqual((original / 'retained-final-lock').read_bytes(), b'REVOKED\n')
        self.assertEqual({p.name: p.read_bytes() for p in output.iterdir()}, observed['foreign'])

    def cli_interruption(self, stage):
        output = self.workspace / 'evidence'; observed = {'interrupted': False, 'closed_after_revoke': False}
        close = self.module.Evidence.close; terminal_print = print
        def promoted(*args, **kwargs):
            output.mkdir(mode=0o700); evidence = self.module.Evidence(output)
            self.module.OWNED_OUTPUT = evidence; self.module.ENGINE_STARTED = False
            self.addCleanup(evidence.close)
            record = {'status': 'PASS-disposable-payload-transaction', 'commit_started': False,
                      'committed': False, 'fixture': 'model only; no package operation'}
            evidence.save('result.json', record)
            for name in ('installed-packages.lock', 'candidate-packages.lock'):
                evidence.write(name, b'fixture 1\n', exclusive=True)
            return record
        def interrupted_print(*args, **kwargs):
            if stage == 'print' and not observed['interrupted']:
                observed['interrupted'] = True
                raise KeyboardInterrupt('modeled terminal print interruption')
            return terminal_print(*args, **kwargs)
        def interrupted_close(evidence, *args, **kwargs):
            selected = evidence.path == output
            if selected and stage == 'close' and not observed['interrupted']:
                observed['interrupted'] = True
                raise KeyboardInterrupt('modeled final custody disposal interruption')
            if selected and observed['interrupted'] and evidence.fd is not None:
                self.assertEqual(json.loads((output / 'result.json').read_bytes())['status'], 'FAIL')
                for name in ('installed-packages.lock', 'candidate-packages.lock'):
                    self.assertFalse((output / name).exists())
                observed['closed_after_revoke'] = True
            return close(evidence, *args, **kwargs)
        argv = ['local_transaction.py', '--contract', str(self.workspace / 'contract.json'),
                '--contract-sha256', '0' * 64, '--output', str(output),
                '--worker-source-sha256', self.module._fixture_source_sha256,
                '--allow-disposable-payload-commit']
        printed = io.StringIO(); code = None
        with patch.object(self.module, 'execute', side_effect=promoted), patch.object(self.module.sys, 'argv', argv), \
             patch.object(self.module.Evidence, 'close', new=interrupted_close), \
             patch('builtins.print', side_effect=interrupted_print), contextlib.redirect_stdout(printed):
            try: code = self.module.main()
            except KeyboardInterrupt: pass
        self.addCleanup(self.module.OWNED_OUTPUT.close)
        self.assertNotEqual(code, 0); self.assertTrue(observed['interrupted'])
        self.assertEqual(json.loads((output / 'result.json').read_bytes())['status'], 'FAIL')
        for name in ('installed-packages.lock', 'candidate-packages.lock'):
            self.assertFalse((output / name).exists())
        self.assertTrue(observed['closed_after_revoke'])
        return observed

    def test_model_cli_print_keyboard_interrupt_revokes_before_fd_close(self):
        self.cli_interruption('print')

    def test_model_final_custody_disposal_interrupt_revokes_before_fd_close(self):
        self.cli_interruption('close')

    def test_model_sigterm_handler_covers_direct_final_promotion(self):
        before = signal.getsignal(signal.SIGTERM)
        report, output, observed = self.model(term_promotion=True)
        self.assertTrue(observed['promotion_handler_callable']); self.assertTrue(observed['promotion_term_delivered'])
        self.assert_no_authority(report, output)
        self.assertEqual(report['parent_error_type'], 'Cancelled')
        self.assertIs(signal.getsignal(signal.SIGTERM), before)

    def terminal_model(self, stage):
        output = self.workspace / 'evidence'; observed = {'delivered': False, 'original_closed': False}
        original_handler = signal.getsignal(signal.SIGTERM); close = self.module.Evidence.close
        def deliver():
            handler = signal.getsignal(signal.SIGTERM)
            self.assertTrue(callable(handler), 'SIGTERM must remain guarded at terminal boundary')
            self.assertIsNotNone(self.module.OWNED_OUTPUT.fd, 'revocable custody must remain open')
            observed['delivered'] = True
            handler(signal.SIGTERM, None)
        def promoted(*args, **kwargs):
            self.assertTrue(callable(signal.getsignal(signal.SIGTERM)), 'CLI execution must install SIGTERM handler')
            output.mkdir(mode=0o700); evidence = self.module.Evidence(output)
            self.module.OWNED_OUTPUT = evidence; self.module.ENGINE_STARTED = False
            self.addCleanup(evidence.close)
            record = {'status': 'PASS-disposable-payload-transaction', 'commit_started': False,
                      'committed': False, 'fixture': 'inert terminal model; no package operation'}
            evidence.save('result.json', record)
            evidence.write('installed-packages.lock', b'fixture 1\n', exclusive=True)
            return record
        terminal_print = print
        def publication(*args, **kwargs):
            if stage == 'publication' and not observed['delivered']: deliver()
            return terminal_print(*args, **kwargs)
        def disposal(evidence, *args, **kwargs):
            selected = evidence.path == output and evidence.fd is not None
            if selected and stage == 'disposal' and not observed['delivered']: deliver()
            result = close(evidence, *args, **kwargs)
            if selected: observed['original_closed'] = True
            return result
        def pending():
            handler = signal.getsignal(signal.SIGTERM)
            selected = (stage == 'inner-restoration' and callable(handler) and handler.__name__ == '<lambda>') or \
                       (stage == 'outer-restoration' and handler is original_handler)
            if selected and observed['original_closed'] and not observed.get('consumed'):
                self.assertIsNotNone(self.module.OWNED_OUTPUT.fd, 'loan must survive guard restoration')
                observed['pending_at_restoration'] = True
                return {signal.SIGTERM}
            return set()
        def consume(numbers):
            self.assertEqual(numbers, {signal.SIGTERM})
            observed['consumed'] = True; observed['delivered'] = True
            return signal.SIGTERM
        observed['flush_calls'] = 0
        class Terminal(io.StringIO):
            def flush(stream):
                observed['flush_calls'] += 1
                if stage == 'flush' and observed['flush_calls'] == 1:
                    observed['flush_failure'] = True
                    raise BrokenPipeError('modeled explicit stdout flush failure')
                return super().flush()
        argv = ['local_transaction.py', '--contract', str(self.workspace / 'contract.json'),
                '--contract-sha256', '0' * 64, '--output', str(output),
                '--worker-source-sha256', self.module._fixture_source_sha256,
                '--allow-disposable-payload-commit']
        stream = Terminal(); code = None; observed['exception'] = None
        with patch.object(self.module, 'execute', side_effect=promoted), patch.object(self.module.sys, 'argv', argv), \
             patch.object(self.module.Evidence, 'close', new=disposal), patch('builtins.print', side_effect=publication), \
             patch.object(signal, 'sigpending', side_effect=pending), patch.object(signal, 'sigwait', side_effect=consume), \
             contextlib.redirect_stdout(stream):
            try: code = self.module.main()
            except BaseException as error: observed['exception'] = type(error).__name__
        self.addCleanup(self.module.OWNED_OUTPUT.close)
        self.assertNotEqual(code, 0)
        receipt = json.loads((output / 'result.json').read_bytes())
        self.assertEqual(receipt['status'], 'FAIL'); self.assertIs(receipt['committed'], False)
        self.assertFalse((output / 'installed-packages.lock').exists())
        self.assertIs(signal.getsignal(signal.SIGTERM), original_handler)
        if stage == 'flush':
            self.assertTrue(observed.get('flush_failure')); self.assertGreater(observed['flush_calls'], 0)
            self.assertIn('stdout flush failure', receipt['parent_error'])
        else:
            self.assertTrue(observed['delivered'])
            self.assertTrue(observed['exception'] == 'Cancelled' or receipt.get('parent_error') == 'cancelled',
                            'delivered soft termination must cause the failed receipt')
        return observed

    def test_model_sigterm_handler_covers_terminal_publication(self):
        self.terminal_model('publication')

    def test_model_explicit_stdout_flush_failure_revokes_promoted_authority(self):
        self.terminal_model('flush')

    def test_model_pending_disposal_sigterm_revokes_retained_custody(self):
        self.terminal_model('disposal')

    def test_model_pending_inner_guard_restoration_sigterm_revokes_retained_loan(self):
        observed = self.terminal_model('inner-restoration')
        self.assertTrue(observed['pending_at_restoration']); self.assertTrue(observed['consumed'])

    def test_model_pending_final_deferral_restoration_sigterm_revokes_retained_loan(self):
        observed = self.terminal_model('outer-restoration')
        self.assertTrue(observed['pending_at_restoration']); self.assertTrue(observed['consumed'])

    def capsule_case(self, fault, *, via_main=False, corrupt=False):
        self.setUp()  # Each causal case owns a fresh workspace and absent output.
        report, output, observed = self.model(capsule_fault=fault, via_main=via_main, corrupt=corrupt)
        try:
            self.assertTrue(observed['capsule_fault_fired'])
            if fault != 'oserror-before': self.assertTrue(observed['capsule_close_effect'])
            if fault == 'term-after': self.assertTrue(observed['capsule_handler_callable'])
            self.assertEqual(observed['new_capsule_fds'], {}, 'capsule cleanup must not abandon any sealed source FD')
            self.assertEqual(observed['retained_capsule_ownership'], 0)
            self.assertTrue(observed['handlers_restored']); self.assertTrue(observed['mask_restored'])
            self.assert_no_authority(report, output)
            if via_main: self.assertNotEqual(observed.get('main_return'), 0)
            if corrupt:
                self.assertIn('export payload differs', report.get('parent_error', '') + report.get('error', ''))
            self.assertEqual(observed['capsule_cleanup_report']['status'], 'FAIL')
        finally:
            # Observations and assertions precede fixture cleanup; baseline leaks remain recorded.
            observed['cleanup_fixture']()

    def test_model_direct_capsule_disposal_faults_revoke_and_close_all_owned_fds(self):
        for fault in ('interrupt-after', 'term-after', 'oserror-before', 'oserror-after'):
            with self.subTest(fault=fault): self.capsule_case(fault)

    def test_model_callable_main_capsule_disposal_faults_revoke_and_close_all_owned_fds(self):
        for fault in ('interrupt-after', 'term-after', 'oserror-before', 'oserror-after'):
            with self.subTest(fault=fault): self.capsule_case(fault, via_main=True)

    def test_model_capsule_cleanup_fault_preserves_existing_export_failure(self):
        for via_main in (False, True):
            with self.subTest(via_main=via_main):
                self.capsule_case('oserror-after', via_main=via_main, corrupt=True)

    def test_model_foreign_result_inserted_at_staged_fsync_is_preserved(self):
        output = self.workspace / 'evidence'; output.mkdir(mode=0o700)
        evidence = self.module.Evidence(output); self.addCleanup(evidence.close)
        evidence.save('result.json', {'status': 'PASS-disposable-payload-transaction'})
        foreign = b'FOREIGN RESULT INSERTED AT STAGED FSYNC\n'; observed = {'injected': False}
        fsync = os.fsync; replace = os.replace
        def insert(fd):
            if not observed['injected'] and stat.S_ISREG(os.fstat(fd).st_mode):
                observed['injected'] = True
                (output / 'result.json').rename(output / 'retained-original-result.json')
                (output / 'result.json').write_bytes(foreign); (output / 'result.json').chmod(0o600)
            return fsync(fd)
        with patch.object(self.module.os, 'fsync', side_effect=insert), \
             patch.object(self.module.os, 'replace', wraps=replace) as rename, self.assertRaises((OSError, ValueError)):
            evidence.save('result.json', {'status': 'PASS-disposable-payload-transaction', 'later': True})
        self.assertTrue(observed['injected']); rename.assert_not_called()
        self.assertEqual((output / 'result.json').read_bytes(), foreign)
        evidence.revoke({'status': 'FAIL', 'commit_started': False, 'committed': False})
        self.assertEqual((output / 'result.json').read_bytes(), foreign)
        self.assertEqual(json.loads((output / 'retained-original-result.json').read_bytes())['status'], 'FAIL')

    def test_model_absent_result_creation_is_exclusive_and_preserves_inserted_foreign_node(self):
        output = self.workspace / 'evidence'; output.mkdir(mode=0o700)
        evidence = self.module.Evidence(output); self.addCleanup(evidence.close)
        evidence.save('result.json', {'status': 'PASS-disposable-payload-transaction'})
        (output / 'result.json').rename(output / 'retained-original-result.json')
        foreign = b'FOREIGN RESULT INSERTED BEFORE ABSENT-NAME CREATE\n'; observed = {}
        write = evidence.write
        def insert(name, *args, **kwargs):
            observed['exclusive'] = kwargs.get('exclusive', False)
            (output / name).write_bytes(foreign); (output / name).chmod(0o600)
            return write(name, *args, **kwargs)
        with patch.object(evidence, 'write', side_effect=insert):
            try: evidence.revoke({'status': 'FAIL', 'commit_started': False, 'committed': False})
            except FileExistsError: pass
        self.assertIs(observed.get('exclusive'), True)
        self.assertEqual((output / 'result.json').read_bytes(), foreign)
        self.assertEqual(json.loads((output / 'retained-original-result.json').read_bytes())['status'], 'FAIL')


class NamespaceEvidenceViewTests(unittest.TestCase):
    """Harmless directory/FD models only; never enter a namespace or bind a mount."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='caa-evidence-view-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.path=self.root/'evidence';self.path.mkdir(mode=0o700)
        self.module=load_worker();self.entered=self.module.namespaces();self.opened=[]
        self.original=self.module.Evidence(self.path);self.oldfd=self.original.fd
        self.addCleanup(self.original.close)
        opening=self.module.os.open
        def tracked(path,*args,**kwargs):
            fd=opening(path,*args,**kwargs)
            if Path(path)==self.path:self.opened.append(fd)
            return fd
        patcher=patch.object(self.module.os,'open',side_effect=tracked);patcher.start();self.addCleanup(patcher.stop)
    def closed(self,fd):
        with self.assertRaises(OSError) as error:os.fstat(fd)
        self.assertEqual(error.exception.errno,errno.EBADF)
    def proc_model(self,fdinfo=None,mountinfo=None):
        opening=Path.open
        def controlled(path,*args,**kwargs):
            name=str(path)
            if name.startswith('/proc/self/fdinfo/'):
                fd=int(name.rsplit('/',1)[1])
                data=(b'mnt_id:\t10\n' if fd==self.oldfd else b'mnt_id:\t20\n') if fdinfo is None else fdinfo
                return io.BytesIO(data)
            if name=='/proc/self/mountinfo':
                return io.BytesIO(b'20 1 0:1 / / rw - fixture fixture rw\n' if mountinfo is None else mountinfo)
            return opening(path,*args,**kwargs)
        return patch.object(Path,'open',controlled)
    def test_current_named_open_preserves_bytes_and_closes_both_views(self):
        payload=b'unchanged precreated evidence';(self.path/'result.json').write_bytes(payload)
        with self.proc_model(),self.module.namespace_evidence_view(self.original,self.entered) as current:
            self.assertNotEqual(current,self.oldfd)
            self.assertEqual(os.fstat(current).st_ino,os.fstat(self.oldfd).st_ino)
            self.assertEqual(self.opened,[current])
        self.closed(current);self.closed(self.oldfd);self.assertIsNone(self.original.fd)
        self.assertEqual((self.path/'result.json').read_bytes(),payload)
    def test_real_own_proc_mount_metadata_is_bounded_and_matches(self):
        before=self.module.namespaces()
        with self.module.namespace_evidence_view(self.original,self.entered) as current:
            self.assertTrue(current in self.opened)
        self.closed(current);self.closed(self.oldfd);self.assertEqual(self.module.namespaces(),before)
    def test_namespace_fields_and_current_identity_refuse_before_open(self):
        for changed in ({},dict(self.entered,extra='mnt:[1]'),dict(self.entered,mnt=True),dict(self.entered,mnt='user:[1]'),dict(self.entered,mnt='mnt:[0]')):
            # A new retained lease per refusal; no allocation or actor is admitted.
            if self.original.fd is None:self.original=self.module.Evidence(self.path);self.oldfd=self.original.fd
            count=len(self.opened)
            with self.assertRaises(ValueError):
                with self.module.namespace_evidence_view(self.original,changed):self.fail('invalid namespace admitted')
            self.assertEqual(len(self.opened),count);self.closed(self.oldfd)
    def test_mount_field_missing_duplicate_foreign_and_bounded_text_refuse(self):
        for fdinfo,mountinfo in ((b'pos:0\n',None),(b'mnt_id:20\nmnt_id:20\n',None),(b'mnt_id:10\n',None),
                                 (b'x'*4097,None),(b'mnt_id:20\n',b'bad mount row\n'),
                                 (b'mnt_id:20\n',b'x'*(4*1024**2+1))):
            if self.original.fd is None:self.original=self.module.Evidence(self.path);self.oldfd=self.original.fd
            with self.proc_model(fdinfo,mountinfo),self.assertRaises(ValueError):
                with self.module.namespace_evidence_view(self.original,self.entered):self.fail('bad mount view admitted')
            self.closed(self.oldfd);self.closed(self.opened[-1])
        self.original=self.module.Evidence(self.path);self.oldfd=self.original.fd
        opening=Path.open;calls=[]
        def changed_mount(path,*args,**kwargs):
            if str(path).startswith('/proc/self/fdinfo/'):
                calls.append(True);return io.BytesIO(b'mnt_id:20\n' if len(calls)==1 else b'mnt_id:21\n')
            if str(path)=='/proc/self/mountinfo':return io.BytesIO(b'20 1 0:1 / / rw\n21 1 0:1 / / rw\n')
            return opening(path,*args,**kwargs)
        with patch.object(Path,'open',changed_mount),self.assertRaisesRegex(ValueError,'mount identity changed'):
            with self.module.namespace_evidence_view(self.original,self.entered):self.fail('changed descriptor mount admitted')
        self.closed(self.oldfd);self.closed(self.opened[-1])
    def test_named_replacement_mode_and_ancestor_alias_are_refused_and_owned_fds_closed(self):
        opening=self.module.os.open
        def replaced(path,*args,**kwargs):
            if Path(path)==self.path:
                self.path.rename(self.root/'original');self.path.mkdir(mode=0o700)
            return opening(path,*args,**kwargs)
        with patch.object(self.module.os,'open',side_effect=replaced),self.assertRaises(ValueError):
            with self.module.namespace_evidence_view(self.original,self.entered):self.fail('replacement admitted')
        self.closed(self.oldfd);self.closed(self.opened[-1])
        self.path.rmdir();(self.root/'original').rename(self.path)
        for change in ('mode','symlink'):
            self.original=self.module.Evidence(self.path);self.oldfd=self.original.fd
            if change=='mode':self.path.chmod(0o755)
            else:self.path.rename(self.root/'original');self.path.symlink_to(self.root/'original',target_is_directory=True)
            with self.assertRaises(ValueError):
                with self.module.namespace_evidence_view(self.original,self.entered):self.fail('unsafe name admitted')
            self.closed(self.oldfd)
            if change=='mode':self.path.chmod(0o700)
            else:self.path.unlink();(self.root/'original').rename(self.path)
    def test_metadata_and_namespace_changes_during_validation_never_yield(self):
        fstat=self.module.os.fstat;changed=[]
        def mode(fd):
            info=fstat(fd)
            if self.opened and fd==self.opened[-1] and not changed:
                self.path.chmod(0o755);changed.append(True)
            return info
        with self.proc_model(),patch.object(self.module.os,'fstat',side_effect=mode),self.assertRaises(ValueError):
            with self.module.namespace_evidence_view(self.original,self.entered):self.fail('changed metadata admitted')
        self.closed(self.oldfd);self.closed(self.opened[-1]);self.path.chmod(0o700)
        self.original=self.module.Evidence(self.path);self.oldfd=self.original.fd
        calls=[]
        def drift():
            calls.append(True);return self.entered if len(calls)==1 else dict(self.entered,mnt='mnt:[0]')
        with patch.object(self.module,'namespaces',side_effect=drift),self.assertRaises(ValueError):
            with self.module.namespace_evidence_view(self.original,self.entered):self.fail('namespace drift admitted')
        self.closed(self.oldfd);self.closed(self.opened[-1])
        self.original=self.module.Evidence(self.path);self.oldfd=self.original.fd;calls.clear()
        original=dict(self.entered)
        def mutable_drift():
            calls.append(True)
            if len(calls)>1:self.entered['mnt']='mnt:[0]'
            return dict(self.entered)
        with patch.object(self.module,'namespaces',side_effect=mutable_drift),self.assertRaises(ValueError):
            with self.module.namespace_evidence_view(self.original,self.entered):self.fail('mutable expected namespace promoted drift')
        self.entered=original;self.closed(self.oldfd);self.closed(self.opened[-1])
    def test_fd_metadata_capture_control_recovers_lease_then_closes_and_preserves_control(self):
        fstat=self.module.os.fstat;control=KeyboardInterrupt('owned capture control');sent=[]
        def interrupted(fd):
            if self.opened and fd==self.opened[-1] and not sent:sent.append(True);raise control
            return fstat(fd)
        with patch.object(self.module.os,'fstat',side_effect=interrupted),self.assertRaises(KeyboardInterrupt) as caught:
            with self.module.namespace_evidence_view(self.original,self.entered):self.fail('capture control admitted')
        self.assertIs(caught.exception,control);self.closed(self.oldfd);self.closed(self.opened[-1])
    def test_close_control_before_after_effect_and_primary_exception_stays_first(self):
        closing=self.module.os.close
        for effect,body in ((False,False),(True,False),(False,True)):
            if self.original.fd is None:self.original=self.module.Evidence(self.path);self.oldfd=self.original.fd
            control=KeyboardInterrupt('private close control');primary=ValueError('private bind refused');sent=[]
            def interrupted(fd):
                if self.opened and fd==self.opened[-1] and not sent:
                    sent.append(True)
                    if effect:closing(fd)
                    raise control
                return closing(fd)
            expected=ValueError if body else KeyboardInterrupt
            with self.proc_model(),patch.object(self.module.os,'close',side_effect=interrupted),self.assertRaises(expected) as caught:
                with self.module.namespace_evidence_view(self.original,self.entered):
                    if body:raise primary
            self.assertIs(caught.exception,primary if body else control)
            self.closed(self.oldfd);self.closed(self.opened[-1])
    def test_persistent_close_refusal_cannot_succeed_and_retained_view_still_closed(self):
        closing=self.module.os.close;calls=[]
        def refused(fd):
            if self.opened and fd==self.opened[-1]:calls.append(fd);raise OSError(errno.EIO,'private close refused')
            return closing(fd)
        with self.proc_model(),patch.object(self.module.os,'close',side_effect=refused),self.assertRaises(OSError):
            with self.module.namespace_evidence_view(self.original,self.entered):pass
        self.assertEqual(len(calls),3);self.closed(self.oldfd)
        # Persistent kernel/API refusal is unavailable cleanup, never a PASS.
        closing(self.opened[-1])


    def test_wrong_current_inode_owner_group_or_mode_refuses_without_leaking_view(self):
        fstat=self.module.os.fstat
        for index in (0,1,2,4,5):
            if self.original.fd is None:self.original=self.module.Evidence(self.path);self.oldfd=self.original.fd
            def poison(fd):
                info=fstat(fd)
                if self.opened and fd==self.opened[-1] and fd!=self.oldfd:
                    row=list(info);row[index]=row[index]+1
                    return os.stat_result(row)
                return info
            with self.proc_model(),patch.object(self.module.os,'fstat',side_effect=poison),self.assertRaises(ValueError):
                with self.module.namespace_evidence_view(self.original,self.entered):self.fail('wrong directory metadata admitted')
            self.closed(self.oldfd);self.closed(self.opened[-1])

    def test_reused_current_fd_is_not_closed_as_if_it_were_the_original_lease(self):
        foreign=self.root/'foreign';foreign.mkdir(mode=0o700)
        descriptor=None
        try:
            with self.proc_model(),self.assertRaisesRegex(ValueError,'lease replaced'):
                with self.module.namespace_evidence_view(self.original,self.entered) as current:
                    os.close(current);descriptor=os.open(foreign,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                    self.assertEqual(descriptor,current)
            self.closed(self.oldfd)
            self.assertEqual(os.fstat(descriptor).st_ino,foreign.stat().st_ino)
        finally:
            if descriptor is not None:os.close(descriptor)

    def test_guard_setup_control_does_not_skip_final_owned_descriptor_cleanup(self):
        actual=self.module.runtime();calls=[];control=KeyboardInterrupt('private signal guard setup')
        @contextlib.contextmanager
        def deferred():
            calls.append(True)
            if len(calls)==2:raise control
            yield []
        fake=types.SimpleNamespace(defer_signals=deferred,Cancelled=actual.Cancelled)
        with self.proc_model(),patch.object(self.module,'runtime',return_value=fake),self.assertRaises(KeyboardInterrupt) as caught:
            with self.module.namespace_evidence_view(self.original,self.entered):pass
        self.assertIs(caught.exception,control);self.closed(self.oldfd);self.closed(self.opened[-1])

    def test_actual_owned_sigterm_during_close_is_latched_after_both_views_close(self):
        closing=self.module.os.close;sent=[];prior=signal.getsignal(signal.SIGTERM)
        def interrupted(fd):
            if self.opened and fd==self.opened[-1] and not sent:
                sent.append(True);os.kill(os.getpid(),signal.SIGTERM)
            return closing(fd)
        with self.proc_model(),patch.object(self.module.os,'close',side_effect=interrupted),self.assertRaises(BaseException) as caught:
            with self.module.namespace_evidence_view(self.original,self.entered):pass
        self.assertEqual(type(caught.exception).__name__,'Cancelled');self.assertEqual(caught.exception.signum,signal.SIGTERM)
        self.assertEqual(signal.getsignal(signal.SIGTERM),prior);self.closed(self.oldfd);self.closed(self.opened[-1])


class SourceLoaderTests(unittest.TestCase):
    """Executable source fixtures only: harmless marker code, no worker engine."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='caa-install-source-fixture-')
        self.addCleanup(self.temp.cleanup); self.workspace = Path(self.temp.name)
        self.module = load_worker()
        self.evidence = self.workspace / 'evidence'; self.evidence.mkdir(mode=0o700)
        self.evidence_fd = os.open(self.evidence, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, self.evidence_fd)
        self.marker = self.evidence / 'source-marker.json'
        self.code = b'''import hashlib,json,os
from pathlib import Path
spec=json.loads(ENGINE_SPEC_BYTES)
assert hashlib.sha256(RUNTIME_BYTES).hexdigest()==spec['runtime_source_sha256']
assert EXECUTED_WORKER_SHA==spec['worker_source_sha256']
Path(spec['fixture_marker']).write_text(json.dumps({'status':'PINNED-MARKER',
 'worker_sha256':EXECUTED_WORKER_SHA,'home':os.environ.get('HOME'),'has_home':'HOME' in os.environ}))
'''
        self.pin = hashlib.sha256(self.code).hexdigest()
        self.worker_fd = self.module.sealed_source(self.code, 'test-only-worker')
        self.runtime_bytes = (HERE.parent / 'port/kernel-native-job/runtime.py').read_bytes()
        self.assertEqual(hashlib.sha256(self.runtime_bytes).hexdigest(), RUNTIME_SHA256)
        self.runtime_fd = self.module.sealed_source(self.runtime_bytes, 'test-only-runtime')
        for fd in (self.worker_fd, self.runtime_fd): self.addCleanup(os.close, fd)
        def reference(fd, data, pin):
            info = os.fstat(fd)
            return {'device': info.st_dev, 'inode': info.st_ino, 'size': len(data), 'sha256': pin}
        info = os.fstat(self.evidence_fd)
        nodes = {}
        for name in ('result.json', 'candidate-packages.lock'):
            path = self.evidence / name; path.write_bytes(b''); path.chmod(0o600)
            node = path.stat(); nodes[name] = [node.st_dev, node.st_ino]
        self.spec = {'worker_source_sha256': self.pin, 'runtime_source_sha256': RUNTIME_SHA256,
                     'worker_reference': reference(self.worker_fd, self.code, self.pin),
                     'runtime_reference': reference(self.runtime_fd, self.runtime_bytes, RUNTIME_SHA256),
                     'evidence_identity': [info.st_dev, info.st_ino], 'evidence_nodes': nodes,
                     'fixture_marker': str(self.marker)}

    def launch(self, *, pin=None, spec=None, spec_pin=None, worker_fd=None, runtime_fd=None, env=None):
        path = self.workspace / 'engine.json'
        if path.exists(): path.chmod(0o600)
        path.write_bytes(encoded(self.spec if spec is None else spec)); path.chmod(0o400)
        command = ['/usr/bin/python3', '-I', '-B', '-c', self.module.CHILD_LOADER,
                   str(self.worker_fd if worker_fd is None else worker_fd), self.pin if pin is None else pin,
                   str(path), sha(path) if spec_pin is None else spec_pin, str(self.evidence_fd),
                   str(self.runtime_fd if runtime_fd is None else runtime_fd), RUNTIME_SHA256]
        return subprocess.run(command, capture_output=True, timeout=10, cwd=self.workspace,
                              env=environment() if env is None else env,
                              pass_fds=(self.worker_fd if worker_fd is None else worker_fd,
                                        self.runtime_fd if runtime_fd is None else runtime_fd, self.evidence_fd))

    def assert_refused(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists(), 'poisoned source must be refused before marker execution')

    def test_source_fixture_pinned_marker_runs_and_inherits_home(self):
        result = self.launch(); self.assertEqual(result.returncode, 0, result.stderr.decode())
        marker = json.loads(self.marker.read_bytes())
        self.assertEqual(marker, {'status': 'PINNED-MARKER', 'worker_sha256': self.pin,
                                 'home': os.environ.get('HOME'), 'has_home': 'HOME' in os.environ})

    def test_source_fixture_absent_home_stays_absent(self):
        result = self.launch(env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'})
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        marker = json.loads(self.marker.read_bytes())
        self.assertIsNone(marker['home']); self.assertFalse(marker['has_home'])

    def test_source_fixture_sealed_buffers_refuse_write_append_and_resize(self):
        seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
        for fd in (self.worker_fd, self.runtime_fd):
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GET_SEALS) & seals, seals)
            before = os.pread(fd, os.fstat(fd).st_size, 0)
            for operation in (lambda: os.pwrite(fd, b'POISON', 0),
                              lambda: os.pwrite(fd, b'POISON', len(before)),
                              lambda: os.ftruncate(fd, 0), lambda: os.ftruncate(fd, len(before) + 1)):
                with self.subTest(fd=fd, operation=operation), self.assertRaises(OSError) as caught: operation()
                self.assertEqual(caught.exception.errno, errno.EPERM)
            self.assertEqual(os.pread(fd, len(before), 0), before)

    def test_source_fixture_changed_capture_rejected_before_execution(self):
        changed = self.module.sealed_source(self.code + b'\n# changed after selection\n', 'test-only-changed')
        self.addCleanup(os.close, changed)
        self.assert_refused(self.launch(worker_fd=changed))
        unsealed = os.memfd_create('test-only-unsealed', os.MFD_ALLOW_SEALING)
        self.addCleanup(os.close, unsealed); os.write(unsealed, self.code); os.fchmod(unsealed, 0o400)
        poisoned = dict(self.spec, worker_reference=self.module.source_reference(unsealed, self.pin))
        self.assert_refused(self.launch(worker_fd=unsealed, spec=poisoned))

    def test_source_fixture_worker_runtime_and_engine_pins_are_bound(self):
        for field in ('worker_source_sha256', 'runtime_source_sha256'):
            poisoned = dict(self.spec, **{field: '0' * 64})
            with self.subTest(field=field): self.assert_refused(self.launch(spec=poisoned))
        self.assert_refused(self.launch(pin='0' * 64))
        self.assert_refused(self.launch(spec_pin='0' * 64))

    def test_source_fixture_code_references_and_runtime_bytes_poison_refused(self):
        for reference in ('worker_reference', 'runtime_reference'):
            for field, value in (('inode', self.spec[reference]['inode'] + 1), ('size', 1), ('sha256', '0' * 64)):
                poisoned = json.loads(json.dumps(self.spec)); poisoned[reference][field] = value
                with self.subTest(reference=reference, field=field): self.assert_refused(self.launch(spec=poisoned))
        changed = self.module.sealed_source(self.runtime_bytes + b'\n# changed\n', 'test-only-runtime-changed')
        self.addCleanup(os.close, changed)
        self.assert_refused(self.launch(runtime_fd=changed))

    def test_source_fixture_adjacent_source_and_bytecode_cache_are_ignored(self):
        foreign = self.workspace / 'sealed-worker.py'
        foreign.write_text("raise RuntimeError('POISONED SOURCE OR BYTECODE EXECUTED')\n")
        cached = Path(py_compile.compile(str(foreign), doraise=True))
        before = {str(path): path.read_bytes() for path in (foreign, cached)}
        result = self.launch(); self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(self.marker.read_bytes())['worker_sha256'], self.pin)
        self.assertEqual({str(path): path.read_bytes() for path in (foreign, cached)}, before)


class ActualTransactionTests(Fixtures):
    """Real GPG/libalpm fixtures, only in owned user/mount/network namespaces."""
    @classmethod
    def setUpClass(cls):
        if REVIEWED_WORKER_SHA256 is None:
            raise unittest.SkipTest('actual transactions held: independently reviewed worker pin not supplied')
        if sha(WORKER) != REVIEWED_WORKER_SHA256: raise AssertionError('reviewed worker source changed')
        super().setUpClass()
        if not shutil.which('unshare') or not Path('/usr/lib/libalpm.so.16.0.1').is_file():
            raise unittest.SkipTest('actual private namespace/libalpm prerequisites unavailable')
        if sha('/usr/lib/libalpm.so.16.0.1') != LIBALPM_SHA256:
            raise unittest.SkipTest('observed fixture libalpm pin changed')
        probe = subprocess.run(['/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--pid', '--mount-proc', '--net',
                                '--fork', '--', '/usr/bin/true'], capture_output=True, timeout=10)
        if probe.returncode:
            raise unittest.SkipTest('user/mount/network namespace unavailable: ' + probe.stderr.decode(errors='replace'))

    def execute(self, contract):
        self.assertIsNotNone(REVIEWED_WORKER_SHA256, 'coordinator-reviewed source pin required for actual trials')
        captured_source = sha(WORKER)
        self.assertEqual(captured_source, REVIEWED_WORKER_SHA256)
        path = self.workspace / 'contract.json'; path.write_bytes(encoded(contract)); path.chmod(0o600)
        command = ['/usr/bin/python3', '-I', '-B', str(WORKER), '--contract', str(path),
                   '--contract-sha256', sha(path), '--output', str(self.workspace / 'evidence'),
                   '--worker-source-sha256', REVIEWED_WORKER_SHA256,
                   '--allow-disposable-payload-commit']
        if FIXTURE_SELECTION_SHA256 is not None: command += ['--selection-sha256', FIXTURE_SELECTION_SHA256]
        result = subprocess.run(command, capture_output=True, timeout=contract['timeout_seconds'] + 30,
                                env=environment())
        try:
            summary = json.loads(result.stdout)
            report_path = self.workspace / 'evidence/result.json'
            report = json.loads(report_path.read_bytes()) if report_path.is_file() else summary
        except (ValueError, UnicodeError):
            self.fail('worker emitted no bounded JSON report: ' + result.stderr.decode(errors='replace')[-4000:])
        type(self).last_execution = {'worker_sha256': captured_source, 'worker_after_sha256': sha(WORKER),
                                    'test': self._testMethodName,
                                    'returncode': result.returncode, 'report': report,
                                    'stdout': result.stdout.decode(errors='replace'),
                                    'stderr': result.stderr.decode(errors='replace')}
        retained = ARTIFACTS
        retained.mkdir(parents=True, exist_ok=True)
        destination = Path(tempfile.mkdtemp(prefix='worker-attempt-', dir=retained))
        if (self.workspace / 'evidence').is_dir():
            shutil.copytree(self.workspace / 'evidence', destination / 'evidence', symlinks=True)
        type(self).last_execution['retained_evidence'] = str(destination)
        if not hasattr(type(self), 'execution_history'): type(self).execution_history = []
        type(self).execution_history.append(type(self).last_execution)
        return result.returncode, report

    def clone_after(self):
        original = self.workspace
        temp = tempfile.TemporaryDirectory(prefix='caa-install-test-next-'); self.addCleanup(temp.cleanup)
        self.workspace = Path(temp.name); self.workspace.chmod(0o700)
        shutil.copytree(original / 'evidence/system-snapshot', self.workspace / 'system')
        self.public_key = self.workspace / 'test-public-key.asc'
        self.public_key.write_bytes(self.keys.certificate.read_bytes()); self.public_key.chmod(0o600)

    def assert_failure(self, contract):
        code, report = self.execute(contract)
        self.assertNotEqual(code, 0); self.assertIn(report['status'], {'FAIL', 'REFUSED'})
        self.assertFalse((self.workspace / 'evidence/installed-packages.lock').exists())
        return report

    def test_actual_signed_tiny_dependency_pair_commit(self):
        dependency, dep_files = self.package('caa-install-fixture-b')
        dependent, files = self.package(depends=('caa-install-fixture-b>=1.0',))
        code, report = self.execute(self.contract([dependent, dependency]))
        self.assertEqual(code, 0, report); self.assertEqual(report['status'], 'PASS-disposable-payload-transaction')
        self.assertTrue(report['commit_started']); self.assertTrue(report['committed'])
        self.assertTrue(report['installed_payload_verified'])
        for relative, data in {**dep_files, **files}.items():
            self.assertEqual((self.workspace / 'evidence/system-snapshot' / relative).read_bytes(), data)
        self.assertFalse((self.workspace / 'system/usr').exists(), 'committed guest payload must not persist on host')
        lock = self.workspace / 'evidence/installed-packages.lock'
        self.assertTrue(lock.is_file())
        self.assertEqual(lock.read_text(), ''.join(f'{name} {version}\n' for name, version in sorted(report['after'].items())))

    def test_actual_missing_dependency_refuses_before_commit(self):
        row, _ = self.package(depends=('caa-install-fixture-missing>=1',))
        report = self.assert_failure(self.contract([row]))
        self.assertFalse(report['commit_started']); self.assertFalse(report['committed'])
        self.assertEqual(report['phase'], 'prepare')
        self.assertIn('actual prepare', report['error'])
        self.assertIn('dependencies', report['error'])
        self.assertFalse((self.workspace / 'system/usr/share/caa-install-fixture-a/data').exists())

    def test_actual_wrong_signer_refuses_before_commit(self):
        row, _ = self.package(); row['signer'] = 'A' * 40
        report = self.assert_failure(self.contract([row]))
        self.assertFalse(report['commit_started']); self.assertFalse(report['committed'])

    def test_actual_invalid_signature_refuses_before_commit(self):
        row, _ = self.package()
        signature = Path(row['signature']['path']); signature.write_bytes(b'NOT A SIGNATURE\n')
        row['signature'] = self.reference(signature)
        report = self.assert_failure(self.contract([row]))
        self.assertFalse(report['commit_started']); self.assertFalse(report['committed'])

    def test_actual_secret_certificate_refuses_before_commit(self):
        row, _ = self.package()
        secret = self.keys.command('--pinentry-mode', 'loopback', '--passphrase', '',
                                   '--armor', '--export-secret-keys', self.keys.fingerprint).stdout
        self.assertIn(b'BEGIN PGP PRIVATE KEY BLOCK', secret)
        self.public_key.write_bytes(secret); self.public_key.chmod(0o600)
        report = self.assert_failure(self.contract([row]))
        self.assertFalse(report['commit_started']); self.assertFalse(report['committed'])
        self.assertEqual(report['phase'], 'isolated')

    def test_actual_signature_subkey_binds_primary_signer(self):
        self.keys.command('--pinentry-mode', 'loopback', '--passphrase', '', '--quick-add-key',
                          self.keys.fingerprint, 'ed25519', 'sign', '0')
        listing = self.keys.command('--with-colons', '--list-keys').stdout.decode()
        fingerprints = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
        self.assertGreater(len(fingerprints), 1)
        certificate = self.keys.command('--armor', '--export', self.keys.fingerprint).stdout
        self.keys.certificate.write_bytes(certificate)
        self.public_key.write_bytes(certificate)
        row, _ = self.package(signing_key=fingerprints[-1] + '!')
        code, report = self.execute(self.contract([row]))
        self.assertEqual(code, 0, report); self.assertTrue(report['committed'])

    def test_actual_input_hardlink_refused_without_commit(self):
        row, _ = self.package(); archive = Path(row['archive']['path'])
        os.link(archive, self.workspace / 'archive-hardlink')
        report = self.assert_failure(self.contract([row]))
        self.assertFalse(report['commit_started']); self.assertFalse(report['committed'])

    def test_actual_escaping_signed_archive_refused_without_escape(self):
        row, _ = self.package(files={'../escape': b'must never escape\n'})
        report = self.assert_failure(self.contract([row]))
        self.assertFalse(report['commit_started']); self.assertFalse(report['committed'])
        self.assertFalse((self.workspace / 'escape').exists())

    def test_actual_existing_root_external_hardlink_refused(self):
        row, files = self.package()
        outside = tempfile.TemporaryDirectory(prefix='caa-install-outside-sentinel-'); self.addCleanup(outside.cleanup)
        sentinel = Path(outside.name) / 'sentinel'; sentinel.write_bytes(b'protected external inode\n')
        root = self.workspace / 'system'; root.mkdir(mode=0o700)
        target = root / next(iter(files)); target.parent.mkdir(parents=True)
        os.link(sentinel, target)
        report = self.assert_failure(self.contract([row]))
        self.assertFalse(report['commit_started']); self.assertFalse(report['committed'])
        self.assertEqual(sentinel.read_bytes(), b'protected external inode\n')

    def test_actual_file_conflict_preserves_foreign_bytes(self):
        row, files = self.package()
        root = self.workspace / 'system'; root.mkdir(mode=0o700)
        path = root / next(iter(files)); path.parent.mkdir(parents=True)
        path.write_bytes(b'foreign unowned bytes\n')
        report = self.assert_failure(self.contract([row]))
        self.assertEqual(path.read_bytes(), b'foreign unowned bytes\n')
        self.assertTrue(report['commit_started']); self.assertFalse(report['committed'])
        self.assertEqual(report['phase'], 'commit')
        self.assertIn('actual commit', report['error'])
        self.assertIn('conflicting files', report['error'])

    def test_declared_after_mismatch_refuses_before_commit(self):
        row, _ = self.package()
        report = self.assert_failure(self.contract([row], after={row['name']: row['version'], 'undeclared-extra': '1'}))
        self.assertFalse(report['commit_started']); self.assertFalse(report['committed'])

    def test_actual_protected_upgrade_refuses_before_commit(self):
        base, _ = self.package()
        code, report = self.execute(self.contract([base])); self.assertEqual(code, 0, report)
        self.clone_after()
        upgrade, _ = self.package(version='2.0-1')
        before = {base['name']: base['version']}
        report = self.assert_failure(self.contract([upgrade], before=before, protected=before))
        self.assertFalse(report['commit_started']); self.assertFalse(report['committed'])
        self.assertEqual((self.workspace / 'system/usr/share/caa-install-fixture-a/data').read_bytes(), b'caa-install-fixture-a\n')

    def test_actual_protected_removal_refuses_before_commit(self):
        base, _ = self.package()
        code, report = self.execute(self.contract([base])); self.assertEqual(code, 0, report)
        self.clone_after()
        before = {base['name']: base['version']}
        unrelated, _ = self.package('caa-install-fixture-b')
        report = self.assert_failure(self.contract([unrelated], before=before, protected=before, remove=before))
        self.assertFalse(report['commit_started']); self.assertFalse(report['committed'])

    def test_actual_signed_removal_uses_installed_seed(self):
        base, files = self.package()
        code, report = self.execute(self.contract([base])); self.assertEqual(code, 0, report)
        self.clone_after()
        before = {base['name']: base['version']}
        code, report = self.execute(self.contract([], before=before, remove=before))
        self.assertEqual(code, 0, report); self.assertTrue(report['committed'])
        self.assertEqual(report['after'], {})
        for relative in files:
            self.assertFalse((self.workspace / 'evidence/system-snapshot' / relative).exists())
        self.assertEqual((self.workspace / 'evidence/installed-packages.lock').read_bytes(), b'')

    def test_actual_upgrade_changes_installed_version_and_payload(self):
        path = 'usr/share/caa-install-fixture-a/data'
        base, _ = self.package(files={path: b'baseline version bytes\n'})
        code, report = self.execute(self.contract([base])); self.assertEqual(code, 0, report)
        self.clone_after()
        upgrade, _ = self.package(version='2.0-1', files={path: b'upgraded version bytes\n'})
        before = {base['name']: base['version']}
        code, report = self.execute(self.contract([upgrade], before=before))
        self.assertEqual(code, 0, report); self.assertTrue(report['committed'])
        self.assertEqual(report['before'], before); self.assertEqual(report['after'], {base['name']: '2.0-1'})
        self.assertEqual((self.workspace / 'evidence/system-snapshot' / path).read_bytes(), b'upgraded version bytes\n')
        self.assertEqual((self.workspace / 'system' / path).read_bytes(), b'baseline version bytes\n')

    def test_actual_unrelated_add_preserves_protected_package_and_file(self):
        path = 'usr/share/caa-install-fixture-a/data'
        base, _ = self.package(files={path: b'protected baseline unchanged\n'})
        code, report = self.execute(self.contract([base])); self.assertEqual(code, 0, report)
        self.clone_after()
        original = sha(self.workspace / 'system' / path)
        added, _ = self.package('caa-install-fixture-b')
        before = {base['name']: base['version']}
        code, report = self.execute(self.contract([added], before=before, protected=before))
        self.assertEqual(code, 0, report); self.assertTrue(report['parent_export_verified'])
        self.assertEqual(report['before'], before)
        self.assertEqual(report['after'], {**before, added['name']: added['version']})
        self.assertEqual(sha(self.workspace / 'evidence/system-snapshot' / path), original)
        self.assertEqual(sha(self.workspace / 'system' / path), original)

    def test_actual_wrong_before_inventory_refuses_before_commit(self):
        row, _ = self.package()
        report = self.assert_failure(self.contract([row], before={'caa-install-fixture-missing': '1.0-1'}))
        self.assertFalse(report['commit_started']); self.assertFalse(report['committed'])
        self.assertIn('before inventory differs', report['error'])


class SupervisionTests(Fixtures):
    @classmethod
    def setUpClass(cls):
        if REVIEWED_WORKER_SHA256 is None:
            raise unittest.SkipTest('actual supervision held: independently reviewed worker pin not supplied')
        if sha(WORKER) != REVIEWED_WORKER_SHA256: raise AssertionError('reviewed worker source changed')
        super().setUpClass()

    def test_actual_timeout_reaps_owned_process_group(self):
        self.assertIsNotNone(REVIEWED_WORKER_SHA256, 'reviewed worker pin required for actual supervision')
        self.assertEqual(self.module._fixture_source_sha256, REVIEWED_WORKER_SHA256)
        marker = self.workspace / 'child-pid'
        logs = self.workspace / 'timeout-logs'; logs.mkdir(mode=0o700)
        command = ['/usr/bin/python3', '-I', '-B', '-c',
                   'import os,pathlib,time,sys; pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)',
                   str(marker)]
        with self.assertRaises((TimeoutError, subprocess.TimeoutExpired)):
            self.module.supervise(command, 1, environment(), logs)
        self.assertTrue(marker.is_file(), 'timeout must occur after actual child start')
        pid = int(marker.read_text())
        with self.assertRaises(ProcessLookupError): os.kill(pid, 0)


class GpgHomePathTests(unittest.TestCase):
    """Pure byte budgets and controlled parent/engine refusal; no authentication actor."""
    def setUp(self):
        self.module = load_worker(); self.addCleanup(self.close_output)
        raw = (HERE.parent / 'port/kernel-native-job/runtime.py').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), RUNTIME_SHA256)
        self.module.RUNTIME_BYTES = raw
    def close_output(self):
        if self.module.OWNED_OUTPUT is not None: self.module.OWNED_OUTPUT.close()
    def test_ASCII_socket_107_accepts_and_108_refuses_closed_reason(self):
        self.module.validate_gpg_home_path('/'+'a'*90)
        with self.assertRaisesRegex(ValueError, '^GPG_HOME_SOCKET_PATH_TOO_LONG$'):
            self.module.validate_gpg_home_path('/'+'a'*91)
    def test_UTF8_filesystem_bytes_decide_instead_of_character_count(self):
        self.module.validate_gpg_home_path('/'+'é'*45)
        workspace = '/'+'é'*45+'a'
        self.assertLess(len(str(Path(workspace)/'gpg/S.gpg-agent')), 107)
        with self.assertRaisesRegex(ValueError, '^GPG_HOME_SOCKET_PATH_TOO_LONG$'):
            self.module.validate_gpg_home_path(workspace)
    def test_terminating_NUL_reserves_one_byte_in_the_108_byte_field(self):
        fitting, oversized = '/'+'a'*90, '/'+'a'*91
        for workspace, expected in ((fitting,108),(oversized,109)):
            raw = os.fsencode(Path(workspace)/'gpg/S.gpg-agent')
            self.assertEqual(len(raw+b'\x00'), expected)
        self.module.validate_gpg_home_path(fitting)
        with self.assertRaises(ValueError): self.module.validate_gpg_home_path(oversized)
        # Embedded NUL remains rejected by the existing private-path gate.
        with self.assertRaises(ValueError): self.module.private('/tmp/invalid\x00workspace',os.getuid())
    def parent(self, *, long_path):
        temp = tempfile.TemporaryDirectory(prefix='caa-gpg-policy-'); self.addCleanup(temp.cleanup)
        base = Path(temp.name); base.chmod(0o700)
        workspace = base/('w'*80) if long_path else base
        if long_path: workspace.mkdir(mode=0o700)
        contract = {'schema_version':1,'scope':'synthetic-fixture','workspace':str(workspace),
                    'architecture':'x86_64','before':{'test-only': '1'},'after':{},'protected':{},
                    'add':[],'remove':{'test-only':'1'},'keyring':{'path':'/not-consumed','size':1,'sha256':'a'*64},
                    'timeout_seconds':20,'libalpm_sha256':LIBALPM_SHA256}
        path = base/'contract.json'; raw = encoded(contract); path.write_bytes(raw); path.chmod(0o600)
        output = workspace/'evidence'; counters = {'copy':0,'capsule':0,'supervise':0,'alpm':0}
        control = ValueError('test-only copied seed stop')
        def copy(*args, **kwargs): counters['copy']+=1; raise control
        def capsule(*args, **kwargs): counters['capsule']+=1; self.fail('source capsule reached')
        def supervise(*args, **kwargs): counters['supervise']+=1; self.fail('worker actor reached')
        def alpm(*args, **kwargs): counters['alpm']+=1; self.fail('package actor reached')
        with patch.object(self.module,'copy_tree',side_effect=copy), patch.object(self.module,'sealed_source',side_effect=capsule), \
                patch.object(self.module,'supervise',side_effect=supervise), patch.object(self.module,'Alpm',side_effect=alpm):
            result = self.module.execute(path,hashlib.sha256(raw).hexdigest(),output,
                        worker_source_sha256=self.module._fixture_source_sha256,allow=True)
        retained = json.loads((output/'result.json').read_bytes())
        self.assertEqual(retained,result); self.assertEqual(result['status'],'FAIL')
        self.assertFalse(result['commit_started']); self.assertFalse(result['committed'])
        self.assertFalse((output/'candidate-packages.lock').exists()); self.assertFalse((output/'installed-packages.lock').exists())
        self.assertFalse(self.module.ENGINE_STARTED); self.assertEqual(result['capsule_cleanup']['owned_remaining'],0)
        return result,counters,workspace
    def test_long_parent_refusal_is_durable_before_copy_capsule_worker_or_package(self):
        result,counters,workspace = self.parent(long_path=True)
        self.assertEqual(result['parent_error_type'],'ValueError')
        self.assertEqual(result['parent_error'],'GPG_HOME_SOCKET_PATH_TOO_LONG')
        self.assertEqual(result['error'],'GPG_HOME_SOCKET_PATH_TOO_LONG')
        self.assertEqual(counters,{'copy':0,'capsule':0,'supervise':0,'alpm':0})
        self.assertFalse((workspace/'system').exists()); self.assertFalse((workspace/'gpg').exists())
    def test_short_parent_passes_path_guard_without_promoting_later_control(self):
        result,counters,_ = self.parent(long_path=False)
        self.assertEqual(result['parent_error'],'test-only copied seed stop')
        self.assertEqual(counters,{'copy':1,'capsule':0,'supervise':0,'alpm':0})
    def test_actual_engine_guard_slice_refuses_before_authentication_command(self):
        import ast
        raw = WORKER.read_bytes(); self.assertEqual(hashlib.sha256(raw).hexdigest(),self.module._fixture_source_sha256)
        engine = next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='engine')
        block = next(n for n in engine.body if isinstance(n,ast.Try) and any(isinstance(x,ast.Expr) and
                     isinstance(x.value,ast.Call) and isinstance(x.value.func,ast.Name) and
                     x.value.func.id=='validate_gpg_home_path' for x in n.body))
        code = compile(ast.fix_missing_locations(ast.Module(block.body[:3],type_ignores=[])), 'actual-engine-guard-slice','exec')
        calls=[]
        for workspace in (Path('/'+'a'*91),Path('/tmp/controlled-short')):
            env = dict(self.module.__dict__,workspace=workspace,keys=workspace/'gpg',
                       contract={'keyring':{'path':'/controlled-never-read'}},command=lambda argv:calls.append(argv))
            if len(os.fsencode(workspace/'gpg/S.gpg-agent'))>107:
                with self.assertRaisesRegex(ValueError,'^GPG_HOME_SOCKET_PATH_TOO_LONG$'): exec(code,env)
                self.assertEqual(calls,[])
            else: exec(code,env)
        self.assertEqual(len(calls),1); self.assertIn('--no-autostart',calls[0]); self.assertIn('--no-auto-key-retrieve',calls[0])


class IsolateAdoptionOrderTests(unittest.TestCase):
    """Execute the actual three-statement evidence slice against modeled RO state."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='caa-adoption-order-'); self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name); self.workspace.chmod(0o700)
        self.path = self.workspace / 'evidence'; self.path.mkdir(mode=0o700)
        self.module = load_worker(); self.directory_fds = {}; self.addCleanup(self.close_output)
        self.nodes = {}; self.payload = b'precreated authority bytes'
        for name in ('result.json', 'candidate-packages.lock'):
            p = self.path / name; p.write_bytes(self.payload); p.chmod(0o600)
            info = p.stat(); self.nodes[name] = [info.st_dev, info.st_ino]
        info = self.path.stat(); self.identity = [info.st_dev, info.st_ino]
    def close_output(self):
        if self.module.OWNED_OUTPUT is not None: self.module.OWNED_OUTPUT.close()
        # Constructor identity refusal has not assigned OWNED_OUTPUT; the fixture
        # still closes only its own observed directory lease.
        for fd, identity in self.directory_fds.items():
            try: info = os.fstat(fd)
            except OSError as error:
                if error.errno != errno.EBADF: raise
            else:
                if (info.st_dev, info.st_ino) == identity: os.close(fd)
        self.directory_fds.clear()
    @staticmethod
    def segment(source, *, historical=False):
        import ast
        function = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'isolate')
        first = next(i for i,n in enumerate(function.body) if isinstance(n, ast.Assign) and
                     any(isinstance(t, ast.Name) and t.id == 'OWNED_OUTPUT' for t in n.targets))
        body = function.body[first:first+3]
        if historical: body = [body[0], body[2], body[1]]
        return compile(ast.fix_missing_locations(ast.Module(body, type_ignores=[])), 'actual-isolate-evidence-slice', 'exec')
    def run_segment(self, *, historical=False, remount_error=None, identity=None, node_change=None, source=None):
        state = {'writable':False, 'calls':[]}; opening = self.module.os.open
        def mount(source, target, flags):
            self.assertIsNone(source); self.assertEqual(target, self.path)
            self.assertEqual(flags, (1 << 5) | (1 << 12) | 2 | 4)
            state['calls'].append('remount')
            if remount_error is not None: raise remount_error
            state['writable'] = True
            if node_change is not None: node_change()
        def open_file(path, flags, *args, **kwargs):
            if flags & os.O_RDWR:
                state['calls'].append('adopt-open')
                if not state['writable']: raise OSError(errno.EROFS, 'modeled evidence still readonly')
            fd = opening(path, flags, *args, **kwargs)
            if flags & os.O_DIRECTORY:
                info = os.fstat(fd); self.directory_fds[fd] = (info.st_dev, info.st_ino)
            return fd
        env = self.module.__dict__
        env.update(workspace=self.workspace, spec={'evidence_identity':self.identity if identity is None else identity,
                                                  'evidence_nodes':self.nodes})
        with patch.object(self.module, 'mount', side_effect=mount), patch.object(self.module.os, 'open', side_effect=open_file):
            raw = WORKER.read_bytes() if source is None else source
            if source is None: self.assertEqual(hashlib.sha256(raw).hexdigest(), self.module._fixture_source_sha256)
            exec(self.segment(raw, historical=historical), env)
        return state
    def test_old_readonly_adoption_refuses_and_corrected_actual_slice_preserves_bytes(self):
        with self.assertRaises(OSError) as caught: self.run_segment(historical=True)
        self.assertEqual(caught.exception.errno, errno.EROFS)
        self.assertFalse(self.module.OWNED_OUTPUT.nodes); self.close_output(); self.module.OWNED_OUTPUT = None
        state = self.run_segment()
        self.assertEqual(state['calls'], ['remount','adopt-open','adopt-open'])
        self.assertEqual(set(self.module.OWNED_OUTPUT.nodes), set(self.nodes))
        for name in self.nodes: self.assertEqual((self.path/name).read_bytes(), self.payload)
    def test_failed_or_cancelled_remount_never_adopts_and_preserves_first_failure(self):
        for error in (ValueError('modeled remount refused'), KeyboardInterrupt('private remount control')):
            self.module.OWNED_OUTPUT = None
            with self.assertRaises(type(error)) as caught: self.run_segment(remount_error=error)
            self.assertIs(caught.exception, error); self.assertFalse(self.module.OWNED_OUTPUT.nodes)
            self.close_output()
    def test_directory_authority_identity_failure_refuses_before_remount(self):
        changed = [self.identity[0], self.identity[1]+1]
        with self.assertRaisesRegex(ValueError, 'directory identity refused'):
            self.run_segment(identity=changed)
        self.assertIsNone(self.module.OWNED_OUTPUT)
    def test_replaced_or_symlinked_receipt_after_remount_is_not_adopted(self):
        for kind in ('replace','symlink'):
            self.module.OWNED_OUTPUT = None
            target = self.path/'result.json'; held = self.path/('old-'+kind)
            def change():
                target.rename(held)
                if kind == 'replace': target.write_bytes(self.payload); target.chmod(0o600)
                else: target.symlink_to(held)
            with self.assertRaises((ValueError, OSError)): self.run_segment(node_change=change)
            self.assertFalse(self.module.OWNED_OUTPUT.nodes); self.close_output()
            target.unlink(); held.rename(target)


class BarrierSourceFixtureTests(unittest.TestCase):
    """Source/layout controls only: never invoke BarrierTests' namespace actor."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='caa-barrier-source-'); self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name); self.workspace.chmod(0o700)
        self.pin = sha(WORKER)
    def loaded(self, path):
        module = types.ModuleType('barrier_source_only'); module.__file__ = str(path)
        exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
        return module
    def test_exact_layout_loads_hash_bound_runtime_without_foreign_pyc(self):
        source, pin = BarrierTests.capture_source(self.workspace, self.pin)
        self.assertEqual(pin, self.pin); self.assertEqual(sha(source), pin)
        helper = source.parents[1] / 'port/kernel-native-job/runtime.py'
        self.assertEqual(sha(helper), RUNTIME_SHA256)
        self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(helper.stat().st_mode), 0o400)
        module = self.loaded(source); runtime = module.runtime()
        self.assertEqual(hashlib.sha256(module.RUNTIME_BYTES).hexdigest(), RUNTIME_SHA256)
        self.assertTrue(callable(runtime.defer_signals)); self.assertFalse(list(self.workspace.rglob('*.pyc')))
    def test_historical_flat_source_missing_runtime_is_causal_and_complete_copy_loads(self):
        flat = self.workspace / 'flat/captured-worker.py'; flat.parent.mkdir(mode=0o700)
        flat.write_bytes(WORKER.read_bytes()); flat.chmod(0o400)
        self.assertEqual(sha(flat), self.pin)
        with self.assertRaises(FileNotFoundError): self.loaded(flat).runtime()
        source, _ = BarrierTests.capture_source(self.workspace, self.pin)
        self.assertTrue(callable(self.loaded(source).runtime().defer_signals))
    def test_missing_changed_symlink_or_hardlinked_origin_runtime_refuses(self):
        scripts = self.workspace / 'origin/scripts'; (scripts / 'install').mkdir(parents=True)
        helper = scripts / 'port/kernel-native-job/runtime.py'; helper.parent.mkdir(parents=True)
        actual = (HERE.parent / 'port/kernel-native-job/runtime.py').read_bytes()
        for kind in ('missing', 'changed', 'symlink', 'hardlink'):
            if helper.exists() or helper.is_symlink(): helper.unlink()
            foreign = helper.parent / ('foreign-' + kind)
            if kind == 'changed': helper.write_bytes(b'wrong runtime')
            elif kind in ('symlink', 'hardlink'):
                foreign.write_bytes(actual)
                if kind == 'symlink': helper.symlink_to(foreign)
                else: os.link(foreign, helper)
            with patch.dict(globals(), {'HERE': scripts / 'install'}), self.assertRaises((ValueError, FileNotFoundError)):
                BarrierTests.capture_source(self.workspace / ('copy-' + kind), self.pin)
    def test_wrong_worker_pin_or_changed_captured_helper_cannot_load(self):
        with self.assertRaises(AssertionError): BarrierTests.capture_source(self.workspace, '0' * 64)
        self.assertFalse((self.workspace / 'captured-source').exists())
        source, _ = BarrierTests.capture_source(self.workspace, self.pin)
        helper = source.parents[1] / 'port/kernel-native-job/runtime.py'
        helper.chmod(0o600); helper.write_bytes(b'changed captured helper')
        with self.assertRaises(ValueError): self.loaded(source).runtime()


class BarrierTests(unittest.TestCase):
    """Actual worker mount isolation only; no GPG/libalpm/package transaction."""
    @staticmethod
    def capture_source(workspace, worker_pin):
        """Capture the exact two-file layout needed by the worker's lazy runtime."""
        module = load_worker()
        if module._fixture_source_sha256 != worker_pin:
            raise AssertionError('reviewed barrier worker source changed')
        runtime = HERE.parent / 'port/kernel-native-job/runtime.py'
        source = workspace / 'captured-source/scripts/install/local_transaction.py'
        helper = workspace / 'captured-source/scripts/port/kernel-native-job/runtime.py'
        for target, origin, pin in ((source, WORKER, worker_pin), (helper, runtime, RUNTIME_SHA256)):
            raw = module.capture({'path': str(origin), 'size': origin.stat().st_size, 'sha256': pin}, 128 * 1024)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(raw); target.chmod(0o400)
            module.capture({'path': str(target), 'size': len(raw), 'sha256': pin}, 128 * 1024)
        return source, worker_pin

    def test_actual_isolate_keeps_host_readonly_and_only_evidence_persistent(self):
        if REVIEWED_WORKER_SHA256 is None:
            self.skipTest('actual barrier held: independently reviewed worker pin not supplied')
        if not shutil.which('unshare'): self.skipTest('unshare unavailable')
        with tempfile.TemporaryDirectory(prefix='caa-install-barrier-') as base, \
                tempfile.TemporaryDirectory(prefix='caa-install-barrier-outside-') as other:
            workspace = Path(base); workspace.chmod(0o700)
            evidence = workspace / 'evidence'; evidence.mkdir(mode=0o700)
            nodes = {}
            for name in ('result.json', 'candidate-packages.lock'):
                path = evidence / name; path.write_bytes(b''); path.chmod(0o600)
                node = path.stat(); nodes[name] = [node.st_dev, node.st_ino]
            sentinel = Path(other) / 'sentinel'; sentinel.write_bytes(b'unchanged outside bytes\n')
            source, captured = self.capture_source(workspace, REVIEWED_WORKER_SHA256)
            evidence_fd = os.open(evidence, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, evidence_fd)
            info = os.fstat(evidence_fd)
            namespaces = {name: os.readlink('/proc/self/ns/' + name) for name in ('user', 'mnt', 'pid', 'net')}
            spec = {'contract': {'workspace': str(workspace)}, 'host_uid': os.getuid(), 'host_namespaces': namespaces,
                    'evidence_identity': [info.st_dev, info.st_ino], 'evidence_nodes': nodes}
            if FIXTURE_SELECTION_SHA256 is not None: spec['contract']['architecture'] = 'aarch64'
            code = '''import ctypes,errno,hashlib,json,os,sys,types
from pathlib import Path
data=Path(sys.argv[1]).read_bytes()
assert hashlib.sha256(data).hexdigest()==sys.argv[2]
module=types.ModuleType("captured_barrier_fixture");module.__file__=sys.argv[1]
exec(compile(data,sys.argv[1],"exec"),module.__dict__)
module.INHERITED_EVIDENCE_FD=int(sys.argv[5])
spec=json.loads(sys.argv[3]);workspace=module.isolate(spec)
module.reduce_capabilities()
status={key:value.strip() for line in Path("/proc/self/status").read_text().splitlines() if ":" in line for key,value in [line.split(":",1)]}
caps={key:int(status[key],16) for key in ("CapEff","CapPrm","CapBnd","CapInh","CapAmb")}
assert all(caps[key]==0x400cb for key in ("CapEff","CapPrm","CapBnd"))
assert caps["CapInh"]==caps["CapAmb"]==0 and status["NoNewPrivs"]=="1"
libc=ctypes.CDLL(None,use_errno=True);denied={}
for number in module.architecture_profile(spec["contract"].get("architecture","x86_64"))[2]:
    ctypes.set_errno(0)
    assert libc.syscall(number,-1,0,0,0,0,0)==-1
    denied[str(number)]=ctypes.get_errno()
    assert denied[str(number)]==errno.EPERM
(workspace/"guest-only").write_bytes(b"private tmpfs bytes\\n")
(workspace/"evidence/allowed-marker").write_bytes(b"owned evidence bytes\\n")
try:
    Path(sys.argv[4]).write_bytes(b"FORBIDDEN")
except OSError as error:
    assert error.errno==errno.EROFS
    outside_errno=error.errno
else:
    raise AssertionError("external write unexpectedly succeeded")
print(json.dumps({"status":"PASS-barrier-only","worker_sha256":sys.argv[2],"outside_errno":outside_errno,
                  "uid":os.getuid(),"namespace_changed":all(module.namespaces()[key]!=value for key,value in spec["host_namespaces"].items()),
                  "denied_service_syscalls":denied,"capabilities":caps,"no_new_privileges":int(status["NoNewPrivs"]),
                  "libalpm_initialized":False,"package_commit":False},sort_keys=True))
'''
            command = ['/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--pid', '--mount-proc',
                       '--net', '--fork', '--kill-child=SIGKILL', '--', '/usr/bin/python3', '-I', '-B', '-c', code,
                       str(source), captured, json.dumps(spec), str(sentinel), str(evidence_fd)]
            result = subprocess.run(command, capture_output=True, timeout=15,
                                    env=environment(LC_ALL='C'), pass_fds=(evidence_fd,))
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
            report = json.loads(result.stdout)
            self.assertEqual(report['status'], 'PASS-barrier-only'); self.assertEqual(report['worker_sha256'], captured)
            self.assertEqual(report['uid'], 0); self.assertTrue(report['namespace_changed'])
            self.assertEqual(report['denied_service_syscalls'],
                             {str(number): 1 for number in load_worker().architecture_profile('aarch64' if FIXTURE_SELECTION_SHA256 else 'x86_64')[2]})
            self.assertEqual(report['capabilities'], {'CapEff': 0x400cb, 'CapPrm': 0x400cb,
                                                     'CapBnd': 0x400cb, 'CapInh': 0, 'CapAmb': 0})
            self.assertEqual(report['no_new_privileges'], 1)
            self.assertFalse(report['libalpm_initialized']); self.assertFalse(report['package_commit'])
            self.assertEqual(sentinel.read_bytes(), b'unchanged outside bytes\n')
            self.assertFalse((workspace / 'guest-only').exists())
            self.assertEqual((evidence / 'allowed-marker').read_bytes(), b'owned evidence bytes\n')
            self.assertEqual({name: os.readlink('/proc/self/ns/' + name) for name in namespaces}, namespaces)
            type(self).last_report = report | {'host_namespace_unchanged': True,
                                               'outside_bytes_unchanged': True,
                                               'guest_file_absent_on_host': True,
                                               'evidence_marker_persisted': True}



class NativeProfileTests(unittest.TestCase):
    """Pure native profile/ABI controls; no native tool is loaded or executed."""
    def setUp(self): self.module = load_worker()
    def contract(self):
        return dict(schema_version=2, scope='native-aarch64-fixture', workspace='/tmp/fixture', architecture='aarch64',
                    before={}, after={'caa-install-fixture-a':'1.0-1'}, protected={}, remove={},
                    add=[dict(name='caa-install-fixture-a',version='1.0-1',archive={},signature={},signer='A'*40)],
                    keyring={}, timeout_seconds=20, libalpm_sha256=self.module.NATIVE_LIBRARY_SHA,
                    profile_sha256=self.module.NATIVE_PROFILE_SHA,input_selection_sha256='b'*64)
    def test_legacy_profile_retains_exact_denials_and_binary(self):
        self.assertEqual(self.module.architecture_profile('x86_64'),(LIBALPM_SHA256,0xc000003e,(42,44,46,307,425,426,427)))
    def test_native_profile_pinned_and_abi_specific(self):
        self.assertEqual(self.module.architecture_profile('aarch64')[1:],(0xc00000b7,(203,206,211,269,425,426,427)))
        self.assertNotEqual(self.module.NATIVE_LIBRARY_SHA,LIBALPM_SHA256)
    def test_unknown_architecture_refused(self):
        for architecture in ('arm','arm64',None,True):
            with self.assertRaises(ValueError):self.module.architecture_profile(architecture)
    def test_native_contract_needs_external_selection(self):
        with self.assertRaises(ValueError):self.module.validate_contract(self.contract())
    def test_native_selected_fixture_contract_admitted_as_data(self):
        self.assertEqual(self.module.validate_contract(self.contract(),'b'*64)['architecture'],'aarch64')
    def test_native_mutated_profile_refused(self):
        c=self.contract();c['profile_sha256']='c'*64
        with self.assertRaises(ValueError):self.module.validate_contract(c,'b'*64)
    def test_native_mutated_library_refused(self):
        c=self.contract();c['libalpm_sha256']=LIBALPM_SHA256
        with self.assertRaises(ValueError):self.module.validate_contract(c,'b'*64)
    def test_native_selection_mismatch_refused(self):
        with self.assertRaises(ValueError):self.module.validate_contract(self.contract(),'c'*64)
    def test_native_wrong_machine_refused(self):
        c=self.contract();c['architecture']='x86_64'
        with self.assertRaises(ValueError):self.module.validate_contract(c,'b'*64)
    def test_real_candidate_name_refused(self):
        c=self.contract();c['add'][0]['name']='cachy-asahi-setup';c['after']={'cachy-asahi-setup':'1.0-1'}
        with self.assertRaises(ValueError):self.module.validate_contract(c,'b'*64)
    def test_native_package_map_limit_stays_128(self):
        c=self.contract();c['before']={f'caa-install-fixture-{i}':'1' for i in range(129)}
        with self.assertRaises(ValueError):self.module.validate_contract(c,'b'*64)
    def test_native_boolean_version_and_nonfinite_timeout_refused(self):
        for key,value in (('schema_version',True),('timeout_seconds',float('nan')),('timeout_seconds',True)):
            c=self.contract();c[key]=value
            with self.assertRaises(ValueError):self.module.validate_contract(c,'b'*64)
    def test_native_profile_missing_refuses_before_cdll(self):
        self.module.NATIVE_PROFILE_SHA=None
        with patch.object(self.module.C,'CDLL',side_effect=AssertionError('actor forbidden')) as actor:
            with self.assertRaises(ValueError):self.module.validate_contract(self.contract(),'b'*64)
        actor.assert_not_called()
    def test_native_seccomp_refuses_wrong_actual_machine_before_prctl(self):
        with patch.object(self.module.os,'uname',return_value=types.SimpleNamespace(machine='x86_64')),patch.object(self.module.C,'CDLL') as actor:
            with self.assertRaises(ValueError):self.module.block_service_ipc('aarch64')
        actor.assert_not_called()


class SeccompProfileModelTests(unittest.TestCase):
    def program(self,architecture):
        module=load_worker();observed=[];library=unittest.mock.MagicMock()
        def prctl(option,*args):
            if option==22:
                p=args[1]._obj;observed.extend((p.filters[i].code,p.filters[i].jt,p.filters[i].jf,p.filters[i].k) for i in range(p.length))
            return 0
        library.prctl.side_effect=prctl
        with patch.object(module.os,'uname',return_value=types.SimpleNamespace(machine=architecture)),patch.object(module.C,'CDLL',return_value=library):module.block_service_ipc(architecture)
        return observed
    def verdict(self,rows,audit,nr):
        index=acc=0
        while True:
            code,jt,jf,k=rows[index]
            if code==0x20:acc=audit if k==4 else nr & 0xffffffff;index+=1
            elif code==0x15:index+=1+(jt if acc==k else jf)
            elif code==0x45:index+=1+(jt if acc & k else jf)
            elif code==0x06:return k
            else:self.fail('unexpected source instruction')
    def test_native_model_denials_allow_other_native_and_kill_foreign_ABI(self):
        p=self.program('aarch64')
        for n in (203,206,211,269,425,426,427):self.assertEqual(self.verdict(p,0xc00000b7,n),0x50001)
        self.assertEqual(self.verdict(p,0xc00000b7,172),0x7fff0000)
        self.assertEqual(self.verdict(p,0xc000003e,203),0x80000000)
        self.assertEqual(self.verdict(p,0x40000028,203),0x80000000)
    def test_legacy_model_retains_denials_and_x32_kill(self):
        p=self.program('x86_64')
        for n in (42,44,46,307,425,426,427):self.assertEqual(self.verdict(p,0xc000003e,n),0x50001)
        self.assertEqual(self.verdict(p,0xc000003e,39),0x7fff0000)
        self.assertEqual(self.verdict(p,0xc000003e,0x40000027),0x80000000)

if __name__ == '__main__':
    unittest.main()
