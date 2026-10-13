#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded actual helper/data captures; no compiler, makepkg, package or daemon actor."""
import copy
import json
import os
import signal
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import inner_evidence as inner
from test_worker import config_fixture
import worker_evidence as diagnostic

HELPER = HERE.parents[2] / 'packages/libraries/cachy-asahi-fdk-aac/inner_observation.py'


def finite(bindings, code=0):
    attempt = {'kind': 'COMPILE', 'index': 0, 'natural': False, 'returncode': None}
    natural = dict(attempt, natural=True, returncode=code)
    return {'schema_version': 1, 'bindings': bindings, 'phase': 'BUILD',
        'first_failure': None if code == 0 else {'phase': 'BUILD', 'predicate': 'COMPILER_NONZERO',
            'reason': 'NONZERO', 'command': natural}, 'cancelled': False, 'write_failed': False,
        'compiler_attempted': True, 'compiler_attempt_count': 1, 'compiler_natural_count': 1,
        'first_compiler_attempt': attempt, 'first_compiler_natural': natural, 'publication': 'NOT ACCEPTED'}


class CaptureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name); self.inputs = self.root / 'inputs'; self.inputs.mkdir()
        self.out = self.root / 'artifacts'; self.out.mkdir()
        self.folder = self.out / 'fdk-inner'; self.folder.mkdir(mode=0o700)
        self.path = self.folder / 'observation.json'; self.lock = self.folder / '.lock'
        self.lock.write_bytes(b''); self.lock.chmod(0o600)
        self.source = self.inputs / 'inner_observation.py'; self.source.write_bytes(HELPER.read_bytes())
        self.reviewed = {'inner_observation.py': inner.sha(self.source.read_bytes()), 'PKGBUILD': 'a' * 64,
            'fdk-aac-3.0.0-selected-source.tar': 'b' * 64, 'build-layout.json': 'c' * 64}
        self.config = config_fixture(self.root)
        self.state = {'container_id': 'e' * 64, 'container_name': 'cachy-asahi-fixture01',
            'image': self.config['image'], 'nonce': self.config['nonce'], 'status': 'exited',
            'running': False, 'exit_code': 4, 'inspect_sha256': 'f' * 64}
        self.value = finite(inner.source_bindings(self.reviewed), 7)
        self.write()

    def write(self):
        self.raw = inner.canonical(self.value) + b'\n'; self.path.write_bytes(self.raw); self.path.chmod(0o600)

    def capture(self):
        return inner.capture_inner(self.out, self.inputs, self.reviewed, self.config, 'd' * 64, self.state)

    def test_actual_helper_load_projects_first_failure_and_raw_digest(self):
        result = self.capture(); self.assertEqual(result['availability'], 'BOUND')
        self.assertEqual(result['raw_sha256'], inner.sha(self.raw))
        self.assertEqual(result['observation']['first_failure']['command']['returncode'], 7)
        context = inner.binding_context(self.config, 'd' * 64, self.reviewed, self.state)
        inner.check_context(context, result, self.config, 'd' * 64, self.reviewed)
        self.assertNotIn(self.config['nonce'], json.dumps(result)); self.assertNotIn('container_id', json.dumps(result))
        self.assertEqual(result['observation']['publication'], 'NOT ACCEPTED')

    def test_once_capture_cannot_be_promoted_by_later_file_rewrite(self):
        reads = []; original = inner.os.read
        def read(fd, size):
            if os.fstat(fd).st_ino == self.path.stat().st_ino: reads.append(fd)
            return original(fd, size)
        with mock.patch.object(inner.os, 'read', side_effect=read): result = self.capture()
        self.assertLessEqual(len(set(reads)), 1)
        self.value['first_failure'] = None; self.value['first_compiler_natural']['returncode'] = 0; self.write()
        self.assertEqual(result['observation']['first_failure']['reason'], 'NONZERO')
        self.assertNotEqual(result['raw_sha256'], inner.sha(self.raw))

    def test_missing_invalid_duplicate_oversize_and_unbound_remain_unknown(self):
        self.path.unlink(); self.assertEqual(self.capture()['reason'], 'MISSING')
        for raw in (b'{', b'{"schema_version":1,"schema_version":1}', b'x' * 4097):
            self.path.write_bytes(raw); self.path.chmod(0o600)
            self.assertEqual(self.capture()['availability'], 'UNKNOWN')
        self.write(); self.state['nonce'] = '1' * 32
        self.assertEqual(self.capture()['reason'], 'UNBOUND')
        self.state['nonce'] = self.config['nonce']; self.value['bindings']['layout_sha256'] = '0' * 64; self.write()
        self.assertEqual(self.capture()['reason'], 'UNBOUND')

    def test_source_pin_imports_and_validator_interface_fail_closed(self):
        original = self.source.read_bytes()
        for suffix in (b'\nimport subprocess\n', b'\nfrom os import system\n', b'\nloads = False\n'):
            self.source.write_bytes(original + suffix)
            self.reviewed['inner_observation.py'] = inner.sha(self.source.read_bytes())
            self.assertEqual(self.capture()['reason'], 'SOURCE_INVALID')
        self.source.write_bytes(original); self.reviewed['inner_observation.py'] = '0' * 64
        self.assertEqual(self.capture()['reason'], 'SOURCE_INVALID')

    def test_source_drift_and_later_source_rewrite_do_not_promote_capture(self):
        original = inner.os.read; done = []
        def drift(fd, size):
            raw = original(fd, size)
            if raw and os.fstat(fd).st_ino == self.source.stat().st_ino and not done:
                done.append(True); self.source.write_bytes(self.source.read_bytes() + b'\n')
            return raw
        with mock.patch.object(inner.os, 'read', side_effect=drift):
            self.assertEqual(self.capture()['reason'], 'SOURCE_INVALID')
        self.source.write_bytes(HELPER.read_bytes())
        bound = self.capture(); self.source.write_bytes(b'import subprocess')
        self.assertEqual(bound['availability'], 'BOUND')
        self.assertEqual(self.capture()['reason'], 'SOURCE_INVALID')

    def test_bytecode_never_substitutes_for_missing_source(self):
        (self.inputs / '__pycache__').mkdir(); (self.inputs / '__pycache__/inner_observation.pyc').write_bytes(b'poison')
        self.source.unlink(); self.assertEqual(self.capture()['reason'], 'SOURCE_INVALID')

    def test_retained_healthy_json_with_refusal_lock_cannot_be_bound(self):
        self.lock.write_bytes(b'{"write_failed":true}')
        result = self.capture(); self.assertEqual(result, inner.unknown('UNAVAILABLE', inner.sha(self.raw)))
        self.lock.write_bytes(b''); self.value['write_failed'] = True; self.write()
        self.assertEqual(self.capture()['reason'], 'UNAVAILABLE')

    def test_owner_mode_hardlink_symlink_fifo_and_private_folder_refused(self):
        self.path.chmod(0o644); self.assertEqual(self.capture()['reason'], 'UNAVAILABLE'); self.path.chmod(0o600)
        self.folder.chmod(0o755); self.assertEqual(self.capture()['reason'], 'UNAVAILABLE'); self.folder.chmod(0o700)
        link = self.folder / 'hard'; os.link(self.path, link)
        self.assertEqual(self.capture()['reason'], 'UNAVAILABLE'); link.unlink()
        self.path.unlink(); self.path.symlink_to(self.source); self.assertEqual(self.capture()['reason'], 'UNAVAILABLE')
        self.path.unlink(); os.mkfifo(self.path, 0o600); self.assertEqual(self.capture()['reason'], 'UNAVAILABLE')
        self.path.unlink(); self.write()
        with mock.patch.object(inner.os, 'getuid', return_value=os.getuid() + 1):
            self.assertEqual(self.capture()['reason'], 'SOURCE_INVALID')

    def test_ancestor_alias_refused_and_changed_record_detected(self):
        alias = self.root / 'alias'; alias.symlink_to(self.out, target_is_directory=True)
        result = inner.capture_inner(alias, self.inputs, self.reviewed, self.config, 'd' * 64, self.state)
        self.assertEqual(result['reason'], 'UNAVAILABLE')
        original = inner.os.read; done = []
        def drift(fd, size):
            data = original(fd, size)
            if data and os.fstat(fd).st_ino == self.path.stat().st_ino and not done:
                done.append(True); self.path.write_bytes(self.raw + b' ')
            return data
        with mock.patch.object(inner.os, 'read', side_effect=drift):
            self.assertEqual(self.capture()['reason'], 'UNAVAILABLE')

    def test_cancellation_propagates_and_all_owned_fds_close(self):
        original_open, original_close = inner.os.open, inner.os.close
        opened, closed = [], []
        error = KeyboardInterrupt('fixture actual control')
        def opening(*args, **kwargs):
            fd = original_open(*args, **kwargs); opened.append(fd); return fd
        def closing(fd): closed.append(fd); return original_close(fd)
        with mock.patch.object(inner.os, 'open', side_effect=opening), mock.patch.object(inner.os, 'close', side_effect=closing), \
             mock.patch.object(inner.os, 'read', side_effect=error):
            with self.assertRaises(KeyboardInterrupt) as got: self.capture()
        self.assertIs(got.exception, error); self.assertEqual(sorted(opened), sorted(closed))

    def test_exact_context_commands_and_original_provenance_are_required(self):
        result = self.capture(); context = inner.binding_context(self.config, 'd' * 64, self.reviewed, self.state)
        commands = {'create': diagnostic.exit_record(0), 'attach': diagnostic.exit_record(4), 'container': diagnostic.exit_record(4)}
        provenance = {'clean_environment_id': self.state['container_name'], 'image': self.config['image'],
            'image_id': self.config['image'], 'entry_script_sha256': inner.ENTRY_SHA, 'recipe_inputs': self.reviewed}
        inner.check_context(context, result, self.config, 'd' * 64, self.reviewed, commands, provenance)
        for key, value in (('container_id', '0' * 64), ('exit_code', True), ('status', 'running'), ('source_bindings', {})):
            changed = copy.deepcopy(context); changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                inner.check_context(changed, result, self.config, 'd' * 64, self.reviewed, commands, provenance)
        commands['container'] = diagnostic.exit_record(0)
        with self.assertRaises(ValueError): inner.check_context(context, result, self.config, 'd' * 64, self.reviewed, commands, provenance)
        provenance['clean_environment_id'] = 'foreign'
        with self.assertRaises(ValueError): inner.check_context(context, result, self.config, 'd' * 64, self.reviewed, None, provenance)

    def test_boolean_or_malformed_helper_results_cannot_escape_unknown(self):
        for returned in (True, {}, {'write_failed': False}):
            with mock.patch.object(inner, 'captured_observer', return_value={'loads': lambda _: returned, 'validate': lambda v: v}):
                self.assertEqual(self.capture()['reason'], 'INVALID')


class CloseOwnershipTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name); self.path = self.root / 'record'
        self.path.write_bytes(b'private finite data'); self.path.chmod(0o600)
        self.foreign_path = self.root / 'foreign'; self.foreign_path.write_bytes(b'foreign')

    def exercise(self, fault, *, original=None, effect=False, reused=False, second=None, boundary='capture_file'):
        registry_before = dict(inner._UNCERTAIN)
        opened, attempts, retained, injected = [], [], [], []
        opening, closing = os.open, os.close
        handlers = {s: signal.getsignal(s) for s in (signal.SIGINT, signal.SIGTERM)}
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        def op(*args, **kwargs):
            fd = opening(*args, **kwargs)
            opened.append((fd, inner.descriptor_identity(os.fstat(fd))))
            return fd
        def close(fd):
            attempts.append(fd)
            if not injected:
                injected.append(fd)
                if effect:
                    closing(fd)
                    if reused:
                        foreign = opening(self.foreign_path, os.O_RDONLY)
                        if foreign != fd:
                            os.dup2(foreign, fd); closing(foreign)
                        retained.append(fd)
                raise fault
            if second is not None and attempts.count(injected[0]) == 2 and fd == injected[0]:
                raise second
            closing(fd)
        def call():
            if boundary == 'capture_file': return inner.capture_file(self.root, 'record', 4096, private=True)
            # Missing pin intentionally avoids any helper execution; its source
            # capture still exercises the same close ownership path.
            (self.root / 'inner_observation.py').write_bytes(b'# finite source fixture')
            return inner.capture_inner(self.root, self.root, {}, {}, None, None)
        outcome = None
        try:
            with mock.patch.object(inner.os, 'open', side_effect=op), mock.patch.object(inner.os, 'close', side_effect=close):
                if original is None:
                    try: outcome = call()
                    except BaseException as error: outcome = error
                else:
                    with mock.patch.object(inner.os, 'read', side_effect=original):
                        try: outcome = call()
                        except BaseException as error: outcome = error
            live_owned = []
            for fd, expected in opened:
                try:
                    if inner.descriptor_identity(os.fstat(fd)) == expected: live_owned.append(fd)
                except OSError: pass
            self.assertEqual(live_owned, [])
            for fd in retained:
                self.assertEqual(os.fstat(fd).st_ino, self.foreign_path.stat().st_ino)
                self.assertEqual(attempts.count(fd), 1)
            self.assertEqual(handlers, {s: signal.getsignal(s) for s in handlers})
            self.assertEqual(mask, signal.pthread_sigmask(signal.SIG_BLOCK, []))
            return outcome, attempts.count(injected[0])
        finally:
            for fd in retained:
                try: closing(fd)
                except OSError: pass
            # Explicit fixture cleanup if an assertion exposes a new leak.
            for fd, expected in opened:
                try:
                    if inner.descriptor_identity(os.fstat(fd)) == expected: closing(fd)
                except OSError: pass
            inner._UNCERTAIN.clear(); inner._UNCERTAIN.update(registry_before)

    def test_single_ordinary_and_control_before_effect_release_all_owned_fds(self):
        for boundary in ('capture_file', 'capture_inner'):
            for error in (OSError('before effect'), KeyboardInterrupt('before effect')):
                with self.subTest(boundary=boundary, error=type(error).__name__):
                    result, calls = self.exercise(error, boundary=boundary)
                    self.assertEqual(calls, 2)
                    if boundary == 'capture_inner' and isinstance(error, Exception):
                        self.assertEqual(result['reason'], 'SOURCE_INVALID')
                    else: self.assertIs(result, error)

    def test_original_business_and_control_identity_survives_ordinary_close_failure(self):
        for original in (ValueError('original business'), KeyboardInterrupt('original control')):
            with self.subTest(original=type(original).__name__):
                result, calls = self.exercise(OSError('close before effect'), original=original)
                self.assertIs(result, original); self.assertEqual(calls, 2)

    def test_later_cancel_before_effect_releases_then_propagates_control(self):
        cancel = KeyboardInterrupt('later close cancellation')
        result, calls = self.exercise(OSError('first before effect'), second=cancel)
        self.assertIs(result, cancel); self.assertEqual(calls, 3)
        business = ValueError('earlier business')
        result, calls = self.exercise(OSError('first before effect'), second=cancel, original=business)
        self.assertIs(result, cancel); self.assertEqual(calls, 3)
        original = KeyboardInterrupt('earlier cancellation')
        result, calls = self.exercise(OSError('first before effect'), second=cancel, original=original)
        self.assertIs(result, original); self.assertEqual(calls, 3)

    def test_after_effect_error_never_retries_released_fd(self):
        for error in (OSError('after effect'), KeyboardInterrupt('after effect')):
            with self.subTest(error=type(error).__name__):
                result, calls = self.exercise(error, effect=True)
                self.assertIs(result, error); self.assertEqual(calls, 1)

    def test_after_effect_reused_foreign_fd_is_not_retried_or_closed(self):
        for error in (OSError('after effect reused'), KeyboardInterrupt('after effect reused')):
            with self.subTest(error=type(error).__name__):
                result, calls = self.exercise(error, effect=True, reused=True)
                self.assertIs(result, error); self.assertEqual(calls, 1)

    def test_initial_cleanup_ownership_drift_does_not_close_foreign_fd(self):
        registry_before = dict(inner._UNCERTAIN)
        opening, closing = os.open, os.close; retained = []
        original = ValueError('original read failure')
        def read(fd, size):
            closing(fd)
            foreign = opening(self.foreign_path, os.O_RDONLY)
            if foreign != fd:
                os.dup2(foreign, fd); closing(foreign)
            retained.append(fd)
            raise original
        try:
            with mock.patch.object(inner.os, 'read', side_effect=read):
                with self.assertRaises(ValueError) as result:
                    inner.capture_file(self.root, 'record', 4096, private=True)
            self.assertIs(result.exception, original)
            self.assertEqual(os.fstat(retained[0]).st_ino, self.foreign_path.stat().st_ino)
        finally:
            for fd in retained: closing(fd)
            inner._UNCERTAIN.clear(); inner._UNCERTAIN.update(registry_before)


class DescriptorRecoveryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root = Path(temp.name); self.path = self.root / 'record'; self.path.write_bytes(b'finite private data')
        self.path.chmod(0o600); self.foreign = self.root / 'foreign'; self.foreign.write_bytes(b'foreign object')
        self.registry = dict(inner._UNCERTAIN)
        self.owned = []
        self.addCleanup(self.restore)

    def restore(self):
        for fd, expected in self.owned:
            try:
                if inner.descriptor_identity(os.fstat(fd)) == expected: os.close(fd)
            except OSError: pass
        inner._UNCERTAIN.clear(); inner._UNCERTAIN.update(self.registry)

    def descriptor(self):
        fd = os.open(self.path, os.O_RDONLY); expected = inner.descriptor_identity(os.fstat(fd))
        self.owned.append((fd, expected)); return fd, expected

    def assert_blocked(self, control=None):
        with mock.patch.object(inner.os, 'open', side_effect=AssertionError('new capture FD forbidden')) as opening:
            with self.assertRaises(KeyboardInterrupt if control is not None else ValueError) as got:
                inner.capture_file(self.root, 'record', 4096, private=True)
            if control is not None: self.assertIs(got.exception, control)
            if control is None:
                self.assertEqual(inner.capture_inner(self.root, self.root, {}, {}, None, None), inner.unknown('UNAVAILABLE'))
            else:
                with self.assertRaises(KeyboardInterrupt) as got:
                    inner.capture_inner(self.root, self.root, {}, {}, None, None)
                self.assertIs(got.exception, control)
            opening.assert_not_called()

    def test_initial_query_error_is_registered_before_rethrow_and_control_stays_sticky(self):
        for fault in (OSError(5, 'initial identity IO'), KeyboardInterrupt('initial identity control')):
            with self.subTest(fault=type(fault).__name__):
                querying, closing = os.fstat, os.close
                inode, unknown, close_calls = self.path.stat().st_ino, [], []
                def query(fd):
                    info = querying(fd)
                    if info.st_ino == inode and not unknown:
                        unknown.append(fd); raise fault
                    return info
                def close(fd): close_calls.append(fd); return closing(fd)
                with mock.patch.object(inner.os, 'fstat', side_effect=query),                      mock.patch.object(inner.os, 'close', side_effect=close):
                    with self.assertRaises(type(fault)) as got:
                        inner.capture_file(self.root, 'record', 4096, private=True)
                self.assertIs(got.exception, fault)
                fd = unknown[0]; row = inner._UNCERTAIN[fd]
                self.assertIsNone(row['identity']); self.assertIs(row['error'], fault)
                control = fault if not isinstance(fault, Exception) else None
                self.assertIs(row['control'], control); self.assertNotIn(fd, close_calls)
                self.assertEqual(querying(fd).st_ino, inode); self.assert_blocked(control)
                closing(fd); self.assertIn(fd, inner._UNCERTAIN); self.assert_blocked(control)
                inner._UNCERTAIN.clear(); inner._UNCERTAIN.update(self.registry)

    def test_single_cleanup_query_error_recovers_without_unknown_close(self):
        for fault in (OSError('one-shot query'), KeyboardInterrupt('one-shot query')):
            with self.subTest(fault=type(fault).__name__):
                opening, closing, querying, releasing = os.open, os.close, os.fstat, inner.release_owned
                opened, queried, closed = [], [], []
                def op(*args, **kwargs):
                    fd = opening(*args, **kwargs); opened.append((fd, inner.descriptor_identity(querying(fd)))); return fd
                def release(fd, expected):
                    if not queried:
                        def query(handle):
                            if handle == fd:
                                queried.append(handle)
                                if len(queried) == 1: raise fault
                            return querying(handle)
                        with mock.patch.object(inner.os, 'fstat', side_effect=query):
                            return releasing(fd, expected)
                    return releasing(fd, expected)
                def close(fd): closed.append(fd); return closing(fd)
                with mock.patch.object(inner.os, 'open', side_effect=op),                      mock.patch.object(inner.os, 'close', side_effect=close),                      mock.patch.object(inner, 'release_owned', side_effect=release):
                    with self.assertRaises(type(fault)) as got:
                        inner.capture_file(self.root, 'record', 4096, private=True)
                self.assertIs(got.exception, fault); self.assertEqual(len(queried), 2)
                self.assertEqual(closed.count(queried[0]), 1); self.assertEqual(inner._UNCERTAIN, {})
                for fd, expected in opened:
                    with self.assertRaises(OSError): querying(fd)

    def test_persistent_query_retains_identity_and_blocks_later_healthy_capture(self):
        for fault in (OSError('persistent query'), KeyboardInterrupt('persistent query')):
            with self.subTest(fault=type(fault).__name__):
                fd, expected = self.descriptor()
                with mock.patch.object(inner.os, 'fstat', side_effect=fault) as query,                      mock.patch.object(inner.os, 'close', side_effect=AssertionError('no identity proof')) as closing:
                    result = inner.release_owned(fd, expected)
                self.assertIs(result, fault); self.assertEqual(query.call_count, 3); closing.assert_not_called()
                self.assertEqual(inner.descriptor_identity(os.fstat(fd)), expected)
                row = inner._UNCERTAIN[fd]
                self.assertEqual(row['identity'], expected); self.assertIs(row['error'], fault)
                self.assertIs(row['control'], fault if not isinstance(fault, Exception) else None)
                self.assert_blocked(fault if not isinstance(fault, Exception) else None)
                os.close(fd)  # Fixture release after measuring the live exact object.
                self.assertIn(fd, inner._UNCERTAIN); self.assert_blocked(fault if not isinstance(fault, Exception) else None)
                inner._UNCERTAIN.clear(); inner._UNCERTAIN.update(self.registry)

    def test_persistent_close_retains_identity_and_blocks_later_healthy_capture(self):
        for fault in (OSError('persistent close'), KeyboardInterrupt('persistent close')):
            with self.subTest(fault=type(fault).__name__):
                fd, expected = self.descriptor()
                with mock.patch.object(inner.os, 'close', side_effect=fault) as closing:
                    result = inner.release_owned(fd, expected)
                self.assertIs(result, fault); self.assertEqual(closing.call_count, 3)
                self.assertEqual(inner.descriptor_identity(os.fstat(fd)), expected)
                self.assertEqual(inner._UNCERTAIN[fd]['identity'], expected)
                self.assert_blocked(fault if not isinstance(fault, Exception) else None)
                os.close(fd); self.assertIn(fd, inner._UNCERTAIN)
                inner._UNCERTAIN.clear(); inner._UNCERTAIN.update(self.registry)

    def test_query_later_control_uses_third_slot_without_losing_first_error(self):
        fd, expected = self.descriptor(); query = os.fstat
        first, control = OSError('first query'), KeyboardInterrupt('later query')
        calls = []
        def fstat(handle):
            calls.append(handle)
            if len(calls) == 1: raise first
            if len(calls) == 2: raise control
            return query(handle)
        with mock.patch.object(inner.os, 'fstat', side_effect=fstat): result = inner.release_owned(fd, expected)
        self.assertIs(result, control); self.assertEqual(len(calls), 3)
        self.assertEqual(inner._UNCERTAIN, {})
        with self.assertRaises(OSError): query(fd)

    def test_unknown_or_different_identity_never_closes_or_deletes_ambiguity(self):
        for expected in (None, (0, 0, 0, 0)):
            with self.subTest(expected=expected):
                fd, actual = self.descriptor()
                with mock.patch.object(inner.os, 'close', side_effect=AssertionError('foreign/unknown close')) as closing:
                    result = inner.release_owned(fd, expected)
                self.assertIsInstance(result, ValueError); closing.assert_not_called()
                self.assertEqual(inner._UNCERTAIN[fd]['identity'], expected)
                self.assertEqual(inner.descriptor_identity(os.fstat(fd)), actual); self.assert_blocked()
                os.close(fd); self.assertIn(fd, inner._UNCERTAIN)
                inner._UNCERTAIN.clear(); inner._UNCERTAIN.update(self.registry)

    def test_after_effect_ebadf_retires_but_reused_foreign_identity_is_retained(self):
        for reused in (False, True):
            with self.subTest(reused=reused):
                fd, expected = self.descriptor(); opening, closing = os.open, os.close
                fault = OSError('after effect'); foreign = []
                def close(handle):
                    self.assertEqual(handle, fd); closing(handle)
                    if reused:
                        replacement = opening(self.foreign, os.O_RDONLY)
                        if replacement != fd:
                            os.dup2(replacement, fd); closing(replacement)
                        foreign.append(fd)
                    raise fault
                try:
                    with mock.patch.object(inner.os, 'close', side_effect=close) as mocked:
                        result = inner.release_owned(fd, expected)
                    self.assertIs(result, fault); self.assertEqual(mocked.call_count, 1)
                    if reused:
                        self.assertEqual(os.fstat(fd).st_ino, self.foreign.stat().st_ino)
                        self.assertEqual(inner._UNCERTAIN[fd]['identity'], expected); self.assert_blocked()
                    else: self.assertEqual(inner._UNCERTAIN, {})
                finally:
                    for handle in foreign: closing(handle)
                    inner._UNCERTAIN.clear(); inner._UNCERTAIN.update(self.registry)

    def test_persistent_cleanup_with_original_cause_keeps_control_and_ownership(self):
        for original in (ValueError('first business'), KeyboardInterrupt('first control')):
            with self.subTest(original=type(original).__name__):
                actual_release, close = inner.release_owned, os.close
                persistent = OSError('persistent close'); target = []
                def release(fd, expected):
                    if not target:
                        target.append((fd, expected))
                        with mock.patch.object(inner.os, 'close', side_effect=persistent):
                            return actual_release(fd, expected)
                    return actual_release(fd, expected)
                with mock.patch.object(inner.os, 'read', side_effect=original),                      mock.patch.object(inner, 'release_owned', side_effect=release):
                    with self.assertRaises(type(original)) as got:
                        inner.capture_file(self.root, 'record', 4096, private=True)
                self.assertIs(got.exception, original)
                fd, expected = target[0]
                self.assertEqual(inner.descriptor_identity(os.fstat(fd)), expected)
                self.assertIs(inner._UNCERTAIN[fd]['error'], persistent)
                self.assert_blocked(); close(fd)
                inner._UNCERTAIN.clear(); inner._UNCERTAIN.update(self.registry)


if __name__ == '__main__': unittest.main()
