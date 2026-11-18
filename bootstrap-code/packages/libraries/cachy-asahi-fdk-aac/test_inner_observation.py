#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded inert FDK recorder controls; no compiler or native builder."""
import copy
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fdk_observer_fixture', BASE/'inner_observation.py')
observer = importlib.util.module_from_spec(spec); spec.loader.exec_module(observer)
PINS = {key: 'a'*64 for key in observer.BINDINGS}


class RecorderTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name); output = root/'out'; output.mkdir(mode=0o700)
        return root, output, observer.Recorder(output, PINS)

    def durable(self, output):
        return observer.loads((output/'fdk-inner/observation.json').read_bytes())

    def test_phase_entered_and_not_passed_and_no_compiler_inference(self):
        _, output, recorder = self.fixture()
        self.assertEqual(recorder.snapshot()['phase'], 'UNKNOWN')
        for phase in observer.PHASES[1:]:
            recorder.phase(phase); self.assertEqual(self.durable(output)['phase'], phase)
        row = self.durable(output)
        self.assertEqual(row['publication'], 'NOT ACCEPTED')
        self.assertNotIn('status', row)
        self.assertFalse(row['compiler_attempted'])
        self.assertEqual(row['compiler_attempt_count'], 0)
        self.assertIsNone(row['first_compiler_natural'])

    def test_natural_nonzero_then_cancel_retains_exact_first_business_fact(self):
        _, output, recorder = self.fixture(); recorder.phase('BUILD')
        recorder.attempt('COMPILE', 0); recorder.returned('COMPILE', 0, 7)
        first = copy.deepcopy(recorder.snapshot()['first_failure'])
        recorder.fail('UNKNOWN', KeyboardInterrupt())
        recorder.phase('PACKAGE')
        row = self.durable(output)
        self.assertEqual(row['first_failure'], first)
        self.assertEqual(first['predicate'], 'COMPILER_NONZERO')
        self.assertEqual(first['command']['returncode'], 7)
        self.assertTrue(row['cancelled']); self.assertEqual(row, recorder.snapshot())
        child = observer.Recorder(output, PINS); child.phase('PREPARE')
        self.assertEqual(child.snapshot()['phase'], 'PACKAGE')
        self.assertEqual(child.snapshot()['first_failure'], first)
        self.assertTrue(child.snapshot()['cancelled'])

    def test_timeout_has_no_natural_return(self):
        _, output, recorder = self.fixture(); recorder.phase('BUILD'); recorder.attempt('LINK', 0)
        error = type('TimeoutExpired', (Exception,), {})('PRIVATE')
        recorder.fail('COMPILER_TIMEOUT', error, observer.command('LINK', 0))
        row = self.durable(output)
        self.assertEqual(row['compiler_natural_count'], 0)
        self.assertIsNone(row['first_compiler_natural'])
        self.assertEqual(row['first_failure']['reason'], 'TIMEOUT')
        self.assertNotIn('PRIVATE', json.dumps(row))

    def test_shared_four_thread_recorder_preserves_all_observed_facts(self):
        _, output, recorder = self.fixture(); recorder.phase('BUILD')
        def actor(index):
            recorder.attempt('COMPILE', index); recorder.returned('COMPILE', index, 0)
        with ThreadPoolExecutor(max_workers=4) as pool: list(pool.map(actor, range(16)))
        row = self.durable(output)
        self.assertEqual(row['compiler_attempt_count'], 16)
        self.assertEqual(row['compiler_natural_count'], 16)
        self.assertIsNone(row['first_failure']); self.assertFalse(row['write_failed'])
        self.assertLessEqual(len(observer.encoded(row)), observer.LIMIT)

    def test_cache_precedes_diagnostic_read_interrupt_and_failure_is_sticky(self):
        _, output, recorder = self.fixture(); recorder.phase('BUILD'); recorder.attempt('COMPILE', 0)
        control = KeyboardInterrupt()
        with mock.patch.object(observer, 'regular_at', side_effect=control):
            with self.assertRaises(KeyboardInterrupt) as caught: recorder.returned('COMPILE', 0, 7)
        self.assertIs(caught.exception, control)
        row = recorder.snapshot()
        self.assertEqual(row['first_failure']['predicate'], 'COMPILER_NONZERO')
        self.assertEqual(row['first_failure']['command']['returncode'], 7)
        self.assertEqual(row['compiler_natural_count'], 1)
        self.assertTrue(row['cancelled']); self.assertTrue(row['write_failed'])
        self.assertFalse((output/'fdk-inner/observation.json').exists())
        child = observer.Recorder(output, PINS); child.phase('PACKAGE')
        after = child.snapshot()
        self.assertEqual(after['first_failure'], row['first_failure'])
        self.assertEqual(after['compiler_natural_count'], 1)
        self.assertTrue(after['write_failed']); self.assertTrue(after['cancelled'])
        refused = observer.loads((output/'fdk-inner/.lock').read_bytes())
        self.assertTrue(refused['write_failed'])

    def test_lock_close_error_before_release_cannot_leave_healthy_record(self):
        _, output, recorder = self.fixture()
        recorder.phase('BUILD'); recorder.attempt('COMPILE', 0)
        original = observer.os.close; retained = []
        def closing(fd):
            if not retained and os.readlink(f'/proc/self/fd/{fd}').endswith('/fdk-inner/.lock'):
                retained.append(fd); raise OSError('injected before close')
            original(fd)
        try:
            with mock.patch.object(observer.os, 'close', side_effect=closing):
                recorder.returned('COMPILE', 0, 0)
            self.assertTrue(recorder.snapshot()['write_failed'])
            self.assertFalse((output/'fdk-inner/observation.json').exists())
            refusal = observer.loads((output/'fdk-inner/.lock').read_bytes())
            self.assertTrue(refusal['write_failed'])
            self.assertEqual(refusal['compiler_natural_count'], 1)
            child = observer.Recorder(output, PINS)
            self.assertTrue(child.snapshot()['write_failed'])
        finally:
            for fd in retained:
                try: os.fstat(fd)
                except OSError: continue
                original(fd)

    def test_temporary_cleanup_control_latches_refusal_and_finishes_owned_cleanup(self):
        _, output, recorder = self.fixture(); recorder.phase('BUILD')
        recorder.attempt('COMPILE',0); recorder.returned('COMPILE',0,0); recorder.attempt('COMPILE',1)
        opening, closing, writing, unlinking = observer.os.open, observer.os.close, observer.os.write, observer.os.unlink
        owned, events = {}, []; control = KeyboardInterrupt()
        def opened(path,*args,**kwargs):
            fd = opening(path,*args,**kwargs); owned[fd] = str(path); return fd
        def closed(fd):
            closing(fd); owned.pop(fd,None)
        def write(fd,data):
            if owned.get(fd,'').startswith('.observation-') and not events:
                events.append('write'); raise OSError('injected temporary write')
            return writing(fd,data)
        def unlink(path,*args,**kwargs):
            if str(path).startswith('.observation-') and len(events) == 1:
                events.append('unlink'); raise control
            return unlinking(path,*args,**kwargs)
        with mock.patch.object(observer.os,'open',side_effect=opened),mock.patch.object(observer.os,'close',side_effect=closed), \
             mock.patch.object(observer.os,'write',side_effect=write),mock.patch.object(observer.os,'unlink',side_effect=unlink):
            with self.assertRaises(KeyboardInterrupt) as caught: recorder.returned('COMPILE',1,7)
        self.assertIs(caught.exception,control); self.assertEqual(owned,{})
        row = recorder.snapshot(); self.assertTrue(row['cancelled']); self.assertTrue(row['write_failed'])
        self.assertEqual(row['first_failure']['command']['returncode'],7)
        self.assertFalse((output/'fdk-inner/observation.json').exists())
        self.assertEqual(list((output/'fdk-inner').glob('.observation-*')),[])
        marker = observer.loads((output/'fdk-inner/.lock').read_bytes())
        self.assertTrue(marker['cancelled']); self.assertEqual(marker['first_failure'],row['first_failure'])
        child = observer.Recorder(output,PINS)
        self.assertTrue(child.snapshot()['cancelled']); self.assertTrue(child.snapshot()['write_failed'])

    def test_owned_close_retries_before_effect_and_retains_first_control(self):
        root, _, _ = self.fixture(); path = root/'owned'; path.write_bytes(b'bound')
        fd = os.open(path,os.O_RDONLY); original = observer.os.close; errors = [OSError('first'),KeyboardInterrupt()]
        def closing(value):
            if value == fd and errors: raise errors.pop(0)
            original(value)
        with mock.patch.object(observer.os,'close',side_effect=closing),self.assertRaises(KeyboardInterrupt):
            observer.close_owned(fd)
        with self.assertRaises(OSError): os.fstat(fd)

    def test_owned_close_never_retries_foreign_reused_descriptor(self):
        root, _, _ = self.fixture(); first = root/'first'; second = root/'second'
        first.write_bytes(b'first'); second.write_bytes(b'foreign')
        fd = os.open(first,os.O_RDONLY); original = observer.os.close; foreign = []
        def closing(value):
            original(value)
            if value == fd and not foreign:
                new = os.open(second,os.O_RDONLY); foreign.append(new)
                self.assertEqual(new,fd); raise OSError('after close and reuse')
        try:
            with mock.patch.object(observer.os,'close',side_effect=closing),self.assertRaises(OSError):
                observer.close_owned(fd)
            self.assertEqual(os.read(fd,7),b'foreign')
        finally:
            for item in foreign:
                original(item); observer._UNCERTAIN.pop(item, None)

    def test_failed_initial_query_never_adopts_later_identity(self):
        root, _, _ = self.fixture(); path = root/'owned'; path.write_bytes(b'owned')
        fd = os.open(path, os.O_RDONLY); querying, closing = os.fstat, os.close
        before = querying(fd); first = OSError(5, 'query EIO'); calls, closed = [], []
        def query(value):
            if value == fd:
                calls.append(value)
                if len(calls) == 1: raise first
            return querying(value)
        def close(value):
            closed.append(value); closing(value)
        try:
            with mock.patch.object(observer.os, 'fstat', side_effect=query), \
                 mock.patch.object(observer.os, 'close', side_effect=close), self.assertRaises(OSError) as caught:
                observer.close_owned(fd)
            self.assertIs(caught.exception, first); self.assertEqual(len(calls), 3)
            self.assertNotIn(fd, closed); self.assertEqual(querying(fd).st_ino, before.st_ino)
            self.assertIsNone(observer._UNCERTAIN[fd]['identity'])
            self.assertIs(observer._UNCERTAIN[fd]['error'], first)
            with self.assertRaises(OSError) as later: observer.close_owned(fd)
            self.assertIs(later.exception, first)
            self.assertEqual(querying(fd).st_ino, before.st_ino)
            self.assertIsNone(observer._UNCERTAIN[fd]['identity'])
        finally:
            try: current = querying(fd)
            except OSError as error:
                self.assertEqual(error.errno, 9)
            else:
                self.assertEqual((current.st_dev, current.st_ino), (before.st_dev, before.st_ino)); closing(fd)
            observer._UNCERTAIN.pop(fd, None)

    def test_failed_initial_query_foreign_reuse_retains_unknown_and_refusal(self):
        for control in (False, True):
            with self.subTest(control=control):
                root, output, recorder = self.fixture(); recorder.phase('BUILD')
                recorder.attempt('COMPILE', 0); recorder.returned('COMPILE', 0, 7)
                first_path, foreign_path = root/'owned', root/'foreign'
                first_path.write_bytes(b'owned'); foreign_path.write_bytes(b'foreign')
                fd = os.open(first_path, os.O_RDONLY); querying, closing = os.fstat, os.close
                original = querying(fd); foreign = foreign_path.stat(); calls, closed = [], []
                self.assertNotEqual((original.st_dev, original.st_ino), (foreign.st_dev, foreign.st_ino))
                first = KeyboardInterrupt() if control else OSError(5, 'initial query EIO')
                def query(value):
                    if value == fd:
                        calls.append(value)
                        if len(calls) == 1:
                            closing(fd); reused = os.open(foreign_path, os.O_RDONLY)
                            self.assertEqual(reused, fd); raise first
                    return querying(value)
                def close(value):
                    closed.append(value); closing(value)
                try:
                    with mock.patch.object(observer.os, 'fstat', side_effect=query), \
                         mock.patch.object(observer.os, 'close', side_effect=close), self.assertRaises(type(first)) as caught:
                        observer.close_owned(fd)
                    self.assertIs(caught.exception, first); self.assertEqual(calls, [fd]*3)
                    self.assertNotIn(fd, closed); current = querying(fd)
                    self.assertEqual((current.st_dev, current.st_ino), (foreign.st_dev, foreign.st_ino))
                    self.assertEqual(os.read(fd, 7), b'foreign')
                    retained = observer._UNCERTAIN[fd]
                    self.assertIsNone(retained['identity']); self.assertIs(retained['error'], first)
                    self.assertIs(retained['control'], first if control else None)
                    with self.assertRaises(type(first)) as later: observer.close_owned(fd)
                    self.assertIs(later.exception, first); self.assertIsNone(retained['identity'])
                    recorder.phase('PACKAGE'); row = recorder.snapshot()
                    self.assertTrue(row['write_failed']); self.assertEqual(row['cancelled'], control)
                    self.assertEqual(row['first_failure']['command']['returncode'], 7)
                    self.assertFalse((output/'fdk-inner/observation.json').exists())
                    marker = observer.loads((output/'fdk-inner/.lock').read_bytes())
                    self.assertTrue(marker['write_failed']); self.assertEqual(marker['first_failure'], row['first_failure'])
                    child = observer.Recorder(output, PINS)
                    self.assertTrue(child.snapshot()['write_failed']); self.assertEqual(child.snapshot()['cancelled'], control)
                    self.assertFalse((output/'fdk-inner/observation.json').exists())
                finally:
                    try: current = querying(fd)
                    except OSError as error:
                        self.assertEqual(error.errno, 9)
                    else:
                        self.assertEqual((current.st_dev, current.st_ino), (foreign.st_dev, foreign.st_ino)); closing(fd)
                    observer._UNCERTAIN.pop(fd, None)

    def test_unknown_ownership_queries_can_prove_ebadf_without_close(self):
        for control in (False, True):
            with self.subTest(control=control):
                root, _, _ = self.fixture(); path = root/'owned'; path.write_bytes(b'owned')
                fd = os.open(path, os.O_RDONLY); querying, closing = os.fstat, os.close
                first = KeyboardInterrupt() if control else OSError(5, 'initial query EIO'); calls = []
                def query(value):
                    if value == fd:
                        calls.append(value)
                        if len(calls) == 1: raise first
                        closing(fd)
                    return querying(value)
                with mock.patch.object(observer.os, 'fstat', side_effect=query), \
                     mock.patch.object(observer.os, 'close', side_effect=AssertionError('unknown descriptor close')), \
                     self.assertRaises(type(first)) as caught:
                    observer.close_owned(fd)
                self.assertIs(caught.exception, first); self.assertEqual(calls, [fd, fd])
                self.assertNotIn(fd, observer._UNCERTAIN)
                with self.assertRaises(OSError) as ended: querying(fd)
                self.assertEqual(ended.exception.errno, 9)

    def test_post_close_query_eio_is_not_release_proof_and_retry_recovers(self):
        root, _, _ = self.fixture(); path = root/'owned'; path.write_bytes(b'owned')
        fd = os.open(path, os.O_RDONLY); querying, closing = os.fstat, os.close
        first = OSError(5, 'close EIO'); calls = [0, 0]
        def query(value):
            if value == fd:
                calls[0] += 1
                if calls[0] == 2: raise OSError(5, 'query EIO')
            return querying(value)
        def close(value):
            if value == fd:
                calls[1] += 1
                if calls[1] == 1: raise first
            closing(value)
        with mock.patch.object(observer.os, 'fstat', side_effect=query), \
             mock.patch.object(observer.os, 'close', side_effect=close), self.assertRaises(OSError) as caught:
            observer.close_owned(fd)
        self.assertIs(caught.exception, first); self.assertEqual(calls, [3, 2])
        self.assertNotIn(fd, observer._UNCERTAIN)
        with self.assertRaises(OSError): querying(fd)

    def test_post_close_persistent_query_retains_known_identity_and_business_exception(self):
        root, _, _ = self.fixture(); path = root/'owned'; path.write_bytes(b'owned')
        fd = os.open(path, os.O_RDONLY); querying, closing = os.fstat, os.close
        before = querying(fd); first = OSError(5, 'close EIO'); calls = [0, 0]
        def query(value):
            if value == fd:
                calls[0] += 1
                if calls[0] > 1: raise OSError(5, 'query EIO')
            return querying(value)
        def close(value):
            if value == fd: calls[1] += 1; raise first
            closing(value)
        business = ValueError('business remains first')
        try:
            with mock.patch.object(observer.os, 'fstat', side_effect=query), \
                 mock.patch.object(observer.os, 'close', side_effect=close), self.assertRaises(ValueError) as caught:
                try: raise business
                finally: observer.close_owned(fd)
            self.assertIs(caught.exception, business); self.assertEqual(calls, [3, 1])
            self.assertEqual(querying(fd).st_ino, before.st_ino)
            self.assertEqual(observer._UNCERTAIN[fd]['identity'][:2], (before.st_dev, before.st_ino))
            self.assertIs(observer._UNCERTAIN[fd]['error'], first)
        finally:
            self.assertEqual(querying(fd).st_ino, before.st_ino)
            closing(fd); observer._UNCERTAIN.pop(fd, None)

    def test_persistent_query_retains_unknown_ownership_and_refuses_new_recorder(self):
        root, output, recorder = self.fixture(); path = root/'owned'; path.write_bytes(b'owned')
        fd = os.open(path, os.O_RDONLY); querying, closing = os.fstat, os.close
        original = querying(fd); first = OSError(5, 'query EIO'); calls = []
        def query(value):
            if value == fd: calls.append(value); raise first
            return querying(value)
        try:
            with mock.patch.object(observer.os, 'fstat', side_effect=query), self.assertRaises(OSError) as caught:
                observer.close_owned(fd)
            self.assertIs(caught.exception, first); self.assertEqual(len(calls), 3)
            self.assertEqual(querying(fd).st_ino, original.st_ino)
            self.assertIsNone(observer._UNCERTAIN[fd]['identity'])
            self.assertIs(observer._UNCERTAIN[fd]['error'], first)
            child = observer.Recorder(output, PINS)
            self.assertTrue(child.snapshot()['write_failed'])
            self.assertFalse((output/'fdk-inner/observation.json').exists())
            self.assertTrue(observer.loads((output/'fdk-inner/.lock').read_bytes())['write_failed'])
            # A later query cannot reconstruct the original unknown identity.
            with self.assertRaises(OSError): observer.close_owned(fd)
            self.assertEqual(querying(fd).st_ino, original.st_ino)
        finally:
            self.assertEqual(querying(fd).st_ino, original.st_ino)
            closing(fd); observer._UNCERTAIN.pop(fd, None)

    def test_persistent_lock_close_retains_each_live_fd_and_first_business_cause(self):
        _, output, recorder = self.fixture(); recorder.phase('BUILD'); recorder.attempt('COMPILE', 0)
        opening, closing, querying = os.open, os.close, os.fstat
        lock_ids, calls = {}, []
        def opened(path, *args, **kwargs):
            fd = opening(path, *args, **kwargs)
            if path == '.lock': lock_ids[fd] = querying(fd)
            return fd
        def close(value):
            if value in lock_ids: calls.append(value); raise OSError(5, 'persistent close EIO')
            closing(value)
        try:
            with mock.patch.object(observer.os, 'open', side_effect=opened), \
                 mock.patch.object(observer.os, 'close', side_effect=close), self.assertRaises(RuntimeError):
                recorder.returned('COMPILE', 0, 7)
            self.assertEqual(len(lock_ids), 2); self.assertEqual(len(calls), 6)
            for fd, before in lock_ids.items():
                self.assertEqual(querying(fd).st_ino, before.st_ino)
                self.assertEqual(observer._UNCERTAIN[fd]['identity'][:2], (before.st_dev, before.st_ino))
            row = recorder.snapshot(); self.assertTrue(row['write_failed'])
            self.assertEqual(row['first_failure']['command']['returncode'], 7)
            self.assertFalse((output/'fdk-inner/observation.json').exists())
            with self.assertRaises(RuntimeError): observer.Recorder(output, PINS)
            marker = observer.loads((output/'fdk-inner/.lock').read_bytes())
            self.assertTrue(marker['write_failed'])
            self.assertEqual(marker['first_failure'], row['first_failure'])
            self.assertFalse((output/'fdk-inner/observation.json').exists())
        finally:
            for fd, before in lock_ids.items():
                self.assertEqual(querying(fd).st_ino, before.st_ino)
                closing(fd); observer._UNCERTAIN.pop(fd, None)

    def test_query_control_remains_sticky_with_prior_business_error(self):
        root, output, recorder = self.fixture(); recorder.phase('BUILD')
        recorder.attempt('COMPILE', 0); recorder.returned('COMPILE', 0, 7)
        path = root/'owned'; path.write_bytes(b'owned'); fd = os.open(path, os.O_RDONLY)
        querying, closing = os.fstat, os.close; before = querying(fd); control = KeyboardInterrupt()
        def query(value):
            if value == fd: raise control
            return querying(value)
        try:
            with mock.patch.object(observer.os, 'fstat', side_effect=query):
                with self.assertRaises(KeyboardInterrupt) as caught:
                    try: raise ValueError('earlier business error')
                    finally: observer.close_owned(fd)
            self.assertIs(caught.exception, control)
            self.assertIs(observer._UNCERTAIN[fd]['control'], control)
            recorder.phase('PACKAGE'); row = recorder.snapshot()
            self.assertTrue(row['cancelled']); self.assertTrue(row['write_failed'])
            self.assertEqual(row['first_failure']['command']['returncode'], 7)
            self.assertFalse((output/'fdk-inner/observation.json').exists())
        finally:
            self.assertEqual(querying(fd).st_ino, before.st_ino)
            closing(fd); observer._UNCERTAIN.pop(fd, None)

    def test_final_close_failure_revokes_record_and_survives_new_process_state(self):
        _, output, recorder = self.fixture(); root_method = recorder._root
        close = observer.os.close; roots = []; fired = []
        def root():
            pair = root_method(); roots.append(pair[0]); return pair
        def closing(fd):
            close(fd)
            if roots and fd == roots[0] and not fired:
                fired.append(True); raise OSError('PRIVATE final close')
        with mock.patch.object(recorder, '_root', side_effect=root), mock.patch.object(observer.os, 'close', side_effect=closing):
            recorder.phase('BUILD')
        self.assertTrue(fired); self.assertTrue(recorder.snapshot()['write_failed'])
        self.assertFalse((output/'fdk-inner/observation.json').exists())
        child = observer.Recorder(output, PINS)
        self.assertTrue(child.snapshot()['write_failed'])
        self.assertTrue(self.durable(output)['write_failed'])

    def test_temp_substitution_is_refused_and_revoked(self):
        _, output, recorder = self.fixture(); replace = observer.os.replace; replaced = []
        def swapping(source, destination, **options):
            directory = options['src_dir_fd']; observer.os.unlink(source, dir_fd=directory)
            fd = observer.os.open(source, observer.os.O_CREAT|observer.os.O_EXCL|observer.os.O_WRONLY, 0o600, dir_fd=directory)
            try: observer.os.write(fd, observer.encoded(recorder.snapshot()))
            finally: observer.os.close(fd)
            replaced.append(True); return replace(source, destination, **options)
        with mock.patch.object(observer.os, 'replace', side_effect=swapping): recorder.phase('BUILD')
        self.assertTrue(replaced); self.assertTrue(recorder.snapshot()['write_failed'])
        self.assertFalse((output/'fdk-inner/observation.json').exists())

    def test_ancestry_alias_cannot_write_foreign_namespace(self):
        root, _, _ = self.fixture(); selected = root/'selected'; foreign = root/'foreign'
        output = selected/'out'; output.mkdir(parents=True, mode=0o700)
        other = foreign/'out'; other.mkdir(parents=True, mode=0o700)
        opening = observer.os.open; swapped = []
        def alias(name, *args, **options):
            if name == 'selected' and 'dir_fd' in options and not swapped:
                selected.rename(root/'original'); selected.symlink_to(foreign, target_is_directory=True); swapped.append(True)
            return opening(name, *args, **options)
        with mock.patch.object(observer.os, 'open', side_effect=alias), self.assertRaises(RuntimeError): observer.Recorder(output, PINS)
        self.assertTrue(swapped); self.assertFalse((other/'fdk-inner').exists())

    def test_strict_schema_has_no_subject_or_counter_coercion(self):
        _, _, recorder = self.fixture(); row = recorder.snapshot()
        cases = []
        for key, value in [('phase','PASS'),('compiler_attempt_count',True),('compiler_natural_count',1),('compiler_attempted',True),('publication','PASS'),('raw','PRIVATE')]:
            changed = copy.deepcopy(row); changed[key] = value; cases.append(changed)
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(ValueError): observer.validate(changed)
        with self.assertRaises(ValueError): observer.loads(b'{"schema_version":1,"schema_version":1}')
        with self.assertRaises(ValueError): observer.loads(b'{"value":NaN}')
        with self.assertRaises(ValueError): observer.loads(b'x'*(observer.LIMIT+1))
        recorder.fail('UNKNOWN', KeyboardInterrupt()); contradiction=recorder.snapshot(); contradiction['cancelled']=False
        with self.assertRaises(ValueError): observer.validate(contradiction)

    def test_duplicate_return_is_not_counted_twice(self):
        _, _, recorder = self.fixture(); recorder.attempt('COMPILE', 0); recorder.returned('COMPILE', 0, 0)
        before = recorder.snapshot()
        with self.assertRaises(ValueError): recorder.returned('COMPILE', 0, 0)
        self.assertEqual(recorder.snapshot(), before)
        for kind,index in [('COMPILE',395),('LINK',2),('COMPILE',True)]:
            with self.subTest(kind=kind,index=index), self.assertRaises(ValueError): recorder.attempt(kind,index)

    def test_actual_private_sigint_during_read_preserves_return_and_business_cause(self):
        root, output, _ = self.fixture()
        code = '''import importlib.util,json,os,signal,sys
s=importlib.util.spec_from_file_location('private_observer',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
r=m.Recorder(sys.argv[2],dict.fromkeys(m.BINDINGS,'a'*64));r.phase('BUILD');r.attempt('COMPILE',0)
read,close=m.os.read,m.os.close;sent=[]
def interrupted(fd,n):
 if not sent:sent.append(True);os.kill(os.getpid(),signal.SIGINT)
 return read(fd,n)
def closing(fd):
 close(fd)
 if isinstance(sys.exc_info()[1],KeyboardInterrupt):raise OSError('private close error')
m.os.read,m.os.close=interrupted,closing
try:r.returned('COMPILE',0,7)
except KeyboardInterrupt:pass
else:raise AssertionError('signal did not propagate')
print(json.dumps(r.snapshot()))
'''
        result = subprocess.run([sys.executable,'-I','-B','-S','-c',code,
            str(BASE/'inner_observation.py'),str(output)],stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(result.stderr); self.assertLessEqual(len(result.stdout),observer.LIMIT)
        row=observer.loads(result.stdout)
        self.assertTrue(row['cancelled']); self.assertTrue(row['write_failed'])
        self.assertEqual(row['first_failure']['predicate'],'COMPILER_NONZERO')
        self.assertEqual(row['first_failure']['command']['returncode'],7)
        self.assertTrue(row['first_compiler_natural']['natural'])
        self.assertEqual(row['compiler_natural_count'],1)

    def test_phase_cli_does_not_mask_controls_or_introduce_ordinary_recipe_failure(self):
        with mock.patch.object(sys,'argv',['observer','phase','PREPARE']), \
                mock.patch.object(observer,'Recorder',side_effect=OSError('private observation failure')):
            self.assertEqual(observer.main(),0)
        control=KeyboardInterrupt()
        with mock.patch.object(sys,'argv',['observer','phase','PREPARE']), \
                mock.patch.object(observer,'Recorder',side_effect=control):
            with self.assertRaises(KeyboardInterrupt) as caught: observer.main()
        self.assertIs(caught.exception,control)

    def test_single_attempt_cannot_claim_a_different_natural_identity(self):
        _,_,recorder=self.fixture();recorder.attempt('COMPILE',0);recorder.returned('COMPILE',0,7)
        changed=recorder.snapshot();changed['first_compiler_natural']['index']=1
        with self.assertRaises(ValueError): observer.validate(changed)
        changed=recorder.snapshot();changed['first_failure']['command']['returncode']=9
        with self.assertRaises(ValueError): observer.validate(changed)


if __name__ == '__main__':
    unittest.main()
