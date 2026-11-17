#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Host/guest canonical-byte agreement, not actual before/after acceptance."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import unittest

resource.setrlimit(resource.RLIMIT_AS, (512 * 1024**2,) * 2)
resource.setrlimit(resource.RLIMIT_CPU, (120,) * 2)
resource.setrlimit(resource.RLIMIT_FSIZE, (4 * 1024**2,) * 2)
resource.setrlimit(resource.RLIMIT_NOFILE, (128,) * 2)
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CURRENT = None
CLEANUP_GROUP = None
ATTEMPTS = []
GUEST_LAUNCHES = 0


def fence(event, args):
    global GUEST_LAUNCHES
    if event == 'os.killpg' and CLEANUP_GROUP is not None and args == (CLEANUP_GROUP, signal.SIGKILL):
        return  # Only this test's retained child, created in a new session, on timeout.
    if event in ('subprocess.Popen', 'os.posix_spawn'):
        if CURRENT is not None and args[0] == CURRENT[0] and list(args[1]) == CURRENT:
            if event == 'subprocess.Popen': GUEST_LAUNCHES += 1
            return
        ATTEMPTS.append(event); raise AssertionError('only the exact pinned guest DATA command may execute')
    if event.startswith(('socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.fork')) or event in (
            'os.system', 'os.kill', 'os.killpg', 'os.pidfd_open', 'fcntl.flock', 'resource.setrlimit'):
        ATTEMPTS.append(event); raise AssertionError('AUXILIARY_DATA_NO_OTHER_ACTOR: ' + event)


sys.addaudithook(fence)


def module(name):
    spec = importlib.util.spec_from_file_location('auxiliary_ci_' + name, HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value


H, C = module('host'), module('corpus')
A = H.reference()
LOCK = json.loads((HERE / 'guest-inputs.lock.json').read_bytes())
for name, row in LOCK['files'].items(): H.checked(ROOT / name, {k: row[k] for k in ('bytes', 'sha256')})
COMMAND = ['/usr/bin/bash', str(ROOT / LOCK['entry'])]
for command in LOCK['required_commands']:
    if not Path(command).is_file() or not os.access(command, os.X_OK):
        raise ValueError('required real tool missing: ' + command + '; install GNU gawk/coreutils/bash explicitly')
BASELINE = H.baseline()


def guest(raw):
    global CURRENT, CLEANUP_GROUP
    if type(raw) is not bytes or len(raw) > A.CAP + 1:
        raise ValueError('finite guest DATA input required')
    CURRENT = COMMAND
    try:
        with subprocess.Popen(COMMAND, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              start_new_session=True, env=dict(PATH='/usr/bin:/bin', LC_ALL='C')) as child:
            try:
                stdout, stderr = child.communicate(raw, timeout=20)
            except subprocess.TimeoutExpired:
                CLEANUP_GROUP = child.pid
                try:
                    try: os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                finally: CLEANUP_GROUP = None
                child.communicate(timeout=5)
                raise AssertionError('owned guest DATA process group exceeded20-second deadline')
            result = subprocess.CompletedProcess(COMMAND, child.returncode, stdout, stderr)
    finally: CURRENT = None
    if len(result.stdout) > A.CAP or len(result.stderr) > 4096:
        raise AssertionError('guest output must remain bounded')
    return result


class Controls(unittest.TestCase):
    def agree(self, raw):
        report, expected = A.normalize(raw); result = guest(raw)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b''); self.assertEqual(result.stdout, expected)
        self.assertEqual(report['selection'], 'UNSELECTED')
        self.assertIsNone(report['Root_acceptance']); self.assertIsNone(report['lifecycle_acceptance'])
        return expected

    def refuse(self, raw):
        with self.assertRaises(ValueError): A.normalize(raw)
        result = guest(raw)
        self.assertNotEqual(result.returncode, 0); self.assertEqual(result.stdout, b'', 'no partial canonical output on refusal')

    def test_actual190_baseline_exact_host_guest_canonical_bytes(self):
        report, canonical = A.normalize(BASELINE)
        self.assertEqual(H.pin(BASELINE), H.BASELINE_PIN); self.assertEqual(report['count'], 190)
        self.assertEqual(sum(row['soname_b64'] is None for row in report['entries']), 1)
        self.assertEqual(H.pin(self.agree(BASELINE)), H.CANONICAL_PIN)

    def test_full_U64_sorting_serialization_and_tuple_prefix_ties(self):
        # Descending input exposes float/awk-strnum ties that sorted input could hide.
        rows = list(reversed(C.unsigned_entries()))
        self.agree(C.model(rows))
        decoded = A.decode(C.model(rows))
        self.assertEqual(max(row['inode'] for row in decoded['entries']), (1 << 64) - 1)

    def test_NULL_empty_full_binary_names_and_versions_are_distinct(self):
        rows = C.named_entries(); canonical = self.agree(C.model(rows))
        for index, name in ((0, b''), (2, b'libX.so.9'), (4, b'lib/full.so.01')):
            changed = copy.deepcopy(rows); changed[index]['name'] = name
            with self.subTest(index=index): self.assertNotEqual(self.agree(C.model(changed)), canonical)

    def test_all_supported_ISA_bits_and_unsupported_profiles_refuse(self):
        levels = [0, *[1 << bit for bit in range(10)], 1023]
        self.agree(C.model([dict(inode=i, isa=level, name=b'isa') for i, level in enumerate(levels)]))
        failures = dict(C.refusals(A.CAP))
        for name in ('wrong-flags', 'negative-flags', 'unsupported-isa'):
            with self.subTest(name=name): self.refuse(failures[name])

    def test_record_string_order_and_only_ABI_padding_are_normalized(self):
        rows = C.named_entries(); raw = C.model(rows); expected = self.agree(raw)
        variants = [C.model(rows, padding=b'\xff\x01\x80\x7f'),
                    C.model(rows, string_order=list(reversed([i for i, r in enumerate(rows) if r['name'] is not None]))),
                    C.model(list(reversed(rows)))]
        for changed in variants:
            with self.subTest(pin=H.pin(changed)):
                self.assertNotEqual(raw, changed); self.assertEqual(self.agree(changed), expected)
                comparison = A.compare(raw, changed)
                self.assertTrue(comparison['defined_fields_equal']); self.assertEqual(comparison['selection'], 'UNSELECTED')
                self.assertIsNone(comparison['actual_cause']); self.assertIsNone(comparison['Root_acceptance'])
                self.assertTrue(comparison['holds'])

    def test_every_defined_stat_ISA_and_name_change_remains_visible(self):
        row = dict(inode=(1 << 63) + 9, ctime=(1 << 53) + 9, size=(1 << 64) - 2,
                   device=0x9999999999999998, isa=0, name=b'libExact.so.09')
        original = self.agree(C.model([row]))
        for key in ('inode', 'ctime', 'size', 'device', 'isa', 'name'):
            changed = dict(row); changed[key] = b'libExact.so.9' if key == 'name' else changed[key] + 1
            with self.subTest(key=key): self.assertNotEqual(self.agree(C.model([changed])), original)

    def test_empty_cache_membership_and_duplicate_identity_refusal(self):
        empty = self.agree(C.model([])); rows = [dict(inode=1, name=b'same'), dict(inode=2, name=b'same')]
        self.assertNotEqual(self.agree(C.model(rows)), empty)
        self.assertEqual(A.decode(C.model(rows))['count'], 2)
        self.refuse(dict(C.refusals(A.CAP))['duplicate-identity'])

    def test_header_geometry_count_extent_and_byte_caps_refuse(self):
        labels = {'empty-input', 'short-header', 'wrong-version', 'count-over-cap', 'zero-string-extent',
                  'huge-string-extent', 'truncated', 'trailing', 'byte-cap', 'big-endian-header'}
        for name, raw in C.refusals(A.CAP):
            if name in labels:
                with self.subTest(name=name): self.refuse(raw)

    def test_segment_offset_alias_NUL_and_name_caps_refuse(self):
        labels = {'interior-name', 'outside-name', 'reused-name', 'unreferenced-name', 'missing-nul', 'name-over-cap'}
        for name, raw in C.refusals(A.CAP):
            if name in labels:
                with self.subTest(name=name): self.refuse(raw)

    def test_maximum_count_near_byte_cap_and_full_binary_name(self):
        rows = [dict(inode=i, name=b'x' * 190 + str(i).encode()) for i in range(A.MAX_ENTRIES)]
        raw = C.model(list(reversed(rows))); self.assertGreater(len(raw), 990000); self.assertLessEqual(len(raw), A.CAP)
        self.agree(raw); self.agree(C.model([dict(inode=1, name=b'\xff' * A.MAX_SONAME)]))


if __name__ == '__main__':
    if not __debug__ or not sys.flags.isolated or not sys.dont_write_bytecode:
        raise ValueError('use unoptimized Python -I -B')
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
    passed = (result.wasSuccessful() and result.testsRun == 10 and not result.skipped and not result.expectedFailures
              and not result.unexpectedSuccesses and not ATTEMPTS)
    print(json.dumps(dict(status='PASS_HOST_GUEST_CANONICAL_DATA_ONLY' if passed else 'FAIL', tests=result.testsRun,
                         skips=len(result.skipped), denied_actor_attempts=len(ATTEMPTS), guest_DATA_launches=GUEST_LAUNCHES,
                         actual_after_body=None, auxcomparison='NOT_ACCEPTED', selection='UNSELECTED',
                         Source65_private_inode_guard='HOLD_UNCHANGED', Root_acceptance=None, lifecycle_acceptance=None,
                         VM=None, M2=None), sort_keys=True))
    sys.exit(0 if passed else 1)
