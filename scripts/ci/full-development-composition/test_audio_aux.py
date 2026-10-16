"""In-memory layout/order refusals and inert-file checkpoint controls; no actors."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


aux = load('aux_fixture_parser', 'audio_aux.py')
audio = load('aux_fixture_checkpoint', 'audio.py')
# These keys have literal buckets0,0,1 for the source's table size1021.
A = ((0, 0, 0, 1021), (2563, b'alpha', 0))
B = ((0, 0, 0, 2042), (2563, None, 0))
C = ((0, 0, 0, 1), (2563, b'', 1))
TAILS = (b'ABCD', b'EFGH', b'IJKL')


def fixture(rows=(A, B, C), tails=TAILS):
    """Independent fixture writer; only synthetic bytes, never actual caches."""
    records, strings = [], bytearray(b'\0')
    for number, (key, (flags, name, isa)) in enumerate(rows):
        offset = 0 if name is None else len(strings)
        if name is not None: strings.extend(name + b'\0')
        records.append(struct.pack('<QQQQiII', *key, flags, offset, isa) + tails[number])
    return b'glibc-ld.so.auxcache-2.0' + struct.pack('<II', len(rows), len(strings)) + b''.join(records) + strings


def overwrite(data, position, replacement):
    return data[:position] + replacement + data[position + len(replacement):]


class Serialization(unittest.TestCase):
    def setUp(self):
        self.before, self.after = fixture(), fixture((B, A, C))

    def refuse(self, after, before=None):
        with self.assertRaises(aux.Refused): aux.compare(self.before if before is None else before, after)

    def test_exact_source_order_and_repeated_immediate_transitions(self):
        self.assertEqual(aux.compare(self.before, self.after)['kind'], 'EXACT_LOAD_SAVE_ORDER')
        self.assertEqual(aux.compare(self.after, self.before)['kind'], 'EXACT_LOAD_SAVE_ORDER')
        self.assertEqual(aux.parse(self.before), [A, B, C])
        self.assertEqual(aux.compare(self.before, self.before), {'kind': 'RAW_EQUAL'})
        # Preserve the old raw-equal route even for an opaque unchanged format.
        self.assertEqual(aux.compare(b'opaque', b'opaque'), {'kind': 'RAW_EQUAL'})

    def test_arbitrary_permutation_refused_despite_equal_maps(self):
        arbitrary = fixture((C, B, A))
        self.assertEqual(dict(aux.parse(self.before)), dict(aux.parse(arbitrary)))
        self.refuse(arbitrary)

    def test_padding_must_hold_at_physical_slot(self):
        self.refuse(fixture((B, A, C), (b'EFGH', b'ABCD', b'IJKL')))
        self.refuse(overwrite(self.after, 32 + 44, b'Z'))

    def test_changed_key_and_each_named_value_refuse(self):
        for position, replacement in [(32, struct.pack('<Q', 9)), (64, struct.pack('<i', 7)),
                                      (72, struct.pack('<I', 9))]:
            with self.subTest(position=position): self.refuse(overwrite(self.after, position, replacement))
        self.refuse(self.after.replace(b'alpha', b'bravo'))
        # NULL and the non-null empty string are different named values.
        self.refuse(fixture(((B[0], (2563, b'', 0)), A, C)))

    def test_duplicate_added_removed_entries_refuse(self):
        for rows in [(B, A, A), (B, A), (B, A, C, ((0, 0, 0, 3), (2563, None, 0)))]:
            tails = TAILS + (b'MNOP',)
            with self.subTest(rows=rows): self.refuse(fixture(rows, tails))

    def test_unknown_magic_endian_stride_truncation_and_trailing_bytes_refuse(self):
        for data in [b'unknown', overwrite(self.after, 0, b'X'),
                     overwrite(self.after, 24, struct.pack('>II', 3, 8)),
                     self.after[:76] + self.after[80:], self.after[:-1], self.after + b'x']:
            with self.subTest(size=len(data)): self.refuse(data)

    def test_counts_and_total_byte_bounds_refuse(self):
        for count, strings in [(0, 8), (4097, 8), (3, 0), (3, aux.MAX_STRINGS + 1), (0xffffffff, 8)]:
            with self.subTest(count=count, strings=strings):
                self.refuse(overwrite(self.after, 24, struct.pack('<II', count, strings)))
        for data in [b'', b'x' * (aux.LIMIT + 1)]:
            with self.subTest(size=len(data)), self.assertRaises(aux.Refused): aux.compare(data, data)

    def test_offsets_nuls_coverage_and_name_bounds_refuse(self):
        start = 32 + 3 * 48
        for offset in [2, 7, 8, 0xffffffff]:
            with self.subTest(offset=offset): self.refuse(overwrite(self.after, 80 + 36, struct.pack('<I', offset)))
        self.refuse(overwrite(self.after, start, b'x'))
        self.refuse(self.after[:-1] + b'x')
        # Extra string bytes with consistent total-size header still refuse.
        extra = overwrite(self.after, 28, struct.pack('<I', 9)) + b'x'
        self.refuse(extra)
        long_name = fixture(((A[0], (2563, b'x' * (aux.MAX_NAME + 1), 0)), B, C))
        self.refuse(long_name)

    def test_hash_wrap_and_fixed_source_prime_table(self):
        self.assertEqual(aux.bucket((0, 0, 0, 1021), 1021), 0)
        self.assertEqual(aux.bucket((0, 0, 0, 2042), 1021), 0)
        # Precomputed uint64-wrap then uint32-return result, independent of bucket code.
        self.assertEqual(aux.bucket((0xffffffffffffffff, 0, 0, 0), 1021), 309)
        self.assertEqual(aux.PRIMES, (1021, 2039, 4093, 8191))


class Checkpoints(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.cache = self.root / 'inert-aux'
        self.before, self.after = fixture(), fixture((B, A, C))
        self.context = {}
        self.base = {'helper': {'sha256': 'helper'}, 'configs': {'conf': {'sha256': 'config'}},
                     'aliases': {'dir': {'mode': 493}}, 'scan': {'lib': {'identity': [1, 2, 3, 4]}},
                     'targets': {'target': {'sha256': 'target'}}, 'mapping': ['first', 'second'],
                     'generator': ['version'], 'caches': {'/etc/ld.so.cache': {'type': 'file', 'sha256': 'main', 'size': 5}}}
        patched = patch.object(audio, 'LD_AUX_INPUT', self.cache); patched.start(); self.addCleanup(patched.stop)
        diagnostic = patch.object(audio, 'ld_aux_diagnostic'); self.diagnostic = diagnostic.start(); self.addCleanup(diagnostic.stop)
        self.baseline = self.checkpoint('B0-587', self.before)

    def checkpoint(self, label, data, mutate=None, baseline=None, mode=0o600):
        self.cache.write_bytes(data); self.cache.chmod(mode)
        state = copy.deepcopy(self.base); state['caches'][audio.LD_AUX_NAME] = audio.ld_node(self.cache)
        if mutate: mutate(state)
        with patch.object(audio, 'ld_state', return_value=state):
            return audio.ld_checkpoint(None, [], self.root, label, baseline, self.context)

    def test_full_sequence_compares_prior_bytes_not_original_baseline(self):
        with patch.object(audio.aux_order, 'compare', wraps=audio.aux_order.compare) as compared:
            states = [self.baseline]
            for label, data in [('B1-593', self.after), ('B2-592', self.before), ('B3-587', self.after)]:
                states.append(self.checkpoint(label, data, baseline=self.baseline))
            self.assertEqual([call.args for call in compared.call_args_list],
                             [(self.before, self.after), (self.after, self.before), (self.before, self.after)])
        self.assertEqual([r['checkpoint'] for r in self.context['transitions']],
                         ['B0-587', 'B1-593', 'B2-592', 'B3-587'])
        self.assertEqual(audio.ld_summary(states, self.context)['auxiliary_exit_status'], 'NOT OBSERVED')
        self.assertEqual(self.cache.read_bytes(), self.after)

    def test_original_baseline_fields_still_refuse_after_valid_order_change(self):
        for field in ['helper', 'configs', 'aliases', 'scan', 'targets', 'mapping', 'generator']:
            def mutate(state): state[field] = ['changed'] if isinstance(state[field], list) else {'changed': {}}
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'changed-state.*' + field):
                self.checkpoint('B1-593', self.after, mutate, self.baseline)
            self.assertEqual(self.context['label'], 'B0-587')
        for name, attribute, value in [(audio.LD_AUX_NAME, 'mode', 420), (audio.LD_AUX_NAME, 'uid', 99),
                                       (audio.LD_AUX_NAME, 'gid', 99), (audio.LD_AUX_NAME, 'type', 'link'),
                                       (audio.LD_AUX_NAME, 'size', 1), ('/etc/ld.so.cache', 'size', 9)]:
            def mutate(state): state['caches'][name][attribute] = value
            with self.subTest(name=name, attribute=attribute), self.assertRaises(ValueError):
                self.checkpoint('B1-593', self.after, mutate, self.baseline)

    def test_metadata_drift_that_joins_current_read_still_refuses_baseline(self):
        with self.assertRaisesRegex(ValueError, 'changed-state.*caches'):
            self.checkpoint('B1-593', self.after, baseline=self.baseline, mode=0o644)

    def test_raw_node_hash_join_and_helper_pin_refuse(self):
        with self.assertRaisesRegex(ValueError, 'aux-diagnostic-node-join'):
            self.checkpoint('B1-593', self.after, lambda s: s['caches'][audio.LD_AUX_NAME].update(sha256='0' * 64), self.baseline)
        with patch.object(audio, 'LD_HELPER', ('0' * 64, 865664)):
            with self.assertRaisesRegex(ValueError, 'aux-order-helper-pin'):
                self.checkpoint('B1-593', self.after, baseline=self.baseline)

    def test_failed_stable_read_cannot_pass_even_raw_equal(self):
        with patch.object(audio.os, 'open', side_effect=PermissionError('inert read refusal')):
            with self.assertRaisesRegex(ValueError, 'PermissionError'):
                self.checkpoint('B1-593', self.before, baseline=self.baseline)
        self.assertEqual(self.context['label'], 'B0-587')
        with self.assertRaisesRegex(ValueError, 'incomplete-checkpoints'):
            audio.ld_summary([self.baseline], self.context)

    def test_raw_equal_keeps_existing_main_hash_exception_only(self):
        self.checkpoint('B1-593', self.before, lambda s: s['caches']['/etc/ld.so.cache'].update(sha256='changed'), self.baseline)
        self.assertEqual(self.context['transitions'][-1]['kind'], 'RAW_EQUAL')

    def test_refusal_preserves_prior_context_and_diagnostics_precede_oracle(self):
        with self.assertRaisesRegex(ValueError, 'aux-order-expected-record'):
            self.checkpoint('B1-593', fixture((C, B, A)), baseline=self.baseline)
        self.assertEqual(self.context['label'], 'B0-587')
        self.assertEqual(self.context['data'], self.before)
        self.assertEqual(self.diagnostic.call_args.args[0], 'B1-593')
        with self.assertRaisesRegex(ValueError, 'checkpoint-sequence'):
            self.checkpoint('B2-592', self.after, baseline=self.baseline)


if __name__ == '__main__': unittest.main()
