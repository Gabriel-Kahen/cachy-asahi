# SPDX-License-Identifier: MIT
"""Real parser operands and benchmark refusal controls; no hardware acceptance."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('apps_parser_benchmark_tested', Path(__file__).with_name('apps_inventory_parser.py'))
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
ROOT = next(p for p in Path(__file__).resolve().parents if (p / 'manifests/packages.toml').is_file())
ORIGINAL = ROOT / 'packages/tools/cachy-asahi-apps/inventory.py'


class AppsParserBenchmarkTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='apps-parser-benchmark-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.baseline = self.root / 'baseline.py'
        self.candidate = self.root / 'candidate.py'
        self.raw = ORIGINAL.read_bytes()
        self.baseline.write_bytes(self.raw)
        self.candidate.write_bytes(self.raw)
        actors = patch.object(subprocess, 'Popen', side_effect=AssertionError('no benchmark actors'))
        actors.start()
        self.addCleanup(actors.stop)

    def run_benchmark(self, **kwargs):
        return b.benchmark(self.baseline, self.candidate, values=64, repeats=2, **kwargs)

    def test_real_parser_balanced_samples_and_source_receipts(self):
        self.candidate.write_bytes(self.raw + b'\nraise RuntimeError("module initializer must not execute")\n')
        report = self.run_benchmark()
        samples = report['timing']['samples']
        self.assertEqual([v['role'] for v in samples], ['baseline', 'candidate', 'candidate', 'baseline'])
        self.assertEqual([v['repeat'] for v in samples], [0, 0, 1, 1])
        self.assertTrue(all(type(v['elapsed_ns']) is int and v['elapsed_ns'] >= 0 for v in samples))
        self.assertEqual(report['sources']['baseline']['sha256'], b.pin(self.raw)['sha256'])
        self.assertEqual(report['workload']['generated_values'], 64)
        self.assertEqual(report['equivalence']['control_cases'], 8)
        self.assertEqual(report['hardware_acceptance'], 'NOT_ESTABLISHED')
        self.assertLess(len(b.encoded(report)), b.MAX_JSON)

    def test_output_mismatch_refuses_before_clock(self):
        self.candidate.write_bytes(self.raw.replace(b'result={};current=None', b"result={'changed':[]};current=None"))
        with patch.object(b.time, 'perf_counter_ns', side_effect=AssertionError('must not time unequal parsers')):
            with self.assertRaisesRegex(ValueError, 'control outputs/refusals differ'):
                self.run_benchmark()

    def test_changed_duplicate_refusal_refuses_before_clock(self):
        anchor = b"current in {'DEPENDS','PROVIDES','CONFLICTS','REPLACES'}"
        self.assertEqual(self.raw.count(anchor), 1)
        self.candidate.write_bytes(self.raw.replace(anchor, b"current in {'FILES','DEPENDS','PROVIDES','CONFLICTS','REPLACES'}"))
        with patch.object(b.time, 'perf_counter_ns', side_effect=AssertionError('must not time different refusals')):
            with self.assertRaisesRegex(ValueError, 'control outputs/refusals differ'):
                self.run_benchmark()

    def test_explicit_refused_record_stays_readonly_and_named(self):
        path = self.root / 'files'
        path.write_bytes(b'%FILES%\na\na\n\n')
        path.chmod(0o444)
        before = path.stat()
        report = self.run_benchmark(record=path)
        self.assertEqual(report['workload']['outcome_status'], 'REFUSED')
        self.assertEqual(report['qualification'], 'EXPLICIT_RECORD_PARSER_MICROBENCHMARK')
        self.assertEqual(path.read_bytes(), b'%FILES%\na\na\n\n')
        self.assertEqual(path.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(report['workload']['generated_values'], None)

    def test_bounds_and_symlinks_refused(self):
        for count in (0, b.MAX_VALUES + 1):
            with self.assertRaises(ValueError):
                b.fixture(count)
        for repeats in (1, 3, 22):
            with self.assertRaises(ValueError):
                b.benchmark(self.baseline, self.candidate, values=2, repeats=repeats)
        link = self.root / 'symlink'
        link.symlink_to(self.baseline)
        with self.assertRaises(OSError):
            b.benchmark(link, self.candidate, values=2, repeats=2)
        path = self.root / 'large'
        path.write_bytes(b'x' * (b.MAX_RECORD + 1))
        with self.assertRaisesRegex(ValueError, 'bounded ordinary input'):
            self.run_benchmark(record=path)
        path.write_bytes(b'\n' * (b.MAX_VALUES + 65))
        with self.assertRaisesRegex(ValueError, 'record byte/line bound'):
            self.run_benchmark(record=path)

    def test_changed_source_during_timing_refused(self):
        ticks = iter(range(10))
        def clock():
            self.candidate.write_bytes(self.raw + b'\n# drift\n')
            return next(ticks)
        with patch.object(b.time, 'perf_counter_ns', side_effect=clock):
            with self.assertRaisesRegex(ValueError, 'source changed'):
                self.run_benchmark()

    def test_record_specific_mismatch_refuses_before_clock(self):
        # Controls agree; only the explicit operand differs, so its own gate is necessary.
        anchor = b"text=raw.decode('utf-8','strict')"
        self.assertEqual(self.raw.count(anchor), 1)
        self.candidate.write_bytes(self.raw.replace(anchor, b"\n    if raw==b'operand':return {}\n    text=raw.decode('utf-8','strict')"))
        path = self.root / 'files'
        path.write_bytes(b'operand')
        with patch.object(b.time, 'perf_counter_ns', side_effect=AssertionError('must gate exact workload')):
            with self.assertRaisesRegex(ValueError, 'workload outputs/refusals differ'):
                self.run_benchmark(record=path)

    def test_unknown_section_names_and_parser_shape_refused(self):
        for sections in ([], ['FILES', 'FILES'], ['bad'], ['X' * 33]):
            with self.assertRaises(ValueError):
                self.run_benchmark(sections=sections)
        self.candidate.write_bytes(self.raw + b'\ndef sections(raw,allowed):return {}\n')
        with self.assertRaisesRegex(ValueError, 'unique need/sections'):
            self.run_benchmark()

    def test_mapping_insertion_order_is_compared(self):
        anchor = b"    return result\n\n\ndef relative"
        self.assertEqual(self.raw.count(anchor), 1)
        changed = b"    if raw.startswith(b'%BACKUP%'):return {'FILES':result['FILES'],'BACKUP':result['BACKUP']}\n" + anchor
        self.candidate.write_bytes(self.raw.replace(anchor, changed))
        record = self.root / 'files'
        record.write_bytes(b'%BACKUP%\na\n\n%FILES%\nb\n\n')
        with patch.object(b.time, 'perf_counter_ns', side_effect=AssertionError('must compare field order')):
            with self.assertRaisesRegex(ValueError, 'workload outputs/refusals differ'):
                self.run_benchmark(record=record)


if __name__ == '__main__':
    unittest.main()
