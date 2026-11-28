# SPDX-License-Identifier: MIT

from pathlib import Path
from runpy import run_path
import tempfile
import unittest

TELEMETRY = run_path(str(Path(__file__).with_name("host_telemetry.py")))


class HostTelemetryTests(unittest.TestCase):
    def test_actor_reports_only_selected_observed_counters(self):
        with tempfile.TemporaryDirectory() as folder:
            group = Path(folder)
            (group / "memory.stat").write_text("file 150\nanon 76\nfile_dirty 9\nfile_writeback 3\npgscan 42\nunknown 5\n")
            pressure = "some avg10=0.40 avg60=0.09 avg300=0.02 total=398\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0"
            (group / "memory.pressure").write_text(pressure + "\n")
            sample = TELEMETRY["actor_memory"](group)
            self.assertEqual(sample["memory_stat"], dict(file=150, anon=76, file_dirty=9, file_writeback=3, pgscan=42))
            self.assertEqual(sample["memory_pressure"], pressure)
            self.assertIn("inactive_file", sample["memory_stat_missing"])
            self.assertNotIn("inactive_file", sample["memory_stat"])

    def test_actor_can_disappear_during_a_sample(self):
        with tempfile.TemporaryDirectory() as folder:
            sample = TELEMETRY["actor_memory"](Path(folder) / "retired")
            self.assertEqual(sample["memory_stat"], {})
            self.assertIn("FileNotFoundError", sample["memory_stat_error"])
            self.assertIn("FileNotFoundError", sample["memory_pressure_error"])

    def test_swap_values_are_cumulative_pages(self):
        with tempfile.TemporaryDirectory() as folder:
            vmstat = Path(folder) / "vmstat"
            vmstat.write_text("pswpin 11\npgmajfault 24\npswpout 99\n")
            self.assertEqual(TELEMETRY["host_swap"](vmstat), {"host_swap_pages": dict(pswpin=11, pswpout=99)})
            vmstat.write_text("pswpout 0\n")
            self.assertEqual(TELEMETRY["host_swap"](vmstat), {"host_swap_pages": dict(pswpout=0),
                                                             "host_swap_pages_missing": ["pswpin"]})

    def test_counter_malformed_or_unbounded_input_is_explicit(self):
        with tempfile.TemporaryDirectory() as folder:
            vmstat = Path(folder) / "vmstat"
            for body in ("pswpin -1\n", "pswpin 1\npswpin 2\n", f"pswpin {1 << 64}\n", "a" * ((64 << 10) + 1)):
                with self.subTest(length=len(body)):
                    vmstat.write_text(body)
                    sample = TELEMETRY["host_swap"](vmstat)
                    self.assertEqual(sample["host_swap_pages"], {})
                    self.assertIn("ValueError", sample["host_swap_pages_error"])


if __name__ == "__main__":
    unittest.main()
