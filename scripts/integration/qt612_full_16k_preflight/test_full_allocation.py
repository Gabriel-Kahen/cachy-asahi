# SPDX-License-Identifier: MIT
"""Inert cadence and receipt controls for the full Qtbase actor."""

from pathlib import Path
from runpy import run_path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


A = SimpleNamespace(**run_path(str(Path(__file__).with_name("full_actor.py"))))


class FullAllocationTests(unittest.TestCase):
    def test_near_budget_sampling_fits_frozen_readback(self):
        actor_clock = SimpleNamespace(now=1.0)

        class Watch:
            last = actor_clock.now
            samples = 1

            def record(self):
                self.last = actor_clock.now
                self.samples += 1

        limits = A.F.DEFAULT_LIMITS
        policy = dict(watched_tree=["/out", 4 * A.F.GIB, A.F.GIB],
                      watched_paths=[["/out/overlay.qcow2", 2 * A.F.GIB]],
                      child_file_size_cap=2 * A.F.GIB, result_disk_bytes=A.F.GIB)
        end = dict(tree_allocated=12288, overlay_allocated=8192, overlay_eof=8192,
                   result_allocated=4096, free=3 * A.F.GIB)
        start = end | dict(tree_allocated=4096, overlay_allocated=0, overlay_eof=0)
        with patch.dict(A.poll_allocation.__globals__,
                        {"time": SimpleNamespace(monotonic=lambda: actor_clock.now)}):
            for seconds in (limits["qemu_seconds"], A.F.LIMITS["qemu_seconds"][1]):
                with self.subTest(seconds=seconds):
                    actor_clock.now = 1.0
                    watch = Watch()
                    watch.record()
                    for tick in range(1, 2 * (seconds + 300) + 1):
                        actor_clock.now = 1.0 + tick / 2
                        A.poll_allocation(watch)
                    # The phase boundaries and report check still sample immediately.
                    for _ in range(10):
                        watch.record()
                    rows = dict(before=start, after=end, peak=end, samples=watch.samples)
                    self.assertEqual(rows["samples"], seconds + 312)
                    A.C.check_watch(rows, policy, end["overlay_eof"])
                    with self.assertRaisesRegex(ValueError, "Finite owned allocation samples"):
                        A.C.check_watch(rows | {"samples": 2 * seconds + 1}, policy, end["overlay_eof"])


if __name__ == "__main__":
    unittest.main()
