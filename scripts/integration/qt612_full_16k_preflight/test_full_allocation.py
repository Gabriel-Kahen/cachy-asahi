# SPDX-License-Identifier: MIT
"""Inert cadence and receipt controls for the full Qtbase actor."""

import json
from pathlib import Path
import resource
from runpy import run_path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
A = SimpleNamespace(**run_path(str(HERE / "full_actor.py")))


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


class ExtendedWriterTests(unittest.TestCase):
    def test_frozen_writer_branch_keeps_original_per_command_cap(self):
        cap = A.F.LEGACY_QEMU_FILE_SIZE_CAP
        runner = SimpleNamespace(plan=dict(qemu_argv=["model-qemu"], qemu_seconds=600),
                                 actor=dict(child_file_size_cap=cap))
        with patch.object(runner, "phase", create=True, return_value="original-pin") as phase:
            self.assertEqual(A.run_qemu(runner), ("original-pin", None))
        phase.assert_called_once_with("qemu", ["model-qemu"], 600, file_cap=cap)

    def test_tighter_inherited_file_limit_is_preserved(self):
        cap = A.F.MAX_OVERLAY_FILE_BYTES
        with (patch.object(resource, "getrlimit", return_value=(cap - 1, resource.RLIM_INFINITY)),
              patch.object(resource, "setrlimit") as change):
            with self.assertRaisesRegex(ValueError, "preserve inherited restrictions"):
                A.install_writer_limit(cap)
            change.assert_not_called()

    def test_extended_writer_observes_real_inherited_kernel_limit(self):
        # Lower the hard limit only in this disposable fixture process.
        script = """
import json, resource, subprocess, sys
from runpy import run_path
from types import SimpleNamespace

actor = run_path(sys.argv[1])
cap = int(sys.argv[2])
argv = [sys.executable, "-I", "-B", "-c", "print('ready', flush=True); input()"]
samples = []
old_guard = lambda: samples.append(True)
runner = SimpleNamespace(plan=dict(qemu_argv=argv, qemu_seconds=600),
                         actor=dict(child_file_size_cap=cap),
                         runtime=SimpleNamespace(GUARD=old_guard))
def phase(label, argv, seconds, *, file_cap=None):
    assert (label, seconds, file_cap) == ("qemu", 600, None)
    runner.runtime.GUARD()
    with subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE) as child:
        assert child.stdout.readline() == b"ready\\n"
        runner.runtime.GUARD()
        child.communicate(b"done\\n", timeout=2)
        assert child.returncode == 0
    return "original-pin"
runner.phase = phase
pin, limits = actor["run_qemu"](runner)
assert pin == "original-pin" and samples == [True, True]
assert runner.runtime.GUARD is old_guard
print(json.dumps(limits))
"""
        cap = A.F.MAX_OVERLAY_FILE_BYTES
        reply = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(HERE / "full_actor.py"), str(cap)],
                               capture_output=True, check=True, timeout=10)
        self.assertEqual(json.loads(reply.stdout), dict(actor=[cap, cap], qemu=[cap, cap]))

    def test_extended_writer_refuses_absent_or_mismatched_child_limit(self):
        cap = A.F.MAX_OVERLAY_FILE_BYTES
        limit = (cap, cap)
        old_guard = lambda: None
        runtime = SimpleNamespace(GUARD=old_guard)

        def phase(*_args):
            runtime.GUARD()
            return "original-pin"

        runner = SimpleNamespace(plan=dict(qemu_argv=["model-qemu"], qemu_seconds=600),
                                 actor=dict(child_file_size_cap=cap), runtime=runtime, phase=phase)
        for observed, message in ((None, "Observed original"), ((cap - 1, cap), "did not inherit")):
            with (self.subTest(observed=observed),
                  patch.object(resource, "getrlimit", return_value=limit),
                  patch.dict(A.run_qemu.__globals__, {"install_writer_limit": lambda _cap: limit,
                                                     "observe_writer_limit": lambda _argv: observed})):
                with self.assertRaisesRegex(ValueError, message):
                    A.run_qemu(runner)
                self.assertIs(runtime.GUARD, old_guard)

    def test_readback_requires_exact_extended_receipt_and_no_legacy_cap_claim(self):
        fixture = run_path(str(HERE / "test_full_readback.py"))
        reader = fixture["R"]
        test = fixture["FullReadbackTests"]()
        cap = A.F.MAX_OVERLAY_FILE_BYTES
        with TemporaryDirectory() as temp:
            output = Path(temp)
            plan, report = fixture["original_actor"](output)
            policy = plan["actor"]
            policy.update(child_file_size_cap=cap, admission_disk_bytes=cap + 3 * A.F.GIB)
            policy["watched_paths"][0][1] = cap
            policy["watched_tree"][1] = cap + A.F.GIB
            for key in ("capacity_before", "capacity_after"):
                report[key]["required_bytes"] = policy["admission_disk_bytes"]
            report.update(kind=reader.EXTENDED_ACTOR_KIND, qemu_file_size_limits=dict(actor=[cap, cap], qemu=[cap, cap]))
            receipt = fixture["FIXTURE"]["natural_record"]
            qemu_pin = fixture["put"](output, "qemu.json", A.C.wire(receipt(plan["qemu_argv"], None)))
            report["qemu"] = qemu_pin
            accepted = test.review(output, plan, report)
            self.assertEqual(accepted["qemu_file_size_limits"], report["qemu_file_size_limits"])
            with self.assertRaisesRegex(ValueError, "scope"):
                test.review(output, plan, report | {"kind": reader.ACTOR_KIND})
            with self.assertRaisesRegex(ValueError, "inherited QEMU file limits"):
                test.review(output, plan, report | {"qemu_file_size_limits": dict(actor=[cap, cap], qemu=[cap - 1, cap])})
            report["qemu"] = fixture["put"](output, "qemu.json", A.C.wire(receipt(plan["qemu_argv"], cap)))
            with self.assertRaisesRegex(ValueError, "owned command retirement"):
                test.review(output, plan, report)


if __name__ == "__main__":
    unittest.main()
