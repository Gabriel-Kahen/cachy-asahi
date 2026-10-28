# SPDX-License-Identifier: GPL-2.0-only
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
spec = importlib.util.spec_from_file_location("regression", HERE / "regression.py")
regression = importlib.util.module_from_spec(spec)
spec.loader.exec_module(regression)


class RegressionTests(unittest.TestCase):
    def setUp(self):
        root = REPO / "artifacts/kernel-native-stage/regression/tests"
        root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="owned-", dir=root)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.baseline = REPO / "artifacts/kernel-candidates/full-baseline-20261012/source-tree/linux-asahi-7.1.13-3/block/bio.c"
        self.candidate = REPO / "artifacts/kernel-candidates/full-candidate-20261012-b/source-tree/linux-asahi-7.1.13-3/block/bio.c"

    def real_inputs(self):
        if not self.baseline.is_file() or not self.candidate.is_file():
            self.skipTest("private pinned Asahi source copies unavailable; real C fixture NOT RUN")
        cc = shutil.which("gcc")
        if not cc:
            self.skipTest("GCC unavailable; real C fixture NOT RUN")
        cc = Path(cc).resolve()
        return cc, hashlib.sha256(cc.read_bytes()).hexdigest()

    def run_fixture(self, output="run", compiler_sha=None):
        cc, pin = self.real_inputs()
        return regression.run_fixture(self.baseline, self.candidate, self.root / output,
                                      cc, pin if compiler_sha is None else compiler_sha,
                                      evidence_root=self.root)

    def test_real_extracted_functions_cover_every_branch_case(self):
        report = self.run_fixture()
        self.assertEqual(report["status"], "PASS", report.get("error"))
        self.assertEqual(len(report["commands"]), 28)
        self.assertEqual(report["actual_kernel_execution"], "NOT RUN")
        self.assertEqual(report["kernel_runtime_plan"]["status"], "NOT RUN")
        self.assertEqual(len(report["variants"]["candidate"]["cases"]), 13)
        for variant in ("baseline", "candidate"):
            for case in report["variants"][variant]["cases"].values():
                self.assertEqual(case["status"], "PASS")
            text = (self.root / "run" / (variant + ".c")).read_bytes()
            original = (self.baseline if variant == "baseline" else self.candidate).read_bytes()
            body = regression.extract_function(original, "struct bio *bio_alloc_bioset(")
            self.assertIn(body, text)
            self.assertEqual(hashlib.sha256(body).hexdigest(), regression.FUNCTION_PINS[variant])

    def test_baseline_bug_and_candidate_fix_are_not_hidden_by_aggregate_pass(self):
        report = self.run_fixture()
        old = report["variants"]["baseline"]["cases"]["cache-miss-slab"]["observed"]
        new = report["variants"]["candidate"]["cases"]["cache-miss-slab"]["observed"]
        self.assertEqual((old["origin"], old["slab_bio"]), (0, 0))
        self.assertEqual((new["origin"], new["slab_bio"]), (2, 1))
        self.assertTrue(new["opf"] & regression.CACHE_FLAG)
        self.assertEqual(new["pool_bio"], 0)

    def test_unexpected_observation_fails_and_keeps_evidence(self):
        original = regression.expected_cases

        def incorrect(variant):
            result = original(variant)
            if variant == "candidate":
                result["cache-hit"]["slab_bio"] = 1
            return result

        with mock.patch.object(regression, "expected_cases", side_effect=incorrect):
            report = self.run_fixture()
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("observation mismatch", report["error"])
        self.assertEqual(report["variants"]["candidate"]["cases"]["cache-hit"]["status"], "FAIL")
        self.assertEqual(json.loads((self.root / "run/result.json").read_text()), report)

    def test_whole_source_pin_rejects_unrelated_change_before_execution(self):
        self.real_inputs()
        changed = self.root / "changed-bio.c"
        changed.write_bytes(self.candidate.read_bytes() + b"\n/* changed */\n")
        with mock.patch.object(regression, "execute") as execute:
            with self.assertRaisesRegex(ValueError, "pin mismatch"):
                regression.fixture_source(changed, "candidate")
            execute.assert_not_called()

    def test_compiler_pin_mismatch_creates_no_output(self):
        with self.assertRaisesRegex(ValueError, "compiler SHA-256 mismatch"):
            self.run_fixture(compiler_sha="0" * 64)
        self.assertFalse((self.root / "run").exists())

    def test_compile_failure_has_authoritative_failure_receipt(self):
        with mock.patch.object(regression, "execute", side_effect=RuntimeError("compile failed")):
            report = self.run_fixture()
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["actual_kernel_execution"], "NOT RUN")
        self.assertIn("compile failed", report["error"])
        self.assertTrue((self.root / "run/result.json").is_file())

    def test_interrupt_retains_failure_receipt(self):
        with mock.patch.object(regression, "execute", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_fixture()
        report = json.loads((self.root / "run/result.json").read_text())
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("KeyboardInterrupt", report["error"])
        self.assertTrue(report["cancelled"])

    def test_worker_baseexception_cancel_propagates_after_failure_receipt(self):
        class Cancelled(BaseException):
            pass
        with mock.patch.object(regression, "execute", side_effect=Cancelled):
            with self.assertRaises(Cancelled):
                self.run_fixture()
        report = json.loads((self.root / "run/result.json").read_text())
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(report["cancelled"])

    def test_canonical_fresh_owned_output_only(self):
        self.assertEqual(regression.new_output(self.root / "new", self.root), self.root / "new")
        for output in (self.root, self.root.parent / "escape", self.root / "../escape", Path("relative")):
            with self.subTest(output=output), self.assertRaises(ValueError):
                regression.new_output(output, self.root)
        (self.root / "existing").mkdir()
        with self.assertRaises(ValueError):
            regression.new_output(self.root / "existing", self.root)

    def test_symlinked_input_or_output_rejected(self):
        target = self.root / "file"
        target.write_bytes(b"x")
        link = self.root / "link"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            regression.read_regular(link, 128)
        with self.assertRaises(ValueError):
            regression.new_output(link / "output", self.root)

    def test_input_byte_limit(self):
        target = self.root / "file"
        target.write_bytes(b"0123456789")
        with self.assertRaisesRegex(ValueError, "bounded regular"):
            regression.read_regular(target, 8)

    def test_fifo_input_rejected_without_waiting_for_writer(self):
        target = self.root / "fifo"
        regression.os.mkfifo(target)
        with self.assertRaisesRegex(ValueError, "bounded regular"):
            regression.read_regular(target, 8)

    def test_aggregate_budget_refuses_command_before_spawn(self):
        target = self.root / "large"
        with target.open("wb") as stream:
            stream.truncate(regression.TOTAL_LIMIT)
        with mock.patch.object(regression.subprocess, "Popen") as spawn:
            with self.assertRaisesRegex(ValueError, "byte cap exhausted"):
                regression.execute(["fixture"], self.root, "budget")
            spawn.assert_not_called()

    def test_duplicate_function_rejected(self):
        body = b"struct bio *bio_alloc_bioset(void)\n{\n}\n"
        with self.assertRaisesRegex(ValueError, "one exact"):
            regression.extract_function(body + body, "struct bio *bio_alloc_bioset(")

    def test_source_version_pins_are_not_overridden_by_caller(self):
        target = self.root / "source"
        target.write_bytes(b"struct bio *bio_alloc_bioset(void)\n{\n}\n")
        with self.assertRaisesRegex(ValueError, "baseline block/bio.c pin mismatch"):
            regression.fixture_source(target, "baseline")

    def test_timeout_kills_and_reaps_owned_process_group(self):
        proc = mock.Mock(pid=12345)
        proc.wait.side_effect = [subprocess.TimeoutExpired(["fixture"], 10), -9]
        with mock.patch.object(regression.subprocess, "Popen", return_value=proc) as spawn:
            with mock.patch.object(regression.os, "killpg") as kill:
                with self.assertRaises(subprocess.TimeoutExpired):
                    regression.execute(["fixture"], self.root, "timeout")
        kill.assert_called_once_with(12345, regression.signal.SIGKILL)
        self.assertEqual(proc.wait.call_count, 2)
        self.assertTrue(spawn.call_args.kwargs["start_new_session"])
        receipt = json.loads((self.root / "timeout.command.json").read_text())
        self.assertEqual(receipt["status"], "FAIL")
        self.assertEqual(receipt["returncode"], -9)
        self.assertIn("TimeoutExpired", receipt["error"])

    def test_cancel_at_spawn_unblock_reaps_already_tracked_child(self):
        class Cancelled(BaseException):
            pass
        proc = mock.Mock(pid=12346)
        proc.wait.return_value = -9
        with mock.patch.object(regression.subprocess, "Popen", return_value=proc):
            with mock.patch.object(regression.signal, "pthread_sigmask",
                                   side_effect=[set(), Cancelled(), set(), set()]):
                with mock.patch.object(regression.os, "killpg") as kill:
                    with self.assertRaises(Cancelled):
                        regression.execute(["fixture"], self.root, "spawn-cancel")
        kill.assert_called_once_with(12346, regression.signal.SIGKILL)
        proc.wait.assert_called_once_with(timeout=10)
        receipt = json.loads((self.root / "spawn-cancel.command.json").read_text())
        self.assertEqual(receipt["status"], "FAIL")
        self.assertIn("Cancelled", receipt["error"])

    def test_reclaim_masks_and_cleanup_are_independently_explicit(self):
        expected = regression.expected_cases("candidate")
        self.assertEqual(expected["bvec-failure-reclaim"]["free_bio"], 1)
        self.assertEqual(expected["bvec-failure-reclaim"]["pool_gfp"], regression.DIRECT | regression.IO)
        self.assertEqual(expected["bvec-failure-reclaim"]["slab_gfp"] & regression.DIRECT, 0)
        self.assertEqual(expected["bvec-failure-reclaim"]["opf"] & regression.CACHE_FLAG, 0)
        self.assertEqual(expected["bvec-failure-reclaim"]["nr"], 256)
        self.assertEqual(expected["large-bvec-success"]["nr"], 16)


if __name__ == "__main__":
    unittest.main()
