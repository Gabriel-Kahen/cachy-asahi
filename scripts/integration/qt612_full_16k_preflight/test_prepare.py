# SPDX-License-Identifier: MIT
"""Controls for the passive full-Qtbase dry-run projection."""

from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest


P = SimpleNamespace(**run_path(str(Path(__file__).with_name("prepare.py"))))


class DryRun(unittest.TestCase):
    def test_reported_work_is_a_multiset_subset_of_the_continuation(self):
        pending = b"compile A\ncompile B\ncompile B\nlink Qt\n"
        dry_run = b"[1/3] compile B\n[2/3] compile B\n[3/3] link Qt\n"
        self.assertEqual(P.dry_run_actions(P.NINJA_IDLE, dry_run, pending), 3)
        self.assertEqual(P.dry_run_actions(P.NINJA_IDLE, P.NINJA_IDLE, pending), 0)

    def test_gui_must_be_idle(self):
        with self.assertRaisesRegex(ValueError, "QtGui target is scheduled"):
            P.dry_run_actions(b"[1/1] rebuild Gui\n", P.NINJA_IDLE, b"link Qt\n")

    def test_foreign_and_duplicate_work_refused(self):
        pending = b"compile A\nlink Qt\n"
        for transcript in (b"[1/1] rerun configure\n", b"[1/2] compile A\n[2/2] compile A\n"):
            with self.subTest(transcript=transcript), self.assertRaisesRegex(ValueError, "exceeds the pinned"):
                P.dry_run_actions(P.NINJA_IDLE, transcript, pending)

    def test_missing_final_newline_and_bad_progress_refused(self):
        with self.assertRaisesRegex(ValueError, "finite Ninja"):
            P.dry_run_actions(P.NINJA_IDLE, b"[1/1] link Qt", b"link Qt\n")
        for transcript in (b"[2/1] link Qt\n", b"[1/2] link Qt\n"):
            with self.subTest(transcript=transcript), self.assertRaisesRegex(ValueError, "dry-run progress"):
                P.dry_run_actions(P.NINJA_IDLE, transcript, b"link Qt\n")

    def test_readback_checks_both_log_pins_and_grants_no_execution_credit(self):
        with TemporaryDirectory() as directory:
            files = {}
            for name, body in (("gui", P.NINJA_IDLE), ("all", b"[1/1] link Qt\n")):
                path = Path(directory) / name
                path.write_bytes(body)
                files[name] = (path, P.C.pin(body)["sha256"])
            observed = P.inspect_dry_run(files, b"link Qt\n")
            self.assertEqual(observed["reported_actions"], 1)
            self.assertFalse(observed["producer_authenticated"])
            self.assertEqual(observed["timing"], "NOT MEASURED")
            files["all"][0].write_bytes(b"[1/1] link wrong Qt\n")
            with self.assertRaisesRegex(ValueError, "External digest differs"):
                P.inspect_dry_run(files, b"link Qt\n")


if __name__ == "__main__":
    unittest.main()
