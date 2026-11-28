# SPDX-License-Identifier: MIT
"""Exercise scoped clone command selection without launching a process."""

import errno
from pathlib import Path
from runpy import run_path
from types import SimpleNamespace
import unittest


OWNER = run_path(str(Path(__file__).with_name("runner.py")))


def need(condition, message):
    if not condition:
        raise ValueError(message)


class Controller:
    def __init__(self):
        self.paths = {"control": Path("/inputs/control"), "seed": Path("/inputs/seed.raw")}
        self.out = Path("/out/asahi629")
        self.calls = []
        self.failure = None
        self.receipt = {"status": "fixture"}

    def command(self, label, name, args, seconds, deadline):
        self.calls.append((label, name, args, seconds, deadline))
        if self.failure is not None:
            raise self.failure
        return self.receipt


class ReflinkTests(unittest.TestCase):
    def setUp(self):
        legacy = SimpleNamespace(Controller=Controller, CONTROL_FILES=Path("verified-candidate"),
                                 T=SimpleNamespace(need=need))
        self.controller = OWNER["scoped_controller"](legacy, None, None, None)()
        self.deadline = object()
        self.clones = {
            "clone-control-root": (Path("/inputs/control/verified-candidate/guest.raw"),
                                   Path("/out/asahi629/reference.raw")),
            "clone-asahi-target": (Path("/inputs/seed.raw"), Path("/out/asahi629/scratch.raw")),
        }

    def test_exact_clones_use_compatible_reflink_flags_and_preserve_paths_and_budgets(self):
        for label, paths in self.clones.items():
            with self.subTest(label=label):
                args = ["--sparse=always", "--reflink=never", *paths]
                seconds = 180 if label == "clone-control-root" else 300
                self.assertIs(self.controller.command(label, "cp", args, seconds, self.deadline),
                              self.controller.receipt)
                self.assertEqual(self.controller.calls[-1],
                                 (label, "cp", ["--sparse=auto", "--reflink=always", *paths],
                                  seconds, self.deadline))
                self.assertEqual(args, ["--sparse=always", "--reflink=never", *paths])

    def test_targeted_commands_refuse_drift_without_dispatch(self):
        for label, (src, dst) in self.clones.items():
            args = ["--sparse=always", "--reflink=never", src, dst]
            for name, changed in (
                ("/usr/bin/cp", args),
                ("mv", args),
                ("cp", ["--reflink=never", "--sparse=always", src, dst]),
                ("cp", ["--sparse=auto", "--reflink=never", src, dst]),
                ("cp", ["--sparse=always", "--reflink=auto", src, dst]),
                ("cp", ["--sparse=always", "--reflink=never", Path("/inputs/other.raw"), dst]),
                ("cp", ["--sparse=always", "--reflink=never", src, Path("/out/asahi629/other.raw")]),
                ("cp", [*args, "--verbose"]),
            ):
                with self.subTest(label=label, name=name, args=changed), self.assertRaises(ValueError):
                    self.controller.command(label, name, changed, 180, self.deadline)
        self.assertEqual(self.controller.calls, [])

    def test_unrelated_commands_pass_through(self):
        for label, name, args in (
            ("unrelated-copy", "cp", ["--sparse=always", "--reflink=never", *self.clones["clone-control-root"]]),
            ("prepare-control", "debugfs", ["-w", "/out/asahi629/reference.raw"]),
        ):
            with self.subTest(label=label):
                self.assertIs(self.controller.command(label, name, args, 90, self.deadline), self.controller.receipt)
                self.assertEqual(self.controller.calls[-1], (label, name, args, 90, self.deadline))
                self.assertIs(self.controller.calls[-1][2], args)

    def test_unsupported_reflink_propagates_without_a_copy_fallback(self):
        paths = self.clones["clone-asahi-target"]
        failure = OSError(errno.EOPNOTSUPP, "reflink unsupported")
        self.controller.failure = failure
        with self.assertRaises(OSError) as caught:
            self.controller.command("clone-asahi-target", "cp", ["--sparse=always", "--reflink=never", *paths],
                                    300, self.deadline)
        self.assertIs(caught.exception, failure)
        self.assertEqual(self.controller.calls, [
            ("clone-asahi-target", "cp", ["--sparse=auto", "--reflink=always", *paths], 300, self.deadline),
        ])


if __name__ == "__main__":
    unittest.main()
