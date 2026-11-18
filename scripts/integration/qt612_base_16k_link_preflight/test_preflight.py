# SPDX-License-Identifier: MIT
"""Passive controls. The actual graph readback is a separate CLI replay."""

from pathlib import Path
from runpy import run_path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import mock_open, patch

P = SimpleNamespace(**run_path(str(Path(__file__).with_name("preflight.py"))))


def fence(event, _args):
    if event.startswith(("subprocess.", "socket.", "os.exec", "os.posix_spawn", "os.system")):
        raise AssertionError("Actor or child process in passive test: " + event)


sys.addaudithook(fence)


class PreflightTests(unittest.TestCase):
    def test_tool_fence_refuses_compile_mount_or_mutation_modes(self):
        work = Path("/fixture")
        for argv, data in (
            (["/usr/bin/cmake", "--build", P.BUILD], None),
            (["/usr/bin/ninja", "-f", "/dev/stdin", "lib/libQt6Core.so"], b"fixture"),
            (["/usr/bin/ninja", "-f", "/dev/stdin", "-t", "commands", "install"], b"fixture"),
            (["/usr/bin/debugfs", "-w", "-R", "stats", "/fixture/scratch.raw"], None),
            (["/usr/bin/debugfs", "-R", "stats", "/original/scratch.raw"], None),
        ):
            with self.subTest(argv=argv), self.assertRaisesRegex(ValueError, "Read-only graph tool"):
                P.inspect_tool(work, argv, data)

    def test_only_one_local_rules_include_is_allowed(self):
        directive = b"include CMakeFiles/rules.ninja\n"
        for graph, rules, error in (
            (directive + b"subninja /remote/other.ninja\n", b"", "single Ninja rules include"),
            (directive, b"include /remote/other.ninja\n", "single Ninja rules include"),
            (directive, b"rule changed\n", "Exact flattened Q3 Ninja graph"),
        ):
            with self.subTest(graph=graph, rules=rules), self.assertRaisesRegex(ValueError, error):
                P.flatten(graph, rules)

    def test_counts_rule_nodes_and_direct_edges(self):
        dot = b"""digraph ninja {
"p1" [label="CXX_COMPILER__Core_Release", shape=ellipse]
"p2" -> "p3" [label=" C_COMPILER__Core_Release"]
"p4" [label="CXX_SHARED_LIBRARY_LINKER__Core_Release", shape=ellipse]
"p5" -> "p6" [label=" CMAKE_SYMLINK_LIBRARY"]
"p7" -> "p6" [arrowhead=none]
}"""
        self.assertEqual(P.graph_cost(dot), dict(edges=4, compiles=2, shared_libraries=["Core"],
                                                shared_links=1, symlink_edges=1))

    def test_resource_check_at_exact_host_gates_and_below(self):
        expected = 6 * P.GIB + 96 * P.MIB
        cpu = {0, 1, 2, 3}
        mem = "MemTotal:         9000000 kB\nMemAvailable:     8388608 kB\n"
        for difference, fits in ((0, True), (-1, False)):
            with patch.object(P.os, "statvfs", return_value=SimpleNamespace(f_bavail=expected + difference, f_frsize=1)), \
                 patch.object(P.os, "sched_getaffinity", return_value=cpu), \
                 patch.object(Path, "open", mock_open(read_data=mem)):
                profile = P.resources(Path("/fixture"), 11 * P.GIB)
            self.assertEqual(profile["numeric_caps_fit"], fits)
            self.assertFalse(profile["completion_budget_measured"])
            self.assertEqual(profile["owned_command"]["watched_tree"], ["/out", expected - 2 * P.GIB, 2 * P.GIB])
            self.assertEqual(profile["owned_command"]["watched_paths"],
                             [["/out/overlay.qcow2", 4 * P.GIB], ["/out/result.raw", 64 * P.MIB]])

    def test_terminal_requires_original_pin_and_refuses_alias(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            leaf = root / "selected"
            leaf.write_bytes(b"x" * P.Q3_TERMINAL[0])
            with self.assertRaisesRegex(ValueError, "Exact Q3 terminal bytes"):
                P.verify_terminal(leaf)
            alias = root / "alias"
            alias.symlink_to(leaf)
            with self.assertRaisesRegex(ValueError, "Canonical original path"):
                P.verify_terminal(alias)


if __name__ == "__main__":
    unittest.main(verbosity=2)
