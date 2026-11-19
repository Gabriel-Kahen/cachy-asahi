import importlib.util
from pathlib import Path
import os
import stat
import tempfile
import unittest
import sys
import io
import json
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("baseline", Path(__file__).with_name("capture-baseline.py"))
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


class BaselineTests(unittest.TestCase):
    def test_target_identity_is_exact_and_architecture_gated(self):
        self.assertIsNone(baseline.target_size("x86_64", "apple,j413\napple,t8112"))
        self.assertIsNone(baseline.target_size("aarch64", "apple,j413-other"))
        self.assertIsNone(baseline.target_size("aarch64", None))
        self.assertEqual(baseline.target_size("aarch64", "apple,j413\napple,t8112"), "13-inch")
        self.assertEqual(baseline.target_size("aarch64", "apple,j415\napple,t8112"), "15-inch")
        # Regression: Contradictory IDs must return None
        self.assertIsNone(baseline.target_size("aarch64", "apple,j413\napple,j415"))
        self.assertIsNone(baseline.target_size("aarch64", "apple,j415\napple,j413"))

    def test_missing_command_retains_failure(self):
        probe = baseline.session_probe()
        with patch.object(probe, "query", return_value=("command-absent", None, b"", b"")):
            result = baseline.command(["pacman", "-Q"], {"local": ({"PATH": "/usr/bin:/bin"}, ())})
        self.assertEqual(result, {"command": ["pacman", "-Q"], "returncode": None, "error": "command-absent"})

    def test_local_probes_keep_schema_and_ignore_ambient_command_environment(self):
        probe = baseline.session_probe()
        env = {"PATH": "/untrusted", "LC_ALL": "untrusted", "GIT_DIR": "/wrong",
               "GIT_EXTERNAL_DIFF": "/wrong/diff", "LD_PRELOAD": "/wrong/lib.so"}
        with patch.dict(os.environ, env, clear=True), patch.object(
                probe, "query", return_value=("query-warning", 0, "café 1\n".encode(), b"warning\n")) as query:
            contexts = probe.contexts(os.environ)
            result = baseline.command(["pacman", "-Q"], contexts)
            actual, deadline, clean = query.call_args.args
            self.assertEqual(actual, ["/usr/bin/pacman", "-Q"])
            self.assertEqual(deadline, 20)
            self.assertEqual(clean["PATH"], "/usr/bin:/bin")
            self.assertEqual(clean["LC_ALL"], "C")
            self.assertNotIn("LD_PRELOAD", clean)
            self.assertEqual(result, {"command": ["pacman", "-Q"], "returncode": 0,
                                      "stdout": "café 1", "stderr": "warning"})
            baseline.command(["git", "-C", "/repo", "status", "--porcelain"], contexts)
            actual, _, clean = query.call_args.args
            self.assertEqual(actual[:3], ["/usr/bin/git", "-c", "core.fsmonitor=false"])
            self.assertEqual(clean["GIT_OPTIONAL_LOCKS"], "0")
            self.assertNotIn("GIT_DIR", clean)
            self.assertNotIn("GIT_EXTERNAL_DIFF", clean)

    def test_session_unavailable_or_replaced_omits_untrusted_output(self):
        probe = baseline.session_probe()
        argv = ["wpctl", "status"]
        path = Path("/run/user/1000/pipewire-0")
        contexts = {"audio": ({"PIPEWIRE_RUNTIME_DIR": str(path.parent), "PIPEWIRE_REMOTE": path.name}, ((path, 1000),))}
        with patch.object(probe, "query", return_value=("observed", 0, b"session details", b"")) as query:
            self.assertEqual(baseline.command(argv, {})["error"], "local-endpoint-unavailable")
            query.assert_not_called()
            with patch.object(probe, "socket_snapshot", side_effect=[("known",), ("known",)]):
                self.assertEqual(baseline.command(argv, contexts)["stdout"], "session details")
            with patch.object(probe, "socket_snapshot", side_effect=[("known",), ("changed",)]):
                result = baseline.command(argv, contexts)
            self.assertEqual(result, {"command": argv, "returncode": None, "error": "local-endpoint-changed"})

    def test_bounded_probe_errors_do_not_publish_partial_output(self):
        probe = baseline.session_probe()
        contexts = {"local": ({}, ())}
        for reason in ("output-limit", "timeout", "child-reservation-lost"):
            with self.subTest(reason=reason), patch.object(
                    probe, "query", return_value=(reason, -9, b"partial", b"partial")):
                self.assertEqual(baseline.command(["pacman", "-Q"], contexts),
                                 {"command": ["pacman", "-Q"], "returncode": None, "error": reason})

    def test_private_output_over_permissive_umask_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "new" / "nested" / "capture.json"
            previous = os.umask(0)
            try:
                baseline.write_private(path, "private record")
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            for parent in (path.parent, path.parent.parent):
                self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
            with self.assertRaises(FileExistsError):
                baseline.write_private(path, "replace")
            self.assertEqual(path.read_text(), "private record")

    def test_output_refuses_linked_filename_and_ancestor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir()
            link = root / "path"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(OSError):
                baseline.write_private(link / "capture.json", "private record")
            leaf = root / "report.json"
            leaf.symlink_to(target / "existing")
            with self.assertRaises(FileExistsError):
                baseline.write_private(leaf, "private record")
            self.assertEqual(list(target.iterdir()), [])

    def test_offline_identity_import_can_stand_alone(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture-baseline.py"
            path.write_bytes(Path(baseline.__file__).read_bytes())
            module = importlib.util.spec_from_file_location("capture_identity_only", path)
            copied = importlib.util.module_from_spec(module)
            module.loader.exec_module(copied)
            self.assertEqual(copied.target_size("aarch64", "apple,j413"), "13-inch")

    def test_repository_snapshot_is_content_identified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "pacman.conf").write_text("[options]\n[core]\nInclude = /etc/pacman.d/mirrorlist\n")
            (root / "core.db").write_bytes(b"first")
            first = baseline.repository_facts(root / "pacman.conf", root)
            (root / "core.db").write_bytes(b"second")
            second = baseline.repository_facts(root / "pacman.conf", root)
            self.assertEqual(first["configured_repositories"], ["core"])
            self.assertNotEqual(first["sync_databases"][0]["sha256"], second["sync_databases"][0]["sha256"])

    def test_required_m2_capture_checks_identity_and_page_size_but_retains_raw_report(self):
        cases = (
            ("13-inch", "apple,j413\napple,t8112", 16384, "physical", 0),
            ("15-inch", "apple,j415\napple,t8112\napple,arm-platform", 16384, "physical", 0),
            ("13-inch", "apple,j413", 16384, "physical", 2),
            ("15-inch", "apple,j415\napple,t8103", 16384, "physical", 2),
            ("13-inch", "apple,j413\napple,j413\napple,t8112", 16384, "physical", 2),
            ("13-inch", "apple,j413\napple,t8112\napple,t8112", 16384, "physical", 2),
            (None, "apple,j413\napple,j415\napple,t8112", 16384, "physical", 2),
            ("13-inch", "apple,j413\napple,t8112", 4096, "physical", 2),
            ("13-inch", "apple,j413\napple,t8112", 16384, "virtual", 2),
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, (label, compatible, pages, context, expected) in enumerate(cases):
                with self.subTest(compatible=compatible, pages=pages, context=context):
                    output = Path(directory) / f"{index}.json"
                    args = ["capture-baseline.py", "--operator", "test", "--execution-context", context,
                            "--require-m2-air", "--output", str(output)]
                    with patch.object(sys, "argv", args), \
                         patch.object(baseline.platform, "machine", return_value="aarch64"), \
                         patch.object(baseline.os, "sysconf", return_value=pages), \
                         patch.object(baseline, "read_text", return_value=compatible), \
                         patch.object(baseline, "command", return_value={}), \
                         patch.object(baseline, "repository_facts", return_value={}), \
                         patch("sys.stdout", new=io.StringIO()) as stdout, \
                         patch("sys.stderr", new=io.StringIO()) as stderr:
                        self.assertEqual(baseline.main(), expected)
                    self.assertEqual(stdout.getvalue(), "")
                    self.assertEqual("hardware gates remain NOT RUN" in stderr.getvalue(), expected == 2)
                    self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
                    record = json.loads(output.read_bytes())
                    self.assertEqual(record["m2_air_size"], label)
                    self.assertEqual(record["page_size_bytes"], pages)
                    self.assertEqual(record["validation_result"], "NOT RUN")


if __name__ == "__main__":
    unittest.main()
