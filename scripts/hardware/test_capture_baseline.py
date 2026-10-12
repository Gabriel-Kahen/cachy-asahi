import importlib.util
from pathlib import Path
import tempfile
import unittest

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

    def test_missing_command_retains_failure(self):
        result = baseline.command(["/nonexistent/cachy-asahi-command"])
        self.assertIsNone(result["returncode"])
        self.assertIn("error", result)
        self.assertNotIn("stdout", result)

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


if __name__ == "__main__":
    unittest.main()
