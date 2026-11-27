# SPDX-License-Identifier: MIT
"""Source-level checks for the Asahi629 runtime fixture."""

from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch


R = runpy.run_path(str(Path(__file__).with_name("runtime.py")))
DIRECT = R["DIRECT"]
PIPEWIRE = R["PIPEWIRE"]


def link(name, directory="/usr/lib"):
    return f"\t{name} => {directory}/{name} (0x0000f123)\n"


class LoaderTests(unittest.TestCase):
    def test_both_phases_and_pipewire(self):
        for version in ("2.1", "2.2"):
            jbig = f"libjbig.so.{version}"
            output = link("libtiff.so.6") + link(jbig, "/lib") + link("libspandsp.so.2")
            self.assertEqual(R["loader_paths"](output, version, pipewire=True), {
                "tiff": "/usr/lib/libtiff.so.6", "jbig": f"/lib/{jbig}", "span": "/usr/lib/libspandsp.so.2",
            })

    def test_missing_duplicate_stale_or_outside_resolution_refuses(self):
        tiff = link("libtiff.so.6")
        valid = tiff + link("libjbig.so.2.2")
        for output in (tiff, valid + tiff, valid + link("libjbig.so.2.1"), valid + "libfoo.so => not found",
                       tiff + link("libjbig.so.2.2", "/tmp")):
            with self.subTest(output=output):
                with self.assertRaises(RuntimeError):
                    R["loader_paths"](output, "2.2")
        with self.assertRaises(RuntimeError):
            R["loader_paths"](valid, "2.2", pipewire=True)


class CommandTests(unittest.TestCase):
    def test_application_commands_enter_owned_chroot_as_ordinary_user(self):
        root = Path("/trial-scratch")
        probe = R["Probe"](root, root / "tmp/scratch")
        with patch.dict(R["execute"].__globals__, {"execute": lambda argv, seconds: (argv, seconds)}):
            argv, seconds = probe.command("/usr/bin/tificc", "a", "b", seconds=17)
        self.assertEqual(seconds, 17)
        self.assertEqual(argv[:5], ["/usr/bin/chroot", str(root), "/usr/bin/setpriv", "--reuid=65534",
                                   "--regid=65534"])
        for option in ("--clear-groups", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all",
                       "--bounding-set=-all", "-i", "HOME=/tmp/scratch/work"):
            self.assertIn(option, argv)
        self.assertEqual(argv[-3:], ["/usr/bin/tificc", "a", "b"])

    def test_failed_execution_and_output_limit(self):
        execute = R["execute"]
        self.assertEqual(execute([sys.executable, "-I", "-c", "print('result')"], 3), "result\n")
        for script, expected in (
            ("raise SystemExit(5)", "exit 5"),
            ("print('a' * 65536)", "output cap"),
        ):
            with self.subTest(script=script), self.assertRaisesRegex(RuntimeError, expected):
                execute([sys.executable, "-I", "-c", script], 3)
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            execute([sys.executable, "-I", "-c", "import time; time.sleep(30)"], 0.1)

    def test_exact_marker_required(self):
        probe = R["Probe"](Path("/trial-scratch"), Path("/trial-scratch/tmp/scratch"))
        for output in ("", "expected expected\n", "expected\nexpected\n"):
            with self.subTest(output=output), patch.object(probe, "command", return_value=output):
                with self.assertRaisesRegex(RuntimeError, "one marker"):
                    probe.marker("expected", "/usr/bin/example")
        with patch.object(probe, "command", return_value="expected\n"):
            probe.marker("expected", "/usr/bin/example")

    def test_every_locked_member_is_loaded_and_each_functional_check_is_called(self):
        probe = R["Probe"](Path("/trial-scratch"), Path("/trial-scratch/tmp/scratch"))

        def fake(*args, **kwargs):
            program, *remainder = args
            if program == R["LOADER"]:
                self.assertEqual(remainder[0], "--list")
                libraries = ("libtiff.so.6", "libjbig.so.2.2")
                if remainder[1] == PIPEWIRE:
                    libraries += ("libspandsp.so.2",)
                return "".join(link(name) for name in libraries)
            if program == "/usr/bin/pkg-config":
                return "-lgtk-4 -ltiff -lspandsp\n"
            if program == "/usr/bin/tiffinfo":
                return "Image Width: 32 Image Length: 4\nCompression Scheme: ISO JBIG\n"
            return ""

        with patch.object(probe, "command", side_effect=fake) as run, patch.object(probe, "marker") as marker:
            self.assertEqual(set(probe.check("2.2")), set((*DIRECT, PIPEWIRE)))
        self.assertEqual([call.args[2] for call in run.call_args_list if call.args[0] == R["LOADER"]],
                         [*DIRECT, PIPEWIRE])
        for tool in ("tificc", "opj_compress", "opj_dump", "opj_decompress"):
            self.assertIn(f"/usr/bin/{tool}", [call.args[0] for call in run.call_args_list])
        self.assertEqual([call.args[0] for call in marker.call_args_list],
                         ["TIFF JBIG roundtrip passed", "RGB_TIFF_FIXTURE_WRITTEN",
                          "RGB_TIFF_PIXELS_MATCH", "GTK_TIFF_PIXELS_MATCH", "RGB_TIFF_PIXELS_MATCH",
                          "SPANDSP_TIFF_FAX_PAGE_ENCODED", "PIPEWIRE_MSBC_PLUGIN_LOADED"])

    def test_non_guest_and_unknown_soname_refuse(self):
        for root, version in ((Path("/"), "2.2"), (Path("/trial-scratch"), "2.3")):
            with self.subTest(root=root, version=version), self.assertRaises((RuntimeError, ValueError)):
                R["run"](root, Path("/unused"), Path("/unused"), soname=version)


class SourceTests(unittest.TestCase):
    def test_only_bounded_regular_source_files_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source = base / "source.c"
            source.write_bytes(b"test")
            bad = base / "symlink.c"
            bad.symlink_to(source)
            dest = base / "dest.c"
            with self.assertRaises(RuntimeError):
                R["copy_source"](bad, dest)
            self.assertFalse(dest.exists())
            R["copy_source"](source, dest)
            self.assertEqual(dest.read_bytes(), b"test")
            self.assertEqual(dest.stat().st_mode & 0o777, 0o444)
            with self.assertRaises(FileExistsError):
                R["copy_source"](source, dest)


if __name__ == "__main__":
    unittest.main()
