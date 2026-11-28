# SPDX-License-Identifier: MIT
"""Source-level checks for the Asahi629 runtime fixture."""

from pathlib import Path
import base64
import copy
import random
import runpy
import sys
import tempfile
import unittest
from unittest.mock import patch


R = runpy.run_path(str(Path(__file__).with_name("runtime.py")))
READER = runpy.run_path(str(Path(__file__).with_name("readback.py")))
DIRECT = R["DIRECT"]
PIPEWIRE = R["PIPEWIRE"]
ROOT = Path("/trial-scratch")
SCRATCH = ROOT / "tmp/jbig-tiff629-phase001"


class Check:
    @staticmethod
    def need(condition, message):
        if not condition:
            raise ValueError(message)


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
        for output in (tiff, valid + tiff, valid + link("libjbig.so.2.1"), valid + link("libjbig85.so.2.1"),
                       valid + "libfoo.so => not found",
                       tiff + link("libjbig.so.2.2", "/tmp")):
            with self.subTest(output=output):
                with self.assertRaises(RuntimeError):
                    R["loader_paths"](output, "2.2")
        with self.assertRaises(RuntimeError):
            R["loader_paths"](valid, "2.2", pipewire=True)


class CommandTests(unittest.TestCase):
    def test_application_commands_enter_owned_chroot_as_ordinary_user(self):
        probe = R["Probe"](ROOT, SCRATCH)
        with patch.object(probe, "step", return_value=dict(problem=None, exit=0, output=b"")) as step:
            probe.command("/usr/bin/tificc", "a", "b", seconds=17)
        argv, seconds = step.call_args.args
        self.assertEqual(seconds, 17)
        self.assertEqual(argv[:5], ["/usr/bin/chroot", str(ROOT), "/usr/bin/setpriv", "--reuid=65534",
                                   "--regid=65534"])
        for option in ("--clear-groups", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all",
                       "--bounding-set=-all", "-i", "HOME=/tmp/jbig-tiff629-phase001/work"):
            self.assertIn(option, argv)
        self.assertEqual(argv[-3:], ["/usr/bin/tificc", "a", "b"])

    def test_failed_execution_and_output_limit(self):
        execute = R["execute"]
        self.assertEqual(execute([sys.executable, "-I", "-c", "print('result')"], 3),
                         outcome(b"result\n"))
        both = "import os; os.write(1, b'out'); os.write(2, b'\\xfferr'); raise SystemExit(5)"
        self.assertEqual(execute([sys.executable, "-I", "-c", both], 3), outcome(b"out\xfferr", exit_code=5))
        capped = execute([sys.executable, "-I", "-c", "print('a' * 65536)"], 3)
        self.assertEqual((capped["problem"], capped["output"], capped["truncated"]),
                         ("output-cap", b"a" * R["MAX_OUTPUT"], True))
        delayed = "import os, time; os.write(2, b'waiting'); time.sleep(30)"
        timeout = execute([sys.executable, "-I", "-c", delayed], 0.5)
        self.assertEqual((timeout["problem"], timeout["output"], timeout["truncated"]), ("timeout", b"waiting", True))
        self.assertIsInstance(timeout["exit"], int)
        self.assertEqual(execute(["/missing/cachy-asahi-runtime-test"], 1), outcome(exit_code=None, problem="spawn"))

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


def outcome(raw=b"", *, exit_code=0, problem=None):
    return dict(exit=exit_code, problem=problem, output=raw, truncated=problem not in (None, "spawn"))


def successful(argv, _seconds):
    args = argv[argv.index("GIO_USE_VFS=local") + 1:]
    tool, *rest = args
    if tool == R["LOADER"]:
        libraries = ("libtiff.so.6", "libjbig.so.2.2") + (("libspandsp.so.2",) if rest[1] == PIPEWIRE else ())
        return outcome("".join(link(name) for name in libraries).encode())
    if tool == "/usr/bin/pkg-config":
        return outcome(b"-lgtk-4 -ltiff -lspandsp\n")
    if tool == "/usr/bin/tiffinfo":
        return outcome(b"Image Width: 32 Image Length: 4\nCompression Scheme: ISO JBIG\n")
    if tool.endswith("/roundtrip"):
        return outcome(b"TIFF JBIG roundtrip passed\n")
    if tool == "/usr/bin/python3":
        return outcome(b"PIPEWIRE_MSBC_PLUGIN_LOADED\n")
    if tool.endswith("/fixture"):
        marker = {"write-rgb": "RGB_TIFF_FIXTURE_WRITTEN", "check-rgb": "RGB_TIFF_PIXELS_MATCH",
                  "gtk": "GTK_TIFF_PIXELS_MATCH", "fax": "SPANDSP_TIFF_FAX_PAGE_ENCODED"}[rest[0]]
        return outcome((marker + "\n").encode())
    return outcome()


class ReplayTests(unittest.TestCase):
    def test_full_replay_and_raw_output_tamper(self):
        report = R["Probe"](ROOT, SCRATCH, executor=successful).receipt("2.2")
        read = READER["read_runtime"]
        self.assertEqual(len(report["commands"]), 23)
        read(Check, report, "2.2")
        for field, new in ((0, "0" * 64), (1, 23), (3, "AAAA"), (4, 10)):
            tampered = copy.deepcopy(report)
            tampered["commands"][0][field] = new
            with self.subTest(field=field), self.assertRaises(ValueError):
                read(Check, tampered, "2.2")
        tampered = copy.deepcopy(report)
        marker = next(row for row in tampered["commands"] if row[3] == R["armor"](b"GTK_TIFF_PIXELS_MATCH\n"))
        replacement = b"GTK_TIFF_PIXELS_MISSING\n"
        marker[3:5] = [R["armor"](replacement), len(replacement)]
        with self.assertRaisesRegex(ValueError, "commands after"):
            read(Check, tampered, "2.2")

    def test_replay_retains_partial_timeout_and_refuses_unobserved_success(self):
        def expired(*_args):
            return outcome(b"first bytes\x00\xff", exit_code=-9, problem="timeout")

        report = R["Probe"](ROOT, SCRATCH, executor=expired).receipt("2.2")
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["commands"][0][1:3], [-9, "timeout"])
        self.assertEqual(list(READER["command_records"](Check, report["commands"]))[0][1]["output"],
                         b"first bytes\x00\xff")
        READER["read_runtime"](Check, report, "2.2", held=True)
        with self.assertRaisesRegex(ValueError, "failed in a completed"):
            READER["read_runtime"](Check, report, "2.2")
        report["failure"] = "a different reason"
        with self.assertRaisesRegex(ValueError, "summary differs"):
            READER["read_runtime"](Check, report, "2.2", held=True)

    def test_budget_refuses_success_and_preserves_only_a_bounded_prefix(self):
        random_bytes = random.Random(42).randbytes(R["MAX_OUTPUT"])
        report = R["Probe"](ROOT, SCRATCH, executor=lambda *_: outcome(random_bytes)).receipt("2.2")
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["commands"][0][1:3], [0, "receipt-cap"])
        self.assertEqual(list(READER["command_records"](Check, report["commands"]))[0][1]["output"],
                         random_bytes[:256])
        READER["read_runtime"](Check, report, "2.2", held=True)

    def test_output_decoder_rejects_trailing_stream_and_expansion(self):
        good = R["armor"](b"two bytes")
        self.assertEqual(READER["command_output"](Check, good, 9), b"two bytes")
        trailing = base64.b64encode(base64.b64decode(good) + base64.b64decode(good)).decode()
        for packed, size in ((good, 2), (good, 10), (trailing, 9), (good + "\n", 9), (good, 0)):
            with self.subTest(packed=packed, size=size), self.assertRaises(ValueError):
                READER["command_output"](Check, packed, size)


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
