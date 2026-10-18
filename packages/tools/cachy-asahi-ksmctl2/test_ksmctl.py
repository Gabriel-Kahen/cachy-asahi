#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 cachy-asahi contributors.
"""Read-only KSM regressions using temporary sysfs-like fixtures only."""
import sys
sys.dont_write_bytecode = True

from contextlib import redirect_stderr, redirect_stdout
from decimal import Decimal, localcontext
import difflib
import hashlib
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("cachy-asahi-ksmctl")
PAGE_COUNTERS = ("pages_shared", "pages_sharing", "pages_unshared", "pages_volatile",
                 "pages_scanned", "pages_skipped", "ksm_zero_pages")
COUNTERS = (*PAGE_COUNTERS, "full_scans", "general_profit")
loader = SourceFileLoader("cachy_asahi_ksmctl_fixture", str(SCRIPT))
ksm = module_from_spec(spec_from_loader(loader.name, loader))
loader.exec_module(ksm)


def snapshot(root):
    result = {}
    for path in root.rglob("*"):
        info = path.lstat()
        data = (os.readlink(path) if stat.S_ISLNK(info.st_mode)
                else path.read_bytes() if stat.S_ISREG(info.st_mode) else None)
        result[str(path.relative_to(root))] = (info.st_mode, info.st_mtime_ns, data)
    return result


class KsmTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cachy-asahi-ksm-test-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.root = self.work / "ksm"
        self.root.mkdir()
        self.put("run", b"1\n")
        for index, name in enumerate(COUNTERS, 1):
            self.put(name, str(index).encode() + b"\n")

    def put(self, name, data):
        path = self.root / name
        if path.exists():
            path.chmod(0o644)
        path.write_bytes(data)
        path.chmod(0o444)

    def readonly(self, function, *args, **kwargs):
        before = snapshot(self.work)
        try:
            return function(*args, **kwargs)
        finally:
            self.assertEqual(snapshot(self.work), before)
            self.assertFalse(list(self.work.rglob("__pycache__")))

    def assert_error(self, function, *args, code=1, **kwargs):
        with self.assertRaises(ksm.Error) as caught:
            self.readonly(function, *args, **kwargs)
        self.assertEqual(caught.exception.code, code)

    def cli(self, arguments, root=None):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            try:
                code = self.readonly(ksm.main, arguments, root=self.root if root is None else root)
            except SystemExit as error:
                code = error.code
        self.assertIs(type(code), int)
        return code, output.getvalue(), errors.getvalue()

    def test_exact_4k_and_16k_conversion_and_units(self):
        for size in (4096, 16384):
            with self.subTest(page_size=size):
                data = self.readonly(ksm.report, self.root, page_size=size)
                self.assertEqual(data["page_size_bytes"], size)
                self.assertFalse(data["management_available"])
                self.assertEqual(set(data["counters"]), set(COUNTERS))
                for index, name in enumerate(COUNTERS, 1):
                    counter = data["counters"][name]
                    self.assertEqual(counter["value"], index)
                    self.assertEqual(counter["unit"], "pages" if name in PAGE_COUNTERS else "scans" if name == "full_scans" else "bytes")
                    if name == "full_scans":
                        self.assertIsNone(counter["mib"])
                    else:
                        self.assertIsInstance(counter["mib"], str)
                        scale = size if name in PAGE_COUNTERS else 1
                        self.assertEqual(Decimal(counter["mib"]), Decimal(index * scale) / 1048576)

    def test_runtime_page_size_is_read_from_os(self):
        with mock.patch.object(ksm.os, "sysconf", return_value=16384) as query:
            data = self.readonly(ksm.report, self.root)
        query.assert_called_once_with("SC_PAGE_SIZE")
        self.assertEqual(data["page_size_bytes"], 16384)
        self.assertEqual(Decimal(data["counters"]["pages_shared"]["mib"]), Decimal("0.015625"))

    def test_bad_runtime_page_sizes_and_sysconf_failure(self):
        for size in (0, -1, 1048577, True, False, 4096.0, float("nan"), float("inf"), "4096", Decimal(4096)):
            with self.subTest(size=repr(size)):
                self.assert_error(ksm.report, self.root, page_size=size)
        for error in (OSError("fixture sysconf failure"), ValueError("fixture sysconf failure")):
            with mock.patch.object(ksm.os, "sysconf", side_effect=error):
                self.assert_error(ksm.report, self.root)
        for size in (1, 1048576):
            self.assertEqual(self.readonly(ksm.report, self.root, page_size=size)["page_size_bytes"], size)

    def test_stopped_scanning_unmerging_and_unknown_states(self):
        descriptions = set()
        for value in (0, 1, 2):
            self.put("run", f"{value}\n".encode())
            self.assertEqual(self.readonly(ksm.status, self.root), value)
            data = self.readonly(ksm.report, self.root, page_size=16384)
            self.assertEqual(data["state"]["run"], value)
            self.assertIsInstance(data["state"]["description"], str)
            descriptions.add(data["state"]["description"])
        self.assertEqual(len(descriptions), 3)
        for value in (b"3\n", b"99\n", b"-1\n"):
            self.put("run", value)
            self.assert_error(ksm.status, self.root)

    def test_absent_root_run_and_optional_counters(self):
        self.assert_error(ksm.status, self.work / "absent", code=3)
        self.assert_error(ksm.report, self.work / "absent", page_size=4096, code=3)
        (self.root / "run").unlink()
        self.assert_error(ksm.status, self.root, code=3)
        self.assert_error(ksm.report, self.root, page_size=4096, code=3)
        self.put("run", b"1\n")
        for name in COUNTERS:
            (self.root / name).unlink()
        data = self.readonly(ksm.report, self.root, page_size=16384)
        for name in COUNTERS:
            self.assertIsNone(data["counters"][name]["value"])
            self.assertIsNone(data["counters"][name]["mib"])

    def test_strict_decimal_lf_and_bounded_reads(self):
        invalid = (b"", b"1", b"1\n\n", b"1\r\n", b" 1\n", b"1 \n", b"+1\n",
                   b"nan\n", b"inf\n", b"1.0\n", b"1e3\n", b"1\x00\n", b"\xff\n", b"1\nextra", b"1" * 65 + b"\n")
        for value in invalid:
            with self.subTest(value=repr(value[:30])):
                self.put("run", value)
                self.assert_error(ksm.status, self.root)
                self.put("run", b"1\n")
                self.put("pages_shared", value)
                self.assert_error(ksm.report, self.root, page_size=4096)
        self.put("pages_shared", b"1\n")
        self.put("general_profit", b"not-a-number\n")
        self.assert_error(ksm.report, self.root, page_size=4096)

    def test_unsigned_page_and_scan_bounds(self):
        maximum = (1 << 64) - 1
        for name in ("pages_shared", "full_scans"):
            self.put(name, f"{maximum}\n".encode())
        data = self.readonly(ksm.report, self.root, page_size=16384)
        self.assertEqual(data["counters"]["pages_shared"]["value"], maximum)
        self.assertEqual(data["counters"]["full_scans"]["value"], maximum)
        with localcontext() as context:
            context.prec = 80
            self.assertEqual(Decimal(data["counters"]["pages_shared"]["mib"]), Decimal(maximum * 16384) / 1048576)
        for name in ("pages_shared", "full_scans"):
            for value in (-1, 1 << 64):
                self.put(name, f"{value}\n".encode())
                self.assert_error(ksm.report, self.root, page_size=16384)
            self.put(name, b"1\n")

    def test_signed_profit_bounds_and_exact_fraction(self):
        for value in (-(1 << 63), -1, 0, 1, (1 << 63) - 1):
            self.put("general_profit", f"{value}\n".encode())
            data = self.readonly(ksm.report, self.root, page_size=16384)
            counter = data["counters"]["general_profit"]
            self.assertEqual(counter["value"], value)
            self.assertEqual(counter["unit"], "bytes")
            with localcontext() as context:
                context.prec = 80
                self.assertEqual(Decimal(counter["mib"]), Decimal(value) / 1048576)
        for value in (-(1 << 63) - 1, 1 << 63):
            self.put("general_profit", f"{value}\n".encode())
            self.assert_error(ksm.report, self.root, page_size=16384)

    def test_unreadable_interface_and_io_failure(self):
        original = os.open

        def denied(path, *args, **kwargs):
            if not isinstance(path, int) and Path(path).name == "run":
                raise PermissionError("fixture unreadable run")
            return original(path, *args, **kwargs)

        with mock.patch.object(ksm.os, "open", side_effect=denied):
            self.assert_error(ksm.status, self.root)
        with mock.patch.object(ksm.os, "read", side_effect=OSError("fixture IO failure")):
            self.assert_error(ksm.report, self.root, page_size=4096)

    def test_symlink_and_special_interface_refusals(self):
        linked = self.work / "linked-root"
        linked.symlink_to(self.root, target_is_directory=True)
        self.assert_error(ksm.status, linked)
        outside = self.work / "outside-value"
        outside.write_bytes(b"1\n")
        for name in ("run", "pages_shared"):
            path = self.root / name
            path.unlink()
            path.symlink_to(outside)
            if name == "run":
                self.assert_error(ksm.status, self.root)
            else:
                self.assert_error(ksm.report, self.root, page_size=4096)
            path.unlink()
            path.mkdir()
            if name == "run":
                self.assert_error(ksm.status, self.root)
            else:
                self.assert_error(ksm.report, self.root, page_size=4096)
            path.rmdir()
            os.mkfifo(path)
            if name == "run":
                self.assert_error(ksm.status, self.root)
            else:
                self.assert_error(ksm.report, self.root, page_size=4096)
            path.unlink()
            self.put(name, b"1\n")

    def test_cli_aliases_and_json_reports(self):
        for arguments in ([], ["--status"], ["-s"]):
            code, output, errors = self.cli(arguments)
            self.assertEqual(code, 0, errors)
            self.assertTrue(output.strip())
        code, output, errors = self.cli(["--status", "--json"])
        self.assertEqual(code, 0, errors)
        data = json.loads(output)
        self.assertEqual(data["state"]["run"], 1)
        self.assertFalse(data["management_available"])
        self.assertNotIn("counters", data)
        with mock.patch.object(ksm.os, "sysconf", return_value=16384):
            for arguments in (["--report", "--json"], ["-r", "--json"]):
                code, output, errors = self.cli(arguments)
                self.assertEqual(code, 0, errors)
                data = json.loads(output)
                self.assertEqual(data["page_size_bytes"], 16384)
                self.assertFalse(data["management_available"])
                self.assertEqual(Decimal(data["counters"]["pages_shared"]["mib"]), Decimal("0.015625"))

    def test_mutating_args_rejected_before_any_reads(self):
        arguments = (["--enable"], ["--disable"], ["--unmerge"], ["--scan"], ["--run", "1"],
                     ["--root", str(self.root)], ["-e"], ["-d"], ["-u"], ["--status", "--report"])
        with mock.patch.object(ksm.os, "open", side_effect=AssertionError("unexpected interface read")), \
             mock.patch.object(ksm.os, "sysconf", side_effect=AssertionError("unexpected sysconf read")):
            for argv in arguments:
                with self.subTest(argv=argv):
                    self.assertEqual(self.cli(argv)[0], 2)

    def test_help_and_version_need_no_interface_and_write_nothing(self):
        with mock.patch.object(ksm.os, "open", side_effect=AssertionError("unexpected interface read")), \
             mock.patch.object(ksm.os, "sysconf", side_effect=AssertionError("unexpected sysconf read")):
            for argv in (["--help"], ["--version"]):
                code, output, errors = self.cli(argv, root=self.work / "absent")
                self.assertEqual(code, 0, errors)
                self.assertTrue(output.strip())
        self.assertEqual(ksm.DEFAULT_ROOT, Path("/sys/kernel/mm/ksm"))

    def test_cli_errors_preserve_distinct_missing_interface_exit(self):
        code, output, errors = self.cli(["--status"], root=self.work / "absent")
        self.assertEqual(code, 3)
        self.assertFalse(output)
        self.assertTrue(errors)
        self.put("run", b"99\n")
        code, output, errors = self.cli(["--status"])
        self.assertEqual(code, 1)
        self.assertFalse(output)
        self.assertTrue(errors)


class ProvenanceTests(unittest.TestCase):
    """Tamper copied inputs without executing either upstream or derived CLI."""
    FILES = ("check-source.py", "source-provenance.json", "upstream-ksmctl",
             "cachy-asahi-ksmctl", "LICENSE", "adaptation.patch")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="cachy-asahi-ksm-provenance-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.originals = {name: (SCRIPT.parent / name).read_bytes() for name in self.FILES}
        self.reset()

    def reset(self):
        for name, data in self.originals.items():
            (self.root / name).write_bytes(data)

    def rehash(self, name, key):
        path = self.root / "source-provenance.json"
        record = json.loads(path.read_bytes())
        record[key] = hashlib.sha256((self.root / name).read_bytes()).hexdigest()
        path.write_text(json.dumps(record) + "\n")

    def check(self, valid):
        before = snapshot(self.root)
        result = subprocess.run([sys.executable, "-B", str(self.root / "check-source.py")],
                                cwd=self.root, capture_output=True, text=True, timeout=10,
                                env={**os.environ, "HOME": str(self.home),
                                     "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(snapshot(self.root), before)
        self.assertFalse(list(self.root.rglob("__pycache__")))
        self.assertEqual(result.returncode, 0 if valid else 1, result.stdout + result.stderr)
        return result

    def test_reviewed_bundle_passes_with_full_origin_and_license_pins(self):
        record = json.loads(self.originals["source-provenance.json"])
        self.assertEqual(record["upstream_commit"], "c7cf5b4f2c70f28ed50601b3f75b19da93ba663f")
        self.assertEqual(record["upstream_sha256"], "cd5c8aa86df5a06a268ecc21297b4cd7d8df1053c90c8bcd4e53ef9bb16194d9")
        self.assertEqual(record["license_sha256"], "edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6")
        self.assertEqual(record["license"], "GPL-2.0-or-later")
        self.check(True)

    def test_original_and_license_drift_fail_even_with_refreshed_hashes(self):
        for name, key in (("upstream-ksmctl", "upstream_sha256"), ("LICENSE", "license_sha256")):
            for coherent in (False, True):
                with self.subTest(name=name, coherent=coherent):
                    self.reset()
                    path = self.root / name
                    path.write_bytes(path.read_bytes() + b"\nTampered fixture text\n")
                    if coherent:
                        self.rehash(name, key)
                    result = self.check(False)
                    self.assertIn("reviewed origin/license" if coherent else "source provenance", result.stderr)

    def test_altered_patch_fails_with_stale_or_coherent_hash(self):
        for coherent in (False, True):
            with self.subTest(coherent=coherent):
                self.reset()
                path = self.root / "adaptation.patch"
                path.write_bytes(path.read_bytes() + b"\n# Unreviewed patch suffix\n")
                if coherent:
                    self.rehash("adaptation.patch", "patch_sha256")
                result = self.check(False)
                self.assertIn("complete source change" if coherent else "source provenance", result.stderr)

    def test_removed_gpl_notice_fails_with_coherent_derived_source_and_patch(self):
        path = self.root / "cachy-asahi-ksmctl"
        notice = "# (at your option) any later version.\n"
        derived = path.read_text()
        self.assertIn(notice, derived)
        derived = derived.replace(notice, "", 1)
        path.write_text(derived)
        origin = (self.root / "upstream-ksmctl").read_text()
        patch = "".join(difflib.unified_diff(origin.splitlines(True), derived.splitlines(True),
                                           fromfile="upstream/ksmctl", tofile="cachy-asahi-ksmctl"))
        (self.root / "adaptation.patch").write_text(patch)
        self.rehash("cachy-asahi-ksmctl", "derived_source_sha256")
        self.rehash("adaptation.patch", "patch_sha256")
        self.assertIn("original copyright/GPL notice missing", self.check(False).stderr)


if __name__ == "__main__":
    unittest.main()
