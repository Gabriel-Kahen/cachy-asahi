# SPDX-License-Identifier: MIT
"""Passive archive, loader, and ALPM controls for unissued installed selection maps."""

import io
import lzma
import os
from pathlib import Path
from runpy import run_path
import shutil
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
S = SimpleNamespace(**run_path(str(HERE / "selection_maps.py")))
T = S.T
fixture = run_path(str(S.P.ROOT / "scripts/ci/platform-namespace-rootfs-v1/test_elf64le_aarch64.py"))["fixture"]
OWNER = S.P.M.PACKAGE
LOADER = "/usr/lib/ld-linux-aarch64.so.1"
QT = "/usr/lib/libQt6Core.so.6.12.0"
WAYLAND = "/usr/lib/libwayland-server.so.0.26.0"
PRIVATE = "/usr/lib/private/libfixture.so.2"
PLAN = dict(package=dict(package=OWNER, version=S.P.M.VERSION, sonames=["libQt6Core.so.6"],
                         plugins=[S.W.OFFSCREEN], tools=["/usr/lib/qt6/bin/tool"]))
DOC = "usr/share/licenses/" + OWNER + "/notice"


def make_tar(extra=(), *, qt=None):
    entries = [
        (".PKGINFO", f"pkgname = {OWNER}\npkgver = {S.P.M.VERSION}\narch = aarch64\n".encode()),
        (".BUILDINFO", f"pkgname = {OWNER}\npkgver = {S.P.M.VERSION}\npkgarch = aarch64\n".encode()),
        (".MTREE", b"inert test control"),
        ("usr/lib", None),
        (QT[1:], fixture(soname="libQt6Core.so.6", runpath="$ORIGIN") if qt is None else qt),
        ("usr/lib/libQt6Core.so.6", "libQt6Core.so.6.12.0"),
        ("usr/lib/libQt6Core.so", "libQt6Core.so.6"),
        (S.W.OFFSCREEN[1:], fixture(needed=("libQt6Core.so.6", "libfixture.so.2"),
                                  runpath="$ORIGIN/../../../private")),
        ("usr/lib/qt6/bin/tool", fixture(interp=S.INTERPRETER)),
        (DOC, b""),
    ]
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in [*entries, *extra]:
            row = tarfile.TarInfo(name)
            if data is None:
                row.type = tarfile.DIRTYPE
            elif isinstance(data, str):
                row.type, row.linkname = tarfile.SYMTYPE, data
            else:
                row.size = len(data)
            tar.addfile(row, io.BytesIO(data) if isinstance(data, bytes) else None)
    return stream.getvalue()


class Baseline:
    def __init__(self):
        self.nodes = {path: ("directory", None) for path in ("/etc", "/usr", "/usr/lib", "/usr/lib/private")}
        self.nodes["/lib"] = ("symlink", "usr/lib")
        self.nodes["/usr/lib/" + S.WAYLAND] = ("symlink", Path(WAYLAND).name)
        self.cache = {S.WAYLAND: ["/lib/" + S.WAYLAND]}
        self.files = {
            LOADER: fixture(soname=Path(LOADER).name),
            WAYLAND: fixture(soname=S.WAYLAND, interp=LOADER),
            PRIVATE: fixture(soname=Path(PRIVATE).name, needed=(Path(LOADER).name,)),
        }

    def node(self, path):
        if path in self.files:
            return ("file", None)
        return self.nodes.get(path)

    def file(self, path, cap):
        return self.files[path]

    def owners(self, pins):
        self.assert_original_pins(pins)
        return {path: dict(pin=pin, owner="fixture", version="1-1") for path, pin in pins.items()}

    def assert_original_pins(self, pins):
        for name, pin in pins.items():
            if pin != T.pin(self.files[name]):
                raise AssertionError("Provider identity did not come from original bytes")


class SelectionMaps(unittest.TestCase):
    def test_complete_payload_and_runpath_cache_supplement_closure(self):
        long_path = "usr/share/" + "p" * 95 + "/notice"
        raw = make_tar([(long_path, b"long PAX name")])
        payload, nodes, elf = S.archive_maps(raw, PLAN)
        self.assertEqual(payload["/" + DOC], {"type": "file", "owner": OWNER, "pin": T.pin(b"")})
        self.assertIn("/" + long_path, payload)
        self.assertNotIn("/usr/lib", payload)
        self.assertEqual(payload["/usr/lib/libQt6Core.so.6"]["target"], Path(QT).name)
        baseline = Baseline()
        support = "/usr/lib/liboptional.so.3"
        baseline.files[support] = fixture(soname=Path(support).name)
        roots = [dict(soname=Path(support).name, reason="Reviewed consumer branch")]
        results = S.provider_map(PLAN, nodes, elf, baseline, roots)
        self.assertEqual(set(results), {LOADER, WAYLAND, PRIVATE, support})
        self.assertNotIn(QT, results)

    def test_xz_stream_must_finish_once_without_trailing_bytes(self):
        data = make_tar()
        compressed = lzma.compress(data)
        self.assertEqual(S.expand_archive(io.BytesIO(compressed)), data)
        with self.assertRaisesRegex(ValueError, "Truncated Qt package XZ"):
            S.expand_archive(io.BytesIO(compressed[:-1]))
        with self.assertRaisesRegex(ValueError, "Trailing data"):
            S.expand_archive(io.BytesIO(compressed + compressed))

    def test_path_bounds_and_unsupported_archive_rows(self):
        for arguments in ([("usr/../etc/example", b"bad")], [(DOC, b"duplicate")],
                          [("usr/share/link", "target"), ("usr/share/link/child", b"bad")],
                          [("etc/example", b"bad")]):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                S.archive_maps(make_tar(arguments), PLAN)
        with self.assertRaisesRegex(ValueError, "missing end markers"):
            S.archive_maps(make_tar()[:512], PLAN)
        with self.assertRaisesRegex(ValueError, "zero tar end markers"):
            S.archive_maps(make_tar() + b"bad", PLAN)

    def test_missing_or_ambiguous_soname_malformed_interpreter_and_legacy_search_refuse(self):
        _, nodes, elf = S.archive_maps(make_tar(), PLAN)
        base = Baseline()
        base.cache[S.WAYLAND].append("/usr/lib/" + Path(PRIVATE).name)
        base.files["/usr/lib/" + Path(PRIVATE).name] = fixture(soname=S.WAYLAND)
        with self.assertRaisesRegex(ValueError, "ambiguous static provider"):
            S.provider_map(PLAN, nodes, elf, base, [])
        base = Baseline()
        base.files[WAYLAND] = fixture(soname=S.WAYLAND, interp="/usr/lib/foreign-loader")
        with self.assertRaisesRegex(ValueError, "Unexpected ELF interpreter"):
            S.provider_map(PLAN, nodes, elf, base, [])
        base = Baseline()
        base.files[WAYLAND] = fixture(soname="wrong.so.0")
        with self.assertRaisesRegex(ValueError, "SONAME differs"):
            S.provider_map(PLAN, nodes, elf, base, [])
        base = Baseline()
        base.files[WAYLAND] = fixture(soname=S.WAYLAND, rpath="/usr/lib")
        with self.assertRaisesRegex(ValueError, "legacy transitive"):
            S.provider_map(PLAN, nodes, elf, base, [])
        base = Baseline()
        base.nodes["/usr/lib/private/glibc-hwcaps"] = ("directory", None)
        with self.assertRaisesRegex(ValueError, "hardware-capability"):
            S.provider_map(PLAN, nodes, elf, base, [])

    def test_alpm_owners_bind_exact_file_metadata_and_handle_empty_meta_package(self):
        q3 = S.Q3("unused", {"empty": "1-1", "fixture": "2:2.0-4"})
        fixed = S.ALPM + "/fixture-2:2.0-4"
        records = {
            S.ALPM + "/empty-1-1/files": b"",
            fixed + "/files": b"%FILES%\nusr/lib/libexample.so.3\n\n%BACKUP%\n",
            fixed + "/desc": b"%NAME%\nfixture\n\n%VERSION%\n2:2.0-4\n\n%VALIDATION%\nsha256\n\n",
        }
        path = "/usr/lib/libexample.so.3"
        pins = {path: T.pin(b"original")}
        q3.debugfs = lambda operation, leaf, cap: records[leaf]
        expected = {path: {"owner": "fixture", "version": "2:2.0-4", "pin": pins[path]}}
        self.assertEqual(q3.owners(pins), expected)
        records[fixed + "/desc"] = records[fixed + "/desc"].replace(b"2:2.0-4", b"2.0-4")
        with self.assertRaisesRegex(ValueError, "package identity differs"):
            q3.owners(pins)
        records[fixed + "/desc"] = records[fixed + "/desc"].replace(b"2.0-4", b"2:2.0-4")
        records[fixed + "/files"] = b"%FILES%\nusr/lib/other.so.1\n\n"
        with self.assertRaisesRegex(ValueError, "Missing original ALPM file owner"):
            q3.owners(pins)

    def test_supplement_data_is_canonical_externally_selected_and_has_reasons(self):
        with TemporaryDirectory() as directory:
            f = Path(directory) / "roots.json"
            roots = [dict(soname="libextra.so.1", reason="Reviewed consumer constructor")]
            raw = S.H.C.wire(dict(kind=S.SUPPLEMENT, roots=roots))
            f.write_bytes(raw)
            self.assertEqual(S.load_supplement(f, T.pin(raw)["sha256"]), (roots, T.pin(raw)))
            with self.assertRaisesRegex(ValueError, "External digest differs"):
                S.load_supplement(f, "0" * 64)
            raw = S.H.C.wire(dict(kind=S.SUPPLEMENT, roots=roots + roots))
            f.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "unique and sorted"):
                S.load_supplement(f, T.pin(raw)["sha256"])

    @unittest.skipUnless(shutil.which("mke2fs") and shutil.which("debugfs"), "ext4 fixture tools unavailable")
    def test_read_only_debugfs_reopens_the_pinned_image_and_aliases(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            tree = root / "tree"
            usr = tree / "root/usr/lib"
            usr.mkdir(parents=True)
            (tree / "root/lib").symlink_to("usr/lib")
            (usr / "libfixture.so.1").symlink_to("libfixture.so.1.2")
            (usr / "libfixture.so.1.2").write_bytes(b"exact leaf")
            disk = root / "original.raw"
            with disk.open("xb") as stream:
                stream.truncate(4 << 20)
            subprocess.run(["/usr/bin/mke2fs", "-q", "-F", "-t", "ext4", "-d", tree, disk],
                           check=True, capture_output=True)
            disk.chmod(0o444)
            expected = T.pin(disk.read_bytes())
            with S.hold(disk, expected, 4 << 20) as held:
                q3 = S.Q3(f"/proc/{os.getpid()}/fd/{held.fileno()}", {})
                leaf = S.resolve("/lib/libfixture.so.1", q3.node)
                self.assertEqual(leaf, "/usr/lib/libfixture.so.1.2")
                self.assertEqual(q3.file(leaf, 128), b"exact leaf")
                self.assertIsNone(q3.node("/usr/lib/absent"))
                with self.assertRaisesRegex(ValueError, "Unsupported guest lookup path"):
                    q3.node("/usr/lib/../../bad")
            self.assertEqual(T.pin(disk.read_bytes()), expected)

    def test_prepare_reuses_handoff_pin_and_returns_only_unissued_maps(self):
        with TemporaryDirectory() as directory:
            stage = Path(directory)
            (stage / "inputs").mkdir()
            scratch = stage / "scratch.raw"
            scratch.write_bytes(b"inert Q3 fixture")
            version_rows = [b"fixture 1-1\n"] + [f"package{i:03d} 1-1\n".encode() for i in range(355)]
            inventory = b"".join(version_rows)
            (stage / "inputs/expected356.lock").write_bytes(inventory)
            raw = T.encoded(PLAN)
            (stage / "inputs/PLAN.json").write_bytes(raw)
            archive = stage / S.H.ARCHIVE_NAME
            archive.write_bytes(lzma.compress(make_tar()))
            controls = dict(kind="QTBASE16K_UNSIGNED_ARCHIVE_HANDOFF_V1", status="PASS_UNSIGNED_ARCHIVE_FOR_TEST_REVIEW",
                            authority=None, package_nonce="2" * 32, archive=T.pin(archive.read_bytes()),
                            packaging_receipt=T.pin(b"readback"), package_actor=T.pin(b"actor"),
                            package_retirement=T.pin(b"retired"), signing="NOT_RUN", installation="NOT_RUN",
                            result_fsck=dict(receipt=T.pin(b"fsck"), stdout=T.pin(b"ok"),
                                             stderr=T.pin(b""), log=T.pin(b"ok"), elapsed_seconds=1))
            handoff = stage / "handoff.json"
            handoff_raw = S.H.C.wire(controls)
            handoff.write_bytes(handoff_raw)
            plan = PLAN | {"baseline": {"scratch": {"path": str(scratch)}}}
            scope = S.prepare.__globals__
            with patch.object(S.P, "Q3_INVENTORY", T.pin(inventory)), \
                 patch.object(S.P, "Q3_SCRATCH", T.pin(scratch.read_bytes())), \
                 patch.object(S.W, "read_plan", return_value=plan), \
                 patch.dict(scope, {"Q3": lambda *_: Baseline()}):
                args = (stage, T.pin(raw)["sha256"], archive, handoff, T.pin(handoff_raw)["sha256"])
                result = S.prepare(*args)
                self.assertEqual(result, S.prepare(*args))
                self.assertEqual(result["kind"], S.RESULT)
                self.assertIsNone(result["authority"])
                self.assertEqual(result["archive"], controls["archive"])
                self.assertEqual(set(result["mandatory_providers"]), {LOADER, WAYLAND, PRIVATE})
                archive.write_bytes(archive.read_bytes() + b"unselected")
                with self.assertRaisesRegex(ValueError, "Exact original file pin required"):
                    S.prepare(*args)

    def test_cli_fails_before_emitting_data_when_stage_is_missing(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            result = subprocess.run([sys.executable, "-I", "-B", str(HERE / "selection_maps.py"),
                                     "--stage", str(root), "--plan-sha256", "f" * 64,
                                     "--archive", str(root / S.H.ARCHIVE_NAME), "--handoff", str(root / "handoff"),
                                     "--handoff-sha256", "e" * 64], capture_output=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"Qtbase installed selection maps refused", result.stderr)


if __name__ == "__main__":
    unittest.main()
