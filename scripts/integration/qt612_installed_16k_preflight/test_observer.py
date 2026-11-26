# SPDX-License-Identifier: MIT
"""Read-only controls for actual Qt observer input and loader evidence."""

import os
from pathlib import Path
from runpy import run_path
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
O = SimpleNamespace(**run_path(str(HERE / "observer.py")))
L = SimpleNamespace(**run_path(str(HERE / "loader_probe.py")))
T, P = O.T, O.P
SO = "/usr/lib/libQt6Core.so.6.12.0"
PROGRAM = "/qt-install-work/consumer/qt612-smoke"
PLUGIN = O.W.OFFSCREEN


def trace(program=PROGRAM, path=PLUGIN):
    return (f"  177: calling init: /lib/ld-linux-aarch64.so.1\n"
            f"  177: initialize program: {program}\n"
            f"  177: calling init: {path}\n"
            f"  177: opening file={path} [0]; direct_opencount=1\n"
            "  183: calling init: /usr/lib/libc.so.6\n").encode()


class Evidence(unittest.TestCase):
    def test_inputs_are_read_and_hashed_from_exact_ordinary_leaves(self):
        with TemporaryDirectory() as temp:
            home = Path(temp)
            media, work = home / "media", home / "work"
            media.mkdir()
            work.mkdir()
            raw = {"archive": b"fixture archive", "certificate": b"model public data", "signature": b"model signature"}
            paths = {"archive": media / Path(P.ARCHIVE).name, "certificate": media / Path(P.CERT).name,
                     "signature": media / (Path(P.ARCHIVE).name + ".sig")}
            for name, path in paths.items():
                path.write_bytes(raw[name])
            (work / "pacman.conf").write_bytes(P.CONFIG.encode())
            evidence = O.input_evidence(media, work)
            self.assertEqual(evidence, dict(input_pins={k: T.pin(v) for k, v in raw.items()},
                                            config_raw=P.CONFIG.encode(), certificate_raw=raw["certificate"],
                                            signature_raw=raw["signature"]))
            paths["signature"].unlink()
            paths["signature"].symlink_to(paths["archive"])
            with self.assertRaises(ValueError):
                O.input_evidence(media, work)

    def test_protected_view_records_metadata_symlinks_and_absence(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            file = root / "configuration"
            file.write_bytes(b"protected")
            file.chmod(0o640)
            alias = root / "alias"
            alias.symlink_to(file.name)
            paths = (root, root / "absent")
            original = O.protected_view(paths)
            rows = T.decode(original)
            self.assertEqual(rows[str(file)], dict(type="file", pin=T.pin(b"protected"),
                                                   uid=os.getuid(), gid=os.getgid(), mode=0o640))
            self.assertEqual(rows[str(alias)]["target"], file.name)
            self.assertEqual(rows[str(root / "absent")], {"type": "absent"})
            file.chmod(0o644)
            self.assertNotEqual(O.protected_view(paths), original)

    def test_offscreen_trace_is_attributed_to_actual_foreground_consumer(self):
        expected = {PLUGIN, "/lib/ld-linux-aarch64.so.1"}
        self.assertEqual(O.plugin_trace(trace(), PROGRAM), expected)
        for bad in (trace(program="/other/qt612-smoke"), trace(path=PLUGIN + ".old"),
                    trace().replace(b"177: opening", b"183: opening"),
                    trace().replace(b"177: calling init: " + PLUGIN.encode(), b"177: trying file=" + PLUGIN.encode())):
            with self.assertRaisesRegex(ValueError, "did not map and open"):
                O.plugin_trace(bad, PROGRAM)

    def test_actual_device_and_inode_observation_and_disappeared_map(self):
        raw = f"7f-8f r-xp 00000000 f:22 125 {SO}\n".encode()
        self.assertEqual(L.file_maps(raw), {SO: [15, 34, 125]})
        with self.assertRaises(ValueError):
            L.file_maps(raw.rstrip(b"\n") + b" (deleted)\n")
        with self.assertRaises(ValueError):
            L.file_maps(raw + raw.replace(b"125", b"126"))
        with TemporaryDirectory() as temp:
            obj = Path(temp) / "a.so"
            obj.write_bytes(b"model ELF")
            pin = O.mapped_identity(obj.lstat())
            row = dict(soname="libQt6Core.so.6", path=SO, maps={SO: pin.copy()}, loaded=[SO])
            with patch.dict(O.read_map.__globals__, path_shape=lambda name, prefix: obj):
                # read_map checks that the observed on-disk inode remains the mapped inode.
                self.assertEqual(O.read_map(row, row["soname"]), (SO, {SO: pin}, [SO]))
                row["maps"][SO][2] += 1
                with self.assertRaisesRegex(ValueError, "device/inode"):
                    O.read_map(row, row["soname"])

    def test_dependencies_only_resolve_into_actual_maps(self):
        libc = "/usr/lib/libc.so.6"
        preload = "/usr/lib/unrelated.so"
        dso = {SO: dict(soname="libQt6Core.so.6", needed=["libc.so.6"]),
               libc: dict(soname="libc.so.6", needed=[]), preload: dict(soname="unrelated.so", needed=[])}
        self.assertEqual(O.closure([SO], dso, dso.__getitem__), {SO, libc})
        self.assertEqual(O.closure([SO, preload], dso, dso.__getitem__), {SO, libc, preload})
        with self.assertRaisesRegex(ValueError, "actual mapped dependency"):
            O.closure([SO], {SO, preload}, dso.__getitem__)

    def test_alpm_listing_supplies_actual_files_and_aliases(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            payload = root / "library.so.6.12.0"
            payload.write_bytes(b"fixture bytes")
            link = root / "library.so.6"
            link.symlink_to(payload.name)
            output = b"/usr/lib/\n/usr/lib/library.so.6\n/usr/lib/library.so.6.12.0\n"
            with patch.dict(O.named_payload.__globals__, path_shape=lambda name, prefix: root / Path(name).name):
                rows = O.named_payload(output, P.M.PACKAGE)
                self.assertEqual(rows["/usr/lib/library.so.6"]["target"], payload.name)
                self.assertEqual(rows["/usr/lib/library.so.6.12.0"]["pin"], T.pin(b"fixture bytes"))
                with self.assertRaisesRegex(ValueError, "Duplicate"):
                    O.named_payload(output + b"/usr/lib/\n", P.M.PACKAGE)

    def test_callback_instruments_only_exact_selected_consumer(self):
        response = dict(stdout=b"stdout", stderr=trace())
        target = O.Observer.__new__(O.Observer)
        target.plan = {"consumer": {"run": [PROGRAM], "environment": {"PATH": "/usr/bin:/bin"}}}
        target.stages = {"install": {}}
        target.execute = Mock(return_value=response)
        target.streams, target.traces = {}, {}
        config = target.plan["consumer"]["environment"]
        target.run("install-consumer-run", [PROGRAM], timeout=600, stdin=None, env=config)
        self.assertEqual(target.execute.call_args.kwargs["env"], config | {"LD_DEBUG": "files"})
        self.assertNotIn("LD_DEBUG", config)
        self.assertEqual(target.traces, {"install": trace()})
        target.run("install-inventory", ["pacman", "-Q"], timeout=90, stdin=None, env=config)
        self.assertEqual(target.streams, {"install": b"stdout"})
        self.assertEqual(target.execute.call_args.kwargs["env"], config)
        with self.assertRaisesRegex(ValueError, "standard loader environment"):
            target.run("install-consumer-run", [PROGRAM], timeout=90, stdin=None, env={"LD_LIBRARY_PATH": "/tmp"})


class HostLoaderFixture(unittest.TestCase):
    @unittest.skipUnless(Path("/usr/lib/libc.so.6").is_file(), "Q3-compatible glibc filesystem layout required")
    def test_real_host_dlopen_reports_original_link_map_and_inode(self):
        result = L.probe("libc.so.6")
        mapped = Path(result["path"])
        self.assertEqual(mapped, Path("/usr/lib/libc.so.6").resolve())
        # A host Btrfs subvolume can report a different st_dev from its physical map.
        self.assertEqual(result["maps"][str(mapped)][2], mapped.lstat().st_ino)
        missing = "libQt6DefinitelyAbsentInObserverFixture.so.6"
        self.assertEqual(L.probe(missing), {"soname": missing, "path": None, "maps": {}, "loaded": []})

    @unittest.skipUnless(Path("/usr/lib/libcrypto.so.3").is_file(), "Local glibc loader fixture unavailable")
    def test_real_glibc_trace_records_opened_library(self):
        library = "/usr/lib/libcrypto.so.3"
        python = "/usr/bin/python3"
        row = subprocess.run([python, "-I", "-B", "-c", "import ctypes,sys; ctypes.CDLL(sys.argv[1])", library],
                             env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "LD_DEBUG": "files"},
                             capture_output=True, check=True, timeout=10)
        self.assertIn(library, O.plugin_trace(row.stderr, python, library))
