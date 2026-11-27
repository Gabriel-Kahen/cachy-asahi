#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the independent successor reader with inert evidence."""

import io
import os
from pathlib import Path
from runpy import run_path
import struct
import tarfile
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch


R = run_path(str(Path(__file__).with_name("arm16k_readback.py")))
C = R["C"]
STAGE = SimpleNamespace(**run_path(str(R["ROOT"] / "packages/port/qt612-gui-server-source-reference/check_stage.py")))
PARSE = run_path(str(R["ROOT"] / "scripts/checks/package_checks.py"))["metadata"]
NONCE = "12345678" * 4


class ReadbackTests(unittest.TestCase):
    def test_checkpoint_and_terminal_are_ordered_and_nonce_bound(self):
        state = R["serial_state"]
        setup = f"QTBASE_SUCCESSOR16K_SETUP {NONCE}\r\n"
        configured = f"QTBASE_SUCCESSOR16K_CONFIGURED {NONCE}\r\n"
        complete = f"QTBASE_SUCCESSOR16K_TERMINAL {NONCE} PASS complete\r\n"
        failed = f"QTBASE_SUCCESSOR16K_TERMINAL {NONCE} HOLD build\r\n"
        self.assertEqual(state((setup + configured + complete).encode(), NONCE), (("PASS", "complete"), True, True))
        self.assertEqual(state((setup + failed).encode(), NONCE), (("HOLD", "build"), True, False))
        for invalid in (configured, setup + setup, setup + complete + configured,
                        setup + failed.replace(NONCE, "f" * 32), setup + "QTBASE_SUCCESSOR16K_TERMINAL\n"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                state(invalid.encode(), NONCE)

    def test_hashed_graph_still_has_to_enable_the_actual_features(self):
        profile = b'set(FEATURE_vulkan ON CACHE BOOL "" FORCE)\n'
        settings = R["FEATURES"] | {"QT612_SERVER_API_LINKS": "1"}
        rows = [f"{name}:INTERNAL={value}\n".encode() for name, value in settings.items()]
        files = {
            "CMakeCache.txt": b"".join(rows),
            "build.ninja": b"include CMakeFiles/rules.ninja\nbuild all: phony lib/something\n",
            "rules.ninja": b"# CMAKE generated file: DO NOT EDIT!\n",
            "features.txt": b"".join(rows),
            "profile.json": b'{"status":"PASS_CONFIGURED_PROFILE_ONLY","settings":1,"native":"NOT_ESTABLISHED"}',
        }

        def refresh():
            pins = {name: R["C"].pin(files[name]) for name in R["GRAPH"]}
            files["graph.sha256"] = "".join(f"{pin['sha256']}  {name}\n" for name, pin in pins.items()).encode()
            return pins

        self.assertEqual(R["graph_checks"](refresh(), files, profile)["QT_FEATURE_vulkan"], "ON")
        files["CMakeCache.txt"] = files["CMakeCache.txt"].replace(b"QT_FEATURE_vulkan:INTERNAL=ON",
                                                                b"QT_FEATURE_vulkan:INTERNAL=OFF")
        with self.assertRaisesRegex(ValueError, "fresh CMake cache differs"):
            R["graph_checks"](refresh(), files, profile)


class ResultCarrierTests(unittest.TestCase):
    def setUp(self):
        work = TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.path = Path(work.name) / "result.raw"
        image = bytearray(4096)
        struct.pack_into("<HH", image, 1024 + 56, 0xEF53, 1)
        image[1024 + 120:1024 + 130] = b"QT16K_SUCC"
        self.raw = bytes(image)
        self.path.write_bytes(self.raw)
        self.pin = C.pin(self.raw)
        self.plan = {"limits": {"result_bytes": len(image)}, "result_uuid": NONCE}
        self.parsed = False
        self.during_inventory = lambda: None
        test = self

        class Reader:
            uuid = NONCE
            incompat = 0x40

            def __init__(self, path, **_):
                self.fd = os.open(path, os.O_RDONLY | os.O_NOATIME)

            def __enter__(self):
                return self

            def __exit__(self, *_):
                os.close(self.fd)

            def read(self, offset, size):
                return os.pread(self.fd, size, offset)

            def inventory(self):
                test.parsed = True
                test.during_inventory()
                directory = dict(type="directory", uid=0, gid=0, xattrs=[])
                return dict(nodes={".": directory | {"mode": 0o755},
                                   "lost+found": directory | {"mode": 0o700}})

        stub = patch.object(C, "ext4_reader", return_value=Reader)
        stub.start()
        self.addCleanup(stub.stop)

    def read(self):
        return R["result_files"](self.path, self.plan, self.pin, load_archive=False)

    def test_parser_consumes_the_held_verified_carrier(self):
        self.assertEqual(self.read(), ({}, {}))
        self.assertTrue(self.parsed)

    def test_same_geometry_replacement_refused_before_inventory(self):
        replacement = self.path.with_suffix(".new")
        replacement.write_bytes(self.raw[:-1] + b"x")
        replacement.replace(self.path)
        with self.assertRaisesRegex(R["ResultPinError"], "digest differs"):
            self.read()
        self.assertFalse(self.parsed)

    def test_path_cannot_change_after_the_descriptor_was_verified(self):
        replacement = self.path.with_suffix(".new")
        replacement.write_bytes(self.raw)
        self.during_inventory = lambda: replacement.replace(self.path)
        with self.assertRaisesRegex(ValueError, "changed during readback"):
            self.read()
        self.assertTrue(self.parsed)


class ArchiveTests(unittest.TestCase):
    def test_tar_controls_cannot_be_nonordinary_or_wrong_mode(self):
        for kind, mode in ((tarfile.REGTYPE, 0o600), (tarfile.SYMTYPE, 0o644)):
            with self.subTest(kind=kind, mode=mode):
                stream = io.BytesIO()
                with tarfile.open(fileobj=stream, mode="w:xz", format=tarfile.PAX_FORMAT) as archive:
                    control = tarfile.TarInfo(".PKGINFO")
                    control.type, control.mode = kind, mode
                    data = b"fixture" if control.isfile() else b""
                    control.size = len(data)
                    archive.addfile(control, io.BytesIO(data))
                with self.assertRaisesRegex(ValueError, "Invalid package control file"):
                    R["archive_contents"](stream.getvalue(), {"stage-contract.json": b"{}"}, {}, {})

    def test_payload_shape_and_independently_required_development_files(self):
        required = R["development_files"](STAGE)
        recorded = dict(files={name: {"mode": 0o644} for name in required}, directories={"usr": 0o755},
                        symlinks={"usr/bin/qmake6": {"target": "../lib/qt6/bin/qmake", "mode": 0o777}})
        packaged = ({name: ("file", 0o644, None) for name in required}
                    | {"usr": ("directory", 0o755, None),
                       "usr/bin/qmake6": ("symlink", 0o777, "../lib/qt6/bin/qmake")})
        check = R["payload_contract"]
        check(STAGE, packaged, recorded)
        header = "usr/include/qt6/QtCore/QtCore"
        for node in (("file", 0o755, None), ("symlink", 0o777, "qtcoreversion.h")):
            with self.subTest(node=node), self.assertRaisesRegex(ValueError, "differs from staging"):
                check(STAGE, packaged | {header: node}, recorded)
        # Even agreeing stage and final manifests may not omit private development files.
        private = "usr/lib/cmake/Qt6WlShellIntegrationPrivate/Qt6WlShellIntegrationPrivateConfig.cmake"
        del packaged[private]
        del recorded["files"][private]
        with self.assertRaisesRegex(ValueError, "lacks required Qt development"):
            check(STAGE, packaged, recorded)

    def test_final_metadata_binds_make_dependencies_options_and_payload_size(self):
        epoch, name, version = (R[key] for key in ("BUILD_EPOCH", "PACKAGE", "VERSION"))
        common = dict(pkgname=name, pkgbase=name, pkgver=version, builddate=epoch, packager="Unknown Packager")
        package = common | dict(arch="aarch64", xdata="pkgtype=pkg", size="42", pkgdesc="Qt fixture",
                                url="https://example.invalid", depend="md4c=0.6.0-2",
                                makedepend="vulkan-headers=1:1.4.363.0-1", provides="qt6-base")
        build = common | dict(pkgarch="aarch64", format="2", pkgbuild_sha256sum="a" * 64, startdir="/qt-successor",
                              builddir="/qt-successor", buildtool="makepkg", buildtoolver="7.1.0",
                              buildenv=["check", "!sign"], options=["!debug"], installed="md4c-0.6.0-2-aarch64")

        def encode(rows):
            return "".join(f"{key} = {value}\n" for key, values in rows.items()
                           for value in (values if isinstance(values, list) else [values])).encode()

        info = encode(dict(pkgdesc=package["pkgdesc"], url=package["url"], depends=package["depend"],
                           makedepends=package["makedepend"], provides=package["provides"], options="!debug"))
        recipe = {"files": {"PKGBUILD": {"sha256": "a" * 64}}}

        def check(pkg=package, report=build):
            R["package_metadata"]({".PKGINFO": encode(pkg), ".BUILDINFO": encode(report)},
                                  info, b"md4c 0.6.0-2\n", recipe, 42, PARSE)

        check()
        for field, value in (("makedepend", "different"), ("size", "41"), ("xdata", "pkgtype=debug")):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "PKGINFO"):
                check(pkg=package | {field: value})
        with self.assertRaisesRegex(ValueError, "BUILDINFO build options"):
            check(report=build | {"options": ["!debug", "debug"]})


if __name__ == "__main__":
    unittest.main()
