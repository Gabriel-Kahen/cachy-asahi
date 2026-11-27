#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the independent successor reader with inert evidence."""

import gzip
import io
import os
from pathlib import Path
from runpy import run_path
import struct
import tarfile
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


R = run_path(str(Path(__file__).with_name("arm16k_readback.py")))
C = R["C"]
STAGE = SimpleNamespace(**run_path(str(R["ROOT"] / "packages/port/qt612-gui-server-source-reference/check_stage.py")))
PARSE = run_path(str(R["ROOT"] / "scripts/checks/package_checks.py"))["metadata"]
NONCE = "12345678" * 4
PARITY = run_path(str(Path(__file__).with_name("check_parity.py")))


def plan_for_recipe(profile, recipe):
    auth = R["AUTH"]
    selected = auth["PROFILES"][profile]
    source = auth["SOURCE_NAME"]
    return dict(kind="QTBASE_SUCCESSOR16K_PLAN_V1", nonce=NONCE, mode="full",
                base_revision="cbc877a35f40aba98aeb53cbcfebd7d18422e5ec",
                inputs={"recipe": selected["recipe"], "source": {"path": "/held/qt", **recipe["qt_source"]}},
                payload={"recipe/" + selected["receipt"]: selected["recipe"], source: recipe["qt_source"]}
                | {"recipe/" + name: pin for name, pin in recipe["files"].items()})


class ReadbackTests(unittest.TestCase):
    def test_profiled_and_historical_plans_bind_selected_recipe_and_upstream(self):
        auth = R["AUTH"]
        here = Path(__file__).resolve().parent
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for profile, selected in auth["PROFILES"].items():
                with self.subTest(profile=profile):
                    recipe_path = root / profile
                    generate = selected["generator"]
                    recipe = run_path(str(here / (generate + ".py")))[generate](recipe_path)
                    if profile == auth["DEFAULT_PROFILE"]:
                        self.assertEqual(R["recipe_inputs"](recipe_path)[0], recipe)
                    else:
                        with self.assertRaises(FileNotFoundError):
                            R["recipe_inputs"](recipe_path)
                        self.assertEqual(R["recipe_inputs"](recipe_path, profile=profile)[0], recipe)
                    source = auth["SOURCE_NAME"]
                    plan = plan_for_recipe(profile, recipe)
                    plan_path = root / "plan.json"

                    def check(candidate, **options):
                        body = C.wire(candidate)
                        plan_path.write_bytes(body)
                        return R["readback"](root, C.pin(body)["sha256"], "fixture", recipe_path, **options)

                    def stop_at_host(*_):
                        raise RuntimeError("verified plan reached host readback")

                    with patch.dict(R["readback"].__globals__, host_receipts=stop_at_host):
                        with self.assertRaisesRegex(ValueError, "source digest required"):
                            check(plan, profile=profile)
                        # Historical evidence carries only the original recorded revision and exact recipe pin.
                        with self.assertRaisesRegex(RuntimeError, "verified plan"):
                            check(plan | {"source_revision": "a" * 40}, profile=profile)
                        plan.update(profile=profile, launcher=C.pin(b"launcher"), actor=C.pin(b"actor"))
                        plan["source_sha256"] = auth["source_sha256"](plan)
                        with self.assertRaisesRegex(RuntimeError, "verified plan"):
                            check(plan, profile=profile)
                        if profile == "parity":
                            with self.assertRaisesRegex(ValueError, "Unexpected sealed build profile"):
                                check(plan)
                        else:
                            with self.assertRaisesRegex(ValueError, "full parity profile"):
                                check(plan, baseline_path=root / "baseline")
                        changed = plan | {"payload": plan["payload"] | {source: C.pin(b"other source")}}
                        changed["source_sha256"] = auth["source_sha256"](changed)
                        with self.assertRaisesRegex(ValueError, "Upstream Qt archive"):
                            check(changed, profile=profile)
                        del plan["source_sha256"]
                        with self.assertRaisesRegex(ValueError, "source digest differs"):
                            check(plan, profile=profile)

    def test_export_requires_pinned_baseline_and_complete_parity_result(self):
        auth = R["AUTH"]
        readback = R["readback"]
        with TemporaryDirectory() as directory:
            root = Path(directory)
            recipe = run_path(str(Path(__file__).with_name("prepare_parity.py")))["prepare_parity"](root / "recipe")
            plan = plan_for_recipe("parity", recipe)
            plan.update(profile="parity", launcher=C.pin(b"launcher"), actor=C.pin(b"actor"))
            plan["source_sha256"] = auth["source_sha256"](plan)
            raw = C.wire(plan)
            (root / "plan.json").write_bytes(raw)
            plan_sha = C.pin(raw)["sha256"]
            baseline, output = root / "baseline.pkg.tar.xz", root / "export.pkg.tar.xz"
            baseline_body = b"pinned baseline fixture"
            baseline.write_bytes(baseline_body)
            archive_body = b"unsigned parity fixture"
            archive = auth["archive_name"]("parity")
            launch = dict(files={"result.raw": C.pin(b"result")}, originals_unchanged=True,
                          container_absent=[True, True], container_exit=0, qemu_exit=0, error=None)
            receipt = {"archive": {"mtree": {}, "path_delta": {}, "atspi_bridge_abi": {}}}
            passed = "PASS_UNSIGNED_EMULATED_AARCH64_16K_PACKAGE"
            host = Mock(return_value=(launch, {}, {}, {}, (("PASS", "complete"), True, True), True))
            evidence = Mock(return_value=({}, {archive: archive_body}))
            guest = Mock(return_value=(receipt, passed))
            with patch.dict(readback.__globals__, BASE_ARCHIVE=C.pin(baseline_body), host_receipts=host,
                            result_files=evidence, guest_checks=guest):
                with self.assertRaisesRegex(ValueError, "requires the pinned parity baseline"):
                    readback(root, plan_sha, "fixture", profile="parity", export=output)
                host.assert_not_called()
                baseline.write_bytes(b"X" + baseline_body[1:])
                with self.assertRaisesRegex(ValueError, "Exact original file pin"):
                    readback(root, plan_sha, "fixture", profile="parity", baseline_path=baseline, export=output)
                evidence.assert_not_called()
                self.assertFalse(output.exists())
                baseline.write_bytes(baseline_body)
                with self.subTest("missing ABI check"):
                    guest.return_value = ({"archive": {"mtree": {}, "path_delta": {}}}, passed)
                    with self.assertRaisesRegex(ValueError, "full PASS"):
                        readback(root, plan_sha, "fixture", profile="parity", baseline_path=baseline, export=output)
                    self.assertFalse(output.exists())
                guest.return_value = (receipt, passed)
                with self.subTest("host did not pass"):
                    successful_host = host.return_value
                    host.return_value = (*successful_host[:-1], False)
                    with self.assertRaisesRegex(ValueError, "full PASS"):
                        readback(root, plan_sha, "fixture", profile="parity", baseline_path=baseline, export=output)
                    self.assertFalse(evidence.call_args.kwargs["load_archive"])
                    self.assertFalse(output.exists())
                    host.return_value = successful_host
                report = readback(root, plan_sha, "fixture", profile="parity", baseline_path=baseline, export=output)
                self.assertEqual(report["guest"], receipt)
                self.assertEqual(report["source_sha256"], plan["source_sha256"])
                self.assertEqual(guest.call_args.kwargs, {"profile": "parity", "baseline": baseline_body})
                self.assertEqual(output.read_bytes(), archive_body)
                self.assertEqual(output.stat().st_mode & 0o777, 0o444)
                with self.assertRaises(FileExistsError):
                    readback(root, plan_sha, "fixture", profile="parity", baseline_path=baseline, export=output)
                self.assertEqual(output.read_bytes(), archive_body)

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
        self.evidence = {}
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
                                   "lost+found": directory | {"mode": 0o700}} | test.evidence)

        stub = patch.object(C, "ext4_reader", return_value=Reader)
        stub.start()
        self.addCleanup(stub.stop)

    def read(self):
        return R["result_files"](self.path, self.plan, self.pin, load_archive=False)

    def test_parser_consumes_the_held_verified_carrier(self):
        self.assertEqual(self.read(), ({}, {}))
        self.assertTrue(self.parsed)

    def test_each_profile_reads_only_its_archive_name(self):
        auth = R["AUTH"]
        for profile, other in (("successor", "parity"), ("parity", "successor")):
            with self.subTest(profile=profile):
                archive = auth["archive_name"](profile)
                pin = C.pin(b"fixture archive")
                self.evidence = {"evidence/" + archive: dict(type="file", links=1, uid=0, gid=0, mode=0o600,
                                                             xattrs=[], size=pin["bytes"], sha256=pin["sha256"])}
                read = R["result_files"]
                self.assertEqual(read(self.path, self.plan, self.pin, load_archive=False, profile=profile),
                                 ({archive: pin}, {}))
                with self.assertRaisesRegex(ValueError, "result namespace"):
                    read(self.path, self.plan, self.pin, load_archive=False, profile=other)

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
    def test_parity_delta_requires_exact_paths_and_all_library_exports(self):
        maps = SimpleNamespace(**run_path(str(R["HERE"].parent / "qt612_installed_16k_preflight/selection_maps.py")))
        maps.expand_archive = lambda stream: stream.read()
        libraries = {f"usr/lib/libQt6{module}.so.6.12.0" for module in (*STAGE.MODULES, *STAGE.PRIVATE_MODULES)}
        added = PARITY["ADDED_FILES"]
        self.assertEqual((len(added), len(libraries)), (31, 18))
        baseline = io.BytesIO()
        prior_files = libraries | {"usr/lib/qt6/held"}
        with tarfile.open(fileobj=baseline, mode="w:") as archive:
            for name in sorted(prior_files):
                member = tarfile.TarInfo(name)
                member.size = 1
                archive.addfile(member, io.BytesIO(b"x"))
        candidate = dict.fromkeys(prior_files | added, ("file", 0o644, None))
        candidate["usr/lib/qt6/plugins/printsupport"] = ("directory", 0o755, None)
        symbols = dict.fromkeys(libraries, ({"old@@Qt_6", "new@@Qt_6"}, set()))
        compare = R["parity_delta"]
        with patch.dict(compare.__globals__, dynamic_symbols=lambda _: ({"old@@Qt_6"}, set())):
            result = compare(baseline.getvalue(), candidate, maps, added, symbols)
            self.assertEqual(result["added_files"], sorted(added))
            self.assertEqual(result["added_directories"], ["usr/lib/qt6/plugins/printsupport"])
            self.assertEqual(result["removed"], [])
            self.assertEqual(result["metadata_changed"], [])
            self.assertEqual(result["qt_dynamic_exports"], dict.fromkeys(libraries, {
                "retained_exports": 1, "new_exports": ["new@@Qt_6"]}))
            with self.assertRaisesRegex(ValueError, "Unexpected parity path delta"):
                compare(baseline.getvalue(), candidate | {"usr/lib/qt6/extra": ("file", 0o644, None)},
                        maps, added, symbols)
            changed = symbols | {min(libraries): ({"new@@Qt_6"}, set())}
            with self.assertRaisesRegex(ValueError, "Project Qt export lost"):
                compare(baseline.getvalue(), candidate, maps, added, changed)

    def test_atspi_receipt_requires_versioned_export_and_both_imports(self):
        gui = "usr/lib/libQt6Gui.so.6.12.0"
        consumers = ["libQt6WaylandClient.so.6.12.0", "libQt6XcbQpa.so.6.12.0"]
        constructor = "_ZN20QSpiAccessibleBridgeC1Ev"
        exported = constructor + "@@Qt_6_PRIVATE_API"
        imported = constructor + "@Qt_6_PRIVATE_API"
        symbols = {gui: ({exported}, set())} | {
            "usr/lib/" + name: ({"other"}, {imported}) for name in consumers}
        check = R["atspi_bridge_abi"]
        self.assertEqual(check(symbols), {"qtgui_export": exported, "consumers": consumers})
        for name in symbols:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "AT-SPI bridge ABI absent"):
                check(symbols | {name: ({constructor}, {constructor})})

    def test_mtree_binds_effective_metadata_content_and_exact_census(self):
        path = "usr/lib/qt6/example"
        raw = b"payload"
        member = tarfile.TarInfo(path)
        member.mode, member.mtime = 0o644, 1234567890
        expected = {path: R["mtree_fields"](member, raw)}
        text = ("#mtree\n/set type=file uid=0 gid=0 mode=644\n"
                f"./{path} time={member.mtime}.0 size={len(raw)} sha256digest={C.pin(raw)['sha256']}\n")
        check = R["verify_mtree"]
        self.assertEqual(check(gzip.compress(text.encode()), expected), expected)
        for bad in (text.replace("mode=644", "mode=755"), text.replace("size=7", "size=8"),
                    text + text.splitlines()[-1] + "\n", text.replace(".0 size=", ".1 size=")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                check(gzip.compress(bad.encode()), expected)
        with self.assertRaisesRegex(ValueError, "census differs"):
            check(gzip.compress(text.encode()), expected | {"usr/lib/qt6/missing": {}})

    def test_versioned_export_and_import_names_are_distinct(self):
        readelf = (" 1: 0000000000000000 0 FUNC GLOBAL DEFAULT UND import@Qt_6_PRIVATE_API (2)\n"
                   " 2: 0000000000001234 8 FUNC GLOBAL DEFAULT  13 export@@Qt_6_PRIVATE_API\n"
                   " 3: 0000000000001234 8 FUNC LOCAL  DEFAULT  13 hidden\n")
        with patch.dict(R["dynamic_symbols"].__globals__, readelf=lambda *_: readelf):
            self.assertEqual(R["dynamic_symbols"](b"fixture"),
                             ({"export@@Qt_6_PRIVATE_API"}, {"import@Qt_6_PRIVATE_API"}))

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
