# SPDX-License-Identifier: MIT
"""Exercise the package-only guest with inert files and command receipts."""

from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
W = SimpleNamespace(**run_path(str(HERE / "package_guest.py")))
F = SimpleNamespace(**run_path(str(HERE / "full_guest.py")))
M = SimpleNamespace(**run_path(str(HERE / "package_metadata.py")))
RECIPE = HERE.parents[2] / "packages/port/qt612-gui-server-source-reference"
GUEST_LINK = HERE.parent / "qt612_gui_16k_link_checkpoint/guest_link.py"
NONCE, OLD, DIGEST = "1" * 32, "2" * 32, "a" * 64
INVENTORY = "".join(f"model-{i:03} 1-1\n" for i in range(356)).encode()
PIN = W.pin(b"fixture")


def fixture():
    full = SimpleNamespace(**{**vars(F), "INHERITED": {}})
    g = SimpleNamespace(**run_path(str(GUEST_LINK)))
    g.INVENTORY = W.pair(INVENTORY)
    projection = M.successor((RECIPE / "PKGBUILD").read_bytes(), (RECIPE / ".SRCINFO").read_bytes())
    info = projection[".SRCINFO"]
    deps = sorted(set(W.metadata_rows(info, "depends") + W.metadata_rows(info, "makedepends")))
    files = {"expected356.lock": INVENTORY, "recipe/PKGBUILD": projection["PKGBUILD"], "recipe/.SRCINFO": info,
             "configure-dependencies.list": ("\n".join(deps) + "\n").encode()}
    completed = dict(libraries={name: PIN | {"aliases": F.alias_metadata(name)} for name in F.LIBRARIES}, ninja_log=PIN)
    plan = dict(kind=W.PLAN_KIND, authority=None, scope=W.SCOPE, nonce=NONCE, source_build_nonce=OLD,
                packaging="NOT_RUN", signing="NOT_RUN", installation="NOT_RUN", hardware="NOT_RUN",
                worker=W.worker_contract(g, full, deps, files, completed),
                expected_archive=W.archive_contract(files["recipe/PKGBUILD"]))
    return g, full, files, plan


def archive_model(files, inventory, lib):
    info = files["recipe/.SRCINFO"]
    pkg = dict(pkgname=[W.PACKAGE], pkgver=[W.VERSION], arch=["aarch64"])
    for old, field in (("depends", "depend"), ("provides", "provides"), ("conflicts", "conflict"), ("license", "license")):
        pkg[field] = W.metadata_rows(info, old)
    build = dict(format=["2"], pkgname=[W.PACKAGE], pkgver=[W.VERSION], pkgarch=["aarch64"],
                 pkgbuild_sha256sum=[W.pin(files["recipe/PKGBUILD"])["sha256"]],
                 startdir=[W.RECIPE], builddir=[W.RECIPE],
                 installed=[line.replace(" ", "-", 1) + "-aarch64" for line in inventory.decode().splitlines()])
    members = {name: {"sha256": PIN["sha256"]} for name in (".PKGINFO", ".BUILDINFO", ".MTREE")}
    package = dict(artifact=W.ARCHIVE, status="artifact-static-pass", errors=[], sha256=PIN["sha256"], members=members,
                   metadata={".PKGINFO": pkg, ".BUILDINFO": build}, elf={})
    stage = dict(status="PASS_QT612_GUI_SERVER_DESTDIR_CONTRACT_ONLY", elf={},
                 server_feature_export=dict(status="PASS_QT612_GUI_SERVER_FEATURE_EXPORT_BYTES_ONLY", files={}))
    for name in lib:
        leaf = "usr/lib/" + name
        package["elf"][leaf] = dict(machine=183, load_segments=1, errors=[])
        stage["elf"][leaf] = dict(soname=name.removesuffix(".so.6.12.0") + ".so.6")
        for link, target in F.alias_metadata(name).items():
            members["usr/lib/" + link] = dict(type="2", link=target)
    return dict(artifacts=[package], errors=[]), stage


class PackageGuest(unittest.TestCase):
    def test_current_scope_and_exact_configuration_binding(self):
        expected = dict(kind=W.SELECTION_KIND, issuer="Root", approved=True, scope=W.SCOPE, nonce=NONCE,
                        plan_sha256=DIGEST, created_utc=1000, expires_utc=1100,
                        makepkg_configuration=dict(main=PIN, dropins={"aarch64.conf": PIN}))
        self.assertEqual(W.selection(W.wire(expected), {"nonce": NONCE}, DIGEST, 1050), expected)
        for change in ({"scope": "build"}, {"plan_sha256": "b" * 64}, {"expires_utc": 1050}, {"approved": False},
                       {"makepkg_configuration": {"main": PIN, "dropins": {"../other.conf": PIN}}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                W.selection(W.wire(expected | change), {"nonce": NONCE}, DIGEST, 1050)

    def test_staged_bytes_and_namespace_must_match(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "recipe").mkdir()
            fixed = {"expected356.lock", "configure-dependencies.list", "metadata-projection.json",
                     "package_checks.py", "package_guest.py", "full_guest.py", "guest_link.py"}
            bodies = {name: b"fixture" for name in fixed | {f"recipe/input-{i}" for i in range(15)}}
            bodies["package_checks.py"] = (HERE.parents[2] / "scripts/checks/package_checks.py").read_bytes()
            for name, body in (bodies | {W.PLAN_NAME: b"plan", W.SELECTION_NAME: b"selection"}).items():
                path = root / name
                path.write_bytes(body)
                path.chmod(0o444)
            plan = {"staging_files": {name: W.pin(body) for name, body in bodies.items()}}
            self.assertEqual(W.stage_files(root, plan), bodies)
            checker = root / "package_checks.py"
            checker.chmod(0o600)
            unreviewed = bodies[checker.name] + b"\n# unreviewed checker\n"
            checker.write_bytes(unreviewed)
            checker.chmod(0o444)
            with self.assertRaisesRegex(ValueError, "exact normal package validator"):
                W.stage_files(root, {"staging_files": plan["staging_files"] | {checker.name: W.pin(unreviewed)}})
            checker.chmod(0o600)
            checker.write_bytes(bodies[checker.name])
            checker.chmod(0o444)
            changed = root / "recipe/input-2"
            changed.chmod(0o600)
            changed.write_bytes(b"changed")
            changed.chmod(0o444)
            with self.assertRaisesRegex(ValueError, "Staged package input differs"):
                W.stage_files(root, plan)
            (root / "unreviewed").touch()
            with self.assertRaisesRegex(ValueError, "staging namespace"):
                W.stage_files(root, plan)

    def test_worker_plan_drift_and_original_inventory_refuse(self):
        g, full, files, plan = fixture()
        self.assertEqual(W.validate_stage_plan(plan, g, full, files), INVENTORY)
        with self.assertRaisesRegex(ValueError, "inventory"):
            W.validate_stage_plan(plan, g, full, files | {"expected356.lock": INVENTORY + b"other 1-1\n"})
        with self.assertRaisesRegex(ValueError, "dependency expressions"):
            W.validate_stage_plan(plan, g, full, files | {"configure-dependencies.list": b"md4c\n"})
        proof = plan["worker"]["completed_build"]
        plan["worker"]["completed_build"] = proof | {"libraries": {}}
        with self.assertRaisesRegex(ValueError, "library map"):
            W.validate_stage_plan(plan, g, full, files)
        plan["worker"]["completed_build"] = proof
        plan["worker"]["actions"][-3]["argv"].append("--install")
        with self.assertRaisesRegex(ValueError, "commands"):
            W.validate_stage_plan(plan, g, full, files)

    def test_archive_binds_original_recipe_inventory_and_provider(self):
        _, full, files, _ = fixture()
        raw, stage = archive_model(files, INVENTORY, full.LIBRARIES)
        def validate(p=PIN):
            return W.archive_receipt(W.wire(raw), stage, p, files["recipe/.SRCINFO"], files["recipe/PKGBUILD"],
                                     INVENTORY, full.LIBRARIES)
        self.assertEqual(validate(), {name: PIN["sha256"] for name in (".PKGINFO", ".BUILDINFO", ".MTREE")})
        with self.assertRaisesRegex(ValueError, "validated archive"):
            validate(W.pin(b"other"))
        row = raw["artifacts"][0]["metadata"]
        original = list(row[".PKGINFO"]["provides"])
        row[".PKGINFO"]["provides"][0] = "qt6-base=6.12.0"
        with self.assertRaisesRegex(ValueError, "metadata differs"):
            validate()
        row[".PKGINFO"]["provides"] = original
        row[".BUILDINFO"]["installed"][0] = "model-000-2-1-aarch64"
        with self.assertRaisesRegex(ValueError, "Q3 inventory"):
            validate()

    def test_empty_dependency_log_and_real_check_gate_repackage(self):
        _, full, files, plan = fixture()
        env = W.execute.__globals__
        for smoke in (False, True):
            with self.subTest(smoke=smoke), TemporaryDirectory() as tmp:
                output = Path(tmp)
                expected_report, expected_stage = archive_model(files, INVENTORY, full.LIBRARIES)
                stage = output.parent / ("missing-fixture-" + output.name)
                plan["expected_archive"]["stage_receipt"] = str(stage)
                issued = dict(makepkg_configuration={}, expires_utc=int(time.time()) + 30)
                roles = []

                def capture(argv, log, _seconds, _cap, *, cwd):
                    role = log.stem
                    roles.append(role)
                    logs = {"inventory": INVENTORY, "inventory-after": INVENTORY, "dependencies": b"",
                            "idle-built-tree": b"ninja: no work to do.\n",
                            "recipe-check": (W.SMOKE + "\n").encode() if smoke else b"missing marker\n",
                            "archive-validation": W.wire(expected_report)}
                    log.write_bytes(logs.get(role, b"fixture\n"))
                    if role == "repackage":
                        (output / W.ARCHIVE).write_bytes(b"fixture")
                    return {"exit_code": 0}

                def read(path, _limit, *, collect=False):
                    if path == stage:
                        return None, None, W.wire(expected_stage)
                    return W.pair(path.read_bytes()), None, b""

                def put(path, raw):
                    if path.parent == output:
                        path.write_bytes(raw)

                g = SimpleNamespace(RECIPE=output, file_data=read, put=put, capture=capture,
                                    require_success=Mock(), put_json=lambda path, value: put(path, W.wire(value)))
                with patch.dict(env, reviewed_configuration=Mock(), preserve_build=Mock(), require_time=Mock()):
                    status = W.execute(g, full, plan, DIGEST, DIGEST, issued, files, INVENTORY, output, 60)
                receipt = W.decode((output / "result.json").read_bytes(), canonical=True)
                self.assertEqual(receipt["commands"]["dependencies"]["log"], W.pin(b""))
                if smoke:
                    self.assertEqual(status, "PASS_UNSIGNED_PACKAGE_FOR_REVIEW")
                    self.assertEqual((receipt["archive"], receipt["signing"]), (PIN, "NOT_RUN"))
                    self.assertLess(roles.index("recipe-check"), roles.index("repackage"))
                else:
                    self.assertEqual((status, receipt["phase"]), ("HOLD", "recipe-check"))
                    self.assertNotIn("repackage", roles)

    def test_time_bound_prevents_start_when_remaining_window_is_short(self):
        with patch.object(W.time, "clock_gettime", return_value=100):
            W.require_time(180, 30)
            for end in (175, 4000):
                with self.subTest(end=end), self.assertRaises(ValueError):
                    W.require_time(end, 30)


if __name__ == "__main__":
    unittest.main()
