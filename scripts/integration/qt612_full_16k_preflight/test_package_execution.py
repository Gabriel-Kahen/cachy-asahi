# SPDX-License-Identifier: MIT
"""Exercise the package adapter and reader using inert package and ext4 fixtures."""

import os
from pathlib import Path
from runpy import run_path
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from uuid import UUID


HERE = Path(__file__).resolve().parent
R = SimpleNamespace(**run_path(str(HERE / "package_result.py")))
G = SimpleNamespace(**run_path(str(HERE / "test_package_guest.py")))
D = SimpleNamespace(**run_path(str(HERE / "test_full_readback.py")))
E, W, C = R.E, R.W, R.C
PLAN, SELECTION = C.pin(b"plan"), C.pin(b"selection")
HISTORICAL_SOURCE = {"package_checks.py": b"historical checker model", "package_guest.py": b"historical worker model"}
HISTORICAL_PINS = tuple(W.pair(body) for body in HISTORICAL_SOURCE.values())


def boot_fixture(complete_bytes=G.PIN["bytes"], *, source=None):
    g, full, files, plan = G.fixture()
    files |= {name: b"fixture" for name in ["metadata-projection.json",
                                          *(f"recipe/operand-{index}" for index in range(13))]}
    files |= {"package_guest.py": (HERE / "package_guest.py").read_bytes(),
              "full_guest.py": (HERE / "full_guest.py").read_bytes(),
              "guest_link.py": G.GUEST_LINK.read_bytes(),
              "package_checks.py": (HERE.parents[2] / "scripts/checks/package_checks.py").read_bytes()}
    if source is not None:
        files.update(source)
    deps = files["configure-dependencies.list"].decode().splitlines()
    plan["worker"] = W.worker_contract(g, full, deps, files, plan["worker"]["completed_build"])
    plan |= dict(staging_files={name: C.pin(body) for name, body in files.items()},
                 readonly_media={name: expected | {"path": "/fixture/" + name}
                                 for name, expected in E.F.LOWER.items()}
                 | {"complete.qcow2": C.file_pin(complete_bytes, G.DIGEST) | {"path": "/fixture/complete.qcow2"}},
                 source_evidence={"boot_template": C.file_pin(E.F.Q.BOOT_BYTES, G.DIGEST) | {"path": "/fixture/boot.raw"}},
                 fresh_child=dict(path=E.CHAIN[0], backing=E.CHAIN[1], backing_format="qcow2",
                                  storage="fresh-writable-child-only"))
    raw = C.wire(plan)
    issue = C.wire(dict(kind=W.SELECTION_KIND, issuer="Root", approved=True, scope=W.SCOPE, nonce=G.NONCE,
                        plan_sha256=C.pin(raw)["sha256"], created_utc=1000, expires_utc=1600,
                        makepkg_configuration=dict(main=G.PIN, dropins={})))
    return g, full, files, raw, issue


def stage_files(root, files):
    for name, value in files.items():
        parent = (root / name).parent
        parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(value)


def bash(body, *argv):
    probe = 'source "$1"; shift; ' + body
    return subprocess.run(["/usr/bin/bash", "--noprofile", "--norc", "-c", probe, "test",
                           str(HERE / "package-guest-init.sh"), *argv],
                          capture_output=True, timeout=10, check=False)


def pass_fixture():
    _, full, files, plan = G.fixture()
    report, stage = G.archive_model(files, G.INVENTORY, full.LIBRARIES)
    bodies = {"archive-validation.log": C.wire(report), "dependencies.log": b"",
              "stage-contract.json": C.wire(stage), "inventory.log": G.INVENTORY, "inventory-after.log": G.INVENTORY,
              "idle-built-tree.log": b"ninja: no work to do.\n", "recipe-check.log": (W.SMOKE + "\n").encode()}
    metric = dict(log_complete=True, natural=True, group_empty=True, timeout=False, overflow=False,
                  exit_code=0, elapsed_ms=0, peak_child_rss_kib=0)
    commands = {}
    for step in plan["worker"]["actions"]:
        role = step["role"]
        body = bodies.setdefault(role + ".log", b"fixture")
        commands[role] = dict(metrics=metric.copy(), log=C.pin(body))
    worker = dict(kind="QTBASE16K_PACKAGING_RESULT_V1", scope=W.SCOPE, nonce=G.NONCE, plan_sha256=PLAN["sha256"],
                  selection_sha256=SELECTION["sha256"], signing="NOT_RUN", installation="NOT_RUN", hardware="NOT_RUN",
                  status="PASS_UNSIGNED_PACKAGE_FOR_REVIEW", phase="complete", commands=commands, archive=G.PIN,
                  metadata={name: G.PIN["sha256"] for name in (".PKGINFO", ".BUILDINFO", ".MTREE")},
                  stage_contract=C.pin(bodies["stage-contract.json"]))
    return plan, files, bodies, worker


class Execution(unittest.TestCase):
    def test_historical_and_mixed_sources_cannot_boot(self):
        with patch.dict(E.validate_package_inputs.__globals__, HISTORICAL_SOURCE_PINS=HISTORICAL_PINS):
            for source in (HISTORICAL_SOURCE, *({name: body} for name, body in HISTORICAL_SOURCE.items())):
                with self.subTest(source=sorted(source)):
                    _, _, files, raw, issue = boot_fixture(source=source)
                    issue_sha = C.pin(issue)["sha256"]
                    with self.assertRaisesRegex(ValueError, "reviewed package worker and normal archive validator"):
                        E.boot_bundle(raw, files, issue, issue_sha, 1100)
                    if source != HISTORICAL_SOURCE:
                        with self.assertRaisesRegex(ValueError, "reviewed package worker and normal archive validator"):
                            E.validate_package_inputs(raw, files, issue, issue_sha, 1100, historical_readback=True)

    def test_role_accepts_the_eight_gib_readonly_predecessor(self):
        def role_with(size):
            g, full, files, raw, issue = boot_fixture(size)
            with patch.object(W, "module", side_effect=[full, g]):
                plan, _, boot = E.boot_bundle(raw, files, issue, C.pin(issue)["sha256"], 1100)
            return E.role_descriptor(plan, boot)

        role = role_with(8 << 30)
        self.assertEqual(role["readonly_media"]["complete.qcow2"]["bytes"], 8 << 30)
        self.assertEqual(role["runtime"]["child_file_size_cap"], 4 << 30)
        with self.assertRaises(ValueError):
            role_with((8 << 30) + 1)

    def test_boot_uses_exact_existing_guest_and_role_is_inert(self):
        g, full, files, raw, issue = boot_fixture()
        issue_sha = C.pin(issue)["sha256"]
        with TemporaryDirectory() as temp, patch.object(W, "module", side_effect=[full, g]):
            root = Path(temp)
            stage_files(root / "stage", files | {W.PLAN_NAME: raw})
            staged = E.staged_inputs(root / "stage", C.json_body(raw))
            plan, _, boot = E.boot_bundle(raw, staged, issue, issue_sha, 1100)
            stage_files(root / "boot", boot)
            role = E.role_descriptor(plan, boot)
            self.assertEqual(role["scope"], W.SCOPE)
            self.assertEqual(role["chain"], list(E.CHAIN))
            self.assertEqual(role["host_adapter"], "REQUIRES_ROLE_AWARE_OWNED_SITE")
            self.assertIsNone(role["authority"])
            self.assertEqual(role["packaging"], "NOT_RUN")
            self.assertEqual(role["runtime"]["network"], "none")
            self.assertEqual(role["boot_payload"]["guest-init.sh"]["mode"], 0o555)
            argv = role["qemu_argv"]
            tokens = argv[argv.index("-append") + 1].split()
            shell = 'path=$1; shift; package_cmdline "$@"; package_payload "$path"; package_caps "$path/CAPS.tsv"'
            passed = bash(shell, str(root / "boot"), *tokens)
            self.assertEqual(passed.returncode, 0, passed.stderr.decode())
            extra = bash(shell, str(root / "boot"), *tokens, tokens[-1])
            self.assertNotEqual(extra.returncode, 0)
            (root / "boot" / "packaging" / "recipe" / "operand-1").write_bytes(b"altered")
            changed = bash(shell, str(root / "boot"), *tokens)
            self.assertNotEqual(changed.returncode, 0)
            (root / "stage" / "unexpected").touch()
            with self.assertRaisesRegex(ValueError, "staging namespace"):
                E.staged_inputs(root / "stage", plan)

    @unittest.skipUnless(os.getuid() == os.getgid() == 1000, "Guest UID/GID fixture requires 1000:1000")
    def test_export_allows_empty_dependency_log_and_refuses_missing_archive(self):
        _, _, _, raw, _ = boot_fixture()
        caps = E.evidence_caps(C.json_body(raw))
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "dest").mkdir()
            stage_files(root / "src", {name: b"x" * low for name, (low, _) in caps.items()})
            (root / "caps").write_bytes(E.caps_bytes(C.json_body(raw)))
            shell = 'package_caps "$1/caps"; package_retain "$1/src" "$1/dest" PASS'
            passed = bash(shell, str(root))
            self.assertEqual(passed.returncode, 0, passed.stderr.decode())
            self.assertEqual((root / "dest/dependencies.log").stat().st_size, 0)
            self.assertEqual((root / "dest/dependencies.log").stat().st_mode & 0o777, 0o600)
            (root / "src" / W.ARCHIVE).unlink()
            (root / "dest" / W.ARCHIVE).unlink()
            self.assertNotEqual(bash(shell, str(root)).returncode, 0)

    def test_terminal_requires_one_nonce_and_known_state(self):
        prefix = E.TERMINAL + b" " + G.NONCE.encode()
        passed = prefix + b" PASS complete\n"
        held = prefix + b" HOLD retain\n"
        self.assertEqual(E.terminal(passed, G.NONCE), ("PASS", "complete"))
        self.assertEqual(E.terminal(held, G.NONCE), ("HOLD", "retain"))
        for raw in (passed + held, prefix + b" PASS package\n", prefix + b" HOLD unknown\n",
                    passed.replace(G.NONCE.encode(), G.OLD.encode())):
            with self.assertRaises(ValueError):
                E.terminal(raw, G.NONCE)

    def test_redirected_worker_failure_reports_hold_on_original_stream(self):
        init = (HERE / "package-guest-init.sh").read_text()
        start = init.index('    guest "$remaining"')
        worker = init[start:init.index("\n}", start)]
        fixture = r'''
ROOT=$1 EXPORT=$1/export result=inert nonce=$2 phase=package
remaining=2700 package_plan=inert package_selection=inert
mkdir "$ROOT$PACKAGE_OUTPUT" "$EXPORT"
worker_exit=$3
guest() {
    printf 'private stdout\n'
    printf 'private stderr\n' >&2
    /usr/bin/bash --noprofile --norc -c 'exit "$1"' bash "$worker_exit"
}
builder_absent() { return 0; }
mount() { return 0; }
mountpoint() { [[ $3 == "$EXPORT" ]]; }
umount() { [[ $3 == "$EXPORT" ]]; }
sync() { return 0; }
fresh_result_root() { return 0; }
package_shutdown() {
    printf '%s %s %s %s\n' "$PACKAGE_TERMINAL" "$nonce" "$1" "$phase"
    exit 0
}
trap 'package_finish HOLD' ERR HUP INT TERM
'''
        for code, expected in ((0, ("PASS", "complete")), (1, ("HOLD", "package")), (124, ("HOLD", "package"))):
            with self.subTest(code=code), TemporaryDirectory() as temp:
                result = bash(fixture + worker, temp, G.NONCE, str(code))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, b"")
                self.assertEqual(result.stdout.count(b"\n"), 1)
                self.assertEqual(E.terminal(result.stdout, G.NONCE), expected)


class OfflineReadback(unittest.TestCase):
    def test_worker_readback_binds_commands_archive_and_metadata(self):
        plan, stage, files, worker = pass_fixture()

        def verify(worker, files=files, archive=G.PIN):
            all_files = files | {"result.json": C.wire(worker)}
            pins = {name: C.pin(body) for name, body in all_files.items()} | {W.ARCHIVE: archive}
            return R.worker_evidence(pins, all_files, plan, stage, PLAN, SELECTION, ("PASS", "complete"))

        self.assertEqual(verify(worker), worker)
        with self.assertRaisesRegex(ValueError, "archive and evidence"):
            verify(worker, archive=C.pin(b"replacement"))
        with self.assertRaisesRegex(ValueError, "metadata digest"):
            verify(worker | {"metadata": {}})
        with self.assertRaisesRegex(ValueError, "success receipt"):
            verify(worker, files | {"dependencies.log": b"unexpected"})
        with self.assertRaisesRegex(ValueError, "scope"):
            verify(worker | {"selection_sha256": PLAN["sha256"]})
        with self.assertRaisesRegex(ValueError, "action sequence"):
            verify(worker | {"commands": {}})

    def test_hold_is_not_promoted_by_a_complete_worker(self):
        plan, stage, files, worker = pass_fixture()
        receipt = C.wire(worker)
        self.assertEqual(R.worker_evidence({"result.json": C.pin(receipt)}, {"result.json": receipt},
                                           plan, stage, PLAN, SELECTION, ("HOLD", "retain")), worker)
        self.assertIsNone(R.worker_evidence({}, {}, plan, stage, PLAN, SELECTION, ("HOLD", "boot")))
        with self.assertRaisesRegex(ValueError, "terminal phase"):
            R.worker_evidence({"result.json": C.pin(receipt)}, {"result.json": receipt}, plan, stage, PLAN, SELECTION,
                              ("HOLD", "boot"))

    def test_small_original_ext4_fixture_reads_allowed_data_only(self):
        with TemporaryDirectory() as temp:
            disk = Path(temp) / "result.raw"
            with patch.object(D.FIXTURE["R"], "RESULT_BYTES", 64 << 10), patch.object(E, "RESULT_BYTES", 64 << 10):
                D.evidence_disk(disk, W.ARCHIVE, b"model archive")
                with disk.open("r+b") as stream:
                    stream.seek(1024 + 120)
                    stream.write(E.RESULT_LABEL.encode().ljust(16, b"\0"))
                    stream.flush()
                sha = C.read(disk, E.RESULT_BYTES, collect=False)[1]["sha256"]
                caps = {W.ARCHIVE: (1, 100), "result.json": (1, 100)}
                pins, files = R.retained(disk, sha, D.UUID, caps, False)
                self.assertEqual(pins, {W.ARCHIVE: C.pin(b"model archive")})
                self.assertEqual(files, {})
                with self.assertRaisesRegex(ValueError, "evidence namespace"):
                    R.retained(disk, sha, D.UUID, caps, True)
                with self.assertRaisesRegex(ValueError, "sealed label and UUID"):
                    R.retained(disk, sha, E.P.result_uuid(G.NONCE), caps, False)
                with self.assertRaisesRegex(ValueError, "Exact original file pin"):
                    R.retained(disk, G.DIGEST, D.UUID, caps, False)

    def test_historical_pin_readback_does_not_issue_or_claim_retirement(self):
        g, full, staged, plan, selection = boot_fixture(source=HISTORICAL_SOURCE)
        with (TemporaryDirectory() as temp, patch.object(W, "module", side_effect=[full, g]),
              patch.dict(E.validate_package_inputs.__globals__, HISTORICAL_SOURCE_PINS=HISTORICAL_PINS),
              patch.object(D.FIXTURE["R"], "RESULT_BYTES", 64 << 10), patch.object(E, "RESULT_BYTES", 64 << 10),
              patch.object(E, "evidence_caps", return_value={W.ARCHIVE: (1, 100)})):
            root = Path(temp)
            stage_files(root / "stage", staged | {W.PLAN_NAME: plan})
            stage_files(root, {"selection": selection, "serial": E.TERMINAL + b" " + G.NONCE.encode() + b" HOLD retain\n"})
            disk = root / "result.raw"
            D.evidence_disk(disk, W.ARCHIVE, b"model archive")
            with disk.open("r+b") as stream:
                stream.seek(1024 + 104)
                stream.write(UUID(E.P.result_uuid(G.NONCE)).bytes + E.RESULT_LABEL.encode().ljust(16, b"\0"))
            result_sha = C.read(disk, E.RESULT_BYTES, collect=False)[1]["sha256"]
            report = R.readback(root / "stage", C.pin(plan)["sha256"], root / "selection", C.pin(selection)["sha256"],
                                root / "serial", C.pin((root / "serial").read_bytes())["sha256"], disk, result_sha)
            self.assertEqual(report["status"], "HOLD")
            self.assertEqual(report["phase"], "retain")
            self.assertEqual(report["host_retirement"], "NOT_OBSERVED")
            self.assertIsNone(report["worker"])
            self.assertTrue(all(report[field] == "NOT_RUN" for field in ("signing", "installation", "hardware")))
