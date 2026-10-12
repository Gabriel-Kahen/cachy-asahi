"""Portable temp-only adapter checks; all native commands and signals are mocked."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).parent
REPO = HERE.parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


corpus = module("stage_corpus", HERE / "corpus.py")
with patch.dict(sys.modules, {"corpus": corpus}):
    arm = module("stage_core", HERE / "arm_c01.py")
with patch.dict(sys.modules, {"arm_c01": arm}):
    stage = module("stage_under_test", HERE / "stage.py")


class StageTests(unittest.TestCase):
    def enterContext(self, manager):
        value = manager.__enter__()
        self.addCleanup(manager.__exit__, None, None, None)
        return value

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="cachy-asahi-stage-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.enterContext(patch.dict(os.environ, {key: value for key, value in os.environ.items()
                                                  if not key.startswith("DOCKER_") and key != "GITHUB_SHA"}, clear=True))
        for name in ("Popen", "run", "call", "check_call", "check_output"):
            self.enterContext(patch.object(subprocess, name, side_effect=AssertionError(
                "No real Docker, package, GPG, native build or subprocess allowed")))
        self.enterContext(patch.object(os, "killpg", side_effect=AssertionError("No actual signals")))
        self.enterContext(patch.object(signal, "signal", return_value=signal.SIG_DFL))
        for name in ("getuid", "geteuid", "getgid", "getegid"):
            self.enterContext(patch.object(os, name, return_value=1000))

    def fixture(self, installed=False):
        source_root = self.root / "source-repo"
        (source_root / "scripts/experiments").mkdir(parents=True)
        for name in stage.FILES:
            shutil.copyfile(HERE / name, source_root / "scripts/experiments" / name)
            (source_root / "scripts/experiments" / name).chmod((HERE / name).stat().st_mode & 0o777)
        exporter = source_root / stage.EXPORTER; exporter.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / stage.EXPORTER, exporter)
        exporter.chmod((REPO / stage.EXPORTER).stat().st_mode & 0o777)
        inputs = self.root / "inputs"; inputs.mkdir()
        archive = inputs / "zlib.tar.gz"; archive.write_bytes(b"synthetic retained source, not upstream archive")
        # Only the input hash constant is mocked; no archive extraction/build occurs.
        self.enterContext(patch.object(arm, "SOURCE_SHA", arm.sha(archive)))
        base = {f"base-{i:03d}": "1-1" for i in range(341)}
        versions = {name: "1.0-1" for name in stage.ORIGINALS}
        expected = base | versions if installed else base
        base_path, expected_path = inputs / "base.lock", inputs / "expected.lock"
        for path, rows in ((base_path, base), (expected_path, expected)):
            path.write_text("".join(f"{name} {version}\n" for name, version in sorted(rows.items())))
        lock_path = self.root / "freeze.json"
        lock = stage.freeze(source_root, lock_path)
        args = SimpleNamespace(source_root=source_root, image="sha256:" + "a" * 64, source_commit="b" * 40,
                               source=archive, base_packages=base_path, base_packages_sha256=arm.sha(base_path),
                               expected_packages=expected_path, expected_packages_sha256=arm.sha(expected_path),
                               lock=lock_path, lock_sha256=arm.sha(lock_path), output=self.root / "output",
                               handoff_dir=None, handoff_pins=None, handoff_pins_sha256=None)
        if installed:
            self.handoff(args, base, expected, versions)
        return args, lock

    def handoff(self, args, base, expected, versions):
        directory = self.root / "handoff"; directory.mkdir()
        (directory / "committed-image").mkdir()
        shutil.copyfile(args.expected_packages, directory / "installed-packages.lock")
        payload = {name: "c" * 64 for name in versions}
        container = "cachy-asahi-handoff-" + "a" * 32
        image_config = {"User": "", "Env": [], "Entrypoint": [], "Cmd": [], "WorkingDir": "/",
                        "Labels": None, "Volumes": None, "ExposedPorts": None, "StopSignal": None,
                        "Shell": [], "Healthcheck": None, "ArgsEscaped": False}
        receipt = {"status": "READY", "purpose": "sanitized-baseline-image-handoff", "source_commit": args.source_commit,
                   "base_packages_sha256": args.base_packages_sha256, "installed_packages_sha256": args.expected_packages_sha256,
                   "installed_package_count": len(expected), "package_versions": versions, "payload_sha256": payload,
                   "image_id": "sha256:" + "d" * 64,
                   "checks": [{"check": name, "status": "PASS"} for name in (
                       "successful-lifecycle-handoff", "exact-base-plus-originals-inventory", "original-payload-hash",
                       "private-keyring-removed", "image-tmp-view-empty")]}
        arm.save(directory / "commit-receipt.json", receipt)
        arm.save(directory / "installed-image.json", {"image_id": args.image, "source_commit": args.source_commit,
                 "lock_sha256": args.expected_packages_sha256, "hardware_validation": "NOT RUN",
                 "commit_receipt_sha256": arm.sha(directory / "commit-receipt.json"),
                 "base_image": receipt["image_id"], "container": container})
        arm.save(directory / "committed-image/result.json", {"status": "PASS", "image_id": args.image,
                 "source_commit": args.source_commit, "installed_packages_sha256": args.expected_packages_sha256,
                 "hardware_validation": "NOT RUN", "baseline": [{"name": name, "version": version,
                 "payload_sha256": payload[name]} for name, version in versions.items()]})
        arm.save(directory / "committed-config.json", {"status": "PASS", "image_id": args.image,
                 "base_image": receipt["image_id"], "accepted_base_config": image_config, "committed_config": image_config,
                 "test_identity_in_image_env": False})
        arm.save(directory / "container-removal.json", {"status": "PASS", "absence_verified": True,
                 "container": container})
        args.handoff_dir = directory
        args.handoff_pins = self.root / "handoff-pins.json"
        self.refresh_handoff(args)

    def refresh_handoff(self, args):
        # Updating metadata's receipt hash keeps logical-negative tests beyond pin checks.
        metadata = json.loads((args.handoff_dir / "installed-image.json").read_text())
        metadata["commit_receipt_sha256"] = arm.sha(args.handoff_dir / "commit-receipt.json")
        arm.save(args.handoff_dir / "installed-image.json", metadata)
        arm.save(args.handoff_pins, {name: arm.sha(args.handoff_dir / name) for name in stage.HANDOFF})
        args.handoff_pins_sha256 = arm.sha(args.handoff_pins)

    def test_freeze_has_exact_six_files_exporter_and_no_native_claim(self):
        args, lock = self.fixture()
        self.assertEqual(set(lock["source_files"]), set(stage.FILES))
        self.assertEqual(len(lock["source_files"]), 6)
        self.assertTrue(lock["development_only"])
        self.assertFalse(lock["selected_for_release"])
        self.assertEqual(lock["exporter"]["sha256"], arm.sha(args.source_root / stage.EXPORTER))
        with self.assertRaises(ValueError):
            stage.freeze(args.source_root, args.lock)

    def test_readonly_base_preflight_requires_341_without_handoff(self):
        args, lock = self.fixture()
        actual_lock, handoff = stage.validate_inputs(args)
        self.assertEqual(actual_lock, lock)
        self.assertEqual(handoff["package_count"], 341)
        self.assertEqual(handoff["kind"], "accepted-base-image")
        self.assertFalse(args.output.exists())

    def test_installed_preflight_accepts_exact_six_receipts_and_four_versions(self):
        args, _ = self.fixture(installed=True)
        _, handoff = stage.validate_inputs(args)
        self.assertEqual((handoff["kind"], handoff["package_count"]), ("verified-original-installed-image", 345))
        self.assertFalse(args.output.exists())

    def test_source_exporter_inventory_archive_and_lock_drift_refused_without_output(self):
        args, _ = self.fixture()
        paths = [args.source_root / "scripts/experiments" / name for name in stage.FILES]
        paths += [args.source_root / stage.EXPORTER, args.base_packages, args.expected_packages, args.source, args.lock]
        for path in paths:
            before = path.read_bytes(); path.write_bytes(before + b"drift")
            with self.subTest(path=path.name), self.assertRaises(ValueError):
                stage.validate_inputs(args)
            self.assertFalse(args.output.exists()); path.write_bytes(before)

    def test_source_mode_symlink_and_workflow_commit_drift_refused(self):
        args, _ = self.fixture()
        source = args.source_root / "scripts/experiments/corpus.py"
        mode = source.stat().st_mode & 0o777; source.chmod(mode ^ 0o100)
        with self.assertRaises(ValueError):
            stage.validate_inputs(args)
        source.chmod(mode)
        original = source.read_bytes(); source.unlink()
        target = self.root / "same-bytes"; target.write_bytes(original); source.symlink_to(target)
        with self.assertRaises(ValueError):
            stage.validate_inputs(args)
        source.unlink(); source.write_bytes(original); source.chmod(mode)
        with patch.dict(os.environ, {"GITHUB_SHA": "c" * 40}), self.assertRaises(ValueError):
            stage.validate_inputs(args)

    def test_wrong_base_count_duplicate_inventory_or_overlay_in_base_refused(self):
        args, _ = self.fixture()
        original = args.base_packages.read_text()
        for text in ("".join(original.splitlines(keepends=True)[:-1]), original + original.splitlines(keepends=True)[0],
                     original.replace("base-000", sorted(stage.ORIGINALS)[0])):
            args.base_packages.write_text(text); args.base_packages_sha256 = arm.sha(args.base_packages)
            with self.subTest(text_length=len(text)), self.assertRaises(ValueError):
                stage.validate_inputs(args)
            self.assertFalse(args.output.exists())

    def test_345_packages_cannot_skip_handoff_or_change_base_versions(self):
        args, _ = self.fixture(installed=True)
        saved = args.handoff_dir; args.handoff_dir = None
        with self.assertRaises(ValueError):
            stage.validate_inputs(args)
        args.handoff_dir = saved
        args.expected_packages.write_text(args.expected_packages.read_text().replace("base-000 1-1", "base-000 2-1"))
        args.expected_packages_sha256 = arm.sha(args.expected_packages)
        with self.assertRaises(ValueError):
            stage.validate_inputs(args)

    def test_installed_handoff_pin_set_and_changed_bytes_refused(self):
        args, _ = self.fixture(installed=True)
        pins = json.loads(args.handoff_pins.read_text()); pins.pop("container-removal.json")
        arm.save(args.handoff_pins, pins); args.handoff_pins_sha256 = arm.sha(args.handoff_pins)
        with self.assertRaises(ValueError):
            stage.validate_inputs(args)
        self.refresh_handoff(args)
        path = args.handoff_dir / "container-removal.json"; path.write_text(path.read_text() + " ")
        with self.assertRaises(ValueError):
            stage.validate_inputs(args)

    def test_handoff_semantic_status_identity_cleanup_and_payload_refused(self):
        args, _ = self.fixture(installed=True)
        cases = [("installed-image.json", "image_id", "sha256:" + "c" * 64),
                 ("installed-image.json", "hardware_validation", "PASS"),
                 ("commit-receipt.json", "status", "PASS"),
                 ("commit-receipt.json", "source_commit", "c" * 40),
                 ("commit-receipt.json", "package_versions", {}),
                 ("commit-receipt.json", "checks", []),
                 ("committed-image/result.json", "status", "FAIL"),
                 ("committed-image/result.json", "baseline", []),
                 ("committed-config.json", "test_identity_in_image_env", True),
                 ("container-removal.json", "absence_verified", False)]
        for name, key, value in cases:
            path = args.handoff_dir / name; original = path.read_bytes()
            data = json.loads(original); data[key] = value; arm.save(path, data); self.refresh_handoff(args)
            with self.subTest(name=name, key=key), self.assertRaises(ValueError):
                stage.validate_inputs(args)
            path.write_bytes(original); self.refresh_handoff(args)

    def test_handoff_cannot_replace_missing_identity_or_config_with_null_equality(self):
        args, _ = self.fixture(installed=True)
        for fields in ((('installed-image.json', 'container'), ('container-removal.json', 'container')),
                       (('committed-config.json', 'accepted_base_config'), ('committed-config.json', 'committed_config'))):
            originals = {name: (args.handoff_dir / name).read_bytes() for name, _ in fields}
            for name, key in fields:
                path = args.handoff_dir / name; data = json.loads(path.read_text()); data.pop(key); arm.save(path, data)
            self.refresh_handoff(args)
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                stage.validate_inputs(args)
            for name, data in originals.items():
                (args.handoff_dir / name).write_bytes(data)
            self.refresh_handoff(args)

    def test_native_x86_root_mismatched_uid_and_docker_overrides_refused_before_output(self):
        args, _ = self.fixture()
        for arch, euid in (("x86_64", 1000), ("aarch64", 0)):
            with self.subTest(arch=arch, euid=euid), patch.object(stage.platform, "machine", return_value=arch), patch.object(os, "geteuid", return_value=euid), self.assertRaises(ValueError):
                stage.run_stage(args)
            self.assertFalse(args.output.exists())
        with patch.object(stage.platform, "machine", return_value="aarch64"), patch.dict(os.environ, {"DOCKER_HOST": "tcp://unreviewed"}), self.assertRaises(ValueError):
            stage.run_stage(args)
        self.assertFalse(args.output.exists())

    def projection(self):
        trial = self.root / "trial"; trial.mkdir(); raw = trial / "raw"; raw.mkdir()
        arm.save(trial / "result.json", {"status": "PASS", "hardware_validation": "NOT RUN"})
        (trial / "004-container.log").write_bytes(b"synthetic public launcher log\n")
        arm.save(raw / "result.json", {"status": "PASS", "hardware_validation": "NOT RUN"})
        arm.save(raw / "environment.json", {"execution": "mocked source test"})
        arm.save(raw / "corpus-manifest.json", {"files": []})
        log = raw / "001-baseline-1-dependencies.log"; log.write_bytes(b"synthetic libc link-input record\n")
        rows = [{"log": log.name, "log_sha256": arm.sha(log), "status": "PASS", "cleanup": "PASS"}]
        arm.save(raw / "commands.json", rows)
        return trial, raw, rows

    def test_projection_renames_link_logs_preserving_hash_and_excludes_binary_private_corpus(self):
        trial, raw, rows = self.projection()
        (raw / "baseline-1").mkdir(); (raw / "baseline-1/minigzip").write_bytes(b"\x7fELF binary")
        (raw / "baseline-1/LICENSE.txt").write_bytes(b"synthetic notice")
        (raw / "corpus").mkdir(); (raw / "corpus/private.txt").write_bytes(b"never export corpus bytes")
        (raw / "private-state").mkdir(); (raw / "private-state/secret.txt").write_bytes(b"never read this")
        selected = self.root / "selected"; stage.project_evidence(trial, selected)
        projected = json.loads((selected / "commands.json").read_text())[0]
        self.assertEqual(projected["log"], "001-baseline-1-link-inputs.log")
        self.assertEqual(projected["producer_log"], rows[0]["log"])
        self.assertEqual(arm.sha(selected / projected["log"]), rows[0]["log_sha256"])
        self.assertFalse((selected / "baseline-1/minigzip").exists())
        self.assertFalse((selected / "corpus").exists()); self.assertFalse((selected / "private-state").exists())

    def test_projection_log_hash_collision_traversal_or_symlink_refused(self):
        trial, raw, rows = self.projection()
        cases = [rows + [{**rows[0], "log": "001-baseline-1-link-inputs.log"}],
                 [{**rows[0], "log_sha256": "0" * 64}], [{**rows[0], "log": "../outside.log"}]]
        for index, case in enumerate(cases):
            arm.save(raw / "commands.json", case)
            with self.subTest(index=index), self.assertRaises(ValueError):
                stage.project_evidence(trial, self.root / f"selected-{index}")
        arm.save(raw / "commands.json", rows)
        log = raw / rows[0]["log"]; before = log.read_bytes(); log.unlink()
        target = self.root / "outside.log"; target.write_bytes(before); log.symlink_to(target)
        with self.assertRaises(ValueError):
            stage.project_evidence(trial, self.root / "selected-link")

    def test_exporter_pin_and_private_content_failure_remain_explicit(self):
        args, lock = self.fixture()
        code = self.root / "snapshot"; stage.snapshot(args, lock, code)
        selected = self.root / "selected"; selected.mkdir()
        (selected / "diagnostic.log").write_bytes(b"password = never-publish-fixture\n")
        result = stage.export_public(code, selected, self.root / "public", lock["exporter"]["sha256"])
        self.assertEqual(result["evidence_export"], "FAIL")
        self.assertFalse((self.root / "public/diagnostic.log").exists())
        (code / "integration_export.py").write_bytes(b"changed exporter")
        with self.assertRaises(ValueError):
            stage.export_public(code, selected, self.root / "public-drift", lock["exporter"]["sha256"])

    def cleanup_fixture(self, endpoint="unix:///var/run/docker.sock", nonce="a" * 32):
        trial = self.root / "cleanup-trial"; (trial / "inputs").mkdir(parents=True)
        arm.save(trial / "inputs/contract.json", {"nonce": nonce})
        arm.save(trial / "001-context.log", [{"Endpoints": {"docker": {"Host": endpoint}}}])
        return trial, "cachy-asahi-arm-c01-" + nonce

    def test_fallback_cleanup_uses_exact_owned_name_and_pinned_local_endpoint(self):
        trial, name = self.cleanup_fixture(); calls = []
        def command(runner, label, argv, **kwargs):
            calls.append((label, argv))
            self.assertEqual(argv[:2], ["docker", "--host=unix:///var/run/docker.sock"])
            if label == "before":
                self.assertIn("name=^/" + name + "$", argv)
                return name.encode()
            if label == "remove":
                self.assertEqual(argv[2:], ["rm", "-f", name])
            return b""
        with patch.object(arm.Commands, "run", autospec=True, side_effect=command):
            result = stage.cleanup_trial(trial, self.root / "cleanup")
        self.assertEqual([row[0] for row in calls], ["before", "remove", "after"])
        self.assertEqual((result["status"], result["container"], result["absence_verified"]), ("PASS", name, True))

    def test_fallback_cleanup_never_removes_an_unexpected_or_remote_container(self):
        trial, _ = self.cleanup_fixture()
        with patch.object(arm.Commands, "run", return_value=b"other-owned-container") as commands, self.assertRaises(ValueError):
            stage.cleanup_trial(trial, self.root / "cleanup-unexpected")
        self.assertEqual(commands.call_count, 1)
        arm.save(trial / "001-context.log", [{"Endpoints": {"docker": {"Host": "tcp://remote"}}}])
        with self.assertRaises(ValueError):
            stage.cleanup_trial(trial, self.root / "cleanup-remote")
        self.assertFalse((self.root / "cleanup-remote").exists())

    def test_fallback_cleanup_requires_verified_absence_and_valid_nonce(self):
        trial, name = self.cleanup_fixture()
        with patch.object(arm.Commands, "run", side_effect=[name.encode(), b"", name.encode()]), self.assertRaises(ValueError):
            stage.cleanup_trial(trial, self.root / "cleanup-present")
        arm.save(trial / "inputs/contract.json", {"nonce": "not-a-nonce"})
        with self.assertRaises(ValueError):
            stage.cleanup_trial(trial, self.root / "cleanup-invalid")
        self.assertFalse((self.root / "cleanup-invalid").exists())

    def test_fallback_cleanup_finishes_absence_check_after_command_receipt_cancel(self):
        trial, name = self.cleanup_fixture()
        events, calls = [], []
        def command(runner, label, argv, **kwargs):
            calls.append(label)
            if label == "before":
                return name.encode()
            if label == "remove":
                raise arm.Cancelled()
            return b""
        with patch.object(arm.Commands, "run", autospec=True, side_effect=command):
            result = stage.cleanup_trial(trial, self.root / "cleanup-cancelled", events)
        self.assertEqual(calls, ["before", "remove", "after"])
        self.assertEqual(events, ["container-cleanup"])
        self.assertEqual((result["status"], result["cancelled"], result["cleanup_uncertain"]), ("FAIL", True, True))
        self.assertTrue(result["absence_verified"])

    def test_final_cleanup_cancel_exports_authoritative_failure_despite_trial_pass(self):
        args, lock = self.fixture()
        for index, interruption in enumerate((arm.Cancelled(), KeyboardInterrupt())):
            args.output = self.root / f"cleanup-cancel-{index}"
            with patch.object(stage, "cleanup_trial", side_effect=interruption):
                result, report = self.fake_run(args, lock)
            self.assertEqual((result, report["status"], report["cancelled"]), (1, "FAIL", True))
            cleanup = report["container_cleanup"]
            self.assertEqual((cleanup["status"], cleanup["cancelled"], cleanup["cleanup_uncertain"]), ("FAIL", True, True))
            self.assertFalse(cleanup["absence_verified"])
            self.assertEqual(json.loads((args.output / "trial/result.json").read_text())["status"], "PASS")
            self.assertEqual(report["evidence_export"], "PASS")
            self.verify_final_bundle(args, "FAIL")

    def fake_run(self, args, lock, error=None, cleanup_ok=True, receiver_error=False, export_error=False, final_cancel=False, final_export_error=False):
        handlers, injected = {}, []
        actual_export = stage.export_public
        def remember(signum, handler):
            previous = handlers.get(signum, signal.SIG_DFL); handlers[signum] = handler; return previous
        def command(runner, name, argv, **kwargs):
            if error:
                raise error
            self.assertEqual(Path(argv[2]).name, "arm_c01.py")
            trial = args.output / "trial"; trial.mkdir(); (trial / "raw").mkdir()
            contract = {"source_commit": args.source_commit, "packages_sha256": args.expected_packages_sha256,
                        "runner_sha256": lock["source_files"]["arm_c01.py"]["sha256"],
                        "corpus_sha256": lock["source_files"]["corpus.py"]["sha256"]}
            arm.save(trial / "result.json", {"status": "PASS", "image": args.image, "contract": contract,
                     "controller_group_cleanup": "PASS", "container_cleanup": "PASS"})
            arm.save(trial / "raw/result.json", {"status": "PASS", "hardware_validation": "NOT RUN"})
            arm.save(trial / "raw/commands.json", [])
        def export(code, selected, output, pin):
            if export_error and output.name == "public":
                return {"evidence_export": "FAIL"}
            if final_export_error and output.name == "public-status":
                return {"evidence_export": "FAIL"}
            result = actual_export(code, selected, output, pin)
            if final_cancel and output.name == "public-status" and not injected:
                injected.append(True); handlers[signal.SIGTERM](signal.SIGTERM, None)
            return result
        with patch.object(stage.platform, "machine", return_value="aarch64"), patch.object(arm.Commands, "run", autospec=True, side_effect=command), patch.object(arm.Commands, "stop", return_value=cleanup_ok), patch.object(arm, "verify_result", side_effect=ValueError("mock receiver failure") if receiver_error else None, return_value={}), patch.object(stage, "export_artifacts", return_value={"development_only": True, "selected_for_release": False}), patch.object(signal, "signal", side_effect=remember), patch.object(stage, "export_public", side_effect=export):
            result = stage.run_stage(args)
        return result, json.loads((args.output / "result.json").read_text())

    def verify_final_bundle(self, args, expected):
        self.assertEqual(json.loads((args.output / "final-status/result.json").read_text())["status"], expected)
        public = args.output / "public-status"
        self.assertEqual(json.loads((public / "result.json").read_text())["status"], expected)
        manifest = json.loads((public / "export-manifest.json").read_text())
        self.assertEqual(manifest["evidence_export"], "PASS")
        row = next(row for row in manifest["accepted"] if row["path"] == "result.json")
        self.assertEqual(row["sha256"], arm.sha(public / "result.json"))

    def test_mocked_native_stage_seals_software_only_public_result(self):
        args, lock = self.fixture(); result, report = self.fake_run(args, lock)
        self.assertEqual((result, report["status"]), (0, "PASS"))
        self.assertEqual(report["hardware_validation"], "NOT RUN")
        self.assertEqual(report["performance_acceptance"], "NOT RUN")
        self.assertFalse(report["selected_for_release"])
        self.verify_final_bundle(args, "PASS")

    def test_failed_delegate_receiver_cleanup_and_export_never_seal_pass(self):
        args, lock = self.fixture()
        for index, options in enumerate(({"error": ValueError("mock trial failure")}, {"error": arm.Cancelled()},
                                          {"receiver_error": True}, {"cleanup_ok": False}, {"export_error": True})):
            args.output = self.root / f"failure-{index}"
            result, report = self.fake_run(args, lock, **options)
            with self.subTest(options=options):
                self.assertEqual((result, report["status"]), (1, "FAIL"))
                self.verify_final_bundle(args, "FAIL")

    def test_late_cancel_after_status_export_reseals_manifest_bound_failure(self):
        args, lock = self.fixture(); result, report = self.fake_run(args, lock, final_cancel=True)
        self.assertEqual((result, report["status"], report["cancelled"]), (1, "FAIL", True))
        self.verify_final_bundle(args, "FAIL")

    def test_final_status_export_failure_cannot_leave_local_pass_receipts(self):
        args, lock = self.fixture()
        try:
            self.fake_run(args, lock, final_export_error=True)
        except ValueError:
            # main() converts a failed final publication into a failure exit.
            pass
        self.assertEqual(json.loads((args.output / "result.json").read_text())["status"], "FAIL")
        self.assertEqual(json.loads((args.output / "final-status/result.json").read_text())["status"], "FAIL")
        if (args.output / "public-status/result.json").exists():
            self.assertEqual(json.loads((args.output / "public-status/result.json").read_text())["status"], "FAIL")

    def artifact_fixture(self):
        raw = self.root / "native-artifacts"; raw.mkdir()
        manifest = corpus.create(raw / "corpus", b"synthetic public heldout fixture")
        # Match the native generator's canonical, byte-identical two manifests.
        shutil.copyfile(raw / "corpus/manifest.json", raw / "corpus-manifest.json")
        builds = []
        for variant in ("baseline", "lto"):
            for attempt in (1, 2):
                prefix = raw / f"{variant}-{attempt}"; prefix.mkdir()
                artifacts, configs = {}, {}
                for name in ("libz.a", "example", "minigzip"):
                    path = prefix / name; path.write_bytes(b"synthetic compiled bytes, not a native binary")
                    artifacts[name] = arm.sha(path)
                for name in ("Makefile", "zconf.h", "configure.log", "LICENSE"):
                    path = prefix / (name + ".txt"); path.write_bytes(b"synthetic public configuration/notice")
                    configs[name] = arm.sha(path)
                builds.append({"variant": variant, "attempt": attempt, "artifacts": artifacts,
                               "generated_configuration_sha256": configs})
        verified = {"builds": builds, "corpus_manifest_sha256": arm.sha(raw / "corpus-manifest.json"),
                    "contract": {"source_commit": "b" * 40, "image": "sha256:" + "a" * 64}}
        return raw, verified, manifest

    def test_development_archive_exact_allowlist_hashes_and_deterministic_bytes(self):
        raw, verified, manifest = self.artifact_fixture()
        extra = raw / "private-key.txt"; extra.write_bytes(b"synthetic private marker; never read")
        (raw / "oci-image.tar").write_bytes(b"synthetic unapproved image marker")
        original_read = Path.read_bytes
        def read_approved(path):
            self.assertNotIn(path.name, ("private-key.txt", "oci-image.tar"))
            return original_read(path)
        with patch.object(Path, "read_bytes", autospec=True, side_effect=read_approved):
            first = stage.export_artifacts(raw, self.root / "archive-first", verified)
            second = stage.export_artifacts(raw, self.root / "archive-second", verified)
        self.assertEqual(first, second)
        self.assertEqual(first["bundle_sha256"], arm.sha(self.root / "archive-first/development-ARM-C01-outputs.tar.gz"))
        self.assertEqual((self.root / "archive-first/development-ARM-C01-outputs.tar.gz").read_bytes(),
                         (self.root / "archive-second/development-ARM-C01-outputs.tar.gz").read_bytes())
        self.assertTrue(first["development_only"]); self.assertFalse(first["selected_for_release"])
        self.assertEqual((first["hardware_validation"], first["performance_acceptance"]), ("NOT RUN", "NOT RUN"))
        expected = {f"{variant}-{attempt}/{name}" for variant in ("baseline", "lto") for attempt in (1, 2)
                    for name in ("libz.a", "example", "minigzip", "Makefile.txt", "zconf.h.txt", "configure.log.txt", "LICENSE.txt")}
        expected |= {"corpus/" + row["path"] for row in manifest["files"]} | {"corpus/manifest.json"}
        with tarfile.open(self.root / "archive-first/development-ARM-C01-outputs.tar.gz", "r:gz") as archive:
            self.assertEqual(set(archive.getnames()), expected)
            self.assertEqual(set(first["files"]), expected)
            for member in archive:
                self.assertTrue(member.isfile())
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 0))
                self.assertEqual(member.mode, 0o755 if member.name.endswith(("/example", "/minigzip")) else 0o644)
                with archive.extractfile(member) as stream:
                    self.assertEqual(arm.hashlib.sha256(stream.read()).hexdigest(), first["files"][member.name])

    def test_development_archive_artifact_drift_and_unapproved_names_refused(self):
        raw, verified, _ = self.artifact_fixture()
        (raw / "baseline-1/minigzip").write_bytes(b"changed after verification")
        with self.assertRaises(ValueError):
            stage.export_artifacts(raw, self.root / "archive-drift", verified)
        self.assertFalse((self.root / "archive-drift/archive-manifest.json").exists())
        verified["builds"][0]["artifacts"]["private.txt"] = "0" * 64
        with self.assertRaises(ValueError):
            stage.export_artifacts(raw, self.root / "archive-unapproved", verified)
        self.assertFalse((self.root / "archive-unapproved").exists())

    def test_development_archive_manifest_drift_cannot_approve_private_extra(self):
        raw, verified, manifest = self.artifact_fixture()
        secret = raw / "corpus/private-key.txt"; secret.write_bytes(b"synthetic private marker, not a key")
        manifest["files"][0].update(path="private-key.txt", sha256=arm.sha(secret), bytes=secret.stat().st_size)
        arm.save(raw / "corpus-manifest.json", manifest)
        shutil.copyfile(raw / "corpus-manifest.json", raw / "corpus/manifest.json")
        original_read = Path.read_bytes
        def no_private_read(path):
            self.assertNotEqual(path, secret, "private member must be rejected before reading")
            return original_read(path)
        with patch.object(Path, "read_bytes", autospec=True, side_effect=no_private_read):
            with self.assertRaises(ValueError):
                stage.export_artifacts(raw, self.root / "archive-stale-manifest", verified)
            # Even a forged new pin cannot expand the fixed nine-name allowlist.
            verified["corpus_manifest_sha256"] = arm.sha(raw / "corpus-manifest.json")
            with self.assertRaises(ValueError):
                stage.export_artifacts(raw, self.root / "archive-forged-allowlist", verified)

    def test_development_archive_retained_manifest_and_corpus_byte_drift_refused(self):
        raw, verified, _ = self.artifact_fixture()
        path = raw / "corpus/manifest.json"; before = path.read_bytes(); path.write_bytes(before + b" ")
        with self.assertRaises(ValueError):
            stage.export_artifacts(raw, self.root / "archive-retained-manifest", verified)
        path.write_bytes(before); (raw / "corpus/onebyte.bin").write_bytes(b"z")
        with self.assertRaises(ValueError):
            stage.export_artifacts(raw, self.root / "archive-corpus-drift", verified)


if __name__ == "__main__":
    unittest.main()
