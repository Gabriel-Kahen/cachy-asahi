# SPDX-License-Identifier: MIT
"""Offline controls for the bounded full Qtbase guest evidence and sequencing."""

from copy import deepcopy
from pathlib import Path
from runpy import run_path
import struct
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


F = SimpleNamespace(**run_path(str(Path(__file__).with_name("full_guest.py"))))
MODULE = F.verify_evidence.__globals__


def plan():
    return dict(kind=F.PLAN_KIND, nonce="9" * 32, target=F.TARGET,
                limits=dict(guest_build_seconds=50, build_log_bytes=1024, artifact_bytes=32 * F.MIB,
                            guest_min_free_bytes=2 * F.GIB),
                inventory=deepcopy(F.INVENTORY), inherited=deepcopy(F.INHERITED),
                dry_run=deepcopy(F.DRY_RUN), all_commands=deepcopy(F.ALL_COMMANDS))


def model_library(alignment=65536):
    body = bytearray(120)
    body[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", body, 16, 3, 183, 1)
    struct.pack_into("<Q", body, 32, 64)
    struct.pack_into("<HHH", body, 52, 64, 56, 1)
    struct.pack_into("<II6Q", body, 64, 1, 5, 0, 0, 0, len(body), len(body), alignment)
    return bytes(body)


def metrics():
    return dict(exit_code=0, elapsed_ms=271, peak_child_rss_kib=12, log_complete=True, natural=True,
                group_empty=True, timeout=False, overflow=False, dry_run_steps=F.REMAINDER_COUNT)


def model():
    files = {name: model_library() for name in F.LIBRARIES}
    files.update({"inventory.before": b"model 1-1\n", "inventory.after": b"model 1-1\n",
                  "gui-dry-run.log": F.NINJA_IDLE, "all-dry-run.log": b"[1/1] model command\n",
                  "all-dry-run.after.log": F.NINJA_IDLE, "all.commands": b"model command\n",
                  "build.log": b"model\n", "metrics.json": F.wire_evidence(metrics())})
    rows = {name: dict(F.pin(files[name]), aliases=F.alias_metadata(name)) for name in F.LIBRARIES}
    outputs = dict(libraries=rows, guest_free_bytes=dict(before=3 * F.GIB, after=2 * F.GIB))
    files["outputs.json"] = F.wire_evidence(outputs)
    fixed = dict(INVENTORY=F.pin(files["inventory.before"]),
                 INHERITED={role: F.pin(files[name]) for role, name in F.ROLE_NAMES.items()}
                 | {"md4c": F.pin(b"model md4c")},
                 DRY_RUN={key: F.pin(files[key + "-dry-run.log"]) for key in ("gui", "all")},
                 ALL_COMMANDS=F.pin(files["all.commands"]))
    selected = plan() | {name.lower(): value for name, value in fixed.items()}
    sha = F.pin(F.wire_plan(selected))["sha256"]
    files["result.json"] = F.wire_evidence(dict(kind=F.RESULT_KIND, status="PASS", phase="complete",
                                               nonce=selected["nonce"], plan_sha256=sha, target=F.TARGET))
    return fixed, selected, sha, files, outputs


class Inputs(unittest.TestCase):
    def test_exact_canonical_guest_plan_and_symlink_refusal(self):
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "plan.json"
            selected = plan()
            for raw in (F.wire_plan(selected), F.wire_evidence(selected)):
                path.write_bytes(raw)
                sha = F.pin(raw)["sha256"]
                if raw == F.wire_plan(selected):
                    self.assertEqual(F.read_plan(path, sha), selected)
                    link = path.with_name("link")
                    link.symlink_to(path.name)
                    with self.assertRaises(ValueError):
                        F.read_plan(link, sha)
                else:
                    with self.assertRaisesRegex(ValueError, "canonical"):
                        F.read_plan(path, sha)

    def test_shape_and_external_pins_refuse(self):
        for key in ("all_commands", "inventory", "dry_run", "inherited"):
            selected = plan()
            selected[key] = F.pin(b"unreviewed model")
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "Exact original Q3"):
                F.evidence_caps(selected)
        selected = plan()
        selected["limits"]["guest_build_seconds"] = True
        with self.assertRaisesRegex(ValueError, "Finite structural"):
            F.validate_plan(selected)

    def test_frozen_sidecar_pin(self):
        path = Path(__file__).resolve().parents[1] / "qt612_gui_16k_link_checkpoint/guest_link.py"
        with patch.dict(MODULE, SIDECAR=path):
            runtime = F.guest_runtime()
        self.assertEqual(runtime.BUILD_ARGV[:-1], F.BUILD_ARGV[:-1])
        self.assertEqual(runtime.BUILD_ARGV[-1], runtime.TARGET)


class Evidence(unittest.TestCase):
    def test_complete_pass_only(self):
        fixed, selected, sha, files, outputs = model()
        with patch.dict(MODULE, fixed):
            report = F.verify_evidence(files, selected, sha)
        self.assertEqual(report["outputs"], outputs)
        self.assertEqual(report["status"], "VERIFIED_QTBASE_BUILD_ONLY")
        self.assertEqual(len(report["outputs"]["libraries"]), 18)

    def test_pin_scope_and_missing_or_nonidle_files_refuse(self):
        fixed, selected, sha, files, _ = model()
        for name in ("result.json", "gui-dry-run.log", "all-dry-run.log", "all-dry-run.after.log",
                     "all.commands", "inventory.before", "inventory.after", "libQt6Gui.so.6.12.0"):
            with self.subTest(name=name), patch.dict(MODULE, fixed), self.assertRaises(ValueError):
                F.verify_evidence(files | {name: b"wrong model bytes\n"}, selected, sha)
        with patch.dict(MODULE, fixed), self.assertRaisesRegex(ValueError, "Exact independently pinned"):
            F.verify_evidence({k: v for k, v in files.items() if k != "build.log"}, selected, sha)

    def test_inherited_pin_and_built_dso_geometry_checked_independently(self):
        fixed, selected, sha, files, outputs = model()
        for name, body in (("libQt6Core.so.6.12.0", model_library() + b"changed"),
                           ("libQt6OpenGL.so.6.12.0", model_library(4096))):
            changed = deepcopy(outputs)
            changed["libraries"][name].update(F.pin(body))
            with self.subTest(name=name), patch.dict(MODULE, fixed), self.assertRaises(ValueError):
                F.verify_evidence(files | {name: body, "outputs.json": F.wire_evidence(changed)}, selected, sha)

    def test_metrics_and_disk_floor_refuse(self):
        fixed, selected, sha, files, outputs = model()
        for key, value in (("elapsed_ms", 50001), ("dry_run_steps", 1215), ("group_empty", 1), ("timeout", True)):
            raw = F.wire_evidence(metrics() | {key: value})
            with self.subTest(key=key), patch.dict(MODULE, fixed), self.assertRaisesRegex(ValueError, "natural"):
                F.verify_evidence(files | {"metrics.json": raw}, selected, sha)
        outputs["guest_free_bytes"]["after"] -= 1
        with patch.dict(MODULE, fixed), self.assertRaisesRegex(ValueError, "disk floor"):
            F.verify_evidence(files | {"outputs.json": F.wire_evidence(outputs)}, selected, sha)


class Worker(unittest.TestCase):
    def test_refusal_before_build_retains_fixed_failure_result(self):
        with TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            selected = plan()
            g = SimpleNamespace(check_inputs=Mock(side_effect=ValueError("hidden host text")), capture=Mock(),
                                put_json=lambda path, value: path.write_bytes(F.wire_evidence(value)))
            self.assertEqual(F.build(g, selected, "0" * 64, evidence), "HOLD")
            g.capture.assert_not_called()
            self.assertEqual({p.name for p in evidence.iterdir()}, {"result.json"})
            result = F.evidence_json((evidence / "result.json").read_bytes())
            self.assertEqual(result["phase"], "inputs")
            self.assertEqual(result["failure_code"], F.FAILURE_CODES["inputs"])
            self.assertNotIn(b"hidden host text", (evidence / "result.json").read_bytes())

    def test_inventory_temporary_name_retired_on_failure(self):
        with TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            def fail(path, name):
                (path / (name + ".raw")).write_bytes(b"diagnostic")
                raise ValueError("model refusal")
            with self.assertRaisesRegex(ValueError, "model refusal"):
                F.inventory(SimpleNamespace(inventory=fail), evidence, "inventory.before")
            self.assertFalse(any(evidence.iterdir()))

    def test_build_order_retires_before_post_build_verification(self):
        with TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            calls = []
            selected = plan()
            def record(*args, **_kwargs):
                calls.append(args[2] if len(args) > 2 else args[0])
            def capture(argv, path, seconds, cap, *, cwd):
                self.assertEqual(argv, F.BUILD_ARGV)
                self.assertEqual((seconds, cap), (50, 1024))
                calls.append(path.name)
                return metrics()
            g = SimpleNamespace(BUILD=evidence, RECIPE=evidence, TARGET="model-gui", check_inputs=Mock(),
                                file_data=Mock(), command_body=Mock(), capture=capture, require_success=Mock(),
                                put_json=lambda path, value: path.write_bytes(F.wire_evidence(value)))
            with patch.dict(MODULE, inherited_state=Mock(return_value=None), inventory=record, dry_run=record,
                            free_space=Mock(return_value=3 * F.GIB), retain_outputs=Mock(return_value={})):
                self.assertEqual(F.build(g, selected, "0" * 64, evidence), "PASS")
            self.assertEqual(calls, ["inventory.before", "gui-dry-run.log", "all-dry-run.log", "build.log",
                                     "all-dry-run.after.log", "inventory.after"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
