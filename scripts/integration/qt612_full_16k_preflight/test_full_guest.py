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


LOAD_ADDRESS = 65536
DYNAMIC_AT = 384
STRINGS_AT = 512
INTERP_AT = 256
ENTRY_AT = 320


def model_library(name, alignment=65536, *, interpreter=None):
    body = bytearray(768)
    body[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", body, 16, 3, 183, 1)
    struct.pack_into("<Q", body, 32, 64)
    struct.pack_into("<HHH", body, 52, 64, F.PHDR.size, 2 + (interpreter is not None))
    F.PHDR.pack_into(body, 64, 1, 5, 0, LOAD_ADDRESS, LOAD_ADDRESS, len(body), len(body), alignment)
    F.PHDR.pack_into(body, 120, 2, 4, DYNAMIC_AT, LOAD_ADDRESS + DYNAMIC_AT, 0, 64, 64, 8)
    strings = b"\0" + name.removesuffix(F.VERSION).encode() + b".so.6\0"
    body[STRINGS_AT:STRINGS_AT + len(strings)] = strings
    for index, (tag, value) in enumerate(((5, LOAD_ADDRESS + STRINGS_AT), (10, len(strings)), (14, 1), (0, 0))):
        F.DYNAMIC.pack_into(body, DYNAMIC_AT + index * F.DYNAMIC.size, tag, value)
    body[ENTRY_AT:ENTRY_AT + 4] = b"\xc0\x03\x5f\xd6"  # AArch64 RET
    if interpreter is not None:
        F.PHDR.pack_into(body, 176, 3, 4, INTERP_AT, LOAD_ADDRESS + INTERP_AT, 0, len(interpreter), len(interpreter), 1)
        body[INTERP_AT:INTERP_AT + len(interpreter)] = interpreter
        struct.pack_into("<Q", body, 24, LOAD_ADDRESS + ENTRY_AT)
    return bytes(body)


def metrics():
    return dict(exit_code=0, elapsed_ms=271, peak_child_rss_kib=12, log_complete=True, natural=True,
                group_empty=True, timeout=False, overflow=False)


def evidence_metrics():
    captured = metrics()
    captured["rusage_children_maxrss_kib"] = captured.pop("peak_child_rss_kib")
    return captured | {"dry_run_scheduled_steps": F.REMAINDER_COUNT}


def model_ninja_log():
    original = F.NINJA_LOG_HEADER + b"0\t7\t1795000000\tlib/libQt6Gui.so.6.12.0\t1\n"
    inherited = set(F.ROLE_NAMES.values())
    names = [name for name in F.LIBRARIES if name not in inherited]
    rows = b"".join(f"{index * 4}\t{index * 4 + 3}\t1795000000\tlib/{name}\t{index + 2:x}\n".encode()
                    for index, name in enumerate(names))
    return original, original + rows


def model():
    files = {name: model_library(name, interpreter=F.CORE_INTERPRETER if name == F.ROLE_NAMES["core"] else None)
             for name in F.LIBRARIES}
    original_log, complete_log = model_ninja_log()
    files.update({"inventory.before": b"model 1-1\n", "inventory.after": b"model 1-1\n",
                  "gui-dry-run.log": F.NINJA_IDLE, "all-dry-run.log": b"[1/1] model command\n",
                  "all-dry-run.after.log": F.NINJA_IDLE, "all.commands": b"model command\n",
                  "build.log": b"model\n", "metrics.json": F.wire_evidence(evidence_metrics()),
                  "ninja-log.after": complete_log})
    rows = {name: dict(F.pin(files[name]), aliases=F.alias_metadata(name)) for name in F.LIBRARIES}
    outputs = dict(libraries=rows, guest_free_bytes=dict(before=3 * F.GIB, after=2 * F.GIB),
                   ninja_log=dict(after=F.pin(complete_log), appended_output_rows=15, distinct_timing_command_tuples=15))
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
    return fixed | {"INITIAL_NINJA_LOG": F.pin_tuple(F.pin(original_log))}, selected, sha, files, outputs


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
        core = F.ROLE_NAMES["core"]
        opengl = "libQt6OpenGL.so.6.12.0"
        for name, body in ((core, files[core] + b"changed"), (opengl, model_library(opengl, 4096))):
            changed = deepcopy(outputs)
            changed["libraries"][name].update(F.pin(body))
            with self.subTest(name=name), patch.dict(MODULE, fixed), self.assertRaises(ValueError):
                F.verify_evidence(files | {name: body, "outputs.json": F.wire_evidence(changed)}, selected, sha)

    def test_resealed_library_swap_refuses_the_wrong_soname(self):
        fixed, selected, sha, files, outputs = model()
        original = "libQt6OpenGL.so.6.12.0"
        substitute = files["libQt6OpenGLWidgets.so.6.12.0"]
        outputs["libraries"][original].update(F.pin(substitute))
        files.update({original: substitute, "outputs.json": F.wire_evidence(outputs)})
        with patch.dict(MODULE, fixed), self.assertRaisesRegex(ValueError, "DT_SONAME differs"):
            F.verify_evidence(files, selected, sha)

    def test_metrics_and_disk_floor_refuse(self):
        fixed, selected, sha, files, outputs = model()
        for key, value in (("elapsed_ms", 50001), ("dry_run_scheduled_steps", 1215), ("group_empty", 1), ("timeout", True)):
            raw = F.wire_evidence(evidence_metrics() | {key: value})
            with self.subTest(key=key), patch.dict(MODULE, fixed), self.assertRaisesRegex(ValueError, "natural"):
                F.verify_evidence(files | {"metrics.json": raw}, selected, sha)
        outputs["guest_free_bytes"]["after"] -= 1
        with patch.dict(MODULE, fixed), self.assertRaisesRegex(ValueError, "disk floor"):
            F.verify_evidence(files | {"outputs.json": F.wire_evidence(outputs)}, selected, sha)

    def test_observed_ninja_records_remain_distinct_from_scheduled_actions(self):
        fixed, selected, sha, files, outputs = model()
        original, complete = model_ninja_log()
        alias = complete.splitlines(keepends=True)[-1].replace(b".so.6.12.0", b".so.6")
        with patch.dict(MODULE, fixed):
            result = F.ninja_log_delta(complete + alias, metrics()["elapsed_ms"])
            self.assertEqual((result["appended_output_rows"], result["distinct_timing_command_tuples"]), (16, 15))
            for changed, cause in ((original[:-1] + b"!\n" + complete[len(original):], "inherited prefix"),
                                   (complete.rsplit(b"\n", 2)[0] + b"\n", "every newly linked"),
                                   (complete + b"0\t400\t1795000000\tmodel\t1\n", "timings exceed"),
                                   (complete + b"malformed\n", "Malformed appended")):
                with self.subTest(cause=cause), self.assertRaisesRegex(ValueError, cause):
                    F.ninja_log_delta(changed, metrics()["elapsed_ms"])
            outputs["ninja_log"]["appended_output_rows"] = F.REMAINDER_COUNT
            with self.assertRaisesRegex(ValueError, "summary differs"):
                F.verify_evidence(files | {"outputs.json": F.wire_evidence(outputs)}, selected, sha)


class Library(unittest.TestCase):
    name = "libQt6OpenGL.so.6.12.0"

    @staticmethod
    def replace(body, fmt, offset, *values):
        mutated = bytearray(body)
        struct.pack_into(fmt, mutated, offset, *values)
        return bytes(mutated)

    def test_dynamic_table_must_be_complete_unique_and_file_backed(self):
        body = model_library(self.name)
        cases = (
            ("missing", "<I", 120, (0,), "one ELF PT_DYNAMIC"),
            ("foreign offset", "<Q", 128, (DYNAMIC_AT + 8,), "Malformed ELF PT_DYNAMIC"),
            ("unmapped table", "<qQ", DYNAMIC_AT, (5, LOAD_ADDRESS + len(body)), "file-backed load"),
            ("oversized SONAME index", "<qQ", DYNAMIC_AT + 32, (14, 500), "DT_SONAME differs"),
            ("missing SONAME", "<qQ", DYNAMIC_AT + 32, (1, 1), "string table and DT_SONAME"),
            ("duplicate SONAME", "<qQ", DYNAMIC_AT + 48, (14, 1), "Duplicate ELF dynamic"),
            ("unterminated dynamic", "<qQ", DYNAMIC_AT + 48, (1, 2), "Unterminated ELF PT_DYNAMIC"),
        )
        for label, fmt, offset, values, message in cases:
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, message):
                F.verify_library(self.name, self.replace(body, fmt, offset, *values))
        duplicate = bytearray(self.replace(body, "<H", 56, 3))
        duplicate[176:232] = duplicate[64:120]
        with self.assertRaisesRegex(ValueError, "one file-backed load"):
            F.verify_library(self.name, duplicate)
        pie = self.replace(body, "<QQ", 152, 80, 80)
        pie = self.replace(pie, "<qQ", DYNAMIC_AT + 48, 0x6ffffffb, 0x08000000)
        with self.assertRaisesRegex(ValueError, "for a shared library"):
            F.verify_library(self.name, pie)

    def test_interpreter_requires_exact_pinned_qtcore(self):
        core = F.ROLE_NAMES["core"]
        fixture = model_library(core, interpreter=F.CORE_INTERPRETER)
        with self.assertRaisesRegex(ValueError, "exact inherited QtCore"):
            F.verify_library(core, fixture)
        with self.assertRaisesRegex(ValueError, "exact inherited QtCore"):
            F.verify_library(self.name, model_library(self.name, interpreter=F.CORE_INTERPRETER))
        with patch.dict(MODULE, INHERITED=F.INHERITED | {"core": F.pin(fixture)}):
            F.verify_library(core, fixture)
        wrong = model_library(core, interpreter=b"/lib/foreign.so" + bytes(1))
        with patch.dict(MODULE, INHERITED=F.INHERITED | {"core": F.pin(wrong)}):
            with self.assertRaisesRegex(ValueError, "interpreter must be exact"):
                F.verify_library(core, wrong)
        wrong = self.replace(fixture, "<Q", 24, LOAD_ADDRESS + len(fixture))
        with patch.dict(MODULE, INHERITED=F.INHERITED | {"core": F.pin(wrong)}):
            with self.assertRaisesRegex(ValueError, "file-backed load"):
                F.verify_library(core, wrong)


class Worker(unittest.TestCase):
    def test_refusal_before_build_retains_fixed_failure_result(self):
        with TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            selected = plan()
            g = SimpleNamespace(check_inputs=Mock(side_effect=ValueError("hidden host text")), capture=Mock(),
                                put_json=lambda path, value: path.write_bytes(F.wire_evidence(value)))
            self.assertEqual(F.build(g, selected, "0" * 64, evidence, 1), "HOLD")
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
                                file_data=Mock(return_value=(None, None, b"model log")),
                                command_body=Mock(), capture=capture, require_success=Mock(),
                                put=lambda path, _: calls.append(path.name),
                                put_json=lambda path, value: path.write_bytes(F.wire_evidence(value)))
            with patch.dict(MODULE, inherited_state=Mock(return_value=None), inventory=record, dry_run=record,
                            free_space=Mock(return_value=3 * F.GIB), retain_outputs=Mock(return_value={}),
                            ninja_log_delta=Mock(return_value={}), require_build_window=Mock()):
                self.assertEqual(F.build(g, selected, "0" * 64, evidence, 1000), "PASS")
            self.assertEqual(calls, ["inventory.before", "gui-dry-run.log", "all-dry-run.log", "build.log",
                                     "ninja-log.after", "all-dry-run.after.log", "inventory.after"])
            self.assertEqual(F.evidence_json((evidence / "metrics.json").read_bytes()), evidence_metrics())

    def test_guest_deadline_gates_compile_after_preflight(self):
        with TemporaryDirectory() as temporary:
            evidence = Path(temporary)
            selected = plan()
            g = SimpleNamespace(BUILD=evidence, TARGET="model-gui", check_inputs=Mock(), file_data=Mock(),
                                command_body=Mock(), capture=Mock(),
                                put_json=lambda path, value: path.write_bytes(F.wire_evidence(value)))
            with patch.dict(MODULE, inherited_state=Mock(return_value=None), inventory=Mock(), dry_run=Mock(),
                            free_space=Mock(return_value=3 * F.GIB)), patch.object(F.time, "clock_gettime", return_value=812):
                cutoff = 812 + selected["limits"]["guest_build_seconds"] + F.POST_BUILD_RESERVE_SECONDS
                F.require_build_window(cutoff + 1, selected["limits"]["guest_build_seconds"])
                self.assertEqual(F.build(g, selected, "0" * 64, evidence, cutoff), "HOLD")
                self.assertEqual(F.evidence_json((evidence / "result.json").read_bytes())["phase"], "build")
                g.capture.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
