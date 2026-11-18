# SPDX-License-Identifier: MIT
"""Inert controls for the QtGui prerequisite, graph and backing-chain checks."""

from pathlib import Path
from runpy import run_path
import struct
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
K = SimpleNamespace(**run_path(str(HERE / "continuation.py")))
I = SimpleNamespace(**run_path(str(HERE / "inspect_checkpoint.py")))


def fence(event, _args):
    if event.startswith(("subprocess.", "socket.", "os.exec", "os.posix_spawn", "os.system")):
        raise AssertionError("Passive QtGui control attempted execution: " + event)


sys.addaudithook(fence)


def header(parent, form):
    data = bytearray(65536)
    pos = 112
    format_bytes = form.encode("ascii")
    struct.pack_into(">II", data, pos, 0xE2792ACA, len(format_bytes))
    data[pos + 8:pos + 8 + len(format_bytes)] = format_bytes
    backing_offset = pos + 24  # eight header, eight padded bytes, eight terminator
    parent = parent.encode("ascii")
    data[backing_offset:backing_offset + len(parent)] = parent
    struct.pack_into(">4sIQIIQIIQQIIQ", data, 0, b"QFI\xfb", 3, backing_offset, len(parent), 16, 16 * K.GIB,
                     0, 32, 196608, 65536, 1, 0, 0)
    struct.pack_into(">QQQII", data, 72, 0, 0, 0, 4, 112)
    return data


class ContinuationTests(unittest.TestCase):
    def test_clean_base_and_child_have_different_required_backing(self):
        for backing, form in ((K.RAW_BACKING, "raw"), (K.CORE_OVERLAY, "qcow2")):
            data = header(backing, form)
            K.qcow_backing(data, 196864, backing, form)
            with self.assertRaisesRegex(ValueError, "backing format"):
                K.qcow_backing(data, 196864, backing, "qcow2" if form == "raw" else "raw")
            with self.assertRaisesRegex(ValueError, "immutable backing path"):
                K.qcow_backing(data, 196864, "/other/image", form)

    def test_dirty_or_external_qcow2_data_flags_refused(self):
        for flag in (1, 2, 4):
            data = header(K.RAW_BACKING, "raw")
            struct.pack_into(">Q", data, 72, flag)
            with self.assertRaisesRegex(ValueError, "clean standard QCOW2"):
                K.qcow_backing(data, 196864, K.RAW_BACKING, "raw")
        data = header(K.RAW_BACKING, "raw")
        struct.pack_into(">I", data, 112, 0x44415441)
        with self.assertRaisesRegex(ValueError, "additional external data"):
            K.qcow_backing(data, 196864, K.RAW_BACKING, "raw")

    def test_held_core_cannot_select_limits_or_open_backing(self):
        with TemporaryDirectory() as tmp:
            folder = Path(tmp)
            p = folder / "independent.json"
            raw = K.C.wire(dict(kind="QTCORE_LINK_INDEPENDENT_READBACK_V1", status="HOLD", phase="boot"))
            p.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "completed and independently verified QtCore"):
                K.closed_core(dict(handoff=dict(path=str(folder / "HANDOFF.UNISSUED.json"), sha256="b" * 64),
                                   post_scope=dict(path=str(folder / "closure"), sha256="c" * 64),
                                   independent=dict(path=str(p), sha256=K.C.pin(raw)["sha256"]),
                                   output=str(folder / "issued.model/output")))

    def test_budget_requires_completed_measured_exact_basis_and_headroom(self):
        caps = dict(guest_build_seconds=6900, build_log_bytes=8 * K.MIB, artifact_bytes=80 * K.MIB,
                    qemu_seconds=7200, overlay_file_bytes=4 * K.GIB, result_disk_bytes=128 * K.MIB,
                    report_allocation_bytes=32 * K.MIB, host_disk_reserve_bytes=2 * K.GIB,
                    guest_memory_bytes=4 * K.GIB, actor_memory_bytes=6 * K.GIB)
        basis = "d" * 64
        selection = dict(budget_basis_sha256=basis, limits=caps)
        actual = dict(status="PASS_EXACT_QTCORE_LINK_ONLY", metrics=dict(elapsed_ms=1234),
                      post_scope=dict(exit_code=0))
        self.assertEqual(K.limit_profile(selection, basis, actual), caps)
        for candidate in (actual | {"metrics": {"elapsed_ms": 0}}, actual | {"post_scope": {"exit_code": 2}}):
            with self.assertRaisesRegex(ValueError, "exact measured completed Core"):
                K.limit_profile(selection, basis, candidate)
        with self.assertRaisesRegex(ValueError, "exact measured completed Core"):
            K.limit_profile(selection, "f" * 64, actual)
        with self.assertRaisesRegex(ValueError, "headroom"):
            K.limit_profile(selection | {"limits": caps | {"result_disk_bytes": 64 * K.MIB}}, basis, actual)

    def test_graph_delta_counts_duplicate_commands_and_rejects_non_subset(self):
        self.assertEqual(I.difference(b"shared\n", b"shared\nshared\nnew\n"), [b"shared\n", b"new\n"])
        with self.assertRaisesRegex(ValueError, "must be contained"):
            I.difference(b"other\n", b"shared\nnew\n")

    def test_preparation_refuses_unissued_predecessor_selection_before_replay(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "selection"
            body = K.C.wire(dict(kind=K.SELECTION_KIND, issuer="Root", approved=None, core={},
                                 limits={}, budget_basis_sha256="a" * 64))
            path.write_bytes(body)
            with patch.dict(K.prepare.__globals__, {"closed_core": lambda _: self.fail("Unissued input reached Core")}):
                with self.assertRaisesRegex(ValueError, "separately selected accepted Core"):
                    K.prepare(path, K.C.pin(body)["sha256"])

    def test_guest_evidence_joins_runtime_md4c_and_exact_accepted_core(self):
        model = SimpleNamespace(**run_path(str(HERE / "test_elf_readback.py")))
        core = model.fixture("core", reloc=None)
        gui = model.fixture("gui", model.REQUIRED)
        dbus = model.fixture("dbus", ["libQt6Core.so.6"], reloc=None)
        md4c = model.fixture("md4c", symbol_section=3, reloc=None)
        inventory, inherited, successor = b"fixture\n", b"core\n", b"core\nlink-gui\n"
        graph = {
            "inventory.before": inventory, "inventory.after": inventory, "core.commands": inherited,
            "gui.commands": successor, "gui.link-command": b"link-gui\n",
            "core-dry-run.log": b"ninja: no work to do.\n", "gui-dry-run.log": b"[1/1] link-gui\n",
            "build.log": b"link-gui\n", "aliases.txt": I.ALIASES,
        }
        metrics = dict(exit_code=0, elapsed_ms=1234, peak_child_rss_kib=400,
                       log_complete=True, natural=True, group_empty=True, timeout=False, overflow=False, dry_run_steps=1)
        pin = K.C.pin
        nonce = "a" * 32
        plan = K.wire_guest(dict(kind="QTGUI_LINK_GUEST_PLAN_V1", authority=None, nonce=nonce, core=pin(core),
                                 target=K.TARGET, limits=dict(guest_build_seconds=30, build_log_bytes=1024,
                                                               artifact_bytes=K.MIB)))
        outcome = K.C.wire(dict(kind="QTGUI_LINK_GUEST_RESULT_V1", status="PASS", phase="complete",
                                plan_sha256=pin(plan)["sha256"], nonce=nonce, core=pin(core), target=K.TARGET))
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            (root / "plan").write_bytes(plan)
            accepted = root / K.CORE_ELF
            accepted.write_bytes(core)
            files = graph | dict(zip(I.DSOS, (gui, dbus, md4c), strict=True)) | {
                "metrics.json": K.C.wire(metrics), "result.json": outcome,
            }
            for name, body in files.items():
                (evidence / name).write_bytes(body)
            with patch.multiple(I.G, INVENTORY=K.F.pin(inventory), CORE_COMMANDS=K.F.pin(inherited),
                                GUI_COMMANDS=K.F.pin(successor), GUI_LINK=K.F.pin(b"link-gui\n")), \
                 patch.dict(I.ELF.verify_link.__globals__, {"MD4C_PIN": pin(md4c)}):
                actual = I.guest_result(evidence, root / "plan", pin(plan)["sha256"], pin(outcome)["sha256"], accepted)
                self.assertTrue(actual["linkage"]["md_parse"]["provider_export"])
                self.assertIsNone(actual["Root_acceptance"])
                accepted.write_bytes(core + b"changed")
                with self.assertRaisesRegex(ValueError, "Exact original file pin"):
                    I.guest_result(evidence, root / "plan", pin(plan)["sha256"], pin(outcome)["sha256"], accepted)


if __name__ == "__main__":
    unittest.main(verbosity=2)
