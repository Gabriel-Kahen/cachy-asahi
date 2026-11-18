# SPDX-License-Identifier: MIT
"""Passive controls for the independent compile reader."""

import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from uuid import UUID
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import readback as R

NONCE = "a" * 32
TEMPLATE_UUID = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"


def empty_ext4(path):
    """A sparse structural model with root and lost+found for the raw reader."""
    block = 4096
    sb = bytearray(1024)
    for offset, value in ((0, 32), (4, R.RESULT_BYTES // block), (24, 2), (32, R.RESULT_BYTES // block),
                          (40, 32), (96, 0x40)):
        struct.pack_into("<I", sb, offset, value)
    struct.pack_into("<HH", sb, 56, 0xEF53, 1)
    struct.pack_into("<H", sb, 88, 128)
    sb[104:120] = UUID(TEMPLATE_UUID).bytes
    sb[120:136] = b"QT16K_MD4C".ljust(16, b"\0")
    with path.open("xb") as stream:
        stream.truncate(R.RESULT_BYTES)
        stream.seek(1024)
        stream.write(sb)
        stream.seek(block + 8)
        stream.write(struct.pack("<I", 2))
        for number, mode, links, physical, children in (
            (2, 0o40755, 3, 4, ((2, b"."), (2, b".."), (3, b"lost+found"))),
            (3, 0o40700, 2, 5, ((3, b"."), (2, b".."))),
        ):
            node = bytearray(128)
            struct.pack_into("<H", node, 0, mode)
            struct.pack_into("<I", node, 4, block)
            struct.pack_into("<H", node, 26, links)
            struct.pack_into("<I", node, 32, 0x80000)
            struct.pack_into("<HHHHI", node, 40, 0xF30A, 1, 4, 0, 0)
            struct.pack_into("<IHHI", node, 52, 0, 1, 0, physical)
            stream.seek(2 * block + (number - 1) * len(node))
            stream.write(node)
            data = bytearray(block)
            offset = 0
            for index, (inode, name) in enumerate(children):
                length = block - offset if index == len(children) - 1 else (len(name) + 11) // 4 * 4
                struct.pack_into("<IHBB", data, offset, inode, length, len(name), 2)
                data[offset + 8:offset + 8 + len(name)] = name
                offset += length
            stream.seek(physical * block)
            stream.write(data)


def overlay_model(eof):
    work = 16 << 30
    backing = "/inputs/scratch.raw"
    nodes = []
    for kind, path, size, allocated in (
        ("qcow2", "/out/overlay.qcow2", (eof + 511) // 512 * 512, 4096), ("raw", backing, work, 8192),
    ):
        file = {"filename": path, "format": "file", "actual-size": allocated, "virtual-size": size,
                "children": [], "dirty-flag": False, "format-specific": {"type": "file", "data": {}}}
        nodes.append({"filename": path, "format": kind, "actual-size": allocated, "virtual-size": work,
                      "children": [{"name": "file", "info": file}], "dirty-flag": False})
    nodes[0].update({"backing-filename": backing, "full-backing-filename": backing,
                     "backing-filename-format": "raw", "cluster-size": 65536,
                     "format-specific": {"type": "qcow2", "data": {"compat": "1.1", "compression-type": "zlib",
                         "lazy-refcounts": False, "refcount-bits": 16, "corrupt": False, "extended-l2": False}}})
    return R.canonical(nodes)


def elf_model(*, machine=183, md_section=0, relocation=283, opcode=0x94000000, offset=0,
              source=R.IMPORTER):
    names = b"\0md_parse\0" + source + b"\0"
    symbols = (bytes(R.ELF_SYMBOL.size) + R.ELF_SYMBOL.pack(1, 0x10, 0, md_section, 0, 0) +
               R.ELF_SYMBOL.pack(len(b"\0md_parse\0"), 0x12, 0, 1, 0, 8))
    contents = [bytes(), struct.pack("<II", opcode, 0xD65F03C0), names, symbols,
                R.ELF_RELA.pack(offset, (1 << 32) | relocation, 0), b"\0"]
    chunks = bytearray(R.ELF_HEADER.size)
    sections = [bytes(R.ELF_SECTION.size)]
    options = [(1, 6, 0, 0, 0), (3, 0, 0, 0, 0), (2, 0, 2, 1, 24),
               (4, 0, 3, 1, 24), (3, 0, 0, 0, 0)]
    for data, (kind, flags, link, info, entry) in zip(contents[1:], options):
        chunks.extend(b"\0" * (-len(chunks) % 8))
        sections.append(R.ELF_SECTION.pack(0, kind, flags, 0, len(chunks), len(data), link, info, 8, entry))
        chunks.extend(data)
    chunks.extend(b"\0" * (-len(chunks) % 8))
    shoff = len(chunks)
    chunks.extend(b"".join(sections))
    R.ELF_HEADER.pack_into(chunks, 0, b"\x7fELF\x02\x01\x01".ljust(16, b"\0"), 1, machine, 1,
                           0, 0, shoff, 0, R.ELF_HEADER.size, 0, 0, R.ELF_SECTION.size, len(sections), 5)
    return bytes(chunks)


class ReaderControls(unittest.TestCase):
    def test_binary_proves_qt_importer_and_real_external_md4c_call(self):
        checked = R.verify_object(elf_model())
        self.assertEqual(checked["machine"], "AArch64")
        self.assertEqual(checked["executable_reference_count"], 1)
        self.assertEqual(checked["undefined_symbol"], "md_parse")
        self.assertEqual(checked["defined_importer"], R.IMPORTER.decode())

    def test_binary_rejects_other_machine_and_missing_importer(self):
        for changes in (dict(machine=62), dict(source=b"model_other_function")):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                R.verify_object(elf_model(**changes))
        with self.assertRaisesRegex(ValueError, "section table"):
            R.verify_object(elf_model()[:-1])

    def test_symbol_text_or_noncode_reference_cannot_pass(self):
        for changes in (dict(md_section=1), dict(relocation=257), dict(opcode=0),
                        dict(offset=1), dict(offset=8)):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                R.verify_object(elf_model(**changes))

    def test_terminal_marker_is_unique_original_and_complete(self):
        marker = b"QTMD4C16K " + NONCE.encode()
        self.assertEqual(R.serial_state(b"line\n" + marker + b" PASS complete\r\n", NONCE), (True, "complete"))
        self.assertEqual(R.serial_state(marker + b" HOLD compile\n", NONCE), (False, "compile"))
        self.assertIsNone(R.verify_guest({}, NONCE, False, "boot"))
        for lines in (marker + b" PASS compile\n", b"no terminal\n",
                      marker + b" PASS complete\n" + marker + b" PASS complete\n",
                      b"QTMD4C16K " + b"b" * 32 + b" PASS complete\n"):
            with self.subTest(lines=lines), self.assertRaises(ValueError):
                R.serial_state(lines, NONCE)

    def test_storage_diagnostic_is_bounded_nonce_bound_and_optional(self):
        nonce = NONCE
        original = f"QTMD4C16K {nonce} HOLD storage\r\n".encode()
        self.assertEqual(R.serial_state(original, nonce), (False, "storage"))
        self.assertIsNone(R.serial_storage_reason(original, nonce, "storage"))
        prefix = b"QTMD4C16K_STORAGE " + nonce.encode() + b" "
        for reason in R.STORAGE_REASONS:
            with self.subTest(reason=reason):
                self.assertEqual(R.serial_storage_reason(prefix + reason + b"\r\n", nonce, "storage"),
                                 reason.decode())
        with self.assertRaisesRegex(ValueError, "one diagnostic"):
            R.serial_storage_reason((prefix + b"GEOMETRY\n") * 2, nonce, "storage")
        with self.assertRaisesRegex(ValueError, "one diagnostic"):
            R.serial_storage_reason(prefix + b"GEOMETRY\n", nonce, "compile")
        for marker in (prefix + b"UNRECOGNIZED\n", prefix + b"WRITE_STATE vda\n",
                       b"QTMD4C16K_STORAGE " + b"0" * 32 + b" GEOMETRY\n"):
            with self.subTest(marker=marker), self.assertRaisesRegex(ValueError, "unknown reason or nonce"):
                R.serial_storage_reason(marker, nonce, "storage")

    def test_overlay_validation_is_path_bound_despite_bare_module_shadow(self):
        eof = 196865
        original = overlay_model(eof)
        active = [True]
        sys.addaudithook(lambda event, args: active[0] and R.audit_fence(event, args))
        try:
            with patch.dict(sys.modules, {"prepare": types.ModuleType("prepare")}):
                R.require_initial_overlay(original, eof, {"overlay_logical_bytes": 16 << 30})
                with self.assertRaisesRegex(ValueError, "file backend"):
                    R.require_initial_overlay(original, eof + 512, {"overlay_logical_bytes": 16 << 30})
        finally:
            active[0] = False

    def test_guest_reports_alone_cannot_pass_without_binary(self):
        files = {"result.json": R.wire(dict(status="PASS", nonce=NONCE, phase="complete", page_size=16384)),
                 "compile.log": b"/usr/include/md4c.h: OK\n/usr/lib/libmd4c.so.0.5.3: OK\n"
                                b"/qt-recipe/src/build/build.ninja: OK\n",
                 "importer.elf": b"  Class: ELF64\n  Type: REL (Relocatable file)\n  Machine: AArch64\n",
                 "importer.symbols": b"  7: 0000000000 0 NOTYPE GLOBAL DEFAULT UND md_parse\n",
                 "importer.o": elf_model()}
        self.assertEqual(R.verify_guest(files, NONCE, True, "complete")["type"], "ET_REL")
        files["importer.o"] = elf_model(machine=62)
        with self.assertRaisesRegex(ValueError, "AArch64"):
            R.verify_guest(files, NONCE, True, "complete")

    def test_clean_structural_result_is_passively_readable_and_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            template = Path(temporary) / "result.raw"
            empty_ext4(template)
            expected = R.read(template, R.RESULT_BYTES, collect=False)
            active = [True]
            sys.addaudithook(lambda event, args: active[0] and R.audit_fence(event, args))
            try:
                self.assertEqual(R.result_files(template, expected, TEMPLATE_UUID, False), {})
                with self.assertRaisesRegex(ValueError, "raw result namespace"):
                    R.result_files(template, expected, TEMPLATE_UUID, True)
                with self.assertRaisesRegex(ValueError, "label and UUID"):
                    R.result_files(template, expected, "0" * 36, False)
                for event, args in (("socket.connect", ()), ("subprocess.Popen", ()), ("os.rename", ()),
                                    ("open", ("evidence", "wb", os.O_WRONLY | os.O_TRUNC))):
                    with self.subTest(event=event), self.assertRaises(ValueError):
                        R.audit_fence(event, args)
            finally:
                active[0] = False

    def test_natural_early_failure_retains_bounded_hold_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            disk = b"short refused test"
            (output / "result.raw").write_bytes(disk)
            plan = {"actor": {"child_file_size_cap": 2 << 30}}
            held = R.actor_result(output, {}, plan, {}, 1)
            self.assertEqual(held["status"], "HOLD_NO_COMPLETE_ACTOR_REPORT")
            self.assertEqual(held["evidence"], {"result.raw": R.pin(disk)})
            with self.assertRaisesRegex(ValueError, "requires complete original result"):
                R.actor_result(output, {}, plan, {}, 0)
            (output / "other.raw").write_bytes(b"unowned")
            with self.assertRaisesRegex(ValueError, "Exact bounded"):
                R.actor_result(output, {}, plan, {}, 1)

    def test_owned_command_joins_original_streams_and_rejects_overruns(self):
        label, argv = "qemu", ["/usr/bin/qemu-system-aarch64"]
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            receipt = dict(argv=argv, exit=0, ownership="REAPED", group_census="EMPTY_TWICE", passed=True,
                           reaped=True, output_complete=True, timeout=False, command_timed_out=False,
                           original_budget_overrun=False, emergency_retirement=False,
                           emergency_retirement_cap_seconds=None, command_cancelled=[], signals=[], error=None,
                           operation_seconds=5, operation_cap_seconds=2100, child_file_size_cap=2 << 30)
            receipt_path = work / f"{label}.json"
            receipt_path.write_bytes(R.wire(receipt))
            for suffix, body in (("stdout", b"serial\n"), ("stderr", b"warning\n"), ("log", b"serial\nwarning\n")):
                (work / f"{label}.{suffix}").write_bytes(body)
            _, stdout = R.runtime_receipt(work, label, R.pin(R.wire(receipt)), argv, 2100, 2 << 30)
            self.assertEqual(stdout, b"serial\n")
            receipt["original_budget_overrun"] = True
            receipt_path.write_bytes(R.wire(receipt))
            with self.assertRaisesRegex(ValueError, "natural owned command retirement"):
                R.runtime_receipt(work, label, R.pin(R.wire(receipt)), argv, 2100, 2 << 30)

    def test_capacity_distinguishes_before_admission_and_after_reserve(self):
        reserve, gate = 2 << 30, 4395630592
        policy = dict(admission_disk_bytes=gate, watched_tree=["/out", 2248146944, reserve])
        row = dict(required_bytes=gate, minimum_memory_bytes=6 << 30, minimum_cpus=4, free_bytes=gate,
                   memory_available_bytes=6 << 30, allowed_cpus=4, fits=True)
        R.require_capacity(row, policy, admission=True)
        row.update(free_bytes=reserve, fits=False)
        R.require_capacity(row, policy, admission=False)
        with self.assertRaises(ValueError):
            R.require_capacity(row, policy, admission=True)
        row["free_bytes"] -= 1
        with self.assertRaises(ValueError):
            R.require_capacity(row, policy, admission=False)

    def test_join_rechecks_the_handoff_plan_and_all_selected_predecessors(self):
        with tempfile.TemporaryDirectory() as temporary:
            tree = Path(temporary)
            root = tree / "packet"
            attempt = root / "issued.model"
            template = tree / "operands"
            for folder in (attempt / "output", root / "root-run.claim", template / "inputs", template / "output"):
                folder.mkdir(parents=True)

            def put(path, body):
                path.write_bytes(body)
                return R.pin(body)

            inputs = {name: put(template / (("output" if name == "result.raw" else "inputs") + "/" + name),
                                name.encode()) for name in ("Image", "boot.raw", "scratch.raw", "result.raw")}
            prior = {role: put(attempt / f"prior-{role}-closure.json", role.encode())
                     for role in ("configure", "previous", "external-stage")}
            gate = 4395630592
            plan = dict(nonce=NONCE, inputs=inputs, q3_closure_sha256=prior["configure"]["sha256"],
                        actor=dict(admission_disk_bytes=gate, watched_tree=["/out", 2248146944, 2 << 30],
                                   child_file_size_cap=2 << 30))
            plan_pin = put(template / "PLAN.UNISSUED.json", R.canonical(plan))
            data = dict(scope="model.scope", operand_root=str(template), result_uuid=TEMPLATE_UUID,
                        plan=plan_pin, prior_closures=prior)
            handoff_sha = put(root / "HANDOFF.DATA.json", R.wire(data))["sha256"]
            selection = R.wire(dict(nonce=NONCE))
            authority_sha = put(attempt / "selection.json", selection)["sha256"]
            group, cid = "/unit/model.scope", "c" * 64
            record = dict(authority_sha256=authority_sha, scope=data["scope"], scope_group=group, cid=cid)
            meta = dict(nonce=NONCE, plan_sha256=plan_pin["sha256"])
            put(attempt / "attempt.json", R.wire(meta))
            put(root / "root-run.claim/attempt.path", (str(attempt) + "\n").encode())
            put(attempt / "run.cid", cid.encode())
            put(attempt / "scope.path", (group + "\n").encode())
            cap = dict(required_bytes=gate, minimum_memory_bytes=6 << 30, minimum_cpus=4, free_bytes=gate,
                       memory_available_bytes=6 << 30, allowed_cpus=4, fits=True)
            put(attempt / "capacity.json", R.wire(cap))
            host = dict(kind="QT_MD4C_HOST_RETIREMENT_V1", nonce=NONCE, natural=True, exit_code=1,
                        container_removed=True, absent_twice=True, **record)
            put(attempt / "host-result.json", R.wire(host))
            for name, body in (("state", b"exited 1 false\n"), ("attach-exit", b"1\n"), ("stdout", b""),
                               ("stderr", b""), ("absence-1", b""), ("absence-2", b"")):
                put(attempt / ("run." + name), body)
            for phase in ("created", "exited"):
                put(attempt / f"run.{phase}.inspect.json", R.wire([{"phase": phase}]))
            put(attempt / "output/result.raw", b"partial result")
            closure = tree / "closure.json"
            closure_sha = put(closure, R.wire(dict(kind="QT_MD4C_POST_SCOPE_READBACK_V1",
                                                   observations=[R.EMPTY, R.EMPTY], **record)))["sha256"]
            entry = types.SimpleNamespace(load_handoff=Mock(return_value=(root, data, plan)),
                                          verify_selection=Mock(return_value={"nonce": NONCE}),
                                          attempt_meta=Mock(return_value=meta), matching_inspects=Mock())
            args = (attempt, handoff_sha, authority_sha, closure, closure_sha)
            with patch.object(sys, "addaudithook") as fence:
                outcome = R.result(*args, entry=entry)
                fence.assert_called_once_with(R.audit_fence)
                self.assertEqual(outcome["host"]["predecessor_closures"], prior)
                self.assertEqual(outcome["original_inputs"], inputs)
                self.assertEqual(outcome["status"], "HOLD_NO_COMPLETE_ACTOR_REPORT")
                entry.verify_selection.assert_called_once_with(selection, authority_sha, data, plan, handoff_sha,
                                                               live=False)
                entry.matching_inspects.assert_called_once_with({"phase": "created"}, {"phase": "exited"},
                                                                attempt, meta, cid, 1, data)
                put(attempt / "prior-external-stage-closure.json", b"changed report")
                with self.assertRaisesRegex(ValueError, "Evidence pin differs"):
                    R.result(*args, entry=entry)
                entry.load_handoff.return_value = (root, data, dict(plan, nonce="b" * 32))
                with self.assertRaisesRegex(ValueError, "exact sealed operand plan"):
                    R.result(*args, entry=entry)
                entry.load_handoff.return_value = (root, dict(data, prior_closures={}), plan)
                with self.assertRaisesRegex(ValueError, "exact sealed compile packet"):
                    R.result(*args, entry=entry)


if __name__ == "__main__":
    unittest.main()
