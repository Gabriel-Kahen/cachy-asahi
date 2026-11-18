# SPDX-License-Identifier: MIT
"""Capsule wiring and filesystem controls using fresh inert model images."""

import hashlib
from pathlib import Path
from runpy import run_path
import struct
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
P = SimpleNamespace(**run_path(str(HERE / "prepare.py")))
C, K = P.C, P.K


def no_actor(event, args):
    if event.startswith(("socket.", "os.exec", "os.posix_spawn", "os.system")):
        raise AssertionError("Network or actor operation in capsule model: " + event)
    if event == "subprocess.Popen":
        path = Path(args[0])
        if path not in {Path("/usr/bin") / name for name in ("debugfs", "mke2fs", "e2fsck")}:
            raise AssertionError("No actor or runtime command in capsule model: " + str(path))


sys.addaudithook(no_actor)


def fs_profile():
    return {name: dict(path=str(path), **C.pin(path.read_bytes()))
            for name in P.FORMAT_TOOLS if (path := Path("/usr/bin") / name).is_file()}


class CapsuleTests(unittest.TestCase):
    def test_descriptor_requires_independent_input_digests(self):
        with TemporaryDirectory(dir=HERE, prefix="qtgui-model-") as tmp:
            model = Path(tmp)
            basis = model / "continuation"
            runner = model / "runner"
            basis.write_bytes(b"unaccepted fixture")
            runner.write_bytes(b"synthetic runner")
            refs = {name: dict(path=str(path), sha256=C.pin(path.read_bytes())["sha256"])
                    for name, path in (("continuation", basis), ("runner", runner))}
            body = C.wire(dict(kind="QTGUI_LINK_CAPSULE_DESCRIPTOR_V1", prepare_tools={}, **refs))
            descriptor = model / "descriptor"
            descriptor.write_bytes(body)
            _, inputs = P.descriptor(descriptor, C.pin(body)["sha256"])
            self.assertEqual(set(inputs), {"descriptor", "runner", "continuation"})
            runner.write_bytes(b"altered")
            with self.assertRaisesRegex(ValueError, "External digest differs"):
                P.descriptor(descriptor, C.pin(body)["sha256"])

    def test_changed_or_symlinked_importer_is_refused_before_staging(self):
        with TemporaryDirectory(dir=HERE, prefix="qtgui-model-") as tmp:
            model = Path(tmp)
            source = model / "source"
            source.mkdir()
            checkout = model / "checkout"
            (checkout / P.PORTABLE).mkdir(parents=True)
            for name in P.PORTABLE_PINS:
                (checkout / name).write_bytes((P.REPO / name).read_bytes())
            with patch.dict(P.stage_source.__globals__, REPO=checkout):
                for name in P.PORTABLE_PINS:
                    with self.subTest(name=name):
                        path = checkout / name
                        body = path.read_bytes()
                        path.write_bytes(bytes([body[0] ^ 1]) + body[1:])
                        with self.assertRaisesRegex(ValueError, "Exact original file pin required"):
                            P.stage_source(source)
                        self.assertEqual(list(source.iterdir()), [])
                        path.write_bytes(body)
                target = Path(P.PORTABLE) / "guest.sh"
                path = checkout / target
                path.unlink()
                path.symlink_to(P.REPO / target)
                with self.assertRaisesRegex(ValueError, "Canonical read-only path required"):
                    P.stage_source(source)
                self.assertEqual(list(source.iterdir()), [])

    def test_new_private_model_boot_result_and_exact_sealed_site(self):
        with TemporaryDirectory(dir=HERE, prefix="qtgui-model-") as tmp:
            model = Path(tmp)
            source = model / "source"
            source.mkdir()
            q = P.stage_source(source)
            tools = P.Formatting(q, fs_profile())
            size = 64 * K.MIB
            nonce = "b" * 32
            limits = dict(guest_build_seconds=900, build_log_bytes=4 * K.MIB, artifact_bytes=32 * K.MIB,
                          qemu_seconds=1200, overlay_file_bytes=2 * K.GIB, result_disk_bytes=size,
                          report_allocation_bytes=32 * K.MIB, host_disk_reserve_bytes=2 * K.GIB,
                          guest_memory_bytes=3 * K.GIB, actor_memory_bytes=5 * K.GIB)
            core_pin = C.pin(b"synthetic Core")
            guest = K.wire_guest(dict(kind="QTGUI_LINK_GUEST_PLAN_V1", authority=None, nonce=nonce, core=core_pin,
                                limits={key: limits[key] for key in K.GUEST_KEYS}, target=K.TARGET))
            backing = dict(nonce=nonce, limits=limits, core_readback=C.pin(b"model evidence"), core_elf=core_pin,
                           overlay_create=["/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
                                           K.CORE_OVERLAY, K.TOP_OVERLAY])
            pin = dict(bytes=262144, sha256="a" * 64)
            carriers = {"boot.raw": pin | {"bytes": q.BOOT_BYTES}, "core.qcow2": pin,
                        "scratch.raw": K.CORE_SCRATCH, "Image": q.CORE_KERNEL,
                        "result.raw": pin | {"bytes": size}}
            runner = dict(kind="ROOT_QTGUI_LINK_RUNNER_PROFILE_V1", actor_image=q.IMAGE, vcpus=4,
                          tools={name: pin for name in q.P.TOOL_NAMES | {"/usr/bin/qemu-img"}},
                          docker=dict(path="/usr/bin/unused-fixture", endpoint="unix:///run/user/1000/docker.sock", **pin))
            plan, payload = q.canonical_plan(nonce, carriers, guest, backing, runner)
            self.assertEqual(plan["attach_seconds"], 1500)
            self.assertEqual(plan["qemu_argv"][plan["qemu_argv"].index("-m") + 1], "3072")
            self.assertEqual(plan["actor"]["overlay_create"][-2:], [K.CORE_OVERLAY, K.TOP_OVERLAY])
            self.assertIn("cachy_qt_gui_result_bytes=67108864", " ".join(plan["qemu_argv"]))
            self.assertEqual(q.P.sha(payload["MANIFEST.sha256"]), plan["guest_payload"]["MANIFEST.sha256"])

            result = model / "model-result.raw"
            P.make_result(q, tools, result, size, nonce)
            self.assertEqual(q.result_uuid(result, size), q.P.result_uuid(nonce))
            boot = model / "model-boot.raw"
            offset = q.P.OFFSET
            with boot.open("xb") as stream:
                stream.truncate(offset + size)
                mbr = bytearray(512)
                mbr[450] = 0x83
                mbr[510:] = b"\x55\xaa"
                struct.pack_into("<II", mbr, 454, offset // 512, size // 512)
                stream.write(mbr)
            q.P.clone(result, boot, count=size, destination=offset, existing=True)
            P.patch_boot(q, tools, boot, nonce, payload, size=offset + size)
            self.assertEqual(boot.read_bytes()[440:444], struct.pack("<I", int(nonce[:8], 16)))

            refs = {name: dict(path=str(model / name), **C.pin(name.encode()))
                    for name in ("descriptor", "runner", "continuation")}
            closes = {name: dict(path=str(model / name), **C.pin(name.encode())) for name in ("q3", "r4", "core")}
            handoff, handoff_pin, plan2 = P.seal(q, model, refs, closes, backing, guest, carriers, runner)
            self.assertEqual(plan, plan2)
            parsed = q.load_handoff(model / q.HANDOFF_LEAF, handoff_pin["sha256"])
            q.verify_source(parsed, source)
            q.verify_binding(parsed, plan)
            changed = plan | {"qemu_argv": plan["qemu_argv"] + ["-net", "user"]}
            with self.assertRaisesRegex(ValueError, "Plan differs"):
                q.verify_binding(parsed, changed)
            self.assertIsNone(handoff["authority"])
            self.assertFalse((model / "root-run.claim").exists())
            sys.path.insert(0, str(source / q.LANE))
            reader = run_path(str(source / q.LANE / "read_capsule.py"))
            with result.open("rb") as stream:
                result_pin = dict(bytes=size, sha256=hashlib.file_digest(stream, "sha256").hexdigest())
            self.assertEqual(reader["raw_files"](result, result_pin, plan["result_uuid"], {"result.json": 4096}, False), {})
            marker = model / "synthetic-result.json"
            marker.write_bytes(b"model result\n")
            changes = model / "model.debugfs"
            changes.write_text("mkdir /evidence\nset_inode_field /evidence mode 040700\n"
                               f"write {marker} /evidence/result.json\n"
                               "set_inode_field /evidence/result.json mode 0100600\n")
            tools.run("debugfs", ["-w", "-f", changes, result], model)
            tools.run("e2fsck", ["-fn", result], model)
            with result.open("rb") as stream:
                result_pin = dict(bytes=size, sha256=hashlib.file_digest(stream, "sha256").hexdigest())
            actual = reader["raw_files"](result, result_pin, plan["result_uuid"], {"result.json": 4096}, True)
            self.assertEqual(actual, {"result.json": b"model result\n"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
