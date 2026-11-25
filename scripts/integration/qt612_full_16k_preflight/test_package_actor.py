# SPDX-License-Identifier: MIT
"""Check the package actor and media contracts using inert disk and process fixtures."""

from copy import deepcopy
import json
from pathlib import Path
from runpy import run_path
import struct
import subprocess
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch


HERE = Path(__file__).resolve().parent
A = SimpleNamespace(**run_path(str(HERE / "package_actor.py")))
M, E, C, F, P = A.M, A.E, A.C, A.F, A.P
GIB = 1 << 30
NONCE = "a" * 32
SHA = "b" * 64


def chain_fixture():
    paths = E.CHAIN
    eof = (196696, 838860800, 750845952, 267386880, 16 << 30)
    sizes = {Path(path).name: size for path, size in zip(paths, eof, strict=True)}
    nodes = []
    for i, (path, size) in enumerate(zip(paths, eof, strict=True)):
        allocate = 65536
        file_node = dict(filename=path, format="file", children=[], **{"actual-size": allocate,
                         "virtual-size": (size + 511) // 512 * 512, "dirty-flag": False,
                         "format-specific": {"type": "file", "data": {}}})
        node = dict(filename=path, format="qcow2" if i < 4 else "raw", children=[dict(name="file", info=file_node)],
                    **{"actual-size": allocate, "virtual-size": 16 << 30, "dirty-flag": False})
        if i < 4:
            node.update({"backing-filename": paths[i + 1], "full-backing-filename": paths[i + 1],
                         "backing-filename-format": ("raw" if i == 3 else "qcow2"), "cluster-size": 65536,
                         "format-specific": {"type": "qcow2", "data": {"compat": "1.1",
                            "compression-type": "zlib", "lazy-refcounts": False, "refcount-bits": 16,
                            "corrupt": False, "extended-l2": False}}})
        nodes.append(node)
    return nodes, sizes


def role_fixture():
    inputs = F.LOWER | {"complete.qcow2": C.file_pin(838860800, SHA)}
    return dict(nonce=NONCE, scope=M.W.SCOPE, readonly_media={name: pin | {"path": "/fixture/" + name}
                for name, pin in inputs.items()}, overlay_create=["create"], overlay_inspect=["inspect"],
                qemu_argv=["fake-qemu"], result_fsck=["fsck"], serial={"maximum": 1 << 20},
                result_carrier={"bytes": E.RESULT_BYTES, "uuid": P.result_uuid(NONCE), "path": "/out/result.raw"},
                runtime={"actor_memory_bytes": 8 << 30, "child_file_size_cap": 4 << 30},
                times={"attach": 3900, "qemu": 3600})


class Chain(unittest.TestCase):
    def test_exact_five_nodes_require_complete_between_package_and_gui(self):
        nodes, sizes = chain_fixture()
        A.validate_chain(json.dumps(nodes).encode(), sizes)
        for index, field, value in ((0, "full-backing-filename", "/inputs/gui.qcow2"),
                                    (1, "filename", "/inputs/archive.qcow2"),
                                    (2, "backing-filename-format", "raw"),
                                    (3, "dirty-flag", True),
                                    (4, "virtual-size", 64 << 30),
                                    (4, "actual-size", 65535)):
            changed = deepcopy(nodes)
            changed[index][field] = value
            with self.subTest(index=index, field=field), self.assertRaises(ValueError):
                A.validate_chain(json.dumps(changed).encode(), sizes)
        with self.assertRaises(ValueError):
            A.validate_chain(json.dumps(nodes[1:]).encode(), sizes)
        with self.assertRaises(ValueError):
            A.validate_chain(json.dumps(nodes).encode(), sizes | {"overlay.qcow2": 2 << 20})
        duplicated = json.dumps(nodes).replace('"dirty-flag": false', '"dirty-flag": false, "dirty-flag": false', 1)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            A.validate_chain(duplicated.encode(), sizes)

    def test_profile_preserves_exact_caps_and_pinned_tools(self):
        role = role_fixture()
        run = dict(actor_image=P.QEMU_ACTOR_IMAGE, tools={name: C.file_pin(2, SHA)
                   for name in P.TOOL_NAMES | {"/usr/bin/qemu-img"}})
        media = dict(boot=C.file_pin(F.Q.BOOT_BYTES, SHA), result=C.file_pin(E.RESULT_BYTES, SHA), runner=run)
        plan = A.runner_plan(role, media)
        policy = plan["actor"]
        self.assertEqual(policy["profile"]["tools"], run["tools"])
        self.assertEqual(policy["result_disk_bytes"], GIB)
        self.assertEqual(policy["child_file_size_cap"], 4 * GIB)
        self.assertEqual(policy["serial_combined_cap"], 1 << 20)
        self.assertEqual(policy["watched_paths"], [["/out/overlay.qcow2", 4 * GIB], ["/out/result.raw", GIB]])
        self.assertEqual(policy["admission_disk_bytes"], 7 * GIB + (128 << 20))
        self.assertEqual(policy["watched_tree"][2], 2 * GIB)


class Actor(unittest.TestCase):
    def test_actor_requires_natural_fsck_and_changed_private_result(self):
        role = role_fixture()
        nodes, sizes = chain_fixture()
        template, emitted = b"empty result", b"completed result"
        media = dict(plan=C.pin(b"original stage"), result=C.pin(template), source={"pinned": True})
        with TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            result = root / "result.raw"
            result.write_bytes(template)
            result.chmod(0o600)
            policy = dict(admission_disk_bytes=1, watched_tree=["/out", 2, 1], watched_paths=[],
                          child_file_size_cap=4 * GIB, result_disk_bytes=128, serial_combined_cap=E.SERIAL_CAP)
            capacity = dict(fits=True, free_bytes=100)
            record = Mock(return_value={"free": 100})
            watch = SimpleNamespace(record=record, peak={"free": 100}, samples=1)
            runner = SimpleNamespace(actor=policy, plan=dict(inputs={k: C.file_pin(v, SHA) for k, v in sizes.items()},
                                     limits={"actor_memory_bytes": 8 << 30}), runtime=SimpleNamespace(GUARD=None),
                                     deadline=time.monotonic() + 3900, authority_sha=SHA, handoff_sha="c" * 64,
                                     issued={"expires_utc": time.time() + 60}, tools={"mock": True},
                                     verify_tools=Mock())

            def phase(name, _argv, _timeout, **kwargs):
                if name == "overlay-create":
                    (root / "overlay.qcow2").write_bytes(b"x" * sizes["overlay.qcow2"])
                if name == "overlay-inspect":
                    (root / "overlay-inspect.stdout").write_bytes(json.dumps(nodes).encode())
                if name == "qemu":
                    with (root / "overlay.qcow2").open("ab") as image:
                        image.write(b"mock")
                    result.write_bytes(emitted)
                    (root / "qemu.stdout").write_bytes(E.TERMINAL + b" " + NONCE.encode() + b" PASS complete\n")
                return C.pin(name.encode())

            runner.phase = Mock(side_effect=phase)
            with (patch.dict(A.run.__globals__, OUT=root, require_absence=Mock()), patch.object(A.B, "AllocationWatch", return_value=watch),
                  patch.object(F.K, "inspect_overlay"), patch.object(F, "capacity", return_value=capacity),
                  patch.object(A.A, "cgroup_peak", return_value=1), patch.object(M, "source_records", return_value=media["source"]),
                  patch.object(M, "verify_inputs"), patch.object(M, "verify_result") as result_verify):
                self.assertEqual(A.run(role, media, runner), 0)
            report = C.json_body((root / A.RESULT_REPORT).read_bytes(), canonical=True)
            self.assertEqual(report["kind"], A.RESULT_KIND)
            self.assertEqual(report["status"], A.PASS)
            self.assertEqual(report["fsck_result"], C.pin(b"fsck-result"))
            self.assertEqual(report["result_disk"], C.pin(emitted))
            self.assertEqual(report["signing"], "NOT_RUN")
            self.assertEqual(runner.phase.call_args_list, [
                call("overlay-create", ["create"], 10), call("overlay-inspect", ["inspect"], 10),
                call("qemu", ["fake-qemu"], 3600, file_cap=4 * GIB), call("fsck-result", ["fsck"], 60)])
            self.assertEqual(result_verify.call_args_list, [call(result, role["result_carrier"]["uuid"], empty=True),
                                                              call(result, role["result_carrier"]["uuid"])])
            self.assertIsNone(runner.runtime.GUARD)
            self.assertGreaterEqual(record.call_count, 3)


FORMAT_TOOLS = ("debugfs", "e2fsck", "mke2fs")


@unittest.skipUnless(all(Path("/usr/bin", name).is_file() for name in FORMAT_TOOLS), "Ext4 fixture tools unavailable")
class InertMedia(unittest.TestCase):
    @staticmethod
    def run_tool(name, args, cwd):
        subprocess.run(["/usr/bin/" + name, *args], cwd=cwd, stdin=subprocess.DEVNULL,
                       capture_output=True, check=True, timeout=10)

    @staticmethod
    def fixture_clone(source, dest, *, start=0, count=0, destination=0, existing=False):
        with source.open("rb") as src, dest.open("r+b" if existing else "xb") as dst:
            src.seek(start)
            dst.seek(destination)
            dst.write(src.read(count))

    def test_nested_boot_and_result_are_exact_and_independently_readable(self):
        size = 8 << 20
        with (TemporaryDirectory() as temp, patch.object(F.Q, "BOOT_BYTES", P.OFFSET + size),
              patch.object(E, "RESULT_BYTES", size), patch.object(P, "clone", side_effect=self.fixture_clone)):
            root = Path(temp)
            tool = SimpleNamespace(run=self.run_tool)
            original = root / "start.ext4"
            with original.open("xb") as stream:
                stream.truncate(size)
            tool.run("mke2fs", ["-q", "-F", "-t", "ext4", "-b", "4096", "-O", "^orphan_file", original], root)
            boot = root / "boot.raw"
            mbr = bytearray(P.OFFSET)
            mbr[450] = 0x83
            struct.pack_into("<II", mbr, 454, P.OFFSET // 512, size // 512)
            mbr[510:512] = b"\x55\xaa"
            boot.write_bytes(mbr + original.read_bytes())
            bundle = {"guest-init.sh": b"pid 1", "packaging/package_guest.py": b"worker",
                      "packaging/recipe/.SRCINFO": b"fixture"}
            role = dict(nonce=NONCE, boot_directory=E.BOOT_DIR, boot_subdirectories=["packaging", "packaging/recipe"],
                        boot_payload={name: C.pin(body) | {"mode": 0o555 if name == "guest-init.sh" else 0o444}
                                      for name, body in bundle.items()},
                        result_carrier={"uuid": P.result_uuid(NONCE)})
            M.patch_boot(boot, tool, role, bundle)
            self.assertEqual(boot.stat().st_mode & 0o777, 0o444)
            wrong = deepcopy(role)
            wrong["boot_payload"]["packaging/recipe/.SRCINFO"]["sha256"] = SHA
            with self.assertRaisesRegex(ValueError, "boot file"):
                M.verify_boot(boot, wrong)
            result = root / "result.raw"
            M.format_result(result, tool, role)
            self.assertEqual(result.stat().st_mode & 0o777, 0o444)
            with self.assertRaisesRegex(ValueError, "result volume"):
                M.verify_result(result, P.result_uuid("c" * 32), empty=True)
