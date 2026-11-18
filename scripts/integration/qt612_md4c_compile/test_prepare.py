# SPDX-License-Identifier: MIT
"""Passive controls for the portable continuation selectors."""

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import prepare as P

OLD = "1" * 32
NEW = "2" * 32
DIGEST = "3" * 64
SCRATCH_UUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def configure_argv():
    disk = "/out/qtbase16k"
    args = ["/usr/bin/qemu-system-aarch64", "-machine", "virt", "-accel", "tcg,thread=multi",
            "-rtc", "base=utc,clock=host", "-cpu", "max", "-smp", "4", "-m", "4096",
            "-nodefaults", "-no-user-config", "-display", "none", "-monitor", "none",
            "-nic", "none", "-no-reboot", "-kernel", disk + "/Image", "-append",
            f"root=PARTUUID={OLD[:8]}-01 rootfstype=ext4 rootflags=noload ro rootwait "
            f"console=ttyAMA0,115200n8 init=/qtbase16k-init cachy_qtbase_nonce={OLD} cachy_qtbase_plan={DIGEST}",
            "-serial", "stdio", "-name", "overlay583-" + OLD,
            "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"]
    for name, mode in (("boot", "on"), ("inputs", "on"), ("scratch", "off"), ("result", "off")):
        args += ["-drive", f"if=none,id={name},file={disk}/{name}.raw,format=raw,readonly={mode}",
                 "-device", f"virtio-blk-device,drive={name}"]
    return args


def selector(directory):
    def ref(path, size=1, digest=DIGEST):
        return {"path": str(path), "bytes": size, "sha256": digest}

    attempt = directory / "packet/issued.sample_01"
    records = {}
    for name, (_, relative) in P.CONFIGURE_FILES.items():
        records[name] = ref(attempt / relative if relative else directory / "readback.json",
                            P.RESULT if name == "guest_result_disk" else 1)
    records.update(attempt=str(attempt), claim=ref(attempt.parent / "root-run.claim/attempt.path"),
                   closure=ref(directory / "closure.json"))
    pins = {"bytes": 1, "sha256": DIGEST}
    tools = dict(kind=P.TOOL_PROFILE_KIND, actor_image=P.QEMU_ACTOR_IMAGE,
                 tools={name: pins for name in P.TOOL_NAMES})
    tool_file = directory / "tools.json"
    raw = P.canonical(tools)
    tool_file.write_bytes(raw)
    return dict(kind=P.PROFILE_KIND, configure=records, original_inputs={
        name: ref(attempt / "output/qtbase16k" / name, size)
        for name, size in {"Image": 1 << 20, "boot.raw": 2 << 20, "scratch.raw": P.WORK}.items()
    }, scratch_uuid=SCRATCH_UUID, tools={"profile": ref(tool_file, len(raw), P.sha(raw)), "qemu_img": pins},
        operand_sha256=dict.fromkeys(P.OPERAND_PATHS, DIGEST), command_sha256=dict.fromkeys(P.COMMANDS, DIGEST))


def rounded_overlay():
    paths = "/out/overlay.qcow2", "/inputs/scratch.raw"
    nodes = []
    for path, fmt, size, allocated in zip(paths, ("qcow2", "raw"), (197120, P.WORK), (200704, 4975878144)):
        children = [{"name": "file", "info": {"filename": path, "format": "file", "actual-size": allocated,
                     "virtual-size": size, "children": [], "dirty-flag": False,
                     "format-specific": {"type": "file", "data": {}}}}]
        nodes.append({"filename": path, "format": fmt, "actual-size": allocated, "virtual-size": P.WORK,
                      "children": children, "dirty-flag": False})
    nodes[0].update({"backing-filename": paths[1], "full-backing-filename": paths[1], "backing-filename-format": "raw",
                     "cluster-size": 65536, "format-specific": {"type": "qcow2", "data": {
                         "compat": "1.1", "compression-type": "zlib", "lazy-refcounts": False, "refcount-bits": 16,
                         "corrupt": False, "extended-l2": False}}})
    return nodes


class PrepareTests(unittest.TestCase):
    def test_profile_is_externally_pinned_and_shape_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            content = selector(directory)
            profile = directory / "profile.json"
            raw = P.canonical(content)
            profile.write_bytes(raw)
            self.assertEqual(P.load_profile(profile, P.sha(raw)), content)
            with self.assertRaisesRegex(ValueError, "pin differs"):
                P.load_profile(profile, "0" * 64)
            content["original_inputs"]["scratch.raw"]["path"] = str(directory / "unjoined.raw")
            raw = P.canonical(content)
            profile.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "Original attempt operand differs"):
                P.load_profile(profile, P.sha(raw))

    def test_profile_refuses_duplicate_json_fields(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "profile.json"
            raw = b'{"kind":"wrong","kind":"other"}'
            path.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
                P.load_profile(path, P.sha(raw))

    def test_predecessor_reopens_exact_claim_and_closed_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            profile = selector(directory)
            configured = profile["configure"]

            def write(name, body):
                ref = configured[name]
                path = Path(ref["path"])
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(body)
                ref.update(bytes=len(body), sha256=P.sha(body))

            write("claim", (configured["attempt"] + "\n").encode())
            for name in P.CONFIGURE_FILES:
                if name == "guest_result_disk":
                    leaf = Path(configured[name]["path"])
                    leaf.parent.mkdir(parents=True, exist_ok=True)
                    with leaf.open("wb") as sparse:
                        sparse.truncate(P.RESULT)
                    configured[name].update(P.observe(leaf, P.RESULT)[1])
                    continue
                body = P.canonical({"argv": configure_argv()}) if name == "original_qemu" else b"passive model"
                write(name, body)
            close = dict(status="CLOSED_QTBASE16K_Q3_PASS", original_custody_pass=True,
                         attempt=configured["attempt"], release="CLOSE_ONLY", full_Qt_build="NOT RUN",
                         issuer="Root", configure="PASS_EXACT_QTBASE16K_CONFIGURE_ONLY",
                         page_size=16384, md4c="0.5.3-1", scoped_TEST_only=True,
                         scope_exit=0, container_exit=0,
                         observations=[dict(container_absent=True, scope_absent=True)] * 2)
            close.update({name: P.ref_pin(configured[name]) for name in P.CONFIGURE_FILES})
            write("closure", P.canonical(close))
            raw = P.canonical(profile)
            selection = directory / "profile.json"
            selection.write_bytes(raw)
            profile = P.load_profile(selection, P.sha(raw))
            configured = profile["configure"]
            self.assertEqual(P.predecessor(profile), configure_argv())
            for changes in ({"issuer": "Builder"}, {"page_size": 4096}, {"scoped_TEST_only": 1},
                            {"md4c": "0.5.1-1"}, {"configure": "HOLD"}):
                with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "closed configure-only"):
                    write("closure", P.canonical(close | changes))
                    P.predecessor(profile)
            write("closure", P.canonical(close))
            Path(configured["guest_serial"]["path"]).write_bytes(b"changed model")
            with self.assertRaisesRegex(ValueError, "File pin differs"):
                P.predecessor(profile)

    def test_qemu_exact_controls_and_storage_selection(self):
        prior = configure_argv()
        output = P.qemu_argv(prior, NEW, DIGEST, SCRATCH_UUID)
        self.assertEqual(output, P.continuation_argv(NEW, DIGEST, SCRATCH_UUID))
        self.assertTrue(output[output.index("-append") + 1].endswith(
            "cachy_qt_compile_scratch_uuid=" + SCRATCH_UUID + " cachy_qt_compile_result_uuid=" + P.result_uuid(NEW)))
        self.assertIn("if=none,id=boot,file=/inputs/boot.raw,format=raw,readonly=on", output)
        self.assertEqual(output.count("-drive"), 3)
        with self.assertRaisesRegex(ValueError, "configure QEMU controls"):
            P.qemu_argv(prior + ["-net", "user"], NEW, DIGEST, SCRATCH_UUID)
        with self.assertRaisesRegex(ValueError, "Fresh boot identity"):
            P.qemu_argv(prior, OLD, DIGEST, SCRATCH_UUID)
        with self.assertRaisesRegex(ValueError, "Distinct canonical"):
            P.continuation_argv(NEW, DIGEST, P.result_uuid(NEW))

    def test_generated_plan_refuses_changed_capacity_and_host_device(self):
        with tempfile.TemporaryDirectory() as temp:
            profile = selector(Path(temp))
            files = P.view_sources(profile) | {"result.raw": {"bytes": P.RESULT, "sha256": DIGEST}}
            plan = P.plan_data(profile, configure_argv(), NEW, files)
            self.assertEqual(P.validate_plan(plan, profile, configure_argv()), plan)
            plan["actor"]["child_file_size_cap"] += 512
            with self.assertRaisesRegex(ValueError, "Exact unissued continuation"):
                P.validate_plan(plan, profile, configure_argv())
            plan = P.plan_data(profile, configure_argv(), NEW, files)
            plan["qemu_argv"].append("-enable-kvm")
            with self.assertRaisesRegex(ValueError, "Exact unissued continuation"):
                P.validate_plan(plan, profile, configure_argv())

    def test_qcow2_refuses_extra_devices_malformed_flags_and_unrounded_eof(self):
        nodes = rounded_overlay()
        P.validate_empty_overlay(json.dumps(nodes).encode(), 196864)
        broken = rounded_overlay()
        broken[0]["children"][0]["info"]["virtual-size"] = 196864
        with self.assertRaisesRegex(ValueError, "Exact ordinary local file"):
            P.validate_empty_overlay(json.dumps(broken).encode(), 196864)
        broken = rounded_overlay()
        broken[0]["format-specific"]["data"]["lazy-refcounts"] = 0
        with self.assertRaisesRegex(ValueError, "Exact ordinary local file"):
            P.validate_empty_overlay(json.dumps(broken).encode(), 196864)
        with self.assertRaisesRegex(ValueError, "One QCOW2 node"):
            P.validate_empty_overlay(json.dumps(nodes + [nodes[1]]).encode(), 196864)


if __name__ == "__main__":
    unittest.main()
