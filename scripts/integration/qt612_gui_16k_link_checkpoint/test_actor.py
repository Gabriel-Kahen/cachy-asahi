# SPDX-License-Identifier: MIT
"""Passive controls for the QtGui backing chain and original actor receipts."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
from runpy import run_path
import sys
from tempfile import TemporaryDirectory
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch


A = SimpleNamespace(**run_path(str(Path(__file__).with_name("actor.py"))))
NONCE, TOP_BYTES, CORE_BYTES = "a2" * 16, 196864, 1024**3 + 256


def fence(event, _args):
    if event.startswith(("subprocess.", "socket.", "os.exec", "os.posix_spawn", "os.system")):
        raise AssertionError("Passive QtGui actor control attempted execution: " + event)


sys.addaudithook(fence)


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def pin(body):
    return dict(bytes=len(body), sha256=hashlib.sha256(body).hexdigest())


def chain():
    common = {"virtual-size": 17179869184, "dirty-flag": False}
    qcow = {"type": "qcow2", "data": {"compat": "1.1", "compression-type": "zlib", "lazy-refcounts": False,
                                       "refcount-bits": 16, "corrupt": False, "extended-l2": False}}

    def node(filename, format, allocated, file_size, backing=None, backing_format=None):
        file = {"filename": filename, "format": "file", "actual-size": allocated, "virtual-size": file_size,
                "children": [], "dirty-flag": False, "format-specific": {"type": "file", "data": {}}}
        row = common | {"filename": filename, "format": format, "actual-size": allocated,
                        "children": [{"name": "file", "info": file}]}
        if backing is not None:
            row |= {"cluster-size": 65536, "format-specific": deepcopy(qcow), "backing-filename": backing,
                    "full-backing-filename": backing, "backing-filename-format": backing_format}
        return row

    return [
        node("/out/overlay.qcow2", "qcow2", 200704, 197120, "/inputs/core.qcow2", "qcow2"),
        node("/inputs/core.qcow2", "qcow2", 128 * 1024**2, 1024**3 + 512, "/inputs/scratch.raw", "raw"),
        node("/inputs/scratch.raw", "raw", 4 * 1024**3, 17179869184),
    ]


class ChainTests(unittest.TestCase):
    def test_exact_three_nodes_with_rounded_file_extents(self):
        A.validate_overlay_chain(encode(chain()), TOP_BYTES, CORE_BYTES)
        with self.assertRaisesRegex(ValueError, "file node"):
            A.validate_overlay_chain(encode(chain()), TOP_BYTES, CORE_BYTES + 512)

    def test_refuses_other_paths_formats_dirty_or_extra_external_data(self):
        cases = ((0, "backing-filename-format", "raw"), (0, "full-backing-filename", "/elsewhere/core.qcow2"),
                 (1, "backing-filename", "https://provider.invalid/scratch.raw"),
                 (1, "dirty-flag", True), (1, "data-file", "/out/sidecar"), (2, "filename", "/out/scratch.raw"))
        for index, key, value in cases:
            with self.subTest(index=index, key=key):
                rows = chain()
                rows[index][key] = value
                with self.assertRaisesRegex(ValueError, "file node"):
                    A.validate_overlay_chain(encode(rows), TOP_BYTES, CORE_BYTES)

    def test_refuses_wrong_count_duplicates_and_unsafe_allocation(self):
        with self.assertRaisesRegex(ValueError, "three-node"):
            A.validate_overlay_chain(encode(chain()[:2]), TOP_BYTES, CORE_BYTES)
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            A.validate_overlay_chain(b'[{"filename":"first","filename":"second"},{},{}]', TOP_BYTES, CORE_BYTES)
        with self.assertRaisesRegex(ValueError, "Nonfinite"):
            A.validate_overlay_chain(b'[{"actual-size":NaN},{},{}]', TOP_BYTES, CORE_BYTES)
        for extra in (False, 200705, 2 * 1024**2):
            rows = chain()
            rows[0]["actual-size"] = extra
            with self.assertRaisesRegex(ValueError, "sector-aligned"):
                A.validate_overlay_chain(encode(rows), TOP_BYTES, CORE_BYTES)

    def test_same_nonce_complete_pass_or_natural_hold(self):
        prefix = b"boot message\nQTGUI_LINK_TERMINAL " + NONCE.encode() + b" "
        self.assertEqual(A.terminal(prefix + b"PASS complete\r\n", NONCE), (True, "complete"))
        self.assertEqual(A.terminal(prefix + b"HOLD storage\n", NONCE), (False, "storage"))
        for body in (prefix + b"PASS link\n", prefix + b"PASS complete\n" + prefix + b"HOLD boot\n",
                     prefix.replace(NONCE.encode(), b"f" * 32) + b"PASS complete\n"):
            with self.assertRaises(ValueError):
                A.terminal(body, NONCE)


class Watch:
    def __init__(self, runtime, policy, output, deadline):
        self.tree = policy["watched_tree"]
        self.peak = {"free": 64 * 1024**3}
        self.samples = 0

    def record(self):
        self.samples += 1
        return dict(self.peak)


class LifecycleTests(unittest.TestCase):
    def run_model(self, work, *, passed=False, corrupt=False):
        out, inputs = work / "out", work / "inputs"
        out.mkdir()
        inputs.mkdir()
        result = out / "result.raw"
        result.write_bytes(b"result template")
        result.chmod(0o600)
        calls = []

        def read(path, cap, *, collect=True):
            body = path.read_bytes()
            self.assertLessEqual(len(body), cap)
            return body if collect else pin(body)

        def capacity(path, _):
            self.assertEqual(path, out)
            return dict(fits=True, free_bytes=64 * 1024**3)

        def check(path, expected):
            self.assertEqual(pin(path.read_bytes()), expected)

        policy = dict(result_disk_bytes=4096, watched_tree=["/out", 8 * 1024**3, 2 * 1024**3],
                      watched_paths=[["/out/overlay.qcow2", 4 * 1024**3], ["/out/result.raw", 4096]],
                      admission_disk_bytes=8 * 1024**3, serial_combined_cap=1024,
                      child_file_size_cap=4 * 1024**3,
                      overlay_create=["/usr/bin/qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                                      "-b", "/inputs/core.qcow2", "/out/overlay.qcow2"],
                      overlay_inspect=["/usr/bin/qemu-img", "info", "-f", "qcow2", "--output=json",
                                       "--backing-chain", "/out/overlay.qcow2"])
        plan = dict(nonce=NONCE, result_uuid="selected-uuid", qemu_argv=["/usr/bin/qemu-system-aarch64"],
                    qemu_seconds=900, inputs={"result.raw": pin(result.read_bytes()),
                                               "core.qcow2": dict(bytes=CORE_BYTES, sha256="b" * 64)},
                    limits=dict(actor_memory_bytes=8 * 1024**3))

        def phase(label, argv, seconds, *, file_cap=None):
            calls.append((label, argv, seconds, file_cap))
            if label == "overlay-create":
                (out / "overlay.qcow2").write_bytes(b"q" * TOP_BYTES)
            if label == "overlay-inspect":
                rows = chain()
                if corrupt:
                    rows[1]["full-backing-filename"] = "/out/untrusted.raw"
                (out / "overlay-inspect.stdout").write_bytes(encode(rows))
            if label == "qemu":
                (out / "qemu.stdout").write_text(f"QTGUI_LINK_TERMINAL {NONCE} "
                                              + ("PASS complete\n" if passed else "HOLD storage\n"))
                if passed:
                    (out / "overlay.qcow2").write_bytes(b"q" * (TOP_BYTES + 4096))
                    result.write_bytes(b"new worker result")
            return pin(label.encode())

        config = SimpleNamespace(T=SimpleNamespace(read=read, pin=pin, encoded=encode),
                                 B=SimpleNamespace(clean_file=Path.stat, AllocationWatch=Watch),
                                 K=SimpleNamespace(inspect_overlay=lambda *args: calls.append(("header", *args))),
                                 capacity=capacity, result_uuid=lambda *_: plan["result_uuid"],
                                 verify_source=lambda *_: calls.append(("source",)), check_pinned_file=check)
        runtime = SimpleNamespace(GUARD=None)
        runner = SimpleNamespace(plan=plan, actor=policy, data=dict(plan=dict(sha256="c" * 64)),
                                 issued=dict(expires_utc=time.time() + 600), runtime=runtime,
                                 verify_tools=lambda: calls.append(("tools",)),
                                 verify_inputs=lambda: calls.append(("inputs",)), deadline=time.monotonic() + 1000,
                                 phase=phase, tools={}, authority_sha="d" * 64, handoff_sha="e" * 64)
        with patch.dict(A.run.__globals__, {"OUT": out, "INPUTS": inputs, "memory_peak": lambda _: 100,
                                           "require_absence": lambda _: calls.append(("absence",))}):
            if corrupt:
                with self.assertRaisesRegex(ValueError, "file node"):
                    A.run(config, runner)
                self.assertNotIn("qemu", [call[0] for call in calls])
                self.assertFalse((out / "actor-result.json").exists())
                self.assertIsNone(runtime.GUARD)
                return
            self.assertEqual(A.run(config, runner), 0 if passed else 2)
        self.assertIsNone(runtime.GUARD)
        report = json.loads((out / "actor-result.json").read_bytes())
        self.assertEqual(report["kind"], "QTGUI_LINK_ACTOR_RESULT_V1")
        self.assertEqual(report["status"], "PASS_QTGUI_LINK_FOR_ROOT_REVIEW" if passed else "HOLD")
        self.assertEqual(report["serial"], pin((out / "qemu.stdout").read_bytes()))
        self.assertEqual(report["result_disk"] == plan["inputs"]["result.raw"], not passed)
        self.assertEqual([x[0] for x in calls], ["tools", "inputs", "header", "absence", "overlay-create", "header",
                                               "overlay-inspect", "qemu", "absence", "fsck-result", "inputs", "tools",
                                               "source", "header"])
        self.assertEqual(calls[7][3], policy["child_file_size_cap"])

    def test_boot_follows_exact_chain_and_retains_natural_results(self):
        with TemporaryDirectory() as tmp:
            for passed in (False, True):
                work = Path(tmp) / str(passed)
                work.mkdir()
                with self.subTest(passed=passed):
                    self.run_model(work, passed=passed)

    def test_foreign_parent_refused_before_boot(self):
        with TemporaryDirectory() as tmp:
            self.run_model(Path(tmp), corrupt=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
