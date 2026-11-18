# SPDX-License-Identifier: MIT
"""Actor-fenced checks against a real staged but unissued QtCore capsule."""

import argparse
import json
from pathlib import Path
from runpy import run_path
import sys
from tempfile import TemporaryDirectory
import unittest


def fence(event, _args):
    if event.startswith(("subprocess.", "socket.", "os.exec", "os.posix_spawn", "os.system")):
        raise AssertionError("Passive capsule check attempted an actor operation: " + event)


class CapsuleTests(unittest.TestCase):
    def test_exact_plan_draws_only_readonly_boot_and_private_writable_drives(self):
        argv = PLAN["qemu_argv"]
        self.assertEqual(argv[argv.index("-nic") + 1], "none")
        drives = [argv[index + 1] for index, option in enumerate(argv) if option == "-drive"]
        self.assertEqual(drives, [
            "if=none,id=boot,file=/inputs/boot.raw,format=raw,readonly=on",
            "if=none,id=scratch,file=/out/overlay.qcow2,format=qcow2,readonly=off,discard=ignore",
            "if=none,id=result,file=/out/result.raw,format=raw,readonly=off",
        ])
        self.assertEqual(PLAN["actor"]["child_file_size_cap"], 4 << 30)
        self.assertEqual(PLAN["qemu_seconds"], 7200)
        self.assertIsNone(PLAN["authority"])

    def test_unsigned_or_modified_binding_cannot_enter(self):
        original = (ROOT / "binding.UNISSUED.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "Fresh finite Root entry window"):
            C.verify_selection(original, C.P.sha(original), HANDOFF, PLAN, HANDOFF_SHA, live=False)
        selected = json.loads(original)
        selected.update(issuer="Root", approved=True, created_utc=100, expires_utc=200)
        model = C.T.encoded(selected)
        self.assertEqual(C.verify_selection(model, C.P.sha(model), HANDOFF, PLAN, HANDOFF_SHA, live=False), selected)
        with self.assertRaisesRegex(ValueError, "entry window"):
            C.verify_selection(model, C.P.sha(model), HANDOFF, PLAN, HANDOFF_SHA)
        changed = C.T.encoded(selected | {"nonce": "a" * 32})
        with self.assertRaisesRegex(ValueError, "sealed unissued QtCore binding"):
            C.verify_selection(changed, C.P.sha(changed), HANDOFF, PLAN, HANDOFF_SHA, live=False)

    def test_modified_qemu_shape_refused_even_when_rehashed(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "plan"
            modified = dict(PLAN, qemu_seconds=7201)
            body = C.T.encoded(modified)
            path.write_bytes(body)
            with self.assertRaisesRegex(ValueError, "bounded unissued plan"):
                C.load_plan(path, C.P.sha(body))

    def test_terminal_is_single_same_nonce_and_only_complete_passes(self):
        marker = f"QTCORE_LINK_TERMINAL {PLAN['nonce']} ".encode()
        self.assertEqual(A["terminal"](marker + b"HOLD storage\n", PLAN["nonce"]), (False, "storage"))
        self.assertEqual(A["terminal"](marker + b"PASS complete\n", PLAN["nonce"]), (True, "complete"))
        for raw in (marker + b"PASS link\n", marker + b"PASS complete\n" + marker + b"HOLD link\n"):
            with self.assertRaises(ValueError):
                A["terminal"](raw, PLAN["nonce"])

    def test_real_result_template_has_exact_distinct_uuid(self):
        template = ROOT / "templates/result.raw"
        self.assertEqual(C.result_uuid(template), PLAN["result_uuid"])
        self.assertNotEqual(PLAN["result_uuid"], C.F.SCRATCH_UUID)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capsule", type=Path, required=True)
    parser.add_argument("--handoff-sha256", required=True)
    arguments = parser.parse_args()
    ROOT, HANDOFF_SHA = arguments.capsule, arguments.handoff_sha256
    sys.addaudithook(fence)
    lane = ROOT / "source/scripts/integration/qt612_base_16k_link_preflight"
    A = run_path(str(lane / "actor.py"))
    C = A["C"]
    HANDOFF = C.load_handoff(ROOT / C.HANDOFF_LEAF, HANDOFF_SHA)
    C.verify_source(HANDOFF, ROOT / "source")
    PLAN = C.load_plan(ROOT / C.PLAN_LEAF, HANDOFF["plan"]["sha256"])
    unittest.main(argv=[sys.argv[0]], verbosity=2)
