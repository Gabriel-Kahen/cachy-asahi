# SPDX-License-Identifier: MIT
"""Pure controls for the new rehearsal purpose. No tool or guest invocation."""

from pathlib import Path
import tempfile
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import controller as C

T = C.T
NONCE = "a" * 32
FILE = Path("/out/qtbase16k")
TOOLS = {name: dict(bytes=size, sha256=digest) for name, (size, digest) in C.O.PROVEN_TOOLS.items()}
TOOLS["/usr/bin/mke2fs"] = dict(bytes=141672, sha256="a" * 64)  # inert selected profile


class Rehearsal(unittest.TestCase):
    def test_requires_full_tool_pins_with_shared_overlay_values(self):
        self.assertEqual(C.selected_tools(TOOLS), TOOLS)
        broken = TOOLS | {"/usr/bin/mke2fs": dict(bytes=141672, sha256="a" * 63)}
        with self.assertRaisesRegex(ValueError, "bounded pin"):
            C.selected_tools(broken)
        broken = TOOLS | {"/usr/bin/cp": dict(bytes=129336, sha256="b" * 64)}
        with self.assertRaisesRegex(ValueError, "Shared Overlay"):
            C.selected_tools(broken)
        with self.assertRaisesRegex(ValueError, "five-tool"):
            C.selected_tools({})

    def test_exact_canonical_tool_profile_and_image(self):
        profile = dict(kind=C.TOOL_PROFILE_KIND, actor_image=C.O.ACTOR_IMAGE, tools=TOOLS)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "tools.json"
            body = T.encoded(profile)
            path.write_bytes(body)
            self.assertEqual(C.load_tool_profile(path, T.pin(body)["sha256"]), TOOLS)
            with self.assertRaisesRegex(ValueError, "independently pinned"):
                C.load_tool_profile(path, "b" * 64)
            body = T.encoded(profile | {"actor_image": "sha256:" + "b" * 64})
            path.write_bytes(body)
            with self.assertRaisesRegex(ValueError, "shared actor image"):
                C.load_tool_profile(path, T.pin(body)["sha256"])

    def test_inherited_qemu_confinement_and_new_guest_entry(self):
        argv = C.qemu_argv(FILE, NONCE, "aaaaaaaa-01", "b" * 64)
        self.assertEqual(argv[argv.index("-nic") + 1], "none")
        self.assertEqual(argv[argv.index("-accel") + 1], "tcg,thread=multi")
        self.assertEqual(argv[argv.index("-m") + 1], "4096")
        command_line = argv[argv.index("-append") + 1]
        self.assertIn("rootflags=noload ro", command_line)
        self.assertIn("init=/qtbase16k-init", command_line)
        self.assertIn(f"cachy_qtbase_nonce={NONCE}", command_line)
        self.assertIn(f"cachy_qtbase_plan={'b' * 64}", command_line)
        self.assertNotIn("cachy_overlay583_", command_line)
        drives = [argv[i + 1] for i, option in enumerate(argv) if option == "-drive"]
        self.assertEqual([d.rsplit("=", 1)[-1] for d in drives], ["on", "on", "off", "off"])
        devices = [argv[i + 1] for i, option in enumerate(argv) if option == "-device"]
        self.assertEqual(devices, [f"virtio-blk-device,drive={name}" for name in ("boot", "inputs", "scratch", "result")])

    def test_unissued_and_mismatched_authority_stop_before_mutation(self):
        model = dict(kind=C.KIND, issuer=None, approved=None, created_utc=None, expires_utc=None, nonce=NONCE, tools=TOOLS)
        raw = T.encoded(model)
        touched = []
        boundary = lambda paths, nonce, tools: touched.append((paths, nonce, tools)) or model.copy()
        with self.assertRaisesRegex(ValueError, "Fresh separately issued"):
            C.verify_authority(raw, T.pin(raw)["sha256"], {}, boundary=boundary, now=100)
        self.assertFalse(touched)
        issued = model | dict(issuer="Root", approved=True, created_utc=100, expires_utc=110)
        raw = T.encoded(issued)
        self.assertEqual(C.verify_authority(raw, T.pin(raw)["sha256"], {}, boundary=boundary, now=101), issued)
        with self.assertRaisesRegex(ValueError, "authority digest"):
            C.verify_authority(raw, "0"*64, {}, boundary=boundary, now=101)
        with self.assertRaisesRegex(ValueError, "Fresh separately issued"):
            C.verify_authority(raw, T.pin(raw)["sha256"], {}, boundary=boundary, now=110)
        tampered = T.encoded(issued | dict(extra="unexpected"))
        with self.assertRaisesRegex(ValueError, "operands differ"):
            C.verify_authority(tampered, T.pin(tampered)["sha256"], {}, boundary=boundary, now=101)

    def test_same_nonce_serial_pass_hold_and_duplicates(self):
        good = f"console\nQTBASE16K {NONCE} PASS 16384\n".encode()
        self.assertTrue(C.terminal(good, NONCE))
        self.assertFalse(C.terminal(f"QTBASE16K {NONCE} HOLD configure\n".encode(), NONCE))
        for raw in (b"", good + good, good.replace(b"16384", b"4096")):
            with self.assertRaisesRegex(ValueError, "terminal marker"):
                C.terminal(raw, NONCE)

    def test_rootfs_signature_uses_dearmored_keyring_and_pinned_operands(self):
        init = (HERE / "guest-init.sh").read_text()
        signed = init[init.index("phase=signed-rootfs"):init.index("phase=alpm")]
        dearmor = signed.index('--output "$official_keyring" --dearmor /qtmedia/official/archlinuxarm.gpg')
        verify = signed.index('gpgv --homedir /run/qtbase-public --keyring "$official_keyring"')
        unpack = signed.index("tar --extract")
        self.assertLess(dearmor, verify)
        self.assertLess(verify, unpack)
        self.assertIn("official_keyring=/run/qtbase-public/archlinuxarm.gpg", signed)
        self.assertIn("/qtmedia/rootfs.tar.gz.sig /qtmedia/rootfs.tar.gz", signed)
        self.assertIn('$3!=fpr || $12!=fpr', signed)
        self.assertNotIn("--keyring /qtmedia/official/archlinuxarm.gpg", signed)

    def test_integrity_commands_have_distinct_receipt_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            runner = object.__new__(C.Runner)
            runner.out = Path(temp)
            with patch.object(runner, "command") as command:
                for name in ("inputs", "scratch", "result"):
                    result = runner.filesystem(name, name, 4096, NONCE, 90)
                runner.check_result_disk(result)
                labels = [call.args[0] for call in command.call_args_list]
                self.assertEqual(len(labels), len(set(labels)))
                self.assertEqual([label for label in labels if label.startswith("fsck-")],
                                 ["fsck-inputs", "fsck-scratch", "fsck-result", "fsck-result-readback"])
                self.assertEqual(command.call_args.args[1:3], ("e2fsck", ["-fn", result]))

    def test_24_gib_gate_refuses_before_output_creation(self):
        self.assertEqual(C.DISK_GATE, 24 * 1024**3)
        with tempfile.TemporaryDirectory() as temp:
            runner = object.__new__(C.Runner)
            runner.out = Path(temp) / "fresh"
            runner.authority = {"nonce": NONCE}
            with patch.object(runner, "require_absent_twice"), patch.object(
                C.shutil, "disk_usage", return_value=SimpleNamespace(free=C.DISK_GATE - 1),
            ):
                with self.assertRaisesRegex(ValueError, "24 GiB free"):
                    runner.run()
            self.assertFalse(runner.out.exists())


if __name__ == "__main__":
    sys.addaudithook(C.O.passive_fence)
    unittest.main()
