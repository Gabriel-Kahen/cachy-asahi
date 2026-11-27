#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert stopped-carrier, path, integrity and atomic publication controls."""

from json import dumps
import os
from pathlib import Path
from runpy import run_path
import shutil
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


E = run_path(str(Path(__file__).with_name("export.py")))
C, R = E["C"], E["R"]
ACTOR = E["ACTOR_DIR"]
NONCE = "a" * 32
FOREIGN = "b" * 32


def jsonl_entry(nonce):
    return (dumps(dict(phase="entry", kind=R["JOURNAL_KIND"], nonce=nonce)) + "\n").encode()


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.carrier = self.root / "result.raw"
        with self.carrier.open("xb") as stream:
            stream.truncate(E["RESULT_BYTES"])
        self.pin = C.read(self.carrier, E["RESULT_BYTES"], collect=False)[1]
        self.bundle = self.root / "bundle"
        self.nodes = {".": dict(type="directory"), "lost+found": dict(type="directory"),
                      "evidence": dict(type="directory"), "evidence/result.json": dict(type="file"),
                      ACTOR: dict(type="directory", uid=0, gid=0, mode=0o700, xattrs={})}
        self.content = {}
        self.start = C.identity(self.carrier.lstat())

        class Image:
            def __init__(trace, path, *, max_nodes, max_file_bytes):
                self.assertEqual(max_nodes, 64)
                self.assertEqual(max_file_bytes, E["MAX_NODE_BYTES"])
                trace.fd = os.open(path, os.O_RDONLY | os.O_NOATIME)

            def __enter__(trace):
                return trace

            def __exit__(trace, *_):
                os.close(trace.fd)

            def inventory(trace):
                return dict(nodes=self.nodes)

            def inode(trace, number):
                node, = (row for row in self.nodes.values() if row.get("inode") == number)
                return {key: value for key, value in node.items() if key != "sha256"}, number

            def chunks(trace, _fields, number):
                yield self.content[number]

        self.reader = self.enterContext(patch.object(C, "ext4_reader", return_value=Image))

    def actor_file(self, name, body, **attributes):
        number = 11 + len(self.content)
        self.content[number] = body
        self.nodes[f"{ACTOR}/{name}"] = dict(type="file", uid=0, gid=0, mode=0o600, links=1, xattrs={},
                                           inode=number, size=len(body), sha256=C.pin(body)["sha256"]) | attributes
        return number

    def owner(self, nonce, *, checkpoint=None):
        payload = C.wire(dict(nonce=nonce, qt_checkpoint=checkpoint))
        self.actor_file("result.json", payload)
        self.nodes["evidence/result.json"] = self.nodes.pop(f"{ACTOR}/result.json")

    def export(self, **inputs):
        return E["export"](self.carrier, self.pin, self.bundle, **inputs)

    def test_collects_partial_hold_and_reports_exact_missing_files(self):
        held = b'{"phase":"terminal","status":"HOLD_QT629_OFFICIAL_RESTORATION_VERIFIED"}\n'
        probes = b'{"checks":{"wayland":{"status":"SKIP"},"vulkan_loader":{"status":"FAIL"}},"status":"FAIL"}\n'
        lifecycle = b'{"status":"HOLD"}\n'
        self.actor_file("transaction.jsonl", held)
        self.actor_file("pacman.log", b"")
        self.actor_file("runtime-probes.json", probes)
        self.actor_file("weston-lifecycle.json", lifecycle)
        result = self.export()
        self.assertTrue(result["actor_directory_present"])
        self.assertEqual(result["evidence"], {"transaction.jsonl": C.pin(held), "pacman.log": C.pin(b""),
                                             "runtime-probes.json": C.pin(probes),
                                             "weston-lifecycle.json": C.pin(lifecycle)})
        self.assertEqual(result["missing_actor_files"], sorted(E["ACTOR_FILES"].keys() - result["evidence"].keys()))
        self.assertEqual((self.bundle / "transaction.jsonl").read_bytes(), held)
        self.assertEqual((self.bundle / "runtime-probes.json").read_bytes(), probes)
        self.assertEqual((self.bundle / "weston-lifecycle.json").read_bytes(), lifecycle)
        self.assertEqual(set(p.name for p in self.bundle.iterdir()), set(result["evidence"]))
        self.assertEqual(C.identity(self.carrier.lstat()), self.start)

    def test_retains_empty_bundle_for_failure_before_actor_entry(self):
        del self.nodes[ACTOR]
        del self.nodes["evidence/result.json"]
        result = self.export(expected_nonce=NONCE)
        self.assertFalse(result["actor_directory_present"])
        self.assertEqual(result["missing_actor_files"], sorted(E["ACTOR_FILES"]))
        self.assertEqual(list(self.bundle.iterdir()), [])

    def test_rejects_foreign_checkpoint_on_held_disk_before_publication(self):
        self.owner(NONCE, checkpoint={"nonce": FOREIGN})
        self.actor_file("pacman.log", b"partial action log\n")
        with self.assertRaisesRegex(ValueError, "Stopped guest evidence nonce differs.*Qt checkpoint"):
            self.export(expected_nonce=NONCE)
        self.assertFalse(self.bundle.exists())

    def test_rejects_foreign_early_asahi_result_before_qt_entry(self):
        del self.nodes[ACTOR]
        self.owner(FOREIGN)
        with self.assertRaisesRegex(ValueError, "Stopped guest evidence nonce differs.*Asahi result"):
            self.export(expected_nonce=NONCE)
        self.assertFalse(self.bundle.exists())

    def test_rejects_foreign_actor_entry_or_completed_report(self):
        self.owner(NONCE, checkpoint={"nonce": NONCE})
        for name in ("transaction.jsonl", "runtime-probes.json", "vendor-runtime-probes.json", "weston-lifecycle.json"):
            with self.subTest(name=name):
                body = jsonl_entry(FOREIGN) if name == "transaction.jsonl" else C.wire(dict(nonce=FOREIGN))
                self.actor_file(name, body)
                with self.assertRaisesRegex(ValueError, "Stopped guest evidence nonce differs.*" + name):
                    self.export(expected_nonce=NONCE)
                del self.nodes[f"{ACTOR}/{name}"]
        self.assertFalse(self.bundle.exists())

    def test_preserves_matching_partial_evidence_after_interrupted_write(self):
        self.owner(NONCE, checkpoint={"nonce": NONCE})
        journal = jsonl_entry(NONCE) + b'{"phase":"terminal"'
        probe = b'{"nonce":"incomplete'
        self.actor_file("transaction.jsonl", journal)
        self.actor_file("runtime-probes.json", probe)
        result = self.export(expected_nonce=NONCE)
        self.assertEqual(result["evidence"], {"transaction.jsonl": C.pin(journal), "runtime-probes.json": C.pin(probe)})
        self.assertEqual((self.bundle / "runtime-probes.json").read_bytes(), probe)

    def test_assembles_exact_originals_and_reviewed_test_operands(self):
        fixture = run_path(str(Path(__file__).with_name("test_readback.py")))
        receipt, originals, evidence = fixture["fixture"]()
        for name in E["ACTOR_FILES"].keys() & evidence.keys():
            self.actor_file(name, evidence[name])
        input_pins = receipt["original_inputs"]
        for role, body in originals.items():
            (self.root / role).write_bytes(body)
        test = {}
        for name in E["TEST_FILES"]:
            path = self.root / name
            path.write_bytes(evidence[name])
            test[name] = path, C.pin(evidence[name])
        with patch.dict(R["ORIGINALS"], input_pins), patch.dict(R["P"]["PINS"], input_pins):
            result = self.export(originals={role: self.root / role for role in originals}, test_inputs=test)
            self.assertEqual(result["missing_actor_files"], [])
            self.assertEqual(result["original_inputs"], input_pins)
            self.assertEqual(result["evidence"], receipt["evidence"])
            self.assertEqual((self.bundle / "runtime-probes.json").read_bytes(), evidence["runtime-probes.json"])
            self.assertFalse((self.bundle / "receipt.json").exists())
            body = C.wire(receipt)
            (self.bundle / "receipt.json").write_bytes(body)
            self.assertEqual(R["readback"](self.bundle, C.pin(body)["sha256"])["untouched_rows"], 628)

    def test_rejects_unallowlisted_names_without_publishing(self):
        self.actor_file("nested/baseline.lock", b"invalid")
        with self.assertRaisesRegex(ValueError, "Unexpected result member"):
            self.export()
        self.assertFalse(self.bundle.exists())

    def test_refuses_symlink_directory_or_leaf_and_multi_link_inode(self):
        self.nodes[ACTOR]["type"] = "symlink"
        with self.assertRaisesRegex(ValueError, "Unexpected Qt actor directory"):
            self.export()
        self.nodes[ACTOR]["type"] = "directory"
        for change in (dict(type="symlink"), dict(links=2), dict(mode=0o644), dict(xattrs={"user.test": "fixture"})):
            with self.subTest(change=change):
                self.actor_file("baseline.lock", b"fixture", **change)
                with self.assertRaisesRegex(ValueError, "Unexpected Qt actor file identity"):
                    self.export()
        self.assertFalse(self.bundle.exists())

    def test_enforces_per_role_cap_and_independent_body_digest(self):
        self.actor_file("baseline.lock", b"short", size=E["ACTOR_FILES"]["baseline.lock"] + 1)
        with self.assertRaisesRegex(ValueError, "Unexpected Qt actor file identity or size"):
            self.export()
        number = self.actor_file("baseline.lock", b"original")
        self.content[number] = b"replaced"
        with self.assertRaisesRegex(ValueError, "Qt actor body changed"):
            self.export()
        self.assertFalse(self.bundle.exists())

    def test_rejects_wrong_carrier_pin_and_source_symlink(self):
        with self.assertRaisesRegex(ValueError, "Exact original file pin"):
            E["export"](self.carrier, dict(self.pin, sha256="0" * 64), self.bundle)
        alias = self.root / "carrier-alias"
        alias.symlink_to(self.carrier)
        with self.assertRaisesRegex(ValueError, "Canonical read-only path"):
            E["export"](alias, self.pin, self.bundle)
        self.reader.assert_not_called()
        self.assertFalse(self.bundle.exists())

    def test_rejects_changed_test_input_before_writing_bundle(self):
        known = {}
        for name in E["TEST_FILES"]:
            path = self.root / name
            path.write_bytes(b"changed")
            known[name] = path, C.pin(b"trusted")
        with self.assertRaisesRegex(ValueError, "Exact original file pin"):
            self.export(test_inputs=known)
        self.assertFalse(self.bundle.exists())

    def test_rejects_guest_certificate_different_from_the_reviewed_bytes(self):
        name = "test-certificate.gpg"
        self.actor_file(name, b"guest substitute")
        known = {}
        for role in E["TEST_FILES"]:
            path = self.root / role
            path.write_bytes(b"reviewed")
            known[role] = path, C.pin(b"reviewed")
        with self.assertRaisesRegex(ValueError, "Guest evidence differs from reviewed TEST operand"):
            self.export(test_inputs=known)
        self.assertFalse(self.bundle.exists())

    def test_refuses_destination_parent_symlink(self):
        target = self.root / "real-parent"
        target.mkdir()
        alias = self.root / "parent-alias"
        alias.symlink_to(target, target_is_directory=True)
        self.bundle = alias / "bundle"
        with self.assertRaisesRegex(ValueError, "Canonical fresh export path"):
            self.export()
        self.assertEqual(list(target.iterdir()), [])

    def test_publication_no_replace_and_failed_stage_cleanup(self):
        self.actor_file("baseline.lock", b"new body")
        self.bundle.mkdir()
        with self.assertRaises(FileExistsError):
            self.export()
        self.assertEqual(list(self.bundle.iterdir()), [])
        self.assertEqual(list(self.root.glob(".qt629-export.*")), [])
        self.bundle.rmdir()
        with patch.dict(E["write_bundle"].__globals__, write_bodies=self.failed_write):
            with self.assertRaisesRegex(OSError, "synthetic write failure"):
                self.export()
        self.assertFalse(self.bundle.exists())
        self.assertEqual(list(self.root.glob(".qt629-export.*")), [])

    def failed_write(self, fd, bodies):
        E["write_bodies"](fd, bodies)
        self.assertFalse(self.bundle.exists())
        raise OSError("synthetic write failure")


@unittest.skipUnless(shutil.which("mke2fs") and shutil.which("debugfs"), "e2fsprogs unavailable")
class RawExt4Test(unittest.TestCase):
    def test_rereads_fresh_unmounted_synthetic_ext4_without_changing_it(self):
        with TemporaryDirectory() as folder:
            root = Path(folder)
            seed = root / "seed"
            actor = seed / ACTOR
            actor.mkdir(parents=True, mode=0o700)
            evidence = actor / "transaction.jsonl"
            evidence.write_bytes(b"partial journal\n")
            evidence.chmod(0o600)
            image = root / "result.raw"
            with image.open("xb") as stream:
                stream.truncate(E["RESULT_BYTES"])
            subprocess.run(["mke2fs", "-q", "-t", "ext4", "-b", "4096", "-O", "^orphan_file",
                            "-d", str(seed), str(image)], check=True, capture_output=True)
            for path in ("/" + ACTOR, "/" + ACTOR + "/transaction.jsonl"):
                for attribute in ("uid", "gid"):
                    subprocess.run(["debugfs", "-w", "-R", f"set_inode_field {path} {attribute} 0", str(image)],
                                   check=True, capture_output=True)
            before = C.identity(image.lstat())
            pin = C.read(image, E["RESULT_BYTES"], collect=False)[1]
            result = E["export"](image, pin, root / "bundle")
            self.assertEqual(result["evidence"], {"transaction.jsonl": C.pin(b"partial journal\n")})
            self.assertEqual(C.identity(image.lstat()), before)
            self.assertEqual(C.read(image, E["RESULT_BYTES"], collect=False)[1], pin)


if __name__ == "__main__":
    unittest.main()
