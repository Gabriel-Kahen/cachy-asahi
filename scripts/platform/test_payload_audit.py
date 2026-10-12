#!/usr/bin/env python3
import hashlib
import importlib.util
import io
import json
import lzma
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("payload", Path(__file__).with_name("payload_audit.py"))
payload = importlib.util.module_from_spec(spec); spec.loader.exec_module(payload)


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def ref(self, path):
        raw = path.read_bytes()
        return {"path": str(path), "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    def document(self, name, value):
        path = self.root / name; path.write_text(json.dumps(value)); return self.ref(path)

    def archive(self, nodes=(), controls=True):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w:") as stream:
            if controls:
                metadata = b"pkgname = alpha\npkgver = 1-1\narch = aarch64\nlicense = MIT\n"
                info = tarfile.TarInfo(".PKGINFO"); info.size = len(metadata)
                stream.addfile(info, io.BytesIO(metadata))
            for name, kind, value in nodes:
                info = tarfile.TarInfo(name); info.mode = 0o755
                if kind == "file":
                    info.size = len(value); stream.addfile(info, io.BytesIO(value))
                else:
                    info.type = {"directory": tarfile.DIRTYPE, "symlink": tarfile.SYMTYPE,
                                 "hardlink": tarfile.LNKTYPE, "fifo": tarfile.FIFOTYPE}[kind]
                    if kind in {"symlink", "hardlink"}:
                        info.linkname = value
                    stream.addfile(info)
        path = self.root / "alpha.pkg.tar.xz"; path.write_bytes(lzma.compress(data.getvalue())); return self.ref(path)

    def contract(self, archive, paths, extra=False):
        metadata = {"NAME": ["alpha"], "VERSION": ["1-1"], "ARCH": ["aarch64"], "LICENSE": ["MIT"],
                    "FILENAME": ["alpha-1-1-aarch64.pkg.tar.xz"], "SHA256SUM": [archive["sha256"]],
                    "CSIZE": [str(archive["size"])]}
        packages = [{"name": "alpha", "version": "1-1", "repo": "extra", "metadata": metadata}]
        selected = [{"name": "alpha", "version": "1-1", "declared_paths": paths}]
        if extra:
            packages.append({"name": "baseline", "version": "1-1", "repo": "installed", "metadata": {}})
            selected.append({"name": "baseline", "version": "1-1", "declared_paths": ["usr/bin/baseline"]})
        status = "PASS-private-metadata-prepare"
        final = self.document("final.json", {"packages": packages, "transaction_status": status,
                                              "dependency_transaction_accepted": False})
        transaction = self.document("transaction.json", {"kind": "private-Asahi-metadata-transaction-prepare",
                                                          "status": status, "proposed_final_inventory": packages})
        owners = self.document("owners.json", {"kind": "metadata-only-declared-ownership-audit",
                                               "transaction_status": status, "input_references": {"final_inventory": final},
                                               "selected_packages": selected})
        return {"schema_version": 1, "transaction": transaction, "ownership": owners,
                "archives": [{"name": "alpha", "archive": archive}]}

    def test_regular_bytes_hash_and_unknown_baseline(self):
        archive = self.archive([("usr/bin/tool", "file", b"payload")])
        report = payload.run(self.contract(archive, ["usr/bin/tool"], extra=True))
        node = report["packages"][0]["nodes"][0]
        self.assertEqual(node["sha256"], hashlib.sha256(b"payload").hexdigest())
        self.assertEqual(report["archive_unavailable_packages"], ["baseline"])
        self.assertFalse(report["complete_installed_payload_verified"])
        self.assertFalse(report["system_mutation"])

    def test_scriptlets_are_inert_text(self):
        archive = self.archive([(".INSTALL", "file", b"post_install() { touch /tmp/forbidden; }\n")])
        with patch("subprocess.run", side_effect=AssertionError("execution forbidden")):
            report = payload.run(self.contract(archive, []))
        self.assertIn("touch", report["packages"][0]["controls"][".INSTALL"]["text"])
        self.assertFalse(report["package_payloads_executed"])

    def test_file_list_mismatch_remains_visible(self):
        archive = self.archive([("usr/new", "file", b"x")])
        row = payload.run(self.contract(archive, ["usr/old"]))["packages"][0]
        self.assertEqual(row["missing_declared_paths"], ["usr/old"])
        self.assertEqual(row["undeclared_archive_paths"], ["usr/new"])

    def test_duplicate_node_refused(self):
        archive = self.archive([("usr/a", "file", b"x"), ("usr/a", "file", b"y")])
        row = payload.run(self.contract(archive, ["usr/a"]))["packages"][0]
        self.assertEqual(row["status"], "payload-inspection-failed")
        self.assertIn("duplicate", row["error"])

    def test_traversal_refused(self):
        archive = self.archive([("../outside", "file", b"x")])
        row = payload.run(self.contract(archive, []))["packages"][0]
        self.assertIn("traversal", row["error"])

    def test_special_node_refused(self):
        archive = self.archive([("usr/fifo", "fifo", "")])
        row = payload.run(self.contract(archive, ["usr/fifo"]))["packages"][0]
        self.assertIn("special", row["error"])

    def test_archive_hash_mismatch_not_inspected(self):
        archive = self.archive(); contract = self.contract(archive, [])
        path = Path(archive["path"]); raw = path.read_bytes(); path.write_bytes(b"!" + raw[1:])
        row = payload.run(contract)["packages"][0]
        self.assertEqual(row["status"], "payload-inspection-failed")
        self.assertIn("checksum", row["error"])

    def test_source_ownership_full_metadata_mismatch(self):
        archive = self.archive(); contract = self.contract(archive, [])
        owners = json.loads(Path(contract["ownership"]["path"]).read_text())
        final = json.loads(Path(owners["input_references"]["final_inventory"]["path"]).read_text())
        final["packages"][0]["metadata"]["ARCH"] = ["any"]
        owners["input_references"]["final_inventory"] = self.document("other-final.json", final)
        contract["ownership"] = self.document("other-owners.json", owners)
        with self.assertRaisesRegex(ValueError, "full final metadata"):
            payload.run(contract)

    def test_source_status_mismatch(self):
        archive = self.archive(); contract = self.contract(archive, [])
        owners = json.loads(Path(contract["ownership"]["path"]).read_text()); owners["transaction_status"] = "FAIL"
        contract["ownership"] = self.document("bad-status.json", owners)
        with self.assertRaisesRegex(ValueError, "full final metadata"):
            payload.run(contract)

    def test_hardlink_observation(self):
        archive = self.archive([("usr/file", "file", b"a"), ("usr/link", "hardlink", "usr/file")])
        report = payload.run(self.contract(archive, ["usr/file", "usr/link"]))
        self.assertEqual(report["links"][0]["resolution"]["status"], "same-archive-file")
        self.assertEqual(report["links"][0]["resolution"]["payload_sha256"], hashlib.sha256(b"a").hexdigest())

    def test_unsafe_hardlink_is_finding(self):
        archive = self.archive([("usr/link", "hardlink", "../outside")])
        report = payload.run(self.contract(archive, ["usr/link"]))
        self.assertEqual(report["links"][0]["resolution"]["status"], "unsafe-hardlink-target")

    def test_symlink_prefix_resolution(self):
        namespace = {"usr/bin/a": {"type": "symlink", "target": "b"}, "usr/bin/b": {"type": "file"}}
        result = payload.resolved_link({"path": "usr/bin/start", "target": "a"}, namespace)
        self.assertEqual(result["status"], "observed-target")
        self.assertFalse(result["filesystem_resolution_verified"])

    def test_link_cycle_and_escape(self):
        namespace = {"a": {"type": "symlink", "target": "b"}, "b": {"type": "symlink", "target": "a"}}
        self.assertEqual(payload.resolved_link({"path": "start", "target": "a"}, namespace)["status"], "observed-link-cycle")
        self.assertEqual(payload.resolved_link({"path": "start", "target": "../out"}, {})["status"], "escapes-proposed-root")

    def test_parent_component_follows_symlink_before_dotdot(self):
        namespace = {"usr/link": {"type": "symlink", "target": "other/deep"},
                     "usr/other": {"type": "directory"}, "usr/other/deep": {"type": "directory"},
                     "usr/other/target": {"type": "file"}, "usr/target": {"type": "file"}}
        result = payload.resolved_link({"path": "usr/start", "target": "link/../target"}, namespace)
        self.assertEqual(result["status"], "observed-target")
        self.assertEqual(result["path"], "usr/other/target")
        self.assertFalse(result["filesystem_resolution_verified"])

    def test_regular_prefix_is_enotdir_even_before_dotdot(self):
        namespace = {"usr/file": {"type": "file"}, "usr/file/child": {"type": "file"},
                     "usr/target": {"type": "file"}}
        for target in ("file/child", "file/../target", "file/.", "file/"):
            with self.subTest(target=target):
                result = payload.resolved_link({"path": "usr/start", "target": target}, namespace)
                self.assertEqual(result["status"], "observed-nondirectory-ancestor")
                self.assertEqual(result["errno"], "ENOTDIR")
                self.assertEqual(result["ancestor"], "usr/file")
                self.assertFalse(result["filesystem_resolution_verified"])

    def test_absolute_and_relative_nested_symlinks_preserve_components(self):
        namespace = {"usr/link": {"type": "symlink", "target": "/opt/alias/deep"},
                     "opt/alias": {"type": "symlink", "target": "real"},
                     "opt/real": {"type": "directory"}, "opt/real/deep": {"type": "directory"},
                     "opt/real/target": {"type": "file"}}
        result = payload.resolved_link({"path": "usr/start", "target": "link/../target"}, namespace)
        self.assertEqual((result["status"], result["path"]), ("observed-target", "opt/real/target"))

    def test_symlink_dotdot_does_not_skip_unknown_baseline_ancestor(self):
        namespace = {"usr/link": {"type": "symlink", "target": "old/deep"},
                     "usr/old": {"type": "directory", "declared_only": True}, "usr/target": {"type": "file"}}
        result = payload.resolved_link({"path": "usr/start", "target": "link/../../target"}, namespace)
        self.assertEqual(result["status"], "unknown-ancestor-type")
        self.assertEqual(result["ancestor"], "usr/old")

    def test_finite_repeated_symlink_is_not_a_cycle_and_growth_is_bounded(self):
        namespace = {"alias": {"type": "symlink", "target": "real"},
                     "real": {"type": "directory"}, "real/file": {"type": "file"}}
        result = payload.resolved_link({"path": "start", "target": "alias/../alias/file"}, namespace)
        self.assertEqual((result["status"], result["path"]), ("observed-target", "real/file"))
        result = payload.resolved_link({"path": "start", "target": "grow"},
                                       {"grow": {"type": "symlink", "target": "grow/child"}}, maximum=2)
        self.assertEqual(result["status"], "link-depth-bound")
        result = payload.resolved_link({"path": "start", "target": "grow"},
                                       {"grow": {"type": "symlink", "target": "grow/" + "x" * 4000}})
        self.assertEqual(result["status"], "link-path-bound")

    def test_unknown_ancestor_remains_unknown(self):
        result = payload.resolved_link({"path": "start", "target": "lib/a"}, {"lib": {"type": "unknown"}})
        self.assertEqual(result["status"], "unknown-ancestor-type")

    def test_declared_directory_is_not_observed_payload(self):
        namespace = {"old": {"type": "directory", "declared_only": True}}
        self.assertEqual(payload.resolved_link({"path": "start", "target": "old"}, namespace)["status"], "declared-target-payload-unknown")
        self.assertEqual(payload.resolved_link({"path": "start", "target": "old/file"}, namespace)["status"], "unknown-ancestor-type")

    def test_decoded_budget_stops_after_single_probe(self):
        budget = {"decoded": 0}; stream = io.BytesIO(b"abcd")
        with patch.object(payload, "TOTAL_DECODED_LIMIT", 2):
            counted = payload.Counted(stream, budget)
            with self.assertRaisesRegex(ValueError, "work bound"):
                counted.read(4)
            self.assertEqual(stream.tell(), 3)
            with self.assertRaisesRegex(ValueError, "exhausted"):
                counted.read(1)
            self.assertEqual(stream.tell(), 3)

    def test_hook_actions_are_parsed_as_data(self):
        text = "[Trigger]\nOperation = Upgrade\nType = Path\nTarget = usr/*\n[Action]\nExec = /usr/bin/false\nNeedsTargets\nAbortOnFail\n"
        result = payload.hook_fields(text)
        self.assertTrue(result["parsed"])
        self.assertEqual(result["sections"][1]["fields"]["Exec"], ["/usr/bin/false"])
        self.assertEqual(result["sections"][1]["fields"]["NeedsTargets"], [True])
        self.assertEqual(result["sections"][1]["fields"]["AbortOnFail"], [True])
        self.assertFalse(result["executed"])


if __name__ == "__main__":
    unittest.main()
