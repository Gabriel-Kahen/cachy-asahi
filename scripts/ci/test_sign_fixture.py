"""TEST signer boundary regressions: temporary fixtures/mocks, no GPG or Docker."""
import hashlib
import base64
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
try:
    SPEC = importlib.util.spec_from_file_location("sign_fixture_tested", HERE / "sign_fixture.py")
    signer = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(signer)
finally:
    sys.path.remove(str(HERE))

PIN = "a" * 64
FP = "A" * 40
VALID = f"[GNUPG:] VALIDSIG {FP} 2026-10-11 1791676800 0 4 0 1 10 00 {FP}\n"


def public_certificate(packets=None):
    # Synthetic packet framing only. fingerprint/signature crypto is mocked;
    # this is never claimed to be a real key or used with a GPG executable.
    packets = packets if packets is not None else b"\xc6\x01x\xcd\x01x\xc2\x01x"
    return (b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n" + base64.b64encode(packets) +
            b"\n-----END PGP PUBLIC KEY BLOCK-----\n")


def contract():
    return {"schema_version": 1, "purpose": signer.PURPOSE, "nonce": "d" * 32,
            "image_id": "sha256:" + PIN, "entry_sha256": PIN, "manifest_sha256": "e" * 64,
            "helpers_sha256": {"runner/native_arm.py": "b" * 64,
                               "scripts/checks/package_checks.py": "c" * 64}}


def probe():
    return {"arch": "aarch64", "uid": 1000, "user": "alarm", "docker_marker": True,
            "interfaces": ["lo"], "docker_socket": False, "caps": 0, "no_new_privs": 1,
            "capabilities": {name: 0 for name in signer.CAPABILITY_FIELDS},
            "nonce": "d" * 32, "device_nodes": {
                name: {"kind": "char", "major": major, "minor": minor}
                for name, (major, minor) in signer.STANDARD_DEVICES.items()}, "sockets": [], "mounts": {
                "/": {"fs": "overlay", "options": ["ro"], "root": "/"},
                "/inputs": {"fs": "ext4", "options": ["ro"], "root": "/runner/inputs"},
                "/out": {"fs": "ext4", "options": ["rw"], "root": "/runner/output"},
                "/tmp": {"fs": "tmpfs", "options": ["rw", "nosuid", "nodev"], "root": "/"},
                **{name: {"fs": fs, "options": sorted(flags),
                          "root": "/null" if name in signer.MASKED_NULL else
                          name.removeprefix('/proc') if fs == 'proc' and name != '/proc' else '/'}
                   for name, (fs, flags) in signer.STANDARD_MOUNTS.items()}}}


def manifest():
    rows = []
    for role, version in (("original", "1-1"), ("upgrade-fixture", "1-2")):
        for name in signer.native.RECIPES:
            path = f"{role}/{name}-{version}-any.pkg.tar.gz"
            rows.append({"name": name, "version": version, "role": role, "path": path,
                         "sha256": hashlib.sha256(path.encode()).hexdigest()})
    return {"schema_version": 1, "purpose": signer.PURPOSE, "source_commit": "f" * 40,
            "archives": rows}


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Any forgotten command execution is an immediate test failure.
        self.no_exec = patch.object(signer.subprocess, "run", side_effect=AssertionError("host command forbidden"))
        self.no_exec.start()
        self.addCleanup(self.no_exec.stop)
        self.no_popen = patch.object(signer.subprocess, "Popen", side_effect=AssertionError("host process forbidden"))
        self.no_popen.start()
        self.addCleanup(self.no_popen.stop)

    def archive(self, path, row, overrides=None, extras=()):
        values = {"pkgname": row["name"], "pkgver": row["version"], "arch": "any", "license": "MIT"}
        values.update(overrides or {})
        data = "".join(f"{key} = {value}\n" for key, value in values.items()).encode()
        build = (f"format = 2\npkgname = {values['pkgname']}\npkgver = {values['pkgver']}\n"
                 f"pkgarch = {values['arch']}\npkgbuild_sha256sum = {PIN}\n").encode()
        path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(path, "w:gz") as archive:
            for name, content in [(".PKGINFO", data), (".BUILDINFO", build), (".MTREE", b"mtree"),
                                  ("usr/share/test/receipt.txt", b"MIT test data"), *extras]:
                entry = tarfile.TarInfo(name)
                entry.uid = entry.gid = 0
                entry.size = len(content)
                archive.addfile(entry, io.BytesIO(content))
        row["sha256"] = signer.native.sha(path)
        return path


class ManifestTests(Base):
    def test_exact_eight_role_name_groups_accepted(self):
        data = manifest()
        self.assertEqual(signer.validate_manifest(data), data["archives"])

    def test_missing_extra_duplicate_or_wrong_groups_rejected(self):
        cases = []
        for count in (0, 7, 9):
            data = manifest()
            data["archives"] = (data["archives"] * 2)[:count]
            cases.append(data)
        for key, value in (("name", "other"), ("role", "release"), ("name", signer.native.RECIPES[1]),
                           ("path", manifest()["archives"][1]["path"])):
            data = manifest(); data["archives"][0][key] = value; cases.append(data)
        for data in cases:
            with self.subTest(data=data), self.assertRaises(ValueError):
                signer.validate_manifest(data)

    def test_version_hash_source_commit_and_test_purpose_required(self):
        for key, value in (("version", ""), ("version", "1-1;cmd"), ("version", "1\n-1"),
                           ("sha256", "A" * 64), ("sha256", "0" * 63)):
            data = manifest(); data["archives"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                signer.validate_manifest(data)
        for key, value in (("source_commit", "f" * 39), ("purpose", "production"), ("schema_version", 2)):
            data = manifest(); data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                signer.validate_manifest(data)
        for key in ("version", "sha256"):
            data = manifest(); data["archives"][4][key] = data["archives"][0][key]
            with self.subTest(reused=key), self.assertRaises(ValueError):
                signer.validate_manifest(data)

    def test_paths_reject_traversal_absolute_aliases_and_wrong_archive_types(self):
        for path in ("../x.pkg.tar.gz", "/x.pkg.tar.gz", "a/../x.pkg.tar.gz", "a//x.pkg.tar.gz",
                     "./x.pkg.tar.gz", "a\\x.pkg.tar.gz", "x\n.pkg.tar.gz", "x.txt", ""):
            data = manifest(); data["archives"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                signer.validate_manifest(data)

    def test_read_json_hashes_and_parses_same_single_read(self):
        original = b'{"schema_version":1,"nested":{"field":"reviewed"}}'
        changed = b'{"schema_version":1,"nested":{"field":"changed"}}'
        with patch.object(Path, "read_bytes", side_effect=[original, changed]) as reader:
            result = signer.read_json(self.root / "manifest.json", hashlib.sha256(original).hexdigest())
        self.assertEqual(result["nested"]["field"], "reviewed")
        self.assertEqual(reader.call_count, 1)

    def test_wrong_hash_and_duplicate_keys_at_any_depth_rejected(self):
        for data in (b'{"purpose":"bad","purpose":"good"}', b'{"x":{"sha":"a","sha":"b"}}'):
            path = self.root / "pin.json"; path.write_bytes(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                signer.read_json(path, hashlib.sha256(data).hexdigest())
        with self.assertRaises(ValueError):
            signer.read_json(path, PIN)

    def test_regular_refuses_symlink_parent_fifo_and_hardlink(self):
        source = self.root / "one"; source.write_bytes(b"data")
        os.link(source, self.root / "two")
        with self.assertRaises(ValueError):
            signer.regular(source)
        source.unlink(); source.write_bytes(b"data")
        (self.root / "link").symlink_to(source)
        (self.root / "dirlink").symlink_to(self.root, target_is_directory=True)
        os.mkfifo(self.root / "pipe")
        for path in (self.root / "link", self.root / "dirlink/one", self.root / "pipe"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                signer.regular(path)


class GuardTests(Base):
    def test_every_capability_set_explicitly_zero_and_no_new_privileges_required(self):
        for field in signer.CAPABILITY_FIELDS:
            for value in (1, -1, "0", False, None):
                observed = probe(); observed["capabilities"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    signer.signer_guard(observed, contract())
            observed = probe(); del observed["capabilities"][field]
            with self.subTest(field=field, missing=True), self.assertRaises(ValueError):
                signer.signer_guard(observed, contract())
        for value in (0, False, "1", None):
            observed = probe(); observed["no_new_privs"] = value
            with self.subTest(nnp=value), self.assertRaises(ValueError):
                signer.signer_guard(observed, contract())

    def test_exact_standard_mount_identity_and_security_flags_required(self):
        for path in signer.STANDARD_MOUNTS:
            observed = probe(); observed["mounts"][path]["fs"] = "ext4"
            with self.subTest(path=path), self.assertRaises(ValueError):
                signer.signer_guard(observed, contract())
            for flag in signer.STANDARD_MOUNTS[path][1]:
                observed = probe(); observed["mounts"][path]["options"].remove(flag)
                with self.subTest(path=path, flag=flag), self.assertRaises(ValueError):
                    signer.signer_guard(observed, contract())
            observed = probe(); observed["mounts"][path]["root"] = "/private-home"
            with self.subTest(path=path, subtree=True), self.assertRaises(ValueError):
                signer.signer_guard(observed, contract())
        observed = probe(); del observed["mounts"]["/sys"]
        with self.assertRaises(ValueError):
            signer.signer_guard(observed, contract())

    def test_reviewed_unintended_mount_reproductions_refused(self):
        for path in ("/dev/dri", "/dev/snd", "/sys/private-home", "/proc/private", "/dev/input"):
            observed = probe(); observed["mounts"][path] = {"fs": "ext4", "options": ["rw"]}
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unexpected signer mount"):
                signer.signer_guard(observed, contract())

    def test_actual_devices_and_sockets_refused_even_without_extra_mounts(self):
        cases = []
        observed = probe(); observed["device_nodes"]["/dev/dri/card0"] = {"kind": "char", "major": 226, "minor": 0}; cases.append(observed)
        observed = probe(); observed["device_nodes"]["/inputs/device"] = {"kind": "block", "major": 8, "minor": 0}; cases.append(observed)
        observed = probe(); observed["device_nodes"]["/dev/null"]["major"] = 8; cases.append(observed)
        observed = probe(); del observed["device_nodes"]["/dev/null"]; cases.append(observed)
        observed = probe(); observed["sockets"] = ["/inputs/docker.sock"]; cases.append(observed)
        for observed in cases:
            with self.subTest(observed=observed), self.assertRaises(ValueError):
                signer.signer_guard(observed, contract())

    def test_exposed_node_observer_finds_actual_device_and_socket_types(self):
        def walk(root, followlinks=False):
            return [(root, [], ["card0"] if root == "/dev" else ["service.sock"] if root == "/inputs" else [])]
        def lstat(path):
            return SimpleNamespace(st_mode=signer.stat.S_IFCHR if str(path) == "/dev/card0" else signer.stat.S_IFSOCK,
                                   st_rdev=os.makedev(226, 0))
        with patch.object(signer.os, "walk", side_effect=walk), patch.object(Path, "lstat", lstat):
            devices, sockets = signer.exposed_nodes()
        self.assertEqual(devices, {"/dev/card0": {"kind": "char", "major": 226, "minor": 0}})
        self.assertEqual(sockets, ["/inputs/service.sock"])

    def test_unreviewed_device_symlink_and_unbounded_tree_refused(self):
        with patch.object(signer.os, "walk", return_value=[("/dev", [], ["link"])]), \
                patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=signer.stat.S_IFLNK)), \
                patch.object(signer.os, "readlink", return_value="/outside/device"), self.assertRaises(ValueError):
            signer.exposed_nodes()
        with patch.object(signer.os, "walk", return_value=[("/inputs", [], [str(i) for i in range(4097)])]), \
                patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=signer.stat.S_IFREG)), \
                self.assertRaisesRegex(ValueError, "exceeds bound"):
            signer.exposed_nodes()

    def test_duplicate_mount_and_conflicting_flags_refused(self):
        row = "1 0 0:1 / /tmp rw - tmpfs tmpfs rw\n"
        with self.assertRaisesRegex(ValueError, "duplicate"):
            signer.mount_table(row + row)
        observed = probe(); observed["mounts"]["/sys"]["options"].append("rw")
        with self.assertRaises(ValueError):
            signer.signer_guard(observed, contract())

    def test_valid_guard_and_each_real_boundary(self):
        signer.signer_guard(probe(), contract())
        for key, value in (("arch", "x86_64"), ("uid", 0), ("user", "root"), ("docker_marker", False),
                           ("interfaces", ["eth0", "lo"]), ("docker_socket", True), ("caps", 1),
                           ("no_new_privs", 0), ("nonce", "0" * 32)):
            observed = probe(); observed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                signer.signer_guard(observed, contract())

    def test_mount_flags_filesystems_and_private_nested_mounts_refused(self):
        for path, field, value in (("/", "options", ["rw"]), ("/", "fs", "ext4"),
                                   ("/inputs", "options", ["rw"]), ("/out", "options", ["ro"]),
                                   ("/tmp", "fs", "ext4"), ("/tmp", "options", ["ro"])):
            observed = probe(); observed["mounts"][path][field] = value
            with self.subTest(path=path, field=field), self.assertRaises(ValueError):
                signer.signer_guard(observed, contract())
        for path in ("/home/alarm", "/root/.gnupg", "/tmp/gpg", "/usr/local", "/var/cache"):
            observed = probe(); observed["mounts"][path] = {"fs": "ext4", "options": ["rw"]}
            with self.subTest(path=path), self.assertRaises(ValueError):
                signer.signer_guard(observed, contract())

    def test_unknown_and_nested_input_output_mounts_refused(self):
        for path in ("/run/secrets", "/secrets", "/inputs/archives", "/out/signatures", "/workspace"):
            observed = probe(); observed["mounts"][path] = {"fs": "ext4", "options": ["rw"]}
            with self.subTest(path=path), self.assertRaises(ValueError):
                signer.signer_guard(observed, contract())

    def test_spoofed_environment_cannot_reach_gpg_on_host(self):
        observed = probe(); observed.update(arch="x86_64", docker_marker=False)
        env = {"CACHY_ASAHI_TEST_SIGNER": contract()["nonce"], "CACHY_ASAHI_SIGNER_CONTRACT_SHA256": PIN,
               "USER": "alarm", "HOME": "/tmp", "CONTAINER": "docker"}
        with patch.dict(os.environ, env), patch.object(signer, "read_json", return_value=contract()), \
                patch.object(signer, "environment", return_value=observed), \
                patch.object(signer, "checked") as command:
            with self.assertRaises(ValueError):
                signer.inside()
            command.assert_not_called()

    def test_nonce_image_and_source_pin_contract_required(self):
        for key, value in (("purpose", "production"), ("schema_version", 0), ("nonce", "d" * 31),
                           ("image_id", "alarm:latest"), ("entry_sha256", "bad"), ("manifest_sha256", "bad")):
            data = contract(); data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                signer.signer_guard(probe(), data)

    def inside_mocks(self, data, pin_override=None):
        def sha(path):
            value = str(path).removeprefix("/inputs/")
            if value == "runner/sign_fixture.py":
                return PIN
            if value in contract()["helpers_sha256"]:
                return pin_override or contract()["helpers_sha256"][value]
            for row in data["archives"]:
                if value == "archives/" + row["path"]:
                    return row["sha256"]
            raise AssertionError("unexpected source hash read: " + value)
        return (patch.object(signer, "__file__", "/inputs/runner/sign_fixture.py"),
                patch.object(signer, "read_json", side_effect=[contract(), data]),
                patch.object(signer, "environment", return_value=probe()),
                patch.object(signer, "regular"), patch.object(signer.native, "sha", side_effect=sha),
                patch.object(Path, "iterdir", return_value=iter(())), patch.object(signer, "artifact_bind"))

    def test_helper_source_drift_rejected_before_commands(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for mock in self.inside_mocks(manifest(), pin_override="0" * 64):
                stack.enter_context(mock)
            command = stack.enter_context(patch.object(signer, "checked"))
            with self.assertRaisesRegex(ValueError, "helper source drift"):
                signer.inside()
            command.assert_not_called()

    def test_alpm_downgrade_and_equal_versions_rejected_before_key_generation(self):
        from contextlib import ExitStack
        for comparison in ("-1\n", "0\n"):
            with self.subTest(comparison=comparison), ExitStack() as stack:
                for mock in self.inside_mocks(manifest()):
                    stack.enter_context(mock)
                command = stack.enter_context(patch.object(signer, "checked", return_value=comparison))
                with self.assertRaisesRegex(ValueError, "greater than original"):
                    signer.inside()
                self.assertEqual(command.call_count, 1)
                self.assertEqual(command.call_args.args[0][0], "vercmp")


class ArtifactTests(Base):
    def test_artifact_identity_uses_actual_archive_metadata(self):
        row = manifest()["archives"][0]
        archive = self.archive(self.root / "sample.pkg.tar.gz", row)
        self.assertFalse(signer.artifact_bind(archive, row)["errors"])
        for key, value in (("pkgname", signer.native.RECIPES[1]), ("pkgver", "2-1"),
                           ("arch", "aarch64"), ("license", "GPL")):
            self.archive(archive, row, {key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                signer.artifact_bind(archive, row)


class PublicKeyTests(Base):
    def listing(self, validity="u", expiry=186400, identity="CACHY-ASAHI TEST ONLY"):
        return (f"pub:{validity}:2048:1:ID:100000:{expiry}:::x:\n"
                f"fpr:::::::::{FP}:\n" +
                ":".join(["uid", "u", "", "", "", "100000", "", "", "", identity, ""]) + "\n")

    def test_single_fresh_expiring_test_identity_required(self):
        valid = self.listing()
        with patch.object(signer.time, "time", return_value=100000), \
                patch.object(signer, "checked", return_value=valid):
            self.assertEqual(signer.fingerprint(self.root), (FP, 186400))
        for text in (self.listing(validity="r"), self.listing(validity="e"),
                     self.listing(expiry=100000), self.listing(expiry=190001),
                     self.listing(identity="ordinary production signer"), valid + valid,
                     valid.replace(FP, "SHORT")):
            with self.subTest(text=text), patch.object(signer.time, "time", return_value=100000), \
                    patch.object(signer, "checked", return_value=text), self.assertRaises(ValueError):
                signer.fingerprint(self.root)

    def test_truncated_packet_lengths_have_controlled_rejection(self):
        for packets in (b"\xc6", b"\xc6\xc0", b"\xc6\xff\0", b"\x99\0"):
            with self.subTest(packets=packets), self.assertRaises(ValueError):
                signer.public_certificate(public_certificate(packets))

    def test_install_hooks_and_elf_cannot_be_test_signed(self):
        row = manifest()["archives"][0]
        for extras in (((".INSTALL", b"post_install() { :; }"),),
                       (("usr/bin/code", b"\x7fELF" + b"\0" * 60),)):
            archive = self.archive(self.root / "sample.pkg.tar.gz", row, extras=extras)
            with self.subTest(extras=extras), self.assertRaises(ValueError):
                signer.artifact_bind(archive, row)


class PublicExportTests(Base):
    def setUp(self):
        super().setUp()
        self.inputs = self.root / "inputs"; self.inputs.mkdir()
        self.public = self.root / "public"; self.public.mkdir()
        self.data = manifest()
        self.expiry = int(time.time()) + 86400
        self.receipt = {"status": signer.STATUS, "purpose": signer.PURPOSE, "fingerprint": FP,
                        "expiry": self.expiry, "production_credentials_used": False,
                        "signatures": {}, "contract": contract(), "guard": probe(),
                        "hardware_status": "NOT RUN"}
        cert = self.public / "public-key.asc"
        cert.write_bytes(public_certificate())
        self.receipt["public_certificate_sha256"] = signer.native.sha(cert)
        for row in self.data["archives"]:
            self.archive(self.inputs / "archives" / row["path"], row)
            signature = self.public / "signatures" / (row["path"] + ".sig")
            signature.parent.mkdir(parents=True, exist_ok=True)
            signature.write_bytes(b"MOCK DETACHED SIGNATURE")
            self.receipt["signatures"][row["path"]] = {"archive_sha256": row["sha256"],
                                                       "signature_sha256": signer.native.sha(signature),
                                                       "status": VALID}
        self.write_receipt()

    def write_receipt(self):
        (self.public / "result.json").write_text(json.dumps(self.receipt))

    def verify(self):
        with patch.object(signer, "fingerprint", return_value=(FP, self.expiry)), \
                patch.object(signer, "checked", return_value=VALID) as command:
            result = signer.verify_exports(self.public, self.inputs, self.data)
            self.assertFalse(any("--generate-key" in call.args[0] or "--quick-generate-key" in call.args[0]
                                 for call in command.call_args_list))
            return result

    def test_exact_public_exports_accepted_with_mocked_public_only_gpg(self):
        self.assertEqual(self.verify()["status"], signer.STATUS)

    def test_extra_private_files_symlinks_and_missing_signatures_rejected(self):
        for name in ("secret-key.asc", "nested/.gnupg/private-keys-v1.d/state.txt"):
            path = self.public / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"private state")
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify()
            path.unlink()
            for parent in path.parents:
                if parent == self.public:
                    break
                if not any(parent.iterdir()):
                    parent.rmdir()
        signature = self.public / "signatures" / (self.data["archives"][0]["path"] + ".sig")
        signature.unlink()
        signature.symlink_to(self.root / "outside")
        with self.assertRaises(ValueError):
            self.verify()

    def test_extra_empty_private_or_unreviewed_directories_refused(self):
        for name in ("nested/.gnupg", "secret", "home/alarm", "unexpected"):
            path = self.public / name; path.mkdir(parents=True)
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.verify()
            path.rmdir()
            for parent in path.parents:
                if parent == self.public:
                    break
                if not any(parent.iterdir()):
                    parent.rmdir()

    def test_duplicate_oversized_private_or_extra_receipt_fields_refused(self):
        original = (self.public / "result.json").read_bytes()
        for payload in (original[:-1] + b',"status":"TEST-SIGNATURES PASS"}',
                        b" " * (signer.LIMIT + 1),
                        original.replace(b'"TEST-ONLY-integration-signatures"', b'"PRIVATE KEY"'),
                        original[:-1] + b',"secret":"PRIVATE PAYLOAD"}'):
            (self.public / "result.json").write_bytes(payload)
            with self.subTest(payload=payload[:50]), self.assertRaises(ValueError):
                self.verify()
        (self.public / "result.json").write_bytes(original)

    def test_nested_unknown_fields_and_forged_guard_receipts_refused(self):
        original = json.loads(json.dumps(self.receipt))
        row = self.data["archives"][0]
        records = (self.receipt["contract"], self.receipt["contract"]["helpers_sha256"],
                   self.receipt["guard"], self.receipt["guard"]["mounts"]["/"],
                   self.receipt["signatures"][row["path"]])
        for record in records:
            record["secret"] = "UNREVIEWED"
            self.write_receipt()
            with self.subTest(keys=list(record)), self.assertRaises(ValueError):
                self.verify()
            del record["secret"]
        self.receipt["signatures"]["unknown.pkg.tar.gz"] = {}
        self.write_receipt()
        with self.assertRaises(ValueError):
            self.verify()
        self.receipt = original
        self.receipt["guard"]["uid"] = 0
        self.write_receipt()
        with self.assertRaises(ValueError):
            self.verify()
        self.receipt = original
        self.receipt["guard"]["uid"] = 1000
        self.receipt["signatures"][row["path"]]["status"] = VALID.replace(FP, "B" * 40)
        self.write_receipt()
        with self.assertRaises(ValueError):
            self.verify()

    def test_certificate_receipt_identity_and_signature_bindings_rejected(self):
        for field, value in (("public_certificate_sha256", "0" * 64), ("fingerprint", "B" * 40),
                             ("purpose", "production"), ("production_credentials_used", True),
                             ("status", "FAIL"), ("expiry", self.expiry + 1)):
            original = self.receipt[field]; self.receipt[field] = value; self.write_receipt()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify()
            self.receipt[field] = original
        row = self.data["archives"][0]
        for field in ("archive_sha256", "signature_sha256"):
            record = self.receipt["signatures"][row["path"]]
            old = record[field]; record[field] = "0" * 64; self.write_receipt()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.verify()
            record[field] = old
        self.write_receipt()

    def test_matching_hash_and_signature_do_not_bypass_actual_package_identity(self):
        row = self.data["archives"][0]
        path = self.inputs / "archives" / row["path"]
        self.archive(path, row, {"pkgname": signer.native.RECIPES[1]})
        self.receipt["signatures"][row["path"]]["archive_sha256"] = row["sha256"]
        self.write_receipt()
        with self.assertRaises(ValueError):
            self.verify()

    def test_archive_changed_after_signing_and_wrong_signature_signer_refused(self):
        row = self.data["archives"][0]
        path = self.inputs / "archives" / row["path"]
        original = path.read_bytes(); path.write_bytes(b"changed archive")
        with self.assertRaises(ValueError):
            self.verify()
        path.write_bytes(original)
        with patch.object(signer, "fingerprint", return_value=(FP, self.receipt["expiry"])), \
                patch.object(signer, "checked", return_value=VALID.replace(FP, "B" * 40)):
            with self.assertRaises(ValueError):
                signer.verify_exports(self.public, self.inputs, self.data)

    def test_private_certificate_or_oversized_signature_refused(self):
        cert = self.public / "public-key.asc"; cert.write_bytes(b"-----BEGIN PGP PRIVATE KEY BLOCK-----")
        self.receipt["public_certificate_sha256"] = signer.native.sha(cert); self.write_receipt()
        with self.assertRaises(ValueError):
            self.verify()
        cert.write_bytes(public_certificate())
        self.receipt["public_certificate_sha256"] = signer.native.sha(cert)
        row = self.data["archives"][0]
        signature = self.public / "signatures" / (row["path"] + ".sig")
        signature.write_bytes(b"x" * 8193)
        self.receipt["signatures"][row["path"]]["signature_sha256"] = signer.native.sha(signature)
        self.write_receipt()
        with self.assertRaises(ValueError):
            self.verify()

    def test_private_packets_cannot_hide_inside_public_certificate_armor(self):
        cert = self.public / "public-key.asc"
        for packet in (b"\xc5\x01x", b"\xc7\x01x", b"\xc9\x01x", b"\xcb\x01x"):
            cert.write_bytes(public_certificate(b"\xc6\x01x\xcd\x01x\xc2\x01x" + packet))
            self.receipt["public_certificate_sha256"] = signer.native.sha(cert)
            self.write_receipt()
            with self.subTest(packet=packet), self.assertRaises(ValueError):
                self.verify()


class CancellationCleanupTests(Base):
    NAME = "cachy-asahi-test-signer-" + "d" * 32

    def result(self, code=0, output=b""):
        return subprocess.CompletedProcess([], code, output, b"")

    def test_remove_requires_success_and_independent_absence(self):
        with patch.object(signer, "command_result", side_effect=[self.result(output=self.NAME.encode()),
                         self.result(), self.result()]) as command:
            result = signer.remove_container(self.NAME)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["container_absent"])
        self.assertEqual(command.call_args_list[1].args[0], ["docker", "rm", "-f", self.NAME])
        self.assertTrue(all(call.args[1] == 10 for call in command.call_args_list))
        self.assertIn("name=^/" + self.NAME + "$", command.call_args_list[2].args[0])

    def test_failed_removal_cannot_pass_even_if_absence_query_succeeds(self):
        with patch.object(signer, "command_result", side_effect=[self.result(output=self.NAME.encode()),
                         self.result(1), self.result()]):
            result = signer.remove_container(self.NAME)
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(result["container_absent"])

    def test_removal_failure_remains_visible_when_later_query_proves_absence(self):
        with patch.object(signer, "command_result", side_effect=[self.result(output=self.NAME.encode()),
                         self.result(1), self.result(output=self.NAME.encode()), self.result()]):
            result = signer.remove_container(self.NAME)
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(result["container_absent"])

    def test_existing_container_or_unverified_daemon_query_blocks_pass(self):
        for reply in (self.result(output=self.NAME.encode()), self.result(1)):
            with self.subTest(reply=reply), patch.object(signer, "command_result", return_value=reply) as command:
                result = signer.remove_container(self.NAME)
                self.assertEqual(result["status"], "FAIL")
                self.assertEqual(len(result["attempts"]), 2)
                self.assertEqual(command.call_count, 6)

    def test_auto_removed_container_verified_without_redundant_removal(self):
        with patch.object(signer, "command_result", return_value=self.result()) as command:
            result = signer.remove_container(self.NAME)
        self.assertEqual(result["status"], "PASS")
        self.assertTrue(result["already_absent"])
        self.assertEqual(command.call_count, 1)

    def test_timeout_cleanup_is_bounded_and_records_safe_failure(self):
        with patch.object(signer, "command_result", side_effect=subprocess.TimeoutExpired("SECRET", 10)) as command:
            result = signer.remove_container(self.NAME)
        self.assertEqual(command.call_count, 2)
        self.assertEqual(result["status"], "FAIL")
        self.assertNotIn("SECRET", json.dumps(result))

    def test_other_container_names_refused_before_any_command(self):
        with patch.object(signer, "command_result") as command, self.assertRaises(ValueError):
            signer.remove_container("unrelated-container")
        command.assert_not_called()

    def test_sigterm_becomes_interruption_and_handler_restored(self):
        before = signal.getsignal(signal.SIGTERM)
        with self.assertRaises(KeyboardInterrupt):
            with signer.cancellation_scope():
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)

    def test_child_timeout_and_interrupt_stop_process_group_and_finalize_log(self):
        for error in (KeyboardInterrupt(), subprocess.TimeoutExpired("fixture", 1)):
            process = Mock(pid=987654, returncode=0)
            process.wait.side_effect = [error, 0]
            with self.subTest(error=type(error).__name__), patch.object(signer.subprocess, "Popen", return_value=process) as spawn, \
                    patch.object(signer.os, "killpg") as kill, self.assertRaises(type(error)):
                signer.command_result(["fixture"], 1, self.root / "cancelled.log")
            self.assertTrue(spawn.call_args.kwargs["start_new_session"])
            self.assertEqual(kill.call_args_list[0].args, (987654, signal.SIGTERM))
            self.assertEqual(kill.call_args_list[-1].args, (987654, signal.SIGKILL))
            self.assertTrue((self.root / "cancelled.log").is_file())

    def test_unresponsive_group_escalates_to_sigkill(self):
        process = Mock(pid=987654)
        process.wait.side_effect = [subprocess.TimeoutExpired("fixture", 5), 0]
        with patch.object(signer.os, "killpg") as kill:
            signer.stop_group(process)
        self.assertEqual([call.args[1] for call in kill.call_args_list],
                         [signal.SIGTERM, signal.SIGKILL, signal.SIGKILL])

    def test_ephemeral_agent_cleanup_runs_after_verification_failure(self):
        with patch.object(signer, "checked") as checked:
            with self.assertRaisesRegex(ValueError, "fixture"):
                with signer.gpg_home("mock-") as home:
                    raise ValueError("fixture")
        self.assertEqual(checked.call_args.args[0], ["gpgconf", "--homedir", str(home), "--kill", "all"])
        self.assertFalse(home.exists())

    def args(self):
        data = manifest()
        for row in data["archives"]:
            self.archive(self.root / "inputs" / row["path"], row)
        path = self.root / "inputs/manifest.json"; path.write_text(json.dumps(data))
        return SimpleNamespace(image="sha256:" + PIN, manifest=path,
                               manifest_sha256=signer.native.sha(path), output=self.root / "stage", timeout=180)

    def run_host(self, cleanup, failure=None):
        args = self.args()
        def run(command, log=None, timeout=180):
            if command[:3] == ["docker", "image", "inspect"]:
                return json.dumps([{"Architecture": "arm64", "Os": "linux", "Id": args.image}])
            self.assertEqual(command[:2], ["docker", "run"])
            if failure:
                raise failure
            return ""
        def receipt(public, inputs, data):
            return {"contract": json.loads((inputs / "contract.json").read_text()), "fingerprint": FP, "expiry": 186400}
        with patch.object(signer, "host_probe"), patch.object(signer, "run", side_effect=run), \
                patch.object(signer, "verify_exports", side_effect=receipt), \
                patch.object(signer, "remove_container", side_effect=cleanup if isinstance(cleanup, BaseException) else None,
                             return_value=cleanup), patch("sys.stdout", new=io.StringIO()), patch("sys.stderr", new=io.StringIO()):
            status = signer.host(args)
        return status, json.loads((args.output / "provenance.json").read_text())

    def test_success_requires_verified_cleanup(self):
        status, record = self.run_host({"status": "PASS", "container_absent": True})
        self.assertEqual(status, 0)
        self.assertEqual(record["status"], signer.STATUS)
        self.assertEqual(record["cleanup"]["status"], "PASS")

    def test_successful_signing_cleanup_failure_overrides_pass_and_saves_evidence(self):
        for cleanup in ({"status": "FAIL", "container_absent": False}, subprocess.TimeoutExpired("SECRET", 30)):
            with self.subTest(cleanup=cleanup):
                status, record = self.run_host(cleanup)
                self.assertEqual(status, 1)
                self.assertEqual(record["status"], "FAIL")
                self.assertEqual(record["cleanup"]["status"], "FAIL")
                self.assertNotIn("SECRET", json.dumps(record))
                import shutil
                shutil.rmtree(self.root / "stage")

    def test_interruption_preserves_failure_and_cleanup_provenance(self):
        for error in (KeyboardInterrupt("SECRET"), ValueError("SECRET")):
            with self.subTest(error=type(error).__name__):
                status, record = self.run_host({"status": "FAIL", "container_absent": False}, error)
                self.assertEqual(status, 1)
                self.assertEqual(record["status"], "FAIL")
                self.assertIn(type(error).__name__, record["error"])
                self.assertEqual(record["cleanup"]["status"], "FAIL")
                self.assertNotIn("SECRET", json.dumps(record))
                import shutil
                shutil.rmtree(self.root / "stage")


if __name__ == "__main__":
    unittest.main()
