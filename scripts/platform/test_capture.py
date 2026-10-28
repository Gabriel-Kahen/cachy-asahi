# SPDX-License-Identifier: MIT
"""Small untrusted-data fixtures; no network, image mounts or installation."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

spec = importlib.util.spec_from_file_location("platform_capture", Path(__file__).with_name("capture.py"))
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def descriptor(name="linux-asahi", version="6.18-1", arch="aarch64"):
    return f"%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%ARCH%\n{arch}\n".encode()


def signature_status(primary=capture.FINGERPRINT, digest="8", signer="A" * 40):
    return f"[GNUPG:] VALIDSIG {signer} 2026-10-11 1791676800 0 4 0 22 {digest} 00 {primary}\n".encode()


class Response(io.BytesIO):
    def __init__(self, data=b"payload", *, status=200, url="https://mirror.example/data?secret=redacted", headers=None):
        super().__init__(data)
        self.status, self.url = status, url
        self.headers = headers or {}


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def zip_fixture(self, changes=None, *, omit=None, duplicate=None):
        rootfs = bytearray(1100)
        rootfs[1080:1082] = b"\x53\xef"
        members = {"esp/": b"", "esp/EFI/": b"", "esp/EFI/BOOT/": b"", "esp/m1n1/": b"",
                   "esp/EFI/BOOT/BOOTAA64.EFI": b"efi", "esp/m1n1/boot.bin": b"boot", "root.img": bytes(rootfs)}
        members.update(changes or {})
        if omit:
            del members[omit]
        archive = self.root / "image.zip"
        with zipfile.ZipFile(archive, "w") as out:
            for name, data in members.items():
                item = zipfile.ZipInfo(name)
                item.create_system = 3
                item.external_attr = ((0o040755 if name.endswith("/") else 0o100644) << 16)
                out.writestr(item, data)
            if duplicate:
                # Duplicate logical names can conceal a second payload.
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    out.writestr(duplicate, members[duplicate])
        destination = self.root / "unpacked"
        destination.mkdir(mode=0o700)
        return archive, destination

    def receipt_fixture(self):
        directory = self.root / "retained"
        directory.mkdir(mode=0o700)
        source_names = ("asahi-alarm.asc", "asahi-alarm.db", "asahi-alarm.db.sig",
                        "asahi-alarm.files", "asahi-alarm.files.sig", "installer-main.py", "installer-v0.9.2.tar.gz")
        sources, files = {}, {}
        for name in source_names:
            data = ("fixture " + name).encode()
            (directory / name).write_bytes(data)
            os.chmod(directory / name, 0o600)
            sources[name] = {"url": "https://asahi-alarm.org/" + name, "max_bytes": 1024, "sha256": sha(data)}
            files[name] = {"url": sources[name]["url"], "bytes": len(data), "sha256": sha(data),
                           "predeclared_sha256": sha(data), "transport_host": "asahi-alarm.org",
                           "advertised_bytes": len(data), "last_modified": None}
        (self.root / "sources.json").write_text(json.dumps(sources))
        self.enterContext(patch.object(capture, "__file__", str(self.root / "capture.py")))
        status = {"status": "cryptographic-signature-valid", "primary_fingerprint": capture.FINGERPRINT,
                  "owner_authentication": "same-organization-pinned-source-only", "independent_owner_trust_accepted": False}
        self.enterContext(patch.object(capture, "verify_signature", return_value=status))
        installer = {"selected_member_sha256": {"src/main.py": sha(b"fixture installer-main.py")},
                     "main_equals_upstream_tag": True, "complete_source_correspondence_accepted": False,
                     "installer_executed": False}
        self.enterContext(patch.object(capture, "installer_inventory", return_value=installer))
        receipt = {"schema_version": 1, "status": "data-captured-not-installation-accepted", "files": files,
                   "source_pins": {"community": capture.ALARM_PIN, "installer": capture.INSTALLER_PIN,
                                   "keyring": capture.KEY_PIN, "recipes": capture.RECIPE_PIN},
                   "captured_utc": "2026-10-11T12:00:00Z", "system_mutation": False,
                   "installation_accepted": False, "hardware_accepted": False,
                   "installer_inventory": installer,
                   "repository_signatures": {name: dict(status) for name in ("asahi-alarm.db", "asahi-alarm.files")}}
        return directory, receipt

    def put_receipt(self, directory, receipt):
        (directory / "capture.json").write_text(json.dumps(receipt))
        os.chmod(directory / "capture.json", 0o600)

    def image_receipt_fixture(self, *, pending=False):
        directory, receipt = self.receipt_fixture()
        archive, unused = self.zip_fixture()
        unused.rmdir()
        archive = archive.rename(directory / "asahi-base.zip")
        os.chmod(archive, 0o600)
        receipt["files"][archive.name] = {"bytes": archive.stat().st_size, "sha256": capture.digest(archive),
                                         "url": "https://asahi-alarm.org/asahi-base.zip", "predeclared_sha256": None}
        receipt["files"].update(capture.unpack_image(archive, directory))
        inventory = {"kind": "observed-image-local-package-metadata", "packages": [], "platform": {},
                     "dependency_transaction_accepted": False, "hardware_accepted": False}
        self.enterContext(patch.object(capture, "image_inventory", return_value=inventory))
        if pending:
            receipt["status"] = "capture-incomplete"
            receipt["error"] = "ValueError: legacy parser rejected empty directory size"
        else:
            path = directory / "image-inventory.json"
            capture.write_json(path, inventory)
            receipt["files"][path.name] = {"bytes": path.stat().st_size, "sha256": capture.digest(path)}
            receipt["image_authentication"] = "observed-HTTPS-bytes-no-independent-image-signature"
        self.put_receipt(directory, receipt)
        return directory, receipt, inventory

    def installer_fixture(self, entries):
        archive = self.root / "installer.tar.gz"
        with tarfile.open(archive, "w:gz") as out:
            for name, data in entries:
                item = tarfile.TarInfo(name)
                item.size = len(data)
                out.addfile(item, io.BytesIO(data))
        expected = self.root / "main.py"
        expected.write_bytes(b"upstream fixture")
        return archive, expected

    def test_descriptor_valid_preserves_dependencies(self):
        fields = capture.parse_desc(descriptor() + b"\n%DEPENDS%\nm1n1>=1\nmesa\n")
        self.assertEqual(fields["NAME"], ["linux-asahi"])
        self.assertEqual(fields["DEPENDS"], ["m1n1>=1", "mesa"])

    def test_descriptor_requires_one_identity_value(self):
        for data in (b"%NAME%\nlinux-asahi\n", descriptor(name=""), descriptor(version=""),
                     descriptor(arch=""), descriptor(name="linux-asahi\nother"), descriptor(version="../1")):
            with self.subTest(data=data), self.assertRaises(ValueError):
                capture.parse_desc(data)

    def test_descriptor_duplicate_invalid_fields_and_values(self):
        for suffix in (b"%NAME%\nother\n", b"%bad%\nvalue\n", b"%DEPENDS%\nmesa\x00evil\n"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                capture.parse_desc(descriptor() + suffix)
        with self.assertRaises(ValueError):
            capture.parse_desc(b"orphan\n" + descriptor())

    def test_descriptor_size_and_utf8_bounds(self):
        for data in (b"x" * (256 * 1024 + 1), descriptor() + b"\xff"):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                capture.parse_desc(data)

    def test_json_duplicate_top_level_and_nested_keys_refused(self):
        path = self.root / "input.json"
        for data in (b'{"status":"capture-incomplete","status":"data-captured-not-installation-accepted"}',
                     b'{"files":{"source":{"bytes":1,"bytes":2}}}'):
            with self.subTest(data=data):
                path.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
                    capture.load_json(path)
                self.assertEqual(path.read_bytes(), data)

    def test_json_input_limit_counts_utf8_bytes_and_accepts_exact_boundary(self):
        path = self.root / "input.json"
        data = '{"name":"é"}'.encode("utf-8")
        path.write_bytes(data)
        self.assertEqual(capture.load_json(path, maximum=len(data)), {"name": "é"})
        with self.assertRaisesRegex(ValueError, "JSON input bound"):
            capture.load_json(path, maximum=len(data) - 1)
        self.assertEqual(path.read_bytes(), data)

    def test_write_json_limits_indented_serialization_before_creating_file(self):
        value = {"values": list(range(20))}
        compact_size = len(json.dumps(value).encode())
        serialized_size = len((json.dumps(value, indent=2, sort_keys=True) + "\n").encode())
        self.assertLessEqual(compact_size, 128)
        self.assertGreater(serialized_size, 128)
        path = self.root / "oversized.json"
        with patch.object(capture, "MIB", 16), self.assertRaisesRegex(ValueError, "serialized metadata bound"):
            capture.write_json(path, value)
        self.assertFalse(path.exists())
        path.write_bytes(b"existing content")
        with patch.object(capture, "MIB", 16), self.assertRaisesRegex(ValueError, "serialized metadata bound"):
            capture.write_json(path, value)
        self.assertEqual(path.read_bytes(), b"existing content")

    def test_source_manifest_rejects_unsafe_origins_names_bounds_and_fields(self):
        self.enterContext(patch.object(capture, "__file__", str(self.root / "capture.py")))
        base = {"url": "https://asahi-alarm.org/source", "max_bytes": 1024, "sha256": "a" * 64}
        cases = [("../escape", base), ("capture.json", base), ("root.img", base)]
        cases += [("source", {**base, "url": url}) for url in (
            "http://asahi-alarm.org/source", "https://attacker.example/source",
            "https://user:secret@asahi-alarm.org/source", "https://asahi-alarm.org/source?token=secret",
            "https://asahi-alarm.org/source#fragment")]
        cases += [("source", {**base, "max_bytes": bound}) for bound in (True, 0, -1, 33 * capture.MIB)]
        cases += [("source", {**base, "sha256": "Z" * 64}), ("source", {**base, "extra": "field"})]
        for name, source in cases:
            with self.subTest(name=name, source=source):
                (self.root / "sources.json").write_text(json.dumps({name: source}))
                with self.assertRaises(ValueError):
                    capture.load_sources()

    def test_installer_inventory_compares_main_without_executing_it(self):
        archive, expected = self.installer_fixture([("installer/src/main.py", b"upstream fixture"),
                                                    ("installer/LICENSE", b"license"),
                                                    ("installer/execute-me", b"raise RuntimeError('must never run')")])
        inventory = capture.installer_inventory(archive, expected)
        self.assertTrue(inventory["main_equals_upstream_tag"])
        self.assertIs(inventory["installer_executed"], False)
        self.assertIs(inventory["complete_source_correspondence_accepted"], False)
        self.assertEqual(set(inventory["selected_member_sha256"]), {"installer/src/main.py", "installer/LICENSE"})
        expected.write_bytes(b"different source")
        self.assertFalse(capture.installer_inventory(archive, expected)["main_equals_upstream_tag"])

    def test_installer_inventory_refuses_missing_or_duplicate_main(self):
        for entries in ([("LICENSE", b"license")], [("a/src/main.py", b"main"), ("b/src/main.py", b"other")]):
            with self.subTest(entries=entries):
                archive, expected = self.installer_fixture(entries)
                with self.assertRaisesRegex(ValueError, "one installer main"):
                    capture.installer_inventory(archive, expected)

    def test_installer_flattened_main_excludes_bundled_unittest_main(self):
        archive, expected = self.installer_fixture([("./main.py", b"upstream fixture"),
                                                    ("./LICENSE", b"license"),
                                                    ("./stdlib/unittest/main.py", b"bundled unittest entry point")])
        inventory = capture.installer_inventory(archive, expected)
        self.assertTrue(inventory["main_equals_upstream_tag"])
        self.assertEqual(inventory["selected_member_sha256"],
                         {"./main.py": sha(b"upstream fixture"), "./LICENSE": sha(b"license")})
        self.assertIs(inventory["installer_executed"], False)

    def test_installer_bundled_unittest_main_alone_is_not_core_main(self):
        archive, expected = self.installer_fixture([("./stdlib/unittest/main.py", b"upstream fixture")])
        with self.assertRaisesRegex(ValueError, "one installer main"):
            capture.installer_inventory(archive, expected)

    def test_image_inventory_observes_arm_metadata_without_acceptance(self):
        listing = b"/1/040755/0/0/./0/\n/2/040755/0/0/linux-asahi-6.18-1/0/\n"
        with patch.object(capture, "bounded_command", side_effect=[(listing, b"debugfs 1.47.3\n"), (descriptor(), b"debugfs 1.47.3\n")]):
            result = capture.image_inventory(self.root / "unused.img")
        self.assertEqual(result["platform"]["linux-asahi"]["ARCH"], ["aarch64"])
        self.assertEqual(result["packages"][0]["descriptor_sha256"], sha(descriptor()))
        self.assertIs(result["dependency_transaction_accepted"], False)
        self.assertIs(result["hardware_accepted"], False)

    def test_image_inventory_accepts_debugfs_empty_directory_sizes(self):
        listing = (b"/1/040755/0/0/.//\n/2/040755/0/0/..//\n"
                   b"/3/100644/0/0/ALPM_DB_VERSION/2/\n/4/040755/0/0/linux-asahi-6.18-1//\n")
        with patch.object(capture, "bounded_command", side_effect=[(listing, b"debugfs 1.47.3\n"), (descriptor(), b"")]) as command:
            result = capture.image_inventory(self.root / "unused.img")
        self.assertEqual([package["directory"] for package in result["packages"]], ["linux-asahi-6.18-1"])
        self.assertEqual(command.call_count, 2)

    def test_image_inventory_refuses_empty_size_on_non_directory(self):
        for name in ("linux-asahi-6.18-1", "ALPM_DB_VERSION"):
            listing = f"/1/100644/0/0/{name}//\n".encode()
            with self.subTest(name=name), patch.object(capture, "bounded_command", return_value=(listing, b"")) as command:
                with self.assertRaises(ValueError):
                    capture.image_inventory(self.root / "unused.img")
                self.assertEqual(command.call_count, 1)

    def test_image_inventory_refuses_read_diagnostics_and_malformed_listing(self):
        listing = b"/2/040755/0/0/linux-asahi-6.18-1/0/\n"
        cases = [(listing, b"debugfs 1.47.3\nFilesystem not open\n"),
                 (b"malformed listing\n", b""),
                 (b"/2/040755/0/0/unsafe name/0/\n", b""),
                 (b"/2/100644/0/0/linux-asahi-6.18-1/0/\n", b"")]
        for output, errors in cases:
            with self.subTest(output=output, errors=errors), patch.object(capture, "bounded_command", return_value=(output, errors)):
                with self.assertRaises(ValueError):
                    capture.image_inventory(self.root / "unused.img")

    def test_image_inventory_refuses_duplicates_non_arm_and_empty(self):
        line = b"/2/040755/0/0/linux-asahi-6.18-1/0/\n"
        cases = [[(b"", b"")], [(line, b""), (descriptor(arch="x86_64"), b"")],
                 [(line * 2, b""), (descriptor(), b"")],
                 [(line + b"/3/040755/0/0/other-1-1/0/\n", b""), (descriptor(), b""), (descriptor(), b"")]]
        for results in cases:
            with self.subTest(results=results), patch.object(capture, "bounded_command", side_effect=results):
                with self.assertRaises(ValueError):
                    capture.image_inventory(self.root / "unused.img")

    def test_zip_valid_layout_retains_exact_payload_hashes(self):
        archive, directory = self.zip_fixture()
        result = capture.unpack_image(archive, directory)
        self.assertEqual(set(result), {"root.img", "esp-boot.bin", "esp-BOOTAA64.EFI"})
        for name, reference in result.items():
            self.assertEqual(reference["sha256"], sha((directory / name).read_bytes()))
            self.assertEqual((directory / name).stat().st_mode & 0o777, 0o600)

    def test_zip_hashing_without_destination_creates_no_files(self):
        archive, directory = self.zip_fixture()
        before = {path.relative_to(self.root): path.stat().st_size for path in self.root.rglob("*")}
        result = capture.unpack_image(archive)
        after = {path.relative_to(self.root): path.stat().st_size for path in self.root.rglob("*")}
        self.assertEqual(before, after)
        self.assertEqual(list(directory.iterdir()), [])
        self.assertEqual(set(result), {"root.img", "esp-boot.bin", "esp-BOOTAA64.EFI"})
        with zipfile.ZipFile(archive) as source:
            for reference in result.values():
                data = source.read(reference["zip_member"])
                self.assertEqual(reference["bytes"], len(data))
                self.assertEqual(reference["sha256"], sha(data))

    def test_zip_path_traversal_and_unexpected_layout_refused(self):
        for name in ("../outside", "/tmp/outside", "esp/../../outside", "extra"):
            with self.subTest(name=name):
                archive, directory = self.zip_fixture({name: b"escape"})
                with self.assertRaisesRegex(ValueError, "layout"):
                    capture.unpack_image(archive, directory)
                self.assertEqual(list(directory.iterdir()), [])
                shutil.rmtree(directory)

    def test_zip_missing_and_duplicate_members_refused(self):
        for kwargs in ({"omit": "esp/"}, {"duplicate": "root.img"}):
            with self.subTest(kwargs=kwargs):
                archive, directory = self.zip_fixture(**kwargs)
                with self.assertRaisesRegex(ValueError, "layout"):
                    capture.unpack_image(archive, directory)
                shutil.rmtree(directory)

    def test_zip_symlink_and_special_member_refused(self):
        for mode in (0o120777, 0o020600, 0o060600, 0o010600):
            with self.subTest(mode=oct(mode)):
                archive, directory = self.zip_fixture()
                data = bytearray(archive.read_bytes())
                offset = data.index(b"PK\x01\x02")
                struct.pack_into("<I", data, offset + 38, mode << 16)
                archive.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "special"):
                    capture.unpack_image(archive, directory)
                self.assertEqual(list(directory.iterdir()), [])
                shutil.rmtree(directory)

    def test_zip_declared_unpack_budget_refused_without_allocating(self):
        archive, directory = self.zip_fixture()
        data = bytearray(archive.read_bytes())
        offset = data.index(b"PK\x01\x02")
        struct.pack_into("<I", data, offset + 24, 0xffffffff)
        archive.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "budget"):
            capture.unpack_image(archive, directory)
        self.assertEqual(list(directory.iterdir()), [])

    def test_zip_oversized_boot_payload_and_encryption_refused(self):
        for mutate in ("size", "encrypted"):
            with self.subTest(mutate=mutate):
                archive, directory = self.zip_fixture()
                data = bytearray(archive.read_bytes())
                offset = 0
                while True:
                    offset = data.index(b"PK\x01\x02", offset)
                    name_size = struct.unpack_from("<H", data, offset + 28)[0]
                    name = bytes(data[offset + 46:offset + 46 + name_size])
                    if name == b"esp/EFI/BOOT/BOOTAA64.EFI":
                        break
                    offset += 4
                if mutate == "size":
                    struct.pack_into("<I", data, offset + 24, 16 * capture.MIB + 1)
                else:
                    struct.pack_into("<H", data, offset + 8, 1)
                archive.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "oversized or encrypted"):
                    capture.unpack_image(archive, directory)
                shutil.rmtree(directory)

    def test_zip_non_ext_root_refused(self):
        archive, directory = self.zip_fixture({"root.img": b"not an ext image"})
        with self.assertRaisesRegex(ValueError, "ext filesystem"):
            capture.unpack_image(archive, directory)

    def test_signature_valid_primary_is_distinct_from_owner_authentication(self):
        with patch.object(capture, "bounded_command", side_effect=[(b"", b""), (signature_status(), b"")]) as command:
            status = capture.verify_signature(self.root, self.root / "cert", self.root / "sig", self.root / "db")
        self.assertEqual(status["primary_fingerprint"], capture.FINGERPRINT)
        self.assertIs(status["independent_owner_trust_accepted"], False)
        self.assertEqual(command.call_args_list[1].args[0][0], "gpgv")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_signature_rejects_wrong_primary_and_weak_hash(self):
        for status in (signature_status(primary="B" * 40), signature_status(digest="2"), signature_status(digest="1")):
            with self.subTest(status=status), patch.object(capture, "bounded_command", side_effect=[(b"", b""), (status, b"")]):
                with self.assertRaisesRegex(ValueError, "primary signer or weak digest"):
                    capture.verify_signature(self.root, self.root / "cert", self.root / "sig", self.root / "db")

    def test_signature_rejects_bad_expired_revoked_and_multiple_statuses(self):
        statuses = [signature_status() + f"[GNUPG:] {name} bad\n".encode()
                    for name in ("BADSIG", "ERRSIG", "EXPKEYSIG", "EXPSIG", "REVKEYSIG", "KEYEXPIRED", "SIGEXPIRED")]
        statuses += [b"", b"[GNUPG:] VALIDSIG short\n", signature_status() * 2]
        for status in statuses:
            with self.subTest(status=status), patch.object(capture, "bounded_command", side_effect=[(b"", b""), (status, b"")]):
                with self.assertRaises(ValueError):
                    capture.verify_signature(self.root, self.root / "cert", self.root / "sig", self.root / "db")

    def test_destination_refuses_outside_existing_and_low_space(self):
        with patch.object(capture, "ROOT", self.root):
            with self.assertRaises(ValueError):
                capture.private_destination(self.root / "outside")
            existing = self.root / "artifacts" / "exists"
            existing.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "absent"):
                capture.private_destination(existing)
            with patch.object(capture.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(100, 99, 1)):
                with self.assertRaisesRegex(ValueError, "reserve"):
                    capture.private_destination(self.root / "artifacts" / "low")

    def test_destination_refuses_symlink_ancestor(self):
        artifacts = self.root / "artifacts"
        artifacts.mkdir()
        (artifacts / "link").symlink_to(self.root, target_is_directory=True)
        with patch.object(capture, "ROOT", self.root), self.assertRaisesRegex(ValueError, "symlink"):
            capture.private_destination(artifacts / "link" / "new")

    def test_destination_is_private_on_success(self):
        with patch.object(capture, "ROOT", self.root), patch.object(capture.shutil, "disk_usage", return_value=shutil._ntuple_diskusage(20 * 1024**3, 0, 20 * 1024**3)):
            directory = capture.private_destination(self.root / "artifacts" / "new")
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_validate_fixture_and_preserve_not_accepted_classification(self):
        directory, receipt = self.receipt_fixture()
        self.put_receipt(directory, receipt)
        result = capture.validate(directory)
        self.assertIs(result["installation_accepted"], False)
        self.assertIs(result["hardware_accepted"], False)

    def test_validate_rejects_misclassified_receipt(self):
        directory, receipt = self.receipt_fixture()
        for field in ("system_mutation", "installation_accepted", "hardware_accepted"):
            for wrong in (True, 0, None):
                with self.subTest(field=field, wrong=wrong):
                    candidate = {**receipt, field: wrong}
                    self.put_receipt(directory, candidate)
                    with self.assertRaisesRegex(ValueError, "misclassified"):
                        capture.validate(directory)
        self.put_receipt(directory, {**receipt, "status": "capture-incomplete"})
        with self.assertRaisesRegex(ValueError, "incomplete"):
            capture.validate(directory)

    def test_validate_rejects_hash_and_size_tampering(self):
        directory, receipt = self.receipt_fixture()
        self.put_receipt(directory, receipt)
        path = directory / "installer-main.py"
        data = path.read_bytes()
        for payload in (data + b"extra", b"X" + data[1:]):
            with self.subTest(payload=payload):
                path.write_bytes(payload)
                with self.assertRaisesRegex(ValueError, "byte mismatch"):
                    capture.validate(directory)

    def test_validate_refuses_path_escape_and_receipt_self_reference(self):
        directory, receipt = self.receipt_fixture()
        for name in ("../outside", "/absolute", "capture.json", ".", ".."):
            with self.subTest(name=name):
                candidate = {**receipt, "files": {**receipt["files"], name: {"bytes": 0, "sha256": sha(b"")}}}
                self.put_receipt(directory, candidate)
                with self.assertRaises(ValueError):
                    capture.validate(directory)

    def test_validate_refuses_public_directory_symlink_and_hardlink(self):
        directory, receipt = self.receipt_fixture()
        self.put_receipt(directory, receipt)
        os.chmod(directory, 0o755)
        with self.assertRaisesRegex(ValueError, "private"):
            capture.validate(directory)
        os.chmod(directory, 0o700)
        path = directory / "installer-main.py"
        target = self.root / "target"
        path.rename(target)
        path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "regular file"):
            capture.validate(directory)
        path.unlink()
        os.link(target, path)
        with self.assertRaisesRegex(ValueError, "regular file"):
            capture.validate(directory)

    def test_validate_signature_receipt_must_match_reverification(self):
        directory, receipt = self.receipt_fixture()
        receipt["repository_signatures"]["asahi-alarm.db"]["independent_owner_trust_accepted"] = True
        self.put_receipt(directory, receipt)
        with self.assertRaisesRegex(ValueError, "signature receipt"):
            capture.validate(directory)

    def test_validate_refuses_omitted_required_file_and_untracked_file(self):
        directory, receipt = self.receipt_fixture()
        reference = receipt["files"].pop("asahi-alarm.asc")
        self.put_receipt(directory, receipt)
        with self.assertRaisesRegex(ValueError, "file set"):
            capture.validate(directory)
        receipt["files"]["asahi-alarm.asc"] = reference
        self.put_receipt(directory, receipt)
        (directory / "untracked").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "file set"):
            capture.validate(directory)

    def test_validate_refuses_source_pin_schema_url_and_digest_claim_drift(self):
        directory, receipt = self.receipt_fixture()
        for field, value in (("schema_version", 2), ("source_pins", {**capture.PINS, "installer": "0" * 40})):
            with self.subTest(field=field):
                self.put_receipt(directory, {**receipt, field: value})
                with self.assertRaisesRegex(ValueError, "schema/source pins"):
                    capture.validate(directory)
        for field, value in (("url", "https://attacker.example/source"), ("predeclared_sha256", "0" * 64)):
            with self.subTest(field=field):
                candidate = json.loads(json.dumps(receipt))
                candidate["files"]["installer-main.py"][field] = value
                self.put_receipt(directory, candidate)
                with self.assertRaisesRegex(ValueError, "pinned manifest"):
                    capture.validate(directory)

    def test_validate_refuses_boolean_float_and_other_schema_types_without_writes(self):
        directory, receipt = self.receipt_fixture()
        for version in (True, False, 1.0, 1.5, "1", None):
            with self.subTest(version=version):
                self.put_receipt(directory, {**receipt, "schema_version": version})
                before = {path.name: path.read_bytes() for path in directory.iterdir()}
                with self.assertRaisesRegex(ValueError, "schema/source pins"):
                    capture.validate(directory)
                self.assertEqual({path.name: path.read_bytes() for path in directory.iterdir()}, before)

    def test_validate_refuses_duplicate_receipt_keys_without_writes(self):
        directory, receipt = self.receipt_fixture()
        self.put_receipt(directory, receipt)
        path = directory / "capture.json"
        data = path.read_bytes()
        path.write_bytes(b'{"schema_version":2,' + data[1:])
        before = {entry.name: entry.read_bytes() for entry in directory.iterdir()}
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            capture.validate(directory)
        self.assertEqual({entry.name: entry.read_bytes() for entry in directory.iterdir()}, before)

    def test_validate_refuses_installer_inventory_claim_drift(self):
        directory, receipt = self.receipt_fixture()
        candidate = json.loads(json.dumps(receipt))
        candidate["installer_inventory"]["installer_executed"] = True
        self.put_receipt(directory, candidate)
        with self.assertRaisesRegex(ValueError, "installer source receipt"):
            capture.validate(directory)

    def test_validate_refuses_root_and_esp_payloads_not_derived_from_zip(self):
        for name in ("root.img", "esp-boot.bin", "esp-BOOTAA64.EFI"):
            with self.subTest(name=name):
                # Keep generic file/receipt hashes coherent to reach the ZIP binding check.
                directory, receipt, _ = self.image_receipt_fixture()
                path = directory / name
                data = path.read_bytes()
                path.write_bytes(b"X" + data[1:])
                receipt["files"][name]["sha256"] = capture.digest(path)
                self.put_receipt(directory, receipt)
                with self.assertRaisesRegex(ValueError, "ZIP derivation mismatch"):
                    capture.validate(directory)
                shutil.rmtree(directory)

    def test_complete_metadata_requires_full_retained_image_before_any_write(self):
        directory, receipt = self.receipt_fixture()
        receipt["status"] = "capture-incomplete"
        receipt["error"] = "ValueError: missing image"
        self.put_receipt(directory, receipt)
        previous = (directory / "capture.json").read_bytes()
        names = {path.name for path in directory.iterdir()}
        with self.assertRaisesRegex(ValueError, "full image required"):
            capture.complete_image_metadata(directory)
        self.assertEqual((directory / "capture.json").read_bytes(), previous)
        self.assertEqual({path.name for path in directory.iterdir()}, names)

    def test_complete_metadata_refuses_tampered_inputs_before_any_write(self):
        for name in ("asahi-alarm.db", "root.img", "esp-boot.bin", "asahi-base.zip"):
            with self.subTest(name=name):
                directory, _, _ = self.image_receipt_fixture(pending=True)
                previous = (directory / "capture.json").read_bytes()
                names = {path.name for path in directory.iterdir()}
                path = directory / name
                data = path.read_bytes()
                path.write_bytes(b"X" + data[1:])
                with self.assertRaisesRegex(ValueError, "byte mismatch"):
                    capture.complete_image_metadata(directory)
                self.assertEqual((directory / "capture.json").read_bytes(), previous)
                self.assertEqual({path.name for path in directory.iterdir()}, names)
                shutil.rmtree(directory)

    def test_complete_metadata_preserves_failure_receipt_and_no_acceptance(self):
        directory, receipt, inventory = self.image_receipt_fixture(pending=True)
        previous = (directory / "capture.json").read_bytes()
        expected_error = receipt["error"]
        result = capture.complete_image_metadata(directory)
        self.assertEqual(result["status"], "retained-image-metadata-completed")
        self.assertEqual(result["previous_error"], expected_error)
        self.assertIs(result["installation_accepted"], False)
        self.assertIs(result["hardware_accepted"], False)
        self.assertEqual((directory / "capture-incomplete.json").read_bytes(), previous)
        completed = json.loads((directory / "capture.json").read_text())
        self.assertEqual(completed["status"], "data-captured-not-installation-accepted")
        self.assertEqual(completed["previous_error"], expected_error)
        self.assertNotIn("error", completed)
        self.assertEqual(json.loads((directory / "image-inventory.json").read_text()), inventory)
        for field in ("system_mutation", "installation_accepted", "hardware_accepted"):
            self.assertIs(completed[field], False)
        for name in ("capture-incomplete.json", "image-inventory.json"):
            path = directory / name
            self.assertEqual(completed["files"][name], {"bytes": path.stat().st_size, "sha256": capture.digest(path)})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertFalse((directory / "capture.json.new").exists())
        self.assertIs(capture.validate(directory)["hardware_accepted"], False)
        with self.assertRaisesRegex(ValueError, "incomplete or misclassified"):
            capture.complete_image_metadata(directory)
        self.assertEqual((directory / "capture-incomplete.json").read_bytes(), previous)

    def test_download_success_retains_hash_mode_and_no_redirect_secrets(self):
        path = self.root / "source"
        with patch.object(capture.urllib.request, "urlopen", return_value=Response(headers={"Content-Length": "7"})):
            result = capture.download("https://source.example/data", path, 7, sha(b"payload"))
        self.assertEqual(path.read_bytes(), b"payload")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(result["sha256"], sha(b"payload"))
        self.assertEqual(result["transport_host"], "mirror.example")
        self.assertNotIn("secret", json.dumps(result))
        self.assertFalse((self.root / "source.partial").exists())

    def test_download_refuses_non_https_before_request(self):
        with patch.object(capture.urllib.request, "urlopen") as request:
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                capture.download("http://source.example/data", self.root / "source", 7)
        request.assert_not_called()

    def test_download_refuses_http_errors_insecure_redirect_and_bad_length(self):
        cases = ({"status": 404}, {"url": "http://mirror.example/data"},
                 {"headers": {"Content-Length": "8"}}, {"headers": {"Content-Length": "-1"}},
                 {"headers": {"Content-Length": "seven"}}, {"headers": {"Content-Length": "6"}})
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), patch.object(capture.urllib.request, "urlopen", return_value=Response(**kwargs)):
                with self.assertRaises(ValueError):
                    capture.download("https://source.example/data", self.root / "source", 7)
                self.assertEqual(list(self.root.iterdir()), [])

    def test_download_observed_byte_cap_and_digest_mismatch_clean_partial(self):
        for data, expected in ((b"12345678", None), (b"payload", "0" * 64)):
            with self.subTest(data=data), patch.object(capture.urllib.request, "urlopen", return_value=Response(data)):
                with self.assertRaises(ValueError):
                    capture.download("https://source.example/data", self.root / "source", 7, expected)
                self.assertEqual(list(self.root.iterdir()), [])

    def test_download_short_response_and_deadline_clean_partial(self):
        with patch.object(capture.urllib.request, "urlopen", return_value=Response(b"short", headers={"Content-Length": "7"})):
            with self.assertRaisesRegex(ValueError, "short"):
                capture.download("https://source.example/data", self.root / "source", 7)
        with patch.object(capture.urllib.request, "urlopen", return_value=Response()), patch.object(capture.time, "monotonic", side_effect=[0, 31]):
            with self.assertRaisesRegex(ValueError, "deadline"):
                capture.download("https://source.example/data", self.root / "source", 7, deadline=30)
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
