#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Camera receiver tests: synthetic metadata, never device or tool queries."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location("camera_probe_under_test", Path(__file__).with_name("probe.py"))
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def fixture(board="apple,j413"):
    return {"schema_version": 1, "purpose": "camera-metadata-observation",
            "origin": "controlled-fixture",
            "identity": {"board": board, "soc": "apple,t8112", "arch": "aarch64",
                         "page_size": 16384, "kernel_release": "fixture-kernel",
                         "kernel_source_revision": "a" * 40,
                         "kernel_image_sha256": "b" * 64,
                         "probe_source_sha256": "c" * 64,
                         "run_id": "fixture-run", "nonce": "d" * 32},
            "state": "observed", "backend": "v4l2",
            "devices": [{"id": "camera0", "driver": "fixture-driver", "state": "available",
                         "capabilities": ["VIDEO_CAPTURE", "STREAMING"],
                         "formats": [{"fourcc": "YUYV", "width": 1280, "height": 720,
                                      "fps_num": 30, "fps_den": 1}]}],
            "hardware_validation": "NOT RUN", "capture": "NOT RUN"}


class ReceiverTests(unittest.TestCase):
    def check_result(self, result):
        self.assertIn(result["status"], ("FAIL", "PASS-metadata"))
        for field in ("hardware_validation", "firmware_validation", "capture", "runtime_preview"):
            self.assertEqual(result[field], "NOT RUN")
        self.assertIs(result["device_access"], False)
        if result["status"] == "FAIL":
            self.assertIn(result["error"], {"schema", "identity", "bounds", "evidence-binding",
                          "no-device", "unsupported", "unknown", "unsafe-namespace",
                          "linked-namespace", "evidence-drift"})
        else:
            self.assertIsNone(result["error"])
        json.dumps(result, allow_nan=False)

    def receive(self, document, expected=None, raw=None, sha=None):
        raw = encoded(document) if raw is None else raw
        expected = copy.deepcopy(document["identity"] if expected is None else expected)
        before = copy.deepcopy(expected)
        result = probe.receive(raw, digest(raw) if sha is None else sha, expected)
        self.assertEqual(expected, before, "receiver changed expectation")
        self.check_result(result)
        return result

    def refused(self, result):
        self.check_result(result)
        self.assertEqual(result["status"], "FAIL")

    def test_both_primary_board_identities_are_metadata_only(self):
        for board in ("apple,j413", "apple,j415"):
            for origin in ("controlled-fixture", "captured-target-metadata"):
                with self.subTest(board=board, origin=origin):
                    document = fixture(board); document["origin"] = origin
                    result = self.receive(document)
                    self.assertEqual(result["status"], "PASS-metadata")

    def test_no_device_unsupported_and_unknown_are_explicit_failures(self):
        for state in ("no-device", "unsupported", "unknown"):
            with self.subTest(state=state):
                document = fixture(); document.update(state=state, devices=[])
                self.refused(self.receive(document))
        document = fixture(); document["devices"] = []
        self.refused(self.receive(document))

    def test_unusable_device_or_backend_never_passes(self):
        for field, value in (("state", "unsupported"), ("state", "unknown"),
                             ("capabilities", ["VIDEO_CAPTURE"]),
                             ("capabilities", ["STREAMING"]), ("formats", [])):
            with self.subTest(field=field, value=value):
                document = fixture(); document["devices"][0][field] = value
                self.refused(self.receive(document))
        for backend in ("unknown", "libcamera"):
            document = fixture(); document["backend"] = backend
            self.refused(self.receive(document))

    def test_source_run_nonce_kernel_and_board_crossbindings(self):
        expectation = fixture()["identity"]
        mutations = {"board": "apple,j415", "soc": "apple,t6020", "arch": "x86_64",
                     "page_size": 4096, "kernel_release": "foreign-kernel",
                     "kernel_source_revision": "1" * 40, "kernel_image_sha256": "2" * 64,
                     "probe_source_sha256": "3" * 64, "run_id": "foreign-run", "nonce": "4" * 32}
        for field, value in mutations.items():
            with self.subTest(field=field):
                document = fixture(); document["identity"][field] = value
                self.refused(self.receive(document, expectation))

    def test_foreign_identity_cannot_be_authorized_by_matching_expectation(self):
        for field, value in (("board", "apple,j414"), ("soc", "apple,t6020"),
                             ("arch", "x86_64"), ("page_size", 4096),
                             ("page_size", True), ("kernel_source_revision", "a" * 39),
                             ("probe_source_sha256", "C" * 64), ("nonce", "x" * 32),
                             ("run_id", "../../foreign")):
            with self.subTest(field=field, value=value):
                document = fixture(); document["identity"][field] = value
                self.refused(self.receive(document))

    def test_schema_unknown_missing_and_extra_fields_refuse(self):
        cases = []
        for field, value in (("schema_version", True), ("schema_version", 2),
                             ("purpose", "different"), ("origin", "unknown"),
                             ("capture", "PASS"), ("hardware_validation", "PASS")):
            document = fixture(); document[field] = value; cases.append(document)
        for missing in ("origin", "capture", "devices"):
            document = fixture(); del document[missing]; cases.append(document)
        for container in ("root", "identity", "device", "format"):
            document = fixture(); target = {"root": document, "identity": document["identity"],
                "device": document["devices"][0], "format": document["devices"][0]["formats"][0]}[container]
            target["raw_private_response"] = "must-not-accept"; cases.append(document)
        for index, document in enumerate(cases):
            with self.subTest(case=index):
                self.refused(self.receive(document, fixture()["identity"]))
        expectation = fixture()["identity"]; expectation["extra"] = "untrusted"
        self.refused(self.receive(fixture(), expectation))

    def test_format_bounds_types_and_nonfinite_values(self):
        bad = {"width": (True, 0, -1, 8193, 1.5, float("inf")),
               "height": (False, 0, 8193), "fps_num": (True, 0, 120001, float("nan")),
               "fps_den": (False, 0, 10001), "fourcc": ("yuyv", "ABCDE", "Y\nYV", 1234)}
        for field, values in bad.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    document = fixture(); document["devices"][0]["formats"][0][field] = value
                    self.refused(self.receive(document))
        document = fixture(); document["devices"][0]["formats"][0].update(fps_num=121, fps_den=1)
        self.refused(self.receive(document))
        document["devices"][0]["formats"][0].update(width=8192, height=8192, fps_num=120000, fps_den=10000)
        self.assertEqual(self.receive(document)["status"], "PASS-metadata")

    def test_device_format_and_capability_counts(self):
        document = fixture(); template = document["devices"][0]
        document["devices"] = [dict(copy.deepcopy(template), id=f"camera{i}") for i in range(8)]
        self.assertEqual(self.receive(document)["status"], "PASS-metadata")
        document["devices"].append(dict(copy.deepcopy(template), id="camera8"))
        self.refused(self.receive(document))
        document = fixture(); form = document["devices"][0]["formats"][0]
        document["devices"][0]["formats"] = [dict(form, width=i + 1) for i in range(16)]
        self.assertEqual(self.receive(document)["status"], "PASS-metadata")
        document["devices"][0]["formats"].append(dict(form, width=17)); self.refused(self.receive(document))
        for capabilities in (["VIDEO_CAPTURE", "STREAMING", "READWRITE", "VIDEO_CAPTURE_MPLANE", "OTHER"],
                             ["VIDEO_CAPTURE", "STREAMING", "STREAMING"], ["VIDEO_CAPTURE", "OTHER"]):
            document = fixture(); document["devices"][0]["capabilities"] = capabilities
            self.refused(self.receive(document))
        for field in ("id", "driver"):
            for value in ("", "x" * 65, "../../camera", True):
                document = fixture(); document["devices"][0][field] = value
                self.refused(self.receive(document))

    def test_duplicate_ids_and_fraction_equivalent_formats_refuse(self):
        document = fixture(); document["devices"].append(copy.deepcopy(document["devices"][0]))
        self.refused(self.receive(document))
        for numerator, denominator in ((30, 1), (60, 2)):
            document = fixture(); form = document["devices"][0]["formats"][0]
            document["devices"][0]["formats"].append(dict(form, fps_num=numerator, fps_den=denominator))
            self.refused(self.receive(document))

    def test_binding_raw_size_malformed_UTF8_and_duplicate_JSON_keys(self):
        document = fixture(); raw = encoded(document)
        self.refused(self.receive(document, sha="0" * 64))
        self.refused(self.receive(document, raw=raw + b" " * (65537 - len(raw))))
        for malformed in (b"\xff", b"{", b"[]", b'{"schema_version":1,"schema_version":1}'):
            with self.subTest(raw=malformed):
                self.refused(self.receive(document, raw=malformed))
        duplicated = b'{"schema_version":1,' + raw[1:]
        self.refused(self.receive(document, raw=duplicated))

    def namespace(self, root):
        document = fixture(); record_raw = encoded(document); expected_raw = encoded(document["identity"])
        (root / "record.json").write_bytes(record_raw); (root / "expected.json").write_bytes(expected_raw)
        return (root, "record.json", digest(record_raw), "expected.json", digest(expected_raw))

    def test_selected_regular_namespace_and_snapshot_binding(self):
        with tempfile.TemporaryDirectory(prefix="camera-receiver-test-") as directory:
            args = self.namespace(Path(directory))
            before = {p.name: p.read_bytes() for p in args[0].iterdir()}
            result = probe.inspect_namespace(*args); self.check_result(result)
            self.assertEqual(result["status"], "PASS-metadata")
            self.assertEqual(before, {p.name: p.read_bytes() for p in args[0].iterdir()})
            (args[0] / "record.json").write_bytes(b"changed")
            self.refused(probe.inspect_namespace(*args))

    def test_mid_read_snapshot_drift_refuses_even_unchanged_bytes(self):
        with tempfile.TemporaryDirectory(prefix="camera-receiver-test-") as directory:
            args = self.namespace(Path(directory)); source = args[0] / "record.json"
            original = source.read_bytes(); inode = source.stat().st_ino; read = os.read
            changed = []

            def drift(fd, size):
                raw = read(fd, size)
                if raw and os.fstat(fd).st_ino == inode and not changed:
                    before = source.stat()
                    os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))
                    changed.append(True)
                return raw

            with mock.patch.object(probe.os, "read", side_effect=drift):
                result = probe.inspect_namespace(*args)
            self.refused(result); self.assertEqual(result["error"], "evidence-drift")
            self.assertEqual(changed, [True]); self.assertEqual(source.read_bytes(), original)

    def test_namespace_record_and_expectation_links_refuse(self):
        with tempfile.TemporaryDirectory(prefix="camera-receiver-test-") as directory:
            root = Path(directory); args = self.namespace(root)
            for name in ("record.json", "expected.json"):
                source = root / name; saved = source.read_bytes(); target = root / "target"
                target.write_bytes(saved); source.unlink(); source.symlink_to(target)
                self.refused(probe.inspect_namespace(*args)); source.unlink(); source.write_bytes(saved); target.unlink()
            linked = root / "linked"; linked.symlink_to(root, target_is_directory=True)
            self.refused(probe.inspect_namespace(linked, *args[1:]))
            hardlink = root / "hard-record"; os.link(root / "record.json", hardlink)
            self.refused(probe.inspect_namespace(*args)); hardlink.unlink()

    def test_namespace_duplicate_expectation_keys_cannot_authorize_claims(self):
        with tempfile.TemporaryDirectory(prefix="camera-receiver-test-") as directory:
            args = self.namespace(Path(directory))
            raw = b'{"board":"apple,j413",' + (args[0] / "expected.json").read_bytes()[1:]
            (args[0] / "expected.json").write_bytes(raw)
            self.refused(probe.inspect_namespace(*args[:4], digest(raw)))

    def test_ancestor_swap_before_acquisition_cannot_redirect_namespace(self):
        with tempfile.TemporaryDirectory(prefix="camera-receiver-test-") as directory:
            base = Path(directory); selected = base / "selected"; foreign = base / "foreign"
            namespace = selected / "metadata"; other = foreign / "metadata"
            namespace.mkdir(parents=True); other.mkdir(parents=True)
            args = self.namespace(namespace); self.namespace(other)
            open_file = os.open; swapped = []

            def swap(path, *values, **options):
                if not swapped and (str(path) in (str(namespace), str(selected)) or
                                    (str(path) == "selected" and "dir_fd" in options)):
                    selected.rename(base / "original")
                    selected.symlink_to(foreign, target_is_directory=True)
                    swapped.append(True)
                return open_file(path, *values, **options)

            with mock.patch.object(probe.os, "open", side_effect=swap):
                result = probe.inspect_namespace(*args)
            self.assertEqual(swapped, [True], "fixture did not reach namespace acquisition")
            self.refused(result)

    def test_namespace_names_traversal_specials_and_caps(self):
        with tempfile.TemporaryDirectory(prefix="camera-receiver-test-") as directory:
            root = Path(directory); args = self.namespace(root)
            for bad in ("../record.json", "./record.json", "/record.json", "nested/record.json", ".."):
                self.refused(probe.inspect_namespace(root, bad, args[2], *args[3:]))
                self.refused(probe.inspect_namespace(root, *args[1:3], bad, args[4]))
            self.refused(probe.inspect_namespace(root / "unused" / "..", *args[1:]))
            self.refused(probe.inspect_namespace(Path("relative"), *args[1:]))
            for name in ("record.json", "expected.json"):
                source = root / name; raw = source.read_bytes(); node = source.stat(); fstat = os.fstat

                def inert_fifo(fd):
                    info = fstat(fd)
                    if (info.st_dev, info.st_ino) == (node.st_dev, node.st_ino):
                        values = {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
                        values["st_mode"] = stat.S_IFIFO | stat.S_IMODE(info.st_mode)
                        return SimpleNamespace(**values)
                    return info

                with mock.patch.object(probe.os, "fstat", side_effect=inert_fifo):
                    self.refused(probe.inspect_namespace(*args))
                source.unlink(); source.mkdir()
                self.refused(probe.inspect_namespace(*args)); source.rmdir(); source.write_bytes(raw)
            for name, maximum in (("record.json", 65536), ("expected.json", 4096)):
                self.namespace(root); (root / name).write_bytes(b" " * (maximum + 1))
                self.refused(probe.inspect_namespace(*args))

    def test_device_namespaces_are_refused_before_any_open(self):
        with mock.patch.object(probe.os, "open", side_effect=AssertionError("host namespace opened")):
            for path in ("/dev", "/dev/metadata", "/proc", "/proc/metadata", "/sys", "/sys/metadata"):
                self.refused(probe.inspect_namespace(Path(path), "record.json", "a" * 64,
                                                  "expected.json", "b" * 64))

    def guarded_metadata(self, changes):
        """Use a plain fixture file but return inert special-file metadata."""
        with tempfile.TemporaryDirectory(prefix="camera-path-only-test-") as directory:
            root = Path(directory); (root / "record.json").write_bytes(b"fixture")
            open_file, fstat = os.open, os.fstat
            parent = open_file(root, os.O_RDONLY | os.O_DIRECTORY)
            owned, events = [], []

            def opening(path, flags, *args, **kwargs):
                events.append("path-only" if flags & os.O_PATH else "read-open")
                fd = open_file(path, flags, *args, **kwargs); owned.append(fd)
                return fd

            def metadata(fd):
                info = fstat(fd)
                if fd in owned:
                    values = {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
                    values.update(changes)
                    return SimpleNamespace(**values)
                return info

            try:
                with mock.patch.object(probe.os, "open", side_effect=opening), \
                     mock.patch.object(probe.os, "fstat", side_effect=metadata), \
                     mock.patch.object(probe.os, "read", side_effect=AssertionError("unvalidated read")):
                    with self.assertRaises(probe.Refused):
                        probe.read_at(parent, "record.json", 64, digest(b"fixture"))
                self.assertEqual(events, ["path-only"], "read access occurred before safe type/size proof")
                for fd in owned:
                    with self.assertRaises(OSError):
                        fstat(fd)
            finally:
                os.close(parent)

    def test_path_only_special_type_proof_precedes_every_data_read_open(self):
        for kind in (stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK,
                     stat.S_IFDIR, stat.S_IFLNK, 0):
            with self.subTest(mock_type=kind):
                self.guarded_metadata({"st_mode": kind | 0o600})

    def test_path_only_link_and_size_proof_precedes_data_read_open(self):
        for changes in ({"st_nlink": 2}, {"st_size": 0}, {"st_size": 65}):
            with self.subTest(mock_metadata=changes):
                self.guarded_metadata(changes)

    def test_read_descriptor_comes_from_the_held_path_only_inode(self):
        with tempfile.TemporaryDirectory(prefix="camera-path-only-test-") as directory:
            root = Path(directory); (root / "record.json").write_bytes(b"fixture")
            open_file, fstat, read = os.open, os.fstat, os.read
            parent = open_file(root, os.O_RDONLY | os.O_DIRECTORY); pointers, readers, calls = [], [], []

            def opening(path, flags, *args, **kwargs):
                if flags & os.O_PATH:
                    self.assertEqual(str(path), "record.json")
                    fd = open_file(path, flags, *args, **kwargs); pointers.append(fd)
                else:
                    self.assertEqual(len(pointers), 1)
                    self.assertEqual(str(path), f"/proc/self/fd/{pointers[0]}")
                    fd = open_file(path, flags, *args, **kwargs); readers.append(fd)
                    self.assertEqual((fstat(fd).st_dev, fstat(fd).st_ino),
                                     (fstat(pointers[0]).st_dev, fstat(pointers[0]).st_ino))
                return fd

            def reading(fd, size):
                self.assertIn(fd, readers); self.assertNotIn(fd, pointers); calls.append(fd)
                return read(fd, size)

            try:
                with mock.patch.object(probe.os, "open", side_effect=opening), \
                     mock.patch.object(probe.os, "read", side_effect=reading):
                    self.assertEqual(probe.read_at(parent, "record.json", 64, digest(b"fixture")), b"fixture")
                self.assertEqual(len(readers), 1); self.assertTrue(calls)
                for fd in pointers + readers:
                    with self.assertRaises(OSError):
                        fstat(fd)
            finally:
                os.close(parent)

    def test_named_entry_swap_cannot_open_a_different_inode_for_read(self):
        with tempfile.TemporaryDirectory(prefix="camera-path-only-test-") as directory:
            root = Path(directory); source = root / "record.json"; source.write_bytes(b"fixture")
            replacement = root / "replacement"; replacement.write_bytes(b"fixture")
            open_file, fstat = os.open, os.fstat; parent = open_file(root, os.O_RDONLY | os.O_DIRECTORY)
            pointers, swapped, readers = [], [], []

            def opening(path, flags, *args, **kwargs):
                if flags & os.O_PATH:
                    fd = open_file(path, flags, *args, **kwargs); pointers.append(fd); return fd
                self.assertEqual(str(path), f"/proc/self/fd/{pointers[0]}")
                source.rename(root / "original"); replacement.rename(source); swapped.append(True)
                fd = open_file(path, flags, *args, **kwargs); readers.append(fd)
                self.assertEqual((fstat(fd).st_dev, fstat(fd).st_ino),
                                 (fstat(pointers[0]).st_dev, fstat(pointers[0]).st_ino))
                self.assertNotEqual(fstat(fd).st_ino, source.stat().st_ino)
                return fd

            try:
                with mock.patch.object(probe.os, "open", side_effect=opening), \
                     mock.patch.object(probe.os, "read", side_effect=AssertionError("raced name read")):
                    with self.assertRaisesRegex(probe.Refused, "evidence-drift"):
                        probe.read_at(parent, "record.json", 64, digest(b"fixture"))
                self.assertEqual(swapped, [True])
                for fd in pointers + readers:
                    with self.assertRaises(OSError):
                        fstat(fd)
            finally:
                os.close(parent)

    def test_single_link_proof_is_retained_during_descriptor_derivation(self):
        with tempfile.TemporaryDirectory(prefix="camera-path-only-test-") as directory:
            root = Path(directory); (root / "record.json").write_bytes(b"fixture")
            open_file, fstat = os.open, os.fstat; parent = open_file(root, os.O_RDONLY | os.O_DIRECTORY)
            readers, pointers = [], []

            def opening(path, flags, *args, **kwargs):
                fd = open_file(path, flags, *args, **kwargs)
                (pointers if flags & os.O_PATH else readers).append(fd)
                return fd

            def metadata(fd):
                info = fstat(fd)
                if fd in readers:
                    values = {key: getattr(info, key) for key in dir(info) if key.startswith("st_")}
                    values["st_nlink"] = 2
                    return SimpleNamespace(**values)
                return info

            try:
                with mock.patch.object(probe.os, "open", side_effect=opening), \
                     mock.patch.object(probe.os, "fstat", side_effect=metadata), \
                     mock.patch.object(probe.os, "read", side_effect=AssertionError("unproved link count read")):
                    with self.assertRaisesRegex(probe.Refused, "evidence-drift"):
                        probe.read_at(parent, "record.json", 64, digest(b"fixture"))
                self.assertEqual(len(pointers), 1); self.assertEqual(len(readers), 1)
                for fd in pointers + readers:
                    with self.assertRaises(OSError):
                        fstat(fd)
            finally:
                os.close(parent)

    def test_missing_path_only_capability_refuses_before_metadata_open(self):
        with tempfile.TemporaryDirectory(prefix="camera-path-only-test-") as directory:
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            capability = os.O_PATH
            try:
                delattr(probe.os, "O_PATH")
                with mock.patch.object(probe.os, "open", side_effect=AssertionError("metadata opened")):
                    with self.assertRaisesRegex(probe.Refused, "unsupported"):
                        probe.read_at(parent, "record.json", 64, digest(b"fixture"))
            finally:
                setattr(probe.os, "O_PATH", capability)
                os.close(parent)


if __name__ == "__main__":
    unittest.main(verbosity=2)
