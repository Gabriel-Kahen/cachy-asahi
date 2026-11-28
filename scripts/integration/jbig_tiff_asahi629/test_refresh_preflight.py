# SPDX-License-Identifier: MIT
"""Exercise the host-only refresh preflight without staging or launching an actor."""

import errno
import os
from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


LANE = Path(__file__).resolve().parent
PREFLIGHT = run_path(str(LANE / "refresh_preflight.py"))
STAGE = run_path(str(LANE / "stage.py"))
T = STAGE["legacy"]().T
BULK = PREFLIGHT["bulk_read"]
PREVIEW = PREFLIGHT["preview_reader"]
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
MIB = 1 << 20


class BulkReadTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name).resolve() / "odd.raw"
        self.body = b"a" * (MIB + PAGE_SIZE + 19)
        self.path.write_bytes(self.body)
        self.pin = T.pin(self.body)

    def test_hashes_odd_tail_and_only_advises_aligned_ranges_on_its_descriptor(self):
        identity = T.identity(self.path.stat())
        calls = []

        def advise(fd, offset, length, mode):
            self.assertEqual(T.identity(os.fstat(fd)), identity)
            calls.append((offset, length, mode))

        observed = {}
        with patch.object(os, "posix_fadvise", side_effect=advise):
            self.assertEqual(BULK(T, self.path, self.pin, cap=len(self.body), observed=observed), self.pin)
        self.assertEqual(observed, {str(self.path): identity})
        self.assertEqual(calls[0], (0, 0, os.POSIX_FADV_RANDOM))
        end = 0
        for offset, length, mode in calls[1:]:
            self.assertEqual((offset, offset % PAGE_SIZE, length % PAGE_SIZE, mode),
                             (end, 0, 0, os.POSIX_FADV_DONTNEED))
            self.assertGreater(length, 0)
            end += length
        self.assertEqual(end, MIB + PAGE_SIZE)

    def test_reopened_identity_must_match_existing_observation(self):
        observed = {str(self.path): (0,) * len(T.identity(self.path.stat()))}
        with patch.object(os, "posix_fadvise"), self.assertRaisesRegex(ValueError, "Reopened bulk file"):
            BULK(T, self.path, self.pin, cap=len(self.body), observed=observed)
        self.assertEqual(observed[str(self.path)], (0,) * len(T.identity(self.path.stat())))

    def test_refuses_noncanonical_linked_and_oversize_operands_before_advice(self):
        link = self.path.with_name("link")
        link.symlink_to(self.path)
        with patch.object(os, "posix_fadvise") as advise:
            with self.assertRaises((ValueError, OSError)):
                BULK(T, link, self.pin, cap=len(self.body))
            with self.assertRaises(ValueError):
                BULK(T, self.path, self.pin, cap=len(self.body) - 1)
            hardlink = self.path.with_name("hardlink")
            hardlink.hardlink_to(self.path)
            with self.assertRaises(ValueError):
                BULK(T, self.path, self.pin, cap=len(self.body))
        advise.assert_not_called()

    def test_refuses_wrong_bytes_even_with_a_matching_file_length(self):
        self.path.write_bytes(self.body[:-1] + b"x")
        with patch.object(os, "posix_fadvise"), self.assertRaises(ValueError):
            BULK(T, self.path, self.pin, cap=len(self.body))

    def test_refuses_truncation_growth_and_equal_byte_replacement(self):
        def replace():
            self.path.unlink()
            self.path.write_bytes(self.body)

        for change in (lambda: self.path.write_bytes(self.body[:-1]),
                       lambda: self.path.write_bytes(self.body + b"x"), replace):
            self.path.write_bytes(self.body)

            def advise(fd, offset, length, mode):
                if mode == os.POSIX_FADV_RANDOM:
                    change()

            with self.subTest(change=change), patch.object(os, "posix_fadvise", side_effect=advise), \
                    self.assertRaises(ValueError):
                BULK(T, self.path, self.pin, cap=len(self.body))

    def test_advice_failure_propagates_without_a_legacy_read(self):
        for mode in (os.POSIX_FADV_RANDOM, os.POSIX_FADV_DONTNEED):
            def advise(fd, offset, length, request):
                if request == mode:
                    raise OSError(errno.EOPNOTSUPP, "fixture advice refusal")

            with self.subTest(mode=mode), patch.object(os, "posix_fadvise", side_effect=advise), \
                    patch.object(T, "read") as legacy:
                with self.assertRaises(OSError) as caught:
                    BULK(T, self.path, self.pin, cap=len(self.body))
                self.assertEqual(caught.exception.errno, errno.EOPNOTSUPP)
                legacy.assert_not_called()


class PreviewReaderTests(unittest.TestCase):
    def setUp(self):
        self.root = Path("/inputs/preview")
        self.large = Path("forward/large.pkg.tar.zst")
        self.small = Path("forward/small.sig")
        self.large_pin = T.pin(b"a" * MIB)
        self.small_pin = T.pin(b"b" * (MIB - 1))
        self.manifest = {"files": {str(self.large): self.large_pin, str(self.small): self.small_pin}}
        self.legacy = Mock(return_value=b"legacy")
        self.api = SimpleNamespace(MAX_MEMBER=T.MAX_MEMBER, need=T.need, read=self.legacy)
        self.reader = PREVIEW(self.api, self.root, self.manifest)

    def test_only_exact_manifest_bulk_noncollect_reads_dispatch(self):
        bulk = Mock(return_value=self.large_pin)
        observed = {}
        with patch.dict(PREVIEW.__globals__, bulk_read=bulk):
            actual = self.reader.read(self.root / self.large, self.large_pin, cap=2 * MIB,
                                      collect=False, observed=observed)
            self.assertIs(actual, self.large_pin)
            bulk.assert_called_once_with(self.api, self.root / self.large, self.large_pin,
                                         cap=2 * MIB, observed=observed)
            for path, expected, collect in (
                (self.root / self.large, self.large_pin, True),
                (self.root / self.small, self.small_pin, False),
                (Path("/inputs/other") / self.large, self.large_pin, False),
                (self.root / "forward/unselected", self.large_pin, False),
            ):
                with self.subTest(path=path, collect=collect):
                    kwargs = dict(cap=2 * MIB, collect=collect, observed=observed, allowed_links=(1,))
                    self.assertEqual(self.reader.read(path, expected, **kwargs), b"legacy")
                    self.legacy.assert_called_with(path, expected, **kwargs)
        self.assertEqual(bulk.call_count, 1)

    def test_selected_pin_and_link_drift_refuse_before_dispatch(self):
        bulk = Mock()
        wrong = self.large_pin | {"sha256": "0" * 64}
        with patch.dict(PREVIEW.__globals__, bulk_read=bulk):
            for expected, links in ((wrong, (1,)), (self.large_pin, (1, 2))):
                with self.assertRaises(ValueError):
                    self.reader.read(self.root / self.large, expected, collect=False, allowed_links=links)
        bulk.assert_not_called()
        self.legacy.assert_not_called()


class WorkerTests(unittest.TestCase):
    def setUp(self):
        work = TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name).resolve()
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        group = self.root / "group"
        group.mkdir()
        self.memory_stat = {"file_dirty": 8, "file": 128, "anon": 64}
        (group / "memory.stat").write_text("anon 64\nfile 128\nfile_dirty 8\n")
        self.memory_pressure = "full avg10=0.00 avg60=0.00 avg300=0.00 total=0"
        (group / "memory.pressure").write_text(self.memory_pressure + "\n")
        self.rows = []
        self.group = group
        self.worker = PREFLIGHT["Worker"](self.runtime, group, self.rows.append)

    def assert_phase(self, name, terminal):
        self.assertEqual([(row["phase"], row["state"]) for row in self.rows],
                         [(name, "begin"), (name, terminal)])
        for row in self.rows:
            for clock in ("at_ns", "monotonic_ns"):
                self.assertIs(type(row[clock]), int)
                self.assertGreater(row[clock], 0)
            self.assertEqual(row["memory_stat"], self.memory_stat)
            self.assertEqual(row["memory_pressure"], self.memory_pressure)
        self.assertLessEqual(self.rows[0]["monotonic_ns"], self.rows[1]["monotonic_ns"])

    def test_held_disk_success_and_hash_refusal_have_phase_receipts(self):
        path = self.root / "held.raw"
        body = b"held-result-disk"
        path.write_bytes(body)
        expected = T.pin(body)
        with patch.object(os, "posix_fadvise"):
            self.assertEqual(self.worker.held_disk(T, path, expected), expected)
            self.assert_phase("held-disk-dry-check", "complete")
            self.rows.clear()
            path.write_bytes(body[:-1] + b"x")
            with self.assertRaises(ValueError):
                self.worker.held_disk(T, path, expected)
            self.assert_phase("held-disk-dry-check", "failed")

    def test_runtime_must_be_private_and_canonical(self):
        link = self.root / "runtime-link"
        link.symlink_to(self.runtime)
        with self.assertRaisesRegex(ValueError, "owned private worker runtime"):
            PREFLIGHT["Worker"](link, self.group, self.rows.append)
        self.runtime.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "owned private worker runtime"):
            PREFLIGHT["Worker"](self.runtime, self.group, self.rows.append)
        self.assertEqual(self.rows, [])

    def test_unrelated_systemd_runtime_refused_before_log_creation(self):
        log = self.root / "phase.jsonl"
        with patch.dict(os.environ, RUNTIME_DIRECTORY=str(self.runtime)), \
                patch.object(Path, "read_text", return_value="0::/some.slice/other.service\n"):
            with self.assertRaisesRegex(ValueError, "Expected a bounded systemd worker"):
                with PREFLIGHT["systemd_worker"](log):
                    self.fail("Unrelated runtime was admitted")
        self.assertFalse(log.exists())

    def test_preview_uses_scoped_reader_inside_recorded_phase(self):
        relative = "forward/large.pkg.tar.zst"
        expected = T.pin(b"a" * MIB)
        manifest = {"files": {relative: expected}}
        bulk = Mock(return_value=expected)

        def rehash(reader, root, value):
            self.assertEqual((root, value), (self.root, manifest))
            self.assertEqual(reader.read(root / relative, expected, collect=False), expected)

        with patch.dict(PREVIEW.__globals__, bulk_read=bulk):
            self.worker.rehash_preview(T, SimpleNamespace(rehash=rehash), self.root, manifest)
        bulk.assert_called_once_with(T, self.root / relative, expected, cap=T.MAX_MEMBER, observed=None)
        self.assert_phase("preview-rehash", "complete")


class HostTrustTests(unittest.TestCase):
    def test_gpg_uses_private_runtime_home_and_never_autostarts(self):
        entry, inputs = STAGE["ENTRY"], STAGE["I"]
        fingerprint = "A" * 40
        keys = dict(not_before=10, not_after=20)
        review = dict(fingerprint=fingerprint, certificate=T.pin(b"certificate"), **keys,
                      signatures={name: T.pin(name.encode()) for name in inputs.PROJECT})
        trial = SimpleNamespace(read=Mock(return_value=b"reviewed bytes"), need=T.need)
        guest = SimpleNamespace(TIMEOUT=1, current_test=Mock(), public_only=Mock(),
                                key_listing=Mock(return_value={fingerprint: keys}), test_signature=Mock())
        homes = set()
        commands = []
        with TemporaryDirectory() as work:
            root = Path(work).resolve()
            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)
            folder = root / "scoped-media"

            def gpg(home, *args, data=None):
                self.assertEqual(home.parent, runtime)
                self.assertTrue(home.is_dir())
                self.assertEqual(args[0], "--no-autostart")
                homes.add(home)
                commands.append(args[1:])
                return b"fixture GPG response"

            with patch.object(entry, "gpg", side_effect=gpg), patch.object(inputs, "require_qualified_tiff"):
                STAGE["host_test"](SimpleNamespace(T=trial, G=guest), folder, review, runtime_directory=runtime)
            self.assertEqual(len(homes), 1)
            self.assertTrue(all(not home.exists() for home in homes))
            self.assertEqual(list(runtime.iterdir()), [])
        self.assertEqual(commands[:3], [
            ("--import",), ("--with-colons", "--fingerprint", "--list-keys"), ("--with-colons", "--list-secret-keys"),
        ])
        self.assertEqual(len(commands), 5)
        for name, args in zip(inputs.PROJECT, commands[3:], strict=True):
            path = folder / inputs.PROVIDERS[name]["filename"]
            self.assertEqual(args, ("--status-fd", "1", "--verify", "--", str(path) + ".sig", str(path)))
        self.assertEqual(guest.test_signature.call_count, 2)


if __name__ == "__main__":
    unittest.main()
