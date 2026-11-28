# SPDX-License-Identifier: MIT
"""Exercise the scoped cache advice and exact image verification without launching."""

import errno
import os
from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch


OWNER = run_path(str(Path(__file__).with_name("runner.py")))
T = OWNER["S"].legacy().T
REHASH = OWNER["rehash_image"]
IMAGE_READER = OWNER["image_reader"]
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")


def control_refs(control, expected):
    return T.read(control / "verified-candidate/guest.raw", expected, cap=expected["bytes"], collect=False)


def phase_reads(paths, refs, *, out=None):
    def read(path, expected):
        return T.read(path, expected, cap=expected["bytes"], collect=False)

    originals = (control_refs(paths["control"], refs["baseline"]), read(paths["seed"], refs["seed"]))
    return originals if out is None else originals + (
        read(out / "reference.raw", refs["baseline"]),
        read(out / "scratch.raw", refs["seed"]),
    )


class ImageReaderTests(unittest.TestCase):
    def setUp(self):
        out = Path("/out/asahi629")
        control = T.pin(b"a" * PAGE_SIZE)
        seed = T.pin(b"b" * PAGE_SIZE)
        self.images = {
            out / "reference.raw": control,
            out / "scratch.raw": seed,
            Path("/inputs/control/verified-candidate/guest.raw"): control,
            Path("/inputs/seed.raw"): seed,
        }
        self.legacy = Mock(return_value="legacy")
        self.api = SimpleNamespace(MAX_MEMBER=T.MAX_MEMBER, need=T.need, read=self.legacy)
        self.read = IMAGE_READER(self.api, self.images)

    def test_dispatches_only_the_exact_selected_image_reads(self):
        verifier = Mock(side_effect=lambda _api, _path, expected: expected)
        with patch.dict(IMAGE_READER.__globals__, rehash_image=verifier):
            for path, pin in self.images.items():
                with self.subTest(path=path):
                    self.assertEqual(self.read(path, pin, cap=pin["bytes"], collect=False), pin)
                    verifier.assert_called_with(self.api, path, pin)
            for path in (Path("/inputs/control/guest.raw"), Path("/inputs/reference.raw"), Path("/out/asahi629/boot.raw")):
                with self.subTest(path=path):
                    options = dict(cap=PAGE_SIZE + 1, collect=False, observed={}, allowed_links=(1, 2))
                    pin = T.pin(b"other")
                    self.assertEqual(self.read(path, pin, **options), "legacy")
                    self.legacy.assert_called_with(path, pin, **options)
        self.assertEqual(verifier.call_count, len(self.images))

    def test_refuses_selected_read_drift_without_dispatch(self):
        verifier = Mock()
        with patch.dict(IMAGE_READER.__globals__, rehash_image=verifier):
            for path, pin in self.images.items():
                exact = dict(expected=pin, cap=pin["bytes"], collect=False)
                for drift in (
                    {"expected": None},
                    {"expected": pin | {"sha256": "0" * 64}},
                    {"cap": pin["bytes"] + 1},
                    {"collect": True},
                    {"observed": {}},
                    {"allowed_links": (1, 2)},
                ):
                    with self.subTest(path=path, drift=drift), self.assertRaises(ValueError):
                        self.read(path, **(exact | drift))
        verifier.assert_not_called()
        self.legacy.assert_not_called()

    def test_rebinding_control_refs_scopes_originals_and_owned_paths_by_phase(self):
        out = Path("/out/asahi629")
        paths = {"control": Path("/inputs/control"), "seed": Path("/inputs/seed.raw")}
        baseline = self.images[out / "reference.raw"]
        seed = self.images[paths["seed"]]
        refs = {"baseline": baseline, "seed": seed}
        expected_originals = [
            call(self.api, paths["control"] / "verified-candidate/guest.raw", baseline),
            call(self.api, paths["seed"], seed),
        ]
        expected_owned = [
            call(self.api, out / "reference.raw", baseline),
            call(self.api, out / "scratch.raw", seed),
        ]
        legacy = SimpleNamespace(T=self.api, CONTROL_FILES=Path("verified-candidate"), control_refs=control_refs)
        verifier = Mock(side_effect=lambda _api, _path, pin: pin)
        with patch.dict(IMAGE_READER.__globals__, rehash_image=verifier):
            binding = OWNER["image_reads"](legacy, paths, refs)
            bound = OWNER["with_globals"](phase_reads, **binding)
            self.assertEqual(bound(paths, refs), (baseline, seed))
            self.assertEqual(verifier.call_args_list, expected_originals)
            self.assertEqual(binding["T"].read(out / "reference.raw", baseline, cap=PAGE_SIZE, collect=False),
                             "legacy")
            self.assertEqual(verifier.call_args_list, expected_originals)
            self.legacy.assert_called_once_with(
                out / "reference.raw", baseline, cap=PAGE_SIZE, collect=False, observed=None, allowed_links=(1,),
            )

            verifier.reset_mock()
            rehearse = OWNER["with_globals"](phase_reads, **OWNER["image_reads"](legacy, paths, refs, out=out))
            self.assertEqual(rehearse(paths, refs, out=out), (baseline, seed, baseline, seed))
            self.assertEqual(verifier.call_args_list, expected_originals + expected_owned)
        self.assertIs(control_refs.__globals__["T"], T)
        self.assertIs(phase_reads.__globals__["T"], T)
        self.assertIs(phase_reads.__globals__["control_refs"], control_refs)


class RehashTests(unittest.TestCase):
    def setUp(self):
        work = TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.path = Path(work.name).resolve() / "reference.raw"
        self.body = b"a" * ((1 << 20) + PAGE_SIZE)
        self.path.write_bytes(self.body)
        self.pin = T.pin(self.body)

    def test_advice_applies_to_the_open_image_and_each_hashed_range(self):
        inode = self.path.stat().st_ino
        calls = []

        def advise(fd, offset, length, mode):
            self.assertEqual(os.fstat(fd).st_ino, inode)
            calls.append((offset, length, mode))

        with patch.object(os, "posix_fadvise", side_effect=advise):
            self.assertEqual(REHASH(T, self.path, self.pin), self.pin)
        self.assertEqual(calls, [
            (0, 0, os.POSIX_FADV_RANDOM),
            (0, 1 << 20, os.POSIX_FADV_DONTNEED),
            (1 << 20, PAGE_SIZE, os.POSIX_FADV_DONTNEED),
        ])

    def test_rejects_wrong_bytes_and_detects_path_replacement_during_use(self):
        with patch.object(os, "posix_fadvise"):
            with self.assertRaisesRegex(ValueError, "Changed pinned image"):
                REHASH(T, self.path, self.pin | {"sha256": "0" * 64})

        def replace(fd, offset, length, mode):
            if mode == os.POSIX_FADV_RANDOM:
                self.path.unlink()
                self.path.write_bytes(self.body)

        with patch.object(os, "posix_fadvise", side_effect=replace):
            with self.assertRaisesRegex(ValueError, "Changed pinned image"):
                REHASH(T, self.path, self.pin)

    def test_rejects_symlink_hardlink_and_unaligned_images_before_advice(self):
        symlink = self.path.with_name("symlink")
        symlink.symlink_to(self.path)
        hardlink = self.path.with_name("hardlink")
        hardlink.hardlink_to(self.path)
        unaligned = self.path.with_name("unaligned.raw")
        unaligned.write_bytes(b"unaligned")
        with patch.object(os, "posix_fadvise") as advise:
            for path, pin in ((symlink, self.pin), (self.path, self.pin), (unaligned, T.pin(b"unaligned"))):
                with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                    REHASH(T, path, pin)
        advise.assert_not_called()

    def test_refuses_truncation_or_growth_after_the_initial_size_check(self):
        for body, reason in ((self.body[:-PAGE_SIZE], "Short pinned image read"),
                             (self.body + b"x", "Pinned image grew")):
            self.path.write_bytes(self.body)

            def advise(fd, offset, length, mode):
                if mode == os.POSIX_FADV_RANDOM:
                    self.path.write_bytes(body)

            with self.subTest(reason=reason), patch.object(os, "posix_fadvise", side_effect=advise):
                with self.assertRaisesRegex(ValueError, reason):
                    REHASH(T, self.path, self.pin)

    def test_advice_failure_holds_without_using_legacy_read(self):
        for mode in (os.POSIX_FADV_RANDOM, os.POSIX_FADV_DONTNEED):
            def advise(fd, offset, length, request):
                if request == mode:
                    raise OSError(errno.EOPNOTSUPP, "cache advice unsupported")

            with self.subTest(mode=mode), patch.object(os, "posix_fadvise", side_effect=advise), \
                    patch.object(T, "read") as legacy:
                read = IMAGE_READER(T, {self.path: self.pin})
                with self.assertRaises(OSError) as caught:
                    read(self.path, self.pin, cap=self.pin["bytes"], collect=False)
                self.assertEqual(caught.exception.errno, errno.EOPNOTSUPP)
                legacy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
