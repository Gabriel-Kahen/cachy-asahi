#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert archive and scratch staging controls for the Weston fixture."""

from hashlib import sha256
import io
import lzma
import os
from pathlib import Path
from runpy import run_path
import stat
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


W = run_path(str(Path(__file__).with_name("weston_fixture.py")))
CHECK = W["_checked_members"]
GLOBALS = CHECK.__globals__
PAYLOAD = {name: name.encode("ascii") for name in W["FILES"]}
PINS = {name: W["pin"](len(body), sha256(body).hexdigest()) for name, body in PAYLOAD.items()}
REAL_ARCHIVE = os.getenv("QT629_WESTON_ARCHIVE")
REAL_KEY = os.getenv("QT629_WESTON_PUBLIC_KEY")


def source_members():
    files = {name: (tarfile.REGTYPE, 0o755, "", body) for name, body in PAYLOAD.items()}
    links = {name: (tarfile.SYMTYPE, 0o777, target, b"") for name, target in W["ARCHIVE_LINKS"].items()}
    return list((files | links).items())


def pack(members, *, trailer=b""):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, (kind, mode, target, data) in members:
            member = tarfile.TarInfo(name)
            member.type, member.mode, member.linkname, member.size = kind, mode, target, len(data)
            archive.addfile(member, io.BytesIO(data) if data else None)
    return lzma.compress(out.getvalue() + trailer)


class WestonFixtureTests(unittest.TestCase):
    def test_filters_members_to_the_five_reviewed_file_bodies(self):
        extra = ("usr/bin/weston-screenshooter", (tarfile.REGTYPE, 0o755, "", b"ignored"))
        with patch.dict(GLOBALS, FILES=PINS):
            self.assertEqual(CHECK(pack([*source_members(), extra])), PAYLOAD)

    def test_refuses_traversal_duplicate_unknown_link_and_special_member(self):
        for name, row in (
            ("/outside", (tarfile.REGTYPE, 0o644, "", b"x")),
            ("usr/../outside", (tarfile.REGTYPE, 0o644, "", b"x")),
            ("usr//outside", (tarfile.REGTYPE, 0o644, "", b"x")),
            source_members()[0],
            ("usr/lib/unknown.so", (tarfile.SYMTYPE, 0o777, "../outside", b"")),
            ("usr/lib/unknown.so", (tarfile.SYMTYPE, 0o777, "sibling", b"")),
            ("usr/lib/unknown.so", (tarfile.LNKTYPE, 0o755, "usr/bin/weston", b"")),
            ("usr/lib/unknown", (tarfile.FIFOTYPE, 0o644, "", b"")),
            ("usr", (tarfile.REGTYPE, 0o644, "", b"")),
        ):
            with self.subTest(name=name, kind=row[0]), patch.dict(GLOBALS, FILES=PINS), self.assertRaises(ValueError):
                CHECK(pack([*source_members(), (name, row)]))

    def test_refuses_changed_or_missing_selected_members(self):
        members = dict(source_members())
        member, body = next(iter(PAYLOAD.items()))
        symlink = next(iter(W["LINKS"]))
        cases = (
            members | {member: (tarfile.REGTYPE, 0o755, "", b"X" * len(body))},
            members | {member: (tarfile.REGTYPE, 0o4755, "", body)},
            members | {symlink: (tarfile.SYMTYPE, 0o777, "/etc/passwd", b"")},
            members | {symlink: (tarfile.REGTYPE, 0o755, "", b"")},
            {name: row for name, row in members.items() if name != member},
            {name: row for name, row in members.items() if name != symlink},
        )
        with patch.dict(GLOBALS, FILES=PINS):
            for index, changed in enumerate(cases):
                with self.subTest(case=index), self.assertRaises(ValueError):
                    CHECK(pack(changed.items()))

    def test_refuses_incomplete_and_oversized_streams_and_trailing_members(self):
        body = pack(source_members())
        with patch.dict(GLOBALS, FILES=PINS):
            for invalid in (body[:-1], body + lzma.compress(b"second stream"), pack(source_members(), trailer=b"x")):
                with self.subTest(bytes=len(invalid)), self.assertRaises(ValueError):
                    CHECK(invalid)
            for bound in (dict(MAX_TAR_BYTES=512), dict(MAX_TAR_MEMBERS=2)):
                with patch.dict(GLOBALS, bound), self.assertRaises(ValueError):
                    CHECK(body)

    def test_publishes_exact_modes_under_guest_umask_and_sticky_parent(self):
        with TemporaryDirectory() as temporary:
            parent = Path(temporary)
            parent.chmod(0o1777)
            destination = parent / "weston"
            previous = os.umask(0o077)
            try:
                W["_write_fixture"](destination, PAYLOAD)
            finally:
                os.umask(previous)
            self.check_tree(destination, PINS)

    def test_refuses_existing_destination_and_symlink_without_replacing_them(self):
        with TemporaryDirectory() as temporary:
            parent = Path(temporary)
            existing = parent / "existing"
            existing.mkdir()
            sentinel = existing / "file"
            sentinel.write_bytes(b"keep")
            alias = parent / "alias"
            alias.symlink_to(existing, target_is_directory=True)
            for path in (existing, alias):
                with self.subTest(path=path.name), self.assertRaises(FileExistsError):
                    W["_write_fixture"](path, PAYLOAD)
            self.assertTrue(alias.is_symlink())
            self.assertEqual(sentinel.read_bytes(), b"keep")
            with self.assertRaisesRegex(ValueError, "Canonical"):
                W["_write_fixture"](alias / "child", PAYLOAD)
            parent.chmod(0o777)
            with self.assertRaisesRegex(ValueError, "protected"):
                W["_write_fixture"](parent / "elsewhere", PAYLOAD)

    def test_copy_failure_removes_partial_fixture(self):
        with TemporaryDirectory() as temporary:
            destination = Path(temporary) / "fixture"
            with patch("os.symlink", side_effect=OSError("injected failure")), self.assertRaisesRegex(OSError, "injected"):
                W["_write_fixture"](destination, PAYLOAD)
            self.assertEqual(list(destination.parent.iterdir()), [])

    def check_tree(self, destination, pins):
        actual = {path.relative_to(destination).as_posix(): path for path in destination.rglob("*")}
        self.assertEqual(actual.keys(), set(W["DIRECTORIES"]) | W["LINKS"].keys() | pins.keys())
        for path in (destination, *(actual[name] for name in W["DIRECTORIES"])):
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o755)
            self.assertEqual(path.stat().st_uid, os.geteuid())
        for name, target in W["LINKS"].items():
            self.assertEqual(os.readlink(actual[name]), target)
            self.assertIn(actual[name].resolve(strict=True), actual.values())
        for name, expected in pins.items():
            path = actual[name]
            self.assertTrue(stat.S_ISREG(path.lstat().st_mode))
            self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o755)
            body = path.read_bytes()
            self.assertEqual(W["pin"](len(body), sha256(body).hexdigest()), expected)

    @unittest.skipUnless(REAL_ARCHIVE or REAL_KEY, "set QT629_WESTON_ARCHIVE and QT629_WESTON_PUBLIC_KEY for real data")
    def test_real_signed_package_stages_and_bad_detached_signature_refuses(self):
        self.assertTrue(REAL_ARCHIVE and REAL_KEY)
        archive = Path(REAL_ARCHIVE)
        signature = archive.with_name(archive.name + ".sig")
        inputs = dict(archive=archive, signature=signature, public_key=Path(REAL_KEY))
        with TemporaryDirectory() as temporary:
            parent = Path(temporary)
            destination = parent / "valid"
            receipt = W["stage"](**inputs, destination=destination)
            self.assertEqual(receipt, W["verify"](**inputs))
            self.assertEqual(receipt["signer"], W["A"]["FINGERPRINT"])
            self.check_tree(destination, W["FILES"])
            changed = parent / "bad.sig"
            body = bytearray(signature.read_bytes())
            body[-1] ^= 1
            changed.write_bytes(body)
            rejected = parent / "bad-fixture"
            with self.assertRaisesRegex(ValueError, "Input pin differs"):
                W["stage"](**(inputs | {"signature": changed}), destination=rejected)
            with patch.dict(W["PINS"], signature=W["pin"](len(body), sha256(body).hexdigest())):
                with self.assertRaisesRegex(ValueError, "ALARM detached signature refused"):
                    W["stage"](**(inputs | {"signature": changed}), destination=rejected)
            self.assertFalse(rejected.exists())
            alias = parent / "key-alias"
            alias.symlink_to(REAL_KEY)
            with self.assertRaisesRegex(ValueError, "Ordinary absolute file required"):
                W["stage"](**(inputs | {"public_key": alias}), destination=rejected)
            self.assertFalse(rejected.exists())


if __name__ == "__main__":
    unittest.main()
