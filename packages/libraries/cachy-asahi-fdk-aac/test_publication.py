#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Publication packet fixtures; never compile, install, or execute contents."""
import sys
sys.dont_write_bytecode = True

import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import publication
import source_check

ROOT = "cachy-asahi-fdk-aac-3.0.0-source/"
PACKET = "fdk-aac-3.0.0-selected-source.tar"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tree(root):
    result = {}
    for path in root.rglob("*"):
        info = path.lstat()
        data = (os.readlink(path) if stat.S_ISLNK(info.st_mode)
                else path.read_bytes() if stat.S_ISREG(info.st_mode) else None)
        result[str(path.relative_to(root))] = (info.st_mode, info.st_mtime_ns, data)
    return result


class PublicationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="fdk-publication-test-")
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.files = {"PKGBUILD": b"# Fixture, never sourced\n", ".SRCINFO": b"fixture\n",
                      PACKET: b"synthetic read_bundle input; not codec source\n"}

    def entries(self, files=None, mapping=None):
        files = self.files if files is None else files
        if mapping is None:
            mapping = json.dumps({name: sha(data) for name, data in sorted(files.items())}).encode()
        entries = [(ROOT + "recipe/" + name, data, {}) for name, data in files.items()]
        return entries + [(ROOT + "SOURCE-MAP.json", mapping, {})], sha(mapping)

    def bundle(self, entries):
        buf = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name, data, fields in entries:
                    member = tarfile.TarInfo(name)
                    member.size, member.mode = len(data), 0o644
                    member.uid = member.gid = 0
                    for key, value in fields.items():
                        setattr(member, key, value)
                    archive.addfile(member, io.BytesIO(data) if member.size == len(data) else None)
        path = self.work / "bundle.tar.gz"
        data = buf.getvalue()
        path.write_bytes(data)
        return path, sha(data)

    def read(self, entries, map_sha, reject=False):
        path, packet_sha = self.bundle(entries)
        before = tree(self.work)
        try:
            if reject:
                with self.assertRaises((ValueError, OSError, tarfile.TarError, EOFError)):
                    publication.read_bundle(path, packet_sha, map_sha)
                return None
            return publication.read_bundle(path, packet_sha, map_sha)
        finally:
            self.assertEqual(tree(self.work), before)
            self.assertFalse(list(self.work.rglob("__pycache__")))

    def test_flat_bundle_reads_without_extracting_or_executing(self):
        entries, map_sha = self.entries()
        self.assertEqual(self.read(entries, map_sha), self.files)

    def test_outer_digest_and_independent_map_digest_are_required(self):
        entries, map_sha = self.entries()
        path, packet_sha = self.bundle(entries)
        for outer, inner in (("0" * 64, map_sha), (packet_sha, "0" * 64)):
            with self.assertRaises(ValueError):
                publication.read_bundle(path, outer, inner)

    def test_payload_and_source_map_tampering_rejected_after_outer_rehash(self):
        entries, map_sha = self.entries()
        name, data, fields = entries[0]
        self.read([(name, data + b"tamper", fields), *entries[1:]], map_sha, reject=True)
        for mapping in (b"[]", b"{broken", json.dumps({"PKGBUILD": "g" * 64}).encode(),
                        json.dumps({name: sha(data) for name, data in self.files.items()
                                    if name != "PKGBUILD"}).encode()):
            changed, changed_sha = self.entries(mapping=mapping)
            self.read(changed, changed_sha, reject=True)
        modified = entries[:-1] + [(ROOT + "SOURCE-MAP.json", entries[-1][1] + b" ", {})]
        self.read(modified, map_sha, reject=True)

    def test_duplicate_members_and_duplicate_map_keys_rejected(self):
        entries, map_sha = self.entries()
        self.read([*entries, entries[0]], map_sha, reject=True)
        mapping = entries[-1][1]
        duplicate = b'{"PKGBUILD":"' + sha(self.files["PKGBUILD"]).encode() + b'",' + mapping[1:]
        altered, digest = self.entries(mapping=duplicate)
        self.read(altered, digest, reject=True)

    def test_paths_must_be_rooted_flat_and_safe(self):
        entries, map_sha = self.entries()
        for name in ("/absolute", "../escape", ROOT + "recipe/../escape",
                     ROOT + "recipe/nested/file", ROOT + "recipe//file",
                     ROOT + "recipe/./file", ROOT + "recipe/back\\slash",
                     ROOT + "recipe/control\x01", "other-root/recipe/file"):
            with self.subTest(name=name):
                self.read([*entries, (name, b"fixture", {})], map_sha, reject=True)
        for name in ("nested/file", "../escape", "back\\slash", "control\x01"):
            entries, map_sha = self.entries(files={**self.files, name: b"coherently mapped unsafe path"})
            self.read(entries, map_sha, reject=True)

    def test_links_special_members_modes_and_owners_are_rejected(self):
        entries, map_sha = self.entries()
        variations = [{"type": kind, "linkname": "PKGBUILD"} for kind in
                      (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE,
                       tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE)]
        variations += [{"mode": 0o755}, {"mode": 0o600}, {"uid": 1}, {"gid": 1}]
        for fields in variations:
            with self.subTest(fields=fields):
                name, data, _ = entries[0]
                self.read([(name, data, fields), *entries[1:]], map_sha, reject=True)

    def test_required_recipe_files_and_source_map_cannot_be_missing(self):
        for name in self.files:
            entries, map_sha = self.entries(files={key: data for key, data in self.files.items() if key != name})
            self.read(entries, map_sha, reject=True)
        entries, map_sha = self.entries()
        self.read(entries[:-1], map_sha, reject=True)

    def test_member_count_and_expanded_size_bounds(self):
        files = {**self.files, **{f"file-{index}": b"" for index in range(124)}}
        entries, map_sha = self.entries(files=files)
        self.assertEqual(self.read(entries, map_sha), files)
        entries, map_sha = self.entries(files={**files, "one-too-many": b""})
        self.read(entries, map_sha, reject=True)
        entries, map_sha = self.entries()
        self.read([*entries, (ROOT + "recipe/large", b"x" * (8 * 1024 * 1024 + 1), {})],
                  map_sha, reject=True)
        files = {**self.files, "large-a": b"a" * (4 * 1024 * 1024),
                 "large-b": b"b" * (4 * 1024 * 1024)}
        entries, map_sha = self.entries(files=files)
        self.read(entries, map_sha, reject=True)
        entries, _ = self.entries(mapping=b" " * 65537)
        self.read(entries, sha(entries[-1][1]), reject=True)

    def test_only_exact_selected_member_gets_20MiB_and_other_total_stays_8MiB(self):
        files = {**self.files, PACKET: b's' * source_check.SELECTED_LIMIT}
        entries, map_sha = self.entries(files=files)
        self.assertEqual(self.read(entries, map_sha), files)
        files[PACKET] += b'!'
        entries, map_sha = self.entries(files=files)
        self.read(entries, map_sha, reject=True)
        entries, map_sha = self.entries(files={**self.files, 'ordinary': b'x' * (8 * 1024 * 1024 + 1)})
        self.read(entries, map_sha, reject=True)
        # Exact non-selected aggregate includes the source map, not only members.
        files = {'PKGBUILD': b'', '.SRCINFO': b'', PACKET: b's' * source_check.SELECTED_LIMIT,
                 'ordinary': b''}
        entries, _ = self.entries(files=files); map_bytes = len(entries[-1][1])
        files['ordinary'] = b'o' * (publication.OTHER_LIMIT - map_bytes)
        entries, map_sha = self.entries(files=files)
        self.assertEqual(self.read(entries, map_sha), files)
        files['ordinary'] += b'!'
        entries, map_sha = self.entries(files=files)
        self.read(entries, map_sha, reject=True)

    def test_cancellation_after_new_reconstruction_removes_only_owned_output(self):
        entries, map_sha = self.entries();path, packet_sha = self.bundle(entries)
        output = self.work / 'cancelled-output'
        with mock.patch.object(publication, 'template_files', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                publication.reconstruct(path, output, packet_sha, map_sha)
        self.assertFalse(output.exists())


    def test_input_reader_rejects_symlink_directory_and_fifo_promptly(self):
        entries, map_sha = self.entries()
        path, packet_sha = self.bundle(entries)
        linked = self.work / "linked"
        linked.symlink_to(path)
        folder = self.work / "directory"
        folder.mkdir()
        fifo = self.work / "fifo"
        os.mkfifo(fifo)
        before = tree(self.work)
        for source in (linked, folder, fifo):
            with self.assertRaises((ValueError, OSError)):
                publication.read_bundle(source, packet_sha, map_sha)
        self.assertEqual(tree(self.work), before)

    def test_outer_size_limit_and_truncated_stream_rejected(self):
        entries, map_sha = self.entries()
        path, _ = self.bundle(entries)
        compressed = path.read_bytes()
        for data in (compressed[:len(compressed) // 2], b"x" * (8 * 1024 * 1024 + 1)):
            path.write_bytes(data)
            before = tree(self.work)
            with self.assertRaises((ValueError, OSError, tarfile.TarError, EOFError)):
                publication.read_bundle(path, sha(data), map_sha)
            self.assertEqual(tree(self.work), before)

    def test_reconstruction_rejection_preserves_existing_and_cleans_new_output(self):
        entries, map_sha = self.entries()
        path, packet_sha = self.bundle(entries)
        existing = self.work / "existing"
        existing.mkdir()
        sentinel = existing / "keep"
        sentinel.write_bytes(b"unchanged")
        with self.assertRaises(ValueError):
            publication.reconstruct(path, existing, packet_sha, map_sha)
        self.assertEqual(sentinel.read_bytes(), b"unchanged")
        output = self.work / "new-output"
        with self.assertRaises((ValueError, OSError)):
            publication.reconstruct(path, output, packet_sha, map_sha)
        self.assertFalse(output.exists())
        output = self.work / "forced-verification-failure"
        with mock.patch.object(publication, "template_files", side_effect=ValueError("fixture verification failure")):
            with self.assertRaises(ValueError):
                publication.reconstruct(path, output, packet_sha, map_sha)
        self.assertFalse(output.exists())

    def test_real_selected_recipe_pack_is_deterministic_and_reconstructs_exactly(self):
        originals = source_check.template_files()
        original_tree = tree(source_check.HERE)
        inputs = dict(originals)
        if PACKET not in inputs:
            packet = Path("/tmp") / PACKET
            source_check.verify_packet(packet)
            inputs[PACKET] = source_check.read_selected_packet(packet)
        recipe = self.work / "recipe"
        recipe.mkdir()
        for name, data in inputs.items():
            (recipe / name).write_bytes(data)
            (recipe / name).chmod(0o644)
        approved = json.dumps({name: sha(data) for name, data in sorted(inputs.items())},
                              sort_keys=True, indent=2).encode() + b"\n"
        reviewed = self.work / "reviewed.json"
        reviewed.write_bytes(approved)
        before = tree(recipe)
        first, second = self.work / "first.tar.gz", self.work / "second.tar.gz"
        report = publication.pack(recipe, first, reviewed, sha(approved))
        repeat = publication.pack(recipe, second, reviewed, sha(approved))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(report, repeat)
        self.assertEqual(report["packet_sha256"], sha(first.read_bytes()))
        self.assertEqual(report["source_map_sha256"], sha(approved))
        self.assertFalse(report["private_full_archive_included"])
        self.assertEqual(report["codec_files"], 900)
        self.assertEqual(publication.read_bundle(first, sha(first.read_bytes()), sha(approved)), inputs)
        with tarfile.open(first, "r:gz") as archive:
            self.assertEqual(archive.extractfile(ROOT + "SOURCE-MAP.json").read(), approved)
            for member in archive:
                self.assertEqual((member.mode, member.uid, member.gid), (0o644, 0, 0))
        output = self.work / "reconstructed"
        restored = publication.reconstruct(first, output, report["packet_sha256"], sha(approved))
        self.assertEqual(source_check.template_files(output), inputs)
        self.assertEqual(restored["input_sha256"], {name: sha(data) for name, data in inputs.items()})
        self.assertEqual(tree(recipe), before)
        self.assertEqual(tree(source_check.HERE), original_tree)
        self.assertEqual(source_check.template_files(), originals)


if __name__ == "__main__":
    unittest.main()
