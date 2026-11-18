#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check version-isolated recipe matching and retained package readback."""

import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("maintenance_history", Path(__file__).with_name("index_maintenance_recipe_history.py"))
index = importlib.util.module_from_spec(spec)
spec.loader.exec_module(index)


class MaintenanceHistoryTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.packages = {}
        for name, (before, after, repo) in index.rollback.EXACT.items():
            self.packages[name] = dict(arch="aarch64", change=dict(name=name, before=before, after=after, repo=repo),
                                       forward=self.pair(name, after), rollback=self.pair(name, before))

    def ref(self, name, raw):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(0o600)
        return dict(path=str(path), size=len(raw), sha256=index.source.digest(raw))

    @staticmethod
    def recipe(name, version):
        return f"pkgname={name}\n# {version}\n".encode()

    def pair(self, name, version):
        pkginfo = f"pkgname = {name}\npkgbase = {name}\npkgver = {version}\narch = aarch64\n".encode()
        digest = index.source.digest(self.recipe(name, version))
        buildinfo = (f"format = 2\npkgname = {name}\npkgbase = {name}\npkgver = {version}\npkgarch = aarch64\n"
                     f"pkgbuild_sha256sum = {digest}\nbuilddate = 1234567890\n").encode()
        filename = f"{name}-{version}-aarch64.pkg.tar.xz"
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:xz") as archive:
            for key, payload in ((".PKGINFO", pkginfo), (".BUILDINFO", buildinfo)):
                member = tarfile.TarInfo(key)
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
        return dict(archive=self.ref(filename, raw.getvalue()), signature=self.ref(filename + ".sig", b"fixture evidence"),
                    verification=dict(status="cryptographic-signature-valid", fresh_verification=True,
                                      independent_owner_trust_accepted=False, primary_fingerprint="A" * 40,
                                      pkginfo_sha256=index.source.digest(pkginfo)))

    def config(self, candidates):
        receipt = dict(kind=index.rollback.KIND + "-result", schema_version=1, status="HOLD", approval_status="UNAPPROVED",
                       production_trust=False, transaction_accepted=False, verified_forward_pair_count=3,
                       verified_rollback_pair_count=3, packages=self.packages)
        archive_join = self.ref("join.json", json.dumps(receipt).encode())
        return dict(kind=index.KIND, schema_version=1, archive_join=archive_join, candidates=candidates)

    def candidate(self, version):
        commit = "a" * 40
        raw = self.recipe("python", "3.14.8-1")
        path = "core/python/PKGBUILD"
        body = dict(type="file", path=path, size=len(raw), encoding="base64",
                    url=f"https://api.github.com/repos/org/package/contents/{path}?ref={commit}",
                    download_url=f"https://raw.githubusercontent.com/org/package/{commit}/{path}",
                    sha=hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest(),
                    content=base64.b64encode(raw).decode())
        return dict(package="python", version=version, repository="https://github.com/org/package",
                    commit=commit, path=path, file_response=self.ref(version + ".json", json.dumps(body).encode()))

    def test_same_blob_matches_only_the_expected_version(self):
        candidates = [self.candidate(version) for version in ("3.14.7-1", "3.14.8-1")]
        result = index.compare(self.config(candidates), "b" * 64)
        self.assertEqual(result["package_count"], 6)
        self.assertEqual(result["exact_recipe_count"], 1)
        self.assertFalse(result["production_trust"])
        rows = {row["direction"]: row for row in result["packages"] if row["package"]["name"] == "python"}
        self.assertEqual(rows["forward"]["status"], "EXACT_SIGNED_RECIPE_MATCH")
        self.assertEqual(rows["rollback"]["candidates"][0]["status"], "SIGNED_RECIPE_DIGEST_MISMATCH")

    def test_changed_retained_signature_is_refused(self):
        configuration = self.config([self.candidate("3.14.8-1")])
        reference = self.packages["perl"]["rollback"]["signature"]
        Path(reference["path"]).write_bytes(b"!" * reference["size"])
        with self.assertRaisesRegex(ValueError, "whole-file reference differs"):
            index.compare(configuration, "b" * 64)

    def test_unrelated_version_or_repeated_candidate_is_refused(self):
        candidate = self.candidate("3.14.8-1")
        for candidates in ([dict(candidate, version="3.14.9-1")], [candidate, candidate]):
            with self.subTest(candidates=candidates), self.assertRaisesRegex(ValueError, "duplicate candidate or unrelated"):
                index.compare(self.config(candidates), "b" * 64)


if __name__ == "__main__":
    unittest.main()
