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
from unittest.mock import patch

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

    def pair(self, name, version, recipe=None):
        pkginfo = f"pkgname = {name}\npkgbase = {name}\npkgver = {version}\narch = aarch64\n".encode()
        digest = index.source.digest(self.recipe(name, version) if recipe is None else recipe)
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

    def candidate(self, version, raw=None):
        commit = "a" * 40
        if raw is None:
            raw = self.recipe("python", "3.14.8-1")
        path = "core/python/PKGBUILD"
        body = dict(type="file", path=path, size=len(raw), encoding="base64",
                    url=f"https://api.github.com/repos/org/package/contents/{path}?ref={commit}",
                    download_url=f"https://raw.githubusercontent.com/org/package/{commit}/{path}",
                    sha=hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest(),
                    content=base64.b64encode(raw).decode())
        return dict(package="python", version=version, repository="https://github.com/org/package",
                    commit=commit, path=path, file_response=self.ref(version + ".json", json.dumps(body).encode()))

    def workunit(self, recipe, extra=None):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:gz") as archive:
            if recipe is not None:
                member = tarfile.TarInfo("./python/PKGBUILD")
                member.size = len(recipe)
                archive.addfile(member, io.BytesIO(recipe))
            if extra:
                archive.addfile(extra)
        return raw.getvalue()

    def build_input(self, kind, raw, *, version="3.14.8-1"):
        return dict(package="python", version=version, kind=kind, artifact=self.ref(kind + ".artifact", raw))

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

    def test_plugbuild_append_matches_only_the_exact_signed_version(self):
        values = (b"0" * 128, b"1" * 128)
        raw = self.recipe("python", "3.14.8-1") + b"sha512sums=('" + b"' '".join(values) + b"')\n"
        generated = raw + b"\nsha512sums=('" + b"'\n            '".join(values) + b"')\n"
        self.packages["python"]["forward"] = self.pair("python", "3.14.8-1", generated)
        cfg = self.config([self.candidate(version, raw) for version in ("3.14.7-1", "3.14.8-1")])
        unchanged = index.compare(cfg, "b" * 64)
        self.assertEqual(unchanged["exact_recipe_count"], 0)
        cfg["plugbuild_client"] = self.ref("client.pl", b"fixture for pinned client")
        with self.assertRaisesRegex(ValueError, "exact archived Arch Linux ARM plugbuild client"):
            index.compare(cfg, "b" * 64)
        with patch.object(index, "PLUGBUILD_CLIENT_SHA256", cfg["plugbuild_client"]["sha256"]):
            result = index.compare(cfg, "b" * 64)
        self.assertEqual(result["exact_recipe_count"], 1)
        self.assertEqual(result["corresponding_source_fulfillment"], "NOT ESTABLISHED")
        forward, rollback = [row for row in result["packages"] if row["package"]["name"] == "python"]
        self.assertEqual(forward["candidates"][0]["status"], "SIGNED_RECIPE_DIGEST_MISMATCH")
        exact = forward["candidates"][0]["plugbuild_candidate"]
        self.assertEqual(exact["status"], "EXACT_SIGNED_RECIPE_MATCH")
        self.assertEqual(base64.b64decode(exact["body_base64"]), generated)
        self.assertNotIn("body_base64", rollback["candidates"][0]["plugbuild_candidate"])

    def test_plugbuild_refuses_unmodeled_checksum_layouts(self):
        simple = b"b2sums=('" + b"a" * 128 + b"')\n"
        for raw in (simple + b"source_aarch64=(other)\n",
                    simple + b"sha256sums=(SKIP)\n", b"b2sums=('SKIP')\n"):
            with self.subTest(raw=raw):
                self.assertEqual(index.plugbuild_candidate(raw, "0" * 64)["status"], "UNSUPPORTED_CHECKSUM_LAYOUT")

    def test_final_bytes_match_only_the_exact_signed_input(self):
        recipe = self.recipe("python", "3.14.8-1")
        exact = self.build_input("final-pkgbuild", recipe)
        drift = dict(exact, version="3.14.7-1")
        cfg = dict(self.config([]), build_inputs=[exact, drift])
        result = index.compare(cfg, "b" * 64)
        forward, rollback = [row for row in result["packages"] if row["package"]["name"] == "python"]
        self.assertEqual(result["exact_recipe_count"], 1)
        self.assertEqual(result["build_input_count"], 2)
        self.assertEqual(base64.b64decode(forward["build_inputs"][0]["body_base64"]), recipe)
        self.assertEqual(rollback["status"], "SIGNED_RECIPE_UNRECOVERED")
        self.assertNotIn("body_base64", rollback["build_inputs"][0])
        self.assertEqual(result["corresponding_source_fulfillment"], "NOT ESTABLISHED")
        with self.assertRaisesRegex(ValueError, "duplicate build input"):
            index.compare(dict(cfg, build_inputs=[exact, exact]), "b" * 64)

    def test_historical_workunit_plus_exact_checksum_stdout(self):
        recipe = self.recipe("python", "3.14.8-1")
        stdout = b"sha512sums=('"+b"a"*128+b"')\n"
        target = recipe + b"\n" + stdout
        self.packages["python"]["forward"] = self.pair("python", "3.14.8-1", target)
        row = self.build_input("workunit", self.workunit(recipe))
        row["checksum_stdout"] = self.ref("checksum.out", stdout)
        cfg = dict(self.config([]), build_inputs=[row])
        with self.assertRaisesRegex(ValueError, "pinned Plugbuild client"):
            index.compare(cfg, "b" * 64)
        cfg["plugbuild_client"] = self.ref("client.pl", b"fixture client")
        with patch.object(index, "PLUGBUILD_CLIENT_SHA256", cfg["plugbuild_client"]["sha256"]):
            result = index.compare(cfg, "b" * 64)
            self.assertEqual(result["exact_recipe_count"], 1)
            forward = next(row for row in result["packages"] if row["package"]["version"] == "3.14.8-1")
            self.assertEqual(base64.b64decode(forward["build_inputs"][0]["plugbuild_candidate"]["body_base64"]), target)
            row["checksum_stdout"] = self.ref("checksum.out", stdout.rstrip(b"\n"))
            self.assertEqual(index.compare(cfg, "b" * 64)["exact_recipe_count"], 0)

    def test_workunit_namespace_and_expansion_are_bounded(self):
        recipe = self.recipe("python", "3.14.8-1")
        raw = self.workunit(recipe)
        self.assertEqual(index.workunit_recipe(raw, "python"), recipe)
        for leaf in ("../foreign", "perl/PKGBUILD", "python/PKGBUILD"):
            with self.subTest(leaf=leaf), self.assertRaises(ValueError):
                index.workunit_recipe(self.workunit(recipe, tarfile.TarInfo(leaf)), "python")
        link = tarfile.TarInfo("python/LICENSES/0BSD.txt")
        link.type = tarfile.SYMTYPE
        link.linkname = "../LICENSE"
        self.assertEqual(index.workunit_recipe(self.workunit(recipe, link), "python"), recipe)
        link.name = "python/PKGBUILD"
        with self.assertRaisesRegex(ValueError, "bounded workunit PKGBUILD"):
            index.workunit_recipe(self.workunit(None, link), "python")
        with patch.object(index, "MAX_WORKUNIT_TAR", 512):
            with self.assertRaisesRegex(ValueError, "bounded decompressed workunit"):
                index.workunit_recipe(raw, "python")


if __name__ == "__main__":
    unittest.main()
