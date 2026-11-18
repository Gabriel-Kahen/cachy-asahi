#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Data-only controls for signed addition source indexing."""

import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("addition_index", Path(__file__).with_name("index_signed_addition_sources.py"))
idx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(idx)


class AdditionSourceTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.package = "helper"
        self.base = "helper-suite"
        self.version = "1.3-2"
        self.selected = dict(name=self.package, repo="project", version=self.version)
        self.recipe = self.ref(self.root / "PKGBUILD", b"original recipe")
        self.pkginfo = f"pkgname = {self.package}\npkgbase = {self.base}\npkgver = {self.version}\narch = any\nlicense = MIT\n".encode()
        self.buildinfo = (f"format = 2\npkgname = {self.package}\npkgver = {self.version}\npkgarch = any\n"
                          f"pkgbase = {self.base}\npkgbuild_sha256sum = {self.recipe['sha256']}\n"
                          "installed = make-4.4-1-aarch64\n").encode()

    def ref(self, path, raw):
        path.write_bytes(raw)
        path.chmod(0o444)
        return dict(path=str(path), size=len(raw), sha256=idx.source.digest(raw))

    def pair(self, buildinfo=None, bad_link=False):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:xz") as archive:
            for name, payload in ((".PKGINFO", self.pkginfo), (".BUILDINFO", buildinfo or self.buildinfo)):
                member = tarfile.TarInfo(name)
                if bad_link and name == ".BUILDINFO":
                    member.type = tarfile.SYMTYPE
                    member.linkname = ".PKGINFO"
                    archive.addfile(member)
                else:
                    member.size = len(payload)
                    archive.addfile(member, io.BytesIO(payload))
        leaf = f"{self.package}-{self.version}-any.pkg.tar.xz"
        return dict(archive=self.ref(self.cache / leaf, raw.getvalue()),
                    signature=self.ref(self.cache / (leaf + ".sig"), b"previously verified fixture signature"),
                    signer_role="project-test", verification=dict(status="cryptographic-signature-valid",
                        fresh_verification=True, primary_fingerprint="A" * 40, pkginfo_sha256=idx.source.digest(self.pkginfo)))

    def inspect(self, pair, originals=None):
        return idx.stage_pair(self.package, pair, self.selected, self.cache, originals)

    def test_split_package_and_build_input_pins(self):
        row = self.inspect(self.pair())
        self.assertEqual(row["package"]["name"], self.package)
        self.assertEqual(row["pkgbase"], self.base)
        self.assertEqual(row["buildinfo"]["sha256"], idx.source.digest(self.buildinfo))
        self.assertEqual(row["buildinfo"]["installed_count"], 1)
        self.assertEqual(row["pkgbuild_sha256"], self.recipe["sha256"])
        self.assertEqual(row["source_status"], "RECIPE_DIGEST_ONLY")

    def test_detached_signature_ref_pin_checked_again(self):
        pair = self.pair()
        path = Path(pair["signature"]["path"])
        path.chmod(0o600)
        path.write_bytes(b"x" * pair["signature"]["size"])
        with self.assertRaisesRegex(ValueError, "whole-file reference differs"):
            self.inspect(pair)

    def test_buildinfo_links_and_identity_mismatch_refused(self):
        with self.assertRaisesRegex(ValueError, "unsafe or oversized"):
            self.inspect(self.pair(bad_link=True))
        for file in self.cache.iterdir():
            file.unlink()
        with self.assertRaisesRegex(ValueError, "BUILDINFO package identity"):
            self.inspect(self.pair(self.buildinfo.replace(b"pkgbase = helper-suite", b"pkgbase = foreign")))

    def test_retained_original_recipe_and_all_inputs_must_match(self):
        license_ref = self.ref(self.root / "LICENSE", b"published license")
        notice_ref = self.ref(self.root / "NOTICE", b"published notice")
        prov = dict(schema_version=1, candidate_version=self.version,
                    input_sha256={"LICENSE": license_ref["sha256"], "NOTICE": notice_ref["sha256"]})
        provenance = self.ref(self.root / "source-provenance.json", json.dumps(prov).encode())
        sources = {"LICENSE": license_ref["sha256"], "NOTICE": notice_ref["sha256"], "source-provenance.json": provenance["sha256"]}
        srcinfo = (f"pkgbase = {self.base}\n\tpkgver = 1.3\n\tpkgrel = 2\n\tarch = any\n\tlicense = MIT\n"
                   + "".join(f"\tsource = {name}\n\tsha256sums = {pin}\n" for name, pin in sources.items())
                   + f"pkgname = {self.package}\n").encode()
        record = dict(name=self.package, recipe=self.recipe, srcinfo=self.ref(self.root / ".SRCINFO", srcinfo),
                      provenance=provenance)
        pair = self.pair()
        row = self.inspect(pair, record)
        self.assertEqual(row["source_status"], "RETAINED_ORIGINAL_INPUTS_HASH_MATCHED")
        self.assertEqual(row["retained_original"]["license_review"], "NOT REVIEWED")
        self.assertEqual(row["retained_original"]["retained_files"]["LICENSE"]["sha256"], license_ref["sha256"])
        srcinfo_path = Path(record["srcinfo"]["path"])
        srcinfo_path.unlink()
        record["srcinfo"] = self.ref(srcinfo_path, srcinfo.replace(b"source = NOTICE", b"source = impostor"))
        with self.assertRaisesRegex(ValueError, "declared local .SRCINFO inputs"):
            self.inspect(pair, record)
        srcinfo_path.unlink()
        record["srcinfo"] = self.ref(srcinfo_path, srcinfo)
        path = Path(license_ref["path"])
        path.chmod(0o600)
        path.write_bytes(b"impostor license")
        with self.assertRaisesRegex(ValueError, "retained original file differs"):
            self.inspect(pair, record)
        path = Path(self.recipe["path"])
        path.unlink()
        record["recipe"] = self.ref(path, b"different exact recipe")
        with self.assertRaisesRegex(ValueError, "does not match signed PKGBUILD"):
            self.inspect(pair, record)


if __name__ == "__main__":
    unittest.main()
