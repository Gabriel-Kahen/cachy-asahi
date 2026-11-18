#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise exact forward catalog pins and baseline rollback identity matching."""

import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("maintenance_rollback", Path(__file__).with_name("join_maintenance_rollback.py"))
join = importlib.util.module_from_spec(spec)
spec.loader.exec_module(join)


class RollbackJoinTests(unittest.TestCase):
    def test_old_build_identity_and_relation_must_match(self):
        baseline = dict(NAME=["python"], BASE=["python"], VERSION=["3.14.7-1"], ARCH=["aarch64"],
                        BUILDDATE=["1786542069"], PACKAGER=["original"], DEPENDS=["libffi", "zlib"])
        signed = dict(pkgname=["python"], pkgbase=["python"], pkgver=["3.14.7-1"], arch=["aarch64"],
                      builddate=["1786542069"], packager=["original"], depend=["zlib", "libffi"])
        join.exact_baseline_pkginfo(baseline, signed)
        with self.assertRaisesRegex(ValueError, "signed installed metadata differs: BUILDDATE"):
            join.exact_baseline_pkginfo(baseline, dict(signed, builddate=["1786542070"]))
        with self.assertRaisesRegex(ValueError, "signed installed metadata differs: DEPENDS"):
            join.exact_baseline_pkginfo(baseline, dict(signed, depend=["libffi"]))

    def test_forward_candidate_needs_catalog_bound_detached_signature(self):
        filename = "python-3.14.8-1-aarch64.pkg.tar.xz"
        signature = b"catalog signature"
        sha = "1" * 64
        selected = dict(name="python", repo="core", metadata=dict(NAME=["python"], VERSION=["3.14.8-1"],
            ARCH=["aarch64"], FILENAME=[filename], CSIZE=["32"], SHA256SUM=[sha],
            PGPSIG=[base64.b64encode(signature).decode()]))
        pair = dict(archive=dict(path="/fixture/" + filename, size=32, sha256=sha),
                    signature=dict(path="/fixture/" + filename + ".sig", size=len(signature),
                                   sha256=hashlib.sha256(signature).hexdigest()))
        self.assertEqual(join.verify_forward_pins(pair, selected), (filename, filename + ".sig"))
        pair["signature"]["sha256"] = "2" * 64
        with self.assertRaisesRegex(ValueError, "signature differs from exact catalog"):
            join.verify_forward_pins(pair, selected)


if __name__ == "__main__":
    unittest.main()
