#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise commit binding and Git blob validation without network or builds."""

import base64
import hashlib
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("recipe_history", Path(__file__).with_name("join_signed_recipe_history.py"))
join = importlib.util.module_from_spec(spec)
spec.loader.exec_module(join)


class HistoryTests(unittest.TestCase):
    repository = "https://github.com/org/packages"
    commit = "a" * 40
    path = "core/demo/PKGBUILD"
    raw = b"pkgname=demo\npkgver=1.2\npkgrel=3\n"

    def github_record(self):
        raw = self.raw
        return dict(type="file", path=self.path, size=len(raw), encoding="base64",
                    url=f"https://api.github.com/repos/org/packages/contents/{self.path}?ref={self.commit}",
                    download_url=f"https://raw.githubusercontent.com/org/packages/{self.commit}/{self.path}",
                    sha=hashlib.sha1(f"blob {len(raw)}\0".encode() + raw).hexdigest(),
                    content=base64.b64encode(raw).decode())

    def test_github_exact_blob_rejects_content_and_commit_substitution(self):
        data = self.github_record()
        result = join.match_file(self.repository, self.commit, self.path, data)
        self.assertEqual(result["pkgbuild_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(result["git_blob_sha1"], data["sha"])
        with self.assertRaisesRegex(ValueError, "repository, commit or path"):
            join.match_file(self.repository, "b" * 40, self.path, data)
        data["content"] = base64.b64encode(self.raw.replace(b"pkgrel=3", b"pkgrel=4")).decode()
        with self.assertRaisesRegex(ValueError, "blob bytes"):
            join.match_file(self.repository, self.commit, self.path, data)

    def test_arch_gitlab_pins_commit_path_blob_and_raw_digest(self):
        github = self.github_record()
        data = dict(file_path="PKGBUILD", ref=self.commit, commit_id=self.commit, blob_id=github["sha"],
                    content_sha256=hashlib.sha256(self.raw).hexdigest(), size=github["size"],
                    encoding="base64", content=github["content"])
        repository = "https://gitlab.archlinux.org/archlinux/packaging/packages/demo"
        result = join.match_file(repository, self.commit, "PKGBUILD", data)
        self.assertEqual(result["git_blob_sha1"], data["blob_id"])
        self.assertIn("archlinux%2Fpackaging%2Fpackages%2Fdemo", result["file_endpoint"])
        with self.assertRaisesRegex(ValueError, "commit or path"):
            join.match_file(repository, self.commit, "core/demo/PKGBUILD", data)
        data["content_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "blob bytes"):
            join.match_file(repository, self.commit, "PKGBUILD", data)


if __name__ == "__main__":
    unittest.main()
