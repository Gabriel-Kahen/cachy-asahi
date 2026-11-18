# SPDX-License-Identifier: MIT
"""Offline Source closure and frozen-input controls."""

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import prepare

R = prepare.R


class RuntimeSourceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def put(self, root, name, raw):
        root.mkdir(exist_ok=True)
        R.write(root, name, raw)
        return R.pin(raw)

    def seal(self, root, bodies):
        for path, raw in bodies.items():
            self.put(root, path, raw)
        mapping = dict(kind=R.KIND, schema=1, files={name:dict(R.pin(body), mode=0o644) for name,body in bodies.items()})
        return self.put(root, R.MAP, R.canonical(mapping))["sha256"]

    def test_namespace_enforces_original_mode_and_extra_leaves(self):
        src = self.root/"src"
        expected = self.seal(src, {R.INPUTS:R.canonical({"entry":None}), "scripts/entry.py":b"# MODEL\n"})
        self.assertEqual(len(R.verify(src, expected)["files"]), 2)
        (src/".git").write_text("MODEL metadata")
        R.verify(src, expected)
        with self.assertRaisesRegex(ValueError, "whole runtime map"):
            R.verify(src, "0"*64)
        body = src/"scripts/entry.py"
        body.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "ordinary runtime Source leaf"):
            R.verify(src, expected)
        body.chmod(0o644)
        self.put(src, "surprise.py", b"")
        with self.assertRaisesRegex(ValueError, "namespace"):
            R.verify(src, expected)

    def test_frozen_helper_staging_refuses_different_bytes(self):
        src, external = self.root/"src", self.root/"external"
        name = f"{R.PARENT}/f-recipe.lock.json"
        body = b"MODEL frozen bytes"
        old = self.put(external, name, body)
        with patch.object(R, "EXTERNAL", {name:old}):
            selected = self.seal(src, {R.INPUTS:R.canonical(dict(entry=None, external_family_locks={name:old},
                                                               helper_files=["scripts/import.py"])),
                                       "scripts/import.py":b"# MODEL"})
            output = self.root/"stage"
            R.stage_helpers(source=src, map_sha256=selected, frozen_locks=external, output=output)
            self.assertEqual((output/name).read_bytes(), body)
            self.assertFalse((src/name).exists())
            (external/name).write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "body pin"):
                R.stage_helpers(source=src, map_sha256=selected, frozen_locks=external, output=self.root/"refused")
            self.assertFalse((self.root/"refused").exists())

    def test_public_boundary_keeps_only_exact_signature_filename(self):
        for path, raw in (("portable/pkg.pkg.tar.xz", b"opaque"),
                          ("runtime.json", b'{"path":"/home/gabe/work"}'),
                          ("private.gpg", b"-----BEGIN PGP PRIVATE KEY BLOCK-----")):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "Host paths, private keys or package archive"):
                    prepare.public_leaf(path, raw)
        prepare.public_leaf(prepare.SIGNED, b"fixture checked independently")

    def test_exact_entry_is_optional_and_only_selected_git_blobs_are_adopted(self):
        repo = self.root/"repo"
        repo.mkdir()

        def git(*args):
            return subprocess.run(["/usr/bin/git", "-C", str(repo), *args], capture_output=True,
                                  check=True, timeout=8).stdout

        git("init", "-q")
        script = self.put(repo, prepare.ENTRY, b"def main():\n    pass\n")
        git("add", "--", prepare.ENTRY)
        git("-c", "user.name=Model", "-c", "user.email=model@example.invalid", "commit", "-qm", "Inert fixture")
        cid = git("rev-parse", "HEAD").decode().strip()
        selection = R.canonical(dict(kind="QT612_GUI_PAIR_ENTRY_SELECTION_V1", commit=cid,
                                     entry=prepare.ENTRY, files={prepare.ENTRY:script}))
        pick = self.put(self.root, "selection.json", selection)
        self.assertEqual(prepare.selected_entry(repo, None, None), (None, {}, None))
        (repo/prepare.ENTRY).write_bytes(b"Working bytes are deliberately different.")
        entry, bodies, _ = prepare.selected_entry(repo, self.root/"selection.json", pick["sha256"])
        self.assertEqual(entry, dict(path=prepare.ENTRY, **script))
        self.assertEqual(R.pin(bodies[prepare.ENTRY]), script)
        with self.assertRaisesRegex(ValueError, "Selected input digest"):
            prepare.selected_entry(repo, self.root/"selection.json", "0"*64)


if __name__ == "__main__":
    unittest.main()
