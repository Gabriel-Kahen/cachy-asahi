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

    def test_md4c_projection_requires_the_complete_original_receipt_sha256(self):
        receipt = "0817066cbec53daf2ed52569340141f842caa03db86cb3fc35d10a4db0f48e97"
        model = dict(schema=1, kind="ROOT_QT612_R128_MD4C_TEST_AUTHORITY_V1", issuer="Root", approved=True,
            status="PASS_MD4C_R128_EXACT_ARCHIVES_SCOPED_TEST_ONLY", source=prepare.R128["commit"],
            run=44241902162, job=134591565463, attempt=1,
            original_log=dict(bytes=2255414, sha256="ec0b1d79132cb9bcb2e5646ac2e70f675c57b8747f60cdab2737dc5bacc4d734"),
            original_receipt=dict(bytes=2466, sha256=receipt),
            archive=dict(bytes=74076, sha256="19149e51f05a7d93426dda7a66fd80d67bd235cab7ac4505130f7de6d40b5b95"),
            signature=prepare.MD4C[prepare.SIGNED], certificate=prepare.MD4C[prepare.CERTIFICATE],
            fingerprint="D02BE98DE9C0986C1120951315A8B1E319DBEE03", created_epoch=1794978886, expires_epoch=1795065286)
        path = self.root/"MODEL-md4c-authority.json"
        raw = R.canonical(model)
        path.write_bytes(raw)
        self.assertEqual(prepare.md4c_authority(path, R.pin(raw)["sha256"]), raw)
        model["original_receipt"]["sha256"] = receipt.replace("86cb", "")
        raw = R.canonical(model)
        path.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "Exact already selected"):
            prepare.md4c_authority(path, R.pin(raw)["sha256"])

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
