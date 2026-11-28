#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Synthetic pinned input and refusal controls with no update or GPG actors."""

from io import BytesIO
from pathlib import Path
from runpy import run_path
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


P = run_path(str(Path(__file__).with_name("asahi629_preflight.py")))
T, O, A = (P[key] for key in ("T", "O", "A"))


class Asahi629PreflightTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.old = {name: versions[0] for name, versions in O["REVERSED"].items()}
        base_dependencies = P["UPDATER_DEPENDS"] - P["RUNTIME_PACKAGES"].keys() - self.old.keys()
        self.old.update(dict.fromkeys(base_dependencies, "1-1"))
        self.old.update({f"base-{index:03}": "1-1" for index in range(629 - len(self.old))})
        self.new = self.old | {name: versions[1] for name, versions in O["REVERSED"].items()}
        self.paths = {role: self.root / (role + ".lock") for role in P["LOCKS"]}
        self.refs = {}
        for role, path in self.paths.items():
            contents = self.new if role == "candidate" else self.old
            raw = self.save_lock(path, contents)
            self.refs[P["LOCKS"][role]] = (629, len(raw), T["pin"](raw)["sha256"])
        self.pins, self.pairs = {}, {}
        self.key = "keys/alarm.gpg"
        self.save(self.key, b"synthetic public certificate")
        signer = A["FINGERPRINT"]
        for role, phase in P["ARCHIVE_PHASES"].items():
            self.pairs[phase] = {}
            for name in O["REVERSED"]:
                version = (self.new if role == "candidate" else self.old)[name]
                leaf = f"{phase}/{name}-{version}-aarch64.pkg.tar.xz"
                self.pairs[phase][name] = dict(archive=leaf, scope="vendor", signer=signer)
                self.save(leaf, f"archive {leaf}".encode())
                self.save(leaf + ".sig", f"signature {leaf}".encode())
        manifest = dict(kind=O["KIND"], keys={"alarm": dict(file=self.key, scope="vendor", fingerprint=signer)},
                        files=self.pins, packages=self.pairs)
        raw = T["encoded"](manifest)
        (self.root / "manifest.json").write_bytes(raw)
        self.enterContext(patch.dict(O, REFS=self.refs))
        self.enterContext(patch.dict(P["audit"].__globals__, TRANSPORT=T["pin"](raw),
                                     public_keyring=lambda _key, home: home / "alarm.gpg"))
        self.enterContext(patch.dict(A, verify_signature=self.verify_pair))

    @staticmethod
    def save_lock(path, inventory):
        raw = "".join(f"{name} {version}\n" for name, version in sorted(inventory.items())).encode()
        path.write_bytes(raw)
        return raw

    def save(self, leaf, raw):
        path = self.root / leaf
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        self.pins[leaf] = T["pin"](raw)

    def verify_pair(self, row, home, keyring):
        self.assertEqual(row["signer"], A["FINGERPRINT"])
        directory = self.root if "/" in row["filename"] else self.root / "runtime"
        self.assertEqual(row["archive"]["path"], directory / row["filename"])
        self.assertEqual(row["signature"]["path"], directory / (row["filename"] + ".sig"))
        self.assertEqual(keyring.parent, home)
        return T["pin"](b"simulated verification")

    @staticmethod
    def package(name, version, arch, depends, conflicts=()):
        fields = [("pkgname", name), ("pkgver", version), ("arch", arch)]
        fields.extend(("depend", dependency) for dependency in sorted(depends))
        fields.extend(("conflict", conflict) for conflict in sorted(conflicts))
        pkginfo = "".join(f"{key} = {value}\n" for key, value in fields).encode()
        raw = BytesIO()
        with tarfile.open(fileobj=raw, mode="w:xz") as archive:
            for leaf, body in ((".BUILDINFO", b"fixture"), (".MTREE", b"fixture"), (".PKGINFO", pkginfo)):
                member = tarfile.TarInfo(leaf)
                member.size = len(body)
                archive.addfile(member, BytesIO(body))
        return raw.getvalue()

    def runtime(self, *, overrides=None):
        overrides = {} if overrides is None else overrides
        pins = {}
        for name, (version, arch, depends) in P["RUNTIME_PACKAGES"].items():
            leaf = f"{name}-{version}-{arch}.pkg.tar.xz"
            self.save("runtime/" + leaf, self.package(name, *overrides.get(name, (version, arch, depends))))
            self.save("runtime/" + leaf + ".sig", f"runtime signature for {name}".encode())
            for part in (leaf, leaf + ".sig"):
                pins[part] = self.pins["runtime/" + part]
        updater = self.package(P["UPDATER_NAME"], "4.4.2-3", "aarch64",
                               P["UPDATER_DEPENDS"], P["UPDATER_CONFLICTS"])
        self.save("updater.pkg", updater)
        self.enterContext(patch.dict(P["audit"].__globals__, UPDATER=T["pin"](updater), runtime_pins=lambda: pins))
        return dict(updater=self.root / "updater.pkg", updater_runtime=self.root / "runtime")

    def audit(self, **paths):
        return P["audit"](**(self.paths | paths), media=self.root)

    def test_complete_vendor_operands_remain_held_for_unselected_update(self):
        result = self.audit()
        self.assertEqual(result["status"], "HOLD_ASAHI629_COORDINATED_UPDATE_INPUTS")
        self.assertIsNone(result["authority"])
        self.assertEqual(result["inventories"]["before"], result["inventories"]["recovery"])
        self.assertEqual(result["missing_retained_files"], [])
        self.assertTrue(result["unselected_prerequisites"])
        self.assertNotIn("updater_runtime_projection", result)
        for phase in ("candidate", "recovery"):
            self.assertEqual(result["operands"][phase].keys(), O["REVERSED"].keys())
            self.assertTrue(all("gpgv_status" in row for row in result["operands"][phase].values()))

    def test_candidate_cannot_reuse_recovery_even_with_all_629_names(self):
        with self.assertRaisesRegex(ValueError, "Changed pinned bytes: recovery.lock"):
            self.audit(candidate=self.paths["recovery"])

    def test_recovery_cannot_change_one_unrelated_row_at_same_count(self):
        self.save_lock(self.paths["recovery"], self.old | {"base-000": "2-1"})
        with self.assertRaisesRegex(ValueError, "Changed pinned bytes: recovery.lock"):
            self.audit()

    def test_missing_recovery_signature_leaves_only_that_pair_unverified(self):
        leaf = self.pairs["rollback"]["python"]["archive"] + ".sig"
        (self.root / leaf).unlink()
        result = self.audit()
        self.assertEqual(result["missing_retained_files"], [leaf])
        self.assertNotIn("gpgv_status", result["operands"]["recovery"]["python"])
        self.assertIn("gpgv_status", result["operands"]["candidate"]["python"])

    def test_signed_operands_cannot_be_exchanged_between_candidate_and_recovery(self):
        left, right = (self.root / (self.pairs[phase]["perl"]["archive"] + ".sig") for phase in ("forward", "rollback"))
        old, new = left.read_bytes(), right.read_bytes()
        left.write_bytes(new)
        right.write_bytes(old)
        with self.assertRaisesRegex(ValueError, "Expected file length or digest differs|Changed pinned bytes"):
            self.audit()

    def test_manifest_pins_cannot_override_a_cryptographic_refusal(self):
        def refuse(_row, _home, _keyring):
            raise ValueError("ALARM detached signature refused")

        with patch.dict(A, verify_signature=refuse), self.assertRaisesRegex(ValueError, "detached signature refused"):
            self.audit()

    def test_symlinked_signature_refused_instead_of_treated_as_absent(self):
        path = self.root / (self.pairs["forward"]["perl"]["archive"] + ".sig")
        path.unlink()
        path.symlink_to(self.root / "missing")
        with self.assertRaisesRegex(ValueError, "Canonical ordinary absolute path"):
            self.audit()

    def test_runtime_projection_checks_four_packages_without_granting_admission(self):
        result = self.audit(**self.runtime())
        projection = result["updater_runtime_projection"]
        self.assertIsNone(result["authority"])
        self.assertEqual(result["status"], "HOLD_ASAHI629_COORDINATED_UPDATE_INPUTS")
        self.assertEqual(projection["status"], "PROJECTED_ONLY")
        self.assertEqual(projection["alpm_prepare"], "NOT RUN")
        self.assertEqual(projection["updater_test_signature"], "PENDING")
        self.assertEqual(projection["signed_repositories"], "PENDING")
        additions = {"archlinux-contrib": "20261009-1", "htmlq": "0.4.0-3",
                     "pyalpm": "0.12.0-1", "cachy-asahi-update": "4.4.2-3"}
        self.assertEqual({name: row["version"] for name, row in projection["packages"].items()}, additions)
        for name in P["RUNTIME_PACKAGES"]:
            self.assertEqual(projection["packages"][name]["gpgv_status"], T["pin"](b"simulated verification"))
        for role, baseline in (("before", self.old), ("candidate", self.new), ("recovery", self.old)):
            path = self.root / ("projected-" + role + ".lock")
            expected = self.save_lock(path, baseline | additions)
            self.assertEqual(projection["inventories"][role], dict(T["pin"](expected), packages=633))
            self.assertEqual(result["inventories"][role]["packages"], 629)

    def test_runtime_projection_requires_updater_archive(self):
        with self.assertRaisesRegex(ValueError, "requires --updater"):
            self.audit(updater_runtime=self.root)

    def test_projection_requires_complete_base_operands(self):
        paths = self.runtime()
        (self.root / self.pairs["rollback"]["perl"]["archive"]).unlink()
        with self.assertRaisesRegex(ValueError, "requires complete retained Asahi629"):
            self.audit(**paths)

    def test_runtime_projection_refuses_changed_signature(self):
        paths = self.runtime()
        signature = paths["updater_runtime"] / "htmlq-0.4.0-3-aarch64.pkg.tar.xz.sig"
        signature.write_bytes(signature.read_bytes()[::-1])
        with self.assertRaisesRegex(ValueError, "Changed pinned bytes"):
            self.audit(**paths)

    def test_runtime_projection_refuses_cryptographic_failure(self):
        paths = self.runtime()

        def refuse(row, home, keyring):
            if row["filename"].startswith("pyalpm-"):
                raise ValueError("runtime signature refused")
            return self.verify_pair(row, home, keyring)

        with patch.dict(A, verify_signature=refuse), self.assertRaisesRegex(ValueError, "runtime signature refused"):
            self.audit(**paths)

    def test_runtime_projection_refuses_mismatched_package_identity(self):
        paths = self.runtime(overrides={"htmlq": ("9-1", "aarch64", ("glibc", "libgcc"))})
        with self.assertRaisesRegex(ValueError, "Unexpected package identity: htmlq"):
            self.audit(**paths)

    def test_runtime_projection_refuses_missing_transitive_dependency_declaration(self):
        paths = self.runtime(overrides={"archlinux-contrib": ("20261009-1", "any", ("bash", "python"))})
        with self.assertRaisesRegex(ValueError, "Unexpected package relations: archlinux-contrib"):
            self.audit(**paths)

    def test_runtime_projection_refuses_unresolved_dependency(self):
        paths = self.runtime()
        for role, inventory in (("before", self.old), ("candidate", self.new), ("recovery", self.old)):
            changed = inventory | {"no-libgcc": "1-1"}
            del changed["libgcc"]
            raw = self.save_lock(self.paths[role], changed)
            self.refs[P["LOCKS"][role]] = (629, len(raw), T["pin"](raw)["sha256"])
        with self.assertRaisesRegex(ValueError, "Unresolved runtime package relations in before lock: htmlq"):
            self.audit(**paths)


if __name__ == "__main__":
    unittest.main()
