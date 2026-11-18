# SPDX-License-Identifier: MIT
"""Offline model for the archived md4c-to-Qt dependency transition."""

import copy
import io
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import md4c_handoff as H

C, M, P = H.C, H.M, H.P
N = C.local("pipeline")
sys.addaudithook(M.fence)
PKGINFO = dict(pkgname=["md4c"], pkgver=["0.5.3-1"], arch=["aarch64"], depend=["glibc"])
SIGNATURE = b"MODEL detached signature bytes, no authentication\n"


def reference(path):
    return dict(path=str(path), **C.pin(path.read_bytes()))


def archive(path, metadata):
    """An XZ tar with real metadata syntax and no compiled payload."""
    raw = "".join(f"{key} = {value}\n" for key, values in metadata.items() for value in values).encode()
    member = tarfile.TarInfo(".PKGINFO")
    member.size = len(raw)
    with tarfile.open(path, "w:xz") as package:
        package.addfile(member, io.BytesIO(raw))


class Handoff(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="qt612-md4c-MODEL-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.package = self.root / H.PACKAGE
        self.signature = self.root / (H.PACKAGE + ".sig")
        archive(self.package, PKGINFO)
        self.signature.write_bytes(SIGNATURE)

    def handoff(self, **changes):
        inputs = dict(archive=self.package, signature=self.signature,
                      archive_pin=C.pin(self.package.read_bytes()), signature_pin=C.pin(SIGNATURE))
        return H.build_reference(**(inputs | changes))

    def test_rejects_wrong_names_and_external_pins(self):
        for overrides, message in (
            (dict(archive=self.root / "renamed.pkg.tar.xz"), "archive and detached signature names"),
            (dict(signature=self.root / "renamed.sig"), "archive and detached signature names"),
            (dict(archive_pin=C.pin(self.package.read_bytes()) | {"sha256": "0" * 64}), "STABLE_WHOLE_FILE_PIN"),
            (dict(signature_pin=C.pin(b"x" * len(SIGNATURE))), "STABLE_WHOLE_FILE_PIN"),
            (dict(signature_pin=C.pin(b"")), "Nonempty package and signature bytes"),
        ):
            with self.subTest(overrides=overrides), self.assertRaisesRegex(ValueError, message):
                self.handoff(**overrides)

    def test_rejects_wrong_package_metadata_even_with_exact_byte_pin(self):
        fields = (dict(pkgver=["0.6.0-2"]), dict(arch=["x86_64"]), dict(depend=["libgcc"]),
                  dict(depend=["glibc", "glibc"]), dict(provides=["md4c=0.5.3"]))
        for change in fields:
            archive(self.package, PKGINFO | change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.handoff()

    def test_cli_emits_only_the_producer_reference(self):
        argv = ["md4c_handoff.py"]
        for role, path in (("archive", self.package), ("signature", self.signature)):
            pin = reference(path)
            argv.extend([f"--{role}", pin["path"], f"--{role}-bytes", str(pin["bytes"]),
                         f"--{role}-sha256", pin["sha256"]])
        output = io.BytesIO()
        with patch.object(sys, "argv", argv), patch.object(sys, "stdout", SimpleNamespace(buffer=output)):
            H.main()
        self.assertEqual(output.getvalue(), C.encoded(self.handoff()))

    def modeled_additions(self, lock):
        model = copy.deepcopy(lock)
        refs = {}
        for row in model["additional"].values():
            name = row["filename"]
            package = self.root / name
            signature = self.root / (name + ".sig")
            archive(package, row["PKGINFO"])
            signature.write_bytes(SIGNATURE)
            for role, path in (("archive", package), ("signature", signature)):
                ref = reference(path)
                refs[path.name] = ref
                row[role] = {key: ref[key] for key in ("bytes", "sha256")}
        candidate_map = self.root / "MODEL-candidates.json"
        candidate_map.write_bytes(C.encoded(refs))
        return model, candidate_map

    def family_source(self, dependencies, inventory):
        root = self.root / "MODEL-family-source"
        writer = M.Writer(root)
        try:
            files = {
                "family-inputs.DATA.json": writer.put(
                    "family-inputs.DATA.json", raw=C.encoded(dict(base_provider=None, dependencies=dependencies))),
                "expected356.lock": writer.put("expected356.lock", raw=inventory),
            }
            mapping = dict(kind="QT612_COMPLETE_FAMILY_SOURCE_DATA_V1", files=files,
                           input_plan_complete=True, actual=dict.fromkeys(M.ACTUAL), Root_acceptance=None)
            raw = C.encoded(mapping)
            writer.put("source-map.json", raw=raw)
        finally:
            writer.close()
        return root, C.pin(raw)["sha256"]

    def test_real_intake_opens_all_seven_pairs_and_plans_the_356_image(self):
        lock = P.selected(C.PARENT / "dependency-candidates.lock.json", P.DEPENDENCIES, {})
        model, candidate_map = self.modeled_additions(lock)
        handoff = self.handoff()
        self.assertEqual(handoff["archive"], reference(self.package))
        self.assertEqual(handoff["signature"], reference(self.signature))
        with patch.object(P, "CANDIDATE_MAP", C.pin(candidate_map.read_bytes())):
            missing = P.dependency_inputs(candidate_map=candidate_map, md4c=None, lock=model, observed={})
            self.assertFalse(missing["complete"])
            self.assertEqual((missing["available_packages"], len(missing["missing_roles"])), (6, 3))
            observed = {}
            ready = P.dependency_inputs(candidate_map=candidate_map, md4c=handoff, lock=model, observed=observed)
            M.unchanged(observed)
            self.assertTrue(ready["complete"])
            self.assertEqual(ready["available_packages"], 7)
            self.assertEqual(ready["packages"]["md4c"], handoff)
            self.assertEqual(len(observed), 15)  # Map and fourteen independently pinned leaves.
            self.assertEqual(ready["GPG"], "NOT_RUN")
            self.assertIsNone(ready["Root_acceptance"])

        baseline_path = HERE.parents[2] / "scripts/ci/hyprland03-native-source-v1/fixtures/expected349.lock"
        raw = M.stream(baseline_path, lock["baseline_inventory"], {}, collect=True)
        inventory = dict(line.split(" ", 1) for line in raw.decode("ascii").splitlines())
        base = dict(kind="QT612_COMPLETE517_INPUT_DATA_ONLY", files=517, inventory=inventory, Root_acceptance=None)
        contract = M.decode((C.PARENT / "fixtures/F-contract.DATA.json").read_bytes())
        recipe = dict(provenance=dict(recipe_commit=P.F_COMMIT),
                      active_files=contract["native_recipe_files"], source_ref13=[{}] * 13)
        policy = P.selected(C.PARENT / "resource-EXPERIMENTAL.json", P.EXPERIMENTAL, {})
        admitted = P.admit_complete_preparation(recipe, base, ready, policy)
        self.assertEqual(len(admitted["inventory"]), 356)
        self.assertEqual(admitted["inventory"]["md4c"], "0.5.3-1")
        self.assertFalse(admitted["actor_enabled"])
        self.assertEqual(admitted["GPG"], "NOT_RUN")
        expected = "".join(f"{name} {version}\n" for name, version in sorted(admitted["inventory"].items()))
        source, digest = self.family_source(ready, expected.encode())

        # External 517-file custody is represented by the pinned 349 inventory in this model.
        options = dict(source=source, source_map_sha256=digest, component="gui_server",
                       baseline_image="sha256:" + "0" * 64, previous={}, uid=1001, gid=1001)
        with patch.object(N.P, "validate_base_provider", return_value=base):
            plan = N.builder_image_plan(**options)
            self.assertEqual(len(plan["signed_context"]), 14)
            self.assertEqual(plan["signed_context"][H.PACKAGE], handoff["archive"])
            self.assertEqual(plan["signed_context"][H.PACKAGE + ".sig"], handoff["signature"])
            self.assertEqual(plan["inventory_pin"], admitted["inventory_pin"])
            self.assertIn("LocalFileSigLevel = Required TrustedOnly", plan["pacman_config"])
            self.assertFalse(plan["actor_enabled"])
            self.signature.write_bytes(b"M" * len(SIGNATURE))
            with self.assertRaisesRegex(ValueError, "STABLE_WHOLE_FILE_PIN"):
                N.builder_image_plan(**options)


if __name__ == "__main__":
    unittest.main()
