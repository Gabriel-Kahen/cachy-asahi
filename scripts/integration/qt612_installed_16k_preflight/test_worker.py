# SPDX-License-Identifier: MIT
"""Inert installed-Qtbase lifecycle controls. No runner or package manager."""

from pathlib import Path
from runpy import run_path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


W = SimpleNamespace(**run_path(str(Path(__file__).with_name("worker.py"))))
P, T = W.P, W.T
FPR = "A" * 40
NOW = 200


def pin(raw):
    return T.pin(raw)


def make_lock(packages):
    return "".join(f"{name} {version}\n" for name, version in sorted(packages.items())).encode()


class Worker(unittest.TestCase):
    def setUp(self):
        baseline_packages = {f"fixture{i:03}": "1-1" for i in range(353)}
        baseline_packages |= {"md4c": "0.5.3-1", "wayland": "1.26.0-1", "libglvnd": "1.7.0-3"}
        self.base = make_lock(baseline_packages)
        self.installed = make_lock(baseline_packages | {P.M.PACKAGE: P.M.VERSION})
        patcher = patch.dict(P.make_plan.__globals__, Q3_INVENTORY=pin(self.base))
        patcher.start()
        self.addCleanup(patcher.stop)
        # The model's staged plan and worker use the same selected baseline pin.
        attr = patch.object(P, "Q3_INVENTORY", pin(self.base))
        attr.start()
        self.addCleanup(attr.stop)
        self.plan = P.make_plan(self.base, "0" * 32, {
            "inventory": pin(self.base) | {"path": "/held/inventory"},
            "scratch": P.Q3_SCRATCH | {"path": "/held/scratch.raw"},
            "terminal": P.Q3_TERMINAL | {"path": "/held/terminal"},
        }, P.recipe_inputs())
        self.raw = T.encoded(self.plan)
        self.plan_sha = pin(self.raw)["sha256"]
        libs, aliases, files = W.payload_requirements(self.plan)
        self.payload = {path: dict(type="file", owner=P.M.PACKAGE, pin=pin(path.encode())) for path in files}
        self.payload |= {path: dict(type="symlink", owner=P.M.PACKAGE, target=target) for path, target in aliases.items()}
        self.providers = {"/usr/lib/libmd4c.so.0.5.3": dict(owner="md4c", version="0.5.3-1", pin=pin(b"model provider"))}
        self.certificate = bytes((198, 1, 1, 205, 1, 1, 194, 1, 1))
        self.signature = bytes((194, 1, 1))
        self.inputs = dict(archive=pin(b"model archive"), certificate=pin(self.certificate),
                           signature=pin(self.signature))
        self.selection = dict(kind="QTBASE16K_INSTALLED_GUEST_SELECTION_V1", plan_sha256=self.plan_sha,
                              packaging_receipt=pin(b"synthetic packaging receipt"),
                              key=dict(fingerprint=FPR, created=100, expires=300, test_only=True),
                              inputs=self.inputs, payload=self.payload, providers=self.providers)
        self.observations = {}
        for stage in self.plan["stages"]:
            present = stage["state"] == "installed"
            self.observations[stage["name"]] = dict(
                payload=self.payload.copy() if present else {},
                database=None if present else b"baseline descriptors",
                protected=b"baseline config and provider bytes",
                sonames={name: (dict(path=path, **self.payload[path]["pin"]) if present else None)
                         for name, path in libs.items()},
                offscreen=dict(path=W.OFFSCREEN, **self.payload[W.OFFSCREEN]["pin"]) if present else None,
                providers=self.providers.copy() if present else {})
        self.called = []
        self.override = {}

    def callback(self, role, argv, *, timeout, stdin, env):
        self.called.append((role, argv, stdin, env))
        apparent = dict(exit_code=0, stdout=b"", stderr=b"", natural=True, group_empty=True, overflow=False)
        if role.endswith("-inventory"):
            stage = role.removesuffix("-inventory")
            apparent["stdout"] = self.base if stage in {"baseline", "remove", "final-remove"} else self.installed
        if role.endswith("-prepare"):
            apparent["stdout"] = (self.plan["package_manager"]["prepare_expected"] + "\n").encode()
        if role == "test-certificate":
            apparent["stdout"] = f"pub:::::100:300:\nuid:::::::::Qt TEST:\nfpr:::::::::{FPR}:\n".encode()
        if role == "signature":
            apparent["stdout"] = (f"[GNUPG:] GOODSIG {FPR[-16:]} Qt TEST\n"
                                  f"[GNUPG:] VALIDSIG {FPR} 1970-01-01 200 0 4 0 1 10 00 {FPR}\n").encode()
        if role.endswith("-official-version"):
            apparent.update(exit_code=127, stdout=W.VERSION_REFUSAL)
        if role.endswith("-consumer-run"):
            apparent["stdout"] = P.SMOKE.encode() + b"\n"
        return apparent | self.override.get(role, {})

    def exercise(self, *, config=None, plan=None, boundary=True):
        raw = T.encoded(self.selection)
        return W.exercise(self.raw if plan is None else plan, self.plan_sha, self.base, raw, pin(raw)["sha256"],
                          now=NOW, config_raw=P.CONFIG.encode() if config is None else config,
                          input_pins=self.inputs, certificate_raw=self.certificate, signature_raw=self.signature,
                          verify_boundary=lambda nonce, guest: nonce == self.plan["nonce"] and
                          guest == self.plan["guest"] and boundary,
                          run=self.callback, observe=self.observations.__getitem__)

    def roles(self):
        return [row[0] for row in self.called]

    def test_exact_normal_lifecycle_restores_and_retires(self):
        result = self.exercise()
        self.assertEqual(result["status"], "LIFECYCLE_CALLBACKS_VERIFIED_ONLY")
        self.assertEqual([role for role in self.roles() if role.endswith("-mutation")],
                         ["install-mutation", "reinstall-mutation", "remove-mutation",
                          "install-again-mutation", "final-remove-mutation"])
        self.assertLess(self.roles().index("signature"), self.roles().index("install-mutation"))
        self.assertEqual(self.roles()[-1], "trust-retirement")
        self.assertIn("install-consumer-build", self.roles())
        self.assertNotIn("reinstall-consumer-build", self.roles())
        self.assertIn("reinstall-consumer-run", self.roles())
        self.assertNotIn("LD_LIBRARY_PATH", next(row[-1] for row in self.called if row[0] == "install-consumer-run"))

    def test_tampered_plan_trust_or_policy_cannot_run(self):
        with self.assertRaisesRegex(ValueError, "externally selected"):
            self.exercise(plan=self.raw + b" ")
        with self.assertRaisesRegex(ValueError, "policy"):
            self.exercise(config=b"SigLevel = Never")
        with self.assertRaisesRegex(ValueError, "guest boundary"):
            self.exercise(boundary=False)
        certificate = self.certificate
        self.certificate = bytes((197, 1, 1))
        self.inputs["certificate"] = pin(self.certificate)
        with self.assertRaisesRegex(ValueError, "public TEST certificate"):
            self.exercise()
        self.certificate = certificate
        self.inputs["certificate"] = pin(certificate)
        self.selection["key"]["expires"] = NOW
        with self.assertRaisesRegex(ValueError, "current|Current"):
            self.exercise()
        self.assertEqual(self.called, [])

    def test_bad_signature_and_uncertain_process_cleanup_stop_before_mutation(self):
        for failure in ({"stdout": b"[GNUPG:] BADSIG bad"},
                        {"group_empty": False}):
            with self.subTest(failure=failure):
                self.called.clear()
                self.override["signature"] = failure
                with self.assertRaises(ValueError):
                    self.exercise()
                self.assertNotIn("install-mutation", self.roles())
                self.assertEqual(self.roles()[-1], "trust-retirement")

    def test_unexpected_dependency_inventory_loader_and_restore_refuse(self):
        for role, change in (("install-official-version", {"stdout": b"\n"}),
                             ("remove-inventory", {"stdout": self.installed}),
                             ("reinstall-consumer-run", {"stdout": b"wrong marker"}),
                             ("install-mutation", {"stderr": b"error: command failed\n"})):
            with self.subTest(role=role):
                self.override = {role: change}
                with self.assertRaises(ValueError):
                    self.exercise()
        self.override.clear()
        self.observations["install"]["providers"] = {}
        with self.assertRaisesRegex(ValueError, "loader mapping"):
            self.exercise()
        self.observations["install"]["providers"] = self.providers.copy()
        self.observations["final-remove"]["database"] = b"same inventory, different metadata"
        with self.assertRaisesRegex(ValueError, "baseline local database"):
            self.exercise()

    def test_checks_original_result_and_separate_negative_clones(self):
        db = b"baseline descriptors"
        rows = {}
        for role, suffix in (("tampered_signature", "1"), ("unknown_key", "2")):
            signature = self.inputs["signature"]
            diagnostic = b"error: required key missing from keyring\n"
            if role == "tampered_signature":
                signature = pin(b"x" * signature["bytes"])
                diagnostic = b"error: invalid or corrupted package (PGP signature)\n"
            rows[role] = dict(clone=suffix * 32, scratch=P.Q3_SCRATCH, configuration=pin(P.CONFIG.encode()),
                              archive=self.inputs["archive"], signature=signature,
                              argv=self.plan["negative_trials"][role]["command"], exit_code=1, natural=True,
                              group_empty=True, stderr=diagnostic, database_before=db, database_after=db)
        result = W.review_negatives(self.plan, self.selection, db, "0" * 32, rows)
        self.assertEqual(len(result["siblings"]), 2)
        rows["unknown_key"]["clone"] = rows["tampered_signature"]["clone"]
        with self.assertRaisesRegex(ValueError, "sibling"):
            W.review_negatives(self.plan, self.selection, db, "0" * 32, rows)


if __name__ == "__main__":
    unittest.main(verbosity=2)
