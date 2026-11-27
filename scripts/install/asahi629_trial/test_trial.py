# SPDX-License-Identifier: MIT
"""629 admission tests. The optional retained-data test never starts a guest."""

from copy import deepcopy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


O = load(HERE / "operands.py")
R = load(HERE / "controller.py")
C, T, G = R.C, R.T, R.G
TEST_FINGERPRINT = "FA" * 20
TEMPORARY_START = 1900000000


def review_fixture(archives, *, fingerprint=TEST_FINGERPRINT):
    return dict(kind=O.TEST_REVIEW_KIND, issuer="Root", scope="project-test", approval_status="UNAPPROVED",
                provenance=deepcopy(O.PROVENANCE),
                key=dict(fingerprint=fingerprint, certificate=T.pin(b"synthetic public bytes"),
                         not_before=TEMPORARY_START, not_after=TEMPORARY_START + 86400),
                operands={name: dict(archive=archive, signature=T.pin(name.encode()))
                          for name, archive in archives.items()})


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.archives = {name: T.pin((name + version).encode()) for name, version in O.PROJECTS.items()}
        self.review = review_fixture(self.archives)
        self.vendor = {"AA" * 20, "BB" * 20}

    def decode(self):
        return O.decode_review(T, T.encoded(self.review), self.archives, self.vendor)

    def test_exact_review(self):
        self.assertEqual(self.decode(), self.review)

    def test_missing_or_retargeted_project_and_incomplete_provenance(self):
        for change in (
            lambda review: review["operands"].pop("cachy-asahi-first-login"),
            lambda review: review["operands"]["cachy-asahi-first-login"].update(archive=T.pin(b"old archive")),
            lambda review: review["provenance"].pop(O.OWNERSHIP),
            lambda review: review.update(approval_status="APPROVED"),
            lambda review: review.update(scope="vendor"),
            lambda review: review.update(issuer=None),
        ):
            with self.subTest(change=change):
                reviewed = deepcopy(self.review)
                change(self.review)
                with self.assertRaises(ValueError):
                    self.decode()
                self.review = reviewed

    def test_vendor_and_withdrawn_test_keys_rejected(self):
        for fingerprint in O.HISTORICAL_TEST | self.vendor:
            with self.subTest(fingerprint=fingerprint):
                self.review["key"]["fingerprint"] = fingerprint
                with self.assertRaisesRegex(ValueError, "Distinct current"):
                    self.decode()

    def test_exact_time_boundaries(self):
        key = self.review["key"]
        manifest = {"keys": {"preview-test": key}}
        O.check_current_trust(T, manifest, key["not_before"])
        O.check_current_trust(T, manifest, key["not_after"] - O.TRUST_ALLOWANCE - 1)
        for when in (key["not_before"] - 1, key["not_after"] - O.TRUST_ALLOWANCE, key["not_after"], False):
            with self.subTest(when=when), self.assertRaisesRegex(ValueError, "cover"):
                O.check_current_trust(T, manifest, when)

    def test_three_inverse_versions(self):
        before = {f"base-{i}": "1" for i in range(258)}
        before.update({name: versions[0] for name, versions in O.REVERSED.items()})
        forward = {f"forward-{i}": "1" for i in range(363)} | O.PROJECTS
        forward.update({name: versions[1] for name, versions in O.REVERSED.items()})
        rollback = {name: versions[0] for name, versions in O.REVERSED.items()}
        rows = {"baseline.lock": before, "forward-preview.lock": forward, "rollback-preview.lock": rollback,
                "forward.lock": before | forward, "rollback.lock": before | forward | rollback}
        O.check_delta(T, rows)
        rows["rollback-preview.lock"]["python"] = rows["rollback.lock"]["python"] = "3.14.6-1"
        with self.assertRaisesRegex(ValueError, "three inverse"):
            O.check_delta(T, rows)

    def test_distinct_profile(self):
        old = load(HERE.parent / "asahi_maintenance_trial/operands.py")
        self.assertNotEqual(old.KIND, O.KIND)
        self.assertEqual(old.SEED, O.SEED)
        self.assertEqual(old.REFS["forward.lock"][0], 626)
        self.assertEqual(O.REFS["forward.lock"][0], 629)


class RunnerTests(unittest.TestCase):
    def test_projected_bootstrap_preserves_the_control_and_unique_target(self):
        init = R.init_bytes()
        self.assertIn(b'blkid -c /dev/null -U ' + O.UUID.encode(), init)
        self.assertIn(b'e2fsck -fn "$scratch"', init)
        self.assertIn(b'resize2fs "$scratch"', init)
        self.assertIn(b'mount -n -t ext4 -o ro,noload,nosuid,nodev "$input"', init)
        self.assertIn(b'/trial-code/asahi-guest.py "$plan" "$worker"', init)
        self.assertIn(b'cleanup.json', init)
        self.assertNotIn(b'-L OV583_WORK', init)

    def test_transaction_and_signature_operands_keep_separate_scopes(self):
        manifest = {
            "keys": {"alarm": {"scope": "vendor"}, "community": {"scope": "vendor"},
                     "preview-test": {"scope": "project-test"}},
            "packages": {
                "forward": {"perl": {"archive": "forward/perl", "scope": "vendor"},
                            "cachy-asahi-setup": {"archive": "forward/setup", "scope": "project-test"}},
                "rollback": {"perl": {"archive": "rollback/perl", "scope": "vendor"}},
            },
        }
        commands = G.command_plan(O, manifest)
        self.assertEqual(commands["apply-forward"][-3:], ["--", "/trial-inputs/forward/setup", "/trial-inputs/forward/perl"])
        self.assertEqual(commands["apply-rollback"][-2:], ["--", "/trial-inputs/rollback/perl"])
        self.assertIn("--upgrade", commands["apply-forward"])
        self.assertIn("--print", commands["preview-rollback"])
        scoped = G.trust_commands(O, manifest)
        self.assertIn("/trial-work/verify-vendor", scoped["verify-rollback-perl"])
        self.assertIn("/trial-work/verify-project-test", scoped["verify-forward-cachy-asahi-setup"])
        self.assertLess(list(scoped).index("verify-rollback-perl"), list(scoped).index("set-ownertrust"))

    def test_cold_hold_cannot_bind(self):
        with tempfile.TemporaryDirectory(prefix="asahi629-cold-hold-") as temp:
            root = Path(temp)
            raw = T.encoded({"status": "HOLD_RETIREMENT_OR_READBACK"})
            (root / "independent-readback-PASS.json").write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "reread and retired"):
                R.control_refs(root, T.pin(raw)["sha256"])

    def test_alpm_action_log_keeps_multiword_versions_in_both_phases(self):
        old = {name: versions[0] for name, versions in O.REVERSED.items()}
        new = {name: versions[1] for name, versions in O.REVERSED.items()}
        installed = {"cachy-asahi-first-login": "0.1.0-3"}
        raw = b"""[2026-11-18T06:16:34+0000] [ALPM] upgraded perl (5.42.2-2 -> 5.42.3-1)
[2026-11-18T06:17:09+0000] [ALPM] upgraded python (3.14.7-1 -> 3.14.8-1)
[2026-11-18T06:18:53+0000] [ALPM] upgraded networkmanager (1.58.1-1 -> 1.58.1-2)
[2026-11-18T06:18:54+0000] [ALPM] installed cachy-asahi-first-login (0.1.0-3)
[2026-11-18T06:19:52+0000] [ALPM] downgraded networkmanager (1.58.1-2 -> 1.58.1-1)
[2026-11-18T06:19:59+0000] [ALPM] downgraded perl (5.42.3-1 -> 5.42.2-2)
[2026-11-18T06:20:06+0000] [ALPM] downgraded python (3.14.8-1 -> 3.14.7-1)
"""
        self.assertEqual(G.log_actions(T, old, new | installed, old | installed, raw, completed=True)["entries"], 7)
        with self.assertRaisesRegex(ValueError, "inverse changes"):
            G.log_actions(T, old, new | installed, old | installed,
                          raw.replace(b"5.42.3-1 -> 5.42.2-2", b"5.42.3-1 -> 5.42.1-2"), completed=True)

    def test_cold_boot_evidence_excludes_credentials_and_partial_packets(self):
        with tempfile.TemporaryDirectory(prefix="asahi629-cold-boot-hold-") as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, "credential-free"):
                R.cold_boot_refs(root, "0" * 64, root, {}, {})
            receipt = root / R.COLD_BOOT_RECEIPT
            receipt.write_bytes(T.encoded({"status": "HOLD"}))
            for relative in R.COLD_BOOT_FILES.values():
                path = root / relative
                path.parent.mkdir(exist_ok=True)
                path.write_bytes(b"fixture")
            with self.assertRaisesRegex(ValueError, "independent cold boot PASS"):
                R.cold_boot_refs(root, T.pin(receipt.read_bytes())["sha256"], root, {}, {})
            (root / "credentials.json").write_bytes(b"unexpected")
            with self.assertRaisesRegex(ValueError, "credential-free"):
                R.cold_boot_refs(root, T.pin(receipt.read_bytes())["sha256"], root, {}, {})

    def test_r132_rtc_must_be_current_and_seed_the_guest(self):
        with tempfile.TemporaryDirectory(prefix="asahi629-rtc-") as temp:
            root = Path(temp)
            (root / "name").write_text("rtc-pl031 9010000.pl031\n")
            (root / "hctosys").write_text("1\n")
            (root / "since_epoch").write_text("1795749000\n")
            G.check_rtc(T, root, 1795749002)
            with self.assertRaisesRegex(ValueError, "RTC must seed"):
                G.check_rtc(T, root, 1795749010)
            (root / "hctosys").write_text("0\n")
            with self.assertRaisesRegex(ValueError, "RTC must seed"):
                G.check_rtc(T, root, 1795749002)

    @unittest.skipUnless(all(os.environ.get(name) for name in (
        "ASAHI629_CONTROL", "ASAHI629_CONTROL_SHA256"
    )), "independent cold control was not supplied")
    def test_reopen_independent_cold_control(self):
        root = Path(os.environ["ASAHI629_CONTROL"])
        digest = os.environ["ASAHI629_CONTROL_SHA256"]
        review, files = R.control_refs(root, digest)
        self.assertEqual(review["receipt"]["sha256"], digest)
        self.assertEqual(set(files), {"baseline", "kernel", "config"})
        self.assertNotEqual(files["baseline"]["sha256"], C.REFERENCES["baseline"][1])
        with self.assertRaisesRegex(ValueError, "reread and retired"):
            R.control_refs(root, "0" * 64)

    @unittest.skipUnless(all(os.environ.get(name) for name in (
        "ASAHI629_CONTROL", "ASAHI629_CONTROL_SHA256", "ASAHI629_CONTROL_BOOT",
        "ASAHI629_CONTROL_BOOT_SHA256", "ASAHI629_TRANSACTION_KERNEL",
    )), "independent cold boot and transaction kernel were not supplied")
    def test_reopen_independent_cold_boot_and_distinct_r132_kernel(self):
        control = Path(os.environ["ASAHI629_CONTROL"])
        boot = Path(os.environ["ASAHI629_CONTROL_BOOT"])
        digest = os.environ["ASAHI629_CONTROL_BOOT_SHA256"]
        assembly, references = R.control_refs(control, os.environ["ASAHI629_CONTROL_SHA256"])
        selected = R.cold_boot_refs(boot, digest, control, assembly, references)
        self.assertEqual(selected["receipt"]["sha256"], digest)
        transaction = R.transaction_kernel_refs(Path(os.environ["ASAHI629_TRANSACTION_KERNEL"]))
        self.assertNotEqual(transaction["transaction_kernel"], references["kernel"])
        with self.assertRaisesRegex(ValueError, "independent cold boot PASS"):
            R.cold_boot_refs(boot, digest, control, assembly, references | {"baseline": T.pin(b"unrelated cold root")})

    def test_retirement_checks_process_absence_and_keeps_only_evidence(self):
        with tempfile.TemporaryDirectory(prefix="asahi629-retire-") as temp:
            root = Path(temp)
            out = root / "output"
            out.mkdir()
            runner = R.Controller.__new__(R.Controller)
            runner.out = out
            (out / "scratch.raw").write_bytes(b"clone")
            (out / "result.raw").write_bytes(b"evidence")
            originals = root / "seed.raw"
            originals.write_bytes(b"original")
            with patch.object(runner, "require_absent_twice", side_effect=ValueError("surviving process")):
                with self.assertRaisesRegex(ValueError, "surviving process"):
                    runner.retire("0" * 32)
            self.assertTrue((out / "scratch.raw").is_file())
            with patch.object(runner, "require_absent_twice") as absent:
                self.assertTrue(runner.retire("0" * 32)["disposable_media_absent"])
            absent.assert_called_once_with("0" * 32)
            self.assertFalse((out / "scratch.raw").exists())
            self.assertEqual((out / "result.raw").read_bytes(), b"evidence")
            self.assertEqual(originals.read_bytes(), b"original")

    def test_authority_cannot_be_replayed_after_output_removal(self):
        with tempfile.TemporaryDirectory(prefix="asahi629-claim-") as temp:
            root = Path(temp)
            output = root / "run"
            nonce, digest = "1" * 32, "2" * 64
            claim = R.claim_run(output, nonce, digest)
            raw = T.read(root / claim["file"], claim["pin"])
            self.assertEqual(T.decode(raw), dict(nonce=nonce, authority_sha256=digest, output=str(output)))
            output.mkdir()
            output.rmdir()
            with self.assertRaises(FileExistsError):
                R.claim_run(output, nonce, digest)
            self.assertEqual(T.read(root / claim["file"], claim["pin"]), raw)

    def test_unissued_and_offline_actor_refusals(self):
        with tempfile.TemporaryDirectory(prefix="asahi629-authority-") as temp:
            root = Path(temp)
            authority = root / "unissued.json"
            raw = T.encoded({"kind": R.KIND, "issuer": None, "approval_status": "UNAPPROVED"})
            authority.write_bytes(raw)
            argv = ["controller.py", "run", "--authority", str(authority), "--authority-sha256", T.pin(raw)["sha256"]]
            with patch("sys.argv", argv), self.assertRaisesRegex(ValueError, "issued"):
                R.main()
            with patch.dict(os.environ, {"CACHY_ASAHI_OVERLAY583_ACTOR": ""}):
                with self.assertRaisesRegex(ValueError, "Explicit disposable actor"):
                    C.actor_boundary({})


@unittest.skipUnless(all(os.environ.get(name) for name in (
    "ASAHI629_PREFLIGHT", "ASAHI629_OWNERSHIP", "ASAHI629_R132_TRANSPORT"
)), "retained exact inputs were not supplied")
class RetainedDataTests(unittest.TestCase):
    def test_stage_and_rehash_exact_data_with_unusable_test_fixture(self):
        preflight_dir = Path(os.environ["ASAHI629_PREFLIGHT"])
        ownership = Path(os.environ["ASAHI629_OWNERSHIP"])
        original = Path(os.environ["ASAHI629_R132_TRANSPORT"])
        preflight = T.decode(T.read(preflight_dir / Path(O.PREFLIGHT).name, O.PROVENANCE[O.PREFLIGHT]))
        project_rows = {row["name"]: row for row in preflight["package_rows"] if row["name"] in O.PROJECTS}
        # These are fixture bytes outside the real TEST signing workflow and cannot authenticate any archive.
        review = review_fixture({name: row["archive_pin"] for name, row in project_rows.items()})
        with tempfile.TemporaryDirectory(prefix="asahi629-retained-data-") as temp:
            root = Path(temp)
            test_inputs = root / "fixture-test-inputs"
            test_inputs.mkdir()
            (test_inputs / "preview-test.gpg").write_bytes(b"synthetic public bytes")
            for name, row in project_rows.items():
                (test_inputs / (Path(row["archive"]).name + ".sig")).write_bytes(name.encode())
            test_review = root / "synthetic-review.json"
            test_review.write_bytes(T.encoded(review))
            digest = T.pin(T.encoded(review))["sha256"]
            value, sources = O.project(T, preflight_dir, ownership, original, test_review, digest, test_inputs)
            staged = root / "staged"
            staged.mkdir()
            for name, ref in sources.items():
                C.checked_copy(Path(ref["path"]), staged / name, {key: ref[key] for key in ("bytes", "sha256")})
            (staged / "manifest.json").write_bytes(T.encoded(value))
            O.rehash(T, staged, value)
            self.assertEqual(len(value["files"]), 767)
            self.assertEqual(sum(row["scope"] == "vendor" for phase in value["packages"].values()
                                 for row in phase.values()), 369)
            self.assertEqual(O.locks(T, staged)["forward.lock"]["qt6-base"], "6.12.0-3")

            _, workers = R.selection()
            plan = dict(kind=G.BOOT, nonce="0" * 32, code=workers, manifest=T.pin(T.encoded(value)), media=value)
            packed = root / "packed"
            files, aliases, directories = R.copy_transport(staged, plan, packed)
            self.assertEqual({leaf: files["inputs/" + leaf] for leaf in value["files"]}, value["files"])
            self.assertEqual(files["code/plan.json"], T.pin(T.encoded(plan)))
            self.assertEqual(files["code/asahi-guest-base.py"], G.BASE_PIN)
            self.assertIn("runtime/usr/bin/python3.14", files)
            self.assertEqual(aliases["runtime/usr/lib/libmpdec.so.4"], "libmpdec.so.4.0.1")
            self.assertIn("inputs/evidence", directories)

            extra = staged / "unexpected"
            extra.mkdir()
            with self.assertRaisesRegex(ValueError, "path census"):
                O.rehash(T, staged, value)
            extra.rmdir()
            provenance = staged / O.OWNERSHIP
            provenance.chmod(0o600)
            provenance.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "length or digest"):
                O.rehash(T, staged, value)

            (test_inputs / "unexpected-private-key").touch()
            with self.assertRaisesRegex(ValueError, "exactly five signatures"):
                O.project(T, preflight_dir, ownership, original, test_review, digest, test_inputs)


if __name__ == "__main__":
    unittest.main()
