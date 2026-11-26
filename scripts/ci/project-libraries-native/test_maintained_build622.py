# SPDX-License-Identifier: MIT
"""Offline controls for the maintained #622 inventories, migration and owner joins."""

from pathlib import Path
import re
from runpy import run_path
import shutil
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
M = SimpleNamespace(**run_path(str(HERE / "maintained_build622.py")))
LOCK = M.B.ROOT / "scripts/ci/maintained-native/locks/builder-successor.lock"


class MaintainedBuild(unittest.TestCase):
    def fixture(self, scratch):
        final = scratch / "tiff.lock"
        base = M.inventory(LOCK, 341)
        official = dict(base)
        del official["jbigkit"]
        official.update(M.TOOLS | dict([M.PROJECT["jbigkit"]]))
        final.write_bytes(M.lock_bytes(official))
        return SimpleNamespace(base_lock=LOCK, tiff_lock=final, producer_source=M.B.ROOT,
                               recipes=scratch / "recipes", cache=scratch / "cache")

    def test_real_maintained_lock_and_dependency_expressions(self):
        with TemporaryDirectory() as directory:
            prepared = self.fixture(Path(directory))
            base, builder, target = M.maintained_inventories(prepared)
            self.assertEqual((len(base), len(builder), len(target)), (341, 346, 341))
            self.assertEqual(base["libjpeg-turbo"], "3.2.0-2")
            self.assertEqual(builder["libjpeg-turbo"], "3.2.0-2")
            self.assertEqual(builder["libtiff"], "4.7.2-1")
            self.assertEqual(builder.keys() - base.keys(), M.TOOLS.keys() | {"cachy-asahi-jbigkit"})
            self.assertEqual(base.keys() - builder.keys(), {"jbigkit"})
            self.assertEqual(base.keys() - target.keys(), {"jbigkit", "libtiff"})
            self.assertEqual(target["lcms2"], base["lcms2"])
            self.assertEqual(M.maintained_dependencies(prepared, base), {"lcms2": ["libtiff"], "libtiff": ["jbigkit"]})

            wrong = dict(builder, **{"libjpeg-turbo": "3.2.1-1"})
            prepared.tiff_lock.write_bytes(M.lock_bytes(wrong))
            with self.assertRaisesRegex(ValueError, "replace only JBIG"):
                M.maintained_inventories(prepared)

    def test_archive_buildinfo_checks_every_selected_package(self):
        archive = Path("fixture")
        report = {
            "errors": [],
            "metadata": {".PKGINFO": {"depend": ["jbigkit=2.2"]},
                         ".BUILDINFO": {"installed": ["arbitrary-name-2:1.2-3-aarch64", "sources-1.0-1-any"]}},
        }
        with patch.object(M.PKG, "package", return_value=report):
            expected = {"arbitrary-name": "2:1.2-3", "sources": "1.0-1"}
            self.assertEqual(M.inspect_build_inventory(archive, expected), {"depend": ["jbigkit=2.2"]})
            with self.assertRaisesRegex(ValueError, "complete selected"):
                M.inspect_build_inventory(archive, dict(expected, sources="1.0-2"))
            report["metadata"][".BUILDINFO"]["installed"].append("sources-1.0-1-any")
            with self.assertRaisesRegex(ValueError, "complete selected"):
                M.inspect_build_inventory(archive, expected)

    def test_inputs_only_causes_complete_audit_without_native_calls(self):
        with TemporaryDirectory() as directory:
            scratch = Path(directory)
            prepared = self.fixture(scratch)
            args = SimpleNamespace(inputs_only=True)
            inputs = SimpleNamespace(prepare_maintained=Mock(return_value=prepared), audit_maintained=Mock())
            history = {"lcms2": {"selected": {"/usr/bin/tificc": {"sha256": "1" * 64}}}}
            native = Mock(side_effect=AssertionError("native call in inputs-only"))
            scope = M.execute.__globals__
            with patch.dict(scope, {"historical_facts": Mock(return_value=history), "native_run": native}):
                report = {}
                M.execute(args, scratch, report, inputs)
                self.assertEqual(report["status"], "MAINTAINED_INPUT_PREFLIGHT_PASSED")
                self.assertEqual(report["historical_tificc_sha256"], "1" * 64)
                inputs.audit_maintained.assert_called_once_with(prepared, scratch, report)
                native.assert_not_called()

                inputs.audit_maintained.side_effect = M.B.GuardFailure("missing original signature")
                report = {}
                with self.assertRaisesRegex(ValueError, "missing original signature"):
                    M.execute(args, scratch, report, inputs)
                self.assertNotIn("status", report)

    def test_migration_receipt_needs_all_three_inventories_and_consumer_checks(self):
        base, project = "a" * 64, "b" * 64
        raw = ("\n".join(f"INVENTORY {role} {digest}" for role, digest in (
            ("before", base), ("project", project), ("restored", base))) + "\n"
            + "\n".join(f"PROVIDER {role} UNCHANGED_TIFICC" for role in ("before", "project", "restored")) + "\n"
            + "TIFF JBIG roundtrip passed\n" * 3
            + "TIFF_UPSTREAM_ONLY_ALIAS_ACCEPTS_ORIGINAL_PKGREL\n"
            + "MAINTAINED_SIGNED_MIGRATION_PASSED\n").encode()
        self.assertEqual(M.review_migration_output(raw, base, project), [base, project, base])
        for changed in (raw.replace(base.encode(), b"c" * 64, 1),
                        raw.replace(b"PROVIDER restored UNCHANGED_TIFICC\n", b""),
                        raw.replace(b"TIFF JBIG roundtrip passed\n", b"", 1),
                        raw.replace(b"TIFF_UPSTREAM_ONLY_ALIAS_ACCEPTS_ORIGINAL_PKGREL\n", b""),
                        raw + b"unretired\n"):
            with self.subTest(changed=changed[-80:]), self.assertRaisesRegex(ValueError, "complete signed"):
                M.review_migration_output(changed, base, project)

    def test_script_contract_is_scoped_and_pairs_remain_atomic(self):
        for script in (M.PROVISION, M.MIGRATE):
            subprocess.run(["/usr/bin/bash", "-n"], input=script.encode(), check=True, capture_output=True, timeout=5)
            self.assertIn("LocalFileSigLevel = Required", script)
            self.assertIn("gpgconf --homedir /etc/pacman.d/gnupg --kill gpg-agent", script)
            self.assertNotRegex(script, r"(?:--nodeps|--assume-installed|pacman -R)")
        transactions = re.findall(r"^pacman -U .*", M.MIGRATE, re.MULTILINE)
        self.assertEqual(transactions, ['pacman -U --noconfirm --noscriptlet --ask 4 "${project[@]}"',
                                        'pacman -U --noconfirm --noscriptlet --ask 4 "${original[@]}"'])
        self.assertIn('cmp "$work/original-consumer" "$work/current-consumer"', M.MIGRATE)

    def test_base_cleanup_runs_despite_scoped_cleanup_failure_and_keeps_first_failure(self):
        report = {}
        docker_error = M.B.GuardFailure("original scoped cleanup failure")
        docker = SimpleNamespace(retire=Mock(side_effect=docker_error))
        baseline = SimpleNamespace(ready=True, observe=Mock())
        runner = object()
        k = SimpleNamespace(runtime=SimpleNamespace(Runner=Mock(return_value=runner), Cancelled=InterruptedError),
                            cleanup_base=Mock(return_value={"status": "PASS"}))
        scratch = Path("fixture")
        error = M.retire(docker, k, baseline, "daemon", {}, scratch, "owned", report)
        self.assertIs(error, docker_error)
        self.assertEqual(report["cleanup"]["status"], "HOLD")
        k.cleanup_base.assert_called_once_with("daemon", runner, scratch, "owned", True, baseline)
        baseline.observe.assert_called_once_with(runner, "after_cleanup")

    def test_retirement_does_not_mask_the_underlying_audit_failure(self):
        with TemporaryDirectory() as directory:
            scratch = Path(directory)
            for name in ("test-key", "producer/gpg"):
                (scratch / name).mkdir(parents=True)
            source_error = M.B.GuardFailure("original audit failure")
            inputs = SimpleNamespace(prepare_maintained=Mock(side_effect=source_error))
            with patch.object(M.B, "command", side_effect=OSError("GPG cleanup failure")) as command:
                report = {}
                with self.assertRaisesRegex(ValueError, "original audit failure"):
                    M.execute(SimpleNamespace(inputs_only=True), scratch, report, inputs)
                self.assertEqual(command.call_count, 2)
                self.assertEqual(report["cleanup"]["status"], "HOLD")

    def test_owned_derived_cleanup_protects_the_untagged_base_from_parent_pruning(self):
        with TemporaryDirectory() as directory:
            scope = M.MaintainedScope(Path(directory))
            with patch.object(M.B.DockerScope, "call") as call:
                scope.call("image", "rm", "owned")
                call.assert_called_once_with("image", "rm", "--no-prune", "owned", seconds=60)

    @unittest.skipUnless(shutil.which("pacman", path="/usr/bin:/bin"), "isolated ALPM query unavailable")
    def test_current_tiff_provide_does_not_distinguish_official_pkgrel(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            db = root / "db"
            data = db / "local/cachy-asahi-libtiff-4.7.2-1.1"
            data.mkdir(parents=True)
            (db / "local/ALPM_DB_VERSION").write_text("9\n")
            (data / "desc").write_text("%NAME%\ncachy-asahi-libtiff\n\n%VERSION%\n4.7.2-1.1\n\n"
                                       "%PROVIDES%\nlibtiff=4.7.2\nlibtiff.so=6-64\n\n")
            (data / "files").write_bytes(b"")
            conf = root / "pacman.conf"
            conf.write_text("[options]\nArchitecture = auto\n")
            argv = [shutil.which("pacman", path="/usr/bin:/bin"), "--config", str(conf), "--dbpath", str(db), "-T"]
            passing = subprocess.run([*argv, "libtiff", "libtiff=4.7.2-1", "libtiff=4.7.2-999", "libtiff.so=6-64"],
                                     capture_output=True, timeout=5)
            self.assertEqual((passing.returncode, passing.stdout, passing.stderr), (0, b"", b""))
            refused = subprocess.run([*argv, "libtiff=4.7.3-1"], capture_output=True, timeout=5)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(refused.stdout, b"libtiff=4.7.3-1\n")


if __name__ == "__main__":
    unittest.main()
