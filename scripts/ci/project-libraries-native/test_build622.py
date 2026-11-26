# SPDX-License-Identifier: MIT
"""Local, no-engine controls for the #622 intake, signature and cleanup boundaries."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build622
import carrier622
import inputs622
import migration622


class IntakeTests(unittest.TestCase):
    def test_candidate_accepts_two_reviewed_recipe_trees(self):
        for tree in ("8cf292a311f6abccbb6de51963fd4751b13bcd5c", "441815470dc9434c9b4f314f57cb2521f19e9520"):
            with self.subTest(tree=tree), patch.object(inputs622, "command", side_effect=(
                subprocess.CompletedProcess([], 0, (tree + "\n").encode()), subprocess.CompletedProcess([], 0, b""),
            )):
                self.assertEqual(inputs622.bind_candidate(), tree)

    def test_candidate_refuses_wrong_tree_or_dirty_recipe_bytes(self):
        for tree, status in (("0" * 40, b""), ("441815470dc9434c9b4f314f57cb2521f19e9520", b" M README.md\n")):
            with self.subTest(tree=tree, status=status), patch.object(inputs622, "command", side_effect=(
                subprocess.CompletedProcess([], 0, (tree + "\n").encode()), subprocess.CompletedProcess([], 0, status),
            )), self.assertRaisesRegex(ValueError, "exact clean #622 candidate tree"):
                inputs622.bind_candidate()

    def test_legacy_zstd_body_is_carried_and_uses_the_locked_signature(self):
        name = "zstd-1.5.7-3-aarch64.pkg.tar.xz"
        pins = inputs622.retained_pins()
        self.assertEqual(pins[name], {
            "bytes": 436532,
            "sha256": "c3b907c36049b338bda0c6d85260251e48d17e2be6c0e11ddc0dfd4cf9d2e89a",
        })
        self.assertNotIn(name + ".sig", pins)

    def test_wrong_cache_bytes_refuse_without_any_endpoint_or_public_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = root / "cache"
            cache.mkdir()
            output = root / "output"
            output.mkdir()
            (cache / "object").write_bytes(b"overflow")
            pin = dict(bytes=8, sha256=hashlib.sha256(b"expected").hexdigest(),
                       url="https://example.invalid/object")
            with patch("inputs622.download") as download:
                with self.assertRaisesRegex(ValueError, "input pin mismatch"):
                    inputs622.stage_object(output, "object", pin, cache)
                download.assert_not_called()


    def test_retained_route_is_used_only_for_retained_bodies(self):
        name = "linux-aarch64-7.3.4-3-aarch64.pkg.tar.xz"
        pin = dict(bytes=4, sha256=hashlib.sha256(b"good").hexdigest(), url="https://public.invalid/object")
        with tempfile.TemporaryDirectory() as directory, patch.object(inputs622, "download") as fetch:
            base = Path(directory)
            retained = base / "retained"
            retained.mkdir()
            (retained / name).write_bytes(b"good")

            def download(url, path, size):
                path.write_bytes(b"good")

            fetch.side_effect = download
            inputs622.stage_set(base / "output", {name: pin, "public": pin}, retained=retained)
            self.assertEqual(fetch.call_count, 1)
            self.assertEqual(fetch.call_args.args[0], pin["url"])
            self.assertEqual(fetch.call_args.args[1].name, "public")

    def test_missing_private_blob_refuses_without_public_fallback(self):
        name = "linux-aarch64-7.3.4-3-aarch64.pkg.tar.xz"
        pin = dict(bytes=4, sha256="0" * 64, url="https://public.invalid/object")
        with tempfile.TemporaryDirectory() as directory, patch.object(inputs622, "download") as fetch:
            base = Path(directory)
            with self.assertRaises(FileNotFoundError):
                inputs622.stage_set(base / "output", {name: pin}, retained=base)
            fetch.assert_not_called()

    def test_incomplete_export_cannot_leave_a_partial_or_replace_existing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "cache"
            cache.mkdir()
            output = root / "output"
            pins = {"one": {"bytes": 4, "sha256": hashlib.sha256(b"good").hexdigest()},
                    "two": {"bytes": 4, "sha256": hashlib.sha256(b"good").hexdigest()}}
            (cache / "one").write_bytes(b"good")
            with patch.object(inputs622, "RETAINED", frozenset(pins)):
                with self.assertRaises(FileNotFoundError):
                    inputs622.export_retained(cache, pins, output)
                self.assertFalse(output.exists())
                output.mkdir()
                (output / "prior").write_bytes(b"keep")
                with self.assertRaises(FileExistsError):
                    inputs622.export_retained(cache, pins, output)
                self.assertEqual((output / "prior").read_bytes(), b"keep")


class CarrierTests(unittest.TestCase):
    def test_tree_refuses_extra_missing_duplicate_or_symlink_blobs(self):
        pin = {"unit": {"bytes": 4}}
        row = b"100644 blob " + b"0" * 40 + b" 4\talarm-cache/unit\0"
        carrier622.verify_tree(row, pin)
        for invalid in (b"", row + row, row.replace(b"100644", b"120000"),
                        row.replace(b" 4\t", b" 5\t"), row.replace(b"alarm-cache", b"extension")):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                carrier622.verify_tree(invalid, pin)

    def test_ssh_fetch_uses_pinned_config_and_retires_key_before_return(self):
        secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----"
        observed = {}

        def check(runner, argv, timeout=15):
            if argv[0].endswith("ssh-keygen"):
                path = Path(argv[2])
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.read_text(), secret + "\n")
                observed["credential"] = path.parent
                return b" ".join(carrier622.DEPLOY_KEY) + b" test (ED25519)\n"
            self.assertNotIn(secret, " ".join(argv))
            ssh = runner.env["GIT_SSH_COMMAND"]
            self.assertIn("StrictHostKeyChecking=yes", ssh)
            self.assertIn("IdentityAgent=none", ssh)
            self.assertIn("HostKeyAlgorithms=ssh-ed25519", ssh)
            self.assertNotIn(secret, ssh)
            self.assertEqual(argv[-2:], [carrier622.REMOTE, f"{carrier622.REF}:{carrier622.REF}"])
            return b""

        with tempfile.TemporaryDirectory() as directory:
            runner = carrier622.private_runner(Path(directory))
            with patch.object(carrier622, "checked", side_effect=check):
                carrier622.ssh_fetch(runner, ["git"], secret, Path(directory))
            self.assertNotIn("GIT_SSH_COMMAND", runner.env)
            self.assertFalse(observed["credential"].exists())

    def test_nonmatching_deploy_key_is_refused_before_fetch(self):
        secret = "-----BEGIN OPENSSH PRIVATE KEY-----\nfixture\n-----END OPENSSH PRIVATE KEY-----"
        with tempfile.TemporaryDirectory() as directory:
            runner = carrier622.private_runner(Path(directory))
            with patch.object(carrier622, "checked", return_value=b"256 SHA256:wrong") as checked:
                with self.assertRaisesRegex(ValueError, "pinned read-only deploy key"):
                    carrier622.ssh_fetch(runner, ["git"], secret, Path(directory))
            self.assertEqual(checked.call_count, 1)
            self.assertEqual(list(Path(directory).iterdir()), [])


class MigrationTests(unittest.TestCase):
    def test_emulated_tiff_requires_explicit_profile_and_preserves_jbig(self):
        native = migration622.project_pins(False)
        emulated = migration622.project_pins(True)
        changed = {name for name in native if native[name] != emulated[name]}
        self.assertEqual(changed, {"cachy-asahi-libtiff-4.7.2-1.1-aarch64.pkg.tar.xz"})
        self.assertEqual(native, migration622.PROJECT_PACKAGES)

    def test_native_wrapper_uses_fresh_base_and_requires_historical_readback(self):
        base = "sha256:" + "b" * 64
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            docker = build622.DockerScope(root)
            packages = [root / name for name in migration622.PROJECT_PACKAGES]
            for package in packages:
                package.write_bytes(b"fixture")
            base_lock = (migration622.BASE_FILES / "expected206.lock").read_bytes()
            historical = migration622.LOCKS["historical.lock"][1]
            project = migration622.LOCKS["project.lock"][1]
            inventories = [hashlib.sha256(base_lock).hexdigest(), historical, project, historical]
            lines = [f"{value}  /tmp/project-libraries-migration.edcba001/inventory" for value in inventories]
            raw = ("\n".join(lines + ["TIFF JBIG roundtrip passed"] * 3 +
                              ["MIGRATION622_PASSED native-tiff"]) + "\n").encode()

            def stage(args):
                self.assertFalse(args.emulated_tiff)
                self.assertEqual(args.historical_cache, root / "historical")
                self.assertEqual(sorted(path.name for path in args.project_cache.iterdir()),
                                 sorted(migration622.PROJECT_PACKAGES))
                args.output.mkdir()
                (args.output / "base.lock").write_bytes(base_lock)
                (args.output / "test-fingerprint").write_text("A" * 40 + "\n")

            def call(*args, seconds):
                self.assertEqual(args[:3], ("run", "--rm", "--name"))
                self.assertIn("--network=none", args)
                self.assertIn(f"type=bind,src={root / 'migration'},dst=/migration,readonly", args)
                self.assertEqual(args[-2:], (base, "/migration/migration.sh"))
                self.assertEqual(seconds, 420)
                return subprocess.CompletedProcess(args, 0, raw, b"")

            with (patch.object(migration622, "stage", side_effect=stage),
                  patch.object(docker, "call", side_effect=call),
                  patch.object(docker, "owned_containers", return_value=[])):
                result = migration622.native_run(docker, base, *packages, root, root / "historical", {})
            self.assertEqual(result["inventory_sequence"], inventories)
            self.assertEqual(result["tiff_jbig_roundtrips"], 3)

    def test_both_migration_locks_preserve_consumer_and_all_unrelated_packages(self):
        contract = inputs622.read_pin(inputs622.PROJECT / "minimal206-extension.json", inputs622.EXTENSION_PIN)
        base = (migration622.BASE_FILES / "expected206.lock").read_bytes()
        locks = migration622.migration_locks(base, contract)
        historical, project = (set(locks[name].decode().splitlines())
                               for name in ("historical.lock", "project.lock"))
        self.assertEqual(len(historical), 212)
        self.assertEqual(len(project), 212)
        self.assertEqual(historical - project, {"jbigkit 2.1-8", "libtiff 4.7.2-1"})
        self.assertEqual(project - historical, {"cachy-asahi-jbigkit 2.2-1.1", "cachy-asahi-libtiff 4.7.2-1.1"})
        self.assertIn("lcms2 2.19.1-1", historical & project)
        self.assertLess(set(base.decode().splitlines()), historical & project)
        with self.assertRaises(ValueError):
            migration622.migration_locks(base + b"foreign 1-1\n", contract)


class BuilderTests(unittest.TestCase):
    def test_provisioning_script_has_fixed_required_trust_and_no_host_actions(self):
        subprocess.run(["bash", "-n"], input=build622.INSTALL, text=True, check=True)
        script = build622.INSTALL
        self.assertIn("LocalFileSigLevel = Required", script)
        self.assertLess(script.index("pacman-key --lsign-key"), script.index("pacman -U --noconfirm"))
        self.assertIn('--noscriptlet "$@"', script)
        self.assertIn("expected210.lock", script)
        self.assertNotIn("SigLevel = Never", script)

    def test_lifecycle_requires_signed_install_reinstall_roundtrips_and_exact_restoration(self):
        script = build622.LIFECYCLE
        subprocess.run(["bash", "-n"], input=script, text=True, check=True)
        self.assertIn("missing required signature", script)
        self.assertEqual(script.count('pacman -U --noconfirm --noscriptlet "$@"'), 2)
        self.assertEqual(script.count("check_pair /tmp/"), 2)
        self.assertEqual(script.count("\nremove_pair\n"), 2)
        self.assertIn("expected206.lock", script)
        self.assertIn("expected211.lock", script)
        self.assertIn("libjbig[.]so[.]2[.]2", script)
        self.assertIn("NATIVE_SIGNED_LIFECYCLE_PASSED", script)

    def test_ephemeral_signer_binds_exact_bytes_and_exports_public_key_only(self):
        with tempfile.TemporaryDirectory(prefix="test622-") as temporary:
            root = Path(temporary)
            package = root / "package"
            package.write_bytes(b"synthetic build output")
            home = root / "gnupg"
            try:
                fingerprint, digest = build622.sign_test(package, root, home)
                self.assertRegex(fingerprint, r"^[0-9A-F]{40}$")
                signature = package.with_suffix(".sig")
                self.assertEqual(build622.sha(signature), digest)
                package.write_bytes(b"tampered build output")
                command = ["gpgv", "--homedir", str(home), "--keyring", str(root / "TEST-public.gpg"),
                           str(signature), str(package)]
                self.assertNotEqual(subprocess.run(command, capture_output=True, timeout=10).returncode, 0)
                self.assertEqual({p.name for p in root.iterdir()}, {"package", "package.sig", "TEST-public.gpg", "gnupg"})
            finally:
                build622.command(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"])

    def test_foreign_container_is_never_removed(self):
        with tempfile.TemporaryDirectory() as temporary:
            scope = build622.DockerScope(Path(temporary))
            container = "0" * 64
            row = {"Id": container, "Config": {"Labels": {build622.LABEL: scope.nonce}}, "Name": "/foreign"}
            responses = [subprocess.CompletedProcess([], 0, f"{container}\n".encode(), b""),
                         subprocess.CompletedProcess([], 0, json.dumps([row]).encode(), b"")]
            with patch.object(scope, "call", side_effect=responses) as call:
                with self.assertRaisesRegex(ValueError, "same scoped container"):
                    scope.retire()
                self.assertEqual(call.call_count, 2)

    def test_build_pair_real_driver_can_launch_and_handle_timeout(self):
        image = "sha256:" + "a" * 64
        for timeout in (False, True):
            with self.subTest(timeout=timeout), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                scope = build622.DockerScope(root)
                scope.images["minimal206"] = image
                recipe = root / "recipes/jbigkit"
                recipe.mkdir(parents=True)
                fixture = b"fixture"
                (recipe / "fixture").write_bytes(fixture)
                pkgbuild = recipe / "PKGBUILD"
                pkgbuild.write_text(
                    "pkgname=fixture\npkgver=1\npkgrel=1\narch=(aarch64)\nlicense=(MIT)\n"
                    f"source=(fixture)\nsha256sums=({hashlib.sha256(fixture).hexdigest()})\n"
                )
                hashes = {path.name: build622.sha(path) for path in recipe.iterdir()}
                (recipe.parent / "jbigkit-reviewed-inputs.json").write_text(json.dumps(hashes))
                lock = root / "expected206.lock"
                lock.write_text("fixture 1-1\n")
                captures = [json.dumps([{"Id": image, "Architecture": "arm64", "Os": "linux"}]), "aarch64"]

                def run(argv, **options):
                    name, = scope.names
                    self.assertRegex(name, r"^cachy-asahi-[0-9a-f]{16}$")
                    output = root / "jbigkit-1"
                    self.assertEqual(argv, [
                        build622.DOCKER, "--config", str(scope.config), "--host", "unix:///run/docker.sock",
                        "run", "--rm", "--name", name, "--label", f"{build622.LABEL}={scope.nonce}",
                        "--memory-swap=4g", "--pull=never", "--platform", "linux/arm64",
                        "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop=ALL",
                        "--security-opt=no-new-privileges", "--read-only", "--pids-limit", "512",
                        "--memory", "4g", "--cpus", "4", "--network", "none", "--tmpfs",
                        "/tmp:rw,nosuid,nodev,exec,size=4g", "--env", "CACHY_ASAHI_CONTAINER=1",
                        "--env", f"SOURCE_DATE_EPOCH={build622.EPOCH['jbigkit']}",
                        "--mount", f"type=bind,src={output / 'inputs'},dst=/inputs,readonly",
                        "--mount", f"type=bind,src={output / 'artifacts'},dst=/out",
                        "--mount", f"type=bind,src={build622.BUILD / 'container-entry-v2.sh'},dst=/builder-entry.sh,readonly",
                        "--mount", f"type=bind,src={output / 'expected-packages.lock'},dst=/expected-packages.lock,readonly",
                        "--entrypoint", "/bin/bash", image, "/builder-entry.sh",
                    ])
                    self.assertEqual(options["timeout"], 900)
                    self.assertEqual(options["stderr"], subprocess.STDOUT)
                    options["stdout"].write(b"docker reached\n")
                    if timeout:
                        raise subprocess.TimeoutExpired(argv, options["timeout"])
                    return subprocess.CompletedProcess(argv, 2)

                def owned():
                    name, = scope.names
                    return iter([{"Name": "/" + name}])

                with (patch.object(scope, "build_v2_capture", side_effect=captures),
                      patch.object(scope, "owned_containers", side_effect=owned),
                      patch.object(scope, "remove_container") as remove,
                      patch("build622.subprocess.run", side_effect=run) as executed):
                    result = {}
                    with self.assertRaisesRegex(ValueError, "jbigkit isolated build 1"):
                        build622.build_pair(scope, "jbigkit", image, lock, root, result)
                    self.assertEqual(result["build_failure"], {
                        "attempt": 1, "category": "container-timeout" if timeout else "container-command-failed",
                        "makepkg_phases_observed": [], "known_markers": [],
                        **({} if timeout else {"container_exit_code": 2}),
                    })
                    self.assertEqual(executed.call_count, 1)
                    if timeout:
                        remove.assert_called_once_with({"Name": "/" + next(iter(scope.names))})
                    else:
                        remove.assert_not_called()
                self.assertEqual((root / "jbigkit-1/build.log").read_bytes(), b"docker reached\n")
                report = json.loads((root / "jbigkit-1/provenance.json").read_text())
                self.assertEqual(report["status"], "failed")
                expected = "builder timeout" if timeout else "container build exited 2"
                self.assertIn(expected, report["error"])

    def test_build_failure_projects_only_known_markers(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            artifacts = output / "artifacts"
            artifacts.mkdir()
            (artifacts / "private-recipe-name-build.log").touch()
            (output / "provenance.json").write_text(json.dumps({
                "error": "PRIVATE_PATH: PT_LOAD fails structural 16K alignment check", "exit_code": 0,
            }))
            (output / "build.log").write_bytes(b"PRIVATE_SOURCE_FILENAME\n==> ERROR: A failure occurred in build().\n")
            self.assertEqual(build622.build_failure(output, 2), {
                "attempt": 2, "category": "driver-validation", "container_exit_code": 0,
                "makepkg_phases_observed": ["build"], "known_markers": ["build", "elf-16k-alignment"],
            })

    def test_existing_build_runner_receives_nonce_label_and_swap_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            scope = build622.DockerScope(Path(temporary))
            image = "sha256:" + "a" * 64
            scope.images["minimal206"] = image
            name = "cachy-asahi-abcd0123abcd0123"
            args = ["docker", "run", "--rm", "--name", name, "--pull=never", "--network", "none",
                    "--entrypoint", "/bin/bash", image, "/builder-entry.sh"]
            with patch("build622.subprocess.run") as runner:
                scope.build_v2_run(args, timeout=20)
                command = runner.call_args.args[0]
                self.assertIn(f"{build622.LABEL}={scope.nonce}", command)
                self.assertIn("--memory-swap=4g", command)
                self.assertEqual(command[-2:], [image, "/builder-entry.sh"])


if __name__ == "__main__":
    unittest.main()
