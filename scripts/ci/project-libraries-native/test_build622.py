# SPDX-License-Identifier: MIT
"""Local, no-engine controls for the #622 intake, signature and cleanup boundaries."""
import hashlib
import json
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


class IntakeTests(unittest.TestCase):
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
