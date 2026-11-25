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
import inputs622


class IntakeTests(unittest.TestCase):
    def test_endpoint_passes_credentials_only_through_stdin(self):
        endpoint = inputs622.Endpoint("https://example.invalid/private-path", "test-token")
        name = "linux-aarch64-7.3.4-3-aarch64.pkg.tar.xz"
        result = subprocess.CompletedProcess([], 0, b"200", b"")
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "cache"
            with patch("inputs622.subprocess.run", return_value=result) as runner:
                endpoint.fetch(name, target, 12)
        args, options = runner.call_args
        self.assertNotIn("--location", args[0])
        self.assertNotIn("test-token", " ".join(args[0]))
        self.assertNotIn("private-path", " ".join(args[0]))
        self.assertIn(("--noproxy", "*"), list(zip(args[0], args[0][1:])))
        self.assertIn(b"/private-path/" + name.encode(), options["input"])
        self.assertIn(b"Authorization: Bearer test-token", options["input"])
        self.assertTrue(options["capture_output"])

    def test_invalid_endpoint_and_token(self):
        for endpoint, token in (
            ("http://example.invalid", ""),
            ("https://user:password@example.invalid", ""),
            ("https://example.invalid?secret=1", ""),
            ("https://example.invalid", 'broken"\nurl = "evil'),
            ("", "orphan-token"),
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                inputs622.Endpoint(endpoint, token)

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


    def test_private_route_is_used_only_for_retained_bodies(self):
        name = "linux-aarch64-7.3.4-3-aarch64.pkg.tar.xz"
        pin = dict(bytes=4, sha256=hashlib.sha256(b"good").hexdigest(), url="https://public.invalid/object")
        endpoint = inputs622.Endpoint("https://private.invalid", "secret")

        def download(url, path, size, **options):
            path.write_bytes(b"good")

        with tempfile.TemporaryDirectory() as directory, patch.object(inputs622, "download", side_effect=download) as fetch:
            root = Path(directory)
            inputs622.stage_object(root, name, pin, endpoint=endpoint)
            inputs622.stage_object(root, "public", pin, endpoint=endpoint)
        private, public = fetch.call_args_list
        self.assertEqual(private.args[0], f"https://private.invalid/{name}")
        self.assertEqual(private.kwargs, {"token": "secret", "private": True})
        self.assertEqual(public.args[0], pin["url"])
        self.assertEqual(public.kwargs, {})

    def test_private_404_holds_instead_of_downgrading(self):
        name = "linux-aarch64-7.3.4-3-aarch64.pkg.tar.xz"
        result = subprocess.CompletedProcess([], 22, b"404", b"secret diagnostic")
        endpoint = inputs622.Endpoint("https://private.invalid", "secret")
        with tempfile.TemporaryDirectory() as directory, patch.object(inputs622.subprocess, "run", return_value=result) as run:
            with self.assertRaisesRegex(ValueError, f"input transport failed: {name}"):
                inputs622.stage_object(Path(directory), name, {"bytes": 4, "sha256": "0" * 64}, endpoint=endpoint)
            self.assertEqual(run.call_count, 1)

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
