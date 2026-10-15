# SPDX-License-Identifier: MIT
"""Source/isolated x86 fixtures only; no installed ARM image or M2 acceptance."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("onboarding", Path(__file__).with_name("onboarding.py"))
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)


class OnboardingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cachy-asahi-onboarding-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.versions = {name: "0.1.0-1" for name in o.PACKAGES}
        self.lock = "".join(f"{name} {version}\n" for name, version in sorted(self.versions.items()))
        self.rows = []
        for name in o.PACKAGES:
            payload = {path.lstrip("/"): hashlib.sha256(name.encode()).hexdigest() for path, owner in o.OWNERS.items() if owner == name}
            self.rows.append({"name": name, "version": self.versions[name], "sha256": "a" * 64, "payload_sha256": payload})
        self.contract = {"software_only": True, "nonce": "b" * 32, "uid": 1001, "gid": 1001, "image_id": "sha256:" + "c" * 64}
        self.facts = {"system": "Linux", "architecture": "aarch64", "dockerenv": True,
                      "uid": 1001, "gid": 1001, "capabilities": 0, "no_new_privileges": "1",
                      "nonce": "b" * 32, "home": "/tmp/onboarding/home", "image_id": self.contract["image_id"],
                      "network_interfaces": ["lo"], "docker_socket_exposed": False,
                      "unexpected_devices": [], "unexpected_sockets": [], "output_empty": True, "fresh_home_absent": True,
                      "directory_owners": {point: {"uid": 1001, "gid": 1001, "mode": 0o700} for point in ("/tmp", "/out")},
                      "mounts": {"/": {"flags": ["ro"], "type": "overlay"},
                                 "/tmp": {"flags": ["rw", "nosuid", "nodev"], "type": "tmpfs"},
                                 "/inputs": {"flags": ["ro"], "type": "ext4"}, "/out": {"flags": ["rw"], "type": "ext4"},
                                 "/dev/pts": {"flags": ["rw", "nosuid"], "type": "devpts"}},
                      "runtime_files": {point: {"regular": True, "uid": 0, "gid": 0, "mode": 0o644} for point in o.RUNTIME_FILES}}
        for point, (types, flags) in o.RUNTIME_TYPES.items():
            self.facts["mounts"][point] = {"flags": sorted(flags), "type": sorted(types)[0]}

    def args(self):
        source = self.root / "hello.c"
        source.write_bytes((o.ROOT / "examples/development/hello.c").read_bytes())
        lock = self.root / "packages.lock"
        lock.write_text(self.lock)
        baseline = self.root / "baseline.json"
        o.save(baseline, {"baseline": self.rows})
        return argparse.Namespace(image="sha256:" + "c" * 64, source=source, source_sha256=o.sha(source),
                                  expected_packages=lock, expected_packages_sha256=o.sha(lock),
                                  baseline_manifest=baseline, baseline_manifest_sha256=o.sha(baseline),
                                  output=self.root / "evidence", timeout=10)

    def test_container_contract_rejects_host_root_unsafe_mounts_and_identity(self):
        o.validate_container(self.contract, self.facts)  # Synthetic validation only.
        for key, value in (("architecture", "x86_64"), ("dockerenv", False), ("uid", 0), ("gid", 0),
                           ("capabilities", 1), ("no_new_privileges", "0"), ("home", "/home/real-user"),
                           ("nonce", "other"), ("image_id", "sha256:" + "d" * 64),
                           ("network_interfaces", ["eth0", "lo"]), ("docker_socket_exposed", True),
                           ("unexpected_devices", ["/dev/dri/renderD128"]), ("unexpected_sockets", ["/run/alternative.sock"]),
                           ("output_empty", False), ("fresh_home_absent", False)):
            with self.subTest(key=key), self.assertRaises(o.Failure):
                o.validate_container(self.contract, self.facts | {key: value})
        for point in ("/", "/inputs", "/out", "/tmp", "/dev/pts"):
            facts = copy.deepcopy(self.facts)
            del facts["mounts"][point]
            with self.subTest(point=point), self.assertRaises(o.Failure):
                o.validate_container(self.contract, facts)
        for owners in ({}, {"/tmp": {"uid": 0, "gid": 0, "mode": 0o777}, "/out": self.facts["directory_owners"]["/out"]}):
            with self.assertRaises(o.Failure):
                o.validate_container(self.contract, self.facts | {"directory_owners": owners})
        facts = copy.deepcopy(self.facts)
        facts["mounts"]["/home/gabe"] = {"flags": ["ro"], "type": "ext4"}
        with self.assertRaisesRegex(o.Failure, "host home"):
            o.validate_container(self.contract, facts)
        for point in ("/extra-real-home", "/extra-keyring", "/dev/dri", "/alternate-socket"):
            facts = copy.deepcopy(self.facts)
            facts["mounts"][point] = {"flags": ["rw"], "type": "ext4"}
            with self.subTest(point=point), self.assertRaisesRegex(o.Failure, "unexpected runtime mount"):
                o.validate_container(self.contract, facts)
        for point in ("/sys", "/proc", "/dev/shm", "/dev/mqueue", "/sys/fs/cgroup"):
            facts = copy.deepcopy(self.facts)
            facts["mounts"][point] = {"flags": ["rw"], "type": "ext4"}
            with self.subTest(point=point), self.assertRaisesRegex(o.Failure, "filesystem type/flags"):
                o.validate_container(self.contract, facts)
        facts = copy.deepcopy(self.facts)
        facts["mounts"]["/proc/kcore"] = {"flags": ["rw"], "type": "tmpfs"}
        facts["null_masks"] = {"/proc/kcore": True}
        o.validate_container(self.contract, facts)  # Audited harmless Docker null-device mask.
        facts["null_masks"]["/proc/kcore"] = False
        with self.assertRaisesRegex(o.Failure, "unsafe runtime mask"):
            o.validate_container(self.contract, facts)

    def test_reviewed_inputs_and_complete_inventory_are_required(self):
        path = self.root / "input"
        path.write_bytes(b"first")
        expected = o.sha(path)
        self.assertEqual(o.pinned_bytes(path, expected), b"first")
        path.write_bytes(b"changed")
        for digest in (expected, "short"):
            with self.assertRaises(o.Failure):
                o.pinned_bytes(path, digest)
        self.assertEqual(o.package_lock(self.lock), self.versions)
        for lock in ("", self.lock.rstrip(), "".join(reversed(self.lock.splitlines(keepends=True))),
                     self.lock + self.lock.splitlines(keepends=True)[-1], "python 1\n"):
            with self.subTest(lock=lock), self.assertRaises(o.Failure):
                o.package_lock(lock)

    def test_baseline_payload_manifest_covers_every_package_and_required_file(self):
        self.assertEqual(len(o.baseline_manifest({"baseline": self.rows}, self.versions)), 4)
        for mutation in ("missing_package", "wrong_version", "missing_helper", "path_escape", "bad_hash"):
            rows = copy.deepcopy(self.rows)
            if mutation == "missing_package":
                rows.pop()
            elif mutation == "wrong_version":
                rows[0]["version"] = "different"
            elif mutation == "missing_helper":
                rows[-1]["payload_sha256"] = {"usr/share/doc/fixture": "a" * 64}
            elif mutation == "path_escape":
                rows[-1]["payload_sha256"]["usr/../../etc/passwd"] = "a" * 64
            else:
                rows[-1]["sha256"] = "bad"
            with self.subTest(mutation=mutation), self.assertRaises(o.Failure):
                o.baseline_manifest({"baseline": rows}, self.versions)

    def test_installed_payload_bytes_regular_type_and_modes_are_bound(self):
        for row in self.rows:
            for relative in row["payload_sha256"]:
                path = self.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(row["name"].encode())
        audit = o.installed_payloads(self.rows, self.root, root_owned=False)
        self.assertEqual(set(audit), set(o.PACKAGES))
        path = self.root / "usr/bin/cachy-asahi-setup"
        path.write_bytes(b"modified installed helper")
        with self.assertRaisesRegex(o.Failure, "payload differs"):
            o.installed_payloads(self.rows, self.root, root_owned=False)
        path.write_bytes(b"cachy-asahi-setup")
        path.chmod(0o666)
        with self.assertRaisesRegex(o.Failure, "payload differs"):
            o.installed_payloads(self.rows, self.root, root_owned=False)
        path.chmod(0o644)
        replacement = self.root / "replacement"
        replacement.write_bytes(path.read_bytes())
        path.unlink()
        path.symlink_to(replacement)
        with self.assertRaisesRegex(o.Failure, "payload differs"):
            o.installed_payloads(self.rows, self.root, root_owned=False)

    def test_native_probe_failure_never_launches_journey(self):
        args = self.args()
        build = Mock(image_pin=lambda value: value)
        native = Mock()
        native.probe.side_effect = ValueError("native Linux ARM host and local ARM Docker daemon required")
        with patch.object(o, "load_tool", side_effect=[build, native]), patch.object(o.subprocess, "run") as run, patch.object(o.subprocess, "Popen") as launch:
            self.assertEqual(o.host(args), 2)
            run.assert_not_called()
            launch.assert_not_called()
        result = json.loads((args.output / "provenance.json").read_text())
        self.assertEqual(result["status"], "failed")
        self.assertIn("native Linux ARM", result["error"])
        self.assertEqual(result["hardware"], "NOT RUN")

    def test_constructed_container_exposes_only_inputs_and_new_artifacts(self):
        args = self.args()
        # Count frozen test sources independently of the changing project suites.
        source_root = self.root / "source-fixture"
        test_sources = {
            "scripts/setup/setup.py": "# Inert setup source fixture.\n",
            "scripts/setup/test_setup.py": ("import unittest\nclass SetupFixture(unittest.TestCase):\n"
                                            "    def test_one(self): pass\n"),
            "scripts/release/release.py": "# Inert release source fixture.\n",
            "scripts/release/source_delivery.py": "# Inert source delivery fixture.\n",
            "scripts/release/test_release.py": ("import unittest\nclass ReleaseFixture(unittest.TestCase):\n"
                                                "    def test_one(self): pass\n"
                                                "    def test_two(self): pass\n"),
        }
        sources = test_sources | {"scripts/build/build.py": "# Inert build fixture.\n",
                                  "scripts/ci/native_arm.py": "# Inert native probe fixture.\n"}
        for relative, text in sources.items():
            target = source_root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        build = Mock(image_pin=lambda value: value)
        native = Mock()
        native.probe.return_value = {"architecture": "aarch64", "scope": "synthetic fixture"}
        native.run.return_value = json.dumps([{"Architecture": "arm64", "Os": "linux", "Id": args.image}])
        commands = []
        def simulated(command, **kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")
        def launch(command, **kwargs):
            commands.append(command)
            contract = json.loads((args.output / "inputs/contract.json").read_text())
            o.save(args.output / "artifacts/result.json", {"status": "SOFTWARE PASS", "contract": contract})
            return Mock(pid=999999999, returncode=0)
        with patch.object(o, "ROOT", source_root), patch.object(o, "load_tool", side_effect=[build, native]), \
                patch.object(o.subprocess, "run", side_effect=simulated), \
                patch.object(o.subprocess, "Popen", side_effect=launch):
            self.assertEqual(o.host(args), 0)
        command = commands[0]
        for flag in ("--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pull=never"):
            self.assertIn(flag, command)
        mounts = [command[i + 1] for i, token in enumerate(command) if token == "--mount"]
        self.assertEqual(len(mounts), 2)
        self.assertIn("dst=/inputs,readonly", mounts[0])
        self.assertIn("dst=/out", mounts[1])
        self.assertNotIn(str(Path.home()), " ".join(mounts))
        self.assertIn("HOME=/tmp/onboarding/home", command)
        self.assertEqual(commands[1][:3], ["docker", "rm", "-f"])
        contract = json.loads((args.output / "inputs/contract.json").read_text())
        self.assertEqual(contract["test_counts"], {"setup": 1, "release": 2})
        self.assertEqual(contract["test_inputs"], {
            relative: hashlib.sha256(text.encode()).hexdigest() for relative, text in test_sources.items()})
        for relative, text in test_sources.items():
            self.assertEqual((args.output / "inputs" / relative).read_bytes(), text.encode())
        self.assertEqual(contract["baseline_manifest_sha256"], args.baseline_manifest_sha256)

    def test_command_timeout_and_literal_argv_retain_raw_evidence(self):
        output = self.root / "commands"
        output.mkdir()
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.root)}
        runner = o.Commands(output, env, self.root, timeout=.05)
        literal = "$(touch NEVER_CREATE); literal"
        text = runner.run("literal", [sys.executable, "-c", "import sys;print(sys.argv[1])", literal])
        self.assertIn(literal, text)
        self.assertFalse((self.root / "NEVER_CREATE").exists())
        with self.assertRaisesRegex(o.Failure, "step failed"):
            runner.run("timeout", [sys.executable, "-c", "import time;print('before timeout',flush=True);time.sleep(.3)"])
        self.assertIn(b"before timeout", (output / "journey-01-timeout.stdout").read_bytes())
        self.assertIn("TimeoutExpired", runner.records[-1]["error"])
        self.assertFalse(runner.records[-1]["success"])

    @unittest.skipUnless(os.geteuid() != 0 and all(shutil.which(name) for name in ("fish", "zsh", "vim", "cc")),
                         "local source smoke needs installed non-root shell/editor/compiler prerequisites")
    def test_actual_pty_editor_and_compile_journey_uses_only_temp_fixture_home(self):
        output = self.root / "journey-evidence"
        output.mkdir()
        templates = self.root / "templates"
        for component in ("fish", "zsh"):
            target = templates / component / f"config.{component}"
            target.parent.mkdir(parents=True, mode=0o700)
            target.write_bytes((o.ROOT / f"packages/shells/cachy-asahi-{component}-config/config.{component}").read_bytes())
        tools = {name: shutil.which(name) for name in ("python3", "fish", "zsh", "cc", "vim")}
        tools["setup"] = [sys.executable, "-I", str(o.ROOT / "scripts/setup/setup.py")]
        prior_home = os.environ.get("HOME")
        result = o.journey(o.ROOT / "examples/development/hello.c", output, self.root / "scratch", tools, templates)
        self.assertEqual(result["steps"], 13)
        self.assertEqual(os.environ.get("HOME"), prior_home)
        self.assertEqual(result["original_source_sha256"], o.sha(o.ROOT / "examples/development/hello.c"))
        self.assertNotEqual(result["edited_source_sha256"], result["original_source_sha256"])
        records = json.loads((output / "journey-commands.json").read_text())
        self.assertTrue(all(record["success"] for record in records))
        self.assertTrue(all(record["environment"]["HOME"].startswith(str(self.root)) for record in records))
        self.assertEqual(next(r for r in records if r["step"] == "compile")["argv"][1:],
                         ["-Wall", "-Wextra", "-Werror", "-O2", "examples/development/hello.c", "-o", "build/onboarding/hello"])
        self.assertEqual((output / "journey-09-hello.stdout").read_text(), "Hello from cachy-asahi\n")
        self.assertIn("not GUI", result["editor_scope"])
        removed = next(record for record in records if record["step"] == "zsh-after-remove")
        self.assertEqual(removed["prompt_response"]["response"], "0\n")
        if removed["prompt_response"]["observed_and_sent"]:
            self.assertTrue((Path(result["home"]) / ".zshrc").is_file())

    def test_suite_wrapper_never_counts_skipped_source_tests_as_pass(self):
        inputs, output, home = self.root / "suite-inputs", self.root / "suite-output", self.root / "suite-home"
        output.mkdir()
        home.mkdir(mode=0o700)
        for name in ("setup", "release"):
            directory = inputs / "scripts" / name
            directory.mkdir(parents=True)
            test = ("import unittest\nclass Fixture(unittest.TestCase):\n"
                    " @unittest.skip('synthetic missing prerequisite')\n"
                    " def test_one(self): pass\n")
            (directory / f"test_{name}.py").write_text(test)
        with self.assertRaisesRegex(o.Failure, "setup-tests"):
            o.run_suites(inputs, output, home, {"setup": 1, "release": 1})
        report = json.loads((output / "setup-tests.json").read_text())
        self.assertEqual(report["tests_run"], 1)
        self.assertEqual(len(report["skipped"]), 1)
        record = json.loads((output / "suites-commands.json").read_text())[0]
        self.assertEqual(record["returncode"], 2)
        self.assertFalse(record["success"])

    def test_sigterm_runs_bounded_pty_cleanup_and_retains_diagnostics(self):
        output = self.root / "signal-evidence"
        output.mkdir()
        code = """import importlib.util,json,os,signal,sys
from pathlib import Path
s=importlib.util.spec_from_file_location('onboarding',sys.argv[1]);o=importlib.util.module_from_spec(s);s.loader.exec_module(o)
signal.signal(signal.SIGTERM,o.interrupt)
out=Path(sys.argv[2]);env={'HOME':str(out),'PATH':'/usr/bin:/bin','TERM':'dumb'}
runner=o.Commands(out,env,out,timeout=.6)
work=[sys.executable,'-c','import os,time;print(os.getpid(),flush=True);time.sleep(.8)']
try:runner.run('signal',work,terminal=True)
except o.Failure:pass
"""
        wrapper = subprocess.Popen([sys.executable, "-I", "-c", code, str(Path(o.__file__).resolve()), str(output)],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            # Wait until the handler and controlled child are established; no real shell/HOME.
            deadline = o.time.monotonic() + .4
            pid = None
            while o.time.monotonic() < deadline:
                children = Path(f"/proc/{wrapper.pid}/task/{wrapper.pid}/children")
                if children.exists() and children.read_text().strip():
                    pid = int(children.read_text().split()[0])
                    break
                o.time.sleep(.005)
            self.assertIsNotNone(pid)
            wrapper.terminate()
            stdout, stderr = wrapper.communicate(timeout=1)
            self.assertEqual(wrapper.returncode, 0, stdout + stderr)
            record = json.loads((output / "journey-commands.json").read_text())[0]
            self.assertIn("Interrupted", record["error"])
            self.assertFalse(record["success"])
            self.assertFalse(Path(f"/proc/{pid}").exists())
        finally:
            if wrapper.poll() is None:
                wrapper.kill()
            wrapper.communicate(timeout=1)

    def test_repeated_cancellation_during_cleanup_cannot_skip_evidence_or_handler_restore(self):
        import signal
        output = self.root / "cleanup-cancellation"
        output.mkdir()
        runner = o.Commands(output, {"HOME": str(self.root), "PATH": "/usr/bin:/bin"}, self.root)
        prior = signal.getsignal(signal.SIGTERM)
        original = os.killpg
        def cancelled(pid, signum):
            os.kill(os.getpid(), signal.SIGTERM)
            os.kill(os.getpid(), signal.SIGTERM)
            return original(pid, signum)
        with patch.object(o.os, "killpg", side_effect=cancelled), self.assertRaisesRegex(o.Failure, "step failed"):
            runner.run("cleanup", [sys.executable, "-I", "-c", "print('work complete')"])
        record = json.loads((output / "journey-commands.json").read_text())[0]
        self.assertEqual(record["error"], "interrupted during cleanup")
        self.assertFalse(record["success"])
        self.assertIn(b"work complete", (output / "journey-00-cleanup.stdout").read_bytes())
        self.assertEqual(signal.getsignal(signal.SIGTERM), prior)

    def test_sigterm_after_slave_close_preserves_fd_ownership_and_diagnostics(self):
        import signal
        output = self.root / "close-cancellation"
        output.mkdir()
        runner = o.Commands(output, {"HOME": str(output), "PATH": "/usr/bin:/bin"}, output, timeout=.6)
        real_close, real_openpty, real_popen = os.close, o.pty.openpty, subprocess.Popen
        parent = os.getpid()
        observed = {"slave_closes": 0}
        def openpty():
            observed["master"], observed["slave"] = real_openpty()
            return observed["master"], observed["slave"]
        def launch(*args, **kwargs):
            observed["process"] = real_popen(*args, **kwargs)
            return observed["process"]
        def close(fd):
            real_close(fd)
            if os.getpid() == parent and fd == observed.get("slave"):
                observed["slave_closes"] += 1
                if not observed.get("signalled"):
                    observed["signalled"] = True
                    observed["blocked"] = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                    os.kill(parent, signal.SIGTERM)
                    # Reuse the closed number: stale ownership could silently close
                    # an unrelated descriptor instead of raising EBADF.
                    observed["replacement"] = os.open(output / "replacement", os.O_CREAT | os.O_RDWR, 0o600)
        previous = signal.signal(signal.SIGTERM, o.interrupt)
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        started = o.time.monotonic()
        argv = [sys.executable, "-I", "-c", "import time;time.sleep(10)"]
        try:
            with patch.object(o.pty, "openpty", side_effect=openpty), \
                    patch.object(o.subprocess, "Popen", side_effect=launch), \
                    patch.object(o.os, "close", side_effect=close), self.assertRaisesRegex(o.Failure, "step failed"):
                runner.run("close", argv, terminal=True)
            self.assertLess(o.time.monotonic() - started, 2)
            self.assertIn(signal.SIGTERM, observed["blocked"])
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), original_mask)
            self.assertIs(signal.getsignal(signal.SIGTERM), o.interrupt)
            self.assertEqual(observed["slave_closes"], 1)
            self.assertEqual(observed["replacement"], observed["slave"])
            os.fstat(observed["replacement"])
            with self.assertRaises(OSError) as closed_master:
                os.fstat(observed["master"])
            self.assertEqual(closed_master.exception.errno, 9)
            child = observed["process"]
            self.assertEqual(child.returncode, -signal.SIGKILL)
            with self.assertRaises(ChildProcessError):
                os.waitpid(child.pid, os.WNOHANG)
            with self.assertRaises(ProcessLookupError):
                os.killpg(child.pid, 0)
            record = json.loads((output / "journey-commands.json").read_text())[0]
            self.assertEqual(record["error"], "Interrupted: interrupted by SIGTERM")
            self.assertFalse(record["success"])
            self.assertEqual(record["returncode"], child.returncode)
            self.assertEqual(record["argv"], argv)
            self.assertEqual(record["terminal"], "PTY, scripted command")
            self.assertEqual(runner.records, [record])
            self.assertEqual((output / record["stdout_file"]).read_bytes(), b"")
            self.assertEqual((output / record["stderr_file"]).read_bytes(), b"")
        finally:
            signal.signal(signal.SIGTERM, previous)
            if "replacement" in observed:
                real_close(observed["replacement"])

    def test_host_inside_flag_refuses_before_any_user_setup(self):
        result = subprocess.run([sys.executable, str(Path(o.__file__).resolve()), "--inside"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("contract refused", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
