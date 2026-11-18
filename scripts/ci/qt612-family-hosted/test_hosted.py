# SPDX-License-Identifier: MIT
"""Passive controls for the first hosted Qt stage."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import capacity
import executor


class CapacityTests(unittest.TestCase):
    def test_exact_outer_threshold_and_fresh_same_mount_after(self):
        row = dict(path="/fixed", device=9, inode=1, mount=7, free_bytes=capacity.MINIMUM_BYTES,
                   readonly=False, observed_monotonic_ns=1)
        with patch.object(capacity, "observe", return_value=row), patch("os.path.lexists", return_value=False):
            self.assertEqual(capacity.require_before("/fixed"), row)
            row["free_bytes"] -= 1
            with self.assertRaisesRegex(ValueError, "14 GiB"):
                capacity.require_before("/fixed")
            row["free_bytes"] += 1
        later = dict(row, free_bytes=capacity.RESERVE_BYTES, observed_monotonic_ns=2)
        image = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_dev=9, st_uid=0, st_nlink=1,
                                st_size=capacity.STORAGE_BYTES, st_blocks=capacity.STORAGE_BYTES//512, st_ino=2)
        with patch.object(capacity, "observe", return_value=later), patch.object(Path, "lstat", return_value=image):
            self.assertEqual(capacity.require_after("/fixed", row)["reservation"]["bytes"], capacity.STORAGE_BYTES)
            later["mount"] += 1
            with self.assertRaisesRegex(ValueError, "Same outer"):
                capacity.require_after("/fixed", row)
            later["mount"] -= 1
            image.st_blocks -= 1
            with self.assertRaisesRegex(ValueError, "fully allocated"):
                capacity.require_after("/fixed", row)

    def test_linux_mount_observation_reads_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder).resolve()
            result = capacity.observe(path)
            self.assertEqual(result["device"], path.stat().st_dev)
            self.assertGreater(result["mount"], 0)
            self.assertEqual(tuple(path.iterdir()), ())

    def test_bulk_budget_uses_owned_inner_mount(self):
        logical = 1_752_637_011
        minimum = 3_572_382_886
        host = dict(path="/fixed", device=9, mount=7, free_bytes=capacity.RESERVE_BYTES, observed_monotonic_ns=2)
        volume = dict(device=10, mount=8, free_bytes=minimum, observed_monotonic_ns=3, readonly=False)
        work = dict(volume, observed_monotonic_ns=4)
        with patch.object(capacity, "observe", side_effect=[volume, work]) as observe:
            result = capacity.require_transfer_volume("/fixed", {"host": host}, logical)
            self.assertEqual(result["minimum_free_bytes"], minimum)
            self.assertEqual([str(call.args[0]) for call in observe.call_args_list],
                             ["/fixed/volume", "/fixed/volume/work"])
        with patch.object(capacity, "observe", side_effect=[volume, dict(work, device=9)]):
            with self.assertRaisesRegex(ValueError, "owned loop mount"):
                capacity.require_transfer_volume("/fixed", {"host": host}, logical)
        with patch.object(capacity, "observe", side_effect=[volume, dict(work, free_bytes=minimum-1)]):
            with self.assertRaisesRegex(ValueError, "owned loop mount"):
                capacity.require_transfer_volume("/fixed", {"host": host}, logical)


class CommandRunner:
    """An inert model of the existing owner's naturally retired Commands rows."""

    def __init__(self, image, nonce):
        self.rows, self.envs = [], []
        self.image, self.nonce = image, nonce
        self.natural = True
        self.occupied = False

    def __call__(self, argv, seconds, env=None):
        if argv[2:4] == ["image", "inspect"]:
            result = [dict(Id=self.image, Architecture="arm64", Os="linux",
                           Config=dict(Labels={executor.LABEL: self.nonce}))]
            body = json.dumps(result).encode()
        elif argv[2:4] == ["container", "ls"]:
            body = b"live\n" if self.occupied else b""
        else:
            body = b'{"comparison": "model"}\n'
        self.envs.append(env)
        self.rows.append(dict(argv=argv, retirement=dict(exit=0, reaped=True, ownership="REAPED",
                             group_census="EMPTY_TWICE", output_complete=self.natural,
                             signals=[], timeout=False, error=None)))
        return subprocess.CompletedProcess(argv, 0, body, b"")


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.out = Path(temp.name)
        self.image, self.nonce = "sha256:"+"1"*64, "2"*32
        compare = ["/usr/bin/python3", "-I", "-B", "comparison"]
        builds = [dict(argv=["/usr/bin/python3", "-I", "-B", "builder", "--output", str(self.out/f"build-{i}")],
                       env={"CACHY_QT612_REFERENCE_ATTEMPT": str(i)}) for i in (1, 2)]
        self.plan = dict(component="gui_server", serial=True, inventory_pin={"sha256": "3"*64},
                         image=self.image, nonce=self.nonce, source_map_sha256="4"*64, builds=builds, compare=compare)
        self.runner = CommandRunner(self.image, self.nonce)
        self.supervisor = Mock()
        self.enterContext(patch.dict(os.environ, {key: "model" for key in (
            "GITHUB_REPOSITORY", "GITHUB_EVENT_NAME", "GITHUB_SHA", "GITHUB_REF", "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT", "UNRELATED_SECRET")}, clear=True))
        self.socket = self.enterContext(patch.object(executor, "private_socket",
            return_value=(Path("/fixed/volume/docker.sock"), (1, 2))))
        self.api = executor.FirstPairExecutor(SimpleNamespace(BUILD_SECONDS=6900, COMPARE_SECONDS=120),
            self.plan, self.runner, self.supervisor, socket="/fixed/volume/docker.sock",
            source="/fixed/family", binding="/fixed/binding", binding_sha256="5"*64)

    def authenticate(self):
        self.api.authenticate_Root_stage_binding({"actual": "inert"})
        self.api.require_domain({"policy": "inert"})
        self.api.require_signed_inventory(component="gui_server", image=self.image,
            inventory_pin=self.plan["inventory_pin"], signature_policy="Required TrustedOnly", previous_providers=[])

    def build(self, index):
        row = self.plan["builds"][index]
        return self.api.run(row["argv"], 6900, env=row["env"])

    def test_two_exact_builds_absence_and_comparison(self):
        with self.assertRaisesRegex(ValueError, "Authenticate"):
            self.build(0)
        self.authenticate()
        self.api.require_no_containers()
        self.assertTrue(self.build(0)["natural"])
        with self.assertRaisesRegex(ValueError, "confirm retirement"):
            self.build(1)
        with self.assertRaisesRegex(ValueError, "exact completed"):
            self.api.require_absent_twice(f"cachy-qt612-family-{self.nonce}-gui_server-2")
        self.api.require_absent_twice(f"cachy-qt612-family-{self.nonce}-gui_server-1")
        self.api.require_no_containers()
        self.build(1)
        self.api.require_absent_twice(f"cachy-qt612-family-{self.nonce}-gui_server-2")
        target = self.out/"comparison.json"
        self.api.run(self.plan["compare"], 120, env={}, stdout=str(target))
        self.assertEqual(target.read_bytes(), b'{"comparison": "model"}\n')
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.api.qualify(owned=True)
        self.supervisor.qualify.assert_called_once_with(owned=True)
        self.assertTrue(all("UNRELATED_SECRET" not in env for env in self.runner.envs if env))
        self.assertTrue(all(row["argv"][1] == "--host=unix:///fixed/volume/docker.sock"
                            for row in self.runner.rows if row["argv"][0] == executor.DOCKER))

    def test_held_build_and_changed_daemon(self):
        self.authenticate()
        self.runner.natural = False
        with self.assertRaisesRegex(ValueError, "Natural complete"):
            self.build(0)
        self.assertEqual(self.api.attempt, 0)
        self.socket.return_value = Path("/fixed/volume/docker.sock"), (1, 3)
        with self.assertRaisesRegex(ValueError, "Same authenticated"):
            self.api.require_no_containers()

    def test_unretired_name_blocks_next_attempt(self):
        self.authenticate()
        self.build(0)
        self.runner.occupied = True
        with self.assertRaisesRegex(ValueError, "remains"):
            self.api.require_absent_twice(f"cachy-qt612-family-{self.nonce}-gui_server-1")
        with self.assertRaisesRegex(ValueError, "confirm retirement"):
            self.build(1)

    def test_builder_child_blocks_force_fallback_before_exec(self):
        source = Path("/fixed/family")
        program = source/"runtime/gui_server/scripts/build/build_family.py"
        pipeline = Mock()
        pipeline.require_actual_family.return_value = {"nonce": self.nonce, "image": self.image}
        child = SimpleNamespace()
        name = f"cachy-qt612-family-{self.nonce}-gui_server-1"
        run_args = ["docker", "run", "--rm", "--name", name, "--pull=never", "--read-only",
                    "--cap-drop=ALL", "--security-opt=no-new-privileges", "--network", "none",
                    "--platform", "linux/arm64", "--cpus", "1", "--memory", "4g", "--memory-swap", "4g",
                    "--pids-limit", "512", "--tmpfs", "/tmp:rw,nosuid,nodev,exec,size=4g",
                    "--user", "1001:1001", "--entrypoint", "/bin/bash", self.image, "/builder-entry.sh"]

        def child_main():
            child.subprocess.run(run_args, timeout=6900)
            with self.assertRaisesRegex(ValueError, "offline GUI container"):
                child.subprocess.run(["docker", "rm", "-f", name])
            return 0

        child.main = child_main
        with patch.dict(os.environ, {executor.SOCKET_ENV: "/fixed/volume/docker.sock",
                                      "QT612_FAMILY_SOURCE_ROOT": str(source),
                                      "CACHY_QT612_REFERENCE_ATTEMPT": "1"}), \
                patch.object(sys, "argv", ["launcher", str(program), "opaque-args"]), \
                patch("os.getuid", return_value=1001), patch("os.geteuid", return_value=1001), \
                patch("os.getgid", return_value=1001), patch.object(executor, "load", side_effect=[pipeline, child]), \
                patch.object(subprocess, "run") as run:
            self.assertEqual(executor.build_child(), 0)
        run.assert_called_once_with([executor.DOCKER, "--host=unix:///fixed/volume/docker.sock", *run_args[1:]], timeout=6900)
        pipeline.require_actual_family.assert_called_once_with("gui_server", actor_argv=["opaque-args"])


if __name__ == "__main__":
    unittest.main()
