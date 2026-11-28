#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the canonical installer carrier and its trusted source consumers."""
import hashlib
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[2]
SOURCE = "a113f522e6f17ac86daf82193442485e88b69316"
FROZEN = "bcf0cee981ee4b7f7b082f636922c859dc7e0abc"
COMPOSITION = "installer-preflight"
HISTORICAL = "scripts/ci/development/packet-installer-preflight.lock.json"
HISTORICAL_SHA = "59f4d6eccb7f62f75f5241d0f3eceb996bd3e0c93dec161d8d22f02a9ea648f0"
PACKET_SHA = "6892cec93380a9773ecd8b4905227fa5aefb4b3796f68271025166d7a6d5d7e3"
ROWS_SHA = "8cc7c63286f41b54d95472b487cd334f6c02f02769d3cd042478b4b1c8916e68"
ISSUER = "scripts/ci/development/repository_handoff.py"
BRIDGE = "scripts/install/native_preflight.py"
RECEIVER = "scripts/install/native_arm_trial.py"
RUNTIME = "scripts/port/kernel-native-job/runtime.py"
INPUTS = "scripts/ci/inputs.lock.json"
INVENTORY = "scripts/port/refreshed-desktop/proposed-builder-inventory.lock"
REPLACEMENTS = {ISSUER, BRIDGE, "scripts/install/test_native_preflight.py",
                "scripts/install/test_native_arm_trial.py"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *arguments):
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null", GIT_TERMINAL_PROMPT="0")
    return subprocess.run(
        ["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null", "-C", str(root), *arguments],
        env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=True,
    ).stdout


class Registration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="installer-source-registration-")
        cls.addClassCleanup(temporary.cleanup)
        cls.work = Path(temporary.name)
        cls.root = cls.work / "source"
        git(PROJECT, "clone", "--quiet", "--shared", "--no-checkout", "--", str(PROJECT), str(cls.root))
        git(cls.root, "checkout", "--quiet", "--detach", SOURCE)
        cls.packet = runpy.run_path(str(cls.root / "scripts/ci/development/packet.py"))
        cls.canonical = cls.root / cls.packet["LOCK"]
        cls.successor = cls.packet["pinned"](cls.canonical, PACKET_SHA)
        cls.historical = cls.packet["pinned"](cls.root / HISTORICAL, HISTORICAL_SHA)

    def preflight(self):
        return self.packet["preflight_composed"](
            self.root, self.canonical, PACKET_SHA, SOURCE, composition=COMPOSITION,
        )

    def test_canonical_git_source_freezes_and_verifies(self):
        self.assertEqual(git(self.root, "rev-parse", "HEAD^").strip().decode(), FROZEN)
        changed = set(git(self.root, "diff-tree", "--no-commit-id", "--name-only", "-r", SOURCE).decode().splitlines())
        self.assertEqual(changed, REPLACEMENTS | {self.packet["LOCK"]})
        self.assertEqual(self.canonical.read_bytes(), (HERE / "packet.lock.json").read_bytes())
        self.assertEqual({k: v for k, v in self.successor.items() if k != "source_files"},
                         {k: v for k, v in self.historical.items() if k != "source_files"})
        new, old = self.successor["source_files"], self.historical["source_files"]
        self.assertEqual(new.keys(), old.keys())
        self.assertEqual({name for name in new if new[name] != old[name]}, REPLACEMENTS)
        self.assertEqual(len(new), 265)
        self.assertEqual(len(self.successor["initial_source_files"]), 159)
        self.assertEqual(len(self.successor["generated_fixture_files"]), 125)
        self.assertEqual(len(self.successor["metadata_pins"]), 12)
        generated = self.work / "replayed.packet.json"
        initial = self.packet["INITIAL"]
        pins = self.successor["metadata_pins"]
        self.assertEqual(self.packet["freeze_composed"](
            self.root, generated, self.root / initial, pins[initial], pins, composition=COMPOSITION,
        ), PACKET_SHA)
        self.assertEqual(generated.read_bytes(), self.canonical.read_bytes())
        self.assertEqual(self.preflight(), self.successor)
        self.packet["snapshot"](self.root, self.work / "snapshot", self.successor)

    def test_trusted_bootstrap_constructs_the_registered_source_session(self):
        launcher_path = self.root / ".github/bootstrap/development-launcher.py"
        bootstrap_path = self.root / ".github/bootstrap/development-bootstrap.py"
        launcher = runpy.run_path(str(launcher_path))
        bootstrap = runpy.run_path(str(bootstrap_path))
        self.assertEqual(launcher["MODES"][COMPOSITION], 265)
        self.assertEqual(digest(bootstrap_path.read_bytes()), launcher["BOOTSTRAP_SHA"])
        clock_path = self.root / launcher["CODE_PATHS"]["issuer"]
        self.assertEqual(digest(clock_path.read_bytes()), launcher["ISSUER_SHA"])
        inputs = self.successor["metadata_pins"]
        rows = self.successor["source_files"]
        encoded = bootstrap["encoded"]
        self.assertEqual(digest(encoded(rows)), ROWS_SHA)
        peer = b"INERT SOURCE REGISTRATION TEST; NO PEER OR RUN AUTHORITY\n"
        selection = {
            "source_commit": SOURCE, "source_files": rows, "metadata_pins": inputs,
            "metadata_hex": {name: (self.root / name).read_bytes().hex() for name in inputs},
            "maps": {role: {"path": name, "sha256": inputs[name]}
                     for role, prefix in bootstrap["PREFIXES"].items()
                     for name in (prefix + "/source-map.json",)},
            "callbacks": bootstrap["CALLBACKS"], "peer_receipt_sha256": digest(peer),
        }
        raw = encoded(selection)
        root_pins = {
            "source_commit": SOURCE, "selection_sha256": digest(raw),
            "peer_receipt_sha256": digest(peer), "source_rows_sha256": ROWS_SHA, "cli_sha256": "f" * 64,
        }
        checked, original = bootstrap["selection"](raw, peer, root_pins, time.monotonic() + 15)
        self.assertEqual(checked, selection)
        self.assertEqual(original["source_files"], self.successor["initial_source_files"])

        runner_temp = self.work / "runner-temp"
        runner_temp.mkdir(mode=0o700)
        environment = {
            "GITHUB_SHA": SOURCE, "GITHUB_WORKFLOW_SHA": SOURCE, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKSPACE": str(self.root), "RUNNER_TEMP": str(runner_temp),
        }
        prepare = bootstrap["prepare"]
        # Exercise only source construction with inert endpoint/CLI observations.
        with patch.dict(prepare.__globals__, {"observe_runtime": lambda *_: ("MODEL", (1, 2, 3, 4, 5, 6))}):
            cutoff = time.monotonic() + 30
            prepared = prepare(raw, peer, root_pins, environment, preparation_deadline=cutoff)
            try:
                result = bootstrap["verify_checkout"](prepared, root_pins, environment, deadline=cutoff)
                self.assertEqual(result["selected_rows_verified"], 265)
                self.check_controller(prepared, environment, cutoff, encoded)
            finally:
                prepared["owned"].dispose()
        self.assertEqual(prepared["owned"].cleanup_errors, [])

    def check_controller(self, prepared, environment, cutoff, encoded):
        development = self.root / "scripts/ci/development"
        name = "registered_installer_controller_model"
        controller = types.ModuleType(name)
        controller.__file__ = str(development / "controller.py")
        runtime = Path(prepared["runtime_contract"][0]).read_bytes()
        layout = prepared["paths"]
        with patch.dict(sys.modules, {name: controller}), patch.object(sys, "path", [str(development), *sys.path]):
            exec(compile(Path(controller.__file__).read_bytes(), controller.__file__, "exec"), vars(controller))
            grant = controller.packet.decode(Path(prepared["execution_grant"][0]).read_bytes())
            # The trusted launcher names the CLI __main__. Use a private test
            # alias to exercise the same constructor without entering its CLI.
            self.assertEqual(grant["callbacks"]["existing_consumers"]["module"], "__main__")
            grant["callbacks"]["existing_consumers"]["module"] = name
            raw = encoded(grant)
            with patch.dict(os.environ, environment):
                session, _, _, _ = controller.composed_sources(
                    self.root, self.successor, raw, digest(raw), runtime, layout["output"], layout["cache"],
                    cutoff, composition=COMPOSITION,
                )
            self.assertEqual(session.composition, COMPOSITION)
            self.assertEqual(session.sources.grant["source_files"], self.successor["source_files"])
            self.assertFalse(session.used)
            self.assertFalse(layout["output"].exists())

    def test_issuer_receiver_profile_runtime_and_builder_pins(self):
        bridge = runpy.run_path(str(self.root / BRIDGE))
        receiver = runpy.run_path(str(self.root / RECEIVER))
        rows = self.successor["source_files"]
        self.assertEqual(bridge["ISSUER_SHA"], rows[ISSUER]["sha256"])
        self.assertEqual(bridge["RECEIVER_SHA"], rows[RECEIVER]["sha256"])
        self.assertEqual(bridge["PROFILE_SHA"], digest(receiver["PROFILE_BYTES"]))
        self.assertEqual(receiver["RUNTIME_SHA"], rows[RUNTIME]["sha256"])
        self.assertEqual(receiver["INPUTS_SHA"], self.successor["metadata_pins"][INPUTS])
        self.assertEqual(receiver["BASE_SHA"], rows[INVENTORY]["sha256"])
        frozen = (self.root / INVENTORY).read_bytes()
        self.assertEqual(len(frozen.splitlines()), 341)
        inputs = bridge["strict"]((self.root / INPUTS).read_bytes())
        versions = {row["name"][0]: row["version"][0] for row in inputs["rootfs_packages"]}
        versions.update({row["name"]: row["version"] for row in inputs["packages"]})
        self.assertEqual(frozen, "".join(f"{k} {v}\n" for k, v in sorted(versions.items())).encode())

    def test_stale_issuer_cannot_pass_registered_preflight(self):
        issuer = self.root / ISSUER
        live = issuer.read_bytes()
        issuer.write_bytes(git(self.root, "show", f"{FROZEN}:{ISSUER}"))
        try:
            with self.assertRaisesRegex(self.packet["PacketError"], "packet-source-map-drift"):
                self.preflight()
        finally:
            issuer.write_bytes(live)


if __name__ == "__main__":
    unittest.main()
