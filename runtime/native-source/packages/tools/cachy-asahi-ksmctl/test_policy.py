#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 cachy-asahi contributors
"""Synthetic, source-only KSM dry-run policy checks; no control writes."""
import sys
sys.dont_write_bytecode = True

import copy
import hashlib
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

loader = SourceFileLoader("ksm_policy_fixture", str(Path(__file__).with_name("policy.py")))
policy = module_from_spec(spec_from_loader(loader.name, loader))
loader.exec_module(policy)

GATES = {"target-capabilities", "native-build", "privilege-boundary",
         "merge-eligibility-security", "activation", "concurrent-change-interruption",
         "low-memory-unmerge-recovery", "control-restoration", "measured-benefit"}


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = {"schema_version": 1, "target": "m2-air-13",
                         "kernel_release": "6.18.0-asahi-fixture", "page_size": 16384,
                         "controls": {"run": 0, "pages_to_scan": 100,
                                      "sleep_millisecs": 20}, "advisor_mode": "none"}

    def request(self, action="enable", tuning=None):
        return {"schema_version": 1, "snapshot_sha256": policy.snapshot_digest(self.snapshot),
                "action": action, "tuning": {} if tuning is None else tuning,
                "acknowledge_unmerge": action == "disable"}

    def plan(self, request=None):
        request = self.request() if request is None else request
        before = copy.deepcopy((self.snapshot, request))
        try:
            return policy.plan(self.snapshot, request)
        finally:
            self.assertEqual((self.snapshot, request), before)

    def reject(self, request=None):
        with self.assertRaises(ValueError):
            self.plan(request)

    def test_digest_is_canonical_and_reordering_does_not_change_binding(self):
        expected = hashlib.sha256(json.dumps(self.snapshot, sort_keys=True,
                                            separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(policy.snapshot_digest(self.snapshot), expected)
        reordered = dict(reversed(list(self.snapshot.items())))
        reordered["controls"] = dict(reversed(list(reordered["controls"].items())))
        self.assertEqual(policy.snapshot_digest(reordered), expected)

    def test_enable_orders_knobs_before_run_and_restores_baseline(self):
        data = self.plan(self.request(tuning={"sleep_millisecs": 5, "pages_to_scan": 500}))
        self.assertEqual(data["changes"], [
            {"control": "pages_to_scan", "from": 100, "to": 500},
            {"control": "sleep_millisecs", "from": 20, "to": 5},
            {"control": "run", "from": 0, "to": 1}])
        self.assertEqual(data["restore"], [{"control": "run", "to": 0},
                                         {"control": "pages_to_scan", "to": 100},
                                         {"control": "sleep_millisecs", "to": 20}])

    def test_pause_restores_scanning_only_after_knobs(self):
        self.snapshot["controls"]["run"] = 1
        data = self.plan(self.request("pause", {"pages_to_scan": 200}))
        self.assertEqual(data["changes"], [{"control": "pages_to_scan", "from": 100, "to": 200},
                                         {"control": "run", "from": 1, "to": 0}])
        self.assertEqual(data["restore"], [{"control": "run", "to": 0},
                                         {"control": "pages_to_scan", "to": 100},
                                         {"control": "run", "to": 1}])

    def test_disable_proposes_unmerge_with_acknowledgement(self):
        for baseline in (0, 1):
            with self.subTest(baseline=baseline):
                self.snapshot["controls"]["run"] = baseline
                data = self.plan(self.request("disable"))
                self.assertEqual(data["changes"], [{"control": "run", "from": baseline, "to": 2}])
                expected = [{"control": "run", "to": 0}]
                if baseline:
                    expected.append({"control": "run", "to": 1})
                self.assertEqual(data["restore"], expected)
                self.assertEqual(data["restore_scope"], "control-values-only")

    def test_noop_controls_are_omitted_from_changes(self):
        for baseline, action in ((0, "pause"), (1, "enable")):
            with self.subTest(action=action):
                self.snapshot["controls"]["run"] = baseline
                data = self.plan(self.request(action, {"pages_to_scan": 100, "sleep_millisecs": 20}))
                self.assertEqual(data["changes"], [])
                self.assertEqual(data["restore"][0], {"control": "run", "to": 0})
                self.assertEqual(len(data["restore"]), baseline + 1)

    def test_stale_and_tampered_snapshot_bindings_fail(self):
        request = self.request()
        self.snapshot["controls"]["pages_to_scan"] += 1
        self.reject(request)
        for digest in ("0" * 64, "f" * 63, "g" * 64, "F" * 64, None, 42):
            with self.subTest(digest=digest):
                request = self.request()
                request["snapshot_sha256"] = digest
                self.reject(request)

    def test_snapshot_schema_keys_and_targets_are_strict(self):
        base = copy.deepcopy(self.snapshot)
        for key, value in (("schema_version", True), ("schema_version", 2),
                           ("target", "m1"), ("target", 13),
                           ("kernel_release", ""), ("kernel_release", None),
                           ("kernel_release", "x" * 100000)):
            with self.subTest(key=key, value=str(value)[:30]):
                self.snapshot = copy.deepcopy(base)
                self.snapshot[key] = value
                self.reject()
        for key in base:
            self.snapshot = copy.deepcopy(base)
            del self.snapshot[key]
            self.reject()
        self.snapshot = {**base, "unexpected": 1}
        self.reject()
        self.snapshot = copy.deepcopy(base)
        self.snapshot["target"] = "m2-air-15"
        self.plan()

    def test_page_size_bounds_and_strict_integer_types(self):
        for size in (0, -1, 1048577, True, False, 16384.0, "16384", None):
            with self.subTest(size=size):
                self.snapshot["page_size"] = size
                self.reject()
        for size in (1, 4096, 16384, 1048576):
            self.snapshot["page_size"] = size
            self.plan()

    def test_control_schema_run_and_uint32_bounds(self):
        base = copy.deepcopy(self.snapshot["controls"])
        for value in (2, -1, True, False, 0.0, "0", None):
            self.snapshot["controls"] = {**base, "run": value}
            self.reject()
        for name in ("pages_to_scan", "sleep_millisecs"):
            for value in (-1, 1 << 32, True, False, 1.0, "1", None):
                with self.subTest(name=name, value=value):
                    self.snapshot["controls"] = {**base, name: value}
                    self.reject()
            for value in (0, (1 << 32) - 1):
                self.snapshot["controls"] = {**base, name: value}
                self.plan()
        for name in base:
            self.snapshot["controls"] = {key: value for key, value in base.items() if key != name}
            self.reject()
        self.snapshot["controls"] = {**base, "extra": 0}
        self.reject()

    def test_advisor_policy_respects_explicit_availability(self):
        for mode in ("none", "unavailable"):
            self.snapshot["advisor_mode"] = mode
            self.plan(self.request(tuning={"pages_to_scan": 101}))
        self.snapshot["advisor_mode"] = "scan-time"
        self.reject(self.request(tuning={"pages_to_scan": 101}))
        self.plan(self.request(tuning={"sleep_millisecs": 1}))
        for mode in ("unknown", "", None, 0):
            self.snapshot["advisor_mode"] = mode
            self.reject()

    def test_request_schema_exact_keys_and_actions(self):
        for key, value in (("schema_version", True), ("schema_version", 2),
                           ("action", "unmerge"), ("action", None), ("tuning", [])):
            request = self.request()
            request[key] = value
            self.reject(request)
        for key in self.request():
            request = self.request()
            del request[key]
            self.reject(request)
        self.reject({**self.request(), "execute": True})

    def test_nonobject_snapshot_request_and_controls_are_rejected(self):
        request = self.request()
        controls = copy.deepcopy(self.snapshot["controls"])
        for value in (None, [], 1, "snapshot"):
            self.snapshot["controls"] = copy.deepcopy(controls)
            with self.assertRaises(ValueError):
                policy.plan(value, request)
            with self.assertRaises(ValueError):
                policy.plan(self.snapshot, value)
            self.snapshot["controls"] = value
            self.reject(self.request())

    def test_unmerge_acknowledgement_is_action_specific_and_boolean(self):
        for action in ("enable", "pause", "disable"):
            for ack in (True, False, 0, 1, "true", None):
                with self.subTest(action=action, ack=ack):
                    request = self.request(action)
                    request["acknowledge_unmerge"] = ack
                    if type(ack) is bool and ack == (action == "disable"):
                        self.plan(request)
                    else:
                        self.reject(request)

    def test_tuning_bounds_types_and_unknown_controls(self):
        for name in ("pages_to_scan", "sleep_millisecs"):
            for value in (-1, 1 << 32, True, False, 0.0, "0", None):
                with self.subTest(name=name, value=value):
                    self.reject(self.request(tuning={name: value}))
            for value in (0, (1 << 32) - 1):
                self.plan(self.request(tuning={name: value}))
        for name in ("run", "advisor_mode", "unknown"):
            self.reject(self.request(tuning={name: 1}))

    def test_output_keeps_execution_and_hardware_gates_open(self):
        data = self.plan()
        for key, value in {"status": "validated-dry-run", "mutation": False,
                           "hardware_status": "NOT RUN", "management_available": False,
                           "execution": "NOT IMPLEMENTED",
                           "restore_scope": "control-values-only"}.items():
            self.assertEqual(data[key], value)
            if type(value) is bool:
                self.assertIs(data[key], value)
        self.assertEqual(set(data["gates"]), GATES)
        self.assertEqual(set(data["gates"].values()), {"NOT RUN"})

    def test_deterministic_input_preserving_plan_needs_no_host_access(self):
        request = self.request(tuning={"pages_to_scan": 200})
        with mock.patch("builtins.open", side_effect=AssertionError("host read")), \
             mock.patch.object(Path, "open", side_effect=AssertionError("host path read")), \
             mock.patch.object(subprocess, "run", side_effect=AssertionError("external command")):
            first = self.plan(request)
            second = self.plan(copy.deepcopy(request))
        self.assertEqual(first, second)

    def test_json_loader_rejects_duplicate_keys_nonfinite_and_oversized_input(self):
        with tempfile.TemporaryDirectory(prefix="ksm-policy-json-") as directory:
            path = Path(directory) / "input.json"
            for data in (b'{"run":0,"run":1}', b'{"outer":{"x":0,"x":1}}',
                         b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}',
                         b'{}' + b' ' * 65535, b'{broken', b'\xff'):
                with self.subTest(data=data[:40]):
                    path.write_bytes(data)
                    before = path.read_bytes()
                    with self.assertRaises(ValueError):
                        policy.load(path)
                    self.assertEqual(path.read_bytes(), before)
            path.write_bytes(b'{}' + b' ' * 65534)
            self.assertEqual(policy.load(path), {})

    def test_reader_rejects_symlink_directory_and_fifo_without_mutation(self):
        with tempfile.TemporaryDirectory(prefix="ksm-policy-special-") as directory:
            root = Path(directory)
            (root / "home").mkdir()
            regular = root / "snapshot.json"
            regular.write_text(json.dumps(self.snapshot))
            request = root / "request.json"
            request.write_text(json.dumps(self.request()))
            linked = root / "symlink.json"
            linked.symlink_to(regular)
            folder = root / "directory.json"
            folder.mkdir()
            fifo = root / "fifo.json"
            os.mkfifo(fifo)

            def inputs():
                result = {}
                for path in root.rglob("*"):
                    info = path.lstat()
                    data = (os.readlink(path) if stat.S_ISLNK(info.st_mode)
                            else path.read_bytes() if stat.S_ISREG(info.st_mode) else None)
                    result[str(path.relative_to(root))] = (info.st_mode, info.st_mtime_ns, data)
                return result

            before = inputs()
            for path, expected in ((regular, 0), (linked, 1), (folder, 1), (fifo, 1)):
                with self.subTest(kind=path.name):
                    result = subprocess.run(
                        [sys.executable, "-B", str(Path(__file__).with_name("policy.py")),
                         str(path), str(request)], capture_output=True, text=True, timeout=2,
                        env={**os.environ, "HOME": str(root / "home"),
                             "PYTHONDONTWRITEBYTECODE": "1"})
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    data = json.loads(result.stderr if expected else result.stdout)
                    self.assertIs(data["mutation"], False)
                    self.assertEqual(data["status"], "rejected" if expected else "validated-dry-run")
                    self.assertEqual(inputs(), before)
                    self.assertFalse(list(root.rglob("__pycache__")))


if __name__ == "__main__":
    unittest.main()
