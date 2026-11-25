#!/usr/bin/env python3
"""Software-only controls for the retained receiver's signal custody."""
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import retained_native248 as receiver


def fixture(run_mode, runner_temp):
    exact = subprocess.check_output(["git", "show", f"{receiver.TRANSPORT_SOURCE}:{receiver.SUPERVISOR[0]}"])
    receiver.require((len(exact), receiver.sha(exact)) == receiver.SUPERVISOR[1:], "fixture-supervisor-pin")
    owner = receiver.module(exact, "pinned-owned-process.py", "native248_fixture_owner")
    prior = {number: signal.getsignal(number) for number in (signal.SIGINT, signal.SIGTERM)}
    staged = Path(runner_temp) / "maintained-desktop-v2-native248-17-1"
    probe, receipt = {}, {}
    environment = {"GITHUB_RUN_ID": "17", "GITHUB_RUN_ATTEMPT": "1", "RUNNER_TEMP": runner_temp}
    transport = SimpleNamespace(
        op=owner,
        reference_policy=lambda: {"outer_seconds": 1},
        deliver=lambda **_: {"status": "PASS_EXACT_RETAINED_GIT_DATA_ONLY", "tree": receiver.TREE,
                            "blob_joins": 1154},
    )
    if run_mode == "unknown":
        owner.supervise = lambda *_: {
            "reaped": False, "ownership": "UNKNOWN", "group_census": "UNKNOWN", "passed": False,
        }

    def verify_ref(*_):
        if run_mode == "unknown":
            probe.update(owner.supervise(None))
            receiver.require(probe["passed"], "fixture-child-refused")
        if run_mode != "interrupt":
            return
        owner.prepare()
        child = subprocess.Popen([sys.executable, "-I", "-B", "-c", "import time; time.sleep(6)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        print("READY", flush=True)
        result = owner.supervise(child, cap=5, retirement=1, grace=0.2,
                                 streams=(child.stdout,), max_output=4096)
        probe.update({key: result[key] for key in ("reaped", "ownership", "group_census", "passed")})
        receiver.require(result["passed"], "fixture-child-refused")

    entered = False
    refused = None
    with patch.multiple(receiver, package_pins=lambda _: {}, carrier_profile=lambda _: b"",
                        verify_git=lambda *_: None, load_transport=lambda *_: transport,
                        verify_ref=verify_ref, project=lambda *_: None):
        try:
            with receiver.stage(environment, "", b"", lambda *_: b"", time.monotonic() + 9,
                                receipt=receipt) as controls:
                assert [p.name for p in staged.iterdir()] == ["packages"]
                assert all(signal.getsignal(number) == controls.remember for number in prior)
                if run_mode == "handoff":
                    workflow = Path(receiver.__file__).resolve().parents[3] / (
                        ".github/workflows/maintained-composed-virtual-desktop-v2-retained.yml")
                    text = workflow.read_text().split("python3 -I -B - <<'PYTHON'\n", 1)[1]
                    inline = textwrap.dedent(text.split("\n          PYTHON\n", 1)[0]).encode()
                    driver = receiver.module(inline, workflow, "native248_fixture_workflow")

                    def waiting_fetch(commit, deadline, check):
                        print("READY", flush=True)
                        while time.monotonic() < deadline:
                            check()
                            time.sleep(0.01)
                        raise AssertionError("fixture signal absent")

                    driver.registered_plan = lambda _: {"code_commit": driver.CODE_COMMIT}
                    driver.fetch_launcher = waiting_fetch
                    driver.invoke({}, entry=time.monotonic(), check=controls.check)
                    raise AssertionError("launcher delivery should have refused")
                trusted = subprocess.check_output(["git", "show",
                    "b489e54b5c526525cc083fba0bdcf89962951d00:.github/bootstrap/development-launcher.py"])
                assert receiver.sha(trusted) == "c592842869d15bbae7833df7671b934cd62207df6ddf17dff640b3d72ca1a5be"
                launcher = receiver.module(trusted, "pinned-development-launcher.py", "native248_fixture_launcher")
                with launcher.controls(time.monotonic() + 2):
                    entered = True
                    assert all(signal.getsignal(number).__qualname__ == "controls.<locals>.interrupt"
                               for number in prior)
                assert all(signal.getsignal(number) == controls.remember for number in prior)
        except (ValueError, InterruptedError) as error:
            refused = str(error)
    print(json.dumps({
        "cleanup": receipt, "entered": entered, "refused": refused, "child": probe,
        "absent": not os.path.lexists(staged),
        "handlers_restored": {number: signal.getsignal(number) for number in prior} == prior,
    }), flush=True)


class StageSignalTests(unittest.TestCase):
    def worker(self, run_mode, signum=None):
        with tempfile.TemporaryDirectory() as temporary, subprocess.Popen(
            [sys.executable, "-B", __file__, "--fixture", run_mode, temporary],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        ) as child:
            if signum is not None:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    self.assertTrue(selector.select(5), "pre-launch child was not ready")
                    self.assertEqual(child.stdout.readline(), b"READY\n")
                child.send_signal(signum)
            output, errors = child.communicate(timeout=8)
            self.assertEqual(child.returncode, 0, errors.decode())
            return json.loads(output)

    def test_prelaunch_controls_reap_the_owned_child_and_retire_the_stage(self):
        for signum in (signal.SIGTERM, signal.SIGINT):
            with self.subTest(signal=signum):
                result = self.worker("interrupt", signum)
                self.assertEqual(result["cleanup"], {"cleanup": "PASS", "signal": signum.name})
                self.assertEqual(result["child"], {
                    "reaped": True, "ownership": "REAPED", "group_census": "EMPTY_TWICE", "passed": False,
                })
                self.assertFalse(result["entered"])
                self.assertEqual(result["refused"], "fixture-child-refused")
                self.assertTrue(result["absent"])
                self.assertTrue(result["handlers_restored"])

    def test_launcher_delivery_refuses_a_signal_after_the_carrier_was_staged(self):
        result = self.worker("handoff", signal.SIGTERM)
        self.assertFalse(result["entered"])
        self.assertEqual(result["refused"], "native248-stage-interrupted")
        self.assertEqual(result["cleanup"], {"cleanup": "PASS", "signal": "SIGTERM"})
        self.assertTrue(result["absent"])
        self.assertTrue(result["handlers_restored"])

    def test_pinned_launcher_controls_overrides_the_bridge_and_cleanup_is_verified(self):
        result = self.worker("normal")
        self.assertTrue(result["entered"])
        self.assertIsNone(result["refused"])
        self.assertEqual(result["cleanup"], {"cleanup": "PASS"})
        self.assertTrue(result["absent"])
        self.assertTrue(result["handlers_restored"])

    def test_unknown_child_retirement_keeps_the_stage_and_withholds_pass(self):
        result = self.worker("unknown")
        self.assertFalse(result["entered"])
        self.assertEqual(result["child"]["ownership"], "UNKNOWN")
        self.assertEqual(result["cleanup"], {"cleanup": "UNCERTAIN"})
        self.assertFalse(result["absent"])
        self.assertTrue(result["handlers_restored"])


if __name__ == "__main__":
    if sys.argv[1:2] == ["--fixture"]:
        fixture(*sys.argv[2:])
    else:
        unittest.main()
