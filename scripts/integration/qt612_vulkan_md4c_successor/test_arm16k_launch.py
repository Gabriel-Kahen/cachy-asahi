#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise the one-use launch and log bounds with an inert container model."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
from runpy import run_path
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
START = run_path(str(HERE / "arm16k.py"))["start"]
LAUNCHER = START.__globals__
CAPTURE = LAUNCHER["capture_process"]
CID = "c" * 64
NONCE = "a" * 32
NAME = "caa-qtbase-successor16k-" + NONCE


class Model:
    def __init__(self, capsule):
        self.capsule = capsule
        self.calls = []
        self.create = "normal"
        self.attach = "normal"
        self.foreign = False
        self.status = None
        self.visibility_delay = 0
        self.lose_remove_reply = False
        self.entry = None
        self.mounts = []

    def call(self, *args):
        self.calls.append(args)
        operation = args[1]
        body = b""
        if operation == "create":
            self.entry = list(args[-4:])
            for index, arg in enumerate(args):
                if arg == "--mount":
                    _, source, target, *mode = args[index + 1].split(",")
                    self.mounts.append(dict(Source=source.removeprefix("source="), Destination=target.removeprefix("target="),
                                            RW=not mode, Type="bind", Propagation="rprivate"))
            if self.create in ("normal", "lost_with_cid", "interrupt"):
                Path(args[args.index("--cidfile") + 1]).write_text(CID)
            self.status = None if self.create == "lost_without_actor" else "created"
            if self.create == "interrupt":
                os.kill(os.getpid(), signal.SIGTERM)
            elif self.create != "normal":
                raise subprocess.TimeoutExpired("model-create", 30)
            body = (CID + "\n").encode()
        elif operation == "ls":
            if self.status is not None and self.visibility_delay == 0:
                body = (CID + "\n").encode()
            elif self.visibility_delay:
                self.visibility_delay -= 1
        elif operation == "inspect":
            nonce = "b" * 32 if self.foreign else NONCE
            host = dict(NetworkMode="none", ReadonlyRootfs=True, Privileged=False, CapDrop=["ALL"],
                        PidsLimit=256, Memory=8 << 30, MemorySwap=8 << 30, NanoCpus=4 * 10**9,
                        CgroupnsMode="private", SecurityOpt=["no-new-privileges"])
            row = dict(Id=CID, Name="/" + NAME, Image=LAUNCHER["IMAGE"], Path="/usr/bin/python3",
                       Args=self.entry, Config={"Labels": {LAUNCHER["ROLE_LABEL"]: nonce}},
                       HostConfig=host, Mounts=self.mounts,
                       State=dict(Status=self.status, Running=self.status == "running",
                                  ExitCode=0, OOMKilled=False, Error=""))
            body = json.dumps([row]).encode()
        elif operation == "stop":
            self.status = "exited"
        elif operation == "rm":
            self.status = None
            if self.lose_remove_reply:
                raise subprocess.TimeoutExpired("model-rm", 30)
            body = (CID + "\n").encode()
        else:
            raise AssertionError(args)
        return SimpleNamespace(stdout=body)

    def argv(self, *args):
        self.calls.append(args)
        if args != ("container", "start", "-a", CID):
            raise AssertionError(args)
        if self.attach == "timeout":
            self.status = "running"
            command = r"import os, time; os.write(1, b'attach\n'); time.sleep(60)"
        elif self.attach == "overflow":
            self.status = "running"
            command = f"import os; os.write(1, b'x' * {LAUNCHER['ATTACH_LOG_BYTES'] + 1})"
        elif self.attach == "refuse":
            command = "import sys; print('attach refused', file=sys.stderr); sys.exit(1)"
        else:
            self.status = "exited"
            (self.capsule / "run/actor.json").write_text('{"qemu_exit":0,"process_reaped":true}')
            command = "print('attach')"
        return [sys.executable, "-I", "-B", "-c", command]


class LaunchTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.model = Model(self.root)
        media = self.root / "media"
        media.mkdir()
        for name in ("Image", "boot.raw", "result.template", "actor.py"):
            content = (HERE / "arm16k_actor.py").read_bytes() if name == "actor.py" else name.encode()
            (media / name).write_bytes(content)
        self.backing = self.root / "backing"
        self.backing.write_bytes(b"original backing")
        self.backing.chmod(0o444)
        pin = LAUNCHER["pin"]
        self.backing_pin = pin(self.backing)
        manifest = "0" * 64
        mode = "full"
        budget = LAUNCHER["limits"](mode)
        plan = dict(kind="QTBASE_SUCCESSOR16K_PLAN_V1", base_revision=LAUNCHER["BASE"], mode=mode, limits=budget,
                    launcher=pin(HERE / "arm16k.py"), actor=pin(media / "actor.py"), runner_image=LAUNCHER["IMAGE"],
                    tools=LAUNCHER["TOOLS"], nonce=NONCE, result_uuid=LAUNCHER["C"]["result_uuid"](NONCE),
                    qemu_argv=LAUNCHER["qemu_args"](NONCE, manifest, mode, budget),
                    payload={"manifest.sha256": {"sha256": manifest}},
                    media={name: pin(media / name) for name in ("boot.raw", "Image")},
                    result_template=pin(media / "result.template"),
                    inputs={"originals": {"backing": {"path": str(self.backing), **self.backing_pin}}},
                    docker={})
        raw = LAUNCHER["wire"](plan)
        (self.root / "plan.json").write_bytes(raw)
        self.args = SimpleNamespace(capsule=self.root, plan_sha256=hashlib.sha256(raw).hexdigest())
        self.enterContext(patch.dict(LAUNCHER, dict(capacity=lambda *_: {}, Docker=lambda _: self.model)))
        self.enterContext(patch.dict(LAUNCHER["C"], clone=lambda source, target: target.write_bytes(source.read_bytes())))
        self.enterContext(patch.object(LAUNCHER["time"], "sleep", lambda _: None))
        self.stdout = self.enterContext(redirect_stdout(io.StringIO()))
        self.stderr = self.enterContext(redirect_stderr(io.StringIO()))

    def receipt(self, name="launch.json"):
        raw = (self.root / name).read_bytes()
        report = json.loads(raw)
        response = json.loads(self.stdout.getvalue())
        key = "launch_sha256" if name == "launch.json" else "hold_sha256"
        self.assertEqual(response[key], hashlib.sha256(raw).hexdigest())
        self.assertEqual(LAUNCHER["pin"](self.backing), self.backing_pin)
        self.assertTrue(report["originals_unchanged"])
        return report

    def assert_retired(self, report):
        self.assertEqual(report["cid"], CID)
        self.assertEqual(report["retirement"], "RETIRED")
        self.assertEqual(report["container_absent"], [True, True])
        self.assertEqual(self.model.calls[-3][1:3], ("rm", CID))
        self.assertTrue(all(("id=" + CID) in call for call in self.model.calls[-2:]))

    def test_success_preserves_one_use_and_readonly_mounts(self):
        self.assertEqual(START(self.args), 0)
        report = self.receipt()
        self.assert_retired(report)
        started_path = self.root / "launch.started.json"
        started = json.loads(started_path.read_bytes())
        self.assertEqual((started["cid"], started["started"]), (report["cid"], report["started"]))
        self.assertEqual(started_path.stat().st_nlink, 1)
        self.assertEqual(report["attach_log"]["bytes"], len(b"attach\n"))
        self.assertEqual([row["Destination"] for row in self.model.mounts if row["RW"]], ["/out"])
        self.assertNotIn("container.log", report["files"])
        with self.assertRaises(FileExistsError):
            START(self.args)
        self.assertEqual(sum(call[1] == "create" for call in self.model.calls), 1)

    def test_lost_create_recovers_by_exact_nonce_and_name(self):
        self.model.create = "lost_without_cid"
        self.model.visibility_delay = 1
        self.assertEqual(START(self.args), 2)
        self.assert_retired(self.receipt())
        self.assertTrue(any(("name=^/" + NAME + "$") in call and
                            ("label=" + LAUNCHER["ROLE_LABEL"] + "=" + NONCE) in call for call in self.model.calls))
        self.assertFalse(any(call[1] == "start" for call in self.model.calls))

    def test_lost_create_with_cid_recovers_when_nonce_listing_lags(self):
        self.model.create = "lost_with_cid"
        self.model.visibility_delay = 4
        self.assertEqual(START(self.args), 2)
        self.assert_retired(self.receipt())

    def test_lost_create_without_identity_keeps_retirement_unverified(self):
        self.model.create = "lost_without_actor"
        self.assertEqual(START(self.args), 2)
        report = self.receipt()
        self.assertIsNone(report["cid"])
        self.assertEqual(report["retirement"], "UNVERIFIED")
        self.assertEqual(report["container_absent"], [])
        self.assertIn("No owned CID found", report["error"])

    def test_foreign_candidate_is_never_stopped_or_removed(self):
        self.model.create = "lost_without_cid"
        self.model.foreign = True
        self.assertEqual(START(self.args), 2)
        report = self.receipt()
        self.assertEqual(report["retirement"], "UNVERIFIED")
        self.assertEqual(report["container_absent"], [])
        self.assertIn("identity differs", report["error"])
        self.assertFalse(any(call[1] in {"stop", "rm", "start"} for call in self.model.calls))

    def test_started_receipt_failure_retires_and_records_terminal(self):
        (self.root / "launch.started.json").write_bytes(b"existing")
        self.assertEqual(START(self.args), 2)
        report = self.receipt()
        self.assert_retired(report)
        self.assertIn("File exists", report["error"])
        self.assertEqual((self.root / "launch.started.json").read_bytes(), b"existing")
        self.assertFalse(any(call[1] == "start" for call in self.model.calls))

    def test_signal_during_create_retires_without_attaching(self):
        self.model.create = "interrupt"
        self.assertEqual(START(self.args), 2)
        report = self.receipt()
        self.assert_retired(report)
        self.assertIn("Received signal", report["error"])
        self.assertFalse(any(call[1] == "start" for call in self.model.calls))

    def test_create_not_dispatched_when_clone_refuses(self):
        def failed_clone(*_args):
            raise OSError("copy refused")

        with patch.dict(LAUNCHER["C"], clone=failed_clone):
            self.assertEqual(START(self.args), 2)
        report = self.receipt()
        self.assertEqual(report["retirement"], "NOT_DISPATCHED")
        self.assertIn("copy refused", report["error"])
        self.assertEqual(self.model.calls, [])

    def test_lost_remove_reply_is_rechecked_for_absence(self):
        self.model.lose_remove_reply = True
        self.assertEqual(START(self.args), 0)
        report = self.receipt()
        self.assertEqual(report["container_absent"], [True, True])
        self.assertEqual(report["retirement"], "RETIRED")
        self.assertEqual(sum(call[1] == "rm" for call in self.model.calls), 1)

    def test_terminal_receipt_failure_keeps_a_hold_receipt(self):
        (self.root / "launch.json").write_bytes(b"existing")
        self.assertEqual(START(self.args), 2)
        report = self.receipt("launch.hold.json")
        self.assert_retired(report)
        self.assertIn("Terminal receipt", report["error"])
        self.assertEqual((self.root / "launch.json").read_bytes(), b"existing")

    def test_both_receipt_writes_fail_after_retirement(self):
        for name in ("launch.json", "launch.hold.json"):
            (self.root / name).write_bytes(b"existing")
        self.assertEqual(START(self.args), 2)
        fallback = json.loads(self.stderr.getvalue())
        self.assert_retired(fallback["launch"])
        self.assertIn("File exists", fallback["receipt_error"])
        self.assertFalse(self.stdout.getvalue())

    def test_attach_refusal_retires_the_created_actor(self):
        self.model.attach = "refuse"
        self.assertEqual(START(self.args), 2)
        report = self.receipt()
        self.assert_retired(report)
        self.assertIn("Actor did not exit", report["error"])
        self.assertEqual((self.root / "container.log").read_bytes(), b"attach refused\n")

    def test_attach_timeout_stops_the_actor_and_keeps_partial_log(self):
        self.model.attach = "timeout"

        def short_capture(argv, path, size, _timeout, observe, **kwargs):
            return CAPTURE(argv, path, size, 0.5, observe, **kwargs)

        with patch.dict(LAUNCHER, capture_process=short_capture):
            self.assertEqual(START(self.args), 2)
        report = self.receipt()
        self.assert_retired(report)
        self.assertIn(("container", "stop", "--time=20", CID), self.model.calls)
        self.assertIn("container.log deadline expired", report["error"])
        self.assertEqual((self.root / "container.log").read_bytes(), b"attach\n")

    def test_attach_overrun_retires_and_writes_only_the_cap(self):
        self.model.attach = "overflow"
        self.assertEqual(START(self.args), 2)
        report = self.receipt()
        self.assert_retired(report)
        self.assertIn("container.log exceeded its byte ceiling", report["error"])
        self.assertEqual(report["attach_log"]["bytes"], LAUNCHER["ATTACH_LOG_BYTES"])


class CaptureTests(unittest.TestCase):
    def setUp(self):
        root = self.enterContext(TemporaryDirectory())
        self.serial = Path(root) / "serial.log"

    def command(self, source):
        return [sys.executable, "-I", "-B", "-c", source]

    def test_tail_is_drained_after_the_writer_exits(self):
        popen = subprocess.Popen

        def exited_process(*args, **kwargs):
            process = popen(*args, **kwargs)
            process.wait(timeout=5)
            return process

        with patch.object(subprocess, "Popen", side_effect=exited_process):
            code, reason = CAPTURE(self.command("print('12345678')"), self.serial, 8, 5, lambda: None)
        self.assertEqual(code, 0)
        self.assertIn("serial.log exceeded its byte ceiling", reason)
        self.assertEqual(self.serial.read_bytes(), b"12345678")

    def test_timeout_reaps_the_writer_and_preserves_its_output(self):
        cmd = self.command("import os, time; os.write(1, b'progress'); time.sleep(60)")
        code, reason = CAPTURE(cmd, self.serial, 8, 0.5, lambda: None)
        self.assertEqual(code, -signal.SIGTERM)
        self.assertEqual(reason, "serial.log deadline expired")
        self.assertEqual(self.serial.read_bytes(), b"progress")

    def test_output_is_visible_before_the_writer_exits(self):
        source = ("import os, sys, time\n"
                  "from pathlib import Path\n"
                  "os.write(1, b'first')\n"
                  "while Path(sys.argv[1]).read_bytes() != b'first': time.sleep(0.01)\n"
                  "os.write(2, b'last')\n")
        code, reason = CAPTURE([*self.command(source), self.serial], self.serial, 9, 5, lambda: None)
        self.assertEqual((code, reason), (0, None))
        self.assertEqual(self.serial.read_bytes(), b"firstlast")


if __name__ == "__main__":
    unittest.main()
