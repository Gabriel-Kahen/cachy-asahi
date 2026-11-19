# SPDX-License-Identifier: MIT
"""Offline controls. No process, lock, socket or native entry is permitted."""

from contextlib import nullcontext, redirect_stderr
from email.message import Message
from io import BytesIO, StringIO
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import entry as E

C = E.C
STATELESS_FIXTURE = "ghs_12345_" + "a"*170 + "." + "b"*170 + "." + "c"*170
REPO = HERE.parents[2]
R128 = os.environ.get("QT612_TEST_R128_SOURCE")
AUTHORITY = os.environ.get("QT612_TEST_MD4C_AUTHORITY")
RUNTIME = os.environ.get("QT612_TEST_RUNTIME_SOURCE")
RUNTIME_SHA = os.environ.get("QT612_TEST_RUNTIME_MAP_SHA256")


def fence(event, _):
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.posix_spawn", "fcntl.flock", "os.fork")):
        raise AssertionError("offline control attempted "+event)


sys.addaudithook(fence)


def fixture():
    repo = C.REPO
    actor = repo.split("/")[0]
    live = "refs/heads/codex/model-qt-pair"
    sha = "a"*40
    env = dict(GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REPOSITORY=repo,
               GITHUB_ACTOR=actor, GITHUB_TRIGGERING_ACTOR=actor, GITHUB_REF=live, GITHUB_SHA=sha,
               GITHUB_WORKFLOW_SHA=sha, GITHUB_RUN_ATTEMPT="1", GITHUB_JOB="pair", GITHUB_RUN_ID="12",
               GITHUB_WORKFLOW_REF=repo+"/"+C.WORKFLOW+"@"+live, RUNNER_OS="Linux", RUNNER_ARCH="ARM64")
    refs = {name: dict(path=f"inputs/{name}.json", **C.pin(name.encode())) for name in C.INPUTS}
    refs["md4c_signature"].update(C.SIGNATURE)
    refs["md4c_certificate"].update(C.CERTIFICATE)
    refs["md4c_authority"].update(C.MD4C_AUTHORITY)
    approval = dict(kind=C.KIND, issuer="Root", approved=True, mode="pair-only", repository=repo, live_ref=live,
               workflow_sha=sha, issued_utc=1000, expires_utc=22600, inputs=refs,
               runtime_source=dict(ref="refs/heads/codex/model-runtime", commit="b"*40, tree="c"*40,
               map=dict(path="source-map.json", **C.pin(b"map")), entry=dict(path=C.ENTRY, **C.pin(b"entry"))))
    return approval, env


class AdapterTest(unittest.TestCase):
    def test_approval_and_job_identity(self):
        approval, env = fixture()
        raw = C.encoded(approval)
        key = C.pin(raw)["sha256"]
        self.assertEqual(C.approval(raw, key, env, 1001), approval)
        for override in (dict(GITHUB_ACTOR="guest"), dict(GITHUB_RUN_ATTEMPT="2"), dict(GITHUB_JOB="backend"),
                         dict(GITHUB_WORKFLOW_SHA="f"*40), dict(RUNNER_ARCH="X64")):
            with self.assertRaisesRegex(ValueError, "ACTUAL_OWNED_WORKFLOW"):
                C.approval(raw, key, env | override, 1001)
        with self.assertRaisesRegex(ValueError, "WHOLE_ROOT_APPROVAL"):
            C.approval(raw, "0"*64, env, 1001)
        row = dict(id=42, run_id=12, run_attempt=1, head_sha=env["GITHUB_SHA"], name="pair",
                   status="in_progress", labels=["ubuntu-24.04-arm"])
        self.assertEqual(C.job_id(C.encoded(dict(total_count=1, jobs=[row])), env), "42")
        with self.assertRaisesRegex(ValueError, "ACTUAL_GUI_SERVER_JOB_METADATA"):
            C.job_id(C.encoded(dict(total_count=1, jobs=[row | dict(run_id=13)])), env)

    def test_whole_runtime_and_closed_namespace(self):
        approval, _ = fixture()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)/"source"
            sealed = Path(tmp)/"sealed"
            source.mkdir()
            sealed.mkdir()
            inputs = approval["inputs"]
            body = {entry["path"]:role.encode() for role, entry in inputs.items()}
            body[C.ENTRY] = b"entry"
            for role in ("md4c_signature", "md4c_certificate", "md4c_authority"):
                inputs[role].update(C.pin(body[inputs[role]["path"]]))
            for name, raw in body.items():
                path = source/name
                path.parent.mkdir(parents=True, exist_ok=True)
                C.write(path, raw, 0o644)
            entries = {key:dict(mode=0o644, **C.pin(val)) for key, val in body.items()}
            raw = C.encoded(dict(kind=C.MAP_KIND, schema=1, files=entries))
            C.write(source/"source-map.json", raw, 0o644)
            approval["runtime_source"]["map"].update(C.pin(raw))
            self.assertEqual(C.entries(source, approval, destination=sealed), entries)
            self.assertEqual(C.entries(sealed, approval), entries)
            C.write(source/"unselected.py", b"x", 0o644)
            with self.assertRaisesRegex(ValueError, "COMPLETE_RUNTIME_NAMESPACE"):
                C.entries(source, approval)

    def test_physical_deadlines_and_late_census(self):
        self.assertEqual(E.duration("5h 50min 30s"), 21030)
        self.assertEqual(C.deadlines(100, 105, 1000, 22600),
                         dict(transfer=340, bootstrap=3040, work=21040, cleanup=21130))
        for fail in ((100, 340, 1000, 22600), (100, 105, 1000, 22000)):
            with self.assertRaisesRegex(ValueError, "COMPLETE_SCOPE"):
                C.deadlines(*fail)
        natural = dict(empty_twice=True, pidfd_exited=True, result="success")
        closure = dict(services=dict(owner=natural, daemon=natural), owned_storage_absent=True,
                       errors=[], host_package_mutations=0)
        self.assertTrue(E.cleanup_passes(closure))
        self.assertFalse(E.cleanup_passes(closure | dict(owned_storage_absent=False)))
        self.assertFalse(E.cleanup_passes(closure | dict(services=dict(owner=natural))))

    def test_stage_helpers_uses_private_modes_and_restores_controller_umask(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            body = b"fixture staging reader"
            reader = source/E.RUNTIME_READER
            reader.parent.mkdir(parents=True)
            C.write(reader, body)
            staged = source/"helpers"

            def stage_helpers(**args):
                args["output"].mkdir(mode=0o700)
                nested = args["output"]/"scripts/ci/helper"
                nested.mkdir(mode=0o700, parents=True)
                for directory in (nested, nested.parent, nested.parent.parent):
                    self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                raise ValueError("fixture stage stop")

            previous_umask = os.umask(0o022)
            try:
                with patch.object(E, "RUNTIME_READER_SHA", C.pin(body)["sha256"]), \
                     patch.object(E, "load", return_value=SimpleNamespace(stage_helpers=stage_helpers)), \
                     self.assertRaisesRegex(ValueError, "fixture stage stop"):
                    E.stage_runtime_helpers(source, {"sha256": "a"*64}, REPO, staged)
            finally:
                observed_umask = os.umask(previous_umask)
            self.assertEqual(observed_umask, 0o022)

    def test_owned_storage_checks_absence_before_inherited_exclusive_open(self):
        sys.path.insert(0, str(REPO/C.HOSTED))
        launch = E.load(REPO/C.HOSTED/"launch.py", "qt612_storage_bridge_control")
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            image = output/"storage.img"
            stages = []
            policy = dict(minimum_disk_bytes=launch.capacity.MINIMUM_BYTES,
                          storage_bytes=launch.capacity.STORAGE_BYTES,
                          host_reserve_bytes=launch.capacity.RESERVE_BYTES,
                          minimum_available_bytes=10*launch.capacity.GIB)
            original_lstat = Path.lstat
            observation = dict(path=str(output), device=output.stat().st_dev, inode=output.stat().st_ino,
                               mount=42, readonly=False, free_bytes=policy["minimum_disk_bytes"])

            def root_file(path):
                row = original_lstat(path)
                if path != image:
                    return row
                fields = ("st_mode", "st_dev", "st_ino", "st_nlink", "st_size", "st_blocks")
                return SimpleNamespace(st_uid=0, **{name:getattr(row,name) for name in fields})

            def allocate(argv, *_):
                self.assertEqual(argv, ["/usr/bin/fallocate", "--length", str(policy["storage_bytes"]), "--", str(image)])
                self.assertEqual(stat.S_IMODE(image.stat().st_mode), 0o600)
                raise ValueError("fixture allocation stop")

            def inherited_setup():
                fd = os.open(image, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
                controller.run(["/usr/bin/fallocate", "--length", str(policy["storage_bytes"]), "--", str(image)], 60)

            controller = SimpleNamespace(out=output, policy=policy, run=allocate, setup=inherited_setup,
                                         tool=lambda name:"/usr/bin/"+name)
            args = dict(selection_sha256="a"*64, logical_bytes=1, stage=stages.append)
            with patch.object(launch.os, "getuid", return_value=0), patch.object(launch.os, "geteuid", return_value=0), \
                 patch.object(launch.capacity, "observe", return_value=observation), patch.object(Path, "lstat", root_file):
                with self.assertRaisesRegex(ValueError, "fixture allocation stop"):
                    launch.reserve_and_bind(controller, None, None, **args)
                self.assertEqual(stages, ["STORAGE_FRESHNESS", "OWNED_HOST_SETUP",
                                          "STORAGE_ALLOCATION_ADMISSION", "STORAGE_ALLOCATION"])
                self.assertIs(controller.run, allocate)
                with self.assertRaisesRegex(ValueError, "reservation must be fresh"):
                    launch.reserve_and_bind(controller, None, None, **args)
                self.assertEqual(stages[-1], "STORAGE_FRESHNESS")

    def test_controller_diagnostic_emits_only_finite_stage(self):
        def fail(_args, trace):
            trace.mark("STORAGE_ALLOCATION_ADMISSION")
            raise ValueError("private token and directory /tmp/credential")

        args = [item for name in ("workflow-root","runtime-source","r128-source","approval","output")
                for item in ("--"+name, "/fixture")]
        args += ["--approval-sha256", "a"*64, "--runner-uid", "1001", "--runner-gid", "1001"]
        stderr = StringIO()
        with patch.object(E, "root_dispatch", side_effect=fail), redirect_stderr(stderr):
            self.assertEqual(E.main(args), 2)
        self.assertEqual(stderr.getvalue(), "HOLD_QT612_PAIR: STORAGE_ALLOCATION_ADMISSION\n")

    def test_r128_transport_tracks_stage_and_keeps_credentials_on_api_origin(self):
        token = STATELESS_FIXTURE
        url = "https://fixture.blob.core.windows.net/log?sealed=opaque"
        headers = Message()
        headers["Location"] = url
        redirect = E.urllib.error.HTTPError(E.LOG_URL, 302, "opaque", headers, BytesIO())
        body = BytesIO(b"fixture body")
        body.status, body.headers = 200, Message()
        seen, stages = [], []

        def open_url(request, timeout):
            self.assertEqual(timeout, 8)
            seen.append((request.full_url, request.get_header("Authorization")))
            if request.full_url == E.LOG_URL:
                raise redirect
            return body

        with patch.object(E.urllib.request, "build_opener", return_value=SimpleNamespace(open=open_url)):
            self.assertEqual(E.fetch(E.LOG_URL, 20, token=token, mark=stages.append), b"fixture body")
        self.assertEqual(seen, [(E.LOG_URL, "Bearer "+token), (url, None)])
        self.assertEqual(stages, ["R128_LOG_API", "R128_LOG_REDIRECT", "R128_LOG_BODY"])

        def deny(request, timeout):
            raise E.urllib.error.HTTPError(request.full_url, 403, "private text /path", Message(), BytesIO())

        trace = E.ControllerTrace()
        with patch.object(E.urllib.request, "build_opener", return_value=SimpleNamespace(open=deny)):
            with self.assertRaises(E.HTTPReadRefused) as held:
                E.fetch(E.LOG_URL, 20, token=token, mark=trace.mark)
        trace.acquisition_detail = held.exception.reason
        stderr = StringIO()
        with redirect_stderr(stderr):
            trace.hold()
        self.assertEqual(stderr.getvalue(), "HOLD_QT612_PAIR: R128_LOG_API\nHOLD_QT612_ACQUISITION: HTTP_403\n")

    def test_r128_refuses_missing_unsafe_or_wrong_route_credentials(self):
        trace = E.ControllerTrace()
        trace.mark("R128_LOG_TOKEN")
        with patch.object(E.urllib.request, "build_opener", side_effect=AssertionError("unexpected HTTP")):
            for token in ("", "fixture with space", "fixture\tvalue", "fixture\r\nX: value", "fixtureé"):
                with self.subTest(token=repr(token)), self.assertRaisesRegex(ValueError, "EXACT_R128_READ_CUSTODY"):
                    E.fetch(E.LOG_URL, 20, token=token, mark=trace.mark)
            with self.assertRaisesRegex(ValueError, "EXACT_R128_READ_CUSTODY"):
                E.fetch(E.LOG_URL+"/wrong", 20, token=STATELESS_FIXTURE, mark=trace.mark)
        self.assertIs(trace.stage, E.Stage.R128_LOG_TOKEN)

    def test_root_scrubs_token_before_work_and_transfer_uses_it_once(self):
        trace = E.ControllerTrace()

        def stop_before_work(*_):
            self.assertNotIn(E.TOKEN, os.environ)
            raise ValueError("stop before work")

        with patch.dict(os.environ, {E.TOKEN: STATELESS_FIXTURE}, clear=True), patch.object(C, "need", stop_before_work):
            with self.assertRaisesRegex(ValueError, "stop before work"):
                E.root_dispatch(None, trace)

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            packet = root/"input-fixture"
            packet.mkdir()
            for attempt in ("first", "second"):
                (root/attempt).mkdir()
            paths = dict(portable_selection=packet/"selection.fixture")
            acquire = SimpleNamespace(time_limit=lambda _: nullcontext())
            transfer = E.transfer_function(acquire, paths, {}, time.monotonic()+10, trace, STATELESS_FIXTURE)
            requests = []

            def deny(request, timeout):
                self.assertNotIn(E.TOKEN, os.environ)
                requests.append((request.full_url, request.get_header("Authorization")))
                raise E.urllib.error.HTTPError(request.full_url, 403, "fixture", Message(), BytesIO())

            def invoke(attempt):
                transfer(owned_workspace=root, device=0, inode=0, mount_id=0, portable=root/attempt/"portable",
                         output=root/attempt/"output")

            with patch.dict(os.environ, {}, clear=True), patch.object(E.urllib.request, "build_opener",
                       return_value=SimpleNamespace(open=deny)):
                with self.assertRaises(E.HTTPReadRefused):
                    invoke("first")
                self.assertEqual(trace.acquisition_detail, "HTTP_403")
                with self.assertRaisesRegex(ValueError, "EXACT_R128_READ_CUSTODY"):
                    invoke("second")
            self.assertEqual(requests, [(E.LOG_URL, "Bearer "+STATELESS_FIXTURE)])

    def test_root_356_readback_before_binding(self):
        approval, env = fixture()
        image = "sha256:"+"d"*64
        marker = dict(nonce="e"*32, uid=1000, gid=1000, source_map=dict(sha256="f"*64),
                      dispatch=C.dispatch(env, "42"), ends=dict(bootstrap=200, work=18100),
                      expires=approval["expires_utc"])
        launch = SimpleNamespace(executor=SimpleNamespace(LABEL="owner-label"), GPGDIR="/private-gpg",
                                 TEST_CERT="/test-cert")
        template = dict(kind="ROOT_QT612_COMPLETE_FAMILY_STAGE_BINDING_V1", policy={"stage_seconds":18000})
        pipeline = SimpleNamespace(binding_template=lambda: template)
        inventory = b"one exact joined inventory\n"
        row = dict(Id=image, Architecture="arm64", Os="linux", RepoDigests=[],
                   RepoTags=[f"cachy-qt612-native-{marker['nonce']}:gui-server356"],
                   Config=dict(User="1000:1000", Labels={"owner-label":marker["nonce"]}))
        calls = []
        def docker(*args):
            calls.append(args)
            return 0, C.encoded([row]) if args[0] == "image" else inventory if args[0] == "run" else b""
        owner = SimpleNamespace(docker=docker)
        request = C.encoded(dict(nonce=marker["nonce"], image=image, inventory=C.pin(inventory),
                                 source_map_sha256=marker["source_map"]["sha256"]))
        trace = E.ControllerTrace()
        with patch.object(E.time, "monotonic", return_value=100), patch.object(E.time, "time", return_value=4000):
            bound = E.authenticate_356(owner, launch, pipeline, marker, inventory, request, trace)
            self.assertEqual(bound["job"], "42")
            self.assertEqual(bound["image"], image)
            self.assertEqual(trace.stage.name, "SIGNED356_BINDING")
            self.assertIn("--network=none", calls[2])
            self.assertEqual([row[0] for row in calls], ["image", "container", "run", "container", "container"])
            row["Architecture"] = "amd64"
            with self.assertRaisesRegex(ValueError, "ROOT_READBACK_OF_FRESH"):
                E.authenticate_356(owner, launch, pipeline, marker, inventory, request, trace)
            self.assertEqual(trace.stage.name, "SIGNED356_READBACK")

    def test_image_request_wait_distinguishes_exit_deadline_and_arrival(self):
        trace = E.ControllerTrace()
        trace.mark("SIGNED356_REQUEST_WAIT")
        marker = dict(ends=dict(bootstrap=1), uid=os.getuid())
        pidfd = 42
        owner = SimpleNamespace(pidfds={"owner": pidfd})
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            for phase in E.OWNER_PROGRESS[:5]:
                E.atomic_marker(E.ordinary_progress_marker(work, phase), phase, 0o600)
            with patch.object(E.select, "poll") as factory, patch.object(E.time, "monotonic", return_value=0):
                watcher = factory.return_value
                watcher.poll.return_value = [(pidfd, E.select.POLLIN)]
                with self.assertRaisesRegex(ValueError, "ORIGINAL_ORDINARY_SERVICE_EXITED"):
                    E.wait_for_image_request(owner, marker, work, trace)
                watcher.register.assert_called_once_with(pidfd, E.select.POLLIN)
                watcher.poll.assert_called_once_with(250)
            result = StringIO()
            with redirect_stderr(result):
                trace.hold()
            self.assertEqual(result.getvalue(), "HOLD_QT612_PAIR: SIGNED356_REQUEST_WAIT\n"
                             "HOLD_QT612_OWNER: OWNER_EXITED SIGNED349_BUILD\n")
            with patch.object(E.select, "poll") as factory, patch.object(E.time, "monotonic", side_effect=(.9, 1)):
                watcher = factory.return_value
                watcher.poll.return_value = []
                with self.assertRaisesRegex(TimeoutError, "BOUND_IMAGE_REQUEST_DEADLINE"):
                    E.wait_for_image_request(owner, marker, work, trace)
                watcher.poll.assert_called_once_with(100)
                self.assertEqual(trace.owner_detail, ("REQUEST_DEADLINE", "SIGNED349_BUILD"))
            E.atomic_marker(work/"image-request.json", dict(image="fixture"), 0o600)
            with patch.object(E.select, "poll") as factory, patch.object(E.time, "monotonic", return_value=0):
                self.assertEqual(E.wait_for_image_request(owner, marker, work, E.ControllerTrace()),
                                 C.encoded(dict(image="fixture")))
                factory.return_value.poll.assert_not_called()

    def test_owner_progress_rejects_nonfixed_body_ownership_and_gaps(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            stage = E.ordinary_progress_marker(work, "SERVICE_JOIN")
            uid = os.getuid()
            self.assertEqual(E.last_ordinary_progress(work, uid), "UNOBSERVED")
            E.atomic_marker(stage, "raw exception /private/path", 0o600)
            self.assertEqual(E.last_ordinary_progress(work, uid), "INVALID_PROGRESS")
            stage.unlink()
            E.atomic_marker(stage, "SERVICE_JOIN", 0o600)
            self.assertEqual(E.last_ordinary_progress(work, uid + 1), "INVALID_PROGRESS")
            E.atomic_marker(E.ordinary_progress_marker(work, "SIGNED356_BUILD"), "SIGNED356_BUILD", 0o600)
            self.assertEqual(E.last_ordinary_progress(work, uid), "INVALID_PROGRESS")

    @unittest.skipUnless(R128 and AUTHORITY, "Exact retained R128 Source and path-free authority were not selected")
    def test_retained_r128_copy_and_negative_authority(self):
        selected = C.MD4C_AUTHORITY
        data = C.read(AUTHORITY, 8192, selected)
        value = C.decode(data)
        now = value["created_epoch"] + 60
        cert = Path(AUTHORITY).parent/C.CERT
        auth = C.trust(data, selected, now, now+2700, cert)
        self.assertEqual(auth["certificate"]["sha256"], C.CERTIFICATE["sha256"])
        with self.assertRaisesRegex(ValueError, "CURRENT_SCOPED_R128_TEST_AUTHORITY"):
            C.trust(data, selected, now, value["expires_epoch"], cert)
        with tempfile.TemporaryDirectory() as tmp:
            staged = Path(tmp)
            E.r128_copy(Path(R128), staged)
            sys.path.insert(0, str(REPO/C.HOSTED))
            launch = E.load(REPO/C.HOSTED/"launch.py", "qt612_sealed_launch_control")
            retained = launch.load_retained_runtime(staged)
            self.assertEqual(retained["policy"]["controller_scope_seconds"], 1740)
            self.assertIn(512, retained["entry"].Commands.__call__.__code__.co_consts)

    @unittest.skipUnless(RUNTIME and RUNTIME_SHA, "Exact portable runtime Source was not selected")
    def test_stage_frozen_helpers_and_plan_retained_bytes(self):
        source = Path(RUNTIME)
        with tempfile.TemporaryDirectory() as tmp:
            staged = Path(tmp)/"helpers"
            expected = dict(sha256=RUNTIME_SHA)
            E.stage_runtime_helpers(source, expected, REPO, staged)
            self.assertEqual(E.helpers(staged).CONTROLLER_SCOPE_SECONDS, 21030)
            acquire = E.load(staged/C.FAMILY/"acquire_runner_inputs.py", "qt612_acquire_control")
            roles = dict(portable_selection=source/"portable/selection.DATA.json",
                         route_plan=source/"inputs/acquisition-routes.DATA.json")
            pins = {key: C.pin(C.read(path, C.MIB)) for key, path in roles.items()}
            self.assertEqual(E.portable_plan(acquire, roles, {"inputs":pins}), 1_752_637_011)


if __name__ == "__main__":
    unittest.main()
