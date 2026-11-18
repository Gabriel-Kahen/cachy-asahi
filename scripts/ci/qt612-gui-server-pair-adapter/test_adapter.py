# SPDX-License-Identifier: MIT
"""Offline controls. No process, lock, socket or native entry is permitted."""

import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import entry as E

C = E.C
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
        with patch.object(E.time, "monotonic", return_value=100), patch.object(E.time, "time", return_value=4000):
            bound = E.authenticate_356(owner, launch, pipeline, marker, inventory, request)
            self.assertEqual(bound["job"], "42")
            self.assertEqual(bound["image"], image)
            self.assertIn("--network=none", calls[2])
            self.assertEqual([row[0] for row in calls], ["image", "container", "run", "container", "container"])
            row["Architecture"] = "amd64"
            with self.assertRaisesRegex(ValueError, "ROOT_READBACK_OF_FRESH"):
                E.authenticate_356(owner, launch, pipeline, marker, inventory, request)

    @unittest.skipUnless(R128 and AUTHORITY, "Exact retained R128 Source and path-free authority were not selected")
    def test_retained_r128_copy_and_negative_authority(self):
        selected = dict(bytes=1034, sha256="cc3dd84c1f96b5204df4e2edd33b10cc4e7907d460c68a311b6122a8c1fca712")
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
