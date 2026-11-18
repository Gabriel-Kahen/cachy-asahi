# SPDX-License-Identifier: MIT
"""Actor-fenced control ZIP and private backend handoff tests."""
import argparse
from datetime import datetime, timezone
import gzip
import io
from pathlib import Path
import sys
import tarfile
from tempfile import TemporaryDirectory
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backend_private_handoff as H
import backend_stage_review as B
from test_source207 import model_case
from test_contract import pack

C, T, S, R = B.C, B.T, B.S, H.reader
NONCE = "a" * 64
BINDING = dict(source=S.CID, ref=S.REF, source_lock=S.SOURCE["source_map"], run="111", job="222", attempt=1)
MODEL = C.pin(b"model body")


def capsule_fixture():
    files = {"context.json": C.encoded(dict(model="context")),
             "delegation.json": C.encoded(dict(model="delegation")),
             "image.public.json": C.encoded(dict(model="image projection")),
             "route.public.json": C.encoded(dict(model="stage projection")),
             "image/base-inputs.public.json": C.encoded(dict(model="base inputs projection"))}
    origins = {name: dict(pin=MODEL, projection=True) for name in files if name.endswith(".public.json")}
    manifest = dict(schema=4, kind="DELEGATED_CURRENT_STAGE_RETENTION_V4", issuer="DELEGATED_RETENTION_PROGRAM_V4",
                    operation=C.OPERATION, stage="backend", binding=BINDING, nonce=NONCE,
                    delegation_pin=C.pin(files["delegation.json"]), context_pin=C.pin(files["context.json"]),
                    stage_report_pin=MODEL, image_report_pin=MODEL, selector_basis=R.INVOCATION_OWNER_BASIS,
                    evidence_state="COMPLETE", holds=[], files={name:C.pin(raw) for name,raw in files.items()},
                    origins=origins, legacy_private_launch_replay=False, provisional_observations_only=True, **C.FINAL)
    raw = files["retention-manifest.json"] = C.encoded(manifest)
    storage = io.BytesIO()
    with tarfile.open(fileobj=storage, mode="w") as tar:
        for name,body in files.items():
            item = tarfile.TarInfo("delegated-backend-public-v4/" + name)
            item.mode, item.size = 0o444, len(body)
            tar.addfile(item, io.BytesIO(body))
    capsule = gzip.compress(storage.getvalue(), mtime=0)
    retention = dict(evidence_state="COMPLETE", capsule_pin=C.pin(capsule), manifest_pin=C.pin(raw))
    result = dict(completed=True, status="DELEGATED_PRIVATE_STAGE_AND_PUBLIC_RETENTION_COMPLETE", binding=BINDING,
                  stage="backend", nonce=NONCE, stage_report_pin=MODEL, retention=retention, **C.FINAL)
    owner = dict(status="DELEGATED_OWNER_RETURNED_DATA_ONLY", binding=BINDING, result=result, **C.FINAL)
    cleanup = dict(owned_storage_absent=True, errors=[],
                   services={name:dict(natural=True, empty_twice=True) for name in ("owner", "daemon")})
    executor = dict(status="DELEGATED_OWNED_STAGE_RETIRED_DATA_ONLY", binding=BINDING, owner=owner,
                    delegation_pin=manifest["delegation_pin"], cleanup=cleanup, **C.FINAL)
    return dict(capsule=capsule, manifest=raw, owner=C.encoded(owner), executor=C.encoded(executor))


class PrivateHandoff(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.control = self.root / ("cachy-current-hosted-" + NONCE)
        self.public = self.control / "public"
        self.public.mkdir(parents=True)
        self.owner = self.root / ("cachy-current-" + NONCE)
        self.private = self.root / "private"
        self.private.mkdir(mode=0o700)
        self.data = capsule_fixture()
        for name,raw in self.data.items():
            file = self.owner / H.CONTENTS[name][0]
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(raw)
        (self.owner/"evidence/daemon.log").write_bytes(b"model private log")
        self.launcher = self.control/H.LAUNCHER
        raw = C.encoded(dict(status="DELEGATED_HOSTED_CONTROLLER_RETIRED_DATA_ONLY", binding=BINDING,
                            controller_retirement=B.RETIRED, material_domain_cleanup=T.CLOSED,
                            scope_absence=dict(scope=f"cachy-current-controller-{NONCE}.scope", empty_twice=True),
                            cleanup=dict(owned_storage_absent=True, error_count=0), **C.FINAL))
        self.launcher.write_bytes(raw)
        self.selection = dict(schema=1, kind=H.SELECTION, issuer="Root", approved=True, binding=BINDING, nonce=NONCE,
                              owner_root=str(self.owner), control_root=str(self.control), private_root=str(self.private),
                              expected={name:C.pin(body) for name,body in dict(self.data, launcher=raw).items()})

    def test_selected_private_snapshot_exact_allowlist_and_actual_reader_hold(self):
        self.assertEqual(H.snapshot(None)["status"], "SOURCE207_PUBLIC_CONTROL_ONLY")
        self.assertEqual(list(self.private.iterdir()), [])
        result = H.snapshot(self.selection, mode=H.MODE)
        self.assertEqual(result["status"], "SOURCE207_PRIVATE_BACKEND_HANDOFF_DATA_ONLY")
        self.assertEqual(list(self.public.iterdir()), [self.launcher])
        output = Path(result["path"])
        self.assertEqual({file.name for file in output.iterdir()},
                         {"backend.capsule.tar.gz", "retention-manifest.json", "owner-completion.data.json", "handoff.json"})
        self.assertEqual((output/"backend.capsule.tar.gz").read_bytes(), self.data["capsule"])
        self.assertEqual((output/"retention-manifest.json").read_bytes(), self.data["manifest"])
        self.assertTrue(all(file.stat().st_mode & 0o777 == 0o400 for file in output.iterdir()))
        with self.assertRaises(FileExistsError):
            H.snapshot(self.selection, mode=H.MODE)
        self.assertEqual(C.pin((output/"handoff.json").read_bytes()), result["transfer_pin"])

        support = self.root/"model-support.json"
        support.write_bytes(C.encoded(dict(model=True)))
        ref = dict(path=str(support), pin=C.pin(support.read_bytes()))
        refs = {name:ref for name in H.SUPPORT}
        manifest = C.decode(self.data["manifest"])
        expected = {key:manifest[key] for key in
                    ("binding", "nonce", "stage", "delegation_pin", "context_pin", "stage_report_pin", "image_report_pin")}
        expected.update(schema=4, kind="ROOT_BOUND_DELEGATED_PUBLIC_READER_V4",
                        capsule_pin=C.pin(self.data["capsule"]), source=dict(retention=R.BASE_RETENTION_PIN),
                        support_pins={name:ref["pin"] for name in refs})
        expected_raw = C.encoded(expected)
        def replay(pins, selector_pin=C.pin(expected_raw)):
            return H.replay(output, result["transfer_pin"], expected_raw=expected_raw, expected_pin=selector_pin,
                            source_files={}, support_refs=pins, now=1000)
        with self.assertRaisesRegex(ValueError, "HOLD_SOURCE207_BACKEND_ROOT_SELECTOR_PIN"):
            replay(refs, MODEL)
        with self.assertRaisesRegex(ValueError, "HOLD_TERMINAL_FIELDS"):
            replay({name:row for name,row in refs.items() if name!="completion"})
        supplied = replay(refs)
        self.assertEqual(supplied["backend_reader"]["reasons"], ["HOLD_DELEGATED_EXTERNAL_SELECTION"])
        self.assertFalse(supplied["first_usable_login_ready"])

    def test_refuses_public_destination_wrong_pin_unsafe_or_linked_body(self):
        self.public.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "HOLD_SOURCE207_BACKEND_PRIVATE_DESTINATION"):
            H.snapshot(self.selection | {"private_root":str(self.public)}, mode=H.MODE)
        with self.assertRaisesRegex(ValueError, "HOLD_SOURCE207_BACKEND_BINDING"):
            H.snapshot(self.selection | {"binding":BINDING | {"ref":"refs/heads/main"}}, mode=H.MODE)
        raw = C.encoded(C.decode(self.launcher.read_bytes()) | {"material_domain_cleanup": None})
        original = self.launcher.read_bytes()
        self.launcher.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "HOLD_SOURCE207_BACKEND_LAUNCHER"):
            H.snapshot(self.selection | {"expected": self.selection["expected"] | {"launcher":C.pin(raw)}}, mode=H.MODE)
        self.launcher.write_bytes(original)
        with self.assertRaisesRegex(ValueError, "HOLD_TERMINAL_LOCAL_REGULAR_FILE|HOLD_SOURCE207_BACKEND_OPERAND_PIN"):
            H.snapshot(self.selection | {"expected": self.selection["expected"] | {"capsule":MODEL}}, mode=H.MODE)
        executor = C.decode(self.data["executor"])
        executor["cleanup"]["services"]["owner"]["natural"] = False
        with self.assertRaisesRegex(ValueError, "HOLD_SOURCE207_BACKEND_CLEANUP"):
            H.validate_snapshot(self.data | {"executor":C.encoded(executor)}, BINDING, NONCE)
        capsule = self.owner/H.CONTENTS["capsule"][0]
        capsule.unlink()
        capsule.symlink_to(self.owner/"evidence/daemon.log")
        with self.assertRaisesRegex(ValueError, "HOLD_TERMINAL_LOCAL_PATH"):
            H.snapshot(self.selection, mode=H.MODE)
        self.assertEqual(list(self.private.iterdir()), [])


def archive(entries):
    storage = io.BytesIO()
    with zipfile.ZipFile(storage, "w", compression=zipfile.ZIP_DEFLATED) as target:
        for name,value in entries.items():
            target.writestr(name,C.encoded(value))
    return storage.getvalue()


class StageRecords(unittest.TestCase):
    def test_late_terminal_preserves_observed_stages_and_refuses_wrong_scope(self):
        group = f"/system.slice/cachy-current-controller-{NONCE}.scope"
        report = dict(binding=BINDING, prerequisite_retirement=B.RETIRED,
                      prerequisite_scope_absence=dict(scope=f"cachy-current-prerequisites-{NONCE}.scope", absent_twice=True),
                      controller_retirement=B.RETIRED, scope_absence=dict(scope=group.rsplit("/",1)[1], empty_twice=True))
        prereq = dict(status="PASS_CI_LIBARCHIVE_TOOLS_PREREQUISITE_ONLY", binding=BINDING, cache_absent=True,
                      tool_count=16, **C.FINAL)
        context = dict(binding=BINDING, observed_epoch=1000)
        controller = dict(kind="CURRENT_HOSTED_CONTROLLER_OBSERVATION_V3", binding=BINDING, policy_pin=MODEL,
                          domain=dict(cgroup=group, limits=C.RESOURCES["scope_limits"], pid=1, starttime=2),
                          properties=dict(ControlGroup=group, ActiveEnterTimestampMonotonic="1000"), **C.FINAL)
        data = {"launcher-report.json":report, "host-prerequisite.json":prereq, "context.json":context}
        def examine(conclusion):
            return B.records_in_archive(archive(data), {"nonce":NONCE},
                {"delegation_json":C.encoded(dict(policy=MODEL)).decode()},
                dict(status=T.RETAINED, workflow_conclusion=conclusion, launcher_failure=None))
        self.assertEqual(examine("failure")["prerequisite"], "PREREQUISITES_RETIRED_CONTEXT_REFRESH_NOT_RETAINED")
        with self.assertRaisesRegex(ValueError, "HOLD_SOURCE207_SUCCESS_WITHOUT_PREREQUISITES_AND_CONTROLLER"):
            examine("success")
        data.update({"context-after-prerequisites.json":context | {"observed_epoch":1001},
                     "controller-observation.json":controller})
        outcome = examine("success")
        self.assertEqual(outcome["material"], T.RETAINED)
        self.assertEqual(outcome["controller"], "HOSTED_CONTROLLER_RETIRED_DATA_ONLY")
        self.assertFalse(outcome["first_usable_login_ready"])
        controller["properties"]["ControlGroup"] = "/elsewhere"
        with self.assertRaisesRegex(ValueError, "HOLD_SOURCE207_CONTROLLER_DOMAIN"):
            examine("success")


def full_review_controls(packet_dir, projection_pin):
    class FullTerminalReview(unittest.TestCase):
        def test_authentic_static_source_and_synthetic_early_original(self):
            main = B.packet(packet_dir, projection_pin)[0]["main"]
            prepared = C.decode((packet_dir/"BACKEND-CHECKPOINT.UNISSUED.json").read_bytes())
            profile = C.decode((packet_dir/"profile").read_bytes())
            entered, values = model_case(profile, prepared)
            values["request"]["trusted_main_commit"] = main["cid"]
            operands,pins = pack(values)
            case = C.decode(operands["case"])
            data = {name:operands[name] for name in ("case","request")}
            data["prepost"] = C.encoded(dict(schema=1, kind="ROOT_SOURCE207_BACKEND_PREPOST_V1", binding=C.binding(case),
                        case=pins["case"], request=pins["request"], operands=pins, once=True, retry=False,
                        release="CLOSE_ONLY", observed_epoch=entered))
            data["execution"] = C.encoded(dict(kind="ROOT_SOURCE207_BACKEND_ONCE_OUTCOME_V1",
                        status="ROOT_SOURCE207_ORIGINAL_RUN_DISCOVERED", prepost=C.pin(data["prepost"]),
                        POSTs=1, once=True, retry=False, release="CLOSE_ONLY", native_acceptance=False,
                        original=dict(run_id=111, workflow_id=S.WORKFLOW_ID, source=S.CID, ref=S.REF, attempt=1)))
            branch = S.REF.removeprefix("refs/heads/")
            time = datetime.fromtimestamp(entered, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            repo = dict(id=444, full_name=C.REPOSITORY)
            run = dict(id=111, status="completed", head_sha=S.CID, head_branch=branch, run_attempt=1,
                       workflow_id=S.WORKFLOW_ID, path=C.WORKFLOW, event="workflow_dispatch", conclusion="failure",
                       repository=repo, head_repository=repo, created_at=time, run_started_at=time, updated_at=time)
            steps = [dict(name=name, status="completed", conclusion="failure" if i==3 else "success", number=i+1)
                     for i,name in enumerate(T.REQUIRED_STEPS)]
            job = dict(id=222, run_id=111, run_attempt=1, head_sha=S.CID, labels=["ubuntu-24.04-arm"], name=T.JOB,
                       status="completed", conclusion="failure", started_at=time, completed_at=time, steps=steps,
                       runner_name="MODEL ARM64")
            data["archive"] = archive({"launcher-report.json":dict(status="HOLD", request_pin=pins["request"],
                                       failure=dict(phase="git_source", reason="VALIDATION_REFUSED"), **C.FINAL)})
            artifact = dict(id=333, name="current-onboarding-control-111-1", expired=False,
                      size_in_bytes=len(data["archive"]), digest="sha256:"+C.pin(data["archive"])["sha256"],
                      workflow_run=dict(id=111, repository_id=444, head_repository_id=444,
                                        head_branch=branch, head_sha=S.CID))
            data.update(run=C.encoded(run), jobs=C.encoded(dict(total_count=1,jobs=[job])),
                        artifacts=C.encoded(dict(total_count=1,artifacts=[artifact])))
            local = Path(self.enterContext(TemporaryDirectory()))
            selection = dict(schema=1, kind=B.KIND, packet=dict(path=str(packet_dir), pin=projection_pin), inputs={})
            for name,raw in data.items():
                path = local/name
                path.write_bytes(raw)
                selection["inputs"][name] = dict(path=str(path), pin=C.pin(raw))
            result = B.review(selection)
            self.assertEqual(result["material"], T.UNRETAINED)
            self.assertEqual(result["main"], main)
            self.assertEqual(result["launcher_failure"]["phase"], "git_source")
            self.assertFalse(result["first_usable_login_ready"])
            del selection["inputs"]["archive"]
            self.assertEqual(B.review(selection)["original"], "NOT_SUPPLIED")
            data["jobs"] = C.encoded(dict(total_count=2,jobs=[job,job | {"id":223}]))
            (local/"jobs").write_bytes(data["jobs"])
            selection["inputs"]["jobs"]["pin"] = C.pin(data["jobs"])
            with self.assertRaisesRegex(ValueError, "HOLD_SOURCE207_JOB_ROSTER"):
                B.review(selection)
    return FullTerminalReview


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet",type=Path)
    parser.add_argument("--projection-sha256")
    args,remaining = parser.parse_known_args()
    sys.addaudithook(B.fence)
    if args.packet:
        raw = (args.packet/"PROJECTION.PASS.DATA.json").read_bytes()
        pin = C.pin(raw)
        if pin["sha256"] != args.projection_sha256:
            parser.error("supply the previously observed projection SHA-256")
        FullTerminalReview = full_review_controls(args.packet,pin)
    unittest.main(argv=[sys.argv[0],*remaining])
