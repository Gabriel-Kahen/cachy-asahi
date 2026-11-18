# SPDX-License-Identifier: MIT
"""Synthetic Original archive and metadata checks. No GitHub or native execution."""
import copy
import io
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import warnings
import zipfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_contract as fixture
import terminal as T

C = T.C
IDS = dict(run=111, job=222, artifact=333)
READER = (HERE.parents[1] / "payload/native/reader_current_v3.py").read_bytes()
EMPTY = C.pin(b"")


class Terminal(unittest.TestCase):
    def setUp(self):
        profile = fixture.G.model_inputs()[3]
        profile["materials"] = {key.lower(): row for key, row in profile["materials"].items()}
        self.profile = C.encoded(profile)
        profile_patch = patch.object(C, "PROFILE", C.pin(self.profile))
        profile_patch.start()
        self.addCleanup(profile_patch.stop)
        with patch.object(fixture.C, "PROFILE", C.pin(self.profile)):
            values = fixture.model_case(profile)
        values["case"]["main"]["reader"] = dict(member=C.READER, **T.READER)
        operands, _ = fixture.pack(values)
        self.operands = {key: operands[key] for key in ("case", "request")}
        self.case = C.decode(self.operands["case"])
        self.request = C.decode(self.operands["request"])
        self.delegation = C.decode(self.request["delegation_json"].encode())
        self.pin = C.pin(self.operands["request"])
        source = self.case["source"]
        self.repo = dict(id=444, full_name=C.REPOSITORY)
        self.run = dict(id=IDS["run"], head_sha=source["cid"], head_branch=source["ref"].removeprefix("refs/heads/"),
                        run_attempt=1, path=C.WORKFLOW, workflow_id=self.case["workflow_id"],
                        event="workflow_dispatch", status="completed", conclusion="failure",
                        repository=self.repo, head_repository=self.repo)
        self.job = dict(id=IDS["job"], run_id=IDS["run"], run_attempt=1, name=T.JOB, head_sha=source["cid"],
                        status="completed", conclusion="failure", labels=["ubuntu-24.04-arm"],
                        runner_name="MODEL ARM64")
        self.job["steps"] = [dict(name=name, status="completed", conclusion="failure" if i == 3 else "success",
                                  number=i + 1) for i, name in enumerate(T.REQUIRED_STEPS)]
        self.jobs = dict(total_count=1, jobs=[self.job])
        self.artifact = dict(id=IDS["artifact"], name="current-onboarding-control-111-1", expired=False,
                             workflow_run=dict(id=IDS["run"], repository_id=self.repo["id"],
                                               head_repository_id=self.repo["id"], head_sha=self.run["head_sha"],
                                               head_branch=self.run["head_branch"]))
        self.artifacts = dict(total_count=1, artifacts=[self.artifact])
        self.binding = dict(attempt=1, job="222", run="111", ref=source["ref"], source=source["cid"],
                            source_lock=source["source_map"])
        self.scope = "cachy-current-materials-" + self.case["nonce"] + ".scope"
        self.context = self.make_context()
        self.timing = dict(schema=3, kind=C.TIMING["kind"], whole_budget_seconds=7560, request_pin=self.pin,
                           delegation_pin=self.context["delegation_pin"], policy_pin=self.context["policy_pin"],
                           boot_pin=C.pin(b"model boot"), expires_epoch=self.case["expires_epoch"],
                           started_monotonic=1.0, deadline_monotonic=501.0, binding=self.binding, **C.FINAL)
        self.report = dict(status="HOLD", request_pin=self.pin, binding=self.binding, intake=None,
                           failure=dict(phase="material_stage", reason="VALIDATION_REFUSED"),
                           material_domain_cleanup=copy.deepcopy(T.CLOSED), **C.FINAL)
        self.entries = {"context.json": self.context, "timing.json": self.timing,
                        "launcher-report.json": self.report}
        self.material_children(False, EMPTY)

    def tearDown(self):
        self.assertEqual(fixture.ACTORS, [])

    def make_context(self):
        source_root = "/home/runner/work/cachy-asahi/cachy-asahi"
        config = self.delegation["hosted"]
        hosted = dict(GITHUB_ACTIONS="true", GITHUB_JOB="current", GITHUB_REF=self.binding["ref"],
                      GITHUB_REPOSITORY=C.REPOSITORY, GITHUB_RUN_ATTEMPT="1", GITHUB_RUN_ID=str(IDS["run"]),
                      GITHUB_SHA=self.binding["source"], GITHUB_WORKFLOW_REF=config["workflow_ref"],
                      GITHUB_WORKFLOW_SHA=self.binding["source"], GITHUB_WORKSPACE=source_root, RUNNER_ARCH="ARM64",
                      RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="Linux", RUNNER_NAME=self.job["runner_name"])
        repo_url = "https://api.github.com/repos/" + C.REPOSITORY
        run_url = repo_url + "/actions/runs/111"
        job = dict(self.job, status="in_progress", conclusion=None, run_url=run_url,
                   url=repo_url + "/actions/jobs/222",
                   html_url="https://github.com/" + C.REPOSITORY + "/actions/runs/111/job/222")
        body = C.encoded(dict(total_count=1, jobs=[job]))
        return dict(schema=4, kind="DELEGATED_CURRENT_ONBOARDING_CONTEXT_V4", issuer="DELEGATED_CONTEXT_PROGRAM_V4",
                    stage="backend", operation=C.OPERATION, nonce=self.case["nonce"], binding=self.binding,
                    delegation_pin=self.request["delegation_pin"], source_root=source_root, hosted=hosted,
                    policy_pin={key: C.POLICY[key] for key in ("bytes", "sha256")},
                    program_pin={key: self.delegation["programs"]["context"][key] for key in ("bytes", "sha256")},
                    observed_epoch=1000, jobs_response_pin=C.pin(body),
                    jobs_response=dict(body=body.decode(), status=200, url=run_url + "/jobs?filter=latest&per_page=100",
                                       received_epoch=998, elapsed_ms=1000), **C.FINAL)

    def archive(self, extra=()):
        storage = io.BytesIO()
        with zipfile.ZipFile(storage, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, value in self.entries.items():
                archive.writestr(name, C.encoded(value))
            for name, raw in extra:
                archive.writestr(name, raw)
        return storage.getvalue()

    def verify(self, archive=None, *, ids=IDS, stale=None, reader_raw=READER):
        original = self.archive() if archive is None else archive
        self.artifact.update(size_in_bytes=len(original), digest="sha256:" + C.pin(original)["sha256"])
        raw = dict(self.operands, archive=original, run=C.encoded(self.run),
                   jobs=C.encoded(self.jobs), artifacts=C.encoded(self.artifacts))
        pins = {key: C.pin(value) for key, value in raw.items()}
        if stale is not None:
            pins[stale] = C.pin(b"stale")
        return T.verify(raw, pins, ids=ids, core_raw=fixture.CORE_RAW, profile_raw=self.profile,
                        reader_raw=reader_raw)

    def material_children(self, success, stderr):
        supervision = dict(group_census="EMPTY_TWICE", output_complete=True, ownership="REAPED", reaped=True,
                           signals_observed=False, supervisor_error=False, timeout=False)
        stage = dict(kind="STAGE", natural_success=success, scope_absent_twice=success, output_pin=EMPTY,
                     stderr_pin=stderr, supervision=dict(exit=0 if success else 2, **supervision))
        close = dict(kind="CLOSE", natural_success=True, scope_absent_twice=True, output_pin=EMPTY,
                     stderr_pin=EMPTY, supervision=dict(exit=0, **supervision))
        self.report["material_failure_before_cleanup"] = dict(
            state="RETAINED_FOR_CONSUMERS" if success else "HOLD_CLOSEONLY", stage_submitted=True,
            children=[stage], source_failure=dict(status="NOT_OBSERVED"), source_hold=dict(status="NOT_OBSERVED"))
        self.report["material_children_after_cleanup"] = dict(state="CLOSED", stage_submitted=True,
                                                              children=[copy.deepcopy(stage), close])

    def add_diagnostic(self, nested=True):
        transport = dict(schema=1, kind="CURRENT_RETAINED_TRANSPORT_FAILURE_V1", phase="REQUIRED_BLOBS_FETCH",
                         operation="GIT_FETCH_BLOBS", error_class="VALIDATION", errno=None, command_ordinal=9,
                         git_exit=128, git_timeout=False, http_status=None)
        packet = dict(schema=2, kind="CURRENT_MATERIAL_STAGE_FAILURE_V2", phase="TRANSPORT_NATIVE248",
                      reason="COMMAND_FAILED", command_ordinal=2, transport=transport if nested else None)
        record = dict(schema=1, kind="CURRENT_MATERIAL_STAGE_FAILURE_RECORD_V1", status="DIAGNOSTIC_ONLY",
                      availability="AVAILABLE", request_pin=C.pin(b"model material request"),
                      context_pin=C.pin(C.encoded(self.context)), stdout_pin=EMPTY, stderr_pin=C.pin(C.encoded(packet)),
                      retirement_pin=C.pin(b"model private retirement"), packet=packet, **C.FINAL)
        self.material_children(False, record["stderr_pin"])
        self.report["material_failure_before_cleanup"]["source_failure"] = dict(record, record_pin=C.pin(C.encoded(record)))
        return transport

    def add_staging(self):
        self.report["failure"]["phase"] = "controller"
        grant = C.decode(self.request["material_staging"]["grant_json"].encode())
        out = grant["storage_parent"] + "/" + self.scope.removesuffix(".scope")
        cache = out + "/cache"
        child = ["/usr/bin/python3.12", "-I", "-B", self.context["source_root"] + "/" +
                 self.delegation["programs"]["materials_stager"]["member"], "transport", "--request",
                 out + "/child-request.json", "--request-sha256", "f" * 64, "--which"]
        argv = [["/usr/bin/systemctl", "show", self.scope, "--no-pager",
                 "--property=RuntimeMaxUSec,ActiveEnterTimestampMonotonic,ControlGroup"],
                [*child, "public14"], [*child, "native248"], *([["MODEL-completed"]] * 24)]
        rows = [dict(argv=row, natural=True, Root_acceptance=None) for row in argv]
        receipt = dict(status="COMPLETE517_HOSTED_CACHE_DATA_ONLY", binding=self.binding,
                       grant_pin=self.request["material_staging"]["grant_pin"], policy_pin=self.context["policy_pin"],
                       Root_expires_epoch=self.case["expires_epoch"], verified_files=517, verified_bytes=2000,
                       cache_created_files=517, provider_validation_archive_copies=0,
                       caller_must_prove_scope_retirement_and_absence=True, cache=cache,
                       materialization="UNCHANGED_ORIGINAL_SEEDS_AND_FIXED_PINNED_DOWNLOADS",
                       domain=dict(cgroup="/system.slice/" + self.scope, pid=11, starttime=5,
                                   limits=C.RESOURCES["scope_limits"], Root_acceptance=None),
                       storage_domain=dict(path=grant["storage_parent"], device=88, total_bytes=8 << 30,
                                           free_bytes=7 << 30, total_nodes=20000, free_nodes=19500,
                                           Root_acceptance=None), commands=rows,
                       whole_deadline_monotonic=501.0, physical_scope_end_monotonic=401.0, **C.FINAL)
        retirement = dict(scope=self.scope, natural=True, scope_absent=True, supervision_pin=C.pin(b"model retirement"),
                          scope_absence_pin=C.pin(C.encoded(dict(scope=self.scope, absent_twice=True))), **C.FINAL)
        self.report["intake"] = dict(files=522, bytes=2200)
        self.entries["material-staging.json"] = dict(receipt=receipt, staging_scope_retirement=retirement,
                                                      intake=self.report["intake"], wrapper_pin=C.pin(b"model wrapper"),
                                                      **C.FINAL)
        self.material_children(True, EMPTY)
        return rows

    def test_checkpoint_and_later_failure(self):
        rows = self.add_staging()
        result = self.verify()
        self.assertEqual(result["status"], T.RETAINED)
        self.assertEqual(result["workflow_conclusion"], "failure")
        self.assertEqual(result["native248_command_pin"], C.pin(C.encoded(rows[2])))
        self.assertIs(result["transport_body_replayed"], False)
        self.assertIsNone(result["Root_final_acceptance"])
        rows[2], rows[3] = rows[3], rows[2]
        with self.assertRaisesRegex(ValueError, "NATIVE248_COMMAND"):
            self.verify()

    def test_checkpoint_and_terminal_success(self):
        self.add_staging()
        self.run["conclusion"] = self.job["conclusion"] = self.job["steps"][3]["conclusion"] = "success"
        self.report["status"] = "DELEGATED_HOSTED_CONTROLLER_RETIRED_DATA_ONLY"
        self.report["cleanup"] = dict(owned_storage_absent=True, error_count=0)
        for name in ("failure", "material_failure_before_cleanup", "material_children_after_cleanup"):
            del self.report[name]
        self.assertEqual(self.verify()["status"], T.RETAINED)

    def test_nested_diagnostic_uses_maintained_reader(self):
        expected = self.add_diagnostic()
        result = self.verify()
        self.assertEqual(result["status"], T.DIAGNOSTIC)
        self.assertEqual(result["material_failure_diagnostic"]["transport"], expected)
        self.assertEqual(result["native248_transport_cause"], "FINITE_DIAGNOSTIC_RETAINED")
        self.assertIsNone(result["native248_command_pin"])
        self.assertIs(result["hardware_acceptance"], False)

    def test_missing_inner_cause_remains_unknown(self):
        self.add_diagnostic(nested=False)
        result = self.verify()
        self.assertEqual(result["status"], T.DIAGNOSTIC)
        self.assertEqual(result["native248_transport_cause"], "UNKNOWN_NOT_RETAINED")
        self.assertIsNone(result["material_failure_diagnostic"]["transport"])

    def test_no_stage_receipt_before_or_after_staging(self):
        for phase in ("git_source", "material_stage", "assembly", "controller"):
            with self.subTest(phase=phase):
                self.report["failure"]["phase"] = phase
                result = self.verify()
                self.assertEqual(result["status"], T.UNRETAINED)
                self.assertEqual(result["native248_transport_cause"], "UNKNOWN_NOT_RETAINED")
        self.entries = {"launcher-report.json": self.report}
        self.report["failure"]["phase"] = "git_source"
        del self.report["binding"], self.report["material_domain_cleanup"]
        del self.report["material_failure_before_cleanup"], self.report["material_children_after_cleanup"]
        self.assertEqual(self.verify()["material_cleanup"], "NOT_RETAINED")

    def test_pin_and_evidence_mismatches(self):
        self.add_diagnostic()
        with self.assertRaisesRegex(ValueError, "OPERAND_PIN"):
            self.verify(stale="archive")
        with self.assertRaisesRegex(ValueError, "TERMINAL_READER"):
            self.verify(reader_raw=b"foreign")
        with self.assertRaisesRegex(ValueError, "TERMINAL_JOB"):
            self.verify(ids=dict(IDS, job=999))
        self.run["run_attempt"] = 2
        with self.assertRaisesRegex(ValueError, "TERMINAL_RUN"):
            self.verify()
        self.run["run_attempt"] = 1
        self.report["material_failure_before_cleanup"]["source_failure"]["record_pin"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "DIAGNOSTIC_RECORD_PIN"):
            self.verify()

    def test_cleanup_ambiguity(self):
        self.add_diagnostic()
        self.report["material_children_after_cleanup"]["children"][1]["scope_absent_twice"] = False
        with self.assertRaisesRegex(ValueError, "DIAGNOSTIC_CLOSE"):
            self.verify()
        self.add_staging()
        self.report["material_domain_cleanup"]["scope_absent"] = False
        with self.assertRaisesRegex(ValueError, "MATERIAL_CLEANUP"):
            self.verify()

    def test_nested_diagnostic_rejects_invented_http_status(self):
        self.add_diagnostic()
        projected = self.report["material_failure_before_cleanup"]["source_failure"]
        record = {key: value for key, value in projected.items() if key != "record_pin"}
        record["packet"]["transport"]["http_status"] = 503
        record["stderr_pin"] = C.pin(C.encoded(record["packet"]))
        self.material_children(False, record["stderr_pin"])
        self.report["material_failure_before_cleanup"]["source_failure"] = dict(
            record, record_pin=C.pin(C.encoded(record)))
        with self.assertRaisesRegex(ValueError, "HOLD_DIAGNOSTIC_FIXED_TRANSPORT"):
            self.verify()

    def test_duplicate_or_unsafe_archive_members(self):
        link = zipfile.ZipInfo("host-prerequisite.json")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            for entry in (("context.json", b"{}"), ("../outside.json", b"{}"),
                          ("unexpected.json", b"{}"), (link, b"/outside")):
                with self.subTest(entry=entry), self.assertRaisesRegex(ValueError, "ARCHIVE_"):
                    self.verify(self.archive([entry]))

    def test_malformed_zip_and_recursion_refuse(self):
        with self.assertRaisesRegex(ValueError, "ARCHIVE_FORMAT"):
            self.verify(b"PK\x03\x04malformed")
        deep = b'{"deep":' + b"[" * 2000 + b"null" + b"]" * 2000 + b"}"
        original = self.archive([("host-prerequisite.json", deep)])
        with self.assertRaisesRegex(ValueError, "TERMINAL_JSON_DEPTH"):
            self.verify(original)
        argv = ["terminal.py", "--selection", "/MODEL-selection.json", "--selection-sha256", C.pin(deep)["sha256"]]
        stdout = io.BytesIO()
        with patch.object(T.sys, "argv", argv), patch.object(T.sys, "stdout", SimpleNamespace(buffer=stdout)), \
                patch.object(T, "read_local", return_value=deep):
            self.assertEqual(T.main(), 2)
        self.assertEqual(C.decode(stdout.getvalue())["status"], "HOLD_TERMINAL_INPUT_REFUSED")
        self.assertEqual(fixture.ACTORS, [])


if __name__ == "__main__":
    unittest.main()
