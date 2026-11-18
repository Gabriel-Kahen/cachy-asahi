# SPDX-License-Identifier: MIT
"""Replay a Root-selected backend Original and terminal metadata as DATA."""

import argparse
import ast
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile
import zlib

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("source205_terminal_contract", HERE / "contract.py")
C = importlib.util.module_from_spec(SPEC)
exec(compile((HERE / "contract.py").read_bytes(), C.__file__, "exec"), C.__dict__)

READER = dict(bytes=284443, sha256="22b8ddc5152d8d104ed40a5240f664761f5d568210378df546c987c5c0ccd304")
MIB = 1 << 20
CAPS = dict(case=C.MAX_BYTES, request=C.LIMITS["request_bytes"], run=MIB, jobs=MIB,
            artifacts=MIB, archive=C.LIMITS["control_bytes"] + MIB)
SELECTION = "SOURCE205_BACKEND_TERMINAL_SELECTION_V1"
SUCCESSOR_SELECTION = "SOURCE206_BACKEND_TERMINAL_SELECTION_V1"
MEMBERS = {"launcher-report.json", "context.json", "timing.json", "material-staging.json",
           "host-prerequisite.json", "context-after-prerequisites.json", "controller-observation.json"}
JOB = "current-onboarding-delegated-v3"
REQUIRED_STEPS = (
    "Bind Root request before checkout or privileged entry",
    "Checkout the exact closed Source at GITHUB_WORKSPACE",
    "Checkout the separate Root-pinned Main launcher",
    "Move trusted code outside the closed Source and invoke direct argv",
    "Retain only selected public context and controller receipts",
)
RETAINED = "CHECKPOINT_NATIVE248_TRANSPORT_RETAINED"
DIAGNOSTIC = "HOLD_NATIVE248_TRANSPORT_DIAGNOSTIC"
UNRETAINED = "HOLD_NATIVE248_CHECKPOINT_NOT_RETAINED"
CLOSED = dict(closed=True, scope_absent=True, input_storage_absent=True, **C.FINAL)
REASONS = {"DEADLINE_EXHAUSTED", "VALIDATION_REFUSED", "REQUIRED_FIELD_MISSING",
           "OS_OPERATION_FAILED", "CHILD_ENTRY_REFUSED", "INTERRUPTED", "UNEXPECTED_FAILURE"}
SUPERVISION = dict(group_census="EMPTY_TWICE", output_complete=True, ownership="REAPED", reaped=True,
                   signals_observed=False, supervisor_error=False, timeout=False)
UNKNOWN_FAILURE = (None, dict(status="NOT_OBSERVED"), dict(status="UNAVAILABLE_OR_UNSAFE"))
PHASES = (
    "git_main", "git_source", "metadata", "context", "timing", "material_grant", "material_open",
    "material_stage", "material_retirement", "material_receipt", "material_fields", "assembly_selection",
    "assembly", "assembly_output", "input_intake", "staging_retention", "post_staging_tools",
    "prerequisites", "context_refresh", "controller", "controller_result", "material_cleanup", "complete",
)


def final(value):
    C.need(type(value) is dict and all(key in value and value[key] is item for key, item in C.FINAL.items()),
           "HOLD_TERMINAL_ACCEPTANCE_FIELDS")


def matches(value, expected, code):
    C.need(type(value) is dict and all(key in value and C.same(value[key], item)
                                       for key, item in expected.items()), code)


def fields(value, expected):
    C.shape(value, expected, "HOLD_TERMINAL_FIELDS")


def untrusted_json(raw, *, cap=MIB, canonical=False):
    def unique(pairs):
        result = dict(pairs)
        C.need(len(result) == len(pairs), "HOLD_TERMINAL_DUPLICATE_JSON")
        return result

    def finite(text):
        value = float(text)
        C.need(math.isfinite(value), "HOLD_TERMINAL_NONFINITE_JSON")
        return value

    C.need(type(raw) is bytes and 0 < len(raw) <= cap, "HOLD_TERMINAL_JSON_BOUND")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_float=finite,
                           parse_constant=lambda _: C.need(False, "HOLD_TERMINAL_NONFINITE_JSON"))
    except RecursionError as error:
        raise ValueError("HOLD_TERMINAL_JSON_DEPTH") from error
    C.need(type(value) is dict, "HOLD_TERMINAL_JSON_OBJECT")
    no_item = object()
    readers = [iter((value,))]
    while readers:
        item = next(readers[-1], no_item)
        if item is no_item:
            readers.pop()
        elif type(item) in (dict, list):
            C.need(len(readers) <= 48, "HOLD_TERMINAL_JSON_DEPTH")
            readers.append(iter(item.values() if type(item) is dict else item))
    if canonical:
        offset = 0
        for text in json.JSONEncoder(sort_keys=True, indent=2, allow_nan=False).iterencode(value):
            part = text.encode()
            C.need(raw.startswith(part, offset), "HOLD_TERMINAL_NONCANONICAL_JSON")
            offset += len(part)
        C.need(raw[offset:] == b"\n", "HOLD_TERMINAL_NONCANONICAL_JSON")
    return value


def inventory(value, key):
    rows = value.get(key)
    count = value.get("total_count")
    C.need(type(rows) is list and C.integer(count, 1, 100) and count == len(rows)
           and all(type(row) is dict and C.integer(row.get("id"), 1) for row in rows)
           and len({row["id"] for row in rows}) == len(rows), "HOLD_TERMINAL_INVENTORY")
    return rows


def terminal_metadata(operands, ids, case):
    run, jobs, artifacts = (untrusted_json(operands[key]) for key in ("run", "jobs", "artifacts"))
    source = case["source"]["cid"]
    branch = case["source"]["ref"].removeprefix("refs/heads/")
    matches(run, dict(id=ids["run"], head_sha=source, head_branch=branch, run_attempt=1, path=C.WORKFLOW,
                      workflow_id=case["workflow_id"], event="workflow_dispatch", status="completed"),
            "HOLD_TERMINAL_RUN")
    conclusion = run.get("conclusion")
    C.need(conclusion in ("failure", "success"), "HOLD_TERMINAL_RUN_CONCLUSION")
    repository = run.get("repository")
    head = run.get("head_repository")
    matches(repository, dict(full_name=C.REPOSITORY), "HOLD_TERMINAL_REPOSITORY")
    C.need(C.integer(repository.get("id"), 1), "HOLD_TERMINAL_REPOSITORY_ID")
    matches(head, dict(id=repository["id"], full_name=C.REPOSITORY), "HOLD_TERMINAL_HEAD_REPOSITORY")
    rows = inventory(jobs, "jobs")
    C.need(len(rows) == 1, "HOLD_TERMINAL_JOB_ROSTER")
    job = rows[0]
    matches(job, dict(id=ids["job"], run_id=ids["run"], run_attempt=1, name=JOB, head_sha=source,
                      status="completed", conclusion=conclusion, labels=["ubuntu-24.04-arm"]),
            "HOLD_TERMINAL_JOB")
    steps = job.get("steps")
    C.need(type(steps) is list and 0 < len(steps) <= 100 and
           all(type(row) is dict and type(row.get("name")) is str and C.integer(row.get("number"), 1)
               for row in steps) and len({row["number"] for row in steps}) == len(steps),
           "HOLD_TERMINAL_STEPS")
    numbers = []
    for name in REQUIRED_STEPS:
        selected = [row for row in steps if row["name"] == name]
        C.need(len(selected) == 1, "HOLD_TERMINAL_STEP_ROSTER")
        matches(selected[0], dict(status="completed",
                                  conclusion=conclusion if name == REQUIRED_STEPS[3] else "success"),
                "HOLD_TERMINAL_STEP_RESULT")
        numbers.append(selected[0]["number"])
    C.need(sorted(numbers) == numbers, "HOLD_TERMINAL_STEP_ORDER")
    rows = inventory(artifacts, "artifacts")
    C.need(len(rows) == 1, "HOLD_TERMINAL_ARTIFACT_ROSTER")
    artifact = rows[0]
    matches(artifact, dict(id=ids["artifact"], name=f"current-onboarding-control-{ids['run']}-1",
                           expired=False, size_in_bytes=len(operands["archive"])),
            "HOLD_TERMINAL_ARTIFACT")
    matches(artifact.get("workflow_run"),
            dict(id=ids["run"], repository_id=repository["id"], head_repository_id=repository["id"],
                 head_sha=source, head_branch=branch), "HOLD_TERMINAL_ARTIFACT_RUN")
    matches(artifact, dict(digest="sha256:" + C.pin(operands["archive"])["sha256"]),
            "HOLD_TERMINAL_ARTIFACT_DIGEST")
    runner = job.get("runner_name")
    C.need(type(runner) is str and 0 < len(runner) <= 200 and all(ord(char) >= 32 for char in runner),
           "HOLD_TERMINAL_RUNNER")
    return conclusion, runner


def public_archive(raw):
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            members = archive.infolist()
            names = [row.filename for row in members]
            C.need("launcher-report.json" in names and set(names) <= MEMBERS and len(set(names)) == len(names),
                   "HOLD_TERMINAL_ARCHIVE_ROSTER")
            C.need(sum(row.file_size for row in members) <= C.LIMITS["control_bytes"],
                   "HOLD_TERMINAL_ARCHIVE_EXPANSION")
            files = {}
            for row in members:
                mode = row.external_attr >> 16
                C.need(row.orig_filename == row.filename and not row.is_dir() and not row.external_attr & 0x10
                       and stat.S_IFMT(mode) in (0, stat.S_IFREG) and row.flag_bits & ~0x80e == 0
                       and row.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                       and 0 < row.file_size <= C.LIMITS["control_bytes"], "HOLD_TERMINAL_ARCHIVE_MEMBER")
                with archive.open(row) as stream:
                    body = stream.read(row.file_size + 1)
                C.need(len(body) == row.file_size, "HOLD_TERMINAL_ARCHIVE_BODY")
                files[row.filename] = body
    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, zlib.error) as error:
        raise ValueError("HOLD_TERMINAL_ARCHIVE_FORMAT") from error
    return files


def diagnostic_reader(reader_raw):
    """Compile precisely the canonical Reader's memory-only diagnostic predicates."""
    functions = {"need", "encoded", "pin", "decode", "whole", "same", "receipt", "transport_packet",
                 "diagnostic_packet", "diagnostic_failure_record"}
    constants = {"MAX_FILE", "MAX_SOURCE", "DIAGNOSTIC_PHASES", "DIAGNOSTIC_FINAL",
                 "TRANSPORT_PHASES", "TRANSPORT_OPERATIONS", "TRANSPORT_ERRORS", "TRANSPORT_ERRNOS"}
    selected = []
    for node in ast.parse(reader_raw).body:
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            C.need(not node.decorator_list, "HOLD_TERMINAL_READER_CLOSURE")
            functions.remove(node.name)
            selected.append(node)
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id in constants):
            constants.remove(node.targets[0].id)
            selected.append(node)
    C.need(not functions and not constants, "HOLD_TERMINAL_READER_CLOSURE")
    scope = dict(hashlib=hashlib, json=json, re=re)
    exec(compile(ast.Module(body=selected, type_ignores=[]), "<pinned-Source205-Reader>", "exec"), scope)
    return scope["diagnostic_failure_record"]


def context_binding(context, case, request, delegation, ids, runner):
    final(context)
    binding = dict(attempt=1, job=str(ids["job"]), run=str(ids["run"]), ref=case["source"]["ref"],
                   source=case["source"]["cid"], source_lock=case["source"]["source_map"])
    matches(context, dict(schema=4, kind="DELEGATED_CURRENT_ONBOARDING_CONTEXT_V4",
                          issuer="DELEGATED_CONTEXT_PROGRAM_V4", stage="backend", operation=C.OPERATION,
                          nonce=case["nonce"], binding=binding, delegation_pin=request["delegation_pin"],
                          policy_pin={k: delegation["policy"][k] for k in ("bytes", "sha256")},
                          program_pin={k: delegation["programs"]["context"][k] for k in ("bytes", "sha256")}),
            "HOLD_TERMINAL_CONTEXT")
    source_root = context.get("source_root")
    C.need(type(source_root) is str and re.fullmatch(r"/[A-Za-z0-9_./-]{1,1023}", source_root)
           and str(PurePosixPath(source_root)) == source_root and ".." not in PurePosixPath(source_root).parts,
           "HOLD_TERMINAL_CONTEXT_ROOT")
    if C.source206_case(case):
        raw = request["material_staging"]["assembler_request"]["json"].encode()
        approval = C.decode(C.decode(raw)["test_trust"]["Root_admission"]["json"].encode())
        C.need(approval["public_key"]["path"] == source_root + "/" + C.S.TEST_PUBLIC_KEY["member"],
               "HOLD_TERMINAL_TEST_APPROVAL_SOURCE_ROOT")
    hosted = context.get("hosted")
    matches(hosted, dict(GITHUB_ACTIONS="true", GITHUB_JOB="current", GITHUB_REF=binding["ref"],
                         GITHUB_REPOSITORY=C.REPOSITORY, GITHUB_RUN_ATTEMPT="1", GITHUB_RUN_ID=binding["run"],
                         GITHUB_SHA=binding["source"], GITHUB_WORKFLOW_REF=delegation["hosted"]["workflow_ref"],
                         GITHUB_WORKFLOW_SHA=binding["source"], GITHUB_WORKSPACE=source_root,
                         RUNNER_ARCH="ARM64", RUNNER_ENVIRONMENT="github-hosted", RUNNER_OS="Linux",
                         RUNNER_NAME=runner),
            "HOLD_TERMINAL_HOSTED")
    observed = context.get("observed_epoch")
    C.need(C.integer(observed, case["issued_epoch"], case["expires_epoch"] - 1), "HOLD_TERMINAL_CONTEXT_TIME")
    repo_url = "https://api.github.com/repos/" + C.REPOSITORY
    run_url = repo_url + "/actions/runs/" + binding["run"]
    response = context.get("jobs_response")
    fields(response, ("url", "status", "body", "received_epoch", "elapsed_ms"))
    matches(response, dict(url=run_url + "/jobs?filter=latest&per_page=100", status=200),
            "HOLD_TERMINAL_CONTEXT_JOBS_RESPONSE")
    C.need(C.integer(response["received_epoch"], max(0, observed - 30), observed)
           and C.integer(response["elapsed_ms"], 0, 30000) and type(response["body"]) is str,
           "HOLD_TERMINAL_CONTEXT_JOBS_TIMING")
    body = response["body"].encode()
    C.need(C.pin(body) == C.whole(context.get("jobs_response_pin"), MIB), "HOLD_TERMINAL_CONTEXT_JOBS_PIN")
    jobs = inventory(untrusted_json(body), "jobs")
    C.need(len(jobs) == 1, "HOLD_TERMINAL_CONTEXT_JOB_ROSTER")
    matches(jobs[0], dict(id=ids["job"], run_id=ids["run"], run_attempt=1, name=JOB, head_sha=binding["source"],
                         runner_name=runner, status="in_progress", conclusion=None, run_url=run_url,
                         url=repo_url + "/actions/jobs/" + binding["job"],
                         html_url="https://github.com/" + C.REPOSITORY + "/actions/runs/" +
                         binding["run"] + "/job/" + binding["job"]), "HOLD_TERMINAL_CONTEXT_JOB")
    return binding


def shared_timing(value, context, case, request_pin):
    final(value)
    matches(value, dict(schema=3, kind=C.TIMING["kind"], whole_budget_seconds=7560,
                        request_pin=request_pin, delegation_pin=context["delegation_pin"],
                        binding=context["binding"], policy_pin=context["policy_pin"],
                        expires_epoch=case["expires_epoch"]), "HOLD_TERMINAL_TIMING")
    started, deadline = (value.get(key) for key in ("started_monotonic", "deadline_monotonic"))
    C.need(all(type(x) in (int, float) and 0 < x < 2**53 and math.isfinite(x) for x in (started, deadline))
           and started < deadline <= started + 7560, "HOLD_TERMINAL_TIMING_WINDOW")
    C.whole(value.get("boot_pin"))


def staging_checkpoint(public, report, context, timing, case, request, delegation):
    fields(public, ("receipt", "staging_scope_retirement", "wrapper_pin", "intake", *C.FINAL))
    final(public)
    receipt = public["receipt"]
    fields(receipt, ("status", "binding", "domain", "storage_domain", "grant_pin", "policy_pin",
                     "whole_deadline_monotonic", "Root_expires_epoch", "physical_scope_end_monotonic",
                     "commands", "verified_files", "verified_bytes", "cache", "materialization",
                     "cache_created_files", "provider_validation_archive_copies",
                     "caller_must_prove_scope_retirement_and_absence", *C.FINAL))
    final(receipt)
    material = request["material_staging"]
    grant = C.decode(material["grant_json"].encode())
    unit = "cachy-current-materials-" + case["nonce"]
    scope = unit + ".scope"
    out = grant["storage_parent"] + "/" + unit
    matches(receipt, dict(status="COMPLETE517_HOSTED_CACHE_DATA_ONLY", binding=context["binding"],
                          grant_pin=material["grant_pin"], policy_pin=context["policy_pin"],
                          Root_expires_epoch=case["expires_epoch"], verified_files=517, cache_created_files=517,
                          provider_validation_archive_copies=0, caller_must_prove_scope_retirement_and_absence=True,
                          cache=out + "/cache",
                          materialization="UNCHANGED_ORIGINAL_SEEDS_AND_FIXED_PINNED_DOWNLOADS"),
            "HOLD_TERMINAL_COMPLETE517")
    end, deadline = (receipt[key] for key in ("physical_scope_end_monotonic", "whole_deadline_monotonic"))
    C.need(type(end) in (int, float) and type(deadline) in (int, float)
           and timing["started_monotonic"] < end <= deadline <= timing["deadline_monotonic"] + .1,
           "HOLD_TERMINAL_MATERIAL_SCOPE_WINDOW")
    domain = receipt["domain"]
    fields(domain, ("cgroup", "pid", "starttime", "limits", "Root_acceptance"))
    matches(domain, dict(cgroup="/system.slice/" + scope, Root_acceptance=None,
                         limits=C.RESOURCES["scope_limits"]), "HOLD_TERMINAL_MATERIAL_SCOPE")
    C.need(C.integer(domain["pid"], 1) and C.integer(domain["starttime"], 1),
           "HOLD_TERMINAL_MATERIAL_SCOPE_OWNER")
    storage = receipt["storage_domain"]
    fields(storage, ("path", "device", "total_bytes", "total_nodes", "free_bytes", "free_nodes", "Root_acceptance"))
    matches(storage, dict(path=grant["storage_parent"], Root_acceptance=None),
            "HOLD_TERMINAL_MATERIAL_STORAGE")
    C.need(C.integer(storage["device"], 1) and C.integer(storage["total_bytes"], 6 << 30, 8 << 30) and
           C.integer(storage["free_bytes"], 6 << 30, storage["total_bytes"]) and
           C.integer(storage["total_nodes"], 18000, 20000) and
           C.integer(storage["free_nodes"], 18000, storage["total_nodes"]), "HOLD_TERMINAL_MATERIAL_STORAGE")
    retire = public["staging_scope_retirement"]
    fields(retire, ("natural", "scope_absent", "scope", "supervision_pin", "scope_absence_pin", *C.FINAL))
    final(retire)
    matches(retire, dict(natural=True, scope_absent=True, scope=scope,
                         scope_absence_pin=C.pin(C.encoded(dict(scope=scope, absent_twice=True)))),
            "HOLD_TERMINAL_STAGING_RETIREMENT")
    C.whole(retire["supervision_pin"], MIB)
    C.whole(public["wrapper_pin"], 4 * MIB)
    intake = public["intake"]
    fields(intake, ("files", "bytes"))
    C.need(C.same(intake, report.get("intake")) and C.integer(intake["files"], 517, C.LIMITS["reference_files"])
           and C.integer(intake["bytes"], 1, C.LIMITS["reference_bytes"])
           and C.integer(receipt["verified_bytes"], 1, intake["bytes"]), "HOLD_TERMINAL_STAGING_INTAKE")
    commands = receipt["commands"]
    C.need(type(commands) is list and len(commands) == 27, "HOLD_TERMINAL_COMMAND_ROSTER")
    for row in commands:
        fields(row, ("argv", "natural", "Root_acceptance"))
        matches(row, dict(natural=True, Root_acceptance=None), "HOLD_TERMINAL_COMMAND_RETIREMENT")
        C.need(type(row["argv"]) is list and 0 < len(row["argv"]) <= 32
               and all(type(arg) is str and 0 < len(arg) <= 4096 and not any(ord(c) < 32 for c in arg)
                       for arg in row["argv"]), "HOLD_TERMINAL_COMMAND_ARGV")
    scope_command, public_command, native_command = (row["argv"] for row in commands[:3])
    C.need(scope_command[0] in ("/usr/bin/systemctl", "/usr/sbin/systemctl") and
           scope_command[1:] == ["show", scope, "--no-pager",
                                 "--property=RuntimeMaxUSec,ActiveEnterTimestampMonotonic,ControlGroup"],
           "HOLD_TERMINAL_MATERIAL_SCOPE_PROBE")
    C.need(len(native_command) == 11 and re.fullmatch(r"/usr/(bin|sbin)/python3(?:\.[0-9]{1,2})?", native_command[0])
           and C.hexid(native_command[8], 64), "HOLD_TERMINAL_NATIVE248_COMMAND")
    expected = [native_command[0], "-I", "-B", context["source_root"] + "/" +
                delegation["programs"]["materials_stager"]["member"], "transport", "--request",
                out + "/child-request.json", "--request-sha256", native_command[8], "--which", "native248"]
    C.need(native_command == expected and
           public_command == [*expected[:-1], "public14"], "HOLD_TERMINAL_NATIVE248_COMMAND")
    return C.pin(C.encoded(commands[2]))


def child_close(report, stage):
    after = report.get("material_children_after_cleanup")
    matches(after, dict(state="CLOSED", stage_submitted=True), "HOLD_TERMINAL_DIAGNOSTIC_CLOSED")
    children = after.get("children")
    C.need(type(children) is list and len(children) == 2 and C.same(children[0], stage),
           "HOLD_TERMINAL_DIAGNOSTIC_CLOSED_CHILDREN")
    close = children[1]
    matches(close, dict(kind="CLOSE", natural_success=True, scope_absent_twice=True, output_pin=C.pin(b"")),
            "HOLD_TERMINAL_DIAGNOSTIC_CLOSE")
    matches(close.get("supervision"), dict(exit=0, **SUPERVISION), "HOLD_TERMINAL_DIAGNOSTIC_CLOSE")
    C.need(C.same(report.get("material_domain_cleanup"), CLOSED), "HOLD_TERMINAL_MATERIAL_CLEANUP")


def material_stage_child(before, state, success):
    matches(before, dict(state=state, stage_submitted=True), "HOLD_TERMINAL_DIAGNOSTIC_STATE")
    children = before.get("children")
    C.need(type(children) is list and len(children) == 1, "HOLD_TERMINAL_DIAGNOSTIC_CHILDREN")
    stage = children[0]
    matches(stage, dict(kind="STAGE", natural_success=success, scope_absent_twice=success, output_pin=C.pin(b"")),
            "HOLD_TERMINAL_DIAGNOSTIC_CHILD")
    matches(stage.get("supervision"), dict(exit=0 if success else 2, **SUPERVISION),
            "HOLD_TERMINAL_DIAGNOSTIC_STAGE")
    return stage


def stage_diagnostic(report, original_context_pin, reader_raw):
    before = report.get("material_failure_before_cleanup")
    if type(before) is not dict:
        return None
    failure = before.get("source_failure")
    if failure in UNKNOWN_FAILURE:
        return None
    C.need(type(failure) is dict and "record_pin" in failure, "HOLD_TERMINAL_DIAGNOSTIC_PROJECTION")
    proof = dict(failure)
    record_pin = proof.pop("record_pin")
    raw = C.encoded(proof)
    C.need(C.pin(raw) == C.whole(record_pin, 4096), "HOLD_TERMINAL_DIAGNOSTIC_RECORD_PIN")
    record = diagnostic_reader(reader_raw)(raw)
    C.need(record["context_pin"] == original_context_pin, "HOLD_TERMINAL_DIAGNOSTIC_CONTEXT")
    packet = record["packet"]
    if packet is None:
        return None
    C.need(packet["schema"] == 2, "HOLD_TERMINAL_DIAGNOSTIC_VERSION")
    stage = material_stage_child(before, "HOLD_CLOSEONLY", False)
    matches(stage, dict(output_pin=record["stdout_pin"], stderr_pin=record["stderr_pin"]),
            "HOLD_TERMINAL_DIAGNOSTIC_STREAMS")
    child_close(report, stage)
    return dict(phase=packet["phase"], reason=packet["reason"], command_ordinal=packet["command_ordinal"],
                transport=packet["transport"], record_pin=record_pin)


def verify(operands, expected_pins, *, ids, core_raw, profile_raw, reader_raw, successor=False):
    """Verify the independently selected immutable bytes. Raises HOLD on inconsistent evidence."""
    fields(operands, CAPS)
    fields(expected_pins, CAPS)
    fields(ids, ("run", "job", "artifact"))
    C.need(all(C.integer(value, 1) for value in ids.values()), "HOLD_TERMINAL_IDS")
    for name, cap in CAPS.items():
        C.need(type(operands[name]) is bytes and len(operands[name]) <= cap
               and C.pin(operands[name]) == C.whole(expected_pins[name], cap), "HOLD_TERMINAL_OPERAND_PIN")
    case = untrusted_json(operands["case"], cap=C.MAX_BYTES, canonical=True)
    C.need(C.integer(case.get("issued_epoch")) and successor == C.source206_case(case), "HOLD_TERMINAL_CASE")
    C.validate_case(case, case["issued_epoch"])
    C.need(case["stage"] == "backend" and C.same(case["pins"]["request"], expected_pins["request"]),
           "HOLD_TERMINAL_CASE_REQUEST")
    profile = C.S.PROFILE if successor else C.PROFILE
    reader = C.S.READER if successor else dict(member=C.READER, **READER)
    reader_pin = {key: reader[key] for key in ("bytes", "sha256")}
    C.need(type(profile_raw) is bytes and len(profile_raw) == profile["bytes"] and C.pin(profile_raw) == profile,
           "HOLD_TERMINAL_PROFILE")
    C.need(type(reader_raw) is bytes and len(reader_raw) == reader["bytes"] and C.pin(reader_raw) == reader_pin
           and C.same(case["main"]["reader"], reader), "HOLD_TERMINAL_READER")
    request = C.validate_request(operands["request"], case, core_raw, C.decode(profile_raw))
    delegation = C.decode(request["delegation_json"].encode())
    conclusion, runner = terminal_metadata(operands, ids, case)
    bodies = public_archive(operands["archive"])
    public = {name: untrusted_json(body, cap=C.LIMITS["control_bytes"], canonical=True)
              for name, body in bodies.items()}
    report = public["launcher-report.json"]
    final(report)
    matches(report, dict(request_pin=expected_pins["request"],
                         status="HOLD" if conclusion == "failure" else "DELEGATED_HOSTED_CONTROLLER_RETIRED_DATA_ONLY"),
            "HOLD_TERMINAL_LAUNCHER")
    C.need("material_cleanup_failure" not in report and "material_cleanup_diagnostic" not in report,
           "HOLD_TERMINAL_MATERIAL_CLEANUP")
    failure = report.get("failure")
    if conclusion == "failure":
        fields(failure, ("phase", "reason"))
        C.need(failure["phase"] in (*PHASES, "UNKNOWN") and failure["reason"] in tuple(REASONS),
               "HOLD_TERMINAL_LAUNCHER_FAILURE")
    else:
        C.need("failure" not in report and C.same(report.get("cleanup"), dict(owned_storage_absent=True, error_count=0)),
               "HOLD_TERMINAL_LAUNCHER_CLEANUP")
    context = public.get("context.json")
    timing = public.get("timing.json")
    cleanup = "NOT_RETAINED"
    if "material_domain_cleanup" in report:
        C.need(C.same(report["material_domain_cleanup"], CLOSED), "HOLD_TERMINAL_MATERIAL_CLEANUP")
        if failure is not None:
            matches(report.get("material_children_after_cleanup"), dict(state="CLOSED"),
                    "HOLD_TERMINAL_MATERIAL_CLEANUP")
        cleanup = "CLOSED_SCOPE_AND_INPUT_STORAGE_ABSENT"
    else:
        C.need("material_children_after_cleanup" not in report, "HOLD_TERMINAL_MATERIAL_CLEANUP")
    if context is not None:
        binding = context_binding(context, case, request, delegation, ids, runner)
        matches(report, dict(binding=binding), "HOLD_TERMINAL_LAUNCHER_BINDING")
    else:
        C.need("binding" not in report and timing is None and len(public) == 1, "HOLD_TERMINAL_MISSING_CONTEXT")
    if timing is not None:
        shared_timing(timing, context, case, expected_pins["request"])
    if "context-after-prerequisites.json" in public:
        context_binding(public["context-after-prerequisites.json"], case, request, delegation, ids, runner)
    staging = public.get("material-staging.json")
    status, command, diagnostic = UNRETAINED, None, None
    if staging is not None:
        C.need(context is not None and timing is not None and cleanup != "NOT_RETAINED" and
               (failure is None or failure["phase"] in PHASES[16:]), "HOLD_TERMINAL_CHECKPOINT_CLEANUP")
        if failure is not None:
            before = report.get("material_failure_before_cleanup")
            stage = material_stage_child(before, "RETAINED_FOR_CONSUMERS", True)
            C.need(before.get("source_failure") in UNKNOWN_FAILURE, "HOLD_TERMINAL_CONTRADICTORY_STAGING")
            child_close(report, stage)
        else:
            C.need(not {"material_failure_before_cleanup", "material_children_after_cleanup"} & report.keys(),
                   "HOLD_TERMINAL_CONTRADICTORY_STAGING")
        command = staging_checkpoint(staging, report, context, timing, case, request, delegation)
        status = RETAINED
    elif conclusion == "failure":
        context_pin = C.pin(bodies["context.json"]) if context is not None else None
        diagnostic = stage_diagnostic(report, context_pin, reader_raw)
        if diagnostic is not None and failure["phase"] == "material_stage" and (
                diagnostic["phase"], diagnostic["reason"], diagnostic["command_ordinal"]) == (
                    "TRANSPORT_NATIVE248", "COMMAND_FAILED", 2):
            status = DIAGNOSTIC
    else:
        C.need(False, "HOLD_TERMINAL_SUCCESS_WITHOUT_STAGING")
    return dict(status=status, stage="backend", attempt=1, source=case["source"]["cid"],
                ref=case["source"]["ref"], repository=C.REPOSITORY, workflow_id=case["workflow_id"], **ids,
                workflow_conclusion=conclusion, request_pin=expected_pins["request"],
                original_archive_pin=expected_pins["archive"], material_cleanup=cleanup,
                launcher_failure=failure, material_failure_diagnostic=diagnostic,
                native248_command_pin=command, transport_body_replayed=False,
                native248_transport_cause=None if status == RETAINED else
                ("FINITE_DIAGNOSTIC_RETAINED" if status == DIAGNOSTIC and diagnostic["transport"] is not None
                 else "UNKNOWN_NOT_RETAINED"),
                **C.FINAL)


def read_local(path, cap):
    C.need(type(path) is str and Path(path).is_absolute() and str(Path(path).resolve()) == path,
           "HOLD_TERMINAL_LOCAL_PATH")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        before = os.fstat(stream.fileno())
        C.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap,
               "HOLD_TERMINAL_LOCAL_REGULAR_FILE")
        raw = stream.read(before.st_size + 1)
        after = os.fstat(stream.fileno())
        C.need(len(raw) == before.st_size and
               (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink) ==
               (before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink),
               "HOLD_TERMINAL_LOCAL_CHANGED_FILE")
        return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", required=True)
    parser.add_argument("--selection-sha256", required=True)
    args = parser.parse_args()
    try:
        raw = read_local(args.selection, C.MAX_BYTES)
        C.need(C.hexid(args.selection_sha256, 64) and C.pin(raw)["sha256"] == args.selection_sha256,
               "HOLD_TERMINAL_SELECTION_PIN")
        selection = untrusted_json(raw, cap=C.MAX_BYTES, canonical=True)
        fields(selection, ("schema", "kind", "ids", "inputs"))
        C.need(type(selection["schema"]) is int and selection["schema"] == 1
               and selection["kind"] in (SELECTION, SUCCESSOR_SELECTION), "HOLD_TERMINAL_SELECTION")
        caps = CAPS | dict(core=MIB, profile=C.MAX_BYTES, reader=MIB)
        fields(selection["inputs"], caps)
        data, pins = {}, {}
        for key, cap in caps.items():
            row = selection["inputs"][key]
            fields(row, ("path", "pin"))
            pins[key] = C.whole(row["pin"], cap)
            data[key] = read_local(row["path"], pins[key]["bytes"])
            C.need(C.pin(data[key]) == pins[key], "HOLD_TERMINAL_LOCAL_PIN")
        result = verify({key: data[key] for key in CAPS}, {key: pins[key] for key in CAPS}, ids=selection["ids"],
                        core_raw=data["core"], profile_raw=data["profile"], reader_raw=data["reader"],
                        successor=selection["kind"] == SUCCESSOR_SELECTION)
    except (ValueError, OSError, KeyError, AttributeError, TypeError, RuntimeError) as error:
        reason = str(error) if isinstance(error, ValueError) and re.fullmatch(r"HOLD_[A-Z_0-9]+", str(error)) else None
        result = dict(status="HOLD_TERMINAL_INPUT_REFUSED", reason=reason, **C.FINAL)
        sys.stdout.buffer.write(C.encoded(result))
        return 2
    sys.stdout.buffer.write(C.encoded(result))
    return 0 if result["status"] == RETAINED else 2


if __name__ == "__main__":
    sys.exit(main())
