# SPDX-License-Identifier: MIT
"""Classify the one original Source207 terminal and its retained control evidence."""
import argparse
from datetime import datetime
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import terminal as T

C = T.C
S = C.S207
KIND = "SOURCE207_BACKEND_STAGE_REVIEW_SELECTION_V1"
CORE = {"core": ("launcher", S.CORE), "profile": ("profile", S.PROFILE),
        "reader": ("reader", {k: S.READER[k] for k in ("bytes", "sha256")})}
CAPS = T.CAPS | {"prepost": C.MAX_BYTES, "execution": C.MAX_BYTES}
TERMINALS = {"success", "failure", "cancelled", "timed_out", "startup_failure", "action_required", "stale", "skipped"}
RETIRED = {"exit": 0, "reaped": True, "group_census": "EMPTY_TWICE", "natural": True}


def utc(value):
    C.need(type(value) is str and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value), "HOLD_SOURCE207_UTC")
    return datetime.fromisoformat(value).timestamp()


def packet(path, expected, source_main=None):
    raw = T.read_local(str(path / "PROJECTION.PASS.DATA.json"), C.MAX_BYTES)
    C.need(C.pin(raw) == C.whole(expected), "HOLD_SOURCE207_PACKET_PIN")
    value = C.decode(raw)
    T.matches(value, {"kind": "SOURCE207_STATIC_CONSTRUCTOR_PROJECTION_DATA_V1", "actor_started": False},
              "HOLD_SOURCE207_PACKET_KIND")
    selection = value["selection"]
    T.matches(selection, {"source": {"cid": S.CID, "ref": S.REF}, "workflow_id": S.WORKFLOW_ID},
              "HOLD_SOURCE207_PACKET_SOURCE")
    if source_main is not None:
        C.need(selection["main"] == source_main, "HOLD_SOURCE207_PACKET_MAIN")
    C.need(set(selection["main"]) == {"cid", "tree"} and all(C.hexid(x, 40) for x in selection["main"].values()),
           "HOLD_SOURCE207_PACKET_MAIN")
    result = {}
    for label, (name, pin) in CORE.items():
        C.need(value["static_inputs"][name] == pin, "HOLD_SOURCE207_PACKET_CODE")
        raw = T.read_local(str(path / name), pin["bytes"])
        C.need(C.pin(raw) == pin, "HOLD_SOURCE207_PACKET_CODE")
        result[label] = raw
    return selection, result


def boundary(data, pins, stage_case, execution):
    prepost = C.decode(data["prepost"])
    T.matches(prepost, {"schema": 1, "kind": "ROOT_SOURCE207_BACKEND_PREPOST_V1",
                       "binding": C.binding(stage_case), "case": pins["case"], "request": pins["request"],
                       "once": True, "retry": False, "release": "CLOSE_ONLY"},
              "HOLD_SOURCE207_PREPOST_JOIN")
    C.need(prepost["operands"]["case"] == pins["case"] and prepost["operands"]["request"] == pins["request"]
           and C.integer(prepost["observed_epoch"], stage_case["issued_epoch"], stage_case["expires_epoch"] - 1),
           "HOLD_SOURCE207_PREPOST_OPERANDS")
    T.matches(execution, {"kind": "ROOT_SOURCE207_BACKEND_ONCE_OUTCOME_V1",
                          "status": "ROOT_SOURCE207_ORIGINAL_RUN_DISCOVERED", "prepost": pins["prepost"],
                          "POSTs": 1, "once": True, "retry": False, "release": "CLOSE_ONLY",
                          "native_acceptance": False}, "HOLD_SOURCE207_POST_RECONCILIATION_REQUIRED")
    original = execution["original"]
    T.fields(original, ("run_id", "workflow_id", "source", "ref", "attempt"))
    T.matches(original, {"workflow_id": S.WORKFLOW_ID, "source": S.CID, "ref": S.REF, "attempt": 1},
              "HOLD_SOURCE207_ORIGINAL_DISCOVERY")
    C.need(C.integer(original["run_id"], 1), "HOLD_SOURCE207_ORIGINAL_RUN")
    return original["run_id"], prepost["observed_epoch"]


def metadata(data, run_id, entered):
    run, roster, inventory = (T.untrusted_json(data[name]) for name in ("run", "jobs", "artifacts"))
    branch = S.REF.removeprefix("refs/heads/")
    T.matches(run, {"id": run_id, "status": "completed", "head_sha": S.CID, "head_branch": branch,
                    "run_attempt": 1, "workflow_id": S.WORKFLOW_ID, "path": C.WORKFLOW,
                    "event": "workflow_dispatch"}, "HOLD_SOURCE207_RUN")
    C.need(run["conclusion"] in TERMINALS, "HOLD_SOURCE207_RUN_CONCLUSION")
    ident = run["repository"]["id"]
    C.need(C.integer(ident, 1), "HOLD_SOURCE207_REPOSITORY")
    for name in ("repository", "head_repository"):
        T.matches(run[name], {"id": ident, "full_name": C.REPOSITORY}, "HOLD_SOURCE207_REPOSITORY")
    jobs = T.inventory(roster, "jobs")
    C.need(len(jobs) == 1, "HOLD_SOURCE207_JOB_ROSTER")
    job = jobs[0]
    T.matches(job, {"run_id": run_id, "run_attempt": 1, "head_sha": S.CID, "labels": ["ubuntu-24.04-arm"],
                    "name": T.JOB, "status": "completed", "conclusion": run["conclusion"]}, "HOLD_SOURCE207_JOB")
    times = [utc(obj[key]) for obj,key in ((run,"created_at"),(run,"run_started_at"),(job,"started_at"),
                                           (job,"completed_at"),(run,"updated_at"))]
    C.need(times == sorted(times) and times[0] >= entered - 2, "HOLD_SOURCE207_TERMINAL_TIMES")
    steps = job["steps"]
    C.need(type(steps) is list and 1 <= len(steps) <= 100 and all(
        type(row) is dict and C.integer(row.get("number"), 1) and type(row.get("name")) is str
        for row in steps) and len({row["number"] for row in steps}) == len(steps), "HOLD_SOURCE207_STEPS")
    outcome = {name: [row for row in steps if row["name"] == name] for name in T.REQUIRED_STEPS}
    C.need(all(len(rows) <= 1 for rows in outcome.values()) and
           [rows[0]["number"] for rows in outcome.values() if rows] == sorted(
               rows[0]["number"] for rows in outcome.values() if rows), "HOLD_SOURCE207_STEPS")
    if run["conclusion"] == "success":
        C.need(all(rows and rows[0]["status"] == "completed" and rows[0]["conclusion"] == "success"
                   for rows in outcome.values()), "HOLD_SOURCE207_SUCCESS_STEPS")
    rows = inventory.get("artifacts")
    C.need(type(rows) is list and type(inventory.get("total_count")) is int and
           inventory["total_count"] == len(rows) <= 1, "HOLD_SOURCE207_ARTIFACT_ROSTER")
    artifact = rows[0] if rows else None
    if artifact is not None:
        T.matches(artifact, {"name": f"current-onboarding-control-{run_id}-1", "expired": False},
                  "HOLD_SOURCE207_ARTIFACT_NAME")
        C.need(C.integer(artifact["id"], 1) and C.integer(artifact["size_in_bytes"], 1, T.CAPS["archive"])
               and re.fullmatch(r"sha256:[0-9a-f]{64}", artifact.get("digest") or ""), "HOLD_SOURCE207_ARTIFACT_PIN")
        T.matches(artifact["workflow_run"], {"id": run_id, "repository_id": ident, "head_repository_id": ident,
                                              "head_sha": S.CID, "head_branch": branch}, "HOLD_SOURCE207_ARTIFACT_RUN")
    stages = dict(zip(("request_binding","source_checkout","main_checkout","launcher","public_retention"),
                      (rows[0]["conclusion"] if rows else None for rows in outcome.values()), strict=True))
    return run, job, artifact, stages


def records_in_archive(archive, case, request, verdict):
    bodies = T.public_archive(archive)
    public = {key:T.untrusted_json(raw,cap=C.LIMITS["control_bytes"],canonical=True) for key,raw in bodies.items()}
    report = public["launcher-report.json"]
    d = C.decode(request["delegation_json"].encode())
    nonce = case["nonce"]
    prereq = public.get("host-prerequisite.json")
    completed = report.get("prerequisite_retirement")
    controller = public.get("controller-observation.json")
    result = {"material": verdict["status"], "prerequisite": "NOT_RETAINED", "controller": "NOT_RETAINED",
              "backend_package_pairs": "BACKEND_CAPSULE_AND_ROOT_OPERANDS_NOT_IN_CONTROL_ZIP",
              "runtime_login": "NOT_RUN", "first_usable_login_ready": False}
    if prereq is not None:
        T.final(prereq)
        T.matches(prereq, {"status": "PASS_CI_LIBARCHIVE_TOOLS_PREREQUISITE_ONLY", "binding": report["binding"],
                           "cache_absent": True, "tool_count": 16}, "HOLD_SOURCE207_PREREQUISITE_BODY")
        result["prerequisite"] = "PREREQUISITE_REPORT_ONLY"
        if completed is not None:
            T.matches(completed, RETIRED, "HOLD_SOURCE207_PREREQUISITE_RETIREMENT")
            result["prerequisite"] = "PREREQUISITES_NATURALLY_REAPED_SCOPE_UNVERIFIED"
            scope = report.get("prerequisite_scope_absence")
            fresh = public.get("context-after-prerequisites.json")
            if scope is not None:
                T.matches(scope, {"scope": f"cachy-current-prerequisites-{nonce}.scope",
                                  "absent_twice": True}, "HOLD_SOURCE207_PREREQUISITE_SCOPE")
                result["prerequisite"] = "PREREQUISITES_RETIRED_CONTEXT_REFRESH_NOT_RETAINED"
            if fresh is not None:
                C.need(scope is not None and fresh["binding"] == report["binding"] and
                       fresh["observed_epoch"] >= public["context.json"]["observed_epoch"],
                       "HOLD_SOURCE207_FRESH_PREREQUISITE_CONTEXT")
                result["prerequisite"] = "PREREQUISITES_RETIRED_AND_CONTEXT_REFRESHED"
    if controller is not None:
        T.final(controller)
        T.matches(controller, {"kind": "CURRENT_HOSTED_CONTROLLER_OBSERVATION_V3", "binding": report["binding"],
                               "policy_pin": {k:d["policy"][k] for k in ("bytes","sha256")}}, "HOLD_SOURCE207_CONTROLLER_BODY")
        group = f"/system.slice/cachy-current-controller-{nonce}.scope"
        T.matches(controller["domain"], {"cgroup": group, "limits": C.RESOURCES["scope_limits"]}, "HOLD_SOURCE207_CONTROLLER_DOMAIN")
        T.matches(controller["properties"], {"ControlGroup": group}, "HOLD_SOURCE207_CONTROLLER_DOMAIN")
        C.need(all(C.integer(controller["domain"][key], 1) for key in ("pid", "starttime")) and
               re.fullmatch(r"[1-9][0-9]{0,19}", controller["properties"]["ActiveEnterTimestampMonotonic"]),
               "HOLD_SOURCE207_CONTROLLER_DOMAIN")
        result["controller"] = "CONTROLLER_OBSERVATION_ONLY"
    if verdict["workflow_conclusion"] == "success":
        C.need(controller is not None and result["prerequisite"] == "PREREQUISITES_RETIRED_AND_CONTEXT_REFRESHED",
               "HOLD_SOURCE207_SUCCESS_WITHOUT_PREREQUISITES_AND_CONTROLLER")
        T.matches(report.get("controller_retirement"), RETIRED, "HOLD_SOURCE207_CONTROLLER_RETIREMENT")
        T.matches(report.get("scope_absence"), {"scope": f"cachy-current-controller-{nonce}.scope", "empty_twice": True},
                  "HOLD_SOURCE207_CONTROLLER_SCOPE")
        result["controller"] = "HOSTED_CONTROLLER_RETIRED_DATA_ONLY"
    result["launcher_failure"] = verdict["launcher_failure"]
    result["control_member_pins"] = {name:C.pin(raw) for name,raw in bodies.items()}
    return result


def review(selection):
    T.fields(selection, ("schema", "kind", "packet", "inputs"))
    C.need(type(selection["schema"]) is int and selection["schema"] == 1 and selection["kind"] == KIND,
           "HOLD_SOURCE207_REVIEW_SELECTION")
    refs = selection["inputs"]
    available = set(CAPS) - {"archive"}
    C.need(set(refs) in (available, available|{"archive"}), "HOLD_SOURCE207_REVIEW_INPUT_ROSTER")
    data,pins = {},{}
    for name,row in refs.items():
        T.fields(row, ("path", "pin"))
        pins[name] = C.whole(row["pin"], CAPS[name])
        data[name] = T.read_local(row["path"], pins[name]["bytes"])
        C.need(C.pin(data[name]) == pins[name], "HOLD_SOURCE207_REVIEW_INPUT_PIN")
    case = C.decode(data["case"])
    C.validate_case(case,case["issued_epoch"])
    C.need(C.case_version(case) == 207 and case["stage"] == "backend" and case["pins"]["request"] == pins["request"],
           "HOLD_SOURCE207_CASE_SELECTION")
    p = selection["packet"]
    T.fields(p, ("path","pin"))
    chosen, code = packet(Path(p["path"]),p["pin"],{k:case["main"][k] for k in ("cid","tree")})
    request = C.validate_request(data["request"],case,code["core"],C.decode(code["profile"]))
    execution = C.decode(data["execution"])
    run_id,entered = boundary(data,pins,case,execution)
    run,job,artifact,steps = metadata(data,run_id,entered)
    outcome = dict(status="SOURCE207_TERMINAL_METADATA_ONLY",main=chosen["main"],source=S.CID,
                   run=run_id,job=job["id"],artifact=None if artifact is None else artifact["id"],
                   workflow_id=S.WORKFLOW_ID,workflow_conclusion=run["conclusion"],steps=steps,
                   material="UNVERIFIED",prerequisite="UNVERIFIED",controller="UNVERIFIED",
                   backend_package_pairs="UNVERIFIED",runtime_login="NOT_RUN",first_usable_login_ready=False,
                   request=pins["request"],case=pins["case"],**C.FINAL)
    if "archive" not in data:
        return dict(outcome,original="ABSENT" if artifact is None else "NOT_SUPPLIED")
    C.need(artifact is not None,"HOLD_SOURCE207_UNLISTED_ORIGINAL")
    ids = {"run":run_id,"job":job["id"],"artifact":artifact["id"]}
    verdict = T.verify({k:data[k] for k in T.CAPS},{k:pins[k] for k in T.CAPS},ids=ids,
                       core_raw=code["core"],profile_raw=code["profile"],reader_raw=code["reader"],source_version=207)
    return outcome | records_in_archive(data["archive"],case,request,verdict) | {
        "status":"SOURCE207_ORIGINAL_CONTROL_REPLAY_DATA_ONLY","original":pins["archive"],"checkpoint":verdict}


def fence(event,_):
    if event.startswith(("subprocess.","socket.","os.exec","os.posix_spawn","os.fork","os.system","os.kill")):
        raise RuntimeError("SOURCE207_TERMINAL_FORBIDS_ACTORS_AND_NETWORK")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection",required=True,type=Path)
    parser.add_argument("--selection-sha256",required=True)
    args = parser.parse_args()
    sys.addaudithook(fence)
    try:
        raw = T.read_local(str(args.selection),C.MAX_BYTES)
        C.need(sys.flags.isolated and sys.dont_write_bytecode and C.pin(raw)["sha256"] == args.selection_sha256,
               "HOLD_SOURCE207_EXTERNAL_SELECTION_PIN")
        result = review(C.decode(raw))
    except (OSError,ValueError,KeyError,TypeError,RuntimeError) as error:
        reason = str(error) if isinstance(error,ValueError) and re.fullmatch(r"HOLD_[A-Z_0-9]+",str(error)) else None
        print(C.encoded(dict(status="HOLD_SOURCE207_STAGE_REVIEW_INPUT_REFUSED",reason=reason,**C.FINAL)).decode(),end="")
        raise SystemExit(2)
    print(C.encoded(result).decode(),end="")
