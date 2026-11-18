# SPDX-License-Identifier: MIT
"""Prepare a source-selected backend checkpoint and delegate live DATA checks to main_route."""

import argparse
import ast
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C = load("source205_main_route", HERE / "contract.py")
R = load("source205_unissued_request", HERE.parent / "request_generation/prepare.py")
STAGE = "backend"
SELECTION = "SOURCE205_BACKEND_DATA_SELECTION_V1"
KIND = "SOURCE205_BACKEND_CHECKPOINT_UNISSUED_V1"
SUCCESSOR_SELECTION = "SOURCE206_BACKEND_DATA_SELECTION_V1"
SUCCESSOR_KIND = "SOURCE206_BACKEND_CHECKPOINT_UNISSUED_V1"
QUALIFICATION_SELECTION = "SOURCE206_BACKEND_QUALIFICATION_SELECTION_V1"
SOURCE196_HOLD = "CONSUMED_HOLD_NATIVE248_TRANSPORT_COMMAND2_FAILURE_AFTER_WORKING_V6_CAPTURE"
CAPS = {role: C.MAX_BYTES for role in ("publication", "source196_close", "profile", "registration",
                                      "launcher", "provenance_operand", "workflow")} | {"reader": 1 << 20}
ROOT_OPERANDS = {
    "case": "Root-selected backend case, fresh scope and nonce, and all six dependent pins",
    "admission": "Root-held reservation with zero active or pending jobs and no exemptions",
    "runtime": "Canonical lease identity, held FD/PIDFD custody, and two converged paginated live job sweeps",
    "registration": "Fresh registered-workflow observation for the exact path and body",
    "readback": "Fresh Source and adopted Main observation with the exact Source205 profile",
    "once": "Exclusive fresh intent after all observations, with no previous POST or uncertainty",
    "request": "Root-issued launch, delegation, material grant, and exact backend assembler input",
}


def observation(raw):
    """Strict JSON for metadata whose producer need not use our canonical encoding."""
    def unique(rows):
        result = dict(rows)
        C.need(len(rows) == len(result), "HOLD_DUPLICATE_OBSERVATION_FIELD")
        return result
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: C.need(False, "HOLD_NONFINITE_OBSERVATION"))
    C.need(type(value) is dict, "HOLD_OBSERVATION_OBJECT")
    return value


def measured_descriptor(member, raw):
    return dict(member=member, **C.pin(raw))


def assembler_template():
    trust = dict(public_key=None, fingerprint=None, Root_admission=None)
    return dict(schema=3, kind="CURRENT_ONBOARDING_INPUT_REQUEST_V3", stage=STAGE, source_date_epoch=None,
                base_lock=None, bootstrap_profile=None, base_materials=None, supplemental_materials=None,
                keyring_materials=None, official_trust=dict(trust), test_trust=dict(trust), products={},
                retention=None)


def prepare(selection, inputs, pins, *, successor=False):
    """Prepare unissued DATA from independently pinned metadata and Main bodies."""
    C.shape(selection, ("source", "main", "workflow_id"), "HOLD_STATIC_SELECTORS")
    C.shape(selection["source"], ("cid", "ref"), "HOLD_STATIC_SOURCE")
    C.shape(selection["main"], ("cid", "tree"), "HOLD_STATIC_MAIN")
    C.need(C.hexid(selection["main"]["tree"], 40) and C.integer(selection["workflow_id"], 1),
           "HOLD_MAIN_TREE_OR_WORKFLOW_ID")
    C.shape(inputs, CAPS, "HOLD_STATIC_INPUT_ROSTER")
    C.shape(pins, CAPS, "HOLD_STATIC_PIN_ROSTER")
    for role, cap in CAPS.items():
        C.whole(pins[role], cap)
        raw = inputs[role]
        C.need(type(raw) is bytes and C.pin(raw) == pins[role], "HOLD_STATIC_" + role.upper() + "_PIN")

    basis = C.S.SOURCE if successor else R.SOURCE205
    reader_member = C.S.READER["member"] if successor else C.READER
    if successor:
        C.need(pins["publication"] == C.S.PUBLICATION
               and selection["source"] == dict(cid=C.S.CID, ref=C.S.REF)
               and selection["workflow_id"] == C.S.WORKFLOW_ID, "HOLD_PUBLISHED_SOURCE206_SELECTOR")
        C.need(pins["reader"] == {field: C.S.READER[field] for field in ("bytes", "sha256")},
               "HOLD_EXACT_SOURCE206_MAIN_READER")

    publication = observation(inputs["publication"])
    prior = observation(inputs["source196_close"])
    workflow = observation(inputs["registration"])
    source, main = selection["source"], selection["main"]
    C.need(publication["status"] == "PASS_COMPLETE_PUBLIC_GIT_READBACK_DATA_ONLY"
           and publication["issuer"] == "Root" and publication["source"] == source["cid"]
           and publication["ref"] == source["ref"] and publication["public_clone_complete"] is True
           and publication["public_blob_tree_join"] is True
           and publication["Root_independent_fresh_ref_commit_recheck"] is True
           and publication["Root_independent_whole_file_mode_recheck"] is True
           and publication["native"] == "NOT RUN"
           and all(C.same(publication[key], basis[key]) for key in ("tree", "files", "bytes"))
           and publication["source_map_sha256"] == basis["source_map"]["sha256"],
           "HOLD_EXACT_PUBLISHED_SOURCE206" if successor else "HOLD_EXACT_PUBLISHED_SOURCE205")
    C.need(prior["status"] == SOURCE196_HOLD and prior["Source"] == R.SOURCE196 and prior["issuer"] == "Root"
           and C.integer(prior["run"], 1) and C.integer(prior["job"], 1)
           and type(prior["attempt"]) is int and prior["attempt"] == 1 and prior["retry"] is False
           and prior["native_acceptance"] is False and prior["underlying_child_cause"] == "UNKNOWN_NOT_RETAINED",
           "HOLD_CONSUMED_SOURCE196_PREDECESSOR")
    C.need(type(workflow["id"]) is int and workflow["id"] == selection["workflow_id"]
           and workflow["path"] == C.WORKFLOW and workflow["state"] == "active"
           and workflow["name"] == "Current onboarding delegated private v3",
           "HOLD_ACTIVE_WORKFLOW_METADATA")
    C.need(pins["launcher"] == pins["provenance_operand"] == C.CORE and pins["workflow"] == C.WORKFLOW_PIN,
           "HOLD_EXACT_CANONICAL_MAIN_ADOPTION")
    parsed = ast.parse(inputs["reader"])
    functions = {node.name for node in parsed.body if isinstance(node, ast.FunctionDef)}
    C.need({"transport_packet", "diagnostic_failure_record", "transport_source_data", "read_delegated_stage"}
           <= functions, "HOLD_MAIN_READER_TRANSPORT_ENTRY_POINTS")
    descriptors = {role: measured_descriptor(path, inputs[role]) for role, path in
                   (("launcher", C.LAUNCHER), ("provenance_operand", R.OPERAND),
                    ("reader", reader_member), ("workflow", C.WORKFLOW))}
    main_selectors = dict(schema=1, kind="EXPLICIT_MAIN_REQUEST_SELECTORS_DATA_ONLY",
                          commit=main["cid"], **descriptors)
    publication_kind = "SOURCE206_PUBLICATION_READBACK_DATA_ONLY" if successor else "SOURCE205_PUBLICATION_READBACK_DATA_ONLY"
    projected = dict(schema=1, kind=publication_kind,
                     status=publication["status"], source=source["cid"], ref=source["ref"],
                     **basis, profile=pins["profile"])
    publication_raw, main_raw = C.encoded(projected), C.encoded(main_selectors)
    request_plan = R.render(published_source_cid=source["cid"], source_ref=source["ref"], main_commit=main["cid"],
                            profile_raw=inputs["profile"], profile_sha256=pins["profile"]["sha256"],
                            publication_raw=publication_raw, publication_sha256=C.pin(publication_raw)["sha256"],
                            main_raw=main_raw, main_sha256=C.pin(main_raw)["sha256"], successor=successor)
    request_plan["request_templates"]["delegation"]["stage"] = STAGE
    R.unissued(request_plan, successor=successor)
    scaffolds = C.templates(successor=successor)
    case = scaffolds["Root-case.TEMPLATE.json"]
    case["source"].update(source)
    case["main"].update(main, **{role: descriptors[role] for role in ("launcher", "reader", "workflow")})
    case.update(workflow_id=selection["workflow_id"], stage=STAGE)
    assembler = assembler_template()
    root_operands = dict(ROOT_OPERANDS)
    if successor:
        assembler["test_trust"].update(public_key=dict(C.S.TEST_PUBLIC_KEY), fingerprint=C.S.TEST_FINGERPRINT)
        root_operands["readback"] = "Fresh exact Source206 and selected Main Reader readback"
    return dict(schema=1, kind=SUCCESSOR_KIND if successor else KIND, status="UNISSUED_BACKEND_CHECKPOINT_DATA",
                dispatch_ready=False, stage=STAGE, native248_command_ordinal=2,
                standalone_transport_stage=False, previous_source196_cause=prior["underlying_child_cause"],
                observations=pins, observed_canonical_main_adoption=True, live_registration_proof=None,
                root_only_operands=root_operands, root_case=case, scaffold=scaffolds,
                assembler=assembler, request_plan=request_plan,
                terminal=dict(kind="ORIGINAL_BOUNDED_CONTROL_ZIP", attempt=1, run=None, job=None, artifact=None,
                              original_pin=None, once=True, retry=False),
                authority=None, native_entered=False, Root_acceptance=None, POSTs=0)


def qualify_backend(checkpoint_raw, checkpoint_pin, operands, expected_pins, *, now, core_raw, profile_raw):
    """Apply the maintained seven-operand contract to the exact prepared backend selector."""
    C.whole(checkpoint_pin, C.MAX_BYTES)
    C.need(type(checkpoint_raw) is bytes and len(checkpoint_raw) <= C.MAX_BYTES
           and C.pin(checkpoint_raw) == checkpoint_pin, "HOLD_STATIC_CHECKPOINT_PIN")
    checkpoint = C.decode(checkpoint_raw)
    C.need(checkpoint["kind"] in (KIND, SUCCESSOR_KIND) and checkpoint["authority"] is None
           and checkpoint["stage"] == STAGE and checkpoint["dispatch_ready"] is False,
           "HOLD_UNISSUED_BACKEND_CHECKPOINT")
    case_raw = operands["case"]
    case_pin = C.whole(expected_pins["case"], C.MAX_BYTES)
    C.need(type(case_raw) is bytes and len(case_raw) <= C.MAX_BYTES and C.pin(case_raw) == case_pin,
           "HOLD_EXTERNAL_CASE_PIN")
    case = C.decode(case_raw)
    C.need((checkpoint["kind"] == SUCCESSOR_KIND) == C.source206_case(case), "HOLD_CHECKPOINT_CASE_KIND")
    for key in ("source", "main", "stage", "workflow_id", "operation", "group", "resources"):
        C.need(C.same(case[key], checkpoint["root_case"][key]), "HOLD_CHECKPOINT_CASE_" + key.upper())
    qualified = C.qualify(operands, expected_pins, now=now, core_raw=core_raw, profile_raw=profile_raw)
    request = qualified["request"]["material_staging"]["assembler_request"]
    assembler = C.decode(request["json"].encode())
    C.need(assembler["products"] == {} and assembler["retention"] is None,
           "HOLD_EXACT_FIRST_BACKEND_PRODUCTS_AND_RETENTION")
    return qualified


def read(path, limit):
    path = Path(path)
    C.need(path.is_absolute() and path.resolve() == path, "HOLD_ORDINARY_LOCAL_FILE_PATH")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        C.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit
               and not before.st_mode & 0o022, "HOLD_ORDINARY_BOUNDED_LOCAL_FILE")
        body = stream.read(limit + 1)
        C.need(len(body) == before.st_size and R.identity(before) == R.identity(os.fstat(fd)) ==
               R.identity(path.lstat()), "HOLD_STABLE_LOCAL_FILE")
        return body


def read_roles(references, caps):
    C.shape(references, caps, "HOLD_LOCAL_FILE_ROSTER")
    inputs, pins = {}, {}
    for role, ref in references.items():
        C.shape(ref, ("path", "bytes", "sha256"), "HOLD_LOCAL_FILE_REFERENCE")
        inputs[role] = read(ref["path"], caps[role])
        pins[role] = C.whole({key: ref[key] for key in ("bytes", "sha256")}, caps[role])
        C.need(C.pin(inputs[role]) == pins[role], "HOLD_LOCAL_FILE_PIN")
    return inputs, pins


def qualify_selection(value, now):
    C.shape(value, ("schema", "kind", "files"), "HOLD_QUALIFICATION_SELECTION_SCHEMA")
    C.need(C.integer(now), "HOLD_EXPLICIT_NOW")
    caps = dict.fromkeys(C.OPERANDS, C.MAX_BYTES) | dict(
        request=C.LIMITS["request_bytes"], checkpoint=C.MAX_BYTES, core=C.MAX_BYTES, profile=C.MAX_BYTES)
    files, pins = read_roles(value["files"], caps)
    C.need(C.decode(files["checkpoint"])["kind"] == SUCCESSOR_KIND, "HOLD_QUALIFICATION_SOURCE206")
    result = qualify_backend(files["checkpoint"], pins["checkpoint"], {key: files[key] for key in C.OPERANDS},
                             {key: pins[key] for key in C.OPERANDS}, now=now,
                             core_raw=files["core"], profile_raw=files["profile"])
    del result["request_raw"], result["request"], result["dispatch_inputs"]
    result["dispatch_body"] = result["dispatch_body"].decode("ascii")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selection", required=True, type=Path)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--now", type=int, help="Root-observed epoch for qualification only")
    args = parser.parse_args()
    C.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__, "HOLD_ISOLATED_PYTHON_REQUIRED")
    raw = read(args.selection, C.MAX_BYTES)
    C.need(re.fullmatch("[0-9a-f]{64}", args.selection_sha256)
           and C.pin(raw)["sha256"] == args.selection_sha256, "HOLD_EXTERNAL_SELECTION_PIN")
    value = C.decode(raw)
    C.need(type(value) is dict and type(value.get("schema")) is int and value["schema"] == 1,
           "HOLD_LOCAL_SELECTION_SCHEMA")
    if value.get("kind") == QUALIFICATION_SELECTION:
        result = qualify_selection(value, args.now)
    else:
        C.shape(value, ("schema", "kind", "selection", "files"), "HOLD_LOCAL_SELECTION_SCHEMA")
        C.need(value["kind"] in (SELECTION, SUCCESSOR_SELECTION) and args.now is None,
               "HOLD_LOCAL_SELECTION_KIND")
        inputs, pins = read_roles(value["files"], CAPS)
        result = prepare(value["selection"], inputs, pins, successor=value["kind"] == SUCCESSOR_SELECTION)
    sys.stdout.buffer.write(C.encoded(result))


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, OSError, TypeError, AttributeError, SyntaxError, RecursionError) as error:
        raise SystemExit(f"Backend checkpoint refused: {error}") from None
