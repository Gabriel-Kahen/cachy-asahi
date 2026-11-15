#!/usr/bin/env python3
"""Re-evaluate this six-case evidence packet; never infer all-file legal rights."""
import argparse
from collections import deque
import hashlib
import json
from pathlib import Path, PurePosixPath
import resource
import signal
import tomllib

HERE = Path(__file__).resolve().parent


def pin(body):
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def blob(body):
    return hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()


def check(body, expected):
    if pin(body) != expected:
        raise ValueError("evidence byte pin changed")


def dependency_paths(packages, roots):
    index = {}
    for item in packages:
        key = (item["name"], item["version"], item.get("source", ""))
        if key in index:
            raise ValueError("ambiguous lock package identity")
        index[key] = item
    def resolve(tokens):
        source = " ".join(tokens[2:]).strip("()") if len(tokens) > 2 else None
        matches = [k for k in index if k[0] == tokens[0] and (len(tokens) == 1 or k[1] == tokens[1])
                   and (source is None or k[2] == source)]
        if len(matches) != 1:
            raise ValueError("ambiguous or missing lock dependency")
        return matches[0]
    paths, pending = {}, deque((resolve(root), []) for root in roots)
    while pending:
        key, parent = pending.popleft()
        if key in paths:
            continue
        if key not in index:
            raise ValueError("lock dependency identity missing")
        paths[key] = parent + [list(key)]
        for text in index[key].get("dependencies", []):
            pending.append((resolve(text.split()), paths[key]))
    return paths


def evaluate_binding(case, captures, tree, grant):
    if tree.get("truncated") is not False:
        raise ValueError("complete exact revision tree required")
    orig = next(r for r in captures if r["path"].endswith("/Cargo.toml.orig"))
    vcs_record = next(r for r in captures if r["path"].endswith("/.cargo_vcs_info.json"))
    if not orig["complete_text"] or not vcs_record["complete_text"]:
        raise ValueError("full manifest and VCS metadata required")
    body = orig["text"].encode()
    check(body, {"bytes": orig["bytes"], "sha256": orig["sha256"]})
    package = tomllib.loads(body.decode())["package"]
    if case["component"] != package["name"] + "-" + package["version"]:
        raise ValueError("exact literal package name/version mismatch")
    vcs = json.loads(vcs_record["text"])
    if vcs["git"]["sha1"] != case["commit"] or vcs["git"].get("dirty") is True:
        raise ValueError("VCS revision mismatch or explicitly dirty source")
    if vcs.get("path_in_vcs") is not None:
        expected_path = (vcs["path_in_vcs"].rstrip("/") + "/" if vcs["path_in_vcs"] else "") + "Cargo.toml"
        if expected_path != case["manifest_path"]:
            raise ValueError("manifest path differs from VCS declaration")
    entries = {r["path"]: r for r in tree["tree"] if r["type"] == "blob"}
    if entries[case["manifest_path"]]["sha"] != blob(body):
        raise ValueError("manifest Git blob mismatch")
    if entries[case["grant_upstream_path"]]["sha"] != blob(grant):
        raise ValueError("license Git blob mismatch")
    if not PurePosixPath(case["manifest_path"]).parent.is_relative_to(PurePosixPath(case["grant_upstream_path"]).parent):
        raise ValueError("license is outside package ancestor scope")
    text = grant.decode()
    if case["manual_grant_kind"] != "MIT complete actual grant/conditions/disclaimer" or not all(
            s in " ".join(text.split()) for s in ("Permission is hereby granted", "copyright notice", "THE SOFTWARE IS PROVIDED")):
        raise ValueError("manual grant review not corroborated by retained text")
    notice = case["manual_named_notice"]
    if case["named_notice_ownership_inferred_from_authors_or_identical_bytes"]:
        raise ValueError("attribution cannot be inferred from authors or equal license bodies")
    if notice and (notice not in text.splitlines() or "copyright" not in notice.lower()
                   or any(token in notice.lower() for token in ("[yyyy]", "[name", "<year", "<owner"))):
        raise ValueError("named notice absent or only template attribution")
    return {"component": case["component"], "name": package["name"], "version": package["version"],
            "commit": case["commit"], "repository": case["repository"], "manifest_path": case["manifest_path"],
            "manifest_bytes": len(body), "manifest_sha256": hashlib.sha256(body).hexdigest(),
            "manifest_git_blob_sha1": blob(body), "source_not_marked_dirty": True,
            "full_vendor_projection_to_Git": "NOT_PERFORMED", "grant_file": case["grant_file"],
            "grant_git_blob_sha1": blob(grant), "grant_text_bound": True, "named_notice": notice,
            "status": "UPSTREAM_ROOT_GRANT_AND_NOTICE_EVIDENCE_COMPLETE" if notice else "UNRESOLVED_ATTRIBUTION",
            "all_file_license_and_legal_acceptance": "HELD"}


def network_summary(receipts):
    if any(not isinstance(r.get("bytes"), int) or r["bytes"] < 0 for r in receipts):
        raise ValueError("invalid body-byte receipt")
    summary = {"HTTP_requests": len(receipts), "response_body_bytes": sum(r["bytes"] for r in receipts)}
    if summary["HTTP_requests"] > 20 or summary["response_body_bytes"] > 8 * 1024**2:
        raise ValueError("followup network budget exceeded")
    return summary


def direct_dependency_evidence(document, names):
    normal = document.get("dependencies", {})
    result = {}
    for name in names:
        declaration = normal.get(name)
        if declaration is None or isinstance(declaration, dict) and declaration.get("optional", False):
            raise ValueError("priority edge is not a non-optional normal dependency")
        result[name] = declaration
    return result


def evaluate(packet_path):
    data = json.loads((HERE / "cases.json").read_text())
    packet_body = packet_path.read_bytes()
    check(packet_body, data["candidate_packet"])
    packet = json.loads(packet_body)
    if not packet["source_pin_verified"]:
        raise ValueError("authenticated complete source packet required")
    prior_body = (HERE.parent / "license-review/review.json").read_bytes()
    check(prior_body, data["prior_review"])
    prior = json.loads(prior_body)
    unresolved = {r["component"] for r in prior["components"] if r["content_review"] == "UNRESOLVED"}
    for filename, expected in data["evidence_files"].items():
        check((HERE / filename).read_bytes(), expected)
    inventory_body = (HERE.parent.parent / "reports/rust.json").read_bytes()
    check(inventory_body, data["root_inventory"])
    inventory = json.loads(inventory_body)
    member = next(r for r in inventory["selected_metadata"] if r["path"] == "Cargo.lock")
    if not inventory["authenticated_source_pin_verified"] or {k: member[k] for k in ("bytes", "sha256")} != data["root_lock_member_pin"]:
        raise ValueError("compiler lock must match prior authenticated archive member")
    lock_body = (HERE / data["root_lock_file"]).read_bytes()
    check(lock_body, data["root_lock_member_pin"])
    paths = dependency_paths(tomllib.loads(lock_body.decode())["package"], data["root_lock_roots"])
    a = json.loads((HERE / "primary-a/requests.json").read_text())["requests"]
    b = json.loads((HERE / "primary-b/requests.json").read_text())["requests"]
    receipts = a + b
    direct = []
    for declaration in data["compiler_priority_manifests"]:
        body = (HERE / declaration["file"]).read_bytes()
        if not any(r.get("HTTP", r.get("status")) == 200 and r["sha256"] == pin(body)["sha256"]
                   and data["rust_source_commit"] in r["url"] for r in receipts):
            raise ValueError("compiler manifest lacks pinned-commit HTTP receipt")
        document = tomllib.loads(body.decode())
        if document["package"]["name"] != declaration["package"]:
            raise ValueError("wrong compiler manifest package")
        direct.append({**declaration, "normal_dependency_declarations": direct_dependency_evidence(document, declaration["dependencies"]),
                       "body_pin": pin(body)})
    cases = []
    for case in data["cases"]:
        if case["component"] not in unresolved or packet["component_statuses"][case["component"]] != "PASS":
            raise ValueError("target must be prior-unresolved and actual checksum-PASS")
        captures = [r for r in packet["candidates"] if r["crate"] == case["component"]]
        tree_body, grant = (HERE / case["tree_file"]).read_bytes(), (HERE / case["grant_file"]).read_bytes()
        if not any(r.get("HTTP", r.get("status")) == 200 and r["sha256"] == pin(tree_body)["sha256"]
                   and "/git/trees/" + case["commit"] in r["url"] for r in receipts):
            raise ValueError("tree bytes lack exact-commit primary HTTP receipt")
        if not any(r.get("HTTP", r.get("status")) == 200 and r["sha256"] == pin(grant)["sha256"] for r in receipts):
            raise ValueError("grant bytes lack primary HTTP receipt")
        result = evaluate_binding(case, captures, json.loads(tree_body), grant)
        target_paths = [path for key, path in paths.items() if key[:2] == (result["name"], result["version"])]
        if len(target_paths) != 1:
            raise ValueError("target not uniquely reachable in compiler lock graph")
        result["compiler_lock_dependency_path"] = target_paths[0]
        result["cfg_features_and_target_selection_evaluated"] = False
        cases.append(result)
    network = network_summary(receipts)
    closed = {r["component"] for r in cases if r["status"] == "UPSTREAM_ROOT_GRANT_AND_NOTICE_EVIDENCE_COMPLETE"}
    return {"schema": 1, "cases": cases, "initial_unresolved": len(unresolved), "batch_reviewed": len(cases),
            "exact_version_commit_grant_bindings": len(cases), "new_scoped_notice_cases_closed": len(closed),
            "remaining_unresolved": len(unresolved - closed), "grant_found_but_attribution_unresolved": len(cases) - len(closed),
            "remaining_components": sorted(unresolved - closed), "network": network,
            "priority": "All six are reachable from rustc-main/rustc_driver in exact authenticated lock graph; direct compiler normal dependencies corroborated; target/cfg/feature resolution not run",
            "direct_compiler_priority_evidence": direct,
            "ruzstd_feature_scope": "Compiler object dependency disables default features and does not explicitly select compression; ruzstd active-feature selection remains unproved",
            "closure_scope": "Exact package-version/commit plus actual upstream root grant and named notice; not all-file coverage or legal acceptance",
            "prior_reports_unchanged": True, "original_recipe_hashes_resolved": 0,
            "original_crate_binary_source_legal_native_acceptance": "HELD", "archives_checkout_payload_execution": "NOT_RUN"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-packet", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.output.resolve().is_relative_to(Path("/tmp")):
        parser.error("new report output must be below /tmp")
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024**2, 128 * 1024**2))
    signal.alarm(30)
    result = evaluate(args.candidate_packet)
    with args.output.open("x") as output:
        json.dump(result, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps({key: result[key] for key in ("new_scoped_notice_cases_closed", "remaining_unresolved", "network")}))
