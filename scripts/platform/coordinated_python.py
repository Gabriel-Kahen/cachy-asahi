#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unadopted single-Python-change metadata proposal; never commit or install."""
import argparse
import hashlib
import io
import json
import lzma
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import time

import importlib.util

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("coordinated_transaction", HERE / "transaction.py")
transaction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transaction)
audit, preview = transaction.tuple_audit, transaction.preview
SIGNER = "68B3537F39A313B3E574D06777193F152BDBE6A6"
CERTIFICATE_SHA256 = "6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f"
CHANGE = {"name": "python", "from": "3.14.7-1", "to": "3.14.8-1"}
ROOT = HERE.parents[1]


def need(condition, message):
    if not condition:
        raise ValueError(message)


def binary(reference, maximum):
    need(set(reference) == {"path", "size", "sha256"}, "binary reference fields refused")
    need(type(reference["size"]) is int and 0 < reference["size"] <= maximum, "binary size bound")
    need(isinstance(reference["sha256"], str) and transaction.re.fullmatch(r"[a-f0-9]{64}", reference["sha256"]), "binary checksum refused")
    path = Path(reference["path"])
    need(path.is_absolute(), "absolute binary path required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        need(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "regular binary input required")
        data = stream.read(reference["size"] + 1)
    need(len(data) == reference["size"] and audit.digest(data) == reference["sha256"], "binary size/checksum mismatch")
    return data


def document(reference):
    return audit.load_json(transaction.bound(reference))


def pkginfo(archive):
    class Reader:
        def __init__(self, stream):
            self.stream, self.total, self.started = stream, 0, time.monotonic()

        def read(self, size):
            need(0 <= size <= 1024**2, "archive read bound")
            data = self.stream.read(size)
            self.total += len(data)
            need(self.total <= transaction.DECODED_LIMIT and time.monotonic() - self.started <= 60,
                 "archive decode/deadline bound")
            return data

    selected = None
    with lzma.LZMAFile(io.BytesIO(archive)) as decoded, tarfile.open(fileobj=Reader(decoded), mode="r|") as members:
        for index, member in enumerate(members):
            need(index < 200000 and member.size <= transaction.DECODED_LIMIT, "archive member bound")
            name = member.name.removeprefix("./")
            need(name and not name.startswith("/") and ".." not in Path(name).parts,
                 "archive metadata path refused")
            need(member.sparse is None and not any(k.startswith("GNU.sparse.") for k in member.pax_headers),
                 "sparse Python archive refused")
            if name == ".PKGINFO":
                need(selected is None and member.isfile() and member.size <= 65536, "duplicate/oversized Python PKGINFO")
                selected = members.extractfile(member).read()
    need(selected is not None, "Python PKGINFO absent")
    fields = {}
    for line in selected.decode().splitlines():
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(" = ")
        need(bool(sep), "invalid Python PKGINFO line")
        fields.setdefault(key, []).append(value)
    return selected, fields


def authenticate_python(receipt, contract, core_reference, core_catalog):
    need(type(receipt.get("schema_version")) is int and receipt.get("schema_version") == 1
         and receipt.get("status") == "signed-coordinated-python-candidate-data",
         "Python signed-data receipt scope refused")
    verification = receipt["signature_verification"]
    need(verification.get("status") == "cryptographic-signature-valid"
         and verification.get("primary_fingerprint") == SIGNER
         and verification.get("independent_owner_trust_accepted") is False,
         "Python signature observation/signer gate refused")
    for name in ("archive", "signature"):
        need(receipt[name] == contract["python_" + name], "Python individual receipt/reference mismatch")
    need(all(receipt["source_db"][key] == core_reference[key] for key in ("size", "sha256")),
         "Python/current core DB binding refused")
    transaction.bound(receipt["source_db"])
    need(receipt["public_certificate"]["sha256"] == CERTIFICATE_SHA256, "Python public certificate source pin refused")
    binary(receipt["public_certificate"], 5 * 1024**2)
    binary(contract["python_signature"], 65536)
    archive = binary(contract["python_archive"], 300_000_000)
    metadata = receipt["metadata"]
    transaction.clean(metadata)
    need(metadata["NAME"] == ["python"] and metadata["VERSION"] == [CHANGE["to"]]
         and metadata["ARCH"] == ["aarch64"], "Python candidate identity refused")
    need(metadata.get("FILENAME") == ["python-3.14.8-1-aarch64.pkg.tar.xz"]
         and metadata.get("SHA256SUM") == [contract["python_archive"]["sha256"]]
         and metadata.get("CSIZE") == [str(contract["python_archive"]["size"])], "Python archive/core identity refused")
    need("python" in core_catalog and all(metadata.get(k, []) == core_catalog["python"].get(k, [])
         for k in ("NAME", "VERSION", "ARCH", "FILENAME", "SHA256SUM", "CSIZE", "DEPENDS", "PROVIDES", "CONFLICTS", "REPLACES", "LICENSE")),
         "Python receipt/current core metadata mismatch")
    raw, parsed = pkginfo(archive)
    observed = receipt["pkginfo"]
    need(observed["text"].encode() == raw and observed["bytes"] == len(raw)
         and observed["sha256"] == audit.digest(raw), "Python receipt/actual PKGINFO mismatch")
    for pkg, db in (("pkgname", "NAME"), ("pkgver", "VERSION"), ("arch", "ARCH"),
                    ("depend", "DEPENDS"), ("provides", "PROVIDES"), ("conflict", "CONFLICTS"),
                    ("replaces", "REPLACES"), ("license", "LICENSE")):
        need(parsed.get(pkg, []) == metadata.get(db, []), "Python PKGINFO/core mismatch: " + db)
    return {"metadata": metadata, "pkginfo": observed, "signature_observation": verification,
            "cached_archive_and_signature_rehashed": True, "fresh_signature_verification": False,
            "independent_owner_trust_accepted": False}


def validate_strict(contract, *, with_source_validation=False):
    strict = document(contract["strict_contract"])
    previous = document(contract["strict_transaction"])
    checkpoint = document(contract["strict_checkpoint"])
    need(previous.get("kind") == "private-Asahi-metadata-transaction-prepare" and previous.get("schema_version") == 1
         and previous.get("status") == "FAIL-incomplete-or-policy-rejected"
         and previous.get("input_references") == strict
         and previous.get("contract_sha256") == contract["strict_contract"]["sha256"], "strict transaction/input binding refused")
    need(previous.get("dependency_transaction_accepted") is False and previous.get("commit_called") is False
         and previous.get("all_protected_versions_preserved") is True, "strict unaccepted/preservation gate refused")
    need(any(e.get("kind") == "protected-root-version-rejected" and e.get("target", {}).get("name") == "python"
             and e.get("target", {}).get("version") == CHANGE["to"]
             and e.get("protected_version") == CHANGE["from"] for e in previous["transaction"]["errors"]),
         "strict Python refusal evidence required")
    need(checkpoint.get("schema_version") == 1 and checkpoint.get("status") == "frozen-data-only-transaction-followup"
         and checkpoint.get("dependency_transaction_accepted") is False, "strict checkpoint scope refused")
    for key in ("strict_contract", "strict_transaction"):
        reference = contract[key]
        need(any((ROOT / entry["path"]).absolute() == Path(reference["path"])
                 and entry["bytes"] == reference["size"] and entry["sha256"] == reference["sha256"]
                 for entry in checkpoint["private_evidence"]), "strict checkpoint/evidence pairing refused")
    files = checkpoint["files"]
    need(isinstance(files, dict) and 1 <= len(files) <= 1000, "finite strict source checkpoint required")
    snapshots = contract.get("strict_source_snapshots", {})
    need(isinstance(snapshots, dict) and set(snapshots) <= set(files), "unknown strict source snapshot name")
    need(all(isinstance(ref, dict) and type(ref.get("size")) is int for ref in snapshots.values())
         and sum(ref["size"] for ref in snapshots.values()) <= 16 * 1024**2, "strict source snapshot aggregate bound")
    source_validation = {"snapshot_sources_executed": False, "historical_checkpoint_sources": {}}
    for name, pin in files.items():
        path = Path(name)
        need(not path.is_absolute() and ".." not in path.parts, "strict source checkpoint path refused")
        current = preview.digest(ROOT / path)
        source = {"original_sha256": pin, "current_sha256": current, "validated_history_source": "current-file"}
        if name in snapshots:
            ref = snapshots[name]
            need(ref.get("sha256") == pin, "strict source snapshot original pin mismatch")
            binary(ref, 1024**2)
            source.update(validated_history_source="retained-snapshot", snapshot_reference=ref)
        else:
            need(current == pin, "strict source checkpoint drift")
        source_validation["historical_checkpoint_sources"][name] = source
    prior_reference = checkpoint["prior_checkpoint_reference"]
    prior = document({"path": str((ROOT / prior_reference["path"]).absolute()),
                      "size": prior_reference["bytes"], "sha256": prior_reference["sha256"]})
    need(isinstance(prior.get("files"), dict) and 1 <= len(prior["files"]) <= 1000, "prior source checkpoint refused")
    for name, pin in prior["files"].items():
        path = Path(name)
        need(not path.is_absolute() and ".." not in path.parts and preview.digest(ROOT / path) == pin,
             "prior source checkpoint drift")
    for name, module_ in (("transaction.py", transaction), ("tuple_audit.py", audit), ("preview.py", preview)):
        need(previous["source_sha256"][name] == preview.digest(module_.__file__), "strict helper provenance drift")
    image_doc, tuple_report, proposal = (document(strict[k]) for k in ("image_inventory", "tuple_report", "proposal"))
    image = audit.packages([p["metadata"] for p in image_doc["packages"]])
    for record in image.values():
        transaction.clean(record)
    need(tuple_report["input_sha256"]["image"] == strict["image_inventory"]["sha256"], "tuple/image pairing refused")
    protected = {p["name"]: p["version"] for p in tuple_report["proposed_installed_dependency_graph"]}
    need(len(protected) == len(tuple_report["proposed_installed_dependency_graph"])
         and all(image.get(n, {}).get("VERSION") == [v] for n, v in protected.items())
         and protected.get("python") == CHANGE["from"], "original protected tuple refused")
    need(len(image) == 261 and len(protected) == 201 and len(proposal["roots"]) == 45
         and len(proposal["provider_constraints"]) == 4, "exact strict baseline/target counts required")
    preserved = previous["protected_preservation"]
    need(len(preserved) == 201 and {p["name"] for p in preserved} == set(protected)
         and all(p["expected"] == p["final"] == protected[p["name"]] and p["preserved"] is True for p in preserved),
         "strict per-package preservation proof refused")
    file_records = transaction.local_files(document(strict["local_files"]), image, strict["image_inventory"]["sha256"]) if "local_files" in strict else {}
    result = (strict, previous, image, protected, proposal, file_records)
    return result + (source_validation,) if with_source_validation else result


def run(contract_path, contract_sha256, output_path):
    contract_path = Path(contract_path)
    contract = document({"path": str(contract_path.absolute()), "sha256": contract_sha256, "size": contract_path.stat().st_size})
    fields = {"schema_version", "proposal_kind", "change", "strict_contract", "strict_transaction", "strict_checkpoint",
              "python_receipt", "python_archive", "python_signature"}
    need(set(contract) in (fields, fields | {"strict_source_snapshots"})
         and type(contract["schema_version"]) is int and contract["schema_version"] == 1
         and contract["proposal_kind"] == "unadopted-coordinated-python-change"
         and contract["change"] == CHANGE, "single unadopted Python change contract required")
    strict, previous, image, original, proposal, file_records, source_validation = validate_strict(contract, with_source_validation=True)
    expected = original | {"python": CHANGE["to"]}
    references = strict["repositories"]
    need([r["name"] for r in references] == ["asahi-alarm", "core", "extra"], "strict repository order refused")
    receipt = document(contract["python_receipt"])
    with tempfile.TemporaryDirectory(prefix="cachy-python-proposal-", dir="/tmp") as temporary:
        work = Path(temporary)
        for name in ("inputs", "root", "db/sync", "cache", "gpg", "hooks"):
            (work / name).mkdir(parents=True, mode=0o700)
        catalogs, diagnostics = {}, []
        for reference in references:
            repo = reference["name"]
            grouped = transaction.repository_records(transaction.bound({k: reference[k] for k in ("path", "size", "sha256")}), diagnostics, repo)
            records = {}
            for folder, record in grouped.items():
                try:
                    transaction.clean(record)
                except ValueError as error:
                    diagnostics.append({"entry": repo + "/" + folder, "reason": str(error), "selectable": False})
                    continue
                name = record["NAME"][0]
                need(name not in records, "duplicate repository package")
                records[name] = record | {"repo": repo}
            catalogs[repo] = records
        core_reference = next(r for r in references if r["name"] == "core")
        evidence = authenticate_python(receipt, contract, {k: core_reference[k] for k in ("path", "size", "sha256")}, catalogs["core"])
        for repo, records in catalogs.items():
            for name in list(records):
                if name == "mesa-dummy" or name in expected and records[name]["VERSION"] != [expected[name]]:
                    diagnostics.append({"name": name, "repo": repo, "version": records[name]["VERSION"][0],
                                        "reason": "protected-version/mesa-dummy excluded", "selectable": False})
                    del records[name]
        targets = previous["targets"]
        targets = [{k: t[k] for k in ("name", "version", "repo", "origin")} for t in targets]
        required_roots = {(r["name"], r["version"]) for r in proposal["roots"] + proposal["provider_constraints"]}
        need(len(targets) == 55 and len({t["name"] for t in targets}) == 55
             and required_roots <= {(t["name"], t["version"]) for t in targets}, "all 55 strict targets required")
        additions = {t["name"]: t for t in targets if t["origin"] == "explicit-Asahi-addition"}
        need(set(additions) == set(transaction.ADDITIONAL)
             and all(additions[n]["repo"] == repo for n, repo in transaction.ADDITIONAL.items())
             and any(t["name"] == "mesa" and t["repo"] == "extra" for t in targets), "strict Asahi/native Mesa providers refused")
        transaction.preview.write_local(work / "db/local", image)
        transaction.write_local_files(work / "db/local", file_records, image, image)
        for repo, records in catalogs.items():
            transaction.write_catalog(work / "db/sync" / (repo + ".db"), records)
        # Only this authenticated, exact Python change is exempted from IgnorePkg.
        ignored = {n: v for n, v in expected.items() if n != "python"}
        result = transaction.prepare(work, image, ignored, catalogs, targets)
        final = dict(image)
        for removed in result["remove"]:
            final.pop(removed["name"], None)
        for item in result["add"]:
            record = catalogs.get(item["repo"], {}).get(item["name"])
            need(record is not None and record["VERSION"] == [item["version"]], "prepared addition/catalog mismatch")
            old = image.get(item["name"], {}).get("VERSION", [None])[0]
            item.update({"old_version": old, "change_kind": "add" if old is None else "change"})
            final[item["name"]] = record
        audit_work = work / "final-audit"
        (audit_work / "root").mkdir(parents=True, mode=0o700)
        preview.write_local(audit_work / "db/local", final)
        transaction.write_local_files(audit_work / "db/local", file_records, final, image)
        relations, conflicts = preview.alpm_audit(audit_work, final)
        preservation = [{"name": n, "original": original[n], "expected": v,
                         "final": final.get(n, {}).get("VERSION", [None])[0],
                         "preserved": final.get(n, {}).get("VERSION") == [v]} for n, v in sorted(expected.items())]
        target_checks = [t | {"final_version": final.get(t["name"], {}).get("VERSION", [None])[0],
                             "satisfied": final.get(t["name"], {}).get("VERSION") == [t["version"]]} for t in targets]
        rejected_providers = any(q["type"] == 32 and q["policy"] != "explicit-root-provider" for q in result["questions"])
        passed = not (result["prepare_exit"] or result["errors"] or result["callback_errors"] or conflicts or rejected_providers
                      or any(not r["provider"] for r in relations) or any(not p["preserved"] for p in preservation)
                      or any(not t["satisfied"] for t in target_checks))
        versions = audit.Versions()
        consumers = []
        for name, record in image.items():
            for dep in record.get("DEPENDS", []):
                if audit.witnesses(dep, {"python": image["python"]}, versions):
                    consumers.append({"package": name, "requires": dep, "original_witness": image["python"]["VERSION"][0],
                                      "new_witness": audit.witnesses(dep, {"python": evidence["metadata"]}, versions),
                                      "protected_consumer": name in original})
        original_relations = audit.requirements(image, image, versions)
        affected, consumer_edges = {"python"}, []
        while True:
            relevant = [r for r in original_relations if any(w["package"] in affected for w in r["witnesses"])]
            expanded = affected | {r["package"] for r in relevant}
            if expanded == affected:
                consumer_edges = relevant
                break
            affected = expanded
        strict_inventory = {p["name"]: p["version"] for p in previous["proposed_final_inventory"]}
        deltas = [{"name": n, "strict_version": strict_inventory.get(n),
                   "proposal_version": final.get(n, {}).get("VERSION", [None])[0]}
                  for n in sorted(set(strict_inventory) | set(final))
                  if strict_inventory.get(n) != final.get(n, {}).get("VERSION", [None])[0]]
        report = {"schema_version": 1, "kind": "private-Asahi-metadata-transaction-prepare",
                  "proposal_kind": contract["proposal_kind"], "adopted": False,
                  "status": "PASS-private-metadata-prepare" if passed else "FAIL-incomplete-or-policy-rejected",
                  "contract_sha256": contract_sha256, "input_references": contract,
                  "strict_source_validation": source_validation,
                  "source_sha256": {"coordinated_python.py": preview.digest(__file__), "transaction.py": preview.digest(transaction.__file__),
                                    "tuple_audit.py": preview.digest(audit.__file__), "preview.py": preview.digest(preview.__file__)},
                  "image_package_count": len(image), "protected_package_count": len(expected), "source_root_count": 45,
                  "targets": target_checks, "transaction": result, "catalog_diagnostics": diagnostics,
                  "protected_preservation": preservation, "all_protected_versions_preserved": all(p["preserved"] for p in preservation),
                  "all_targets_satisfied": all(t["satisfied"] for t in target_checks),
                  "strict_to_proposal_version_deltas": deltas,
                  "scoped_change_graph": {"changed_node": CHANGE, "original_pkginfo_available": False,
                                          "original_pkginfo_supplied_to_contract": False,
                                          "original_fields_source": "observed image descriptor; original archive PKGINFO not supplied to this contract",
                                          "original_depends": image["python"].get("DEPENDS", []), "original_provides": image["python"].get("PROVIDES", []),
                                          "new_depends": evidence["metadata"].get("DEPENDS", []), "new_provides": evidence["metadata"].get("PROVIDES", []),
                                          "direct_original_consumers": consumers,
                                          "all_original_consumer_edges": consumer_edges,
                                          "affected_original_nodes": [{"name": n, "original_version": image[n]["VERSION"][0],
                                                                       "proposal_version": final.get(n, {}).get("VERSION", [None])[0],
                                                                       "protected": n in original} for n in sorted(affected)]},
                  "python_signed_data_evidence": evidence, "ignorepkg_policy": {"count": len(ignored), "only_exemption": CHANGE},
                  "proposed_final_count": len(final), "proposed_final_inventory_scope": "unadopted alternative; tentative/partial on FAIL",
                  "proposed_final_inventory": [{"name": n, "version": p["VERSION"][0], "repo": p.get("repo", "installed"), "metadata": p}
                                               for n, p in sorted(final.items())],
                  "dependency_relationships": relations, "package_conflicts": conflicts,
                  "commit_called": False, "downloads_or_repository_updates": False, "host_database_used": False,
                  "dependency_transaction_accepted": False, "image_authentication_accepted": False,
                  "installation_accepted": False, "hardware_accepted": False, "file_conflicts_checked": False,
                  "fresh_signature_verification": False, "runtime_abi_accepted": False,
                  "limitations": ["Unadopted alternative to the preserved strict refusal; metadata prepare only.",
                                  "Retained signature observation and matching bytes do not independently authenticate the key owner.",
                                  "Old Python fields are image descriptor declarations; original signed PKGINFO is not supplied to this contract.",
                                  "No package payload installation, Python consumer execution, filesystem conflict or hardware check."]}
    audit.write_private(output_path, report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--contract-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        result = run(args.contract, args.contract_sha256, args.output)
    except (ValueError, OSError, KeyError, TypeError, EOFError, tarfile.TarError, lzma.LZMAError) as error:
        parser.exit(2, "coordinated Python proposal refused: " + str(error) + "\n")
    print(json.dumps({"status": result["status"], "adopted": False, "commit_called": False}))
    return 0 if result["status"].startswith("PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
