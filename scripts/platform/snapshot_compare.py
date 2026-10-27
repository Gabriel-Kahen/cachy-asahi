#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare two retained Asahi snapshot bundles as data; print JSON, never write.

Exit 0 admits only the declared data comparison, 2 blocks it, 1 refuses the
contract. No discovery, package/archive execution, transaction, or hardware test.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, path):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


snapshot = module("comparison_snapshot", HERE / "target_snapshot.py")
preflight = module("comparison_preflight", HERE / "recovery_preflight.py")
audit, need = snapshot.audit, snapshot.need
MIB = snapshot.MIB
MAX_ROWS = 8192
MAX_BYTES = 512 * MIB
MAX_OBJECTS = 65536
ASSETS = preflight.BOOT_ROLES | preflight.CONFIG_ROLES
PROTECTED = preflight.PLATFORM | snapshot.capture.PLATFORM
FALSE_CLAIMS = ("hardware_accepted", "boot_accepted", "recovery_accepted",
                "backup_completeness_accepted", "installed_payload_authenticated")
NODE = {"dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns"}


def fields(value, keys, message):
    need(isinstance(value, dict) and set(value) == set(keys), message)


def rows(value, maximum=MAX_ROWS):
    need(isinstance(value, list) and len(value) <= maximum, "finite row list required")
    return value


def version(value):
    need(type(value) is int and value == 1, "schema version refused")


def content(ref):
    return {key: ref[key] for key in ("size", "sha256")}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


class Reader(snapshot.Reader):
    """Keep the collector's stable no-follow reads with a two-bundle byte budget."""
    def read(self, path, maximum, *, remember=True):
        data, observed = super().read(path, maximum, remember=False)
        if remember:
            name = str(path)
            if name not in self.files:
                self.total += len(data)
                need(self.total <= MAX_BYTES and len(self.files) < MAX_OBJECTS, "comparison aggregate input bound exceeded")
            else:
                need(self.files[name] == observed, "comparison source changed between reads")
            self.files[name] = observed
        return data, observed


class Comparison:
    def __init__(self):
        self.reader = Reader()
        self.findings = []
        self.producer_roots = set()

    def producer_complete(self, root):
        fd = snapshot.opened(root, directory=True)
        try:
            try:
                snapshot.os.stat("INCOMPLETE", dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise ValueError("retained bundle publication is incomplete")
        finally:
            snapshot.os.close(fd)

    def document(self, ref):
        value = audit.load_json(self.reader.bound(ref, 8 * MIB))
        need(isinstance(value, dict), "JSON object required")
        return value

    def finding(self, status, code, **details):
        self.findings.append({"status": status, "code": code, **details})

    def retained_inputs(self, bundle, receipt):
        document = self.document(bundle["inputs"])
        fields(document, {"schema_version", "kind", "collection", "files"}, "retention map fields refused")
        version(document["schema_version"])
        need(document["kind"] == "collector-retained-input-map" and document["collection"] == bundle["collection"],
             "retention map/collection pairing refused")
        retained = {}
        for row in rows(document["files"]):
            fields(row, {"source_path", "retained"}, "retention row fields refused")
            name = str(snapshot.absolute(row["source_path"]))
            need(name not in retained, "duplicate retained source")
            retained[name] = (row["retained"], self.reader.bound(row["retained"], 32 * MIB))
        sources = {}
        for source in rows(receipt["sources"]):
            fields(source, {"path", "size", "sha256", "node"}, "collector source fields refused")
            name = str(snapshot.absolute(source["path"]))
            need(name not in sources and name in retained, "incomplete/duplicate retained input map")
            fields(source["node"], NODE, "collector node identity fields refused")
            need(all(type(value) is int for value in source["node"].values())
                 and source["node"]["size"] == source["size"], "collector node size/type refused")
            need(content(source) == content(retained[name][0]), "retained input size/hash pairing refused")
            sources[name] = source
        need(set(sources) == set(retained) and type(receipt["source_bytes"]) is int
             and receipt["source_bytes"] == sum(row["size"] for row in sources.values()),
             "whole collector input map/byte count required")

        def original(ref):
            fields(ref, {"path", "size", "sha256"}, "original reference fields refused")
            need(ref["path"] in retained and content(ref) == content(retained[ref["path"]][0]),
                 "original reference not bound by retained input map")
            return retained[ref["path"]][1]

        contract = audit.load_json(original(receipt["contract_reference"]))
        version(contract.get("schema_version"))
        need(contract.get("mode") in {"fixture", "live"}
             and contract.get("selected_files") == receipt["selected_files"], "collector contract pairing refused")
        mode = contract["mode"]
        allowed = {"schema_version", "mode", "selected_files"} | ({"fixture_root", "fixture_runtime"} if mode == "fixture" else set())
        need(set(contract) in (allowed, allowed | {"preflight"}), "collector contract fields refused")
        root = snapshot.absolute(contract["fixture_root"]) if mode == "fixture" else Path("/")
        need(receipt["scope"] == ("SYNTHETIC_FIXTURE" if mode == "fixture" else "OBSERVED_LIVE_METADATA"),
             "collector scope mismatch")
        if mode == "fixture":
            runtime = audit.load_json(original(contract["fixture_runtime"]))
        else:
            runtime = None
        if "preflight" in contract:
            adapter = contract["preflight"]
            fields(adapter, {"prepared_update", "recovery_receipts"}, "collector preflight map refused")
            for ref in [adapter["prepared_update"], *rows(adapter["recovery_receipts"], 32)]:
                audit.load_json(original(ref))
        return retained, original, root, runtime

    def recovery(self, context, packages, assets, side):
        recovery = context["recovery"]
        fields(recovery, {"receipts", "assets"}, "recovery context fields refused")
        recovered, seen = set(), set()
        for ref in rows(recovery["receipts"], 32):
            receipt = self.document(ref)
            version(receipt["schema_version"])
            need(receipt["kind"] == "exact-superseded-recovery-archive-data"
                 and receipt["status"] in {"PASS-all-exact-old-recovery-archive-data", "FAIL-incomplete-recovery-archive-data"}
                 and all(receipt.get(key) is False for key in ("system_mutation", "installation_accepted", "hardware_accepted",
                                                              "image_payload_correspondence_accepted", "independent_owner_trust_accepted")),
                 "recovery receipt kind/scope refused")
            inputs = receipt["inputs"]
            need(set(inputs) <= {"schema_version", "image_inventory", "old_availability", "certificate", "previous_receipt"}
                 and {"image_inventory", "certificate"} <= set(inputs), "recovery input map refused")
            inventory = preflight.metadata(self.document(inputs["image_inventory"])["packages"])
            if inventory != packages:
                self.finding("MISSING_EVIDENCE", "stale-recovery-inventory", side=side)
                continue
            for key in ("certificate", "old_availability", "previous_receipt"):
                if key in inputs:
                    self.reader.bound(inputs[key], 8 * MIB)
            entries = rows(receipt["packages"], 4096)
            passed = sum(row.get("status") == "PASS-signed-old-archive-data-matches-image-metadata" for row in entries)
            need(type(receipt["planned_count"]) is int and receipt["planned_count"] == len(entries)
                 and type(receipt["verified_count"]) is int and receipt["verified_count"] == passed
                 and (receipt["status"] == "PASS-all-exact-old-recovery-archive-data") == (passed == len(entries)),
                 "recovery receipt completion map refused")
            for row in entries:
                name = row["name"]
                need(name not in seen and name in packages, "duplicate/unknown recovery package")
                seen.add(name)
                if (row["observed_image_metadata"] != packages[name] or row["version"] != packages[name]["VERSION"][0]
                        or row["arch"] != packages[name]["ARCH"][0]):
                    self.finding("MISSING_EVIDENCE", "stale-recovery-package", side=side, package=name)
                    continue
                if row["status"] == "FAIL":
                    continue
                need(row["status"] == "PASS-signed-old-archive-data-matches-image-metadata", "recovery row status refused")
                for key, maximum in (("archive", 32 * MIB), ("signature", 65536),
                                     ("operator_index", MIB), ("inspection", 8 * MIB)):
                    self.reader.bound(preflight.recovery.ref_only(row[key]), maximum)
                inspection = self.document(preflight.recovery.ref_only(row["inspection"]))
                expected = preflight.recovery.expected(packages[name])
                mapping = {"pkgname": "name", "pkgver": "version", "arch": "arch", "license": "license",
                           "depend": "depends", "provides": "provides", "conflict": "conflicts", "replaces": "replaces"}
                need(all(inspection["metadata"].get(key, []) == (expected[field] if isinstance(expected[field], list) else [expected[field]])
                         for key, field in mapping.items()), "recovery inspection metadata pairing refused")
                recovered.add(name)
        for name in sorted((PROTECTED & set(packages)) - recovered):
            self.finding("MISSING_EVIDENCE", "exact-recovery-reference-missing", side=side, package=name)
        saved = set()
        for row in rows(recovery["assets"], len(ASSETS)):
            fields(row, {"role", "artifact"}, "recovery asset fields refused")
            role = row["role"]
            need(role in ASSETS and role not in saved, "duplicate/unknown recovery asset")
            self.reader.bound(row["artifact"], 32 * MIB)
            saved.add(role)
            if role not in assets or row["artifact"] != assets[role]:
                self.finding("MISSING_EVIDENCE", "stale-recovery-asset", side=side, role=role)
        for role in sorted(ASSETS - saved):
            self.finding("MISSING_EVIDENCE", "recovery-asset-reference-missing", side=side, role=role)

    def bundle(self, bundle, side):
        fields(bundle, {"snapshot", "collection", "inputs", "context"}, "snapshot bundle fields refused")
        target, receipt = self.document(bundle["snapshot"]), self.document(bundle["collection"])
        version(receipt["schema_version"])
        need(receipt["kind"] == "read-only-Asahi-target-snapshot-collection"
             and receipt["status"] == "CAPTURED_METADATA_ONLY" and receipt["snapshot"] == bundle["snapshot"]
             and receipt["sources_rechecked"] is True and all(receipt.get(key) is False for key in FALSE_CLAIMS),
             "collector receipt/snapshot/scope pairing refused")
        code = receipt["source_code_sha256"]
        core = {"scripts/platform/target_snapshot.py", "scripts/platform/capture.py",
                "scripts/platform/tuple_audit.py", "scripts/hardware/capture-baseline.py"}
        producer = "scripts/platform/retained_bundle.py"
        need(isinstance(code, dict) and set(code) in (core, core | {producer})
             and all(isinstance(key, str) and isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value)
                     for key, value in code.items()), "collector code map refused")
        if producer in code:
            root = Path(bundle["context"]["path"]).parent
            self.producer_complete(root)
            manifest = audit.load_json(self.reader.read(root / "bundle.json", 8 * MIB)[0])
            provenance = audit.load_json(self.reader.read(root / "producer-receipt.json", 8 * MIB)[0])
            need(manifest == bundle and provenance.get("bundle") == bundle
                 and provenance.get("source_code_sha256") == code
                 and provenance.get("status") == "RETAINED_METADATA_ONLY", "retained bundle producer binding refused")
            self.producer_roots.add(root)
        retained, original, root, fixture_runtime = self.retained_inputs(bundle, receipt)
        fields(target, {"schema_version", "kind", "model", "device_tree_compatible", "packages", "captured_at",
                        "runtime", "boot_assets", "configuration_backups"}, "snapshot fields refused")
        version(target["schema_version"])
        need(target["kind"] == "operator-supplied-offline-Asahi-target-snapshot", "snapshot kind refused")
        runtime = target["runtime"]
        fields(runtime, {"architecture", "kernel_release", "kernel_package_version", "page_size"}, "runtime fields refused")
        base_runtime = {key: runtime[key] for key in ("architecture", "kernel_release", "page_size")}
        raw = self.reader.bound(target["device_tree_compatible"], 65536)
        need(retained[str(root / "sys/firmware/devicetree/base/compatible")][1] == raw, "retained compatible mismatch")
        model = snapshot.validate_runtime(base_runtime, raw)
        need(model == target["model"] and (fixture_runtime is None or fixture_runtime == base_runtime),
             "snapshot model/runtime input mismatch")
        prefix = "SYNTHETIC-FIXTURE " if receipt["scope"] == "SYNTHETIC_FIXTURE" else "OBSERVED-LIVE-METADATA "
        need(isinstance(target["captured_at"], str) and target["captured_at"].startswith(prefix)
             and len(target["captured_at"]) <= 128, "snapshot observation label mismatch")
        packages = preflight.metadata(target["packages"])
        desc_paths = set()
        for row in rows(target["packages"], 4096):
            fields(row, {"directory", "descriptor_sha256", "metadata"}, "snapshot package row fields refused")
            name, package_version = (row["metadata"][key][0] for key in ("NAME", "VERSION"))
            need(row["directory"] == name + "-" + package_version and snapshot.capture.NAME.fullmatch(row["directory"]),
                 "snapshot package directory identity mismatch")
            path = str(root / "var/lib/pacman/local" / row["directory"] / "desc")
            ref, data = retained[path]
            need(ref["sha256"] == row["descriptor_sha256"] and snapshot.capture.parse_desc(data) == row["metadata"],
                 "retained descriptor/snapshot mismatch")
            desc_paths.add(path)
        need({path for path in retained if path.startswith(str(root / "var/lib/pacman/local") + "/") and path.endswith("/desc")} == desc_paths,
             "snapshot omits a retained package descriptor")
        need(packages.get("linux-asahi", {}).get("VERSION") == [runtime["kernel_package_version"]],
             "running kernel package mismatch")
        module_path = "usr/lib/modules/" + runtime["kernel_release"] + "/pkgbase"
        need(retained[str(root / module_path)][1] == b"linux-asahi\n", "retained running kernel pkgbase mismatch")
        kernel_files = retained[str(root / "var/lib/pacman/local" / ("linux-asahi-" + runtime["kernel_package_version"]) / "files")][1]
        need(module_path in audit.parse_desc(kernel_files.decode())["FILES"], "retained kernel ownership mismatch")
        for name in sorted(preflight.PLATFORM - set(packages)):
            self.finding("MISSING_EVIDENCE", "required-platform-package-missing", side=side, package=name)
        selections = {}
        for row in rows(receipt["selected_files"], len(ASSETS)):
            fields(row, {"role", "source"}, "selected file fields refused")
            role = row["role"]
            need(role in ASSETS and role not in selections, "duplicate/unknown selected role")
            selections[role] = original(row["source"])
        assets = {}
        for field, allowed in (("boot_assets", preflight.BOOT_ROLES), ("configuration_backups", preflight.CONFIG_ROLES)):
            for row in rows(target[field], len(allowed)):
                fields(row, {"role", "artifact"}, "snapshot asset fields refused")
                role = row["role"]
                need(role in allowed and role not in assets and role in selections, "unknown/duplicate snapshot asset role")
                data = self.reader.bound(row["artifact"], 32 * MIB)
                need(data == selections[role], "selected asset/source map mismatch")
                if role == "kernel-release":
                    need(data.decode("ascii").strip() == runtime["kernel_release"], "kernel-release asset mismatch")
                assets[role] = row["artifact"]
        need(set(assets) == set(selections), "snapshot/selection role map mismatch")
        for role in sorted(ASSETS - set(assets)):
            self.finding("MISSING_EVIDENCE", "retained-asset-missing", side=side, role=role)
        context = self.document(bundle["context"])
        fields(context, {"schema_version", "kind", "snapshot", "machine_id", "model", "configuration_ownership", "recovery"},
               "comparison context fields refused")
        version(context["schema_version"])
        need(context["kind"] == "snapshot-comparison-context" and context["snapshot"] == bundle["snapshot"]
             and context["model"] == model and isinstance(context["machine_id"], str)
             and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", context["machine_id"]), "snapshot context identity binding refused")
        configs, config_roles = {}, set()
        for row in rows(context["configuration_ownership"], 2):
            fields(row, {"path", "role", "owner", "artifact"}, "configuration ownership fields refused")
            path, role = str(snapshot.absolute(row["path"])), row["role"]
            need(role in preflight.CONFIG_ROLES and role not in config_roles and path not in configs
                 and row["artifact"] == assets.get(role), "configuration role/artifact binding refused")
            owner = row["owner"]
            fields(owner, {"kind", "id"}, "configuration owner fields refused")
            need(owner["kind"] in {"user", "package"} and isinstance(owner["id"], str)
                 and re.fullmatch(r"[A-Za-z0-9@._+:-]{1,128}", owner["id"])
                 and (owner["kind"] != "package" or owner["id"] in packages), "configuration owner identity refused")
            configs[path] = {"role": role, "owner": owner, "artifact": content(row["artifact"])}
            config_roles.add(role)
        for role in sorted(preflight.CONFIG_ROLES - config_roles):
            self.finding("MISSING_EVIDENCE", "configuration-ownership-missing", side=side, role=role)
        self.recovery(context, packages, assets, side)
        return {"packages": packages, "assets": {role: content(ref) for role, ref in assets.items()}, "runtime": runtime,
                "configuration_ownership": configs, "model": model, "machine_id": context["machine_id"],
                "compatible": raw.hex(), "scope": receipt["scope"], "collector_code": code}

    def compare(self, before, after, proposal):
        if any(before[key] != after[key] for key in ("model", "machine_id", "compatible", "scope", "collector_code")):
            self.finding("INCOMPATIBLE_BASELINE", "machine-or-collector-identity-mismatch")
            return
        for category in ("packages", "assets", "runtime", "configuration_ownership"):
            expected = {}
            for row in rows(proposal[category]):
                fields(row, {"key", "from", "to"}, "proposed change row fields refused")
                key = row["key"]
                need(isinstance(key, str) and key not in expected and row["from"] != row["to"],
                     "duplicate/empty proposed change")
                expected[key] = row
            for key in sorted(set(before[category]) | set(after[category]) | set(expected)):
                old, new = before[category].get(key), after[category].get(key)
                change = expected.get(key)
                if change is not None:
                    status = "INTENDED_CHANGE" if (old, new) == (change["from"], change["to"]) else "UNEXPECTED_DRIFT"
                    code = "declared-change-matches" if status == "INTENDED_CHANGE" else "declared-change-mismatch"
                elif old == new:
                    status, code = "UNCHANGED", "unchanged"
                else:
                    status, code = "UNEXPECTED_DRIFT", "undeclared-change"
                self.finding(status, code, category=category, key=key, before=old, after=new,
                             protected=(key in PROTECTED if category == "packages" else True))

    def run(self, contract_ref):
        contract = self.document(contract_ref)
        fields(contract, {"schema_version", "kind", "before", "after", "proposed_changes"}, "comparison contract fields refused")
        version(contract["schema_version"])
        need(contract["kind"] == "retained-Asahi-snapshot-comparison", "comparison contract kind refused")
        proposal = self.document(contract["proposed_changes"])
        fields(proposal, {"schema_version", "kind", "baseline_snapshot", "candidate_snapshot", "packages", "assets", "runtime",
                          "configuration_ownership"}, "proposed changes fields refused")
        version(proposal["schema_version"])
        need(proposal["kind"] == "explicit-snapshot-change-set", "proposed change kind refused")
        if (proposal["baseline_snapshot"] != contract["before"]["snapshot"]
                or proposal["candidate_snapshot"] != contract["after"]["snapshot"]):
            self.finding("INCOMPATIBLE_BASELINE", "proposal-snapshot-binding-mismatch")
        loaded = {}
        for side in ("before", "after"):
            try:
                loaded[side] = self.bundle(contract[side], side)
            except (ValueError, OSError, KeyError, TypeError, AttributeError, UnicodeError) as error:
                self.finding("MISSING_EVIDENCE", "bundle-evidence-refused", side=side, reason=str(error))
        if len(loaded) == 2:
            self.compare(loaded["before"], loaded["after"], proposal)
        try:
            self.reader.recheck()
            for root in self.producer_roots:
                self.producer_complete(root)
        except (ValueError, OSError) as error:
            self.finding("MISSING_EVIDENCE", "input-drift-before-report", reason=str(error))
        statuses = {row["status"] for row in self.findings}
        status = next((value for value in ("INCOMPATIBLE_BASELINE", "MISSING_EVIDENCE", "UNEXPECTED_DRIFT", "INTENDED_CHANGE")
                       if value in statuses), "UNCHANGED")
        admitted = status in {"UNCHANGED", "INTENDED_CHANGE"}
        return {"schema_version": 1, "kind": "retained-Asahi-snapshot-comparison-report", "status": status,
                "comparison_data_admitted": admitted, "contract_reference": contract_ref, "input_references": contract,
                "findings": self.findings, "tuple_sha256": {side: digest(value) for side, value in loaded.items()},
                "source_bytes_rechecked": self.reader.total, "system_mutation": False,
                "hardware_accepted": False, "boot_accepted": False, "installation_accepted": False,
                "recovery_accepted": False, "installed_payload_authenticated": False, "configuration_ownership_verified": False,
                "fresh_signature_verification": False, "dependency_transaction_accepted": False,
                "source_sha256": {"snapshot_compare.py": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
                "limitations": ["Admission covers only retained data equality against the exact declared change set.",
                                "Machine pseudonym and configuration ownership are operator-supplied assertions.",
                                "Recovery references are rehashed and metadata-paired; signatures and archive contents are not replayed.",
                                "Selected artifacts do not establish complete backups, usability, compatibility, or boot/session recovery.",
                                "No target was discovered or probed; no package operations or physical checks ran."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--contract-sha256", required=True)
    args = parser.parse_args()
    try:
        path = snapshot.absolute(str(args.contract))
        reader = snapshot.Reader()
        data, _ = reader.read(path, 8 * MIB)
        ref = {"path": str(path), "size": len(data), "sha256": args.contract_sha256}
        report = Comparison().run(ref)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, UnicodeError) as error:
        parser.exit(1, "snapshot comparison refused: " + str(error) + "\n")
    print(json.dumps(report, sort_keys=True, allow_nan=False))
    return 0 if report["comparison_data_admitted"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
