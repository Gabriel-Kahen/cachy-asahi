#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Join retained advisory reports to explicit pre-change rebuild metadata offline."""
import argparse
import copy
import importlib.util
from pathlib import Path
import sys

ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / "scripts/release/check_source_pins.py").is_file())
ADVISORY = ROOT / "scripts/maintenance/security_advisories.py"
REBUILD = ROOT / "scripts/maintenance/rebuild_plan.py"
if not REBUILD.is_file():
    REBUILD = ROOT / ("artifacts/development/repository-rebuild-planner-20261027/"
                      "proposal/scripts/maintenance/rebuild_plan.py")
FROZEN_REBUILD_SHA256 = "472f9bb621d78f79f5016a662b7f72eb03e995dae787c7846bc1f947ff21313c"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


a = load("update_advisories", ADVISORY)
# Refuse interface drift before executing the frozen planner.
try:
    a.need(a.pin(a.read(REBUILD))["sha256"] == FROZEN_REBUILD_SHA256,
           "rebuild planner changed; review and repin the frozen interface")
except (OSError, ValueError) as error:
    raise SystemExit("maintenance planner: " + str(error)) from None
b = load("update_rebuild", REBUILD)
INPUTS = ("inventory", "advisories", "provenance", "advisory_report", "graph")
MAX_TOTAL = 24 * 1024**2


def hold(code, action):
    return dict(code=code, action=action)


def replay(raws, as_of, max_age_hours):
    """Recompute the original report, then assess its age at the planning time."""
    a.need(type(max_age_hours) is int and 1 <= max_age_hours <= 24 * 365,
           "bounded cache/report age setting")
    now = a.utc(as_of)
    items = a.inventory(a.decode(raws["inventory"]))
    a.need(len(items) <= b.MAX_PACKAGES, "inventory exceeds frozen graph package bound")
    groups = a.decode(raws["advisories"])
    index = a.advisories(groups)
    a.need(sum(len(index.get(row["name"], [])) for row in items) <= b.MAX_PACKAGES,
           "advisory root count exceeds frozen planner bound; select a finite reviewed batch")
    # Bound duplicated tracker content before report() expands groups across
    # matching binary outputs. The extra allowance covers generated actions.
    sizes = {group["name"]: len(a.encoded(group)) + 4096 for group in groups}
    a.need(sum(sizes[group["name"]] for row in items for group in index.get(row["name"], []))
           + len(raws["inventory"]) * 4 <= b.pins.MAX_OUTPUT // 2,
           "advisory replay expansion bound; select a smaller explicit batch")
    provenance = a.decode(raws["provenance"])
    report = a.decode(raws["advisory_report"])
    a.need(type(report) is dict and type(report.get("cache")) is dict,
           "supported original advisory report required")
    report_time = a.utc(report.get("as_of"))
    a.need(report_time <= now, "advisory report time is in the future")
    original_age = report["cache"].get("max_age_hours")
    a.need(type(original_age) is int and 1 <= original_age <= 24 * 365,
           "original report age setting required")
    cache = a.provenance(provenance, raws["advisories"], report_time, original_age)
    expected = a.report(items, groups, cache, report["as_of"])
    expected["inputs"] = {key + ".json": a.pin(raws[key])
                          for key in ("inventory", "advisories", "provenance")}
    a.need(a.encoded(report) == a.encoded(expected),
           "advisory report does not replay against the exact inventory/cache/provenance")
    current_cache = a.provenance(provenance, raws["advisories"], now, max_age_hours)
    age = int((now - report_time).total_seconds())
    return items, report, dict(as_of=as_of, report_age_seconds=age,
                               report_stale=(now - report_time).total_seconds() > max_age_hours * 3600,
                               cache=current_cache)


def plan(raws, as_of, max_age_hours=24):
    a.need(set(raws) == set(INPUTS) and all(type(v) is bytes for v in raws.values()),
           "five explicit original inputs required")
    a.need(sum(map(len, raws.values())) <= MAX_TOTAL, "total input byte bound")
    items, report, freshness = replay(raws, as_of, max_age_hours)
    graph = a.decode(raws["graph"])
    # Validate the entire frozen graph before selecting advisory roots. This
    # retains the planner's source-pin and real ALPM dependency semantics.
    b.plan(graph)
    packages = {row["name"]: row for row in graph["packages"]}
    a.need(set(packages) == {row["name"] for row in items},
           "inventory and pre-change graph binary package sets differ")
    for row in items:
        other = packages[row["name"]]
        a.need(all(row[key] == other[key] for key in ("version", "arch")),
               "inventory and graph version/architecture mismatch: " + row["name"])
        if "provides" in row:
            b.relations(row["provides"], provides=True)
        if "provides" in row and "provides" in other:
            a.need(b.relations(row["provides"], provides=True) ==
                   b.relations(other["provides"], provides=True),
                   "inventory and graph provides mismatch: " + row["name"])
    selected = copy.deepcopy(graph)
    derived_roots = [{"package": row["name"], "reference": finding["url"]}
                     for row in report["packages"] for finding in row["findings"]]
    a.need(len(derived_roots) + len(selected["changed"]["advisories"]) <= b.MAX_PACKAGES,
           "advisory root count exceeds frozen planner bound; select a finite reviewed batch")
    selected["changed"]["advisories"].extend(derived_roots)
    rebuild = b.plan(selected)
    by_name = {row["name"]: row for row in items}
    builds = {row["package"]: row for row in graph["build_dependencies"]}
    source_ids = {row["id"] for row in graph["sources"]}
    reviews = []
    for row in report["packages"]:
        name = row["name"]
        holds = []
        build = builds.get(name, {})
        if not build:
            holds.append(hold("UNKNOWN_BUILD_METADATA", "Supply the explicit pre-change build dependency and source mapping record for " + name + "."))
        if not build.get("owner"):
            holds.append(hold("UNKNOWN_PACKAGE_OWNER", "Assign an accountable package maintainer for " + name + "."))
        if build.get("source_id") not in source_ids:
            holds.append(hold("UNKNOWN_SOURCE_PINS", "Supply the exact recipe hash and immutable source pins for " + name + "."))
        if "provides" not in by_name[name]:
            holds.append(hold("INVENTORY_PROVIDES_UNKNOWN",
                              "Retain explicit provides metadata, including an empty list, for " + name + "."))
        if not row["findings"]:
            holds.append(hold("ADVISORY_COVERAGE_UNKNOWN",
                              "Review upstream/security coverage for this exact binary; pkgbase/provides are not advisory aliases."))
        else:
            holds.extend([hold("ARM_AFFECTEDNESS_UNKNOWN",
                               "Assign the package owner to review each CVE against the selected ARM source, patches and configuration."),
                          hold("ARM_FIX_EVIDENCE_MISSING",
                               "Retain reviewed ARM fix correspondence and authenticated candidate build evidence; Arch status/version ordering is insufficient.")])
        reviews.append(dict(name=name, version=row["version"], arch=row["arch"],
                            pkgbase=row["pkgbase"], provides=by_name[name].get("provides"),
                            source_id=builds.get(name, {}).get("source_id"),
                            owner=builds.get(name, {}).get("owner"),
                            matching_basis=row["matching_basis"], advisory_status=row["status"],
                            findings=row["findings"], holds=holds,
                            arm_affectedness="UNKNOWN", arm_fix_status="UNKNOWN"))
    global_holds = []
    if freshness["report_stale"]:
        global_holds.append(hold("STALE_ADVISORY_REPORT", "Retain and regenerate the report from reviewed explicit inputs at the selected planning time."))
    if freshness["cache"]["cache_stale"]:
        global_holds.append(hold("STALE_ADVISORY_CACHE", freshness["cache"]["action"]))
    actions = {
        "UNKNOWN_PACKAGE_OWNER": "Assign an accountable package maintainer before scheduling work.",
        "UNKNOWN_SOURCE_PINS": "Supply the exact recipe hash and immutable source pins for the package build unit.",
        "UNKNOWN_BUILD_METADATA": "Supply explicit runtime/make/check/toolchain metadata for the pre-change snapshot.",
        "EXTERNAL_UPDATE_REVIEW": "Obtain reviewed upstream ARM update availability and compatibility evidence.",
        "EXPLICIT_HOLD": "Resolve the package's recorded hold reason with its owner.",
        "CAPACITY_OR_CAPACITY_OWNER_UNAVAILABLE": "Assign a builder owner and reviewed native aarch64 capacity reference.",
    }
    for code in rebuild["global_holds"]:
        global_holds.append(hold(code, actions.get(code, "Resolve the frozen rebuild planner's coverage/root review before scheduling.")))
    package_holds = {row["name"]: row["holds"] for row in reviews}
    groups = copy.deepcopy(rebuild["groups"])
    by_group = {}
    for group in groups:
        group["maintenance_holds"] = [dict(package=name, **reason)
                                      for name in group["packages"] for reason in package_holds[name]]
        group["rebuild_actions"] = [hold(code, actions.get(code.split(":")[0],
                                                  "Resolve this dependency/provider/bootstrap review with the package owner."))
                                    for code in group["holds"]]
        group["held_prerequisites"] = [key for key in group["prerequisites"] if by_group[key]["held"]]
        group["held"] = bool(group["held"] or group["maintenance_holds"] or
                             group["held_prerequisites"] or global_holds)
        by_group[group["id"]] = group
    return dict(schema_version=1, status="OFFLINE_MAINTENANCE_REVIEW_PLAN_NOT_EXECUTION",
                as_of=as_of, release_id=rebuild["release_id"], snapshot_id=rebuild["snapshot_id"],
                inputs={key: dict(**a.pin(raws[key]), authenticated=False) for key in INPUTS},
                freshness=freshness, global_holds=global_holds, package_reviews=reviews,
                derived_advisory_roots=sorted(derived_roots, key=lambda row: (row["package"], row["reference"])),
                rebuild=rebuild, maintenance_groups=groups,
                maintenance_review_held=bool(global_holds or any(row["holds"] for row in reviews) or any(row["held"] for row in groups)),
                build_status="NOT_RUN", arm_security_status="UNKNOWN", release_acceptance="NOT_ESTABLISHED",
                limitations=["Digests bind supplied bytes; origin, pins, owners and capacity are not authenticated or exercised.",
                             "All exact binary advisory matches seed review, including versions at or above Arch fixed references.",
                             "Missing tracker matches create coverage holds, never unaffectedness or inferred rebuild roots.",
                             "Graph unaffectedness means only no path from declared roots in supplied pre-change metadata.",
                             "ARM affectedness/fix evidence is not accepted by this planning command; retain it for separate review.",
                             "No network, build, source mutation, installation, signing, publishing or hardware checks execute."])


def text_report(value):
    lines = [value["status"], f"Release {value['release_id']}; snapshot {value['snapshot_id']}",
             "Builds NOT_RUN; ARM security UNKNOWN; release acceptance NOT_ESTABLISHED"]
    for row in value["global_holds"]:
        lines.append("GLOBAL HOLD " + row["code"] + ": " + row["action"])
    for row in value["package_reviews"]:
        lines.append(f"{row['name']} {row['version']} pkgbase={row['pkgbase']} source_id={row['source_id']} owner={row['owner']}: {row['advisory_status']}")
        for reason in row["holds"]:
            lines.append("  HOLD " + reason["code"] + ": " + reason["action"])
        for finding in row["findings"]:
            lines.append("  " + finding["url"] + " " + finding["version_relation"] + ": " + finding["action"])
    for row in value["maintenance_groups"]:
        lines.append(f"{row['id']} {'HELD' if row['held'] else 'CONDITIONAL'} {', '.join(row['packages'])}; prerequisites: {', '.join(row['prerequisites']) or 'none'}")
        for reason in row["rebuild_actions"]:
            lines.append("  HOLD " + reason["code"] + ": " + reason["action"])
        if row["held_prerequisites"]:
            lines.append("  HELD PREREQUISITES: " + ", ".join(row["held_prerequisites"]))
    lines.extend(["", b.text_report(value["rebuild"]), *value["limitations"]])
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for key in INPUTS:
        flag = key.replace("_", "-")
        parser.add_argument("--" + flag, type=Path, required=True)
        parser.add_argument("--" + flag + "-sha256", required=True)
    parser.add_argument("--as-of", required=True, help="explicit UTC planning time ending Z")
    parser.add_argument("--max-age-hours", type=int, default=24)
    parser.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args(argv)
    try:
        raws = {}
        for key in INPUTS:
            raw = a.read(getattr(args, key))
            checksum = getattr(args, key + "_sha256")
            a.need(type(checksum) is str and b.r.HEX.fullmatch(checksum) and a.pin(raw)["sha256"] == checksum,
                   key + " input checksum mismatch")
            raws[key] = raw
        value = plan(raws, args.as_of, args.max_age_hours)
        dependencies = (Path(__file__).resolve(), ADVISORY, REBUILD, b.DEPENDENCY,
                        b.DEPENDENCY.with_name("release.py"), b.DEPENDENCY.with_name("source_delivery.py"))
        value["implementation_dependencies"] = {str(path.relative_to(ROOT)): a.pin(a.read(path)) for path in dependencies}
        for key in INPUTS:
            a.need(a.read(getattr(args, key)) == raws[key], "input changed during planning: " + key)
        output = b.pins.encoded(value) if args.format == "json" else text_report(value).encode()
        a.need(len(output) <= b.pins.MAX_OUTPUT, "report byte bound")
        sys.stdout.write(output.decode())
        return 0
    except (b.r.Error, b.s.Error, OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print("maintenance planner: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
