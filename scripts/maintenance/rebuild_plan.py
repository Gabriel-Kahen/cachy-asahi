#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Plan conservative rebuild review from explicit, finite offline release inputs."""
import argparse
from collections import defaultdict, deque
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

# Works in the proposal tree and after integration; no copied relation solver.
ROOT = next(parent for parent in Path(__file__).resolve().parents
            if (parent / "scripts/release/check_source_pins.py").is_file())
DEPENDENCY = ROOT / "scripts/release/check_source_pins.py"
spec = importlib.util.spec_from_file_location("rebuild_source_pins", DEPENDENCY)
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)
r, s = pins.r, pins.s
MAX_PACKAGES, MAX_RELATIONS, MAX_CHECKS, MAX_WORK = 4096, 65536, 65536, 262144
need = r.require


def text(value):
    need(type(value) is str and 0 < len(value) <= 512 and value.isprintable(), "bounded nonempty text required")
    return value


def name(value):
    need(type(value) is str and len(value) <= 128, "bounded name required")
    return r.valid_name(value)


def rows(value):
    need(type(value) is list and len(value) <= MAX_PACKAGES, "bounded explicit list required")
    return value


def relations(value, provides=False):
    need(type(value) is list and len(value) <= 256, "bounded explicit relation list required")
    for item in value:
        text(item)
        _, operator, _ = r.relation(item)
        need(not provides or operator in (None, "="), "provides supports only unversioned or '=' relations")
    return sorted(set(value))


def indexed(value, key):
    result = {}
    for row in rows(value):
        need(type(row) is dict and key in row, "record missing " + key)
        item = name(row[key])
        need(item not in result, "duplicate " + key + ": " + item)
        result[item] = row
    return result


def components(graph):
    """Iterative Kosaraju; edges point from a consumer to its prerequisites."""
    seen, finish = set(), []
    for node in sorted(graph):
        if node in seen:
            continue
        seen.add(node)
        stack = [(node, iter(sorted(graph[node])))]
        while stack:
            node, children = stack[-1]
            child = next(children, None)
            if child is None:
                finish.append(node)
                stack.pop()
            elif child not in seen:
                seen.add(child)
                stack.append((child, iter(sorted(graph[child]))))
    reverse = {node: set() for node in graph}
    for node, children in graph.items():
        for child in children:
            reverse[child].add(node)
    seen, groups = set(), []
    for node in reversed(finish):
        if node in seen:
            continue
        seen.add(node)
        stack, group = [node], []
        while stack:
            node = stack.pop()
            group.append(node)
            for child in sorted(reverse[node]):
                if child not in seen:
                    seen.add(child)
                    stack.append(child)
        groups.append(sorted(group))
    return sorted(groups)


def provider_context(package, field, dependency, candidates, packages):
    """Bind the complete consumer/candidate metadata without deleting offers."""
    def projection(name):
        return {key: packages[name].get(key) for key in ("name", "version", "arch", "depend", "provides")}
    return dict(package=package, field=field, dependency=dependency,
                consumer=projection(package), candidates=[projection(name) for name in sorted(candidates)])


def provider_selections(value, packages, builds):
    result = {}
    witnesses = set()
    inventory = "".join(package + " " + row["version"] + "\n" for package, row in sorted(packages.items())
                        if builds.get(package, {}).get("disposition") == "external")
    inventory_sha256 = pins.digest(inventory.encode())
    for row in rows(value):
        pins.fields(row, ("package", "field", "dependency", "provider", "evidence"))
        package, provider = name(row["package"]), name(row["provider"])
        field, dependency = row["field"], text(row["dependency"])
        need(field == "depend", "installed provider selections require runtime depend field")
        evidence = row["evidence"]
        pins.fields(evidence, ("kind", "image", "inventory_sha256", "capture_sha256", "metadata_sha256"))
        need(evidence["kind"] == "INSTALLED_ALPM_CACHE_QUERY_V1", "provider selection evidence kind")
        need(type(evidence["image"]) is str and evidence["image"].startswith("sha256:") and
             r.HEX.fullmatch(evidence["image"][7:]), "selected installed image ID required")
        for key in ("inventory_sha256", "capture_sha256", "metadata_sha256"):
            need(type(evidence[key]) is str and r.HEX.fullmatch(evidence[key]), "provider selection checksum")
        witnesses.add((evidence["image"], evidence["inventory_sha256"], evidence["capture_sha256"]))
        need(len(witnesses) == 1, "provider selections must bind one installed-image capture")
        need(evidence["inventory_sha256"] == inventory_sha256, "provider selection inventory differs")
        need(package in packages and provider in packages, "provider selection outside finite package set")
        key = (package, field, dependency)
        need(key not in result, "duplicate provider selection")
        result[key] = row
    return result


def plan(value):
    need(type(value) is dict, "explicit input object required")
    selection_rows = value.get("provider_selections", [])
    pins.fields({key: row for key, row in value.items() if key != "provider_selections"}, ("schema_version", "metadata_role", "release_id", "snapshot_id", "packages", "sources",
                       "build_dependencies", "changed", "capacity"))
    need(type(value["schema_version"]) is int and value["schema_version"] == 1, "unsupported schema")
    need(value["metadata_role"] == "pre-change-release", "pre-change release metadata required to preserve prior provider edges")
    release_id, snapshot_id = text(value["release_id"]), text(value["snapshot_id"])
    packages = indexed(value["packages"], "name")
    need(packages, "nonempty finite release package set required")
    sources = indexed(value["sources"], "id")
    builds = indexed(value["build_dependencies"], "package")
    need(not (builds.keys() - packages.keys()), "build record outside release package set")
    for source in sources.values():
        pins.fields(source, ("id", "recipe_sha256", "sources"))
        # Identical pin validation to check_source_pins' provenance projection.
        pins.project(dict(package=dict(name=source["id"], version="1-1", arch="aarch64"),
                          recipe_sha256=source["recipe_sha256"], sources=source["sources"]))
    holds, unknown = defaultdict(set), set()
    units, members, dependencies = {}, defaultdict(set), {}
    relation_count = 0
    for package, row in sorted(packages.items()):
        s.identity(dict(name=package, version=row.get("version"), arch=row.get("arch"), sha256="0" * 64))
        for field in ("depend", "provides"):
            if field not in row:
                holds[package].add("UNKNOWN_" + field.upper())
                unknown.add(package)
        depend = relations(row.get("depend", []))
        relations(row.get("provides", []), provides=True)
        build = builds.get(package)
        if build is None:
            holds[package].add("UNKNOWN_BUILD_METADATA")
            unknown.add(package)
            build = {}
        else:
            pins.fields(build, ("package", "source_id", "makedepend", "checkdepend", "toolchain",
                               "disposition", "owner", "hold_reason"))
            need(build["disposition"] in ("build", "external", "hold"), "unknown build disposition")
            need(build["owner"] is None or text(build["owner"]), "owner must be text or null")
            need(build["hold_reason"] is None or text(build["hold_reason"]), "hold reason must be text or null")
            if build["disposition"] != "build":
                holds[package].add("EXTERNAL_UPDATE_REVIEW" if build["disposition"] == "external" else "EXPLICIT_HOLD")
            if build["disposition"] == "hold":
                need(build["hold_reason"] is not None, "held package requires a reason")
        if not build.get("owner"):
            holds[package].add("UNKNOWN_PACKAGE_OWNER")
        source_id = build.get("source_id")
        if source_id is not None:
            name(source_id)
        if source_id not in sources:
            holds[package].add("UNKNOWN_SOURCE_PINS")
        units[package] = "source:" + source_id if source_id else "package:" + package
        members[units[package]].add(package)
        dependencies[package] = [("depend", dependency) for dependency in depend]
        for field in ("makedepend", "checkdepend", "toolchain"):
            dependencies[package].extend((field, dependency) for dependency in relations(build.get(field, [])))
        relation_count += len(dependencies[package]) + len(row.get("provides", []))
        need(relation_count <= MAX_RELATIONS, "relation count bound")
    unmapped_sources = sorted(sources.keys() - {row.get("source_id") for row in builds.values()})
    capacity = value["capacity"]
    pins.fields(capacity, ("native_aarch64_slots", "owner", "reference"))
    slots = capacity["native_aarch64_slots"]
    need(slots is None or type(slots) is int and 0 <= slots <= 1024, "explicit capacity slots or null required")
    for field in ("owner", "reference"):
        need(capacity[field] is None or text(capacity[field]), "capacity text or null required")
    global_holds = []
    if unmapped_sources:
        global_holds.append("UNMAPPED_SOURCE_RECORDS")
    if not slots or not capacity["owner"] or not capacity["reference"]:
        global_holds.append("CAPACITY_OR_CAPACITY_OWNER_UNAVAILABLE")

    selections = provider_selections(selection_rows, packages, builds)
    used_selections = set()

    offers = defaultdict(set)
    for package, row in sorted(packages.items()):
        for offer in [package, *[r.relation(item)[0] for item in row.get("provides", [])]]:
            offers[offer].add(package)
    reverse, edges, issues, checks = defaultdict(list), [], [], 0
    for package in sorted(packages):
        for field, dependency in dependencies[package]:
            candidates = sorted(offers[r.relation(dependency)[0]])
            matches = []
            for provider in candidates:
                checks += 1
                need(checks <= MAX_CHECKS, "provider match count bound")
                if r.satisfies(dependency, packages[provider]):
                    matches.append(provider)
            selection_key = (package, field, dependency)
            selected = selections.get(selection_key)
            if selected is not None:
                need(len(matches) > 1 and selected["provider"] in matches, "selection must resolve an actually ambiguous satisfying provider")
                need(builds.get(package, {}).get("disposition") == "external" and
                     all(builds.get(provider, {}).get("disposition") == "external" for provider in candidates),
                     "installed provider selections are unchanged external baseline only")
                context = provider_context(package, field, dependency, candidates, packages)
                need(pins.digest(pins.encoded(context)) == selected["evidence"]["metadata_sha256"], "provider selection metadata differs")
                used_selections.add(selection_key)
            if len(matches) != 1:
                state = "UNAVAILABLE_DEPENDENCY" if not matches else "AMBIGUOUS_PROVIDER"
                if selected is None:
                    holds[package].add(state + ":" + field + ":" + dependency)
                issue = dict(package=package, field=field, dependency=dependency, status=state,
                             candidates=candidates, matching_providers=matches)
                if selected is not None:
                    issue.update(status="AMBIGUOUS_PROVIDER_BOUND_TO_INSTALLED_QUERY", selection=selected)
                issues.append(issue)
            # Rejected named candidates still carry conservative review impact:
            # a changed version/offer may have satisfied a consumer previously.
            for provider in candidates:
                edge = dict(package=package, field=field, dependency=dependency, provider=provider,
                            relation_satisfied=provider in matches)
                edges.append(edge)
                reverse[provider].append(edge)
                need(len(edges) <= MAX_RELATIONS, "edge count bound")

    need(used_selections == set(selections), "unused/stale provider selection")

    changed = value["changed"]
    pins.fields(changed, ("sources", "toolchains", "advisories"))
    reasons, roots = defaultdict(list), []
    unresolved_roots = []
    def seed(kind, target, selected, reference=None):
        row = dict(kind=kind, target=target, packages=sorted(selected))
        if reference is not None:
            row["reference"] = reference
        roots.append(row)
        if not selected:
            unresolved_roots.append(row)
        for package in sorted(selected):
            reasons[package].append(dict(kind=kind, target=target, **({"reference": reference} if reference else {})))
    for source_id in sorted(set(name(item) for item in rows(changed["sources"]))):
        seed("SOURCE_CHANGE", source_id, members.get("source:" + source_id, set()))
    for package in sorted(set(name(item) for item in rows(changed["toolchains"]))):
        seed("TOOLCHAIN_CHANGE", package, {package} if package in packages else set())
    advisory_roots = set()
    for row in rows(changed["advisories"]):
        pins.fields(row, ("package", "reference"))
        advisory_roots.add((name(row["package"]), text(row["reference"])))
    for package, reference in sorted(advisory_roots):
        # Never match advisory names through provides or source/pkgbase aliases.
        seed("ADVISORY_REVIEW", package, {package} if package in packages else set(), reference)
    if roots:
        for package in sorted(unknown):
            reasons[package].append(dict(kind="UNKNOWN_DEPENDENCY_COVERAGE"))
        for issue in issues:
            if issue["status"] == "UNAVAILABLE_DEPENDENCY":
                reasons[issue["package"]].append(dict(kind="UNAVAILABLE_BUILD_INPUT_REVIEW",
                                                      field=issue["field"], dependency=issue["dependency"]))
        if any("UNKNOWN_PROVIDES" in holds[package] for package in packages):
            global_holds.append("UNKNOWN_PROVIDER_COVERAGE_FULL_SET_REVIEW")
            for package in sorted(packages):
                reasons[package].append(dict(kind="UNKNOWN_PROVIDER_CONSERVATIVE_REVIEW"))
    if unresolved_roots:
        global_holds.append("UNRESOLVED_CHANGE_ROOTS_FULL_SET_REVIEW")
        for package in sorted(packages):
            reasons[package].append(dict(kind="UNRESOLVED_ROOT_CONSERVATIVE_REVIEW"))
    affected, queue, work = set(reasons), deque(sorted(reasons)), 0
    while queue:
        provider = queue.popleft()
        for sibling in sorted(members[units[provider]] - affected):
            reasons[sibling].append(dict(kind="SAME_SOURCE_BUILD", package=provider, unit=units[provider]))
            affected.add(sibling)
            queue.append(sibling)
        for edge in reverse[provider]:
            package = edge["package"]
            reasons[package].append(dict(kind="REVERSE_BUILD_INPUT", **edge))
            if package not in affected:
                affected.add(package)
                queue.append(package)
        work += 1 + len(members[units[provider]]) + len(reverse[provider])
        need(work <= MAX_WORK, "impact traversal work bound")

    for key, selection in selections.items():
        package, field, dependency = key
        context = next(issue for issue in issues if (issue["package"], issue["field"], issue["dependency"]) == key)
        need(package not in affected and not (set(context["candidates"]) & affected),
             "installed provider selection cannot discharge affected-package review")

    for edge in edges:
        if edge["package"] in affected and not edge["relation_satisfied"]:
            holds[edge["package"]].add("UNSATISFIED_NAMED_PROVIDER_REVIEW:" + edge["provider"])
    # Baseline prerequisites are not rebuild tasks, but an explicit hold or
    # incomplete input metadata must still block their consumers transitively.
    blocked_inputs = {package for package in packages
                      if holds[package] - ({"EXTERNAL_UPDATE_REVIEW"} if package not in affected else set())}
    queue = deque(sorted(blocked_inputs))
    while queue:
        provider = queue.popleft()
        for edge in reverse[provider]:
            package = edge["package"]
            if package not in blocked_inputs:
                blocked_inputs.add(package)
                queue.append(package)
    for edge in edges:
        if edge["package"] in affected and edge["provider"] not in affected and edge["provider"] in blocked_inputs:
            holds[edge["package"]].add("HELD_BASELINE_INPUT:" + edge["provider"])
    inputs = defaultdict(set)
    for edge in edges:
        inputs[edge["package"]].add(edge["provider"])
    prerequisite_closure, queue = set(affected), deque(sorted(affected))
    while queue:
        for provider in sorted(inputs[queue.popleft()]):
            if provider not in prerequisite_closure:
                prerequisite_closure.add(provider)
                queue.append(provider)

    graph = {units[package]: set() for package in affected}
    for edge in edges:
        if edge["package"] in affected and edge["provider"] in affected:
            graph[units[edge["package"]]].add(units[edge["provider"]])
    groups = components(graph)
    ids = {unit: f"group-{i:04d}" for i, group in enumerate(groups, 1) for unit in group}
    pending, group_rows = {}, {}
    for group in groups:
        group_id = ids[group[0]]
        package_names = sorted(package for unit in group for package in members[unit])
        prerequisites = sorted({ids[child] for unit in group for child in graph[unit]} - {group_id})
        cycle = len(group) > 1 or any(unit in graph[unit] for unit in group)
        direct_holds = sorted({hold for package in package_names for hold in holds[package]})
        if cycle:
            direct_holds.append("CYCLE_BOOTSTRAP_REVIEW_REQUIRED")
        group_rows[group_id] = dict(id=group_id, units=group, packages=package_names, cycle=cycle,
                                    prerequisites=prerequisites, holds=direct_holds)
        pending[group_id] = set(prerequisites)
    order, levels = [], []
    while pending:
        ready = sorted(group_id for group_id, deps in pending.items() if not deps)
        need(ready, "internal SCC ordering failure")
        levels.append(ready)
        for group_id in ready:
            row = group_rows[group_id]
            row["held_prerequisites"] = [other for other in row["prerequisites"] if group_rows[other]["held"]]
            row["held"] = bool(row["holds"] or row["held_prerequisites"] or global_holds)
            order.append(row)
            del pending[group_id]
        for deps in pending.values():
            deps.difference_update(ready)
    report = dict(schema_version=1, status="REBUILD_REVIEW_PLAN_NOT_EXECUTION", release_id=release_id,
                snapshot_id=snapshot_id, metadata_role=value["metadata_role"],
                scope="ONLY_EXPLICIT_PRE_CHANGE_RELEASE_BUILD_INPUTS",
                provider_policy="ALL_MATCHING_PROVIDERS_PLUS_REJECTED_NAMED_CANDIDATES_FOR_REVIEW",
                roots=roots, unresolved_roots=unresolved_roots, capacity=capacity, global_holds=global_holds,
                unmapped_sources=unmapped_sources,
                dependency_issues=issues, unknown_dependency_coverage=sorted(unknown),
                build_inputs=[edge for edge in edges if edge["package"] in affected],
                baseline_inputs=[dict(name=package, holds=sorted(holds[package] - {"EXTERNAL_UPDATE_REVIEW"}),
                                      held=package in blocked_inputs,
                                      owner=builds.get(package, {}).get("owner"),
                                      disposition=builds.get(package, {}).get("disposition", "unknown"),
                                      hold_reason=builds.get(package, {}).get("hold_reason"),
                                      prerequisites=sorted(inputs[package]))
                                 for package in sorted(prerequisite_closure - affected)],
                packages=[dict(name=package, version=packages[package]["version"], unit=units[package],
                               owner=builds.get(package, {}).get("owner"),
                               disposition=builds.get(package, {}).get("disposition", "unknown"),
                               hold_reason=builds.get(package, {}).get("hold_reason"),
                               holds=sorted(holds[package]), reasons=reasons[package]) for package in sorted(affected)],
                groups=order, prerequisite_levels=levels,
                unaffected_by_declared_graph=sorted(packages.keys() - affected),
                build_status="NOT_RUN", dependency_solution="NOT_ESTABLISHED", advisory_fix_status="UNKNOWN",
                limitations=["Order is conditional on review; cycles need an external bootstrap plan.",
                             "Runtime, make, check and explicit implicit-toolchain inputs are conservative build inputs.",
                             "Unchanged build-input providers must preexist in the selected snapshot; their availability is not tested.",
                             "Input metadata must precede changes; post-change/new dependency impact and final consistency are not established.",
                             "External packages require upstream update/availability review; they are not project build successes.",
                             "Capacity and owners are supplied claims, not measured capacity or ongoing staffing acceptance.",
                             "No conflict solving, ABI analysis, build, installation, hardware test, network or system mutation."])

    if selections:
        report["provider_selections"] = [selections[key] for key in sorted(selections)]
        report["limitations"].append("Installed-image provider query bindings discharge only exact unchanged-baseline ambiguity; all candidate edges remain.")
    return report


def text_report(value):
    lines = [value["status"], f"Release {value['release_id']}; snapshot {value['snapshot_id']}",
             "Metadata role: " + value["metadata_role"],
             "Builds NOT_RUN; dependency solution NOT_ESTABLISHED; advisory fixes UNKNOWN",
             "Capacity (operator supplied): " + json.dumps(value["capacity"], sort_keys=True)]
    if "input" in value:
        lines.append("Input SHA-256 (not authenticated): " + value["input"]["sha256"])
    for hold in value["global_holds"]:
        lines.append("GLOBAL HOLD: " + hold)
    for row in value["unresolved_roots"]:
        lines.append("UNRESOLVED ROOT: " + json.dumps(row, sort_keys=True))
    for row in value["dependency_issues"]:
        lines.append("DEPENDENCY REVIEW: " + json.dumps(row, sort_keys=True))
    for row in value["baseline_inputs"]:
        lines.append("BASELINE INPUT: " + json.dumps(row, sort_keys=True))
    for row in value["groups"]:
        lines.append(f"{row['id']} {'HELD' if row['held'] else 'CONDITIONAL'}: {', '.join(row['packages'])}")
        lines.append("  prerequisites: " + (", ".join(row["prerequisites"]) or "none"))
        lines.append("  holds: " + (", ".join(row["holds"] + row["held_prerequisites"]) or "none"))
    for row in value["packages"]:
        lines.append(f"{row['name']} owner={row['owner']} disposition={row['disposition']} hold_reason={row['hold_reason']}")
        lines.extend("  reason: " + json.dumps(reason, sort_keys=True) for reason in row["reasons"])
    lines.extend(value["limitations"])
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--input-sha256", required=True, help="explicitly selected input digest; not authentication")
    parser.add_argument("--format", choices=("json", "text"), default="json")
    args = parser.parse_args(argv)
    try:
        raw = s.read_file(args.input, pins.MAX_JSON)
        need(type(args.input_sha256) is str and r.HEX.fullmatch(args.input_sha256) and
             pins.digest(raw) == args.input_sha256, "input checksum mismatch")
        value = plan(s.decode(raw))
        value["input"] = dict(bytes=len(raw), sha256=pins.digest(raw), authenticated=False)
        value["implementation_dependencies"] = {str(path.relative_to(ROOT)): pins.digest(path.read_bytes()) for path in
                                                (DEPENDENCY, DEPENDENCY.with_name("release.py"), DEPENDENCY.with_name("source_delivery.py"))}
        need(s.read_file(args.input, pins.MAX_JSON) == raw, "input changed during planning")
        output = pins.encoded(value).decode() if args.format == "json" else text_report(value)
        need(len(output.encode()) <= pins.MAX_OUTPUT, "report byte bound")
        print(output, end="")
        return 0
    except (r.Error, s.Error, OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print("rebuild planner: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
