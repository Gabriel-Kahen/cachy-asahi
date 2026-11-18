#!/usr/bin/env python3
"""Validate worker Cargo metadata and retain an inert Linux-only source closure.

Never invokes Cargo, rustc, crate code, a compiler, or a container. This is a
conservative metadata source closure, not a compilation-unit or license approval.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tomllib
import time

TARGET = "aarch64-unknown-linux-gnu"
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
PINS = {
    "manifest": "fcae83c668f4aa18800450ca165d87cd929cbf1141f33177628c32e451a2582a",
    "lock": "0f12cdc2bd6e3838d67b08f0566f75f477bc83121196cf14d0ea5ce07faa3753",
    "audit": "01d8fdc321d58f0153019b576db5abfd3e4a66320d5c26507cb40df7e9ff7ff8",
}
BLOCKED = {("block", "0.1.6"), ("malloc_buf", "0.0.6"),
           ("objc-foundation", "0.1.1"), ("objc_id", "0.1.1")}
SUPPLEMENTAL_PIN = "74a1dbfa75de13df5c82525af8d684e38b772c31bdf912d61f7fe74e7646c591"
SUPPLEMENTAL_ALLOWED = {("defmt-parser", "1.0.0"), ("r-efi", "6.0.0"),
                        ("winapi-i686-pc-windows-gnu", "0.4.0"),
                        ("winapi-x86_64-pc-windows-gnu", "0.4.0")}
LIMIT = 64 * 1024 * 1024


class ClosureError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ClosureError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def read(path, limit=LIMIT):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), "symlink input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= limit,
                "unbounded, special, or hardlinked input")
        chunks, size = [], 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            require(size <= limit, "input exceeded bound")
        data = b"".join(chunks)
        require(len(data) == info.st_size, "input truncated/changed")
        return data
    finally:
        os.close(fd)


def load(data):
    def unique(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def indexed(rows, field):
    result = {}
    for row in rows:
        key = row[field]
        require(key not in result, "duplicate " + field)
        result[key] = row
    return result


def identity(package):
    return package["name"], package["version"]


def cfg_values(text):
    values = set()
    for line in text.splitlines():
        require(re.fullmatch(r'[a-zA-Z_][a-zA-Z_0-9]*(?:="[^"\n]*")?', line) is not None,
                "invalid rustc cfg line")
        require(line not in values, "duplicate rustc cfg line")
        values.add(line)
    required = {'unix', 'target_arch="aarch64"', 'target_os="linux"',
                'target_env="gnu"', 'target_family="unix"', 'target_pointer_width="64"',
                'target_endian="little"', 'target_vendor="unknown"'}
    require(required <= values and 'windows' not in values, "wrong native Linux ARM cfg")
    require(not any(x.startswith('feature=') for x in values), "feature cfg is not a platform cfg")
    return values


def platform(predicate, values):
    """Evaluate Cargo target cfg syntax only, never Python eval or Rust code."""
    if predicate is None:
        return True
    if not predicate.startswith("cfg("):
        return predicate == TARGET
    tokens = re.findall(r'[A-Za-z_][A-Za-z_0-9]*|"[^"\n]*"|[(),=]', predicate)
    require("".join(tokens) == re.sub(r"\s+", "", predicate), "invalid cfg tokens")
    pos = 0

    def token():
        nonlocal pos
        require(pos < len(tokens), "truncated cfg")
        value = tokens[pos]
        pos += 1
        return value

    def expression(depth=0):
        nonlocal pos
        require(depth < 64, "cfg nesting bound")
        key = token()
        require(re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", key) is not None, "invalid cfg atom")
        require(key != "feature", "unsupported Cargo feature predicate")
        if pos < len(tokens) and tokens[pos] == "(":
            token()
            args = []
            while pos < len(tokens) and tokens[pos] != ")":
                args.append(expression(depth + 1))
                require(pos < len(tokens), "truncated cfg expression")
                if tokens[pos] != ")":
                    require(token() == ",", "invalid cfg separator")
            require(token() == ")", "invalid cfg close")
            require(key in ("all", "any", "not", "cfg"), "unknown cfg operator")
            if key in ("not", "cfg"):
                require(len(args) == 1, "cfg operator arity")
                return not args[0] if key == "not" else args[0]
            return all(args) if key == "all" else any(args)
        if pos < len(tokens) and tokens[pos] == "=":
            token()
            value = token()
            require(value.startswith('"'), "invalid cfg value")
            key += "=" + value
        return key in values

    result = expression()
    require(pos == len(tokens), "extra cfg tokens")
    return result


def canonical_platform(predicate):
    if predicate is None or not predicate.startswith("cfg("):
        return predicate
    # Cargo renders target cfg with normalized whitespace. Preserve quoted
    # values while comparing tokens from pinned source/actual metadata.
    tokens = re.findall(r'[A-Za-z_][A-Za-z_0-9]*|"[^"\n]*"|[(),=]', predicate)
    require("".join(tokens) == re.sub(r"\s+", "", predicate), "invalid cfg tokens")
    return "".join(tokens)


def declarations(manifest):
    result = []
    groups = [(None, manifest)] + list(manifest.get("target", {}).items())
    for target, tables in groups:
        for table, kind in (("dependencies", None), ("build-dependencies", "build"),
                            ("dev-dependencies", "dev")):
            for alias, raw in tables.get(table, {}).items():
                row = {"version": raw} if isinstance(raw, str) else raw
                require(not any(k in row for k in ("path", "git", "registry")),
                        "unsupported unpinned dependency source")
                result.append({"alias": alias, "name": row.get("package", alias), "kind": kind,
                               "target": target, "optional": row.get("optional", False),
                               "features": row.get("features", []),
                               "default": row.get("default-features", True),
                               "version": row.get("version", "*")})
    return result


def features(manifest, deps):
    result = dict(manifest.get("features", {}))
    suppressed = {x[4:] for vals in result.values() for x in vals if x.startswith("dep:")}
    for row in deps:
        name = row["alias"]
        if row["optional"] and name not in suppressed and name not in result:
            result[name] = ["dep:" + name]
    return result


def active_features(feature_map, enabled, deps):
    require(len(enabled) == len(set(enabled)), "duplicate selected feature")
    require(set(enabled) <= set(feature_map), "unknown selected feature")
    aliases = {x["alias"] for x in deps}
    activated, forwarded = set(), {}
    for feature in enabled:
        for item in feature_map[feature]:
            if item.startswith("dep:"):
                require(item[4:] in aliases, "unknown feature dependency")
                activated.add(item[4:])
            elif "/" in item:
                alias, child = item.split("/", 1)
                weak = alias.endswith("?")
                alias = alias.rstrip("?")
                require(alias in aliases, "unknown forwarded feature dependency")
                forwarded.setdefault(alias, []).append((child, weak))
                if not weak:
                    activated.add(alias)
            else:
                require(item in enabled, "missing transitive local feature")
    return activated, forwarded


def normalized_req(version):
    return ", ".join(re.sub(r"^(?=[0-9])", "^", re.sub(r"\s+", "", x))
                     for x in version.split(","))


def version_matches(version, requirement):
    """Fail-closed subset of semver covering the pinned stable lock requirements."""
    base = version.split("+", 1)[0]
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", base), "unreviewed prerelease version")
    actual = tuple(map(int, base.split(".")))
    for part in requirement.split(","):
        match = re.fullmatch(r"\s*([<>=^~]*)\s*([0-9xX*]+(?:\.[0-9xX*]+){0,2})\s*", part)
        require(match is not None, "unreviewed semver requirement")
        op, raw = match.groups()
        bits = raw.split(".")
        fixed = []
        for bit in bits:
            if bit in ("x", "X", "*"):
                break
            fixed.append(int(bit))
        require(all(x in ("x", "X", "*") for x in bits[len(fixed):]), "invalid version wildcard")
        low = tuple(fixed + [0] * (3 - len(fixed)))
        prefix = actual[:len(fixed)]
        if not fixed:
            require(op in ("", "="), "unreviewed wildcard comparator")
            okay = True
        elif op in ("=",):
            okay = prefix == tuple(fixed)
        elif op in ("<", ">=", ">", "<="):
            compared = prefix if len(fixed) < 3 else actual
            target = tuple(fixed)
            okay = {"<": compared < target, ">=": compared >= target,
                    ">": compared > target, "<=": compared <= target}[op]
        elif "*" in raw or "x" in raw.lower():
            require(op == "", "unreviewed wildcard operator")
            okay = prefix == tuple(fixed)
        else:
            require(op in ("", "^", "~"), "unknown semver comparator")
            if op == "~":
                bump = 0 if len(fixed) == 1 else 1
            else:
                bump = next((i for i, x in enumerate(fixed) if x), len(fixed) - 1)
            upper = list(low)
            upper[bump] += 1
            upper[bump + 1:] = [0] * (2 - bump)
            okay = low <= actual < tuple(upper)
        if not okay:
            return False
    return True


def check_package(package, manifest, deps):
    require(identity(package) == identity(manifest["package"]), "metadata manifest identity drift")
    require(package["features"] == features(manifest, deps), "metadata feature declaration drift")
    expected = []
    for row in deps:
        expected.append((row["name"], row["alias"] if row["alias"] != row["name"] else None,
                         row["kind"], canonical_platform(row["target"]), row["optional"], row["default"],
                         tuple(sorted(row["features"])), normalized_req(row["version"])))
    actual = []
    for row in package["dependencies"]:
        require(row.get("source") == REGISTRY and not row.get("path"), "metadata dependency source drift")
        require(row.get("registry") in (None, "https://github.com/rust-lang/crates.io-index"),
                "metadata alternate registry")
        actual.append((row["name"], row["rename"], row["kind"], canonical_platform(row["target"]), row["optional"],
                       row["uses_default_features"], tuple(sorted(row["features"])), row["req"]))
    require(sorted(expected, key=repr) == sorted(actual, key=repr), "metadata dependency declaration drift")
    target_kinds = [kind for target in package["targets"] for kind in target["kind"]]
    proc = manifest.get("lib", {}).get("proc-macro", False)
    for target in package["targets"]:
        if any(kind in ("lib", "rlib", "dylib", "cdylib", "staticlib", "proc-macro") for kind in target["kind"]):
            require(target["name"] == manifest.get("lib", {}).get("name", package["name"].replace("-", "_")),
                    "library target name drift")
    build = manifest.get("package", {}).get("build")
    require(("proc-macro" in target_kinds) == proc, "proc-macro target drift")
    if build is False:
        require("custom-build" not in target_kinds, "unexpected build script")
    elif isinstance(build, str):
        require("custom-build" in target_kinds, "missing build script target")


def vendor_files(root, row, lock):
    root = Path(root) / (row["name"] + "-" + row["version"])
    checksums_data = read(root / ".cargo-checksum.json", 8 * 1024 * 1024)
    checksums = load(checksums_data)
    require(checksums["package"] == lock["checksum"] == row["archive_sha256"], "registry checksum drift")
    expected = checksums["files"]
    require(len(expected) <= 20000 and digest(canonical(expected)) == row["source_files_sha256"],
            "source ledger drift")
    paths = {}
    total = 0
    deadline = time.monotonic() + 30
    for number, path in enumerate(root.rglob("*"), 1):
        require(number <= 40000 and time.monotonic() <= deadline, "vendor traversal bound")
        require(not path.is_symlink(), "vendor symlink")
        if path.is_dir():
            continue
        name = path.relative_to(root).as_posix()
        data = read(path)
        total += len(data)
        require(total <= 256 * 1024 * 1024, "vendor expanded bound")
        if name != ".cargo-checksum.json":
            require(name in expected and digest(data) == expected[name], "vendor file hash/extra drift")
        paths[name] = data
    require(set(paths) == set(expected) | {".cargo-checksum.json"}, "missing vendor file")
    require(digest(paths["Cargo.toml"]) == row["normalized_manifest_sha256"], "vendor manifest drift")
    return paths


def supplemental_notice(key, row, files, supplemental_data, notice_root, pin=SUPPLEMENTAL_PIN):
    require(key in SUPPLEMENTAL_ALLOWED and supplemental_data is not None,
            "selected dependency notice evidence missing")
    require(digest(supplemental_data) == pin, "supplemental notice ledger pin mismatch")
    supplement = load(supplemental_data)
    require(supplement["cargo_lock_sha256"] == PINS["lock"], "supplemental lock mismatch")
    entries = {identity(x): x for x in supplement["entries"]}
    require(len(entries) == len(supplement["entries"]), "ambiguous supplemental identities")
    complete = {k for k, e in entries.items() if e["notice_status"] == "COMPLETE SOURCE EVIDENCE"}
    require(complete == SUPPLEMENTAL_ALLOWED, "unknown supplemental grant set")
    entry = entries[key]
    require(not entry["blockers"] and entry["registry_source_archive_sha256"] == row["archive_sha256"]
            and entry["declared_spdx"] == row["declared_spdx"], "supplemental source/license binding")
    for declaration in entry["retained_declarations"]:
        path = declaration["path"]
        require(path in files and digest(files[path]) == declaration["sha256"], "supplemental declaration/source drift")
    comparison = entry["source_comparison"]
    require(not comparison["different_source_bytes"] and not comparison["missing_source_paths"],
            "supplemental source mismatch")
    manifest = comparison["manifest"]
    require(manifest["registry_manifest_sha256"] == row["normalized_manifest_sha256"]
            and manifest["version_matches"] and manifest["declared_license_matches"], "supplemental manifest drift")
    notices = []
    require(entry["notices"], "missing supplemental notice texts")
    chosen = entry.get("preferred_branch_for_notice_collection", "MIT")
    require(chosen == "MIT", "unreviewed supplemental license choice")
    selected_notices = [n for n in entry["notices"] if n.get("contains_full_text_for", "MIT") == chosen]
    require(selected_notices, "chosen complete license notice missing")
    for notice in selected_notices:
        name = Path(notice["upstream_path"]).name
        require(name == notice["upstream_path"], "unsafe supplemental notice path")
        if notice_root is None:
            data = notice.get("full_notice_text", "").encode("utf-8")
            origin = {"inline_utf8": data.decode("utf-8")}
        else:
            path = Path(notice_root) / key[0] / name
            data = read(path, 1024 * 1024)
            origin = {"input_path": str(path.absolute())}
        require(len(data) == notice["bytes"] and digest(data) == notice["sha256"], "supplemental notice bytes drift")
        notices.append({"package": key[0], "version": key[1], "name": name, "chosen_license": chosen,
                        "sha256": digest(data), "bytes": len(data), **origin})
    return notices


def worker_check(worker, metadata_data, inputs, cfg_data):
    require(worker.get("schema_version") == 1, "worker evidence schema")
    require(worker.get("host") == worker.get("target") == TARGET, "native host/target required")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", worker.get("image_id", "")), "unpinned worker image")
    argv = ["/usr/bin/cargo", "metadata", "--format-version", "1", "--offline", "--locked",
            "--filter-platform", TARGET, "--manifest-path", worker.get("manifest_path")]
    require(worker.get("metadata_argv") == argv, "wrong metadata command or feature flags")
    require(isinstance(argv[-1], str) and argv[-1].startswith("/") and argv[-1].endswith("/Cargo.toml"),
            "worker manifest path")
    expected = dict(inputs, metadata=digest(metadata_data), cfg=digest(cfg_data))
    require(worker.get("sha256") == expected, "worker input/output hash binding")
    # Caller/coordinator must independently verify this evidence against retained
    # worker logs and image pins. JSON cannot authenticate its own origin.


def validate(metadata_data, worker, manifest_data, lock_data, audit_data, cfg_data, vendor,
             pins=PINS, expected_count=168, supplemental_data=None, notice_root=None):
    inputs = {"manifest": digest(manifest_data), "lock": digest(lock_data), "audit": digest(audit_data)}
    require(inputs == pins, "original manifest/lock/all-target audit pin mismatch")
    worker_check(worker, metadata_data, inputs, cfg_data)
    cfg = cfg_values(cfg_data.decode())
    metadata, audit = load(metadata_data), load(audit_data)
    manifest, lock = tomllib.loads(manifest_data.decode()), tomllib.loads(lock_data.decode())
    require(lock.get("version") == 4 and len(lock["package"]) == expected_count, "original lock cardinality/schema")
    locked = {identity(x): x for x in lock["package"]}
    require(len(locked) == expected_count, "ambiguous lock identity")
    local = identity(manifest["package"])
    require(locked.get(local, {}).get("source") is None, "root not local lock entry")
    for key, row in locked.items():
        require(key == local or row.get("source") == REGISTRY, "unknown locked source")
        require(key == local or re.fullmatch(r"[a-f0-9]{64}", row.get("checksum", "")), "unknown locked checksum")
    ledger = {identity(x): x for x in audit["registry_sources"]}
    require(len(ledger) == expected_count - 1 and set(ledger) == set(locked) - {local}, "incomplete original all-target ledger")
    require(audit["cargo_lock_sha256"] == inputs["lock"], "audit lock binding")
    require(audit["locked_packages"] == expected_count and audit["registry_packages"] == expected_count - 1,
            "audit cardinality mismatch")
    for key, row in ledger.items():
        require(row["registry"] == REGISTRY and row["checksum"] == "PASS"
                and row["archive_sha256"] == locked[key]["checksum"], "unknown audit source/checksum")
    require(metadata.get("version") == 1 and isinstance(metadata.get("resolve"), dict), "missing resolve graph")
    packages = indexed(metadata["packages"], "id")
    require(len({identity(x) for x in packages.values()}) == len(packages), "ambiguous package identity")
    for package in packages.values():
        key = identity(package)
        require(key in locked, "metadata package outside original lock")
        require(package["source"] == locked[key].get("source"), "metadata package source drift")
    root = metadata["resolve"]["root"]
    require(root in packages and identity(packages[root]) == local, "wrong resolve root")
    require(packages[root]["manifest_path"] == worker["manifest_path"], "worker/root manifest mismatch")
    require(metadata["workspace_members"] == [root] and metadata["workspace_default_members"] == [root],
            "unexpected workspace members")
    nodes = indexed(metadata["resolve"]["nodes"], "id")
    require(root in nodes and set(nodes) <= set(packages), "missing package/node")
    seen, todo = set(), [root]
    while todo:
        node_id = todo.pop()
        if node_id in seen:
            continue
        require(node_id in nodes, "edge to missing node")
        seen.add(node_id)
        node = nodes[node_id]
        require(len(node["dependencies"]) == len(set(node["dependencies"])), "duplicate node dependency")
        require(set(node["dependencies"]) == {edge["pkg"] for edge in node["deps"]}, "legacy/typed edge disagreement")
        todo.extend(node["dependencies"])
    require(seen == set(nodes), "extra unreachable resolve nodes")
    sources, manifests, dep_rows, notices = {}, {}, {}, []
    for node_id in sorted(nodes):
        package = packages[node_id]
        key = identity(package)
        if key == local:
            data = manifest
        else:
            require(key not in BLOCKED, "selected unresolved historical notice dependency")
            files = vendor_files(vendor, ledger[key], locked[key])
            if ledger[key]["license_evidence_blockers"]:
                notices.extend(supplemental_notice(key, ledger[key], files, supplemental_data, notice_root))
            sources[key] = files
            data = tomllib.loads(files["Cargo.toml"].decode())
        deps = declarations(data)
        check_package(package, data, deps)
        custom = any("custom-build" in target["kind"] for target in package["targets"])
        if key != local:
            scripts = ledger[key].get("build_scripts", [])
            require(custom == bool(scripts), "metadata/locked build script target drift")
            for script in scripts:
                require(script["path"] in files and digest(files[script["path"]]) == script["sha256"],
                        "build script source drift")
        else:
            require(not custom, "unexpected root build script")
        manifests[node_id], dep_rows[node_id] = data, deps
    for name in ("gettext-rs", "gettext-sys"):
        selected = [node for node_id, node in nodes.items() if packages[node_id]["name"] == name]
        for node in selected:
            require("gettext-system" in node["features"], "system gettext feature required")
    for node_id, node in nodes.items():
        if packages[node_id]["name"] == "system-deps":
            require("binary" not in node["features"], "system-deps binary feature forbidden")
    edges, host_nodes = [], set()
    for node_id, node in nodes.items():
        deps = dep_rows[node_id]
        feature_map = features(manifests[node_id], deps)
        activated, forwarded = active_features(feature_map, node["features"], deps)
        potential = {i for i, row in enumerate(deps) if platform(row["target"], cfg)
                     and (row["kind"] != "dev" or node_id == root)}
        expected = {i for i in potential if not deps[i]["optional"] or deps[i]["alias"] in activated}
        matched = set()
        for edge in node["deps"]:
            require(edge["pkg"] in nodes and edge["dep_kinds"], "missing edge target/kinds")
            require(len(edge["dep_kinds"]) == len({(k["kind"], canonical_platform(k["target"])) for k in edge["dep_kinds"]}),
                    "duplicate edge kind")
            target_package = packages[edge["pkg"]]
            edge_active = False
            kind_seen = set()
            for kind in edge["dep_kinds"]:
                matches = [i for i, row in enumerate(deps)
                           if (row["alias"].replace("-", "_") if row["alias"] != row["name"]
                               else manifests[edge["pkg"]].get("lib", {}).get("name", row["name"].replace("-", "_"))) == edge["name"]
                           and row["name"] == target_package["name"]
                           and (row["kind"], canonical_platform(row["target"])) == (kind["kind"], canonical_platform(kind["target"]))]
                require(len(matches) == 1 and matches[0] not in kind_seen, "extra/ambiguous target or kind edge")
                i = matches[0]
                kind_seen.add(i)
                active = i in expected
                if i in potential:
                    edge_active = True
                if active:
                    require(i not in matched, "duplicate active dependency edge")
                    matched.add(i)
                row = deps[i]
                require(version_matches(target_package["version"], row["version"]), "edge version does not satisfy source requirement")
                locked_edges = locked[identity(packages[node_id])].get("dependencies", [])
                require(any(x.split(" ")[0] == target_package["name"]
                            and (len(x.split(" ")) == 1 or x.split(" ")[1] == target_package["version"])
                            for x in locked_edges), "edge outside locked dependencies")
                require(sum(k[0] == target_package["name"] for k in locked) == 1
                        or any(x.split(" ")[:2] == [target_package["name"], target_package["version"]]
                               for x in locked_edges), "ambiguous unversioned lock edge")
                needed = set(row["features"]) if active else set()
                if active and row["default"] and "default" in target_package["features"]:
                    needed.add("default")
                if active:
                    needed.update(f for f, weak in forwarded.get(row["alias"], [])
                                  if not weak or not row["optional"] or row["alias"] in activated)
                require(needed <= set(nodes[edge["pkg"]]["features"]), "missing dependency feature activation")
                proc = any("proc-macro" in x["kind"] for x in target_package["targets"])
                if i in potential and (kind["kind"] == "build" or proc):
                    host_nodes.add(edge["pkg"])
                edges.append({"from": node_id, "to": edge["pkg"], "alias": edge["name"],
                              "kind": kind["kind"], "target": kind["target"], "platform_active": i in potential, "feature_active": active,
                              "required_features": sorted(needed), "proc_macro": proc})
            # Cargo retains inactive dep_kinds on a package edge whenever another
            # declaration for the same package survives --filter-platform.
            require(edge_active, "edge has no active source dependency")
        require(matched == expected, "missing active source dependency edge")
    if "default" in packages[root]["features"]:
        require("default" in nodes[root]["features"], "root default feature missing")
    # Host build/proc-macro transitive dependencies also execute/compile on host.
    todo = list(host_nodes)
    while todo:
        current = todo.pop()
        for edge in edges:
            if edge["from"] == current and edge["platform_active"] and edge["kind"] != "dev" and edge["to"] not in host_nodes:
                host_nodes.add(edge["to"])
                todo.append(edge["to"])
    report = {"schema_version": 1, "status": "VALIDATED METADATA SOURCE CLOSURE",
              "scope": "Linux/aarch64 filtered metadata source superset; not all-target closure or build approval",
              "host": TARGET, "target": TARGET, "sha256": dict(inputs, metadata=digest(metadata_data), cfg=digest(cfg_data)),
              "supplemental_notice_ledger_sha256": digest(supplemental_data) if supplemental_data is not None else None,
              "supplemental_notices": notices,
              "original_locked_packages": expected_count, "selected_registry_packages": len(sources),
              "retained_original_lock": True, "retained_original_all_target_audit": True,
              "selected_nodes": [{"id": node_id, "name": packages[node_id]["name"],
                                  "version": packages[node_id]["version"], "features": sorted(nodes[node_id]["features"]),
                                  "host_dependency": node_id in host_nodes,
                                  "custom_build": any("custom-build" in target["kind"] for target in packages[node_id]["targets"])} for node_id in sorted(nodes)],
              "selected_edges": sorted(edges, key=lambda x: canonical(x)),
              "excluded_registry_packages": [list(k) for k in sorted(set(ledger) - set(sources))],
              "native_compilation": "NOT RUN", "license_compatibility": "NOT ACCEPTED",
              "subset_only_offline_resolution": "NOT RUN; unchanged lock may require excluded target manifests",
              "feature_limit": "Metadata unions package features; not a host/target compilation-unit feature graph",
              "build_scripts": "Source/behavior review and actual build receipts are separate gates",
              "worker_origin": "Must be independently verified against retained native worker logs/image"}
    return report, sources


def retain(destination, report, sources, original):
    destination = Path(destination).absolute()
    require(destination.is_relative_to(Path("/tmp")) and destination != Path("/tmp"), "output must be fresh under /tmp")
    require(not any(p.is_symlink() for p in (destination, *destination.parents)), "output symlink")
    require(not destination.exists(), "output must not exist")
    destination.mkdir(mode=0o700)
    for name, data in original.items():
        require(name in {"Cargo.lock", "Cargo.toml", "cargo-audit-all-target.json", "metadata.json", "worker.json", "target-cfg.txt"},
                "unknown retained evidence path")
        (destination / name).write_bytes(data)
        (destination / name).chmod(0o600)
    for (name, version), files in sorted(sources.items()):
        for relative, data in sorted(files.items()):
            parts = relative.split("/")
            require(parts and all(p not in ("", ".", "..") for p in parts) and not relative.startswith("/")
                    and "\\" not in relative, "unsafe vendor path")
            output = destination / "vendor" / (name + "-" + version) / relative
            output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            output.write_bytes(data)
            output.chmod(0o600)
    for notice in report.get("supplemental_notices", []):
        data = (read(notice["input_path"], 1024 * 1024) if "input_path" in notice
                else notice["inline_utf8"].encode("utf-8"))
        require(digest(data) == notice["sha256"] and len(data) == notice["bytes"], "notice changed before retention")
        output = destination / "license-notices" / (notice["package"] + "-" + notice["version"]) / notice["name"]
        output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        output.write_bytes(data)
        output.chmod(0o600)
    (destination / "linux-closure.json").write_bytes(canonical(report) + b"\n")
    (destination / "linux-closure.json").chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("metadata", "worker", "manifest", "lock", "audit", "cfg", "vendor", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--supplemental", type=Path)
    parser.add_argument("--notice-root", type=Path)
    args = parser.parse_args()
    try:
        blobs = {name: read(getattr(args, name)) for name in ("metadata", "worker", "manifest", "lock", "audit", "cfg")}
        report, sources = validate(blobs["metadata"], load(blobs["worker"]), blobs["manifest"], blobs["lock"],
                                   blobs["audit"], blobs["cfg"], args.vendor,
                                   supplemental_data=read(args.supplemental) if args.supplemental else None,
                                   notice_root=args.notice_root)
        retain(args.output, report, sources, {"Cargo.lock": blobs["lock"], "Cargo.toml": blobs["manifest"],
               "cargo-audit-all-target.json": blobs["audit"], "metadata.json": blobs["metadata"],
               "worker.json": blobs["worker"], "target-cfg.txt": blobs["cfg"]})
    except (ClosureError, KeyError, TypeError, OSError, ValueError) as error:
        parser.exit(1, "REFUSED: " + str(error) + "\n")
    print(json.dumps({"status": report["status"], "selected_registry_packages": len(sources), "output": str(args.output)}))


if __name__ == "__main__":
    main()
