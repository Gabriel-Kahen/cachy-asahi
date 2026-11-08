#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Local signed pacman staging. Never installs, uploads, or edits pacman trust."""
import argparse
import base64
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

HEX = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
RELATION = re.compile(r"([A-Za-z0-9@._+-]+)(?:(>=|<=|=|>|<)([^\s]+))?\Z")
MODELS = {"m2-air-13", "m2-air-15"}
FUNCTIONAL = {"accelerated-login", "scaling-brightness", "keyboard-trackpad", "wifi-bluetooth",
              "audio-speaker-protection", "headset-microphone", "browser-video", "lock-unlock",
              "repeated-sleep-wake", "applications-preserved"}
LIFECYCLE = {"fresh-install", "existing-config", "interrupted-setup", "repeat-setup", "remove",
             "reinstall", "user-edits-preserved"}
RECOVERY = {"repository-trust-bootstrap", "repository-fresh-install", "previous-release-upgrade",
            "base-overlay-full-upgrade", "interrupted-upgrade", "failed-upgrade", "service-startup-failure",
            "rollback", "boot-recovery", "session-recovery", "functional-baseline-rerun"}


class Error(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Error(message)


def run(argv, *, env=None):
    p = subprocess.run([str(a) for a in argv], capture_output=True, env=env)
    require(p.returncode == 0, f"command failed: {argv[0]}: {p.stderr.decode(errors='replace')[-3000:]}")
    return p.stdout


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def load(path):
    try:
        return json.loads(path.read_text())
    except (ValueError, OSError) as e:
        raise Error(f"cannot read JSON {path}: {e}") from e


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")


def valid_name(value):
    require(isinstance(value, str) and NAME.fullmatch(value), f"invalid name: {value!r}")
    require(value != "current", "'current' is a reserved name")
    return value


def file_ref(base, ref):
    require(isinstance(ref, dict) and HEX.fullmatch(ref.get("sha256", "")), "file reference needs SHA-256")
    rel = Path(ref["path"])
    require(not rel.is_absolute() and ".." not in rel.parts and rel.parts, "unsafe input path")
    p = base / rel
    require(all(not x.is_symlink() for x in [p, *p.parents] if x != base.parent), "symlink input rejected")
    require(p.is_file() and p.resolve().is_relative_to(base.resolve()), f"missing input file: {rel}")
    require(sha(p) == ref["sha256"], f"checksum mismatch: {rel}")
    return p


def text_field(obj, key):
    require(isinstance(obj.get(key), str) and bool(obj[key].strip()), f"missing {key}")
    return obj[key]


def archive_members(path):
    members = run(["bsdtar", "-tf", path]).decode().splitlines()
    normalized = [m.removeprefix("./").rstrip("/") for m in members]
    require(len(normalized) == len(set(normalized)), f"duplicate archive entries: {path.name}")
    for name in normalized:
        require(name and not name.startswith("/") and ".." not in Path(name).parts and Path(name).as_posix() == name,
                f"unsafe archive entry: {name}")
    return dict(zip(normalized, members))


def pkginfo(path):
    members = archive_members(path)
    require(".PKGINFO" in members, f"missing .PKGINFO: {path.name}")
    info = {}
    for line in run(["bsdtar", "-xOf", path, members[".PKGINFO"]]).decode().splitlines():
        if not line or line.startswith("#"):
            continue
        require(" = " in line, "malformed .PKGINFO")
        k, v = line.split(" = ", 1)
        info.setdefault(k, []).append(v)
    for key in ("pkgname", "pkgver", "arch"):
        require(len(info.get(key, [])) == 1, f"missing/duplicate .PKGINFO {key}")
    valid_name(info["pkgname"][0])
    require(info["arch"][0] in {"aarch64", "any"}, "package is not aarch64/any")
    require(info.get("license"), "package license metadata missing")
    return {"name": info["pkgname"][0], "version": info["pkgver"][0], "arch": info["arch"][0],
            "license": info["license"], "depend": info.get("depend", []),
            "provides": info.get("provides", []), "conflict": info.get("conflict", []),
            "replaces": info.get("replaces", []),
            "files": sorted(n for n in members if not n.startswith(".") and not members[n].endswith("/"))}


def relation(value):
    m = RELATION.fullmatch(value)
    require(m, f"unsupported ALPM relation: {value}")
    return m.groups()


def satisfies(dep, package):
    name, op, version = relation(dep)
    offers = [(package["name"], "=", package["version"])] + [relation(x) for x in package.get("provides", [])]
    for offered, provide_op, provided in offers:
        require(provide_op in {None, "="}, "provides supports only unversioned or '=' relations")
        if offered != name or (op and provided is None):
            continue
        if not op:
            return True
        cmp = int(run(["vercmp", provided, version]).strip())
        if {"=": cmp == 0, ">": cmp > 0, "<": cmp < 0, ">=": cmp >= 0, "<=": cmp <= 0}[op]:
            return True
    return False


def dependency_check(spec, overlay, base):
    require(base.get("schema_version") == 1 and base.get("snapshot_id") == spec["base"]["snapshot_id"],
            "base inventory/snapshot mismatch")
    require(base.get("target_arch") == "aarch64" and base.get("kind") == "complete-target-transaction",
            "base must describe the full target transaction, not repository alternatives")
    packages = base.get("packages", [])
    require(packages, "empty base inventory")
    for p in packages:
        valid_name(p["name"])
        text_field(p, "version")
        require(p.get("arch") in {"aarch64", "any"}, "wrong base architecture")
        for key in ("depend", "provides", "conflict", "files"):
            require(isinstance(p.get(key), list), f"base package missing {key}")
    require(len({p["name"] for p in packages}) == len(packages), "duplicate base packages")
    policy = spec["policy"]
    selected = policy.get("selected_packages", [])
    require(selected and len(set(selected)) == len(selected) and set(selected) == {p["name"] for p in overlay},
            "artifact set differs from explicitly selected package set")
    protected = set(policy.get("protected_packages", []))
    require(protected and protected <= {p["name"] for p in packages}, "protected platform list missing from base")
    for p in overlay:
        require(p["name"] not in protected, "overlay replaces a protected platform package")
        require(not any(relation(x)[0] in protected for x in p["provides"] + p["replaces"] + p["conflict"]),
                "overlay relation targets a protected platform package")
        require(not p["replaces"], "replaces requires manual base redesign; unsupported by this transaction checker")
    effective = [p for p in packages if p["name"] not in selected] + overlay
    owners = {}
    for p in effective:
        for dep in p.get("depend", []):
            require(any(satisfies(dep, q) for q in effective), f"unsatisfied dependency: {p['name']}: {dep}")
        for c in p.get("conflict", []):
            require(not any(q["name"] != p["name"] and satisfies(c, q) for q in effective),
                    f"package conflict: {p['name']}: {c}")
        for filename in p["files"]:
            require(isinstance(filename, str) and filename and not filename.startswith("/") and
                    ".." not in Path(filename).parts and Path(filename).as_posix() == filename,
                    "unsafe or noncanonical file ownership record")
            require(filename not in owners, f"file conflict: {filename}: {owners.get(filename)} / {p['name']}")
            owners[filename] = p["name"]
    versions = {p["name"]: p["version"] for p in effective}
    require(policy.get("coordinated_sets"), "no coordinated desktop compatibility set")
    for group in policy["coordinated_sets"]:
        text_field(group, "name")
        require(group.get("versions"), "empty coordinated compatibility set")
        for name, version in group["versions"].items():
            require(versions.get(name) == version, f"coordinated version mismatch: {name}")


def provenance_check(p, record, digest, spec):
    require(record.get("schema_version") == 1 and record.get("artifact_sha256") == digest,
            "provenance artifact checksum mismatch")
    require(record.get("package") == {k: p[k] for k in ("name", "version", "arch")}, "provenance package mismatch")
    require(record.get("source_commit") == spec["source_commit"], "provenance project commit mismatch")
    require(HEX.fullmatch(record.get("recipe_sha256", "")), "recipe checksum missing")
    require(record.get("licenses") and record.get("sources"), "source/license provenance missing")
    for src in record["sources"]:
        text_field(src, "url")
        require(HEX.fullmatch(src.get("sha256", "")) or re.fullmatch(r"[0-9a-f]{40}", src.get("commit", "")),
                "source is not pinned by SHA-256 or full Git commit")
    build = record.get("build", {})
    require(build.get("execution") in {"native", "cross", "emulated", "synthetic"}, "build execution not labeled")
    text_field(build, "architecture")
    text_field(build, "environment")
    valid_name(build.get("snapshot_id"))


def gpg_env(home, root):
    home = Path(home).resolve()
    require(home.is_dir() and not home.is_relative_to(root.resolve()), "GPG home must exist outside repository storage")
    require(not home.is_relative_to(Path(__file__).resolve().parents[2]), "GPG home must stay outside project checkout")
    return dict(os.environ, GNUPGHOME=str(home))


def fingerprint(value):
    require(re.fullmatch(r"[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}", value), "supply a full signing fingerprint")
    return value.upper()


def sign(path, key, env):
    run(["gpg", "--batch", "--local-user", key, "--digest-algo", "SHA256", "--detach-sign", "--output", str(path) + ".sig", path], env=env)
    verify_signature(path, key, env)


def verify_signature(path, key, env):
    data = run(["gpg", "--batch", "--no-auto-key-retrieve", "--status-fd", "1", "--verify", str(path) + ".sig", path], env=env)
    good = False
    rejected = {"KEYEXPIRED", "SIGEXPIRED", "EXPKEYSIG", "EXPSIG", "REVKEYSIG", "KEYREVOKED", "BADSIG",
                "ERRSIG", "NO_PUBKEY", "NODATA", "FAILURE", "ERROR"}
    for line in data.decode().splitlines():
        words = line.split()
        if len(words) > 1 and words[0] == "[GNUPG:]":
            require(words[1] not in rejected, f"unacceptable signature/key status: {words[1]}")
        if len(words) >= 11 and words[1] == "VALIDSIG":
            require(words[9] in {"8", "9", "10", "11"}, "weak signature digest rejected")
            good |= key in {words[2], words[-1]}
    require(good, f"signature does not match pinned fingerprint: {path.name}")


def add_database(database, packages, key, env):
    probe_env = dict(env, LC_ALL="C")
    version = run(["repo-add", "--version"], env=probe_env).splitlines()
    match = re.fullmatch(rb"repo-add \(pacman\) (\d+)\.(\d+)\.(\d+)(?:\.r\d+\.g[0-9a-f]+)?(?:-\d+)?",
                         version[0] if version else b"")
    require(match is not None, "unrecognized repo-add version")
    family = tuple(int(value) for value in match.groups()[:2])
    # Upstream 6.0 embeds signatures by default; 6.1 introduced the opt-in.
    require(family in {(6, 0), (6, 1), (7, 0), (7, 1)}, "unsupported repo-add version")
    help_text = run(["repo-add", "--help"], env=probe_env)
    advertised = re.search(rb"(?<![\w-])--include-sigs(?![\w-])", help_text) is not None
    options = ["--include-sigs"] if family != (6, 0) or advertised else []
    # A failed database command is terminal: never retry with weaker options.
    run(["repo-add", *options, "--sign", "--key", key, database, *packages], env=env)


def database_check(directory, repo_name, packages):
    db = directory / f"{repo_name}.db.tar.gz"
    members = archive_members(db)
    records = []
    for name, member in members.items():
        if not name.endswith("/desc"):
            continue
        info, key = {}, None
        for line in run(["bsdtar", "-xOf", db, member]).decode().splitlines():
            if line.startswith("%") and line.endswith("%"):
                require(re.fullmatch(r"%[A-Z0-9_]+%", line), "malformed repository database field header")
                key = line[1:-1]
                require(key not in info, "duplicate repository database field")
                info[key] = []
            elif line and key:
                info[key].append(line)
        records.append(info)
    require(len(records) == len(packages), "repository database package count mismatch")
    for package in packages:
        matches = [r for r in records if r.get("NAME") == [package["name"]]]
        require(len(matches) == 1, "repository database package identity mismatch")
        record = matches[0]
        for field, values in {"VERSION": [package["version"]], "ARCH": [package["arch"]],
                              "FILENAME": [package["filename"]], "SHA256SUM": [package["sha256"]],
                              "DEPENDS": package["depend"], "PROVIDES": package["provides"],
                              "CONFLICTS": package["conflict"], "REPLACES": package["replaces"]}.items():
            require(record.get(field, []) == values, f"repository database field mismatch: {field}")
        signature = Path(str(directory / package["filename"]) + ".sig").read_bytes()
        require(record.get("PGPSIG") == [base64.b64encode(signature).decode("ascii")],
                "repository database package signature mismatch")


def payload_files(directory):
    return {p.relative_to(directory).as_posix(): sha(p) for p in directory.rglob("*")
            if p.is_file() and not p.is_symlink() and
            p.relative_to(directory).as_posix() not in {"release.json", "release.json.sig"}}



def source_delivery_module():
    """Load the reviewed sibling helper without searching caller directories."""
    path = Path(__file__).resolve().with_name('source_delivery.py')
    selected = importlib.util.spec_from_file_location('release_source_delivery', path)
    module = importlib.util.module_from_spec(selected)
    selected.loader.exec_module(module)
    return module


def source_associations(directory, manifest, spec):
    """Check declared associations against the enclosing signed payload map."""
    if 'source_delivery' not in spec:
        return None
    helper = source_delivery_module()
    evidence = {item['id']: item for item in spec.get('evidence', [])}
    require(len(evidence) == len(spec.get('evidence', [])), 'source delivery duplicate evidence ID')
    def read_evidence(eid, limit):
        name = 'evidence/' + valid_name(eid)
        require(eid in evidence and name in manifest['files'] and
                evidence[eid]['sha256'] == manifest['files'][name], 'source delivery evidence/payload binding')
        raw = helper.read_file(directory / name, limit)
        require(hashlib.sha256(raw).hexdigest() == manifest['files'][name], 'source delivery payload changed')
        return raw
    def read_provenance(package):
        name = package['provenance']
        require(name in manifest['files'], 'source delivery provenance payload missing')
        raw = helper.read_file(directory / name, 4 * 1024**2)
        require(hashlib.sha256(raw).hexdigest() == manifest['files'][name], 'source delivery provenance changed')
        return helper.decode(raw)
    try:
        return helper.verify_associations(spec, manifest['packages'], read_evidence, read_provenance)
    except ValueError as error:
        raise Error('source delivery: ' + str(error)) from error


def verify_release(directory, key, env):
    require(directory.is_dir() and not directory.is_symlink(), "release directory missing or symlink")
    verify_signature(directory / "release.json", key, env)
    manifest = load(directory / "release.json")
    require(manifest.get("schema_version") == 1 and manifest.get("signer") == key, "release schema/signer mismatch")
    require(payload_files(directory) == manifest["files"], "release payload changed or unrecorded files present")
    links = {p.relative_to(directory).as_posix(): os.readlink(p) for p in directory.rglob("*") if p.is_symlink()}
    require(links == manifest["symlinks"] and all("/" not in v and
            (Path(k).parent / v).as_posix() in manifest["files"] for k, v in links.items()),
            "unexpected repository symlink")
    spec = load(directory / "spec.json")
    require(manifest["release_id"] == spec["release_id"], "release/spec ID mismatch")
    require(sha(directory / "base.json") == spec["base"]["sha256"], "copied base differs from input checksum")
    if spec.get("project_license"):
        require(sha(directory / "project-license.txt") == spec["project_license"]["sha256"],
                "copied license differs from input checksum")
    for item in spec.get("evidence", []):
        require(sha(directory / "evidence" / valid_name(item["id"])) == item["sha256"],
                "copied evidence differs from input checksum")
    packages = []
    for recorded in manifest["packages"]:
        archive = directory / "repo" / recorded["filename"]
        verify_signature(archive, key, env)
        p = pkginfo(archive)
        require(p == {k: recorded[k] for k in p}, "artifact metadata changed")
        provenance_check(p, load(directory / recorded["provenance"]), recorded["sha256"], spec)
        inputs = [item for item in spec["packages"] if Path(item["artifact"]["path"]).name == recorded["filename"]]
        require(len(inputs) == 1 and inputs[0]["artifact"]["sha256"] == recorded["sha256"] and
                inputs[0]["provenance"]["sha256"] == sha(directory / recorded["provenance"]),
                "copied package/provenance differs from input checksum")
        packages.append(p)
    dependency_check(spec, packages, load(directory / "base.json"))
    source_associations(directory, manifest, spec)
    for name in (f"{spec['repo_name']}.db.tar.gz", f"{spec['repo_name']}.files.tar.gz"):
        verify_signature(directory / "repo" / name, key, env)
    database_check(directory / "repo", spec["repo_name"], manifest["packages"])
    return manifest, spec


@contextlib.contextmanager
def locked(root):
    root.mkdir(parents=True, exist_ok=True)
    storage_check(root)
    with (root / ".release.lock").open("a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def storage_check(root):
    for name in ("staging", "stable", "promotions", "withdrawals", ".release.lock"):
        path = root / name
        require(not path.is_symlink(), f"managed storage path is a symlink: {name}")
        if path.exists():
            require(path.is_file() if name == ".release.lock" else path.is_dir(), f"wrong storage path type: {name}")


def stage(args, root, key, env):
    storage_check(root)
    spec_path = Path(args.spec).resolve()
    spec, base_dir = load(spec_path), spec_path.parent
    require(spec.get("schema_version") == 1 and spec.get("target_arch") == "aarch64", "invalid release schema/architecture")
    rid, repo = valid_name(spec["release_id"]), valid_name(spec["repo_name"])
    require(re.fullmatch(r"[0-9a-f]{40}", spec.get("source_commit", "")), "full project source commit required")
    models = spec["policy"].get("supported_models", [])
    require(models and len(set(models)) == len(models) and set(models) <= MODELS, "explicit exact supported M2 Air sizes required")
    destination = root / "staging" / rid
    require(not destination.exists() and not destination.is_symlink() and
            not (root / "withdrawals" / f"{rid}.json").exists(), "release ID already used or withdrawn")
    destination.parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".staging-", dir=root) as temp:
        out = Path(temp)
        (out / "repo").mkdir()
        (out / "provenance").mkdir()
        (out / "evidence").mkdir()
        shutil.copyfile(spec_path, out / "spec.json")
        base_path = file_ref(base_dir, spec["base"])
        shutil.copyfile(base_path, out / "base.json")
        packages = []
        for item in spec.get("packages", []):
            archive = file_ref(base_dir, item["artifact"])
            require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+:-]*\.pkg\.tar\.(?:gz|xz|zst)", archive.name), "invalid package filename")
            copied = out / "repo" / archive.name
            require(not copied.exists(), "duplicate package filename")
            shutil.copyfile(archive, copied)
            p = pkginfo(copied)
            require(p["name"] not in {q["name"] for q in packages}, "duplicate package name")
            record_path = file_ref(base_dir, item["provenance"])
            provenance_check(p, load(record_path), item["artifact"]["sha256"], spec)
            record_name = f"provenance/{p['name']}.json"
            shutil.copyfile(record_path, out / record_name)
            p.update(filename=archive.name, sha256=sha(copied), provenance=record_name)
            packages.append(p)
        dependency_check(spec, packages, load(out / "base.json"))
        if 'source_delivery' in spec:
            declared = spec['source_delivery']
            require(type(declared) is dict and set(declared) == {'schema_version', 'index'} and
                    type(declared['schema_version']) is int and declared['schema_version'] == 1,
                    'source delivery declaration schema')
            helper = source_delivery_module()
            try:
                assembled = helper.assemble(base_dir, declared['index'], packages,
                    spec['policy']['selected_packages'], spec.get('synthetic'),
                    lambda package: load(out / package['provenance']))
            except ValueError as error:
                raise Error('source delivery: ' + str(error)) from error
            retained = {item['id']: item for item in spec.get('evidence', [])}
            require(len(retained) == len(spec.get('evidence', [])), 'source delivery duplicate evidence ID')
            for item in assembled:
                if item['id'] in retained:
                    require(all(retained[item['id']].get(k) == item[k] for k in ('path', 'sha256')),
                            'source delivery evidence collision')
                else:
                    retained[item['id']] = item
            spec['evidence'] = list(retained.values())
            write(out / 'spec.json', spec)
        for evidence in spec.get("evidence", []):
            eid = valid_name(evidence["id"])
            path = out / "evidence" / eid
            require(not path.exists(), "duplicate evidence ID")
            shutil.copyfile(file_ref(base_dir, evidence), path)
        if spec.get("project_license"):
            text_field(spec["project_license"], "spdx")
            shutil.copyfile(file_ref(base_dir, spec["project_license"]), out / "project-license.txt")
        source_associations(out, {'packages': packages, 'files': payload_files(out)}, spec)
        for p in packages:
            sign(out / "repo" / p["filename"], key, env)
        add_database(out / "repo" / f"{repo}.db.tar.gz",
                     [out / "repo" / p["filename"] for p in packages], key, env)
        # repo-add signs the .files archive on current pacman; explicitly handle older versions.
        files_db = out / "repo" / f"{repo}.files.tar.gz"
        if not Path(str(files_db) + ".sig").exists():
            sign(files_db, key, env)
        manifest = {"schema_version": 1, "release_id": rid, "signer": key,
                    "created_utc": datetime.now(timezone.utc).isoformat(), "packages": packages,
                    "files": payload_files(out), "symlinks": {p.relative_to(out).as_posix(): os.readlink(p)
                                                             for p in out.rglob("*") if p.is_symlink()}}
        write(out / "release.json", manifest)
        sign(out / "release.json", key, env)
        verify_release(out, key, env)
        os.rename(out, destination)
    return {"status": "local-staging", "path": str(destination), "release_sha256": sha(destination / "release.json"),
            "source_delivery": "CHECKED_DECLARED_ASSOCIATIONS" if 'source_delivery' in spec else "NOT_DECLARED",
            "source_completeness_accepted": False}


def gates_check(directory, manifest, spec, gates_path):
    gates = load(gates_path)
    require(gates.get("schema_version") == 1 and gates.get("release_id") == manifest["release_id"], "gate identity mismatch")
    require(gates.get("release_sha256") == sha(directory / "release.json"), "gates not bound to signed release")
    require(not spec.get("synthetic") and not gates.get("synthetic"), "synthetic fixtures cannot enter stable")
    require(spec.get("project_license") and "project-license.txt" in manifest["files"], "project license missing; stable blocked")
    require(gates.get("source_commit") == spec["source_commit"] and gates.get("base_sha256") == spec["base"]["sha256"],
            "gate source/base mismatch")
    require(gates.get("project_license_sha256") == spec["project_license"]["sha256"], "license gate mismatch")
    require(gates.get("package_sha256") == {p["name"]: p["sha256"] for p in manifest["packages"]}, "gate artifact set mismatch")
    records = gates.get("records", [])

    def evidence(eid):
        valid_name(eid)
        path = directory / "evidence" / eid
        require(f"evidence/{eid}" in manifest["files"] and path.stat().st_size > 0, f"missing raw evidence: {eid}")
        return path

    def record(kind, **identity):
        matches = [r for r in records if r.get("kind") == kind and all(r.get(k) == v for k, v in identity.items())]
        require(len(matches) == 1, f"missing/duplicate gate: {kind}: {identity}")
        r = matches[0]
        require(r.get("result") == "PASS" and not r.get("synthetic"), f"gate not passed: {kind}")
        text_field(r, "operator")
        text_field(r, "date_utc")
        require(isinstance(r.get("commands"), list) and r["commands"] and all(isinstance(x, str) and x.strip() for x in r["commands"]),
                f"recorded commands missing: {kind}")
        require(r.get("logs"), f"raw logs missing: {kind}")
        for eid in r["logs"]:
            evidence(eid)
        return r

    release_review = record("release-review")
    for field in ("custodian", "alternate_custodian", "hardware_owner"):
        text_field(release_review, field)
    for field in ("release_notes", "retained_base_inputs", "recovery_plan", "license_review"):
        evidence(release_review[field])
    for p in manifest["packages"]:
        prov = load(directory / p["provenance"])
        require(prov["build"]["execution"] == "native" and prov["build"]["architecture"] == "aarch64",
                f"native aarch64 provenance required: {p['name']}")
        builders, logs, operators, build_logs = set(), set(), set(), set()
        for attempt in (1, 2):
            r = record("native-build", package=p["name"], attempt=attempt)
            require(r.get("execution") == "native" and r.get("architecture") == "aarch64", "emulation/cross build is not native")
            require(r.get("artifact_sha256") == p["sha256"] and r.get("snapshot_id") == prov["build"]["snapshot_id"], "build checksum/snapshot mismatch")
            require(re.fullmatch(r"sha256:[0-9a-f]{64}", r.get("environment_digest", "")), "builder image not digest pinned")
            raw = load(evidence(r["build_record"]))
            require(raw.get("schema_version") == 1 and raw.get("status") == "built-package-static-pass" and
                    raw.get("mode") == "native" and raw.get("builder_host_arch") in {"aarch64", "arm64"},
                    "raw native build provenance missing or failed")
            require(raw.get("image_id") == r["environment_digest"] and
                    re.fullmatch(r"(?:[A-Za-z0-9][A-Za-z0-9._:/-]*@)?sha256:[0-9a-f]{64}", raw.get("image", "")),
                    "raw builder image differs or is unpinned")
            require(raw.get("clean_environment_id") == r.get("clean_environment_id") and raw.get("exit_code") == 0 and
                    raw.get("artifacts") == {p["filename"]: p["sha256"]}, "raw build identity/artifact mismatch")
            require(isinstance(raw.get("command"), list) and raw["command"] and all(isinstance(x, str) for x in raw["command"]),
                    "raw builder command missing")
            require(raw.get("recipe_inputs", {}).get("PKGBUILD") == prov["recipe_sha256"], "raw build recipe differs from provenance")
            require(raw.get("files") and set(r.get("file_bindings", {})) == set(raw["files"]), "raw build evidence bindings incomplete")
            require({"build.log", "validation.json", f"artifacts/{p['filename']}"} <= set(raw["files"]),
                    "raw build log/inspection/artifact files missing")
            require(r["file_bindings"]["build.log"] in r["logs"], "native gate logs omit actual build log")
            build_logs.add(r["file_bindings"]["build.log"])
            for filename, digest in raw["files"].items():
                require(sha(evidence(r["file_bindings"][filename])) == digest, "raw build file digest mismatch")
            require(raw.get("expected_packages_sha256") == sha(evidence(r["builder_package_lock"])),
                    "raw builder package lock differs from retained lock")
            require(raw.get("recipe_inputs") and set(r.get("recipe_bindings", {})) == set(raw["recipe_inputs"]),
                    "retained recipe inputs incomplete")
            for filename, digest in raw["recipe_inputs"].items():
                require(sha(evidence(r["recipe_bindings"][filename])) == digest, "retained recipe input digest mismatch")
            builders.add(text_field(r, "clean_environment_id"))
            operators.add(r["operator"])
            logs.update(r["logs"])
            lock = load(evidence(r["dependency_lock"]))
            require(lock.get("schema_version") == 1 and lock.get("snapshot_id") == prov["build"]["snapshot_id"] and
                    lock.get("packages") and lock.get("retrievable_inputs"), "dependency lock/input retention missing")
            for dep in lock["packages"]:
                text_field(dep, "name")
                text_field(dep, "version")
                require(HEX.fullmatch(dep.get("sha256", "")), "dependency artifact checksum missing")
            for src in lock["retrievable_inputs"]:
                text_field(src, "uri")
                require(HEX.fullmatch(src.get("sha256", "")), "retained input checksum missing")
            original_lock = evidence(r["builder_package_lock"]).read_text().splitlines()
            pairs = set()
            for line in original_lock:
                require(len(line.split()) == 2, "malformed builder package lock")
                pairs.add(tuple(line.split()))
            augmented = {(d["name"], d["version"]) for d in lock["packages"]}
            require(pairs == augmented and len(augmented) == len(lock["packages"]),
                    "augmented dependency lock omits/differs from builder package set")
        require(len(builders) == 2 and len(logs) >= 2 and len(build_logs) == 2,
                "two independent clean environments/build logs required")
        review = record("package-review", package=p["name"])
        require(review["operator"] not in operators, "package review must be independent of build operator")
        for check in ("licenses", "source-pins", "files-ownership", "hooks", "config-preservation", "protected-platform", "16k-pages"):
            require(review.get("checks", {}).get(check) == "PASS", f"package review incomplete: {check}")
        evidence(review["inspection_report"])
        repro = record("reproducibility", package=p["name"])
        require(repro.get("method") == "byte-identical" and repro.get("artifact_sha256") == [p["sha256"], p["sha256"]],
                "byte-identical rebuild evidence required; content-only exception is not implemented")
        require(sha(evidence(repro["second_artifact"])) == p["sha256"], "second build artifact differs")
    for model in spec["policy"]["supported_models"]:
        machines, machine_records = set(), set()
        for kind, checks in (("functional", FUNCTIONAL), ("install-removal", LIFECYCLE), ("upgrade-recovery", RECOVERY)):
            r = record(kind, model=model)
            machines.add(text_field(r, "machine_id"))
            machine_records.add(r["machine_record"])
            machine = load(evidence(r["machine_record"]))
            require(machine.get("model") == model and machine.get("machine_id") == r["machine_id"] and
                    machine.get("soc") == "M2" and machine.get("execution") == "physical", "exact physical M2 machine evidence required")
            require(machine.get("base_sha256") == spec["base"]["sha256"] and machine.get("package_sha256") == gates["package_sha256"],
                    "machine record differs from release transaction")
            require(machine.get("platform_versions") and machine.get("baseline") and machine.get("acceptance_contract"), "machine baseline/version contract missing")
            evidence(machine["baseline"])
            evidence(machine["acceptance_contract"])
            for check in checks:
                result = r.get("checks", {}).get(check, {})
                require(result.get("result") == "PASS", f"hardware gate incomplete: {model}: {check}")
                evidence(result.get("evidence", ""))
            if kind == "functional":
                contract = load(evidence(machine["acceptance_contract"]))
                count = contract.get("sleep_wake_repetitions")
                require(isinstance(count, int) and not isinstance(count, bool) and count > 0 and
                        isinstance(r.get("sleep_wake_completed"), int) and r["sleep_wake_completed"] >= count,
                        "frozen sleep/wake repetition count not exercised")
            if kind == "upgrade-recovery":
                text_field(r, "previous_release_id")
                require(r["previous_release_id"] != manifest["release_id"], "tested release pair required")
                evidence(r["previous_release_record"])
        require(len(machines) == 1 and len(machine_records) == 1,
                "hardware gates use different machine identities/version records")
    return gates


def promote(args, root, key, env):
    storage_check(root)
    source = root / "staging" / valid_name(args.release_id)
    require(not (root / "withdrawals" / f"{args.release_id}.json").exists(), "release withdrawn")
    manifest, spec = verify_release(source, key, env)
    gate_path = Path(args.gates).resolve()
    gates = gates_check(source, manifest, spec, gate_path)
    stable = root / "stable"
    stable.mkdir(exist_ok=True)
    destination = stable / args.release_id
    require(not destination.exists(), "stable release ID already retained")
    current = stable / "current"
    if current.is_symlink():
        previous, _ = verify_release(stable / valid_name(os.readlink(current)), key, env)
        versions = {p["name"]: p["version"] for p in previous["packages"]}
        for p in manifest["packages"]:
            require(p["name"] not in versions or int(run(["vercmp", p["version"], versions[p["name"]]])) >= 0,
                    "stable downgrade blocked; recovery needs an explicit tested operator plan")
    elif current.exists():
        raise Error("stable/current must be a managed symlink")
    with tempfile.TemporaryDirectory(prefix=".promotion-", dir=root) as temp:
        out = Path(temp)
        shutil.copytree(source, out / "release", symlinks=True)
        copied_manifest, copied_spec = verify_release(out / "release", key, env)
        write(out / "gates.json", gates)
        gates_check(out / "release", copied_manifest, copied_spec, out / "gates.json")
        # Promotion evidence is kept outside the immutable signed release payload.
        write(out / "promotion.json", {"schema_version": 1, "release_id": args.release_id,
              "release_sha256": sha(out / "release/release.json"), "gates": gates,
              "promoted_utc": datetime.now(timezone.utc).isoformat()})
        sign(out / "promotion.json", key, env)
        verify_release(out / "release", key, env)
        os.rename(out / "release", destination)
        history = root / "promotions"
        history.mkdir(exist_ok=True)
        os.rename(out / "promotion.json", history / f"{args.release_id}.json")
        os.rename(out / "promotion.json.sig", history / f"{args.release_id}.json.sig")
        link = stable / ".current-next"
        require(not link.exists() and not link.is_symlink(), "stale activation temporary file")
        link.symlink_to(args.release_id)
        os.replace(link, current)
    return {"status": "local-stable", "path": str(destination), "published": False}


def withdraw(args, root, key, env):
    storage_check(root)
    rid = valid_name(args.release_id)
    require((root / "staging" / rid).is_dir() or (root / "stable" / rid).is_dir(), "unknown release")
    reason = Path(args.reason).resolve()
    require(reason.is_file() and reason.stat().st_size, "nonempty incident/recovery record required")
    target = root / "withdrawals"
    target.mkdir(exist_ok=True)
    require(not (target / f"{rid}.json").exists(), "release already withdrawn")
    with tempfile.TemporaryDirectory(prefix=".withdrawal-", dir=root) as temp:
        out = Path(temp)
        write(out / "record.json", {"schema_version": 1, "release_id": rid, "signer": key,
              "withdrawn_utc": datetime.now(timezone.utc).isoformat(), "reason": reason.read_text(),
              "reason_sha256": sha(reason), "packages_retained": True})
        sign(out / "record.json", key, env)
        os.rename(out / "record.json.sig", target / f"{rid}.json.sig")
        os.rename(out / "record.json", target / f"{rid}.json")
    current = root / "stable" / "current"
    if current.is_symlink() and os.readlink(current) == rid:
        current.unlink()
    return {"status": "withdrawn-locally", "release_id": rid, "clients_contacted": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="local repository storage; all releases retained")
    parser.add_argument("--gpg-home", required=True, help="explicit external GnuPG home")
    parser.add_argument("--key", required=True, help="full externally supplied signing/verification fingerprint")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("stage")
    p.add_argument("--spec", required=True)
    p = sub.add_parser("verify")
    p.add_argument("--release-id", required=True)
    p.add_argument("--channel", choices=("staging", "stable"), default="staging")
    p = sub.add_parser("promote")
    p.add_argument("--release-id", required=True)
    p.add_argument("--gates", required=True)
    p = sub.add_parser("withdraw")
    p.add_argument("--release-id", required=True)
    p.add_argument("--reason", required=True, help="incident/recovery text; retained in signed record")
    args = parser.parse_args()
    root, key = Path(args.root).resolve(), fingerprint(args.key)
    env = gpg_env(args.gpg_home, root)
    with locked(root):
        if args.command == "stage":
            result = stage(args, root, key, env)
        elif args.command == "promote":
            result = promote(args, root, key, env)
        elif args.command == "withdraw":
            result = withdraw(args, root, key, env)
        else:
            rid = valid_name(args.release_id)
            require(not (root / "withdrawals" / f"{rid}.json").exists(), "release withdrawn; retained files are recovery evidence only")
            manifest, _ = verify_release(root / args.channel / rid, key, env)
            if args.channel == "stable":
                promotion = root / "promotions" / f"{rid}.json"
                verify_signature(promotion, key, env)
                saved = load(promotion)
                require(saved["release_sha256"] == sha(root / args.channel / rid / "release.json"), "promotion record checksum mismatch")
                # Recheck all gate evidence, including explicit exclusions.
                with tempfile.TemporaryDirectory(prefix=".verify-", dir=root) as tmp:
                    gate_file = Path(tmp) / "gates.json"
                    write(gate_file, saved["gates"])
                    gates_check(root / args.channel / rid, manifest, load(root / args.channel / rid / "spec.json"), gate_file)
            result = {"status": "verified-locally", "channel": args.channel, "release_id": manifest["release_id"]}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (Error, KeyError, TypeError, ValueError, OSError) as e:
        print(f"release error: {e}", file=sys.stderr)
        sys.exit(1)
