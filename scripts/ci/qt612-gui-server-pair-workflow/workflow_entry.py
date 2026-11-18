#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the immutable Source roles of one Root-selected hosted Qt GUI pair."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import time

REPOSITORY = "Gabriel-Kahen/cachy-asahi"
OWNER = "Gabriel-Kahen"
WORKFLOW = ".github/workflows/native-arm-qt612-gui-server-pair.yml"
ENTRY = "scripts/ci/qt612-gui-server-pair-adapter/entry.py"
KIND = "ROOT_QT612_GUI_SERVER_PAIR_APPROVAL_V1"
MAP_KIND = "QT612_GUI_PAIR_WORKFLOW_SOURCE_V1"
R128 = {
    "ref": "refs/heads/codex/md4c053-reference-native-source-20261118-r11",
    "commit": "eed0513b957ef265b334a7762bdfba4f50afd500",
    "tree": "1b204ef98333aaf116fb1fe346b49b37a19e8ef7",
    "map": {"path": "source-map.json", "bytes": 20426,
            "sha256": "42bffdd05941787940bbc5a459cb4ce66cf26b0b01b6e5ebdb96e3d1b2e9d473"},
}
FROZEN_LOCKS = "scripts/ci/qt612-reference-native-source"
FROZEN = {
    "f-recipe.lock.json": {"bytes": 7754, "sha256": "a6ecf61d9bb36e1525e01f791cd51958426cd59c961b2f0a1d80d912fc0a1d52"},
    "f-serial-recipe.lock.json": {"bytes": 10713, "sha256": "020c248a7fc63bb058b0d607b83f6f711f0a5ae1d81354ce22b4dfaf0e2afec0"},
}
PUBLIC_TRUST = {
    "md4c_signature": {"bytes": 119, "sha256": "63dda83d805e4ad8023fcbe35b6abc63e74646becd4f9e2ada339526a2fddc85"},
    "md4c_certificate": {"bytes": 265, "sha256": "4d1ea2e70ae86992f626a38acd9c61a3d9060261c5fb733bd99e91cc6ab27095"},
}
ROLES = {*PUBLIC_TRUST, "portable_selection", "route_plan", "md4c_authority"}
HEX40 = re.compile("[0-9a-f]{40}")
HEX64 = re.compile("[0-9a-f]{64}")
REF = re.compile(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
FILES, TOTAL = 1024, 32 * 1024**2
APPROVAL_CAP = 64 * 1024
EVIDENCE_CAP = 2 * 1024**3
EXPORT_FILES = 2048
MANIFEST = "pair-export.json"
OWNER_REPORT = "owner-report.json"
ROOT_UID = 0


def need(condition, message):
    if not condition:
        raise ValueError(message)


def fields(value, keys):
    need(type(value) is dict and value.keys() == set(keys), "EXACT_RECORD_FIELDS_REQUIRED")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        result = dict(items)
        need(len(result) == len(items), "DUPLICATE_JSON_KEY")
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, "NONFINITE_JSON_VALUE"))


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and ".." not in path.parts and not any(q.is_symlink() for q in (path, *path.parents)),
         "CANONICAL_ORDINARY_ABSOLUTE_PATH_REQUIRED")
    return path


def relative(value):
    path = PurePosixPath(value)
    need(path.as_posix() == value and not path.is_absolute() and 0 < len(value) <= 240
         and ".git" not in path.parts and all(part not in {".", ".."} and re.fullmatch(r"[A-Za-z0-9._+@~-]+", part)
                                               for part in value.split("/")),
         "ORDINARY_RELATIVE_SOURCE_LEAF_REQUIRED")
    return value


def reference(ref, cap=TOTAL):
    fields(ref, ("path", "bytes", "sha256"))
    relative(ref["path"])
    need(type(ref["bytes"]) is int and 0 <= ref["bytes"] <= cap and HEX64.fullmatch(ref["sha256"]),
         "BOUNDED_CHECKSUM_DESCRIPTOR_REQUIRED")


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_nlink,
            st.st_ctime_ns, st.st_mtime_ns, st.st_size)


def read(path, *, limit, pinned=None, mode=None, owner=None, collect=True):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        previous = os.fstat(fd)
        need(stat.S_ISREG(previous.st_mode) and previous.st_nlink == 1 and previous.st_size <= limit
             and not previous.st_mode & 0o022
             and (owner is None or previous.st_uid == owner)
             and (mode is None or stat.S_IMODE(previous.st_mode) == mode)
             and (pinned is None or previous.st_size == pinned["bytes"]), "ORDINARY_BOUNDED_SOURCE_FILE_REQUIRED")
        h, count, parts = hashlib.sha256(), 0, []
        while chunk := stream.read(min(65536, previous.st_size - count + 1)):
            count += len(chunk)
            need(count <= previous.st_size, "SOURCE_FILE_GREW")
            h.update(chunk)
            if collect:
                parts.append(chunk)
        need(count == previous.st_size and identity(previous) == identity(os.fstat(fd)) == identity(path.lstat())
             and (pinned is None or h.hexdigest() == pinned["sha256"]), "EXACT_STABLE_FILE_BYTES_REQUIRED")
        return b"".join(parts) if collect else None


def valid_ref(value):
    need(REF.fullmatch(value) and ".." not in value and "//" not in value
         and not any(part.startswith(".") or part.endswith((".", ".lock")) for part in value.split("/")),
         "EXACT_BRANCH_REF_REQUIRED")


def approval(raw, sha, environ, now):
    need(0 < len(raw) <= APPROVAL_CAP and HEX64.fullmatch(sha) and digest(raw) == sha,
         "EXACT_ROOT_APPROVAL_SHA256_REQUIRED")
    record = decode(raw)
    fields(record, ("kind", "issuer", "approved", "mode", "repository", "live_ref", "workflow_sha",
                    "runtime_source", "inputs", "issued_utc", "expires_utc"))
    need(record["kind"] == KIND and record["issuer"] == "Root" and record["approved"] is True
         and record["mode"] == "pair-only" and record["repository"] == REPOSITORY, "ROOT_PAIR_ONLY_APPROVAL_REQUIRED")
    valid_ref(record["live_ref"])
    need(HEX40.fullmatch(record["workflow_sha"]) and type(record["issued_utc"]) is type(record["expires_utc"]) is int
         and record["issued_utc"] <= now < record["expires_utc"]
         and 0 < record["expires_utc"] - record["issued_utc"] <= 6 * 3600, "CURRENT_ROOT_DISPATCH_WINDOW_REQUIRED")
    observed = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_ACTOR": OWNER,
        "GITHUB_TRIGGERING_ACTOR": OWNER,
        "GITHUB_REF": record["live_ref"],
        "GITHUB_SHA": record["workflow_sha"],
        "GITHUB_WORKFLOW_SHA": record["workflow_sha"],
        "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/{WORKFLOW}@{record['live_ref']}",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "pair",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "ARM64",
    }
    need(all(environ.get(k) == want for k, want in observed.items())
         and re.fullmatch("[1-9][0-9]{0,19}", environ.get("GITHUB_RUN_ID", "")),
         "EXACT_HOSTED_OWNER_DISPATCH_CONTEXT_REQUIRED")
    runtime = record["runtime_source"]
    fields(runtime, ("ref", "commit", "tree", "map", "entry"))
    valid_ref(runtime["ref"])
    need(HEX40.fullmatch(runtime["commit"]) and HEX40.fullmatch(runtime["tree"])
         and runtime["ref"] != record["live_ref"], "SEPARATE_IMMUTABLE_DEPENDENCY_SOURCE_REQUIRED")
    reference(runtime["map"], 1024**2)
    need(runtime["map"]["path"] == "source-map.json", "EXACT_RUNTIME_SOURCE_MAP_PATH_REQUIRED")
    reference(runtime["entry"], 256 * 1024)
    need(runtime["entry"]["path"] == ENTRY,
         "SELECTED_DISTRIBUTED_OWNER_ENTRY_REQUIRED")
    fields(record["inputs"], ROLES)
    for ref in record["inputs"].values():
        reference(ref, 1024**2)
    need(all({key: record["inputs"][name][key] for key in pin} == pin for name, pin in PUBLIC_TRUST.items())
         and len({ref["path"] for ref in record["inputs"].values()}) == len(ROLES),
         "EXACT_DISTINCT_PUBLIC_INPUT_ROLES_REQUIRED")
    return record


def git_identity(root):
    env = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"}
    need(ordinary(root / ".git").is_dir(), "ORDINARY_CHECKOUT_METADATA_REQUIRED")
    result = subprocess.run(["/usr/bin/git", "--no-replace-objects", "--no-optional-locks", "-C", str(root),
                             "rev-parse", "HEAD", "HEAD^{tree}"],
                            env=env, capture_output=True, timeout=10, check=True)
    return tuple(result.stdout.decode("ascii").splitlines())


def verify_frozen_locks(root, workflow_sha):
    need(git_identity(root)[0] == workflow_sha, "EXACT_LIVE_WORKFLOW_CHECKOUT_REQUIRED")
    for name, row in FROZEN.items():
        read(root / FROZEN_LOCKS / name, limit=row["bytes"], pinned=row, mode=0o644, collect=False)


def verify_git(root, selected):
    need(git_identity(root) == (selected["commit"], selected["tree"]), "IMMUTABLE_SOURCE_COMMIT_TREE_MISMATCH")
    metadata = selected["map"]
    return read(root / metadata["path"], limit=1024**2, pinned=metadata, mode=0o644)


def verify_source(root, selected, inputs):
    mapping = decode(verify_git(root, selected))
    fields(mapping, ("kind", "schema", "files"))
    need(mapping["kind"] == MAP_KIND and type(mapping["schema"]) is int and mapping["schema"] == 1,
         "EXACT_WORKFLOW_SOURCE_MAP_KIND_REQUIRED")
    entries = mapping["files"]
    need(type(entries) is dict and 0 < len(entries) <= FILES, "BOUNDED_SOURCE_MAP_REQUIRED")
    map_name = selected["map"]["path"]
    need(map_name not in entries, "SOURCE_MAP_CANNOT_INDEX_ITSELF")
    for item in (selected["entry"], *inputs.values()):
        row = entries[item["path"]]
        need(all(row[key] == item[key] for key in ("bytes", "sha256")), "REVIEWED_ROLE_BYTES_DIFFER")
    closed_tree(root, entries.keys() | {map_name}, FILES * 2, git=True)
    size = 0
    for name, row in entries.items():
        fields(row, ("bytes", "sha256", "mode"))
        reference(dict(path=name, bytes=row["bytes"], sha256=row["sha256"]))
        need(type(row["mode"]) is int and row["mode"] in (0o644, 0o755), "EXACT_REVIEWED_SOURCE_MODE_REQUIRED")
        size += row["bytes"]
        need(size <= TOTAL, "WORKFLOW_SOURCE_TOTAL_EXCEEDED")
        read(root / name, limit=TOTAL, pinned=row, mode=row["mode"], collect=False)


def closed_tree(root, expected, max_nodes, *, git=False, owner=None):
    expected_dirs = {parent.as_posix() for name in expected
                     for parent in PurePosixPath(relative(name)).parents if parent != PurePosixPath(".")}
    found, directories = set(), set()
    for folder, dirs, names in os.walk(root, followlinks=False):
        folder = Path(folder)
        observed = folder.lstat()
        need(stat.S_ISDIR(observed.st_mode) and not observed.st_mode & 0o022
             and (owner is None or observed.st_uid == owner), "ORDINARY_READ_ONLY_EXPORT_DIRECTORY_REQUIRED")
        if git and folder == root and ".git" in dirs:
            need(not (root / ".git").is_symlink(), "ORDINARY_CHECKOUT_METADATA_REQUIRED")
            dirs.remove(".git")
        for name in dirs + names:
            path = folder / name
            need(len(found) + len(directories) < max_nodes and not path.is_symlink(),
                 "BOUNDED_ORDINARY_SOURCE_NAMESPACE_REQUIRED")
            (found if name in names else directories).add(path.relative_to(root).as_posix())
    need(found == expected and directories == expected_dirs, "EXACT_CLOSED_WORKFLOW_SOURCE_NAMESPACE_REQUIRED")


def verify_export(root, environ):
    sha = environ.get("QT612_ROOT_APPROVAL_SHA256", "")
    observed = root.lstat()
    need(HEX64.fullmatch(sha) and observed.st_uid == ROOT_UID and stat.S_ISDIR(observed.st_mode)
         and stat.S_IMODE(observed.st_mode) == 0o711, "ROOT_OWNED_CLEANUP_OUTPUT_REQUIRED")
    owner = decode(read(root / OWNER_REPORT, limit=1024**2, mode=0o444, owner=ROOT_UID))
    need(owner["status"] == "PASS_QT612_GUI_SERVER_PAIR_EXTERNAL_CLEANUP_ONLY"
         and owner["approval"]["sha256"] == sha and owner["lifecycle_status"] == "NOT_RUN"
         and owner["native_acceptance"] is owner["Root_acceptance"] is None
         and owner["cleanup"]["owned_storage_absent"] is True and not owner["cleanup"]["errors"],
         "EXACT_ROOT_QUALIFIED_PAIR_CLOSURE_REQUIRED")
    dispatch = owner["dispatch"]
    fields(dispatch, ("source", "ref", "run", "job", "attempt"))
    valid_ref(dispatch["ref"])
    need(HEX40.fullmatch(dispatch["source"]) and re.fullmatch("[1-9][0-9]{0,19}", dispatch["run"])
         and re.fullmatch("[1-9][0-9]{0,19}", dispatch["job"]) and dispatch["source"] == environ.get("GITHUB_SHA") and dispatch["ref"] == environ.get("GITHUB_REF")
         and dispatch["run"] == environ.get("GITHUB_RUN_ID") and dispatch["attempt"] == environ.get("GITHUB_RUN_ATTEMPT") == "1",
         "SAME_PAIR_WORKFLOW_RUN_REQUIRED")
    evidence = root / "evidence"
    selection = owner["evidence"]
    expected = selection["manifest_pin"]
    reference(dict(path=MANIFEST, **expected), 1024**2)
    manifest = decode(read(evidence / MANIFEST, limit=1024**2, pinned=expected, mode=0o644, owner=ROOT_UID))
    fields(manifest, ("kind", "selected", "files", "lifecycle_status", "native_acceptance", "Root_acceptance"))
    need(manifest["kind"] == "QT612_HOSTED_PAIR_EXACT_EXPORT_V1" and manifest["selected"] == selection["selected"]
         and manifest["selected"]["dispatch"] == dispatch and manifest["lifecycle_status"] == "NOT_RUN"
         and manifest["native_acceptance"] is manifest["Root_acceptance"] is None,
         "SAME_EXACT_QUALIFIED_EXPORT_REQUIRED")
    files = manifest["files"]
    need(type(files) is dict and 0 < len(files) <= EXPORT_FILES and MANIFEST not in files,
         "BOUNDED_EXACT_PAIR_EXPORT_REQUIRED")
    size = 0
    for name, row in files.items():
        ref = dict(path=name, **row)
        reference(ref, 512 * 1024**2)
        need(all(not part.startswith(".") for part in name.split("/"))
             or re.fullmatch(r"build-[12]/inputs/\.SRCINFO", name), "ONLY_EXPECTED_PUBLIC_HIDDEN_EVIDENCE")
        size += row["bytes"]
        need(size <= EVIDENCE_CAP, "BOUNDED_EXACT_PAIR_EXPORT_REQUIRED")
    need(selection["qualification"] == dict(status="PASS_QT612_HOSTED_PAIR_EXACT_READBACK_ONLY", files=len(files),
         bytes=size, lifecycle_status="NOT_RUN", Root_acceptance=None), "SAME_ROOT_PAIR_EXPORT_READBACK_REQUIRED")
    closed_tree(evidence, files.keys() | {MANIFEST}, EXPORT_FILES * 2, owner=ROOT_UID)
    for name, row in files.items():
        read(evidence / name, limit=row["bytes"], pinned=row, mode=0o644, owner=ROOT_UID, collect=False)


def fresh(path, body):
    path = ordinary(path)
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
        stream.write(body)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    actions = p.add_subparsers(dest="action", required=True)
    preflight = actions.add_parser("preflight")
    preflight.add_argument("--approval", type=Path, required=True)
    preflight.add_argument("--github-output", type=Path, required=True)
    evidence = actions.add_parser("verify-export")
    evidence.add_argument("--owner-output", type=Path, required=True)
    verify = actions.add_parser("verify")
    for flag in ("approval", "workflow-root", "runtime-source", "r128-source"):
        verify.add_argument("--" + flag, type=Path, required=True)
    args = p.parse_args(argv)
    if args.action == "verify-export":
        verify_export(ordinary(args.owner_output), os.environ)
        print("QT612_PAIR_WORKFLOW_CLOSED_EXPORT_VERIFIED")
        return 0
    raw = (os.environ.get("QT612_ROOT_APPROVAL_JSON", "").encode() if args.action == "preflight"
           else read(args.approval, limit=APPROVAL_CAP))
    sha = os.environ.get("QT612_ROOT_APPROVAL_SHA256", "")
    approved = approval(raw, sha, os.environ, int(time.time()))
    runtime = approved["runtime_source"]
    if args.action == "preflight":
        fresh(args.approval, raw)
        fd = os.open(ordinary(args.github_output), os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "a", encoding="ascii") as target:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "ORDINARY_GITHUB_OUTPUT_FILE_REQUIRED")
            target.write("runtime_ref=" + runtime["ref"] + "\n")
    else:
        verify_frozen_locks(ordinary(args.workflow_root), approved["workflow_sha"])
        verify_source(ordinary(args.runtime_source), runtime, approved["inputs"])
        verify_git(ordinary(args.r128_source), R128)
    print("QT612_PAIR_WORKFLOW_INPUT_IDENTITIES_VERIFIED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        print("Qt GUI pair workflow admission held", file=sys.stderr)
        raise SystemExit(1) from None
