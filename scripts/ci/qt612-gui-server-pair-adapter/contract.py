# SPDX-License-Identifier: MIT
"""Whole input and run authority checks for the first hosted GUI pair."""

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

REPO = "Gabriel-Kahen/cachy-asahi"
WORKFLOW = ".github/workflows/native-arm-qt612-gui-server-pair.yml"
ENTRY = "scripts/ci/qt612-gui-server-pair-adapter/entry.py"
FAMILY = "scripts/ci/qt612-complete-family-native-source"
HOSTED = "scripts/ci/qt612-family-hosted"
KIND = "ROOT_QT612_GUI_SERVER_PAIR_APPROVAL_V1"
MAP_KIND = "QT612_GUI_PAIR_WORKFLOW_SOURCE_V1"
MIB = 1024**2
TOTAL = 32 * MIB
TRANSFER, BOOTSTRAP, COMPONENT, CLEANUP = 240, 2700, 18000, 90
WORK = TRANSFER + BOOTSTRAP + COMPONENT
SCOPE = WORK + CLEANUP
R128_COMMIT = "eed0513b957ef265b334a7762bdfba4f50afd500"
R128_TREE = "1b204ef98333aaf116fb1fe346b49b37a19e8ef7"
R128_MAP = dict(bytes=20426, sha256="42bffdd05941787940bbc5a459cb4ce66cf26b0b01b6e5ebdb96e3d1b2e9d473")
PACKAGE = "md4c-0.5.3-1-aarch64.pkg.tar.xz"
ARCHIVE = dict(bytes=74076, sha256="19149e51f05a7d93426dda7a66fd80d67bd235cab7ac4505130f7de6d40b5b95")
SIGNATURE = dict(bytes=119, sha256="efe73e02383cbe16a9478952a43b22c3db256d1070275c3264f62240e48db18a")
CERT = "md4c-r128-TEST-public.gpg"
CERTIFICATE = dict(bytes=265, sha256="662fb30f2002c9a26570f4c43e3dfd85fcbdcb38c417ad9378d922b18f0821ff")
ORIGINAL_RECEIPT = dict(bytes=2466, sha256="0817066cbec53daf2ed52569340141f842caa03db86cb3fc35d10a4db0f48e97")
MD4C_AUTHORITY = dict(bytes=1170, sha256="b975ae30c0361432c665de8da025f3cb58ecb0a431922f3135645278c27d93c5")
FINGERPRINT = "CE8ED75F205581BFF9C470173F6B1AA9DA3ABD8A"
R128_LOG = dict(bytes=2255414, sha256="ec0b1d79132cb9bcb2e5646ac2e70f675c57b8747f60cdab2737dc5bacc4d734")
INPUTS = ("portable_selection", "route_plan", "md4c_signature", "md4c_certificate", "md4c_authority")
DISPATCH_ENV = ("GITHUB_ACTIONS", "GITHUB_EVENT_NAME", "GITHUB_REPOSITORY", "GITHUB_ACTOR",
                "GITHUB_TRIGGERING_ACTOR", "GITHUB_REF", "GITHUB_SHA", "GITHUB_WORKFLOW_SHA",
                "GITHUB_WORKFLOW_REF", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_RUN_ID",
                "RUNNER_OS", "RUNNER_ARCH")


def need(condition, code):
    if not condition:
        raise ValueError(code)


def shape(value, keys, code):
    need(type(value) is dict and value.keys() == set(keys), code)


def decode(raw):
    def unique(pairs):
        result = dict(pairs)
        need(len(result) == len(pairs), "DUPLICATE_JSON_KEY")
        return result
    return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: need(False, "NONFINITE_JSON"))


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def whole(row):
    return {key: row[key] for key in ("bytes", "sha256")}


def hexid(value, size=64):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % size, value) is not None


def identifier(value):
    return type(value) is str and re.fullmatch("[1-9][0-9]{0,19}", value) is not None


def relative(value):
    need(type(value) is str and 0 < len(value) <= 240 and PurePosixPath(value).as_posix() == value
         and all(re.fullmatch("[A-Za-z0-9._+@~-]+", part) and part not in (".", "..", ".git")
                 for part in value.split("/")), "ORDINARY_RELATIVE_SOURCE_LEAF")
    return value


def ref(value, cap=MIB):
    shape(value, ("path", "bytes", "sha256"), "EXACT_WHOLE_REFERENCE")
    relative(value["path"])
    need(type(value["bytes"]) is int and 0 <= value["bytes"] <= cap and hexid(value["sha256"]),
         "BOUNDED_WHOLE_REFERENCE")


def branch(value):
    need(type(value) is str and re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", value)
         and ".." not in value and "//" not in value
         and not any(part.startswith(".") or part.endswith((".", ".lock")) for part in value.split("/")),
         "EXACT_BRANCH_REFERENCE")


def ordinary(value):
    path = Path(value)
    need(path.is_absolute() and path == path.resolve() and re.fullmatch(r"/[A-Za-z0-9_./@+~:-]+", str(path)),
         "CANONICAL_ABSOLUTE_PATH")
    return path


def identity(row):
    return (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid, row.st_nlink,
            row.st_size, row.st_mtime_ns, row.st_ctime_ns)


def read(path, cap, expected=None, *, owner=None, mode=None):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap
             and not before.st_mode & 0o022 and (owner is None or before.st_uid == owner)
             and (mode is None or stat.S_IMODE(before.st_mode) == mode), "BOUNDED_ORDINARY_FILE")
        if expected is not None:
            need(before.st_size == expected["bytes"], "FILE_SIZE_PIN")
        raw = stream.read(before.st_size + 1)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat())
             and (expected is None or pin(raw) == whole(expected)), "STABLE_WHOLE_FILE_PIN")
    return raw


def write(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(raw)


def approval(raw, sha, env, now):
    need(0 < len(raw) <= 65536 and hexid(sha) and pin(raw)["sha256"] == sha, "WHOLE_ROOT_APPROVAL_PIN")
    row = decode(raw)
    shape(row, ("kind", "issuer", "approved", "mode", "repository", "live_ref", "workflow_sha",
                "runtime_source", "inputs", "issued_utc", "expires_utc"), "ROOT_APPROVAL_FIELDS")
    need(row["kind"] == KIND and row["issuer"] == "Root" and row["approved"] is True
         and row["mode"] == "pair-only" and row["repository"] == REPO, "ROOT_PAIR_ONLY_APPROVAL")
    branch(row["live_ref"])
    sha = row["workflow_sha"]
    need(hexid(sha, 40) and type(now) is type(row["issued_utc"]) is type(row["expires_utc"]) is int
         and row["issued_utc"] <= now < row["expires_utc"]
         and 0 < row["expires_utc"] - row["issued_utc"] <= 21600, "FRESH_BOUNDED_ROOT_APPROVAL")
    actor = REPO.split("/")[0]
    expected = dict(GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REPOSITORY=REPO,
                    GITHUB_ACTOR=actor, GITHUB_TRIGGERING_ACTOR=actor, GITHUB_REF=row["live_ref"],
                    GITHUB_SHA=sha, GITHUB_WORKFLOW_SHA=sha, GITHUB_RUN_ATTEMPT="1", GITHUB_JOB="pair",
                    GITHUB_WORKFLOW_REF=REPO+"/"+WORKFLOW+"@"+row["live_ref"], RUNNER_OS="Linux", RUNNER_ARCH="ARM64")
    need(all(env.get(key) == value for key, value in expected.items()) and identifier(env.get("GITHUB_RUN_ID")),
         "ACTUAL_OWNED_WORKFLOW_CONTEXT")
    source = row["runtime_source"]
    shape(source, ("ref", "commit", "tree", "map", "entry"), "RUNTIME_SOURCE_FIELDS")
    branch(source["ref"])
    need(source["ref"] != row["live_ref"] and hexid(source["commit"], 40) and hexid(source["tree"], 40),
         "SEPARATE_IMMUTABLE_RUNTIME_SOURCE")
    ref(source["map"])
    ref(source["entry"], 256 * 1024)
    need(source["entry"]["path"] == ENTRY, "EXACT_ADAPTER_ENTRY")
    shape(row["inputs"], INPUTS, "EXACT_PUBLIC_INPUT_ROLES")
    for item in row["inputs"].values():
        ref(item)
    for name, expected in (("md4c_signature", SIGNATURE), ("md4c_certificate", CERTIFICATE),
                           ("md4c_authority", MD4C_AUTHORITY)):
        need(whole(row["inputs"][name]) == expected, "EXACT_R128_TRUST_OPERAND")
    need(len({item["path"] for item in row["inputs"].values()}) == len(INPUTS), "DISTINCT_INPUT_PATHS")
    return row


def entries(root, approved, *, destination=None):
    """Check all leaves before imports and optionally preserve them in Root custody."""
    source = approved["runtime_source"]
    map_ref = source["map"]
    raw = read(root/map_ref["path"], MIB, map_ref)
    index = decode(raw)
    shape(index, ("kind", "schema", "files"), "CLOSED_RUNTIME_MAP_FIELDS")
    files = index["files"]
    need(index["kind"] == MAP_KIND and type(index["schema"]) is int and index["schema"] == 1
         and type(files) is dict and 0 < len(files) <= 1024 and map_ref["path"] not in files,
         "CLOSED_RUNTIME_MAP")
    for item in (source["entry"], *approved["inputs"].values()):
        need(whole(files[item["path"]]) == whole(item), "SAME_PINNED_RUNTIME_ROLE")
    found, count, total = set(), 0, 0
    for folder, dirs, names in os.walk(root, followlinks=False):
        if Path(folder) == root and ".git" in dirs and not (root/".git").is_symlink():
            dirs.remove(".git")
        for name in dirs + names:
            member = Path(folder)/name
            count += 1
            need(count <= 2048 and not member.is_symlink(), "CLOSED_ORDINARY_RUNTIME_NAMESPACE")
            if name in names:
                found.add(member.relative_to(root).as_posix())
    need(found == files.keys() | {map_ref["path"]}, "COMPLETE_RUNTIME_NAMESPACE")
    for name, selected in sorted(files.items()):
        shape(selected, ("bytes", "sha256", "mode"), "RUNTIME_LEAF_FIELDS")
        ref(dict(path=name, **whole(selected)), TOTAL)
        need(type(selected["mode"]) is int and selected["mode"] in (0o644, 0o755), "RUNTIME_LEAF_MODE")
        total += selected["bytes"]
        need(total <= TOTAL, "RUNTIME_SOURCE_BYTE_BOUND")
        body = read(root/name, TOTAL, selected, mode=selected["mode"])
        if destination is not None:
            path = destination/name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            write(path, body, selected["mode"])
    if destination is not None:
        path = destination/map_ref["path"]
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        write(path, raw, 0o644)
    return files


def trust(raw, expected, now, bootstrap_end_utc, certificate):
    need(pin(raw) == whole(expected) and len(raw) <= 8192, "WHOLE_ROOT_SELECTED_R128_TEST_PROJECTION")
    row = decode(raw)
    exact = dict(schema=1, kind="ROOT_QT612_R128_MD4C_TEST_RENEWAL_AUTHORITY_V1", issuer="Root", approved=True,
                 status="PASS_MD4C_R128_EXACT_ARCHIVES_SCOPED_TEST_ONLY", source=R128_COMMIT,
                 run=44241902162, job=134591565463, attempt=1, original_log=R128_LOG,
                 original_receipt=ORIGINAL_RECEIPT, archive=ARCHIVE, signature=SIGNATURE, certificate=CERTIFICATE,
                 fingerprint=FINGERPRINT, created_epoch=1795068921, expires_epoch=1795155321,
                 renewal_receipt=dict(bytes=2328, sha256="d4defeda32d8084e04a300c21d505b3fec0d8e7741508ba760d163fdd0c6fbc3"))
    need(encoded(row) == encoded(exact) and row["created_epoch"] <= now < bootstrap_end_utc < row["expires_epoch"],
         "CURRENT_SCOPED_R128_TEST_AUTHORITY")
    return dict(certificate=dict(path=str(certificate), **CERTIFICATE), fingerprint=FINGERPRINT,
                expires_epoch=row["expires_epoch"], archive=ARCHIVE, signature=SIGNATURE,
                root_evidence=pin(raw))


def job_id(raw, env):
    row = decode(raw)
    jobs = row["jobs"]
    need(type(row["total_count"]) is int and row["total_count"] == len(jobs) == 1, "ONE_CURRENT_ATTEMPT_JOB")
    job = jobs[0]
    checks = dict(run_id=int(env["GITHUB_RUN_ID"]), run_attempt=1, head_sha=env["GITHUB_SHA"],
                  name=env["GITHUB_JOB"], status="in_progress", labels=["ubuntu-24.04-arm"])
    need(all(type(job.get(key)) is type(value) and job[key] == value for key, value in checks.items())
         and type(job["id"]) is int and identifier(str(job["id"])), "ACTUAL_GUI_SERVER_JOB_METADATA")
    return str(job["id"])


def scope_name(run):
    need(identifier(run), "CURRENT_GITHUB_RUN_ID")
    return f"cachy-qt612-gui-server-controller-{run}-1.scope"


def deadlines(started, now, epoch, expiry):
    need(0 < started <= now < started + TRANSFER and started + SCOPE <= now + expiry - epoch,
         "COMPLETE_SCOPE_EXCEEDS_ROOT_AUTHORITY")
    return dict(transfer=started + TRANSFER, bootstrap=started + TRANSFER + BOOTSTRAP,
                work=started + WORK, cleanup=started + SCOPE)


def dispatch(env, job):
    need(identifier(job), "CURRENT_NUMERIC_JOB")
    return dict(source=env["GITHUB_SHA"], ref=env["GITHUB_REF"], run=env["GITHUB_RUN_ID"], job=job, attempt="1")


def late_binding(template, *, dispatch, nonce, map_sha, image, inventory, now, expiry):
    need(type(now) is int and type(expiry) is int and 0 < expiry-now <= COMPONENT
         and hexid(nonce, 32) and hexid(map_sha) and type(image) is str and image.startswith("sha256:")
         and hexid(image[7:]) and type(inventory["bytes"]) is int and 0 < inventory["bytes"] <= MIB
         and hexid(inventory["sha256"]), "FRESH_ACTUAL_356_STAGE_OPERANDS")
    return dict(template, **dispatch, issued_by="Root", accepted=True, component="gui_server", nonce=nonce,
                source_map_sha256=map_sha, image=image, inventory_pin=inventory, created_utc=now, expires_utc=expiry)
