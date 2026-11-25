#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage exact carrier DATA for the maintained desktop workflow."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import types


CARRIER = "4659076d3a1d3e5cf87c185a3ff383fbc38e734d"
TREE = "e21f947bac3afdfbd67e4e65c8234b35ae42b00f"
REF = "refs/heads/codex/native574-complete-retained-inputs-v1"
REMOTE = "https://github.com/Gabriel-Kahen/cachy-asahi.git"
TRANSPORT_SOURCE = "751e798bee99db973d4c19902793c611ea052b1f"
TRANSPORT = ("scripts/maintenance/retained_git_transport.py", 25334,
             "9b90c423fd67c261d8be1dddd8450df5b927b6dbaba9972c4daff8c0da2836b7")
SUPERVISOR = ("scripts/virtual/owned_process.py", 25140,
              "83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f")
DECLARATION = ("scripts/ci/retained-build-inputs/carrier-profile.json", 195440,
               "4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c")
PROFILE_SHA = "47ea6a3f358922ad1d643bc2cbd517fe0335f5dbe1313a87af3d24396d5a39ea"
INPUTS_SHA = "beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f"
INDEX_SHA = "51a53c9e0d9eab1728f350f9ab8d3d7b8932891ab0ed68c7876a1440166ff486"
GIT = Path("/usr/bin/git")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def live(deadline):
    require(time.monotonic() < deadline, "native248-preparation-deadline")


def owned_directory(path, *, private):
    require(path.is_absolute() and path.resolve(strict=True) == path, "native248-directory-path")
    node = path.lstat()
    require(stat.S_ISDIR(node.st_mode) and node.st_uid == os.getuid() == os.geteuid() > 0
            and (stat.S_IMODE(node.st_mode) == 0o700 if private else not node.st_mode & 0o022),
            "native248-directory-owner")
    return node.st_dev, node.st_ino


def file_state(node):
    return (node.st_dev, node.st_ino, node.st_uid, node.st_mode, node.st_nlink,
            node.st_size, node.st_mtime_ns, node.st_ctime_ns)


def verify_git(expected, deadline):
    require(GIT.resolve(strict=True) == GIT, "native248-git-path")
    with os.fdopen(os.open(GIT, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        node = os.fstat(stream.fileno())
        require(stat.S_ISREG(node.st_mode) and stat.S_IMODE(node.st_mode) == 0o755
                and node.st_uid == 0 and node.st_nlink == 1 and 0 < node.st_size <= 128 * 1024**2,
                "native248-git-custody")
        found = hashlib.sha256()
        size = 0
        while chunk := stream.read(1024**2):
            live(deadline)
            size += len(chunk)
            require(size <= node.st_size, "native248-git-drift")
            found.update(chunk)
        require(size == node.st_size and found.hexdigest() == expected
                and file_state(node) == file_state(os.fstat(stream.fileno())) == file_state(GIT.lstat()),
                "native248-git-pin")


def package_pins(raw):
    require(len(raw) == 328101 and sha(raw) == INPUTS_SHA, "native248-input-lock")
    packages = json.loads(raw)["packages"]
    pins = {}
    for item in packages:
        name = item["filename"]
        require(re.fullmatch(r"[A-Za-z0-9._+@:~-]+\.pkg\.tar\.xz", name) and name not in pins,
                "native248-input-name")
        pins[name] = {"bytes": item["size"], "sha256": item["sha256"]}
        pins[name + ".sig"] = {"bytes": item["signature_size"], "sha256": item["signature_sha256"]}
    require(len(packages) == 248 and len(pins) == 496
            and sum(row["bytes"] for row in pins.values()) == 702251555, "native248-input-membership")
    return pins


def carrier_profile(raw):
    require(sha(raw) == DECLARATION[2], "native248-historical-profile-pin")
    profile = json.loads(raw)
    require(profile["source"] == "ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad"
            and "refs/heads/" + profile["ref"] == REF and len(profile["files"]) == 1154,
            "native248-carrier-profile")
    profile["source"] = CARRIER
    data = (json.dumps(profile, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    require(sha(data) == PROFILE_SHA, "native248-physical-profile-pin")
    return data


def module(raw, path, name):
    loaded = types.ModuleType(name)
    loaded.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), loaded.__dict__)
    return loaded


def load_transport(fetch, code, deadline):
    supervisor = fetch(TRANSPORT_SOURCE, *SUPERVISOR, deadline)
    transport = fetch(TRANSPORT_SOURCE, *TRANSPORT, deadline)
    require(sha(supervisor) == SUPERVISOR[2] and sha(transport) == TRANSPORT[2],
            "native248-helper-pin")
    require("owned_process" not in sys.modules, "native248-ambient-supervisor")
    original_path = list(sys.path)
    try:
        # The known import resolves only to the hash-verified supervisor bytes.
        sys.modules["owned_process"] = module(supervisor, code / SUPERVISOR[0], "owned_process")
        return module(transport, code / TRANSPORT[0], "maintained_native248_transport")
    finally:
        sys.modules.pop("owned_process", None)
        sys.path[:] = original_path


def verify_ref(transport, scratch, deadline):
    opts = ["-c", "credential.helper=", "-c", "http.extraHeader=", "-c", "http.proxy=",
            "-c", "http.followRedirects=false", "-c", "http.sslVerify=true",
            "-c", "protocol.allow=never", "-c", "protocol.https.allow=always"]
    argv = [str(GIT), "--no-replace-objects", *opts, "ls-remote", "--exit-code", "--refs", REMOTE, REF]
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(scratch),
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
    budget = min(20, deadline - time.monotonic())
    require(budget > 2, "native248-advertisement-budget")
    transport.op.prepare()
    child = subprocess.Popen(argv, cwd=scratch, env=env, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    observation = transport.op.supervise(child, cap=budget, retirement=1, grace=0.2,
                                         streams=(child.stdout,), max_output=4096)
    require(observation["passed"] and observation["output"] == f"{CARRIER}\t{REF}\n".encode(),
            "native248-carrier-ref-drift")


def project(data, packages, pins, raw_inputs, deadline):
    index_raw = (data / "index.json").read_bytes()
    require(sha(index_raw) == INDEX_SHA and (data / "native-inputs.lock.json").read_bytes() == raw_inputs,
            "native248-carrier-lock")
    index = json.loads(index_raw)["files"]
    require(len(index) == 1148 and all(index.get(name) == row for name, row in pins.items()),
            "native248-carrier-membership")
    source = data / "packages"
    source_id = owned_directory(source, private=True)
    require(set(os.listdir(source)) == set(index), "native248-carrier-membership")
    destination_id = owned_directory(packages, private=True)
    require(not os.listdir(packages), "native248-stage-not-empty")
    for name, row in sorted(pins.items()):
        live(deadline)
        require(owned_directory(source, private=True) == source_id and
                owned_directory(packages, private=True) == destination_id, "native248-stage-drift")
        origin = source / name
        target = packages / name
        with os.fdopen(os.open(origin, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
            before = os.fstat(stream.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                    and before.st_nlink == 1 and before.st_size == row["bytes"]
                    and file_state(before) == file_state(origin.lstat()), "native248-carrier-leaf")
            os.fchmod(stream.fileno(), 0o600)
            os.link(origin, target, follow_symlinks=False)
            linked = os.fstat(stream.fileno())
            require(linked.st_nlink == 2 and file_state(linked) == file_state(origin.lstat())
                    == file_state(target.lstat()), "native248-stage-drift")
            origin.unlink()
            final = os.fstat(stream.fileno())
            require(final.st_nlink == 1 and file_state(target.lstat()) == file_state(final),
                    "native248-stage-drift")
    require(owned_directory(packages, private=True) == destination_id and set(os.listdir(packages)) == set(pins),
            "native248-stage-membership")


@contextmanager
def stage(environment, git_sha, raw_inputs, fetch, deadline):
    """Authenticate and deliver before yielding a path, then retire only this stage."""
    run = environment["GITHUB_RUN_ID"]
    attempt = environment["GITHUB_RUN_ATTEMPT"]
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run) and re.fullmatch(r"[1-9][0-9]{0,9}", attempt),
            "native248-attempt")
    temporary = Path(environment["RUNNER_TEMP"])
    temp_id = owned_directory(temporary, private=False)
    require(shutil.rmtree.avoids_symlink_attacks, "native248-safe-retirement")
    pins = package_pins(raw_inputs)
    profile = carrier_profile(fetch(TRANSPORT_SOURCE, *DECLARATION, deadline))
    verify_git(git_sha, deadline)
    destination = temporary / f"maintained-desktop-v2-native248-{run}-{attempt}"
    destination.mkdir(mode=0o700)
    identity = owned_directory(destination, private=True)
    try:
        packages = destination / "packages"
        packages.mkdir(mode=0o700)
        with tempfile.TemporaryDirectory(prefix="maintained-native248-", dir=temporary) as work:
            scratch = Path(work)
            code = scratch / "code"
            code.mkdir(mode=0o700)
            transport = load_transport(fetch, code, deadline)
            verify_ref(transport, scratch, deadline)
            verify_git(git_sha, deadline)
            policy = transport.reference_policy()
            require(deadline - time.monotonic() >= policy["outer_seconds"], "native248-delivery-budget")
            receipt = transport.deliver(url=REMOTE, expected_source=CARRIER, profile_raw=profile,
                                        profile_sha256=PROFILE_SHA, destination=scratch / "delivery",
                                        executable_root=code, policy=policy)
            require(receipt["status"] == "PASS_EXACT_RETAINED_GIT_DATA_ONLY" and receipt["tree"] == TREE
                    and receipt["blob_joins"] == 1154, "native248-carrier-proof")
            project(scratch / "delivery/data", packages, pins, raw_inputs, deadline)
        live(deadline)
        yield
    finally:
        require(owned_directory(temporary, private=False) == temp_id
                and owned_directory(destination, private=True) == identity, "native248-retirement-custody")
        shutil.rmtree(destination)
        require(not os.path.lexists(destination), "native248-retirement")
