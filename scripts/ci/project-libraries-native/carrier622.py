#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage the reviewed private #622 Git carrier without passing SSH credentials to builds."""
import argparse
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from inputs622 import ROOT, require, retained_pins, stage_set

# Share the #623 process budget and bounded command runner.
sys.path.insert(0, str(ROOT / "scripts/port/kernel-native-job"))
from runtime import Runner, cancellation_handlers, Cancelled

SSH_ENV = "CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY"
REMOTE = "git@github.com:Gabriel-Kahen/cachy-asahi-ci-inputs.git"
REF = "refs/heads/native622-r1"
COMMIT = "c6ed50287db7e7d743111d76e9f0c35179c90b7f"
TREE = "203b14cc4d8afc806c97b10f53518b6b3b5c8659"
ALARM_TREE = "446263ab279603bfda93641c87aa8cad6f53c899"
HOST_KEY = "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n"
DEPLOY_KEY = [b"256", b"SHA256:6gnCZBWA+I9mccJV/YzywHoefkGrpuKBHU0dVcgqn7k"]
GIT = ["/usr/bin/git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
       "-c", "core.autocrlf=false", "-c", "core.attributesFile=/dev/null", "-c", "maintenance.auto=false",
       "-c", "gc.auto=0", "-c", "pack.threads=1", "-c", "protocol.allow=never",
       "-c", "protocol.ssh.allow=always", "-c", "fetch.fsckObjects=true"]


def checked(runner, argv, timeout=15):
    result = runner.run(argv, timeout=timeout, limit=65536)
    require(result.returncode == 0, "carrier command refused")
    return result.stdout


def ssh_fetch(runner, git, secret, scratch):
    require(64 <= len(secret) <= 32768 and secret.startswith("-----BEGIN OPENSSH PRIVATE KEY-----\n")
            and secret.rstrip().endswith("-----END OPENSSH PRIVATE KEY-----"), "OpenSSH deploy key required")
    with tempfile.TemporaryDirectory(prefix="credential-", dir=scratch) as temporary:
        key, known = Path(temporary) / "identity", Path(temporary) / "known_hosts"
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(secret.rstrip() + "\n")
        known.write_text(HOST_KEY, encoding="ascii")
        fingerprint = checked(runner, ["/usr/bin/ssh-keygen", "-lf", str(key), "-E", "sha256"]).split()
        require(fingerprint[:2] == DEPLOY_KEY, "pinned read-only deploy key")
        ssh = ["/usr/bin/ssh", "-q", "-F", "/dev/null", "-i", str(key), "-o", "BatchMode=yes",
               "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=yes",
               "-o", "UserKnownHostsFile=" + str(known), "-o", "GlobalKnownHostsFile=/dev/null",
               "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ClearAllForwardings=yes",
               "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=15"]
        runner.env["GIT_SSH_COMMAND"] = shlex.join(ssh)
        try:
            checked(runner, git + ["fetch", "--quiet", "--depth=1", "--no-tags", "--no-recurse-submodules",
                                   "--no-write-fetch-head", REMOTE, f"{REF}:{REF}"], timeout=175)
        finally:
            del runner.env["GIT_SSH_COMMAND"]


def verify_tree(raw, pins):
    require(raw.endswith(b"\0"), "complete carrier tree")
    expected = {f"alarm-cache/{name}".encode(): pin["bytes"] for name, pin in pins.items()}
    for row in raw[:-1].split(b"\0"):
        header, path = row.split(b"\t")
        mode, kind, oid, size = header.split()
        require(mode == b"100644" and kind == b"blob" and re.fullmatch(b"[0-9a-f]{40}", oid)
                and size == str(expected.pop(path, None)).encode(), "exact regular carrier blob")
    require(not expected, "complete carrier blob membership")


def materialize(runner, git, scratch, destination):
    def read(*args, timeout=15):
        return checked(runner, git + list(args), timeout)

    require(read("rev-parse", "--verify", REF + "^{commit}") == (COMMIT + "\n").encode(), "reviewed carrier commit")
    headers = read("cat-file", "commit", COMMIT).split(b"\n\n", 1)[0].splitlines()
    require(headers[0] == ("tree " + TREE).encode() and not any(row.startswith(b"parent ") for row in headers),
            "reviewed parentless carrier commit")
    require(read("ls-tree", "-z", TREE) == f"040000 tree {ALARM_TREE}\talarm-cache\0".encode(),
            "exact alarm-cache carrier tree")
    pins = retained_pins()
    verify_tree(read("ls-tree", "-r", "-l", "-z", "--full-tree", TREE), pins)
    checkout = scratch / "checkout"
    checkout.mkdir(mode=0o700)
    read("--work-tree=" + str(checkout), "read-tree", TREE)
    read("--work-tree=" + str(checkout), "checkout-index", "--all", "--prefix=" + str(checkout) + "/", timeout=35)
    stage_set(destination, pins, checkout / "alarm-cache")


def private_runner(scratch):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(scratch), "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_SSH_VARIANT": "ssh"}
    return Runner(210, env, scratch)


def stage(destination, secret):
    # The output name is unique to this attempt. Move the complete verified
    # flat cache into the reserved directory after retiring the credentials.
    destination.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory(prefix="carrier-", dir=destination.parent) as temporary:
            scratch = Path(temporary)
            runner = private_runner(scratch)
            store = scratch / "carrier.git"
            checked(runner, GIT + ["init", "--bare", "--quiet", "--template=", "--object-format=sha1", str(store)])
            git = GIT + ["--git-dir=" + str(store)]
            ssh_fetch(runner, git, secret, scratch)
            del secret
            ready = scratch / "verified"
            materialize(runner, git, scratch, ready)
            ready.rename(destination)
    except BaseException:
        retire(destination)
        raise


def retire(destination):
    try:
        facts = destination.lstat()
    except FileNotFoundError:
        return
    require(stat.S_ISDIR(facts.st_mode) and stat.S_IMODE(facts.st_mode) == 0o700
            and facts.st_uid == os.getuid() and shutil.rmtree.avoids_symlink_attacks, "owned private carrier cache")
    shutil.rmtree(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("stage", "retire"))
    args = parser.parse_args()
    os.umask(0o077)
    secret = os.environ.pop(SSH_ENV, "")
    try:
        run, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
        temporary = Path(os.environ["RUNNER_TEMP"])
        require(re.fullmatch("[0-9]{1,20}", run) and re.fullmatch("[0-9]{1,10}", attempt)
                and temporary.is_absolute() and temporary == temporary.resolve() and temporary.is_dir()
                and temporary.stat().st_uid == os.getuid(),
                "owned runner attempt path")
        destination = temporary / f"libraries622-retained-{run}-{attempt}"
        with cancellation_handlers():
            if args.mode == "stage":
                stage(destination, secret)
            else:
                retire(destination)
    except (Exception, Cancelled):
        # Git and SSH diagnostics can contain protected configuration.
        print("PROJECT_LIBRARIES_CARRIER_REFUSED", file=sys.stderr)
        return 1
    print("PROJECT_LIBRARIES_CARRIER_STAGED" if args.mode == "stage" else "PROJECT_LIBRARIES_CARRIER_RETIRED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
