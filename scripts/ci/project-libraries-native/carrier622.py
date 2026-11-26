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
REF = "refs/heads/native622-r2"
COMMIT = "8532184d4d6b3a0d8d3b12289fae1e19e270938e"
TREE = "70b65df54a630428e86adab3bf9faf26054fce79"
ALARM_TREE = "e0bc8a6531473f02c86ed5d7ada2ec34387ddd81"
HISTORICAL_REF = "refs/heads/native622-historical-r1"
HISTORICAL_COMMIT = "564f5c74b11b73eb43fe6b1879412c82ade3e6be"
HISTORICAL_TREE = "96812687497a5f7674136b187a6a56300781bbe7"
HISTORICAL_ALARM_TREE = "0e72c9c6cfec72215f86c475972474277692d148"
MAINTAINED_REF = "refs/heads/native622-maintained-extension-r1"
MAINTAINED_COMMIT = "02bb95c5e2e2bdd5856bcd47f97d9674d999d7e2"
MAINTAINED_TREE = "850138f95224b2057b21c810a64ce78f0ebb5033"
MAINTAINED_ALARM_TREE = "8a7bf7392193d010654e0b904e86ae11b9d47601"
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


def ssh_fetch(runner, git, secret, scratch, ref=REF):
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
                                   "--no-write-fetch-head", REMOTE, f"{ref}:{ref}"], timeout=175)
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


def carrier_profile(historical=False, maintained=False):
    if maintained:
        from maintained_inputs622 import extension_pins

        return MAINTAINED_REF, MAINTAINED_COMMIT, MAINTAINED_TREE, MAINTAINED_ALARM_TREE, extension_pins()
    if historical:
        from migration622 import HISTORICAL

        pins = {name: {"bytes": size, "sha256": digest} for name, (size, digest) in HISTORICAL.items()}
        return HISTORICAL_REF, HISTORICAL_COMMIT, HISTORICAL_TREE, HISTORICAL_ALARM_TREE, pins
    return REF, COMMIT, TREE, ALARM_TREE, retained_pins()


def materialize(runner, git, scratch, destination, profile):
    ref, commit, tree, alarm_tree, pins = profile
    def read(*args, timeout=15):
        return checked(runner, git + list(args), timeout)

    require(read("rev-parse", "--verify", ref + "^{commit}") == (commit + "\n").encode(), "reviewed carrier commit")
    headers = read("cat-file", "commit", commit).split(b"\n\n", 1)[0].splitlines()
    require(headers[0] == ("tree " + tree).encode() and not any(row.startswith(b"parent ") for row in headers),
            "reviewed parentless carrier commit")
    require(read("ls-tree", "-z", tree) == f"040000 tree {alarm_tree}\talarm-cache\0".encode(),
            "exact alarm-cache carrier tree")
    verify_tree(read("ls-tree", "-r", "-l", "-z", "--full-tree", tree), pins)
    checkout = scratch / "checkout"
    checkout.mkdir(mode=0o700)
    read("--work-tree=" + str(checkout), "read-tree", tree)
    read("--work-tree=" + str(checkout), "checkout-index", "--all", "--prefix=" + str(checkout) + "/", timeout=35)
    stage_set(destination, pins, checkout / "alarm-cache")


def private_runner(scratch):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(scratch), "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0", "GIT_SSH_VARIANT": "ssh"}
    return Runner(210, env, scratch)


def stage(destination, secret, historical=False, maintained=False):
    # The output name is unique to this attempt. Move the complete verified
    # flat cache into the reserved directory after retiring the credentials.
    destination.mkdir(mode=0o700)
    try:
        with tempfile.TemporaryDirectory(prefix="carrier-", dir=destination.parent) as temporary:
            scratch = Path(temporary)
            runner = private_runner(scratch)
            profile = carrier_profile(historical, maintained)
            store = scratch / "carrier.git"
            checked(runner, GIT + ["init", "--bare", "--quiet", "--template=", "--object-format=sha1", str(store)])
            git = GIT + ["--git-dir=" + str(store)]
            ssh_fetch(runner, git, secret, scratch, profile[0])
            del secret
            ready = scratch / "verified"
            materialize(runner, git, scratch, ready, profile)
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
    profiles = parser.add_mutually_exclusive_group()
    profiles.add_argument("--historical", action="store_const", const="historical", dest="lane",
                          help="use the separate historical-provider carrier")
    profiles.add_argument("--maintained-extension", action="store_const", const="maintained", dest="lane",
                          help="use the maintained builder extension carrier")
    profiles.add_argument("--maintained-base", action="store_const", const="maintained-base", dest="lane",
                          help="retire a maintained base cache staged by kernel intake")
    parser.set_defaults(lane="retained")
    args = parser.parse_args()
    if args.mode == "stage" and args.lane == "maintained-base":
        parser.error("maintained base is staged through kernel intake")
    os.umask(0o077)
    secret = os.environ.pop(SSH_ENV, "")
    try:
        run, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
        temporary = Path(os.environ["RUNNER_TEMP"])
        require(re.fullmatch("[0-9]{1,20}", run) and re.fullmatch("[0-9]{1,10}", attempt)
                and temporary.is_absolute() and temporary == temporary.resolve() and temporary.is_dir()
                and temporary.stat().st_uid == os.getuid(),
                "owned runner attempt path")
        name = "kernel623-retained" if args.lane == "maintained-base" else f"libraries622-{args.lane}"
        destination = temporary / f"{name}-{run}-{attempt}"
        with cancellation_handlers():
            if args.mode == "stage":
                stage(destination, secret, historical=args.lane == "historical", maintained=args.lane == "maintained")
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
