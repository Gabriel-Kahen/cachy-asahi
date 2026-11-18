# SPDX-License-Identifier: MIT
"""Stage the original Setup7 archive and plan a disposable signed Setup8 update."""

import argparse
from contextlib import ExitStack
import importlib.util
from io import BytesIO
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "overlay583_install_trial", HERE.parent / "overlay583_trial/trial.py"
)
T = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(T)

PACKAGE = "cachy-asahi-setup"
OLD = "0.1.0-7"
NEW = "0.3.0-1"
ARCHIVE = f"{PACKAGE}-{OLD}-any.pkg.tar.xz"
SIGNATURE = ARCHIVE + ".sig"
PUBLIC = "rehearsal-TEST-public.gpg"
RECEIPT = "predecessor.json"
PREDECESSOR = "upgrade-predecessor"
ARTIFACT = dict(bytes=2516591, sha256="2f27ac455f2a1bd1961d2b9c4021849eac7ecf1d24c01e35147298f2f35f25ba")
PREVIOUS = dict(bytes=30316, sha256="027c802a90fde820a4773b259203a77e18132cbb7b0fb9454c2d368426f66d09")
SUCCESSOR = dict(bytes=33900, sha256="8de3bd0cf2d9333b41925fecdef5cbfe2ec6d40c3424d90746182142e0c7dc47")
SOURCE = "5d0f5ae6331807704a8ebafc7922972629e0b96f"
TARGET = dict(bytes=11450, sha256="12e5f0d74f8530fee9cc2b10ad7887748c2f9d5fdfed259b498f4b3db87167ba")
FINGERPRINT = re.compile("[0-9A-F]{40}")
KIND = "OVERLAY583_SETUP7_PREDECESSOR_TEST_STAGING_V1"
CACHE = T.WORK / "upgrade-cache"
TRANSACTIONS = {"install-base-and-shells", "install-predecessor", "upgrade"}


def previous_archive(artifact):
    raw = T.read(artifact, ARTIFACT, cap=4 * 1024**2)
    with zipfile.ZipFile(BytesIO(raw)) as retained:
        bodies = []
        for pair in ("a", "b"):
            name = f"packages/cachy-asahi-setup7-{pair}/{ARCHIVE}"
            members = [item for item in retained.infolist() if item.filename == name]
            T.need(len(members) == 1 and members[0].file_size == PREVIOUS["bytes"],
                   "Original Setup7 artifact member differs")
            body = retained.read(members[0])
            T.need(T.pin(body) == PREVIOUS, "Original Setup7 .pkg.tar.xz differs")
            bodies.append(body)
    T.need(bodies[0] == bodies[1], "Original Setup7 pair differs")
    return bodies[0]


def key_command(home, *arguments):
    return subprocess.run(
        ["/usr/bin/gpg", "--no-options", "--homedir", str(home), "--batch",
         "--no-auto-key-retrieve", *arguments],
        stdin=subprocess.DEVNULL, capture_output=True, check=True, timeout=30,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GNUPGHOME": str(home)},
    ).stdout


def staged_tree(out, signer, source_pin):
    files = {name: dict(T.read(out / name, cap=128 * 1024, collect=False))
             for name in (ARCHIVE, SIGNATURE, PUBLIC)}
    T.need(files[ARCHIVE] == PREVIOUS, "Exact original Setup7 required")
    return dict(kind=KIND, version=OLD, architecture="any", package=PACKAGE,
                signer=signer, public_test_only=True, artifact=source_pin,
                original_native_source=SOURCE, files=files)


def check_stage(out, receipt_pin):
    """Reopen the whole predecessor operand set against external receipt bytes."""
    out = T.ordinary(out)
    T.need({item.name for item in out.iterdir()} == {ARCHIVE, SIGNATURE, PUBLIC, RECEIPT},
           "Closed predecessor staging required")
    observed = {}
    raw = T.read(out / RECEIPT, receipt_pin, cap=16 * 1024, observed=observed)
    value = T.decode(raw)
    signer = value.get("signer")
    T.need(type(signer) is str and FINGERPRINT.fullmatch(signer),
           "Exact rehearsal TEST signer fingerprint required")
    T.need(raw == T.encoded(value) and value == staged_tree(out, signer, ARTIFACT),
           "Predecessor receipt differs from its staged files")
    for name,pin in value["files"].items():
        T.read(out / name, pin, cap=128 * 1024, collect=False, observed=observed)
    T.unchanged(observed)
    return dict(value, receipt=receipt_pin)


def stage(artifact, output):
    """Sign only the retained original archive with a one-day throwaway TEST key."""
    body = previous_archive(artifact)
    out = T.ordinary(output)
    out.mkdir(mode=0o700)
    (out / ARCHIVE).write_bytes(body)
    with tempfile.TemporaryDirectory(prefix="overlay583-upgrade-gpg-") as temp:
        home = Path(temp)
        try:
            key_command(home, "--pinentry-mode", "loopback", "--passphrase", "",
                        "--quick-generate-key", "Cachy-Asahi Overlay583 Rehearsal TEST", "ed25519", "sign", "1d")
            entries = key_command(home, "--with-colons", "--fingerprint", "--list-keys").decode("ascii")
            fingerprints = [row.split(":")[9] for row in entries.splitlines() if row.startswith("fpr:")]
            T.need(len(fingerprints) == 1 and FINGERPRINT.fullmatch(fingerprints[0]),
                   "One fresh local TEST signing identity required")
            signer = fingerprints[0]
            (out / PUBLIC).write_bytes(key_command(home, "--export", signer))
            key_command(home, "--local-user", signer, "--pinentry-mode", "loopback",
                        "--passphrase", "", "--output", str(out / SIGNATURE),
                        "--detach-sign", str(out / ARCHIVE))
            status = key_command(home, "--status-fd", "1", "--verify", str(out / SIGNATURE), str(out / ARCHIVE))
            valid = [row.split() for row in status.decode("ascii").splitlines()
                     if row.startswith("[GNUPG:] VALIDSIG ")]
            T.need(len(valid) == 1 and valid[0][2] == signer == valid[0][-1],
                   "Same original archive and whole TEST signature identity required")
        finally:
            subprocess.run(["/usr/bin/gpgconf", "--homedir", str(home), "--kill", "all"],
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=True)
    receipt = T.encoded(staged_tree(out, signer, ARTIFACT))
    (out / RECEIPT).write_bytes(receipt)
    return check_stage(out, T.pin(receipt))


def inventories(lock):
    T.need(T.pin(lock) == TARGET, "Exact currently selected Overlay583 inventory required")
    rows = T.canonical_lock(lock, 583)
    T.need(rows.get(PACKAGE) == NEW, "Setup8 successor row differs")
    rows[PACKAGE] = OLD
    predecessor = "".join(f"{name} {version}\n" for name,version in sorted(rows.items())).encode("ascii")
    del rows[PACKAGE]
    without = "".join(f"{name} {version}\n" for name,version in sorted(rows.items())).encode("ascii")
    return without, predecessor


def plan(packet, lock, predecessor, nonce):
    """Reuse the reviewed install plan's paths and retain only one changed version."""
    standard = T.guest_plan(packet, nonce)
    without, before = inventories(lock)
    rows = packet["packages"]
    successor_archive = T.REPOS[T.OVERLAY_REPO] + f"/{PACKAGE}-{NEW}-any.pkg.tar.xz"
    T.need(packet["target"] == TARGET and rows[PACKAGE] == {"version": NEW, "repo": T.OVERLAY_REPO}
           and packet["files"].get(successor_archive) == SUCCESSOR
           and predecessor["signer"] not in packet["signers"], "Distinct exact Setup8 staging and predecessor trust required")
    T.need(predecessor["kind"] == KIND and predecessor["files"][ARCHIVE] == PREVIOUS,
           "Exact independently selected TEST predecessor required")
    T.need(T.canonical_lock(lock,583) == {name:row["version"] for name,row in rows.items()},
           "Every signed repository row must join the exact target inventory")
    command = standard["operations"][0][1][:-3]
    new_cache = list(command)
    new_cache[new_cache.index("--cachedir") + 1] = str(CACHE)
    keep = [row["repo"] + "/" + name for name,row in sorted(rows.items()) if name != PACKAGE]
    current = T.OVERLAY_REPO + "/" + PACKAGE
    old_archive = str(T.IN / PREDECESSOR / ARCHIVE)
    return dict(kind="OVERLAY583_SETUP7_TO_SETUP8_GUEST_PLAN_V1", nonce=nonce, packet=packet,
                predecessor=predecessor, without=T.pin(without), before=T.pin(before),
                timeout_seconds=standard["timeout_seconds"], Root_acceptance=None,
                operations=[
                    standard["operations"][0],
                    ["resolve-base-and-shells", [*command,"--sync","--print","--print-format","%n %v %r","--",*keep],120],
                    ["install-base-and-shells", [*command,"--sync","--noconfirm","--",*keep],2700],
                    ["query-without-setup", [*command,"--query"],60],
                    ["check-without-setup", [*command,"--database","--check"],60],
                    ["predecessor-plan", [*command,"--upgrade","--print","--print-format","%n %v","--",old_archive],60],
                    ["install-predecessor", [*command,"--upgrade","--noconfirm","--",old_archive],120],
                    ["query-before", [*command,"--query"],60],
                    ["check-before", [*command,"--database","--check"],60],
                    ["upgrade-plan", [*new_cache,"--sync","--print","--print-format","%n %v %r","--",current],60],
                    ["upgrade", [*new_cache,"--sync","--noconfirm","--",current],180],
                    ["query-after", [*command,"--query"],60],
                    ["check-after", [*command,"--database","--check"],60],
                ])


def expected_output(plan, lock):
    without, before = inventories(lock)
    resolution = T.pacman_plan(plan["packet"])
    target = f"{PACKAGE} {NEW} {T.OVERLAY_REPO}\n".encode("ascii")
    T.need(resolution.splitlines(keepends=True).count(target) == 1,
           "Expected exactly one Setup8 repository resolution row")
    return {
        "resolve-base-and-shells": (resolution.replace(target, b""),None),
        "query-without-setup": (without,"without-setup.lock"),
        "predecessor-plan": (f"{PACKAGE} {OLD}\n".encode("ascii"),None),
        "query-before": (before,"before-upgrade.lock"),
        "upgrade-plan": (target,None),
        "query-after": (lock,"after-upgrade.lock"),
    }


def confirm_transaction(log):
    match = re.compile(rb"^\[[^\]\r\n]+\] \[ALPM\] (installed|removed|upgraded|downgraded|reinstalled) "
                       rb"cachy-asahi-setup ([^\r\n]+)$", re.M)
    expected = [(b"installed", f"({OLD})".encode()),
                (b"upgraded", f"({OLD} -> {NEW})".encode())]
    T.need(match.findall(log) == expected, "Expected exact Setup7 install and one actual Setup8 upgrade")

def execute(plan_value, lock, run, env, config):
    """Execute inside the owning trial's mounted guest after public trust import."""
    T.need(os.getuid() == os.geteuid() == 0
           and os.sysconf("SC_PAGE_SIZE") == 16384 and os.uname().machine == "aarch64",
           "Exact AArch64 16 KiB guest root required")
    mounts = Path("/proc/self/mountinfo").read_text().splitlines()
    for path in (T.IN, T.PLAN.parent):
        T.mount_mode(path, "ro", mounts)
    T.mount_mode(T.WORK, "rw", mounts)
    T.need(T.WORK.stat().st_dev != Path("/").stat().st_dev
           and {item.name for item in Path("/sys/class/net").iterdir()} <= {"lo"}
           and Path("/proc/cmdline").read_text().split().count("cachy_overlay583_nonce="+plan_value["nonce"]) == 1,
           "Bound offline guest and distinct scratch mount required")
    predecessor = check_stage(T.IN / PREDECESSOR, plan_value["predecessor"]["receipt"])
    T.need(plan_value == plan(plan_value["packet"], lock, predecessor, plan_value["nonce"]),
           "Recomputed exact upgrade plan required")
    public = T.read(T.IN / PREDECESSOR / PUBLIC, predecessor["files"][PUBLIC], cap=128 * 1024)
    gpg = ["/usr/bin/gpg","--batch","--no-options"]
    run("import-predecessor", [*gpg,"--import"], 30, public)
    run("trust-predecessor", [*gpg,"--import-ownertrust"], 30,
        (predecessor["signer"] + ":6:\n").encode("ascii"))
    CACHE.mkdir(mode=0o700)
    expected = expected_output(plan_value,lock)
    for role,argv,seconds in plan_value["operations"]:
        T.read(T.CONFIG,T.pin(config),cap=4096)
        if role == "upgrade":
            T.need(not list(CACHE.iterdir()), "Upgrade package cache must start empty")
        if role in TRANSACTIONS:
            with ExitStack() as mounts:
                T.target_api_mounts(T.TARGET,env,mounts)
                T.run_operation(role,argv,seconds,expected,run,env,None)
            T.check_hooks(T.OUTPUT,role)
        else:
            T.run_operation(role,argv,seconds,expected,run,env,None)
    confirm_transaction(T.read(T.OUTPUT / "pacman.log", cap=8 * 1024**2))
    T.need(check_stage(T.IN / PREDECESSOR, plan_value["predecessor"]["receipt"]) == predecessor,
           "Same read-only predecessor transit at retirement")


def evidence_names(plan_value):
    roles = {"import-0","import-1","import-2","ownertrust","import-predecessor","trust-predecessor"}
    roles.update(row[0] for row in plan_value["operations"])
    return {"without-setup.lock","before-upgrade.lock","after-upgrade.lock","pacman.log","result.json"} | {
        f"{role}.{stream}" for role in roles for stream in ("stdout","stderr")
    }


def readback(output, plan_value, lock):
    """Independently reopen positive inventory and ALPM transition evidence."""
    output = T.ordinary(output)
    T.need({item.name for item in output.iterdir()} == evidence_names(plan_value),
           "Exact closed upgrade evidence namespace required")
    observed = {}
    result = T.decode(T.read(output / "result.json", cap=256 * 1024, observed=observed))
    T.need(result["status"] == "PASS_DISPOSABLE_OVERLAY583_SETUP_UPGRADE_ONLY"
           and result["nonce"] == plan_value["nonce"] and result["plan"] == T.pin(T.encoded(plan_value))
           and result["installed_lock"] == TARGET and result["Root_acceptance"] is None,
           "Exact positive guest upgrade result required")
    gpg = ["/usr/bin/gpg","--batch","--no-options"]
    trust = [(f"import-{index}", [*gpg,"--import"]) for index in range(len(T.GPG_PATHS))]
    trust += [("ownertrust", [*gpg,"--import-ownertrust"]),
              ("import-predecessor", [*gpg,"--import"]),
              ("trust-predecessor", [*gpg,"--import-ownertrust"])]
    ledger = [dict(role=role,argv=argv,exit=0)
              for role,argv in trust + [(role,argv) for role,argv,_ in plan_value["operations"]]]
    T.need(result["commands"] == ledger, "Exact successful trust and ALPM step ledger required")
    evidence = {}
    for name in sorted(evidence_names(plan_value)):
        evidence[name] = T.read(output/name, cap=8 * 1024**2, collect=False, observed=observed)
    for role,(expected,snapshot) in expected_output(plan_value,lock).items():
        raw = T.read(output/(role+".stdout"), cap=256 * 1024, observed=observed)
        T.need(T.sorted_rows(raw) == expected, "Different upgrade pacman evidence: "+role)
        if snapshot:
            T.read(output/snapshot, T.pin(expected), cap=256 * 1024, observed=observed)
    for role in TRANSACTIONS:
        T.check_hooks(output,role,observed=observed)
    confirm_transaction(T.read(output/"pacman.log", cap=8 * 1024**2, observed=observed))
    T.unchanged(observed)
    return evidence


def digest_pin(path, digest):
    T.need(T.HEX.fullmatch(digest), "External SHA-256 required")
    path = T.ordinary(path)
    ref = dict(bytes=path.stat().st_size, sha256=digest)
    T.read(path, ref, cap=64 * 1024, collect=False)
    return ref


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    stage_cli = commands.add_parser("stage", help="Sign the exact native Setup7 predecessor with a fresh TEST key")
    stage_cli.add_argument("--artifact", type=Path, required=True)
    stage_cli.add_argument("--output", type=Path, required=True)
    prepare = commands.add_parser("prepare", help="Verify inputs and emit an unissued guest plan")
    for name in ("staging", "preflight", "predecessor"):
        prepare.add_argument("--" + name, type=Path, required=True)
    for name in ("preflight-sha256","predecessor-sha256","nonce"):
        prepare.add_argument("--" + name, required=True)
    args = parser.parse_args()
    if args.command == "stage":
        value = stage(args.artifact, args.output)
    else:
        predecessor = check_stage(args.predecessor,digest_pin(args.predecessor / RECEIPT,args.predecessor_sha256))
        packet = T.choose(args.staging, selected_lock=T.PINS)
        preflight_pin = digest_pin(args.preflight, args.preflight_sha256)
        packet = T.admit(packet, T.read(args.preflight, preflight_pin, cap=64 * 1024), preflight_pin)
        lock = T.read(args.staging / "target.lock",TARGET,cap=64 * 1024)
        value = plan(packet,lock,predecessor,args.nonce)
    sys.stdout.buffer.write(T.encoded(value))


if __name__ == "__main__":
    main()
