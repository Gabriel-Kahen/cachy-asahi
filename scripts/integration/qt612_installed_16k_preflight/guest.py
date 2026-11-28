# SPDX-License-Identifier: MIT
"""Entry point for the installed Qtbase worker in an already admitted Q3 guest."""

import argparse
import importlib.util
import os
from pathlib import Path
import re
from runpy import run_path
import signal
import stat
import sys
from tempfile import TemporaryFile
import time
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
O = SimpleNamespace(**run_path(str(HERE / "observer.py")))
W, P, T = O.W, O.P, O.T
MEDIA, WORK = Path(P.MEDIA), Path(P.WORK)
SOURCE = P.ROOT
BOOT_NONCE = "cachy_qt_install_nonce="
BOOT_CASE = "cachy_qt_install_case="
BOOT_CLONE = "cachy_qt_install_clone="
PLAN_FILE = "PLAN.json"
SELECTION_FILE = "SELECTION.json"
INVENTORY_FILE = "expected356.lock"
USER = 1000
CLEANUP_SECONDS = 30
STREAM_CAP = 1 << 20  # The original owned recorder's combined stream cap.
CONSUMER = re.compile(r"(?:install|reinstall|install-again)-consumer-(configure|build|run)")
PROBE = re.compile(r"(?:baseline|install|reinstall|remove|install-again|final-remove)-observe-soname-[0-9]{1,2}")
DROP = ["/usr/bin/setpriv", f"--reuid={USER}", f"--regid={USER}", "--clear-groups", "--no-new-privs"]


def kernel_text(path):
    with Path(path).open("rb") as stream:
        raw = stream.read((1 << 20) + 1)
    T.need(0 < len(raw) <= 1 << 20, "Bounded guest kernel report required")
    return raw.decode("ascii")


def verify_mounts(lines, source, media, guest):
    T.mount_mode(source, "ro", lines)
    T.mount_mode(media, "ro", lines)
    mounts = [tuple(row.split()) for row in lines]
    T.need(all("ro" in row[5].split(",") for row in mounts if len(row) >= 10
               and any(Path(row[4]).is_relative_to(path) for path in (source, media))),
           "Pinned guest source and media mount trees must be read-only")
    roots = [row for row in mounts if len(row) >= 10 and row[4] == "/"]
    # The owner self-binds /qtwork/root before chroot. The scratch ext4 mount
    # appears inside the chroot with filesystem root /root and mountpoint /.
    T.need(len(roots) == 1 and roots[0][3] == "/" + Path(guest["root"]).name
           and "rw" in roots[0][5].split(",") and roots[0][roots[0].index("-") + 1] == "ext4",
           "Admitted writable Q3 ext4 root required")
    protected = (Path("/var/lib/pacman"), WORK)
    T.need(all(not any(path.is_relative_to(point) or point.is_relative_to(path) for path in protected)
               for row in mounts if len(row) >= 10 and (point := Path(row[4])) != Path("/")),
           "Qt work and local package database must belong to the disposable Q3 root")


def verify_boot_case(args, nonce, *, case=None, clone=None):
    selected = [arg for arg in args if arg.startswith((BOOT_CASE, BOOT_CLONE))]
    allowed = {(), (BOOT_CASE + "main", BOOT_CLONE + nonce)} if case is None else {
        (BOOT_CASE + case, BOOT_CLONE + clone)
    }
    # Ordering on the kernel command line does not confer authority.
    T.need([arg for arg in args if arg.startswith(BOOT_NONCE)] == [BOOT_NONCE + nonce]
           and any(sorted(selected) == sorted(pair) for pair in allowed), "Exact guest boot case and clone required")


def verify_boundary(nonce, guest, *, case=None, clone=None):
    T.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__ and os.getuid() == os.geteuid() == 0
           and os.uname().machine == guest["architecture"] == "aarch64"
           and os.sysconf("SC_PAGE_SIZE") == guest["page_size_bytes"] == 16384,
           "Expected isolated root program in the admitted AArch64 16 KiB guest")
    args = kernel_text("/proc/cmdline").split()
    verify_boot_case(args, nonce, case=case, clone=clone)
    T.need({node.name for node in Path("/sys/class/net").iterdir()} == {"lo"}, "Offline guest required")
    verify_mounts(kernel_text("/proc/self/mountinfo").splitlines(), SOURCE, MEDIA, guest)
    root_device = Path("/").stat().st_dev
    T.need(all(T.ordinary(path).stat().st_dev == root_device for path in (WORK, Path("/var/lib/pacman/local"))),
           "Exact local Q3 workspace and package database required")
    return True


def protected_paths(paths):
    entries = tuple(Path(value) for value in paths)
    T.need(0 < len(entries) <= 512 and len(set(entries)) == len(entries)
           and all(path.is_absolute() and path != Path("/") and str(path) == value and ".." not in path.parts
                   and all(32 < ord(ch) < 127 for ch in value) for path, value in zip(entries, paths)),
           "Exact protected paths must be selected by the guest owner")
    return entries


def prepare_work():
    status = WORK.lstat()
    T.need(stat.S_ISDIR(status.st_mode) and status.st_uid == status.st_gid == 0
           and stat.S_IMODE(status.st_mode) == 0o755 and {path.name for path in WORK.iterdir()} == {"pacman.conf"},
           "Fresh root-owned Qt workspace with selected configuration required")
    for name in ("gnupg", "cache", "evidence", "home", "runtime", "consumer"):
        path = WORK / name
        path.mkdir(mode=0o700)
        if name in {"home", "runtime", "consumer"}:
            os.chown(path, USER, USER)
    commands = WORK / "evidence" / "commands"
    commands.mkdir(mode=0o700)
    return commands


def runtime_module():
    path = P.PROJECT / "arm16k_perl5423_vm/runtime.py"
    spec = importlib.util.spec_from_file_location("qt_installed_owned_runtime", path)
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    return runtime


class Runner:
    def __init__(self, runtime, output, deadline, consumer):
        self.runtime, self.output, self.deadline, self.consumer = runtime, output, deadline, consumer

    def command_argv(self, role, argv, env):
        consumer = CONSUMER.fullmatch(role)
        probe = PROBE.fullmatch(role)
        if consumer:
            step = consumer[1]
            wanted = self.consumer["environment"] | ({"LD_DEBUG": "files"} if step == "run" else {})
            T.need(argv == self.consumer[step] and env == wanted, "Exact ordinary-user consumer command required")
        else:
            T.need(env == W.NORMAL_ENV, "Exact installed-trial command environment required")
            if probe:
                T.need(argv[:4] == ["/usr/bin/python3", "-I", "-B", O.PROBE] and len(argv) == 5,
                       "Exact ordinary-user normal loader probe required")
        # The recorder launches setpriv with its own fixed clean environment.
        # env sets LD_DEBUG only when it execs the already unprivileged consumer.
        return (DROP if consumer or probe else []) + ["/usr/bin/env", "-i",
            *(f"{key}={env[key]}" for key in sorted(env)), *argv]

    def __call__(self, role, argv, *, timeout, stdin, env):
        if role == "key-trust":
            T.need(argv == W.GPG + ["--import-ownertrust"]
                   and type(stdin) is bytes and re.fullmatch(rb"[0-9A-F]{40}:6:\n", stdin),
                   "Exact public TEST ownertrust input and command required")
        else:
            T.need(stdin is None, "Only key-trust may receive command input")
        wrapped = self.command_argv(role, argv, env)
        cutoff = self.deadline if role == "trust-retirement" else self.deadline - CLEANUP_SECONDS
        with TemporaryFile(dir=self.output) as source:
            if stdin is not None:
                path = self.output / "key-trust.stdin"
                with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as evidence:
                    evidence.write(stdin)
                source.write(stdin)
                source.seek(0)
            result = self.runtime.command(wrapped, self.output, role, seconds=timeout, deadline=cutoff,
                                          input_file=source if stdin is not None else None,
                                          completed=True, check=False)
        receipt = self.runtime.receipt(self.output / (role + ".json"))
        T.need(self.runtime._retired(receipt) and receipt["argv"] == wrapped and receipt["exit"] == result.returncode
               and len(result.stdout) + len(result.stderr) <= STREAM_CAP,
               "Owned Qt command failed its exact natural-retirement receipt")
        return dict(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr,
                    natural=True, group_empty=True, overflow=False)


def retain_view(root, role, sight):
    report = {name: body for name, body in sight.items() if name not in ("protected", "database")}
    for name, limit in (("protected", O.VIEW_CAP), ("database", 128 << 20)):
        raw = sight[name]
        if raw is None:
            report[name] = None
            continue
        T.need(type(raw) is bytes and 0 < len(raw) <= limit, "Bounded original observation required: " + name)
        with (root / f"{role}-{name}.json").open("xb") as stream:
            stream.write(raw)
        report[name] = T.pin(raw)
    raw = T.encoded(report)
    T.need(len(raw) <= W.MAX_SELECTION, "Bounded original installed-stage view required")
    with (root / f"{role}-observed.json").open("xb") as stream:
        stream.write(raw)
    return sight


def execute(plan_raw, plan_sha, inventory, selection_raw, selection_sha, *, now, deadline, protected):
    plan = W.read_plan(plan_raw, plan_sha, inventory)
    selection = W.read_selection(selection_raw, selection_sha, plan_sha, now)
    verify_boundary(plan["nonce"], plan["guest"])
    inputs = O.input_evidence(MEDIA, WORK)
    T.need(inputs["input_pins"] == selection["inputs"] and inputs["config_raw"] == P.CONFIG.encode(),
           "Selected archive, TEST materials and ALPM configuration required")
    for name, digest in plan["consumer"]["files"].items():
        T.read(MEDIA / "consumer" / name, digest, cap=128 << 10)
    probe = T.read(HERE / "loader_probe.py", cap=128 << 10)
    T.read(MEDIA / "loader_probe.py", T.pin(probe), cap=128 << 10)
    T.need(time.monotonic() + CLEANUP_SECONDS + 3 < deadline, "Insufficient owned guest time")
    commands = prepare_work()
    run = Runner(runtime_module(), commands, deadline, plan["consumer"])
    observer = O.Observer(plan, selection, run, protected)

    def observe(role):
        return retain_view(commands.parent, role, observer.observe(role))

    result = W.exercise(plan_raw, plan_sha, inventory, selection_raw, selection_sha, now=now,
                        **inputs, verify_boundary=verify_boundary, run=observer.run, observe=observe)
    with (commands.parent / "result.json").open("xb") as output:
        output.write(T.encoded(result))


def retain_database(output, point):
    original = W.stopped_database(Path("/"))
    T.need(0 < len(original) <= 128 << 20, "Bounded stopped Q3 database required")
    with (output / f"database-{point}.json").open("xb") as stream:
        stream.write(original)
    return original


def execute_negative(plan_raw, plan_sha, inventory, selection_raw, selection_sha, *,
                     now, deadline, case, clone, signature_sha):
    plan = W.read_plan(plan_raw, plan_sha, inventory)
    selection = W.read_selection(selection_raw, selection_sha, plan_sha, now)
    nonce = plan["nonce"]
    T.need(case in W.NEGATIVE_CASES and type(clone) is str and re.fullmatch("[0-9a-f]{32}", clone)
           and clone != nonce and type(signature_sha) is str and T.HEX.fullmatch(signature_sha),
           "Exact selected signature-refusal clone required")
    original_signature = selection["inputs"]["signature"]
    tampered = case == "tampered_signature"
    T.need((signature_sha != original_signature["sha256"]) == tampered,
           "Signature differs from the selected case operand")
    expected = selection["inputs"] | {"signature": original_signature | {"sha256": signature_sha}}
    verify_boundary(nonce, plan["guest"], case=case, clone=clone)
    W.check_signed_inputs(expected, **O.input_evidence(MEDIA, WORK))
    T.need(time.monotonic() + CLEANUP_SECONDS + 3 < deadline, "Insufficient owned guest time")
    commands = prepare_work()
    run = Runner(runtime_module(), commands, deadline, plan["consumer"])
    baseline = plan["stages"][0]
    key = selection["key"]
    argv = plan["negative_trials"][case]["command"]

    def inventory_at(point):
        queried = W.command(run, f"inventory-{point}", baseline["inventory_query"])["stdout"]
        pin = T.pin(T.sorted_rows(queried))
        T.need(pin == baseline["inventory"], "Signature refusal clone has the wrong Q3 inventory")
        return pin

    def empty_keyring(point):
        listing = W.command(run, f"keyring-{point}", W.KEYRING_LIST)["stdout"]
        W.verify_empty_keyring(listing)

    primary = None
    try:
        inventory_before = inventory_at("before")
        before = retain_database(commands.parent, "before")
        empty_keyring("before")
        if tampered:
            shown = W.command(run, "test-certificate", W.CERTIFICATE_SHOW)["stdout"]
            W.verify_test_certificate(shown, key, now)
            W.command(run, "key-import", W.GPG + ["--import", "--", P.CERT])
            listing = W.command(run, "imported-keyring", W.KEYRING_LIST)["stdout"]
            W.verify_test_certificate(listing, key, now)
            checked = W.command(run, "tampered-signature-gpg", W.SIGNATURE_VERIFY, accepted=(1,))["stdout"]
            W.verify_bad_signature(checked, key)
            W.command(run, "key-trust", W.GPG + ["--import-ownertrust"], data=(key["fingerprint"] + ":6:\n").encode())
        refusal = W.command(run, "signature-refusal", argv, accepted=(1,), timeout=240)
        after = retain_database(commands.parent, "after")
        inventory_after = inventory_at("after")
        if not tampered:
            empty_keyring("after")
        result = dict(clone=clone, scratch=P.Q3_SCRATCH, configuration=T.pin(P.CONFIG.encode()),
                      archive=expected["archive"], signature=expected["signature"], argv=argv,
                      database_before=before, database_after=after,
                      **{name: refusal[name] for name in ("exit_code", "natural", "group_empty", "stderr")})
        W.review_negative(plan, selection, before, {nonce}, case, result)
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            W.command(run, "trust-retirement", W.RETIRE)
        except Exception as error:
            if primary is None:
                raise
            primary.add_note("Owned TEST trust retirement also failed: " + str(error))

    for name in ("database_before", "database_after", "stderr"):
        result[name] = T.pin(result[name])
    result.update(kind="QTBASE16K_INSTALLED_NEGATIVE_RESULT_V1", status="SIGNATURE_REFUSAL_VERIFIED_ONLY",
                  case=case, nonce=nonce, plan_sha256=plan_sha, selection_sha256=selection_sha,
                  inventory_before=inventory_before, inventory_after=inventory_after)
    with (commands.parent / "result.json").open("xb") as output:
        output.write(T.encoded(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-sha256", required=True)
    parser.add_argument("--selection-sha256", required=True)
    parser.add_argument("--deadline-uptime", type=int, required=True)
    parser.add_argument("--protect", action="append")
    parser.add_argument("--case", choices=W.NEGATIVE_CASES)
    parser.add_argument("--clone")
    parser.add_argument("--signature-sha256")
    args = parser.parse_args()

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt("Installed Qtbase guest cancelled")

    signal.signal(signal.SIGTERM, interrupt)
    try:
        remaining = args.deadline_uptime - time.clock_gettime(time.CLOCK_BOOTTIME)
        deadline = time.monotonic() + remaining
        os.umask(0o077)
        plan = T.read(MEDIA / PLAN_FILE, cap=64 << 10)
        selected = T.read(MEDIA / SELECTION_FILE, cap=W.MAX_SELECTION)
        inventory = T.read(MEDIA / INVENTORY_FILE, P.Q3_INVENTORY, cap=16 << 10)
        now = int(time.time())
        if args.case is None:
            T.need(args.clone is None and args.signature_sha256 is None, "Sibling options require a selected case")
            execute(plan, args.plan_sha256, inventory, selected, args.selection_sha256,
                    now=now, deadline=deadline, protected=protected_paths(args.protect or ()))
        else:
            T.need(args.protect is None, "Protected paths belong to the main installed trial")
            execute_negative(plan, args.plan_sha256, inventory, selected, args.selection_sha256,
                             now=now, deadline=deadline, case=args.case, clone=args.clone,
                             signature_sha=args.signature_sha256)
    except (OSError, KeyError, TypeError, ValueError, KeyboardInterrupt):
        sys.exit("Installed Qtbase guest refused or held")


if __name__ == "__main__":
    main()
