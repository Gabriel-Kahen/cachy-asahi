# SPDX-License-Identifier: MIT
"""Run the exact 629-package rehearsal in the private offline Asahi clone."""

from base64 import b64decode, b64encode
from contextlib import ExitStack
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
GUEST_CODE = Path("/trial-code")
BASE_NAME = "asahi-guest-base.py"
BASE_PIN = dict(bytes=16922, sha256="2df92fc3d1eadea719b45a7bd4a21dbb3ae414ae2e0f32ae6845e310fe1ac78b")
BOOT = "ASAHI629_EXACT_GUEST_PLAN_V1"
PASS = "PASS_DISPOSABLE_ASAHI_629_THREE_VERSION_REVERSE"
HOLD = "HOLD_DISPOSABLE_ASAHI_629_MAINTENANCE"
FINGERPRINT = re.compile(r"[A-F0-9]{40}")
EPOCH = re.compile(r"[0-9]{1,12}")


def bounded(path, limit):
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if not 0 < len(raw) <= limit:
        raise ValueError("Invalid guest code or plan length: " + path.name)
    return raw


def pinned_module(path, reference):
    raw = bounded(path, 128 * 1024)
    if dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest()) != reference:
        raise ValueError("Guest dependency differs: " + path.name)
    spec = importlib.util.spec_from_file_location("asahi629_" + path.stem, path)
    loaded = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), "exec"), loaded.__dict__)
    return loaded


base_path = HERE / BASE_NAME if HERE == GUEST_CODE else HERE.parent / "asahi_maintenance_trial/guest.py"
base = pinned_module(base_path, BASE_PIN)
SHOW = base.SHOW
TIMEOUT = base.TIMEOUT
NAMES = base.NAMES | {"trust.json", "cleanup.json", "platform-state.json"}
INITRAMFS = base.INITRAMFS
INITRAMFS_PIN = base.INITRAMFS_PIN
INITRAMFS_OWNER = base.INITRAMFS_OWNER
INITRAMFS_LIMIT = base.INITRAMFS_LIMIT
GENERATED = base.GENERATED
evidence_limit = base.evidence_limit
regeneration = base.regeneration
signature = base.signature
command_plan = base.command_plan
log_actions = base.log_actions


def trust_homes(O):
    return {
        "vendor": O.WORK / "verify-vendor",
        "project-test": O.WORK / "verify-project-test",
        "pacman": O.WORK / "trust",
    }


def trust_commands(O, manifest):
    keys = manifest["keys"]
    homes = trust_homes(O)
    groups = {
        "vendor": sorted(name for name in keys if keys[name]["scope"] == "vendor"),
        "project-test": ["preview-test"],
        "pacman": sorted(keys),
    }

    def gpg(scope):
        return ["/usr/bin/gpg", "--batch", "--no-options", "--no-auto-key-retrieve", "--homedir", str(homes[scope])]

    def inspection(scope):
        return {
            **{f"import-{scope}-{name}": [*gpg(scope), "--import"] for name in groups[scope]},
            f"keys-{scope}": [*gpg(scope), "--with-colons", "--fingerprint", "--list-keys"],
            f"secrets-{scope}": [*gpg(scope), "--with-colons", "--list-secret-keys"],
        }

    verification = {}
    for phase in SHOW[1:]:
        for name, row in sorted(manifest["packages"][phase].items()):
            archive = str(O.IN / row["archive"])
            verification["verify-" + phase + "-" + name] = [
                *gpg(row["scope"]), "--status-fd", "1", "--verify", archive + ".sig", archive,
            ]
    return {
        **inspection("vendor"),
        **inspection("project-test"),
        **verification,
        **inspection("pacman"),
        "set-ownertrust": [*gpg("pacman"), "--import-ownertrust"],
    }


def key_listing(T, raw):
    """Parse GnuPG's public primary rows and each matching fingerprint."""
    primary = {}
    pending = None
    for line in raw.decode("utf-8").splitlines():
        cells = line.split(":")
        tag = cells[0]
        if tag == "pub":
            T.need(pending is None and len(cells) >= 12 and cells[1] not in {"e", "r", "d", "i"}
                   and EPOCH.fullmatch(cells[5]) and (not cells[6] or EPOCH.fullmatch(cells[6])),
                   "Unusable or malformed selected public primary")
            pending = (cells[4], int(cells[5]), int(cells[6] or 0))
        elif pending is not None:
            T.need(tag == "fpr" and len(cells) >= 10 and FINGERPRINT.fullmatch(cells[9])
                   and cells[9][-16:] == pending[0] and cells[9] not in primary,
                   "Public primary lacks one exact fingerprint")
            primary[cells[9]] = dict(not_before=pending[1], not_after=pending[2])
            pending = None
    T.need(pending is None and bool(primary), "Incomplete public-key listing")
    return primary


def verify_key_listing(T, keys, scope, raw):
    primary = key_listing(T, raw)
    pins = {row["fingerprint"] for row in keys.values() if scope == "pacman" or row["scope"] == scope}
    T.need(set(primary) == pins, "Wrong keys in " + scope + " keyring")
    test = keys["preview-test"]
    if scope != "vendor":
        T.need(primary[test["fingerprint"]] == {name: test[name] for name in ("not_before", "not_after")},
               "Selected TEST public certificate lifetime differs")
    return primary


def public_only(T, raw):
    T.need(all(line.startswith(b"tru:") for line in raw.splitlines()),
           "The disposable keyring must contain only public certificates")


def current_test(T, key, now, *, remaining=0):
    T.need(type(now) is int and key["not_before"] <= now < key["not_after"] - remaining,
           "Reviewed 629 TEST certificate must be current for the selected window")


def test_signature(T, raw, key, observed_at):
    current_test(T, key, observed_at)
    observed = signature(T, raw, key["fingerprint"])
    valid, = [row.split() for row in raw.decode("utf-8").splitlines() if row.startswith("[GNUPG:] VALIDSIG ")]
    T.need(FINGERPRINT.fullmatch(valid[2]) and EPOCH.fullmatch(valid[4]) and EPOCH.fullmatch(valid[5])
           and key["not_before"] <= int(valid[4]) <= observed_at
           and (int(valid[5]) == 0 or observed_at < int(valid[5])),
           "TEST detached signature is outside its reviewed certificate window")
    return observed


def review_extra(T, O, output, plan, result, seen, *, held):
    """Read back scoped verification, protected state and cleanup evidence."""
    trust = T.decode(T.read(output / "trust.json", result["trust"], cap=128 * 1024))
    cleanup = T.decode(T.read(output / "cleanup.json", result["cleanup"], cap=16 * 1024))
    platform = T.decode(T.read(output / "platform-state.json", result["platform_state"], cap=2 * 1024**2))
    T.need(set(trust) == {"time", "public"} and set(cleanup) == {"target_submounts", "keyrings", "completed"},
           "Exact scoped trust and cleanup receipts required")
    T.need({label: T.pin(T.encoded(snapshot)) for label, snapshot in platform.items()} == result["platform"],
           "Protected boot and mount-configuration snapshot digest differs")
    commands = trust_commands(O, plan["media"])
    order = ["query-baseline", "check-baseline", *commands]
    for stage in SHOW[1:]:
        order.extend(verb + "-" + stage for verb in ("preview", "apply", "query", "check"))
    actual = list(seen)
    T.need(actual == order[:len(actual)] and (held or actual == order),
           "Scoped trust and transaction commands must follow the exact sequence")
    if held:
        return

    T.need(set(platform) == set(SHOW) and platform["baseline"] == platform["forward"] == platform["rollback"]
           and {"boot", "etc/fstab", "etc/crypttab"} <= set(platform["baseline"]),
           "Boot and mount configuration must survive both transactions")
    T.need(cleanup == dict(target_submounts=[], keyrings={scope: "removed" for scope in trust_homes(O)}, completed=True),
           "All disposable keyrings and target API mounts must retire")
    marker_order = ("entry", "verified", "forward", "rollback", "seal")
    T.need(set(trust["time"]) == set(marker_order) and set(trust["public"]) == set(trust_homes(O)),
           "Complete scoped TEST verification chronology required")
    times = [trust["time"][label] for label in marker_order]
    keys = plan["media"]["keys"]
    key = keys["preview-test"]
    for now in times:
        current_test(T, key, now)
    current_test(T, key, times[0], remaining=TIMEOUT)
    T.need(times == sorted(times), "TEST verification times are reordered")

    for role, argv in commands.items():
        T.need(seen[role]["argv"] == argv and seen[role]["exit"] == 0,
               "Changed scoped trust command: " + role)
    for scope, receipt in trust["public"].items():
        listing = b64decode(receipt["keys"], validate=True)
        secrets = b64decode(receipt["secrets"], validate=True)
        T.need(set(receipt) == {"keys", "secrets"} and T.pin(listing) == seen["keys-" + scope]["stdout"]
               and T.pin(secrets) == seen["secrets-" + scope]["stdout"], "Scoped GPG listing evidence drifted")
        verify_key_listing(T, keys, scope, listing)
        public_only(T, secrets)
    signatures = T.decode(T.read(output / "signatures.json", cap=512 * 1024))
    for name, row in plan["media"]["packages"]["forward"].items():
        if row["scope"] == "project-test":
            raw = b64decode(signatures["forward"][name]["original"], validate=True)
            test_signature(T, raw, key, trust["time"]["verified"])


def target_submounts(target):
    rows = Path("/proc/self/mountinfo").read_text().splitlines()
    return sorted(row.split()[4] for row in rows if row.split()[4].startswith(str(target) + "/"))


def check_mounts(T, O, lines):
    selections = (
        (Path("/"), "ro", "ext4", set()),
        (GUEST_CODE, "ro", "ext4", {"nosuid", "nodev", "noexec"}),
        (O.IN, "ro", "ext4", {"nosuid", "nodev", "noexec"}),
        (O.TARGET, "rw", "ext4", {"nosuid", "nodev"}),
        (O.WORK, "rw", "tmpfs", {"nosuid", "nodev", "noexec"}),
    )
    for path, mode, fstype, options in selections:
        T.mount_mode(path, mode, lines)
        row = next(fields for line in lines if (fields := line.split())[4] == str(path))
        T.need(row[row.index("-") + 1] == fstype and options <= set(row[5].split(",")),
               "Unexpected isolated guest filesystem or mount flags: " + str(path))


def execute(T, O, selected):
    manifest = selected["media"]
    evidence = O.WORK / "evidence"
    evidence.mkdir(mode=0o700)
    homes = trust_homes(O)
    trust = dict(time={}, public={})
    config = O.WORK / "pacman.conf"
    env = {"PATH": "/usr/bin:/bin", "HOME": str(O.WORK), "LC_ALL": "C", "TZ": "UTC"}
    steps, signatures, inventory, previews, system, snapshots, observed = [], {}, {}, {}, {}, {}, {}
    artifacts = dict(path=INITRAMFS.as_posix(), baseline=None, phases={})
    phase = "rehash"
    deadline = time.monotonic() + TIMEOUT - 90
    final = HOLD
    commands = command_plan(O, manifest)
    gpg_commands = trust_commands(O, manifest)
    test = manifest["keys"]["preview-test"]

    def mark(role, *, remaining=0):
        now = int(time.time())
        current_test(T, test, now, remaining=remaining)
        if trust["time"]:
            T.need(now >= max(trust["time"].values()), "Guest clock moved backward during TEST verification")
        trust["time"][role] = now
        return now

    def call(role, argv, seconds, data=None):
        nonlocal phase
        phase = role
        remaining = deadline - time.monotonic()
        T.need(remaining > 0, "Guest transaction deadline exhausted")
        out_path = O.WORK / (role + ".stdout")
        err_path = O.WORK / (role + ".stderr")
        with out_path.open("xb") as stdout, err_path.open("xb") as stderr:
            with subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL if data is None else subprocess.PIPE,
                                  stdout=stdout, stderr=stderr, start_new_session=True) as process:
                try:
                    process.communicate(input=data, timeout=min(seconds, remaining))
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    raise
        out = T.read(out_path, cap=2 * 1024**2)
        err = T.read(err_path, cap=2 * 1024**2)
        steps.append(dict(role=role, argv=argv, exit=process.returncode, stdout=T.pin(out), stderr=T.pin(err)))
        if role in ("apply-forward", "apply-rollback"):
            (evidence / out_path.name).write_bytes(out)
            (evidence / err_path.name).write_bytes(err)
            T.need(not T.HOOK_FAILURE.search(out) and not T.HOOK_FAILURE.search(err),
                   "Pacman reported a failed hook or scriptlet")
        T.need(process.returncode == 0, "Selected guest command failed: " + role)
        return out

    def verify_all():
        roles = {f"verify-{stage}-{name}": (stage, name, row)
                 for stage in SHOW[1:] for name, row in manifest["packages"][stage].items()}
        stable = {}
        for role, argv in gpg_commands.items():
            data = None
            if role.startswith("import-"):
                name = next(name for name in manifest["keys"] if role.endswith("-" + name))
                leaf = manifest["keys"][name]["file"]
                data = T.read(O.IN / leaf, manifest["files"][leaf], cap=64 * 1024, observed=observed)
            elif role == "set-ownertrust":
                data = "".join(fpr + ":6:\n" for fpr in sorted(stable["pacman"])).encode("ascii")
            out = call(role, argv, 20 if role in roles else 30, data)
            if role.startswith("keys-"):
                scope = role.removeprefix("keys-")
                stable[scope] = verify_key_listing(T, manifest["keys"], scope, out)
                trust["public"][scope] = dict(keys=b64encode(out).decode("ascii"))
            elif role.startswith("secrets-"):
                scope = role.removeprefix("secrets-")
                public_only(T, out)
                trust["public"][scope]["secrets"] = b64encode(out).decode("ascii")
            elif role in roles:
                stage, name, row = roles[role]
                seen = (test_signature(T, out, test, int(time.time())) if row["scope"] == "project-test"
                        else signature(T, out, row["signer"]))
                signatures.setdefault(stage, {})[name] = dict(seen, scope=row["scope"],
                                                               original=b64encode(out).decode("ascii"))

    def query(label):
        lock_name = label + ".lock"
        expected = T.read(O.IN / lock_name, O.lock_ref(lock_name), cap=64 * 1024, observed=observed)
        data = T.sorted_rows(call("query-" + label, commands["query-" + label], 60))
        T.need(data == expected, "Complete installed inventory differs: " + label)
        (evidence / lock_name).write_bytes(data)
        inventory[label] = T.pin(data)
        call("check-" + label, commands["check-" + label], 60)
        snapshots[label] = base.platform(T, O.TARGET)
        system[label] = T.pin(T.encoded(snapshots[label]))
        T.need(snapshots[label] == snapshots["baseline"], "Asahi boot and mount configuration changed in the copy")

    try:
        O.rehash(T, O.IN, manifest, observed=observed)
        mark("entry", remaining=TIMEOUT)
        T.need(not target_submounts(O.TARGET), "Target API mounts must start empty")
        free = os.statvfs(O.TARGET)
        T.need(free.f_bavail * free.f_frsize >= 8 * 1024**3, "Target clone must be expanded before package changes")
        for directory in (*homes.values(), O.WORK / "cache"):
            directory.mkdir(mode=0o700)
        config.write_text("[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\n"
                          "LocalFileSigLevel = Required TrustedOnly\n")
        with ExitStack() as mounts:
            phase = "target-api-mounts"
            T.target_api_mounts(O.TARGET, env, mounts)
            phase = "preserve-baseline"
            initramfs_path = O.TARGET / INITRAMFS
            original, origin, atime = base.initramfs(T, initramfs_path, INITRAMFS_PIN)
            artifacts["baseline"] = origin
            query("baseline")
            verify_all()
            mark("verified")
            for stage in SHOW[1:]:
                preview = stage + "-preview.lock"
                reference = T.read(O.IN / preview, O.lock_ref(preview), cap=64 * 1024, observed=observed)
                actual = T.sorted_rows(call("preview-" + stage, commands["preview-" + stage], 180))
                T.need(actual == reference, "Local package preview differs: " + stage)
                (evidence / preview).write_bytes(actual)
                previews[stage] = T.pin(actual)
                phase = "trust-before-" + stage
                mark(stage)
                stdout = call("apply-" + stage, commands["apply-" + stage], 2400 if stage == "forward" else 420)
                phase = "preserve-" + stage
                base.preserve_initramfs(T, initramfs_path, original, origin, atime, evidence, artifacts["phases"],
                                        stage, stdout)
                query(stage)
        phase = "seal"
        T.unchanged(observed)
        rows = O.locks(T, O.IN)
        O.check_delta(T, rows)
        log_actions(T, rows["baseline.lock"], rows["forward.lock"], rows["rollback.lock"],
                    T.read(evidence / "pacman.log", cap=2 * 1024**2), completed=True)
        mark("seal")
        final = PASS
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Asahi 629 rehearsal HOLD {phase}: {error}", file=sys.stderr, flush=True)
    finally:
        cleanup = dict(target_submounts=None, keyrings={}, completed=False)
        for scope, home in homes.items():
            try:
                if home.exists():
                    subprocess.run(["/usr/bin/gpgconf", "--homedir", str(home), "--kill", "all"], env=env,
                                   stdin=subprocess.DEVNULL, timeout=20, check=True)
                    shutil.rmtree(home)
                T.need(not home.exists(), "Disposable keyring still present")
                cleanup["keyrings"][scope] = "removed"
            except (OSError, ValueError, subprocess.SubprocessError):
                cleanup["keyrings"][scope] = "failed"
        try:
            cleanup["target_submounts"] = target_submounts(O.TARGET)
        except OSError:
            pass
        cleanup["completed"] = (cleanup["target_submounts"] == []
                                and set(cleanup["keyrings"].values()) == {"removed"})
        if not cleanup["completed"] and final == PASS:
            phase, final = "cleanup", HOLD
    extra = dict(trust=trust, cleanup=cleanup, platform_state=snapshots)
    leaves = {"commands": steps, "platform": system, "boot-artifacts": artifacts, "signatures": signatures,
              **{name.replace("_", "-"): value for name, value in extra.items()}}
    for name, value in leaves.items():
        (evidence / (name + ".json")).write_bytes(T.encoded(value))
    result = dict(status=final, phase=None if final == PASS else phase, nonce=selected["nonce"],
                  plan=T.pin(T.encoded(selected)), approval_status="UNAPPROVED", Root_acceptance=None,
                  inventory=inventory, previews=previews, platform=system, boot_artifacts=T.pin(T.encoded(artifacts)),
                  M2="NOT RUN", physical_installation="NOT RUN",
                  **{name: T.pin(T.encoded(value)) for name, value in extra.items()})
    (evidence / "result.json").write_bytes(T.encoded(result))
    return 0 if final == PASS else 75


def boot(plan_sha, worker_sha):
    if (os.getuid() != os.geteuid() or os.getuid() != 0 or os.uname().machine != "aarch64"
            or os.sysconf("SC_PAGE_SIZE") != 16384
            or {p.name for p in Path("/sys/class/net").iterdir()} != {"lo"}):
        raise ValueError("Exact offline aarch64 16 KiB control guest required")
    raw = bounded(GUEST_CODE / "plan.json", 512 * 1024)
    if (hashlib.sha256(raw).hexdigest() != plan_sha
            or hashlib.sha256(bounded(Path(__file__), 128 * 1024)).hexdigest() != worker_sha):
        raise ValueError("Asahi 629 guest pack must match the held plan and worker")
    code = json.loads(raw)["code"]
    T = pinned_module(GUEST_CODE / "trial.py", code["trial.py"])
    O = pinned_module(GUEST_CODE / "operands.py", code["operands.py"])
    plan = T.decode(raw)
    T.need(raw == T.encoded(plan) and plan["kind"] == BOOT and code[BASE_NAME] == BASE_PIN
           and code["asahi-guest.py"]["sha256"] == worker_sha
           and re.fullmatch(r"[a-f0-9]{32}", plan["nonce"])
           and Path("/proc/cmdline").read_text().split().count("cachy_overlay583_nonce=" + plan["nonce"]) == 1,
           "Exact nonce and separate Asahi 629 worker profile required")
    check_mounts(T, O, Path("/proc/self/mountinfo").read_text().splitlines())
    T.need(len({path.stat().st_dev for path in (Path("/"), O.IN, O.TARGET, O.WORK)}) == 4
           and not any(O.WORK.iterdir()), "Control, media, clone and fresh temporary trust must be separate")
    manifest = T.read(O.IN / "manifest.json", plan["manifest"], cap=512 * 1024)
    T.need(manifest == T.encoded(plan["media"]), "Reviewed 629 media and guest plan disagree")
    return execute(T, O, plan)


if __name__ == "__main__":
    raise SystemExit(boot(*sys.argv[1:]))
