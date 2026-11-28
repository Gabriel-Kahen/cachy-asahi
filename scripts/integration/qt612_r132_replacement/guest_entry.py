# SPDX-License-Identifier: MIT
"""Enter the scoped Qt rehearsal at the live Asahi629 rollback checkpoint.

The owning 629 worker calls run_checkpoint after query("rollback"), inside
its target API mount context and before its trust cleanup. The selected boot
plan and code/media pins come from the owning controller. This module has no
standalone entry point and does not start or retire a guest.
"""

import os
from pathlib import Path
import re
import stat
import subprocess
import time


CODE = Path("/trial-code")
LANE = "scripts/integration/qt612_r132_replacement/"
NONCE_ARG = "cachy_overlay583_nonce"
PACKAGE_POLICY = (b"[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\n"
                  b"LocalFileSigLevel = Required TrustedOnly\n")
PROBE_FILE = "runtime-probes.json"
QT_ALARM_NAME = "alarm-public-key.gpg"
ASAHI629_ALARM = dict(bytes=3098, sha256="6ce771e853f04a38a5b533cb33e61f877b9b06b58b6db051eb8a15d737a2332f")
# transaction.py loads prepare.py, whose existing audit helpers resolve paths
# relative to their original source locations. Keep that layout on code media.
SOURCES = frozenset({
    LANE + "guest_entry.py", LANE + "transaction.py", LANE + "runtime_probes.py", LANE + "prepare.py",
    LANE + "weston_fixture.py", LANE + "weston_run.py",
    "scripts/checks/package_checks.py",
    "scripts/ci/platform-namespace-rootfs-v1/elf64le_aarch64.py",
    "scripts/install/overlay583_trial/controller.py",
    "scripts/install/overlay583_trial/trial.py",
    "scripts/integration/fish_config_overlay583/guest.py",
    "scripts/integration/lifecycle.py",
    "scripts/integration/llhttp_overlay583/operands.py",
    "scripts/integration/qt612_base_16k_link_preflight/preflight.py",
    "scripts/integration/qt612_base_16k_link_preflight/readback.py",
    "scripts/integration/qt612_full_16k_preflight/full_capsule.py",
    "scripts/integration/qt612_full_16k_preflight/package_execution.py",
    "scripts/integration/qt612_full_16k_preflight/package_guest.py",
    "scripts/integration/qt612_full_16k_preflight/package_metadata.py",
    "scripts/integration/qt612_gui_16k_link_checkpoint/continuation.py",
    "scripts/integration/qt612_gui_16k_link_checkpoint/gui_capsule.py",
    "scripts/integration/qt612_installed_16k_preflight/package_handoff.py",
    "scripts/integration/qt612_installed_16k_preflight/preflight.py",
    "scripts/integration/qt612_installed_16k_preflight/selection_maps.py",
    "scripts/integration/qt612_installed_16k_preflight/worker.py",
    "scripts/integration/qt612_md4c_compile/actor.py",
    "scripts/integration/qt612_md4c_compile/common.py",
    "scripts/integration/qt612_md4c_compile/prepare.py",
    "scripts/integration/qt612_vulkan_md4c_successor/arm16k_inputs.py",
    "scripts/port/qt612-gui-native-v1/archive.py",
})


def boot_nonce(T, cmdline, expected):
    words = [word for word in cmdline.split() if word.partition("=")[0] == NONCE_ARG]
    T.need(type(expected) is str and re.fullmatch(r"[0-9a-f]{32}", expected)
           and words == [f"{NONCE_ARG}={expected}"], "Qt checkpoint boot nonce differs from the selected guest plan")
    return expected


def environment(T, O, G, selected):
    T.need(os.getuid() == os.geteuid() == 0 and os.uname().machine == "aarch64"
           and os.sysconf("SC_PAGE_SIZE") == 16384 and set(os.listdir("/sys/class/net")) == {"lo"},
           "Expected the owned offline 16 KiB AArch64 629 guest")
    T.need(selected["kind"] == G.BOOT, "Expected the selected Asahi629 guest plan")
    raw = G.bounded(CODE / "plan.json", 512 << 10)
    T.need(raw == T.encoded(selected), "Qt checkpoint plan differs from the boot-selected code media")
    lines = Path("/proc/self/mountinfo").read_text().splitlines()
    G.check_mounts(T, O, lines)
    T.need(len({path.stat().st_dev for path in (Path("/"), O.IN, O.TARGET, O.WORK)}) == 4,
           "Expected separate control, media, clone and temporary trust filesystems")
    mounts = {fields[4]: (set(fields[5].split(",")), fields[fields.index("-") + 1])
              for line in lines if (fields := line.split())}
    T.need(not any(path.startswith(str(root) + "/") for path in mounts for root in (O.IN, CODE)),
           "Qt inputs and source must stay on the read-only media mounts")
    T.need(set(G.target_submounts(O.TARGET)) == {str(O.TARGET / leaf) for leaf in ("dev", "proc", "run", "sys")},
           "Qt checkpoint requires the active Asahi629 target API mounts")
    for leaf, mode, fstype in (("dev", "rw", "tmpfs"), ("proc", "ro", "proc"), ("run", "rw", "tmpfs"),
                                ("sys", "ro", "sysfs")):
        path = O.TARGET / leaf
        T.mount_mode(path, mode, lines)
        options, actual = mounts[str(path)]
        flags = {"nosuid", "noexec"} | ({"nodev"} if leaf != "dev" else set())
        T.need(actual == fstype and flags <= options, "Unexpected target API mount policy: " + leaf)
    G.check_rtc(T, Path("/sys/class/rtc/rtc0"), int(time.time()))
    cmdline = G.bounded(Path("/proc/cmdline"), 16 << 10).decode("ascii")
    return boot_nonce(T, cmdline, selected["nonce"])


def modules(T, G, selected, observed):
    pins = selected["code"]
    T.need(SOURCES <= pins.keys(), "Complete boot-pinned Qt checkpoint source selection required")
    for leaf in sorted(SOURCES):
        T.read(CODE / leaf, pins[leaf], cap=128 << 10, collect=False, observed=observed)
    return tuple(G.pinned_module(CODE / (LANE + leaf), pins[LANE + leaf])
                 for leaf in ("transaction.py", "runtime_probes.py", "weston_fixture.py", "weston_run.py"))


def media(T, O, tx, fixture, weston, selected, observed):
    addon = selected["qt_replacement"]
    p = tx.P
    profile = p["plan_profile"](addon)
    review = tx.checked_review(addon["project_review"])
    wayland = addon["wayland_socket"]
    T.need(wayland is None or wayland == weston.SOCKET, "Expected the exact selected guest Weston socket")
    fixed = p["profile_pins"](profile)
    official, candidate = p["OFFICIAL_NAME"], p["project_name"](profile)
    files = {
        "rollback.lock": fixed["rollback_lock"], "result.json": fixed["rollback_result"],
        official: fixed["official_archive"], official + ".sig": fixed["official_signature"],
        candidate: fixed["project_archive"], candidate + ".sig": review["signature"],
        "test-certificate.gpg": review["certificate"], QT_ALARM_NAME: fixed["alarm_public_key"],
    }
    if wayland is not None:
        files.update({fixture.ARCHIVE: fixture.PINS["archive"], fixture.ARCHIVE + ".sig": fixture.PINS["signature"]})
    folder = O.IN / "qt-replacement"
    T.need(T.ordinary(folder).is_dir() and folder.stat().st_dev == O.IN.stat().st_dev
           and {path.name for path in folder.iterdir()} == files.keys(), "Exact Qt read-only media members required")
    for name, expected in files.items():
        T.read(folder / name, expected, cap=expected["bytes"], collect=False, observed=observed)
    manifest = selected["media"]
    alarm = manifest["keys"]["alarm"]
    T.need(alarm["scope"] == "vendor" and alarm["fingerprint"] == tx.A["FINGERPRINT"]
           and manifest["files"][alarm["file"]] == ASAHI629_ALARM and ASAHI629_ALARM != fixed["alarm_public_key"],
           "Asahi629 must carry its distinct original ALARM public certificate")
    T.read(O.IN / O.relative(T, alarm["file"]), ASAHI629_ALARM, cap=64 << 10,
           collect=False, observed=observed)
    qt_key = T.read(folder / QT_ALARM_NAME, fixed["alarm_public_key"], cap=64 << 10, observed=observed)
    p["verify_official"]({"official_archive": folder / official, "official_signature": folder / (official + ".sig")}, qt_key)
    return folder, review, wayland


def path_absent(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return True
    return False


def private_homes(T, O, G):
    homes = G.trust_homes(O)
    T.need(homes == {"vendor": O.WORK / "verify-vendor", "project-test": O.WORK / "verify-project-test",
                     "pacman": O.WORK / "trust"}, "Unexpected Qt verification or ALPM keyring paths")
    work_dev = O.WORK.stat().st_dev
    for home in homes.values():
        info = T.ordinary(home).lstat()
        T.need(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) == (0, 0)
               and stat.S_IMODE(info.st_mode) == 0o700 and info.st_dev == work_dev,
               "Expected private root-owned temporary keyring: " + home.name)
        T.need(all(path_absent(home / name) for name in ("gpg.conf", "gpg-agent.conf", "common.conf")),
               "Private Qt keyring contains unexpected GnuPG configuration")
        secrets = home / "private-keys-v1.d"
        if not path_absent(secrets):
            T.need(T.ordinary(secrets).is_dir() and not any(secrets.iterdir()), "Unexpected private key material")
    return homes


def call_gpg(T, home, *args, data=None):
    command = ["/usr/bin/gpg", "--batch", "--no-options", "--no-auto-key-retrieve", "--homedir", str(home), *args]
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}
    input_args = {"stdin": subprocess.DEVNULL} if data is None else {"input": data}
    run = subprocess.run(command, env=env, capture_output=True, timeout=30, **input_args)
    T.need(run.returncode == 0 and len(run.stdout) <= 128 << 10 and len(run.stderr) <= 128 << 10,
           f"Qt private keyring command failed: {home.name} {args[-1]}")
    return run.stdout


def check_keyrings(T, G, homes, keys, *, candidate=None):
    for role, home in homes.items():
        listing = call_gpg(T, home, "--with-colons", "--fingerprint", "--list-keys")
        expected = {key["fingerprint"] for key in keys.values() if role == "pacman" or key["scope"] == role}
        if candidate is not None and role != "vendor":
            actual = G.key_listing(T, listing)
            qt = candidate["fingerprint"]
            T.need(set(actual) == expected | {qt} and actual[qt] == {
                name: candidate[name] for name in ("not_before", "not_after")},
                "Selected Qt TEST certificate differs in " + role + " keyring")
            preview = keys["preview-test"]
            T.need(actual[preview["fingerprint"]] == {name: preview[name] for name in ("not_before", "not_after")},
                   "Original 629 TEST certificate changed in " + role + " keyring")
            expected.add(qt)
        else:
            G.verify_key_listing(T, keys, role, listing)
        G.public_only(T, call_gpg(T, home, "--with-colons", "--list-secret-keys"))
        trust = call_gpg(T, home, "--export-ownertrust")
        actual_trust = sorted(row for row in trust.splitlines() if row and not row.startswith(b"#"))
        wanted = [f"{fpr}:6:".encode("ascii") for fpr in sorted(expected)] if role == "pacman" else []
        T.need(actual_trust == wanted, "Unexpected ownertrust in the private " + role + " keyring")


def select_trust(T, O, G, tx, manifest, folder, review, *, profile=None):
    p = tx.P
    p["choose_review"](profile, review)
    candidate = folder / p["project_name"](profile)
    keys = manifest["keys"]
    fingerprint = review["fingerprint"]
    T.need(fingerprint not in O.HISTORICAL_TEST | {key["fingerprint"] for key in keys.values()},
           "Qt TEST key must be separate from previous project and vendor roles")
    config = T.read(O.WORK / "pacman.conf", cap=4096)
    T.need(config == PACKAGE_POLICY, "Exact Required TrustedOnly pacman policy required")
    homes = private_homes(T, O, G)
    check_keyrings(T, G, homes, keys)
    _, body = tx.certificate(folder / "test-certificate.gpg", review, homes["project-test"])
    call_gpg(T, homes["project-test"], "--import", data=body)
    signature_input = dict(archive=p["profile_pins"](profile)["project_archive"],
                           signature=review["signature"], fingerprint=fingerprint)
    _, status = tx.signature(candidate, tx.PROJECT, signature_input, homes["project-test"])
    G.test_signature(T, status, review, int(time.time()))
    call_gpg(T, homes["pacman"], "--import", data=body)
    call_gpg(T, homes["pacman"], "--import-ownertrust", data=f"{fingerprint}:6:\n".encode("ascii"))
    check_keyrings(T, G, homes, keys, candidate=review)


def probe_evidence(T, R, path, socket, *, nonce, passed, restored=False, expected_status=None):
    if path_absent(path):
        T.need(not passed, "Successful Qt transaction lacks its runtime probe report")
        T.need(expected_status is None, "Completed Qt probe lacks its runtime probe report")
        return None
    body = T.read(path, cap=2 << 20)
    report = T.decode(body)
    T.need(T.encoded(report) == body and report["kind"] == R.KIND and report["wayland_socket"] == socket
           and report["nonce"] == nonce and report.get("phase") == ("restoration" if restored else None)
           and report["uid"] == report["gid"] == R.USER and report["vulkan_icd"] == R.LAVAPIPE
           and set(report["checks"]) == set(R.PHASES), "Runtime probe evidence differs from the selected Qt scope")
    outcomes = {row["status"] for row in report["checks"].values()}
    T.need(outcomes <= {"PASS", "FAIL", "SKIP"}
           and report["status"] == ("FAIL" if "FAIL" in outcomes else "PARTIAL" if "SKIP" in outcomes else "PASS")
           and (expected_status is None or report["status"] == expected_status)
           and (not passed or outcomes == {"PASS"}), "Qt runtime coverage differs from the transaction outcome")
    T.need(socket is not None or all(report["checks"][name]["status"] == "SKIP" for name in ("wayland", "vulkan_qrhi")),
           "Unselected Wayland compositor cannot yield a Wayland or QRhi probe result")
    for name in ("wayland", "vulkan_qrhi"):
        check = report["checks"][name]
        if check["status"] == "PASS":
            process = check["process"]
            T.need(set(process) == {"pid", "start_ticks"} and all(type(value) is int and value > 0 for value in process.values()),
                   "Completed Qt Wayland observation requires the supervising launcher process identity")
    return T.pin(body)


def run_checkpoint(T, O, G, selected):
    """Return nonce, Qt transaction result and runtime report pin to the owner.

    The 629 runner owns the outer authority, mounts and all three keyrings.
    It retires them on every outcome. This checkpoint stages, starts and
    retires Weston while those target API mounts stay active.
    """
    nonce = environment(T, O, G, selected)
    observed = {}
    tx, runtime, fixture, weston = modules(T, G, selected, observed)
    folder, review, socket = media(T, O, tx, fixture, weston, selected, observed)
    profile = tx.P["plan_profile"](selected["qt_replacement"])
    retained = T.decode(T.read(folder / "result.json", tx.P["PINS"]["rollback_result"], cap=64 << 10,
                               observed=observed))
    tx.checked_nonce(nonce, retained["nonce"])
    T.read(O.WORK / "evidence/rollback.lock", tx.P["PINS"]["rollback_lock"], cap=64 << 10)

    def platform():
        return T.encoded(G.base.platform(T, O.TARGET))

    T.need(T.pin(platform()) == retained["platform"]["rollback"], "Qt entry requires the exact protected 629 checkpoint")
    select_trust(T, O, G, tx, selected["media"], folder, review, profile=profile)
    evidence_dir = O.WORK / "qt-replacement-evidence"
    report_path = evidence_dir / PROBE_FILE
    vendor_report = O.WORK / runtime.VENDOR_REPORT

    def transact(compositor):
        def restored_probe():
            failure = None
            try:
                runtime.run(nonce=nonce, wayland_socket=socket, weston=compositor, phase="restoration")
            except runtime.RestoredCoverageError as error:
                failure = error
            report = probe_evidence(T, runtime, evidence_dir / runtime.RESTORED_REPORT, socket, nonce=nonce,
                                    passed=failure is None, restored=True,
                                    expected_status=failure.status if failure is not None else None)
            return report, failure

        parity = {"profile": profile, "restored_probe": restored_probe} if profile is not None else {}
        return tx.run(project_review=review,
                      probe=lambda: runtime.run(nonce=nonce, wayland_socket=socket, weston=compositor),
                      platform=platform, nonce=nonce, **parity)

    mask = os.umask(0o077)
    try:
        if socket is None:
            result = transact(None)
        else:
            T.need(path_absent(vendor_report), "Expected fresh vendor Qt runtime evidence")

            def stage_fixture(destination):
                return fixture.stage(archive=folder / fixture.ARCHIVE, signature=folder / (fixture.ARCHIVE + ".sig"),
                                     public_key=folder / QT_ALARM_NAME, destination=destination)

            try:
                parity = {"parity": True} if profile is not None else {}
                with weston.supervise(nonce=nonce, stage_fixture=stage_fixture, **parity) as compositor:
                    T.need(compositor.socket == socket, "Owned Weston must serve the selected socket")
                    runtime.run(nonce=nonce, wayland_socket=socket, weston=compositor, phase="vendor")
                    probe_evidence(T, runtime, vendor_report, socket, nonce=nonce, passed=True)
                    result = transact(compositor)
            finally:
                try:
                    if not path_absent(vendor_report):
                        os.link(vendor_report, evidence_dir / runtime.VENDOR_REPORT, follow_symlinks=False)
                        vendor_report.unlink()
                except OSError as error:
                    raise ValueError("Qt checkpoint HOLD_DISCARD: vendor runtime evidence custody could not be verified") from error
    finally:
        os.umask(mask)
        T.unchanged(observed)
    evidence = probe_evidence(T, runtime, report_path, socket, nonce=nonce, passed=result["status"] == tx.PASS)
    return dict(nonce=nonce, transaction=result, runtime_probe=evidence)
