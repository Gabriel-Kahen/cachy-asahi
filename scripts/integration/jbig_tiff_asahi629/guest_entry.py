# SPDX-License-Identifier: MIT
"""Run the pair from the boot-selected Asahi629 rollback checkpoint."""

import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

CODE = Path("/trial-code/jbig-tiff")
SCOPE = "jbig-tiff/"
CERTIFICATE = "test-certificate.gpg"
SOURCES = frozenset({"inputs.py", "transaction.py", "runtime.py", "consumer_probe.c", "tiff-jbig-roundtrip.c"})
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}
POLICY = b"[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\nLocalFileSigLevel = Required TrustedOnly\n"
ALPM_ACTION = re.compile(r"\[ALPM\] (installed|removed|upgraded|reinstalled|downgraded) ([^ ]+) \(([^)]+)\)$")


def review_shape(T, data, project):
    T.need(type(data) is dict and data.keys() == {"certificate", "fingerprint", "not_before", "not_after", "signatures"}
           and type(data["fingerprint"]) is str and re.fullmatch(r"[A-F0-9]{40}", data["fingerprint"])
           and type(data["not_before"]) is type(data["not_after"]) is int and 0 < data["not_before"] < data["not_after"]
           and type(data["signatures"]) is dict and data["signatures"].keys() == project.keys(),
           "Exact library TEST certificate and two detached signature pins required")
    for pin in [data["certificate"], *data["signatures"].values()]:
        T.need(type(pin) is dict and pin.keys() == {"bytes", "sha256"} and type(pin["bytes"]) is int
               and 0 < pin["bytes"] <= 64 << 10 and type(pin["sha256"]) is str and re.fullmatch(r"[a-f0-9]{64}", pin["sha256"]),
               "Invalid scoped certificate or signature pin")
    return data


def media_pins(I, review):
    fixed = {CERTIFICATE: review["certificate"]}
    for name, row in I.PROVIDERS.items():
        leaf = row["filename"]
        fixed[leaf] = row["archive"]
        fixed[leaf + ".sig"] = row["signature"] if name in I.OFFICIAL else review["signatures"][name]
    return {SCOPE + leaf: pin for leaf, pin in fixed.items()}


def call(argv, *, data=None, seconds=40):
    inputs = dict(stdin=subprocess.DEVNULL) if data is None else dict(input=data)
    result = subprocess.run(argv, env=ENV, timeout=seconds, capture_output=True, **inputs)
    if result.returncode or len(result.stdout) > 128 << 10 or len(result.stderr) > 128 << 10:
        raise ValueError(f"Guest command failed (exit {result.returncode}): {argv[0]}")
    return result.stdout


def gpg(home, *args, data=None):
    return call(["/usr/bin/gpg", "--batch", "--no-options", "--no-auto-key-retrieve", "--homedir",
                 str(home), *args], data=data)


def authenticate(T, O, G, selected, I, review, paths):
    homes = G.trust_homes(O)
    keys = selected["media"]["keys"]
    fpr = review["fingerprint"]
    T.need(fpr not in O.HISTORICAL_TEST | {row["fingerprint"] for row in keys.values()}
           and keys["alarm"]["fingerprint"] == I.ALARM_FINGERPRINT
           and T.read(O.WORK / "pacman.conf", cap=4096) == POLICY, "Distinct library TEST key and Required TrustedOnly required")
    for role, home in homes.items():
        info = T.ordinary(home).lstat()
        T.need(stat.S_ISDIR(info.st_mode) and info.st_dev == O.WORK.stat().st_dev
               and (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (0, 0, 0o700)
               and all(not os.path.lexists(home / name) for name in ("gpg.conf", "gpg-agent.conf", "common.conf")),
               "Expected scoped disposable trust home: " + role)
        G.verify_key_listing(T, keys, role, gpg(home, "--with-colons", "--fingerprint", "--list-keys"))
        G.public_only(T, gpg(home, "--with-colons", "--list-secret-keys"))
    certificate = T.read(O.IN / SCOPE / CERTIFICATE, review["certificate"], cap=64 << 10)
    for role in ("project-test", "pacman"):
        home = homes[role]
        # Parse the selected body in isolation before importing it into an existing home.
        raw = gpg(home, "--with-colons", "--fingerprint", "--import-options", "show-only", "--dry-run",
                  "--import", data=certificate)
        window = {key: review[key] for key in ("not_before", "not_after")}
        T.need(G.key_listing(T, raw) == {fpr: window}
               and not any(row.startswith((b"sec:", b"ssb:")) for row in raw.splitlines()),
               "Expected exactly one public TEST primary and its reviewed lifetime")
        gpg(home, "--import", data=certificate)
        actual = G.key_listing(T, gpg(home, "--with-colons", "--fingerprint", "--list-keys"))
        enrolled = {key["fingerprint"] for key in keys.values() if role == "pacman" or key["scope"] == role}
        T.need(set(actual) == enrolled | {fpr} and actual[fpr] == window, "Unexpected TEST trust enrollment")
        G.public_only(T, gpg(home, "--with-colons", "--list-secret-keys"))
    gpg(homes["pacman"], "--import-ownertrust", data=(fpr + ":6:\n").encode("ascii"))
    expected_ownertrust = sorted(row["fingerprint"] + ":6:" for row in keys.values()) + [fpr + ":6:"]
    ownertrust = gpg(homes["pacman"], "--export-ownertrust").decode("ascii").splitlines()
    T.need(sorted(line for line in ownertrust if line and not line.startswith("#")) == sorted(expected_ownertrust),
           "Unexpected libalpm trust roots")
    signatures = {}
    for name, path in paths.items():
        project = name in I.PROJECT
        raw = gpg(homes["project-test" if project else "vendor"], "--status-fd", "1", "--verify", "--",
                  str(path) + ".sig", str(path))
        now = int(time.time())
        proof = (G.test_signature(T, raw, review, now) if project else G.signature(T, raw, I.ALARM_FINGERPRINT))
        signatures[name] = dict(proof=proof, status=raw.decode("utf-8"), observed_at=now)
    return dict(policy="Required TrustedOnly", fingerprint=fpr, signatures=signatures)


def absent(T, path):
    T.need(not os.path.lexists(path), "Unexpected package path remains: " + str(path))


def check_links(T, target, soname):
    links = {"libjbig.so": f"libjbig.so.{soname}", "libjbig85.so": f"libjbig85.so.{soname}",
             "libtiff.so": "libtiff.so.6", "libtiff.so.6": "libtiff.so.6.3.0",
             "libtiffxx.so": "libtiffxx.so.6", "libtiffxx.so.6": "libtiffxx.so.6.3.0"}
    for name, expected in links.items():
        T.need(os.readlink(target / "usr/lib" / name) == expected, "Installed provider symlink differs: " + name)


def observer(T, O, G, I):
    initial_metadata = {}

    def observe(label, providers, reasons, raw):
        project = label == "replacement"
        target = O.TARGET
        platform = T.pin(T.encoded(G.base.platform(T, target)))
        T.need(platform == I.PLATFORM, "Protected Asahi boot and mount entries changed")
        pacman = ["/usr/bin/chroot", str(target), "/usr/bin/pacman", "--color", "never"]
        call([*pacman, "-Dk"])
        call([*pacman, "-Qk", "--", *providers])
        payloads = {name: T.read(target / name, pin, cap=pin["bytes"], collect=False)
                    for package in providers for name, pin in I.PROVIDER_FILES[package].items()}
        for package in providers:
            for relative in I.PROVIDER_FILES[package]:
                T.need(call([*pacman, "-Qoq", "--", "/" + relative]) == (package + "\n").encode(),
                       "Wrong installed provider ownership: " + relative)
        consumers = {}
        for relative, row in I.CONSUMERS.items():
            package, version, pin = row["package"], row["version"], row["pin"]
            consumers[relative] = T.read(target / relative, pin, cap=pin["bytes"], collect=False)
            T.need(call([*pacman, "-Qoq", "--", "/" + relative]) == (package + "\n").encode(),
                   "Unexpected unchanged consumer ownership: " + relative)
            if package not in initial_metadata or label != "baseline":
                directory = target / "var/lib/pacman/local" / f"{package}-{version}"
                observed = {leaf: T.read(directory / leaf, cap=8 << 20, collect=False)
                            for leaf in ("desc", "files", "mtree")}
                if label == "baseline":
                    initial_metadata[package] = observed
                else:
                    T.need(observed == initial_metadata[package], "Consumer ALPM metadata differs: " + package)
        current, stale = ("2.2", "2.1") if project else ("2.1", "2.2")
        check_links(T, target, current)
        absent(T, target / f"usr/lib/libjbig.so.{stale}")
        absent(T, target / f"usr/lib/libjbig85.so.{stale}")
        if project:
            absent(T, target / "usr/bin/tiffgt")
        else:
            absent(T, target / "usr/share/doc/cachy-asahi-jbigkit/source/PKGBUILD")
            absent(T, target / "usr/share/cachy-asahi-libtiff/corresponding-source/inventory.json")
        return dict(lock=T.pin(raw), platform=platform, provider_reasons=reasons, provider_files=payloads,
                    consumers=consumers, consumer_metadata=initial_metadata.copy(), tiffgt="ABSENT_PARITY_GAP" if project else "OFFICIAL")

    return observe


def check_log(T, raw, official, project):
    groups, active = [], None
    for line in raw.splitlines():
        if line.endswith("[ALPM] transaction started"):
            T.need(active is None, "Nested ALPM transaction")
            active = []
        elif line.endswith("[ALPM] transaction completed"):
            T.need(active is not None, "ALPM transaction completion without a start")
            groups.append(active)
            active = None
        elif match := ALPM_ACTION.search(line):
            T.need(active is not None, "ALPM changed a package outside the selected transactions")
            active.append(match.groups())
    expected = [sorted([("removed", n, v) for n, v in leave.items()] + [("installed", n, v) for n, v in enter.items()])
                for leave, enter in ((official, project), (project, official))]
    T.need(active is None and [sorted(group) for group in groups] == expected, "ALPM journal does not show exactly both pair swaps")
    return groups


def run(T, O, G, selected):
    """Entrypoint for the digest-bound copy of the original guest worker."""
    nonce = selected["nonce"]
    T.need(os.getuid() == os.geteuid() == 0 and os.uname().machine == "aarch64"
           and os.sysconf("SC_PAGE_SIZE") == 16384 and set(os.listdir("/sys/class/net")) == {"lo"},
           "Expected an offline emulated AArch64/16 KiB guest")
    G.check_mounts(T, O, Path("/proc/self/mountinfo").read_text().splitlines())
    T.need(set(G.target_submounts(O.TARGET)) == {str(O.TARGET / leaf) for leaf in ("dev", "proc", "run", "sys")}
           and Path("/proc/cmdline").read_text().split().count("cachy_overlay583_nonce=" + nonce) == 1,
           "Exact Asahi629 boot nonce and target mount scope required")
    pins = selected["code"]
    for name in SOURCES:
        T.read(CODE / name, pins[SCOPE + name], cap=128 << 10, collect=False)
    I, tx, runtime = [G.pinned_module(CODE / (role + ".py"), pins[SCOPE + role + ".py"])
                      for role in ("inputs", "transaction", "runtime")]
    review = review_shape(T, selected["jbig_tiff"]["test_review"], I.PROJECT)
    T.need(selected["jbig_tiff_media"] == media_pins(I, review), "Scoped library input pins differ")
    baseline = T.read(O.IN / "rollback.lock", I.BASELINE, cap=64 << 10)
    replacement, _ = I.project(baseline)
    paths = {name: O.IN / SCOPE / row["filename"] for name, row in I.PROVIDERS.items()}
    log = O.WORK / "jbig-tiff-alpm.log"
    backend = tx.Backend(G.trust_homes(O)["pacman"], log, paths)

    def current():
        G.current_test(T, review, int(time.time()))

    current()
    G.check_rtc(T, Path("/sys/class/rtc/rtc0"), int(time.time()))
    T.read(CODE / "tiff-jbig-roundtrip.c", I.ROUNDTRIP_SOURCE, cap=128 << 10, collect=False)
    report = tx.lifecycle(backend, I.OFFICIAL, I.PROJECT, baseline, replacement, observer(T, O, G, I),
                          lambda soname: runtime.run(O.TARGET, CODE / "tiff-jbig-roundtrip.c",
                                                     CODE / "consumer_probe.c", soname=soname),
                          lambda: authenticate(T, O, G, selected, I, review, paths), current,
                          dict(kind="ASAHI629_JBIG_TIFF_CHECKPOINT_V1", nonce=nonce))
    if report["status"] in (tx.PASS, tx.HOLD_RESTORED) and log.is_file():
        body = T.read(log, cap=32 << 10)
        try:
            report["alpm"] = check_log(T, body.decode("ascii"), I.OFFICIAL, I.PROJECT)
            report["alpm_log"] = body.decode("ascii")
        except (ValueError, OSError) as error:
            report["status"] = tx.HOLD_DISCARD
            report["failure"] = dict(phase="alpm-readback", message=str(error)[:640])
    T.need(len(T.encoded(report)) <= 96 << 10, "Scoped guest evidence exceeded result envelope")
    return report
