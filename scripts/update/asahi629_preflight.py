#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit retained Asahi629 update inputs without staging or applying an update."""

import argparse
from pathlib import Path
from runpy import run_path
import subprocess
import sys
from tempfile import TemporaryDirectory


SCRIPTS = Path(__file__).resolve().parents[1]
T = run_path(str(SCRIPTS / "install/overlay583_trial/trial.py"))
O = run_path(str(SCRIPTS / "install/asahi629_trial/operands.py"))
A = run_path(str(SCRIPTS / "integration/qt612_vulkan_md4c_successor/arm16k_inputs.py"))
read, need = T["read"], T["need"]
TRANSPORT = dict(bytes=200263, sha256="11959697e9dd4dcce85d1d7878504c57bf3a74e22b04649b9c2056028deda89a")
UPDATER = dict(bytes=3084316, sha256="44b89959b768c80e82d1e32b29348bdd4b58bfb1fabfba393b14794178d086dc")
# Unversioned depend entries from the pinned updater archive's .PKGINFO.
UPDATER_DEPENDS = frozenset(("archlinux-contrib", "bash", "coreutils", "curl", "diffutils", "fakeroot",
                             "gettext", "glib2", "glibc", "hicolor-icon-theme", "htmlq", "libgcc",
                             "pacman", "pacman-contrib", "python", "systemd", "util-linux", "xdg-utils"))
LOCKS = {"before": "rollback.lock", "candidate": "forward.lock", "recovery": "rollback.lock"}
ARCHIVE_PHASES = {"candidate": "forward", "recovery": "rollback"}
UNSELECTED = (
    "asahi629-updater-runtime-dependency-closure-and-before-lock",
    "asahi629-updater-detached-signature-and-current-public-test-trust",
    "signed-candidate-and-recovery-repository-databases",
    "pinned-protected-platform-transition-and-pre-post-observations",
    "exact-recovery-boot-assets-and-restore-observation",
)


def inventories(paths):
    rows, pins = {}, {}
    for role, leaf in LOCKS.items():
        count, size, digest = O["REFS"][leaf]
        pin = dict(bytes=size, sha256=digest)
        rows[role] = T["canonical_lock"](read(paths[role], pin, cap=64 << 10), count)
        pins[role] = dict(pin, packages=count)
    before, candidate, recovery = (rows[role] for role in LOCKS)
    changed = {name: (before[name], candidate[name]) for name in before.keys() & candidate.keys()
               if before[name] != candidate[name]}
    need(before == recovery and before.keys() == candidate.keys() and changed == O["REVERSED"],
         "Expected only the exact three Asahi629 maintenance changes and full inverse")
    return rows, pins


def present(path):
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def public_keyring(key, home):
    command = ["/usr/bin/gpg", "--batch", "--no-options", "--no-autostart",
               "--homedir", str(home), "--dearmor"]
    result = subprocess.run(command, input=key, capture_output=True, env=A["ENV"], timeout=15)
    need(result.returncode == 0 and 0 < len(result.stdout) <= 64 << 10, "Invalid retained ALARM public key")
    keyring = home / "alarm.gpg"
    keyring.write_bytes(result.stdout)
    return keyring


def audit(before, candidate, recovery, media, updater=None):
    """Return the exact read-only operand census and a bounded HOLD record."""
    rows, locks = inventories(dict(before=before, candidate=candidate, recovery=recovery))
    media = T["ordinary"](media)
    need(media.is_dir(), "Expected a canonical retained transport directory")
    manifest = T["decode"](read(media / "manifest.json", TRANSPORT, cap=O["PLAN_LIMIT"]))
    need(manifest["kind"] == O["KIND"], "Expected the retained Asahi629 transport")
    alarm = manifest["keys"]["alarm"]
    signer = A["FINGERPRINT"]
    need(alarm == dict(file="keys/alarm.gpg", scope="vendor", fingerprint=signer),
         "Expected the exact ALARM public trust role")
    key_pin = manifest["files"][alarm["file"]]
    key_path = media / alarm["file"]
    key = read(key_path, key_pin, cap=64 << 10) if present(key_path) else None

    missing = [] if key is not None else [alarm["file"]]
    operands = {}
    with TemporaryDirectory(prefix="asahi629-updater-public-") as folder:
        home = Path(folder)
        keyring = public_keyring(key, home) if key is not None else None
        for role, phase in ARCHIVE_PHASES.items():
            operands[role] = {}
            for name in sorted(O["REVERSED"]):
                version = rows[role][name]
                archive = f"{phase}/{name}-{version}-aarch64.pkg.tar.xz"
                need(manifest["packages"][phase][name] == dict(archive=archive, scope="vendor", signer=signer),
                     f"Unexpected {role} operand for {name}")
                entry = dict(version=version, signer=signer)
                available = {}
                for part, leaf, cap in (("archive", archive, 64 << 20), ("signature", archive + ".sig", 64 << 10)):
                    pin = manifest["files"][leaf]
                    entry[part] = dict(path=leaf, **pin)
                    path = media / leaf
                    if present(path):
                        read(path, pin, cap=cap, collect=False)
                        available[part] = dict(path=path, **pin)
                    else:
                        missing.append(leaf)
                if keyring is not None and len(available) == 2:
                    entry["gpgv_status"] = A["verify_signature"](
                        dict(filename=archive, signer=signer, **available), home, keyring)
                operands[role][name] = entry
    if updater is not None:
        read(updater, UPDATER, cap=4 << 20, collect=False)
    return dict(kind="ASAHI629_COORDINATED_UPDATE_INPUT_AUDIT_V1",
                status="HOLD_ASAHI629_COORDINATED_UPDATE_INPUTS", authority=None,
                scope="retained-three-version-maintenance-replay",
                transport=TRANSPORT, inventories=locks, operands=operands,
                alarm_public_key=dict(alarm, **key_pin), missing_retained_files=sorted(missing),
                updater_archive=dict(UPDATER, status="PIN_MATCHED" if updater is not None else "NOT_SUPPLIED"),
                updater_direct_names_absent=sorted(UPDATER_DEPENDS - rows["before"].keys()),
                unselected_prerequisites=list(UNSELECTED))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in (*LOCKS, "media"):
        parser.add_argument("--" + role, type=Path, required=True)
    parser.add_argument("--updater", type=Path)
    try:
        report = audit(**vars(parser.parse_args()))
    except (KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError) as error:
        sys.exit(f"Asahi629 updater input refused: {error}")
    sys.stdout.buffer.write(T["encoded"](report))


if __name__ == "__main__":
    main()
