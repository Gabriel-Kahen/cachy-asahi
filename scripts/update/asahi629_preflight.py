#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Audit retained Asahi629 update inputs without staging or applying an update."""

import argparse
from io import BytesIO
from pathlib import Path
from runpy import run_path
import subprocess
import sys
import tarfile
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
UPDATER_NAME = "cachy-asahi-update"
UPDATER_CONFLICTS = ("arch-update", "cachy-update")
RUNTIME_PACKAGES = {
    "archlinux-contrib": ("20261009-1", "any", ("bash", "pyalpm", "python")),
    "htmlq": ("0.4.0-3", "aarch64", ("glibc", "libgcc")),
    "pyalpm": ("0.12.0-1", "aarch64", ("pacman", "python")),
}
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


def runtime_pins():
    retained = run_path(str(SCRIPTS / "port/updater-native-stage/runtime_intake.py"))
    return {leaf: dict(bytes=size, sha256=digest)
            for leaf, _url, (size, digest) in retained["runtime_files"]()}


def inspect_runtime_archive(raw, parse, name, version, arch, depends, conflicts=()):
    # All four pinned XZ archives place these controls before the payload.
    with tarfile.open(fileobj=BytesIO(raw), mode="r|xz") as archive:
        for leaf in (".BUILDINFO", ".MTREE", ".PKGINFO"):
            member = archive.next()
            need(member is not None and member.name == leaf and member.isfile()
                 and 0 < member.size <= 128 << 10, f"Unexpected package control layout: {name}")
        with archive.extractfile(member) as stream:
            body = stream.read()
    fields = parse(body.decode())
    need((fields.get("pkgname"), fields.get("pkgver"), fields.get("arch")) == ([name], [version], [arch]),
         f"Unexpected package identity: {name}")
    need(sorted(fields.get("depend", ())) == sorted(depends)
         and sorted(fields.get("conflict", ())) == sorted(conflicts)
         and not fields.get("provides") and not fields.get("replaces"),
         f"Unexpected package relations: {name}")
    return dict(version=version, arch=arch, depends=sorted(depends),
                conflicts=sorted(conflicts), pkginfo=T["pin"](body))


def project_runtime(rows, updater, directory, home, keyring, signer):
    directory = T["ordinary"](directory)
    need(directory.is_dir(), "Expected a canonical updater runtime directory")
    parse = run_path(str(SCRIPTS / "checks/package_checks_v2.py"))["metadata"]
    pins = runtime_pins()
    packages = {}
    for name, (version, arch, depends) in RUNTIME_PACKAGES.items():
        filename = f"{name}-{version}-{arch}.pkg.tar.xz"
        detached = filename + ".sig"
        archive, signature = pins[filename], pins[detached]
        raw = read(directory / filename, archive, cap=1 << 20)
        read(directory / detached, signature, cap=64 << 10, collect=False)
        status = A["verify_signature"](
            dict(filename=filename, signer=signer,
                 archive=dict(archive, path=directory / filename),
                 signature=dict(signature, path=directory / detached)), home, keyring)
        packages[name] = dict(inspect_runtime_archive(raw, parse, name, version, arch, depends),
                              archive=dict(archive, filename=filename),
                              signature=dict(signature, filename=detached), signer=signer, gpgv_status=status)
    raw = read(updater, UPDATER, cap=4 << 20)
    packages[UPDATER_NAME] = dict(inspect_runtime_archive(
        raw, parse, UPDATER_NAME, "4.4.2-3", "aarch64", UPDATER_DEPENDS, UPDATER_CONFLICTS),
        archive=UPDATER)
    additions = {name: row["version"] for name, row in packages.items()}
    projected = {}
    for role, baseline in rows.items():
        need(not additions.keys() & baseline.keys(), f"Runtime package already present in {role} lock")
        inventory = baseline | additions
        need(len(inventory) == 633, f"Expected exact 633-package {role} projection")
        for name, row in packages.items():
            need(set(row["depends"]) <= inventory.keys() and not set(row["conflicts"]) & inventory.keys(),
                 f"Unresolved runtime package relations in {role} lock: {name}")
        body = "".join(f"{name} {version}\n" for name, version in sorted(inventory.items())).encode()
        projected[role] = dict(T["pin"](body), packages=len(inventory))
    return dict(status="PROJECTED_ONLY", inventories=projected, packages=packages,
                updater_test_signature="PENDING", signed_repositories="PENDING", alpm_prepare="NOT RUN")


def audit(before, candidate, recovery, media, updater=None, updater_runtime=None):
    """Return the exact read-only operand census and a bounded HOLD record."""
    need(updater_runtime is None or updater is not None, "Updater runtime projection requires --updater")
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
    operands, projection = {}, None
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
        if updater_runtime is not None:
            need(not missing, "Updater runtime projection requires complete retained Asahi629 signatures and archives")
            projection = project_runtime(rows, updater, updater_runtime, home, keyring, signer)
    if updater is not None and updater_runtime is None:
        read(updater, UPDATER, cap=4 << 20, collect=False)
    result = dict(
        kind="ASAHI629_COORDINATED_UPDATE_INPUT_AUDIT_V1",
        status="HOLD_ASAHI629_COORDINATED_UPDATE_INPUTS", authority=None,
        scope="retained-three-version-maintenance-replay", transport=TRANSPORT,
        inventories=locks, operands=operands, alarm_public_key=dict(alarm, **key_pin),
        missing_retained_files=sorted(missing),
        updater_archive=dict(UPDATER, status="PIN_MATCHED" if updater is not None else "NOT_SUPPLIED"),
        updater_direct_names_absent=sorted(UPDATER_DEPENDS - rows["before"].keys()),
        unselected_prerequisites=list(UNSELECTED))
    if projection is not None:
        result["updater_runtime_projection"] = projection
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in (*LOCKS, "media"):
        parser.add_argument("--" + role, type=Path, required=True)
    parser.add_argument("--updater", type=Path)
    parser.add_argument("--updater-runtime", type=Path)
    try:
        report = audit(**vars(parser.parse_args()))
    except (KeyError, OSError, TypeError, ValueError, EOFError, tarfile.TarError, subprocess.SubprocessError) as error:
        sys.exit(f"Asahi629 updater input refused: {error}")
    sys.stdout.buffer.write(T["encoded"](report))


if __name__ == "__main__":
    main()
