#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify and describe unissued Qt provider replacement inputs for Asahi629."""

import argparse
import io
import lzma
from pathlib import Path
from runpy import run_path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory


INTEGRATION = Path(__file__).resolve().parents[1]
A = run_path(str(INTEGRATION / "qt612_vulkan_md4c_successor/arm16k_inputs.py"))
M = run_path(str(INTEGRATION / "qt612_installed_16k_preflight/selection_maps.py"))
C, PKG = M["H"].C, M["PKG"]
need = A["need"]
PROJECT = "cachy-asahi-qt612-gui-server-source-reference"
OFFICIAL = "qt6-base"
VERSION = "6.12.0-3"
PARITY_PROJECT_VERSION = "6.12.0-4"
COUNT = 629
PASS629 = "PASS_DISPOSABLE_ASAHI_629_THREE_VERSION_REVERSE"
OFFICIAL_NAME = f"{OFFICIAL}-{VERSION}-aarch64.pkg.tar.xz"
PROJECT_NAME = f"{PROJECT}-{VERSION}-aarch64.pkg.tar.xz"
PINS = {
    "project_archive": C.file_pin(14172388, "6420f8ee8d8ebc106072c9bedb111c6b2dd780eb4e4629bceec4dc71a2b774c4"),
    "recovery_seal": C.file_pin(2345, "0cadd13f3f8d44d0a8ccf180c08176d7703b4f97ff97e73361ba8bf43b793cae"),
    "official_archive": C.file_pin(15177820, "2777135b375ba82250896fa9a993926bf3c05b59dd22217f63d6a1391c1b4c31"),
    "official_signature": C.file_pin(566, "8db1bcda35923c7e719b2b82162521e59edc4aeb0ec45a270e94f0327a2673f5"),
    "alarm_public_key": A["KEY"],
    "rollback_lock": C.file_pin(12346, "f335e8430a1d6f8463e95e16524cf78fc224c24fb31cf8717723370490bae9fa"),
    "rollback_result": C.file_pin(1954, "7acb1874ae50cd41910e3bc420e67afbb63147d93140ed7e482faa52e860987b"),
    "owned_terminal": C.file_pin(2092, "d32b162c363160e8a7f36794019cbf94b76ba45dcc91b843583660d450c85435"),
    "abi_comparison": C.file_pin(252319, "44de3677704545315fc1955acebeb24e22c7d03829c371061369effbc6044171"),
    "alpm_prepare": C.file_pin(1520, "66c08476ffcdb2714a6e0e2d69f7240eb2482abc6291686c9d490bdd6e36e5b7"),
}
FIELDS = dict(NAME="pkgname", VERSION="pkgver", ARCH="arch", DEPENDS="depend",
              PROVIDES="provides", CONFLICTS="conflict", REPLACES="replaces")
OWNED_SUCCESS = "PASS_ASAHI629_OFFLINE_FORWARD_AND_DECLARED_REVERSE_ONLY"


def reference(role, path):
    return dict(path=str(path), **PINS[role])


def read(role, path):
    try:
        return C.read(path, PINS[role]["bytes"], PINS[role])[0]
    except (OSError, ValueError) as error:
        raise ValueError(f"{role}: {path}: {error}") from error


def provider_versions(project_version=VERSION):
    need(type(project_version) is str and project_version in (VERSION, PARITY_PROJECT_VERSION),
         "Expected an exact Qt project provider version")
    return {OFFICIAL: VERSION, PROJECT: project_version}


def projected_swap(body, remove, add, *, project_version=VERSION):
    versions = provider_versions(project_version)
    need({remove, add} == versions.keys(), "Expected the exact official and project Qt providers")
    rows = A["package_inventory"](body, COUNT)
    removed, added = remove.encode("ascii"), add.encode("ascii")
    need(rows.get(removed) == versions[remove].encode("ascii") and added not in rows,
         f"Expected only the selected installed provider {remove} {versions[remove]}")
    del rows[removed]
    rows[added] = versions[add].encode("ascii")
    return b"".join(name + b" " + release + b"\n" for name, release in sorted(rows.items()))


def project(body, *, project_version=VERSION):
    replacement = projected_swap(body, OFFICIAL, PROJECT, project_version=project_version)
    restored = projected_swap(replacement, PROJECT, OFFICIAL, project_version=project_version)
    need(restored == body, "Restoration projection differs from original lock bytes")
    return replacement, restored


def archive_metadata(role, path, owner):
    try:
        with A["opened"](path, PINS[role]) as stream:
            raw = M["expand_archive"](stream)
    except (OSError, ValueError) as error:
        raise ValueError(f"{role}: {path}: {error}") from error
    if role == "project_archive":
        M["archive_headers"](raw)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:", encoding="utf-8", errors="strict") as archive:
        entries = []
        for index, member in enumerate(archive):
            need(index < 32768, f"{role}: archive member count exceeded")
            if member.name.removeprefix("./") == ".PKGINFO":
                entries.append(member)
        need(len(entries) == 1 and entries[0].isfile() and 0 < entries[0].size <= 32 << 10,
             f"{role}: expected one bounded regular .PKGINFO")
        body = archive.extractfile(entries[0]).read()
    parsed = PKG.metadata(body.decode("utf-8"))
    metadata = {field: parsed.get(name, []) for field, name in FIELDS.items()}
    need(metadata["NAME"] == [owner] and metadata["VERSION"] == [VERSION] and metadata["ARCH"] == ["aarch64"]
         and not metadata["REPLACES"], f"{role}: package identity or replacement metadata differs")
    return metadata, C.pin(body)


def verify_recovery(seal):
    recovered = seal["recovery_scope"]
    need(seal["kind"] == "qt612-successor-retired-overlay-recovery"
         and seal["files"][PROJECT_NAME] == PINS["project_archive"]
         and seal["original_scope"]["natural_retirement"] is True
         and seal["original_scope"]["status"] == "HOLD"
         and recovered["status"] == "OFFLINE_ARCHIVE_CONTRACT_VERIFIED"
         and recovered["package"] == PROJECT and recovered["version"] == VERSION
         and recovered["architecture"] == "aarch64" and recovered["build_guest_page_size"] == 16384
         and recovered["package_is_unsigned"] is True and recovered["original_paths_unchanged"] is True,
         "Expected the original offline recovery seal for the unsigned candidate")


def verify_predecessor(result, terminal):
    need(result["status"] == PASS629 and result["inventory"]["rollback"] == PINS["rollback_lock"]
         and result["nonce"] == terminal["nonce"]
         and terminal["status"] == OWNED_SUCCESS and terminal["controller_result"]["status"] == PASS629
         and terminal["retained_result_files"]["evidence/result.json"] == PINS["rollback_result"]
         and terminal["outer_container_absent_twice"] is True and terminal["inputs_reverified_after"] is True,
         "Expected the exact successful, retired Asahi629 rollback result")


def verify_audit(comparison, transcript, metadata):
    bound = dict(project=PINS["project_archive"], official=PINS["official_archive"], rollback629=PINS["rollback_lock"])
    need(all(comparison["inputs"][role] == pin for role, pin in bound.items())
         and comparison["locks"]["exact629"] == COUNT, "ABI audit refers to different inputs")
    for role, observed in metadata.items():
        recorded = comparison["metadata"][role]
        need(all(sorted(values) == sorted(recorded[field]) for field, values in observed.items()),
             f"{role}: original .PKGINFO differs from the ABI audit")
    candidate = metadata["project"]
    need(OFFICIAL in candidate["CONFLICTS"]
         and [value for value in candidate["PROVIDES"] if value.split("=", 1)[0] == OFFICIAL] == [OFFICIAL],
         "Expected an explicit conflict and bare Qt provider")
    checks = comparison["metadata"]["solves"]["629"]
    need(all(checks[role]["tests"]["whole"] == [0, [], []] for role in metadata),
         "Expected both 629 inventory solves in the retained audit")
    objects = [elf for consumer in comparison["abi"]["consumers"].values() for elf in consumer["objects"].values()]
    count = sum(elf["strong_qt_symbols"] for elf in objects)
    need(len(objects) == 145 and count == 18661
         and all(not elf["missing_project"] and not elf["missing_project_versions"]
                 and not elf["missing_project_unversioned"] for elf in objects), "Incomplete Qt consumer ABI audit")
    for route, add, remove in (("official to project", PROJECT, OFFICIAL), ("project to official", OFFICIAL, PROJECT)):
        transaction = (f"629 {route}, accept\nconflict: add {add}, remove {remove}, initial answer 0\n"
                       f"prepare: 0 ok\n{add} {VERSION}\n{remove} {VERSION}\n").encode("ascii")
        need(transcript.count(transaction) == 1, f"Missing exact prepare-only transaction for {route}")
    return dict(consumer_elfs=len(objects), versioned_references=count, alpm="PREPARE_ONLY")


def verify_official(paths, public_key):
    row = dict(filename=OFFICIAL_NAME, signer=A["FINGERPRINT"],
               archive=reference("official_archive", paths["official_archive"]),
               signature=reference("official_signature", paths["official_signature"]))
    with TemporaryDirectory(prefix="qt629-public-check-") as folder:
        home = Path(folder)
        keyring = home / "alarm-public.gpg"
        keyring.write_bytes(public_key)
        status = A["verify_signature"](row, home, keyring)
    return dict(fingerprint=A["FINGERPRINT"], status_stream=status)


def step(before, after, remove, add, archive, *, project_version=VERSION):
    versions = provider_versions(project_version)
    return dict(before=C.pin(before), after=C.pin(after),
                remove=[dict(name=remove, version=versions[remove])],
                add=[dict(name=add, version=versions[add], archive_input=archive)])


def handoff(recovery, official_archive, rollback_evidence, terminal, public_key, audit):
    need(official_archive.name == OFFICIAL_NAME, f"Expected the exact official archive name {OFFICIAL_NAME}")
    paths = dict(project_archive=recovery / PROJECT_NAME, recovery_seal=recovery / "recovery.SEAL.json",
                 official_archive=official_archive, official_signature=official_archive.with_name(OFFICIAL_NAME + ".sig"),
                 alarm_public_key=public_key, rollback_lock=rollback_evidence / "rollback.lock",
                 rollback_result=rollback_evidence / "result.json", owned_terminal=terminal,
                 abi_comparison=audit / "comparison.json", alpm_prepare=audit / "alpm-prepare.txt")
    data = {name: read(name, path) for name, path in paths.items() if not name.endswith("_archive")}
    verify_recovery(C.json_body(data["recovery_seal"]))
    result = C.json_body(data["rollback_result"])
    verify_predecessor(result, C.json_body(data["owned_terminal"]))
    baseline = data["rollback_lock"]
    replacement, restored = project(baseline)
    signature = verify_official(paths, data["alarm_public_key"])
    metadata, info = {}, {}
    for role, owner in (("project", PROJECT), ("official", OFFICIAL)):
        key = role + "_archive"
        metadata[role], info[role] = archive_metadata(key, paths[key], owner)
    audit_report = verify_audit(C.json_body(data["abi_comparison"]), data["alpm_prepare"], metadata)
    return dict(kind="QT612_R132_REPLACEMENT_INPUT_HANDOFF_UNISSUED_V1",
                authority=None, candidate_signature=None,
                target=dict(inventory="ASAHI629_ROLLBACK", packages=COUNT, nonce=result["nonce"]),
                inputs={name: reference(name, path) for name, path in paths.items()},
                pkginfo=info, official_signature=signature, prior_audit=audit_report,
                projection=dict(replacement=step(baseline, replacement, OFFICIAL, PROJECT, "project_archive"),
                                restoration=step(replacement, restored, PROJECT, OFFICIAL, "official_archive"),
                                byte_exact_restoration=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("recovery", "official-archive", "rollback-evidence", "terminal", "public-key", "audit"):
        parser.add_argument("--" + name, type=Path, required=True)
    try:
        sys.stdout.buffer.write(C.wire(handoff(**vars(parser.parse_args()))))
    except (KeyError, OSError, ValueError, lzma.LZMAError, tarfile.TarError, subprocess.SubprocessError) as error:
        sys.exit(f"Qt629 handoff refused: {error}")


if __name__ == "__main__":
    main()
