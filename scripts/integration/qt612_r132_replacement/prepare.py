#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify and describe unissued Qt provider replacement inputs for Asahi629."""

import argparse
import hashlib
import io
import json
import lzma
from pathlib import Path
import re
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
HANDOFF_KIND = "QT612_R132_REPLACEMENT_INPUT_HANDOFF_UNISSUED_V1"
PARITY_HANDOFF_KIND = "QT612_ASAHI629_PARITY_HANDOFF_UNISSUED_V1"
PARITY_KIND = "QT612_ASAHI629_REVIEWED_PARITY_PROFILE_V1"
PARITY_RECIPE = C.file_pin(4460, "0fc98bc3f5556b96012efa230d97f5eace3046c0f42984f9fc562040a7af0364")
PROFILE_CAP = 16 << 10
ARCHIVE_CAP = 16 << 20
PARITY_INPUT_CAPS = dict(project_archive=ARCHIVE_CAP, build_plan=128 << 10, build_receipt=2 << 20,
                         abi_comparison=2 << 20, alpm_prepare=128 << 10)
# Match the parity producer's checked package path and ABI report.
PARITY_PRINT_DIRECTORY = "usr/lib/qt6/plugins/printsupport"
PARITY_ADDED_FILES = frozenset({
    *("usr/include/qt6/QtGui/6.12.0/QtGui/private/" + name + ".h" for name in (
        "atspiadaptor_p", "bus_interface_p", "cache_adaptor_p", "dbusconnection_p",
        "deviceeventcontroller_adaptor_p", "properties_interface_p", "qspi_constant_mappings_p",
        "qspi_struct_marshallers_p", "qspiaccessiblebridge_p", "qspiapplicationadaptor_p",
        "qspidbuscache_p", "qspimatchrulematcher_p", "socket_interface_p",
    )),
    *("usr/include/qt6/QtPrintSupport/6.12.0/QtPrintSupport/private/" + name + ".h"
      for name in ("qcups_p", "qcupsjobwidget_p")),
    *(f"usr/lib/cmake/{target}{suffix}.cmake" for target in (
        "Qt6Gui/Qt6QXcbEglIntegrationPlugin", "Qt6PrintSupport/Qt6QCupsPrinterSupportPlugin",
    ) for suffix in ("AdditionalTargetInfo", "Config", "ConfigVersion", "ConfigVersionImpl",
                     "Targets-release", "Targets", "TargetsPrecheck")),
    PARITY_PRINT_DIRECTORY + "/libcupsprintersupport.so",
    "usr/lib/qt6/plugins/xcbglintegrations/libqxcb-egl-integration.so",
})
PARITY_LIBRARIES = frozenset(f"usr/lib/libQt6{name}.so.6.12.0" for name in (
    "Core", "Concurrent", "DBus", "Gui", "Network", "OpenGL", "OpenGLWidgets", "PrintSupport", "Sql",
    "Test", "Widgets", "Xml", "WaylandClient", "XcbQpa", "EglFSDeviceIntegration", "EglFsKmsGbmSupport",
    "EglFsKmsSupport", "WlShellIntegration",
))
PARITY_QTGUI = "usr/lib/libQt6Gui.so.6.12.0"
PARITY_ATSPI_EXPORT = "_ZN20QSpiAccessibleBridgeC1Ev@@Qt_6_PRIVATE_API"
PARITY_ATSPI_CONSUMERS = ("libQt6WaylandClient.so.6.12.0", "libQt6XcbQpa.so.6.12.0")
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


def test_review(review):
    need(type(review) is dict and review.keys() == {"fingerprint", "signature", "certificate", "not_before", "not_after"},
         "Exact Qt TEST certificate and signature review required")
    fingerprint, before, after = (review[name] for name in ("fingerprint", "not_before", "not_after"))
    need(type(fingerprint) is str and re.fullmatch(r"[0-9A-F]{40}", fingerprint)
         and fingerprint != A["FINGERPRINT"] and type(before) is type(after) is int and 0 < before < after,
         "Separate finite Qt TEST certificate required")
    for name, cap in (("signature", 64 << 10), ("certificate", 128 << 10)):
        pin = review[name]
        need(C.check_pin(pin, cap) and pin["bytes"] > 0, "Exact Qt TEST pin required for " + name)
    return review


def checked_profile(profile):
    need(type(profile) is dict and profile.keys() == PARITY_INPUT_CAPS.keys() | {
        "kind", "official_version", "project_version", "recipe", "test_review",
    } and profile["kind"] == PARITY_KIND and profile["official_version"] == VERSION
         and profile["project_version"] == PARITY_PROJECT_VERSION and profile["recipe"] == PARITY_RECIPE,
         "Exact reviewed Qt629 parity profile required")
    for name, cap in PARITY_INPUT_CAPS.items():
        pin = profile[name]
        need(C.check_pin(pin, cap) and pin["bytes"] > 0, "Exact parity pin required for " + name)
    need(all(profile[name] != PINS[name] for name in ("project_archive", "abi_comparison", "alpm_prepare"))
         and profile["project_archive"] != PINS["official_archive"], "Prior Qt evidence cannot select a parity candidate")
    review = test_review(profile["test_review"])
    need(review["certificate"] != PINS["alarm_public_key"] and review["signature"] != PINS["official_signature"],
         "Parity TEST operands must be distinct from the official trust inputs")
    return profile


def load_profile(path, digest):
    if path is None and digest is None:
        return None
    need(path is not None and type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest),
         "Parity profile path and independent SHA-256 are required together")
    return checked_profile(C.json_body(C.external(path, PROFILE_CAP, digest)[0], canonical=True))


def profile_pins(profile):
    if profile is None:
        return PINS
    checked_profile(profile)
    return {key: pin for key, pin in PINS.items() if key != "recovery_seal"} | {
        name: profile[name] for name in PARITY_INPUT_CAPS
    } | {"parity_recipe": profile["recipe"]}


def project_name(profile):
    return PROJECT_NAME if profile is None else f"{PROJECT}-{checked_profile(profile)['project_version']}-aarch64.pkg.tar.xz"


def choose_review(profile, review):
    if profile is not None:
        need(checked_profile(profile)["test_review"] == review, "Qt TEST review differs from the selected parity profile")
    return review


def plan_profile(addon):
    fields = {"project_review", "wayland_socket"}
    need(type(addon) is dict and addon.keys() in (fields, fields | {"parity_profile"}),
         "Exact Qt checkpoint plan fields required")
    if "parity_profile" in addon:
        profile = checked_profile(addon["parity_profile"])
        choose_review(profile, addon["project_review"])
        return profile
    return None


def verify_parity_build(profile, plan_raw, receipt_raw, recipe_raw):
    need((C.pin(plan_raw), C.pin(receipt_raw), C.pin(recipe_raw)) ==
         (profile["build_plan"], profile["build_receipt"], profile["recipe"]), "Parity build evidence pins differ")
    plan, receipt = (C.json_body(body, canonical=True) for body in (plan_raw, receipt_raw))
    need(plan["kind"] == "QTBASE_SUCCESSOR16K_PLAN_V1" and plan["mode"] == "full"
         and plan["inputs"]["recipe"] == plan["payload"]["recipe/PARITY.UNISSUED.json"] == profile["recipe"]
         and receipt["kind"] == "QTBASE_SUCCESSOR16K_INDEPENDENT_READBACK_V1"
         and receipt["status"] == "PASS_UNSIGNED_EMULATED_AARCH64_16K_PACKAGE" and receipt["mode"] == "full"
         and receipt["nonce"] == plan["nonce"] and receipt["plan"] == profile["build_plan"]
         and receipt["originals_unchanged"] is True and receipt["container_retired"] == [True, True]
         and type(receipt["container_exit"]) is type(receipt["qemu_exit"]) is int
         and receipt["container_exit"] == receipt["qemu_exit"] == 0,
         "Expected accepted full retired ARM16K parity build")
    provenance = {"profile", "source_sha256"}
    if provenance & (plan.keys() | receipt.keys()):
        selected = {name: plan[name] for name in ("profile", "payload", "launcher", "actor")}
        source = json.dumps(selected, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        need(plan["profile"] == receipt.get("profile") == "parity"
             and plan.get("source_sha256") == receipt.get("source_sha256") == hashlib.sha256(source).hexdigest(),
             "Parity build binder source or profile differs")
    guest = receipt["guest"]
    archive = guest["archive"]
    worker = guest["worker"]
    delta = archive["path_delta"]
    need(guest["evidence"][project_name(profile)] == profile["project_archive"]
         and worker["architecture"] == "aarch64" and worker["page_size"] == 16384
         and worker["nonce"] == receipt["nonce"] and worker["phase"] == "complete" and worker["status"] == "PASS",
         "Expected exact parity archive and complete ARM16K worker")
    need(delta["added_files"] == sorted(PARITY_ADDED_FILES)
         and delta["added_directories"] == [PARITY_PRINT_DIRECTORY]
         and delta["removed"] == delta["metadata_changed"] == [],
         "Parity archive path delta differs from the 31 reviewed files")
    exports = delta["qt_dynamic_exports"]
    need(type(archive["libraries"]) is dict and archive["libraries"].keys() == PARITY_LIBRARIES
         and type(exports) is dict and exports.keys() == PARITY_LIBRARIES,
         "Parity archive library identities differ")
    need(archive["atspi_bridge_abi"] == dict(qtgui_export=PARITY_ATSPI_EXPORT, consumers=list(PARITY_ATSPI_CONSUMERS))
         and type(exports[PARITY_QTGUI]["new_exports"]) is list
         and PARITY_ATSPI_EXPORT in exports[PARITY_QTGUI]["new_exports"],
         "Parity AT-SPI symbol or consumer identities differ")


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


def archive_metadata(role, path, owner, *, profile=None):
    version = VERSION if profile is None or owner == OFFICIAL else profile["project_version"]
    try:
        with A["opened"](path, profile_pins(profile)[role]) as stream:
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
    need(metadata["NAME"] == [owner] and metadata["VERSION"] == [version] and metadata["ARCH"] == ["aarch64"]
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


def verify_audit(comparison, transcript, metadata, *, profile=None):
    pins = profile_pins(profile)
    versions = provider_versions(profile["project_version"] if profile is not None else VERSION)
    bound = dict(project=pins["project_archive"], official=pins["official_archive"], rollback629=pins["rollback_lock"])
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
                       f"prepare: 0 ok\n{add} {versions[add]}\n{remove} {versions[remove]}\n").encode("ascii")
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


def handoff(recovery, official_archive, rollback_evidence, terminal, public_key, audit, *, profile=None):
    need(official_archive.name == OFFICIAL_NAME, f"Expected the exact official archive name {OFFICIAL_NAME}")
    paths = dict(project_archive=recovery / project_name(profile),
                 official_archive=official_archive, official_signature=official_archive.with_name(OFFICIAL_NAME + ".sig"),
                 alarm_public_key=public_key, rollback_lock=rollback_evidence / "rollback.lock",
                 rollback_result=rollback_evidence / "result.json", owned_terminal=terminal,
                 abi_comparison=audit / "comparison.json", alpm_prepare=audit / "alpm-prepare.txt")
    pins = profile_pins(profile)
    if profile is None:
        paths["recovery_seal"] = recovery / "recovery.SEAL.json"
    else:
        paths.update(build_plan=recovery / "plan.json", build_receipt=recovery / "build-readback.json",
                     parity_recipe=recovery / "PARITY.UNISSUED.json")
    data = {name: C.read(path, pins[name]["bytes"], pins[name])[0]
            for name, path in paths.items() if not name.endswith("_archive")}
    if profile is None:
        verify_recovery(C.json_body(data["recovery_seal"]))
    else:
        verify_parity_build(profile, data["build_plan"], data["build_receipt"], data["parity_recipe"])
    result = C.json_body(data["rollback_result"])
    verify_predecessor(result, C.json_body(data["owned_terminal"]))
    baseline = data["rollback_lock"]
    version = VERSION if profile is None else profile["project_version"]
    replacement, restored = project(baseline, project_version=version)
    signature = verify_official(paths, data["alarm_public_key"])
    metadata, info = {}, {}
    for role, owner in (("project", PROJECT), ("official", OFFICIAL)):
        key = role + "_archive"
        metadata[role], info[role] = archive_metadata(key, paths[key], owner, profile=profile)
    audit_report = verify_audit(C.json_body(data["abi_comparison"]), data["alpm_prepare"], metadata, profile=profile)
    record = dict(kind=HANDOFF_KIND if profile is None else PARITY_HANDOFF_KIND,
                authority=None, candidate_signature=None,
                target=dict(inventory="ASAHI629_ROLLBACK", packages=COUNT, nonce=result["nonce"]),
                inputs={name: dict(path=str(path), **pins[name]) for name, path in paths.items()},
                pkginfo=info, official_signature=signature, prior_audit=audit_report,
                projection=dict(replacement=step(baseline, replacement, OFFICIAL, PROJECT, "project_archive",
                                                 project_version=version),
                                restoration=step(replacement, restored, PROJECT, OFFICIAL, "official_archive",
                                                 project_version=version),
                                byte_exact_restoration=True))
    if profile is not None:
        record["parity_profile"] = C.pin(C.wire(profile))
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("recovery", "official-archive", "rollback-evidence", "terminal", "public-key", "audit"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--profile-sha256")
    try:
        args = vars(parser.parse_args())
        args["profile"] = load_profile(args.pop("profile"), args.pop("profile_sha256"))
        sys.stdout.buffer.write(C.wire(handoff(**args)))
    except (KeyError, OSError, ValueError, lzma.LZMAError, tarfile.TarError, subprocess.SubprocessError) as error:
        sys.exit(f"Qt629 handoff refused: {error}")


if __name__ == "__main__":
    main()
