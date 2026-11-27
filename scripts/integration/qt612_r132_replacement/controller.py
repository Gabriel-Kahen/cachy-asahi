# SPDX-License-Identifier: MIT
"""Prepare unissued Qt629 controller inputs and read independently retired disks.

This module does not issue authority or start actors. A draft preserves exact
fixed inputs even while the Qt TEST pair or the display route is pending.
With a selected TEST pair and socket, the same preparation can produce a
complete guest input fragment for the owning, separately issued controller.
"""

import argparse
from hashlib import sha256
import os
from pathlib import Path
import re
from runpy import run_path
import secrets
import shutil
import sys
import time
from uuid import UUID


HERE = Path(__file__).resolve().parent
H = run_path(str(HERE / "host_stage.py"))
C, P, E, need = (H[name] for name in ("C", "P", "E", "need"))
R = E["R"]
LEGACY = "scripts/install/asahi629_trial/controller.py"
RETAINED_AUTHORITY = "fc727bb745bc16a917917b1e32a2aa3f7809e910ecc8db355562499361461ea3"
SOURCE_COMMIT = "c7bf684c8a4e107e9e2b132ceabb77ae5f5f60ca"
KIND = "QT629_CONTROLLER_PREPARATION_UNISSUED_V1"
DRAFT = "QT629_GUEST_PLAN_DRAFT_UNISSUED_V1"
STOPPED = "QT629_STOPPED_RESULT_OBSERVATION_V1"
SOURCE_CAP = 128 << 10
PREPARATION = "controller.UNISSUED.json"
FIXED_MEDIA = {
    "rollback.lock": "rollback_lock",
    "result.json": "rollback_result",
    H["QT_ALARM_NAME"]: "alarm_public_key",
    P["OFFICIAL_NAME"]: "official_archive",
    P["OFFICIAL_NAME"] + ".sig": "official_signature",
    P["PROJECT_NAME"]: "project_archive",
}
TEST_MEDIA = {P["PROJECT_NAME"] + ".sig", "test-certificate.gpg"}
WESTON_ARCHIVE = "weston-15.0.1-3-aarch64.pkg.tar.xz"
WESTON_MEDIA = {WESTON_ARCHIVE, WESTON_ARCHIVE + ".sig"}
WESTON_SOURCE = H["LANE"] + "weston_fixture.py"
DISPLAY = "weston-15.0.1-3-headless-pixman"
DISPLAY_SOCKET = "/run/qt629-wl/wayland-0"


def records(paths, pins):
    need(type(paths) is dict and paths.keys() == pins.keys(), "Exact input role set required")
    return {name: dict(path=str(paths[name]), **C.read(paths[name], pin["bytes"], pin, collect=False)[1])
            for name, pin in pins.items()}


def retained_controller(run):
    raw, pin = C.external(run / "authority.ROOT.json", SOURCE_CAP, RETAINED_AUTHORITY)
    authority = C.json_body(raw, canonical=True)
    need(authority["kind"] == "ROOT_ASAHI629_OFFLINE_TRANSACTION_SELECTION_V1" and authority["issuer"] == "Root",
         "Expected the exact recorded predecessor Asahi629 authority")
    source = run / "source"
    for leaf, expected in authority["source"].items():
        C.read(source / leaf, SOURCE_CAP, expected, collect=False)
    legacy = run_path(str(source / LEGACY))
    return legacy, authority, pin


def source_selection(source):
    paths = H["GUEST_ENTRY"]["SOURCES"]
    return {name: C.read(source / name, SOURCE_CAP, collect=False)[1] for name in sorted(paths)}


def selected_originals(handoff, digest, r132):
    raw, pin = C.external(handoff, 32 << 10, digest)
    value = C.json_body(raw, canonical=True)
    need(value["kind"] == "QT612_R132_REPLACEMENT_INPUT_HANDOFF_UNISSUED_V1"
         and value["authority"] is value["candidate_signature"] is None
         and value["inputs"].keys() == P["PINS"].keys(), "Expected exact unissued Qt provider handoff")
    need(all(row == dict(path=row["path"], **P["PINS"][role]) for role, row in value["inputs"].items()),
         "Qt handoff operand pins differ")
    need(type(r132) is dict and r132.keys() == R["ORIGINALS"].keys() - P["PINS"].keys(),
         "Exact retained R132 input role set required")
    paths = {role: Path(row["path"]) for role, row in value["inputs"].items()} | r132
    originals = records(paths, R["ORIGINALS"])
    result = C.json_body(C.read(paths["rollback_result"], 64 << 10, P["PINS"]["rollback_result"])[0])
    terminal = C.json_body(C.read(paths["owned_terminal"], 64 << 10, P["PINS"]["owned_terminal"])[0])
    P["verify_predecessor"](result, terminal)
    need(value["target"] == dict(inventory="ASAHI629_ROLLBACK", packages=629, nonce=result["nonce"]),
         "Qt handoff target or predecessor nonce differs")
    return originals, pin, result["nonce"]


def put(path, body):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(body)
        os.fchmod(stream.fileno(), 0o400)
        stream.flush()
        os.fsync(stream.fileno())
    return C.pin(body)


def display_intake(qt_source, receipt, digest):
    display = dict(fixture=DISPLAY, socket=DISPLAY_SOCKET, source=None, intake_receipt=None,
                   media={name: None for name in WESTON_MEDIA}, package_inventory=629)
    if receipt is None and digest is None:
        return display
    need(receipt is not None and digest is not None, "Exact Weston receipt and digest required together")
    raw, pin = C.external(receipt, 32 << 10, digest)
    value = C.json_body(raw, canonical=True)
    fixture_source = qt_source / WESTON_SOURCE
    source_path = HERE / "weston_fixture.py"
    _, source_pin = C.read(source_path, SOURCE_CAP, collect=False)
    fixture = run_path(str(source_path))
    members = {name: dict(type="file", mode=0o755, **ref) for name, ref in fixture["FILES"].items()}
    members.update({name: dict(type="symlink", target=target) for name, target in fixture["LINKS"].items()})
    need(value.keys() == {"kind", "filename", "inputs", "signer", "signature_status", "members"}
         and value["kind"] == fixture["KIND"] and value["filename"] == WESTON_ARCHIVE
         and value["inputs"] == fixture["PINS"] and value["members"] == members
         and value["signer"] == fixture["A"]["FINGERPRINT"], "Selected Weston fixture receipt differs")
    source = dict(path=str(fixture_source), **C.read(fixture_source, SOURCE_CAP, source_pin, collect=False)[1])
    pins = {WESTON_ARCHIVE: fixture["PINS"]["archive"], WESTON_ARCHIVE + ".sig": fixture["PINS"]["signature"]}
    paths = {name: receipt.parent / name for name in pins}
    return display | dict(source=source, intake_receipt=dict(path=str(receipt), **pin), media=records(paths, pins))


def preview_stage(run, worker_paths, base, qt_source, qt_pins, originals, display, root):
    """Stage fixed bytes and a draft plan with a schema the guest will refuse."""
    needed = {"qt-replacement/" + name for name in FIXED_MEDIA.keys() | TEST_MEDIA | WESTON_MEDIA}
    code = {name: C.read(path, SOURCE_CAP, base["code"][name])[0] for name, path in worker_paths.items()}
    code["asahi-guest.py"], code["operands.py"] = H["guest_checkpoint"](
        code["asahi-guest.py"], code["operands.py"], needed)
    code.update({name: C.read(qt_source / name, SOURCE_CAP, pin)[0] for name, pin in qt_pins.items()})
    if display["source"] is not None:
        row = display["source"]
        code[WESTON_SOURCE] = C.read(Path(row["path"]), SOURCE_CAP, C.file_pin(row["bytes"], row["sha256"]))[0]
    code_pins = {name: put(root / "code" / name, body) for name, body in code.items()}
    media = {}
    for leaf, role in FIXED_MEDIA.items():
        row, path = originals[role], root / "inputs/qt-replacement" / leaf
        body, _ = C.read(Path(row["path"]), row["bytes"], R["ORIGINALS"][role])
        media["qt-replacement/" + leaf] = put(path, body)
    for leaf, row in display["media"].items():
        name = "qt-replacement/" + leaf
        media[name] = None if row is None else put(root / "inputs" / name, C.read(
            Path(row["path"]), row["bytes"], C.file_pin(row["bytes"], row["sha256"]))[0])
    media |= {"qt-replacement/" + name: None for name in TEST_MEDIA}
    init = H["guest_init"](C.read(run / "output/asahi629/init.readback", SOURCE_CAP, H["PID1"])[0])
    draft = base | dict(kind=DRAFT, code=code_pins, qt_media=media,
                        qt_replacement=dict(project_review=None, wayland_socket=None),
                        display=dict(fixture=DISPLAY, socket=DISPLAY_SOCKET, source=code_pins.get(WESTON_SOURCE),
                                     intake_receipt=display["intake_receipt"]))
    return dict(init=put(root / "guest-init.sh", init), worker=code_pins["asahi-guest.py"],
                draft_plan=put(root / "guest-plan.UNISSUED.json", C.wire(draft)), plan=None,
                files={"code/" + name: pin for name, pin in code_pins.items()} |
                      {"inputs/" + name: pin for name, pin in media.items() if pin is not None})


def prepare(*, run, preview, handoff, handoff_sha, qt_source, r132, output,
            test_review=None, test_paths=None, wayland_socket=None, reviewed_source_pins=None,
            weston_receipt=None, weston_receipt_sha=None):
    """Create a fresh private packet and return its unissued preparation pin."""
    legacy, retained, authority_pin = retained_controller(run)
    originals, handoff_pin, predecessor = selected_originals(handoff, handoff_sha, r132)
    need(retained["nonce"] == predecessor, "Retained Asahi and Qt precursor nonces differ")
    worker_paths, worker_pins = legacy["selection"]()
    raw, preview_pin = C.read(preview / "manifest.json", H["MAX_PLAN"])
    media = C.json_body(raw, canonical=True)
    legacy["O"].rehash(legacy["T"], preview, media)
    now = int(time.time())
    preview_test = media["keys"]["preview-test"]
    preview_current = preview_test["not_before"] <= now and now + legacy["O"].TRUST_ALLOWANCE < preview_test["not_after"]
    qt_pins = source_selection(qt_source)
    display = display_intake(qt_source, weston_receipt, weston_receipt_sha)
    nonce = secrets.token_hex(16)
    need(nonce != predecessor, "Fresh Qt trial nonce required")
    base = dict(kind=H["KIND"], nonce=nonce, code=worker_pins, manifest=preview_pin, media=media)
    selected = any(value is not None for value in (test_review, test_paths, wayland_socket, reviewed_source_pins))
    if selected:
        need(all(value is not None for value in (test_review, test_paths, wayland_socket, reviewed_source_pins))
             and qt_pins == reviewed_source_pins and preview_current and wayland_socket == DISPLAY_SOCKET
             and display["intake_receipt"] is not None and H["WESTON_SOURCES"] <= qt_pins.keys(),
             "A fully selected stage requires current Preview trust, reviewed source, Qt TEST inputs and display")
        need(type(test_paths) is dict and test_paths.keys() == TEST_MEDIA, "Exact Qt TEST operand paths required")
        need(test_review["not_before"] <= now and now + legacy["O"].TRUST_ALLOWANCE < test_review["not_after"],
             "The selected Qt TEST lifetime does not cover the retained preparation allowance")
    need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent,
         "Canonical fresh private preparation path required")
    output.mkdir(mode=0o700)
    try:
        root = output / "stage"
        if selected:
            paths = {leaf: Path(originals[role]["path"]) for leaf, role in FIXED_MEDIA.items()} | test_paths
            staged = H["stage"](retained_source=run / "source", retained_init=run / "output/asahi629/init.readback",
                                qt_source=qt_source, qt_source_pins=reviewed_source_pins, baseline_plan=base,
                                project_review=test_review, media_paths=paths, wayland_socket=wayland_socket, output=root,
                                weston=display["media"])
        else:
            staged = preview_stage(run, worker_paths, base, qt_source, qt_pins, originals, display, root)
        source = {name: C.read(HERE / name, SOURCE_CAP, collect=False)[1]
                  for name in ("controller.py", "host_stage.py", "export.py", "readback.py")}
        record = dict(kind=KIND, authority=None, nonce=nonce, predecessor_nonce=predecessor,
                      preparation="GUEST_FRAGMENT_STAGED" if selected else "FIXED_BYTES_STAGED",
                      retained=dict(source=SOURCE_COMMIT, authority=authority_pin, source_pins=retained["source"],
                                    control=retained["control"], control_boot=retained["control_boot"],
                                    references=retained["references"], actor_image=retained["actor_image"]),
                      preview=dict(path=str(preview), manifest=preview_pin, current_at_preparation=preview_current),
                      handoff=handoff_pin, originals=originals, source=source, qt_source=qt_pins, staged=staged,
                      display=display,
                      pending=[] if selected else ["separate Qt TEST review and detached signature"] +
                              ([] if display["intake_receipt"] else ["reviewed Weston fixture intake"]) +
                              ["Weston guest supervisor and runtime evidence integration"],
                      execution="NOT RUN")
        pin = put(output / PREPARATION, C.wire(record))
    except BaseException:
        shutil.rmtree(output)
        raise
    return dict(path=str(output / PREPARATION), **pin, nonce=nonce, staged=staged)


def pack_inputs(legacy, preview, base_plan, root, stage_root, staged, *, display):
    """Owning controller hook before its ext4 image writer and verifier."""
    need(staged.get("authority") is None and staged.get("kind") == "QT629_HOST_STAGE_UNISSUED_V1"
         and staged["path"] == str(stage_root), "Expected the selected complete staged guest fragment")
    raw, _ = C.read(stage_root / "code/plan.json", H["MAX_PLAN"], staged["plan"])
    plan = C.json_body(raw, canonical=True)
    need(plan.keys() == base_plan.keys() | {"qt_media", "qt_replacement"}
         and all(plan[name] == value for name, value in base_plan.items() if name != "code"),
         "Qt boot plan differs from the base input scope")
    overlay = {"code/" + name: pin for name, pin in plan["code"].items()} | {
        "inputs/" + name: pin for name, pin in plan["qt_media"].items()} | {"code/plan.json": staged["plan"]}
    need(overlay == staged["files"] and plan["code"]["asahi-guest.py"] == staged["worker"]
         and plan["code"].keys() == base_plan["code"].keys() | H["GUEST_ENTRY"]["SOURCES"] | H["WESTON_SOURCES"]
         and plan["qt_media"].keys() == {"qt-replacement/" + name for name in FIXED_MEDIA.keys() | TEST_MEDIA | WESTON_MEDIA}
         and not os.path.lexists(root), "Staged guest pins, file allowlist or fresh packed tree differ")
    need(display["fixture"] == DISPLAY and display["package_inventory"] == 629
         and display["intake_receipt"] is not None and display["source"] is not None
         and display["media"].keys() == WESTON_MEDIA
         and plan["qt_replacement"]["wayland_socket"] == display["socket"] == DISPLAY_SOCKET,
         "Exact reviewed Weston fixture and socket required")
    for leaf, row in display["media"].items():
        need(plan["qt_media"]["qt-replacement/" + leaf] == C.file_pin(row["bytes"], row["sha256"]),
             "Staged Weston media differs from the verified intake")
    row = display["source"]
    need(plan["code"][WESTON_SOURCE] == C.file_pin(row["bytes"], row["sha256"]),
         "Staged Weston code differs from the reviewed source")
    for name, pin in overlay.items():
        C.read(stage_root / name, pin["bytes"], pin, collect=False)
    root.mkdir(mode=0o700)
    try:
        files, aliases, _ = legacy["copy_transport"](preview, base_plan, root)
        for covered in ("code/plan.json", *("code/" + name for name in base_plan["code"])):
            (root / covered).unlink()
        for name, pin in overlay.items():
            legacy["C"].checked_copy(stage_root / name, root / name, pin)
        directories = {str(path.relative_to(root)) for path in root.rglob("*") if not path.is_symlink() and path.is_dir()}
        return plan, (files | overlay, aliases, directories)
    except BaseException:
        if root.is_dir() and not root.is_symlink():
            shutil.rmtree(root)
        raise


def stopped(retirement, digest, nonce, disk_pin):
    need(type(nonce) is str and re.fullmatch(r"[0-9a-f]{32}", nonce)
         and C.check_pin(disk_pin, E["RESULT_BYTES"]) and disk_pin["bytes"] == E["RESULT_BYTES"],
         "Exact run nonce and stopped result disk pin required")
    raw, pin = C.external(retirement, SOURCE_CAP, digest)
    row = C.json_body(raw, canonical=True)
    need(row.keys() == {"kind", "nonce", "disk", "held", "retirement"} and row["kind"] == STOPPED
         and row["nonce"] == nonce and row["disk"] == disk_pin and type(row["held"]) is bool,
         "Expected exact stopped result observation")
    observations = row["retirement"]
    if row["held"]:
        outer = observations["outer_container"]
        need(observations["nonce"] == nonce and observations["qemu"]["reaped"] is True and outer["removed"] is True
             and type(outer["id"]) is str and re.fullmatch(r"[0-9a-f]{64}", outer["id"])
             and observations["observations"] == [dict(event=kind, qemu=[], outer_containers=[])
                                                   for kind in ("absence-first", "absence-second")],
             "Held disk requires reaped QEMU and two owned absence observations")
    else:
        R["retirement"](observations, nonce)
    return row["held"], pin


def require_result_uuid(path, pin, nonce):
    # Match the result filesystem stamped by the retained launcher before guest boot.
    expected = str(UUID(bytes=sha256((nonce + ":OV583_RESULT").encode("ascii")).digest()[:16]))
    before = C.identity(path.lstat())
    C.read(path, E["RESULT_BYTES"], pin, collect=False)
    with C.ext4_reader()(path) as disk:
        need(C.identity(os.fstat(disk.fd)) == before == C.identity(path.lstat()),
             "Stopped result disk changed before UUID verification")
        need(disk.uuid == expected, "Stopped result disk ext4 UUID differs from the run nonce")


def export_stopped(*, disk_path, disk_pin, retirement, retirement_sha, nonce, bundle,
                   originals=None, test_inputs=None, asahi_bundle=None):
    """Owning controller hook after QEMU and the outer container retire."""
    held, receipt = stopped(retirement, retirement_sha, nonce, disk_pin)
    if held:
        require_result_uuid(disk_path, disk_pin, nonce)
    result = H["export_result"](disk_path, disk_pin, bundle, held=held, originals=originals,
                                test_inputs=test_inputs, asahi_bundle=asahi_bundle, expected_nonce=nonce)
    return dict(held=held, retirement=receipt, **result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run", "preview", "handoff", "qt-source", "output", "r132-kernel", "r132-config", "r132-transport"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--handoff-sha", required=True)
    parser.add_argument("--weston-receipt", type=Path)
    parser.add_argument("--weston-receipt-sha")
    args = vars(parser.parse_args())
    try:
        args["r132"] = {name: args.pop(name) for name in ("r132_kernel", "r132_config", "r132_transport")}
        report = prepare(**args)
        sys.stdout.buffer.write(C.wire(report))
    except (OSError, ValueError, KeyError, TypeError) as error:
        sys.exit(f"Qt629 unissued preparation refused: {error}")


if __name__ == "__main__":
    main()
