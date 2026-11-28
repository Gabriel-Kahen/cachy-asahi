# SPDX-License-Identifier: MIT
"""Shared installed guest role and authority checks for the Qt site and actor."""

from pathlib import Path
import re
from runpy import run_path
from types import SimpleNamespace
from uuid import NAMESPACE_URL, uuid5

HERE = Path(__file__).resolve().parent
W = SimpleNamespace(**run_path(str(HERE / "worker.py")))
P, T = W.P, W.T
PACKAGE = HERE.parent / "qt612_full_16k_preflight"
M = SimpleNamespace(**run_path(str(PACKAGE / "package_media.py")))
F, C = M.F, M.C
BOOT_DIR = "/qtbase-installed"
CASES = ("main", "tampered_signature", "unknown_key")
CLAIM = "installed-trial.claim"
MEDIA_NAME = "MEDIA.UNISSUED.json"
MEDIA_KIND = "QTBASE16K_INSTALLED_MEDIA_UNISSUED_V1"
AUTH_KIND = "ROOT_QTBASE16K_INSTALLED_OWNER_V2"
ROLE_FLAG = "CACHY_ASAHI_QTBASE16K_INSTALLED_ACTOR"
RESULT_KIND = "QTBASE16K_INSTALLED_ACTOR_RESULT_V1"
HOST_KIND = "QTBASE16K_INSTALLED_HOST_RETIREMENT_V1"
OBSERVATION_KIND = "QTBASE16K_INSTALLED_POST_SCOPE_V1"
ACTOR_BYTES, GUEST_BYTES, WRITER_CAP = 8 << 30, 6 << 30, 4 << 30
DATA_BYTES, RESULT_BYTES = 1 << 30, M.E.RESULT_BYTES
QEMU_SECONDS, ATTACH_SECONDS = 3600, 3900
BOOT_FILES = ("guest-init.sh", "root-helpers.sh", "rtc-clock.sh", "protect.list", "source.sha256", "MANIFEST.sha256")
SOURCE_FILES = F.SOURCE_FILES | {f"scripts/integration/{folder}/{name}" for folder, names in {
    "qt612_full_16k_preflight": ("package_actor.py", "package_media.py", "package_execution.py", "package_guest.py",
                                  "package_metadata.py"),
    "qt612_gui_16k_link_checkpoint": ("prepare.py",),
    "qt612_installed_16k_preflight": ("actor.py", "owned.py", "guest.py", "loader_probe.py", "observer.py",
                                      "preflight.py", "worker.py"),
    "llhttp_overlay583": ("operands.py",),
    "fish_config_overlay583": ("guest.py",),
}.items() for name in names}
SOURCE_FILES |= {
    "scripts/port/qt612-gui-native-v1/trust.py",
} | {f"packages/port/qt612-gui-server-source-reference/{name}" for name in P.RECIPE_INPUTS}


def clone_id(case, clone, plan_nonce):
    C.need(case in CASES and F.Q.NONCE.fullmatch(clone) and clone[:8] != "00000000"
           and (clone == plan_nonce if case == "main" else clone[:8] != plan_nonce[:8]),
           "Fresh case-specific installed guest identity required")


def volume_uuid(label, clone):
    return str(uuid5(NAMESPACE_URL, f"cachy-asahi/qtbase-installed/{label}/{clone}"))


def source_manifest(records):
    return "".join(f"{pin['sha256']}  {name}\n" for name, pin in sorted(records.items())).encode()


def role(plan_nonce, case, clone, manifest_sha, plan_sha, signed_sha, signature_sha, epoch):
    clone_id(case, clone, plan_nonce)
    C.need(all(type(value) is str and C.SHA.fullmatch(value)
               for value in (manifest_sha, plan_sha, signed_sha, signature_sha))
           and type(epoch) is int and 10 ** 8 <= epoch < 10 ** 12, "Finite installed guest boot operands required")
    data_uuid = volume_uuid("operands", clone)
    result_uuid = F.P.result_uuid(clone)
    fields = dict(nonce=plan_nonce, case=case, clone=clone, manifest=manifest_sha, plan=plan_sha,
                  selection=signed_sha, signature=signature_sha, data_uuid=data_uuid, result_uuid=result_uuid,
                  deadline=QEMU_SECONDS - 180)
    append = F.P.boot_cmdline(clone, BOOT_DIR + "/guest-init.sh")
    append += "".join(f" cachy_qt_install_{key}={value}" for key, value in fields.items())
    append += f" arm16k_rtc_host_epoch={epoch}"
    argv = F.P.vm_argv("/inputs/Image", append, "qtbase-installed-" + clone, (
        ("boot", "file=/inputs/boot.raw,format=raw,readonly=on"),
        ("scratch", "file=/out/overlay.qcow2,format=qcow2,readonly=off,discard=ignore"),
        ("operands", "file=/inputs/operands.raw,format=raw,readonly=on"),
        ("result", "file=/out/result.raw,format=raw,readonly=off"),
    ))
    argv[argv.index("-m") + 1] = str(GUEST_BYTES >> 20)
    return dict(nonce=clone, data_uuid=data_uuid, result_uuid=result_uuid, qemu_argv=argv)


def load_media(raw, media_sha):
    media = C.json_body(raw, canonical=True)
    C.need(C.pin(raw)["sha256"] == media_sha and media.keys() == {
        "kind", "authority", "case", "clone", "plan", "selection", "handoff", "retirement", "source",
        "runner", "inputs", "result", "signature", "boot_manifest", "boot_payload",
    } and media["kind"] == MEDIA_KIND and media["authority"] is None,
        "Exact unissued installed media descriptor required")
    for leaf, bound in (("plan", 64 << 10), ("selection", W.MAX_SELECTION), ("handoff", 16 << 10),
                        ("retirement", 16 << 10), ("signature", W.INPUT_LIMITS["signature"])):
        C.need(C.check_pin(media[leaf], bound) and media[leaf]["bytes"] > 0, "Bounded installed media control required")
    pins = media["inputs"]
    C.need(pins.keys() == {"Image", "scratch.raw", "operands.raw", "boot.raw"}
           and pins["Image"] == F.LOWER["Image"] and pins["scratch.raw"] == P.Q3_SCRATCH
           and all(C.check_pin(pin, size) and pin["bytes"] == size for pin, size in (
               (pins["boot.raw"], F.Q.BOOT_BYTES), (pins["operands.raw"], DATA_BYTES),
               (media["result"], RESULT_BYTES))), "Exact installed guest carrier geometry required")
    C.need(media["boot_payload"].keys() == set(BOOT_FILES)
           and all(C.check_pin(pin, 128 << 10) and pin["bytes"] > 0 for pin in media["boot_payload"].values())
           and media["boot_manifest"] == media["boot_payload"]["MANIFEST.sha256"]["sha256"],
           "Exact installed boot payload required")
    F.Q.runner_shape(media["runner"])
    C.need(C.pin(C.wire(media["runner"])) == F.RUNNER_PIN and media["source"].keys() == SOURCE_FILES
           and all(C.check_pin(pin, 128 << 10) and pin["bytes"] > 0 for pin in media["source"].values()),
           "Exact installed source set and local runner profile required")
    C.need(media["boot_payload"]["source.sha256"] == C.pin(source_manifest(media["source"])),
           "Guest source payload must equal the actor source selection")
    return media


def read_authority(raw, digest, media, media_sha, *, site_sha=None, now=None):
    authority = C.json_body(raw, canonical=True)
    start, end = authority["created_utc"], authority["expires_utc"]
    selected_site = authority["site_sha256"]
    expected = dict(kind=AUTH_KIND, issuer="Root", approved=True, scope=P.SCOPE,
                    case=media["case"], clone=media["clone"], media_sha256=media_sha,
                    site_sha256=selected_site, created_utc=start, expires_utc=end)
    C.need(C.pin(raw)["sha256"] == digest and C.wire(expected) == raw
           and type(selected_site) is str and C.SHA.fullmatch(selected_site)
           and (site_sha is None or selected_site == site_sha)
           and type(start) is type(end) is int and 0 < end - start <= 3600
           and (now is None or start <= now < end), "Current exact installed guest authority required")
    return authority


def verify_controls(stage, media, *, now):
    raw = T.read(stage / "PLAN.json", media["plan"], cap=64 << 10)
    inventory = T.read(stage / "expected356.lock", P.Q3_INVENTORY, cap=16 << 10)
    plan = W.read_plan(raw, media["plan"]["sha256"], inventory)
    clone_id(media["case"], media["clone"], plan["nonce"])
    signed = T.read(stage / "SELECTION.json", media["selection"], cap=W.MAX_SELECTION)
    selection = W.read_selection(signed, media["selection"]["sha256"], media["plan"]["sha256"], now)
    W.check_payload_selection(plan, selection["payload"])
    W.check_provider_selection(inventory, selection["providers"])
    handoff = T.decode(T.read(stage / "PACKAGE-HANDOFF.json", media["handoff"], cap=16 << 10))
    post_raw = T.read(stage / "PACKAGE-RETIREMENT.json", media["retirement"], cap=16 << 10)
    post = T.decode(post_raw)
    C.need(handoff["kind"] == "QTBASE16K_UNSIGNED_ARCHIVE_HANDOFF_V1"
           and handoff["status"] == "PASS_UNSIGNED_ARCHIVE_FOR_TEST_REVIEW" and handoff["authority"] is None
           and handoff["archive"] == selection["inputs"]["archive"]
           and handoff["packaging_receipt"] == selection["packaging_receipt"]
           and handoff["package_retirement"] == media["retirement"] and handoff["package_actor"] == post["actor_result"]
           and handoff["package_nonce"] == post["nonce"] and post["kind"] == "QTBASE16K_PACKAGE_POST_SCOPE_V1"
           and post["scope"] == M.W.SCOPE and C.SHA.fullmatch(post["cid"]) and type(post["exit_code"]) is int
           and post["exit_code"] == 0 and post["observations"] == [dict(scope_absent=True, container_absent=True)] * 2,
           "Installed selection must join the exact retired package and archive")
    signature = selection["inputs"]["signature"]
    C.need((media["signature"]["bytes"] == signature["bytes"] and media["signature"] != signature)
           if media["case"] == "tampered_signature" else media["signature"] == signature,
           "Detached signature does not match the installed trial case")
    return plan, (post["scope"], post["cid"], post_raw)


def verify_source(source, records):
    base = T.ordinary(source)
    actual = {path.relative_to(base).as_posix() for path in base.rglob("*") if not path.is_dir() or path.is_symlink()}
    C.need(actual == records.keys(), "Exact installed actor source namespace required")
    for name, pin in records.items():
        C.read(base / name, 128 << 10, pin, collect=False)


def boot_role(media):
    return dict(nonce=media["clone"], boot_directory=BOOT_DIR, boot_subdirectories=[],
                boot_payload={name: pin | {"mode": 0o555 if name == "guest-init.sh" else 0o444}
                              for name, pin in media["boot_payload"].items()},
                result_carrier=dict(uuid=F.P.result_uuid(media["clone"])))


def verify_carriers(inputs, media):
    C.need(T.ordinary(inputs) == inputs and {leaf.name for leaf in inputs.iterdir()} == media["inputs"].keys(),
           "Exact installed guest carrier namespace required")
    for name, pin in media["inputs"].items():
        C.need((inputs / name).lstat().st_mode & 0o777 == 0o444, "Expected read-only installed carrier")
        C.read(inputs / name, pin["bytes"], pin, collect=False)
    M.verify_boot(inputs / "boot.raw", boot_role(media))


def terminal(serial, clone):
    prefix = b"QTBASE_INSTALLED16K_TERMINAL "
    matches = [line for line in serial.splitlines() if line.startswith(prefix)]
    C.need(len(matches) == 1, "Exactly one installed guest terminal required")
    row = re.fullmatch(prefix + clone.encode() + rb" (PASS|HOLD)", matches[0])
    C.need(row is not None, "Installed guest terminal identity differs")
    return row[1].decode()
