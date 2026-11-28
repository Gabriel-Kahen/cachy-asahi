# SPDX-License-Identifier: MIT
"""Stage a boot-pinned Qt checkpoint on copies of the retained Asahi629 workers.

The owner supplies a fresh, unissued Asahi629 plan from the existing binding
and independently reviewed Qt sources and TEST operands. Stage returns the
new plan and transport pins. Insert its code tree and Qt input files while
packing the new transport, and use its PID 1 bytes for the new control disk.
The original 629 transport manifest remains the input to the original review.
After retirement, export_result reads the result disk without mounting it.
"""

import os
from pathlib import Path
import re
from runpy import run_path
import shutil
import subprocess
import tempfile
import time


HERE = Path(__file__).resolve().parent
E = run_path(str(HERE / "export.py"))
GUEST_ENTRY = run_path(str(HERE / "guest_entry.py"))
C, need = E["C"], E["need"]
P = E["R"]["P"]
KIND = "ASAHI629_EXACT_GUEST_PLAN_V1"
LANE = GUEST_ENTRY["LANE"]
WESTON_ARCHIVE = "weston-15.0.1-3-aarch64.pkg.tar.xz"
WESTON_SOURCES = {LANE + name for name in ("weston_fixture.py", "weston_run.py")}
QT_ALARM_NAME = "alarm-public-key.gpg"
MAX_SOURCE = 128 << 10
MAX_PLAN = 512 << 10
BASE = {
    "asahi-guest.py": ("scripts/install/asahi629_trial/guest.py", 21854,
                       "19ce3dafe0b626d5a1b9fe2f4333d50a30f2c22fced4e2c7e026cca793b233a4"),
    "asahi-guest-base.py": ("scripts/install/asahi_maintenance_trial/guest.py", 16922,
                            "2df92fc3d1eadea719b45a7bd4a21dbb3ae414ae2e0f32ae6845e310fe1ac78b"),
    "operands.py": ("scripts/install/asahi629_trial/operands.py", 17512,
                    "b2faea755ac35c59547d5f329cb989d7babf36fe14902693321b0de63a0dead0"),
    "trial.py": ("scripts/install/overlay583_trial/trial.py", 62735,
                 "6d048fb0a943c988a7cfb521d3173a7900932c2704250f0d1f20339474da9b45"),
}
PID1 = C.file_pin(6290, "ce23ab3003fa134de07b9af638c534362a7ab8d3a34ca6ed1c7de2d2936cfc36")
ASAHI_FILES = frozenset({
    "apply-forward.stderr", "apply-forward.stdout", "apply-rollback.stderr", "apply-rollback.stdout",
    "baseline.lock", "boot-artifacts.json", "cleanup.json", "commands.json", "forward-preview.lock",
    "forward.lock", "pacman.log", "platform-state.json", "platform.json", "result.json",
    "rollback-preview.lock", "rollback.lock", "signatures.json", "trust.json",
})
ASAHI_GENERATED = {f"generated-initramfs-{phase}.img" for phase in ("forward", "rollback")}


def replace_once(source, before, after):
    need(source.count(before) == 1, "Exact retained source seam required")
    return source.replace(before, after, 1)


def guest_checkpoint(worker, operands, qt_media):
    checkpoint = f'''
            phase = "qt-provider-checkpoint"
            try:
                checkpoint = pinned_module(GUEST_CODE / "{LANE}guest_entry.py",
                                           selected["code"]["{LANE}guest_entry.py"])
                qt_checkpoint = checkpoint.run_checkpoint(T, O, sys.modules[__name__], selected)
            except Exception as error:
                failure = dict(error_type=type(error).__name__, error=str(error)[:384])
                retained = O.WORK / "qt-replacement-evidence"
                disposition, runtime_pin = None, None
                try:
                    journal = T.read(retained / "transaction.jsonl", cap=128 << 10).splitlines()
                    entry, terminal = T.decode(journal[0]), T.decode(journal[-1])
                    if (entry["phase"] == "entry" and entry["nonce"] == selected["nonce"]
                            and terminal["phase"] == "terminal"):
                        disposition = {{key: value for key, value in terminal.items() if key not in ("phase", "at_ns")}}
                except (OSError, ValueError, KeyError, IndexError, TypeError):
                    pass
                try:
                    runtime_pin = T.read(retained / "runtime-probes.json", cap=2 << 20, collect=False)
                except (OSError, ValueError):
                    pass
                qt_checkpoint = dict(nonce=selected["nonce"], transaction=disposition,
                                     runtime_probe=runtime_pin, failure=failure)
                raise ValueError(f"Qt provider checkpoint failed: {{failure['error_type']}}: {{failure['error']}}") from error
            T.need(qt_checkpoint["nonce"] == selected["nonce"]
                   and qt_checkpoint["transaction"]["status"] == "PASS_QT629_PROVIDER_ROUND_TRIP",
                   "Qt provider checkpoint held: " + qt_checkpoint["transaction"]["status"])
'''.encode("ascii")
    worker = replace_once(worker, b'                query(stage)\n        phase = "seal"\n',
                          b'                query(stage)\n' + checkpoint + b'        phase = "seal"\n')
    worker = replace_once(worker, b"O.rehash(T, O.IN, manifest, observed=observed)",
                          b'O.rehash(T, O.IN, manifest, observed=observed, qt_media=selected["qt_media"])')
    start = b'    commands = command_plan(O, manifest)\n'
    worker = replace_once(worker, start, b'    qt_checkpoint, trust_retired_at_ns = None, None\n' + start)
    cleanup = b'        if not cleanup["completed"] and final == PASS:\n'
    worker = replace_once(worker, cleanup, b'        if cleanup["completed"]:\n'
                          b'            trust_retired_at_ns = time.time_ns()\n' + cleanup)
    result = b'    (evidence / "result.json").write_bytes(T.encoded(result))\n'
    worker = replace_once(worker, result, b'    result.update(qt_checkpoint=qt_checkpoint, '
                          b'trust_retired_at_ns=trust_retired_at_ns)\n' + result)
    operands = replace_once(operands, b"def rehash(T, root, value, observed=None):",
                           b"def rehash(T, root, value, observed=None, *, qt_media=None):")
    extra = f'''
    if qt_media is not None:
        expected = {tuple(sorted(qt_media))!r}
        T.need(type(qt_media) is dict and set(qt_media) == set(expected)
               and not files.keys() & qt_media.keys()
               and all(valid_pin(T, ref, 16 << 20) for ref in qt_media.values()),
               "Exact Qt replacement media files required")
        files |= qt_media
'''.encode("ascii")
    marker = b'    directories = {str(parent) for name in files for parent in Path(name).parents if parent != Path(".")}\n'
    operands = replace_once(operands, marker, extra + marker)
    compile(worker, "asahi-guest.py", "exec")
    compile(operands, "operands.py", "exec")
    return worker, operands


def guest_init(body, *, profile=None):
    allowed = E["actor_files"](profile)
    cases = "\n".join(f"            {name}) limit={cap} ;;" for name, cap in sorted(allowed.items()))
    function = r'''export_qt_evidence() {
    local source=$1 dest=$2 file name metadata links bytes uid gid mode limit
    if [[ ! -e $source && ! -L $source ]]; then return 0; fi
    [[ -d $source && ! -L $source && $(stat -c '%u:%g:%a' -- "$source") == 0:0:700 ]] || return 1
    shopt -s nullglob dotglob
    local -a actual=("$source"/*) census=()
    [[ ${#actual[@]} -le @COUNT@ ]] || return 1
    for file in "${actual[@]}"; do
        name=${file##*/}
        case "$name" in
@CASES@
            *) return 1 ;;
        esac
        [[ -f $file && ! -L $file ]] || return 1
        metadata=$(stat -c '%d %i %h %s %u %g %a %y %z' -- "$file") || return 1
        read -r _ _ links bytes uid gid mode _ <<< "$metadata" || return 1
        [[ $links == 1 && $uid == 0 && $gid == 0 && $mode == 600 && $bytes =~ ^(0|[1-9][0-9]{0,7})$ && $bytes -le $limit ]] || return 1
        census+=("$metadata")
    done
    mkdir -m 0700 "$dest" || return 1
    local index
    for index in "${!actual[@]}"; do
        file=${actual[index]}
        name=${file##*/}
        metadata=${census[index]}
        read -r _ _ _ bytes _ <<< "$metadata" || return 1
        [[ -f $file && ! -L $file && $(stat -c '%d %i %h %s %u %g %a %y %z' -- "$file") == "$metadata" ]] || return 1
        head -c "$((bytes+1))" -- "$file" > "$dest/$name" || return 1
        [[ $(stat -c '%s' -- "$dest/$name") == "$bytes" ]] || return 1
        [[ $(stat -c '%d %i %h %s %u %g %a %y %z' -- "$file") == "$metadata" ]] || return 1
    done
}

'''.replace("@CASES@", cases).replace("@COUNT@", str(len(allowed))).encode("ascii")
    entry = b"[[ $$ == 1 && $# == 0 && $EUID == 0 ]]\n"
    body = replace_once(body, entry, function + entry)
    marker = b"export_evidence /trial-work/evidence /trial-export/evidence\n"
    return replace_once(body, marker, marker + (
        b"phase=qt-evidence-export\n"
        b"export_qt_evidence /trial-work/qt-replacement-evidence /trial-export/qt-replacement-evidence\n"))


def reviewed_media(paths, review, *, profile=None):
    P["choose_review"](profile, review)
    need(type(review) is dict and review.keys() == {"fingerprint", "certificate", "signature", "not_before", "not_after"}
         and type(review["fingerprint"]) is str and re.fullmatch(r"[0-9A-F]{40}", review["fingerprint"])
         and type(review["not_before"]) is type(review["not_after"]) is int
         and 0 < review["not_before"] < review["not_after"], "Exact reviewed Qt TEST selection required")
    original = P["profile_pins"](profile)
    official, project = P["OFFICIAL_NAME"], P["project_name"](profile)
    expected = {
        "rollback.lock": original["rollback_lock"], "result.json": original["rollback_result"],
        official: original["official_archive"], official + ".sig": original["official_signature"],
        project: original["project_archive"], project + ".sig": review["signature"],
        "test-certificate.gpg": review["certificate"],
        QT_ALARM_NAME: original["alarm_public_key"],
    }
    need(type(paths) is dict and paths.keys() == expected.keys()
         and C.check_pin(review["certificate"], 128 << 10) and C.check_pin(review["signature"], 64 << 10)
         and all(pin["bytes"] > 0 for pin in expected.values()), "Exact pinned Qt media input set required")
    pins = {"qt-replacement/" + name: pin for name, pin in expected.items()}
    bodies = {"inputs/qt-replacement/" + name: C.read(paths[name], pin["bytes"], pin)[0]
              for name, pin in expected.items()}
    return bodies, pins


def verify_qt_test(directory, review, *, profile=None):
    """Verify the exact selected archive and detached signature using public data only."""
    tx = run_path(str(HERE / "transaction.py"))
    review = tx["checked_review"](review)
    P["choose_review"](profile, review)
    archive = directory / P["project_name"](profile)
    with tempfile.TemporaryDirectory(prefix="qt629-test-verify-") as folder:
        keyring = Path(folder)
        certificate, body = tx["certificate"](directory / "test-certificate.gpg", review, keyring)
        command = ["/usr/bin/gpg", "--batch", "--no-options", "--no-autostart", "--no-auto-key-retrieve",
                   "--homedir", folder, "--import"]
        imported = subprocess.run(command, env=tx["A"]["ENV"], input=body, capture_output=True, timeout=30)
        need(imported.returncode == 0, "Could not import the reviewed Qt TEST public certificate")
        verification = dict(archive=P["profile_pins"](profile)["project_archive"], signature=review["signature"],
                            fingerprint=review["fingerprint"])
        detached, status = tx["signature"](archive, tx["PROJECT"], verification, keyring)
    created, expires = E["R"]["signature_status"](status, review["fingerprint"])
    observed = int(time.time())
    need(review["not_before"] <= created <= observed < review["not_after"] and (expires == 0 or observed < expires),
         "Qt TEST detached signature is outside its reviewed certificate window")
    return dict(certificate=certificate, signature=detached, verified_at=observed)


def stage(*, retained_source, retained_init, qt_source, qt_source_pins, baseline_plan,
          project_review, media_paths, wayland_socket, output, weston=None, profile=None):
    """Publish an isolated stage and return the exact new input-tree manifest delta."""
    base_pins = {name: C.file_pin(size, sha256) for name, (_, size, sha256) in BASE.items()}
    need(type(baseline_plan) is dict and baseline_plan.keys() == {"kind", "nonce", "code", "manifest", "media"}
         and baseline_plan["kind"] == KIND and baseline_plan["code"] == base_pins
         and type(baseline_plan["nonce"]) is str and re.fullmatch(r"[0-9a-f]{32}", baseline_plan["nonce"])
         and C.pin(C.wire(baseline_plan["media"])) == baseline_plan["manifest"], "Exact unissued base plan required")
    need(wayland_socket is None or type(wayland_socket) is str and len(wayland_socket) <= 107
         and re.fullmatch(r"/run/(?:[A-Za-z0-9_.-]+/)*wayland-[0-9]+", wayland_socket)
         and not {".", ".."}.intersection(wayland_socket.split("/")), "Invalid selected Wayland socket")
    need(type(qt_source_pins) is dict and qt_source_pins.keys() == GUEST_ENTRY["SOURCES"],
         "Exact reviewed Qt source allowlist required")
    base = {name: C.read(retained_source / relative, MAX_SOURCE, base_pins[name])[0]
            for name, (relative, _, _) in BASE.items()}
    qt = {name: C.read(qt_source / name, MAX_SOURCE, pin)[0] for name, pin in qt_source_pins.items()}
    need(all(qt.values()), "Empty Qt source is not a boot worker")
    media, qt_media = reviewed_media(media_paths, project_review, profile=profile)
    if weston is not None:
        need(type(weston) is dict and weston.keys() == {WESTON_ARCHIVE, WESTON_ARCHIVE + ".sig"}
             and WESTON_SOURCES <= qt_source_pins.keys() and wayland_socket == "/run/qt629-wl/wayland-0",
             "Weston media needs the integrated and pinned guest supervisor")
        for name, row in weston.items():
            limit = (64 << 10) if name.endswith(".sig") else (16 << 20)
            need(type(row) is dict and row.keys() == {"path", "bytes", "sha256"}, "Expected reviewed Weston input pin")
            key = "qt-replacement/" + name
            pin = C.file_pin(row["bytes"], row["sha256"])
            need(C.check_pin(pin, limit) and pin["bytes"] > 0, "Invalid reviewed Weston input size or digest")
            media["inputs/" + key], qt_media[key] = C.read(Path(row["path"]), limit, pin)
    predecessor = C.json_body(media["inputs/qt-replacement/result.json"])
    need(baseline_plan["nonce"] != predecessor["nonce"], "Fresh Qt checkpoint nonce required")
    base["asahi-guest.py"], base["operands.py"] = guest_checkpoint(base["asahi-guest.py"], base["operands.py"], qt_media)
    code_bodies = base | qt
    code = {name: C.pin(body) for name, body in code_bodies.items()}
    plan = baseline_plan | {"code": code, "qt_media": qt_media,
                            "qt_replacement": {"project_review": project_review, "wayland_socket": wayland_socket}}
    if profile is not None:
        plan["qt_replacement"]["parity_profile"] = profile
    plan_bytes = C.wire(plan)
    need(len(plan_bytes) <= MAX_PLAN, "Extended guest plan exceeds the boot size limit")
    init = guest_init(C.read(retained_init, PID1["bytes"], PID1)[0], profile=profile)
    files = {"code/" + name: body for name, body in code_bodies.items()} | {"code/plan.json": plan_bytes} | media
    with E["directory"](output.parent) as parent:
        meta = os.fstat(parent)
        need(output.is_absolute() and output.parent.resolve(strict=True) == output.parent and output.name
             and meta.st_uid == os.getuid() and not meta.st_mode & 0o022, "Protected fresh stage parent required")
        temp = Path(tempfile.mkdtemp(prefix=".qt629-stage.", dir=output.parent))
        try:
            for name, body in (files | {"guest-init.sh": init}).items():
                path = temp / name
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with path.open("xb") as stream:
                    stream.write(body)
                    stream.flush()
                    os.fchmod(stream.fileno(), 0o400)
                    os.fsync(stream.fileno())
            E["publish"](parent, temp.name, output.name)
            os.fsync(parent)
        finally:
            if temp.exists():
                shutil.rmtree(temp)
    return dict(kind="QT629_HOST_STAGE_UNISSUED_V1", authority=None, path=str(output),
                plan=C.pin(plan_bytes), init=C.pin(init), worker=code["asahi-guest.py"],
                files={name: C.pin(body) for name, body in files.items()})


def checkpoint_observations(asahi, qt, *, held, profile=None):
    if "result.json" not in asahi:
        need(held, "Completed Qt result requires the Asahi owner result")
        return None, None
    owner = C.json_body(asahi["result.json"], canonical=True)
    names = {"qt_checkpoint", "trust_retired_at_ns"}
    if not owner.keys() & names:
        need(held, "Completed Qt result requires checkpoint and trust retirement observations")
        return None, None
    need(names <= owner.keys(), "Incomplete Qt checkpoint and trust retirement observations")
    checkpoint, stamp = (owner[name] for name in ("qt_checkpoint", "trust_retired_at_ns"))
    if stamp is not None:
        raw = asahi.get("cleanup.json")
        need(type(stamp) is int and 0 < stamp < 2**63 and raw is not None and owner["cleanup"] == C.pin(raw),
             "Trust retirement time must bind the original cleanup evidence")
        cleanup = C.json_body(raw, canonical=True)
        need(cleanup == dict(completed=True, target_submounts=[],
                             keyrings=dict.fromkeys(E["R"]["TRUST_HOMES"], "removed")) and cleanup["completed"] is True,
             "Trust retirement time requires retired keyrings and target submounts")
    if checkpoint is not None:
        keys = {"nonce", "transaction", "runtime_probe"}
        need(type(checkpoint) is dict and checkpoint.keys() in (keys, keys | {"failure"})
             and checkpoint["nonce"] == owner["nonce"], "Expected the structured checkpoint for this guest nonce")
        probe = qt.get("runtime-probes.json")
        pinned = checkpoint["runtime_probe"]
        need(pinned is None or C.check_pin(pinned, 2 << 20)
             and (probe is None and held or probe is not None and C.pin(probe) == pinned),
             "Checkpoint runtime evidence pin differs from the stopped disk")
        if checkpoint["transaction"] is not None and qt.get("transaction.jsonl"):
            if profile is not None:
                entry = C.json_body(qt["transaction.jsonl"].splitlines()[0])
                need(entry.get("parity_profile") == C.pin(C.wire(profile)),
                     "Stopped guest journal differs from the selected parity profile")
            last = C.json_body(qt["transaction.jsonl"].splitlines()[-1])
            when, phase = last.pop("at_ns"), last.pop("phase")
            need(phase == "terminal" and last == checkpoint["transaction"] and type(when) is int
                 and 0 < when < 2**63 and (stamp is None or when < stamp),
                 "Checkpoint disposition or trust retirement disagrees with the terminal journal")
        if profile is not None and checkpoint["transaction"] is not None:
            restored_pin = checkpoint["transaction"].get("restored_runtime_probe")
            restored = qt.get(E["R"]["RESTORED_REPORT"])
            need((held and restored_pin is None) or (restored is not None and C.pin(restored) == restored_pin),
                 "Restored runtime evidence pin differs from the stopped disk")
    need(held or stamp is not None and checkpoint is not None and qt.get("transaction.jsonl")
         and checkpoint["runtime_probe"] is not None
         and checkpoint["transaction"]["status"] == "PASS_QT629_PROVIDER_ROUND_TRIP",
         "Completed Qt result requires the checkpoint PASS and witnessed cleanup")
    return checkpoint, stamp


def export_result(disk_path, disk_pin, bundle, *, held, originals=None, test_inputs=None, asahi_bundle=None,
                  expected_nonce=None, profile=None):
    """Validate both result namespaces, then publish separate inert readback bundles."""
    need(type(held) is bool, "Expected explicit outer hold observation")
    before = C.identity(disk_path.lstat())
    allowed = E["actor_files"](profile)
    present, qt = E["actor_bodies"](disk_path, disk_pin, expected_nonce=expected_nonce, profile=profile)
    asahi = {}
    with C.ext4_reader()(disk_path, max_nodes=64, max_file_bytes=E["MAX_NODE_BYTES"]) as disk:
        need(C.identity(os.fstat(disk.fd)) == before, "Stopped result disk changed before Asahi evidence check")
        nodes = disk.inventory()["nodes"]
        if "evidence" in nodes:
            folder = nodes["evidence"]
            need(folder["type"] == "directory" and folder["uid"] == folder["gid"] == 0 and folder["mode"] == 0o700
                 and not folder["xattrs"], "Unexpected Asahi629 evidence directory identity")
        members = {path.removeprefix("evidence/"): row for path, row in nodes.items() if path.startswith("evidence/")}
        need(members.keys() <= ASAHI_FILES | ASAHI_GENERATED and (not members or "evidence" in nodes)
             and (held or ASAHI_FILES <= members.keys() and qt.keys() == allowed.keys()),
             "Unexpected or incomplete Asahi629/Qt result namespace")
        need(sum(row["size"] for row in members.values()) <= 32 << 20, "Asahi629 result evidence exceeds total cap")
        for name, row in members.items():
            limit = (14 if name in ASAHI_GENERATED else 8) << 20
            need(row["type"] == "file" and row["uid"] == row["gid"] == 0 and row["mode"] == 0o600
                 and row["links"] == 1 and not row["xattrs"] and 0 <= row["size"] <= limit,
                 "Unexpected Asahi629 evidence member: " + name)
            fields, raw = disk.inode(row["inode"])
            body = b"".join(disk.chunks(fields, raw))
            need(C.pin(body) == C.file_pin(row["size"], row["sha256"]), "Asahi629 evidence body changed: " + name)
            asahi[name] = body
        need(C.identity(os.fstat(disk.fd)) == before, "Stopped result disk changed during Asahi evidence check")
    need(C.identity(disk_path.lstat()) == before, "Stopped result disk pathname changed")
    profile_arg = {"profile": profile} if profile is not None else {}
    checkpoint, stamp = checkpoint_observations(asahi, qt, held=held, **profile_arg)
    original_bodies, test_bodies = E["reviewed_bodies"](originals, test_inputs, **profile_arg)
    need(all(qt[name] == test_bodies[name] for name in qt.keys() & test_bodies.keys()),
         "Guest evidence differs from reviewed TEST operand")
    evidence = test_bodies | qt
    E["write_bundle"](bundle, evidence, original_bodies)
    if asahi_bundle is not None:
        E["write_bundle"](asahi_bundle, asahi, {})
    return dict(result_disk=disk_pin, actor_directory_present=present,
                missing_actor_files=sorted(allowed.keys() - qt.keys()),
                missing_asahi_files=sorted(ASAHI_FILES - asahi.keys()),
                qt_checkpoint=checkpoint, trust_retired_at_ns=stamp,
                original_inputs={name: C.pin(body) for name, body in original_bodies.items()},
                evidence={name: C.pin(body) for name, body in evidence.items()},
                asahi={name: C.pin(body) for name, body in asahi.items()})
