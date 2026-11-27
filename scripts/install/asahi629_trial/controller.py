#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare and run the isolated 629-package Asahi TEST rehearsal."""

import argparse
from base64 import b64decode
import importlib.util
from itertools import islice
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BASE = HERE.parent / "overlay583_trial"
MAINTENANCE = HERE.parent / "asahi_maintenance_trial"
COLD_ORIGIN = REPO / "scripts/integration/arm16k_systemd_tcg_guest/validation.json"
COLD_BOOT_CONTROLLER = COLD_ORIGIN.with_name("boot.py")
COLD_BOOT_HELPER = COLD_ORIGIN.parent / "frozen/reference_controller.py"
COLD_SOURCE = "b623a99825270a77c57ce7a347504c9220833202"
COLD_TOOL_PARENT = "sha256:c6bd2d0ed8c437a74b3e1713b7bfcb023b7446f1abe3c0d27a6a5b4fd734f925"
COLD_SIGNER = "68B3537F39A313B3E574D06777193F152BDBE6A6"
COLD_LOCK = dict(bytes=1996, sha256="dcc7bbdfeb3c242ffad6ead9378a75e4a2355d5e67c659ba887d7baa20583b66")
CONTROL_NAMES = {"baseline": "guest.raw", "kernel": "Image", "config": "kernel.config"}
CONTROL_STATUS = "PASS_COLD_GENERIC_111_ASSEMBLED_NOT_BOOTED"
CONTROL_FILES = Path("verified-candidate")
COLD_BOOT_STATUS = "PASS_EMULATED_ARM16K_SYSTEMD_SERIAL_PAM_SESSION_ONLY"
COLD_BOOT_RECEIPT = "independent-boot-qualification.json"
COLD_BOOT_FILES = {
    "controller_report": Path("boot/report.json"),
    "serial_redacted": Path("boot/serial.redacted.log"),
    "qemu_retirement": Path("boot/qemu-retirement.json"),
    "embedded_tool_source": Path("stopped-source-readback.json"),
}
COLD_CATALOGS = {
    "core.db": "aec62efbfb59d300204f936a633a59d3c89d6a7e7f94852b8f621b61a253afae",
    "extra.db": "1b4caf18e4a57ba10f201c7b19892bb55a37283c2b0369b39cc6c4f6b654151d",
}
COLD_SELECTOR_PINS = {
    "select_guest.py": "b6458d46d1176b3e1c5064bf5f75a71a9c93c92b6aa712d1b60e76760140a9eb",
    "test_guest.py": "1d5a33d3567e6e9ba01db82ef71553971474e67a13d1dbeb15f99e91730aeee8",
}
KIND = "ROOT_ASAHI629_OFFLINE_TRANSACTION_SELECTION_V1"
HOLD = "HOLD_ASAHI629_CONTROLLER"
ACTOR = "CACHY_ASAHI_629_ACTOR"
GPG = "/usr/bin/gpg"
GPG_PIN = (1189008, "2721faffe5dd60b369a9eea5d09f83d4473ee4c2e45ecb7a20eb508eb4d36888")


def module(path):
    spec = importlib.util.spec_from_file_location("asahi629_" + path.stem, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


M = module(MAINTENANCE / "controller.py")
C, T, B = M.C, M.T, M.B
O = module(HERE / "operands.py")
G = module(HERE / "guest.py")
CANCEL_SOURCE = C.PERL / "frozen/reference_controller.py"


def disjoint(output, paths):
    T.need(all(not output.is_relative_to(path) and not path.is_relative_to(output) for path in paths),
           "Fresh output must be disjoint from every selected input")


def claim_run(output, nonce, authority_digest):
    """Persist an exclusive claim outside the disposable output tree."""
    T.need(re.fullmatch("[a-f0-9]{32}", nonce) and T.HEX.fullmatch(authority_digest),
           "Exact nonce and issued authority digest required")
    path = output.parent / (".asahi629-claim-" + nonce)
    value = T.encoded(dict(nonce=nonce, authority_sha256=authority_digest, output=str(output)))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return dict(file=path.name, pin=T.pin(value))


def prepare(preflight_dir, ownership_receipt, original_transport, test_review, test_review_sha256,
            test_inputs, output):
    """Passively stage the exact reviewed public files."""
    preflight, ownership, transport, review, test = map(
        C.absolute, (preflight_dir, ownership_receipt, original_transport, test_review, test_inputs))
    out = C.absolute(output)
    disjoint(out, (preflight, ownership, transport, review, test))
    value, sources = O.project(T, preflight, ownership, transport, review, test_review_sha256, test)
    disjoint(out, [Path(ref["path"]) for ref in sources.values()])
    O.check_current_trust(T, value, int(time.time()))
    out.mkdir(mode=0o700)
    try:
        for name, ref in sources.items():
            C.checked_copy(Path(ref["path"]), out / O.relative(T, name), O.pin(ref))
        receipt = T.encoded(value)
        manifest = out / "manifest.json"
        manifest.write_bytes(receipt)
        manifest.chmod(0o444)
        O.rehash(T, out, value)
    except BaseException:
        shutil.rmtree(out)
        raise
    return dict(status="PREPARED_ASAHI629_TRANSPORT_DATA_ONLY", path=str(out), manifest=T.pin(receipt),
                test_review=value["test_review"], authority=None, installation="NOT RUN")


def selection():
    paths = {
        "trial.py": BASE / "trial.py",
        "asahi-guest.py": HERE / "guest.py",
        "asahi-guest-base.py": MAINTENANCE / "guest.py",
        "operands.py": HERE / "operands.py",
    }
    pins = {name: T.read(path, cap=128 * 1024, collect=False) for name, path in paths.items()}
    T.need(pins["asahi-guest-base.py"] == G.BASE_PIN, "Exact fixed 626 guest helper required")
    return paths, pins


def source_pins():
    paths, _ = selection()
    extra = {*paths.values(), HERE / "controller.py", MAINTENANCE / "controller.py",
             MAINTENANCE / "operands.py", MAINTENANCE / "bootstrap.py", COLD_ORIGIN, COLD_BOOT_CONTROLLER,
             COLD_BOOT_HELPER, CANCEL_SOURCE}
    return C.source_pins() | {
        str(path.relative_to(REPO)): T.read(path, cap=128 * 1024, collect=False) for path in extra
    }


def tool_pins():
    gpg = C.absolute(GPG)
    mode = gpg.lstat()
    T.need(mode.st_uid == mode.st_gid == 0 and stat.S_IMODE(mode.st_mode) == 0o755,
           "Fixed root-owned actor GnuPG required")
    return C.tool_pins() | {GPG: C.pinned(gpg, GPG_PIN)}


def init_bytes():
    large = {name: G.INITRAMFS_LIMIT for name in G.GENERATED.values()}
    return B.project(T, T.read(BASE / "guest-init.sh", cap=128 * 1024), O.UUID, G.NAMES, large)


def check_retired(row):
    T.need(row["cleanup_errors"] == [] and all(row[key] is True for key in (
        "cleanup_ownership_verified", "owned_container_removed", "owned_container_absence_verified"))
        and re.fullmatch("[a-f0-9]{64}", row["container_id"]), "Independent cold-control container retirement required")


def pin_for(row, relative):
    source = Path(row["path"])
    T.need(source.is_absolute() and ".." not in source.parts and source.parts[-len(relative.parts):] == relative.parts,
           "Unexpected cold readback path: " + str(relative))
    return {key: row[key] for key in ("bytes", "sha256")}


def control_refs(root, expected_digest):
    """Join the relocated cold control to its independent readback and original assembly."""
    historical = T.decode(T.read(COLD_ORIGIN, cap=128 * 1024))
    raw = T.read(root / "independent-readback-PASS.json", cap=128 * 1024)
    readback = T.decode(raw)
    receipt = T.pin(raw)
    T.need(receipt["sha256"] == expected_digest and T.encoded(readback) == raw
           and readback.get("status") == CONTROL_STATUS and readback["reusable_candidate"] is True
           and not readback["exact_historical_warm_raw"] and readback["owned_container_absent_twice"] is True
           and readback["original_inputs_remain_sealed"] is True and readback["stopped_audits_absent_twice"] == 4
           and type(readback["actor_exit"]) is int and readback["actor_exit"] == 0
           and all(readback[name] == "NOT RUN" for name in ("boot", "package_install", "signing"))
           and readback["toolbox"] == historical["tool_image_id"] and readback["source_revision"] == COLD_SOURCE,
           "Exact independently reread and retired cold control receipt required")
    original = Path("assembly-only-receipt.json")
    assembly_pin = pin_for(readback["original_first_readback_hold"], original)
    review = T.decode(T.read(root / original, assembly_pin, cap=128 * 1024))
    T.need(review.get("status") == "HOLD_RETIREMENT_OR_READBACK" and review["assembly_started"] is True
           and type(review["actor_exit"]) is int and review["actor_exit"] == 0
           and review["historical_warm_identity_reproduced"] is False and review["owned_container_absent_twice"] is True
           and all(review[name] == "NOT RUN" for name in ("boot", "package_install", "signing"))
           and review["toolbox"] == readback["toolbox"] and review["parent_toolbox"] == COLD_TOOL_PARENT
           and review["source_revision"] == COLD_SOURCE and review["historical_materials"] == historical["inputs"],
           "Exact original cold assembly provenance required")
    check_retired(review["cleanup"])
    audited = {
        "assemble.py": "opt/arm16k/assemble.py", "guest-proof.sh": "opt/arm16k/guest-proof.sh",
        "package-refs.json": "opt/package-refs.json", "tool-provenance.json": "opt/tool-provenance.json",
    }
    T.need(set(review["stopped_audits"]) == set(audited)
           and set(review["toolbox_embedded_public_source"]) == set(audited.values()),
           "Complete cold toolbox audit required")
    for name, row in review["stopped_audits"].items():
        check_retired(row)
        T.need(row["absent_twice"] is True, "Cold toolbox check must be retired")
        if name in historical["source_pins"]:
            T.need(review["toolbox_embedded_public_source"][audited[name]]["sha256"]
                   == historical["source_pins"][name], "Cold toolbox source differs")

    candidate = readback["candidate"]
    T.need(set(candidate) == {*CONTROL_NAMES.values(), "prepared.json"},
           "Complete independently read cold candidate required")
    refs = {leaf: pin_for(row, CONTROL_FILES / leaf) for leaf, row in candidate.items()}
    manifest_path = CONTROL_FILES / "input-manifest.json"
    manifest_pin = pin_for(readback["manifest"], manifest_path)
    T.need(manifest_pin == review["manifest"] and refs["prepared.json"] == review["prepared"]
           and {leaf: refs[leaf] for leaf in CONTROL_NAMES.values()} == review["files"],
           "Independent cold readback differs from the sealed assembly")
    manifest = T.decode(T.read(root / manifest_path, manifest_pin, cap=128 * 1024))
    prepared = T.decode(T.read(root / CONTROL_FILES / "prepared.json", refs["prepared.json"], cap=128 * 1024))
    signature = manifest["rootfs_signature"].split()
    T.need(manifest["material_files"] == historical["inputs"] and manifest["tool_image_id"] == review["toolbox"]
           and manifest["tool_parent_id"] == COLD_TOOL_PARENT and manifest["schema_version"] == 1
           and signature[:3] == ["[GNUPG:]", "VALIDSIG", COLD_SIGNER] and signature[-1] == COLD_SIGNER
           and manifest["frozen_catalogs"] == COLD_CATALOGS
           and all(manifest["source_pins"].get(name) == pin
                   for name, pin in (historical["source_pins"] | COLD_SELECTOR_PINS).items()),
           "Cold control input and vendor source provenance differs")
    refs, facts = manifest["new_host_packages"], manifest["tool_signature_provenance"]["packages"]
    T.need(len(refs) == len(facts) == 2
           and {row["name"] for row in refs} == {"qemu-system-aarch64", "edk2-aarch64"}
           and all(all(fact[key] == ref[key] for key in ref) and fact["VALIDSIG"].startswith("[GNUPG:] VALIDSIG ")
                   for ref, fact in zip(refs, facts)),
           "Cold control tooling selections differ")
    T.need(prepared["status"] == "PREPARED_NOT_BOOTED" and prepared["VM_boot"] == "NOT RUN"
           and prepared["provenance"] == manifest and prepared["files"] == review["files"],
           "Cold control prepared disk and provenance must join")
    lock = "".join(sorted(f"{row['name']} {row['version']}\n" for row in prepared["base_packages"])).encode()
    T.need(T.pin(lock) == COLD_LOCK, "Exact independently selected cold 111-package inventory required")
    db_path = Path("independent-database-paths.txt")
    db_pin = pin_for(readback["independent_alpm_database"], db_path)
    database = T.read(root / db_path, db_pin, cap=64 * 1024)
    directories = "".join(sorted(row["directory"] + "\n" for row in prepared["base_packages"])).encode()
    T.need(readback["independent_alpm_database"]["package_directories"] == 111 and database == directories,
           "Independent cold ALPM database result differs")
    check_path = Path("independent-e2fsck.log")
    check_pin = pin_for(readback["independent_ext4_check"], check_path)
    fsck = T.read(root / check_path, check_pin, cap=64 * 1024)
    T.need(re.fullmatch(rb"ARM16K_SYSTEMD: [0-9]+/[0-9]+ files \([0-9.]+% non-contiguous\), [0-9]+/[0-9]+ blocks",
                        fsck.splitlines()[-1]), "Independent cold ext4 check result differs")

    files = review["files"]
    T.need(set(files) == set(CONTROL_NAMES.values())
           and all(files[leaf] == historical["inputs"][leaf] for leaf in ("Image", "kernel.config"))
           and files["guest.raw"]["bytes"] == C.REFERENCES["baseline"][0]
           and files["guest.raw"] != historical["prepared_files"]["guest.raw"]
           and files["guest.raw"]["sha256"] != C.REFERENCES["baseline"][1],
           "Fresh cold control disk and original cold kernel/config required")
    references = {name: T.read(root / CONTROL_FILES / leaf, files[leaf], cap=files[leaf]["bytes"], collect=False)
                  for name, leaf in CONTROL_NAMES.items()}
    return dict(receipt=receipt, assembly=assembly_pin, prepared=review["prepared"],
                manifest=manifest_pin, database=db_pin, ext4=check_pin), references


def cold_boot_refs(root, expected_digest, control, assembly, references):
    """Require the separately observed login and retirement for these cold bytes."""
    files = {Path(COLD_BOOT_RECEIPT), *COLD_BOOT_FILES.values()}
    directories = {Path("boot")}
    nodes = {path.relative_to(root): path for path in islice(root.rglob("*"), len(files | directories) + 1)}
    T.need(set(nodes) == files | directories and all(not path.is_symlink() and
           (path.is_dir() if name in directories else path.is_file()) for name, path in nodes.items()),
           "Exact credential-free cold boot evidence directory required")
    raw = T.read(root / COLD_BOOT_RECEIPT, cap=32 * 1024)
    proof = T.decode(raw)
    receipt = T.pin(raw)
    T.need(receipt["sha256"] == expected_digest and T.encoded(proof) == raw
           and set(proof) == {"status", "cold_base", "prepared", "controller", "controller_exit", "actor_toolbox",
                              "historical_warm_raw_reproduced", "no_package_transaction", "signing",
                              "owned_container_absent_twice", "original_and_selected_readonly_operands_rehashed",
                              *COLD_BOOT_FILES}
           and proof["status"] == COLD_BOOT_STATUS and type(proof["controller_exit"]) is int
           and proof["controller_exit"] == 0 and proof["historical_warm_raw_reproduced"] is False
           and proof["signing"] == "NOT RUN" and all(proof[key] is True for key in (
               "no_package_transaction", "owned_container_absent_twice", "original_and_selected_readonly_operands_rehashed"))
           and pin_for(proof["cold_base"], CONTROL_FILES / "guest.raw") == references["baseline"]
           and pin_for(proof["prepared"], CONTROL_FILES / "prepared.json") == assembly["prepared"],
           "Exact independent cold boot PASS for the selected disk and preparation required")
    origin = T.decode(T.read(COLD_ORIGIN, cap=128 * 1024))
    controller = pin_for(proof["controller"], COLD_BOOT_CONTROLLER.relative_to(REPO))
    T.need(proof["actor_toolbox"] == origin["tool_image_id"]
           and controller["sha256"] == origin["source_pins"]["boot.py"],
           "Original bounded cold boot controller and toolbox required")
    T.read(COLD_BOOT_CONTROLLER, controller, cap=128 * 1024)
    pins = {key: pin_for(proof[key], relative) for key, relative in COLD_BOOT_FILES.items()}
    bodies = {key: T.read(root / relative, pins[key], cap=1024 * 1024)
              for key, relative in COLD_BOOT_FILES.items()}
    report = T.decode(bodies["controller_report"])
    retirement = T.decode(bodies["qemu_retirement"])
    check_retired(report)
    T.need(report["status"] == COLD_BOOT_STATUS and report["image_id"] == proof["actor_toolbox"]
           and report["normal_PAM_logout_observed"] is True and report["QMP_quit_requested"] is True
           and report["guest_shutdown"] == "NOT QUALIFIED; QMP emulator quit after logout"
           and all(report[key] == "NOT RUN" for key in ("M2", "native_ARM", "release"))
           and report["QEMU_retirement"] == retirement and type(retirement["exit"]) is int
           and retirement["exit"] == 0 and retirement["passed"] is True and retirement["reaped"] is True
           and retirement["group_census"] == "EMPTY_TWICE" and retirement["ownership"] == "REAPED"
           and retirement["output_complete"] is True and retirement["timeout"] is False
           and retirement["error"] is None and not retirement["signals"] and not retirement["actor_cancelled"]
           and report["runtime"] == dict(NetworkMode="none", ReadonlyRootfs=True, CapDrop=["ALL"], CapAdd=None,
                                         Privileged=False, Devices=[], Memory=3 * 1024**3,
                                         NanoCpus=2_000_000_000, PidsLimit=256),
           "Exact offline cold boot and clean QEMU/PAM retirement required")
    audits = T.decode(bodies["embedded_tool_source"])
    expected = {"vm_actor.py": "vm_actor.py", "owned_process.py": "frozen/owned_process.py"}
    T.need(set(audits) == set(expected), "Complete cold boot source readback required")
    for name, row in audits.items():
        check_retired(row)
        T.need(row["absence_twice"] is True and row["embedded_source"]["sha256"] == origin["source_pins"][expected[name]],
               "Cold boot embedded source or retirement differs")
    T.need(len({report["container_id"], *(row["container_id"] for row in audits.values())}) == 3,
           "Cold boot and stopped source-audit owners must be separate")
    prepared = T.decode(T.read(control / CONTROL_FILES / "prepared.json", assembly["prepared"], cap=128 * 1024))
    T.need(module(COLD_BOOT_CONTROLLER).parse_session(bodies["serial_redacted"], prepared["nonce"]) == report["session"],
           "Original cold guest login proof differs")
    return dict(receipt=receipt, controller=controller, **pins)


def transaction_kernel_refs(root):
    """Select the RTC-capable generic kernel used by the successful R132 trial."""
    return {"transaction_" + name: C.pinned(root / leaf, C.REFERENCES[name])
            for name, leaf in (("kernel", "Image"), ("config", "config"))}


def binding(*, staging, seed, control, control_boot, transaction_kernel, output, nonce, media_digest, control_receipt_sha256,
            control_boot_receipt_sha256, issuer=None):
    paths = {key: C.absolute(value) for key, value in
             dict(staging=staging, seed=seed, control=control, control_boot=control_boot,
                  transaction_kernel=transaction_kernel, output=output).items()}
    T.need(re.fullmatch("[a-f0-9]{32}", nonce) and T.HEX.fullmatch(media_digest)
           and T.HEX.fullmatch(control_receipt_sha256) and T.HEX.fullmatch(control_boot_receipt_sha256)
           and issuer in (None, "Root"), "Exact scope pins required")
    disjoint(paths["output"], [path for key, path in paths.items() if key != "output"])
    raw = T.read(paths["staging"] / "manifest.json", cap=O.PLAN_LIMIT)
    value = T.decode(raw)
    media = T.pin(raw)
    T.need(media["sha256"] == media_digest and T.encoded(value) == raw, "Exact staged 629 manifest required")
    control_provenance, references = control_refs(paths["control"], control_receipt_sha256)
    boot_provenance = cold_boot_refs(paths["control_boot"], control_boot_receipt_sha256,
                                    paths["control"], control_provenance, references)
    references.update(transaction_kernel_refs(paths["transaction_kernel"]))
    O.rehash(T, paths["staging"], value)
    references["seed"] = T.read(paths["seed"], O.SEED, cap=O.SEED["bytes"], collect=False)
    _, files = selection()
    plan = dict(kind=G.BOOT, nonce=nonce, code=files, manifest=media, media=value)
    data = dict(kind=KIND, issuer=issuer, approval_status="UNAPPROVED", nonce=nonce, actor_image=C.ACTOR_IMAGE,
                paths={key: str(path) for key, path in paths.items()}, media=media, control=control_provenance,
                control_boot=boot_provenance,
                plan=T.pin(T.encoded(plan)), init=T.pin(init_bytes()), references=references,
                source=source_pins(), tools=tool_pins())
    O.check_current_trust(T, value, int(time.time()))
    return data, plan


def copy_transport(staging, plan, root):
    media=root/"inputs"
    code=root/"code"
    values=plan["media"]["files"]|{"manifest.json":plan["manifest"]}
    files={}
    for name,ref in values.items():
        C.checked_copy(staging/name,media/name,ref)
        files["inputs/"+name]=ref
    workers,_=selection()
    for leaf,ref in plan["code"].items():
        C.checked_copy(workers[leaf],code/leaf,ref)
        files["code/"+leaf]=ref
    (code/"plan.json").write_bytes(T.encoded(plan))
    files["code/plan.json"]=T.pin(T.encoded(plan))
    aliases={}
    for name,ref in C.runtime_payload(media,root/"runtime").items():
        if isinstance(ref,dict):
            files["runtime/"+name]=ref
        elif isinstance(ref,str):
            aliases["runtime/"+name]=ref
    directories={str(path.relative_to(root)) for path in root.rglob("*") if not path.is_symlink() and path.is_dir()}
    return files,aliases,directories


def export(reader, disk_path, out, *, held):
    with reader.Ext4Reader(disk_path,max_nodes=64,max_file_bytes=G.INITRAMFS_LIMIT) as disk:
        nodes=disk.inventory()["nodes"]
        folders={".","lost+found","evidence"}
        files=set(nodes)-folders
        required={"evidence/"+name for name in ("result.json", "commands.json", "signatures.json", "platform.json",
                                                    "boot-artifacts.json", "trust.json", "cleanup.json",
                                                    "platform-state.json")}
        completed={"evidence/"+name for name in G.NAMES}
        allowed=completed|{"evidence/"+name for name in G.GENERATED.values()}
        T.need(folders<=set(nodes) and all(nodes[name]["type"]=="directory" for name in folders)
               and required<=files<=allowed and (held or completed<=files)
               and sum(nodes[key]["size"] for key in files)<=32*1024**2,"Exact bounded Asahi evidence namespace required")
        out.mkdir(mode=0o700)
        for name in sorted(files):
            row=nodes[name]
            T.need(row["type"]=="file" and row["uid"]==row["gid"]==0 and row["mode"]==0o600
                   and row["links"]==1 and row["size"]<=G.evidence_limit(Path(name).name),
                   "Original guest evidence identity differs")
            fields,raw=disk.inode(row["inode"])
            body=b"".join(disk.chunks(fields,raw))
            T.need(T.pin(body)==dict(bytes=row["size"],sha256=row["sha256"]),"Asahi result reread differs")
            with (out/Path(name).name).open("xb") as stream:
                stream.write(body)


def review(output, plan, *, held):
    result=T.decode(T.read(output/"result.json",cap=128*1024))
    T.need(result["nonce"]==plan["nonce"] and result["plan"]==T.pin(T.encoded(plan))
           and result["approval_status"]=="UNAPPROVED" and result["Root_acceptance"] is None
           and result["M2"]==result["physical_installation"]=="NOT RUN"
           and result["status"]==(G.HOLD if held else G.PASS),"Original exact Asahi development receipt required")
    raw=T.read(output/"commands.json",cap=2*1024**2)
    commands=T.decode(raw)
    seen={row["role"]:row for row in commands}
    expected=G.command_plan(O,plan["media"])
    trust_commands=G.trust_commands(O,plan["media"])
    T.need(raw==T.encoded(commands) and len(commands)==len(seen) and set(seen)<=set(expected)|set(trust_commands),
           "Exact non-repeated 629 transaction and trust commands required")
    actual=[row["role"] for row in commands if row["role"] in expected]
    roles=["query-baseline","check-baseline","preview-forward","apply-forward","query-forward","check-forward",
           "preview-rollback","apply-rollback","query-rollback","check-rollback"]
    T.need(actual==roles[:len(actual)] and (held or actual==roles),"Missing or reordered Asahi transaction commands")
    T.need(all(row["argv"]==expected[role] for role,row in seen.items() if role in expected)
           and (held or all(row["exit"]==0 for row in commands)),"Actual guest command arguments or exits differ")
    M.review_boot_artifacts(output,result,seen,held=held)
    mounted={}
    for name,(count,_,_) in O.REFS.items():
        path=output/name
        if path.is_file():
            mounted[name]=T.canonical_lock(T.read(path,O.lock_ref(name),cap=64*1024),count)
    if not held:
        T.need(set(mounted)==set(O.REFS),"Five original locks required after the declared reverse")
        O.check_delta(T,mounted)
        phases=set(G.SHOW)
        trust=T.decode(T.read(output/"signatures.json",cap=512*1024))
        T.need(set(trust)=={"forward","rollback"},"Both original signature phase receipts required")
        for stage,rows in plan["media"]["packages"].items():
            T.need(set(trust[stage])==set(rows),"All original matching detached signature observations required")
            for name,row in rows.items():
                receipt=trust[stage][name]
                original=b64decode(receipt["original"],validate=True)
                observed=G.signature(T,original,row["signer"])
                T.need(receipt==dict(observed,scope=row["scope"],original=receipt["original"])
                       and observed["status"]==seen["verify-"+stage+"-"+name]["stdout"],
                       "Independent original signed archive evidence differs: "+name)
        platform=T.decode(T.read(output/"platform.json",cap=128*1024))
        T.need(platform==result["platform"] and set(platform)==phases
               and platform["baseline"]==platform["forward"]==platform["rollback"],
               "Preserved Asahi platform output required")
        T.need(result["inventory"]=={name:O.lock_ref(name+".lock") for name in phases}
               and result["previews"]=={name:O.lock_ref(name+"-preview.lock") for name in ("forward","rollback")},
               "Exact physical command inventories and previews required")
        for phase in ("forward","rollback"):
            for stream in ("stdout","stderr"):
                file=output/("apply-"+phase+"."+stream)
                body=T.read(file,seen["apply-"+phase][stream],cap=2*1024**2)
                T.need(not T.HOOK_FAILURE.search(body),"Asahi ALPM hooks did not pass")
        G.log_actions(T,mounted["baseline.lock"],mounted["forward.lock"],mounted["rollback.lock"],
                      T.read(output/"pacman.log",cap=2*1024**2),completed=True)
    G.review_extra(T, O, output, plan, result, seen, held=held)
    result["files"]={path.name:T.read(path,cap=G.evidence_limit(path.name),collect=False) for path in sorted(output.iterdir())}
    return result


class Controller(C.Controller):
    def run_asahi629(self, authority_path, authority_digest):
        C.actor_boundary(self.paths | {"authority": authority_path})
        T.need(os.environ.get(ACTOR) == "1" and sys.flags.isolated and sys.dont_write_bytecode,
               "Explicit isolated 629 rehearsal actor entry required")
        disjoint(self.out, (authority_path, REPO))
        actual, plan = binding(**self.paths, nonce=self.authority["nonce"],
                               media_digest=self.authority["media"]["sha256"],
                               control_receipt_sha256=self.authority["control"]["receipt"]["sha256"],
                               control_boot_receipt_sha256=self.authority["control_boot"]["receipt"]["sha256"],
                               issuer="Root")
        T.need(actual == self.authority, "Exact independently issued 629 authority required")
        headroom = O.SIZE + C.INPUT_SIZE + 2 * actual["references"]["baseline"]["bytes"] + C.RESERVE
        T.need(not self.out.exists() and shutil.disk_usage(self.out.parent).free >= headroom,
               "Fresh private output and selected VM disk headroom required")
        self.runtime = C.module(C.PERL / "runtime.py")
        self.reader = C.module(C.PERL / "frozen/independent_readback.py")
        cancellation = module(CANCEL_SOURCE).Cancellation
        with cancellation() as cancelled:
            nonce = actual["nonce"]
            claim = claim_run(self.out, nonce, authority_digest)
            self.out.mkdir(mode=0o700)
            report = dict(status=HOLD, approval_status="UNAPPROVED", Root_acceptance=None, nonce=nonce, claim=claim,
                          authority_sha256=authority_digest, generic_control=actual["control"],
                          generic_control_boot=actual["control_boot"],
                          seed=actual["references"]["seed"], physical_installation="NOT RUN", M2="NOT RUN")
            try:
                report["host_project_trust"] = self.verify_preview_test(plan["media"])
                guest = self.rehearse(actual, plan, authority_path, authority_digest)
                report.update(guest, transaction_status=guest["status"])
            except (OSError, ValueError, RuntimeError, KeyError, TypeError, KeyboardInterrupt) as failure:
                report["failure"] = dict(category=type(failure).__name__, detail=str(failure)[:1024])
            finally:
                cancelled.cleaning = True
                try:
                    report["cleanup"] = self.retire(nonce)
                except (OSError, ValueError, RuntimeError) as failure:
                    report["status"] = HOLD
                    report["cleanup_failure"] = dict(category=type(failure).__name__, detail=str(failure)[:1024])
                if cancelled.pending:
                    report["status"] = HOLD
                    report["signals"] = cancelled.pending
                with (self.out / "report.json").open("xb") as stream:
                    stream.write(T.encoded(report))
        return report

    def verify_preview_test(self, manifest):
        """Read back the selected TEST certificate and all five signatures in the offline actor."""
        work = self.out / "test-verification"
        home = work / "gnupg"
        work.mkdir(mode=0o700)
        home.mkdir(mode=0o700)
        stage = self.paths["staging"]
        key = manifest["keys"]["preview-test"]
        commands = [GPG, "--batch", "--no-options", "--no-autostart", "--no-auto-key-retrieve",
                    "--homedir", str(home)]
        deadline = time.monotonic() + 120

        def copy(leaf):
            target = work / O.relative(T, leaf)
            C.checked_copy(stage / leaf, target, manifest["files"][leaf])
            return str(target)

        def run(role, *args):
            result = self.runtime.command([*commands, *args], self.out, "project-test-" + role,
                                          seconds=20, deadline=deadline, completed=True,
                                          watched_tree=(self.out, 24 * 1024**3, C.RESERVE))
            return result.stdout

        try:
            run("import", "--import", copy(key["file"]))
            listing = run("keys", "--with-colons", "--fingerprint", "--list-keys")
            G.verify_key_listing(T, manifest["keys"], "project-test", listing)
            secrets = run("secrets", "--with-colons", "--list-secret-keys")
            G.public_only(T, secrets)
            entries = manifest["packages"]["forward"]
            signatures = {}
            for name in sorted(O.PROJECTS):
                leaf = entries[name]["archive"]
                T.need(entries[name]["scope"] == "project-test", "Exact reviewed project TEST scope required")
                status = run(name, "--status-fd", "1", "--verify", copy(leaf + ".sig"), copy(leaf))
                signatures[name] = G.test_signature(T, status, key, int(time.time()))
            valid_at = int(time.time())
            O.check_current_trust(T, manifest, valid_at)
            return dict(verified_at=valid_at, keys=T.pin(listing), secret_keys=T.pin(secrets), signatures=signatures)
        finally:
            shutil.rmtree(work)

    def rehearse(self, actual, plan, authority_path, authority_digest):
        out = self.out
        deadline = time.monotonic() + C.PHASE_BUDGET
        refs = actual["references"]
        control = self.paths["control"]
        candidate = control / CONTROL_FILES
        kernel = self.paths["transaction_kernel"]
        C.checked_copy(kernel / "Image", out / "Image", refs["transaction_kernel"])
        clone = out / "reference.raw"
        self.command("clone-control-root", "cp",
                     ["--sparse=always", "--reflink=never", candidate / "guest.raw", clone], 180, deadline)
        T.read(clone, refs["baseline"], cap=refs["baseline"]["bytes"], collect=False)
        clone.chmod(0o600)
        init = out / "init.selected"
        init.write_bytes(init_bytes())
        script = out / "init.debugfs"
        script.write_text("".join(f"mkdir /{name}\n" for name in C.MOUNTPOINTS)
                          + f"write {init} /{C.BOOT}\nset_inode_field /{C.BOOT} mode 0100755\n"
                          + f"set_inode_field /{C.BOOT} uid 0\nset_inode_field /{C.BOOT} gid 0\n")
        self.command("prepare-control", "debugfs", ["-w", "-f", script, clone], 90, deadline)
        self.command("check-control", "e2fsck", ["-fn", clone], 120, deadline)
        dump = out / "init.readback"
        self.command("read-control-init", "debugfs", ["-R", f"dump /{C.BOOT} {dump}", clone], 30, deadline)
        T.read(dump, actual["init"], cap=128 * 1024)
        nonce = actual["nonce"]
        part = C.partition_boot(clone, out / "boot.raw", nonce)
        clone.unlink()

        packed = out / "input-tree"
        manifest = copy_transport(self.paths["staging"], plan, packed)
        inputs = self.filesystem("inputs", "OV583_INPUT", C.INPUT_SIZE, nonce, deadline, packed)
        C.verify_input(self.reader, inputs, manifest)
        shutil.rmtree(packed)
        inputs.chmod(0o444)
        result = self.filesystem("result", "OV583_RESULT", C.RESULT_SIZE, nonce, deadline)
        scratch = out / "scratch.raw"
        self.command("clone-asahi-target", "cp",
                     ["--sparse=always", "--reflink=never", self.paths["seed"], scratch], 300, deadline)
        T.read(scratch, O.SEED, cap=O.SEED["bytes"], collect=False)
        scratch.chmod(0o600)
        with scratch.open("r+b") as stream:
            stream.truncate(O.SIZE)
        before = {name: T.read(out / name, cap=C.INPUT_SIZE, collect=False) for name in ("Image", "boot.raw", "inputs.raw")}

        host_before = int(time.time())
        G.current_test(T, plan["media"]["keys"]["preview-test"], host_before, remaining=G.TIMEOUT)
        argv = C.qemu_argv(out, nonce, part, actual["plan"]["sha256"], plan["code"]["asahi-guest.py"]["sha256"])
        self.runtime.command(argv, out, "qemu", seconds=G.TIMEOUT, deadline=time.monotonic() + G.TIMEOUT,
                             watched_tree=(out, 24 * 1024**3, C.RESERVE))
        host_after = int(time.time())
        process = self.runtime.receipt(out / "qemu.json")
        T.need(self.runtime.natural(process) and process["argv"] == argv, "Natural owned QEMU retirement required")
        self.require_absent_twice(nonce)
        serial = T.read(out / "qemu.stdout", cap=1024**2)
        held = not C.serial_pass(serial, nonce, lifecycle=True)
        for name, pin in before.items():
            T.read(out / name, pin, cap=C.INPUT_SIZE, collect=False)
        T.need(control_refs(control, actual["control"]["receipt"]["sha256"])
               == (actual["control"], {name: refs[name] for name in CONTROL_NAMES}),
               "Original cold control provenance or bytes changed")
        T.need(cold_boot_refs(self.paths["control_boot"], actual["control_boot"]["receipt"]["sha256"],
                              control, actual["control"], refs) == actual["control_boot"],
               "Original independent cold boot evidence changed")
        T.need(transaction_kernel_refs(kernel) == {name: refs[name] for name in ("transaction_kernel", "transaction_config")},
               "Original R132 RTC kernel or config changed")
        T.read(self.paths["seed"], refs["seed"], cap=O.SEED["bytes"], collect=False)
        T.need(source_pins() == actual["source"] and tool_pins() == actual["tools"],
               "Selected reviewed source or tool bytes changed")
        T.need(T.pin(T.read(authority_path, cap=128 * 1024))["sha256"] == authority_digest, "Root authority changed")
        self.command("check-result", "e2fsck", ["-fn", result], 60, time.monotonic() + 70)
        evidence = out / "evidence"
        export(self.reader, result, evidence, held=held)
        report = review(evidence, plan, held=held)
        if not held:
            times = T.decode(T.read(evidence / "trust.json", report["trust"], cap=128 * 1024))["time"]
            T.need(host_before - 3 <= times["entry"] <= times["seal"] <= host_after + 3,
                   "Guest TEST verification time is outside the observed host QEMU window")
        report.update(qemu=T.read(out / "qemu.json", cap=128 * 1024, collect=False), serial=T.pin(serial),
                      result_disk=T.read(result, cap=C.RESULT_SIZE, collect=False), originals_verified=True,
                      host_realtime=dict(before=host_before, after=host_after))
        return report

    def retire(self, nonce):
        self.require_absent_twice(nonce)
        paths = [self.out / name for name in ("scratch.raw", "reference.raw", "boot.raw", "inputs.raw", "Image")]
        removed = []
        for path in paths:
            if path.exists():
                row = path.lstat()
                T.need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1, "Only owned disposable image artifacts may retire")
                path.unlink()
                removed.append(path.name)
        trees = [self.out / name for name in ("input-tree", "test-verification")]
        for tree in trees:
            if tree.exists():
                T.need(tree.is_dir() and not tree.is_symlink(), "Only owned private trees may retire")
                shutil.rmtree(tree)
                removed.append(tree.name)
        T.need(all(not path.exists() and not path.is_symlink() for path in (*paths, *trees)),
               "Disposable disk and private media retirement required")
        return dict(qemu_absent_twice=True, retired=removed, disposable_media_absent=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    pack = modes.add_parser("prepare-transport")
    for name in ("preflight-dir", "ownership-receipt", "original-transport", "test-review",
                 "test-review-sha256", "test-inputs", "output"):
        pack.add_argument("--" + name, required=True)
    bind = modes.add_parser("bind")
    for name in ("staging", "seed", "control", "control-receipt-sha256", "control-boot", "control-boot-receipt-sha256",
                 "transaction-kernel", "output", "nonce", "media-digest"):
        bind.add_argument("--" + name, required=True)
    run = modes.add_parser("run")
    run.add_argument("--authority", required=True)
    run.add_argument("--authority-sha256", required=True)
    args = vars(parser.parse_args())
    mode = args.pop("mode")
    if mode != "run":
        sys.addaudithook(C.passive_fence)
        value = prepare(**args) if mode == "prepare-transport" else binding(**args)[0]
        print(T.encoded(value).decode(), end="")
        return 0
    path = C.absolute(args["authority"])
    raw = T.read(path, cap=128 * 1024)
    value = T.decode(raw)
    expected = args["authority_sha256"]
    T.need(T.pin(raw)["sha256"] == expected and T.encoded(value) == raw and value["kind"] == KIND
           and value["issuer"] == "Root" and value["approval_status"] == "UNAPPROVED",
           "Exact independently issued Root 629 authority required")
    report = Controller(value).run_asahi629(path, expected)
    print(T.encoded(report).decode(), end="")
    return int(report["status"] != G.PASS)


if __name__ == "__main__":
    raise SystemExit(main())
