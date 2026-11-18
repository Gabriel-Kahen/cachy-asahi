# SPDX-License-Identifier: MIT
"""Opt-in private job-local Source207 backend custody and passive package replay."""
import argparse
import os
from pathlib import Path
import re
import sys
import tarfile
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parent))
import backend_stage_review as review
import reader_current_v3_source207 as reader

C, T, S = review.C, review.T, review.S
MODE = "private-same-job"
SELECTION = "ROOT_SOURCE207_PRIVATE_BACKEND_SNAPSHOT_V1"
CONTENTS = {
    "capsule": ("evidence/public/delegated-backend-public-v4.tar.gz", "backend.capsule.tar.gz", reader.MAX_COMPRESSED),
    "manifest": ("evidence/public/delegated-backend-public-v4/retention-manifest.json", "retention-manifest.json", T.MIB),
    "owner": ("evidence/owner-result.json", None, T.MIB),
    "executor": ("executor-report.json", None, T.MIB),
}
LAUNCHER = "public/launcher-report.json"
SUPPORT = frozenset({"inputs", "runtime", "domain_qualification", "image_qualification", "command_observations",
                     "completion", "component_enrollment", "component_first-login", *reader.BASE_METADATA_PINS,
                     *reader.PREREQUISITE_SUPPORT, *reader.MATERIAL_RUNTIME_SUPPORT})
CAP = 32 * T.MIB


def exact_binding(value):
    T.fields(value, ("source", "ref", "run", "job", "attempt", "source_lock"))
    T.matches(value, {"source": S.CID, "ref": S.REF, "attempt": 1, "source_lock": S.SOURCE["source_map"]},
              "HOLD_SOURCE207_BACKEND_BINDING")
    C.need(all(type(value[k]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value[k]) for k in ("run","job")),
           "HOLD_SOURCE207_BACKEND_BINDING")
    return value


def private_directory(path):
    C.need(path.is_absolute() and path.resolve(strict=True) == path and path.is_dir()
           and not path.stat().st_mode & 0o077 and path.stat().st_uid == os.getuid() > 0,
           "HOLD_SOURCE207_PRIVATE_BACKEND_ROOT")


def disjoint(a, b):
    return a != b and not a.is_relative_to(b) and not b.is_relative_to(a)


def validate_snapshot(operands, binding, nonce):
    capsule, manifest_raw, owner_raw, executor_raw = (operands[k] for k in CONTENTS)
    manifest, owner, executor = (T.untrusted_json(raw, canonical=True) for raw in (manifest_raw,owner_raw,executor_raw))
    for record in (manifest,owner,executor):
        T.final(record)
    T.matches(manifest, {"schema":4,"kind":"DELEGATED_CURRENT_STAGE_RETENTION_V4",
                         "issuer":"DELEGATED_RETENTION_PROGRAM_V4","operation":C.OPERATION,
                         "stage":"backend","binding":binding,"nonce":nonce,"holds":[],"evidence_state":"COMPLETE"},
              "HOLD_SOURCE207_BACKEND_MANIFEST")
    T.matches(owner, {"status":"DELEGATED_OWNER_RETURNED_DATA_ONLY","binding":binding}, "HOLD_SOURCE207_BACKEND_OWNER")
    result = owner["result"]
    T.final(result)
    retained = {"evidence_state":"COMPLETE","capsule_pin":C.pin(capsule),"manifest_pin":C.pin(manifest_raw)}
    T.matches(result, {"completed":True,"status":"DELEGATED_PRIVATE_STAGE_AND_PUBLIC_RETENTION_COMPLETE",
                       "binding":binding,"stage":"backend","nonce":nonce,
                       "stage_report_pin":manifest["stage_report_pin"],"retention":retained},
              "HOLD_SOURCE207_BACKEND_OWNER_RETENTION")
    T.matches(executor, {"status":"DELEGATED_OWNED_STAGE_RETIRED_DATA_ONLY","binding":binding,"owner":owner,
                         "delegation_pin":manifest["delegation_pin"]}, "HOLD_SOURCE207_BACKEND_EXECUTOR")
    cleanup=executor["cleanup"]
    T.matches(cleanup, {"owned_storage_absent":True,"errors":[]}, "HOLD_SOURCE207_BACKEND_CLEANUP")
    T.fields(cleanup["services"], ("owner", "daemon"))
    for row in cleanup["services"].values():
        T.matches(row, {"natural": True, "empty_twice": True}, "HOLD_SOURCE207_BACKEND_CLEANUP")
    # Apply the existing independent Reader's bounded capsule and strict origin rules.
    origins = {name: {"original":value["pin"],"projection":manifest["files"][name]}
               for name,value in manifest["origins"].items()}
    expected={"stage":"backend","source":{"retention":reader.BASE_RETENTION_PIN},
              "binding":binding,"nonce":nonce,"capsule_pin":C.pin(capsule),"origin_pins":origins,
              **{k:manifest[k] for k in ("delegation_pin","context_pin","stage_report_pin","image_report_pin")}}
    files, parsed = reader.delegated_capsule_files(capsule, expected)
    C.need(parsed == manifest and files["retention-manifest.json"] == manifest_raw, "HOLD_SOURCE207_BACKEND_CAPSULE_MANIFEST")
    return result


def snapshot(selection, *, mode=None):
    """The default selects only the original control ZIP and opens no private files."""
    if mode is None:
        return dict(status="SOURCE207_PUBLIC_CONTROL_ONLY", files=None, **C.FINAL)
    C.need(mode == MODE, "HOLD_SOURCE207_BACKEND_MODE")
    T.fields(selection, ("schema","kind","issuer","approved","binding","nonce","owner_root","private_root",
                         "control_root","expected"))
    T.matches(selection, {"schema":1,"kind":SELECTION,"issuer":"Root","approved":True},
              "HOLD_SOURCE207_BACKEND_SNAPSHOT_SELECTION")
    binding = exact_binding(selection["binding"])
    nonce=selection["nonce"]
    C.need(C.hexid(nonce,64), "HOLD_SOURCE207_BACKEND_NONCE")
    owner, private, control = (Path(selection[k]) for k in ("owner_root","private_root","control_root"))
    private_directory(private)
    C.need(owner.is_absolute() and owner.resolve(strict=True) == owner and owner.is_dir() and
           owner.name == f"cachy-current-{nonce}" and control.is_absolute() and control.resolve(strict=True) == control
           and control.name == f"cachy-current-hosted-{nonce}" and (control/"public").is_dir()
           and (control/"public").resolve(strict=True) == control/"public"
           and all(disjoint(a,b) for a,b in ((private,owner),(private,control),(owner,control))),
           "HOLD_SOURCE207_BACKEND_PRIVATE_DESTINATION")
    destination=private/"backend-handoff"
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    T.fields(selection["expected"], (*CONTENTS, "launcher"))
    launcher_pin = C.whole(selection["expected"]["launcher"], T.MIB)
    launcher_raw = T.read_local(str(control/LAUNCHER), launcher_pin["bytes"])
    C.need(C.pin(launcher_raw) == launcher_pin, "HOLD_SOURCE207_BACKEND_LAUNCHER_PIN")
    launcher = T.untrusted_json(launcher_raw, canonical=True)
    T.final(launcher)
    T.matches(launcher, {"status": "DELEGATED_HOSTED_CONTROLLER_RETIRED_DATA_ONLY", "binding": binding,
                         "cleanup": {"owned_storage_absent": True, "error_count": 0},
                         "material_domain_cleanup": T.CLOSED}, "HOLD_SOURCE207_BACKEND_LAUNCHER")
    T.matches(launcher.get("controller_retirement"), review.RETIRED, "HOLD_SOURCE207_BACKEND_LAUNCHER")
    T.matches(launcher.get("scope_absence"), {"scope": f"cachy-current-controller-{nonce}.scope",
                                             "empty_twice": True}, "HOLD_SOURCE207_BACKEND_LAUNCHER")
    data={}
    for role,(relative,_,cap) in CONTENTS.items():
        expected=C.whole(selection["expected"][role],cap)
        body=T.read_local(str(owner/relative),expected["bytes"])
        C.need(C.pin(body)==expected, "HOLD_SOURCE207_BACKEND_OPERAND_PIN")
        data[role]=body
    completion=validate_snapshot(data,binding,nonce)
    payload={name:data[role] for role,(_,name,_) in CONTENTS.items() if name is not None}
    payload["owner-completion.data.json"]=C.encoded(completion)
    transfer=dict(status="SOURCE207_PRIVATE_BACKEND_HANDOFF_DATA_ONLY",mode=MODE,binding=binding,nonce=nonce,
                  files={name:C.pin(raw) for name,raw in payload.items()}, original_private_operands=selection["expected"],
                  stage_replayed=False,first_usable_login_ready=False,**C.FINAL)
    payload["handoff.json"]=C.encoded(transfer)
    with TemporaryDirectory(prefix=".source207-backend-",dir=private) as temporary:
        staged=Path(temporary)/"handoff"
        staged.mkdir(mode=0o700)
        for name,body in payload.items():
            with (staged/name).open("xb") as stream:
                stream.write(body)
            (staged/name).chmod(0o400)
            C.need(T.read_local(str(staged/name),len(body))==body,"HOLD_SOURCE207_BACKEND_STAGED_BYTES")
        destination.mkdir(mode=0o700)
        try:
            staged.rename(destination)
        except OSError:
            destination.rmdir()
            raise
    return dict(transfer, path=str(destination), transfer_pin=C.pin(payload["handoff.json"]))


def replay(root, transfer_pin, *, expected_raw, expected_pin, source_files, support_refs, now):
    """Run the unchanged Source207 Reader with independently selected whole Root operands."""
    private_directory(root)
    C.need(type(expected_raw) is bytes and C.pin(expected_raw) == C.whole(expected_pin, T.MIB),
           "HOLD_SOURCE207_BACKEND_ROOT_SELECTOR_PIN")
    expected = T.untrusted_json(expected_raw, canonical=True)
    T.matches(expected, {"schema": 4, "kind": "ROOT_BOUND_DELEGATED_PUBLIC_READER_V4", "stage": "backend"},
              "HOLD_SOURCE207_BACKEND_ROOT_SELECTOR")
    raw=T.read_local(str(root/"handoff.json"),C.MAX_BYTES)
    C.need(C.pin(raw)==C.whole(transfer_pin), "HOLD_SOURCE207_BACKEND_TRANSFER_PIN")
    record=C.decode(raw)
    T.final(record)
    T.matches(record, {"status":"SOURCE207_PRIVATE_BACKEND_HANDOFF_DATA_ONLY","mode":MODE,
                       "binding":exact_binding(expected["binding"]),"nonce":expected["nonce"],
                       "stage_replayed":False,"first_usable_login_ready":False}, "HOLD_SOURCE207_BACKEND_TRANSFER")
    names={"backend.capsule.tar.gz","retention-manifest.json","owner-completion.data.json"}
    C.need(set(record["files"])==names and {entry.name for entry in root.iterdir()}==names|{"handoff.json"} and
           record["files"]["backend.capsule.tar.gz"] == expected["capsule_pin"],
           "HOLD_SOURCE207_BACKEND_TRANSFER_FILES")
    T.fields(support_refs, SUPPORT)
    C.need(set(expected["support_pins"])==SUPPORT,"HOLD_SOURCE207_BACKEND_ROOT_SUPPORT")
    bodies={}
    for name,pin in record["files"].items():
        cap=reader.MAX_COMPRESSED if name=="backend.capsule.tar.gz" else T.MIB
        body=T.read_local(str(root/name),C.whole(pin,cap)["bytes"])
        C.need(C.pin(body)==pin,"HOLD_SOURCE207_BACKEND_TRANSFER_BODY")
        bodies[name]=body
    manifest_raw = bodies["retention-manifest.json"]
    manifest = T.untrusted_json(manifest_raw, canonical=True)
    T.matches(manifest, {key: expected[key] for key in
                         ("binding", "nonce", "delegation_pin", "context_pin", "stage_report_pin", "image_report_pin")},
              "HOLD_SOURCE207_BACKEND_ROOT_MANIFEST")
    completion = T.untrusted_json(bodies["owner-completion.data.json"], canonical=True)
    T.final(completion)
    T.matches(completion, {"binding": expected["binding"], "nonce": expected["nonce"], "stage": "backend",
                           "completed": True, "stage_report_pin": expected["stage_report_pin"],
                           "retention": {"evidence_state": "COMPLETE", "manifest_pin": C.pin(manifest_raw),
                                         "capsule_pin": expected["capsule_pin"]}}, "HOLD_SOURCE207_BACKEND_OWNER_COMPLETION")
    support={}
    for name,ref in support_refs.items():
        T.fields(ref, ("path","pin"))
        pin=C.whole(ref["pin"],CAP)
        C.need(pin==expected["support_pins"][name] and sum(map(len,support.values()))+pin["bytes"]<=CAP,
               "HOLD_SOURCE207_BACKEND_ROOT_SUPPORT_PIN")
        body=T.read_local(ref["path"],pin["bytes"])
        C.need(C.pin(body)==pin,"HOLD_SOURCE207_BACKEND_ROOT_SUPPORT_PIN")
        support[name]=body
    outcome=reader.read_delegated_stage(bodies["backend.capsule.tar.gz"],expected=expected,
                                        source_files=source_files,support_files=support,now=now)
    if outcome["status"] == "PASS_DELEGATED_PUBLIC_CURRENT_STAGE_DATA_ONLY":
        files, _ = reader.delegated_capsule_files(bodies["backend.capsule.tar.gz"], expected)
        C.need(files["retention-manifest.json"] == manifest_raw, "HOLD_SOURCE207_BACKEND_CAPSULE_MANIFEST")
    return dict(status=outcome["status"],backend_reader=outcome,transfer_pin=transfer_pin,
                first_usable_login_ready=False,runtime_login="NOT_RUN",**C.FINAL)


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode",choices=(MODE,))
    parser.add_argument("--selection",type=Path)
    parser.add_argument("--selection-sha256")
    args=parser.parse_args()
    sys.addaudithook(review.fence)
    C.need(sys.flags.isolated and sys.dont_write_bytecode and __debug__,"HOLD_ISOLATED_SOURCE207_HANDOFF")
    try:
        selection=None
        if args.mode is not None:
            C.need(args.selection is not None,"HOLD_SOURCE207_BACKEND_SNAPSHOT_SELECTION")
            raw=T.read_local(str(args.selection),C.MAX_BYTES)
            C.need(C.pin(raw)["sha256"]==args.selection_sha256,"HOLD_SOURCE207_BACKEND_SNAPSHOT_SELECTION_PIN")
            selection=C.decode(raw)
        result = snapshot(selection,mode=args.mode)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, tarfile.TarError) as error:
        reason = str(error) if isinstance(error, ValueError) and re.fullmatch(r"HOLD_[A-Z_0-9]+", str(error)) else None
        print(C.encoded(dict(status="HOLD_SOURCE207_PRIVATE_BACKEND_INPUT_REFUSED", reason=reason, **C.FINAL)).decode(), end="")
        raise SystemExit(2)
    print(C.encoded(result).decode(),end="")
