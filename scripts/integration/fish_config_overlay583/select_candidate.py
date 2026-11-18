#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Select the exact rehearsed Fish config replacement as development DATA."""

import argparse
import importlib.util
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
KIND = "OVERLAY583_FISH_CONFIG_DEVELOPMENT_CANDIDATE_V1"
TERMINAL = "CLOSED_LOCAL_OVERLAY583_FISH_UPGRADE_R1_PASS"
LOCK = "target-candidate.lock"
RECEIPT = "candidate.DATA.json"


def load_trial():
    path = HERE.parents[1] / "install/overlay583_trial/trial.py"
    spec = importlib.util.spec_from_file_location("fish_candidate_trial", path)
    trial = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(trial)
    return trial


def pinned(trial, ref, cap, observed):
    trial.need(type(ref) is dict and set(ref) == {"path", "bytes", "sha256"}, "exact Fish input reference required")
    return trial.read(Path(ref["path"]), dict(bytes=ref["bytes"], sha256=ref["sha256"]), cap=cap, observed=observed)


def reference(path, pin):
    return dict(path=str(path), **pin)


def bound_guest(trial, operand, packet, stage, terminal, selection):
    trial.need(terminal["issuer"] == "Root" and terminal["status"] == TERMINAL
               and terminal["phase"] is None and terminal["guest_platform"] == "aarch64 QEMU TCG"
               and terminal["page_size"] == 16384 and terminal["physical_M2"] == "NOT RUN"
               and terminal["native_16KiB_hardware"] == "NOT RUN"
               and terminal["evidence_files"] == 22, "independently closed 16 KiB Fish rehearsal required")
    absent = dict(bind_container_absent=True, run_container_absent=True, scope_absent=True)
    trial.need(terminal["observations"] == [absent, absent]
               and terminal["native_pair"] == stage["qualification"] and terminal["test_signer"] == stage["rehearsal"],
               "Fish rehearsal native source, TEST signer or retirement differs")
    expected = {phase: dict(stage["inventories"][phase], count=583) for phase in ("before", "upgraded", "restored")}
    trial.need(terminal["matched_locks"] == expected, "original guest inventory observation differs")
    actual_code = {f"scripts/integration/fish_config_overlay583/{name}": stage["files"][name] for name in operand.CODE}
    trial.need(selection["kind"] == "ROOT_OVERLAY583_QEMU_TCG_SELECTION_V1" and selection["issuer"] == "Root"
               and selection["preflight"] == packet["preflight"] and selection["fish_upgrade"] == stage["receipt"]
               and all(selection["source"].get(name) == pin for name, pin in actual_code.items()),
               "original rehearsal selected a different baseline or signed Fish supplement")


def build_candidate(trial, config, output):
    trial.need(type(config) is dict and set(config) == {"kind", "schema", "staging", "preflight", "supplement",
                                                       "native_builds", "guest_terminal", "guest_selection", "guest_evidence"}
               and config["kind"] == KIND and config["schema"] == 1, "exact development candidate config required")
    output = trial.ordinary(output)
    staging = trial.ordinary(config["staging"])
    supplement = trial.ordinary(config["supplement"]["path"]).parent
    trial.need(Path(config["supplement"]["path"]).name == "supplement.json" and not output.exists()
               and all(not out.is_relative_to(output) and not output.is_relative_to(out)
                       for out in (staging, supplement)), "fresh output disjoint from accepted baseline and supplement required")
    observed = {}
    stage_raw = pinned(trial, config["supplement"], 64 * 1024, observed)
    stage = trial.fish_upgrade_selection(supplement, config["supplement"]["sha256"])
    trial.need(stage["receipt"] == trial.pin(stage_raw), "reopened Fish supplement receipt differs")
    o = trial.fish_upgrade_module("operands.py", stage["files"]["operands.py"])
    g = trial.fish_upgrade_module("guest.py", stage["files"]["guest.py"])
    p = trial.fish_upgrade_module("probe.py", stage["files"]["probe.py"])
    adapter = trial.fish_trial()

    packet = trial.choose(staging, selected_lock=trial.PINS)
    preflight_raw = pinned(trial, config["preflight"], 128 * 1024, observed)
    packet = trial.admit(packet, preflight_raw, trial.pin(preflight_raw))
    archive = stage["files"][o.SUCCESSOR]
    native = config["native_builds"]
    trial.need(type(native) is list and len(native) == 2, "two original native archive references required")
    first, second = (trial.ordinary(ref["path"]) for ref in native)
    trial.need(not first.samefile(second), "two distinct original native archives required")
    trial.need(first.name == second.name == o.SUCCESSOR
               and all(trial.pin(pinned(trial, ref, 128 * 1024, observed)) == archive for ref in native),
               "native archives and signed successor differ")

    _, target = o.inventories(adapter, trial.target_bytes(packet))
    baseline = trial.read(staging / "target.lock", o.TARGET, cap=64 * 1024, observed=observed)
    trial.need(stage["inventories"] == o.baseline(adapter, staging, Path(config["preflight"]["path"]))
               and stage["inventories"]["upgraded"] == trial.pin(target),
               "signed Fish supplement has a different original package or lock")
    previous = f"{o.REPO}/{o.PREVIOUS}"
    trial.need(packet["packages"][o.PACKAGE] == dict(repo=trial.OVERLAY_REPO, version=o.OLD)
               and packet["files"][previous] == o.PIN_OLD and packet["files"][previous + ".sig"] == o.PIN_OLD_SIG
               and packet["signers"][0] == g.OVERLAY_SIGNER
               and stage["rehearsal"]["fingerprint"] not in packet["signers"],
               "exact original Fish archive and separate rehearsal TEST signer required")

    terminal = trial.decode(pinned(trial, config["guest_terminal"], 64 * 1024, observed))
    selection = pinned(trial, config["guest_selection"], 64 * 1024, observed)
    evidence = pinned(trial, config["guest_evidence"], g.MAX_EVIDENCE, observed)
    trial.need(trial.pin(selection) == terminal["authority"] and trial.pin(evidence) == terminal["fish_upgrade_evidence"],
               "original guest selection or evidence differs from the independent terminal")
    bound_guest(trial, o, packet, stage, terminal, trial.decode(selection))
    result = g.readback(adapter, o, p, evidence, baseline=baseline, stage=stage, held=False)
    trial.need(result["db"] == terminal["guest_normalized_db"] and result["probes"] == terminal["probes"]
               and result["user_config"]["before"] == terminal["user_config"] and result["alpm"] == terminal["fish_alpm"],
               "retained raw commands and terminal observations disagree")
    leaves = {leaf: reference(supplement / leaf, stage["files"][leaf])
              for leaf in (o.SUCCESSOR, o.SUCCESSOR + ".sig", o.PUBLIC)}
    for ref in leaves.values():
        pinned(trial, ref, 128 * 1024, observed)
    trial.unchanged(observed)

    output.mkdir(mode=0o700)
    lock_path = output / LOCK
    with lock_path.open("xb") as writer:
        writer.write(target)
    lock_path.chmod(0o444)
    receipt = dict(kind=KIND, schema=1, status="UNAPPROVED_DEVELOPMENT_CANDIDATE", package_count=583,
                   accepted_baseline=dict(staging=str(staging), preflight=config["preflight"], staging_receipt=packet["staging_receipt"],
                                          release=packet["release"], lock=reference(staging / "target.lock", o.TARGET)),
                   candidate_lock=reference(lock_path, trial.pin(target)),
                   replace=dict(name=o.PACKAGE, original_repo=trial.OVERLAY_REPO,
                                previous=dict(version=o.OLD, archive=reference(staging / previous, o.PIN_OLD),
                                              signature=reference(staging / (previous + ".sig"), o.PIN_OLD_SIG)),
                                candidate=dict(version=o.NEW, archive=leaves[o.SUCCESSOR], signature=leaves[o.SUCCESSOR + ".sig"],
                                               public_certificate=leaves[o.PUBLIC], signer=stage["rehearsal"], trust_scope="development-TEST")),
                   native_evidence=dict(qualification=stage["qualification"], original_archives=native),
                   guest_evidence=dict(status=result["status"], page_size=result["page_size"],
                                       original_terminal=config["guest_terminal"], original_commands=config["guest_evidence"],
                                       original_selection=trial.pin(selection), signed_supplement=config["supplement"]),
                   production_trust=False, production_selection=False, actor_authorized=False, physical_M2="NOT RUN")
    raw = trial.encoded(receipt)
    with (output / RECEIPT).open("xb") as writer:
        writer.write(raw)
    (output / RECEIPT).chmod(0o444)
    return reference(output / RECEIPT, trial.pin(raw))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--config-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    trial = load_trial()

    def fence(event, _):
        trial.need(not event.startswith(("subprocess.", "socket.", "ctypes."))
                   and event not in ("os.system", "os.exec", "os.fork", "os.forkpty", "os.posix_spawn"),
                   "No actor is permitted during candidate selection")

    sys.addaudithook(fence)
    try:
        raw = trial.read(args.config, cap=64 * 1024)
        trial.need(trial.pin(raw)["sha256"] == args.config_sha256, "exact externally pinned candidate config required")
        result = build_candidate(trial, trial.decode(raw), args.output)
        print(trial.encoded(result).decode(), end="")
    except (KeyError, TypeError, ValueError, OSError) as error:
        print(f"Fish candidate selection refused: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
