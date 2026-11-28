# SPDX-License-Identifier: MIT
"""Assemble a complete Qt629 receipt from a selected retired result disk.

The outer owner supplies the selected nonce and exact SHA-256 of its canonical
QT629_STOPPED_RESULT_OBSERVATION_V1 record. The record has kind, nonce, disk,
held, retirement and host_times fields. The host_times object holds UTC
nanoseconds for inputs-verified, vm-exited, absence-first and absence-second.
Guest observations come from the stopped disk's transaction and cleanup
evidence. The caller also supplies the original paths and reviewed TEST pins.

Use the partial exporter for a held disk. This module publishes a fresh bundle
only after all evidence passes readback verification.
"""

import os
from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory


H = run_path(str(Path(__file__).with_name("host_stage.py")))
E = H["E"]
R = E["R"]
C, need = R["C"], R["need"]
STOPPED = R["STOPPED_KIND"]
HOST_TIMES = R["HOST_TIMES"]


def stopped(path, digest, nonce):
    raw, observation = C.external(path, 128 << 10, digest)
    return R["stopped_observation"](C.json_body(raw, canonical=True), nonce), observation


def receipt(qt, asahi, exported, observed, *, profile=None, provenance=None):
    nonce = observed["nonce"]
    need(exported["result_disk"] == observed["disk"] and exported["actor_directory_present"] is True
         and exported["missing_actor_files"] == exported["missing_asahi_files"] == []
         and exported["original_inputs"] == R["originals"](profile), "Complete exact stopped export required")
    evidence = exported["evidence"]
    need(evidence.keys() == R["evidence_files"](profile).keys(), "Complete Qt receipt evidence required")

    owner_raw, _ = C.read(asahi / "result.json", 128 << 10, exported["asahi"]["result.json"])
    owner = C.json_body(owner_raw, canonical=True)
    journal_raw, _ = C.read(qt / "transaction.jsonl", R["EVIDENCE"]["transaction.jsonl"], evidence["transaction.jsonl"])
    rows = R["journal_rows"](journal_raw, parity=profile is not None)
    checkpoint = exported["qt_checkpoint"]
    E["require_guest_nonce"](nonce, owner, {"transaction.jsonl": journal_raw})
    original_lock = R["ORIGINALS"]["rollback_lock"]
    need(owner["status"] == R["P"]["PASS629"] and owner["inventory"]["rollback"] == original_lock
         and exported["asahi"]["rollback.lock"] == original_lock
         and owner["platform"]["rollback"] == evidence["baseline-platform.json"]
         and checkpoint == owner["qt_checkpoint"] and checkpoint["runtime_probe"] == evidence["runtime-probes.json"],
         "Stopped Asahi629 result differs from the completed Qt checkpoint")

    stamps = {row["phase"]: row["at_ns"] for row in rows}
    times = observed["host_times"] | {event: stamps[phase] for phase, event in R["JOURNAL_EVENTS"].items()}
    need(type(exported["trust_retired_at_ns"]) is int and exported["trust_retired_at_ns"] == owner["trust_retired_at_ns"],
         "Expected the original guest trust retirement timestamp")
    times["trust-retired"] = owner["trust_retired_at_ns"]
    chronology = [dict(event=event, at_ns=times[event]) for event in R["EVENTS"]]
    R["chronology"](chronology)
    phases = {phase: dict(lock=evidence[f"{phase}.lock"], platform=evidence[f"{phase}-platform.json"])
              for phase in R["PHASES"]}
    guest_trust = next(row for row in rows if row["phase"] == "trust")
    certificate = guest_trust["test_certificate"]
    trust = dict(policy=guest_trust["policy"], test_certificate=certificate["pin"],
                 test_fingerprint=certificate["fingerprint"], test_not_before=certificate["not_before"],
                 test_not_after=certificate["not_after"])
    record = dict(kind=R["KIND"], nonce=nonce, original_inputs=exported["original_inputs"], evidence=evidence,
                  chronology=chronology, phases=phases, trust=trust, retirement=observed["retirement"])
    if profile is not None:
        need(type(provenance) is dict and provenance.keys() == R["PARITY_EVIDENCE"].keys()
             and provenance["asahi_owner"] == C.pin(owner_raw) and owner["plan"] == provenance["guest_plan"],
             "Stopped Asahi owner result does not bind the staged guest plan")
        record.update(provenance, kind=R["PARITY_KIND"], parity_profile=C.pin(C.wire(profile)),
                      stopped_disk=observed["disk"])
    return C.wire(record)


def assemble(*, disk_path, observation, observation_sha, nonce, bundle, originals, test_inputs, profile=None,
             guest_plan=None):
    """Reopen the exact stopped carrier and publish a verified, no-replace bundle."""
    observed, selected = stopped(observation, observation_sha, nonce)
    need(originals is not None and test_inputs is not None, "Selected original and TEST operands required")
    need((profile is None) == (guest_plan is None), "Selected parity profile and staged guest plan required together")
    if profile is not None:
        path, selected_plan = guest_plan
        cap = R["PARITY_EVIDENCE"]["guest_plan"][1]
        need(C.check_pin(selected_plan, cap) and selected_plan["bytes"] > 0, "Exact selected staged guest plan pin required")
        plan_body, plan_pin = C.read(path, cap, selected_plan)
    profile_arg = {"profile": profile} if profile is not None else {}
    with E["output_parent"](bundle) as parent, TemporaryDirectory(prefix=".qt629-receipt.", dir=bundle.parent) as folder:
        staging = Path(folder)
        qt, asahi = staging / "qt", staging / "asahi"
        exported = H["export_result"](disk_path, observed["disk"], qt, held=False, originals=originals,
                                      test_inputs=test_inputs, asahi_bundle=asahi, **profile_arg)
        records = {}
        if profile is not None:
            owner_pin = exported["asahi"]["result.json"]
            owner, _ = C.read(asahi / "result.json", R["PARITY_EVIDENCE"]["asahi_owner"][1], owner_pin)
            evidence = {"guest_plan": plan_body, "stopped_observation": C.wire(observed), "asahi_owner": owner}
            profile_arg["provenance"] = dict(guest_plan=plan_pin, stopped_observation=selected, asahi_owner=owner_pin)
            records = {R["PARITY_EVIDENCE"][role][0]: raw for role, raw in evidence.items()}
        body = receipt(qt, asahi, exported, observed, **profile_arg)
        pin = C.pin(body)
        with E["directory"](qt) as directory:
            E["write_bodies"](directory, records | {"receipt.json": body})
        verified = R["readback"](qt, pin["sha256"], profile=profile)
        with E["directory"](staging) as source:
            E["publish"](parent, "qt", bundle.name, source_parent=source)
        os.fsync(parent)
    return dict(bundle=str(bundle), receipt=pin, nonce=nonce, result_disk=observed["disk"],
                stopped_observation=selected, readback=verified)
