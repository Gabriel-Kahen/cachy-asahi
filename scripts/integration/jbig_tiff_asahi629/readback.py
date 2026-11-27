# SPDX-License-Identifier: MIT
"""Independently reopen the bounded Asahi629 pair evidence after guest retirement."""

import argparse
import hashlib
from pathlib import Path
from runpy import run_path
import tempfile
from types import SimpleNamespace
from uuid import UUID

HERE = Path(__file__).resolve().parent
S = SimpleNamespace(**run_path(str(HERE / "stage.py")))
TX = SimpleNamespace(**run_path(str(HERE / "transaction.py")))
RUNTIME = SimpleNamespace(**run_path(str(HERE / "runtime.py")))
STOPPED = "ASAHI629_JBIG_TIFF_STOPPED_V1"
CHECKPOINT = "ASAHI629_JBIG_TIFF_CHECKPOINT_V1"


def read_runtime(T, row, soname):
    T.need(row.keys() == {"status", "uid", "gid", "jbig_soname", "loaders", "probes"}
           and row["status"] == "PASS" and row["uid"] == row["gid"] == 65534
           and row["jbig_soname"] == soname and row["probes"] == RUNTIME.PROBES
           and set(row["loaders"]) == {"/" + name for name in S.I.CONSUMERS},
           "Ordinary-user TIFF, GTK, OpenJPEG, SpanDSP and PipeWire checks are incomplete")
    for name, record in row["loaders"].items():
        wanted = {"tiff": "libtiff.so.6", "jbig": f"libjbig.so.{soname}"}
        if name == RUNTIME.PIPEWIRE:
            wanted["span"] = "libspandsp.so.2"
        T.need(record.keys() == wanted.keys()
               and all(record[key] in ("/usr/lib/" + value, "/lib/" + value) for key, value in wanted.items()),
               "Unexpected runtime loader evidence for " + name)


def validate(T, G, result, plan, *, held):
    I = S.I
    row = result.get("jbig_tiff_checkpoint")
    if row is None:
        T.need(held, "Missing completed pair checkpoint")
        return None
    T.need(row["kind"] == CHECKPOINT and row["nonce"] == result["nonce"] == plan["nonce"],
           "Pair checkpoint identity differs from its owning Asahi629 boot")
    if held and row["status"] != TX.PASS:
        T.need(row["status"] in (TX.HOLD_BASELINE, TX.HOLD_DISCARD, TX.HOLD_RESTORED, "HOLD_ASAHI629_JBIG_TIFF_ENTRY"),
               "Unexpected pair status on a held guest")
        return row
    T.need(row["status"] == TX.PASS and row["failure"] is row["probe_failure"] is None
           and row["unsigned_control"] == "package missing required signature", "Pair replacement or unsigned refusal held")
    review = plan["jbig_tiff"]["test_review"]
    trust = row["trust"]
    T.need(trust["policy"] == "Required TrustedOnly" and trust["fingerprint"] == review["fingerprint"]
           and set(trust["signatures"]) == set(I.PROVIDERS), "The scoped signature review is incomplete")
    for name, signed in trust["signatures"].items():
        raw = signed["status"].encode("utf-8")
        proof = (G.test_signature(T, raw, review, signed["observed_at"]) if name in I.PROJECT
                 else G.signature(T, raw, I.ALARM_FINGERPRINT))
        T.need(signed["proof"] == proof, "Scoped signature evidence differs: " + name)
    groups = S.ENTRY.check_log(T, row["alpm_log"], I.OFFICIAL, I.PROJECT)
    T.need(T.encoded(groups) == T.encoded(row["alpm"]), "Guest ALPM log projection differs")
    T.need(set(row["transactions"]) == {"replacement", "restoration"}, "Both exact pair preparations required")
    for label, incoming, outgoing in (("replacement", I.PROJECT, I.OFFICIAL), ("restoration", I.OFFICIAL, I.PROJECT)):
        transaction = row["transactions"][label]
        conflicts = [item | {"pair": tuple(map(tuple, item["pair"]))} for item in transaction["conflicts"]]
        TX.check_prepared(transaction["add"], transaction["remove"], conflicts, incoming, outgoing)
    phases = row["phases"]
    T.need(set(phases) == {"baseline", "replacement", "restoration"}, "Exact three pair checkpoints required")
    baseline_metadata = phases["baseline"]["consumer_metadata"]
    T.need(set(baseline_metadata) == {ref["package"] for ref in I.CONSUMERS.values()}
           and all(data.keys() == {"desc", "files", "mtree"} for data in baseline_metadata.values()),
           "Complete unchanged consumer ALPM metadata evidence required")
    for name, phase in phases.items():
        project = name == "replacement"
        providers = I.PROJECT if project else I.OFFICIAL
        T.need(phase["lock"] == (I.REPLACEMENT if project else I.BASELINE)
               and phase["platform"] == I.PLATFORM
               and phase["provider_reasons"] == dict.fromkeys(providers, 1)
               and phase["provider_files"] == {path: pin for pkg in providers for path, pin in I.PROVIDER_FILES[pkg].items()}
               and phase["consumers"] == {path: ref["pin"] for path, ref in I.CONSUMERS.items()}
               and phase["consumer_metadata"] == baseline_metadata
               and phase["tiffgt"] == ("ABSENT_PARITY_GAP" if project else "OFFICIAL"),
               "Wrong installed package files, ownership or protected paths at " + name)
        read_runtime(T, phase["runtime"], "2.2" if project else "2.1")
    return row


def review(L, out, plan, *, held):
    base = L.review(out, plan, held=held)
    validate(L.T, L.G, base, plan, held=held)
    return base


def independent(L, stage, disk, observation, sha256):
    T = L.T
    raw = T.read(observation, cap=64 << 10)
    observed = T.decode(raw)
    T.need(T.pin(raw)["sha256"] == sha256 and raw == T.encoded(observed)
           and observed.keys() == {"kind", "nonce", "disk", "held", "qemu", "container", "absence"}
           and observed["kind"] == STOPPED and type(observed["held"]) is bool, "Expected selected stopped-disk observation")
    qemu, container = observed["qemu"], observed["container"]
    T.need(qemu["reaped"] is True and container["removed"] is True
           and S.LHEX.fullmatch(observed["nonce"]) and len(container["id"]) == 64
           and all(char in "0123456789abcdef" for char in container["id"])
           and observed["absence"] == [{"qemu": [], "containers": []}, {"qemu": [], "containers": []}]
           and (observed["held"] or (qemu["exit"] == container["exit"] == 0 and qemu["output_complete"] is True
                                     and qemu["timeout"] is False and qemu["signals"] == [])),
           "Owned QEMU and container retirement are required before readback")
    plan_bytes = T.read(stage / S.PLAN, cap=S.CAP)
    plan = T.decode(plan_bytes)
    record = T.decode(T.read(stage / S.STAGE, cap=S.CAP))
    T.need(T.pin(plan_bytes) == record["plan"] and plan_bytes == T.encoded(plan)
           and plan["nonce"] == record["nonce"] == observed["nonce"], "Stopped-disk nonce and plan differ")
    base = {key: plan[key] for key in ("kind", "nonce", "manifest", "media")} | {"code": S.BASE_CODE}
    expected, _ = S.derive(L, base, plan["jbig_tiff"]["test_review"])
    T.need(plan == expected, "Reconstructed boot-selection plan differs")
    T.need(observed["disk"]["bytes"] == L.C.RESULT_SIZE, "Unexpected stopped result-disk size")
    original_identity = T.identity(disk.lstat())
    T.read(disk, observed["disk"], cap=L.C.RESULT_SIZE, collect=False)
    reader = L.C.module(L.C.PERL / "frozen/independent_readback.py")
    nonce_uuid = str(UUID(bytes=hashlib.sha256((plan["nonce"] + ":OV583_RESULT").encode()).digest()[:16]))
    with reader.Ext4Reader(disk) as image:
        T.need(image.uuid == nonce_uuid, "Result filesystem UUID differs from the boot nonce")
    with tempfile.TemporaryDirectory(prefix="jbig-tiff-readback-") as work:
        evidence = Path(work) / "evidence"
        L.export(reader, disk, evidence, held=observed["held"])
        verified = review(L, evidence, plan, held=observed["held"])
    T.need(T.identity(disk.lstat()) == original_identity, "Stopped result disk changed during review")
    T.read(disk, observed["disk"], cap=L.C.RESULT_SIZE, collect=False)
    checkpoint = verified.get("jbig_tiff_checkpoint")
    return dict(kind="ASAHI629_JBIG_TIFF_INDEPENDENT_READBACK_V1", nonce=plan["nonce"], disk=observed["disk"],
                observation=T.pin(raw), checkpoint=checkpoint, original_asahi=verified["status"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("stage", "disk", "observation"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    L = S.legacy()
    try:
        result = independent(L, args.stage, args.disk, args.observation, args.sha256)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, f"JBIG/TIFF evidence refused: {error}\n")
    print(L.T.encoded(result).decode(), end="")
    return int(result["original_asahi"] != L.G.PASS or result["checkpoint"] is None
               or result["checkpoint"]["status"] != TX.PASS)


if __name__ == "__main__":
    raise SystemExit(main())
