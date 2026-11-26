# SPDX-License-Identifier: MIT
"""Join three independently pinned installed Qtbase case readbacks."""

import argparse
from pathlib import Path
from runpy import run_path
import sys
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
H = SimpleNamespace(**run_path(str(HERE / "owned.py")))
C, W = H.C, H.W
CASE_KIND = "QTBASE16K_INSTALLED_CASE_READBACK_V2"
CASE_CAP = 512 << 10
FIELDS = {
    "kind", "status", "case", "clone", "plan", "selection", "scratch", "retirement", "baseline_database",
    "original_files", "physical_M2", "media_sha256", "site_sha256", "authority_sha256", "protection",
}
COMMON = ("plan", "selection", "scratch", "baseline_database")
IDENTITIES = ("media_sha256", "site_sha256", "authority_sha256")


def expected_case(raw, case):
    report = C.json_body(raw, canonical=True)
    C.need(report.keys() == FIELDS and report["kind"] == CASE_KIND
           and report["status"] == "PASS_INSTALLED_CASE_READBACK_ONLY"
           and report["case"] == case and report["physical_M2"] == "NOT_RUN"
           and type(report["clone"]) is str and H.F.Q.NONCE.fullmatch(report["clone"])
           and report["clone"][:8] != "00000000"
           and all(type(report[key]) is str and C.SHA.fullmatch(report[key]) for key in IDENTITIES),
           "Exact independently reviewed installed case required")
    for name, bound in (("plan", 64 << 10), ("selection", W.MAX_SELECTION), ("retirement", 16 << 10),
                        ("baseline_database", 128 << 20)):
        C.need(C.check_pin(report[name], bound) and report[name]["bytes"] > 0, "Missing original installed case join")
    C.need(report["scratch"] == H.P.Q3_SCRATCH and type(report["original_files"]) is dict
           and "evidence/result.json" in report["original_files"] and len(report["original_files"]) <= 905,
           "Exact Q3-backed original case namespace required")
    protection = report["protection"]
    if case == "main":
        C.need(type(protection) is dict and protection.keys() == {"selected", "baseline"},
               "Exact qualified selected-path evidence required")
        names, baseline = protection["selected"], protection["baseline"]
        C.need(type(names) is list and 0 < len(names) <= 512
               and all(type(name) is str and Path(name).is_absolute() for name in names)
               and len(names) == len(set(names)) and type(baseline) is dict and set(names) == baseline.keys()
               and all(type(row) is dict and type(row.get("present")) is bool for row in baseline.values()),
               "Selected paths and their original existence must agree")
    else:
        C.need(protection is None, "Signature-refusal siblings cannot claim main protected-path coverage")
    return report


def qualify(references):
    C.need(references.keys() == set(H.CASES), "Main and both negative installed case references required")
    reports, pins = {}, {}
    for case in H.CASES:
        path, digest = references[case]
        raw, pins[case] = C.external(path, CASE_CAP, digest)
        reports[case] = expected_case(raw, case)
    main = reports["main"]
    C.need(all(tuple(report[key] for key in COMMON) == tuple(main[key] for key in COMMON)
               for report in reports.values()), "Installed cases do not share the exact selected plan, Q3 and baseline")
    C.need(len({report["clone"][:8] for report in reports.values()}) == len(H.CASES)
           and all(len({report[key] for report in reports.values()}) == len(H.CASES) for key in IDENTITIES)
           and len({report["retirement"]["sha256"] for report in reports.values()}) == len(H.CASES),
           "Independent case identities, media, authorities and retirements required")
    return dict(kind="QTBASE16K_INSTALLED_LIFECYCLE_READBACK_V1", status="PASS_EXACT_EMULATED_INSTALLED_LIFECYCLE",
                cases={case: dict(receipt=pins[case], clone=report["clone"], retirement=report["retirement"],
                                  **{key: report[key] for key in IDENTITIES}) for case, report in reports.items()},
                **{key: main[key] for key in COMMON},
                selected_path_protection=main["protection"], physical_M2="NOT_RUN")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for case in H.CASES:
        flag = "--" + case.replace("_", "-")
        parser.add_argument(flag, type=Path, required=True)
        parser.add_argument(flag + "-sha256", required=True)
    args = parser.parse_args()
    try:
        sys.addaudithook(C.audit_fence)
        refs = {case: (getattr(args, case), getattr(args, case + "_sha256")) for case in H.CASES}
        sys.stdout.buffer.write(C.wire(qualify(refs)))
    except (OSError, ValueError, KeyError, TypeError):
        sys.exit("Qtbase installed lifecycle readback refused")


if __name__ == "__main__":
    main()
