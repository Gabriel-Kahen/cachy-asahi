#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture two battery readings around operator-led suspend and compare them offline."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time

SPEC = importlib.util.spec_from_file_location("platform_metrics", Path(__file__).with_name("platform_metrics.py"))
metrics = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(metrics)

ENDPOINT = "cachy-asahi-suspend-endpoint-v1"
REPORT = "cachy-asahi-suspend-drain-v1"
MACHINE_ID = re.compile(r"m2-[0-9a-f]{32}")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}")
DIGEST = re.compile(r"[0-9a-f]{64}")
MODELS = {"apple,j413", "apple,j415"}
IDENTITY_FIELDS = ("type", "manufacturer", "model_name", "technology")
CONTEXT_FIELDS = ["status", "present", "online"]
NANOSECONDS = 10**9


def checked_json(path, expected, cap):
    raw = metrics.ordinary(path, cap)
    pin = metrics.pin_bytes(raw)
    metrics.need(pin["sha256"] == expected, "whole input SHA-256 mismatch")

    def unique(pairs):
        value = dict(pairs)
        metrics.need(len(value) == len(pairs), "duplicate JSON key")
        return value

    return json.loads(raw, object_pairs_hook=unique,
                      parse_constant=lambda _: metrics.need(False, "nonfinite JSON")), pin


def machine():
    compatible = metrics.read_text(Path("/sys/firmware/devicetree/base/compatible"))
    raw = compatible["raw"] if compatible["status"] == "ok" else ""
    devices = [name for name in raw.split("\0") if name]
    models = MODELS.intersection(devices)
    model = next(iter(models)) if "apple,t8112" in devices and len(models) == 1 and len(set(devices)) == len(devices) else None
    boot = metrics.read_text(Path("/proc/sys/kernel/random/boot_id"))
    boot_id = (boot["raw"] or "").strip()
    metrics.need(boot["status"] == "ok" and re.fullmatch(
        r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", boot_id), "Linux boot identity unavailable")
    uname = os.uname()
    return dict(architecture=uname.machine, kernel=uname.release, page_size_bytes=os.sysconf("SC_PAGE_SIZE"),
                model=model, boot_id_sha256=metrics.pin_bytes(boot_id.encode())["sha256"])


def energy_sensor(directory):
    return dict(id=str(directory / "energy_now"), directory=str(directory), resolved_directory=str(directory.resolve()),
                family="power_supply", attribute="energy_now", unit="uWh", kind="stored_energy",
                identity={key: metrics.signature(metrics.read_text(directory / key)) for key in IDENTITY_FIELDS},
                identity_required="type", context_fields=CONTEXT_FIELDS)


def collector():
    return {path.name: metrics.pin_bytes(metrics.ordinary(path, 128 * 1024))
            for path in (Path(__file__), Path(metrics.__file__))}


def capture(args):
    metrics.need(sys.platform == "linux" and hasattr(time, "CLOCK_BOOTTIME"), "Linux boottime clock required")
    observed = machine()
    baseline, pin = checked_json(args.baseline, args.baseline_sha256, 2 * 1024**2)
    metrics.need(baseline["schema_version"] == 1 and baseline["record_type"] == "environment-baseline"
                 and baseline["execution_context"] == args.execution_context
                 and all(baseline[key] == observed[key] for key in ("architecture", "kernel", "page_size_bytes")),
                 "baseline context, architecture, kernel or page size differs from capture")
    if observed["model"] is not None:
        expected = {"13-inch": "apple,j413", "15-inch": "apple,j415"}.get(baseline["m2_air_size"])
        metrics.need(expected == observed["model"], "baseline M2 Air model differs from capture")
    sensor = energy_sensor(Path("/sys/class/power_supply") / args.battery)
    trial = dict(machine_id=args.machine_id, trial_id=args.trial_id, battery=args.battery,
                 execution_context=args.execution_context, minimum_suspended_seconds=args.minimum_suspended_seconds)
    return dict(schema=ENDPOINT, phase=args.phase, baseline=pin, trial=trial, machine=observed, collector=collector(),
                sensor=sensor, sample=metrics.snapshot({"sensors": [sensor]}, 0))


def validate(endpoint, phase):
    metrics.need(endpoint["schema"] == ENDPOINT and endpoint["phase"] == phase, "wrong endpoint schema or phase")
    sensor, trial = endpoint["sensor"], endpoint["trial"]
    metrics.need(NAME.fullmatch(trial["battery"]) and MACHINE_ID.fullmatch(trial["machine_id"])
                 and NAME.fullmatch(trial["trial_id"]) and type(trial["minimum_suspended_seconds"]) is int
                 and trial["minimum_suspended_seconds"] > 0, "invalid trial identity or minimum suspend time")
    metrics.need(sensor["directory"] == "/sys/class/power_supply/" + trial["battery"]
                 and (sensor["family"], sensor["attribute"], sensor["unit"], sensor["kind"]) ==
                 ("power_supply", "energy_now", "uWh", "stored_energy")
                 and set(sensor["identity"]) == set(IDENTITY_FIELDS)
                 and sensor["identity_required"] == "type" and sensor["context_fields"] == CONTEXT_FIELDS,
                 "unexpected battery energy sensor")
    attributes = sensor["identity"].values()
    metrics.need(all(row["status"] in metrics.STATES and
                     (row["status"] != "ok" or isinstance(row["raw"], str)) for row in attributes),
                 "invalid battery identity attribute")
    metrics.validate_samples({"schema": metrics.SCHEMA, "sensors": [sensor]}, [endpoint["sample"]])


def elapsed(before, after, clock):
    lower = after["start"][clock] - before["end"][clock]
    upper = after["end"][clock] - before["start"][clock]
    metrics.need(0 < lower <= upper, "endpoint windows overlap or are reversed")
    return {"lower": lower, "upper": upper}


def compare(before, after, pins):
    validate(before, "before")
    validate(after, "after")
    metrics.need(all(before[key] == after[key] for key in ("trial", "machine", "baseline", "collector")),
                 "different trial, machine, running boot, baseline or collector")
    trial, machine_info = before["trial"], before["machine"]
    start, end = before["sample"], after["sample"]
    wall = elapsed(start, end, "boottime_ns")
    awake = elapsed(start, end, "monotonic_ns")
    # Both snapshots bracket the energy read. Combine the independent clock
    # bounds conservatively, including time spent reading the endpoints.
    slept = {"lower": max(0, wall["lower"] - awake["upper"]),
             "upper": max(0, wall["upper"] - awake["lower"])}
    left, right = start["readings"][0], end["readings"][0]
    report = dict(schema=REPORT, status="INCOMPLETE", endpoints=pins, trial=trial, machine=machine_info,
                  baseline=before["baseline"],
                  endpoint_collector=before["collector"], comparison_collector=collector(),
                  elapsed_ns=wall, awake_ns=awake, kernel_suspended_ns=slept, energy_endpoints_uwh={
                      "before": left["value"], "after": right["value"]},
                  energy_lost_uwh=None, window_average_w=None, hardware_validation="NOT RUN",
                  energy_scope="Battery gauge difference across the full window, including awake time.",
                  operator_review="Confirm actual sleep mode, wakes, power continuity and gauge resolution.")
    if not (trial["execution_context"] == "physical" and machine_info["architecture"] == "aarch64"
            and machine_info["page_size_bytes"] == 16384 and machine_info["model"] in MODELS):
        report["reason"] = "declared physical M2 Air with aarch64 and 16 KiB pages required"
    elif before["sensor"] != after["sensor"]:
        report["reason"] = "battery identity changed between endpoints"
    elif any(row["status"] != "ok" for row in (left, right)):
        report["reason"] = "battery energy endpoint missing or unreadable"
    elif slept["lower"] < trial["minimum_suspended_seconds"] * NANOSECONDS:
        report["reason"] = "kernel-clock lower bound falls short of planned suspend duration"
    else:
        # The stored-energy branch evaluates gauge delta and power state.
        _, reason = metrics.interval_energy(before["sensor"], left, right, 0)
        if reason is not None:
            report["reason"] = reason
        else:
            loss = left["value"] - right["value"]
            report["energy_lost_uwh"] = loss
            if loss:
                report["status"] = "OBSERVED_WINDOW"
                report["window_average_w"] = {key: loss * 3.6e6 / wall[opposite]
                                              for key, opposite in (("lower", "upper"), ("upper", "lower"))}
            else:
                report["reason"] = "gauge did not resolve a change"
    return report


def matched(pattern, description):
    def parse(value):
        if not pattern.fullmatch(value):
            raise argparse.ArgumentTypeError(description)
        return value
    return parse


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    endpoint = modes.add_parser("capture", help="Read one endpoint before suspend or immediately after waking")
    endpoint.add_argument("--phase", choices=("before", "after"), required=True)
    endpoint.add_argument("--machine-id", type=matched(MACHINE_ID, "use the existing opaque M2 pseudonym"), required=True)
    for name in ("trial-id", "battery"):
        endpoint.add_argument("--" + name, type=matched(NAME, "use a short identifier"), required=True)
    endpoint.add_argument("--execution-context", choices=("physical", "virtual", "emulated", "unknown"), default="unknown")
    endpoint.add_argument("--minimum-suspended-seconds", type=int, required=True,
                          help="Predeclared positive minimum, identical for both captures")
    review = modes.add_parser("compare", help="Read two endpoints by SHA-256 and retain the measured window")
    for mode, inputs in ((endpoint, ("baseline",)), (review, ("before", "after"))):
        mode.add_argument("--output", type=Path, required=True, help="New private evidence file")
        for name in inputs:
            mode.add_argument("--" + name, type=Path, required=True)
            mode.add_argument("--" + name + "-sha256", type=matched(DIGEST, "expected lowercase SHA-256"), required=True)
    args = parser.parse_args(argv)
    try:
        if args.mode == "capture":
            metrics.need(args.minimum_suspended_seconds > 0, "positive minimum suspend duration required")
            result = capture(args)
            validate(result, args.phase)
        else:
            before, left = checked_json(args.before, args.before_sha256, 64 * 1024)
            after, right = checked_json(args.after, args.after_sha256, 64 * 1024)
            result = compare(before, after, {"before": left, "after": right})
        raw = metrics.encoded(result)
        metrics.fresh_file(args.output, raw)
        print(json.dumps(metrics.pin_bytes(raw), sort_keys=True))
        return 2 if result.get("status") == "INCOMPLETE" else 0
    except (OSError, KeyError, TypeError, ValueError, OverflowError) as error:
        print(f"{type(error).__name__}: {str(error)[:200]}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
