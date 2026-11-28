#!/usr/bin/env python3
"""Version 2 owned-retirement measurement orchestration. Workloads execute as argv in caller-owned cwd.

This tool never grants optimization acceptance. Workloads themselves are trusted
operator code; no shell execution is used by the harness, but this is not a sandbox.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import cache
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import queue
import re
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from types import ModuleType

_memory_spec = importlib.util.spec_from_file_location('process_group_memory', Path(__file__).with_name('process_group_memory.py'))
process_group_memory = importlib.util.module_from_spec(_memory_spec)
_memory_spec.loader.exec_module(process_group_memory)

CLEANUP_SECONDS = 0.25
_active_sampler = None
_platform_adapter = None
_retirement_adapter = None
OWNED_RETIREMENT_ADAPTER_SHA256 = '418892c3c108549610234645dd80d49ec692ab7dc0708e530974667ba6d568ce'
EXECUTION_LAYER = "benchmark-owned-retirement-v2"
CAPTURE_SOURCE = Path(__file__).resolve().parents[1] / "hardware/capture-baseline.py"
PAIRED_ZLIB_SOURCE = Path(__file__).resolve().with_name("paired_zlib_v2.py")
OBSERVED_CONDITIONS_MAX_AGE = 30
OBSERVED_CONDITIONS_MAX_BYTES = 64 * 1024


class Invalid(ValueError):
    pass


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text())


def write_json(path, data):
    with Path(path).open("x") as output:
        json.dump(data, output, indent=2, allow_nan=False)
        output.write("\n")


def publish_paired_trial(path, data):
    with tempfile.TemporaryDirectory(prefix=".trial-", dir=path.parent) as staging:
        temporary = Path(staging) / path.name
        write_json(temporary, data)
        os.link(temporary, path)


def now():
    return datetime.now(timezone.utc).isoformat()


def utc_timestamp(value):
    timestamp = datetime.fromisoformat(value)
    if timestamp.tzinfo is None:
        raise Invalid("timezone-aware evidence timestamps required")
    return timestamp.astimezone(timezone.utc)


def pin_file(path):
    path = Path(path).absolute()
    return {"path": str(path), "resolved_path": str(path.resolve(strict=True)), "sha256": digest(path)}


def check_pin(pin, label):
    path = Path(pin["path"])
    resolved = path.resolve(strict=True)
    raw = resolved.read_bytes()
    if (str(resolved) != pin["resolved_path"] or path.resolve(strict=True) != resolved
            or hashlib.sha256(raw).hexdigest() != pin["sha256"]):
        raise Invalid(f"{label} changed after declaration: {pin['path']}")
    return raw


@cache
def capture_source():
    module = ModuleType("benchmark_baseline_capture")
    module.__file__ = str(CAPTURE_SOURCE)
    exec(compile(CAPTURE_SOURCE.read_bytes(), str(CAPTURE_SOURCE), "exec"), vars(module))
    return module


@contextmanager
def term_interrupts():
    events = []
    previous = signal.signal(signal.SIGTERM, lambda signum, frame: events.append(signum))
    try:
        yield events
    finally:
        signal.signal(signal.SIGTERM, previous)


def text_file(path):
    try:
        return Path(path).read_text().replace("\0", "\n").strip()
    except (OSError, UnicodeError):
        return None


def state_identity(record):
    """Ignore collection time/operator/desktop status; retain base versions and DB hashes."""
    if not isinstance(record, dict) or not isinstance(record.get("packages", {}), dict):
        raise Invalid("expected a capture record and package inventory query")
    packages = record.get("packages", {})
    return {key: record.get(key) for key in (
        "architecture", "machine_model", "device_tree_compatible", "page_size_bytes",
        "kernel", "os_release", "execution_context", "m2_air_size")} | {
        "packages": packages.get("stdout") if packages.get("returncode") == 0 else None,
        "repositories": [{"name": db["name"], "sha256": db.get("sha256")}
                         for db in record.get("repositories", {}).get("sync_databases", [])]}


def live_identity(context):
    try:
        result = subprocess.run(["/usr/bin/pacman", "-Q"], capture_output=True, text=True, timeout=20)
        packages = result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        packages = None
    compatible = text_file("/proc/device-tree/compatible")
    architecture = platform.machine()
    size = capture_source().target_size(architecture, compatible)
    return {"architecture": architecture, "machine_model": text_file("/proc/device-tree/model"),
            "device_tree_compatible": compatible, "page_size_bytes": os.sysconf("SC_PAGE_SIZE"),
            "kernel": platform.release(), "os_release": text_file("/etc/os-release"),
            "execution_context": context, "m2_air_size": size, "packages": packages,
            "repositories": [{"name": p.name, "sha256": digest(p)}
                             for p in sorted(Path("/var/lib/pacman/sync").glob("*.db"))]}


def number(value, name, low=None, high=None):
    if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
        raise Invalid(f"{name}: finite number required")
    if (low is not None and value < low) or (high is not None and value > high):
        raise Invalid(f"{name}: outside allowed range")
    return value


def validate_config(config):
    for key in ("experiment_id", "machine_id", "base_id", "workload_id"):
        if not isinstance(config.get(key), str) or not config[key].strip():
            raise Invalid(f"{key}: nonempty identifier required")
    if config.get("execution_context") not in ("physical", "virtual", "emulated", "unknown"):
        raise Invalid("execution_context required")
    if "paired_zlib" in config:
        scope = "exact-arm" if config["execution_context"] == "physical" else "control-only"
        if (config["paired_zlib"] != scope or not isinstance(config.get("inputs"), list)
                or str(PAIRED_ZLIB_SOURCE) not in config["inputs"]):
            raise Invalid("paired zlib requires its matching scope and pinned verifier source")
        if "platform_metrics" in config:
            raise Invalid("paired zlib requires the ordinary owned-retirement runner")
    change = config.get("change", {})
    for key in ("variable", "baseline", "candidate", "rationale"):
        if not isinstance(change.get(key), str) or not change[key].strip():
            raise Invalid(f"change.{key}: one explicit variable and values required")
    if change["baseline"] == change["candidate"]:
        raise Invalid("change must have distinct declared values")
    argv = config.get("argv")
    if not isinstance(argv, list) or not argv or any(not isinstance(a, str) or "\0" in a for a in argv):
        raise Invalid("argv must be a nonempty string array")
    if not Path(argv[0]).is_absolute():
        raise Invalid("argv[0] must be absolute to avoid PATH drift")
    if Path(argv[0]).name in ("sudo", "su", "doas", "pkexec"):
        raise Invalid("privilege escalation is not a workload")
    if not isinstance(config.get("inputs"), list) or not config["inputs"]:
        raise Invalid("inputs must pin workload sources/data/executable")
    if argv[0] not in config["inputs"]:
        raise Invalid("executable must be included in pinned inputs")
    if not isinstance(config.get("env", {}), dict) or any(
            not isinstance(k, str) or not k or not isinstance(v, str) or "=" in k or "\0" in k + v
            for k, v in config.get("env", {}).items()):
        raise Invalid("env must map variable names to strings")
    variants = config.get("variant_env")
    if variants is not None:
        key = change.get("environment_key")
        if (not isinstance(key, str) or not key or "=" in key or "\0" in key
                or not isinstance(variants, dict) or set(variants) != {"baseline", "candidate"}):
            raise Invalid("variant_env requires one explicit change.environment_key and both variants")
        for variant in ("baseline", "candidate"):
            if variants[variant] != {key: change[variant]}:
                raise Invalid("variant_env may change only the declared key to its declared value")
    variant_inputs = config.get("variant_inputs", {})
    if not isinstance(variant_inputs, dict) or any(
            key not in ("baseline", "candidate") or not isinstance(paths, list)
            or any(not isinstance(p, str) for p in paths) for key, paths in variant_inputs.items()):
        raise Invalid("variant_inputs maps baseline/candidate to artifact file paths")
    order = config.get("order", [])
    minimum = config.get("minimum_trials")
    if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 5:
        raise Invalid("minimum_trials must be at least five")
    if not isinstance(order, list) or any(v not in ("baseline", "candidate") for v in order):
        raise Invalid("order must contain only baseline/candidate")
    if any(order.count(v) < minimum for v in ("baseline", "candidate")):
        raise Invalid("order has inadequate trials")
    if any(order[i:i + 3] == [order[i]] * 3 for i in range(len(order) - 2)):
        raise Invalid("order must interleave variants; no three identical consecutive slots")
    number(config.get("timeout_seconds"), "timeout_seconds", 0.01)
    number(config.get("sample_seconds"), "sample_seconds", 0.02)
    thresholds = config.get("thresholds", {})
    number(thresholds.get("minimum_elapsed_improvement_pct"), "minimum_elapsed_improvement_pct", 0, 100)
    number(thresholds.get("maximum_elapsed_range_pct"), "maximum_elapsed_range_pct", 0)
    controls = config.get("controls", {})
    for key in ("power_source", "display_config", "brightness", "cache_mode", "background_load", "warmup"):
        if not isinstance(controls.get(key), str) or not controls[key].strip():
            raise Invalid(f"controls.{key} required")
    for key in ("ambient_C", "thermal_start_C", "battery_soc_percent"):
        bounds = controls.get(key)
        if not isinstance(bounds, list) or len(bounds) != 2:
            raise Invalid(f"controls.{key}: [minimum, maximum] required")
        number(bounds[0], key)
        number(bounds[1], key, bounds[0])
    allowed = config.get("allowed_state_changes", [])
    if not isinstance(allowed, list) or any(v not in ("kernel", "packages") for v in allowed):
        raise Invalid("only predeclared kernel/packages state differences allowed")
    if allowed and not config.get("state_change_evidence"):
        raise Invalid("state_change_evidence file required for allowed state changes")
    if "packages" in allowed:
        packages = config.get("changed_packages")
        if (not isinstance(packages, list) or not packages or len(set(packages)) != len(packages)
                or any(not isinstance(p, str) or not p or any(c.isspace() for c in p) for p in packages)):
            raise Invalid("changed_packages must name the exact packages changed by the sole experiment variable")
    if config["execution_context"] == "physical" and not config.get("hardware_gate_evidence"):
        raise Invalid("physical trials require reviewed baseline-functional and recovery evidence file")
    if ('platform_metrics' not in config and (config['sample_seconds'] > 60 or
            math.ceil((config['timeout_seconds'] + .5) / config['sample_seconds']) + 3 > 4096)):
        raise Invalid('v2 legacy owned RSS sample bound; redeclare a longer sample interval')
    validate_owned_rss(config)
    guardrails = thresholds.get("maximum_regression", {})
    if not isinstance(guardrails, dict):
        raise Invalid("maximum_regression must be an object")
    for key, limit in guardrails.items():
        if key not in ("root_rss_kib_pct", "process_group_sampled_rss_kib_pct", "thermal_raw_mC", "power_raw_uW_pct"):
            raise Invalid(f"unsupported guardrail {key}")
        number(limit, key, 0)
    domains = config.get("power_domains", {})
    if not isinstance(domains, dict):
        raise Invalid("power_domains must map sensor paths to reviewed identities")
    for path, review in domains.items():
        if not isinstance(path, str) or not isinstance(review, dict):
            raise Invalid("invalid power domain review")
        for key in ("domain", "reviewer", "evidence"):
            if not isinstance(review.get(key), str) or not review[key].strip():
                raise Invalid(f"power_domains.{path}.{key} required")
        for key in ("chip_name", "channel_label", "device"):
            if key not in review or (review[key] is not None and not isinstance(review[key], str)):
                raise Invalid(f"power_domains.{path}.{key} must record identity or explicit null")


def platform_adapter():
    """Load the optional instrumentation only when explicitly declared/selected."""
    global _platform_adapter
    if _platform_adapter is None:
        spec = importlib.util.spec_from_file_location('benchmark_platform_metrics', Path(__file__).with_name('benchmark_platform_metrics.py'))
        _platform_adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_platform_adapter)
    return _platform_adapter


def retirement_adapter():
    global _retirement_adapter
    path = Path(__file__).with_name('benchmark_owned_retirement.py')
    if path.is_symlink() or digest(path) != OWNED_RETIREMENT_ADAPTER_SHA256:
        raise Invalid('v2 owned retirement adapter source changed')
    if _retirement_adapter is None:
        spec = importlib.util.spec_from_file_location('benchmark_v2_retirement', path)
        _retirement_adapter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(_retirement_adapter)
    return _retirement_adapter


def execution_binding():
    adapter = retirement_adapter()
    return {'schema': EXECUTION_LAYER, 'runner': pin_file(Path(__file__).resolve()),
            'adapter': pin_file(Path(adapter.__file__).resolve()),
            'owner': pin_file(adapter.owner_path())}


def package_inventory(value):
    if not isinstance(value, str) or not value.strip():
        raise Invalid("package inventories must contain pacman name/version lines")
    inventory = {}
    for line in value.splitlines():
        pair = line.split()
        if len(pair) != 2 or pair[0] in inventory:
            raise Invalid("package inventory has malformed or duplicate pacman rows")
        name, version = pair
        inventory[name] = version
    return inventory


def plan_states(config, bindings):
    states = {v: json.loads(check_pin(pin, f"{v} state file")) for v, pin in bindings.items()}
    identities = {v: state_identity(s) for v, s in states.items()}
    inventories = {}
    for variant, identity in identities.items():
        if identity["execution_context"] != config["execution_context"]:
            raise Invalid("state execution context differs from plan")
        if config["execution_context"] == "physical":
            record = states[variant]
            capture = capture_source()
            compatible = identity["device_tree_compatible"]
            size = (capture.exact_target_size(identity["architecture"], compatible)
                    if isinstance(compatible, str) else None)
            if (size is None or size != identity["m2_air_size"]
                    or type(identity["page_size_bytes"]) is not int
                    or identity["page_size_bytes"] != capture.TARGET_PAGE_SIZE
                    or type(record.get("schema_version")) is not int or record["schema_version"] != 1
                    or record.get("record_type") != "environment-baseline"
                    or record.get("validation_result") != "NOT RUN"):
                raise Invalid("physical plan needs an exact M2 Air baseline capture with 16 KiB pages")
            query = record.get("packages", {})
            if (query.get("command") != ["pacman", "-Q"] or type(query.get("returncode")) is not int
                    or query["returncode"] != 0):
                raise Invalid("physical plan needs a successful captured pacman -Q package inventory")
        if config["execution_context"] == "physical" or identity["packages"] is not None:
            inventories[variant] = package_inventory(identity["packages"])
    differences = [key for key in identities["baseline"]
                   if identities["baseline"][key] != identities["candidate"][key]]
    if set(differences) != set(config.get("allowed_state_changes", [])):
        raise Invalid(f"state differences {differences} disagree with predeclared allowed_state_changes")
    if "packages" in differences:
        if inventories.keys() != identities.keys():
            raise Invalid("package changes need complete baseline and candidate inventories")
        names = set(inventories["baseline"]) | set(inventories["candidate"])
        changed = {name for name in names if inventories["baseline"].get(name) != inventories["candidate"].get(name)}
        if changed != set(config["changed_packages"]):
            raise Invalid(f"unrelated/missing package changes: observed {sorted(changed)}")
    return identities


def input_paths(config, binding, declared_from):
    paths = list(config["inputs"]) + [str(CAPTURE_SOURCE), str(Path(process_group_memory.__file__).resolve())]
    for values in config.get("variant_inputs", {}).values():
        paths.extend(values)
    if "platform_metrics" in config:
        paths.extend(str(p) for p in platform_adapter().source_paths())
    paths.extend(config[key] for key in ("state_change_evidence", "hardware_gate_evidence") if config.get(key))
    paths.extend(binding[key]["path"] for key in ("runner", "adapter", "owner"))
    return list(dict.fromkeys(str(declared_from / path) for path in paths))


def workload_argv(plan):
    """Use the exact pinned access paths for declared relative file operands."""
    config = plan["config"]
    declared_from = Path(plan["declared_from"])
    inputs = set(config["inputs"])
    for paths in config.get("variant_inputs", {}).values():
        inputs.update(paths)
    pinned_paths = {declared_from / path for path in inputs}

    def bind(value):
        path = Path(value)
        absolute = declared_from / path
        if value and not path.is_absolute() and absolute in pinned_paths:
            return str(absolute)
        return value

    argv = []
    for argument in config["argv"]:
        option, separator, value = argument.partition("=")
        if option.startswith("-"):
            argv.append(option + separator + bind(value) if separator else argument)
        else:
            argv.append(bind(argument))
    return argv


def validate_hardware_gates(config, pins, declared_from):
    if config.get("hardware_gate_evidence"):
        path = str(declared_from / config["hardware_gate_evidence"])
        gates = json.loads(check_pin(pins[path], "hardware gate evidence"))
        if (gates.get("machine_id") != config["machine_id"] or gates.get("base_id") != config["base_id"]
                or gates.get("baseline_functional") != "PASS" or gates.get("recovery") != "PASS"
                or not gates.get("evidence") or not gates.get("reviewer")):
            raise Invalid("hardware gates are not reviewed PASS evidence for this machine/base")


def freeze(config_path, baseline_path, candidate_path, output):
    config = read_json(config_path)
    validate_config(config)
    if "platform_metrics" in config:
        platform_adapter().validate_config(config["platform_metrics"], config["timeout_seconds"])
    states = {"baseline": pin_file(baseline_path), "candidate": pin_file(candidate_path)}
    identities = plan_states(config, states)
    binding = execution_binding()
    declared_from = Path.cwd()
    pins = {path: pin_file(path) for path in input_paths(config, binding, declared_from)}
    validate_hardware_gates(config, pins, declared_from)
    plan = {"schema_version": 2, "execution_layer": binding, "record_type": "frozen-experiment-plan-v2", "frozen_at": now(),
            "config": config, "declared_from": str(declared_from), "inputs": list(pins.values()), "states": identities,
            "baseline_binding": states["baseline"], "candidate_binding": states["candidate"],
            "optimization_acceptance": "NOT RUN"}
    write_json(output, plan)


def load_plan(path):
    plan = read_json(path)
    if plan.get("schema_version") != 2 or plan.get("record_type") != "frozen-experiment-plan-v2":
        raise Invalid("not a supported v2 frozen plan; historical plans must be redeclared")
    binding = execution_binding()
    if plan.get('execution_layer') != binding:
        raise Invalid('v2 execution binding missing/changed; historical plans must be redeclared')
    config = plan["config"]
    validate_config(config)
    if "platform_metrics" in config:
        platform_adapter().validate_config(config["platform_metrics"], config["timeout_seconds"])
    utc_timestamp(plan["frozen_at"])
    declared_from = Path(plan["declared_from"])
    if not declared_from.is_absolute():
        raise Invalid("plan declaration directory must be absolute")
    pins = {pin["path"]: pin for pin in plan["inputs"]}
    if pins.keys() != set(input_paths(config, binding, declared_from)) or len(pins) != len(plan["inputs"]):
        raise Invalid("declared input lacks an exact pin or has an extra or duplicate pin")
    for pin in pins.values():
        check_pin(pin, "input")
    validate_hardware_gates(config, pins, declared_from)
    states = {variant: plan[f"{variant}_binding"] for variant in ("baseline", "candidate")}
    if canonical(plan.get("states")) != canonical(plan_states(config, states)):
        raise Invalid("plan states differ from pinned captures")
    return plan


def validate_conditions(config, conditions):
    controls = config["controls"]
    for key in ("power_source", "display_config", "brightness", "cache_mode", "background_load", "warmup"):
        if conditions.get(key) != controls[key]:
            raise Invalid(f"uncontrolled condition: {key}")
    for key in ("ambient_C", "thermal_start_C", "battery_soc_percent"):
        number(conditions.get(key), key, *controls[key])
    if not conditions.get("operator") or not conditions.get("notes"):
        raise Invalid("conditions require operator and notes (including instrumentation/cache/warmup evidence)")


def sensor(path, unit):
    raw = text_file(path)
    try:
        value = int(raw)
        return {"path": str(path), "unit": unit, "value": value, "status": "available"}
    except (ValueError, TypeError):
        return {"path": str(path), "unit": unit, "value": None, "status": "unavailable",
                "reason": "attribute absent/unreadable" if raw is None else "noninteger driver reading"}


def telemetry(pid, sysroot=Path("/sys"), procroot=Path("/proc")):
    thermal = [sensor(p, "mC") | {"label": text_file(p.parent / "type")}
               for p in sorted((sysroot / "class/thermal").glob("thermal_zone*/temp"))]
    power = []
    for p in sorted((sysroot / "class/hwmon").glob("hwmon*/power*_input")):
        device = p.parent / "device"
        power.append(sensor(p, "uW") | {"chip_name": text_file(p.parent / "name"),
                     "channel_label": text_file(p.with_name(p.name.removesuffix("_input") + "_label")),
                     "device": str(device.resolve()) if device.exists() else None})
    battery = []
    units = {"energy_now": "uWh", "charge_now": "uAh", "power_now": "uW", "current_now": "uA",
             "voltage_now": "uV", "capacity": "percent", "temp": "tenths_C", "online": "driver_state"}
    for supply in sorted((sysroot / "class/power_supply").glob("*")):
        battery.append({"path": str(supply), "type": text_file(supply / "type"),
                        "status": text_file(supply / "status"),
                        "readings": [sensor(supply / key, unit) for key, unit in units.items()]})
    status_path = procroot / str(pid) / "status"
    status = text_file(status_path) or ""
    state = next((line.split()[1] for line in status.splitlines() if line.startswith("State:")), None)
    lifecycle = "exited" if state in ("Z", "X") or (not status and not status_path.exists()) else "live" if state else "unknown"
    rss = next((int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:")), None)
    meminfo = text_file(procroot / "meminfo") or ""
    available = next((int(line.split()[1]) for line in meminfo.splitlines()
                      if line.startswith("MemAvailable:")), None)
    return {"monotonic_ns": time.monotonic_ns(), "thermal": thermal, "power": power, "battery": battery,
            "process_group_memory": process_group_memory.sample(pid, procroot),
            "memory": {"root_rss_kib": rss, "system_available_kib": available,
                       "lifecycle": lifecycle, "proc_state": state, "path": str(status_path),
                       "scope": "sampled root process only; children/shared mappings excluded"},
            "missing": [name for name, values in (("thermal", thermal), ("power", power), ("battery", battery))
                        if not values]}


def legacy_sensor_snapshot(sysroot=Path("/sys"), procroot=Path("/proc")):
    thermal = [sensor(p, "mC") | {"label": text_file(p.parent / "type")}
               for p in sorted((sysroot / "class/thermal").glob("thermal_zone*/temp"))]
    power = []
    for p in sorted((sysroot / "class/hwmon").glob("hwmon*/power*_input")):
        device = p.parent / "device"
        power.append(sensor(p, "uW") | {"chip_name": text_file(p.parent / "name"),
                     "channel_label": text_file(p.with_name(p.name.removesuffix("_input") + "_label")),
                     "device": str(device.resolve()) if device.exists() else None})
    battery = []
    units = {"energy_now": "uWh", "charge_now": "uAh", "power_now": "uW", "current_now": "uA",
             "voltage_now": "uV", "capacity": "percent", "temp": "tenths_C", "online": "driver_state"}
    for supply in sorted((sysroot / "class/power_supply").glob("*")):
        battery.append({"path": str(supply), "type": text_file(supply / "type"),
                        "status": text_file(supply / "status"),
                        "readings": [sensor(supply / key, unit) for key, unit in units.items()]})
    return {"monotonic_ns": time.monotonic_ns(), "thermal": thermal, "power": power, "battery": battery,
            "memory": {"root_rss_kib": None, "lifecycle": "unknown"},
            "missing": [name for name, values in (("thermal", thermal), ("power", power), ("battery", battery))
                        if not values] + ["memory"],
            "reason": "PID-free sensors; child/root/group RSS is recorded separately by the owned supervisor"}


def execute(argv, cwd, env, directory, timeout, interval):
    return retirement_adapter().execute(argv, cwd, env, directory, timeout, interval,
                                        legacy_sensor_snapshot, metrics, owned_rss_metrics)


def metrics(samples):
    live = [s["memory"].get("root_rss_kib") for s in samples if s["memory"].get("lifecycle") == "live"]
    unknown = sum(s["memory"].get("lifecycle") not in ("live", "exited") for s in samples)
    coverage = {"live_samples": len(live), "missing_live_samples": sum(v is None for v in live),
                "excluded_exited_samples": sum(s["memory"].get("lifecycle") == "exited" for s in samples),
                "unknown_lifecycle_samples": unknown}
    result = {"root_rss_kib": max(live) if live and not unknown and all(v is not None for v in live) else None,
              "rss_coverage": coverage, "thermal": {}, "power": {}}
    result.update(process_group_memory.summarize([s.get("process_group_memory") for s in samples]))
    for group in ("thermal", "power"):
        paths = sorted({r["path"] for s in samples for r in s[group]})
        for path in paths:
            readings = [r["value"] for s in samples for r in s[group] if r["path"] == path]
            # Partial sensor coverage cannot silently yield a usable guardrail.
            result[group][path] = (max(readings) if group == "thermal" else statistics.median(readings)) if (
                len(readings) == len(samples) and all(v is not None for v in readings)) else None
    return result


# Owner-aware RSS is separately frozen; ordinary/default calls do not select it.
OWNED_RSS_CORE_SHA256 = '83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
OWNED_RSS_SCHEMA = 'benchmark-owned-group-rss-v1'


def validate_owned_rss(config):
    if 'owned_rss' not in config:
        return
    value = config['owned_rss']
    if ('platform_metrics' not in config or type(value) is not dict
            or set(value) != {'interval_seconds'}):
        raise Invalid('owned_rss requires platform_metrics and only interval_seconds')
    interval = value['interval_seconds']
    if (type(interval) not in (int, float) or not math.isfinite(interval)
            or not .01 <= interval <= 60
            or math.ceil((config['timeout_seconds'] + .5) / interval) + 1 > 4096):
        raise Invalid('owned RSS interval/retained sample bound')
    if digest(platform_adapter().dependencies()['owner']) != OWNED_RSS_CORE_SHA256:
        raise Invalid('owned RSS requires Root adoption of the prepared core/pin before freezing')


def owned_rss_metrics(rss, start, end, interval):
    """Validate captured member data offline; never probe a retired numeric PID."""
    def integer(value, low=0):
        if type(value) is not int or value < low:
            raise Invalid('owned RSS integer bound')
        return value

    if (type(rss) is not dict or rss.get('interval_seconds') != interval
            or rss.get('sample_budget_seconds') != .1
            or rss.get('scope') != process_group_memory.SCOPE
            or rss.get('process_group_rss_scope') != process_group_memory.SCOPE):
        raise Invalid('owned RSS schema/unit/scope/config mismatch')
    problem = rss.get('error')
    if problem is not None and (type(problem) is not str or not problem or len(problem) > 512):
        raise Invalid('owned RSS error field')
    samples = rss.get('samples')
    if type(samples) is not list or len(samples) > 4096:
        raise Invalid('owned RSS sample bound')
    previous, rows, group, leaders, excluded, incomplete = start, 0, None, [], 0, 0
    for sample in samples:
        gid = integer(sample['group_id'], 1)
        if group is not None and gid != group:
            raise Invalid('owned RSS group identity changed')
        group = gid
        began, ended = integer(sample['monotonic_start_ns']), integer(sample['monotonic_end_ns'])
        if not start <= previous <= began <= ended <= end or sample['scope'] != process_group_memory.SCOPE:
            raise Invalid('owned RSS clock/window/scope mismatch')
        previous = ended
        state = sample['status']
        members = sample['members']
        if state not in ('complete', 'exited', 'incomplete') or type(members) is not list or len(members) > 512:
            raise Invalid('owned RSS state/member bound')
        rows += len(members)
        if rows > 8192:
            raise Invalid('owned RSS retained member-row bound')
        ids, live, total, leader = set(), 0, 0, None
        for member in members:
            pid = integer(member['pid'], 1)
            integer(member['start_ticks'])
            value = integer(member['rss_kib'])
            integer(member['group'], 1); integer(member['session'], 1)
            if (pid in ids or member['group'] != gid or member['session'] != gid
                    or type(member['state']) is not str or len(member['state']) != 1):
                raise Invalid('owned RSS member identity mismatch')
            ids.add(pid)
            zombie = member['state'] in ('Z', 'X')
            if zombie and value != 0:
                raise Invalid('owned RSS zombie value mismatch')
            live += not zombie
            total += value
            if pid == gid:
                leader = member
        if state == 'complete':
            if not live or leader is None or type(sample['rss_sum_kib']) is not int or sample['rss_sum_kib'] != total:
                raise Invalid('owned RSS complete sum/leader mismatch')
            if leader['state'] not in ('Z', 'X'):
                leaders.append(leader['rss_kib'])
            else:
                excluded += 1
        elif state == 'exited':
            if live or leader is None or sample['rss_sum_kib'] is not None:
                raise Invalid('owned RSS exited snapshot mismatch')
            excluded += 1
        else:
            if sample['rss_sum_kib'] is not None or not sample.get('reason'):
                raise Invalid('owned RSS incomplete snapshot mismatch')
            incomplete += 1
    group_summary = process_group_memory.summarize(samples)
    usable = group_summary['process_group_sampled_rss_kib'] is not None and problem is None
    if not usable:
        group_summary['process_group_sampled_rss_kib'] = None
    root = max(leaders) if usable and leaders else None
    expected_state = 'complete' if usable else 'partial' if group_summary['process_group_observed_rss_kib'] is not None else 'error' if problem else 'unavailable'
    expected = group_summary | {'status': expected_state, 'leader_sampled_rss_kib': root,
                                'leader_observed_rss_kib': max(leaders) if leaders else None}
    if any(rss.get(key) != value for key, value in expected.items()):
        raise Invalid('owned RSS cached summary differs from member samples')
    return group_summary | {'root_rss_kib': root, 'rss_coverage': {
        'live_samples': len(leaders), 'missing_live_samples': incomplete,
        'excluded_exited_samples': excluded, 'unknown_lifecycle_samples': incomplete}}


def execute_owned_rss(config, argv, cwd, environment, output):
    """Pass only the built-in RSS option; no arbitrary PID callback/thread."""
    from types import SimpleNamespace
    adapter = platform_adapter()
    collector, owner = adapter.load_dependencies()
    if digest(owner.__file__) != OWNED_RSS_CORE_SHA256:
        raise Invalid('owner-aware RSS requires the prepared exact core; Root pin adoption is a prerequisite')
    interval = config['owned_rss']['interval_seconds']
    def supervise(child, **kwargs):
        return owner.supervise(child, **kwargs, rss_interval=interval)
    facade = SimpleNamespace(prepare=owner.prepare, supervise=supervise)
    previous = adapter.load_dependencies
    adapter.load_dependencies = lambda: (collector, facade)
    try:
        result = adapter.execute(argv, cwd, environment, output, config['timeout_seconds'],
                                 config['sample_seconds'], config['platform_metrics'], metrics)
    finally:
        adapter.load_dependencies = previous
    capture_data = collector.ordinary(output / 'platform-metrics/capture.json', 16 * 1024**2)
    capture = json.loads(capture_data)
    replayable = len(capture_data) <= collector.MAX_LINE
    observation = capture['supervision'].get('rss')
    raw = {'schema': OWNED_RSS_SCHEMA, 'owner_sha256': OWNED_RSS_CORE_SHA256,
           'interval_seconds': interval, 'monotonic_start_ns': result['monotonic_start_ns'],
           'monotonic_end_ns': result['monotonic_end_ns'], 'observation': observation}
    write_json(output / 'owned-rss.json', raw)
    projected = owned_rss_metrics(observation, raw['monotonic_start_ns'], raw['monotonic_end_ns'], interval)
    result['metrics'].update(projected)
    result['owned_rss'] = {'schema': OWNED_RSS_SCHEMA, 'owner_sha256': OWNED_RSS_CORE_SHA256,
                           'interval_seconds': interval, 'status': observation['status'],
                           'scope': process_group_memory.SCOPE, 'raw': 'owned-rss.json',
                           'capture_replayable': replayable}
    if not replayable:
        result['error'] = result['error'] or 'owned RSS capture exceeds metadata replay bound; retain raw evidence, no valid trial'
    if observation['status'] != 'complete' or projected['root_rss_kib'] is None:
        result['error'] = result['error'] or 'owned RSS incomplete/unavailable; diagnostic peaks are not usable'
    return result


def verify_owned_rss(directory, trial, config, legacy, *, raw_files=None):
    """Bind the new raw artifact to the existing source/clock/workload capture."""
    collector, owner = platform_adapter().load_dependencies()
    if digest(owner.__file__) != OWNED_RSS_CORE_SHA256:
        raise Invalid('owned RSS core source mismatch')
    def read(name, cap):
        return json.loads(raw_files[name] if raw_files is not None else collector.ordinary(directory / name, cap))

    raw = read('owned-rss.json', 16 * 1024**2)
    interval = config['owned_rss']['interval_seconds']
    expected_record = {'schema': OWNED_RSS_SCHEMA, 'owner_sha256': OWNED_RSS_CORE_SHA256,
                       'interval_seconds': interval, 'scope': process_group_memory.SCOPE,
                       'raw': 'owned-rss.json', 'status': raw['observation']['status'], 'capture_replayable': True}
    if trial.get('owned_rss') != expected_record:
        raise Invalid('owned RSS trial declaration differs from frozen/raw evidence')
    capture = read('platform-metrics/capture.json', collector.MAX_LINE)
    if (raw['schema'] != OWNED_RSS_SCHEMA or raw['owner_sha256'] != OWNED_RSS_CORE_SHA256
            or raw['interval_seconds'] != interval
            or raw['monotonic_start_ns'] != trial['monotonic_start_ns']
            or raw['monotonic_end_ns'] != trial['monotonic_end_ns']
            or raw['observation'] != capture['supervision'].get('rss')):
        raise Invalid('owned RSS capture/source/config/window mismatch')
    projected = owned_rss_metrics(raw['observation'], trial['monotonic_start_ns'], trial['monotonic_end_ns'], interval)
    supervision = capture['supervision']
    if trial.get('valid') is True and (
            supervision.get('passed') is not True or supervision.get('error') is not None
            or supervision.get('timeout') is not False or supervision.get('signals') != []
            or supervision.get('output_complete') is not True
            or supervision.get('group_census') != 'RESERVED_LEADER_ONLY'
            or raw['observation']['status'] != 'complete' or projected['root_rss_kib'] is None
            or projected['process_group_sampled_rss_kib'] is None):
        raise Invalid('successful owned RSS trial contradicts supervision/usable coverage evidence')
    return metrics(legacy) | projected


def paired_step(step, slot, *, measured_only=False):
    if (type(step) is not dict or set(step) != {"session_id", "phase", "index"}
            or not isinstance(step["session_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", step["session_id"])
            or type(step["index"]) is not int or step["index"] < 0
            or step["phase"] not in ("correctness", "warmup", "measured")
            or (step["phase"] == "measured" and step["index"] != slot)
            or (measured_only and step["phase"] != "measured")):
        raise Invalid("invalid paired zlib trial session, phase or slot")
    return step


def paired_replay(plan):
    pin = next(pin for pin in plan["inputs"] if pin["path"] == str(PAIRED_ZLIB_SOURCE))
    module = ModuleType("benchmark_paired_zlib_replay")
    module.__file__ = str(PAIRED_ZLIB_SOURCE)
    exec(compile(check_pin(pin, "paired zlib verifier"), module.__file__, "exec"), vars(module))
    module.validate(plan, plan["config"]["paired_zlib"] == "control-only", replay=True)
    return module.workload_check(plan)


def validate_observed_conditions(conditions, step, receipt, latest_at):
    if type(receipt) is not dict or set(receipt) != {"requested_at", "received_at", "sha256"}:
        raise Invalid("paired observed conditions receipt required")
    observation = conditions.get("observation") if type(conditions) is dict else None
    if (type(observation) is not dict or set(observation) != (step.keys() | {"observed_at"})
            or any(type(observation[key]) is not type(value) or observation[key] != value
                   for key, value in step.items())):
        raise Invalid("conditions observation differs from the requested session or step")
    requested, observed, received, latest = map(utc_timestamp, (
        receipt["requested_at"], observation["observed_at"], receipt["received_at"], latest_at))
    if not requested <= observed <= received <= latest:
        raise Invalid("conditions timestamps must follow request, observation, receipt and launch order")
    if (latest - observed).total_seconds() > OBSERVED_CONDITIONS_MAX_AGE:
        raise Invalid(f"conditions observation exceeds {OBSERVED_CONDITIONS_MAX_AGE}-second launch age limit")


def read_observed_conditions(path):
    return retirement_adapter().ordinary(path, OBSERVED_CONDITIONS_MAX_BYTES)


def check_conditions_pin(data, receipt):
    if hashlib.sha256(data).hexdigest() != receipt["sha256"]:
        raise Invalid("retained conditions differ from the accepted observation")


def verify_paired_conditions(directory, trial, proof, step, *, required):
    receipt = proof.get("conditions_receipt")
    if receipt is None:
        if required:
            raise Invalid("physical paired zlib requires observed conditions for this slot")
        return
    launch_checked_at = proof["conditions_launch_checked_at"]
    if not utc_timestamp(trial["started_at"]) <= utc_timestamp(launch_checked_at) <= utc_timestamp(trial["finished_at"]):
        raise Invalid("conditions launch check falls outside the trial")
    validate_observed_conditions(trial["conditions"], step, receipt, launch_checked_at)
    data = read_observed_conditions(directory / "conditions.json")
    check_conditions_pin(data, receipt)
    if json.loads(data) != trial["conditions"]:
        raise Invalid("trial conditions differ from retained observation")


def run(plan_path, slot, state_path, conditions_path, cwd, output, *, platform_metrics=False,
        paired=None, check_workload=None, conditions_receipt=None):
    if os.geteuid() == 0:
        raise Invalid("root workload execution is refused")
    plan = load_plan(plan_path)
    config = plan["config"]
    if type(platform_metrics) is not bool or platform_metrics != ("platform_metrics" in config):
        raise Invalid("platform metrics flag must match the frozen instrumentation declaration")
    if slot < 0 or slot >= len(config["order"]):
        raise Invalid("slot outside declared order")
    if "paired_zlib" in config:
        if not callable(check_workload):
            raise Invalid("paired zlib trials must run through paired_zlib_v2.py")
        paired_step(paired, slot)
        if config["paired_zlib"] == "exact-arm" and conditions_receipt is None:
            raise Invalid("physical paired zlib requires observed conditions for this slot")
    elif paired is not None or check_workload is not None or conditions_receipt is not None:
        raise Invalid("paired zlib execution requires a matching frozen plan")
    variant = config["order"][slot]
    if digest(state_path) != plan[f"{variant}_binding"]["sha256"]:
        raise Invalid("state record does not match frozen variant binding")
    if live_identity(config["execution_context"]) != plan["states"][variant]:
        raise Invalid("live machine/base differs from frozen state; recapture and predeclare a new plan")
    observed = read_observed_conditions(conditions_path) if conditions_receipt is not None else None
    conditions = json.loads(observed) if observed is not None else read_json(conditions_path)
    if observed is not None:
        validate_observed_conditions(conditions, paired, conditions_receipt, now())
        check_conditions_pin(observed, conditions_receipt)
    validate_conditions(config, conditions)
    cwd = Path(cwd).resolve(strict=True)
    if not cwd.is_dir():
        raise Invalid("cwd must be a caller-selected isolated directory")
    argv = workload_argv(plan)
    output = Path(output)
    output.mkdir(parents=False, exist_ok=False)
    environment = os.environ.copy()
    environment.update(config.get("env", {}))
    declared_env = config.get("env", {}) | config.get("variant_env", {}).get(variant, {})
    environment.update(declared_env)
    comparable_env = environment.copy()
    if config.get("variant_env"):
        comparable_env.pop(config["change"]["environment_key"], None)
    record = {"schema_version": 1, "record_type": "benchmark-trial", "plan_sha256": digest(plan_path),
              "slot": slot, "variant": variant, "started_at": now(), "hostname": platform.node(),
              "machine_id": config["machine_id"], "base_id": config["base_id"],
              "workload_id": config["workload_id"], "state": plan["states"][variant],
              "conditions": conditions, "argv": argv, "cwd": str(cwd),
              "environment_sha256": canonical(environment), "comparable_environment_sha256": canonical(comparable_env),
              "declared_environment": declared_env,
              "execution_label": "M2 physical measurement pending review" if config["execution_context"] == "physical"
              else f"{platform.machine()}/{config['execution_context']} nonacceptance smoke",
              "optimization_acceptance": "NOT RUN"}
    if paired is not None:
        record["paired_zlib"] = {"step": paired}
    if observed is not None:
        record["paired_zlib"]["conditions_receipt"] = conditions_receipt
        (output / "conditions.json").write_bytes(observed)
    write_json(output / "started.json", record)
    if observed is not None:
        launch_checked_at = now()
        validate_observed_conditions(conditions, paired, conditions_receipt, launch_checked_at)
        record["paired_zlib"]["conditions_launch_checked_at"] = launch_checked_at
    if platform_metrics and "owned_rss" in config:
        result = execute_owned_rss(config, argv, cwd, environment, output)
    elif platform_metrics:
        result = platform_adapter().execute(argv, cwd, environment, output,
                                            config["timeout_seconds"], config["sample_seconds"], config["platform_metrics"], metrics)
    else:
        result = execute(argv, cwd, environment, output, config["timeout_seconds"], config["sample_seconds"])
    record.update(result)
    record["finished_at"] = now()
    if platform_metrics:
        record["raw_sha256"] = {str(p.relative_to(output)): digest(p) for p in output.rglob('*')
                                if p.is_file() and p != output / 'started.json'}
    else:
        separate_receipts = {"started.json"}
        if observed is not None:
            separate_receipts.add("conditions.json")
        record["raw_sha256"] = {p.name: digest(p) for p in output.iterdir() if p.name not in separate_receipts}
    record["state_after"] = live_identity(config["execution_context"])
    record["valid"] = (result["error"] is None and result["returncode"] == 0
                       and record["state_after"] == record["state"])
    if paired is not None:
        if record["valid"]:
            try:
                adapter = retirement_adapter()
                stdout = adapter.ordinary(output / "stdout.txt", adapter.MAX_OUTPUT)
                if hashlib.sha256(stdout).hexdigest() != record["raw_sha256"]["stdout.txt"]:
                    raise Invalid("paired stdout changed before workload verification")
                report = check_workload(stdout, variant)
                if type(report) is not dict:
                    raise Invalid("paired workload verification did not return a report")
                record["paired_zlib"]["report"] = report
            except (OSError, ValueError, KeyError, TypeError) as error:
                record["valid"] = False
                record["error"] = f"paired workload verification failed: {str(error)[:400]}"
        publish_paired_trial(output / "trial.json", record)
    else:
        write_json(output / "trial.json", record)
    return 0 if record["valid"] else 2


def describe(values):
    median = statistics.median(values)
    return {"n": len(values), "median": median, "minimum": min(values), "maximum": max(values),
            "median_absolute_deviation": statistics.median(abs(v - median) for v in values),
            "range_pct_of_median": 100 * (max(values) - min(values)) / median if median else None}


def sensor_identity(sample):
    return {group: sorted([{key: reading.get(key) for key in keys} for reading in sample[group]],
                          key=lambda value: value["path"])
            for group, keys in (("thermal", ("path", "label", "unit")),
                                ("power", ("path", "chip_name", "channel_label", "device", "unit")))}


def compare(plan_path, directories, output):
    plan = load_plan(plan_path)
    config = plan["config"]
    argv = workload_argv(plan)
    platform_reader = platform_adapter() if 'platform_metrics' in config else None
    trials, sensor_ids = [], None
    check_workload = paired_replay(plan) if "paired_zlib" in config else None
    session_id = None
    for directory in directories:
        directory = Path(directory)
        trial = read_json(directory / "trial.json")
        if ("owned_rss" in config) != ("owned_rss" in trial):
            raise Invalid("owned RSS instrumentation differs from frozen plan")
        if ("platform_metrics" in config) != ("platform_metrics" in trial):
            raise Invalid("trial instrumentation differs from frozen plan")
        if trial.get("record_type") != "benchmark-trial" or trial.get("plan_sha256") != digest(plan_path):
            raise Invalid("differing plan/base/machine/workload binding")
        slot = trial.get("slot")
        if isinstance(slot, bool) or not isinstance(slot, int) or not 0 <= slot < len(config["order"]):
            raise Invalid("invalid trial slot")
        variant = config["order"][slot]
        for key in ("machine_id", "base_id", "workload_id"):
            if trial.get(key) != config[key]:
                raise Invalid(f"differing {key}")
        if trial.get("argv") != argv:
            raise Invalid("differing argv")
        if (trial.get("state") != plan["states"][variant] or trial.get("state_after") != trial.get("state")
                or trial.get("variant") != variant):
            raise Invalid("differing observed variant machine/base state")
        validate_conditions(config, trial["conditions"])
        if trial.get("valid") is not True or trial.get("returncode") != 0 or trial.get("error") is not None:
            raise Invalid("failed/interrupted workload; retain evidence and declare a new complete block")
        if (check_workload is not None) != ("paired_zlib" in trial):
            raise Invalid("paired zlib trial admission differs from frozen plan")
        sampling = trial.get("sampling_status", {})
        if (sampling.get("worker_stopped") is not True or sampling.get("workload_reaped") is not True
                or sampling.get("error") is not None or sampling.get("dropped_samples") != 0):
            raise Invalid("incomplete telemetry or cleanup status")
        number(trial.get("elapsed_ns"), "elapsed_ns", 1)
        start = number(trial.get("monotonic_start_ns"), "monotonic_start_ns", 0)
        end = number(trial.get("monotonic_end_ns"), "monotonic_end_ns", start)
        if end - start != trial["elapsed_ns"]:
            raise Invalid("elapsed duration differs from monotonic boundaries")
        if utc_timestamp(trial["finished_at"]) < utc_timestamp(trial["started_at"]):
            raise Invalid("trial timestamps reversed")
        if utc_timestamp(trial["started_at"]) < utc_timestamp(plan["frozen_at"]):
            raise Invalid("trial predates frozen plan; clock discontinuity requires a new declaration")
        expected_env = config.get("env", {}) | config.get("variant_env", {}).get(variant, {})
        if trial.get("declared_environment") != expected_env:
            raise Invalid("differing declared environment")
        expected_raw = {"stdout.txt", "stderr.txt", "telemetry.jsonl"}
        if "platform_metrics" in config:
            expected_raw.update('platform-metrics/' + name for name in
                                ('started.json', 'inventory.json', 'samples.jsonl', 'capture.json', 'summary.json'))
        if "owned_rss" in config:
            expected_raw.add("owned-rss.json")
        if 'platform_metrics' not in config:
            expected_raw.add('owned-retirement.json')
        if set(trial.get("raw_sha256", {})) != expected_raw:
            raise Invalid("missing raw outputs")
        bounded_raw = (platform_reader.raw_files(directory, owned_rss='owned_rss' in config)
                       if platform_reader is not None else retirement_adapter().raw_files(directory))
        for name, expected in trial["raw_sha256"].items():
            observed = hashlib.sha256(bounded_raw[name]).hexdigest()
            if observed != expected:
                raise Invalid(f"raw output changed: {name}")
        if check_workload is not None:
            proof = trial["paired_zlib"]
            if type(proof) is not dict:
                raise Invalid("invalid paired zlib trial proof")
            step = paired_step(proof["step"], slot, measured_only=True)
            if session_id is not None and step["session_id"] != session_id:
                raise Invalid("paired zlib measurements belong to different sessions")
            session_id = step["session_id"]
            verify_paired_conditions(directory, trial, proof, step, required=config["paired_zlib"] == "exact-arm")
            if proof.get("report") != check_workload(bounded_raw["stdout.txt"], variant):
                raise Invalid("paired workload report differs from verified stdout")
        if platform_reader is None:
            samples = [json.loads(line) for line in bounded_raw['telemetry.jsonl'].splitlines()]
        else:
            platform_reader.verify_trial(directory, trial, config['platform_metrics'], raw=bounded_raw)
            samples = [platform_reader.unavailable_legacy(start)]
        if not samples or trial.get("sample_count", len(samples)) != len(samples):
            raise Invalid("missing telemetry samples or differing sample count")
        times = [number(s.get("monotonic_ns"), "sample monotonic_ns", start, end) for s in samples]
        if times != sorted(times):
            raise Invalid("telemetry timestamps are out of order")
        if platform_reader is None:
            measured = retirement_adapter().verify(directory, trial, config['sample_seconds'], samples,
                                                    metrics, owned_rss_metrics)
        else:
            measured = (verify_owned_rss(directory, trial, config, samples, raw_files=bounded_raw)
                        if 'owned_rss' in config else metrics(samples))
        if trial.get("metrics") != measured:
            raise Invalid("summary differs from raw telemetry")
        for sample in samples:
            identity = sensor_identity(sample)
            if sensor_ids is not None and identity != sensor_ids:
                raise Invalid("sensor source/chip/channel/device/unit changed within or between trials")
            sensor_ids = identity
        trials.append(trial)
    trials.sort(key=lambda t: t["slot"])
    if [t["slot"] for t in trials] != list(range(len(config["order"]))):
        raise Invalid("inadequate, duplicate or missing trials; complete predeclared order required")
    if len({t["hostname"] for t in trials}) != 1 or len({t["comparable_environment_sha256"] for t in trials}) != 1:
        raise Invalid("differing host or inherited environment")
    for before, after in zip(trials, trials[1:]):
        if utc_timestamp(before["finished_at"]) > utc_timestamp(after["started_at"]):
            raise Invalid("trials overlap or run out of predeclared order")
    summary = {v: describe([t["elapsed_ns"] / 1e9 for t in trials if t["variant"] == v])
               for v in ("baseline", "candidate")}
    improvement = 100 * (1 - summary["candidate"]["median"] / summary["baseline"]["median"])
    failures, missing = [], []
    if improvement < config["thresholds"]["minimum_elapsed_improvement_pct"]:
        failures.append("elapsed improvement below declared useful threshold")
    for variant, stats in summary.items():
        if stats["range_pct_of_median"] > config["thresholds"]["maximum_elapsed_range_pct"]:
            failures.append(f"{variant} elapsed variability above declared limit")
    guardrails = {}
    for name, budget in config["thresholds"].get("maximum_regression", {}).items():
        group = "thermal" if name == "thermal_raw_mC" else "power" if name == "power_raw_uW_pct" else None
        keys = sorted({key for t in trials for key in t["metrics"][group]}) if group else ["process_group_sampled_rss_kib" if name == "process_group_sampled_rss_kib_pct" else "root_rss_kib"]
        if not keys:
            missing.append(name)
        for key in keys:
            if group == "power":
                review = config.get("power_domains", {}).get(key)
                observed = next(reading for reading in sensor_ids["power"] if reading["path"] == key)
                if review is None or any(review[field] != observed[field] for field in ("chip_name", "channel_label", "device")):
                    missing.append(f"{name}:{key}: unreviewed/mismatched power domain")
                    continue
            values = {v: [(t["metrics"][group].get(key) if group else t["metrics"].get(key))
                          for t in trials if t["variant"] == v] for v in summary}
            if any(x is None for xs in values.values() for x in xs):
                missing.append(f"{name}:{key}")
                continue
            medians = {v: statistics.median(xs) for v, xs in values.items()}
            if name.endswith("_pct") and medians["baseline"] <= 0:
                missing.append(f"{name}:{key}: nonpositive baseline")
                continue
            delta = medians["candidate"] - medians["baseline"]
            regression = 100 * delta / medians["baseline"] if name.endswith("_pct") else delta
            guardrails[f"{name}:{key}"] = {"baseline": medians["baseline"], "candidate": medians["candidate"],
                                           "regression": regression, "budget": budget}
            if regression > budget:
                failures.append(f"guardrail exceeded: {name}:{key}")
    result = {"schema_version": 1, "record_type": "preliminary-comparison", "plan_sha256": digest(plan_path),
              "summary_seconds": summary, "median_elapsed_improvement_pct": improvement,
              "guardrails": guardrails, "failures": failures, "missing_guardrail_telemetry": missing,
              "preliminary_result": "FAIL" if failures else "INCOMPLETE" if missing else "MEETS_TIMING_RULE_ONLY",
              "optimization_acceptance": "NOT RUN",
              "limitations": ["No confidence interval or population/performance claim is inferred from medians.",
                              "Operator controls and state-change scope require independent review.",
                              "Frame/interactive latency, power/battery, suspend, sustained thermals, functional and recovery gates require separate physical evidence."],
              "trial_bindings": [{"slot": t["slot"], "directory": str(Path(d).resolve()),
                                  "sha256": digest(Path(d) / "trial.json")}
                                 for d in directories for t in [read_json(Path(d) / "trial.json")]]}
    write_json(output, result)
    return 2 if failures or missing else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare-plan")
    prepare.add_argument("--config", required=True, type=Path)
    prepare.add_argument("--baseline", required=True, type=Path)
    prepare.add_argument("--candidate-state", required=True, type=Path)
    prepare.add_argument("--output", required=True, type=Path)
    runner = commands.add_parser("run")
    runner.add_argument("--plan", required=True, type=Path)
    runner.add_argument("--slot", required=True, type=int)
    runner.add_argument("--state", required=True, type=Path)
    runner.add_argument("--conditions", required=True, type=Path)
    runner.add_argument("--cwd", required=True, type=Path)
    runner.add_argument("--output", required=True, type=Path)
    runner.add_argument("--platform-metrics", action="store_true", help="use the frozen optional platform instrumentation")
    comparator = commands.add_parser("compare")
    comparator.add_argument("--plan", required=True, type=Path)
    comparator.add_argument("--runs", required=True, nargs="+", type=Path)
    comparator.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "prepare-plan":
            freeze(args.config, args.baseline, args.candidate_state, args.output)
            return 0
        if args.command == "run":
            return run(args.plan, args.slot, args.state, args.conditions, args.cwd, args.output, platform_metrics=args.platform_metrics)
        return compare(args.plan, args.runs, args.output)
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"benchmark refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
