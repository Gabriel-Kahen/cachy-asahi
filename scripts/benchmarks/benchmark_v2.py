#!/usr/bin/env python3
"""Version 2 owned-retirement measurement orchestration. Workloads execute as argv in caller-owned cwd.

This tool never grants optimization acceptance. Workloads themselves are trusted
operator code; no shell execution is used by the harness, but this is not a sandbox.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import queue
import signal
import statistics
import subprocess
import sys
import threading
import time

_memory_spec = importlib.util.spec_from_file_location('process_group_memory', Path(__file__).with_name('process_group_memory.py'))
process_group_memory = importlib.util.module_from_spec(_memory_spec)
_memory_spec.loader.exec_module(process_group_memory)

CLEANUP_SECONDS = 0.25
_active_sampler = None
_platform_adapter = None
_retirement_adapter = None
OWNED_RETIREMENT_ADAPTER_SHA256 = '0d682260c424abf4207b90cc92607528ae1b17656ebd3093d4e9d3919463748c'
EXECUTION_LAYER = "benchmark-owned-retirement-v2"


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
    if (str(Path(pin["path"]).resolve(strict=True)) != pin["resolved_path"]
            or digest(pin["path"]) != pin["sha256"]):
        raise Invalid(f"{label} changed after declaration: {pin['path']}")


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
    packages = record.get("packages", {})
    return {key: record.get(key) for key in (
        "architecture", "machine_model", "device_tree_compatible", "page_size_bytes",
        "kernel", "os_release", "execution_context", "m2_air_size")} | {
        "packages": packages.get("stdout") if packages.get("returncode") == 0 else None,
        "repositories": [{"name": db["name"], "sha256": db.get("sha256")}
                         for db in record.get("repositories", {}).get("sync_databases", [])]}


def live_identity(context):
    try:
        result = subprocess.run(["pacman", "-Q"], capture_output=True, text=True, timeout=20)
        packages = result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        packages = None
    compatible = text_file("/proc/device-tree/compatible")
    size = None
    if platform.machine() == "aarch64":
        ids = (compatible or "").splitlines()
        size = "13-inch" if "apple,j413" in ids else "15-inch" if "apple,j415" in ids else None
    return {"architecture": platform.machine(), "machine_model": text_file("/proc/device-tree/model"),
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


def freeze(config_path, baseline_path, candidate_path, output):
    config = read_json(config_path)
    validate_config(config)
    if "platform_metrics" in config:
        platform_adapter().validate_config(config["platform_metrics"], config["timeout_seconds"])
    states = {"baseline": read_json(baseline_path), "candidate": read_json(candidate_path)}
    identities = {v: state_identity(s) for v, s in states.items()}
    differences = [key for key in identities["baseline"]
                   if identities["baseline"][key] != identities["candidate"][key]]
    if set(differences) != set(config.get("allowed_state_changes", [])):
        raise Invalid(f"state differences {differences} disagree with predeclared allowed_state_changes")
    if "packages" in differences:
        inventories = {}
        for variant, identity in identities.items():
            lines = (identity["packages"] or "").splitlines()
            if not lines or any(len(line.split()) != 2 for line in lines):
                raise Invalid("package inventories must contain pacman name/version lines")
            inventories[variant] = dict(line.split() for line in lines)
        names = set(inventories["baseline"]) | set(inventories["candidate"])
        changed = {name for name in names if inventories["baseline"].get(name) != inventories["candidate"].get(name)}
        if changed != set(config["changed_packages"]):
            raise Invalid(f"unrelated/missing package changes: observed {sorted(changed)}")
    for identity in identities.values():
        if identity["execution_context"] != config["execution_context"]:
            raise Invalid("state execution context differs from plan")
        if config["execution_context"] == "physical":
            expected = {"13-inch": "apple,j413", "15-inch": "apple,j415"}.get(identity["m2_air_size"])
            ids = (identity["device_tree_compatible"] or "").splitlines()
            if (identity["architecture"] != "aarch64" or expected is None or expected not in ids
                    or identity["packages"] is None):
                raise Invalid("physical acceptance plan needs an exact M2 Air record and package inventory")
    paths = list(config["inputs"])
    for source in (str(Path(__file__).resolve()), str(Path(process_group_memory.__file__).resolve())):
        if source not in paths:
            paths.append(source)
    for values in config.get("variant_inputs", {}).values():
        paths.extend(values)
    if "platform_metrics" in config:
        paths.extend(str(p) for p in platform_adapter().source_paths())
    pins = [pin_file(p) for p in paths]
    for key in ("state_change_evidence", "hardware_gate_evidence"):
        if config.get(key):
            evidence = Path(config[key]).absolute()
            if key == "hardware_gate_evidence":
                gates = read_json(evidence)
                if (gates.get("machine_id") != config["machine_id"] or gates.get("base_id") != config["base_id"]
                        or gates.get("baseline_functional") != "PASS" or gates.get("recovery") != "PASS"
                        or not gates.get("evidence") or not gates.get("reviewer")):
                    raise Invalid("hardware gates are not reviewed PASS evidence for this machine/base")
            pins.append(pin_file(evidence))
    for entry in execution_binding().values():
        if isinstance(entry, dict) and entry['path'] not in {p['path'] for p in pins}:
            pins.append(entry)
    plan = {"schema_version": 2, "execution_layer": execution_binding(), "record_type": "frozen-experiment-plan-v2", "frozen_at": now(),
            "config": config, "inputs": pins, "states": identities,
            "baseline_binding": pin_file(baseline_path), "candidate_binding": pin_file(candidate_path),
            "optimization_acceptance": "NOT RUN"}
    write_json(output, plan)


def load_plan(path):
    plan = read_json(path)
    if plan.get("schema_version") != 2 or plan.get("record_type") != "frozen-experiment-plan-v2":
        raise Invalid("not a supported v2 frozen plan; historical plans must be redeclared")
    if plan.get('execution_layer') != execution_binding():
        raise Invalid('v2 execution binding missing/changed; historical plans must be redeclared')
    validate_config(plan["config"])
    if "platform_metrics" in plan["config"]:
        platform_adapter().validate_config(plan["config"]["platform_metrics"], plan["config"]["timeout_seconds"])
    utc_timestamp(plan["frozen_at"])
    for variant in ("baseline", "candidate"):
        check_pin(plan[f"{variant}_binding"], f"{variant} state file")
    for pin in plan["inputs"]:
        check_pin(pin, "input")
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


def verify_owned_rss(directory, trial, config, legacy):
    """Bind the new raw artifact to the existing source/clock/workload capture."""
    collector, owner = platform_adapter().load_dependencies()
    if digest(owner.__file__) != OWNED_RSS_CORE_SHA256:
        raise Invalid('owned RSS core source mismatch')
    raw = json.loads(collector.ordinary(directory / 'owned-rss.json', 16 * 1024**2))
    interval = config['owned_rss']['interval_seconds']
    expected_record = {'schema': OWNED_RSS_SCHEMA, 'owner_sha256': OWNED_RSS_CORE_SHA256,
                       'interval_seconds': interval, 'scope': process_group_memory.SCOPE,
                       'raw': 'owned-rss.json', 'status': raw['observation']['status'], 'capture_replayable': True}
    if trial.get('owned_rss') != expected_record:
        raise Invalid('owned RSS trial declaration differs from frozen/raw evidence')
    capture = json.loads(collector.ordinary(directory / 'platform-metrics/capture.json', collector.MAX_LINE))
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


def run(plan_path, slot, state_path, conditions_path, cwd, output, *, platform_metrics=False):
    if os.geteuid() == 0:
        raise Invalid("root workload execution is refused")
    plan = load_plan(plan_path)
    config = plan["config"]
    if type(platform_metrics) is not bool or platform_metrics != ("platform_metrics" in config):
        raise Invalid("platform metrics flag must match the frozen instrumentation declaration")
    if slot < 0 or slot >= len(config["order"]):
        raise Invalid("slot outside declared order")
    variant = config["order"][slot]
    if digest(state_path) != plan[f"{variant}_binding"]["sha256"]:
        raise Invalid("state record does not match frozen variant binding")
    if live_identity(config["execution_context"]) != plan["states"][variant]:
        raise Invalid("live machine/base differs from frozen state; recapture and predeclare a new plan")
    conditions = read_json(conditions_path)
    validate_conditions(config, conditions)
    cwd = Path(cwd).resolve(strict=True)
    if not cwd.is_dir():
        raise Invalid("cwd must be a caller-selected isolated directory")
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
              "conditions": conditions, "argv": config["argv"], "cwd": str(cwd),
              "environment_sha256": canonical(environment), "comparable_environment_sha256": canonical(comparable_env),
              "declared_environment": declared_env,
              "execution_label": "M2 physical measurement pending review" if config["execution_context"] == "physical"
              else f"{platform.machine()}/{config['execution_context']} nonacceptance smoke",
              "optimization_acceptance": "NOT RUN"}
    write_json(output / "started.json", record)
    if platform_metrics and "owned_rss" in config:
        result = execute_owned_rss(config, config["argv"], cwd, environment, output)
    elif platform_metrics:
        result = platform_adapter().execute(config["argv"], cwd, environment, output,
                                            config["timeout_seconds"], config["sample_seconds"], config["platform_metrics"], metrics)
    else:
        result = execute(config["argv"], cwd, environment, output, config["timeout_seconds"], config["sample_seconds"])
    record.update(result)
    record["finished_at"] = now()
    if platform_metrics:
        record["raw_sha256"] = {str(p.relative_to(output)): digest(p) for p in output.rglob('*')
                                if p.is_file() and p != output / 'started.json'}
    else:
        record["raw_sha256"] = {p.name: digest(p) for p in output.iterdir() if p.name != "started.json"}
    record["state_after"] = live_identity(config["execution_context"])
    record["valid"] = (result["error"] is None and result["returncode"] == 0
                       and record["state_after"] == record["state"])
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
    trials, sensor_ids = [], None
    for directory in directories:
        directory = Path(directory)
        trial = read_json(directory / "trial.json")
        if ("owned_rss" in config) != ("owned_rss" in trial):
            raise Invalid("owned RSS instrumentation differs from frozen plan")
        if ("platform_metrics" in config) != ("platform_metrics" in trial):
            raise Invalid("trial instrumentation differs from frozen plan")
        if "platform_metrics" in config:
            platform_adapter().verify_trial(directory, trial, config["platform_metrics"])
        if trial.get("record_type") != "benchmark-trial" or trial.get("plan_sha256") != digest(plan_path):
            raise Invalid("differing plan/base/machine/workload binding")
        slot = trial.get("slot")
        if isinstance(slot, bool) or not isinstance(slot, int) or not 0 <= slot < len(config["order"]):
            raise Invalid("invalid trial slot")
        variant = config["order"][slot]
        for key in ("machine_id", "base_id", "workload_id", "argv"):
            if trial.get(key) != config[key]:
                raise Invalid(f"differing {key}")
        if (trial.get("state") != plan["states"][variant] or trial.get("state_after") != trial.get("state")
                or trial.get("variant") != variant):
            raise Invalid("differing observed variant machine/base state")
        validate_conditions(config, trial["conditions"])
        if trial.get("valid") is not True or trial.get("returncode") != 0 or trial.get("error") is not None:
            raise Invalid("failed/interrupted workload; retain evidence and declare a new complete block")
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
        bounded_raw = retirement_adapter().raw_files(directory) if 'platform_metrics' not in config else None
        for name, expected in trial["raw_sha256"].items():
            observed = hashlib.sha256(bounded_raw[name]).hexdigest() if bounded_raw is not None else digest(directory / name)
            if observed != expected:
                raise Invalid(f"raw output changed: {name}")
        telemetry_bytes = bounded_raw['telemetry.jsonl'] if bounded_raw is not None else (directory / "telemetry.jsonl").read_bytes()
        samples = [json.loads(line) for line in telemetry_bytes.splitlines()]
        if not samples or trial.get("sample_count", len(samples)) != len(samples):
            raise Invalid("missing telemetry samples or differing sample count")
        times = [number(s.get("monotonic_ns"), "sample monotonic_ns", start, end) for s in samples]
        if times != sorted(times):
            raise Invalid("telemetry timestamps are out of order")
        if 'platform_metrics' not in config:
            measured = retirement_adapter().verify(directory, trial, config['sample_seconds'], samples,
                                                    metrics, owned_rss_metrics)
        else:
            measured = verify_owned_rss(directory, trial, config, samples) if "owned_rss" in config else metrics(samples)
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
