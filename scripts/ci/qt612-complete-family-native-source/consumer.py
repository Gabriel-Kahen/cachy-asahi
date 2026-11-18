# SPDX-License-Identifier: MIT
"""Join E's installed desktop checks to a separately authorized Qt family image."""

import importlib.util
import os
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent


def local(name):
    spec = importlib.util.spec_from_file_location("family_consumer_"+name, HERE/(name+".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


C, P, W = local("common"), local("pipeline"), local("consumer_worker")
M, need = C.M, C.need
TIMEOUT = 1080
MEMORY_BYTES = 2 * 1024**3


def commands(*, source, source_map_sha256, image, inventory, output, nonce):
    source, inventory, output = map(M.ordinary, (source, inventory, output))
    need(not output.exists() and output.parent.is_dir() and not output.is_relative_to(source)
         and not source.is_relative_to(output), "Fresh private consumer output required")
    need(re.fullmatch(r"sha256:[a-f0-9]{64}", image or "") and re.fullmatch("[a-f0-9]{32}", nonce or ""),
         "Immutable image and stage nonce required")
    need(not any(ch in str(p) for p in (source, inventory, output) for ch in ",\n"),
         "Unambiguous container mount paths required")
    mapping = C.read_source(source, source_map_sha256)
    lock = C.load_lock()["consumer"]
    need(mapping["input_plan_complete"] is True and mapping.get("desktop_consumer") == lock["commit"],
         "Held signed dependency or consumer input")
    files = {name.removeprefix("consumer/"): row for name, row in mapping["files"].items()
             if name.startswith("consumer/")}
    need(files == {name: dict(pin, mode=0o644) for name, pin in lock["files"].items()},
         "Exact frozen consumer source closure required")
    expected = P.expected_inventory(source, mapping, P.DESKTOP_CONSUMER)
    inventory_pin = P.inventory_pin(inventory, 361, expected_raw=expected)
    worker = source/"scripts/ci/qt612-complete-family-native-source/consumer_worker.py"
    container = "cachy-qt612-desktop-"+nonce
    argv = ["/usr/bin/docker", "run", "--rm", "--name", container, "--pull=never", "--platform", "linux/arm64",
            "--network", "none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--cpus", "1", "--memory", "2g", "--memory-swap", "2g", "--pids-limit", "128",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--tmpfs", "/scratch:rw,nosuid,nodev,exec,size=1g",
            "--env", "QT612_FAMILY_DESKTOP_WORKER=1",
            "--mount", f"type=bind,src={source/'consumer'},dst=/consumer,readonly",
            "--mount", f"type=bind,src={worker},dst=/worker.py,readonly",
            "--mount", f"type=bind,src={inventory},dst=/expected-inventory,readonly",
            "--mount", f"type=bind,src={output},dst=/out",
            "--entrypoint", "/usr/bin/python3", image, "-I", "-B", "/worker.py"]
    return dict(component=P.DESKTOP_CONSUMER, image=image, inventory_pin=inventory_pin,
                source_map_sha256=source_map_sha256, consumer_commit=lock["commit"], argv=argv,
                container=container, timeout=TIMEOUT, Root_binding=None)


def observed_owner(path, resolved, package):
    parts = Path(path).parts
    components = C.load_lock()["components"]
    names = {key: row["package"] for key, row in components.items()}
    if path == "/usr/bin/wayland-scanner":
        return package == "wayland" and resolved == path
    if W.WAYLAND.fullmatch(path):
        return package == "wayland" and bool(W.WAYLAND.fullmatch(resolved)) and path.split(".so.",1)[0] == resolved.split(".so.",1)[0]
    if path in W.TOOLS:
        expected = "shadertools" if path.endswith("/qsb") else "gui_server"
        return package == names[expected] and path == resolved
    if W.PLUGIN.fullmatch(path):
        if "/qml/QtWayland/" in path:
            expected = "wayland"
        elif "/qml/" in path:
            expected = "declarative"
        elif path.endswith("/libqsvg.so"):
            expected = "svg"
        elif path.endswith("/libqoffscreen.so"):
            expected = "gui_server"
        else:
            return resolved == path and package in names.values()
        return package == names[expected] and resolved == path
    if W.LIB.fullmatch(path) and ".." not in parts:
        soname = path.removeprefix("/usr/lib/").removesuffix(".12.0")
        matches = {row["package"] for row in components.values() if soname in row["metadata"]["provides"]}
        return resolved == "/usr/lib/"+soname+".12.0" and (package in matches if matches else package in names.values())
    return False


def read_result(output, plan, *, inventory):
    """Read original logs, per-process runtime objects and exact owner evidence."""
    output = M.ordinary(output)
    expected_inventory = M.stream(inventory, plan["inventory_pin"], {}, collect=True)
    checks = C.load_lock()["consumer"]["checks"]
    logs = {"inventory-before.log", "configure.log", "build.log", "test-list.log", "tests.log",
            "ctest.xml", "inventory-after.log", "worker.json"}
    traces = set()
    for path in output.iterdir():
        need(not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode), "Ordinary consumer evidence required")
        if re.fullmatch(r"loader\.[1-9][0-9]{0,9}", path.name):
            traces.add(path.name)
        else:
            need(path.name in logs, "Unexpected consumer evidence")
        need(len(traces) <= 16, "Finite library-loader evidence required")
    names = logs | traces
    observed, rows, raw = {}, {}, {}
    total = 0
    for name in sorted(names):
        body = M.stream(output/name, None, observed, collect=True, cap=W.MAX_FILE)
        total += len(body)
        need(total <= 24 * 1024**2, "Consumer evidence byte budget")
        raw[name] = body
        rows[name] = C.pin(body)
    for phase in ("before", "after"):
        need(b"".join(sorted(raw["inventory-"+phase+".log"].splitlines(keepends=True))) == expected_inventory,
             "Different installed inventory in consumer image")
    W.validate_list(raw["test-list.log"], checks)
    W.validate_junit(raw["ctest.xml"], checks)
    need(all(tool.encode() in raw["build.log"] for tool in W.TOOLS),
         "Installed qsb, rcc and both Wayland scanners must execute in the consumer build")
    loaded = W.loader_paths([raw[name] for name in sorted(traces)], checks)
    report = M.decode(raw["worker.json"])
    inventory_command = ["/usr/bin/pacman", "-Q"]
    command_rows = [("inventory-before", inventory_command)] + [(role, argv) for role, argv, _ in W.commands(checks)]
    command_rows.append(("inventory-after", inventory_command))
    need(set(report) == {"commands", "owners"} and
         report["commands"] == [dict(role=role, argv=argv, exit=0) for role, argv in command_rows],
         "Exact consumer command sequence required")
    paths = W.TOOLS | {path for group in loaded.values() for path in group}
    for row in report["owners"].values():
        M.descriptor(row["body"],128*1024**2)
        need(row["body"]["bytes"]>0,"Nonempty installed library/tool body required")
    need(set(report["owners"]) == paths and all(
        set(row) == {"resolved", "package", "body"} and observed_owner(path, row["resolved"], row["package"])
        for path, row in report["owners"].items()), "Consumer object ownership differs from the selected family")
    need({p.name for p in output.iterdir()} == names, "Consumer evidence namespace changed")
    M.unchanged(observed)
    return dict(status="PASS_QT612_INSTALLED_DESKTOP_CONSUMER_EVIDENCE_ONLY",
                consumer_commit=plan["consumer_commit"], image=plan["image"], inventory_pin=plan["inventory_pin"],
                checks=sorted(checks), loaded=loaded, installed_objects=report["owners"],
                files=rows, Root_acceptance=None, native_acceptance=None)


def run_stage(*, source, source_map_sha256, inventory, output, executor):
    component = P.DESKTOP_CONSUMER
    binding = P.require_actual_family(component, source=source, source_map_sha256=source_map_sha256)
    need(getattr(executor, "API", None) == "ROOT_QT612_COMPLETE_FAMILY_OWNED_EXECUTOR_V1",
         "Selected owned family executor required")
    plan = commands(source=source, source_map_sha256=source_map_sha256, image=binding["image"],
                    inventory=inventory, output=output, nonce=binding["nonce"])
    need(plan["inventory_pin"] == binding["inventory_pin"], "Selected installed inventory differs")
    mapping = C.read_source(source, source_map_sha256)
    for name in ("consumer.py", "consumer_worker.py", "pipeline.py"):
        row = mapping["files"]["scripts/ci/qt612-complete-family-native-source/"+name]
        M.stream(HERE/name, {key: row[key] for key in ("bytes", "sha256")}, {}, mode=0o644)
    executor.authenticate_Root_stage_binding(binding)
    executor.require_domain(P.POLICY)
    executor.require_signed_inventory(component=component, image=plan["image"], inventory_pin=plan["inventory_pin"],
                                      previous_providers=list(C.ORDER), signature_policy="Required TrustedOnly")
    executor.require_no_containers()
    writer = M.Writer(output)
    writer.close()
    receipt = executor.run(plan["argv"], plan["timeout"], env={})
    need(type(receipt.get("exit")) is int and receipt["exit"] == 0
         and all(receipt.get(key) is True for key in ("natural", "reaped", "output_complete")),
         "The native desktop consumer did not finish naturally")
    executor.require_absent_twice(plan["container"])
    executor.require_no_containers()
    return read_result(output, plan, inventory=inventory)
