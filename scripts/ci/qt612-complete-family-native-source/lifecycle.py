# SPDX-License-Identifier: MIT
"""Normal package lifecycle commands for a separately owned disposable ARM image."""

import re
from pathlib import Path

TRANSACTION_CONFIG = "/family-trust/pacman.conf"
SIGNED_DIR = "/family-signed/"
PROBE = "/family/lifecycle.py"

# Only these absolute library paths are opened by the disposable native probe.
LIBRARY = re.compile(r"/usr/lib/libQt6[A-Za-z0-9]+\.so\.6")


def command_plan(row, base_inventory, qualified_pin, archive_pin):
    """Return an exact transaction ledger with final state equal to the base."""
    package = row["package"]
    archive = SIGNED_DIR + row["filename"]
    depends = row["metadata"]["depends"]
    provides = row["metadata"]["provides"]
    libraries = ["/usr/lib/" + name for name in provides if name.startswith("libQt6")]
    if not libraries or not all(LIBRARY.fullmatch(name) for name in libraries):
        raise ValueError("Expected pinned Qt module SONAMEs")
    base = dict(line.split(" ", 1) for line in base_inventory.decode("ascii").splitlines())
    if package in base or len(base) not in range(356, 361):
        raise ValueError("A clean pinned stage inventory is required")
    installed = dict(base, **{package: "6.12.0-1"})
    after = "".join(f"{name} {version}\n" for name, version in sorted(installed.items()))
    pacman = ["/usr/bin/pacman", "--config", TRANSACTION_CONFIG]
    steps = []

    def add(role, argv, seconds, output=None):
        steps.append(dict(role=role, argv=argv, seconds=seconds, exact_stdout=output))

    def inventory(role, expected):
        add(role, pacman + ["-Q"], 15, expected)

    def install(role):
        add(role, pacman + ["-U", "--noconfirm", archive], 240)

    def remove(role):
        add(role, pacman + ["-R", "--noconfirm", package], 120)

    inventory("before", base_inventory.decode("ascii"))
    install("install")
    inventory("installed", after)
    add("normal-dependencies", pacman + ["-T", *depends], 30, "")
    add("package-files", pacman + ["-Qk", package], 60)
    add("module-loads", ["/usr/bin/python3", "-I", "-B", PROBE, "load", *libraries], 60,
        "PASS_INSTALLED_QT_MODULE_LOADS\n")
    if "shadertools" in package:
        add("installed-qsb", ["/usr/lib/qt6/bin/qsb", "--version"], 10)
    install("reinstall")
    inventory("reinstalled", after)
    remove("rollback-to-base")
    inventory("rolled-back", base_inventory.decode("ascii"))
    install("reinstall-after-rollback")
    inventory("restored", after)
    remove("remove")
    inventory("removed", base_inventory.decode("ascii"))
    return dict(schema=1, kind="QT612_DISPOSABLE_COMPONENT_LIFECYCLE_V1",
                package=package, archive=archive, archive_pin=archive_pin, qualification_pin=qualified_pin,
                signature_policy="Required TrustedOnly", steps=steps)


def validate_receipt(plan, result, *, canonical_pin):
    """Join the exact commands and output of the authenticated private executor."""
    if (type(result) is not dict or result.get("plan_pin") != canonical_pin(plan)
            or result.get("signature_policy") != "Required TrustedOnly"
            or result.get("archive_pin") != plan["archive_pin"]
            or result.get("configuration_unchanged") is not True
            or result.get("host_state_unchanged") is not True):
        raise ValueError("Current authenticated lifecycle evidence is required")
    signature = result.get("signature_pin")
    if (type(signature) is not dict or set(signature) != {"bytes", "sha256"}
            or type(signature["bytes"]) is not int or not 0 < signature["bytes"] <= 1024 * 1024
            or not isinstance(signature["sha256"], str) or not re.fullmatch("[0-9a-f]{64}", signature["sha256"])):
        raise ValueError("The authenticated detached signature needs a whole pin")
    receipts = result.get("commands")
    if type(receipts) is not list or len(receipts) != len(plan["steps"]):
        raise ValueError("Complete ordered lifecycle command evidence is required")
    for step, receipt in zip(plan["steps"], receipts, strict=True):
        if (receipt.get("role") != step["role"] or receipt.get("argv") != step["argv"]
                or type(receipt.get("exit")) is not int or receipt["exit"] != 0
                or any(receipt.get(key) is not True for key in ("natural", "reaped", "output_complete"))):
            raise ValueError("Lifecycle command failed or did not retire: " + step["role"])
        stdout = receipt.get("stdout")
        if type(stdout) is not str or len(stdout.encode()) > 1024 * 1024:
            raise ValueError("Finite lifecycle output is required")
        expected = step["exact_stdout"]
        if expected is not None and stdout != expected:
            raise ValueError("Lifecycle inventory, dependencies or module load differs: " + step["role"])
        if step["role"] == "installed-qsb" and not re.search(r"\b6\.12\.0\b", stdout):
            raise ValueError("The installed qsb must report the selected Qt version")


def load_modules(paths):
    """Native module loader invoked only in the authenticated lifecycle image."""
    import ctypes
    import os
    import sys

    if (sys.argv[1:2] != ["load"] or os.uname().machine != "aarch64"
            or len(paths) > 24 or not paths or len(paths) != len(set(paths))
            or os.environ.get("QT612_FAMILY_PRIVATE_LIFECYCLE") != "1"):
        raise ValueError("The selected native lifecycle environment is required")
    libraries = []
    for name in paths:
        if not LIBRARY.fullmatch(name) or not Path(name).is_file():
            raise ValueError("Expected an installed Qt SONAME")
        path = Path(name).resolve(strict=True)
        if path != Path(name + ".12.0"):
            raise ValueError("Unexpected installed Qt library target")
        libraries.append(ctypes.CDLL(str(path), mode=os.RTLD_NOW | os.RTLD_LOCAL))
    print("PASS_INSTALLED_QT_MODULE_LOADS")


if __name__ == "__main__":
    import sys
    load_modules(sys.argv[2:])
