#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors.
"""Run bounded regressions against a helper using temporary homes/templates only."""
import argparse
import copy
import hashlib
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def load_helper(path):
    loader = SourceFileLoader("cachy_asahi_packaged_fixture", str(path))
    module = module_from_spec(spec_from_loader(loader.name, loader))
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def fixture(root, module):
    home, templates = root / "home", root / "templates"
    home.mkdir(mode=0o700)
    templates.mkdir(mode=0o700)
    for relative in module.TEMPLATES.values():
        path = templates / relative
        path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        path.write_bytes(b"# trusted fixture; never sourced\n")
        path.chmod(0o600)
    return home, templates


def invoke(helper, home, templates, arguments):
    env = dict(os.environ, HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
               XDG_STATE_HOME=str(home / ".local/state"), XDG_DATA_HOME=str(home / ".local/share"),
               XDG_CACHE_HOME=str(home / ".cache"), ZDOTDIR=str(home), PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-B", str(helper), *arguments,
                           "--home", str(home), "--template-root", str(templates)],
                          cwd=home, env=env, capture_output=True, text=True, timeout=30)


def oversized(root, module, helper, apply, mixed):
    home, templates = fixture(root, module)
    component = "zsh" if mixed else "fish"
    target = home / (".zshrc" if mixed else ".config/fish/config.fish")
    target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    original = b"#" * (module.MAX_BYTES - 33) + b"\n"
    target.write_bytes(original)
    target.chmod(0o600)
    observed = {target: original}
    if mixed:
        fish = home / ".config/fish/config.fish"
        fish.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        fish.write_bytes(b"# existing fish config\n")
        fish.chmod(0o600)
        observed[fish] = fish.read_bytes()
    assert len(original) <= module.MAX_BYTES
    assert len(original + module.block(component, templates / module.TEMPLATES[component]).encode()) > module.MAX_BYTES
    args = ["activate", "--components", *( ["fish", "zsh"] if mixed else ["fish"] )]
    result = invoke(helper, home, templates, args + (["--apply"] if apply else []))
    failures = []
    if result.returncode != 1:
        failures.append(f"expected refusal exit 1, got {result.returncode}")
    if any(path.read_bytes() != before for path, before in observed.items()):
        failures.append("activation changed configuration before rejecting oversized output")
    state = home / ".local/state/cachy-asahi/setup"
    if (state / "journal.json").exists() or (state / "state.json").exists():
        failures.append("planning refusal left journal or committed state")
    if not apply and state.exists():
        failures.append("preview created state storage")
    return failures


def forged_journal(root, module, helper, apply):
    home, templates = fixture(root, module)
    target = home / ".config/fish/config.fish"
    target.parent.mkdir(parents=True, mode=0o700)
    before = b"# existing fish config\n"
    target.write_bytes(before)
    target.chmod(0o600)
    setup = module.Setup(home, templates)
    atomic = setup.fs.atomic
    intercepted = []

    def interrupt(path, data, expected, private=False):
        if path == setup.targets["fish"] and not private:
            intercepted.append(path)
            raise module.Error("temporary fixture interruption before first config write")
        return atomic(path, data, expected, private=private)

    setup.fs.atomic = interrupt
    try:
        try:
            setup.run("activate", ("fish",), apply=True)
        except module.Error:
            pass
        journal_path = home / setup.journal_path
        assert intercepted and journal_path.is_file() and target.read_bytes() == before
        journal = json.loads(journal_path.read_bytes())
    finally:
        setup.close()
    unapproved = root / "unapproved-templates"
    unapproved.mkdir(mode=0o700)
    entry = journal["entries"][0]
    assert entry["component"] == "fish" and entry["change"]["type"] == "append"
    new = copy.deepcopy(entry["new_record"])
    new["source_root"] = str(unapproved)
    new["block"] = module.block("fish", unapproved / module.TEMPLATES["fish"])
    entry["new_record"] = new
    journal["new_state"]["components"]["fish"] = copy.deepcopy(new)
    entry["change"]["new"] = new["block"]
    entry["after"] = module.checksum(before + new["block"].encode())
    forged = (json.dumps(journal, sort_keys=True, indent=2) + "\n").encode()
    journal_path.write_bytes(forged)
    journal_path.chmod(0o600)
    result = invoke(helper, home, templates, ["recover"] + (["--apply"] if apply else []))
    failures = []
    if result.returncode != 1:
        failures.append(f"expected forged-root refusal exit 1, got {result.returncode}")
    if target.read_bytes() != before:
        failures.append("recovery published forged source-root shell block")
    if not journal_path.exists() or journal_path.read_bytes() != forged:
        failures.append("recovery removed or changed the refused journal")
    if (home / ".local/state/cachy-asahi/setup/state.json").exists():
        failures.append("recovery committed forged component state")
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", type=Path, default=Path(__file__).with_name("cachy-asahi-setup"))
    args = parser.parse_args()
    helper = args.helper.resolve()
    if os.geteuid() == 0 or not helper.is_file():
        parser.error("run as non-root and select an existing reviewed helper")
    module = load_helper(helper)
    results = []
    for kind, mixed in (("oversized-fish", False), ("mixed-oversized-zsh", True), ("forged-journal-root", False)):
        for apply in (False, True):
            name = kind + ("-apply" if apply else "-preview")
            with tempfile.TemporaryDirectory(prefix="cachy-asahi-packaged-regression-") as temporary:
                root = Path(temporary)
                try:
                    errors = (forged_journal(root, module, helper, apply) if kind == "forged-journal-root"
                              else oversized(root, module, helper, apply, mixed))
                    if list(root.rglob("__pycache__")):
                        errors.append("fixture created bytecode directories")
                except (AssertionError, OSError, ValueError, subprocess.TimeoutExpired) as error:
                    errors = [f"fixture failed: {type(error).__name__}: {error}"]
                results.append({"case": name, "passed": not errors, "failures": errors})
    passed = all(item["passed"] for item in results)
    print(json.dumps({"result": "PASS" if passed else "FAIL", "helper_sha256": hashlib.sha256(helper.read_bytes()).hexdigest(),
                      "scope": "temporary homes/templates only; no shell blocks or session commands executed", "cases": results}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
