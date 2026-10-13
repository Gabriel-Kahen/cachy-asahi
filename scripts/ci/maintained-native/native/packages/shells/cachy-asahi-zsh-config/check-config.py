#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run host Zsh checks in a temporary HOME; never install the package."""
from pathlib import Path
import subprocess
import tempfile

config = str(Path(__file__).with_name("config.zsh").resolve())
cases = {
    "noninteractive_noop": (False, 'PROMPT=mine; source "$1"; [[ $PROMPT == mine && ${+_CACHY_ASAHI_ZSH_LOADED} == 0 ]]'),
    "completion_and_preservation": (True, 'PROMPT=mine; HISTFILE=mine; alias make=mine; source "$1"; [[ ${+_comps} == 1 && $PROMPT == mine && $HISTFILE == mine && $aliases[make] == mine ]]'),
    "completion_optout": (True, 'CACHY_ASAHI_ZSH_COMPLETION=0; source "$1"; [[ ${+_comps} == 0 && $_CACHY_ASAHI_ZSH_LOADED == 1 ]]'),
    "existing_completion": (True, 'typeset -A _comps=(mine mine); source "$1"; [[ $_comps[mine] == mine && ${#_comps} == 1 ]]'),
    "prompt_optin": (True, 'CACHY_ASAHI_ZSH_PROMPT=1; source "$1"; [[ $PROMPT == "%n@%m %~ %# " ]]'),
    "repeated_source": (True, 'source "$1"; PROMPT=mine; source "$1"; [[ $PROMPT == mine ]]'),
    "removed_config_guard": (True, 'PROMPT=mine; [[ ! -r "$HOME/removed/config.zsh" ]] || source "$HOME/removed/config.zsh"; [[ $PROMPT == mine ]]'),
}
subprocess.run(["zsh", "-n", config], check=True)
with tempfile.TemporaryDirectory(prefix="cachy-asahi-zsh-check-") as home:
    env = {"HOME": home, "XDG_CACHE_HOME": home + "/cache", "PATH": "/usr/bin:/bin", "TERM": "dumb", "LANG": "C"}
    Path(home, ".zshrc").write_text("# user-owned sentinel\n")
    before = {str(p.relative_to(home)): p.read_bytes() for p in Path(home).rglob("*") if p.is_file()}
    for name, (interactive, code) in cases.items():
        args = ["zsh", "-d", "-f"] + (["-i"] if interactive else [])
        result = subprocess.run(args + ["-c", code, "--", config], env=env, capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f"{name}: {result.returncode}: {result.stderr}")
        print(f"PASS {name}")
    after = {str(p.relative_to(home)): p.read_bytes() for p in Path(home).rglob("*") if p.is_file()}
    assert before == after, "The configuration changed user files"
    assert sorted(p.name for p in Path(home).iterdir()) == [".zshrc"], "The configuration created files or directories"
    print("PASS user_files_unchanged")
