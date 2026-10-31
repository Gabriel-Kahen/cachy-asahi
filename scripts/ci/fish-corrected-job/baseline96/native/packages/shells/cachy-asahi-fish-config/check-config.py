#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exercise opt-in behavior in temporary homes; no installed user config is read."""
import os
from pathlib import Path
import subprocess
import tempfile

config = Path(__file__).with_name("config.fish").resolve()
with tempfile.TemporaryDirectory(prefix="cachy-asahi-fish-") as work:
    env = dict(os.environ, HOME=work, XDG_CONFIG_HOME=work + "/config",
               XDG_DATA_HOME=work + "/data", TERM="xterm-256color")

    def run(code, interactive=True):
        command = ["fish", "--no-config", "--private"]
        if interactive:
            command.append("--interactive")
        # Argument passing preserves paths containing whitespace or shell tokens.
        result = subprocess.run(command + ["--command", code, str(config)],
                                cwd=work, env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr + result.stdout
        return result.stdout

    run('source "$argv[1]"; functions -q caa_ll; and exit 9; true', False)
    assert run('function caa_ll; echo existing; end; source "$argv[1]"; caa_ll').strip() == "existing"
    run('source "$argv[1]"; source "$argv[1]"; caa_mcd "space directory"; test "$PWD" = "' + work + '/space directory"')
    assert (Path(work) / "space directory").is_dir()
    run('source "$argv[1]"; caa_mcd "-leading"; test -d "$PWD"')
    run('source "$argv[1]"; caa_mcd; test $status -eq 2')
    run('source "$argv[1]"; caa_mcd one two; test $status -eq 2')
    assert "space directory" in run('source "$argv[1]"; caa_ll')
    run('source "$argv[1]"; for n in grubup fixpacman update mirror cleanup; functions -q $n; and exit 9; end; true')
    assert not (Path(work) / "config/fish/fish_variables").exists()
print("PASS: noninteractive guard, existing helpers, repeated source, safe path handling, no privileged aliases or universal-variable writes")
