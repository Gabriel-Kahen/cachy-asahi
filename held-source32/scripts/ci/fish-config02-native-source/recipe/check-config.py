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

    def run(code, interactive=True, arguments=()):
        command = ["fish", "--no-config", "--private"]
        if interactive:
            command.append("--interactive")
        # Argument passing preserves paths containing whitespace or shell tokens.
        result = subprocess.run(command + ["--command", code, str(config), *map(str, arguments)],
                                cwd=work, env=env, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr + result.stdout
        return result.stdout

    run('source "$argv[1]"; functions -q caa_ll; and exit 9; true', False)
    assert run('function caa_ll; echo existing; end; source "$argv[1]"; caa_ll').strip() == "existing"
    run('source "$argv[1]"; source "$argv[1]"; caa_mcd "space directory"; test "$PWD" = "' + work + '/space directory"')
    assert (Path(work) / "space directory").is_dir()
    run('source "$argv[1]"; caa_mcd "-leading"; test -d "$PWD"')
    lookup = Path(work) / "lookup"
    lookup.mkdir()
    for target in ("target", "space directory", "-leading", "-"):
        (lookup / target).mkdir()
        run('source "$argv[1]"; set -gx CDPATH "$argv[2]/lookup"; '
            'caa_mcd "$argv[3]"; or exit 9; '
            'test "$PWD" = "$argv[2]/$argv[3]"; and test "$CDPATH" = "$argv[2]/lookup"',
            arguments=(work, target))
        assert (Path(work) / target).is_dir()
    absolute = Path(work) / "absolute directory"
    run('source "$argv[1]"; set -gx CDPATH "$argv[2]/lookup"; '
        'caa_mcd "$argv[3]"; or exit 9; test "$PWD" = "$argv[3]"',
        arguments=(work, absolute))
    (Path(work) / "collision").write_text("existing file")
    for target in ("collision", ""):
        run('source "$argv[1]"; set -l before "$PWD"; '
            'caa_mcd "$argv[2]" 2>/dev/null; set -l result $status; '
            'test $result -eq 1; and test "$PWD" = "$before"', arguments=(target,))
    assert (Path(work) / "collision").read_text() == "existing file"
    run('source "$argv[1]"; caa_mcd; test $status -eq 2')
    run('source "$argv[1]"; caa_mcd one two; test $status -eq 2')
    assert "space directory" in run('source "$argv[1]"; caa_ll')
    run('source "$argv[1]"; for n in grubup fixpacman update mirror cleanup; functions -q $n; and exit 9; end; true')
    assert not (Path(work) / "config/fish/fish_variables").exists()
print("PASS: noninteractive guard, existing helpers, repeated source, CDPATH-independent relative/absolute paths, mkdir failure preservation, no privileged aliases or universal-variable writes")
