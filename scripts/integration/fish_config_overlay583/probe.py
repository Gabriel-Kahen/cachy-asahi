# SPDX-License-Identifier: MIT
"""The same installed-configuration startup probe for all three Fish phases."""

from pathlib import PurePosixPath

ACCOUNT = "caa-fish-upgrade-guest"
UID = 29084
PRIVATE = PurePosixPath("/run/caa-fish-upgrade")
HOME = PRIVATE/"home"
USER_CONFIG = ".config/fish/config.fish"
SENTINEL = "keep-through-fish-upgrade"
USER_BYTES = ("# Existing private Fish edits\nset -g CAA_FISH_UPGRADE_SENTINEL "+SENTINEL+"\n").encode()
PHASES = ("before", "upgraded", "restored")
SCRIPT = r'''
set -l work "$argv[1]"
set -l uid "$argv[2]"
test (command id -u) = "$uid"; or exit 30
test "$CAA_FISH_UPGRADE_SENTINEL" = 'keep-through-fish-upgrade'; or exit 31
functions -q caa_mcd; or exit 32
command mkdir -p -- "$work/lookup/space directory"; or exit 33
cd -- "$work"; or exit 34
set -gx CDPATH "$work/lookup"
caa_mcd 'space directory'; or exit 35
test "$CDPATH" = "$work/lookup"; or exit 36
test -d "$work/space directory"; or exit 37
printf 'CAA_FISH_UPGRADE\t%s\t%s\t%s\n' (command id -u) "$PWD" "$CDPATH"
'''


def command(target, phase):
    if phase not in PHASES:
        raise ValueError("Unknown fixed Fish lifecycle phase")
    return ["/usr/bin/chroot", str(target), "/usr/bin/runuser", "-u", ACCOUNT, "--", "/usr/bin/env", "-i",
            "HOME="+str(HOME), "XDG_CONFIG_HOME="+str(HOME/".config"),
            "XDG_DATA_HOME="+str(HOME/".local/share"), "XDG_STATE_HOME="+str(HOME/".local/state"),
            "XDG_CACHE_HOME="+str(HOME/".cache"), "PATH=/usr/bin:/bin", "LC_ALL=C.UTF-8", "TZ=UTC", "TERM=dumb",
            "/usr/bin/fish", "--private", "--interactive", "--command", SCRIPT, str(HOME/phase), str(UID)]


def receipt(raw, work, uid, *, expect_local):
    tag=b"CAA_FISH_UPGRADE\t"
    rows=[line for line in raw.splitlines() if line.startswith(tag)]
    leaf=str(work)+"/space directory"
    lookup=str(work)+"/lookup"
    selected=leaf if expect_local else lookup+"/space directory"
    if rows != [tag+str(uid).encode()+b"\t"+selected.encode()+b"\t"+lookup.encode()]:
        raise ValueError("Original Fish startup or CDPATH result differs")
    return dict(ordinary_uid=uid, entered=selected, cdpath=lookup, created_local=leaf,
                local_selected=expect_local, scripted_interactive=True)
