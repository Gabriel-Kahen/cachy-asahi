#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Expose this pinned Perl's core scripts with package-owned relative links."""
import argparse
from pathlib import Path
import stat

COMMANDS = tuple('''corelist cpan enc2xs encguess h2ph h2xs instmodsh json_pp
libnetcfg perlbug perldoc perlivp perlthanks piconv pl2pm pod2html pod2man
pod2text pod2usage podchecker prove ptar ptardiff ptargrep shasum splain
streamzip xsubpp zipdetails'''.split())


def deliver(root):
    root = Path(root)
    if not (root.is_absolute() and root == root.resolve() and root != Path('/')):
        raise ValueError('canonical non-root staging directory required')
    bindir = root/'usr/bin'
    core = bindir/'core_perl'
    for path in (root, root/'usr', bindir, core):
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise ValueError('ordinary staging directories required')
    if {p.name for p in core.iterdir()} != set(COMMANDS):
        raise ValueError('exact pinned core command set required')
    # Validate the entire set before creating anything. Never replace a path,
    # including a dangling link, directory or file owned by another package.
    for name in COMMANDS:
        script = core/name
        mode = script.lstat().st_mode
        if not stat.S_ISREG(mode) or stat.S_IMODE(mode) != 0o755:
            raise ValueError('ordinary executable core script required: '+name)
        if (bindir/name).exists() or (bindir/name).is_symlink():
            raise ValueError('command destination already exists: '+name)
    for name in COMMANDS:
        (bindir/name).symlink_to('core_perl/'+name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    deliver(parser.parse_args().root)
