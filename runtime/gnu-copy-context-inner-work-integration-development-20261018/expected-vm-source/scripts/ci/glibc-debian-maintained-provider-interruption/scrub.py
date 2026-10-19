#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Retired-consumer recovery only: dispose two explicitly named private roots."""
import os
from pathlib import Path
import platform
import shutil

def main():
    root=Path('/work')
    assert os.geteuid()==0 and platform.machine()=='aarch64' and Path('/.dockerenv').is_file()
    assert os.environ.get('CACHY_GNU_PROVIDER_INTERRUPTION')=='1' and root.is_mount() and not root.is_symlink()
    assert shutil.rmtree.avoids_symlink_attacks
    assert set(p.name for p in root.iterdir())<={'pristine','modified'}
    for path in root.iterdir():
        assert path.is_dir() and not path.is_symlink() and not path.is_mount()
        shutil.rmtree(path)
    assert not any(root.iterdir())
    os.chown(root,int(os.environ['OUTPUT_UID']),int(os.environ['OUTPUT_GID']))

if __name__=='__main__':main()
