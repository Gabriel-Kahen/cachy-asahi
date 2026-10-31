#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Remove only the recorded owned preparation stage after all actors retire."""
import os
from pathlib import Path
import shutil
import stat
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

def main():
    C.need(os.getuid()==os.geteuid()==0 and Path('/.dockerenv').is_file() and os.environ.get('CAA_INSTALLED16K_PREPARE')=='1' and Path('/out').is_mount(),'owned scrub container only')
    selection=C.decode(C.read('/selection/selection.json'));marker=C.decode(C.read('/out/preparation-owner.json'));stage=Path('/out/stage');info=stage.lstat()
    C.need(shutil.rmtree.avoids_symlink_attacks and marker['nonce']==selection['nonce'] and marker['stage']==[info.st_dev,info.st_ino] and stat.S_ISDIR(info.st_mode) and not stage.is_mount(),'exact recorded ordinary stage inode required')
    shutil.rmtree(stage);C.need(not stage.exists() and not stage.is_symlink(),'recorded stage remains')

if __name__=='__main__':main()
