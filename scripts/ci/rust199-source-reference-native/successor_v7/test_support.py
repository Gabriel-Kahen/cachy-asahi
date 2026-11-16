# SPDX-License-Identifier: MIT
"""Assemble portable test-only code DATA; never constructs an actual native Source."""
import atexit
import hashlib
import json
from pathlib import Path
import shutil
import tempfile

HERE=Path(__file__).resolve().parent


def assembled(successor=True):
    temporary=tempfile.TemporaryDirectory(prefix='FENCED-rust-v7-code-')
    atexit.register(temporary.cleanup)
    root=Path(temporary.name)/'payload'
    shutil.copytree(HERE.parent/'payload',root)
    for source in (HERE.parent/'successor_v2/payload',HERE.parent/'successor_v3/payload',HERE.parent/'successor_v4/payload',HERE.parent/'successor_v5/payload',HERE.parent/'successor_v6/payload'):
        shutil.copytree(source,root,dirs_exist_ok=True)
    shutil.copytree(HERE.parent/'candidate',root/'packages/port/rust199-source-reference')
    if successor:shutil.copytree(HERE/'payload',root,dirs_exist_ok=True)
    return root
