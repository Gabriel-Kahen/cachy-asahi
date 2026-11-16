# SPDX-License-Identifier: MIT
"""Assemble test-only code operands; never constructs a native Source export."""
import atexit
from pathlib import Path
import shutil
import tempfile

HERE=Path(__file__).resolve().parent


def assembled():
    temporary=tempfile.TemporaryDirectory(prefix='FENCED-rust-v6-code-')
    atexit.register(temporary.cleanup)
    payload=Path(temporary.name)/'payload'
    shutil.copytree(HERE.parent/'successor_v5/payload',payload)
    shutil.copytree(HERE/'payload',payload,dirs_exist_ok=True)
    return payload
