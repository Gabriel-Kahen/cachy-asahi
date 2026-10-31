#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Isolated Python entrypoint; only its ordinary source directory is importable."""
import runpy,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
runpy.run_module('lane',run_name='__main__')
