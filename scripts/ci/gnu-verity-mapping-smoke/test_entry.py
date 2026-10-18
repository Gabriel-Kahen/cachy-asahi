#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import runpy,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
runpy.run_module('test_lane',run_name='__main__',alter_sys=True)
