#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import runpy,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
runpy.run_module('kernel_input',run_name='__main__')
