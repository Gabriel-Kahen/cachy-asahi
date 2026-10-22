#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import derive
derive.run('inspection',globals())
