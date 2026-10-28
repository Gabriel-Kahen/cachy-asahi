#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'implementation'))
from entry import cleanup_main
if __name__=='__main__':cleanup_main()
