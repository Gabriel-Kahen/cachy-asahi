#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import lifecycle as L
import lifecycle607,boundary,recovery
def main():
    L.execute=lambda C,R,T,normal,calls:lifecycle607.run(C,R,T,normal,L,boundary,recovery,calls)
    return L.main()
if __name__=='__main__':raise SystemExit(main())
