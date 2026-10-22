#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact source proof, strict owned cleanup and closed setup5/retained4 export."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import prepare


if __name__=='__main__':
    C.need('--source' in sys.argv,'explicit source root required');root=C.safe(Path(sys.argv[sys.argv.index('--source')+1]).absolute());C.verify_source(root)
    prepare.adapter('job',root)['main']()
