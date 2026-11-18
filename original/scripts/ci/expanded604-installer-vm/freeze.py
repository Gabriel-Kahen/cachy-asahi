#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-only adopted604 installer byte freeze; authority must already be bound."""
import argparse
import json
from pathlib import Path
import contract as C

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True)
    print(json.dumps(C.freeze(parser.parse_args().source),sort_keys=True))
