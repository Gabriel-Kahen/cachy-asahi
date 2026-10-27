#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the additive source then enter the unchanged original574 producer."""
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import contract as C

if __name__ == '__main__':
    C.need('--source' in sys.argv, 'explicit source root required')
    root = C.safe(Path(sys.argv[sys.argv.index('--source') + 1]).absolute())
    C.verify_source(root)
    held = root / 'scripts/ci/setup7-native/producer.py'
    # A new interpreter ensures the held producer imports its own frozen contract.
    os.execv(sys.executable, [sys.executable, '-I', '-B', str(held), *sys.argv[1:]])
