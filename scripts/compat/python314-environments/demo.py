# SPDX-License-Identifier: MIT
"""Original tiny wheel payload; no dependencies or build backend."""
import importlib.metadata
import json
from pathlib import Path
import sys

__version__ = '0.1.0'


def main():
    version = importlib.metadata.version('cachy-asahi-env-demo')
    if version != __version__ or sys.version_info[:3] != (3, 14, 8):
        raise RuntimeError('demo version/interpreter identity refused')
    print(json.dumps({'answer': 42, 'version': version, 'python': sys.version,
                      'executable': sys.executable, 'prefix': sys.prefix,
                      'base_prefix': sys.base_prefix, 'module': str(Path(__file__).resolve())},
                     sort_keys=True))
    return 0
