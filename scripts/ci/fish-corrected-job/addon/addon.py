# SPDX-License-Identifier: MIT
"""Root authenticates entry and engine before binding the existing six-argument API."""
from pathlib import Path
from types import SimpleNamespace

def bind(authenticated_engine):
    api = authenticated_engine.bind('fish-history-v1', Path(__file__).resolve().parent)
    return SimpleNamespace(**api)
