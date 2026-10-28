# SPDX-License-Identifier: MIT
"""Entry point for the separately selected managed user-session profile."""
import importlib.util
from pathlib import Path
import sys


def load(name, filename):
    path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    base = load('managed_base_guest', 'base_guest.py')
    api = load('managed_profile_api', 'managed_session.py')
    api.bind(base)
    return base.main()


if __name__ == '__main__':
    raise SystemExit(main())
