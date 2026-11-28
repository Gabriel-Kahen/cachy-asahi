#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run retained support exporter tests with their original transport files."""
import argparse
from contextlib import contextmanager
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

TESTS = ('test_support_source_delivery_v1.py', 'test_support_source_delivery_v2.py')


def stage(root, temporary):
    release = root / 'scripts/release'
    frozen_release = temporary / 'scripts/release'
    frozen_release.mkdir(parents=True)
    tools = Path('packages/tools')
    for name in ('recipe_source_delivery.py', 'source_delivery.py'):
        shutil.copy2(root / tools / 'cachy-asahi-release-tools' / name, frozen_release / name)
    for name in ('support_source_delivery_v1.py', 'support_source_delivery_v2.py', *TESTS):
        shutil.copy2(release / name, frozen_release / name)
    for name in ('cachy-asahi-support', 'cachy-asahi-support2'):
        shutil.copytree(root / tools / name, temporary / tools / name)
    return frozen_release


@contextmanager
def discovery_loader(root, temporary):
    """Use the frozen fixture for just the two historical release modules."""
    live_release = root / 'scripts/release'
    frozen_release = stage(root, temporary)
    module_names = []

    class Loader(unittest.TestLoader):
        def loadTestsFromModule(self, module, *, pattern=None):
            source = Path(module.__file__).resolve()
            if source.parent == live_release and source.name in TESTS:
                spec = importlib.util.spec_from_file_location('_frozen_' + source.stem, frozen_release / source.name)
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                module_names.append(spec.name)
                spec.loader.exec_module(module)
            return super().loadTestsFromModule(module, pattern=pattern)

    try:
        yield Loader()
    finally:
        for name in module_names:
            del sys.modules[name]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('test', choices=TESTS)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    with tempfile.TemporaryDirectory(prefix='support-source-') as temporary:
        release = stage(root, Path(temporary))
        subprocess.run([sys.executable, '-B', '-S', '-Werror::ResourceWarning', release / args.test], check=True)


if __name__ == '__main__':
    main()
