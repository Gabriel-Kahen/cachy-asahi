#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Passive GUI18 source inspection only; no native entry or grant issuer."""
import sys


def no_actors(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in (
            'os.system', 'os.exec', 'os.fork', 'os.forkpty', 'os.posix_spawn',
            'fcntl.flock', 'resource.setrlimit', 'os.kill', 'os.killpg'):
        raise ValueError('GUI18_PASSIVE_ENTRY_NO_ACTORS')


sys.addaudithook(no_actors)
import argparse
import importlib.util
from pathlib import Path

path = Path(__file__).resolve().with_name('common.py')
spec = importlib.util.spec_from_file_location('gui18_source_common',path)
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root',type=Path,required=True)
    args = parser.parse_args()
    source = C.inspect_recipe(args.recipe_root)
    print(C.encode(dict(kind='QT612_GUI18_NATIVE_ADAPTER_SOURCE_INSPECTION_ONLY',
        recipe_commit=C.RECIPE_COMMIT,recipe_map=source['recipe_map'],
        recipe_contract=source['contract_pin'],stage_program=source['stage_program_pin'],
        intended_modules=18,baseline_modules=13,added_modules=5,other54='OUTSIDE_SCOPE',
        native_acceptance=False,actual_C_binding=None,actual_package_tuple=None,
        Root_grant=None,runtime=None,capacity_acceptance=None,M2=None,
        official_0bd04f_correspondence='HOLD_UNCHANGED')).decode(),end='')


if __name__ == '__main__':
    main()
