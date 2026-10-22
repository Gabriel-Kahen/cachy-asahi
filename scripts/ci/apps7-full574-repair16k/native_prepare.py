# SPDX-License-Identifier: MIT
"""Explicit native preparation capacity; original policy and transaction bodies held."""
import sys
from pathlib import Path

PROFILE = 'REPAIR_NATIVE_PREVM_COLD_VALIDATION_2400_V1'


def validation_seconds(original):
    def selected(args=None):
        seconds = original(args)
        if args is not None and getattr(args, 'action', None) == 'prepare-copy':
            if type(seconds) is not int or seconds != 600:
                raise ValueError('original authenticated native600 policy required')
            return 2400
        return seconds
    return selected


def main():
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import contract as C
    C.need(sys.argv[1:2] == ['prepare-copy'], 'native profile permits preparation only')
    root = Path('/source')
    C.check_source(root)
    original = C.load('native_preparation_original_transaction', root / C.NATIVE / 'transaction.py')
    original.execution_seconds = validation_seconds(original.execution_seconds)
    return original.main()


if __name__ == '__main__':
    raise SystemExit(main())
