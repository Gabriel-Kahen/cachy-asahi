#!/usr/bin/env python3
"""Explicit-cache source validation and corruption control; no acquisition."""
import argparse
from pathlib import Path
import shutil
import tempfile
from validate_sources import validate

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--cache', type=Path, required=True)
args = parser.parse_args()
assert len(validate(args.cache)) == 2
with tempfile.TemporaryDirectory(prefix='source-controls-') as scratch:
    cache = Path(scratch)
    for filename in ('llhttp-9.3.1.tar.gz', 'libgit2-1.9.7.tar.gz'):
        shutil.copyfile(args.cache / filename, cache / filename)
    for filename in ('llhttp-9.3.1.tar.gz', 'libgit2-1.9.7.tar.gz'):
        path = cache / filename
        original = path.read_bytes()
        path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        try:
            validate(cache)
        except ValueError as error:
            assert 'checksum differs' in str(error), str(error)
        else:
            raise AssertionError(f'accepted same-size tampered source: {filename}')
        path.write_bytes(original)
    assert len(validate(cache)) == 2
print('PASS: complete source pins, both same-size corruption refusals and restored inputs')
