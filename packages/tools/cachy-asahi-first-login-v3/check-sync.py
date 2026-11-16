#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check retained source pins and the optional repository copies."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ADAPTERS = (
    ("ROOT = Path(__file__).resolve().parents[2]", "ROOT = Path(__file__).resolve().parent"),
    ("ROOT / 'packages/tools/cachy-asahi-setup8/setup.py'", "ROOT / 'setup8-fixture.py'"),
    ("ROOT / 'packages/tools/cachy-asahi-setup8/cachy-asahi-setup'", "ROOT / 'setup8-fixture.py'"),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path)
    args = parser.parse_args()
    provenance = json.loads((HERE / 'source-provenance.json').read_text())
    for name, expected in provenance['input_sha256'].items():
        assert hashlib.sha256((HERE / name).read_bytes()).hexdigest() == expected, name + ' pin differs'
    if args.root:
        for name, source in provenance['canonical_sources'].items():
            raw = (args.root / source).read_bytes()
            if name == 'test_first_login.py':
                text = raw.decode()
                for before, after in ADAPTERS:
                    assert text.count(before) == 1, 'test adapter source changed'
                    text = text.replace(before, after)
                raw = text.encode()
            assert raw == (HERE / name).read_bytes(), name + ' canonical source differs'
    print('First-login retained source pins and requested canonical copies match.')


if __name__ == '__main__':
    main()
