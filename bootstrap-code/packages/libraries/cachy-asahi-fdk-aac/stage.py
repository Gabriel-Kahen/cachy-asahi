#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Stage exact library/header/pkgconfig paths inside the native package root."""
import argparse
import json
import os
from pathlib import Path
import platform
from source_check import read_regular


def write(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(data)
    path.chmod(mode)


def main():
    if os.environ.get('CACHY_ASAHI_CONTAINER') != '1' or platform.machine() != 'aarch64':
        raise SystemExit('requires the explicit native aarch64 container; no host staging')
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'build', 'package'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    layout = json.loads(read_regular(Path(__file__).resolve().with_name('build-layout.json'), 1024 * 1024))
    for name, lib in layout['libraries'].items():
        dest = args.package / 'usr/lib'
        write(dest / lib['file'], read_regular(args.build / lib['file'], 32 * 1024 * 1024), 0o755)
        (dest / lib['soname']).symlink_to(lib['file'])
        (dest / (name + '.so')).symlink_to(lib['soname'])
        for header in lib['headers']:
            write(args.package / 'usr/include' / lib['pkgconfig'] / Path(header).name,
                  read_regular(args.source / header, 8 * 1024 * 1024), 0o644)
        write(dest / 'pkgconfig' / (lib['pkgconfig'] + '.pc'),
              read_regular(args.build / (lib['pkgconfig'] + '.pc'), 65536), 0o644)


if __name__ == '__main__':
    main()
