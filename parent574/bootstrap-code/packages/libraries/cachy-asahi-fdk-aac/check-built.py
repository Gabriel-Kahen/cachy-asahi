#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Native-container ELF/ABI checks; never compile or install on the host."""
import json
import os
from pathlib import Path
import platform
import re
import subprocess


def main():
    if os.environ.get('CACHY_ASAHI_CONTAINER') != '1' or platform.machine() != 'aarch64':
        raise SystemExit('requires the explicit native aarch64 container')
    results = {}
    layout = json.loads(Path(__file__).resolve().with_name('build-layout.json').read_text())
    for name, soname in (('libfdk-aac', 'libfdk-aac.so.2'), ('libfdk-xhe-aac', 'libfdk-xhe-aac.so.0')):
        path = Path(name + '.so')
        headers = subprocess.check_output(['readelf', '-hW', str(path)], text=True)
        dynamic = subprocess.check_output(['readelf', '-dW', str(path)], text=True)
        if not re.search(r'Class:\s+ELF64', headers) or not re.search(r'Machine:\s+AArch64', headers):
            raise SystemExit('built library is not ELF64 AArch64: ' + name)
        actual = re.findall(r'\(SONAME\).*\[([^]]+)\]', dynamic)
        needed = re.findall(r'\(NEEDED\).*\[([^]]+)\]', dynamic)
        if actual != [soname] or not set(needed) <= {'libc.so.6', 'libm.so.6', 'ld-linux-aarch64.so.1'}:
            raise SystemExit('unexpected SONAME/runtime dependencies: ' + name)
        symbols = subprocess.check_output(['readelf', '--dyn-syms', '-W', str(path)], text=True)
        defined = [r.split() for r in symbols.splitlines()]
        exported = {r[7] for r in defined if len(r) >= 8 and r[4] == 'GLOBAL' and r[6] != 'UND'}
        if exported != set(layout['libraries'][name]['exports']):
            raise SystemExit('public export inventory mismatch: ' + name)
        segments = subprocess.check_output(['readelf', '-lW', str(path)], text=True)
        loads = [line.split() for line in segments.splitlines() if line.strip().startswith('LOAD ')]
        if not loads or any(int(row[-1], 16) < 16384 or
                            (int(row[1], 16) - int(row[2], 16)) % 16384 for row in loads):
            raise SystemExit('ELF LOAD segments do not support 16 KiB mapping: ' + name)
        results[name] = {'soname': soname, 'needed': needed, 'exports': len(exported), 'elf_16k_geometry': 'PASS'}
    print(json.dumps({'status': 'native-ELF-ABI-pass', 'libraries': results,
                      'hardware_status': 'NOT RUN', '16k_runtime': 'NOT RUN'}, sort_keys=True))


if __name__ == '__main__':
    main()
