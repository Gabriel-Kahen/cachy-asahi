#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Copy reviewed selected codec source into a new external recipe; no build/install."""
import argparse
import json
from pathlib import Path
import shutil
from source_check import HERE, PACKET, PACKET_SHA, load_map, read_regular, repository_roots, sha, template_files, verify_packet


def materialize(packet, output, reviewed_inputs=None, reviewed_sha256=None):
    requested = Path(output)
    output = requested.resolve()
    roots = repository_roots(HERE)
    if any(output.is_relative_to(p) for p in roots) or output.exists() or requested.is_symlink():
        raise ValueError('output must be new and outside the repository')
    inputs = template_files()
    if reviewed_inputs is None or reviewed_sha256 is None:
        raise ValueError('independently reviewed template map and SHA256 required')
    approved = read_regular(reviewed_inputs, 65536)
    if sha(approved) != reviewed_sha256:
        raise ValueError('reviewed template map digest mismatch')
    if load_map(approved) != {n: sha(b) for n, b in sorted(inputs.items())}:
        raise ValueError('template differs from independently reviewed full input map')
    report = verify_packet(packet)
    archive = read_regular(packet, 8 * 1024 * 1024)
    if sha(archive) != PACKET_SHA:
        raise ValueError('packet changed during verification')
    inputs[PACKET] = archive
    output.mkdir(parents=True, exist_ok=False)
    try:
        for name, data in inputs.items():
            with (output / name).open('xb') as stream:
                stream.write(data)
            (output / name).chmod(0o644)
        captured = template_files(output)
        if captured != inputs:
            raise ValueError('materialized snapshot differs from reviewed inputs')
        return {**report, 'status': 'materialized-source-only', 'recipe': str(output),
                'input_sha256': {n: sha(b) for n, b in sorted(inputs.items())},
                'host_build_install': 'NOT RUN', 'hardware_status': 'NOT RUN'}
    except BaseException:
        shutil.rmtree(output)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reviewed-template', type=Path, required=True)
    parser.add_argument('--reviewed-template-sha256', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(materialize(args.archive, args.output, args.reviewed_template,
                                     args.reviewed_template_sha256), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
