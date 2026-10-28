#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors.
"""Read-only provenance check; never copy files or execute the runtime helper."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys


def digest(path):
    if not path.is_file():
        raise ValueError(f"missing or nonregular input: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--canonical", type=Path, help="explicit canonical helper, including outside the checkout")
    parser.add_argument("--copy", type=Path, help="packaged helper; provenance and LICENSE are read beside it")
    parser.add_argument("--license", type=Path, help="canonical project license; defaults to repository LICENSE")
    args = parser.parse_args()
    here = Path(__file__).resolve()
    root = here.parents[3] if len(here.parents) > 3 else None
    copy = args.copy or here.with_name("cachy-asahi-setup")
    try:
        record = json.loads(copy.with_name("source-provenance.json").read_text())
        if not isinstance(record, dict):
            raise ValueError("provenance must be a JSON object")
        name = record.get("canonical_path")
        if (not isinstance(name, str) or "\\" in name
                or any(part in ("", ".", "..") for part in name.split("/"))
                or PurePosixPath(name).is_absolute()
                or PurePosixPath(name).parts[:2] != ("scripts", "setup")
                or len(PurePosixPath(name).parts) < 3):
            raise ValueError("unsafe canonical_path: expected a relative file below scripts/setup/")
        if record.get("packaged_source") != "cachy-asahi-setup":
            raise ValueError("unexpected packaged_source in provenance")
        for key in ("sha256", "license_sha256"):
            if not isinstance(record.get(key), str) or not re.fullmatch(r"[0-9a-f]{64}", record[key]):
                raise ValueError(f"invalid provenance {key}")
        if root is None and (args.canonical is None or args.license is None):
            raise ValueError("cannot infer repository root; provide --canonical and --license")
        canonical = args.canonical or root / name
        if args.canonical is None and not canonical.resolve().is_relative_to(root):
            raise ValueError("canonical_path resolves outside the repository")
        license_path = args.license or root / "LICENSE"
        for label, path, expected in (
            ("canonical helper", canonical, record["sha256"]),
            ("packaged helper", copy, record["sha256"]),
            ("canonical license", license_path, record["license_sha256"]),
            ("packaged license", copy.with_name("LICENSE"), record["license_sha256"]),
        ):
            if digest(path) != expected:
                raise ValueError(f"{label} differs from pinned provenance: {path}")
    except (OSError, ValueError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: canonical and packaged helper/license bytes match pinned provenance")
    return 0


if __name__ == "__main__":
    sys.exit(main())
