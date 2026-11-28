# SPDX-License-Identifier: MIT
"""Stage the pinned Asahi629 TIFF source successor without building a package."""

import argparse
import hashlib
import json
from pathlib import Path
from runpy import run_path
import shutil
import stat


HERE = Path(__file__).resolve().parent
PLAN_PIN = {"bytes": 60646, "sha256": "892b271cd5dc8ff22f103b875adcca87b75ce8b98a2b35ca5b258225ca17923f"}
PARENT_PIN = {"bytes": 4950, "sha256": "217634ec9084aacf2c2583c566cc6a82167d00a27195d45636ad9552fbe86630"}
PKGBUILD_PIN = {"bytes": 4968, "sha256": "583aeb9b6a967ac7c2ba639bb176dbc7b11b5a7d2e17e41583765169133775e4"}
PACKAGE = "cachy-asahi-libtiff"
VERSION = "4.7.2-1.2"
JPEG_DEPENDENCY = "libjpeg.so=8-64"
FILES = frozenset({"PKGBUILD", "libtiff-project-4.7.2-source.tar.gz", "UPSTREAM-NOTICES.txt",
                   "LICENSE.MIT", "PUBLICATION.md", "source-filter.json", "stage-source.py"})


def pin(body):
    return {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def recipe(parent):
    require(pin(parent) == PARENT_PIN, "Exact historical #622 TIFF PKGBUILD required")
    release = b"pkgrel=1.1\n"
    dependency = b"libdeflate libjpeg-turbo libwebp"
    require(parent.count(release) == parent.count(dependency) == 1, "Historical source splice differs")
    corrected = parent.replace(release, b"pkgrel=1.2\n").replace(
        dependency, b"libdeflate libjpeg-turbo '" + JPEG_DEPENDENCY.encode("ascii") + b"' libwebp")
    require(pin(corrected) == PKGBUILD_PIN, "Asahi629 TIFF successor source pin differs")
    return corrected


def source_specs(read):
    # Only host source materialization uses the repository layout.
    materialization_plan = HERE.parents[2] / "scripts/build/project-libraries/materialization-plan.json"
    plan = json.loads(read(materialization_plan, PLAN_PIN))
    rows = [row for row in plan["outputs"] if row["package"] == "libtiff"]
    specs = {row["filename"]: {key: row[key] for key in ("bytes", "sha256")} for row in rows}
    require(len(rows) == len(FILES) and specs.keys() == FILES and specs["PKGBUILD"] == PARENT_PIN
            and all(row["mode"] == 0o644 for row in rows), "Historical TIFF source closure differs")
    return specs


def place(materialized, output):
    read = run_path(str(HERE / "inputs.py"))["read"]
    source = Path(materialized).absolute()
    target = Path(output).absolute()
    require(source.resolve(strict=True) == source and source.is_dir(), "Ordinary materialized input directory required")
    require(target.parent.resolve(strict=True) == target.parent and target.parent.is_dir()
            and not target.is_relative_to(source), "Fresh output must be outside the historical source directory")
    specs = source_specs(read)
    require({path.name for path in source.iterdir()} == FILES, "Expected exact seven-file historical source closure")
    content = {name: read(source / name, expected) for name, expected in specs.items()}
    content["PKGBUILD"] = recipe(content["PKGBUILD"])
    expected = specs | {"PKGBUILD": PKGBUILD_PIN}
    target.mkdir(mode=0o700)
    try:
        for name, body in sorted(content.items()):
            path = target / name
            with path.open("xb") as file:
                file.write(body)
            path.chmod(0o644)
        require({path.name for path in target.iterdir()} == FILES, "Output file membership changed")
        for name, reference in expected.items():
            path = target / name
            require(stat.S_IMODE(path.lstat().st_mode) == 0o644 and read(path, reference) == content[name],
                    "Output source file changed: " + name)
    except BaseException:
        shutil.rmtree(target)
        raise
    return dict(kind="ASAHI629_TIFF_JPEG_DEPENDENCY_SOURCE_V1", package=PACKAGE, version=VERSION,
                jpeg_dependency=JPEG_DEPENDENCY, materialization_plan=PLAN_PIN,
                parent_files=specs, files=expected, archive=None, build="NOT RUN",
                archive_admission="REBUILD_AND_PIN_REQUIRED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--materialized", type=Path, required=True, help="exact historical libtiff recipe directory")
    parser.add_argument("--output", type=Path, required=True, help="fresh private source output directory")
    args = parser.parse_args()
    try:
        result = place(args.materialized, args.output)
    except (KeyError, OSError, ValueError) as error:
        parser.exit(1, f"Asahi629 TIFF source staging refused: {error}\n")
    print(json.dumps(result, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
