# SPDX-License-Identifier: MIT
"""Prepare the exact JBIG/TIFF recipes for the offline build runner."""
import argparse
import json
from pathlib import Path
import stat
import sys
import tarfile
import time

import materialize

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "checks"))
from package_checks import recipe


HERE = Path(__file__).resolve().parent
PACKAGES = ("jbigkit", "libtiff")
UPSTREAM = ("jbigkit", "libtiff", "shared_patch", "reuse")


def load_plan(check):
    body = materialize.read(HERE / "materialization-plan.json", 131072, check)
    materialize.need(materialize.sha(body) == materialize.PLAN_SHA256, "materialization plan pin")
    return json.loads(body)


def verify_recipe(directory, package, plan):
    rows = {row["filename"]: row for row in plan["outputs"] if row["package"] == package}
    materialize.need(stat.S_ISDIR(directory.lstat().st_mode), f"{package} ordinary recipe directory")
    materialize.need({item.name for item in directory.iterdir()} == rows.keys(), f"{package} recipe file set")
    expected = {name: row["sha256"] for name, row in rows.items()}
    for name, row in rows.items():
        facts = (directory / name).lstat()
        materialize.need(stat.S_ISREG(facts.st_mode) and facts.st_size == row["bytes"] and
                         stat.S_IMODE(facts.st_mode) == row["mode"],
                         f"{package} recipe size/mode: {name}")
    report = recipe(directory / "PKGBUILD")
    materialize.need(not report["errors"], f"{package} recipe review: {report['errors']}")
    materialize.need(report["input_sha256"] == expected, f"{package} pinned recipe contents")
    materialize.need(set(report["metadata"]["source"]) | {"PKGBUILD"} == rows.keys(),
                     f"{package} literal source closure")
    return report


def prepare(upstream, output, check):
    plan = load_plan(check)
    report = materialize.prepare_sources(
        {name: HERE / "recipes" / name for name in PACKAGES}, upstream, output, check,
    )
    for package in PACKAGES:
        check("before-recipe-review")
        reviewed = verify_recipe(output / package, package, plan)
        body = (json.dumps(reviewed["input_sha256"], indent=2, sort_keys=True) + "\n").encode()
        materialize.write(output / f"{package}-reviewed-inputs.json", body, 0o644, check)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in UPSTREAM:
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="fresh private directory")
    args = parser.parse_args()
    deadline = time.monotonic() + 30

    def check(label):
        if time.monotonic() >= deadline:
            raise ValueError(f"preparation deadline at {label}")

    try:
        print(json.dumps(prepare({name: getattr(args, name) for name in UPSTREAM}, args.output, check),
                         indent=2, sort_keys=True))
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.exit(1, f"Source preparation failed: {error}\n")


if __name__ == "__main__":
    main()
