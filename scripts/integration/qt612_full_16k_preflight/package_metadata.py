#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare the exact Qtbase package-only recipe and provider metadata."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


PACKAGE = "cachy-asahi-qt612-gui-server-source-reference"
VERSION = "6.12.0-2"
RECIPE_PINS = {
    (6145, "121f2ec8f25a8c935be16136cd3dc036603679fdaea2f1b95e45a7a2201f852b"):
        ("canonical", (7474, "b62040f3ede97d3548271f80fc903e87d48db1682fbd6c5f6a4bdc2d0b6913a8")),
    (6232, "b8ab08950fc2e5729e00bc066e13897163ae52362105aa90d58569f603e07296"):
        ("q3", (7561, "7d2ee635058190e7ccad69ca4546920f88136e1ce79daee5a9388f953a6bb149")),
}
SRCINFO_INPUT = (3856, "9c132b1d743040efcfad23401efee5879270fab91d71877fe0972d6501bdb445")
SRCINFO_OUTPUT = (3858, "d6ce3f256bbdab09b98f03bb7163b637635d5e820ed3a09492da7399225070b8")

NORMALIZE_TOOL_ALIASES = br'''_qt_normalize_tool_aliases() (
  local bin="$pkgdir/usr/lib/qt6/bin" tool original alias tmp=
  local -a left=() right=() copies=()
  [[ $(realpath -e -- "$bin") == "$bin" ]] || return 1
  for tool in qmake qtpaths; do
    original=$bin/$tool alias=$bin/${tool}6
    [[ -f $original && ! -L $original && -f $alias && ! -L $alias ]] || return 1
    read -r -a left <<< "$(stat -c '%d %i %h %a %s %u %g' -- "$original")" || return
    read -r -a right <<< "$(stat -c '%d %i %h %a %s %u %g' -- "$alias")" || return
    [[ ${#left[@]} == 7 && ${#right[@]} == 7 && ${left[*]:3} == "${right[*]:3}" &&
       ${left[3]} == 755 && ${left[4]} -gt 0 && ${left[4]} -le 134217728 ]] || return 1
    if [[ ${left[0]}:${left[1]} == "${right[0]}:${right[1]}" ]]; then
      [[ ${left[2]} == 2 && ${right[2]} == 2 ]] || return 1
      copies+=("$alias")
    else
      [[ ${left[2]} == 1 && ${right[2]} == 1 ]] && cmp -s -- "$original" "$alias" || return 1
    fi
  done

  trap '[[ -z $tmp ]] || rm -f -- "$tmp"' EXIT
  for alias in "${copies[@]}"; do
    tmp=$(mktemp -- "$bin/.qt-alias.XXXXXXXX") || return
    cp --preserve=mode,ownership,timestamps -- "$alias" "$tmp" || return
    cmp -s -- "$alias" "$tmp" && mv -T -- "$tmp" "$alias" || return
    tmp=
  done
)

'''
STAGE_CHECK = (b'  python "$srcdir/check_stage.py" --root "$pkgdir" \\\n'
               b'    --license-manifest "$srcdir/source-notices.json"')
PROJECTED_STAGE_CHECK = (b'  _qt_normalize_tool_aliases || return\n'
                         b'  python "$srcdir/check_stage.py" --root "$pkgdir" \\\n'
                         b'    --license-manifest "$pkgdir/usr/share/licenses/$pkgname/source-notices.json"')


def pin(body):
    return len(body), hashlib.sha256(body).hexdigest()


def describe(body):
    size, digest = pin(body)
    return dict(bytes=size, sha256=digest)


def successor(recipe, srcinfo):
    selected = RECIPE_PINS.get(pin(recipe))
    if selected is None or pin(srcinfo) != SRCINFO_INPUT:
        raise ValueError("Expected exact canonical or Q3 Qtbase recipe and SRCINFO")
    profile, expected = selected
    # Use the complete version. libalpm compares without pkgrel when either
    # side omits it, which would also satisfy an official -3 exact dependency.
    projected = recipe.replace(b"\npkgrel=1\n", b"\npkgrel=2\n").replace(
        b'provides=("qt6-base=$pkgver" ', b'provides=("qt6-base=$pkgver-$pkgrel" ')
    # Qt creates two versioned private hardlinks. Its own fallback is a byte
    # copy. Keep the checker on ordinary files, including makepkg's notice input.
    projected = projected.replace(b"\npackage() {\n", b"\n" + NORMALIZE_TOOL_ALIASES + b"package() {\n", 1).replace(
        STAGE_CHECK, PROJECTED_STAGE_CHECK, 1)
    projected_info = srcinfo.replace(b"\tpkgrel = 1\n", b"\tpkgrel = 2\n").replace(
        b"\tprovides = qt6-base=6.12.0\n", b"\tprovides = qt6-base=6.12.0-2\n")
    if pin(projected) != expected or pin(projected_info) != SRCINFO_OUTPUT:
        raise ValueError("Exact Qtbase packaging-only projection required")
    inputs = {"PKGBUILD": recipe, ".SRCINFO": srcinfo}
    outputs = {"PKGBUILD": projected, ".SRCINFO": projected_info}
    receipt = dict(kind="QTBASE_PROVIDER_METADATA_PROJECTION_V1", profile=profile,
                   package=PACKAGE, version=VERSION, provides="qt6-base=" + VERSION,
                   inputs={name: describe(body) for name, body in inputs.items()},
                   outputs={name: describe(body) for name, body in outputs.items()},
                   packaging="NOT_RUN", installation="NOT_RUN", authority=None)
    return outputs | {"receipt": (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()}


def read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 8192:
            raise ValueError("Expected a bounded ordinary Qtbase recipe file")
        return stream.read(info.st_size + 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe-dir", type=Path, required=True)
    parser.add_argument("--emit", choices=("PKGBUILD", ".SRCINFO", "receipt"), default="receipt")
    args = parser.parse_args()
    try:
        recipe = read(args.recipe_dir / "PKGBUILD")
        srcinfo = read(args.recipe_dir / ".SRCINFO")
        sys.stdout.buffer.write(successor(recipe, srcinfo)[args.emit])
    except (OSError, ValueError) as error:
        sys.exit(str(error) if isinstance(error, ValueError) else "Cannot read the selected Qtbase recipe")


if __name__ == "__main__":
    main()
