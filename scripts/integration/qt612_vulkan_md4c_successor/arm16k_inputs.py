#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Authenticate the retained source, ALARM closure and read-only Qt ARM16K VM inputs."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
from runpy import run_path
import shutil
import stat
import subprocess
import sys
from tempfile import TemporaryDirectory


HERE = Path(__file__).resolve().parent
SOURCE_NAME = "qtbase-everywhere-src-6.12.0.tar.xz"
FINGERPRINT = "68B3537F39A313B3E574D06777193F152BDBE6A6"
TRANSACTION = {
    "md4c-0.6.0-2-aarch64.pkg.tar.xz",
    "vulkan-headers-1:1.4.363.0-1-any.pkg.tar.xz",
}
PARITY_RECIPE = {"bytes": 4460, "sha256": "0fc98bc3f5556b96012efa230d97f5eace3046c0f42984f9fc562040a7af0364"}
PARITY_BASE_PACKAGES = {
    "at-spi2-core-2.62.1-1-aarch64.pkg.tar.xz": (b"at-spi2-core", b"2.62.1-1"),
    "libcups-2:2.4.20-1-aarch64.pkg.tar.xz": (b"libcups", b"2:2.4.20-1"),
}
ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"}


def pin(size, sha256):
    return {"bytes": size, "sha256": sha256}


CLOSURE = pin(232288, "b0e4df5d96aff109c130e3bab7e143bb041d6cf3b17cfe2e388675392fe54858")
KEY = pin(2228, "9403f923eed777ba0896a0b225e1522d3a7625234694c753ae26b27c29672aae")
KERNEL = pin(9019400, "36066ded2f5721fd9bb257cebb2e4cb32084f45c3717f4d7a45430fe3cdcc494")
CONFIG = pin(71585, "b8bc8c636ae7e58e8e338e7dba87d84a390d0555fa7307fc76217e0d56553d7f")
BOOTS = [
    pin(1611661312, "77f702098144cceec83c62d9d6cf7a5a1de37d3c5d6ebee20c926319b555a72f"),
    pin(1611661312, "007b552b6bb66ffe9cd84a21baac3a5477dfd6a2fba3aeefeacdf30db32ea7df"),
]
REFUSAL = re.compile(rb"^(EXPSIG|EXPKEYSIG|KEYEXPIRED|SIGEXPIRED|REVKEYSIG|BADSIG|ERRSIG|NO_PUBKEY)$")


def need(condition, message):
    if not condition:
        raise ValueError(message)


def metadata(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_ctime_ns, info.st_mtime_ns


def file_pin(stream, size):
    return pin(size, hashlib.file_digest(stream, "sha256").hexdigest())


@contextmanager
def opened(path, expected=None, readonly=False):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, f"Ordinary absolute file required: {path}")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags), "rb") as stream:
        first = os.fstat(stream.fileno())
        need(stat.S_ISREG(first.st_mode) and (not readonly or not first.st_mode & 0o222),
             f"Unexpected file type or mode: {path}")
        if expected is not None:
            need(first.st_size == expected["bytes"] and file_pin(stream, first.st_size) == expected,
                 f"Input pin differs: {path}")
            stream.seek(0)
        yield stream
        need(metadata(first) == metadata(os.fstat(stream.fileno())) == metadata(path.lstat()),
             f"Input changed while open: {path}")


def verify(path, expected=None, *, readonly=False):
    """Return the stable file pin or raise if the exact supplied pin differs."""
    with opened(path, expected, readonly) as stream:
        return expected if expected is not None else file_pin(stream, os.fstat(stream.fileno()).st_size)


def read(path, expected):
    with opened(path, expected) as stream:
        return stream.read(expected["bytes"] + 1)


def stage_file(source, expected, destination):
    with opened(source, expected) as stream, destination.open("xb") as output:
        shutil.copyfileobj(stream, output, length=1 << 20)
    verify(destination, expected)


def verify_signature(row, home, key):
    name = row["filename"]
    need(row["signer"] == FINGERPRINT, f"Unexpected signer pin: {name}")
    archive, signature = (row[key] for key in ("archive", "signature"))
    with opened(archive["path"], pin(archive["bytes"], archive["sha256"])) as data:
        with opened(signature["path"], pin(signature["bytes"], signature["sha256"])) as sig:
            args = ["/usr/bin/gpgv", "--homedir", str(home), "--keyring", str(key), "--status-fd", "1", "--",
                    f"/proc/self/fd/{sig.fileno()}", f"/proc/self/fd/{data.fileno()}"]
            result = subprocess.run(args, env=ENV, stdin=subprocess.DEVNULL, capture_output=True, timeout=90,
                                    pass_fds=(data.fileno(), sig.fileno()))
    rows = [line.split() for line in result.stdout.splitlines()]
    valid = [fields for fields in rows if fields[:2] == [b"[GNUPG:]", b"VALIDSIG"]]
    expected = FINGERPRINT.encode()
    need(result.returncode == 0 and len(valid) == 1 and len(valid[0]) == 12
         and valid[0][2] == valid[0][-1] == expected
         and not any(len(fields) > 1 and REFUSAL.fullmatch(fields[1]) for fields in rows),
         f"ALARM detached signature refused: {name}")
    return pin(len(result.stdout), hashlib.sha256(result.stdout).hexdigest())


def package_inventory(body, count):
    lines = body.splitlines(keepends=True)
    need(len(lines) == count and lines == sorted(lines)
         and all(re.fullmatch(rb"[A-Za-z0-9_.+@-]+ [A-Za-z0-9_.+:~@-]+\n", line) for line in lines),
         f"Expected {count} sorted package rows")
    result = dict(line.split() for line in lines)
    need(len(result) == count, f"Expected {count} distinct package names")
    return result


def original_media(boot, kernel, config, backing, closure):
    boot_pin = verify(boot, readonly=True)
    need(boot_pin in BOOTS, "Expected a retained partitioned Q3 boot derivative")
    verify(kernel, KERNEL, readonly=True)
    need(b"CONFIG_ARM64_16K_PAGES=y" in read(config, CONFIG).splitlines(),
         "Kernel configuration must select 16 KiB pages")
    raw = verify(backing, closure["original_raw_q3"], readonly=True)
    return {name: dict(path=str(path), **record) for name, path, record in (
        ("boot", boot, boot_pin), ("kernel", kernel, KERNEL), ("config", config, CONFIG), ("backing", backing, raw))}


def authenticate(evidence, q3, boot, kernel, config, backing, stage):
    """Verify exact original files and stage the two-package update route."""
    parent = stage.parent
    info = parent.stat()
    need(parent.is_absolute() and parent.resolve(strict=True) == parent and stat.S_ISDIR(info.st_mode)
         and info.st_uid == os.getuid() and not info.st_mode & 0o022 and not os.path.lexists(stage),
         "Fresh staging path under an owned directory required")
    closure = json.loads(read(evidence / "closure.UNISSUED.json", CLOSURE))
    q3_files = json.loads(read(q3 / "plan.json", closure["q3_media_plan"]))["files"]
    before = package_inventory(read(q3 / "expected356.lock", closure["q3_356"]), 356)
    after = package_inventory(read(evidence / "expected357.lock", closure["expected357"]), 357)
    need(before.get(b"md4c") == b"0.5.3-1" and b"vulkan-headers" not in before
         and b"qt6-base" not in before
         and after == before | {b"md4c": b"0.6.0-2", b"vulkan-headers": b"1:1.4.363.0-1"},
         "Q3 to successor package inventory differs")
    packages = closure["packages"]
    need(len(packages) == len({row["filename"] for row in packages}) == closure["package_pairs"] == 264
         and sum(row["phase"] == "alpm-base" for row in packages) == 256
         and sum(row["phase"] == "alpm-add" for row in packages) == 8
         and TRANSACTION <= {row["filename"] for row in packages if row["phase"] == "alpm-add"},
         "Expected the original 264-package closure and two-package transaction")
    source = {"path": str(q3 / SOURCE_NAME), **q3_files[SOURCE_NAME]}

    with TemporaryDirectory(prefix=".qt-successor-inputs-", dir=parent) as private:
        private = Path(private)
        payload, key_home = (private / name for name in ("payload", "keyring"))
        for directory in (payload, key_home, payload / "alpm-add"):
            directory.mkdir(mode=0o700)
        key = payload / "alarm-public.gpg"
        stage_file(evidence / key.name, KEY, key)
        official_name = "official/archlinuxarm.gpg"
        armored = read(q3 / official_name, q3_files[official_name])
        dearmor = subprocess.run(["/usr/bin/gpg", "--batch", "--no-options", "--no-autostart",
                                  "--homedir", str(key_home), "--dearmor"], input=armored,
                                 env=ENV, capture_output=True, check=True, timeout=10)
        need(dearmor.stdout == read(key, KEY), "Staged ALARM key differs from the pinned certificate")
        rows = [closure["rootfs"], *packages]
        with ThreadPoolExecutor(max_workers=4) as pool:
            originals = pool.submit(original_media, boot, kernel, config, backing, closure)
            statuses = list(pool.map(lambda row: verify_signature(row, key_home, key), rows))
            media = originals.result()
        recipe = run_path(str(HERE / "prepare_parity.py"))["prepare_parity"](payload / "recipe")
        recipe_pin = verify(payload / "recipe" / "PARITY.UNISSUED.json", PARITY_RECIPE)
        need(recipe["qt_source"] == q3_files[SOURCE_NAME] and recipe["official_inputs"]["fingerprint"] == FINGERPRINT
             and recipe["base_recipe_sha256"] == closure["staged_recipe"]["sha256"],
             "Regenerated parity recipe source, signer or basis differs")
        by_name = {row["filename"]: row for row in packages}
        for filename, (name, version) in PARITY_BASE_PACKAGES.items():
            row, selected = by_name[filename], recipe["official_inputs"][filename]
            need(row["phase"] == "alpm-base" and before.get(name) == after.get(name) == version
                 and pin(row["archive"]["bytes"], row["archive"]["sha256"]) == pin(selected["bytes"], selected["sha256"])
                 and pin(row["signature"]["bytes"], row["signature"]["sha256"]) == selected["signature"],
                 f"Parity dependency is outside the signed baseline: {filename}")
        for name in sorted(TRANSACTION):
            row, selected = by_name[name], recipe["official_inputs"][name]
            for field, filename, expected in (
                ("archive", name, pin(selected["bytes"], selected["sha256"])),
                ("signature", name + ".sig", selected["signature"]),
            ):
                ref = row[field]
                need(expected == pin(ref["bytes"], ref["sha256"]), f"Recipe and closure differ: {filename}")
                stage_file(evidence / "alpm-add" / filename, expected, payload / "alpm-add" / filename)
        for origin, name, expected in (
            (q3, "expected356.lock", closure["q3_356"]),
            (evidence, "expected357.lock", closure["expected357"]),
            (q3, "disabled-hooks.list", q3_files["disabled-hooks.list"]),
            (q3, SOURCE_NAME, q3_files[SOURCE_NAME]),
        ):
            stage_file(origin / name, expected, payload / name)
        staged = {path.relative_to(payload).as_posix(): verify(path)
                  for path in sorted(payload.rglob("*")) if path.is_file()}
        need(not os.path.lexists(stage), "Staging path appeared during authentication")
        payload.rename(stage)
    return dict(kind="QTBASE_SUCCESSOR_ARM16K_AUTHENTICATED_INPUTS_V1",
                closure=CLOSURE, originals=media, recipe=recipe_pin, source=source, official_key=KEY,
                official_fingerprint=FINGERPRINT, package_pairs=len(packages), seed=closure["rootfs"]["archive"],
                signature_status={row["filename"]: record for row, record in zip(rows, statuses, strict=True)},
                staged=staged)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for argument in ("evidence", "q3", "boot", "kernel", "config", "backing", "stage"):
        parser.add_argument("--" + argument, required=True, type=Path)
    try:
        print(json.dumps(authenticate(**vars(parser.parse_args())), sort_keys=True, indent=2))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(f"Qt successor input authentication refused: {error}")
