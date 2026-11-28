#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare the exact #622 historical-provider transaction for a disposable root."""
import argparse
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build622 import command, sign_archive, sign_test
from inputs622 import EXTENSION_PIN, INPUTS_PIN, PROJECT, ROOT, read_pin, require, stage_object
from native_arm import valid_signature

sys.path.insert(0, str(PROJECT))
from baseline import derive
from materialize import sha

HISTORICAL = {
    "jbigkit-2.1-8-aarch64.pkg.tar.xz": (48816, "ecaddb099f4a1f1bcbc1497fd0f3dc98581552b9eacaa17c5568211c38bec1db"),
    "jbigkit-2.1-8-aarch64.pkg.tar.xz.sig": (566, "f00be593f9ab5855f9e450d054e6cacd319ec834ef7fc97c51bcf3be3ebfdb1f"),
    "libtiff-4.7.2-1-aarch64.pkg.tar.xz": (354480, "02a5d2d74019b39befd6cf63d9bde95a2d16f91b4d0d56939498375e0e491ffd"),
    "libtiff-4.7.2-1-aarch64.pkg.tar.xz.sig": (566, "8dae1efda531e3ac7db09512cfe0c619eaae6787cc16fdea1315588b4fc340fa"),
    "lcms2-2.19.1-1-aarch64.pkg.tar.xz": (205460, "5f93d01820b4e1a463f3cb11e19916bb3761b4faca20d4e1f0854329ba3f46f8"),
    "lcms2-2.19.1-1-aarch64.pkg.tar.xz.sig": (566, "3e35d43d7cd15dc360e2c250b32610f97330b239ba30d2917d6998c1d337dd5c"),
}
PROJECT_PACKAGES = {
    "cachy-asahi-jbigkit-2.2-1.1-aarch64.pkg.tar.xz":
        (143352, "98636579a9653b64987646ab2066fb0e4d9763ae44d52984c7d4677827a2af97"),
    "cachy-asahi-libtiff-4.7.2-1.1-aarch64.pkg.tar.xz":
        (862056, "93e380ec45bc69059c643968f84fd3328a654e532bff0cf5f58e6362e62eb27f"),
}
EMULATED_TIFF = (861864, "085e8293b170ef5fa30febd3f7d4079da69b4b104c0e91733a30640e2e3f8875")
LOCKS = {
    "historical.lock": (("jbigkit 2.1-8", "libtiff 4.7.2-1"),
                        "9203a23bef9d2a8ba4eb9135536d146ae8a8d89b936072e89851c91afde6cd87"),
    "project.lock": (("cachy-asahi-jbigkit 2.2-1.1", "cachy-asahi-libtiff 4.7.2-1.1"),
                     "abbc68dd92b0324962fb309f848bad485f745368fd769516fcf4300aef0283e4"),
}
BASE_FILES = ROOT / "scripts/port/minimal-native-builder-inputs"


def migration_locks(base, extension):
    derive(base, extension)
    rows = base.decode("ascii").splitlines()
    rows += ["lcms2 2.19.1-1", *(f"{name} {version}" for name, version in extension["codec_versions"].items())]
    locks = {}
    for name, (extra, digest) in LOCKS.items():
        lock = "".join(row + "\n" for row in sorted([*rows, *extra])).encode()
        require(sha(lock) == digest, f"exact migration inventory: {name}")
        locks[name] = lock
    return locks


def copy_pinned(output, cache, pins):
    for name, (size, digest) in pins.items():
        stage_object(output, name, {"bytes": size, "sha256": digest}, cache)


def project_pins(emulated_tiff):
    pins = PROJECT_PACKAGES.copy()
    if emulated_tiff:
        pins["cachy-asahi-libtiff-4.7.2-1.1-aarch64.pkg.tar.xz"] = EMULATED_TIFF
    return pins


def stage(args):
    contract = read_pin(PROJECT / "minimal206-extension.json", EXTENSION_PIN)
    base = (BASE_FILES / "expected206.lock").read_bytes()
    locks = migration_locks(base, contract)
    codecs = {name: (row["bytes"], row["sha256"]) for name, row in contract["codec_files"].items()}
    args.output.mkdir(mode=0o700)
    try:
        copy_pinned(args.output, args.historical_cache, HISTORICAL)
        copy_pinned(args.output, args.codec_cache, codecs)
        copy_pinned(args.output, args.project_cache, project_pins(args.emulated_tiff))
        with tempfile.TemporaryDirectory(prefix="migration622-") as temporary:
            scratch = Path(temporary)
            lock = read_pin(BASE_FILES / "native-inputs.lock.json", INPUTS_PIN)
            key, = [row for row in lock["keyring_files"] if row["filename"] == "archlinuxarm.gpg"]
            armored = stage_object(scratch, key["filename"], {"bytes": key["size"], "sha256": key["sha256"]},
                                   args.minimal_cache)
            keyring = scratch / "alarm.gpg"
            command(["gpg", "--batch", "--no-options", "--homedir", str(scratch), "--dearmor",
                     "--output", str(keyring), str(armored)])
            for name in sorted(HISTORICAL.keys() | codecs.keys()):
                if name.endswith(".sig"):
                    result = command(["gpgv", "--homedir", str(scratch), "--keyring", str(keyring), "--status-fd", "1",
                                      str(args.output / name), str(args.output / name.removesuffix(".sig"))])
                    valid_signature(result.stdout.decode(), contract["signer_fingerprint"])
            home = scratch / "test-key"
            jbig, tiff = (args.output / name for name in PROJECT_PACKAGES)
            try:
                signer, _ = sign_test(jbig, args.output, home)
                sign_archive(tiff, args.output / "TEST-public.gpg", home, signer)
            finally:
                if home.is_dir():
                    command(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"])
        (args.output / "test-fingerprint").write_text(signer + "\n")
        profile = "emulated-tiff" if args.emulated_tiff else "native-tiff"
        (args.output / "profile").write_text(profile + "\n")
        for name, lock in {"base.lock": base, **locks}.items():
            (args.output / name).write_bytes(lock)
        shutil.copyfile(PROJECT / "tiff-jbig-roundtrip.c", args.output / "roundtrip.c")
        shutil.copyfile(Path(__file__).with_suffix(".sh"), args.output / "migration.sh")
        checksums = "".join(f"{sha(path.read_bytes())}  {path.name}\n" for path in sorted(args.output.iterdir()))
        (args.output / "SHA256SUMS").write_text(checksums)
    except BaseException:
        shutil.rmtree(args.output)
        raise


def native_run(docker, base, jbig, tiff, scratch, historical_cache, report):
    incoming = scratch / "migration-project-cache"
    incoming.mkdir(mode=0o700)
    for package in (jbig, tiff):
        shutil.copyfile(package, incoming / package.name)
    output = scratch / "migration"
    stage(SimpleNamespace(historical_cache=historical_cache, codec_cache=scratch / "codecs",
                          project_cache=incoming, minimal_cache=scratch / "cache", output=output,
                          emulated_tiff=False))
    scope = docker.container_args("cachy-622-migration-" + docker.nonce)
    log = scratch / "historical-migration.log"
    try:
        result = docker.call("run", "--rm", *scope, "--pull=never", "--platform", "linux/arm64",
                             "--network=none", "--security-opt=no-new-privileges", "--pids-limit=128",
                             "--memory=2g", "--memory-swap=2g", "--cpus=2", "--user=0:0",
                             "--mount", f"type=bind,src={output},dst=/migration,readonly",
                             "--env", "CACHY_ASAHI_MIGRATION=1", "--entrypoint", "/bin/bash", base,
                             "/migration/migration.sh", seconds=420)
    except subprocess.CalledProcessError as error:
        private = (error.stdout or b"") + (error.stderr or b"")
        log.write_bytes(private)
        report["historical_migration_failure"] = {
            "container_exit_code": error.returncode,
            "completed_provider_checks": private.count(b"provider and unchanged tificc passed"),
            "log_sha256": sha(private),
        }
        raise
    private = result.stdout + result.stderr
    log.write_bytes(private)
    lines = result.stdout.splitlines()
    inventories = [line.split()[0].decode() for line in lines
                   if re.fullmatch(rb"[0-9a-f]{64}  /tmp/project-libraries-migration[.][A-Za-z0-9]+/inventory", line)]
    previous = LOCKS["historical.lock"][1]
    replacement = LOCKS["project.lock"][1]
    require(inventories == [sha((output / "base.lock").read_bytes()), previous, replacement, previous],
            "historical replacement and restoration inventory readback")
    require(lines[-1:] == [b"MIGRATION622_PASSED native-tiff"]
            and lines.count(b"TIFF JBIG roundtrip passed") == 3 and not list(docker.owned_containers()),
            "native historical replacement and restoration terminal marker")
    return {"status": "PASSED", "scope": "Minimal206 plus exact historical providers and lcms2",
            "archives": {name: digest for name, (_, digest) in PROJECT_PACKAGES.items()},
            "historical_package_signatures": 3, "inventory_sequence": inventories,
            "unchanged_tificc_checks": 3, "tiff_jbig_roundtrips": 3,
            "hosted_shared_library_hash_checks": 4,
            "test_signer": (output / "test-fingerprint").read_text().strip(), "log_sha256": sha(private)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("historical-cache", "codec-cache", "project-cache", "minimal-cache", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--emulated-tiff", action="store_true",
                        help="use the exact recorded local emulated TIFF archive for the reduced fixture")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        stage(args)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Migration inputs refused: {error}\n")
    print("MIGRATION622_INPUTS_AUTHENTICATED", "emulated-tiff" if args.emulated_tiff else "native-tiff")
    return 0


if __name__ == "__main__":
    sys.exit(main())
