# SPDX-License-Identifier: MIT
"""Private intake and exact r12 authentication for the #622 build-only lane."""
from concurrent.futures import as_completed, ThreadPoolExecutor
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys

from preflight import INPUTS_PIN, PRODUCER, ROOT, producer_blob

CANDIDATE = "a7c2a30fb37934cad320d982b7d2ab2413dab2a7"
CANDIDATE_TREE = "8cf292a311f6abccbb6de51963fd4751b13bcd5c"
# 6835cdf1 changed only the guide inside the qualified recipe tree.
CANDIDATE_TREES = frozenset((CANDIDATE_TREE, "441815470dc9434c9b4f314f57cb2521f19e9520"))
PROJECT = ROOT / "scripts/build/project-libraries"
# Exact bodies whose pinned primary routes returned 404 on 2026-11-25.
# Every size and digest comes from the r12 lock, including the kernel body.
RETAINED = frozenset({
    "ca-certificates-mozilla-3.133-1-aarch64.pkg.tar.xz",
    "cmake-4.5.0-1-aarch64.pkg.tar.xz",
    "cryptsetup-2.8.8-2-aarch64.pkg.tar.xz",
    "flex-2.6.10-1-aarch64.pkg.tar.xz",
    "gdb-18.1-1-aarch64.pkg.tar.xz",
    "gdb-common-18.1-1-aarch64.pkg.tar.xz",
    "gnutls-3.8.13-3-aarch64.pkg.tar.xz",
    "gpgme-2.2.0-1-aarch64.pkg.tar.xz",
    "kmod-34.3-2-aarch64.pkg.tar.xz",
    "libffi-3.8.0-1-aarch64.pkg.tar.xz",
    "libseccomp-2.6.0-1-aarch64.pkg.tar.xz",
    "linux-aarch64-7.3.4-3-aarch64.pkg.tar.xz",
    "pacman-mirrorlist-20260411-2-any.pkg.tar.xz",
    "tpm2-tss-4.2.1-2-aarch64.pkg.tar.xz",
})
EXTENSION_PIN = "f95032f8c8ffaec5a16ba372952328eaaab97a87d3535504bffcf541716ce4d1"
PRODUCER_FILES = (
    "entry.py", "contract.py", "profile.json", "expected206.lock", "rootfs_bootstrap_core.py",
    "runtime/scripts/ci/inputs.lock.json", "runtime/scripts/ci/native_arm.py",
    "runtime/scripts/checks/package_checks.py",
)


class GuardFailure(ValueError):
    """A refusal with a public-safe reason."""


def require(condition, message):
    if not condition:
        raise GuardFailure(message)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(argv, *, timeout=60, **kwargs):
    return subprocess.run(argv, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, **kwargs)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_pin(path, expected):
    with path.open("rb") as stream:
        body = stream.read(2**20 + 1)
    require(len(body) <= 2**20 and hashlib.sha256(body).hexdigest() == expected, "locked input contract")
    return json.loads(body)


def bind_candidate():
    folder = PROJECT.relative_to(ROOT)
    oid = command(["git", "rev-parse", f"HEAD:{folder}"], cwd=ROOT).stdout.decode().strip()
    status = command(["git", "status", "--porcelain=v1", "--untracked-files=all", "--", str(folder)],
                     cwd=ROOT).stdout
    require(oid in CANDIDATE_TREES and not status, "exact clean #622 candidate tree")
    return oid


def stage_producer(scratch):
    root = scratch / "r12"
    for relative in PRODUCER_FILES:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(producer_blob(relative))
    inputs = read_pin(root / "runtime/scripts/ci/inputs.lock.json", INPUTS_PIN)
    native = load(root / "runtime/scripts/ci/native_arm.py", "_minimal206_native")
    entry = load(root / "entry.py", "_minimal206_entry")
    core = load(root / "rootfs_bootstrap_core.py", "_minimal206_rootfs")
    return root, inputs, native, entry, core


def retained_pins():
    path = ROOT / "scripts/port/minimal-native-builder-inputs/native-inputs.lock.json"
    lock = read_pin(path, INPUTS_PIN)
    pins = {row["filename"]: {"bytes": row["size"], "sha256": row["sha256"]}
            for row in lock["packages"] if row["filename"] in RETAINED}
    require(pins.keys() == RETAINED, "exact r12 retained namespace")
    return pins


def check_retained_directory(directory):
    facts = directory.lstat()
    require(stat.S_ISDIR(facts.st_mode) and stat.S_IMODE(facts.st_mode) == 0o700
            and facts.st_uid == os.getuid(), "owned private retained cache")
    require({item.name for item in directory.iterdir()} == RETAINED, "exact retained cache membership")


def download(url, path, size):
    require(re.fullmatch(r'[^\x00-\x20\x7f-\uffff"\\]+', url), "invalid pinned HTTPS URL")
    args = ["curl", "-q", "--silent", "--fail", "--globoff", "--proto", "=https",
            "--connect-timeout", "15", "--max-time", "240", "--max-filesize", str(max(1, size)),
            "--output", str(path), "--write-out", "%{http_code}", "--location",
            "--proto-redir", "=https", "--max-redirs", "3", "--", url]
    result = subprocess.run(args, capture_output=True, timeout=250)
    require(result.returncode == 0 and result.stdout == b"200", f"input transport failed: {path.name}")


def stage_object(directory, name, pin, local=None):
    path = directory / name
    size, digest = pin["bytes"], pin["sha256"]
    source = local / name if local else None
    if source is not None:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(source, flags), "rb") as stream:
            facts = os.fstat(stream.fileno())
            require(stat.S_ISREG(facts.st_mode) and facts.st_size == size, f"cached input size/type: {name}")
            with path.open("xb") as output:
                remaining = size
                while remaining:
                    chunk = stream.read(min(remaining, 1024**2))
                    require(chunk, f"truncated cached input: {name}")
                    output.write(chunk)
                    remaining -= len(chunk)
                require(not stream.read(1), f"oversized cached input: {name}")
    else:
        require("url" in pin, f"missing cached input: {name}")
        download(pin["url"], path, size)
    require(path.stat().st_size == size and sha(path) == digest, f"input pin mismatch: {name}")
    return path


def stage_set(directory, pins, local=None, retained=None):
    directory.mkdir(mode=0o700)
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(stage_object, directory, name, row,
                               retained if name in RETAINED and retained is not None else local)
                   for name, row in pins.items()]
        try:
            for future in as_completed(futures):
                future.result()
        except BaseException:
            for future in futures:
                future.cancel()
            raise


def export_retained(cache, pins, output):
    # Refuse an existing destination and remove only our own incomplete export.
    output.mkdir(mode=0o700)
    try:
        for name in sorted(RETAINED):
            stage_object(output, name, pins[name], cache)
    except BaseException:
        shutil.rmtree(output)
        raise


def prepare_inputs(args, scratch, report):
    recipe_tree = bind_candidate()
    root, inputs, native, entry, core = stage_producer(scratch)
    sys.path.insert(0, str(PROJECT))
    import baseline
    import prepare

    cache, boot = scratch / "cache", scratch / "bootstrap"
    boot.mkdir(mode=0o700)
    # The pinned profile already provides the 206 exact detached signatures.
    objects = [*inputs["keyring_files"], inputs["rootfs"], native.signature_item(inputs["rootfs"]),
               *inputs["packages"]]
    base_pins = {native.input_name(row["filename"]):
                 {"bytes": row["size"], "sha256": row["sha256"], "url": row["url"]} for row in objects}
    require(len(base_pins) == 211 and RETAINED <= base_pins.keys(), "r12 body/key namespace")
    # A full local cache supplies every byte. A hosted run selects only the
    # 14 already staged private objects before authenticating the same lock.
    if args.minimal_cache:
        for item in inputs["packages"]:
            signature = native.signature_item(item)
            base_pins[signature["filename"]] = {"bytes": signature["size"], "sha256": signature["sha256"]}
    report["phase"] = "minimal206-acquisition"
    if args.retained_cache is not None:
        check_retained_directory(args.retained_cache)
    stage_set(cache, base_pins, args.minimal_cache, args.retained_cache)
    if not args.minimal_cache:
        entry.C.seed_minimal_public_signatures(cache, inputs, json.loads((root / "profile.json").read_bytes()))
    shutil.copyfile(root / "runtime/scripts/ci/inputs.lock.json", boot / "inputs.lock.json")
    report["phase"] = "minimal206-authentication"
    require(native.audit(inputs, cache, boot) == 206, "complete r12 signature audit")
    totals = json.loads((boot / "acquisition.json").read_text())["counts"]
    require(totals == {"total": 417, "pass": 417, "fail": 0, "pending": 0}, "full r12 input custody")
    core.signed_rootfs_layout(cache / inputs["rootfs"]["filename"])
    report["minimal206"] = {"pinned_objects": 417, "verified_signatures": 207, "producer": PRODUCER,
                            "inputs_sha256": INPUTS_PIN, "signed_rootfs_layout": "PASSED"}

    report["phase"] = "codec-authentication"
    extension = read_pin(PROJECT / "minimal206-extension.json", EXTENSION_PIN)
    require(extension["base_source"] == PRODUCER
            and extension["signer_fingerprint"] == inputs["signer_fingerprint"], "r12 extension binding")
    codecs = scratch / "codecs"
    pins = extension["codec_files"]
    if not args.codec_cache:
        pins = {name: dict(row, url=extension["codec_origin"] + name) for name, row in pins.items()}
    stage_set(codecs, pins, args.codec_cache)
    keyring = scratch / "alarm.gpg"
    command(["gpg", "--batch", "--no-options", "--homedir", str(boot / "gpg"), "--dearmor",
             "--output", str(keyring), str(cache / "archlinuxarm.gpg")])
    baseline.verify_codecs(codecs, keyring, extension)
    (scratch / "expected210.lock").write_bytes(baseline.derive((root / "expected206.lock").read_bytes(), extension))
    report["codecs"] = {"verified_signatures": 3, "signer": extension["signer_fingerprint"]}

    report["phase"] = "recipe-materialization"
    upstream = scratch / "upstream"
    plan = prepare.load_plan(lambda _: None)
    pins = plan["upstream"]
    if args.upstream_dir:
        pins = {name: {"bytes": row["bytes"], "sha256": row["sha256"]} for name, row in pins.items()}
    stage_set(upstream, pins, args.upstream_dir)
    sources = {name: upstream / name for name in prepare.UPSTREAM}
    first = prepare.prepare(sources, scratch / "recipes", lambda _: None)
    second = prepare.prepare(sources, scratch / "recipes-recheck", lambda _: None)
    require(first == second, "two recipe materializations agree")
    for package in prepare.PACKAGES:
        filename = f"{package}-reviewed-inputs.json"
        require((scratch / "recipes" / filename).read_bytes() ==
                (scratch / "recipes-recheck" / filename).read_bytes(), "reviewed recipe hash maps agree")
    report["recipe_tree"] = recipe_tree
    report["recipe_materializations"] = {"runs": 2, "pinned_files": first["files_count"],
                                         "plan_sha256": first["plan_sha256"]}
    report["retained"] = {name: {key: base_pins[name][key] for key in ("bytes", "sha256")}
                          for name in sorted(RETAINED)}
    if args.export_retained is not None:
        require(not args.export_retained.resolve().is_relative_to(args.minimal_cache.resolve()),
                "retained export must be outside the source cache")
        export_retained(cache, base_pins, args.export_retained)
    return root, inputs, native, entry, core
