#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Deterministic C01 correctness inputs, written only to a fresh supplied directory.

Exercise every input for correctness. Future training may use only ``train``;
future timing may use only caller-reviewed ``heldout`` bytes. Public provenance
and native minigzip rejection of corrupt gzip files require the runner's checks.
The gzip reference uses one stored DEFLATE block, independent of compressor versions.
"""
import binascii
import hashlib
import json
from pathlib import Path
import random

LIMIT = 16 * 1024 * 1024
SEED = 0xCA5A11
TRAIN = b"cachy-asahi deterministic native compiler correctness corpus\n" * 2048
GZIP_PAYLOAD = b"cachy-asahi gzip correctness reference\n" * 8


def create(output, heldout_bytes):
    """Return and save a manifest; validation failures precede directory creation.

    The 16 MiB bound includes payloads and manifest.json. Existing destinations
    are refused, including symlinks. No parent directories are created or files
    outside the supplied output directory written. Partial I/O failures remain
    visible rather than deleting caller paths.
    """
    if not isinstance(heldout_bytes, bytes):
        raise TypeError("heldout_bytes must be caller-reviewed public source bytes")
    if not heldout_bytes or len(heldout_bytes) > LIMIT:
        raise ValueError("nonempty held-out bytes within the corpus limit required")
    if heldout_bytes == TRAIN:
        raise ValueError("training and held-out timing bytes must be disjoint")
    rng = random.Random(SEED)
    size = len(GZIP_PAYLOAD)
    reference = (b"\x1f\x8b\x08\x00\0\0\0\0\x00\xff\x01" + size.to_bytes(2, "little")
                 + (size ^ 0xffff).to_bytes(2, "little") + GZIP_PAYLOAD
                 + binascii.crc32(GZIP_PAYLOAD).to_bytes(4, "little") + size.to_bytes(4, "little"))
    bad_crc = bytearray(reference)
    bad_crc[-8] ^= 1  # Keep gzip magic valid: minigzip can transparently read non-gzip.
    blobs = [
        ("empty.bin", b"", "input", "correctness"),
        ("onebyte.bin", b"x", "input", "correctness"),
        ("repeated.txt", TRAIN, "input", "train"),
        ("allbytes.bin", bytes(range(256)) * 256, "input", "correctness"),
        ("incompressible.bin", bytes(rng.getrandbits(8) for _ in range(256 * 1024)), "input", "correctness"),
        ("heldout-source.bin", heldout_bytes, "input", "heldout"),
        ("gzip-reference.gz", reference, "input", "correctness"),
        ("corrupt-crc.gz", bytes(bad_crc), "corrupt", "correctness"),
        ("truncated-trailer.gz", reference[:-8], "corrupt", "correctness"),
    ]
    manifest = {"schema_version": 1, "files": [
        {"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "kind": kind, "role": role}
        for name, data, kind, role in blobs]}
    encoded = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    if sum(len(data) for _, data, _, _ in blobs) + len(encoded) > LIMIT:
        raise ValueError("complete corpus including manifest exceeds 16 MiB")
    directory = Path(output)
    directory.mkdir(mode=0o700, exist_ok=False)
    for name, data, _, _ in blobs:
        with (directory / name).open("xb") as stream:
            stream.write(data)
    with (directory / "manifest.json").open("xb") as stream:
        stream.write(encoded)
    return manifest
