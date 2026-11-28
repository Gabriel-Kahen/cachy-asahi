#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify and stage the headless Weston fixture for the Asahi629 Qt checkpoint."""

import argparse
from hashlib import sha256
import io
import json
import lzma
import os
from pathlib import Path
from runpy import run_path
import shutil
import stat
import subprocess
import tarfile
from tempfile import TemporaryDirectory


INTEGRATION = Path(__file__).resolve().parents[1]
A = run_path(str(INTEGRATION / "qt612_vulkan_md4c_successor/arm16k_inputs.py"))
need, pin = A["need"], A["pin"]
KIND = "QT629_WESTON_FIXTURE_VERIFIED_V1"
ARCHIVE = "weston-15.0.1-3-aarch64.pkg.tar.xz"
PINS = {
    "archive": pin(1404596, "2da79ea9f1059b5e068debbf6c5b4f650c59c9b6725d98479c5c99753d878f36"),
    "signature": pin(566, "8c9ebba381aa0bee1b59aaff78e982401ede6f0d6c44c0864659db835661152a"),
    "alarm_public_key": A["KEY"],
}
FILES = {
    "usr/bin/weston": pin(67720, "c7c57b3c5fc46321c13d8ad46891e1c8eb382ff26d5f08108937b27e15bc0ea4"),
    "usr/lib/libweston-15.so.0.0.1": pin(593992, "120bea10b92bc949810acb6e88978b53ac5c5e4a917dbc41d233959bca82cd5e"),
    "usr/lib/libweston-15/headless-backend.so": pin(67568, "3ae0227efba215ea3f42fc299cb3b5a7cd98c9cd832a32f98f3f963780f7cbe6"),
    "usr/lib/weston/libexec_weston.so.0.0.0": pin(199000, "94b181d42f178ad42f129f70f600c1c7eb62e0fa7119d58f1f89458bb79d7d58"),
    "usr/lib/weston/kiosk-shell.so": pin(67672, "62902992bacf93e14271f7e592ebb8748f648ace63f8eae4f542e9fce72b9a3e"),
}
LINKS = {
    "usr/lib/libweston-15.so.0": "libweston-15.so.0.0.1",
    "usr/lib/weston/libexec_weston.so.0": "libexec_weston.so.0.0.0",
}
# The vendor archive also includes linker-time aliases. They are never staged.
ARCHIVE_LINKS = LINKS | {
    "usr/lib/libweston-15.so": "libweston-15.so.0",
    "usr/lib/weston/libexec_weston.so": "libexec_weston.so.0",
}
DIRECTORIES = ("usr", "usr/bin", "usr/lib", "usr/lib/libweston-15", "usr/lib/weston")
MAX_TAR_BYTES = 10 << 20
MAX_TAR_MEMBERS = 256
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _checked_members(body):
    """Read only the reviewed payload, with bounds on the entire tar stream."""
    decoder = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=64 << 20)
    raw = decoder.decompress(body, max_length=MAX_TAR_BYTES + 1)
    need(len(raw) <= MAX_TAR_BYTES and decoder.eof and not decoder.unused_data,
         "Expected one bounded Weston XZ stream")
    files, seen = {}, set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:", encoding="utf-8", errors="strict") as archive:
        for member in archive:
            name = member.name
            need(len(seen) < MAX_TAR_MEMBERS, "Too many Weston tar members")
            need(not {"", ".", ".."}.intersection(name.split("/")) and name not in seen
                 and not member.pax_headers and member.offset_data == member.offset + tarfile.BLOCKSIZE,
                 f"Unexpected Weston tar path or metadata: {name}")
            seen.add(name)
            if name in ARCHIVE_LINKS or member.issym():
                need(member.issym() and ARCHIVE_LINKS.get(name) == member.linkname
                     and member.size == 0 and (member.uid, member.gid, member.mode) == (0, 0, 0o777),
                     f"Unexpected Weston archive link: {name}")
            elif name in FILES:
                expected = FILES[name]
                need(member.type == tarfile.REGTYPE and not member.linkname and member.size == expected["bytes"]
                     and (member.uid, member.gid, member.mode) == (0, 0, 0o755),
                     f"Unexpected Weston payload metadata: {name}")
                with archive.extractfile(member) as stream:
                    payload = stream.read(expected["bytes"] + 1)
                need(pin(len(payload), sha256(payload).hexdigest()) == expected,
                     f"Unexpected Weston payload digest: {name}")
                files[name] = payload
            else:
                need(member.type in (tarfile.REGTYPE, tarfile.DIRTYPE) and not member.linkname
                     and (name not in DIRECTORIES or member.isdir()), f"Unexpected Weston archive member: {name}")
        need(not any(raw[archive.offset:]), "Unexpected data after the Weston tar members")
    need(files.keys() == FILES.keys() and LINKS.keys() <= seen, "Incomplete Weston fixture payload")
    return files


def _verified_payload(archive, signature, public_key):
    row = dict(filename=ARCHIVE, signer=A["FINGERPRINT"],
               archive=dict(path=archive, **PINS["archive"]), signature=dict(path=signature, **PINS["signature"]))
    key = A["read"](public_key, PINS["alarm_public_key"])
    with TemporaryDirectory(prefix="qt629-weston-key-") as temporary:
        home = Path(temporary)
        keyring = home / "alarm-public.gpg"
        keyring.write_bytes(key)
        keyring.chmod(0o400)
        status = A["verify_signature"](row, home, keyring)
    files = _checked_members(A["read"](archive, PINS["archive"]))
    members = {name: dict(type="file", mode=0o755, **expected) for name, expected in FILES.items()}
    members.update({name: dict(type="symlink", target=target) for name, target in LINKS.items()})
    inputs = {role: expected.copy() for role, expected in PINS.items()}
    return files, dict(kind=KIND, filename=ARCHIVE, inputs=inputs, signer=row["signer"],
                       signature_status=status, members=members)


def verify(*, archive, signature, public_key):
    """Return the detached signature and exact member receipt without staging."""
    _, receipt = _verified_payload(archive, signature, public_key)
    return receipt


def _write_fixture(destination, files):
    destination = Path(destination)
    parent_path = destination.parent
    need(destination.is_absolute() and destination.name not in ("", ".", "..")
         and parent_path.resolve(strict=True) == parent_path, "Canonical Weston fixture destination required")
    parent = os.open(parent_path, DIR_FLAGS)
    try:
        meta = os.fstat(parent)
        need(meta.st_uid == os.geteuid() and (not meta.st_mode & 0o022 or meta.st_mode & stat.S_ISVTX),
             "Weston fixture parent must be actor-owned and protected")
        os.mkdir(destination.name, 0o700, dir_fd=parent)
        try:
            root = os.open(destination.name, DIR_FLAGS, dir_fd=parent)
            try:
                for name in DIRECTORIES:
                    os.mkdir(name, 0o700, dir_fd=root)
                    os.chmod(name, 0o755, dir_fd=root)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
                for name, body in files.items():
                    with os.fdopen(os.open(name, flags, 0o600, dir_fd=root), "wb") as stream:
                        stream.write(body)
                        os.fchmod(stream.fileno(), 0o755)
                for name, target in LINKS.items():
                    os.symlink(target, name, dir_fd=root)
                os.fchmod(root, 0o755)
            finally:
                os.close(root)
        except BaseException:
            shutil.rmtree(destination.name, dir_fd=parent)
            raise
    finally:
        os.close(parent)


def stage(*, archive, signature, public_key, destination):
    """Validate all inputs and populate a fresh actor-owned destination."""
    files, receipt = _verified_payload(archive, signature, public_key)
    _write_fixture(destination, files)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--signature", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    inputs = dict(archive=args.archive, signature=args.signature, public_key=args.public_key)
    try:
        receipt = verify(**inputs) if args.destination is None else stage(**inputs, destination=args.destination)
    except (EOFError, OSError, ValueError, lzma.LZMAError, tarfile.TarError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Weston fixture refused: {error}\n")
    print(json.dumps(receipt, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
