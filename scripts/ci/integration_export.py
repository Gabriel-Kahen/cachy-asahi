#!/usr/bin/env python3
"""Export bounded public integration receipts, never component state or archives.

The controller must supply deliberately public receipts. This conservative filter
is defense in depth, not a detector for arbitrary credentials embedded in prose.
All reads/writes are local; this module never executes commands or installs files.
"""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

FILE_LIMIT = 4 * 1024**2
TOTAL_LIMIT = 16 * 1024**2  # Includes the diagnostic manifest.
ENTRY_LIMIT = 2048
DEPTH_LIMIT = 32
PATH_LIMIT = 512
MANIFEST = "export-manifest.json"
SUFFIXES = {".json", ".log", ".txt"}
SENSITIVE_PATH = re.compile(
    r"gpg|gnupg|secret|private|(?:^|[._-])(?:home[s]?|"
    r"homedir|scratch|rootfs|dependency|dependencies|cache)(?:$|[._-])", re.I)
PRIVATE_CONTENT = re.compile(
    r"-----BEGIN (?:PGP PRIVATE KEY BLOCK|(?:[A-Z0-9 ]* )?PRIVATE KEY)-----|"
    r"\((?:protected-|shadowed-)?private-key\b|"
    r"\bsecret[-_ ](?:sub)?keys?\b|--(?:export-secret[^\s]*|passphrase[^\s]*)|"
    r"[\"']?(?:password|passwd|passphrase|private[_-]?key|secret|client_secret|"
    r"token|api[_-]?key|access_token|refresh_token|authorization)[\"']?\s*[:=]\s*\S+|"
    r"\bBearer\s+\S+", re.I)


def _json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _directory(path):
    """Reject symlink components, including the input root and output parents."""
    if ".." in Path(path).parts:
        raise ValueError("parent traversal is not allowed")
    path = Path(os.path.abspath(path))
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if not stat.S_ISDIR(current.lstat().st_mode):
            raise ValueError("directory component is not a real directory")
    return path


def export_evidence(raw, output):
    """Return manifest; output must be new. Rejections produce FAIL, safe files stay.

    Paths never come from receipt contents. Traversal does not follow symlinks;
    directory/file descriptors bind reads to the scanned tree. Sensitive subtrees
    are rejected at their root without reading or enumerating their contents.
    """
    raw = _directory(raw)
    if ".." in Path(output).parts:
        raise ValueError("parent traversal is not allowed")
    output = Path(os.path.abspath(output))
    _directory(output.parent)
    if raw == output or raw in output.parents or output in raw.parents:
        raise ValueError("input and output directories overlap")
    output.mkdir(mode=0o700)  # Never reuse or overwrite previous evidence.
    accepted, rejected = [], []
    seen = 0
    total = 0
    stopped = False
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK

    def reject(relative, reason, size=None):
        name = relative.as_posix()
        if len(name) > PATH_LIMIT:
            name = "[path-sha256:" + hashlib.sha256(os.fsencode(name)).hexdigest() + "]"
        record = {"path": name, "reason": reason}
        if size is not None:
            record["bytes"] = size
        rejected.append(record)

    def walk(directory_fd, prefix, depth):
        nonlocal seen, total, stopped
        # Bound inventory memory too, not just the exported file bytes.
        entries = []
        with os.scandir(directory_fd) as iterator:
            for entry in iterator:
                seen += 1
                if seen > ENTRY_LIMIT:
                    reject(prefix, "entry-limit-exceeded; remaining tree not exported")
                    stopped = True
                    break
                entries.append(entry.name)
        for name in sorted(entries):
            if stopped:
                break
            relative = prefix / name
            if (len(relative.as_posix()) > PATH_LIMIT or
                    any(ord(char) < 32 or ord(char) > 126 for char in name)):
                reject(relative, "unsafe-or-overlong-path")
                continue
            if SENSITIVE_PATH.search(name):
                reject(relative, "sensitive-path; subtree not exported")
                continue
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISLNK(info.st_mode):
                    reject(relative, "symlink")
                elif stat.S_ISDIR(info.st_mode):
                    if depth >= DEPTH_LIMIT:
                        reject(relative, "depth-limit-exceeded; subtree not exported")
                        continue
                    fd = os.open(name, flags | os.O_DIRECTORY, dir_fd=directory_fd)
                    try:
                        opened = os.fstat(fd)
                        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                            reject(relative, "directory-changed-during-read")
                        else:
                            walk(fd, relative, depth + 1)
                    finally:
                        os.close(fd)
                elif not stat.S_ISREG(info.st_mode):
                    reject(relative, "nonregular-file")
                elif info.st_nlink != 1:
                    reject(relative, "hardlinked-file")
                elif relative.as_posix() == MANIFEST:
                    reject(relative, "reserved-manifest-path")
                elif Path(name).suffix.lower() not in SUFFIXES:
                    reject(relative, "unsupported-file-type; archives never exported", info.st_size)
                elif info.st_size > FILE_LIMIT:
                    reject(relative, "per-file-byte-limit", info.st_size)
                elif total + info.st_size > TOTAL_LIMIT:
                    reject(relative, "total-byte-limit", info.st_size)
                else:
                    fd = os.open(name, flags, dir_fd=directory_fd)
                    with os.fdopen(fd, "rb") as stream:
                        opened = os.fstat(stream.fileno())
                        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                                (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)):
                            reject(relative, "file-changed-during-read")
                            continue
                        data = stream.read(FILE_LIMIT + 1)
                        after = os.fstat(stream.fileno())
                    if len(data) > FILE_LIMIT:
                        reject(relative, "per-file-byte-limit", len(data))
                        continue
                    if (len(data) != info.st_size or
                            (after.st_size, after.st_mtime_ns, after.st_ctime_ns) !=
                            (info.st_size, info.st_mtime_ns, info.st_ctime_ns)):
                        reject(relative, "file-changed-during-read")
                        continue
                    try:
                        content = data.decode("utf-8")
                    except UnicodeDecodeError:
                        reject(relative, "non-utf8-content")
                        continue
                    if any(ord(char) < 32 and char not in "\n\r\t" for char in content):
                        reject(relative, "binary-control-content")
                        continue
                    if PRIVATE_CONTENT.search(content):
                        reject(relative, "private-key-or-credential-content")
                        continue
                    if Path(name).suffix.lower() == ".json":
                        try:
                            json.loads(content)
                        except (ValueError, RecursionError):
                            reject(relative, "invalid-json")
                            continue
                    target = output / relative
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with target.open("xb") as stream:
                        stream.write(data)
                    accepted.append({"path": relative.as_posix(), "bytes": len(data),
                                     "sha256": hashlib.sha256(data).hexdigest()})
                    total += len(data)
            except OSError:
                reject(relative, "filesystem-read-failed")

    fd = os.open(raw, flags | os.O_DIRECTORY)
    try:
        walk(fd, Path(), 0)
    finally:
        os.close(fd)

    while True:
        manifest = {"schema_version": 1, "evidence_export": "FAIL" if rejected else "PASS",
                    "accepted": accepted, "rejected": rejected, "accepted_bytes": total,
                    "limits": {"per_file_bytes": FILE_LIMIT, "total_bytes_including_manifest": TOTAL_LIMIT,
                               "entries": ENTRY_LIMIT, "depth": DEPTH_LIMIT},
                    "inventory_limit_exceeded": stopped,
                    "inventory_scope": "sensitive subtrees are rejected without enumeration"}
        encoded = _json_bytes(manifest)
        if total + len(encoded) <= TOTAL_LIMIT:
            break
        if not accepted:
            raise ValueError("diagnostic manifest exceeds total byte limit")
        item = accepted.pop()
        (output / item["path"]).unlink()
        total -= item["bytes"]
        reject(Path(item["path"]), "total-byte-limit-including-manifest", item["bytes"])
    (output / MANIFEST).write_bytes(encoded)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = export_evidence(args.raw, args.output)
    except (OSError, ValueError):
        print("Evidence export failed: invalid paths, existing output, or diagnostic budget.", file=sys.stderr)
        return 2
    print(json.dumps({"evidence_export": result["evidence_export"],
                      "accepted_files": len(result["accepted"]), "rejected_entries": len(result["rejected"])}))
    return 0 if result["evidence_export"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
