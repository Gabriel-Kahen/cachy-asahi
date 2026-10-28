#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline, checksum-bound package metadata witnesses; never a transaction solver."""
import argparse
import ctypes
import ctypes.util
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

MAX_BYTES = 8 * 1024**2
PINS = {
    "image": "5c1630b5cdf07898118979895682c3a3b705e416c9840ada4e1a5193dccd6941",
    "signed": "c0f093e209cc4bb94b6057380e444670232f0452768c71e6bd5201e59e290f7a",
    "metadata": "910ffee18475e5e1bb2e56b8f4f568af267f66e24c0d7dce2f45029a8c9fb2bf",
    "repository": "bb500d9a8293142332189946b6fce5cf927ed677f73f749d35f4f3eff0a5d217",
}
BOOT = ("linux-asahi", "m1n1", "uboot-asahi", "asahi-scripts", "asahi-fwextract")
AUDIO = ("asahi-audio", "speakersafetyd")
ROOTS = ("asahi-meta", "grub", "mkinitcpio", "lzfse", "alsa-ucm-conf",
         "linux-firmware", "archlinuxarm-keyring", "archlinux-keyring")
RELATION = re.compile(r"([A-Za-z0-9@_+.:-]+)(?:(>=|<=|=|>|<)([^\s<>=]+))?")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_bound(path, expected):
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("invalid expected checksum")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("input must be a regular file")
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES or digest(data) != expected:
        raise ValueError("input size/checksum mismatch: " + str(path))
    return data


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def load_json(data):
    def invalid(value):
        raise ValueError("non-finite JSON value: " + value)
    return json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs,
                      parse_constant=invalid)


def relation(value):
    match = RELATION.fullmatch(value)
    if not match or len(value) > 512:
        raise ValueError("invalid package relation: " + repr(value))
    return match.groups()


def packages(records):
    if not isinstance(records, list) or len(records) > 4096:
        raise ValueError("invalid package inventory")
    result = {}
    for entry in records:
        if not isinstance(entry, dict) or any(
                not isinstance(k, str) or not isinstance(v, list) or len(v) > 256
                or any(not isinstance(x, str) or len(x) > 16384 for x in v)
                for k, v in entry.items()):
            raise ValueError("invalid package metadata fields")
        for field in ("NAME", "VERSION", "ARCH"):
            if len(entry.get(field, [])) != 1:
                raise ValueError("missing or repeated package identity")
        name, version = entry["NAME"][0], entry["VERSION"][0]
        if relation(name)[1] or not version or re.search(r"\s|[<>=]", version):
            raise ValueError("invalid package identity")
        if entry["ARCH"][0] not in ("aarch64", "any") or name in result:
            raise ValueError("wrong architecture or duplicate package")
        for field in ("DEPENDS", "PROVIDES", "CONFLICTS", "REPLACES"):
            for value in entry.get(field, []):
                relation(value)
        result[name] = entry
    return result


class Versions:
    def __init__(self):
        library = ctypes.util.find_library("alpm")
        if not library:
            raise ValueError("preinstalled libalpm is required; nothing is installed")
        self.library = ctypes.CDLL(library)
        self.compare = self.library.alpm_pkg_vercmp
        self.compare.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
        self.compare.restype = ctypes.c_int

    def satisfies(self, actual, operator, required):
        if operator is None:
            return True
        if actual is None:
            return False
        value = self.compare(actual.encode(), required.encode())
        return {"=": value == 0, ">=": value >= 0, "<=": value <= 0,
                ">": value > 0, "<": value < 0}[operator]


def witnesses(requirement, inventory, versions):
    name, operator, required = relation(requirement)
    found = []
    for package, data in sorted(inventory.items()):
        candidates = [(data["VERSION"][0], "name")] if package == name else []
        for provision in data.get("PROVIDES", []):
            provided, op, version = relation(provision)
            if op not in (None, "="):
                raise ValueError("invalid provision operator")
            if provided == name:
                candidates.append((version, provision))
        for actual, via in candidates:
            if versions.satisfies(actual, operator, required):
                found.append({"package": package, "version": data["VERSION"][0],
                              "via": via, "effective_version": actual})
                break
    return found


def requirements(inventory, available, versions):
    return [{"package": name, "requires": dep,
             "witnesses": witnesses(dep, available, versions)}
            for name, data in sorted(inventory.items())
            for dep in data.get("DEPENDS", [])]


def parse_desc(text):
    result, field = {}, None
    for line in text.splitlines():
        if line.startswith("%") and line.endswith("%"):
            field = line[1:-1]
            if not field or field in result:
                raise ValueError("duplicate/empty repository field")
            result[field] = []
        elif line:
            if field is None:
                raise ValueError("repository value without field")
            result[field].append(line)
    return result


def repository(data):
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        decoded = stream.read(MAX_BYTES + 1)
    if len(decoded) > MAX_BYTES:
        raise ValueError("repository decoded size limit")
    records = []
    with tarfile.open(fileobj=io.BytesIO(decoded), mode="r:") as archive:
        for index, member in enumerate(archive):
            if index >= 2048 or member.size > 65536:
                raise ValueError("repository member limit")
            if member.isdir():
                continue
            if not member.isfile() or not re.fullmatch(r"[^/]+/desc", member.name):
                raise ValueError("unexpected repository member")
            records.append(parse_desc(archive.extractfile(member).read().decode("utf-8")))
    return packages(records)


def verify_pkginfo(signed, inspections):
    if not isinstance(inspections, list) or len(inspections) != len(signed):
        raise ValueError("incorrect package inspection count")
    seen = set()
    mappings = (("pkgname", "NAME"), ("pkgver", "VERSION"), ("arch", "ARCH"),
                ("pkgbase", "BASE"), ("depend", "DEPENDS"), ("provides", "PROVIDES"),
                ("conflict", "CONFLICTS"), ("replaces", "REPLACES"))
    for inspection in inspections:
        name = inspection["name"]
        if name not in signed or name in seen:
            raise ValueError("incorrect/duplicate inspection package")
        seen.add(name)
        source = signed[name]
        if inspection["archive_sha256"] != source["archive"]["sha256"]:
            raise ValueError("inspection/archive checksum mismatch")
        selected = inspection["selected_data"][".PKGINFO"]
        data = selected["text"].encode("utf-8")
        if len(data) > 65536 or len(data) != selected["bytes"] or digest(data) != selected["sha256"]:
            raise ValueError("PKGINFO content checksum/size mismatch")
        fields = {}
        for line in selected["text"].splitlines():
            if not line or line.startswith("#"):
                continue
            key, sep, value = line.partition(" = ")
            if not sep:
                raise ValueError("invalid PKGINFO line")
            fields.setdefault(key, []).append(value)
        for pkginfo, repo in mappings:
            if fields.get(pkginfo, []) != source["metadata"].get(repo, []):
                raise ValueError("PKGINFO/repository mismatch: " + name + "/" + repo)


def run(image_path, signed_path, metadata_path, repository_path=None, *, expected_hashes=None):
    """Return data only. Default pins are retained receipts, not owner authentication."""
    pins = PINS if expected_hashes is None else expected_hashes
    paths = {"image": image_path, "signed": signed_path, "metadata": metadata_path}
    if repository_path is not None:
        paths["repository"] = repository_path
    raw = {key: read_bound(path, pins[key]) for key, path in paths.items()}
    image_doc, signed_doc = load_json(raw["image"]), load_json(raw["signed"])
    image = packages([entry["metadata"] for entry in image_doc["packages"]])
    published = packages([entry["metadata"] for entry in signed_doc["packages"]])
    if set(published) != set(BOOT + AUDIO):
        raise ValueError("expected exactly seven retained platform packages")
    signed = {entry["metadata"]["NAME"][0]: entry for entry in signed_doc["packages"]}
    verify_pkginfo(signed, load_json(raw["metadata"]))
    repo = repository(raw["repository"]) if "repository" in raw else {}
    if repo:
        if signed_doc["repository_sha256"] != digest(raw["repository"]):
            raise ValueError("signed capture/repository checksum mismatch")
        for name, data in published.items():
            if name not in repo or any(data.get(k, []) != repo[name].get(k, [])
                    for k in ("NAME", "VERSION", "ARCH", "DEPENDS", "PROVIDES", "CONFLICTS", "REPLACES")):
                raise ValueError("capture/repository metadata mismatch: " + name)
    versions = Versions()
    baseline = requirements(image, image, versions)
    combined = {**image, **published}
    audio_requirements = requirements({n: published[n] for n in AUDIO}, combined, versions)
    # Expand only observed repository packages, preserving unresolved ALARM inputs.
    extensions, pending = {}, [r["requires"] for r in audio_requirements if not r["witnesses"]]
    while pending:
        dep = pending.pop()
        for witness in witnesses(dep, repo, versions):
            name = witness["package"]
            if name not in combined and name not in extensions:
                extensions[name] = repo[name]
                pending.extend(repo[name].get("DEPENDS", []))
    extended = {**combined, **extensions}
    extension_requirements = requirements(extensions, extended, versions)
    closure, pending, edges = set(), list(ROOTS), []
    while pending:
        name = pending.pop()
        if name in closure or name not in image:
            continue
        closure.add(name)
        for dep in image[name].get("DEPENDS", []):
            found = witnesses(dep, image, versions)
            edges.append({"package": name, "requires": dep, "witnesses": found})
            pending.extend(w["package"] for w in found)
    differences = []
    for name in BOOT + AUDIO:
        old = image.get(name, {}).get("VERSION", [None])[0]
        current = published[name]["VERSION"][0]
        differences.append({"name": name, "image_version": old, "published_version": current,
                            "relation": "absent" if old is None else "same" if old == current else "different",
                            "archive_sha256": signed[name]["archive"]["sha256"]})
    missing = [r for r in baseline if not r["witnesses"]]
    return {
        "schema_version": 1, "kind": "offline-platform-metadata-witnesses",
        "input_sha256": {k: digest(v) for k, v in raw.items()},
        "image_package_count": len(image), "published_comparison": differences,
        "pkginfo_repository_fields_match": True,
        "baseline_requirements": baseline, "baseline_missing_requirements": missing,
        "multiple_provider_relations": [r for r in baseline if len(r["witnesses"]) > 1],
        "audio_after_seven_archives_requirements": audio_requirements,
        "repository_extension_candidates": [{"name": n, "version": p["VERSION"][0]}
                                            for n, p in sorted(extensions.items())],
        "repository_extension_requirements": extension_requirements,
        "remaining_audio_requirements": sorted({r["requires"] for r in
            requirements({n: published[n] for n in AUDIO}, extended, versions) + extension_requirements
            if not r["witnesses"]}),
        "proposed_protected_roots": [{"name": n, "version": image[n]["VERSION"][0] if n in image else None}
                                     for n in ROOTS],
        "proposed_installed_dependency_graph": [{"name": n, "version": image[n]["VERSION"][0]}
                                                for n in sorted(closure)],
        "protected_graph_requirements": sorted(edges, key=lambda e: (e["package"], e["requires"])),
        "dependency_transaction_accepted": False, "image_authentication_accepted": False,
        "independent_owner_trust_accepted": False, "installation_accepted": False,
        "hardware_accepted": False, "system_mutation": False,
        "repository_extension_archives_verified": False,
        "limitations": ["Metadata witnesses do not select or prepare a libalpm transaction.",
                        "Installed file identity, ownership, conflicts, hooks and scriptlets are not inspected.",
                        "Same versions do not prove installed bytes equal retained signed archives.",
                        "Repository extension candidates are metadata availability; their archives/signatures are not inspected.",
                        "Input checksums bind retained observations; this run does not authenticate signatures or owners."],
    }


def write_private(path, report):
    """Create one new report inside an existing private directory; never overwrite."""
    path = Path(path).absolute()
    parent = path.parent
    # Reject symbolic ancestors before opening the directory itself without following.
    if any(p.is_symlink() for p in (parent, *parent.parents)):
        raise ValueError("output ancestors must not be symlinks")
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(directory)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("output parent must be owned by this user with mode 0700")
        encoded = bytearray()
        for chunk in json.JSONEncoder(indent=2, sort_keys=True, allow_nan=False).iterencode(report):
            part = chunk.encode()
            if len(encoded) + len(part) + 1 > MAX_BYTES:
                raise ValueError("serialized report size limit")
            encoded.extend(part)
        encoded.extend(b"\n")
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        except BaseException:
            os.unlink(path.name, dir_fd=directory)
            raise
    finally:
        os.close(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("image", "signed", "metadata", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--repository", type=Path)
    args = parser.parse_args()
    try:
        report = run(args.image, args.signed, args.metadata, args.repository)
        if report["image_package_count"] != 261:
            raise ValueError("retained image must contain 261 packages")
        write_private(args.output, report)
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError, EOFError) as error:
        parser.exit(1, "tuple audit refused: " + str(error) + "\n")
    print(json.dumps({"report": str(args.output.absolute()), "dependency_transaction_accepted": False,
                      "hardware_accepted": False}, sort_keys=True))


if __name__ == "__main__":
    main()
